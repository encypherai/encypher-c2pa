//! OCSP response evaluation for stapled revocation status (RFC 6960).
//!
//! C2PA validators check revocation in this order: (1) the OCSP staple in the
//! COSE manifest, (2) a freshly fetched OCSP response if enabled, (3) a
//! `CertificateStatus` assertion. This module covers (1): parse a DER OCSP
//! response, extract the single cert status and the `thisUpdate`/`nextUpdate`
//! validity window, and evaluate it against the validation time.
//!
//! The parser is intentionally minimal — it walks the DER structure of a
//! `BasicOCSPResponse` to the `SingleResponse` `certStatus` and the two
//! `GeneralizedTime` fields. It does not (yet) verify the OCSP responder's own
//! signature; that requires the responder cert chain and is gated behind the
//! same trust-list machinery as the signing chain (future work, noted in the
//! verifier).

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::OffsetDateTime;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// OID constants (local to this module; mirror the values in `lib.rs`).
// ---------------------------------------------------------------------------

/// `id-kp-OCSPSigning` — the EKU a delegated OCSP responder certificate must
/// carry to be authorized by its issuing CA (RFC 6960 §4.2.2.2).
const OID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const OID_EXT_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_CURVE_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Revocation status decoded from an OCSP single response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate is revoked.
    Revoked,
    /// Responder does not know the certificate's status.
    Unknown,
}

/// Result of evaluating a stapled OCSP response.
#[derive(Debug, Clone)]
pub struct OcspEvaluation {
    /// Decoded certificate status.
    pub status: OcspStatus,
    /// `thisUpdate` — when the responder last knew this status.
    pub this_update: Option<OffsetDateTime>,
    /// `nextUpdate` — when newer status info will be available.
    pub next_update: Option<OffsetDateTime>,
}

impl OcspEvaluation {
    /// True when the response is fresh at `at`: `thisUpdate <= at < nextUpdate`
    /// (a missing `nextUpdate` is treated as still-valid).
    pub fn is_fresh_at(&self, at: OffsetDateTime) -> bool {
        let after_this = self.this_update.map(|t| at >= t).unwrap_or(true);
        let before_next = self.next_update.map(|t| at < t).unwrap_or(true);
        after_this && before_next
    }
}

/// Parse and evaluate a DER-encoded OCSP response (`OCSPResponse`).
///
/// Returns `None` if the bytes are not a parseable OCSP response with a single
/// cert status. Errors are folded into `None` (the verifier treats an
/// unparseable staple as "no usable staple" rather than failing hard).
pub fn evaluate(der: &[u8]) -> Option<OcspEvaluation> {
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ... }
    let mut p = Der::new(der);
    let resp = p.sequence()?;
    let mut r = Der::new(resp);
    let status = r.enumerated()?; // responseStatus: 0 = successful
    if status != 0 {
        return None;
    }
    // responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING }
    let rb = r.tagged(0)?;
    let mut rb = Der::new(rb);
    let rb_seq = rb.sequence()?;
    let mut rb_seq = Der::new(rb_seq);
    rb_seq.skip()?; // responseType OID (id-pkix-ocsp-basic)
    let basic_octets = rb_seq.octet_string()?;
    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm, signature, [0] certs }
    let mut basic = Der::new(basic_octets);
    let tbs = basic.sequence()?;
    let mut tbs = Der::new(tbs);
    let tbs_inner = tbs.sequence()?;
    // ResponseData ::= SEQUENCE { [0] version?, responderID, producedAt GenTime, responses SEQUENCE OF SingleResponse, ... }
    let mut rd = Der::new(tbs_inner);
    // Walk fields until we reach the `responses` SEQUENCE OF SingleResponse.
    // Skip optional [0] version, responderID (context [1]/[2]), producedAt.
    let responses = rd.find_responses()?;
    // Take the first SingleResponse.
    let mut resp_list = Der::new(responses);
    let single = resp_list.sequence()?;
    let mut sr = Der::new(single);
    let _certid = sr.sequence()?; // CertID
    let cert_status = sr.cert_status()?;
    let this_update = sr.generalized_time().ok();
    // nextUpdate is [0] EXPLICIT GeneralizedTime (optional).
    // nextUpdate is [0] EXPLICIT GeneralizedTime: the context tag wraps a full
    // GeneralizedTime TLV, so parse the inner value, not the wrapper bytes.
    let next_update = sr
        .tagged(0)
        .and_then(|b| Der::new(b).generalized_time().ok());

    Some(OcspEvaluation {
        status: cert_status,
        this_update,
        next_update,
    })
}

/// Parse, **verify**, and evaluate a DER-encoded OCSP response.
///
/// In addition to everything [`evaluate`] does, this verifies that the staple
/// genuinely originates from an authorized responder before trusting its
/// status, as required by RFC 6960 §3.2:
///
/// 1. The responder is either the certificate issuer itself, or a certificate
///    *issued by* the issuer that carries the `id-kp-OCSPSigning` EKU
///    (`1.3.6.1.5.5.7.3.9`).
/// 2. The responder certificate is valid at `validation_time`.
/// 3. The `signature` BIT STRING verifies over the exact DER encoding of
///    `tbsResponseData` under the responder's public key.
///
/// If the optional `[0] certs` field is present, the first certificate is taken
/// as the responder; otherwise the response is assumed to be signed directly by
/// `issuer_der` (a "direct" issuer-signed response).
///
/// Returns `None` (staple ignored — treated as "no usable staple") if parsing
/// fails or **any** authorization/signature/validity check fails.
pub fn evaluate_verified(
    der: &[u8],
    issuer_der: &[u8],
    subject_der: Option<&[u8]>,
    validation_time: OffsetDateTime,
) -> Option<OcspEvaluation> {
    let mut p = Der::new(der);
    let resp = p.sequence()?;
    let mut r = Der::new(resp);
    let status = r.enumerated()?;
    if status != 0 {
        return None;
    }
    let rb = r.tagged(0)?;
    let mut rb = Der::new(rb);
    let rb_seq = rb.sequence()?;
    let mut rb_seq = Der::new(rb_seq);
    rb_seq.skip()?; // responseType OID (id-pkix-ocsp-basic)
    let basic_octets = rb_seq.octet_string()?;

    // BasicOCSPResponse ::= SEQUENCE {
    //   tbsResponseData ResponseData, signatureAlgorithm AlgorithmIdentifier,
    //   signature BIT STRING, [0] EXPLICIT certs SEQUENCE OF Certificate OPTIONAL }
    let mut basic = Der::new(basic_octets);
    let basic_inner = basic.sequence()?;
    let mut b = Der::new(basic_inner);

    // Capture tbsResponseData as its full TLV (the signed message), then descend
    // into its contents for the cert-status fields.
    let tbs_tlv = b.peek_tlv_bytes()?;
    let tbs_inner = b.sequence()?;

    // signatureAlgorithm AlgorithmIdentifier ::= SEQUENCE { algorithm OID, params OPT }
    let sig_alg_inner = b.sequence()?;
    let sig_alg_oid = Der::new(sig_alg_inner).object_identifier()?;

    // signature BIT STRING.
    let signature = b.bit_string()?;

    // Optional [0] EXPLICIT certs SEQUENCE OF Certificate -> first certificate.
    let responder_owned: Vec<u8>;
    let responder_der: &[u8] = match b.tagged(0) {
        Some(certs_explicit) => {
            let mut wrapper = Der::new(certs_explicit);
            let cert_list = wrapper.sequence()?;
            let first = Der::new(cert_list).peek_tlv_bytes()?;
            responder_owned = first.to_vec();
            &responder_owned
        }
        None => issuer_der,
    };

    // Cert-status fields (mirrors `evaluate`).
    let mut rd = Der::new(tbs_inner);
    let responses = rd.find_responses()?;
    let mut resp_list = Der::new(responses);
    let single = resp_list.sequence()?;
    let mut sr = Der::new(single);
    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash OCTET STRING,
    //   issuerKeyHash OCTET STRING, serialNumber INTEGER }. When the subject
    // certificate is supplied, the response's serialNumber MUST match it,
    // otherwise the staple is for a different certificate (RFC 6960 §4.1.1) and
    // must be ignored.
    let certid = sr.sequence()?;
    if let Some(subj) = subject_der {
        let subj_cert = Certificate::from_der(subj).ok()?;
        let subj_serial = subj_cert.tbs_certificate.serial_number.as_bytes();
        let mut cid = Der::new(certid);
        cid.skip()?; // hashAlgorithm
        cid.skip()?; // issuerNameHash
        cid.skip()?; // issuerKeyHash
        let resp_serial = cid.integer()?;
        // Compare as unsigned magnitudes (ignore a leading sign-guard 0x00).
        let trim = |b: &[u8]| -> Vec<u8> {
            let mut s = b;
            while s.len() > 1 && s[0] == 0 {
                s = &s[1..];
            }
            s.to_vec()
        };
        if trim(resp_serial) != trim(subj_serial) {
            return None;
        }
    }
    let cert_status = sr.cert_status()?;
    let this_update = sr.generalized_time().ok();
    let next_update = sr
        .tagged(0)
        .and_then(|x| Der::new(x).generalized_time().ok());

    // ---- Responder authorization + signature verification ----
    let responder_cert = Certificate::from_der(responder_der).ok()?;
    let issuer_cert = Certificate::from_der(issuer_der).ok()?;

    // The responder is the issuer when the DER matches or the public keys match
    // (the issuer may include its own cert in `certs`).
    let resp_spki = responder_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    let iss_spki = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    let responder_is_issuer = responder_der == issuer_der || resp_spki == iss_spki;

    if !responder_is_issuer {
        // Delegated responder: must be issued by the CA AND hold the OCSP-signing
        // EKU. Either failing means the staple is unauthorized -> ignore.
        if !cert_signed_by(&responder_cert, &issuer_cert) {
            return None;
        }
        if !has_ocsp_signing_eku(&responder_cert) {
            return None;
        }
    }

    // Responder cert must be valid at the validation instant.
    if !valid_at(&responder_cert, validation_time) {
        return None;
    }

    // The OCSP signature must verify over tbsResponseData under the responder key.
    if !verify_message(&responder_cert, sig_alg_oid, signature, tbs_tlv) {
        return None;
    }

    Some(OcspEvaluation {
        status: cert_status,
        this_update,
        next_update,
    })
}

#[derive(Clone, Copy)]
enum SigHash {
    Sha256,
    Sha384,
    Sha512,
}

fn digest_bytes(hash: SigHash, msg: &[u8]) -> Vec<u8> {
    match hash {
        SigHash::Sha256 => Sha256::digest(msg).to_vec(),
        SigHash::Sha384 => Sha384::digest(msg).to_vec(),
        SigHash::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

/// Verify that `subject`'s certificate signature was produced by `issuer`'s key.
fn cert_signed_by(subject: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = subject.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = subject.signature.as_bytes() else {
        return false;
    };
    verify_message(issuer, subject.signature_algorithm.oid, sig, &tbs)
}

/// Verify `signature` over `message` under `signer`'s public key, selecting the
/// algorithm from `sig_alg` (the signatureAlgorithm OID) and the key type /
/// curve from `signer`'s SubjectPublicKeyInfo.
///
/// Mirrors the dispatch in `lib.rs::verify_signature`: ECDSA over NIST
/// P-256/P-384/P-521, RSA PKCS#1 v1.5, and Ed25519. Unsupported algorithms
/// return `false`.
fn verify_message(
    signer: &Certificate,
    sig_alg: ObjectIdentifier,
    sig: &[u8],
    message: &[u8],
) -> bool {
    let spki = &signer.tbs_certificate.subject_public_key_info;
    let Some(pubkey) = spki.subject_public_key.as_bytes() else {
        return false;
    };
    let key_alg = spki.algorithm.oid;

    if key_alg == OID_EC_PUBLIC_KEY {
        let hash = match sig_alg {
            OID_ECDSA_SHA256 => SigHash::Sha256,
            OID_ECDSA_SHA384 => SigHash::Sha384,
            OID_ECDSA_SHA512 => SigHash::Sha512,
            _ => return false,
        };
        let curve = match spki.algorithm.parameters.as_ref() {
            Some(p) => match p.decode_as::<ObjectIdentifier>() {
                Ok(oid) => oid,
                Err(_) => return false,
            },
            None => return false,
        };
        verify_ecdsa(curve, hash, pubkey, sig, message)
    } else if key_alg == OID_RSA_ENCRYPTION {
        let hash = match sig_alg {
            OID_RSA_SHA256 => SigHash::Sha256,
            OID_RSA_SHA384 => SigHash::Sha384,
            OID_RSA_SHA512 => SigHash::Sha512,
            _ => return false,
        };
        verify_rsa(hash, pubkey, sig, message)
    } else if key_alg == OID_ED25519 {
        verify_ed25519(pubkey, sig, message)
    } else {
        false
    }
}

fn verify_ecdsa(
    curve: ObjectIdentifier,
    hash: SigHash,
    pubkey: &[u8],
    sig_der: &[u8],
    message: &[u8],
) -> bool {
    let prehash = digest_bytes(hash, message);
    if curve == OID_CURVE_P256 {
        let (Ok(vk), Ok(sig)) = (
            p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p256::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else if curve == OID_CURVE_P384 {
        let (Ok(vk), Ok(sig)) = (
            p384::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p384::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else if curve == OID_CURVE_P521 {
        let (Ok(vk), Ok(sig)) = (
            p521::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p521::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else {
        false
    }
}

fn verify_rsa(hash: SigHash, pubkey_der: &[u8], sig: &[u8], message: &[u8]) -> bool {
    let Ok(pubkey) = rsa::RsaPublicKey::from_pkcs1_der(pubkey_der) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    match hash {
        SigHash::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pubkey)
            .verify(message, &signature)
            .is_ok(),
        SigHash::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(pubkey)
            .verify(message, &signature)
            .is_ok(),
        SigHash::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(pubkey)
            .verify(message, &signature)
            .is_ok(),
    }
}

fn verify_ed25519(pubkey: &[u8], sig: &[u8], message: &[u8]) -> bool {
    let Ok(key_bytes): Result<[u8; 32], _> = pubkey.try_into() else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_strict(message, &signature).is_ok()
}

/// True when `cert` carries an Extended Key Usage extension listing
/// `id-kp-OCSPSigning`.
fn has_ocsp_signing_eku(cert: &Certificate) -> bool {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_EXT_EKU) else {
        return false;
    };
    let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) else {
        return false;
    };
    eku.0.contains(&OID_KP_OCSP_SIGNING)
}

/// True when the certificate's validity window contains `t`.
fn valid_at(cert: &Certificate, t: OffsetDateTime) -> bool {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    let now = t.unix_timestamp();
    nb <= now && now <= na
}

/// Minimal DER cursor.
struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data, pos: 0 }
    }

    /// Read a (tag, contents) TLV at the cursor, advancing past it.
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.pos)?;
        let len_byte = *self.data.get(self.pos + 1)? as usize;
        let (len, hdr) = if len_byte < 0x80 {
            (len_byte, 2)
        } else {
            let n = len_byte & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | (*self.data.get(self.pos + 2 + i)? as usize);
            }
            (len, 2 + n)
        };
        let start = self.pos + hdr;
        let end = start.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some((tag, &self.data[start..end]))
    }

    /// Expect a SEQUENCE (0x30), return its contents.
    fn sequence(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.tlv()?;
        if tag == 0x30 {
            Some(body)
        } else {
            None
        }
    }

    /// Expect an OCTET STRING (0x04), return its contents.
    fn octet_string(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.tlv()?;
        if tag == 0x04 {
            Some(body)
        } else {
            None
        }
    }

    /// Expect an ENUMERATED (0x0a), return its first byte value.
    fn enumerated(&mut self) -> Option<u8> {
        let (tag, body) = self.tlv()?;
        if tag == 0x0a {
            body.first().copied()
        } else {
            None
        }
    }
    /// Expect an INTEGER (0x02), returning the raw big-endian content bytes
    /// (including any DER sign-guard `0x00`).
    fn integer(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.tlv()?;
        if tag == 0x02 {
            Some(body)
        } else {
            None
        }
    }
    /// Expect a context-tagged [n] constructed element, return its contents.
    fn tagged(&mut self, n: u8) -> Option<&'a [u8]> {
        let (tag, body) = self.tlv()?;
        if tag == (0xa0 | n) {
            Some(body)
        } else {
            None
        }
    }

    /// Skip one TLV.
    fn skip(&mut self) -> Option<()> {
        self.tlv().map(|_| ())
    }

    /// Read a GeneralizedTime (0x18) and parse it.
    fn generalized_time(&mut self) -> Result<OffsetDateTime, ()> {
        let (tag, body) = self.tlv().ok_or(())?;
        if tag != 0x18 {
            return Err(());
        }
        parse_generalized_time(body).ok_or(())
    }

    /// Read the `certStatus` CHOICE: [0] good (primitive), [1] revoked
    /// (constructed), [2] unknown (primitive).
    fn cert_status(&mut self) -> Option<OcspStatus> {
        let (tag, _) = self.tlv()?;
        match tag {
            0x80 => Some(OcspStatus::Good),    // [0] IMPLICIT NULL
            0xa1 => Some(OcspStatus::Revoked), // [1] RevokedInfo (constructed)
            0x82 => Some(OcspStatus::Unknown), // [2] IMPLICIT NULL
            _ => None,
        }
    }

    /// Within ResponseData, skip leading fields and return the `responses`
    /// SEQUENCE OF SingleResponse contents.
    ///
    /// ResponseData fields in order: optional version [0], responderID
    /// (byName [1] / byKey [2]), producedAt (GeneralizedTime 0x18), then the
    /// responses SEQUENCE (0x30). We scan for the first plain SEQUENCE that
    /// follows the producedAt time.
    fn find_responses(&mut self) -> Option<&'a [u8]> {
        let mut seen_time = false;
        loop {
            let tag = *self.data.get(self.pos)?;
            let save = self.pos;
            let (_, body) = self.tlv()?;
            if tag == 0x18 {
                seen_time = true;
            } else if tag == 0x30 && seen_time {
                return Some(body);
            } else if tag == 0x30 && !seen_time {
                // Could be responderID byName or producedAt-less; keep the
                // first SEQUENCE after we've passed responderID. Heuristic:
                // accept it if the next item looks like a SingleResponse.
                let _ = save;
            }
        }
    }

    /// Return the full TLV slice (tag + length + contents) at the cursor
    /// without advancing. Used to capture `tbsResponseData` exactly as encoded
    /// — the byte string the OCSP signature is computed over.
    fn peek_tlv_bytes(&self) -> Option<&'a [u8]> {
        let len_byte = *self.data.get(self.pos + 1)? as usize;
        let (len, hdr) = if len_byte < 0x80 {
            (len_byte, 2)
        } else {
            let n = len_byte & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | (*self.data.get(self.pos + 2 + i)? as usize);
            }
            (len, 2 + n)
        };
        let end = self.pos.checked_add(hdr)?.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[self.pos..end])
    }

    /// Expect a BIT STRING (0x03) with zero unused bits, returning the bit
    /// octets (the signature value of a `BasicOCSPResponse`).
    fn bit_string(&mut self) -> Option<&'a [u8]> {
        let (tag, body) = self.tlv()?;
        if tag != 0x03 {
            return None;
        }
        match body.split_first() {
            Some((0, bits)) => Some(bits),
            _ => None,
        }
    }

    /// Expect an OBJECT IDENTIFIER (0x06), returning the decoded OID.
    fn object_identifier(&mut self) -> Option<ObjectIdentifier> {
        let (tag, body) = self.tlv()?;
        if tag != 0x06 {
            return None;
        }
        ObjectIdentifier::from_bytes(body).ok()
    }
}

/// Parse a DER GeneralizedTime body (`YYYYMMDDHHMMSSZ`) to `OffsetDateTime`.
fn parse_generalized_time(body: &[u8]) -> Option<OffsetDateTime> {
    let s = std::str::from_utf8(body).ok()?;
    // Expect at least YYYYMMDDHHMMSSZ (15 chars).
    if s.len() < 15 || !s.ends_with('Z') {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u8 = s.get(4..6)?.parse().ok()?;
    let day: u8 = s.get(6..8)?.parse().ok()?;
    let hour: u8 = s.get(8..10)?.parse().ok()?;
    let min: u8 = s.get(10..12)?.parse().ok()?;
    let sec: u8 = s.get(12..14)?.parse().ok()?;
    let month = time::Month::try_from(month).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let t = time::Time::from_hms(hour, min, sec).ok()?;
    Some(date.with_time(t).assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_generalized_time() {
        let t = parse_generalized_time(b"20130601120000Z").unwrap();
        assert_eq!(t.year(), 2013);
        assert_eq!(t.month() as u8, 6);
        assert_eq!(t.day(), 1);
    }

    #[test]
    fn freshness_window() {
        let e = OcspEvaluation {
            status: OcspStatus::Good,
            this_update: parse_generalized_time(b"20130101000000Z"),
            next_update: parse_generalized_time(b"20130201000000Z"),
        };
        assert!(e.is_fresh_at(parse_generalized_time(b"20130115000000Z").unwrap()));
        assert!(!e.is_fresh_at(parse_generalized_time(b"20130301000000Z").unwrap()));
        assert!(!e.is_fresh_at(parse_generalized_time(b"20121201000000Z").unwrap()));
    }

    #[test]
    fn rejects_non_ocsp_bytes() {
        assert!(evaluate(&[0x00, 0x01, 0x02]).is_none());
        assert!(evaluate(b"not der at all").is_none());
    }

    // --- evaluate_verified: responder authorization & signature checks ---

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use time::macros::datetime;

    /// Encode a DER length (short or long form).
    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let mut bytes = Vec::new();
            let mut n = len;
            while n > 0 {
                bytes.push((n & 0xff) as u8);
                n >>= 8;
            }
            bytes.reverse();
            let mut out = vec![0x80 | bytes.len() as u8];
            out.extend(bytes);
            out
        }
    }

    /// Build a DER TLV from a tag and contents.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + content.len());
        v.push(tag);
        v.extend(der_len(content.len()));
        v.extend_from_slice(content);
        v
    }

    /// A fixed, deterministic `tbsResponseData` (status = good) so the signature
    /// computed over it stays stable across helper calls.
    fn build_tbs() -> Vec<u8> {
        let responder_id = tlv(0xa1, &tlv(0x30, &[])); // [1] EXPLICIT Name (empty RDNSequence)
        let produced_at = tlv(0x18, b"20260101000000Z");
        let cert_id = tlv(0x30, &[]); // opaque CertID (skipped by the parser)
        let cert_status = tlv(0x80, &[]); // [0] good
        let this_update = tlv(0x18, b"20260101000000Z");
        let next_update = tlv(0xa0, &tlv(0x18, b"20270101000000Z")); // [0] EXPLICIT
        let mut single = Vec::new();
        single.extend(cert_id);
        single.extend(cert_status);
        single.extend(this_update);
        single.extend(next_update);
        let single = tlv(0x30, &single);
        let responses = tlv(0x30, &single);
        let mut rd = Vec::new();
        rd.extend(responder_id);
        rd.extend(produced_at);
        rd.extend(responses);
        tlv(0x30, &rd)
    }

    /// ECDSA-P256-SHA256 sign `msg` with an rcgen key pair, returning the DER
    /// `ECDSA-Sig-Value`.
    fn sign_p256(key: &KeyPair, msg: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;
        let sk = SigningKey::from_pkcs8_der(&key.serialize_der()).expect("load pkcs8 key");
        let sig: Signature = sk.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }

    /// Assemble a full `OCSPResponse` from a `tbsResponseData`, a signature, and
    /// an optional responder certificate (DER, full TLV) for the `[0] certs`
    /// field.
    fn assemble(tbs: &[u8], sig_der: &[u8], cert_der: Option<&[u8]>) -> Vec<u8> {
        let sig_alg = tlv(0x30, &OID_ECDSA_SHA256.to_der().unwrap());
        let mut sig_bits = vec![0x00]; // zero unused bits
        sig_bits.extend_from_slice(sig_der);
        let signature = tlv(0x03, &sig_bits);

        let mut basic = Vec::new();
        basic.extend_from_slice(tbs);
        basic.extend(sig_alg);
        basic.extend(signature);
        if let Some(cert) = cert_der {
            let cert_list = tlv(0x30, cert); // SEQUENCE OF Certificate (single)
            basic.extend(tlv(0xa0, &cert_list)); // [0] EXPLICIT
        }
        let basic = tlv(0x30, &basic);

        let basic_oid = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
        let octet = tlv(0x04, &basic);
        let mut rb = Vec::new();
        rb.extend(basic_oid.to_der().unwrap());
        rb.extend(octet);
        let rb = tlv(0x30, &rb);
        let rb_explicit = tlv(0xa0, &rb);

        let status = tlv(0x0a, &[0x00]); // responseStatus = successful
        let mut top = Vec::new();
        top.extend(status);
        top.extend(rb_explicit);
        tlv(0x30, &top)
    }

    /// Self-signed CA certificate + key pair.
    fn make_ca(cn: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("ca keypair");
        let mut params = CertificateParams::new(vec!["ca.example".to_string()]).expect("params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).expect("self-signed ca");
        (cert, key)
    }

    /// Responder certificate signed by `issuer`, optionally carrying the
    /// OCSP-signing EKU.
    fn make_responder(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
        with_eku: bool,
    ) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("responder keypair");
        let mut params =
            CertificateParams::new(vec!["responder.example".to_string()]).expect("params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "OCSP Responder");
        params.distinguished_name = dn;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = IsCa::NoCa;
        if with_eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        }
        let cert = params
            .signed_by(&key, issuer, issuer_key)
            .expect("issued responder");
        (cert, key)
    }

    const AT: time::OffsetDateTime = datetime!(2026-06-01 0:00 UTC);

    #[test]
    fn verified_accepts_delegated_responder() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let tbs = build_tbs();
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));

        let ev = evaluate_verified(&resp, &issuer_der, None, AT).expect("authorized staple");
        assert_eq!(ev.status, OcspStatus::Good);
    }

    /// Like [`build_tbs`] but with a CertID carrying the given serial number, so
    /// the subject-serial match path can be exercised.
    fn build_tbs_with_serial(serial: &[u8]) -> Vec<u8> {
        let responder_id = tlv(0xa1, &tlv(0x30, &[]));
        let produced_at = tlv(0x18, b"20260101000000Z");
        // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serial }
        let mut certid = Vec::new();
        certid.extend(tlv(
            0x30,
            &ObjectIdentifier::new_unwrap("1.3.14.3.2.26")
                .to_der()
                .unwrap(),
        )); // sha1 alg id (opaque)
        certid.extend(tlv(0x04, &[0u8; 20])); // issuerNameHash
        certid.extend(tlv(0x04, &[0u8; 20])); // issuerKeyHash
        certid.extend(tlv(0x02, serial)); // serialNumber
        let cert_id = tlv(0x30, &certid);
        let cert_status = tlv(0x80, &[]);
        let this_update = tlv(0x18, b"20260101000000Z");
        let next_update = tlv(0xa0, &tlv(0x18, b"20270101000000Z"));
        let mut single = Vec::new();
        single.extend(cert_id);
        single.extend(cert_status);
        single.extend(this_update);
        single.extend(next_update);
        let single = tlv(0x30, &single);
        let responses = tlv(0x30, &single);
        let mut rd = Vec::new();
        rd.extend(responder_id);
        rd.extend(produced_at);
        rd.extend(responses);
        tlv(0x30, &rd)
    }

    #[test]
    fn verified_rejects_certid_serial_mismatch() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        // Subject = the responder cert here only as a serial source; its serial
        // will not equal the hard-coded CertID serial below.
        let subj_der = responder_der.clone();
        let subj = Certificate::from_der(&subj_der).unwrap();
        let subj_serial = subj.tbs_certificate.serial_number.as_bytes().to_vec();
        // Build a CertID whose serial differs from the subject's.
        let mut wrong = subj_serial.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0xff;
        let tbs = build_tbs_with_serial(&wrong);
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));
        // Without a subject -> serial not checked -> accepted.
        assert!(evaluate_verified(&resp, &issuer_der, None, AT).is_some());
        // With the subject -> serial mismatch -> ignored.
        assert!(evaluate_verified(&resp, &issuer_der, Some(&subj_der), AT).is_none());
    }

    #[test]
    fn verified_accepts_certid_serial_match() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let subj = Certificate::from_der(&responder_der).unwrap();
        let subj_serial = subj.tbs_certificate.serial_number.as_bytes().to_vec();
        let tbs = build_tbs_with_serial(&subj_serial);
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));
        let ev = evaluate_verified(&resp, &issuer_der, Some(&responder_der), AT)
            .expect("matching-serial staple accepted");
        assert_eq!(ev.status, OcspStatus::Good);
    }

    #[test]
    fn verified_rejects_bad_signature() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let tbs = build_tbs();
        let mut sig = sign_p256(&responder_key, &tbs);
        // Flip a byte inside the DER signature value: still well-formed DER, but
        // the ECDSA verification over tbsResponseData now fails.
        let last = sig.len() - 1;
        sig[last] ^= 0xff;
        let resp = assemble(&tbs, &sig, Some(&responder_der));

        assert!(evaluate_verified(&resp, &issuer_der, None, AT).is_none());
    }

    #[test]
    fn verified_rejects_responder_without_eku() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, false);
        let responder_der = responder.der().as_ref().to_vec();

        let tbs = build_tbs();
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));

        assert!(evaluate_verified(&resp, &issuer_der, None, AT).is_none());
    }

    #[test]
    fn verified_rejects_wrong_ca_responder() {
        let (ca, _ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        // Responder issued by a *different* CA, even though it has the EKU.
        let (other_ca, other_key) = make_ca("Rogue CA");
        let (responder, responder_key) = make_responder(&other_ca, &other_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let tbs = build_tbs();
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));

        assert!(evaluate_verified(&resp, &issuer_der, None, AT).is_none());
    }

    #[test]
    fn verified_accepts_direct_issuer_signed() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();

        // No `certs` field: the response is signed directly by the issuer key.
        let tbs = build_tbs();
        let sig = sign_p256(&ca_key, &tbs);
        let resp = assemble(&tbs, &sig, None);

        let ev = evaluate_verified(&resp, &issuer_der, None, AT).expect("issuer-signed staple");
        assert_eq!(ev.status, OcspStatus::Good);
    }

    #[test]
    fn verified_rejects_responder_expired_at_validation_time() {
        let (ca, ca_key) = make_ca("Test Issuer CA");
        let issuer_der = ca.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&ca, &ca_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let tbs = build_tbs();
        let sig = sign_p256(&responder_key, &tbs);
        let resp = assemble(&tbs, &sig, Some(&responder_der));

        // 2099 is well past the responder's notAfter (2030) -> ignored.
        let after = datetime!(2099-01-01 0:00 UTC);
        assert!(evaluate_verified(&resp, &issuer_der, None, after).is_none());
    }
}
