//! OCSP response evaluation for stapled revocation status (RFC 6960).
//!
//! Embedded OCSP evidence can come from the COSE `rVals` header or a
//! `c2pa.certificate-status` assertion. This module parses DER OCSP responses,
//! verifies the full RFC 6960 certificate identity and responder authority,
//! and applies the C2PA historical-signing-time policy.

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
const OID_PKIX_OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
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

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Maximum DER bytes accepted for one embedded OCSP response.
pub(crate) const MAX_OCSP_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum certificates inspected from `BasicOCSPResponse.certs`.
const MAX_OCSP_RESPONDER_CERTIFICATES: usize = 16;
/// Maximum DER bytes accepted for one embedded responder certificate.
const MAX_OCSP_RESPONDER_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum aggregate DER bytes accepted for embedded responder certificates.
const MAX_OCSP_RESPONDER_CERTIFICATE_TOTAL_BYTES: usize = 256 * 1024;
/// Maximum `SingleResponse` entries inspected in one OCSP response.
const MAX_OCSP_SINGLE_RESPONSES: usize = 64;

/// Reason carried by an RFC 6960 `RevokedInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OcspRevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
    Unknown(u8),
}

impl OcspRevocationReason {
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            other => Self::Unknown(other),
        }
    }
}

/// Revocation status decoded from an OCSP single response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// Certificate is not revoked.
    Good,
    /// Certificate was revoked at `revocation_time`.
    Revoked {
        revocation_time: OffsetDateTime,
        reason: Option<OcspRevocationReason>,
    },
    /// Responder does not know the certificate's status.
    Unknown,
}

impl OcspStatus {
    /// Merge evidence using an order-independent, fail-closed precedence.
    ///
    /// Non-`removeFromCRL` revocation dominates good. Good dominates unknown
    /// or absent evidence. `removeFromCRL` is affirmative non-revocation
    /// evidence under the embedded C2PA policy and therefore merges as good.
    pub(crate) fn merge(accumulated: Option<Self>, candidate: Option<Self>) -> Option<Self> {
        fn decisive(status: Option<OcspStatus>) -> Option<OcspStatus> {
            match status {
                Some(OcspStatus::Unknown) | None => None,
                Some(OcspStatus::Revoked {
                    reason: Some(OcspRevocationReason::RemoveFromCrl),
                    ..
                }) => Some(OcspStatus::Good),
                status => status,
            }
        }

        match (decisive(accumulated), decisive(candidate)) {
            (
                Some(
                    left @ Self::Revoked {
                        revocation_time: left_time,
                        reason: left_reason,
                    },
                ),
                Some(
                    right @ Self::Revoked {
                        revocation_time: right_time,
                        reason: right_reason,
                    },
                ),
            ) => Some(if (left_time, left_reason) <= (right_time, right_reason) {
                left
            } else {
                right
            }),
            (Some(revoked @ Self::Revoked { .. }), _)
            | (_, Some(revoked @ Self::Revoked { .. })) => Some(revoked),
            (Some(Self::Good), _) | (_, Some(Self::Good)) => Some(Self::Good),
            (None, None) => None,
            _ => unreachable!("decisive OCSP status is good or revoked"),
        }
    }
}

/// Result of evaluating a stapled OCSP response.
#[derive(Debug, Clone)]
pub struct OcspEvaluation {
    /// Decoded certificate status.
    pub status: OcspStatus,
    /// `producedAt` - when the responder signed this response.
    pub produced_at: OffsetDateTime,
    /// `thisUpdate` - when the responder last knew this status.
    pub this_update: OffsetDateTime,
    /// `nextUpdate` - when newer status info will be available.
    pub next_update: Option<OffsetDateTime>,
}

impl OcspEvaluation {
    /// Apply C2PA 2.4 section 15.9.1 to verified embedded evidence.
    ///
    /// `None` means this response does not establish a status at signing.
    /// `removeFromCRL` establishes that the certificate was not revoked at the
    /// attested signing time. Every other revoked status remains revoked.
    pub fn status_at_signing(
        &self,
        signed_at: Option<OffsetDateTime>,
        verification_time: OffsetDateTime,
    ) -> Option<OcspStatus> {
        let signed_at = signed_at?;
        if self.produced_at > verification_time || verification_time < self.this_update {
            return None;
        }
        // C2PA deliberately permits an attested time before `thisUpdate` and
        // uses `producedAt` only for the no-`nextUpdate` 24-hour limit. Do not
        // impose an extra producedAt/thisUpdate/nextUpdate ordering rule.
        let covers_signing_time = if signed_at < self.this_update {
            true
        } else if signed_at > self.this_update {
            match self.next_update {
                Some(next_update) => signed_at < next_update,
                None => self
                    .produced_at
                    .checked_add(time::Duration::hours(24))
                    .is_some_and(|limit| signed_at < limit),
            }
        } else {
            false
        };
        if !covers_signing_time {
            return None;
        }
        match self.status {
            OcspStatus::Good => Some(OcspStatus::Good),
            OcspStatus::Unknown => None,
            OcspStatus::Revoked {
                reason: Some(OcspRevocationReason::RemoveFromCrl),
                ..
            } => Some(OcspStatus::Good),
            revoked @ OcspStatus::Revoked { .. } => Some(revoked),
        }
    }
}

/// Parse, verify, and evaluate every matching `SingleResponse` in a
/// DER-encoded OCSP response.
///
/// The response is accepted only when:
///
/// 1. The full `CertID` tuple identifies `subject_der` and `issuer_der`.
/// 2. The response signature is valid and its `ResponderID` identifies the
///    signer.
/// 3. The responder is the issuer, or is directly issued by it with the
///    `id-kp-OCSPSigning` EKU.
/// 4. The responder certificate is valid at `producedAt`, and `producedAt` is
///    not later than `verification_time`.
///
/// Embedded responder certificates are an unordered, bounded set. The issuer
/// certificate remains a candidate for direct issuer-signed responses even
/// when helper certificates are embedded. Matching statuses are reduced only
/// after applying the C2PA signing-time policy to each `SingleResponse`.
///
/// Returns `None` (staple ignored - treated as "no usable staple") if parsing
/// fails, authorization fails, or no matching response establishes a decisive
/// status at `signed_at`.
pub fn evaluate_verified(
    der: &[u8],
    issuer_der: &[u8],
    subject_der: &[u8],
    signed_at: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
) -> Option<OcspStatus> {
    if der.len() > MAX_OCSP_RESPONSE_BYTES {
        return None;
    }

    let mut p = Der::new(der);
    let resp = p.sequence()?;
    if !p.is_empty() {
        return None;
    }
    let mut r = Der::new(resp);
    if r.enumerated()? != 0 {
        return None;
    }
    let rb = r.tagged(0)?;
    if !r.is_empty() {
        return None;
    }
    let mut rb = Der::new(rb);
    let rb_seq = rb.sequence()?;
    if !rb.is_empty() {
        return None;
    }
    let mut rb_seq = Der::new(rb_seq);
    if rb_seq.object_identifier()? != OID_PKIX_OCSP_BASIC {
        return None;
    }
    let basic_octets = rb_seq.octet_string()?;
    if !rb_seq.is_empty() {
        return None;
    }

    let mut basic = Der::new(basic_octets);
    let basic_inner = basic.sequence()?;
    if !basic.is_empty() {
        return None;
    }
    let mut b = Der::new(basic_inner);
    let tbs_tlv = b.peek_tlv_bytes()?;
    let tbs_inner = b.sequence()?;
    let sig_alg_inner = b.sequence()?;
    let sig_alg_oid = Der::new(sig_alg_inner).object_identifier()?;
    let signature = b.bit_string()?;
    let certs_explicit = if b.peek_tag() == Some(0xa0) {
        Some(b.tagged(0)?)
    } else {
        None
    };
    if !b.is_empty() {
        return None;
    }
    let responder_certificates = bounded_responder_certificates(certs_explicit)?;

    let mut rd = Der::new(tbs_inner);
    let (responder_id, produced_at, responses) = rd.response_data()?;
    if produced_at > verification_time {
        return None;
    }

    let issuer_cert = Certificate::from_der(issuer_der).ok()?;
    if !authorized_response_signer(
        &responder_certificates,
        issuer_der,
        &issuer_cert,
        responder_id,
        produced_at,
        sig_alg_oid,
        signature,
        tbs_tlv,
    ) {
        return None;
    }

    let subject_cert = Certificate::from_der(subject_der).ok()?;
    matching_single_response_status(
        responses,
        &issuer_cert,
        &subject_cert,
        produced_at,
        signed_at,
        verification_time,
    )
}

fn bounded_responder_certificates(certs_explicit: Option<&[u8]>) -> Option<Vec<&[u8]>> {
    let Some(certs_explicit) = certs_explicit else {
        return Some(Vec::new());
    };
    let mut wrapper = Der::new(certs_explicit);
    let cert_list = wrapper.sequence()?;
    if !wrapper.is_empty() {
        return None;
    }

    let mut certificates = Vec::new();
    let mut total_bytes = 0usize;
    let mut cert_list = Der::new(cert_list);
    while !cert_list.is_empty() {
        if certificates.len() >= MAX_OCSP_RESPONDER_CERTIFICATES {
            return None;
        }
        let certificate = cert_list.peek_tlv_bytes()?;
        if certificate.len() > MAX_OCSP_RESPONDER_CERTIFICATE_BYTES {
            return None;
        }
        total_bytes = total_bytes.checked_add(certificate.len())?;
        if total_bytes > MAX_OCSP_RESPONDER_CERTIFICATE_TOTAL_BYTES {
            return None;
        }
        cert_list.sequence()?;
        certificates.push(certificate);
    }
    Some(certificates)
}

#[allow(clippy::too_many_arguments)]
fn authorized_response_signer(
    embedded_certificates: &[&[u8]],
    issuer_der: &[u8],
    issuer_cert: &Certificate,
    responder_id: ResponderId<'_>,
    produced_at: OffsetDateTime,
    signature_algorithm: ObjectIdentifier,
    signature: &[u8],
    signed_response_data: &[u8],
) -> bool {
    let issuer_spki = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok();
    for responder_der in embedded_certificates
        .iter()
        .copied()
        .chain(std::iter::once(issuer_der))
    {
        let Ok(responder_cert) = Certificate::from_der(responder_der) else {
            continue;
        };
        if !responder_id_matches(responder_id, &responder_cert)
            || !verify_message(
                &responder_cert,
                signature_algorithm,
                signature,
                signed_response_data,
            )
        {
            continue;
        }

        let responder_is_issuer = responder_der == issuer_der
            || issuer_spki.as_ref().is_some_and(|issuer_spki| {
                responder_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .ok()
                    .as_ref()
                    == Some(issuer_spki)
            });
        if valid_at(&responder_cert, produced_at)
            && (responder_is_issuer
                || (cert_signed_by(&responder_cert, issuer_cert)
                    && has_ocsp_signing_eku(&responder_cert)))
        {
            return true;
        }
    }
    false
}

fn matching_single_response_status(
    responses: &[u8],
    issuer: &Certificate,
    subject: &Certificate,
    produced_at: OffsetDateTime,
    signed_at: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
) -> Option<OcspStatus> {
    let mut preflight = Der::new(responses);
    let mut response_count = 0usize;
    while !preflight.is_empty() {
        if response_count >= MAX_OCSP_SINGLE_RESPONSES {
            return None;
        }
        preflight.sequence()?;
        response_count += 1;
    }

    let mut accumulated = None;
    let mut response_list = Der::new(responses);
    while !response_list.is_empty() {
        let single = response_list.sequence()?;
        let mut single = Der::new(single);
        let cert_id = single.sequence()?;
        if !cert_id_matches(cert_id, issuer, subject) {
            continue;
        }
        let status = single.cert_status()?;
        let this_update = single.generalized_time().ok()?;
        let next_update = if single.peek_tag() == Some(0xa0) {
            single
                .tagged(0)
                .and_then(|body| Der::new(body).generalized_time().ok())
        } else {
            None
        };
        let candidate = OcspEvaluation {
            status,
            produced_at,
            this_update,
            next_update,
        }
        .status_at_signing(signed_at, verification_time);
        accumulated = OcspStatus::merge(accumulated, candidate);
    }
    accumulated
}

fn cert_id_matches(cert_id: &[u8], issuer: &Certificate, subject: &Certificate) -> bool {
    let mut cert_id = Der::new(cert_id);
    let Some(algorithm) = cert_id.sequence() else {
        return false;
    };
    let Some(algorithm) = Der::new(algorithm).object_identifier() else {
        return false;
    };
    let (Some(name_hash), Some(key_hash), Some(serial)) = (
        cert_id.octet_string(),
        cert_id.octet_string(),
        cert_id.integer(),
    ) else {
        return false;
    };
    if !cert_id.is_empty() {
        return false;
    }
    let Ok(issuer_name) = issuer.tbs_certificate.subject.to_der() else {
        return false;
    };
    let Some(issuer_key) = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
    else {
        return false;
    };
    hash_matches(algorithm, &issuer_name, name_hash)
        && hash_matches(algorithm, issuer_key, key_hash)
        && trim_unsigned(serial) == trim_unsigned(subject.tbs_certificate.serial_number.as_bytes())
}

fn responder_id_matches(responder_id: ResponderId<'_>, responder: &Certificate) -> bool {
    match responder_id {
        ResponderId::ByName(name) => responder
            .tbs_certificate
            .subject
            .to_der()
            .is_ok_and(|subject| subject == name),
        ResponderId::ByKey(key_hash) => responder
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .is_some_and(|key| sha1_digest(key).as_slice() == key_hash),
    }
}

fn hash_matches(algorithm: ObjectIdentifier, input: &[u8], expected: &[u8]) -> bool {
    match algorithm {
        OID_SHA1 => sha1_digest(input).as_slice() == expected,
        OID_SHA256 => &Sha256::digest(input)[..] == expected,
        OID_SHA384 => &Sha384::digest(input)[..] == expected,
        OID_SHA512 => &Sha512::digest(input)[..] == expected,
        _ => false,
    }
}

fn trim_unsigned(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    bytes
}

fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let blocks = input.len().saturating_add(72) / 64;
    for block_index in 0..blocks {
        let mut block = [0u8; 64];
        for (offset, byte) in block.iter_mut().enumerate() {
            let index = block_index * 64 + offset;
            *byte = if index < input.len() {
                input[index]
            } else if index == input.len() {
                0x80
            } else if index >= blocks * 64 - 8 {
                bit_len.to_be_bytes()[index - (blocks * 64 - 8)]
            } else {
                0
            };
        }
        let mut schedule = [0u32; 80];
        for (word, bytes) in schedule[..16].iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-1 word"));
        }
        for index in 16..80 {
            schedule[index] = (schedule[index - 3]
                ^ schedule[index - 8]
                ^ schedule[index - 14]
                ^ schedule[index - 16])
                .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in schedule.into_iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
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

#[derive(Clone, Copy)]
enum ResponderId<'a> {
    ByName(&'a [u8]),
    ByKey(&'a [u8]),
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

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
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
        let (tag, body) = self.tlv()?;
        match tag {
            0x80 if body.is_empty() => Some(OcspStatus::Good),
            0xa1 => {
                let mut revoked = Der::new(body);
                let revocation_time = revoked.generalized_time().ok()?;
                let reason = if revoked.peek_tag() == Some(0xa0) {
                    let mut encoded_reason = Der::new(revoked.tagged(0)?);
                    let reason = OcspRevocationReason::from_code(encoded_reason.enumerated()?);
                    if !encoded_reason.is_empty() {
                        return None;
                    }
                    Some(reason)
                } else {
                    None
                };
                if !revoked.is_empty() {
                    return None;
                }
                Some(OcspStatus::Revoked {
                    revocation_time,
                    reason,
                })
            }
            0x82 if body.is_empty() => Some(OcspStatus::Unknown),
            _ => None,
        }
    }

    /// Decode the signed responder identity, `producedAt`, and responses.
    fn response_data(&mut self) -> Option<(ResponderId<'a>, OffsetDateTime, &'a [u8])> {
        if self.peek_tag() == Some(0xa0) {
            self.tagged(0)?; // version
        }
        let (tag, body) = self.tlv()?;
        let responder_id = match tag {
            0xa1 => {
                let mut explicit = Der::new(body);
                let name = explicit.peek_tlv_bytes()?;
                explicit.sequence()?;
                if !explicit.is_empty() {
                    return None;
                }
                ResponderId::ByName(name)
            }
            0xa2 => {
                let mut explicit = Der::new(body);
                let key_hash = explicit.octet_string()?;
                if !explicit.is_empty() {
                    return None;
                }
                ResponderId::ByKey(key_hash)
            }
            _ => return None,
        };
        let produced_at = self.generalized_time().ok()?;
        let responses = self.sequence()?;
        Some((responder_id, produced_at, responses))
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

/// Parse the exact GeneralizedTime form supported by this verifier.
fn parse_generalized_time(body: &[u8]) -> Option<OffsetDateTime> {
    if body.len() != 15 || body[14] != b'Z' || !body[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let s = std::str::from_utf8(body).ok()?;
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
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    use time::macros::datetime;

    const AT: OffsetDateTime = datetime!(2026-06-01 0:00 UTC);
    const SIGNED_AT: OffsetDateTime = datetime!(2026-02-01 0:00 UTC);

    fn evaluate_verified(
        der: &[u8],
        issuer_der: &[u8],
        subject_der: &[u8],
        verification_time: OffsetDateTime,
    ) -> Option<OcspStatus> {
        super::evaluate_verified(
            der,
            issuer_der,
            subject_der,
            Some(SIGNED_AT),
            verification_time,
        )
    }

    fn at(value: &[u8]) -> OffsetDateTime {
        parse_generalized_time(value).expect("test time")
    }

    fn evaluation(status: OcspStatus) -> OcspEvaluation {
        OcspEvaluation {
            status,
            produced_at: at(b"20260102000000Z"),
            this_update: at(b"20260101000000Z"),
            next_update: Some(at(b"20270101000000Z")),
        }
    }

    #[test]
    fn generalized_time_parser_accepts_only_exact_supported_form() {
        let parsed = parse_generalized_time(b"20130601120000Z").expect("valid time");
        assert_eq!(parsed, datetime!(2013-06-01 12:00 UTC));
        assert!(parse_generalized_time(b"20130601120000JUNKZ").is_none());
        assert!(parse_generalized_time(b"20130601120000.1Z").is_none());
        assert!(parse_generalized_time(b"20130601120000").is_none());
    }

    #[test]
    fn sha1_matches_known_vector() {
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn embedded_policy_accepts_pre_this_update_and_open_freshness_window() {
        let response = evaluation(OcspStatus::Good);
        assert_eq!(
            response.status_at_signing(Some(at(b"20251231000000Z")), AT),
            Some(OcspStatus::Good)
        );
        assert_eq!(
            response.status_at_signing(Some(at(b"20260601000000Z")), AT),
            Some(OcspStatus::Good)
        );
        assert_eq!(
            response.status_at_signing(Some(at(b"20260101000000Z")), AT),
            None
        );
        assert_eq!(
            response.status_at_signing(Some(at(b"20270101000000Z")), AT),
            None
        );
        let mut status_from_future = response.clone();
        status_from_future.produced_at = at(b"20251230000000Z");
        assert_eq!(
            status_from_future
                .status_at_signing(Some(at(b"20251229000000Z")), at(b"20251231000000Z")),
            None
        );
        assert_eq!(response.status_at_signing(None, AT), None);
    }

    #[test]
    fn missing_next_update_uses_open_produced_at_plus_twenty_four_hour_window() {
        let mut response = evaluation(OcspStatus::Good);
        response.next_update = None;
        assert_eq!(
            response.status_at_signing(Some(at(b"20260102235959Z")), AT),
            Some(OcspStatus::Good)
        );
        assert_eq!(
            response.status_at_signing(Some(at(b"20260103000000Z")), AT),
            None
        );
    }

    #[test]
    fn future_response_cannot_establish_status() {
        let mut response = evaluation(OcspStatus::Good);
        response.produced_at = at(b"20270101000000Z");
        assert_eq!(
            response.status_at_signing(Some(at(b"20260601000000Z")), AT),
            None
        );
    }

    #[test]
    fn revoked_info_parses_time_and_reason() {
        let encoded = revoked_status(b"20260301000000Z", Some(8));
        let parsed = Der::new(&encoded).cert_status().expect("revoked info");
        assert_eq!(
            parsed,
            OcspStatus::Revoked {
                revocation_time: at(b"20260301000000Z"),
                reason: Some(OcspRevocationReason::RemoveFromCrl),
            }
        );
    }

    #[test]
    fn embedded_policy_keeps_post_signing_key_compromise_revoked() {
        let revoked = OcspStatus::Revoked {
            revocation_time: at(b"20260301000000Z"),
            reason: Some(OcspRevocationReason::KeyCompromise),
        };
        let response = evaluation(revoked);

        assert_eq!(
            response.status_at_signing(Some(at(b"20260201000000Z")), AT),
            Some(revoked)
        );
    }

    #[test]
    fn embedded_policy_treats_remove_from_crl_as_good() {
        let response = evaluation(OcspStatus::Revoked {
            revocation_time: at(b"20260115000000Z"),
            reason: Some(OcspRevocationReason::RemoveFromCrl),
        });

        assert_eq!(
            response.status_at_signing(Some(at(b"20260201000000Z")), AT),
            Some(OcspStatus::Good)
        );
    }

    #[test]
    fn remove_from_crl_and_good_merge_to_good_in_either_order() {
        let remove_from_crl = OcspStatus::Revoked {
            revocation_time: at(b"20260115000000Z"),
            reason: Some(OcspRevocationReason::RemoveFromCrl),
        };
        for statuses in [
            [Some(remove_from_crl), Some(OcspStatus::Good)],
            [Some(OcspStatus::Good), Some(remove_from_crl)],
        ] {
            assert_eq!(
                statuses.into_iter().fold(None, OcspStatus::merge),
                Some(OcspStatus::Good)
            );
        }
    }

    #[test]
    fn revocation_at_or_before_signing_is_revoked_only_after_freshness() {
        let revoked = OcspStatus::Revoked {
            revocation_time: at(b"20260201000000Z"),
            reason: Some(OcspRevocationReason::KeyCompromise),
        };
        let response = evaluation(revoked);
        assert_eq!(
            response.status_at_signing(Some(at(b"20260201000000Z")), AT),
            Some(revoked)
        );
        assert_eq!(
            response.status_at_signing(Some(at(b"20280101000000Z")), AT),
            None
        );
    }

    #[test]
    fn verified_evaluator_rejects_non_ocsp_bytes() {
        assert!(evaluate_verified(&[0x00, 0x01, 0x02], &[], &[], AT).is_none());
        assert!(evaluate_verified(b"not der at all", &[], &[], AT).is_none());
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else {
            let mut bytes = Vec::new();
            let mut remaining = len;
            while remaining > 0 {
                bytes.push((remaining & 0xff) as u8);
                remaining >>= 8;
            }
            bytes.reverse();
            let mut encoded = vec![0x80 | bytes.len() as u8];
            encoded.extend(bytes);
            encoded
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(2 + content.len());
        encoded.push(tag);
        encoded.extend(der_len(content.len()));
        encoded.extend_from_slice(content);
        encoded
    }

    fn revoked_status(revocation_time: &[u8], reason: Option<u8>) -> Vec<u8> {
        let mut body = tlv(0x18, revocation_time);
        if let Some(reason) = reason {
            body.extend(tlv(0xa0, &tlv(0x0a, &[reason])));
        }
        tlv(0xa1, &body)
    }

    #[derive(Clone, Copy)]
    enum CertIdMutation {
        None,
        HashAlgorithm,
        NameHash,
        KeyHash,
        Serial,
    }

    fn cert_id(issuer_der: &[u8], subject_der: &[u8], mutation: CertIdMutation) -> Vec<u8> {
        let issuer = Certificate::from_der(issuer_der).expect("issuer certificate");
        let subject = Certificate::from_der(subject_der).expect("subject certificate");
        let issuer_name = issuer
            .tbs_certificate
            .subject
            .to_der()
            .expect("issuer name");
        let issuer_key = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .expect("issuer key");
        let mut name_hash = sha1_digest(&issuer_name);
        let mut key_hash = sha1_digest(issuer_key);
        let mut serial = subject.tbs_certificate.serial_number.as_bytes().to_vec();
        let algorithm = if matches!(mutation, CertIdMutation::HashAlgorithm) {
            OID_SHA256
        } else {
            OID_SHA1
        };
        match mutation {
            CertIdMutation::NameHash => name_hash[0] ^= 0xff,
            CertIdMutation::KeyHash => key_hash[0] ^= 0xff,
            CertIdMutation::Serial => serial[0] ^= 0xff,
            CertIdMutation::None | CertIdMutation::HashAlgorithm => {}
        }
        let mut body = tlv(0x30, &algorithm.to_der().expect("hash algorithm"));
        body.extend(tlv(0x04, &name_hash));
        body.extend(tlv(0x04, &key_hash));
        body.extend(tlv(0x02, &serial));
        tlv(0x30, &body)
    }

    fn responder_id(responder_der: &[u8], matches_signer: bool) -> Vec<u8> {
        let responder = Certificate::from_der(responder_der).expect("responder certificate");
        let responder_key = responder
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .expect("responder key");
        let mut key_hash = sha1_digest(responder_key);
        if !matches_signer {
            key_hash[0] ^= 0xff;
        }
        tlv(0xa2, &tlv(0x04, &key_hash))
    }

    fn build_tbs(
        issuer_der: &[u8],
        subject_der: &[u8],
        responder_der: &[u8],
        produced_at: &[u8],
        mutation: CertIdMutation,
        responder_id_matches: bool,
    ) -> Vec<u8> {
        build_tbs_with_response_count(
            issuer_der,
            subject_der,
            responder_der,
            produced_at,
            mutation,
            responder_id_matches,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tbs_with_response_count(
        issuer_der: &[u8],
        subject_der: &[u8],
        responder_der: &[u8],
        produced_at: &[u8],
        mutation: CertIdMutation,
        responder_id_matches: bool,
        response_count: usize,
    ) -> Vec<u8> {
        let statuses = vec![tlv(0x80, &[]); response_count];
        build_tbs_with_statuses(
            issuer_der,
            subject_der,
            responder_der,
            produced_at,
            mutation,
            responder_id_matches,
            &statuses,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tbs_with_statuses(
        issuer_der: &[u8],
        subject_der: &[u8],
        responder_der: &[u8],
        produced_at: &[u8],
        mutation: CertIdMutation,
        responder_id_matches: bool,
        statuses: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut response_entries = Vec::new();
        for status in statuses {
            let mut single = cert_id(issuer_der, subject_der, mutation);
            single.extend_from_slice(status);
            single.extend(tlv(0x18, b"20260101000000Z"));
            single.extend(tlv(0xa0, &tlv(0x18, b"20270101000000Z")));
            response_entries.extend(tlv(0x30, &single));
        }
        let responses = tlv(0x30, &response_entries);

        let mut response_data = responder_id(responder_der, responder_id_matches);
        response_data.extend(tlv(0x18, produced_at));
        response_data.extend(responses);
        tlv(0x30, &response_data)
    }

    fn sign_p256(key: &KeyPair, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;
        let key =
            SigningKey::from_pkcs8_der(&key.serialize_der()).expect("load responder private key");
        let signature: Signature = key.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    fn assemble(tbs: &[u8], signature: &[u8], responder_der: Option<&[u8]>) -> Vec<u8> {
        match responder_der {
            Some(responder_der) => assemble_with_certificates(tbs, signature, &[responder_der]),
            None => assemble_with_certificates(tbs, signature, &[]),
        }
    }

    fn assemble_with_certificates(tbs: &[u8], signature: &[u8], certificates: &[&[u8]]) -> Vec<u8> {
        let signature_algorithm = tlv(0x30, &OID_ECDSA_SHA256.to_der().expect("signature OID"));
        let mut signature_bits = vec![0x00];
        signature_bits.extend_from_slice(signature);
        let mut basic = tbs.to_vec();
        basic.extend(signature_algorithm);
        basic.extend(tlv(0x03, &signature_bits));
        if !certificates.is_empty() {
            let certificate_bytes = certificates.concat();
            basic.extend(tlv(0xa0, &tlv(0x30, &certificate_bytes)));
        }
        let basic = tlv(0x30, &basic);
        let mut response_bytes = OID_PKIX_OCSP_BASIC.to_der().expect("basic OCSP OID");
        response_bytes.extend(tlv(0x04, &basic));
        let response_bytes = tlv(0xa0, &tlv(0x30, &response_bytes));
        let mut response = tlv(0x0a, &[0x00]);
        response.extend(response_bytes);
        tlv(0x30, &response)
    }

    fn make_ca(common_name: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::new(vec!["ca.example".to_string()]).expect("CA params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2040-01-01 0:00 UTC);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = params.self_signed(&key).expect("self-signed CA");
        (certificate, key)
    }

    fn make_responder(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
        with_eku: bool,
    ) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("responder key");
        let mut params = CertificateParams::new(vec!["responder.example".to_string()])
            .expect("responder params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "OCSP Responder");
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = IsCa::NoCa;
        if with_eku {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        }
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("issued responder");
        (certificate, key)
    }

    fn delegated_response(
        issuer_der: &[u8],
        subject_der: &[u8],
        responder_der: &[u8],
        responder_key: &KeyPair,
        produced_at: &[u8],
        mutation: CertIdMutation,
        responder_id_matches: bool,
    ) -> Vec<u8> {
        let tbs = build_tbs(
            issuer_der,
            subject_der,
            responder_der,
            produced_at,
            mutation,
            responder_id_matches,
        );
        let signature = sign_p256(responder_key, &tbs);
        assemble(&tbs, &signature, Some(responder_der))
    }

    #[test]
    fn verified_accepts_full_cert_id_and_authorized_delegated_responder() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let response = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        assert_eq!(
            evaluate_verified(&response, &issuer_der, &responder_der, AT)
                .expect("authorized response"),
            OcspStatus::Good
        );
    }

    #[test]
    fn contradictory_matching_single_responses_are_order_independent() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let good = tlv(0x80, &[]);
        let revoked = revoked_status(b"20260115000000Z", Some(1));

        for statuses in [vec![good.clone(), revoked.clone()], vec![revoked, good]] {
            let tbs = build_tbs_with_statuses(
                &issuer_der,
                &responder_der,
                &responder_der,
                b"20260101000000Z",
                CertIdMutation::None,
                true,
                &statuses,
            );
            let signature = sign_p256(&responder_key, &tbs);
            let response = assemble(&tbs, &signature, Some(&responder_der));
            assert!(matches!(
                evaluate_verified(&response, &issuer_der, &responder_der, AT),
                Some(OcspStatus::Revoked { .. })
            ));
        }
    }

    #[test]
    fn verified_rejects_non_basic_ocsp_response_type() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let mut response = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        let basic_oid = OID_PKIX_OCSP_BASIC.to_der().expect("basic OCSP OID");
        let wrong_oid = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2")
            .to_der()
            .expect("wrong response OID");
        assert_eq!(basic_oid.len(), wrong_oid.len());
        let oid_offset = response
            .windows(basic_oid.len())
            .position(|window| window == basic_oid.as_slice())
            .expect("responseType OID");
        response[oid_offset..oid_offset + basic_oid.len()].copy_from_slice(&wrong_oid);

        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
    }

    #[test]
    fn verified_selects_responder_anywhere_in_bounded_certificate_list() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let tbs = build_tbs(
            &issuer_der,
            &responder_der,
            &responder_der,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        let signature = sign_p256(&responder_key, &tbs);
        let mut certificates = vec![issuer_der.as_slice(); MAX_OCSP_RESPONDER_CERTIFICATES - 1];
        certificates.push(responder_der.as_slice());
        let response = assemble_with_certificates(&tbs, &signature, &certificates);
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_some());

        certificates.push(issuer_der.as_slice());
        let over_limit = assemble_with_certificates(&tbs, &signature, &certificates);
        assert!(evaluate_verified(&over_limit, &issuer_der, &responder_der, AT).is_none());
    }

    #[test]
    fn verified_rejects_response_and_responder_certificate_byte_limits() {
        let oversized_response = vec![0; MAX_OCSP_RESPONSE_BYTES + 1];
        assert!(evaluate_verified(&oversized_response, &[], &[], AT).is_none());

        let oversized_certificate = tlv(0x30, &vec![0; MAX_OCSP_RESPONDER_CERTIFICATE_BYTES]);
        let certs = tlv(0x30, &oversized_certificate);
        assert!(bounded_responder_certificates(Some(&certs)).is_none());

        let certificate = tlv(
            0x30,
            &vec![0; MAX_OCSP_RESPONDER_CERTIFICATE_TOTAL_BYTES / 5],
        );
        assert!(certificate.len() <= MAX_OCSP_RESPONDER_CERTIFICATE_BYTES);
        let certificates = certificate.repeat(5);
        let certs = tlv(0x30, &certificates);
        assert!(bounded_responder_certificates(Some(&certs)).is_none());
    }

    #[test]
    fn verified_bounds_single_response_scan_before_accepting_status() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let at_limit = build_tbs_with_response_count(
            &issuer_der,
            &responder_der,
            &responder_der,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
            MAX_OCSP_SINGLE_RESPONSES,
        );
        let signature = sign_p256(&responder_key, &at_limit);
        let response = assemble(&at_limit, &signature, Some(&responder_der));
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_some());

        let over_limit = build_tbs_with_response_count(
            &issuer_der,
            &responder_der,
            &responder_der,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
            MAX_OCSP_SINGLE_RESPONSES + 1,
        );
        let signature = sign_p256(&responder_key, &over_limit);
        let response = assemble(&over_limit, &signature, Some(&responder_der));
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
    }

    #[test]
    fn verified_rejects_every_wrong_cert_id_field() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        for mutation in [
            CertIdMutation::HashAlgorithm,
            CertIdMutation::NameHash,
            CertIdMutation::KeyHash,
            CertIdMutation::Serial,
        ] {
            let response = delegated_response(
                &issuer_der,
                &responder_der,
                &responder_der,
                &responder_key,
                b"20260101000000Z",
                mutation,
                true,
            );
            assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
        }
    }

    #[test]
    fn verified_rejects_responder_id_mismatch() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let response = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20260101000000Z",
            CertIdMutation::None,
            false,
        );
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
    }

    #[test]
    fn verified_rejects_bad_signature() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let tbs = build_tbs(
            &issuer_der,
            &responder_der,
            &responder_der,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        let mut signature = sign_p256(&responder_key, &tbs);
        let last = signature.len() - 1;
        signature[last] ^= 0xff;
        let response = assemble(&tbs, &signature, Some(&responder_der));
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
    }

    #[test]
    fn verified_rejects_delegated_responder_without_eku_or_correct_issuer() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (subject, _) = make_responder(&issuer, &issuer_key, true);
        let subject_der = subject.der().as_ref().to_vec();

        let (without_eku, without_eku_key) = make_responder(&issuer, &issuer_key, false);
        let without_eku_der = without_eku.der().as_ref().to_vec();
        let response = delegated_response(
            &issuer_der,
            &subject_der,
            &without_eku_der,
            &without_eku_key,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        assert!(evaluate_verified(&response, &issuer_der, &subject_der, AT).is_none());

        let (rogue_ca, rogue_ca_key) = make_ca("Rogue CA");
        let (rogue, rogue_key) = make_responder(&rogue_ca, &rogue_ca_key, true);
        let rogue_der = rogue.der().as_ref().to_vec();
        let response = delegated_response(
            &issuer_der,
            &subject_der,
            &rogue_der,
            &rogue_key,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        assert!(evaluate_verified(&response, &issuer_der, &subject_der, AT).is_none());
    }

    #[test]
    fn verified_accepts_direct_issuer_signed_response() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (subject, _) = make_responder(&issuer, &issuer_key, true);
        let subject_der = subject.der().as_ref().to_vec();
        let tbs = build_tbs(
            &issuer_der,
            &subject_der,
            &issuer_der,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        let signature = sign_p256(&issuer_key, &tbs);
        let response = assemble(&tbs, &signature, None);
        assert_eq!(
            evaluate_verified(&response, &issuer_der, &subject_der, AT)
                .expect("issuer-signed response"),
            OcspStatus::Good
        );
    }

    #[test]
    fn responder_authorization_is_checked_at_produced_at() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();

        let historical = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20260101000000Z",
            CertIdMutation::None,
            true,
        );
        assert!(evaluate_verified(
            &historical,
            &issuer_der,
            &responder_der,
            datetime!(2035-01-01 0:00 UTC)
        )
        .is_some());

        let post_expiry = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20310101000000Z",
            CertIdMutation::None,
            true,
        );
        assert!(evaluate_verified(
            &post_expiry,
            &issuer_der,
            &responder_der,
            datetime!(2035-01-01 0:00 UTC)
        )
        .is_none());
    }

    #[test]
    fn verified_rejects_response_produced_in_the_future() {
        let (issuer, issuer_key) = make_ca("Test Issuer");
        let issuer_der = issuer.der().as_ref().to_vec();
        let (responder, responder_key) = make_responder(&issuer, &issuer_key, true);
        let responder_der = responder.der().as_ref().to_vec();
        let response = delegated_response(
            &issuer_der,
            &responder_der,
            &responder_der,
            &responder_key,
            b"20270101000000Z",
            CertIdMutation::None,
            true,
        );
        assert!(evaluate_verified(&response, &issuer_der, &responder_der, AT).is_none());
    }
}
