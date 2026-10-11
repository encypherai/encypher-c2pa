// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE_Sign1 verification and header extraction.
//!
//! Verification reconstructs the detached RFC 9052 `Sig_structure` from the
//! protected header and supplied claim bytes. Header readers accept the
//! standard integer labels and legacy text labels found in deployed assets.

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use der::{Decode, Encode};
use spki::DecodePublicKey;

use crate::c2pa_crypto::alg::CoseAlg;
use crate::c2pa_crypto::error::CryptoError;
use crate::c2pa_crypto::mldsa::{ml_dsa_public_key_from_spki, verify_ml_dsa};

/// CBOR tag for a `COSE_Sign1_Tagged` structure (RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;
/// COSE protected-header key for the algorithm.
const COSE_HDR_ALG: i128 = 1;
/// RFC 9052 integer label for an x5chain certificate chain.
const COSE_HDR_X5CHAIN: i128 = 33;
/// Maximum certificates accepted from a COSE x5chain.
const MAX_X5CHAIN_CERTIFICATES: usize = 20;
/// Maximum DER bytes accepted for one x5chain certificate.
const MAX_X5CHAIN_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum aggregate DER bytes accepted for one x5chain.
const MAX_X5CHAIN_TOTAL_BYTES: usize = 512 * 1024;

/// CBOR profile used for all COSE substructures (matches Python `cbor2.dumps`).
const PROFILE: Profile = Profile::LegacyPipelineBDefinite;

/// Build the `Sig_structure` bytes that are fed to the signature algorithm.
fn sig_structure_bytes(protected_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    Ok(encode(&sig_structure, PROFILE)?)
}

/// Borrow the four-element array inside a `COSE_Sign1_Tagged` value.
fn cose_array(value: &Value) -> Result<&[Value], CryptoError> {
    match value {
        Value::Tag(COSE_SIGN1_TAG, inner) => match inner.as_ref() {
            Value::Array(items) if items.len() == 4 => Ok(items),
            _ => Err(CryptoError::Malformed(
                "tag 18 content is not a 4-element array".into(),
            )),
        },
        _ => Err(CryptoError::Malformed(
            "not a COSE_Sign1_Tagged (tag 18) structure".into(),
        )),
    }
}

/// Find a value in a CBOR map by integer key.
fn map_get_int(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(n) if *n == key))
        .map(|(_, v)| v)
}

/// Find a value in a CBOR map by text key.
fn map_get_text<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Verify a `COSE_Sign1_Tagged` signature over `claim_cbor` using the public
/// key from the supplied end-entity certificate (DER).
///
/// C2PA signs claims in detached content mode, so the `payload` field of the
/// `COSE_Sign1_Tagged` structure must be `nil` and the `Sig_structure` payload
/// is reconstructed from `claim_cbor`. A signature that carries any payload —
/// including an empty byte string — is rejected rather than silently verified
/// against the external claim bytes.
///
/// Returns `Ok(())` only when the signature is valid; any structural problem,
/// unsupported algorithm, or signature mismatch yields an error.
pub fn verify_claim(
    cose_sign1: &[u8],
    claim_cbor: &[u8],
    cert_der: &[u8],
) -> Result<(), CryptoError> {
    verify_claim_with(cose_sign1, claim_cbor, cert_der, ClaimAlgorithmList::V2_4)
}

/// Which revision's claim-signature algorithm list governs a verification.
///
/// C2PA 2.2 and 2.4 list ES256/384/512, PS256/384/512 and EdDSA
/// (Ed25519). C2PA 2.5 adds the fully specified ECDSA identifiers ESP256
/// (`-9`), ESP384 (`-51`) and ESP512 (`-52`) from RFC 9864, each bound to one
/// curve, and ML-DSA-44/65/87 (`-48`/`-49`/`-50`) from RFC 9964.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimAlgorithmList {
    /// The C2PA 2.2 list.
    V2_2,
    /// The C2PA 2.4 list.
    V2_4,
    /// The C2PA 2.5 list.
    V2_5,
}

impl ClaimAlgorithmList {
    /// Whether `alg` is on this revision's allowed list. Both deprecated
    /// lists are empty, so allowed is the whole of what a validator accepts.
    pub fn permits(self, alg: CoseAlg) -> bool {
        match self {
            ClaimAlgorithmList::V2_2 | ClaimAlgorithmList::V2_4 => !alg.introduced_in_c2pa_2_5(),
            ClaimAlgorithmList::V2_5 => true,
        }
    }

    /// The listed algorithm for a protected-header `alg` value, or
    /// [`CryptoError::UnsupportedAlg`] when the value is unknown or not on
    /// this list.
    pub fn algorithm(self, alg_id: i128) -> Result<CoseAlg, CryptoError> {
        CoseAlg::from_cose_id(alg_id)
            .filter(|alg| self.permits(*alg))
            .ok_or(CryptoError::UnsupportedAlg(alg_id))
    }
}

/// [`verify_claim`] under an explicit revision's algorithm list.
///
/// An algorithm outside `list` is [`CryptoError::UnsupportedAlg`] and is
/// never evaluated. Under [`ClaimAlgorithmList::V2_5`] an ESP identifier
/// requires the curve RFC 9864 binds to it and a fixed-width `r || s`
/// signature, and an ML-DSA identifier requires a certificate key of the same
/// parameter set (C2PA 2.5 Cryptography, Signature Algorithms).
pub fn verify_claim_with(
    cose_sign1: &[u8],
    claim_cbor: &[u8],
    cert_der: &[u8],
    list: ClaimAlgorithmList,
) -> Result<(), CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;

    if !matches!(array[2], Value::Null) {
        return Err(CryptoError::PayloadNotDetached);
    }
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("signature is not a byte string".into()))?;

    let alg = list.algorithm(protected_alg_id(protected_bytes)?)?;
    let sig_input = sig_structure_bytes(protected_bytes, claim_cbor)?;
    verify_signature(alg, &sig_input, signature, cert_der)
}

/// The integer `alg` (label 1) of a serialized protected header map.
fn protected_alg_id(protected_bytes: &[u8]) -> Result<i128, CryptoError> {
    let protected = decode(protected_bytes)?;
    match &protected {
        Value::Map(entries) => map_get_int(entries, COSE_HDR_ALG).and_then(|value| match value {
            Value::Integer(id) => Some(*id),
            _ => None,
        }),
        _ => None,
    }
    .ok_or_else(|| CryptoError::Malformed("missing algorithm in protected header".into()))
}

/// Return the protected COSE algorithm from a `COSE_Sign1_Tagged` value.
///
/// This names any algorithm this crate knows, for reporting. Whether the
/// algorithm is acceptable is decided by [`ClaimAlgorithmList`] at
/// verification time.
pub fn extract_cose_alg(cose_sign1: &[u8]) -> Result<CoseAlg, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let alg_id = protected_alg_id(protected_bytes)?;
    CoseAlg::from_cose_id(alg_id).ok_or(CryptoError::UnsupportedAlg(alg_id))
}

/// DER-encoded `SubjectPublicKeyInfo` of the certificate's public key.
fn leaf_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| CryptoError::CertParse(format!("DER certificate parse failed: {e}")))?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| CryptoError::CertParse(format!("SPKI re-encode failed: {e}")))
}

/// Parse an RSA public key from an SPKI that uses either the `rsaEncryption`
/// (1.2.840.113549.1.1.1) or the `id-RSASSA-PSS` (1.2.840.113549.1.1.10)
/// AlgorithmIdentifier.
///
/// 1.x-era C2PA certificates (the in-the-wild legacy corpus, e.g. the
/// c2pa-rs `C.jpg` family) carry id-RSASSA-PSS SPKIs; RustCrypto's
/// `from_public_key_der` only accepts rsaEncryption. The BIT STRING payload
/// is the same PKCS#1 `RSAPublicKey` in both forms, so for the PSS form we
/// unwrap it directly. The COSE `alg` header still pins the digest.
fn rsa_public_key_from_spki(
    spki_der: &[u8],
    cose_alg: CoseAlg,
) -> Result<rsa::RsaPublicKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::traits::PublicKeyParts as _;

    const ID_RSASSA_PSS: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    const ID_MGF1: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
    const ID_SHA256: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    const ID_SHA384: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    const ID_SHA512: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    let info = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| CryptoError::CertParse(format!("SPKI parse failed: {e}")))?;
    let public_key = if let Ok(public_key) = rsa::RsaPublicKey::from_public_key_der(spki_der) {
        public_key
    } else {
        if info.algorithm.oid != ID_RSASSA_PSS {
            return Err(CryptoError::CertParse(format!(
                "unsupported RSA SPKI algorithm: {}",
                info.algorithm.oid
            )));
        }
        let raw = info.subject_public_key.as_bytes().ok_or_else(|| {
            CryptoError::CertParse("RSASSA-PSS SPKI bit string has unused bits".into())
        })?;
        rsa::RsaPublicKey::from_pkcs1_der(raw).map_err(|e| {
            CryptoError::CertParse(format!("PKCS#1 RSA public key parse failed: {e}"))
        })?
    };
    if public_key.n().bits() < 2048 {
        return Err(CryptoError::CertParse(
            "RSA public key modulus is smaller than 2048 bits".into(),
        ));
    }

    if info.algorithm.oid == ID_RSASSA_PSS {
        let (expected_hash, expected_salt_len) = match cose_alg {
            CoseAlg::Ps256 => (ID_SHA256, 32),
            CoseAlg::Ps384 => (ID_SHA384, 48),
            CoseAlg::Ps512 => (ID_SHA512, 64),
            _ => {
                return Err(CryptoError::CertParse(
                    "RSASSA-PSS key used with a non-PSS COSE algorithm".into(),
                ))
            }
        };
        if let Some(raw_parameters) = info.algorithm.parameters.as_ref() {
            let parameters_der = raw_parameters.to_der().map_err(|e| {
                CryptoError::CertParse(format!("PSS parameters encode failed: {e}"))
            })?;
            let parameters = rsa::pkcs1::RsaPssParams::try_from(parameters_der.as_slice())
                .map_err(|e| CryptoError::CertParse(format!("PSS parameters parse failed: {e}")))?;
            let mask_hash =
                parameters.mask_gen.parameters.as_ref().ok_or_else(|| {
                    CryptoError::CertParse("PSS MGF1 parameters are missing".into())
                })?;
            if parameters.hash.oid != expected_hash
                || parameters.mask_gen.oid != ID_MGF1
                || mask_hash.oid != expected_hash
                || parameters.salt_len as usize != expected_salt_len
                || parameters.trailer_field != Default::default()
            {
                return Err(CryptoError::CertParse(
                    "COSE algorithm violates RSASSA-PSS SPKI constraints".into(),
                ));
            }
        }
    }
    Ok(public_key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    fn name(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
            EcCurve::P384 => "P-384",
            EcCurve::P521 => "P-521",
        }
    }
}

fn ec_curve_from_spki(spki_der: &[u8]) -> Result<EcCurve, CryptoError> {
    const ID_EC_PUBLIC_KEY: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const P256: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const P384: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.34");
    const P521: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.132.0.35");

    let info = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| CryptoError::CertParse(format!("SPKI parse failed: {e}")))?;
    if info.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(CryptoError::CertParse(
            "certificate public key is not EC".into(),
        ));
    }
    let curve = info
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<spki::ObjectIdentifier>().ok())
        .ok_or_else(|| CryptoError::CertParse("EC SPKI has no named curve".into()))?;
    match curve {
        P256 => Ok(EcCurve::P256),
        P384 => Ok(EcCurve::P384),
        P521 => Ok(EcCurve::P521),
        _ => Err(CryptoError::CertParse(format!(
            "unsupported EC curve: {curve}"
        ))),
    }
}

/// Verify `signature` over `data` against the public key in `cert_der`.
///
/// The key must be correct for `alg` (C2PA 2.5 Cryptography, Signature
/// Algorithms): ESP identifiers require their RFC 9864 curve and a
/// fixed-width `r || s` value, PS identifiers an RSA key of at least 2048
/// bits, EdDSA an Ed25519 key and ML-DSA a key of the same parameter set.
/// The ES identifiers keep their established acceptance of any permitted
/// NIST curve and of DER-encoded legacy signatures.
pub(crate) fn verify_signature(
    alg: CoseAlg,
    data: &[u8],
    signature: &[u8],
    cert_der: &[u8],
) -> Result<(), CryptoError> {
    use signature::Verifier as _;

    let spki = leaf_spki_der(cert_der)?;
    let bad = |e: signature::Error| CryptoError::Verify(e.to_string());
    let key_err = |what: &'static str| {
        move |e: spki::Error| CryptoError::CertParse(format!("{what} public key parse failed: {e}"))
    };

    match alg {
        CoseAlg::Es256 | CoseAlg::Es384 | CoseAlg::Es512 => {
            verify_ecdsa(alg, data, signature, &spki, None)
        }
        CoseAlg::Esp256 => verify_ecdsa(alg, data, signature, &spki, Some(EcCurve::P256)),
        CoseAlg::Esp384 => verify_ecdsa(alg, data, signature, &spki, Some(EcCurve::P384)),
        CoseAlg::Esp512 => verify_ecdsa(alg, data, signature, &spki, Some(EcCurve::P521)),
        CoseAlg::Ps256 => {
            let public_key = rsa_public_key_from_spki(&spki, alg)?;
            let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key);
            let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
            verifying_key.verify(data, &signature).map_err(bad)
        }
        CoseAlg::Ps384 => {
            let public_key = rsa_public_key_from_spki(&spki, alg)?;
            let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha384>::new(public_key);
            let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
            verifying_key.verify(data, &signature).map_err(bad)
        }
        CoseAlg::Ps512 => {
            let public_key = rsa_public_key_from_spki(&spki, alg)?;
            let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha512>::new(public_key);
            let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
            verifying_key.verify(data, &signature).map_err(bad)
        }
        CoseAlg::EdDsa => {
            let verifying_key = ed25519_dalek::VerifyingKey::from_public_key_der(&spki)
                .map_err(key_err("Ed25519"))?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(bad)?;
            verifying_key.verify(data, &signature).map_err(bad)
        }
        CoseAlg::MlDsa44 | CoseAlg::MlDsa65 | CoseAlg::MlDsa87 => {
            let (key_alg, public_key) = ml_dsa_public_key_from_spki(&spki)?;
            if key_alg != alg {
                return Err(CryptoError::Verify(format!(
                    "{} requires an {} key, found {}",
                    alg.iana_name(),
                    alg.iana_name(),
                    key_alg.iana_name()
                )));
            }
            verify_ml_dsa(alg, public_key, data, signature)
        }
    }
}

/// ECDSA over the leaf's NIST curve with the digest `alg` names.
///
/// `required_curve` is the RFC 9864 curve of an ESP identifier. Fully
/// specified identifiers accept only the COSE fixed-width `r || s` encoding;
/// the ES identifiers also accept the DER form legacy assets carry.
fn verify_ecdsa(
    alg: CoseAlg,
    data: &[u8],
    signature: &[u8],
    spki: &[u8],
    required_curve: Option<EcCurve>,
) -> Result<(), CryptoError> {
    use sha2::Digest as _;
    use signature::hazmat::PrehashVerifier as _;

    let bad = |e: signature::Error| CryptoError::Verify(e.to_string());
    let key_err = |what: &'static str| {
        move |e: spki::Error| CryptoError::CertParse(format!("{what} public key parse failed: {e}"))
    };
    let mut digest = [0_u8; 64];
    let digest_len = match alg {
        CoseAlg::Es256 | CoseAlg::Esp256 => {
            digest[..32].copy_from_slice(&sha2::Sha256::digest(data));
            32
        }
        CoseAlg::Es384 | CoseAlg::Esp384 => {
            digest[..48].copy_from_slice(&sha2::Sha384::digest(data));
            48
        }
        CoseAlg::Es512 | CoseAlg::Esp512 => {
            digest.copy_from_slice(&sha2::Sha512::digest(data));
            64
        }
        _ => return Err(CryptoError::UnsupportedAlg(alg.cose_id())),
    };
    let digest = &digest[..digest_len];
    let curve = ec_curve_from_spki(spki)?;
    if let Some(required) = required_curve.filter(|required| *required != curve) {
        return Err(CryptoError::Verify(format!(
            "{} requires a {} key, found {}",
            alg.iana_name(),
            required.name(),
            curve.name()
        )));
    }
    let legacy_der = required_curve.is_none();
    match curve {
        EcCurve::P256 => {
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_public_key_der(spki).map_err(key_err("P-256"))?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .or_else(|e| {
                    if legacy_der {
                        p256::ecdsa::Signature::from_der(signature)
                    } else {
                        Err(e)
                    }
                })
                .map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
        EcCurve::P384 => {
            let verifying_key =
                p384::ecdsa::VerifyingKey::from_public_key_der(spki).map_err(key_err("P-384"))?;
            let signature = p384::ecdsa::Signature::from_slice(signature)
                .or_else(|e| {
                    if legacy_der {
                        p384::ecdsa::Signature::from_der(signature)
                    } else {
                        Err(e)
                    }
                })
                .map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
        EcCurve::P521 => {
            use p521::elliptic_curve::sec1::ToEncodedPoint;
            let public_key =
                p521::PublicKey::from_public_key_der(spki).map_err(key_err("P-521"))?;
            let verifying_key =
                p521::ecdsa::VerifyingKey::from_encoded_point(&public_key.to_encoded_point(false))
                    .map_err(bad)?;
            let signature = p521::ecdsa::Signature::from_slice(signature)
                .or_else(|e| {
                    if legacy_der {
                        p521::ecdsa::Signature::from_der(signature)
                    } else {
                        Err(e)
                    }
                })
                .map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
    }
}

/// Extract the DER certificate chain from a `COSE_Sign1`.
///
/// C2PA 2.4 accepts integer label `33` or legacy text label `x5chain` from
/// either header bucket. Integer `33` wins when both label forms are present.
/// The signature is malformed only when the chosen label occurs in both
/// buckets, or the same exact label is duplicated within one bucket.
pub fn extract_x5chain(cose_sign1: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;

    let protected = match array[0].as_bytes() {
        Some(bytes) => match decode(bytes)? {
            Value::Map(map) => map,
            _ => Vec::new(),
        },
        None => Vec::new(),
    };
    let unprotected: &[(Value, Value)] = match &array[1] {
        Value::Map(map) => map,
        _ => &[],
    };

    let protected_integer = find_x5chain_label(&protected, true)?;
    let unprotected_integer = find_x5chain_label(unprotected, true)?;
    let selected = match (protected_integer, unprotected_integer) {
        (Some(_), Some(_)) => {
            return Err(CryptoError::Malformed(
                "integer 33 x5chain appears in both protected and unprotected headers".into(),
            ))
        }
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => {
            let protected_text = find_x5chain_label(&protected, false)?;
            let unprotected_text = find_x5chain_label(unprotected, false)?;
            match (protected_text, unprotected_text) {
                (Some(_), Some(_)) => {
                    return Err(CryptoError::Malformed(
                        "text x5chain appears in both protected and unprotected headers".into(),
                    ))
                }
                (Some(value), None) | (None, Some(value)) => Some(value),
                (None, None) => None,
            }
        }
    }
    .ok_or_else(|| {
        CryptoError::Malformed("no x5chain in protected or unprotected header".into())
    })?;

    x5chain_to_ders(selected)
}

/// Locate at most one x5chain entry with the exact selected label.
fn find_x5chain_label(
    map: &[(Value, Value)],
    integer_label: bool,
) -> Result<Option<&Value>, CryptoError> {
    let mut matching = map.iter().filter(|(key, _)| {
        if integer_label {
            matches!(key, Value::Integer(value) if *value == COSE_HDR_X5CHAIN)
        } else {
            key.as_text() == Some("x5chain")
        }
    });
    let found = matching.next().map(|(_, value)| value);
    if matching.next().is_some() {
        let label = if integer_label { "integer 33" } else { "text" };
        return Err(CryptoError::Malformed(format!(
            "duplicate {label} x5chain entries in one COSE header bucket"
        )));
    }
    Ok(found)
}

/// Decode an x5chain value into its constituent DER certificates, accepting
/// both single-certificate (byte string) and chain (array of byte strings).
fn x5chain_to_ders(x5: &Value) -> Result<Vec<Vec<u8>>, CryptoError> {
    let certificates = match x5 {
        Value::Array(items) => {
            if items.len() > MAX_X5CHAIN_CERTIFICATES {
                return Err(CryptoError::Malformed(format!(
                    "x5chain has too many certificates ({} > {MAX_X5CHAIN_CERTIFICATES})",
                    items.len()
                )));
            }
            items
                .iter()
                .map(|item| {
                    item.as_bytes().ok_or_else(|| {
                        CryptoError::Malformed("x5chain entries must be byte strings".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        Value::Bytes(bytes) => vec![bytes.as_slice()],
        _ => {
            return Err(CryptoError::Malformed(
                "x5chain is neither a byte string nor an array".into(),
            ))
        }
    };

    let mut total_bytes = 0usize;
    for certificate in &certificates {
        if certificate.len() > MAX_X5CHAIN_CERTIFICATE_BYTES {
            return Err(CryptoError::Malformed(format!(
                "x5chain certificate exceeds {MAX_X5CHAIN_CERTIFICATE_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes.checked_add(certificate.len()).ok_or_else(|| {
            CryptoError::Malformed("x5chain certificate byte count overflow".into())
        })?;
        if total_bytes > MAX_X5CHAIN_TOTAL_BYTES {
            return Err(CryptoError::Malformed(format!(
                "x5chain exceeds {MAX_X5CHAIN_TOTAL_BYTES} total certificate bytes"
            )));
        }
    }

    Ok(certificates.into_iter().map(<[u8]>::to_vec).collect())
}

/// Timestamp header generation carried by a C2PA claim signature.
#[derive(Clone, Copy)]
pub enum ClaimTimestampVersion {
    /// Legacy claim-v1 `sigTst`, whose imprint covers the claim payload.
    V1,
    /// Claim-v2 `sigTst2`, whose imprint covers the encoded COSE signature.
    V2,
}

/// Extract the claim timestamp header and preserve malformed token entries.
///
/// `None` means no timestamp header. `Some((_, []))` means the header exists
/// but its `tstTokens` member is malformed or empty.
pub fn extract_claim_tsa_tokens(
    cose_sign1: &[u8],
) -> Option<(ClaimTimestampVersion, Vec<Option<Vec<u8>>>)> {
    let decoded = decode(cose_sign1).ok()?;
    let array = cose_array(&decoded).ok()?;
    let Value::Map(unprotected) = &array[1] else {
        return None;
    };
    let (header, version) = if let Some(header) = map_get_text(unprotected, "sigTst2") {
        (header, ClaimTimestampVersion::V2)
    } else {
        (
            map_get_text(unprotected, "sigTst")?,
            ClaimTimestampVersion::V1,
        )
    };
    let tokens = match header.get("tstTokens") {
        Some(Value::Array(tokens)) => tokens
            .iter()
            .map(|token| {
                token
                    .get("val")
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec)
            })
            .collect(),
        _ => Vec::new(),
    };
    Some((version, tokens))
}

/// Extract every RFC 3161 token entry from `sigTst2.tstTokens`.
///
/// Malformed entries remain as `None` so a caller's cardinality check cannot
/// accidentally turn `[valid_token, malformed_entry]` into one valid token.
pub fn extract_tsa_tokens(cose_sign1: &[u8]) -> Vec<Option<Vec<u8>>> {
    let Ok(decoded) = decode(cose_sign1) else {
        return Vec::new();
    };
    let Ok(array) = cose_array(&decoded) else {
        return Vec::new();
    };
    let Value::Map(unprotected) = &array[1] else {
        return Vec::new();
    };
    let Some(sig_tst2) = map_get_text(unprotected, "sigTst2") else {
        return Vec::new();
    };
    let Some(Value::Array(tokens)) = sig_tst2.get("tstTokens") else {
        return Vec::new();
    };
    tokens
        .iter()
        .map(|token| {
            token
                .get("val")
                .and_then(Value::as_bytes)
                .map(<[u8]>::to_vec)
        })
        .collect()
}

/// Build the C2PA v2 CounterSignature `ToBeSigned` value timestamped by
/// `sigTst2`. The signature field includes its complete CBOR byte-string
/// encoding, including type and length.
pub fn timestamp_input(cose_sign1: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("signature is not a byte string".into()))?;
    let serialized_signature = encode(&Value::Bytes(signature.to_vec()), PROFILE)?;
    counter_signature_input(protected, &serialized_signature)
}

/// Build the legacy C2PA claim-v1 `sigTst` CounterSignature input.
pub fn timestamp_input_v1(cose_sign1: &[u8], claim_cbor: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    counter_signature_input(protected, claim_cbor)
}

fn counter_signature_input(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(
        &Value::Array(vec![
            Value::Text("CounterSignature".to_string()),
            Value::Bytes(protected.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.to_vec()),
        ]),
        PROFILE,
    )
    .map_err(Into::into)
}

/// Visit stapled OCSP responses from the COSE unprotected
/// `rVals.ocspVals` array without cloning their DER bytes.
///
/// `max_values` is checked against the array length before any response is
/// visited. The return value is `false` only when that entry limit is exceeded;
/// absent or malformed revocation material produces no visits and returns
/// `true`.
pub fn visit_ocsp_staples(
    cose_sign1: &[u8],
    max_values: usize,
    mut visit: impl FnMut(&[u8]),
) -> bool {
    let Ok(decoded) = decode(cose_sign1) else {
        return true;
    };
    let Ok(array) = cose_array(&decoded) else {
        return true;
    };
    let Value::Map(unprotected) = &array[1] else {
        return true;
    };
    let Some(rvals) = map_get_text(unprotected, "rVals") else {
        return true;
    };
    let Some(Value::Array(items)) = rvals.get("ocspVals") else {
        return true;
    };
    if items.len() > max_values {
        return false;
    }
    for item in items {
        if let Some(bytes) = item.as_bytes() {
            visit(bytes);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c2pa_2_2_and_2_4_have_the_same_claim_algorithm_policy() {
        for algorithm in CoseAlg::ALL {
            assert_eq!(
                ClaimAlgorithmList::V2_2.permits(algorithm),
                ClaimAlgorithmList::V2_4.permits(algorithm),
                "{algorithm:?}"
            );
        }
    }

    fn cose_with_headers(
        protected: Vec<(Value, Value)>,
        unprotected: Vec<(Value, Value)>,
    ) -> Vec<u8> {
        let protected = encode(&Value::Map(protected), PROFILE).expect("encode protected");
        encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(unprotected),
                    Value::Bytes(b"payload".to_vec()),
                    Value::Bytes(b"signature".to_vec()),
                ])),
            ),
            PROFILE,
        )
        .expect("encode cose")
    }

    fn integer(value: u8) -> (Value, Value) {
        (
            Value::Integer(COSE_HDR_X5CHAIN),
            Value::Bytes(vec![0x30, value, 0x00]),
        )
    }

    fn text(value: u8) -> (Value, Value) {
        (
            Value::Text("x5chain".into()),
            Value::Bytes(vec![0x30, value, 0x00]),
        )
    }

    #[test]
    fn accepts_x5chain_from_protected_or_unprotected_bucket() {
        for cose in [
            cose_with_headers(vec![integer(1)], Vec::new()),
            cose_with_headers(Vec::new(), vec![integer(1)]),
            cose_with_headers(vec![text(1)], Vec::new()),
            cose_with_headers(Vec::new(), vec![text(1)]),
        ] {
            assert_eq!(
                extract_x5chain(&cose).expect("compatible x5chain"),
                vec![vec![0x30, 0x01, 0x00]]
            );
        }
    }

    #[test]
    fn integer_label_wins_over_text_in_same_or_different_buckets() {
        for cose in [
            cose_with_headers(vec![text(2), integer(1)], Vec::new()),
            cose_with_headers(Vec::new(), vec![text(2), integer(1)]),
            cose_with_headers(vec![integer(1)], vec![text(2)]),
            cose_with_headers(vec![text(2)], vec![integer(1)]),
        ] {
            assert_eq!(
                extract_x5chain(&cose).expect("integer label"),
                vec![vec![0x30, 0x01, 0x00]]
            );
        }
    }

    #[test]
    fn chosen_label_in_both_buckets_is_rejected() {
        let integer_duplicate = cose_with_headers(vec![integer(1)], vec![integer(2), text(3)]);
        assert!(extract_x5chain(&integer_duplicate).is_err());

        let text_duplicate = cose_with_headers(vec![text(1)], vec![text(2)]);
        assert!(extract_x5chain(&text_duplicate).is_err());
    }

    #[test]
    fn duplicate_exact_label_in_one_bucket_is_rejected() {
        let integer_duplicate = cose_with_headers(vec![integer(1), integer(2)], Vec::new());
        assert!(extract_x5chain(&integer_duplicate).is_err());

        let text_duplicate = cose_with_headers(Vec::new(), vec![text(1), text(2)]);
        assert!(extract_x5chain(&text_duplicate).is_err());
    }

    #[test]
    fn malformed_integer_value_does_not_fall_back_to_text_label() {
        let cose = cose_with_headers(
            vec![(Value::Integer(COSE_HDR_X5CHAIN), Value::Integer(7))],
            vec![text(1)],
        );
        assert!(extract_x5chain(&cose).is_err());
    }

    #[test]
    fn x5chain_certificate_limits_accept_boundaries_and_reject_excess() {
        let at_count_limit = Value::Array(
            (0..MAX_X5CHAIN_CERTIFICATES)
                .map(|_| Value::Bytes(vec![0x30, 0x00]))
                .collect(),
        );
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), at_count_limit)],
        );
        assert_eq!(
            extract_x5chain(&cose).expect("chain at count limit").len(),
            MAX_X5CHAIN_CERTIFICATES
        );

        let at_certificate_limit = Value::Bytes(vec![0; MAX_X5CHAIN_CERTIFICATE_BYTES]);
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), at_certificate_limit)],
        );
        assert_eq!(
            extract_x5chain(&cose)
                .expect("certificate at byte limit")
                .first()
                .map(Vec::len),
            Some(MAX_X5CHAIN_CERTIFICATE_BYTES)
        );

        assert_eq!(MAX_X5CHAIN_TOTAL_BYTES % MAX_X5CHAIN_CERTIFICATE_BYTES, 0);
        let total_certificate_count = MAX_X5CHAIN_TOTAL_BYTES / MAX_X5CHAIN_CERTIFICATE_BYTES;
        let at_total_limit = Value::Array(
            (0..total_certificate_count)
                .map(|_| Value::Bytes(vec![0; MAX_X5CHAIN_CERTIFICATE_BYTES]))
                .collect(),
        );
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), at_total_limit)],
        );
        assert_eq!(
            extract_x5chain(&cose)
                .expect("chain at total byte limit")
                .len(),
            total_certificate_count
        );

        let over_count_limit = Value::Array(
            (0..=MAX_X5CHAIN_CERTIFICATES)
                .map(|_| Value::Bytes(vec![0x30, 0x00]))
                .collect(),
        );
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), over_count_limit)],
        );
        assert!(extract_x5chain(&cose).is_err());

        let oversized_certificate = Value::Bytes(vec![0; MAX_X5CHAIN_CERTIFICATE_BYTES + 1]);
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), oversized_certificate)],
        );
        assert!(extract_x5chain(&cose).is_err());

        let certificate_bytes = MAX_X5CHAIN_TOTAL_BYTES / 9 + 1;
        assert!(certificate_bytes <= MAX_X5CHAIN_CERTIFICATE_BYTES);
        let over_total_limit = Value::Array(
            (0..9)
                .map(|_| Value::Bytes(vec![0; certificate_bytes]))
                .collect(),
        );
        let cose = cose_with_headers(
            Vec::new(),
            vec![(Value::Integer(COSE_HDR_X5CHAIN), over_total_limit)],
        );
        assert!(extract_x5chain(&cose).is_err());
    }

    /// Build a real ES256 `COSE_Sign1_Tagged` over `claim`, placing `payload`
    /// in the third array slot. Returns `(cose, leaf_der)`.
    fn sign_claim_with_payload(claim: &[u8], payload: Value, alg_id: i128) -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;
        use rcgen::{CertificateParams, IsCa, KeyPair};

        let key = KeyPair::generate().expect("keypair");
        let mut params =
            CertificateParams::new(vec!["signer.example".to_string()]).expect("params");
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::EmailProtection];
        let certificate = params.self_signed(&key).expect("self-signed leaf");
        let leaf_der = certificate.der().as_ref().to_vec();

        let protected = encode(
            &Value::Map(vec![(Value::Integer(COSE_HDR_ALG), Value::Integer(alg_id))]),
            PROFILE,
        )
        .expect("encode protected");
        let sig_input = sig_structure_bytes(&protected, claim).expect("sig structure");
        let signing_key =
            SigningKey::from_pkcs8_der(&key.serialize_der()).expect("load signing key");
        let signature: Signature = signing_key.sign(&sig_input);
        let cose = encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(Vec::new()),
                    payload,
                    Value::Bytes(signature.to_der().as_bytes().to_vec()),
                ])),
            ),
            PROFILE,
        )
        .expect("encode cose");
        (cose, leaf_der)
    }

    #[test]
    fn detached_nil_payload_verifies_and_any_carried_payload_is_rejected() {
        let claim = b"claim-cbor-bytes".to_vec();
        // Detached content mode: payload is nil (CBOR major type 7, value 22).
        let (cose, leaf) = sign_claim_with_payload(&claim, Value::Null, -7);
        verify_claim(&cose, &claim, &leaf).expect("nil payload is the only conformant form");

        // An embedded payload, and an empty byte string, are both non-nil and
        // must be rejected even though the reconstructed Sig_structure would
        // still verify against the claim bytes.
        for carried in [Value::Bytes(claim.clone()), Value::Bytes(Vec::new())] {
            let (cose, leaf) = sign_claim_with_payload(&claim, carried, -7);
            assert!(
                matches!(
                    verify_claim(&cose, &claim, &leaf),
                    Err(CryptoError::PayloadNotDetached)
                ),
                "a COSE_Sign1 payload that is not nil must be rejected"
            );
        }
    }

    /// A real certificate carrying `spki`, issued by a fixed P-256 test CA.
    /// Claim verification reads only the leaf key; the issuer signature is
    /// genuine so the certificate is also usable by chain-level tests.
    fn certificate_for(spki: spki::SubjectPublicKeyInfoOwned) -> Vec<u8> {
        use p256::ecdsa::{signature::Signer as _, DerSignature, SigningKey};
        use std::str::FromStr as _;
        use x509_cert::certificate::{Certificate, TbsCertificate, Version};
        use x509_cert::time::{Time, Validity};

        let at = |seconds: u64| {
            Time::UtcTime(
                der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(seconds))
                    .expect("UTC time"),
            )
        };
        let algorithm = spki::AlgorithmIdentifierOwned {
            oid: spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
            parameters: None,
        };
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[0x25]).expect("serial"),
            signature: algorithm.clone(),
            issuer: x509_cert::name::Name::from_str("CN=C2PA 2.5 Test CA,O=Encypher Test")
                .expect("issuer"),
            validity: Validity {
                not_before: at(1_700_000_000),
                not_after: at(2_000_000_000),
            },
            subject: x509_cert::name::Name::from_str("CN=C2PA 2.5 Test Signer,O=Encypher Test")
                .expect("subject"),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let issuer = SigningKey::from_slice(&[0x25; 32]).expect("CA key");
        let signature: DerSignature = issuer.sign(&tbs_certificate.to_der().expect("TBS"));
        Certificate {
            tbs_certificate,
            signature_algorithm: algorithm,
            signature: der::asn1::BitString::from_bytes(signature.as_bytes()).expect("bits"),
        }
        .to_der()
        .expect("certificate")
    }

    fn certificate_for_spki_der(spki_der: &[u8]) -> Vec<u8> {
        certificate_for(spki::SubjectPublicKeyInfoOwned::from_der(spki_der).expect("SPKI"))
    }

    /// A detached `COSE_Sign1_Tagged` over `claim` with protected `{1: alg}`.
    fn detached_cose(alg_id: i128, claim: &[u8], sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        let protected = encode(
            &Value::Map(vec![(Value::Integer(COSE_HDR_ALG), Value::Integer(alg_id))]),
            PROFILE,
        )
        .expect("encode protected");
        let signature = sign(&sig_structure_bytes(&protected, claim).expect("sig structure"));
        encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(Vec::new()),
                    Value::Null,
                    Value::Bytes(signature),
                ])),
            ),
            PROFILE,
        )
        .expect("encode cose")
    }

    struct EcSigner {
        p256: p256::ecdsa::SigningKey,
        p384: p384::ecdsa::SigningKey,
        p521: p521::ecdsa::SigningKey,
    }

    impl EcSigner {
        fn new() -> Self {
            let mut rng = rand_core::OsRng;
            Self {
                p256: p256::ecdsa::SigningKey::random(&mut rng),
                p384: p384::ecdsa::SigningKey::random(&mut rng),
                p521: p521::ecdsa::SigningKey::random(&mut rng),
            }
        }

        fn leaf(&self, curve: EcCurve) -> Vec<u8> {
            use p256::pkcs8::EncodePublicKey as _;
            let spki = match curve {
                EcCurve::P256 => self.p256.verifying_key().to_public_key_der(),
                EcCurve::P384 => self.p384.verifying_key().to_public_key_der(),
                EcCurve::P521 => p521::PublicKey::from_sec1_bytes(
                    p521::ecdsa::VerifyingKey::from(&self.p521)
                        .to_encoded_point(false)
                        .as_bytes(),
                )
                .expect("P-521 point")
                .to_public_key_der(),
            }
            .expect("SPKI");
            certificate_for_spki_der(spki.as_bytes())
        }

        /// Fixed-width `r || s`, the COSE encoding (RFC 9053 section 2.1).
        fn raw(&self, curve: EcCurve, data: &[u8]) -> Vec<u8> {
            use signature::Signer as _;
            match curve {
                EcCurve::P256 => {
                    let signature: p256::ecdsa::Signature = self.p256.sign(data);
                    signature.to_bytes().to_vec()
                }
                EcCurve::P384 => {
                    let signature: p384::ecdsa::Signature = self.p384.sign(data);
                    signature.to_bytes().to_vec()
                }
                EcCurve::P521 => {
                    let signature: p521::ecdsa::Signature = self.p521.sign(data);
                    signature.to_bytes().to_vec()
                }
            }
        }
    }

    /// `(ESP id, its RFC 9864 curve, the ES twin with the same digest, digest bits)`.
    const ESP: [(i128, EcCurve, i128, u16); 3] = [
        (-9, EcCurve::P256, -7, 256),
        (-51, EcCurve::P384, -35, 384),
        (-52, EcCurve::P521, -36, 512),
    ];

    #[test]
    fn esp_signatures_verify_on_their_bound_curve_only_under_the_2_5_list() {
        let signer = EcSigner::new();
        let claim = b"esp claim bytes".to_vec();
        for (alg_id, curve, _, _) in ESP {
            let leaf = signer.leaf(curve);
            let cose = detached_cose(alg_id, &claim, |data| signer.raw(curve, data));
            verify_claim_with(&cose, &claim, &leaf, ClaimAlgorithmList::V2_5)
                .unwrap_or_else(|e| panic!("ESP {alg_id} on its own curve must verify: {e}"));
            assert!(matches!(
                verify_claim(&cose, &claim, &leaf),
                Err(CryptoError::UnsupportedAlg(id)) if id == alg_id
            ));

            let mut tampered = claim.clone();
            tampered[0] ^= 0x01;
            assert!(verify_claim_with(&cose, &tampered, &leaf, ClaimAlgorithmList::V2_5).is_err());
        }
    }

    #[test]
    fn esp_refuses_a_key_on_any_other_curve_even_with_a_valid_signature() {
        let signer = EcSigner::new();
        let claim = b"esp pairing".to_vec();
        for (alg_id, bound, es_twin, bits) in ESP {
            for (_, other, _, _) in ESP {
                // A 256-bit digest is shorter than half of P-521's field, which
                // RustCrypto ECDSA refuses (bits2field); C2PA lets validators
                // reject non-matching pairings, so that one has no ES baseline.
                if other == bound || (bits == 256 && other == EcCurve::P521) {
                    continue;
                }
                // Both signatures are genuinely valid ECDSA by `other`'s key
                // over the same digest. The ES identifier accepts that
                // pairing; only the RFC 9864 binding makes the ESP one wrong.
                let leaf = signer.leaf(other);
                let sign = |data: &[u8]| prehash_sign(&signer, other, sha2_digest(bits, data));
                let es_cose = detached_cose(es_twin, &claim, sign);
                verify_claim_with(&es_cose, &claim, &leaf, ClaimAlgorithmList::V2_5)
                    .expect("the ES twin keeps its cross-curve acceptance");
                let esp_cose = detached_cose(alg_id, &claim, sign);
                assert!(matches!(
                    verify_claim_with(&esp_cose, &claim, &leaf, ClaimAlgorithmList::V2_5),
                    Err(CryptoError::Verify(_))
                ));
            }
        }
    }

    fn sha2_digest(bits: u16, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match bits {
            256 => sha2::Sha256::digest(data).to_vec(),
            384 => sha2::Sha384::digest(data).to_vec(),
            _ => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn prehash_sign(signer: &EcSigner, curve: EcCurve, digest: Vec<u8>) -> Vec<u8> {
        use signature::hazmat::PrehashSigner as _;
        match curve {
            EcCurve::P256 => {
                let signature: p256::ecdsa::Signature =
                    signer.p256.sign_prehash(&digest).expect("P-256 prehash");
                signature.to_bytes().to_vec()
            }
            EcCurve::P384 => {
                let signature: p384::ecdsa::Signature =
                    signer.p384.sign_prehash(&digest).expect("P-384 prehash");
                signature.to_bytes().to_vec()
            }
            EcCurve::P521 => {
                let signature: p521::ecdsa::Signature =
                    signer.p521.sign_prehash(&digest).expect("P-521 prehash");
                signature.to_bytes().to_vec()
            }
        }
    }

    #[test]
    fn esp_accepts_only_the_fixed_width_cose_signature_encoding() {
        let signer = EcSigner::new();
        let claim = b"esp encoding".to_vec();
        let leaf = signer.leaf(EcCurve::P256);
        let der_signed = |alg_id| {
            detached_cose(alg_id, &claim, |data| {
                use signature::Signer as _;
                let signature: p256::ecdsa::Signature = signer.p256.sign(data);
                signature.to_der().as_bytes().to_vec()
            })
        };
        // ES256 keeps accepting the DER form legacy assets carry.
        verify_claim_with(&der_signed(-7), &claim, &leaf, ClaimAlgorithmList::V2_5)
            .expect("legacy ES256 DER signature");
        assert!(matches!(
            verify_claim_with(&der_signed(-9), &claim, &leaf, ClaimAlgorithmList::V2_5),
            Err(CryptoError::Verify(_))
        ));
    }

    struct Rfc9964Claim {
        alg_id: i128,
        public_key: &'static [u8],
        sign1: &'static [u8],
        to_be_signed: &'static [u8],
    }

    /// RFC 9964 Appendix A.2: COSE_Sign1 values signed by an independent
    /// ML-DSA implementation. Re-expressed in C2PA detached form, the RFC
    /// payload becomes the claim and the Sig_structure is unchanged.
    const RFC9964: [Rfc9964Claim; 3] = [
        Rfc9964Claim {
            alg_id: -48,
            public_key: include_bytes!("fixtures/ml_dsa_44_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_44_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_44_rfc9964.tbs"),
        },
        Rfc9964Claim {
            alg_id: -49,
            public_key: include_bytes!("fixtures/ml_dsa_65_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_65_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_65_rfc9964.tbs"),
        },
        Rfc9964Claim {
            alg_id: -50,
            public_key: include_bytes!("fixtures/ml_dsa_87_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_87_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_87_rfc9964.tbs"),
        },
    ];

    const RFC9881_CERTIFICATES: [&[u8]; 3] = [
        include_bytes!("fixtures/ml_dsa_44_rfc9881_cert.der"),
        include_bytes!("fixtures/ml_dsa_65_rfc9881_cert.der"),
        include_bytes!("fixtures/ml_dsa_87_rfc9881_cert.der"),
    ];

    /// `(detached C2PA COSE, claim bytes, leaf certificate)` for an RFC vector.
    fn rfc9964_claim(vector: &Rfc9964Claim) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let decoded = decode(vector.sign1).expect("RFC COSE_Sign1");
        let items = cose_array(&decoded).expect("RFC COSE_Sign1 array");
        let protected = items[0].as_bytes().expect("protected").to_vec();
        let payload = items[2]
            .as_bytes()
            .expect("RFC example carries its payload")
            .to_vec();
        let signature = items[3].as_bytes().expect("signature").to_vec();
        assert_eq!(
            sig_structure_bytes(&protected, &payload).expect("sig structure"),
            vector.to_be_signed,
            "our Sig_structure encoding must equal the RFC's ToBeSigned bytes"
        );
        let cose = encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(Vec::new()),
                    Value::Null,
                    Value::Bytes(signature),
                ])),
            ),
            PROFILE,
        )
        .expect("detached cose");
        let oid = match vector.alg_id {
            -48 => "2.16.840.1.101.3.4.3.17",
            -49 => "2.16.840.1.101.3.4.3.18",
            _ => "2.16.840.1.101.3.4.3.19",
        };
        let leaf = certificate_for(spki::SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: spki::ObjectIdentifier::new_unwrap(oid),
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(vector.public_key)
                .expect("bit string"),
        });
        (cose, payload, leaf)
    }

    #[test]
    fn rfc9964_ml_dsa_claims_verify_only_under_the_2_5_list() {
        for vector in &RFC9964 {
            let (cose, claim, leaf) = rfc9964_claim(vector);
            verify_claim_with(&cose, &claim, &leaf, ClaimAlgorithmList::V2_5)
                .unwrap_or_else(|e| panic!("RFC 9964 {} must verify: {e}", vector.alg_id));
            assert!(matches!(
                verify_claim(&cose, &claim, &leaf),
                Err(CryptoError::UnsupportedAlg(id)) if id == vector.alg_id
            ));
            assert_eq!(
                extract_cose_alg(&cose).expect("known algorithm").cose_id(),
                vector.alg_id
            );

            let mut tampered = claim.clone();
            tampered[0] ^= 0x01;
            assert!(matches!(
                verify_claim_with(&cose, &tampered, &leaf, ClaimAlgorithmList::V2_5),
                Err(CryptoError::Verify(_))
            ));
        }
    }

    #[test]
    fn ml_dsa_refuses_a_certificate_key_of_another_parameter_set_or_owner() {
        for (index, vector) in RFC9964.iter().enumerate() {
            let (cose, claim, _) = rfc9964_claim(vector);
            for (other, certificate) in RFC9881_CERTIFICATES.iter().enumerate() {
                // Same parameter set, different key: a signature mismatch.
                // Different parameter set: refused before any verification.
                let result =
                    verify_claim_with(&cose, &claim, certificate, ClaimAlgorithmList::V2_5);
                assert!(
                    matches!(result, Err(CryptoError::Verify(_))),
                    "vector {index} against RFC 9881 certificate {other}: {result:?}"
                );
            }
            let ec_leaf = EcSigner::new().leaf(EcCurve::P256);
            assert!(matches!(
                verify_claim_with(&cose, &claim, &ec_leaf, ClaimAlgorithmList::V2_5),
                Err(CryptoError::CertParse(_))
            ));
        }
    }

    #[test]
    fn a_classical_algorithm_id_never_verifies_with_an_ml_dsa_key() {
        let (_, claim, ml_dsa_leaf) = rfc9964_claim(&RFC9964[0]);
        let signer = EcSigner::new();
        let cose = detached_cose(-7, &claim, |data| signer.raw(EcCurve::P256, data));
        assert!(matches!(
            verify_claim_with(&cose, &claim, &ml_dsa_leaf, ClaimAlgorithmList::V2_5),
            Err(CryptoError::CertParse(_))
        ));
    }
}
