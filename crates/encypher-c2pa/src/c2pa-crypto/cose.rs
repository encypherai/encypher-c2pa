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
/// Returns `Ok(())` only when the signature is valid; any structural problem,
/// unsupported algorithm, or signature mismatch yields an error.
pub fn verify_claim(
    cose_sign1: &[u8],
    claim_cbor: &[u8],
    cert_der: &[u8],
) -> Result<(), CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;

    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("signature is not a byte string".into()))?;

    // Algorithm lives in the protected header map.
    let protected = decode(protected_bytes)?;
    let alg_id = match &protected {
        Value::Map(m) => map_get_int(m, COSE_HDR_ALG).and_then(|v| match v {
            Value::Integer(n) => Some(*n),
            _ => None,
        }),
        _ => None,
    }
    .ok_or_else(|| CryptoError::Malformed("missing algorithm in protected header".into()))?;
    let alg = CoseAlg::from_cose_id(alg_id).ok_or(CryptoError::UnsupportedAlg(alg_id))?;

    let sig_input = sig_structure_bytes(protected_bytes, claim_cbor)?;
    verify_signature(alg, &sig_input, signature, cert_der)
}

/// Return the protected COSE algorithm from a `COSE_Sign1_Tagged` value.
pub fn extract_cose_alg(cose_sign1: &[u8]) -> Result<CoseAlg, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let protected = decode(protected_bytes)?;
    let alg_id = match &protected {
        Value::Map(entries) => map_get_int(entries, COSE_HDR_ALG).and_then(|value| match value {
            Value::Integer(id) => Some(*id),
            _ => None,
        }),
        _ => None,
    }
    .ok_or_else(|| CryptoError::Malformed("missing algorithm in protected header".into()))?;
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

#[derive(Clone, Copy)]
enum EcCurve {
    P256,
    P384,
    P521,
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
pub(crate) fn verify_signature(
    alg: CoseAlg,
    data: &[u8],
    signature: &[u8],
    cert_der: &[u8],
) -> Result<(), CryptoError> {
    use sha2::Digest as _;
    use signature::{hazmat::PrehashVerifier as _, Verifier as _};

    let spki = leaf_spki_der(cert_der)?;
    let bad = |e: signature::Error| CryptoError::Verify(e.to_string());
    let key_err = |what: &'static str| {
        move |e: spki::Error| CryptoError::CertParse(format!("{what} public key parse failed: {e}"))
    };

    if matches!(alg, CoseAlg::Es256 | CoseAlg::Es384 | CoseAlg::Es512) {
        let digest = match alg {
            CoseAlg::Es256 => sha2::Sha256::digest(data).to_vec(),
            CoseAlg::Es384 => sha2::Sha384::digest(data).to_vec(),
            CoseAlg::Es512 => sha2::Sha512::digest(data).to_vec(),
            _ => unreachable!(),
        };
        return match ec_curve_from_spki(&spki)? {
            EcCurve::P256 => {
                let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)
                    .map_err(key_err("P-256"))?;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .or_else(|_| p256::ecdsa::Signature::from_der(signature))
                    .map_err(bad)?;
                verifying_key
                    .verify_prehash(&digest, &signature)
                    .map_err(bad)
            }
            EcCurve::P384 => {
                let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(&spki)
                    .map_err(key_err("P-384"))?;
                let signature = p384::ecdsa::Signature::from_slice(signature)
                    .or_else(|_| p384::ecdsa::Signature::from_der(signature))
                    .map_err(bad)?;
                verifying_key
                    .verify_prehash(&digest, &signature)
                    .map_err(bad)
            }
            EcCurve::P521 => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                let public_key =
                    p521::PublicKey::from_public_key_der(&spki).map_err(key_err("P-521"))?;
                let verifying_key = p521::ecdsa::VerifyingKey::from_encoded_point(
                    &public_key.to_encoded_point(false),
                )
                .map_err(bad)?;
                let signature = p521::ecdsa::Signature::from_slice(signature)
                    .or_else(|_| p521::ecdsa::Signature::from_der(signature))
                    .map_err(bad)?;
                verifying_key
                    .verify_prehash(&digest, &signature)
                    .map_err(bad)
            }
        };
    }

    match alg {
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
        CoseAlg::Es256 | CoseAlg::Es384 | CoseAlg::Es512 => unreachable!(),
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
}
