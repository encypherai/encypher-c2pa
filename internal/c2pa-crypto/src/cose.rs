//! COSE_Sign1 verification and header extraction.
//!
//! Verification reconstructs the detached RFC 9052 `Sig_structure` from the
//! protected header and supplied claim bytes. Header readers accept the
//! standard integer labels and legacy text labels found in deployed assets.

use c2pa_cbor::{decode, encode, Profile, Value};
use der::{Decode, Encode};
use spki::DecodePublicKey;

use crate::alg::CoseAlg;
use crate::error::CryptoError;

/// CBOR tag for a `COSE_Sign1_Tagged` structure (RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;
/// COSE protected-header key for the algorithm.
const COSE_HDR_ALG: i128 = 1;
/// RFC 9052 integer label for an x5chain certificate chain.
const COSE_HDR_X5CHAIN: i128 = 33;

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
                let signature = p256::ecdsa::Signature::from_slice(signature).map_err(bad)?;
                verifying_key
                    .verify_prehash(&digest, &signature)
                    .map_err(bad)
            }
            EcCurve::P384 => {
                let verifying_key = p384::ecdsa::VerifyingKey::from_public_key_der(&spki)
                    .map_err(key_err("P-384"))?;
                let signature = p384::ecdsa::Signature::from_slice(signature).map_err(bad)?;
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
                let signature = p521::ecdsa::Signature::from_slice(signature).map_err(bad)?;
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
/// The x5chain may live in either the protected or the unprotected header.
/// Live c2pa-rs signatures place it in the protected header map, while legacy
/// Encypher assets carry it in the unprotected map. Both the text
/// `"x5chain"` and integer (33) labels are accepted, as are the
/// single-certificate (byte string) and chain (array of byte strings) forms.
/// The protected header is checked first; the first chain found is returned.
pub fn extract_x5chain(cose_sign1: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;

    // Protected header: a CBOR map serialized as a byte string.
    let protected_x5 = match array[0].as_bytes() {
        Some(bytes) => match decode(bytes)? {
            Value::Map(m) => find_x5chain(&m),
            _ => None,
        },
        None => None,
    };

    let x5 = match protected_x5 {
        Some(v) => v,
        None => {
            let unprotected = match &array[1] {
                Value::Map(m) => m,
                _ => {
                    return Err(CryptoError::Malformed(
                        "unprotected header is not a map".into(),
                    ))
                }
            };
            find_x5chain(unprotected).ok_or_else(|| {
                CryptoError::Malformed("no x5chain in protected or unprotected header".into())
            })?
        }
    };

    x5chain_to_ders(&x5)
}

/// Extract the DER certificate chain only when `x5chain` is integrity
/// protected by the COSE signature.
///
/// CAWG Identity 1.2 imports the C2PA signing-credential rule that the
/// end-entity certificate be integrity protected. An unprotected-only chain is
/// therefore not an acceptable named-actor credential.
pub fn extract_protected_x5chain(cose_sign1: &[u8]) -> Result<Vec<Vec<u8>>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not bytes".into()))?;
    let protected_map = match decode(protected)? {
        Value::Map(map) => map,
        _ => {
            return Err(CryptoError::Malformed(
                "protected header is not a map".into(),
            ))
        }
    };
    let x5chain = find_x5chain(&protected_map)
        .ok_or_else(|| CryptoError::Malformed("no x5chain in protected header".into()))?;
    x5chain_to_ders(&x5chain)
}

/// Locate an x5chain entry in a header map under either the text `"x5chain"`
/// or integer (33) label.
fn find_x5chain(map: &[(Value, Value)]) -> Option<Value> {
    map_get_text(map, "x5chain")
        .or_else(|| map_get_int(map, COSE_HDR_X5CHAIN))
        .cloned()
}

/// Decode an x5chain value into its constituent DER certificates, accepting
/// both single-certificate (byte string) and chain (array of byte strings).
fn x5chain_to_ders(x5: &Value) -> Result<Vec<Vec<u8>>, CryptoError> {
    match x5 {
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_bytes().map(|bytes| bytes.to_vec()).ok_or_else(|| {
                    CryptoError::Malformed("x5chain entries must be byte strings".into())
                })
            })
            .collect(),
        Value::Bytes(b) => Ok(vec![b.clone()]),
        _ => Err(CryptoError::Malformed(
            "x5chain is neither a byte string nor an array".into(),
        )),
    }
}

/// Extract the RFC 3161 timestamp token from the `sigTst2` unprotected header,
/// if present.
pub fn extract_tsa_token(cose_sign1: &[u8]) -> Option<Vec<u8>> {
    let decoded = decode(cose_sign1).ok()?;
    let array = cose_array(&decoded).ok()?;
    let unprotected = match &array[1] {
        Value::Map(map) => map,
        _ => return None,
    };
    let sig_tst2 = map_get_text(unprotected, "sigTst2")?;
    let tokens = sig_tst2.get("tstTokens")?;
    let first = match tokens {
        Value::Array(items) => items.first()?,
        _ => return None,
    };
    first
        .get("val")
        .and_then(Value::as_bytes)
        .map(<[u8]>::to_vec)
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
    encode(
        &Value::Array(vec![
            Value::Text("CounterSignature".to_string()),
            Value::Bytes(protected.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(serialized_signature),
        ]),
        PROFILE,
    )
    .map_err(Into::into)
}

/// Extract the first stapled OCSP response (DER) from the COSE unprotected
/// header, if present.
///
/// Per the C2PA spec / c2pa-rs, revocation material is carried under the
/// unprotected `rVals` map as `ocspVals`: an array of DER-encoded OCSP
/// responses. Returns the first response, which covers the signing chain.
pub fn extract_ocsp_staple(cose_sign1: &[u8]) -> Option<Vec<u8>> {
    let decoded = decode(cose_sign1).ok()?;
    let array = cose_array(&decoded).ok()?;
    let unprotected = match &array[1] {
        Value::Map(m) => m,
        _ => return None,
    };
    let rvals = map_get_text(unprotected, "rVals")?;
    let ocsp_vals = rvals.get("ocspVals")?;
    match ocsp_vals {
        Value::Array(items) => items.first().and_then(|v| v.as_bytes()).map(|b| b.to_vec()),
        _ => None,
    }
}

/// Extract **all** stapled OCSP responses (DER) from the COSE unprotected
/// `rVals.ocspVals` array, in order. A C2PA signature may staple one OCSP
/// response per certificate in the chain (leaf and each intermediate), so a
/// verifier must inspect every entry to catch a revoked intermediate.
pub fn extract_ocsp_staples(cose_sign1: &[u8]) -> Vec<Vec<u8>> {
    let Ok(decoded) = decode(cose_sign1) else {
        return Vec::new();
    };
    let Ok(array) = cose_array(&decoded) else {
        return Vec::new();
    };
    let Value::Map(unprotected) = &array[1] else {
        return Vec::new();
    };
    let Some(rvals) = map_get_text(unprotected, "rVals") else {
        return Vec::new();
    };
    let Some(Value::Array(items)) = rvals.get("ocspVals") else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|v| v.as_bytes().map(|b| b.to_vec()))
        .collect()
}
