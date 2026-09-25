// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE_Key verification for C2PA live-video session keys.
//!
//! Verification only. A session key is read, never minted: this module has no
//! signer and no key generation, so nothing here can produce a signature.

use crate::c2pa_cbor::{decode, encode, Profile, Value};

use super::{CoseAlg, CryptoError};

const COSE_SIGN1_TAG: u64 = 18;

/// Verified embedded COSE_Sign1 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCoseKeySignature {
    /// Unprotected `kid` (label 4), when the signature carries one.
    pub key_id: Option<Vec<u8>>,
    /// Embedded payload authenticated by the session key.
    pub payload: Vec<u8>,
    /// Protected signature algorithm.
    pub algorithm: CoseAlg,
}

/// Verify an embedded COSE_Sign1 with a serialized COSE_Key.
///
/// The protected `alg` must equal the key's `alg`; algorithms are never inferred
/// from coordinate shape. Detached payloads are not accepted for session data.
pub fn verify_with_cose_key(
    cose_sign1: &[u8],
    cose_key: &[u8],
) -> Result<VerifiedCoseKeySignature, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not bytes".into()))?;
    let protected = decode(protected_bytes)?;
    let protected = protected
        .as_map()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a map".into()))?;
    let alg_id = required_integer(protected, 1, "protected alg")?;
    let algorithm = CoseAlg::from_cose_id(alg_id).ok_or(CryptoError::UnsupportedAlg(alg_id))?;
    if optional_unique_bytes(protected, 4, "protected kid")?.is_some() {
        return Err(CryptoError::Malformed(
            "session signature kid must be unprotected".into(),
        ));
    }
    let unprotected = array[1]
        .as_map()
        .ok_or_else(|| CryptoError::Malformed("unprotected header is not a map".into()))?;
    let key_id = optional_unique_bytes(unprotected, 4, "unprotected kid")?.map(ToOwned::to_owned);
    let payload = array[2]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("session signature payload is detached".into()))?;
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("signature is not bytes".into()))?;

    let key_value = decode(cose_key)?;
    let key = key_value
        .as_map()
        .ok_or_else(|| CryptoError::KeyParse("COSE_Key is not a map".into()))?;
    let key_alg = required_integer(key, 3, "COSE_Key alg")?;
    if key_alg != alg_id {
        return Err(CryptoError::Verify(
            "signature algorithm does not match COSE_Key alg".into(),
        ));
    }
    let sig_structure = encode(
        &Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected_bytes.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.to_vec()),
        ]),
        Profile::LegacyPipelineBDefinite,
    )?;
    verify_key_signature(algorithm, key, &sig_structure, signature)?;
    Ok(VerifiedCoseKeySignature {
        key_id,
        payload: payload.to_vec(),
        algorithm,
    })
}

/// Return the required `kid` (label 2) from a serialized C2PA session COSE_Key.
pub fn cose_key_id(cose_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(cose_key)?;
    let map = decoded
        .as_map()
        .ok_or_else(|| CryptoError::KeyParse("COSE_Key is not a map".into()))?;
    required_bytes(map, 2, "COSE_Key kid").map(ToOwned::to_owned)
}

fn verify_key_signature(
    alg: CoseAlg,
    key: &[(Value, Value)],
    data: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use rsa::traits::PublicKeyParts as _;
    use sha2::Digest as _;
    use signature::{hazmat::PrehashVerifier as _, Verifier as _};

    let kty = required_integer(key, 1, "COSE_Key kty")?;
    let bad = |error: signature::Error| CryptoError::Verify(error.to_string());
    match alg {
        CoseAlg::Es256 => {
            require_key_type_and_curve(kty, key, 2, 1)?;
            let point = ec_point(key, 32)?;
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(&sha2::Sha256::digest(data), &signature)
                .map_err(bad)
        }
        CoseAlg::Es384 => {
            require_key_type_and_curve(kty, key, 2, 2)?;
            let point = ec_point(key, 48)?;
            let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = p384::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(&sha2::Sha384::digest(data), &signature)
                .map_err(bad)
        }
        CoseAlg::Es512 => {
            require_key_type_and_curve(kty, key, 2, 3)?;
            let point = ec_point(key, 66)?;
            let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = p521::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(&sha2::Sha512::digest(data), &signature)
                .map_err(bad)
        }
        CoseAlg::EdDsa => {
            require_key_type_and_curve(kty, key, 1, 6)?;
            let x = required_bytes(key, -2, "COSE_Key x")?;
            let x: [u8; 32] = x
                .try_into()
                .map_err(|_| CryptoError::KeyParse("Ed25519 x must be 32 bytes".into()))?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&x)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(bad)?;
            verifying_key.verify(data, &signature).map_err(bad)
        }
        CoseAlg::Ps256 | CoseAlg::Ps384 | CoseAlg::Ps512 => {
            if kty != 3 {
                return Err(CryptoError::KeyParse("RSA algorithm requires kty 3".into()));
            }
            let modulus = rsa::BigUint::from_bytes_be(required_bytes(key, -1, "COSE_Key n")?);
            let exponent = rsa::BigUint::from_bytes_be(required_bytes(key, -2, "COSE_Key e")?);
            let public_key = rsa::RsaPublicKey::new(modulus, exponent)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            if public_key.n().bits() < 2048 {
                return Err(CryptoError::KeyParse(
                    "RSA session key modulus is smaller than 2048 bits".into(),
                ));
            }
            match alg {
                CoseAlg::Ps256 => {
                    let key = rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key);
                    let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
                    key.verify(data, &signature).map_err(bad)
                }
                CoseAlg::Ps384 => {
                    let key = rsa::pss::VerifyingKey::<sha2::Sha384>::new(public_key);
                    let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
                    key.verify(data, &signature).map_err(bad)
                }
                CoseAlg::Ps512 => {
                    let key = rsa::pss::VerifyingKey::<sha2::Sha512>::new(public_key);
                    let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
                    key.verify(data, &signature).map_err(bad)
                }
                _ => unreachable!("outer match already restricted this arm to the PSS algorithms"),
            }
        }
    }
}

fn require_key_type_and_curve(
    actual_kty: i128,
    key: &[(Value, Value)],
    expected_kty: i128,
    expected_curve: i128,
) -> Result<(), CryptoError> {
    if actual_kty != expected_kty || required_integer(key, -1, "COSE_Key curve")? != expected_curve
    {
        return Err(CryptoError::KeyParse(
            "COSE_Key type or curve does not match algorithm".into(),
        ));
    }
    Ok(())
}

fn ec_point(key: &[(Value, Value)], coordinate_length: usize) -> Result<Vec<u8>, CryptoError> {
    let x = required_bytes(key, -2, "COSE_Key x")?;
    let y = required_bytes(key, -3, "COSE_Key y")?;
    if x.len() != coordinate_length || y.len() != coordinate_length {
        return Err(CryptoError::KeyParse(
            "COSE_Key EC coordinate length does not match curve".into(),
        ));
    }
    let mut point = Vec::with_capacity(1 + coordinate_length * 2);
    point.push(4);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
}

fn required_integer(map: &[(Value, Value)], label: i128, name: &str) -> Result<i128, CryptoError> {
    let values = integer_values(map, label);
    match values.as_slice() {
        [Value::Integer(value)] => Ok(*value),
        [_] => Err(CryptoError::Malformed(format!("{name} is not an integer"))),
        [] => Err(CryptoError::Malformed(format!("missing {name}"))),
        _ => Err(CryptoError::Malformed(format!("duplicate {name}"))),
    }
}

fn required_bytes<'a>(
    map: &'a [(Value, Value)],
    label: i128,
    name: &str,
) -> Result<&'a [u8], CryptoError> {
    match optional_unique_bytes(map, label, name)? {
        Some(bytes) if !bytes.is_empty() => Ok(bytes),
        Some(_) => Err(CryptoError::Malformed(format!("{name} is empty"))),
        None => Err(CryptoError::Malformed(format!("missing {name}"))),
    }
}

fn optional_unique_bytes<'a>(
    map: &'a [(Value, Value)],
    label: i128,
    name: &str,
) -> Result<Option<&'a [u8]>, CryptoError> {
    let values = integer_values(map, label);
    match values.as_slice() {
        [Value::Bytes(bytes)] => Ok(Some(bytes)),
        [_] => Err(CryptoError::Malformed(format!("{name} is not bytes"))),
        [] => Ok(None),
        _ => Err(CryptoError::Malformed(format!("duplicate {name}"))),
    }
}

fn integer_values(map: &[(Value, Value)], label: i128) -> Vec<&Value> {
    map.iter()
        .filter_map(|(key, value)| matches!(key, Value::Integer(n) if *n == label).then_some(value))
        .collect()
}

fn cose_array(value: &Value) -> Result<&[Value], CryptoError> {
    match value {
        Value::Tag(COSE_SIGN1_TAG, inner) => match inner.as_ref() {
            Value::Array(items) if items.len() == 4 => Ok(items),
            _ => Err(CryptoError::Malformed(
                "tag 18 content is not a 4-element array".into(),
            )),
        },
        Value::Array(items) if items.len() == 4 => Ok(items),
        _ => Err(CryptoError::Malformed("not a COSE_Sign1 structure".into())),
    }
}
