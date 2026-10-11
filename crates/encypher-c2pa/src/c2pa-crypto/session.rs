// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE_Key verification for C2PA live-video session keys.
//!
//! Verification only. A session key is read, never minted: this module has no
//! signer and no key generation, so nothing here can produce a signature.

use crate::c2pa_cbor::{decode, encode, Profile, Value};

use super::{ClaimAlgorithmList, CoseAlg, CryptoError};
use crate::c2pa_crypto::mldsa::verify_ml_dsa;

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

/// Verify an embedded COSE_Sign1 with a serialized COSE_Key under the C2PA
/// 2.4 algorithm list.
///
/// The protected `alg` must equal the key's `alg`; algorithms are never inferred
/// from coordinate shape. Detached payloads are not accepted for session data.
pub fn verify_with_cose_key(
    cose_sign1: &[u8],
    cose_key: &[u8],
) -> Result<VerifiedCoseKeySignature, CryptoError> {
    verify_with_cose_key_with(cose_sign1, cose_key, ClaimAlgorithmList::V2_4)
}

/// [`verify_with_cose_key`] under an explicit revision's algorithm list.
///
/// C2PA session keys may use any algorithm allowed for claim signing
/// (Live Media, Session Keys), so the 2.5 list adds ESP256/384/512 keys
/// (`kty` EC2 on the bound curve) and ML-DSA-44/65/87 keys (`kty` AKP with a
/// `pub` of the parameter set's exact length and no `priv`, RFC 9964).
pub fn verify_with_cose_key_with(
    cose_sign1: &[u8],
    cose_key: &[u8],
    list: ClaimAlgorithmList,
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
    let algorithm = list.algorithm(alg_id)?;
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
        CoseAlg::Es256 | CoseAlg::Esp256 => {
            require_key_type_and_curve(kty, key, 2, 1)?;
            let point = ec_point(key, 32)?;
            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(&sha2::Sha256::digest(data), &signature)
                .map_err(bad)
        }
        CoseAlg::Es384 | CoseAlg::Esp384 => {
            require_key_type_and_curve(kty, key, 2, 2)?;
            let point = ec_point(key, 48)?;
            let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|error| CryptoError::KeyParse(error.to_string()))?;
            let signature = p384::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(&sha2::Sha384::digest(data), &signature)
                .map_err(bad)
        }
        CoseAlg::Es512 | CoseAlg::Esp512 => {
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
        CoseAlg::MlDsa44 | CoseAlg::MlDsa65 | CoseAlg::MlDsa87 => {
            if kty != COSE_KTY_AKP {
                return Err(CryptoError::KeyParse(
                    "ML-DSA algorithm requires kty 7 (AKP)".into(),
                ));
            }
            if !integer_values(key, -2).is_empty() {
                return Err(CryptoError::KeyParse(
                    "a public AKP COSE_Key must not carry priv".into(),
                ));
            }
            let public_key = required_bytes(key, -1, "COSE_Key pub")?;
            verify_ml_dsa(alg, public_key, data, signature)
        }
    }
}

/// RFC 9964 Algorithm Key Pair key type.
const COSE_KTY_AKP: i128 = 7;

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

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: Profile = Profile::LegacyPipelineBDefinite;

    fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
        encode(
            &Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(protected.to_vec()),
                Value::Bytes(Vec::new()),
                Value::Bytes(payload.to_vec()),
            ]),
            PROFILE,
        )
        .expect("Sig_structure")
    }

    /// An ESP256 session key and an embedded-payload segment signature.
    fn esp256_session(curve_label: i128) -> (Vec<u8>, Vec<u8>) {
        use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

        let key = SigningKey::from_slice(&[0x5e; 32]).expect("session key");
        let point = key.verifying_key().to_encoded_point(false);
        let cose_key = encode(
            &Value::Map(vec![
                (Value::Integer(1), Value::Integer(2)),
                (Value::Integer(2), Value::Bytes(b"esp-session".to_vec())),
                (Value::Integer(3), Value::Integer(-9)),
                (Value::Integer(-1), Value::Integer(curve_label)),
                (
                    Value::Integer(-2),
                    Value::Bytes(point.x().expect("x").to_vec()),
                ),
                (
                    Value::Integer(-3),
                    Value::Bytes(point.y().expect("y").to_vec()),
                ),
            ]),
            PROFILE,
        )
        .expect("COSE_Key");
        let protected = encode(
            &Value::Map(vec![(Value::Integer(1), Value::Integer(-9))]),
            PROFILE,
        )
        .expect("protected");
        let payload = b"segment-info-map".to_vec();
        let signature: Signature = key.sign(&sig_structure(&protected, &payload));
        let cose = encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(vec![(
                        Value::Integer(4),
                        Value::Bytes(b"esp-session".to_vec()),
                    )]),
                    Value::Bytes(payload),
                    Value::Bytes(signature.to_bytes().to_vec()),
                ])),
            ),
            PROFILE,
        )
        .expect("COSE_Sign1");
        (cose, cose_key)
    }

    #[test]
    fn esp_session_keys_verify_only_under_the_2_5_list() {
        let (cose, key) = esp256_session(1);
        let verified =
            verify_with_cose_key_with(&cose, &key, ClaimAlgorithmList::V2_5).expect("ESP256");
        assert_eq!(verified.algorithm, CoseAlg::Esp256);
        assert_eq!(verified.payload, b"segment-info-map");
        assert!(matches!(
            verify_with_cose_key(&cose, &key),
            Err(CryptoError::UnsupportedAlg(-9))
        ));

        // The same key labelled as P-384 contradicts ESP256's bound curve.
        let (cose, wrong_curve) = esp256_session(2);
        assert!(matches!(
            verify_with_cose_key_with(&cose, &wrong_curve, ClaimAlgorithmList::V2_5),
            Err(CryptoError::KeyParse(_))
        ));
    }

    struct Rfc9964 {
        alg: CoseAlg,
        public_key: &'static [u8],
        sign1: &'static [u8],
        to_be_signed: &'static [u8],
    }

    const RFC9964: [Rfc9964; 3] = [
        Rfc9964 {
            alg: CoseAlg::MlDsa44,
            public_key: include_bytes!("fixtures/ml_dsa_44_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_44_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_44_rfc9964.tbs"),
        },
        Rfc9964 {
            alg: CoseAlg::MlDsa65,
            public_key: include_bytes!("fixtures/ml_dsa_65_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_65_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_65_rfc9964.tbs"),
        },
        Rfc9964 {
            alg: CoseAlg::MlDsa87,
            public_key: include_bytes!("fixtures/ml_dsa_87_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_87_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_87_rfc9964.tbs"),
        },
    ];

    /// The public half of the RFC 9964 Appendix A.2 AKP COSE_Key.
    fn akp_key(vector: &Rfc9964, kty: i128, with_priv: bool) -> Vec<(Value, Value)> {
        let mut key = vec![
            (Value::Integer(1), Value::Integer(kty)),
            (Value::Integer(3), Value::Integer(vector.alg.cose_id())),
            (Value::Integer(-1), Value::Bytes(vector.public_key.to_vec())),
        ];
        if with_priv {
            key.push((Value::Integer(-2), Value::Bytes(vec![0; 32])));
        }
        key
    }

    fn rfc_signature(vector: &Rfc9964) -> Vec<u8> {
        let decoded = decode(vector.sign1).expect("RFC COSE_Sign1");
        cose_array(&decoded).expect("array")[3]
            .as_bytes()
            .expect("signature")
            .to_vec()
    }

    #[test]
    fn akp_session_keys_verify_rfc9964_ml_dsa_signatures() {
        for vector in &RFC9964 {
            let signature = rfc_signature(vector);
            let key = akp_key(vector, COSE_KTY_AKP, false);
            verify_key_signature(vector.alg, &key, vector.to_be_signed, &signature)
                .unwrap_or_else(|e| panic!("{:?} AKP key must verify: {e}", vector.alg));

            let mut tampered = vector.to_be_signed.to_vec();
            tampered[20] ^= 0x01;
            assert!(matches!(
                verify_key_signature(vector.alg, &key, &tampered, &signature),
                Err(CryptoError::Verify(_))
            ));
            assert!(matches!(
                verify_key_signature(
                    vector.alg,
                    &akp_key(vector, COSE_KTY_AKP, true),
                    vector.to_be_signed,
                    &signature
                ),
                Err(CryptoError::KeyParse(_))
            ));
            assert!(matches!(
                verify_key_signature(
                    vector.alg,
                    &akp_key(vector, 2, false),
                    vector.to_be_signed,
                    &signature
                ),
                Err(CryptoError::KeyParse(_))
            ));
        }
    }

    #[test]
    fn ml_dsa_session_signatures_follow_the_list_and_unprotected_kid_rules() {
        let vector = &RFC9964[0];
        let key = encode(&Value::Map(akp_key(vector, COSE_KTY_AKP, false)), PROFILE).expect("key");
        assert!(matches!(
            verify_with_cose_key(vector.sign1, &key),
            Err(CryptoError::UnsupportedAlg(-48))
        ));
        // The RFC example protects its kid; a C2PA segment signature carries
        // the session key identifier in the unprotected bucket.
        assert!(matches!(
            verify_with_cose_key_with(vector.sign1, &key, ClaimAlgorithmList::V2_5),
            Err(CryptoError::Malformed(_))
        ));
    }
}
