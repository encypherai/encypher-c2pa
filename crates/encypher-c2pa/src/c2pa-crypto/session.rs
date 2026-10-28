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

/// Verify an embedded COSE_Sign1 with a serialized COSE_Key under an explicit
/// revision's algorithm list.
///
/// The protected `alg` (label 1) is authoritative: it selects the verification
/// algorithm and is never inferred from coordinate shape. C2PA 2.4 session keys
/// need only a `kid`, so the COSE_Key `alg` (label 3) is optional; when present
/// it must be a single integer equal to the protected `alg`. An EC2 key's curve
/// comes from its `crv` and the ECDSA digest from the protected `alg`, so every
/// P-256/P-384/P-521 key verifies ES256, ES384 and ES512, as C2PA requires and
/// as the certificate verifier accepts. Detached payloads are not accepted for
/// session data.
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
    if let Some(key_alg) = optional_integer(key, 3, "COSE_Key alg")? {
        if key_alg != alg_id {
            return Err(CryptoError::Verify(
                "signature algorithm does not match COSE_Key alg".into(),
            ));
        }
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
    use signature::Verifier as _;

    // RSA and Ed25519 errors are `signature` 2 types; ECDSA (`signature` 3 via
    // ecdsa 0.17) is mapped in `verify_ecdsa`. All become the same failure.
    fn bad(error: impl std::fmt::Display) -> CryptoError {
        CryptoError::Verify(error.to_string())
    }

    let kty = required_integer(key, 1, "COSE_Key kty")?;
    match alg {
        CoseAlg::Es256 => verify_ecdsa(kty, key, &sha2::Sha256::digest(data), signature, None),
        CoseAlg::Es384 => verify_ecdsa(kty, key, &sha2::Sha384::digest(data), signature, None),
        CoseAlg::Es512 => verify_ecdsa(kty, key, &sha2::Sha512::digest(data), signature, None),
        CoseAlg::Esp256 => verify_ecdsa(kty, key, &sha2::Sha256::digest(data), signature, Some(1)),
        CoseAlg::Esp384 => verify_ecdsa(kty, key, &sha2::Sha384::digest(data), signature, Some(2)),
        CoseAlg::Esp512 => verify_ecdsa(kty, key, &sha2::Sha512::digest(data), signature, Some(3)),
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

/// Verify ECDSA with the protected algorithm's digest and the key's curve.
/// ESP requires its designated curve. Both ES and ESP require fixed-width
/// COSE signatures.
fn verify_ecdsa(
    kty: i128,
    key: &[(Value, Value)],
    digest: &[u8],
    signature: &[u8],
    required_curve: Option<i128>,
) -> Result<(), CryptoError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;

    fn bad(error: impl std::fmt::Display) -> CryptoError {
        CryptoError::Verify(error.to_string())
    }
    fn key_err(error: impl std::fmt::Display) -> CryptoError {
        CryptoError::KeyParse(error.to_string())
    }

    if kty != 2 {
        return Err(CryptoError::KeyParse(
            "ECDSA algorithm requires COSE_Key kty 2".into(),
        ));
    }
    let curve = required_integer(key, -1, "COSE_Key curve")?;
    if required_curve.is_some_and(|required| required != curve) {
        return Err(CryptoError::KeyParse(
            "COSE_Key type or curve does not match algorithm".into(),
        ));
    }
    match curve {
        1 => {
            let point = ec_point(key, 32)?;
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(key_err)?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
        2 => {
            let point = ec_point(key, 48)?;
            let verifying_key =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(key_err)?;
            let signature = p384::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
        3 => {
            let point = ec_point(key, 66)?;
            let verifying_key =
                p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(key_err)?;
            let signature = p521::ecdsa::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(digest, &signature)
                .map_err(bad)
        }
        curve => Err(CryptoError::KeyParse(format!(
            "unsupported COSE_Key EC curve {curve}"
        ))),
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
    optional_integer(map, label, name)?
        .ok_or_else(|| CryptoError::Malformed(format!("missing {name}")))
}

fn optional_integer(
    map: &[(Value, Value)],
    label: i128,
    name: &str,
) -> Result<Option<i128>, CryptoError> {
    let values = integer_values(map, label);
    match values.as_slice() {
        [Value::Integer(value)] => Ok(Some(*value)),
        [_] => Err(CryptoError::Malformed(format!("{name} is not an integer"))),
        [] => Ok(None),
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
        let point = key.verifying_key().to_sec1_point(false);
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
            verify_with_cose_key_with(&cose, &key, ClaimAlgorithmList::V2_4),
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
            verify_with_cose_key_with(vector.sign1, &key, ClaimAlgorithmList::V2_4),
            Err(CryptoError::UnsupportedAlg(-48))
        ));
        // The RFC example protects its kid; a C2PA segment signature carries
        // the session key identifier in the unprotected bucket.
        assert!(matches!(
            verify_with_cose_key_with(vector.sign1, &key, ClaimAlgorithmList::V2_5),
            Err(CryptoError::Malformed(_))
        ));
    }

    const KID: &[u8] = b"session-key-0001";
    const PAYLOAD: &[u8] = b"segment info";
    const ECDSA: [CoseAlg; 3] = [CoseAlg::Es256, CoseAlg::Es384, CoseAlg::Es512];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Curve {
        P256,
        P384,
        P521,
    }

    const CURVES: [Curve; 3] = [Curve::P256, Curve::P384, Curve::P521];

    impl Curve {
        fn crv(self) -> i128 {
            match self {
                Curve::P256 => 1,
                Curve::P384 => 2,
                Curve::P521 => 3,
            }
        }

        fn coordinate_len(self) -> usize {
            match self {
                Curve::P256 => 32,
                Curve::P384 => 48,
                Curve::P521 => 66,
            }
        }

        /// A fixed private scalar below every curve order, so signatures are
        /// deterministic (RFC 6979) and failures reproduce.
        fn secret(self) -> Vec<u8> {
            let mut scalar = vec![0x5a; self.coordinate_len()];
            if self == Curve::P521 {
                scalar[0] = 0x01;
            }
            scalar
        }

        /// Uncompressed SEC1 public point: 0x04 || X || Y.
        fn public_point(self) -> Vec<u8> {
            let secret = self.secret();
            match self {
                Curve::P256 => p256::ecdsa::SigningKey::from_slice(&secret)
                    .expect("P-256 scalar")
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
                Curve::P384 => p384::ecdsa::SigningKey::from_slice(&secret)
                    .expect("P-384 scalar")
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
                Curve::P521 => p521::ecdsa::SigningKey::from_slice(&secret)
                    .expect("P-521 scalar")
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec(),
            }
        }

        /// Sign `data` with this curve's key over the digest `digest_alg` names.
        fn sign(self, digest_alg: CoseAlg, data: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::hazmat::PrehashSigner as _;
            use sha2::Digest as _;

            let digest = match digest_alg {
                CoseAlg::Es256 | CoseAlg::Esp256 => sha2::Sha256::digest(data).to_vec(),
                CoseAlg::Es384 | CoseAlg::Esp384 => sha2::Sha384::digest(data).to_vec(),
                CoseAlg::Es512 | CoseAlg::Esp512 => sha2::Sha512::digest(data).to_vec(),
                other => panic!("{other:?} is not an ECDSA algorithm"),
            };
            let secret = self.secret();
            match self {
                Curve::P256 => {
                    let key = p256::ecdsa::SigningKey::from_slice(&secret).expect("P-256 key");
                    let signature: p256::ecdsa::Signature =
                        key.sign_prehash(&digest).expect("P-256 sign");
                    signature.to_bytes().to_vec()
                }
                Curve::P384 => {
                    let key = p384::ecdsa::SigningKey::from_slice(&secret).expect("P-384 key");
                    let signature: p384::ecdsa::Signature =
                        key.sign_prehash(&digest).expect("P-384 sign");
                    signature.to_bytes().to_vec()
                }
                Curve::P521 => {
                    let key = p521::ecdsa::SigningKey::from_slice(&secret).expect("P-521 key");
                    let signature: p521::ecdsa::Signature =
                        key.sign_prehash(&digest).expect("P-521 sign");
                    signature.to_bytes().to_vec()
                }
            }
        }
    }

    fn cbor(value: &Value) -> Vec<u8> {
        encode(value, Profile::LegacyPipelineBDefinite).expect("encode CBOR")
    }

    /// An EC2 COSE_Key; `alg_entries` are appended verbatim as label 3 values,
    /// so a test can omit `alg`, mistype it, or repeat it.
    fn ec_cose_key(curve: Curve, kty: i128, crv: i128, alg_entries: &[Value]) -> Vec<u8> {
        let point = curve.public_point();
        let split = 1 + curve.coordinate_len();
        let mut map = vec![
            (Value::Integer(1), Value::Integer(kty)),
            (Value::Integer(2), Value::Bytes(KID.to_vec())),
        ];
        map.extend(
            alg_entries
                .iter()
                .map(|alg| (Value::Integer(3), alg.clone())),
        );
        map.extend([
            (Value::Integer(-1), Value::Integer(crv)),
            (Value::Integer(-2), Value::Bytes(point[1..split].to_vec())),
            (Value::Integer(-3), Value::Bytes(point[split..].to_vec())),
        ]);
        cbor(&Value::Map(map))
    }

    /// A tagged COSE_Sign1 whose protected header names `protected_alg`. The
    /// signature covers `signed_payload`; the message carries
    /// `carried_payload`, which differs only in tamper tests.
    fn session_sign1(
        protected_alg: CoseAlg,
        signed_payload: &[u8],
        carried_payload: &[u8],
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let protected = cbor(&Value::Map(vec![(
            Value::Integer(1),
            Value::Integer(protected_alg.cose_id()),
        )]));
        let to_be_signed = cbor(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(signed_payload.to_vec()),
        ]));
        let signature = sign(&to_be_signed);
        cbor(&Value::Tag(
            COSE_SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![(Value::Integer(4), Value::Bytes(KID.to_vec()))]),
                Value::Bytes(carried_payload.to_vec()),
                Value::Bytes(signature),
            ])),
        ))
    }

    fn ecdsa_sign1(curve: Curve, alg: CoseAlg) -> Vec<u8> {
        session_sign1(alg, PAYLOAD, PAYLOAD, |data| curve.sign(alg, data))
    }

    #[test]
    fn every_ec_curve_verifies_every_ecdsa_algorithm_with_and_without_key_alg() {
        for curve in CURVES {
            for alg in ECDSA {
                let message = ecdsa_sign1(curve, alg);
                let declared = [Value::Integer(alg.cose_id())];
                for alg_entries in [&declared[..], &[]] {
                    let key = ec_cose_key(curve, 2, curve.crv(), alg_entries);
                    let verified =
                        verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4)
                            .unwrap_or_else(|error| {
                                panic!("{curve:?} {alg:?} key alg {alg_entries:?}: {error}")
                            });
                    assert_eq!(verified.algorithm, alg);
                    assert_eq!(verified.payload, PAYLOAD);
                    assert_eq!(verified.key_id.as_deref(), Some(KID));
                }
            }
        }
    }

    #[test]
    fn tampered_payload_fails_for_every_curve_and_algorithm() {
        for curve in CURVES {
            for alg in ECDSA {
                let message =
                    session_sign1(alg, PAYLOAD, b"segment inf0", |data| curve.sign(alg, data));
                for alg_entries in [&[Value::Integer(alg.cose_id())][..], &[]] {
                    let key = ec_cose_key(curve, 2, curve.crv(), alg_entries);
                    assert!(
                        matches!(
                            verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4),
                            Err(CryptoError::Verify(_))
                        ),
                        "{curve:?} {alg:?} accepted a tampered payload"
                    );
                }
            }
        }
    }

    #[test]
    fn protected_alg_selects_the_digest() {
        // A P-384 signature over the SHA-256 digest must not verify when the
        // protected header claims ES384 or ES512, with or without key alg.
        for claimed in [CoseAlg::Es384, CoseAlg::Es512] {
            let message = session_sign1(claimed, PAYLOAD, PAYLOAD, |data| {
                Curve::P384.sign(CoseAlg::Es256, data)
            });
            let key = ec_cose_key(Curve::P384, 2, 2, &[]);
            assert!(
                matches!(
                    verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4),
                    Err(CryptoError::Verify(_))
                ),
                "SHA-256 signature verified under protected {claimed:?}"
            );
        }
    }

    #[test]
    fn explicit_key_alg_must_equal_protected_alg() {
        let message = ecdsa_sign1(Curve::P256, CoseAlg::Es256);
        for conflicting in [
            CoseAlg::Es384,
            CoseAlg::Es512,
            CoseAlg::EdDsa,
            CoseAlg::Ps256,
        ] {
            let key = ec_cose_key(Curve::P256, 2, 1, &[Value::Integer(conflicting.cose_id())]);
            match verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4) {
                Err(CryptoError::Verify(reason)) => {
                    assert_eq!(reason, "signature algorithm does not match COSE_Key alg")
                }
                other => panic!("key alg {conflicting:?} was not rejected: {other:?}"),
            }
        }
        // An unregistered key alg conflicts as well.
        let key = ec_cose_key(Curve::P256, 2, 1, &[Value::Integer(-65_535)]);
        assert!(matches!(
            verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4),
            Err(CryptoError::Verify(_))
        ));
    }

    #[test]
    fn mistyped_or_duplicate_key_alg_is_malformed() {
        let message = ecdsa_sign1(Curve::P256, CoseAlg::Es256);
        let es256 = Value::Integer(CoseAlg::Es256.cose_id());
        for (alg_entries, expected) in [
            (
                vec![Value::Text("ES256".into())],
                "COSE_Key alg is not an integer",
            ),
            (
                vec![Value::Bytes(vec![0x26])],
                "COSE_Key alg is not an integer",
            ),
            (vec![es256.clone(), es256.clone()], "duplicate COSE_Key alg"),
            (
                vec![es256, Value::Integer(CoseAlg::Es384.cose_id())],
                "duplicate COSE_Key alg",
            ),
        ] {
            let key = ec_cose_key(Curve::P256, 2, 1, &alg_entries);
            match verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4) {
                Err(CryptoError::Malformed(reason)) => assert_eq!(reason, expected),
                other => panic!("key alg {alg_entries:?} was not rejected: {other:?}"),
            }
        }
    }

    #[test]
    fn ec_key_type_curve_and_coordinates_are_enforced() {
        let message = ecdsa_sign1(Curve::P256, CoseAlg::Es256);
        // OKP key type with an ECDSA protected alg.
        let key = ec_cose_key(Curve::P256, 1, 1, &[]);
        assert!(matches!(
            verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4),
            Err(CryptoError::KeyParse(_))
        ));
        // Ed25519 and unregistered curves are not ECDSA curves.
        for crv in [6, 4, 0] {
            let key = ec_cose_key(Curve::P256, 2, crv, &[]);
            match verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4) {
                Err(CryptoError::KeyParse(reason)) => {
                    assert_eq!(reason, format!("unsupported COSE_Key EC curve {crv}"))
                }
                other => panic!("crv {crv} was not rejected: {other:?}"),
            }
        }
        // P-256 coordinates labelled as P-384 or P-521 fail the length check.
        for crv in [2, 3] {
            let key = ec_cose_key(Curve::P256, 2, crv, &[]);
            match verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4) {
                Err(CryptoError::KeyParse(reason)) => {
                    assert_eq!(reason, "COSE_Key EC coordinate length does not match curve")
                }
                other => panic!("crv {crv} with P-256 coordinates: {other:?}"),
            }
        }
        // The right curve label with another key's point fails verification.
        let key = ec_cose_key(Curve::P384, 2, 2, &[]);
        assert!(matches!(
            verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_4),
            Err(CryptoError::Verify(_))
        ));
    }

    #[test]
    fn ed25519_session_key_keeps_okp_checks_and_optional_alg() {
        use ed25519_dalek::Signer as _;

        let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let message = session_sign1(CoseAlg::EdDsa, PAYLOAD, PAYLOAD, |data| {
            signing.sign(data).to_bytes().to_vec()
        });
        let okp_key = |kty: i128, crv: i128, alg_entries: &[Value]| {
            let mut map = vec![
                (Value::Integer(1), Value::Integer(kty)),
                (Value::Integer(2), Value::Bytes(KID.to_vec())),
            ];
            map.extend(
                alg_entries
                    .iter()
                    .map(|alg| (Value::Integer(3), alg.clone())),
            );
            map.extend([
                (Value::Integer(-1), Value::Integer(crv)),
                (
                    Value::Integer(-2),
                    Value::Bytes(signing.verifying_key().to_bytes().to_vec()),
                ),
            ]);
            cbor(&Value::Map(map))
        };
        for alg_entries in [&[Value::Integer(CoseAlg::EdDsa.cose_id())][..], &[]] {
            let verified = verify_with_cose_key_with(
                &message,
                &okp_key(1, 6, alg_entries),
                ClaimAlgorithmList::V2_4,
            )
            .expect("Ed25519 session signature");
            assert_eq!(verified.algorithm, CoseAlg::EdDsa);
        }
        for (kty, crv) in [(2, 6), (1, 1)] {
            assert!(matches!(
                verify_with_cose_key_with(
                    &message,
                    &okp_key(kty, crv, &[]),
                    ClaimAlgorithmList::V2_4
                ),
                Err(CryptoError::KeyParse(_))
            ));
        }
        let tampered = session_sign1(CoseAlg::EdDsa, PAYLOAD, b"segment inf0", |data| {
            signing.sign(data).to_bytes().to_vec()
        });
        assert!(matches!(
            verify_with_cose_key_with(&tampered, &okp_key(1, 6, &[]), ClaimAlgorithmList::V2_4),
            Err(CryptoError::Verify(_))
        ));
    }

    #[test]
    fn esp_sessions_bind_real_keys_to_curves_and_explicit_profiles() {
        for (alg, required) in [
            (CoseAlg::Esp256, Curve::P256),
            (CoseAlg::Esp384, Curve::P384),
            (CoseAlg::Esp512, Curve::P521),
        ] {
            for curve in CURVES {
                let message = ecdsa_sign1(curve, alg);
                for entries in [&[Value::Integer(alg.cose_id())][..], &[]] {
                    let key = ec_cose_key(curve, 2, curve.crv(), entries);
                    let result =
                        verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_5);
                    if curve == required {
                        assert_eq!(result.expect("bound ESP key").algorithm, alg);
                    } else {
                        assert!(matches!(result, Err(CryptoError::KeyParse(_))));
                    }
                    for list in [ClaimAlgorithmList::V2_2, ClaimAlgorithmList::V2_4] {
                        assert!(matches!(
                            verify_with_cose_key_with(&message, &key, list),
                            Err(CryptoError::UnsupportedAlg(id)) if id == alg.cose_id()
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn legacy_mixed_curve_sessions_remain_valid_under_every_profile() {
        let message = ecdsa_sign1(Curve::P384, CoseAlg::Es256);
        let key = ec_cose_key(Curve::P384, 2, 2, &[]);
        for list in [
            ClaimAlgorithmList::V2_2,
            ClaimAlgorithmList::V2_4,
            ClaimAlgorithmList::V2_5,
        ] {
            verify_with_cose_key_with(&message, &key, list).expect("legacy ES256/P-384");
        }
    }

    #[test]
    fn session_ecdsa_requires_fixed_width_signatures_for_legacy_and_esp() {
        for (curve, alg) in [
            (Curve::P256, CoseAlg::Es256),
            (Curve::P256, CoseAlg::Esp256),
            (Curve::P384, CoseAlg::Es384),
            (Curve::P384, CoseAlg::Esp384),
            (Curve::P521, CoseAlg::Es512),
            (Curve::P521, CoseAlg::Esp512),
        ] {
            let key = ec_cose_key(curve, 2, curve.crv(), &[]);
            let fixed_width = ecdsa_sign1(curve, alg);
            verify_with_cose_key_with(&fixed_width, &key, ClaimAlgorithmList::V2_5)
                .expect("fixed-width session signature");
            let message = session_sign1(alg, PAYLOAD, PAYLOAD, |data| {
                let raw = curve.sign(alg, data);
                match curve {
                    Curve::P256 => p256::ecdsa::Signature::from_slice(&raw)
                        .expect("P-256 signature")
                        .to_der()
                        .as_bytes()
                        .to_vec(),
                    Curve::P384 => p384::ecdsa::Signature::from_slice(&raw)
                        .expect("P-384 signature")
                        .to_der()
                        .as_bytes()
                        .to_vec(),
                    Curve::P521 => p521::ecdsa::Signature::from_slice(&raw)
                        .expect("P-521 signature")
                        .to_der()
                        .as_bytes()
                        .to_vec(),
                }
            });
            assert!(matches!(
                verify_with_cose_key_with(&message, &key, ClaimAlgorithmList::V2_5),
                Err(CryptoError::Verify(_))
            ));
        }
    }
}
