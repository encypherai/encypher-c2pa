// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA (FIPS 204) verification for COSE (RFC 9964) and X.509 (RFC 9881).
//!
//! Every ML-DSA use C2PA admits is the pure signing mode with an empty
//! context string: RFC 9964 section 5 for COSE signatures and RFC 9881
//! section 3 for certificates. HashML-DSA is not registered for either and is
//! never attempted. The lattice arithmetic is RustCrypto's `ml-dsa` crate;
//! this module only selects the parameter set and enforces the encodings.

use ::ml_dsa::{
    EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, VerifyingKey,
};
use spki::ObjectIdentifier;

use crate::c2pa_crypto::alg::CoseAlg;
use crate::c2pa_crypto::error::CryptoError;

/// RFC 9881 `id-ml-dsa-44`.
const ID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
/// RFC 9881 `id-ml-dsa-65`.
const ID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
/// RFC 9881 `id-ml-dsa-87`.
const ID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// The ML-DSA COSE algorithm an RFC 9881 OID names, if it names one.
pub(crate) fn ml_dsa_alg_for_oid(oid: &ObjectIdentifier) -> Option<CoseAlg> {
    match *oid {
        ID_ML_DSA_44 => Some(CoseAlg::MlDsa44),
        ID_ML_DSA_65 => Some(CoseAlg::MlDsa65),
        ID_ML_DSA_87 => Some(CoseAlg::MlDsa87),
        _ => None,
    }
}

/// FIPS 204 Table 2 encoded public-key length, for ML-DSA algorithms only.
pub(crate) fn ml_dsa_public_key_len(alg: CoseAlg) -> Option<usize> {
    match alg {
        CoseAlg::MlDsa44 => Some(1312),
        CoseAlg::MlDsa65 => Some(1952),
        CoseAlg::MlDsa87 => Some(2592),
        _ => None,
    }
}

/// FIPS 204 Table 2 encoded signature length, for ML-DSA algorithms only.
pub(crate) fn ml_dsa_signature_len(alg: CoseAlg) -> Option<usize> {
    match alg {
        CoseAlg::MlDsa44 => Some(2420),
        CoseAlg::MlDsa65 => Some(3309),
        CoseAlg::MlDsa87 => Some(4627),
        _ => None,
    }
}

/// Read an RFC 9881 ML-DSA `SubjectPublicKeyInfo`.
///
/// Returns the parameter set and the raw FIPS 204 `pkEncode` bytes. The
/// AlgorithmIdentifier parameters must be absent (RFC 9881 section 2, C2PA
/// 2.5 certificate profile), the BIT STRING must have no unused bits, and the
/// key must have the exact length of its parameter set.
pub(crate) fn ml_dsa_public_key_from_spki(
    spki_der: &[u8],
) -> Result<(CoseAlg, &[u8]), CryptoError> {
    let info = spki::SubjectPublicKeyInfoRef::try_from(spki_der)
        .map_err(|e| CryptoError::CertParse(format!("SPKI parse failed: {e}")))?;
    let alg = ml_dsa_alg_for_oid(&info.algorithm.oid).ok_or_else(|| {
        CryptoError::CertParse(format!(
            "public key algorithm {} is not ML-DSA",
            info.algorithm.oid
        ))
    })?;
    if info.algorithm.parameters.is_some() {
        return Err(CryptoError::CertParse(
            "ML-DSA SubjectPublicKeyInfo parameters must be absent".into(),
        ));
    }
    let public_key = info.subject_public_key.as_bytes().ok_or_else(|| {
        CryptoError::CertParse("ML-DSA public key bit string has unused bits".into())
    })?;
    let expected = ml_dsa_public_key_len(alg).ok_or(CryptoError::UnsupportedAlg(alg.cose_id()))?;
    if public_key.len() != expected {
        return Err(CryptoError::CertParse(format!(
            "{} public key is {} bytes; {expected} required",
            alg.iana_name(),
            public_key.len()
        )));
    }
    Ok((alg, public_key))
}

/// The ML-DSA parameter set of an RFC 9881 `SubjectPublicKeyInfo`, after
/// checking its OID, absent parameters and exact key length.
///
/// The trust layer uses this to apply the C2PA 2.5 certificate-profile
/// public-key rule without re-implementing the encoding checks.
pub fn ml_dsa_spki_alg(spki_der: &[u8]) -> Result<CoseAlg, CryptoError> {
    ml_dsa_public_key_from_spki(spki_der).map(|(alg, _)| alg)
}

/// Verify a pure-mode ML-DSA signature with an empty context string.
///
/// `alg` selects the parameter set; the public key and signature must have
/// that set's exact encoded lengths. Any other algorithm is refused rather
/// than verified.
pub(crate) fn verify_ml_dsa(
    alg: CoseAlg,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    match alg {
        CoseAlg::MlDsa44 => verify_parameter_set::<MlDsa44>(alg, public_key, message, signature),
        CoseAlg::MlDsa65 => verify_parameter_set::<MlDsa65>(alg, public_key, message, signature),
        CoseAlg::MlDsa87 => verify_parameter_set::<MlDsa87>(alg, public_key, message, signature),
        _ => Err(CryptoError::UnsupportedAlg(alg.cose_id())),
    }
}

fn verify_parameter_set<P: MlDsaParams>(
    alg: CoseAlg,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let encoded = EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| {
        CryptoError::KeyParse(format!(
            "{} public key is {} bytes; {} required",
            alg.iana_name(),
            public_key.len(),
            ml_dsa_public_key_len(alg).unwrap_or_default()
        ))
    })?;
    let verifying_key = VerifyingKey::<P>::decode(&encoded);
    if Some(signature.len()) != ml_dsa_signature_len(alg) {
        return Err(CryptoError::Verify(format!(
            "{} signature is {} bytes; {} required",
            alg.iana_name(),
            signature.len(),
            ml_dsa_signature_len(alg).unwrap_or_default()
        )));
    }
    // `try_from` rejects a malformed hint encoding or an out-of-range `z`
    // (FIPS 204 sigDecode and the verification norm check).
    let signature = Signature::<P>::try_from(signature)
        .map_err(|_| CryptoError::Verify(format!("malformed {} signature", alg.iana_name())))?;
    if verifying_key.verify_with_context(message, &[], &signature) {
        Ok(())
    } else {
        Err(CryptoError::Verify(format!(
            "{} signature does not verify",
            alg.iana_name()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{decode, Value};

    struct Rfc9964Vector {
        alg: CoseAlg,
        public_key: &'static [u8],
        sign1: &'static [u8],
        to_be_signed: &'static [u8],
    }

    /// RFC 9964 Appendix A.2 COSE examples (all-zero seed). These are an
    /// independent implementation's signatures, not ones this crate made.
    const RFC9964: [Rfc9964Vector; 3] = [
        Rfc9964Vector {
            alg: CoseAlg::MlDsa44,
            public_key: include_bytes!("fixtures/ml_dsa_44_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_44_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_44_rfc9964.tbs"),
        },
        Rfc9964Vector {
            alg: CoseAlg::MlDsa65,
            public_key: include_bytes!("fixtures/ml_dsa_65_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_65_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_65_rfc9964.tbs"),
        },
        Rfc9964Vector {
            alg: CoseAlg::MlDsa87,
            public_key: include_bytes!("fixtures/ml_dsa_87_rfc9964.pub"),
            sign1: include_bytes!("fixtures/ml_dsa_87_rfc9964.sign1"),
            to_be_signed: include_bytes!("fixtures/ml_dsa_87_rfc9964.tbs"),
        },
    ];

    fn signature_of(sign1: &[u8]) -> Vec<u8> {
        match decode(sign1).expect("RFC COSE_Sign1 decodes") {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => items[3].as_bytes().expect("signature").to_vec(),
                _ => panic!("RFC COSE_Sign1 is not an array"),
            },
            _ => panic!("RFC COSE_Sign1 is not tagged"),
        }
    }

    #[test]
    fn rfc9964_signatures_verify_and_reject_every_tamper() {
        for vector in &RFC9964 {
            let signature = signature_of(vector.sign1);
            verify_ml_dsa(
                vector.alg,
                vector.public_key,
                vector.to_be_signed,
                &signature,
            )
            .unwrap_or_else(|e| panic!("{:?} RFC vector must verify: {e}", vector.alg));

            let mut message = vector.to_be_signed.to_vec();
            *message.last_mut().expect("non-empty") ^= 0x01;
            assert!(verify_ml_dsa(vector.alg, vector.public_key, &message, &signature).is_err());

            let mut forged = signature.clone();
            forged[0] ^= 0x01;
            assert!(
                verify_ml_dsa(vector.alg, vector.public_key, vector.to_be_signed, &forged).is_err()
            );

            let mut other_key = vector.public_key.to_vec();
            other_key[40] ^= 0x01;
            assert!(
                verify_ml_dsa(vector.alg, &other_key, vector.to_be_signed, &signature).is_err()
            );
        }
    }

    #[test]
    fn a_parameter_set_never_verifies_another_sets_signature() {
        for vector in &RFC9964 {
            let signature = signature_of(vector.sign1);
            for other in [CoseAlg::MlDsa44, CoseAlg::MlDsa65, CoseAlg::MlDsa87] {
                if other == vector.alg {
                    continue;
                }
                assert!(
                    verify_ml_dsa(other, vector.public_key, vector.to_be_signed, &signature)
                        .is_err(),
                    "{other:?} accepted a {:?} key and signature",
                    vector.alg
                );
            }
            assert!(matches!(
                verify_ml_dsa(
                    CoseAlg::Es256,
                    vector.public_key,
                    vector.to_be_signed,
                    &signature
                ),
                Err(CryptoError::UnsupportedAlg(-7))
            ));
        }
    }

    #[test]
    fn truncated_or_padded_signatures_are_refused_before_decoding() {
        let vector = &RFC9964[0];
        let signature = signature_of(vector.sign1);
        let mut padded = signature.clone();
        padded.push(0);
        for wrong in [
            &signature[..signature.len() - 1],
            padded.as_slice(),
            &[][..],
        ] {
            assert!(matches!(
                verify_ml_dsa(vector.alg, vector.public_key, vector.to_be_signed, wrong),
                Err(CryptoError::Verify(_))
            ));
        }
        assert!(matches!(
            verify_ml_dsa(
                vector.alg,
                &vector.public_key[1..],
                vector.to_be_signed,
                &signature
            ),
            Err(CryptoError::KeyParse(_))
        ));
    }

    #[test]
    fn rfc9881_certificate_keys_parse_with_their_parameter_set() {
        use der::{Decode as _, Encode as _};

        for (cert_der, alg) in [
            (
                &include_bytes!("fixtures/ml_dsa_44_rfc9881_cert.der")[..],
                CoseAlg::MlDsa44,
            ),
            (
                &include_bytes!("fixtures/ml_dsa_65_rfc9881_cert.der")[..],
                CoseAlg::MlDsa65,
            ),
            (
                &include_bytes!("fixtures/ml_dsa_87_rfc9881_cert.der")[..],
                CoseAlg::MlDsa87,
            ),
        ] {
            let certificate =
                x509_cert::Certificate::from_der(cert_der).expect("RFC 9881 certificate");
            let spki = certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("SPKI");
            assert_eq!(ml_dsa_spki_alg(&spki).expect("ML-DSA SPKI"), alg);

            // Parameters present: RFC 9881 requires them absent.
            let mut with_parameters = certificate.tbs_certificate.subject_public_key_info.clone();
            with_parameters.algorithm.parameters =
                Some(der::Any::from(der::AnyRef::from(der::asn1::Null)));
            assert!(ml_dsa_spki_alg(&with_parameters.to_der().expect("SPKI")).is_err());

            // A key one byte short for its declared parameter set.
            let mut short = certificate.tbs_certificate.subject_public_key_info.clone();
            let bytes = short.subject_public_key.raw_bytes().to_vec();
            short.subject_public_key =
                der::asn1::BitString::from_bytes(&bytes[..bytes.len() - 1]).expect("bit string");
            assert!(ml_dsa_spki_alg(&short.to_der().expect("SPKI")).is_err());
        }
    }
}
