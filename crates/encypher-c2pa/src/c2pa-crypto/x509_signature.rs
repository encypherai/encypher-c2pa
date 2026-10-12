// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Signature verification for X.509 structures: certificates, OCSP responses
//! and CMS SignerInfos.
//!
//! These signatures name their algorithm with an ASN.1 AlgorithmIdentifier
//! rather than a COSE `alg`, and encode ECDSA values as DER. The verifier
//! requires the signer's key type to be the one the AlgorithmIdentifier
//! names, so a key is never used with an algorithm it was not issued for
//! (RFC 4055 section 1.2 for RSASSA-PSS keys, RFC 9881 for ML-DSA).
//!
//! Key-size and certificate-profile policy belongs to the trust layer; this
//! module answers only whether the signature is cryptographically valid.

use der::Decode;
use spki::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};

use crate::c2pa_crypto::error::CryptoError;
use crate::c2pa_crypto::mldsa::{ml_dsa_alg_for_oid, ml_dsa_public_key_from_spki, verify_ml_dsa};

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const CURVE_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_digest_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            ID_SHA256 => Some(Hash::Sha256),
            ID_SHA384 => Some(Hash::Sha384),
            ID_SHA512 => Some(Hash::Sha512),
            _ => None,
        }
    }

    fn digest<'a>(self, message: &[u8], output: &'a mut [u8; 64]) -> &'a [u8] {
        use sha2::Digest as _;
        let length = match self {
            Hash::Sha256 => {
                output[..32].copy_from_slice(&sha2::Sha256::digest(message));
                32
            }
            Hash::Sha384 => {
                output[..48].copy_from_slice(&sha2::Sha384::digest(message));
                48
            }
            Hash::Sha512 => {
                output.copy_from_slice(&sha2::Sha512::digest(message));
                64
            }
        };
        &output[..length]
    }
}

/// Verify `signature` over `message` with the key in `signer_spki_der`, under
/// the DER `AlgorithmIdentifier` in `signature_algorithm_der`.
///
/// `message` is the exact signed DER: a `TBSCertificate`, an OCSP
/// `ResponseData`, or CMS signed attributes. Supported pairs:
///
/// - `ecdsa-with-SHA256/384/512` (DER `Ecdsa-Sig-Value`) with an
///   `id-ecPublicKey` key on P-256, P-384 or P-521;
/// - `sha256/384/512WithRSAEncryption` (RSASSA-PKCS1-v1_5) with an
///   `rsaEncryption` key;
/// - `id-RSASSA-PSS` with explicit SHA-256/384/512 parameters, MGF1 over the
///   same hash and trailer field 1, with an `rsaEncryption` key or an
///   `id-RSASSA-PSS` key whose own parameters admit the signature's;
/// - `id-Ed25519` with an Ed25519 key, verified strictly;
/// - `id-ml-dsa-44/65/87` with a key of the same parameter set (pure mode,
///   empty context, RFC 9881 section 3).
///
/// Any other algorithm, absent-but-required parameters, or key/algorithm
/// mismatch is an error; nothing is verified with a guessed algorithm.
pub fn verify_x509_signature(
    signer_spki_der: &[u8],
    signature_algorithm_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let algorithm = AlgorithmIdentifierRef::from_der(signature_algorithm_der).map_err(|e| {
        CryptoError::Malformed(format!("signature AlgorithmIdentifier parse failed: {e}"))
    })?;
    let key = SubjectPublicKeyInfoRef::try_from(signer_spki_der)
        .map_err(|e| CryptoError::CertParse(format!("SPKI parse failed: {e}")))?;

    match algorithm.oid {
        ECDSA_WITH_SHA256 | ECDSA_WITH_SHA384 | ECDSA_WITH_SHA512 => {
            require_absent_parameters(&algorithm)?;
            let hash = match algorithm.oid {
                ECDSA_WITH_SHA256 => Hash::Sha256,
                ECDSA_WITH_SHA384 => Hash::Sha384,
                _ => Hash::Sha512,
            };
            verify_ecdsa(&key, hash, message, signature)
        }
        SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA => {
            require_null_or_absent_parameters(&algorithm)?;
            if key.algorithm.oid != RSA_ENCRYPTION {
                return Err(key_mismatch(&algorithm, &key));
            }
            let public_key = rsa_key(&key)?;
            let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(bad)?;
            match algorithm.oid {
                SHA256_WITH_RSA => verify_with(
                    &rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key),
                    message,
                    &signature,
                ),
                SHA384_WITH_RSA => verify_with(
                    &rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key),
                    message,
                    &signature,
                ),
                _ => verify_with(
                    &rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key),
                    message,
                    &signature,
                ),
            }
        }
        ID_RSASSA_PSS => {
            let (hash, salt_len) = pss_parameters(&algorithm)?;
            if key.algorithm.oid == ID_RSASSA_PSS {
                // RFC 4055 section 1.2: a PSS key's own parameters restrict
                // the hash and MGF and set a minimum salt length.
                if key.algorithm.parameters.is_some() {
                    let (key_hash, key_salt) = pss_parameters(&key.algorithm)?;
                    if key_hash != hash || salt_len < key_salt {
                        return Err(key_mismatch(&algorithm, &key));
                    }
                }
            } else if key.algorithm.oid != RSA_ENCRYPTION {
                return Err(key_mismatch(&algorithm, &key));
            }
            let public_key = rsa_key(&key)?;
            let signature = rsa::pss::Signature::try_from(signature).map_err(bad)?;
            match hash {
                Hash::Sha256 => verify_with(
                    &rsa::pss::VerifyingKey::<sha2::Sha256>::new_with_salt_len(
                        public_key, salt_len,
                    ),
                    message,
                    &signature,
                ),
                Hash::Sha384 => verify_with(
                    &rsa::pss::VerifyingKey::<sha2::Sha384>::new_with_salt_len(
                        public_key, salt_len,
                    ),
                    message,
                    &signature,
                ),
                Hash::Sha512 => verify_with(
                    &rsa::pss::VerifyingKey::<sha2::Sha512>::new_with_salt_len(
                        public_key, salt_len,
                    ),
                    message,
                    &signature,
                ),
            }
        }
        ID_ED25519 => {
            require_absent_parameters(&algorithm)?;
            if key.algorithm.oid != ID_ED25519 || key.algorithm.parameters.is_some() {
                return Err(key_mismatch(&algorithm, &key));
            }
            let raw: [u8; 32] = key
                .subject_public_key
                .as_bytes()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    CryptoError::CertParse("Ed25519 public key is not 32 bytes".into())
                })?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .map_err(|e| CryptoError::CertParse(format!("Ed25519 public key: {e}")))?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(bad)?;
            verifying_key
                .verify_strict(message, &signature)
                .map_err(bad)
        }
        oid => {
            let Some(alg) = ml_dsa_alg_for_oid(&oid) else {
                return Err(CryptoError::UnsupportedSignatureAlgorithm(oid.to_string()));
            };
            require_absent_parameters(&algorithm)?;
            let (key_alg, public_key) = ml_dsa_public_key_from_spki(signer_spki_der)?;
            if key_alg != alg {
                return Err(key_mismatch(&algorithm, &key));
            }
            verify_ml_dsa(alg, public_key, message, signature)
        }
    }
}

fn bad(error: signature::Error) -> CryptoError {
    CryptoError::Verify(error.to_string())
}

fn verify_with<S, V: signature::Verifier<S>>(
    key: &V,
    message: &[u8],
    signature: &S,
) -> Result<(), CryptoError> {
    key.verify(message, signature).map_err(bad)
}

fn key_mismatch(
    algorithm: &AlgorithmIdentifierRef<'_>,
    key: &SubjectPublicKeyInfoRef<'_>,
) -> CryptoError {
    CryptoError::Verify(format!(
        "signature algorithm {} does not match signer key algorithm {}",
        algorithm.oid, key.algorithm.oid
    ))
}

fn require_absent_parameters(algorithm: &AlgorithmIdentifierRef<'_>) -> Result<(), CryptoError> {
    if algorithm.parameters.is_some() {
        return Err(CryptoError::Malformed(format!(
            "signature algorithm {} must not carry parameters",
            algorithm.oid
        )));
    }
    Ok(())
}

/// RFC 4055 section 5 says NULL; deployed encoders also omit it.
fn require_null_or_absent_parameters(
    algorithm: &AlgorithmIdentifierRef<'_>,
) -> Result<(), CryptoError> {
    match algorithm.parameters.as_ref() {
        None => Ok(()),
        Some(parameters) if parameters.is_null() => Ok(()),
        Some(_) => Err(CryptoError::Malformed(format!(
            "signature algorithm {} parameters must be NULL",
            algorithm.oid
        ))),
    }
}

/// Hash and salt length of an RFC 4055 `RSASSA-PSS-params` value.
///
/// Parsed here rather than with `pkcs1::RsaPssParams`, whose `u8` salt length
/// cannot represent the maximal salts OpenSSL emits by default (478 bytes for
/// a 4096-bit key with SHA-256). Absent hash or mask parameters default to
/// SHA-1, which C2PA does not allow, so they are refused rather than assumed.
fn pss_parameters(algorithm: &AlgorithmIdentifierRef<'_>) -> Result<(Hash, usize), CryptoError> {
    use der::{Reader as _, TagMode, TagNumber};

    let raw = algorithm.parameters.ok_or_else(|| {
        CryptoError::Malformed("RSASSA-PSS parameters are absent (SHA-1 default refused)".into())
    })?;
    let malformed =
        |e: der::Error| CryptoError::Malformed(format!("PSS parameters parse failed: {e}"));
    let (hash, mask_gen, salt_len, trailer) = raw
        .sequence(|reader| {
            let hash: Option<AlgorithmIdentifierRef<'_>> =
                reader.context_specific(TagNumber::N0, TagMode::Explicit)?;
            let mask_gen: Option<spki::AlgorithmIdentifier<AlgorithmIdentifierRef<'_>>> =
                reader.context_specific(TagNumber::N1, TagMode::Explicit)?;
            let salt_len: Option<u32> =
                reader.context_specific(TagNumber::N2, TagMode::Explicit)?;
            let trailer: Option<u32> = reader.context_specific(TagNumber::N3, TagMode::Explicit)?;
            Ok((
                hash.map(|hash| hash.oid),
                mask_gen.map(|mask| (mask.oid, mask.parameters.map(|inner| inner.oid))),
                salt_len,
                trailer,
            ))
        })
        .map_err(malformed)?;
    let hash_oid = hash.ok_or_else(|| {
        CryptoError::Malformed("RSASSA-PSS hash is absent (SHA-1 default refused)".into())
    })?;
    let hash = Hash::from_digest_oid(hash_oid).ok_or_else(|| {
        CryptoError::UnsupportedSignatureAlgorithm(format!("RSASSA-PSS with digest {hash_oid}"))
    })?;
    if mask_gen != Some((ID_MGF1, Some(hash_oid))) {
        return Err(CryptoError::Malformed(
            "PSS mask generation must be MGF1 over the signature hash".into(),
        ));
    }
    if trailer.unwrap_or(1) != 1 {
        return Err(CryptoError::Malformed("PSS trailer field must be 1".into()));
    }
    let salt_len = usize::try_from(salt_len.unwrap_or(20))
        .map_err(|_| CryptoError::Malformed("PSS salt length does not fit in memory".into()))?;
    Ok((hash, salt_len))
}

fn rsa_key(key: &SubjectPublicKeyInfoRef<'_>) -> Result<rsa::RsaPublicKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    let raw = key.subject_public_key.as_bytes().ok_or_else(|| {
        CryptoError::CertParse("RSA public key bit string has unused bits".into())
    })?;
    rsa::RsaPublicKey::from_pkcs1_der(raw)
        .map_err(|e| CryptoError::CertParse(format!("PKCS#1 RSA public key parse failed: {e}")))
}

fn verify_ecdsa(
    key: &SubjectPublicKeyInfoRef<'_>,
    hash: Hash,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use signature::hazmat::PrehashVerifier as _;

    if key.algorithm.oid != ID_EC_PUBLIC_KEY {
        return Err(CryptoError::Verify(format!(
            "ECDSA signature with non-EC signer key {}",
            key.algorithm.oid
        )));
    }
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
        .ok_or_else(|| CryptoError::CertParse("EC SPKI has no named curve".into()))?;
    let point = key
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CryptoError::CertParse("EC public key bit string has unused bits".into()))?;
    let point_error = |e: signature::Error| CryptoError::CertParse(format!("EC public key: {e}"));
    let mut prehash = [0_u8; 64];
    let prehash = hash.digest(message, &mut prehash);
    match curve {
        CURVE_P256 => {
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(point_error)?;
            let signature = p256::ecdsa::Signature::from_der(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(prehash, &signature)
                .map_err(bad)
        }
        CURVE_P384 => {
            let verifying_key =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(point_error)?;
            let signature = p384::ecdsa::Signature::from_der(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(prehash, &signature)
                .map_err(bad)
        }
        CURVE_P521 => {
            let verifying_key =
                p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(point_error)?;
            let signature = p521::ecdsa::Signature::from_der(signature).map_err(bad)?;
            verifying_key
                .verify_prehash(prehash, &signature)
                .map_err(bad)
        }
        other => Err(CryptoError::CertParse(format!(
            "unsupported EC curve: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode as _;

    /// The certificate's own signature: `(issuer SPKI, AlgorithmIdentifier,
    /// TBSCertificate, signature)` for a self-signed certificate.
    fn self_signature(cert_der: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let certificate = x509_cert::Certificate::from_der(cert_der).expect("certificate");
        (
            certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .expect("SPKI"),
            certificate.signature_algorithm.to_der().expect("algorithm"),
            certificate.tbs_certificate.to_der().expect("TBS"),
            certificate.signature.raw_bytes().to_vec(),
        )
    }

    fn assert_valid_and_tamper_evident(cert_der: &[u8]) {
        let (spki, algorithm, tbs, signature) = self_signature(cert_der);
        verify_x509_signature(&spki, &algorithm, &tbs, &signature)
            .expect("self-signature verifies");

        let mut tampered = tbs.clone();
        let middle = tampered.len() / 2;
        tampered[middle] ^= 0x01;
        assert!(verify_x509_signature(&spki, &algorithm, &tampered, &signature).is_err());

        let mut forged = signature.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert!(verify_x509_signature(&spki, &algorithm, &tbs, &forged).is_err());
    }

    const ML_DSA_CERTIFICATES: [&[u8]; 3] = [
        include_bytes!("fixtures/ml_dsa_44_rfc9881_cert.der"),
        include_bytes!("fixtures/ml_dsa_65_rfc9881_cert.der"),
        include_bytes!("fixtures/ml_dsa_87_rfc9881_cert.der"),
    ];

    #[test]
    fn rfc9881_ml_dsa_self_signed_certificates_verify() {
        for cert in ML_DSA_CERTIFICATES {
            assert_valid_and_tamper_evident(cert);
        }
    }

    #[test]
    fn an_ml_dsa_signature_oid_never_uses_another_parameter_sets_key() {
        let (key_44, _, _, _) = self_signature(ML_DSA_CERTIFICATES[0]);
        let (_, algorithm_65, tbs_65, signature_65) = self_signature(ML_DSA_CERTIFICATES[1]);
        assert!(matches!(
            verify_x509_signature(&key_44, &algorithm_65, &tbs_65, &signature_65),
            Err(CryptoError::Verify(_))
        ));
    }

    #[test]
    fn openssl_rsassa_pss_certificate_signature_verifies_with_its_salt_length() {
        // OpenSSL `genpkey -algorithm RSA-PSS` self-signed certificate: PSS
        // key, PSS signature with SHA-256/MGF1-SHA-256 and a 478-byte salt.
        assert_valid_and_tamper_evident(include_bytes!("fixtures/pss_spki_cert.der"));
    }

    #[test]
    fn rsassa_pss_without_parameters_is_refused() {
        let (spki, _, tbs, signature) =
            self_signature(include_bytes!("fixtures/pss_spki_cert.der"));
        let bare = spki::AlgorithmIdentifierOwned {
            oid: ID_RSASSA_PSS,
            parameters: None,
        }
        .to_der()
        .expect("algorithm");
        assert!(matches!(
            verify_x509_signature(&spki, &bare, &tbs, &signature),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn rcgen_ecdsa_and_ed25519_certificate_signatures_verify() {
        for alg in [
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &rcgen::PKCS_ED25519,
        ] {
            let key = rcgen::KeyPair::generate_for(alg).expect("key");
            let params = rcgen::CertificateParams::new(vec!["x509.test".into()]).expect("params");
            let certificate = params.self_signed(&key).expect("certificate");
            assert_valid_and_tamper_evident(certificate.der());
        }
    }

    #[test]
    fn a_signature_algorithm_never_uses_a_key_of_another_type() {
        let ec = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("EC key");
        let ec_cert = rcgen::CertificateParams::new(vec!["ec.test".into()])
            .expect("params")
            .self_signed(&ec)
            .expect("EC certificate");
        let (ec_spki, ec_algorithm, ec_tbs, ec_signature) = self_signature(ec_cert.der());
        let (pss_spki, pss_algorithm, pss_tbs, pss_signature) =
            self_signature(include_bytes!("fixtures/pss_spki_cert.der"));
        let (ml_spki, ml_algorithm, ml_tbs, ml_signature) = self_signature(ML_DSA_CERTIFICATES[0]);

        assert!(verify_x509_signature(&pss_spki, &ec_algorithm, &ec_tbs, &ec_signature).is_err());
        assert!(verify_x509_signature(&ml_spki, &pss_algorithm, &pss_tbs, &pss_signature).is_err());
        assert!(verify_x509_signature(&ec_spki, &ml_algorithm, &ml_tbs, &ml_signature).is_err());

        // RFC 4055 section 1.2: a key issued for PSS must not verify PKCS#1 v1.5.
        let pkcs1 = spki::AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: Some(der::Any::from(der::AnyRef::from(der::asn1::Null))),
        }
        .to_der()
        .expect("algorithm");
        assert!(matches!(
            verify_x509_signature(&pss_spki, &pkcs1, &pss_tbs, &pss_signature),
            Err(CryptoError::Verify(_))
        ));
    }

    #[test]
    fn an_unknown_signature_algorithm_is_refused_by_name() {
        let (spki, _, tbs, signature) = self_signature(ML_DSA_CERTIFICATES[0]);
        // id-dsa-with-sha256: a real algorithm outside every C2PA list.
        let dsa = spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.2"),
            parameters: None,
        }
        .to_der()
        .expect("algorithm");
        assert!(matches!(
            verify_x509_signature(&spki, &dsa, &tbs, &signature),
            Err(CryptoError::UnsupportedSignatureAlgorithm(oid)) if oid == "2.16.840.1.101.3.4.3.2"
        ));
    }
}
