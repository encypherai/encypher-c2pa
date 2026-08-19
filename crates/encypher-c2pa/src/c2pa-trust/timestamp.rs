//! RFC 3161 timestamp-token verification for C2PA `sigTst2` headers.
//!
//! A timestamp is accepted only when its CMS signature, signed attributes,
//! message imprint, timestamping EKU, certificate validity, and chain to the
//! caller-supplied TSA trust list all verify.

use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::ObjectIdentifier;
use der::{asn1::OctetString, Decode, Encode};
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::{pkcs1::DecodeRsaPublicKey, signature::Verifier as _};
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::{Duration, OffsetDateTime};
use x509_cert::{
    attr::Attribute,
    ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier},
    Certificate,
};
use x509_tsp::{TimeStampResp, TstInfo};

use super::{common_name, validate_chain, TrustList, OID_KP_TIME_STAMPING};

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXT_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_KP_TIME_STAMPING_OBJ: ObjectIdentifier =
    ObjectIdentifier::new_unwrap(OID_KP_TIME_STAMPING);

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
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

const MAX_FUTURE_SKEW: Duration = Duration::minutes(5);

/// Result of verifying one RFC 3161 timestamp token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampResult {
    /// True only when every cryptographic and trust check passed.
    pub verified: bool,
    /// Trusted timestamp generation time.
    pub time: Option<OffsetDateTime>,
    /// Common Name of the verified TSA signer certificate, when present.
    pub tsa_common_name: Option<String>,
    /// Stable failure reason. `None` when `verified` is true.
    pub error: Option<&'static str>,
}

impl TimestampResult {
    fn failure(error: &'static str) -> Self {
        Self {
            verified: false,
            time: None,
            tsa_common_name: None,
            error: Some(error),
        }
    }

    fn success(time: OffsetDateTime, tsa_common_name: Option<String>) -> Self {
        Self {
            verified: true,
            time: Some(time),
            tsa_common_name,
            error: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Extract the CMS `TimeStampToken` from a legacy RFC 3161 `TimeStampResp`.
pub fn token_from_timestamp_response(response_der: &[u8]) -> Result<Vec<u8>, &'static str> {
    let response =
        TimeStampResp::from_der(response_der).map_err(|_| "timestamp_response_parse_error")?;
    response
        .time_stamp_token
        .ok_or("timestamp_response_token_missing")?
        .to_der()
        .map_err(|_| "timestamp_response_token_invalid")
}

/// Verify an RFC 3161 `TimeStampToken` against the exact C2PA timestamp input.
///
/// `timestamp_input` is the C2PA v2 CounterSignature `ToBeSigned` value, not the
/// raw COSE signature bytes. `tsa_trust` must contain the permitted TSA roots.
pub fn verify_timestamp_token(
    token_der: &[u8],
    timestamp_input: &[u8],
    tsa_trust: &TrustList,
    verification_time: OffsetDateTime,
) -> TimestampResult {
    verify_timestamp_token_inner(token_der, timestamp_input, tsa_trust, verification_time)
        .unwrap_or_else(TimestampResult::failure)
}

/// Validate a timestamp token's structure, imprint, CMS signature, and TSA
/// leaf profile without deciding whether its certificate chain is trusted.
pub fn inspect_timestamp_token(
    token_der: &[u8],
    timestamp_input: &[u8],
    verification_time: OffsetDateTime,
) -> Result<(), &'static str> {
    match verify_timestamp_token_inner(
        token_der,
        timestamp_input,
        &TrustList::default(),
        verification_time,
    ) {
        Err("no_tsa_anchors") => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Ok(()),
    }
}

fn verify_timestamp_token_inner(
    token_der: &[u8],
    timestamp_input: &[u8],
    tsa_trust: &TrustList,
    verification_time: OffsetDateTime,
) -> Result<TimestampResult, &'static str> {
    let content_info = ContentInfo::from_der(token_der).map_err(|_| "timestamp_parse_error")?;
    if content_info.content_type != OID_SIGNED_DATA {
        return Err("timestamp_not_signed_data");
    }
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| "timestamp_signed_data_invalid")?;
    if signed_data.encap_content_info.econtent_type != OID_TST_INFO {
        return Err("timestamp_not_tst_info");
    }
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("timestamp_tst_info_missing")?;
    let tst_octets = econtent
        .decode_as::<OctetString>()
        .map_err(|_| "timestamp_tst_info_invalid")?;
    let tst_bytes = tst_octets.as_bytes();
    let tst_info = TstInfo::from_der(tst_bytes).map_err(|_| "timestamp_tst_info_invalid")?;

    let generated_at =
        OffsetDateTime::from_unix_timestamp(tst_info.gen_time.to_unix_duration().as_secs() as i64)
            .map_err(|_| "timestamp_time_invalid")?;
    if generated_at > verification_time + MAX_FUTURE_SKEW {
        return Err("timestamp_time_in_future");
    }

    let imprint_hash = HashAlgorithm::from_oid(tst_info.message_imprint.hash_algorithm.oid)
        .ok_or("timestamp_imprint_hash_unsupported")?;
    if imprint_hash.digest(timestamp_input) != tst_info.message_imprint.hashed_message.as_bytes() {
        return Err("timestamp_imprint_mismatch");
    }

    if signed_data.signer_infos.0.len() != 1 {
        return Err("timestamp_signer_info_count_invalid");
    }
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or("timestamp_signer_info_count_invalid")?;
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or("timestamp_signed_attrs_missing")?;
    let content_type = single_attribute(signed_attrs.iter(), OID_CONTENT_TYPE_ATTR)
        .ok_or("timestamp_content_type_attr_invalid")?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| "timestamp_content_type_attr_invalid")?;
    if content_type != OID_TST_INFO {
        return Err("timestamp_content_type_attr_invalid");
    }

    let signer_hash = HashAlgorithm::from_oid(signer_info.digest_alg.oid)
        .ok_or("timestamp_digest_hash_unsupported")?;
    let message_digest = single_attribute(signed_attrs.iter(), OID_MESSAGE_DIGEST_ATTR)
        .ok_or("timestamp_message_digest_attr_invalid")?
        .decode_as::<OctetString>()
        .map_err(|_| "timestamp_message_digest_attr_invalid")?;
    if signer_hash.digest(tst_bytes) != message_digest.as_bytes() {
        return Err("timestamp_message_digest_mismatch");
    }

    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or("timestamp_signer_cert_missing")?;
    let signer_cert = certificates
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) if signer_matches(signer_info, cert) => {
                Some(cert)
            }
            _ => None,
        })
        .next()
        .ok_or("timestamp_signer_cert_missing")?;
    let signer_der = signer_cert
        .to_der()
        .map_err(|_| "timestamp_signer_cert_invalid")?;

    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|_| "timestamp_signed_attrs_invalid")?;
    if !verify_signer_signature(signer_cert, signer_info, signer_hash, &signed_attrs_der) {
        return Err("timestamp_signature_invalid");
    }
    if !has_strict_timestamping_eku(signer_cert) {
        return Err("timestamp_eku_invalid");
    }
    if !tsa_leaf_profile_acceptable(signer_cert) {
        return Err("timestamp_tsa_leaf_profile_invalid");
    }

    let included_der: Vec<Vec<u8>> = certificates
        .0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => cert.to_der().ok(),
            _ => None,
        })
        .filter(|der| der != &signer_der)
        .collect();
    if tsa_trust.anchors.is_empty() {
        return Err("no_tsa_anchors");
    }
    let chain = validate_chain(&signer_der, &included_der, tsa_trust, Some(generated_at));
    if !chain.chain_validity_ok {
        return Err("timestamp_tsa_outside_validity");
    }
    if !chain.trusted {
        return Err("timestamp_tsa_untrusted");
    }

    Ok(TimestampResult::success(
        generated_at,
        common_name(signer_cert),
    ))
}

fn single_attribute<'a>(
    attrs: impl Iterator<Item = &'a Attribute>,
    oid: ObjectIdentifier,
) -> Option<&'a der::Any> {
    let mut matches = attrs.filter(|attr| attr.oid == oid);
    let attr = matches.next()?;
    if matches.next().is_some() || attr.values.len() != 1 {
        return None;
    }
    attr.values.iter().next()
}

fn signer_matches(signer_info: &SignerInfo, cert: &Certificate) -> bool {
    match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(sid) => {
            cert.tbs_certificate.issuer == sid.issuer
                && cert.tbs_certificate.serial_number == sid.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(sid) => cert
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|extension| extension.extn_id == OID_SUBJECT_KEY_IDENTIFIER)
            })
            .and_then(|extension| {
                SubjectKeyIdentifier::from_der(extension.extn_value.as_bytes()).ok()
            })
            .map(|cert_sid| cert_sid.0.as_bytes() == sid.0.as_bytes())
            .unwrap_or(false),
    }
}

fn has_strict_timestamping_eku(cert: &Certificate) -> bool {
    let Some(extension) = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == OID_EXT_EKU)
        })
    else {
        return false;
    };
    if !extension.critical {
        return false;
    }
    ExtendedKeyUsage::from_der(extension.extn_value.as_bytes())
        .map(|eku| eku.0.len() == 1 && eku.0[0] == OID_KP_TIME_STAMPING_OBJ)
        .unwrap_or(false)
}

fn tsa_leaf_profile_acceptable(cert: &Certificate) -> bool {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    let is_ca = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_EXT_BASIC_CONSTRAINTS)
        .and_then(|extension| BasicConstraints::from_der(extension.extn_value.as_bytes()).ok())
        .is_some_and(|constraints| constraints.ca);
    if is_ca {
        return false;
    }
    extensions
        .iter()
        .find(|extension| extension.extn_id == OID_EXT_KEY_USAGE)
        .and_then(|extension| KeyUsage::from_der(extension.extn_value.as_bytes()).ok())
        .is_some_and(|usage| usage.digital_signature() && !usage.key_cert_sign())
}

fn verify_signer_signature(
    cert: &Certificate,
    signer_info: &SignerInfo,
    digest_hash: HashAlgorithm,
    signed_attrs_der: &[u8],
) -> bool {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let Some(public_key) = spki.subject_public_key.as_bytes() else {
        return false;
    };
    let signature = signer_info.signature.as_bytes();
    let signature_oid = signer_info.signature_algorithm.oid;

    if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        let signature_hash = match signature_oid {
            OID_ECDSA_SHA256 => HashAlgorithm::Sha256,
            OID_ECDSA_SHA384 => HashAlgorithm::Sha384,
            OID_ECDSA_SHA512 => HashAlgorithm::Sha512,
            _ => return false,
        };
        if signature_hash != digest_hash {
            return false;
        }
        let Some(curve) = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
        else {
            return false;
        };
        verify_ecdsa_signature(
            curve,
            signature_hash,
            public_key,
            signature,
            signed_attrs_der,
        )
    } else if spki.algorithm.oid == OID_RSA_ENCRYPTION || spki.algorithm.oid == OID_RSASSA_PSS {
        if signature_oid == OID_RSASSA_PSS {
            let Some(parameters) = signer_info.signature_algorithm.parameters.as_ref() else {
                return false;
            };
            return verify_rsa_pss_signature(
                digest_hash,
                public_key,
                signature,
                signed_attrs_der,
                parameters,
            );
        }
        let signature_hash = match signature_oid {
            OID_RSA_ENCRYPTION => digest_hash,
            OID_RSA_SHA256 => HashAlgorithm::Sha256,
            OID_RSA_SHA384 => HashAlgorithm::Sha384,
            OID_RSA_SHA512 => HashAlgorithm::Sha512,
            _ => return false,
        };
        signature_hash == digest_hash
            && verify_rsa_signature(signature_hash, public_key, signature, signed_attrs_der)
    } else if spki.algorithm.oid == OID_ED25519 && signature_oid == OID_ED25519 {
        verify_ed25519_signature(public_key, signature, signed_attrs_der)
    } else {
        false
    }
}

fn verify_ecdsa_signature(
    curve: ObjectIdentifier,
    hash: HashAlgorithm,
    public_key: &[u8],
    signature_der: &[u8],
    message: &[u8],
) -> bool {
    let prehash = hash.digest(message);
    if curve == OID_CURVE_P256 {
        let (Ok(key), Ok(signature)) = (
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key),
            p256::ecdsa::Signature::from_der(signature_der),
        ) else {
            return false;
        };
        key.verify_prehash(&prehash, &signature).is_ok()
    } else if curve == OID_CURVE_P384 {
        let (Ok(key), Ok(signature)) = (
            p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key),
            p384::ecdsa::Signature::from_der(signature_der),
        ) else {
            return false;
        };
        key.verify_prehash(&prehash, &signature).is_ok()
    } else if curve == OID_CURVE_P521 {
        let (Ok(key), Ok(signature)) = (
            p521::ecdsa::VerifyingKey::from_sec1_bytes(public_key),
            p521::ecdsa::Signature::from_der(signature_der),
        ) else {
            return false;
        };
        key.verify_prehash(&prehash, &signature).is_ok()
    } else {
        false
    }
}

fn verify_rsa_signature(
    hash: HashAlgorithm,
    public_key_der: &[u8],
    signature: &[u8],
    message: &[u8],
) -> bool {
    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(public_key_der) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    match hash {
        HashAlgorithm::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key)
            .verify(message, &signature)
            .is_ok(),
        HashAlgorithm::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(public_key)
            .verify(message, &signature)
            .is_ok(),
        HashAlgorithm::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public_key)
            .verify(message, &signature)
            .is_ok(),
    }
}

fn verify_rsa_pss_signature(
    digest_hash: HashAlgorithm,
    public_key_der: &[u8],
    signature: &[u8],
    message: &[u8],
    parameters: &der::Any,
) -> bool {
    let Ok(parameters_der) = parameters.to_der() else {
        return false;
    };
    let Ok(parameters) = rsa::pkcs1::RsaPssParams::try_from(parameters_der.as_slice()) else {
        return false;
    };
    let Some(hash) = HashAlgorithm::from_oid(parameters.hash.oid) else {
        return false;
    };
    let Some(mask_hash) = parameters.mask_gen.parameters.as_ref() else {
        return false;
    };
    if hash != digest_hash
        || parameters.mask_gen.oid != OID_MGF1
        || HashAlgorithm::from_oid(mask_hash.oid) != Some(hash)
        || parameters.trailer_field != Default::default()
    {
        return false;
    }
    let Ok(public_key) = rsa::RsaPublicKey::from_pkcs1_der(public_key_der) else {
        return false;
    };
    let Ok(signature) = rsa::pss::Signature::try_from(signature) else {
        return false;
    };
    let salt_len = parameters.salt_len as usize;
    match hash {
        HashAlgorithm::Sha256 => {
            rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(public_key, salt_len)
                .verify(message, &signature)
                .is_ok()
        }
        HashAlgorithm::Sha384 => {
            rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(public_key, salt_len)
                .verify(message, &signature)
                .is_ok()
        }
        HashAlgorithm::Sha512 => {
            rsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(public_key, salt_len)
                .verify(message, &signature)
                .is_ok()
        }
    }
}

fn verify_ed25519_signature(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Ok(key_bytes): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return false;
    };
    key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = b"C2PA timestamp payload fixture";

    fn token() -> Vec<u8> {
        hex::decode(include_str!("tests/fixtures/rfc3161_token.hex").trim()).unwrap()
    }

    fn trust() -> TrustList {
        TrustList::from_pem(include_str!("tests/fixtures/rfc3161_root.pem")).unwrap()
    }

    fn verification_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_785_839_000).unwrap()
    }

    #[test]
    fn verifies_cms_imprint_eku_chain_and_generation_time() {
        let result = verify_timestamp_token(&token(), PAYLOAD, &trust(), verification_time());

        assert_eq!(result.error, None);
        assert!(result.verified);
        assert_eq!(
            result.time.unwrap().unix_timestamp(),
            1_785_838_908,
            "fixture genTime must be returned as the trusted validation instant"
        );
        assert_eq!(result.tsa_common_name.as_deref(), Some("CAWG Fixture TSA"));
    }

    #[test]
    fn rejects_an_imprint_for_different_c2pa_timestamp_input() {
        let result = verify_timestamp_token(
            &token(),
            b"different payload",
            &trust(),
            verification_time(),
        );

        assert!(!result.verified);
        assert_eq!(result.error, Some("timestamp_imprint_mismatch"));
        assert_eq!(result.time, None);
    }

    #[test]
    fn rejects_a_tampered_cms_signature() {
        let mut token = token();
        *token.last_mut().unwrap() ^= 1;
        let result = verify_timestamp_token(&token, PAYLOAD, &trust(), verification_time());

        assert!(!result.verified);
        assert_eq!(result.error, Some("timestamp_signature_invalid"));
    }

    #[test]
    fn rejects_a_valid_token_under_an_unrelated_trust_list() {
        let result = verify_timestamp_token(
            &token(),
            PAYLOAD,
            &TrustList {
                anchors: vec![vec![0x30, 0x00]],
            },
            verification_time(),
        );

        assert!(!result.verified);
        assert_eq!(result.error, Some("timestamp_tsa_untrusted"));
    }

    #[test]
    fn rejects_a_token_generated_after_the_supplied_validation_time() {
        let before_token = OffsetDateTime::from_unix_timestamp(1_785_838_000).unwrap();
        let result = verify_timestamp_token(&token(), PAYLOAD, &trust(), before_token);

        assert!(!result.verified);
        assert_eq!(result.error, Some("timestamp_time_in_future"));
    }
}
