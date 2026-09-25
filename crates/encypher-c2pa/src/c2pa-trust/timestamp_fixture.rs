// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Deterministic RFC 3161 timestamp fixtures for the offline test suite.
//!
//! The verifier ships no signer, so the timestamp rules (VAL-CRYP-0017..0026,
//! VAL-TIME-0001..0008) can only be exercised against tokens this module mints.
//! Everything here is `#[cfg(test)]`: it is compiled out of the published
//! library and unreachable from the public surface.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use time::OffsetDateTime;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TspVersion, TstInfo};

use super::TrustList;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST_ATTR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_EXT_EKU: &[u64] = &[2, 5, 29, 37];
const OID_KP_TIME_STAMPING_DER: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
];

/// A timestamp authority: a self-signed root plus the leaf it issues.
pub struct TestTsa {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key: KeyPair,
    leaf_not_after: OffsetDateTime,
}

impl TestTsa {
    /// Mint a TSA whose leaf certificate is valid over `[not_before, not_after]`
    /// and carries a critical, sole `id-kp-timeStamping` EKU.
    pub fn new(not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        let root_key = KeyPair::generate().expect("TSA root key");
        let mut root_params =
            CertificateParams::new(vec!["tsa-root.example".to_string()]).expect("root params");
        let mut root_name = DistinguishedName::new();
        root_name.push(DnType::CommonName, "Encypher Fixture TSA Root");
        root_params.distinguished_name = root_name;
        root_params.not_before = not_before;
        root_params.not_after = not_after;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root = root_params
            .self_signed(&root_key)
            .expect("self-signed root");

        let leaf_key = KeyPair::generate().expect("TSA leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["tsa.example".to_string()]).expect("leaf params");
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, "Encypher Fixture TSA");
        leaf_params.distinguished_name = leaf_name;
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // rcgen writes a non-critical EKU; the verifier requires a critical,
        // sole timeStamping EKU, so the extension is written by hand.
        let mut eku =
            CustomExtension::from_oid_content(OID_EXT_EKU, OID_KP_TIME_STAMPING_DER.to_vec());
        eku.set_criticality(true);
        leaf_params.custom_extensions.push(eku);
        // RFC 5280 4.2.1.1 via the C2PA profile: any certificate that is not
        // self-signed carries an Authority Key Identifier. rcgen omits it
        // unless asked.
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf = leaf_params
            .signed_by(&leaf_key, &root, &root_key)
            .expect("issued TSA leaf");

        Self {
            root_der: root.der().as_ref().to_vec(),
            leaf_der: leaf.der().as_ref().to_vec(),
            leaf_key,
            leaf_not_after: not_after,
        }
    }

    /// A time-stamping trust list containing only this authority's root.
    pub fn trust_list(&self) -> TrustList {
        TrustList::from_certificates(
            crate::c2pa_trust::AnchorPurpose::TimeStamping,
            [self.root_der.clone()],
        )
    }

    /// The instant this authority's certificates stop being valid.
    pub fn not_after(&self) -> OffsetDateTime {
        self.leaf_not_after
    }

    /// Mint a `TimeStampToken` over `message_imprint_input`, attesting `gen_time`.
    pub fn token(&self, message_imprint_input: &[u8], gen_time: OffsetDateTime) -> Vec<u8> {
        self.token_over_digest(&Sha256::digest(message_imprint_input), gen_time)
    }

    /// Mint a token whose message imprint is `digest`, which lets a test build a
    /// token that is internally sound but does not bind the C2PA input.
    pub fn token_over_digest(&self, digest: &[u8], gen_time: OffsetDateTime) -> Vec<u8> {
        let tst_info = TstInfo {
            version: TspVersion::V1,
            policy: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.1"),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: OID_SHA256,
                    parameters: Some(Any::null()),
                },
                hashed_message: OctetString::new(digest.to_vec()).expect("imprint octets"),
            },
            serial_number: Int::new(&[0x01]).expect("serial"),
            gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
                gen_time.unix_timestamp() as u64,
            ))
            .expect("genTime"),
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };
        let tst_der = tst_info.to_der().expect("encode TSTInfo");

        let signed_attrs: Attributes = SetOfVec::try_from(vec![
            Attribute {
                oid: OID_CONTENT_TYPE_ATTR,
                values: SetOfVec::try_from(vec![Any::new(
                    Tag::ObjectIdentifier,
                    OID_TST_INFO.as_bytes(),
                )
                .expect("content-type value")])
                .expect("content-type set"),
            },
            Attribute {
                oid: OID_MESSAGE_DIGEST_ATTR,
                values: SetOfVec::try_from(vec![Any::new(
                    Tag::OctetString,
                    Sha256::digest(&tst_der).to_vec(),
                )
                .expect("message-digest value")])
                .expect("message-digest set"),
            },
        ])
        .expect("signed attributes");

        // RFC 5652 5.4: the signature covers the DER SET OF encoding of the
        // signed attributes, not their IMPLICIT [0] tagging inside SignerInfo.
        let signed_attrs_der = signed_attrs.to_der().expect("encode signed attributes");
        let key = SigningKey::from_pkcs8_der(&self.leaf_key.serialize_der()).expect("TSA key");
        let signature: Signature = key.sign(&signed_attrs_der);

        let leaf = Certificate::from_der(&self.leaf_der).expect("parse TSA leaf");
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: leaf.tbs_certificate.issuer.clone(),
                serial_number: leaf.tbs_certificate.serial_number.clone(),
            }),
            digest_alg: AlgorithmIdentifierOwned {
                oid: OID_SHA256,
                parameters: Some(Any::null()),
            },
            signed_attrs: Some(signed_attrs),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: OID_ECDSA_SHA256,
                parameters: None,
            },
            signature: OctetString::new(signature.to_der().as_bytes().to_vec())
                .expect("signature octets"),
            unsigned_attrs: None,
        };

        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![AlgorithmIdentifierOwned {
                oid: OID_SHA256,
                parameters: Some(Any::null()),
            }])
            .expect("digest algorithms"),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: OID_TST_INFO,
                econtent: Some(
                    Any::new(
                        Tag::OctetString,
                        OctetString::new(tst_der.clone())
                            .expect("econtent octets")
                            .as_bytes()
                            .to_vec(),
                    )
                    .expect("econtent"),
                ),
            },
            certificates: Some(
                vec![CertificateChoices::Certificate(leaf)]
                    .try_into()
                    .expect("certificate set"),
            ),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info]).expect("signer infos")),
        };
        let content_info = ContentInfo {
            content_type: OID_SIGNED_DATA,
            content: Any::encode_from(&signed_data).expect("encode SignedData"),
        };
        content_info.to_der().expect("encode TimeStampToken")
    }

    /// Wrap a token in an RFC 3161 `TimeStampResp` with the given
    /// `PKIStatusInfo.status`, which is what a legacy `sigTst` header carries.
    pub fn response(status: u8, token_der: &[u8]) -> Vec<u8> {
        let mut status_info = vec![0x30, 0x03, 0x02, 0x01, status];
        status_info.extend_from_slice(token_der);
        let mut response = Vec::with_capacity(status_info.len() + 4);
        response.push(0x30);
        encode_definite_length(&mut response, status_info.len());
        response.extend(status_info);
        response
    }
}

/// Write a DER definite-length header body for `length`.
fn encode_definite_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-zero length");
    out.push(0x80 | (bytes.len() - first) as u8);
    out.extend_from_slice(&bytes[first..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_trust::verify_timestamp_token;
    use time::macros::datetime;

    /// The fixture authority must satisfy the production verifier end to end.
    /// Without this, a timestamp test that "passes" could be measuring a
    /// fixture defect rather than the rule under test.
    #[test]
    fn minted_tokens_verify_against_the_production_verifier() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let gen_time = datetime!(2026-06-01 12:00 UTC);
        let token = tsa.token(b"c2pa timestamp input", gen_time);

        let verified = verify_timestamp_token(
            &token,
            b"c2pa timestamp input",
            &tsa.trust_list(),
            datetime!(2026-09-01 0:00 UTC),
        );
        assert_eq!(verified.error, None);
        assert!(verified.verified);
        assert_eq!(verified.time, Some(gen_time));

        // A different imprint input must not verify against the same token.
        let other = verify_timestamp_token(
            &token,
            b"a different input",
            &tsa.trust_list(),
            datetime!(2026-09-01 0:00 UTC),
        );
        assert_eq!(other.error, Some("timestamp_imprint_mismatch"));
    }

    /// `response` must produce bytes the legacy `sigTst` unwrapper accepts.
    #[test]
    fn granted_responses_unwrap_to_the_same_token() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let token = tsa.token(b"input", datetime!(2026-06-01 12:00 UTC));
        let response = TestTsa::response(0, &token);
        assert_eq!(
            crate::c2pa_trust::token_from_timestamp_response(&response).expect("unwrap"),
            token
        );
    }
}
