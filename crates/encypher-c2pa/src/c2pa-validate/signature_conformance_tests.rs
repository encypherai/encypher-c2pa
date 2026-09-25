// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! End-to-end status-code tests for the claim-signature, credential, trust,
//! timestamp, and revocation steps of [`super::verify_manifest`].
//!
//! Each fixture is minted in-process from `rcgen` key material, so the suite is
//! deterministic and offline. The module is `#[cfg(test)]` in its entirety: no
//! signing capability reaches the published library.

use std::collections::HashMap;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use time::macros::datetime;
use time::OffsetDateTime;

use super::*;
use crate::c2pa_cbor::{encode, Profile};
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_trust::ocsp::fixture::{issuer_signed_response, FixtureStatus};
use crate::c2pa_trust::{timestamp_fixture::TestTsa, AnchorPurpose};

const MANIFEST_LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-000000000001";
const NOT_BEFORE: OffsetDateTime = datetime!(2025-01-01 0:00 UTC);
const NOT_AFTER: OffsetDateTime = datetime!(2030-01-01 0:00 UTC);
const NOW: OffsetDateTime = datetime!(2026-06-01 0:00 UTC);

fn enc(value: &Value) -> Vec<u8> {
    encode(value, Profile::LegacyPipelineBDefinite).expect("encode")
}

/// A claim-signing credential: a self-signed CA plus the leaf it issues.
pub struct Signer {
    root_der: Vec<u8>,
    root_key: KeyPair,
    leaf_der: Vec<u8>,
    leaf_key: KeyPair,
}

/// How a test leaf departs from the C2PA claim-signing profile.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LeafShape {
    /// A conformant claim signer.
    Conformant,
    /// The leaf's only EKU is `id-kp-timeStamping`.
    SoleTimeStamping,
    /// No Authority Key Identifier, which RFC 5280 4.2.1.1 requires on any
    /// certificate that is not self-signed.
    NoAuthorityKeyIdentifier,
    /// The `issuerUniqueID`/`subjectUniqueID` fields are present, which
    /// RFC 5280 4.1.2.8 forbids.
    UniqueIdPresent,
    /// A critical extension the validator cannot process, which RFC 5280
    /// 6.1.4(f) requires it to reject the path over.
    UnknownCriticalExtension,
    /// A conformant claim signer whose AIA extension names an OCSP responder.
    OcspResponder,
}

/// The responder URL [`LeafShape::OcspResponder`] publishes.
const RESPONDER_URL: &str = "http://ocsp.fixture.test/responder";

/// An `AuthorityInfoAccessSyntax` naming one `id-ad-ocsp` access location.
pub(super) fn aia_extension(url: &str) -> CustomExtension {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag, content.len() as u8];
        encoded.extend_from_slice(content);
        encoded
    }
    // id-ad-ocsp, 1.3.6.1.5.5.7.48.1.
    let mut description = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    description.extend(tlv(0x86, url.as_bytes()));
    CustomExtension::from_oid_content(
        &[1, 3, 6, 1, 5, 5, 7, 1, 1],
        tlv(0x30, &tlv(0x30, &description)),
    )
}

impl Signer {
    fn new(shape: LeafShape, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params =
            CertificateParams::new(vec!["root.example".to_string()]).expect("root params");
        let mut root_name = DistinguishedName::new();
        root_name.push(DnType::CommonName, "Encypher Fixture Signing Root");
        root_params.distinguished_name = root_name;
        root_params.not_before = NOT_BEFORE;
        root_params.not_after = NOT_AFTER;
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let root = root_params
            .self_signed(&root_key)
            .expect("self-signed root");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["signer.example".to_string()]).expect("leaf params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Encypher Fixture Claim Signer");
        params.distinguished_name = name;
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // RFC 5280 4.2.1.1: a certificate that is not self-signed carries an
        // Authority Key Identifier. rcgen omits it unless asked.
        params.use_authority_key_identifier_extension = true;
        match shape {
            LeafShape::SoleTimeStamping => {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::TimeStamping];
            }
            _ => {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            }
        }
        if shape == LeafShape::UnknownCriticalExtension {
            let mut extension = CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 62558, 9, 7],
                vec![0x05, 0x00],
            );
            extension.set_criticality(true);
            params.custom_extensions.push(extension);
        }
        if shape == LeafShape::OcspResponder {
            params.custom_extensions.push(aia_extension(RESPONDER_URL));
        }
        let leaf = params
            .signed_by(&leaf_key, &root, &root_key)
            .expect("issued leaf");
        let mut leaf_der = leaf.der().as_ref().to_vec();
        match shape {
            LeafShape::NoAuthorityKeyIdentifier => {
                leaf_der = strip_extension(&leaf_der, &[0x55, 0x1d, 0x23]);
            }
            LeafShape::UniqueIdPresent => leaf_der = splice_unique_ids(&leaf_der),
            _ => {}
        }

        Self {
            root_der: root.der().as_ref().to_vec(),
            root_key,
            leaf_der,
            leaf_key,
        }
    }

    pub fn conformant() -> Self {
        Self::new(LeafShape::Conformant, NOT_BEFORE, NOT_AFTER)
    }

    fn trust_list(&self) -> TrustList {
        TrustList::from_certificates(AnchorPurpose::ClaimSigning, [self.root_der.clone()])
    }

    /// Sign `claim_cbor` with the leaf key, producing a `COSE_Sign1_Tagged`.
    pub fn sign(&self, claim_cbor: &[u8]) -> Vec<u8> {
        self.sign_with(claim_cbor, -7, Value::Null, None)
    }

    /// Sign with an explicit algorithm label, payload slot, and optional
    /// unprotected header entries.
    fn sign_with(
        &self,
        claim_cbor: &[u8],
        alg: i128,
        payload: Value,
        unprotected: Option<Vec<(Value, Value)>>,
    ) -> Vec<u8> {
        let protected = enc(&Value::Map(vec![
            (Value::Integer(1), Value::Integer(alg)),
            (
                Value::Integer(33),
                Value::Array(vec![
                    Value::Bytes(self.leaf_der.clone()),
                    Value::Bytes(self.root_der.clone()),
                ]),
            ),
        ]));
        let sig_input = enc(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(claim_cbor.to_vec()),
        ]));
        let key = SigningKey::from_pkcs8_der(&self.leaf_key.serialize_der()).expect("signing key");
        let signature: Signature = key.sign(&sig_input);
        enc(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(unprotected.unwrap_or_default()),
                payload,
                Value::Bytes(signature.to_der().as_bytes().to_vec()),
            ])),
        ))
    }

    /// Mint an issuer-signed OCSP response for this signer's leaf.
    fn ocsp(&self, status: FixtureStatus) -> Vec<u8> {
        issuer_signed_response(&self.root_der, &self.leaf_der, &self.root_key, status)
    }

    /// Sign with the supplied OCSP responses stapled in the `rVals`
    /// unprotected header, under a trusted RFC 3161 timestamp attesting
    /// `signed_at`.
    ///
    /// The timestamp is minted in two passes: its message imprint covers the
    /// protected bucket and the claim, neither of which the unprotected
    /// headers change, so a probe signature yields the imprint for the real
    /// token.
    fn sign_timestamped_with_stapled_ocsp(
        &self,
        claim_cbor: &[u8],
        tsa: &TestTsa,
        signed_at: OffsetDateTime,
        responses: &[Vec<u8>],
    ) -> Vec<u8> {
        let rvals = (
            Value::Text("rVals".into()),
            Value::Map(vec![(
                Value::Text("ocspVals".into()),
                Value::Array(
                    responses
                        .iter()
                        .map(|response| Value::Bytes(response.clone()))
                        .collect(),
                ),
            )]),
        );
        let probe = self.sign_with(
            claim_cbor,
            -7,
            Value::Null,
            Some(vec![
                sig_tst_header("sigTst", TestTsa::response(0, &[0x30, 0x00])),
                rvals.clone(),
            ]),
        );
        let imprint = match crate::c2pa_crypto::parse_timestamp_header(&probe, claim_cbor)
            .expect("probe header")
        {
            crate::c2pa_crypto::TimestampHeaderEvidence::Present(header) => {
                header.message_imprint_input
            }
            other => panic!("probe header did not parse: {other:?}"),
        };
        let token = TestTsa::response(0, &tsa.token(&imprint, signed_at));
        self.sign_with(
            claim_cbor,
            -7,
            Value::Null,
            Some(vec![sig_tst_header("sigTst", token), rvals]),
        )
    }
}

/// Remove the extension with `oid` (DER content octets) from a certificate.
///
/// Used to build a certificate that omits an extension the C2PA profile
/// requires.
fn strip_extension(cert_der: &[u8], oid: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode};
    let mut certificate = x509_cert::Certificate::from_der(cert_der).expect("parse certificate");
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("certificate has extensions");
    extensions.retain(|extension| extension.extn_id.as_bytes() != oid);
    // The signature no longer matches the edited TBS, which is irrelevant here:
    // the profile check runs before, and independently of, chain verification.
    certificate.to_der().expect("re-encode certificate")
}

/// Add the `issuerUniqueID` and `subjectUniqueID` TBSCertificate fields, which
/// RFC 5280 4.1.2.8 forbids and `rcgen` cannot emit.
fn splice_unique_ids(cert_der: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode};
    let mut certificate = x509_cert::Certificate::from_der(cert_der).expect("parse certificate");
    let identifier = der::asn1::BitString::from_bytes(&[0x01]).expect("bit string");
    certificate.tbs_certificate.issuer_unique_id = Some(identifier.clone());
    certificate.tbs_certificate.subject_unique_id = Some(identifier);
    certificate.to_der().expect("re-encode certificate")
}

/// The assertions a standard 2.x manifest must declare for its structure to be
/// sound: a hard binding and an inception actions assertion.
fn fixture_assertions() -> Vec<(String, Vec<u8>)> {
    let data_hash = enc(&Value::Map(vec![
        (Value::Text("exclusions".into()), Value::Array(Vec::new())),
        (Value::Text("alg".into()), Value::Text("sha256".into())),
        (Value::Text("hash".into()), Value::Bytes(vec![0x11; 32])),
    ]));
    let actions = enc(&Value::Map(vec![(
        Value::Text("actions".into()),
        Value::Array(vec![Value::Map(vec![
            (
                Value::Text("action".into()),
                Value::Text("c2pa.created".into()),
            ),
            (
                Value::Text("digitalSourceType".into()),
                Value::Text("http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into()),
            ),
        ])]),
    )]));
    vec![
        ("c2pa.hash.data".to_string(), data_hash),
        ("c2pa.actions.v2".to_string(), actions),
    ]
}

/// A structurally complete v2 claim referencing [`fixture_assertions`].
fn claim() -> Value {
    Value::Map(vec![
        (
            Value::Text("instanceID".into()),
            Value::Text("xmp:iid:fixture".into()),
        ),
        (
            Value::Text("claim_generator_info".into()),
            Value::Map(vec![(
                Value::Text("name".into()),
                Value::Text("Encypher Fixture".into()),
            )]),
        ),
        (
            Value::Text("created_assertions".into()),
            Value::Array(
                fixture_assertions()
                    .iter()
                    .map(|(label, payload)| {
                        Value::Map(vec![
                            (
                                Value::Text("url".into()),
                                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                            ),
                            (Value::Text("alg".into()), Value::Text("sha256".into())),
                            (
                                Value::Text("hash".into()),
                                Value::Bytes(sha2::Sha256::digest(payload).to_vec()),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Value::Text("signature".into()),
            Value::Text("self#jumbf=c2pa.signature".into()),
        ),
    ])
}

/// Run one manifest through the full per-manifest pipeline.
fn verify(
    claim_cbor: &[u8],
    cose: &[u8],
    trust: Option<&TrustList>,
    tsa_trust: Option<&TrustList>,
    profile: EngineProfile,
    now: OffsetDateTime,
) -> VerifyOutput {
    let assertions = fixture_assertions();
    let manifest = ParsedManifest {
        label: MANIFEST_LABEL.into(),
        manifest_jumbf: &[],
        assertions: assertions
            .iter()
            .map(|(label, payload)| (label.clone(), payload.as_slice()))
            .collect(),
        assertion_jumbf: Vec::new(),
        claim_cbor: Some(claim_cbor),
        signature_cose: Some(cose),
        claim_count: 1,
        claim_box_label: Some("c2pa.claim.v2".into()),
    };
    let manifest_hashes = HashMap::new();
    let input = VerifyInput {
        data: &[],
        mime: "application/c2pa",
        claim_signer_trust: trust,
        tsa_trust,
        allowed_certs: None,
        validation_time: Some(now),
        profile,
        evidence: Default::default(),
        cawg_strict_encoding: false,
    };
    let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
    verify_manifest(
        &manifest,
        StoreContext {
            manifests: std::slice::from_ref(&manifest),
            manifest_hashes: &manifest_hashes,
        },
        &input,
        AssetFormat::C2paStore,
        &[],
        None,
        CawgTrustInputs::default(),
        &mut report_decode_nodes,
    )
}

fn codes(statuses: &[StatusCode]) -> Vec<&str> {
    statuses.iter().map(|status| status.code.as_str()).collect()
}

#[test]
fn a_conformant_claim_signature_validates_and_is_trusted() {
    let signer = Signer::conformant();
    let claim_cbor = enc(&claim());
    let cose = signer.sign(&claim_cbor);

    let out = verify(
        &claim_cbor,
        &cose,
        Some(&signer.trust_list()),
        None,
        EngineProfile::GENEROUS,
        NOW,
    );

    assert!(
        out.results.has_success(CLAIM_SIGNATURE_VALIDATED),
        "expected a validated claim signature, got failures {:?} and successes {:?}",
        out.results.failure,
        codes(&out.results.success)
    );
    assert!(out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
    // The fixture carries no asset bytes and no assertion JUMBF boxes, so the
    // content binding and the hashed-URI bindings necessarily fail. What this
    // test defends is that nothing on the signature, credential, or timestamp
    // axis fails for a conformant signer.
    for status in &out.results.failure {
        assert!(
            status.code.starts_with("assertion.") || status.code.starts_with("hashedURI."),
            "conformant signer produced a non-assertion failure: {status:?}"
        );
    }
}

#[test]
fn a_carried_cose_payload_is_rejected_instead_of_verified_against_the_claim() {
    let signer = Signer::conformant();
    let claim_cbor = enc(&claim());

    // The Sig_structure is reconstructed from the external claim bytes, so a
    // signature with an embedded payload would otherwise verify. C2PA 2.4
    // requires detached content mode with a `nil` payload
    // (Claims "Signing a Claim"; Cryptography "Digital Signatures"), so it
    // must be reported as a claim-signature failure instead.
    for carried in [
        Value::Bytes(claim_cbor.clone()),
        Value::Bytes(Vec::new()),
        Value::Text(String::new()),
    ] {
        let cose = signer.sign_with(&claim_cbor, -7, carried, None);
        let out = verify(
            &claim_cbor,
            &cose,
            Some(&signer.trust_list()),
            None,
            EngineProfile::GENEROUS,
            NOW,
        );

        assert!(!out.results.has_success(CLAIM_SIGNATURE_VALIDATED));
        assert!(out.results.has_failure(CLAIM_SIGNATURE_MISMATCH));
        assert_eq!(out.validation_state, ValidationState::Invalid);
    }
}

#[test]
fn an_unsupported_signature_algorithm_reports_algorithm_unsupported() {
    let signer = Signer::conformant();
    let claim_cbor = enc(&claim());
    // -65535 is RS1 (RSASSA-PKCS1-v1_5 with SHA-1), a registered COSE
    // algorithm the C2PA allowed list excludes.
    let cose = signer.sign_with(&claim_cbor, -65535, Value::Null, None);

    let out = verify(
        &claim_cbor,
        &cose,
        Some(&signer.trust_list()),
        None,
        EngineProfile::GENEROUS,
        NOW,
    );

    // VAL-CRYP-0007 gives this its own code. Reporting
    // `claimSignature.mismatch` would tell a reader the signature was forged
    // when the verifier simply refused the algorithm.
    assert!(out.results.has_failure(ALGORITHM_UNSUPPORTED));
    assert!(!out.results.has_failure(CLAIM_SIGNATURE_MISMATCH));
    assert_eq!(out.validation_state, ValidationState::Invalid);
}

#[test]
fn a_sole_timestamping_leaf_is_not_a_valid_claim_signer() {
    let signer = Signer::new(LeafShape::SoleTimeStamping, NOT_BEFORE, NOT_AFTER);
    let claim_cbor = enc(&claim());
    let cose = signer.sign(&claim_cbor);

    let out = verify(
        &claim_cbor,
        &cose,
        Some(&signer.trust_list()),
        None,
        EngineProfile::GENEROUS,
        NOW,
    );

    // The signature itself is cryptographically sound; the credential is not
    // authorized for claim signing (VAL-CRYP-0005/0006).
    assert!(out.results.has_failure(SIGNING_CREDENTIAL_INVALID));
    assert!(!out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
    assert_eq!(out.validation_state, ValidationState::Invalid);
}

#[test]
fn a_leaf_outside_the_certificate_profile_is_not_a_valid_claim_signer() {
    // VAL-CRYP-0005/0006: the credential is validated against the C2PA
    // certificate profile, and a non-compliant one is rejected with
    // `signingCredential.invalid` no matter how sound its signature is.
    for shape in [
        LeafShape::NoAuthorityKeyIdentifier,
        LeafShape::UniqueIdPresent,
        LeafShape::UnknownCriticalExtension,
    ] {
        let signer = Signer::new(shape, NOT_BEFORE, NOT_AFTER);
        let claim_cbor = enc(&claim());
        let cose = signer.sign(&claim_cbor);

        let out = verify(
            &claim_cbor,
            &cose,
            Some(&signer.trust_list()),
            None,
            EngineProfile::GENEROUS,
            NOW,
        );

        assert!(out.results.has_failure(SIGNING_CREDENTIAL_INVALID));
        assert!(!out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
        assert_eq!(out.validation_state, ValidationState::Invalid);
    }

    // The same fixture without the defect is trusted, so the profile check is
    // what decided the three cases above.
    let signer = Signer::conformant();
    let claim_cbor = enc(&claim());
    let out = verify(
        &claim_cbor,
        &signer.sign(&claim_cbor),
        Some(&signer.trust_list()),
        None,
        EngineProfile::GENEROUS,
        NOW,
    );
    assert!(!out.results.has_failure(SIGNING_CREDENTIAL_INVALID));
    assert!(out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
}

#[test]
fn a_trusted_legacy_timestamp_keeps_an_expired_signer_inside_validity() {
    // The signing certificate expired before the validation time, so without a
    // timestamp the claim signature is outside its validity window.
    let signer = Signer::new(
        LeafShape::Conformant,
        datetime!(2025-01-01 0:00 UTC),
        datetime!(2025-12-31 0:00 UTC),
    );
    let tsa = TestTsa::new(NOT_BEFORE, NOT_AFTER);
    let claim_cbor = enc(&claim());

    let without = verify(
        &claim_cbor,
        &signer.sign(&claim_cbor),
        Some(&signer.trust_list()),
        Some(&tsa.trust_list()),
        EngineProfile::GENEROUS,
        NOW,
    );
    assert!(without
        .results
        .has_failure(CLAIM_SIGNATURE_OUTSIDE_VALIDITY));

    // Mint a legacy `sigTst` over the v1 CounterSignature input for this exact
    // signature, then re-sign with the header in place. The imprint input
    // depends only on the protected bucket and the claim, both unchanged.
    let probe = signer.sign_with(
        &claim_cbor,
        -7,
        Value::Null,
        Some(vec![sig_tst_header(
            "sigTst",
            TestTsa::response(0, &[0x30, 0x00]),
        )]),
    );
    let imprint = match crate::c2pa_crypto::parse_timestamp_header(&probe, &claim_cbor)
        .expect("probe header")
    {
        crate::c2pa_crypto::TimestampHeaderEvidence::Present(header) => {
            header.message_imprint_input
        }
        other => panic!("probe header did not parse: {other:?}"),
    };
    let response = TestTsa::response(0, &tsa.token(&imprint, datetime!(2025-06-01 0:00 UTC)));
    let cose = signer.sign_with(
        &claim_cbor,
        -7,
        Value::Null,
        Some(vec![sig_tst_header("sigTst", response)]),
    );

    let with = verify(
        &claim_cbor,
        &cose,
        Some(&signer.trust_list()),
        Some(&tsa.trust_list()),
        EngineProfile::GENEROUS,
        NOW,
    );

    // VAL-CRYP-0028: the attested time, not the current time, decides
    // certificate validity once a timestamp is present, trusted, and validated.
    assert!(with.results.has_success(TIME_STAMP_TRUSTED));
    assert!(with.results.has_success(CLAIM_SIGNATURE_INSIDE_VALIDITY));
    assert!(!with.results.has_failure(CLAIM_SIGNATURE_OUTSIDE_VALIDITY));
    assert!(with
        .results
        .has_informational(timestamp_assertion::TIMESTAMP_V1_SIGNATURE_UNBOUND));
}

fn sig_tst_header(label: &str, token: Vec<u8>) -> (Value, Value) {
    (
        Value::Text(label.into()),
        Value::Map(vec![(
            Value::Text("tstTokens".into()),
            Value::Array(vec![Value::Map(vec![(
                Value::Text("val".into()),
                Value::Bytes(token),
            )])]),
        )]),
    )
}

#[test]
fn a_qualifying_good_ocsp_response_outranks_a_revoked_one_only_under_conformance() {
    // Embedded OCSP evidence is only decisive against an attested signing
    // time, so the fixture carries a trusted RFC 3161 timestamp.
    const SIGNED_AT: OffsetDateTime = datetime!(2026-03-01 0:00 UTC);
    let signer = Signer::conformant();
    let tsa = TestTsa::new(NOT_BEFORE, NOT_AFTER);
    let claim_cbor = enc(&claim());
    let good = signer.ocsp(FixtureStatus::Good);
    // Revoked before the attested signing time, so the revocation applies.
    let revoked = signer.ocsp(FixtureStatus::RevokedAt(b"20250601000000Z"));

    // Both orders, so the outcome is decided by the rule and not by the order
    // the responses happen to be stapled in.
    for stapled in [
        vec![good.clone(), revoked.clone()],
        vec![revoked.clone(), good.clone()],
    ] {
        let cose =
            signer.sign_timestamped_with_stapled_ocsp(&claim_cbor, &tsa, SIGNED_AT, &stapled);

        // Default posture: fail closed. The revoked response stands.
        let default = verify(
            &claim_cbor,
            &cose,
            Some(&signer.trust_list()),
            Some(&tsa.trust_list()),
            EngineProfile::GENEROUS,
            NOW,
        );
        assert!(default.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(!default
            .results
            .has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
        assert!(!default
            .results
            .has_informational(revocation::OCSP_CONFLICTING_REVOKED_RESPONSE));

        // Conformance posture: VAL-STRU-0027/VAL-CRYP-0034. The good response
        // settles the status, and the outranked revoked response is reported.
        let strict = verify(
            &claim_cbor,
            &cose,
            Some(&signer.trust_list()),
            Some(&tsa.trust_list()),
            EngineProfile::strict(SpecVersion::V2_4),
            NOW,
        );
        assert!(!strict.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(strict
            .results
            .has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
        assert!(strict
            .results
            .has_informational(revocation::OCSP_CONFLICTING_REVOKED_RESPONSE));
    }

    // A revoked response with nothing to outrank stays a failure in both
    // postures, so the conformance reading did not simply disable the check.
    let only_revoked =
        signer.sign_timestamped_with_stapled_ocsp(&claim_cbor, &tsa, SIGNED_AT, &[revoked]);
    for profile in [
        EngineProfile::GENEROUS,
        EngineProfile::strict(SpecVersion::V2_4),
    ] {
        let out = verify(
            &claim_cbor,
            &only_revoked,
            Some(&signer.trust_list()),
            Some(&tsa.trust_list()),
            profile,
            NOW,
        );
        assert!(out.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(!out
            .results
            .has_informational(revocation::OCSP_CONFLICTING_REVOKED_RESPONSE));
    }

    // A lone good response is accepted in both postures, which is what makes
    // the fixture responses valid evidence in the first place.
    let only_good =
        signer.sign_timestamped_with_stapled_ocsp(&claim_cbor, &tsa, SIGNED_AT, &[good]);
    let out = verify(
        &claim_cbor,
        &only_good,
        Some(&signer.trust_list()),
        Some(&tsa.trust_list()),
        EngineProfile::GENEROUS,
        NOW,
    );
    assert!(out.results.has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
}

/// Online OCSP: need collection, and the C2PA 2.4 online response rules.
mod online_ocsp {
    use std::collections::HashMap;

    use super::super::network_needs::NetworkNeed;
    use super::super::OnlineEvidence;
    use super::*;
    use crate::c2pa_trust::ocsp::fixture::{response, Responder, ResponseSpec};

    /// A signer whose leaf publishes an OCSP responder in its AIA extension.
    fn responder_signer() -> Signer {
        Signer::new(LeafShape::OcspResponder, NOT_BEFORE, NOT_AFTER)
    }

    fn leaf_key(signer: &Signer) -> String {
        hex::encode(sha2::Sha256::digest(&signer.leaf_der))
    }

    fn online_response(signer: &Signer, spec: ResponseSpec) -> Vec<u8> {
        response(
            &signer.root_der,
            &signer.leaf_der,
            &Responder {
                certificate_der: &signer.root_der,
                key: &signer.root_key,
                embed_certificate: false,
            },
            spec,
        )
    }

    /// Verify with caller-supplied online evidence for the leaf.
    fn verify_with_evidence(signer: &Signer, evidence: OnlineEvidence<'_>) -> VerifyOutput {
        let claim_cbor = enc(&claim());
        let cose = signer.sign(&claim_cbor);
        let assertions = fixture_assertions();
        let manifest = ParsedManifest {
            label: MANIFEST_LABEL.into(),
            manifest_jumbf: &[],
            assertions: assertions
                .iter()
                .map(|(label, payload)| (label.clone(), payload.as_slice()))
                .collect(),
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim_cbor),
            signature_cose: Some(&cose),
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let trust = signer.trust_list();
        let manifest_hashes = HashMap::new();
        let input = VerifyInput {
            data: &[],
            mime: "application/c2pa",
            claim_signer_trust: Some(&trust),
            tsa_trust: None,
            allowed_certs: None,
            validation_time: Some(NOW),
            profile: EngineProfile::GENEROUS,
            evidence,
            cawg_strict_encoding: false,
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        verify_manifest(
            &manifest,
            StoreContext {
                manifests: std::slice::from_ref(&manifest),
                manifest_hashes: &manifest_hashes,
            },
            &input,
            AssetFormat::C2paStore,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        )
    }

    #[test]
    fn an_offline_run_records_the_query_that_would_settle_revocation() {
        let signer = responder_signer();
        let out = verify_with_evidence(&signer, OnlineEvidence::default());

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        let leaf = out
            .network_needs
            .iter()
            .find(|need| match need {
                NetworkNeed::Ocsp {
                    certificate_sha256_hex,
                    ..
                } => *certificate_sha256_hex == leaf_key(&signer),
                _ => false,
            })
            .expect("a need for the leaf certificate");
        assert_eq!(
            leaf.to_json(),
            serde_json::json!({
                "kind": "ocsp",
                "purpose": "claim_signer",
                "responder_url": RESPONDER_URL,
                "certificate_sha256": leaf_key(&signer),
            })
        );
        let NetworkNeed::Ocsp { request_der, .. } = leaf else {
            unreachable!("matched above")
        };
        assert!(
            !request_der.is_empty() && request_der[0] == 0x30,
            "the need carries the DER OCSPRequest a fetcher would POST"
        );
    }

    #[test]
    fn a_certificate_with_no_responder_produces_no_query() {
        let signer = Signer::conformant();
        let out = verify_with_evidence(&signer, OnlineEvidence::default());

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        assert!(
            out.network_needs.is_empty(),
            "an issuer that published no query method has nothing to ask: {:?}",
            out.network_needs
        );
    }

    #[test]
    fn a_good_online_response_replaces_the_skipped_code() {
        let signer = responder_signer();
        let responses = HashMap::from([(
            leaf_key(&signer),
            online_response(&signer, ResponseSpec::fresh(FixtureStatus::Good)),
        )]);
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_responses: Some(&responses),
                ..OnlineEvidence::default()
            },
        );

        assert!(out.results.has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
        assert!(!out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        assert!(out.network_needs.is_empty());
        assert!(out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
    }

    #[test]
    fn a_revoked_online_response_rejects_the_signature() {
        let signer = responder_signer();
        let responses = HashMap::from([(
            leaf_key(&signer),
            online_response(
                &signer,
                ResponseSpec::fresh(FixtureStatus::RevokedAt(b"20250601000000Z")),
            ),
        )]);
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_responses: Some(&responses),
                ..OnlineEvidence::default()
            },
        );

        assert!(out.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(!out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
    }

    #[test]
    fn an_unknown_online_response_is_informational_and_leaves_trust_intact() {
        let signer = responder_signer();
        let responses = HashMap::from([(
            leaf_key(&signer),
            online_response(&signer, ResponseSpec::fresh(FixtureStatus::Unknown)),
        )]);
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_responses: Some(&responses),
                ..OnlineEvidence::default()
            },
        );

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_UNKNOWN));
        assert!(!out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        assert!(!out.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(out.results.has_success(SIGNING_CREDENTIAL_TRUSTED));
    }

    #[test]
    fn a_response_from_the_wrong_responder_reads_as_no_answer() {
        let signer = responder_signer();
        let impostor = responder_signer();
        // Signed by a key that does not belong to this certificate's issuer.
        let responses = HashMap::from([(
            leaf_key(&signer),
            response(
                &signer.root_der,
                &signer.leaf_der,
                &Responder {
                    certificate_der: &impostor.root_der,
                    key: &impostor.root_key,
                    embed_certificate: true,
                },
                ResponseSpec::fresh(FixtureStatus::Good),
            ),
        )]);
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_responses: Some(&responses),
                ..OnlineEvidence::default()
            },
        );

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE));
        assert!(!out.results.has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
    }

    #[test]
    fn a_stale_response_reads_as_no_answer_rather_than_a_revocation() {
        let signer = responder_signer();
        let responses = HashMap::from([(
            leaf_key(&signer),
            online_response(
                &signer,
                ResponseSpec {
                    status: FixtureStatus::Good,
                    produced_at: b"20250101000000Z",
                    this_update: b"20250101000000Z",
                    next_update: Some(b"20250102000000Z"),
                },
            ),
        )]);
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_responses: Some(&responses),
                ..OnlineEvidence::default()
            },
        );

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE));
        assert!(!out.results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED));
        assert!(!out.results.has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED));
    }

    #[test]
    fn a_responder_that_was_tried_and_failed_reports_inaccessible() {
        let signer = responder_signer();
        let unreachable = vec![leaf_key(&signer)];
        let out = verify_with_evidence(
            &signer,
            OnlineEvidence {
                ocsp_unreachable: Some(&unreachable),
                ..OnlineEvidence::default()
            },
        );

        assert!(out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE));
        assert!(!out
            .results
            .has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
    }
}
