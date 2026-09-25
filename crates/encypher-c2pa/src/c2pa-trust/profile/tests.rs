// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Certificate-profile and path-constraint tests.
//!
//! Fixtures are minted in-process with `rcgen`, so the suite is deterministic
//! and offline. Where `rcgen` cannot express a defect (unique IDs, a v1
//! certificate, a truncated RSA modulus) the encoded certificate is edited
//! through `x509_cert` and re-encoded; the profile runs before and
//! independently of signature verification, so the broken signature that
//! results is irrelevant to what is under test.

use der::asn1::{BitString, Ia5String, OctetString};
use der::{Decode, Encode};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use time::macros::datetime;
use time::OffsetDateTime;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::{NameConstraints, PolicyConstraints};
use x509_cert::Certificate;

use super::*;
use crate::c2pa_trust::{validate_chain, AnchorPurpose, TrustAnchor, TrustList};

const NOT_BEFORE: OffsetDateTime = datetime!(2025-01-01 0:00 UTC);
const NOT_AFTER: OffsetDateTime = datetime!(2030-01-01 0:00 UTC);
const NOW: OffsetDateTime = datetime!(2026-06-01 0:00 UTC);

/// A conformant end-entity certificate, self-issued by `ca` when supplied.
fn leaf_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(vec!["leaf.example".to_string()]).expect("params");
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.not_before = NOT_BEFORE;
    params.not_after = NOT_AFTER;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    // rcgen omits the Authority Key Identifier unless asked; RFC 5280 4.2.1.1
    // requires it on every certificate that is not self-signed.
    params.use_authority_key_identifier_extension = true;
    params
}

fn ca_params(common_name: &str, constraint: BasicConstraints) -> CertificateParams {
    let mut params = CertificateParams::new(vec!["ca.example".to_string()]).expect("params");
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.not_before = NOT_BEFORE;
    params.not_after = NOT_AFTER;
    params.is_ca = IsCa::Ca(constraint);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.use_authority_key_identifier_extension = true;
    params
}

/// A root CA plus a leaf it issued.
struct Pair {
    root: Certificate,
    leaf: Certificate,
}

fn issue(leaf: CertificateParams, root: CertificateParams) -> Pair {
    let root_key = KeyPair::generate().expect("root key");
    let root_cert = root.self_signed(&root_key).expect("root");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf
        .signed_by(&leaf_key, &root_cert, &root_key)
        .expect("leaf");
    Pair {
        root: Certificate::from_der(root_cert.der()).expect("parse root"),
        leaf: Certificate::from_der(leaf_cert.der()).expect("parse leaf"),
    }
}

fn conformant() -> Pair {
    issue(
        leaf_params("Profile Fixture Leaf"),
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    )
}

fn violation(cert: &Certificate) -> Option<&'static str> {
    profile_violation(cert, CertRole::EndEntity)
}

#[test]
fn a_conformant_end_entity_certificate_passes_the_profile() {
    let pair = conformant();
    assert_eq!(violation(&pair.leaf), None);
    assert_eq!(
        profile_violation(&pair.root, CertRole::Intermediate),
        None,
        "the fixture root must satisfy the CA profile so the negative cases are meaningful"
    );
}

#[test]
fn a_certificate_below_version_three_is_rejected() {
    // RFC 5280 4.1.2.1 via the C2PA profile: "Version shall be v3".
    let mut pair = conformant();
    for version in [Version::V1, Version::V2] {
        pair.leaf.tbs_certificate.version = version;
        assert_eq!(violation(&pair.leaf), Some("certificate is not X.509 v3"));
    }
}

#[test]
fn issuer_or_subject_unique_ids_are_rejected() {
    // RFC 5280 4.1.2.8: the unique-ID fields shall not be present.
    let identifier = BitString::from_bytes(&[0x01]).expect("bit string");
    for set in [
        (Some(identifier.clone()), None),
        (None, Some(identifier.clone())),
        (Some(identifier.clone()), Some(identifier)),
    ] {
        let mut pair = conformant();
        pair.leaf.tbs_certificate.issuer_unique_id = set.0;
        pair.leaf.tbs_certificate.subject_unique_id = set.1;
        assert_eq!(
            violation(&pair.leaf),
            Some("certificate carries an issuerUniqueID or subjectUniqueID")
        );
    }
}

#[test]
fn a_non_self_signed_certificate_without_an_authority_key_identifier_is_rejected() {
    let mut pair = conformant();
    let extensions = pair
        .leaf
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("extensions");
    extensions.retain(|extension| extension.extn_id != OID_EXT_AUTHORITY_KEY_IDENTIFIER);
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate is not self-signed and has no Authority Key Identifier")
    );
}

#[test]
fn a_ca_certificate_without_a_subject_key_identifier_is_rejected() {
    let mut pair = conformant();
    let extensions = pair
        .root
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("extensions");
    extensions.retain(|extension| extension.extn_id != OID_EXT_SUBJECT_KEY_IDENTIFIER);
    assert_eq!(
        profile_violation(&pair.root, CertRole::Intermediate),
        Some("CA certificate has no Subject Key Identifier")
    );
}

#[test]
fn an_unrecognized_critical_extension_is_rejected() {
    // RFC 5280 6.1.4(f): a path carrying a critical extension the validator
    // cannot process must be rejected, not silently accepted.
    let mut params = leaf_params("Critical Extension Leaf");
    let mut extension =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 62558, 9, 7], vec![0x05, 0x00]);
    extension.set_criticality(true);
    params.custom_extensions.push(extension);
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate carries an unrecognized critical extension")
    );

    // The same extension marked non-critical is ignorable and accepted.
    let mut params = leaf_params("Critical Extension Leaf");
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 62558, 9, 7],
            vec![0x05, 0x00],
        ));
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(violation(&pair.leaf), None);
}

#[test]
fn a_certificate_without_a_key_usage_extension_is_rejected() {
    let mut params = leaf_params("No Key Usage Leaf");
    params.key_usages = Vec::new();
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate has no Key Usage extension")
    );
}

#[test]
fn key_cert_sign_without_the_ca_basic_constraint_is_rejected() {
    // "The keyCertSign bit shall only be asserted if the cA boolean is
    // asserted in the Basic Constraints extension."
    let mut params = leaf_params("Key Cert Sign Leaf");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate asserts keyCertSign without the cA basic constraint")
    );
}

#[test]
fn a_ca_certificate_that_does_not_assert_key_cert_sign_is_rejected() {
    let mut params = ca_params("No Key Cert Sign CA", BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("ca");
    let cert = Certificate::from_der(cert.der()).expect("parse");
    assert_eq!(
        profile_violation(&cert, CertRole::Intermediate),
        Some("CA certificate does not assert keyCertSign")
    );
}

#[test]
fn an_end_entity_without_a_usable_extended_key_usage_is_rejected() {
    let mut params = leaf_params("No EKU Leaf");
    params.extended_key_usages = Vec::new();
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("end-entity certificate has no Extended Key Usage extension")
    );

    let mut params = leaf_params("Any EKU Leaf");
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::Any,
        ExtendedKeyUsagePurpose::EmailProtection,
    ];
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("end-entity certificate carries anyExtendedKeyUsage")
    );

    // "If a certificate is valid for either id-kp-timeStamping or
    // id-kp-OCSPSigning, it shall be valid for exactly one of those two
    // purposes, and not valid for any other purpose."
    let mut params = leaf_params("Mixed Purpose Leaf");
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::EmailProtection,
    ];
    let pair = issue(
        params,
        ca_params("Profile Fixture Root", BasicConstraints::Unconstrained),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate mixes time-stamping or OCSP signing with another purpose")
    );
}

#[test]
fn a_certificate_signature_algorithm_outside_the_allow_list_is_rejected() {
    let mut pair = conformant();
    // id-dsa-with-sha256: a real algorithm, outside the C2PA allow list.
    let dsa = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.2"),
        parameters: None,
    };
    pair.leaf.signature_algorithm = dsa.clone();
    pair.leaf.tbs_certificate.signature = dsa;
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate signature algorithm is outside the C2PA allow list")
    );
}

#[test]
fn a_mismatched_outer_and_inner_signature_algorithm_is_rejected() {
    // RFC 5280 4.1.1.2: the two AlgorithmIdentifiers must be identical.
    let mut pair = conformant();
    pair.leaf.signature_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA512,
        parameters: None,
    };
    pair.leaf.tbs_certificate.signature = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA384,
        parameters: None,
    };
    assert_eq!(
        violation(&pair.leaf),
        Some("certificate signature algorithm does not match its TBSCertificate")
    );
}

/// An `id-RSASSA-PSS` AlgorithmIdentifier with the supplied parameter DER.
fn pss_algorithm(parameters: Option<der::Any>) -> x509_cert::spki::AlgorithmIdentifierOwned {
    x509_cert::spki::AlgorithmIdentifierOwned {
        oid: OID_RSASSA_PSS,
        parameters,
    }
}

fn pss_params(hash: ObjectIdentifier, mgf_hash: ObjectIdentifier) -> der::Any {
    let params = rsa::pkcs1::RsaPssParams {
        hash: x509_cert::spki::AlgorithmIdentifierRef {
            oid: hash,
            parameters: None,
        },
        mask_gen: x509_cert::spki::AlgorithmIdentifier {
            oid: OID_MGF1,
            parameters: Some(x509_cert::spki::AlgorithmIdentifierRef {
                oid: mgf_hash,
                parameters: None,
            }),
        },
        salt_len: 32,
        trailer_field: Default::default(),
    };
    der::Any::from_der(&params.to_der().expect("encode pss params")).expect("any")
}

#[test]
fn rsassa_pss_certificate_signature_parameters_are_checked() {
    let mut pair = conformant();

    // No parameters at all.
    pair.leaf.signature_algorithm = pss_algorithm(None);
    pair.leaf.tbs_certificate.signature = pss_algorithm(None);
    assert_eq!(
        violation(&pair.leaf),
        Some("RSASSA-PSS certificate signature has no parameters")
    );

    // MGF1 hash different from the hashAlgorithm: the profile requires them to
    // be equal.
    let mismatched = pss_algorithm(Some(pss_params(OID_SHA256, OID_SHA384)));
    pair.leaf.signature_algorithm = mismatched.clone();
    pair.leaf.tbs_certificate.signature = mismatched;
    assert_eq!(
        violation(&pair.leaf),
        Some("RSASSA-PSS MGF1 hash does not match hashAlgorithm")
    );

    // SHA-1 as the PSS hash is outside the allowed digests.
    let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
    let deprecated = pss_algorithm(Some(pss_params(sha1, sha1)));
    pair.leaf.signature_algorithm = deprecated.clone();
    pair.leaf.tbs_certificate.signature = deprecated;
    assert_eq!(
        violation(&pair.leaf),
        Some("RSASSA-PSS hashAlgorithm is not SHA-256, SHA-384 or SHA-512")
    );

    // A conformant PSS AlgorithmIdentifier is accepted.
    let good = pss_algorithm(Some(pss_params(OID_SHA384, OID_SHA384)));
    pair.leaf.signature_algorithm = good.clone();
    pair.leaf.tbs_certificate.signature = good;
    assert_eq!(violation(&pair.leaf), None);
}

/// A PKCS#1 `RSAPublicKey` whose modulus is exactly `bits` bits.
fn rsa_public_key(bits: usize) -> Vec<u8> {
    let mut modulus = vec![0xffu8; bits / 8];
    modulus[0] = 0x80;
    rsa::pkcs1::RsaPublicKey {
        modulus: der::asn1::UintRef::new(&modulus).expect("modulus"),
        public_exponent: der::asn1::UintRef::new(&[0x01, 0x00, 0x01]).expect("exponent"),
    }
    .to_der()
    .expect("encode RSAPublicKey")
}

#[test]
fn an_rsa_modulus_below_two_thousand_forty_eight_bits_is_rejected() {
    let mut pair = conformant();
    let mut with_modulus = |bits: usize| {
        pair.leaf.tbs_certificate.subject_public_key_info =
            x509_cert::spki::SubjectPublicKeyInfoOwned {
                algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                    oid: OID_RSA_ENCRYPTION,
                    parameters: Some(der::Any::null()),
                },
                subject_public_key: BitString::from_bytes(&rsa_public_key(bits))
                    .expect("bit string"),
            };
        violation(&pair.leaf)
    };
    assert_eq!(
        with_modulus(1024),
        Some("RSA modulus is shorter than 2048 bits")
    );
    // The floor itself is accepted, so the rejection above is the bit length
    // and not the RSA form.
    assert_eq!(with_modulus(2048), None);
}

#[test]
fn an_ec_public_key_outside_the_named_curve_set_is_rejected() {
    let mut pair = conformant();
    // secp256k1: a real curve, outside the C2PA profile's three.
    pair.leaf
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters = Some(
        der::Any::from_der(
            &ObjectIdentifier::new_unwrap("1.3.132.0.10")
                .to_der()
                .expect("curve der"),
        )
        .expect("any"),
    );
    assert_eq!(
        violation(&pair.leaf),
        Some("EC public key does not use prime256v1, secp384r1 or secp521r1")
    );
}

// ---------------------------------------------------------------------------
// Path constraints, exercised through validate_chain
// ---------------------------------------------------------------------------

fn der(cert: &Certificate) -> Vec<u8> {
    cert.to_der().expect("encode certificate")
}

fn claim_signing_trust(root: &Certificate) -> TrustList {
    TrustList::from_certificates(AnchorPurpose::ClaimSigning, [der(root)])
}

/// Root -> intermediate -> leaf, with the intermediate configurable.
struct Hierarchy {
    root: Certificate,
    intermediate: Certificate,
    leaf: Certificate,
}

fn hierarchy(
    intermediate_params: impl FnOnce(&mut CertificateParams),
    leaf_params_hook: impl FnOnce(&mut CertificateParams),
) -> Hierarchy {
    let root_key = KeyPair::generate().expect("root key");
    let root = ca_params("Hierarchy Root", BasicConstraints::Unconstrained)
        .self_signed(&root_key)
        .expect("root");

    let mut params = ca_params("Hierarchy Intermediate", BasicConstraints::Unconstrained);
    intermediate_params(&mut params);
    let intermediate_key = KeyPair::generate().expect("intermediate key");
    let intermediate = params
        .signed_by(&intermediate_key, &root, &root_key)
        .expect("intermediate");

    let mut params = leaf_params("Hierarchy Leaf");
    leaf_params_hook(&mut params);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = params
        .signed_by(&leaf_key, &intermediate, &intermediate_key)
        .expect("leaf");

    Hierarchy {
        root: Certificate::from_der(root.der()).expect("parse root"),
        intermediate: Certificate::from_der(intermediate.der()).expect("parse intermediate"),
        leaf: Certificate::from_der(leaf.der()).expect("parse leaf"),
    }
}

#[test]
fn a_path_builds_through_an_unordered_bag_of_intermediates() {
    let wanted = hierarchy(|_| {}, |_| {});
    // Decoys: unrelated CAs, plus one that shares the intermediate's subject
    // name but not its key. A greedy single-candidate walk would stop on the
    // decoy and report the leaf untrusted.
    let decoy = hierarchy(
        |params| {
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "Hierarchy Intermediate");
            params.distinguished_name = name;
        },
        |_| {},
    );
    let bag = vec![
        der(&decoy.intermediate),
        der(&decoy.root),
        der(&wanted.intermediate),
    ];

    let result = validate_chain(
        &der(&wanted.leaf),
        &bag,
        &claim_signing_trust(&wanted.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(result.trusted, "{:?}", result.reason);
    assert!(result.leaf_acceptable);
}

#[test]
fn an_intermediate_path_len_constraint_of_zero_rejects_a_deeper_path() {
    let root_key = KeyPair::generate().expect("root key");
    let root = ca_params("PathLen Root", BasicConstraints::Unconstrained)
        .self_signed(&root_key)
        .expect("root");

    let constrained_key = KeyPair::generate().expect("constrained key");
    let constrained = ca_params("PathLen Constrained CA", BasicConstraints::Constrained(0))
        .signed_by(&constrained_key, &root, &root_key)
        .expect("constrained CA");

    let sub_key = KeyPair::generate().expect("sub key");
    let sub = ca_params("PathLen Sub CA", BasicConstraints::Unconstrained)
        .signed_by(&sub_key, &constrained, &constrained_key)
        .expect("sub CA");

    let direct_key = KeyPair::generate().expect("direct leaf key");
    let direct = leaf_params("PathLen Direct Leaf")
        .signed_by(&direct_key, &constrained, &constrained_key)
        .expect("direct leaf");
    let deep_key = KeyPair::generate().expect("deep leaf key");
    let deep = leaf_params("PathLen Deep Leaf")
        .signed_by(&deep_key, &sub, &sub_key)
        .expect("deep leaf");

    let anchors =
        TrustList::from_certificates(AnchorPurpose::ClaimSigning, [root.der().as_ref().to_vec()]);

    // pathLenConstraint 0 permits an end entity directly beneath the CA.
    let allowed = validate_chain(
        direct.der(),
        &[constrained.der().as_ref().to_vec()],
        &anchors,
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(allowed.trusted, "{:?}", allowed.reason);

    // One more CA beneath it exceeds the constraint.
    let rejected = validate_chain(
        deep.der(),
        &[
            sub.der().as_ref().to_vec(),
            constrained.der().as_ref().to_vec(),
        ],
        &anchors,
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!rejected.trusted);
    assert_eq!(
        rejected.reason.as_deref(),
        Some("issuer pathLenConstraint violated")
    );
}

/// Wrap a DER extension value in a `CustomExtension` for rcgen.
fn custom(oid: &[u64], value: Vec<u8>, critical: bool) -> CustomExtension {
    let mut extension = CustomExtension::from_oid_content(oid, value);
    extension.set_criticality(critical);
    extension
}

#[test]
fn a_leaf_outside_its_issuer_permitted_name_subtree_is_rejected() {
    let constraints = |permitted: &str| {
        NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::DnsName(Ia5String::new(permitted).expect("ia5")),
                minimum: 0,
                maximum: None,
            }]),
            excluded_subtrees: None,
        }
        .to_der()
        .expect("encode name constraints")
    };

    // The leaf's SAN dNSName is `leaf.example`, inside `example` but outside
    // `other.example`.
    let inside = hierarchy(
        |params| {
            params
                .custom_extensions
                .push(custom(&[2, 5, 29, 30], constraints("example"), true))
        },
        |_| {},
    );
    let result = validate_chain(
        &der(&inside.leaf),
        &[der(&inside.intermediate)],
        &claim_signing_trust(&inside.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(result.trusted, "{:?}", result.reason);

    let outside = hierarchy(
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 30],
                constraints("other.example"),
                true,
            ))
        },
        |_| {},
    );
    let result = validate_chain(
        &der(&outside.leaf),
        &[der(&outside.intermediate)],
        &claim_signing_trust(&outside.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!result.trusted);
    assert_eq!(
        result.reason.as_deref(),
        Some("certificate name falls outside every permitted name subtree")
    );
}

#[test]
fn a_leaf_inside_an_excluded_name_subtree_is_rejected() {
    let excluded = NameConstraints {
        permitted_subtrees: None,
        excluded_subtrees: Some(vec![GeneralSubtree {
            base: GeneralName::DnsName(Ia5String::new("leaf.example").expect("ia5")),
            minimum: 0,
            maximum: None,
        }]),
    }
    .to_der()
    .expect("encode name constraints");

    let blocked = hierarchy(
        |params| {
            params
                .custom_extensions
                .push(custom(&[2, 5, 29, 30], excluded, true))
        },
        |_| {},
    );
    let result = validate_chain(
        &der(&blocked.leaf),
        &[der(&blocked.intermediate)],
        &claim_signing_trust(&blocked.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!result.trusted);
    assert_eq!(
        result.reason.as_deref(),
        Some("certificate name falls inside an excluded name subtree")
    );
}

#[test]
fn require_explicit_policy_rejects_a_path_without_a_common_policy() {
    let policy_constraints = PolicyConstraints {
        require_explicit_policy: Some(0),
        inhibit_policy_mapping: None,
    }
    .to_der()
    .expect("encode policy constraints");

    let path = hierarchy(
        |params| {
            params
                .custom_extensions
                .push(custom(&[2, 5, 29, 36], policy_constraints, true))
        },
        |_| {},
    );
    let result = validate_chain(
        &der(&path.leaf),
        &[der(&path.intermediate)],
        &claim_signing_trust(&path.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!result.trusted);
    assert_eq!(
        result.reason.as_deref(),
        Some("an explicit certificate policy is required but not asserted")
    );
}

#[test]
fn certificate_policy_mapping_is_rejected_rather_than_ignored() {
    let mappings =
        x509_cert::ext::pkix::PolicyMappings(vec![x509_cert::ext::pkix::PolicyMapping {
            issuer_domain_policy: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.10"),
            subject_domain_policy: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.11"),
        }])
        .to_der()
        .expect("encode policy mappings");

    let path = hierarchy(
        |params| {
            params
                .custom_extensions
                .push(custom(&[2, 5, 29, 33], mappings, false))
        },
        |_| {},
    );
    let result = validate_chain(
        &der(&path.leaf),
        &[der(&path.intermediate)],
        &claim_signing_trust(&path.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!result.trusted);
    assert_eq!(
        result.reason.as_deref(),
        Some("certificate policy mapping is not supported")
    );
}

// ---------------------------------------------------------------------------
// Trust-anchor configuration (VAL-CRYP-0010/0011)
// ---------------------------------------------------------------------------

#[test]
fn an_anchor_configured_for_another_purpose_never_validates_a_claim_signer() {
    let pair = conformant();
    let anchors = |purpose| TrustList::from_certificates(purpose, [der(&pair.root)]);

    let trusted = validate_chain(
        &der(&pair.leaf),
        &[],
        &anchors(AnchorPurpose::ClaimSigning),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(trusted.trusted, "{:?}", trusted.reason);

    for configured in [AnchorPurpose::TimeStamping, AnchorPurpose::CawgIdentity] {
        let result = validate_chain(
            &der(&pair.leaf),
            &[],
            &anchors(configured),
            AnchorPurpose::ClaimSigning,
            Some(NOW),
        );
        assert!(!result.trusted);
        assert_eq!(
            result.reason.as_deref(),
            Some("certificate does not chain to a trusted anchor")
        );
    }
}

#[test]
fn an_anchor_outside_its_configured_window_is_not_used() {
    let pair = conformant();
    let configured = |not_before, not_after| TrustList {
        anchors: vec![TrustAnchor {
            not_before,
            not_after,
            ..TrustAnchor::new(der(&pair.root), AnchorPurpose::ClaimSigning)
        }],
    };

    // VAL-CRYP-0010: before the configured start.
    let early = validate_chain(
        &der(&pair.leaf),
        &[],
        &configured(Some(datetime!(2027-01-01 0:00 UTC)), None),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!early.trusted);

    // VAL-CRYP-0011: after the configured end.
    let late = validate_chain(
        &der(&pair.leaf),
        &[],
        &configured(None, Some(datetime!(2025-06-01 0:00 UTC))),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(!late.trusted);

    // Inside the configured window the same anchor validates, so the window is
    // what decided the two cases above.
    let inside = validate_chain(
        &der(&pair.leaf),
        &[],
        &configured(
            Some(datetime!(2025-06-01 0:00 UTC)),
            Some(datetime!(2027-01-01 0:00 UTC)),
        ),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
    );
    assert!(inside.trusted, "{:?}", inside.reason);
}

#[test]
fn ip_and_rfc822_name_constraint_matching() {
    // 10.0.0.0/8 permits 10.1.2.3 and excludes 11.1.2.3.
    let base = OctetString::new([10, 0, 0, 0, 255, 0, 0, 0].as_slice()).expect("base");
    let inside = OctetString::new([10, 1, 2, 3].as_slice()).expect("inside");
    let outside = OctetString::new([11, 1, 2, 3].as_slice()).expect("outside");
    assert!(name_within(
        &GeneralName::IpAddress(inside),
        &GeneralName::IpAddress(base.clone())
    ));
    assert!(!name_within(
        &GeneralName::IpAddress(outside),
        &GeneralName::IpAddress(base)
    ));

    let ia5 = |value: &str| Ia5String::new(value).expect("ia5");
    // A bare domain base constrains the host part of an address.
    assert!(rfc822_within("editor@news.example", "news.example"));
    assert!(!rfc822_within("editor@other.example", "news.example"));
    // A leading dot admits subdomains but not the domain itself.
    assert!(rfc822_within("editor@desk.news.example", ".news.example"));
    assert!(!rfc822_within("editor@news.example", ".news.example"));
    // A full mailbox base is an exact match.
    assert!(name_within(
        &GeneralName::Rfc822Name(ia5("editor@news.example")),
        &GeneralName::Rfc822Name(ia5("editor@news.example"))
    ));
    assert!(!name_within(
        &GeneralName::Rfc822Name(ia5("other@news.example")),
        &GeneralName::Rfc822Name(ia5("editor@news.example"))
    ));
    // A URI constraint matches on the authority's host.
    assert!(name_within(
        &GeneralName::UniformResourceIdentifier(ia5("https://desk.news.example/a?b#c")),
        &GeneralName::UniformResourceIdentifier(ia5("news.example"))
    ));
    assert!(!name_within(
        &GeneralName::UniformResourceIdentifier(ia5("https://news.example.org/")),
        &GeneralName::UniformResourceIdentifier(ia5("news.example"))
    ));
}
