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
use der::{Decode, Encode, Tag};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use time::macros::datetime;
use time::OffsetDateTime;
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::certpolicy::{PolicyInformation, PolicyQualifierInfo};
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::{
    CertificatePolicies, InhibitAnyPolicy, NameConstraints, PolicyConstraints, PolicyMapping,
    PolicyMappings,
};
use x509_cert::Certificate;

use super::*;
use crate::c2pa_trust::{
    validate_chain, validate_chain_with, AnchorPurpose, TrustAnchor, TrustList,
};

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
    assert!(
        violation(&pair.leaf).is_some_and(|reason| reason.contains("Authority Key Identifier")),
        "missing AKI must be rejected"
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

fn certificate_policies(oids: &[ObjectIdentifier]) -> Vec<u8> {
    CertificatePolicies(
        oids.iter()
            .map(|oid| PolicyInformation {
                policy_identifier: *oid,
                policy_qualifiers: None,
            })
            .collect(),
    )
    .to_der()
    .expect("encode certificate policies")
}

fn policy_mappings(issuer: ObjectIdentifier, subject: ObjectIdentifier) -> Vec<u8> {
    PolicyMappings(vec![PolicyMapping {
        issuer_domain_policy: issuer,
        subject_domain_policy: subject,
    }])
    .to_der()
    .expect("encode policy mappings")
}

fn policy_constraints(require: Option<u32>, inhibit_mapping: Option<u32>) -> Vec<u8> {
    PolicyConstraints {
        require_explicit_policy: require,
        inhibit_policy_mapping: inhibit_mapping,
    }
    .to_der()
    .expect("encode policy constraints")
}

/// Root -> upper CA -> lower CA -> leaf as parsed, signed certificate fixtures.
fn policy_hierarchy(
    upper_hook: impl FnOnce(&mut CertificateParams),
    lower_hook: impl FnOnce(&mut CertificateParams),
    leaf_hook: impl FnOnce(&mut CertificateParams),
    self_issued_lower: bool,
) -> Vec<Certificate> {
    let root_key = KeyPair::generate().expect("root key");
    let root = ca_params("Policy Root", BasicConstraints::Unconstrained)
        .self_signed(&root_key)
        .expect("root");

    let upper_key = KeyPair::generate().expect("upper key");
    let mut upper_params = ca_params("Policy Upper", BasicConstraints::Unconstrained);
    upper_hook(&mut upper_params);
    let upper = upper_params
        .signed_by(&upper_key, &root, &root_key)
        .expect("upper CA");

    let lower_key = KeyPair::generate().expect("lower key");
    let lower_name = if self_issued_lower {
        "Policy Upper"
    } else {
        "Policy Lower"
    };
    let mut lower_params = ca_params(lower_name, BasicConstraints::Unconstrained);
    lower_hook(&mut lower_params);
    let lower = lower_params
        .signed_by(&lower_key, &upper, &upper_key)
        .expect("lower CA");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf = leaf_params("Policy Leaf");
    leaf_hook(&mut leaf);
    let leaf = leaf.signed_by(&leaf_key, &lower, &lower_key).expect("leaf");

    [&leaf, &lower, &upper, &root]
        .into_iter()
        .map(|cert| Certificate::from_der(cert.der()).expect("parse policy fixture"))
        .collect()
}

fn validate_policy_path(path: &[Certificate]) -> crate::c2pa_trust::ChainResult {
    let path_der: Vec<Vec<u8>> = path
        .iter()
        .map(|certificate| certificate.to_der().expect("policy path DER"))
        .collect();
    validate_chain_with(
        &path_der[0],
        &[path_der[1].clone(), path_der[2].clone()],
        &claim_signing_trust(&path[3]),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    )
}

fn policy_information(
    oid: ObjectIdentifier,
    qualifiers: Option<Vec<PolicyQualifierInfo>>,
) -> PolicyInformation {
    PolicyInformation {
        policy_identifier: oid,
        policy_qualifiers: qualifiers,
    }
}

fn validate_policy_leaf(extensions: Vec<CustomExtension>) -> crate::c2pa_trust::ChainResult {
    let path = hierarchy(
        |_| {},
        |params| {
            params.custom_extensions.extend(extensions);
        },
    );
    validate_chain_with(
        &der(&path.leaf),
        &[der(&path.intermediate)],
        &claim_signing_trust(&path.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    )
}

fn cartesian_policy_chain(intermediate_count: usize) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let policies = [
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.90"),
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.91"),
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.92"),
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.93"),
    ];
    let mappings = PolicyMappings(
        policies
            .iter()
            .flat_map(|issuer| {
                policies.iter().map(move |subject| PolicyMapping {
                    issuer_domain_policy: *issuer,
                    subject_domain_policy: *subject,
                })
            })
            .collect(),
    )
    .to_der()
    .expect("Cartesian mappings");

    let root_key = KeyPair::generate().expect("root key");
    let root = ca_params("Cartesian Root", BasicConstraints::Unconstrained)
        .self_signed(&root_key)
        .expect("root");
    let root_der = root.der().to_vec();
    let mut issuer = root;
    let mut issuer_key = root_key;
    let mut intermediates = Vec::with_capacity(intermediate_count);
    for index in 0..intermediate_count {
        let key = KeyPair::generate().expect("intermediate key");
        let mut params = ca_params(
            &format!("Cartesian CA {index}"),
            BasicConstraints::Unconstrained,
        );
        params.custom_extensions.extend([
            custom(&[2, 5, 29, 32], certificate_policies(&policies), false),
            custom(&[2, 5, 29, 33], mappings.clone(), true),
        ]);
        if index == 0 {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 36],
                policy_constraints(Some(0), None),
                true,
            ));
        }
        let certificate = params
            .signed_by(&key, &issuer, &issuer_key)
            .expect("intermediate");
        intermediates.push(certificate.der().to_vec());
        issuer = certificate;
        issuer_key = key;
    }
    intermediates.reverse();

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf = leaf_params("Cartesian Leaf");
    leaf.custom_extensions.push(custom(
        &[2, 5, 29, 32],
        certificate_policies(&policies),
        false,
    ));
    let leaf = leaf
        .signed_by(&leaf_key, &issuer, &issuer_key)
        .expect("leaf");
    (leaf.der().to_vec(), intermediates, root_der)
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

#[test]
fn exact_v2_5_accepts_a_valid_mapped_policy_chain() {
    let issuer_policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.20");
    let subject_policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.21");
    let path = hierarchy(
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[issuer_policy]),
                    false,
                ),
                custom(
                    &[2, 5, 29, 33],
                    policy_mappings(issuer_policy, subject_policy),
                    true,
                ),
                custom(&[2, 5, 29, 36], policy_constraints(Some(0), None), true),
            ]);
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[subject_policy]),
                false,
            ));
        },
    );

    let result = validate_chain_with(
        &der(&path.leaf),
        &[der(&path.intermediate)],
        &claim_signing_trust(&path.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(result.trusted, "{:?}", result.reason);
}

#[test]
fn exact_v2_5_rejects_any_policy_mappings_on_the_processed_path() {
    let mapped_policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.22");
    let path = hierarchy(
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 33],
                policy_mappings(OID_ANY_POLICY, mapped_policy),
                true,
            ));
        },
        |_| {},
    );
    let result = validate_chain_with(
        &der(&path.leaf),
        &[der(&path.intermediate)],
        &claim_signing_trust(&path.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(!result.trusted);
    assert_eq!(
        result.reason.as_deref(),
        Some("policy mapping to or from anyPolicy is forbidden")
    );
}

#[test]
fn exact_v2_5_enforces_mapping_and_any_policy_inhibit_counters() {
    let issuer_policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.30");
    let subject_policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.31");
    let inhibited_mapping = policy_hierarchy(
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[issuer_policy]),
                    false,
                ),
                custom(&[2, 5, 29, 36], policy_constraints(Some(0), Some(0)), true),
            ]);
        },
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[issuer_policy]),
                    false,
                ),
                custom(
                    &[2, 5, 29, 33],
                    policy_mappings(issuer_policy, subject_policy),
                    true,
                ),
            ]);
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[subject_policy]),
                false,
            ));
        },
        false,
    );
    let inhibited_mapping = validate_policy_path(&inhibited_mapping);
    assert_eq!(
        inhibited_mapping.reason.as_deref(),
        Some("an explicit certificate policy is required but not asserted")
    );

    let any_policy_inhibited = hierarchy(
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[issuer_policy]),
                    false,
                ),
                custom(&[2, 5, 29, 36], policy_constraints(Some(0), None), true),
                custom(
                    &[2, 5, 29, 54],
                    InhibitAnyPolicy(0)
                        .to_der()
                        .expect("encode inhibit anyPolicy"),
                    true,
                ),
            ]);
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[OID_ANY_POLICY]),
                false,
            ));
        },
    );
    let any_policy_inhibited = validate_chain_with(
        &der(&any_policy_inhibited.leaf),
        &[der(&any_policy_inhibited.intermediate)],
        &claim_signing_trust(&any_policy_inhibited.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert_eq!(
        any_policy_inhibited.reason.as_deref(),
        Some("an explicit certificate policy is required but not asserted")
    );
}

#[test]
fn exact_v2_5_honors_self_issued_any_policy_and_anchor_boundaries() {
    let policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.40");
    let self_issued_rollover = policy_hierarchy(
        |params| {
            params.custom_extensions.extend([
                custom(&[2, 5, 29, 32], certificate_policies(&[policy]), false),
                custom(&[2, 5, 29, 36], policy_constraints(Some(0), None), true),
                custom(
                    &[2, 5, 29, 54],
                    InhibitAnyPolicy(0)
                        .to_der()
                        .expect("encode inhibit anyPolicy"),
                    true,
                ),
            ]);
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[OID_ANY_POLICY]),
                false,
            ));
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[policy]),
                false,
            ));
        },
        true,
    );
    let rollover_der: Vec<Vec<u8>> = self_issued_rollover.iter().map(der).collect();
    let result = validate_chain_with(
        &rollover_der[0],
        &[rollover_der[1].clone(), rollover_der[2].clone()],
        &claim_signing_trust(&self_issued_rollover[3]),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(result.trusted, "{:?}", result.reason);
    let selected_rollover_anchor = validate_chain_with(
        &rollover_der[0],
        &[],
        &claim_signing_trust(&self_issued_rollover[1]),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(
        selected_rollover_anchor.trusted,
        "a self-issued old-key anchor with AKI is admitted: {:?}",
        selected_rollover_anchor.reason
    );
    let mut rollover_without_aki = self_issued_rollover[1].clone();
    rollover_without_aki
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("rollover extensions")
        .retain(|extension| extension.extn_id != OID_EXT_AUTHORITY_KEY_IDENTIFIER);
    let rejected = validate_chain_with(
        &rollover_der[0],
        &[],
        &claim_signing_trust(&rollover_without_aki),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(
        rejected
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Authority Key Identifier")),
        "an old-key anchor without AKI must be rejected"
    );
    let rollover_without_aki = policy_hierarchy(
        |_| {},
        |params| params.use_authority_key_identifier_extension = false,
        |_| {},
        true,
    );
    let rejected = validate_policy_path(&rollover_without_aki);
    assert!(
        rejected
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("Authority Key Identifier")),
        "a valid old-key signature does not make a self-issued rollover self-signed"
    );

    let anchor_mapping = policy_mappings(OID_ANY_POLICY, ObjectIdentifier::new_unwrap("1.2.3.4"));
    let anchor_constrained = issue(leaf_params("Anchor Boundary Leaf"), {
        let mut root = ca_params("Anchor Boundary Root", BasicConstraints::Unconstrained);
        root.custom_extensions.extend([
            custom(&[2, 5, 29, 33], anchor_mapping, true),
            custom(&[2, 5, 29, 36], policy_constraints(Some(0), Some(0)), true),
        ]);
        root
    });
    let result = validate_chain_with(
        &der(&anchor_constrained.leaf),
        &[],
        &claim_signing_trust(&anchor_constrained.root),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(
        result.trusted,
        "trust-anchor certificate extensions are outside the processed path: {:?}",
        result.reason
    );
    let mut contradictory_anchor = self_issued_rollover[1].clone();
    let extensions = contradictory_anchor
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("anchor extensions");
    let mut duplicate = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_EXT_BASIC_CONSTRAINTS)
        .expect("basic constraints")
        .clone();
    duplicate.extn_value = OctetString::new(
        x509_cert::ext::pkix::BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_der()
        .expect("contradictory basic constraints"),
    )
    .expect("extension value");
    extensions.push(duplicate);
    let rejected = validate_chain_with(
        &rollover_der[0],
        &[],
        &claim_signing_trust(&contradictory_anchor),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert_eq!(
        rejected.reason.as_deref(),
        Some("certificate repeats an extension OID")
    );
}

#[test]
fn exact_v2_5_validates_target_policy_extensions_and_qualifiers() {
    let policy = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.70");
    let duplicate = CertificatePolicies(vec![
        policy_information(policy, None),
        policy_information(policy, None),
    ])
    .to_der()
    .expect("duplicate policy DER");
    let result = validate_policy_leaf(vec![custom(&[2, 5, 29, 32], duplicate, false)]);
    assert_eq!(
        result.reason.as_deref(),
        Some("certificate policies extension repeats a policy OID")
    );

    let repeated_extension = certificate_policies(&[policy]);
    let result = validate_policy_leaf(vec![
        custom(&[2, 5, 29, 32], repeated_extension.clone(), false),
        custom(&[2, 5, 29, 32], repeated_extension, false),
    ]);
    assert_eq!(
        result.reason.as_deref(),
        Some("certificate repeats an extension OID")
    );

    let malformed = validate_policy_leaf(vec![custom(&[2, 5, 29, 33], vec![0x01], true)]);
    assert_eq!(
        malformed.reason.as_deref(),
        Some("policy mappings extension is malformed")
    );
    assert_eq!(
        validate_policy_leaf(vec![custom(&[2, 5, 29, 54], vec![0x01], true)])
            .reason
            .as_deref(),
        Some("inhibit anyPolicy extension is malformed")
    );
    assert_eq!(
        validate_policy_leaf(vec![custom(
            &[2, 5, 29, 36],
            policy_constraints(None, None),
            true,
        )])
        .reason
        .as_deref(),
        Some("policy constraints extension is empty")
    );
    for mappings in [
        policy_mappings(OID_ANY_POLICY, policy),
        policy_mappings(policy, OID_ANY_POLICY),
    ] {
        let result = validate_policy_leaf(vec![custom(&[2, 5, 29, 33], mappings, true)]);
        assert_eq!(
            result.reason.as_deref(),
            Some("policy mapping to or from anyPolicy is forbidden")
        );
    }

    let unknown_qualifier = PolicyQualifierInfo {
        policy_qualifier_id: ObjectIdentifier::new_unwrap("1.2.3.99"),
        qualifier: Some(der::Any::new(Tag::Null, Vec::new()).expect("NULL qualifier")),
    };
    let critical_unknown = CertificatePolicies(vec![policy_information(
        policy,
        Some(vec![unknown_qualifier.clone()]),
    )])
    .to_der()
    .expect("critical unknown qualifier");
    let result = validate_policy_leaf(vec![custom(&[2, 5, 29, 32], critical_unknown, true)]);
    assert_eq!(
        result.reason.as_deref(),
        Some("critical certificate policy has an unknown qualifier")
    );

    let noncritical_unknown = CertificatePolicies(vec![policy_information(
        policy,
        Some(vec![unknown_qualifier]),
    )])
    .to_der()
    .expect("noncritical unknown qualifier");
    assert!(
        validate_policy_leaf(vec![custom(&[2, 5, 29, 32], noncritical_unknown, false,)]).trusted
    );

    let cps = PolicyQualifierInfo {
        policy_qualifier_id: OID_QT_CPS,
        qualifier: Some(
            der::Any::new(Tag::Ia5String, b"https://example.test/cps".to_vec())
                .expect("CPS qualifier"),
        ),
    };
    let valid = CertificatePolicies(vec![policy_information(policy, Some(vec![cps]))])
        .to_der()
        .expect("valid CPS policy");
    assert!(
        validate_policy_leaf(vec![custom(&[2, 5, 29, 32], valid, true)]).trusted,
        "a known, well-formed critical qualifier is processed"
    );
    let user_notice_policy = |encoded: &[u8]| {
        let notice = PolicyQualifierInfo {
            policy_qualifier_id: OID_QT_USER_NOTICE,
            qualifier: Some(der::Any::from_der(encoded).expect("userNotice DER")),
        };
        CertificatePolicies(vec![policy_information(policy, Some(vec![notice]))])
            .to_der()
            .expect("userNotice policy")
    };
    let valid_notice = [
        0x30, 0x12, 0x30, 0x0a, 0x1a, 0x03, b'O', b'r', b'g', 0x30, 0x03, 0x02, 0x01, 0x01, 0x1e,
        0x04, 0x00, b'O', 0x00, b'K',
    ];
    assert!(
        validate_policy_leaf(vec![custom(
            &[2, 5, 29, 32],
            user_notice_policy(&valid_notice),
            true,
        )])
        .trusted,
        "a noticeRef with VisibleString organization and BMPString explicitText is valid"
    );
    let mut overlong_explicit_text = vec![0x30, 0x81, 0xcc, 0x0c, 0x81, 0xc9];
    overlong_explicit_text.extend(std::iter::repeat_n(b'x', 201));
    assert!(
        validate_policy_leaf(vec![custom(
            &[2, 5, 29, 32],
            user_notice_policy(&overlong_explicit_text),
            true,
        )])
        .trusted,
        "RFC 5280 clients must gracefully handle explicitText over 200 characters"
    );
    let mut generalized_time_notice = vec![0x30, 0x11, 0x18, 0x0f];
    generalized_time_notice.extend_from_slice(b"20260101000000Z");
    let missing_notice_numbers = [0x30, 0x07, 0x30, 0x05, 0x1a, 0x03, b'O', b'r', b'g'];
    for invalid_notice in [&generalized_time_notice[..], &missing_notice_numbers[..]] {
        assert_eq!(
            validate_policy_leaf(vec![custom(
                &[2, 5, 29, 32],
                user_notice_policy(invalid_notice),
                true,
            )])
            .reason
            .as_deref(),
            Some("certificate policy userNotice qualifier is malformed")
        );
    }
}

#[test]
fn exact_v2_5_keeps_surviving_policy_branches_when_mapping_is_inhibited() {
    let mapped = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.71");
    let subject = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.72");
    let surviving = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.73");
    let path = policy_hierarchy(
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[mapped, surviving]),
                    false,
                ),
                custom(&[2, 5, 29, 36], policy_constraints(Some(0), Some(0)), true),
            ]);
        },
        |params| {
            params.custom_extensions.extend([
                custom(
                    &[2, 5, 29, 32],
                    certificate_policies(&[mapped, surviving]),
                    false,
                ),
                custom(&[2, 5, 29, 33], policy_mappings(mapped, subject), true),
            ]);
        },
        |params| {
            params.custom_extensions.push(custom(
                &[2, 5, 29, 32],
                certificate_policies(&[surviving]),
                false,
            ));
        },
        false,
    );
    let path_der: Vec<Vec<u8>> = path.iter().map(der).collect();
    let result = validate_chain_with(
        &path_der[0],
        &[path_der[1].clone(), path_der[2].clone()],
        &claim_signing_trust(&path[3]),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(result.trusted, "{:?}", result.reason);
}

#[test]
fn exact_v2_5_stops_at_an_admitted_non_self_signed_anchor() {
    let path = policy_hierarchy(
        |params| {
            params.not_after = datetime!(2025-06-01 0:00 UTC);
        },
        |_| {},
        |_| {},
        false,
    );
    let mut above_anchor = path[3].clone();
    above_anchor.tbs_certificate.version = Version::V1;
    let above_anchor = der(&above_anchor);
    let path_der: Vec<Vec<u8>> = path.iter().map(der).collect();
    let selected = claim_signing_trust(&path[2]);
    let exact = validate_chain_with(
        &path_der[0],
        &[path_der[1].clone(), above_anchor.clone()],
        &selected,
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(exact.trusted, "{:?}", exact.reason);
    let mut invalid_anchor = path[2].clone();
    invalid_anchor.tbs_certificate.version = Version::V1;
    let invalid_anchor = claim_signing_trust(&invalid_anchor);
    let rejected = validate_chain_with(
        &path_der[0],
        &[path_der[1].clone()],
        &invalid_anchor,
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert_eq!(
        rejected.reason.as_deref(),
        Some("certificate is not X.509 v3"),
        "trust configuration does not bypass C2PA anchor admission"
    );
    assert!(
        !validate_chain(
            &path_der[0],
            &[path_der[1].clone(), above_anchor],
            &selected,
            AnchorPurpose::ClaimSigning,
            Some(NOW),
        )
        .trusted,
        "2.4 retains anchor-certificate validity behavior"
    );
}

#[test]
fn exact_v2_5_bounds_cartesian_policy_mappings_near_the_path_depth_limit() {
    let (leaf, intermediates, root) = cartesian_policy_chain(17);
    let result = validate_chain_with(
        &leaf,
        &intermediates,
        &TrustList::from_certificates(AnchorPurpose::ClaimSigning, [root]),
        AnchorPurpose::ClaimSigning,
        Some(NOW),
        CertificateProfile::V2_5,
    );
    assert!(result.trusted, "{:?}", result.reason);
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

#[test]
fn v2_5_claim_algorithm_rules_exempt_ca_tsa_and_ocsp_certificates_only() {
    let dsa = x509_cert::spki::AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.2"),
        parameters: None,
    };

    let mut claim_leaf = conformant().leaf;
    claim_leaf.signature_algorithm = dsa.clone();
    claim_leaf.tbs_certificate.signature = dsa.clone();
    let claim_rules =
        ProfileRules::for_purpose(CertificateProfile::V2_5, AnchorPurpose::ClaimSigning);
    assert_eq!(
        profile_violation_with(&claim_leaf, CertRole::EndEntity, claim_rules),
        Some("certificate signature algorithm is outside the C2PA allow list")
    );

    let exempt_rules = ProfileRules::exempt_end_entity(CertificateProfile::V2_5);
    assert_eq!(
        profile_violation_with(&claim_leaf, CertRole::EndEntity, exempt_rules),
        None,
        "TSA and OCSP leaves are exempt only from the claim algorithm/key list"
    );

    let mut ca = conformant().root;
    ca.signature_algorithm = dsa.clone();
    ca.tbs_certificate.signature = dsa;
    assert_eq!(
        profile_violation_with(&ca, CertRole::Intermediate, claim_rules),
        None,
        "CA certificates are not claim-signing credentials"
    );
}

#[test]
fn v2_5_algorithm_exemptions_keep_structural_profile_checks() {
    let mut tsa_or_ocsp = conformant().leaf;
    tsa_or_ocsp
        .tbs_certificate
        .extensions
        .as_mut()
        .expect("extensions")
        .retain(|extension| extension.extn_id != OID_EXT_KEY_USAGE);
    assert_eq!(
        profile_violation_with(
            &tsa_or_ocsp,
            CertRole::EndEntity,
            ProfileRules::exempt_end_entity(CertificateProfile::V2_5),
        ),
        Some("certificate has no Key Usage extension")
    );

    let mut ca = conformant().root;
    ca.tbs_certificate
        .extensions
        .as_mut()
        .expect("extensions")
        .retain(|extension| extension.extn_id != OID_EXT_KEY_USAGE);
    assert_eq!(
        profile_violation_with(
            &ca,
            CertRole::Intermediate,
            ProfileRules::for_purpose(CertificateProfile::V2_5, AnchorPurpose::ClaimSigning),
        ),
        Some("certificate has no Key Usage extension")
    );
}
