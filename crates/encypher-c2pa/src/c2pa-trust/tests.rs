// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust-list, EKU policy, chain validation, and revocation.

use super::*;
use der::Encode;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, SerialNumber,
};
use time::macros::datetime;
use x509_cert::ext::pkix::ExtendedKeyUsage as X509Eku;

/// Build a self-signed certificate, returning `(der, pem)`.
fn make_cert(configure: impl FnOnce(&mut CertificateParams)) -> (Vec<u8>, String) {
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(vec!["test.example".to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Encypher Test Root CA");
    params.distinguished_name = dn;
    params.not_before = datetime!(2025-01-01 0:00 UTC);
    params.not_after = datetime!(2027-01-01 0:00 UTC);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    configure(&mut params);
    let cert = params.self_signed(&key).expect("self-signed cert");
    (cert.der().as_ref().to_vec(), cert.pem())
}

fn make_named_ca(common_name: &str) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("CA key");
    let mut params = CertificateParams::new(vec!["ca.example".to_string()]).expect("CA params");
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    params.not_before = datetime!(2025-01-01 0:00 UTC);
    params.not_after = datetime!(2030-01-01 0:00 UTC);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params.self_signed(&key).expect("self-signed CA");
    (certificate, key)
}

/// DER bytes of an EKU extension value containing a single OID.
fn eku_value(oid: &str) -> Vec<u8> {
    let oid = const_oid::ObjectIdentifier::new_unwrap(oid);
    X509Eku(vec![oid]).to_der().expect("encode eku")
}

/// DER bytes of an EKU extension value containing several OIDs.
fn eku_value_multi(oids: &[&str]) -> Vec<u8> {
    X509Eku(
        oids.iter()
            .map(|oid| const_oid::ObjectIdentifier::new_unwrap(oid))
            .collect(),
    )
    .to_der()
    .expect("encode eku")
}

/// Non-CA leaf with digitalSignature keyUsage carrying exactly the given EKUs.
fn leaf_with_ekus(oids: &[&str]) -> Vec<u8> {
    let (der, _) = make_cert(|p| {
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            eku_value_multi(oids),
        ));
    });
    der
}

#[test]
fn claim_signer_profile_accepts_the_full_reference_eku_set() {
    // The reference validator's claim-signing EKU set: emailProtection,
    // both documentSigning OIDs, c2pa-kp-claimSigning, and Microsoft C2PA.
    for oid in [
        OID_C2PA_CLAIM_SIGNING,
        OID_ADOBE_DOCUMENT_SIGNING,
        OID_IETF_DOCUMENT_SIGNING,
        OID_EMAIL_PROTECTION,
        OID_MICROSOFT_C2PA,
    ] {
        assert!(
            leaf_acceptable_der(&leaf_with_ekus(&[oid])),
            "{oid} must be an acceptable claim-signer EKU"
        );
    }
    // ServerAuth alone stays rejected.
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        "1.3.6.1.5.5.7.3.1"
    ])));
    // anyExtendedKeyUsage stays rejected, even combined with a permitted OID.
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_EMAIL_PROTECTION,
        "2.5.29.37.0"
    ])));
}

#[test]
fn timestamping_and_ocsp_ekus_never_authorize_claim_signing() {
    // Trust Model, Certificate Trust Chain: "A validator shall ensure a signing
    // certificate is authorized for the purpose for which it is being used, and
    // reject certificates used for an unauthorized purpose", with a certificate
    // "authorized for no more than one of the three purposes: C2PA signing,
    // time-stamp signing, or OCSP response signing". A sole timeStamping or
    // OCSPSigning EKU authorizes that other purpose, never claim signing.
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_KP_TIME_STAMPING
    ])));
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_KP_OCSP_SIGNING
    ])));
    // Combining either with a claim-signing EKU breaks the profile's
    // "valid for exactly one of those two purposes, and not valid for any
    // other purpose" rule, so it is rejected as well.
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_KP_TIME_STAMPING,
        OID_EMAIL_PROTECTION
    ])));
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_KP_OCSP_SIGNING,
        OID_C2PA_CLAIM_SIGNING
    ])));
    // Both together is likewise unauthorized.
    assert!(!leaf_acceptable_der(&leaf_with_ekus(&[
        OID_KP_TIME_STAMPING,
        OID_KP_OCSP_SIGNING
    ])));
}

#[test]
fn trust_list_anchor_subjects() {
    let (_, pem) = make_cert(|_| {});
    let trust = TrustList::from_pem(&pem).expect("parse pem");
    assert_eq!(trust.anchors.len(), 1);
    assert_eq!(
        trust.anchor_subjects(),
        vec!["Encypher Test Root CA".to_string()]
    );
}

#[test]
fn from_pem_rejects_empty_input() {
    assert!(matches!(
        TrustList::from_pem("not a certificate"),
        Err(TrustError::NoCertificates) | Err(TrustError::Decode(_))
    ));
    // A zero-byte or whitespace-only bundle must be a clean error, never a
    // panic: x509-cert's load_pem_chain overflows on blockless input, and the
    // live IPTC VNPL anchor list is served as a legitimate empty file.
    assert!(matches!(
        TrustList::from_pem(""),
        Err(TrustError::NoCertificates)
    ));
    assert!(matches!(
        TrustList::from_pem("\n"),
        Err(TrustError::NoCertificates)
    ));
}

/// Claim-signing anchors with no configured window.
fn claim_signing_anchors(certificates: impl IntoIterator<Item = Vec<u8>>) -> TrustList {
    TrustList::from_certificates(AnchorPurpose::ClaimSigning, certificates)
}

#[test]
fn self_signed_cert_chains_to_itself_as_anchor() {
    let (der, _) = make_cert(|_| {});
    let trust = claim_signing_anchors([der.clone()]);
    // Validate within the cert's validity window.
    let at = Some(datetime!(2026-01-01 0:00 UTC));
    let result = validate_chain(&der, &[], &trust, AnchorPurpose::ClaimSigning, at);
    assert!(
        result.trusted,
        "self-signed anchor should be trusted: {:?}",
        result.reason
    );
    assert!(result.reason.is_none());
}

#[test]
fn untrusted_when_anchor_not_present() {
    let (der, _) = make_cert(|_| {});
    let empty = TrustList::default();
    let at = Some(datetime!(2026-01-01 0:00 UTC));
    let result = validate_chain(&der, &[], &empty, AnchorPurpose::ClaimSigning, at);
    assert!(!result.trusted);
    assert!(result.reason.unwrap().contains("does not chain"));
}

#[test]
fn chain_builder_skips_same_subject_ca_with_wrong_key() {
    let (wrong_issuer, _) = make_named_ca("Shared Test CA");
    let (issuer, issuer_key) = make_named_ca("Shared Test CA");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
    params.not_before = datetime!(2025-01-01 0:00 UTC);
    params.not_after = datetime!(2027-01-01 0:00 UTC);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    params.use_authority_key_identifier_extension = true;
    let leaf = params
        .signed_by(&leaf_key, &issuer, &issuer_key)
        .expect("issued leaf");
    let trust = claim_signing_anchors([
        wrong_issuer.der().as_ref().to_vec(),
        issuer.der().as_ref().to_vec(),
    ]);

    let result = validate_chain(
        leaf.der().as_ref(),
        &[],
        &trust,
        AnchorPurpose::ClaimSigning,
        Some(datetime!(2026-01-01 0:00 UTC)),
    );
    assert!(result.trusted, "{:?}", result.reason);
}

#[test]
fn non_admitted_anchor_can_bridge_to_an_admitted_anchor() {
    let (root, root_key) = make_named_ca("Admitted Root");
    let bridge_key = KeyPair::generate().expect("bridge key");
    let mut bridge_params =
        CertificateParams::new(vec!["bridge.example".to_string()]).expect("bridge params");
    let mut bridge_name = DistinguishedName::new();
    bridge_name.push(DnType::CommonName, "Profile Bridge");
    bridge_params.distinguished_name = bridge_name;
    bridge_params.not_before = datetime!(2025-01-01 0:00 UTC);
    bridge_params.not_after = datetime!(2027-01-01 0:00 UTC);
    bridge_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    bridge_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    bridge_params.use_authority_key_identifier_extension = true;
    let bridge = bridge_params
        .signed_by(&bridge_key, &root, &root_key)
        .expect("bridge certificate");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["leaf.example".to_string()]).expect("leaf params");
    leaf_params.not_before = datetime!(2025-01-01 0:00 UTC);
    leaf_params.not_after = datetime!(2027-01-01 0:00 UTC);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf = leaf_params
        .signed_by(&leaf_key, &bridge, &bridge_key)
        .expect("issued leaf");

    let mut trust = TrustList::from_certificates(
        AnchorPurpose::ClaimSigning,
        [bridge.der().to_vec(), root.der().to_vec()],
    );
    trust.anchors[0].cawg_source = CawgTrustSource::SmimeInterim;
    trust.anchors[1].cawg_source = CawgTrustSource::CallerSupplied;
    let result = validate_chain_admitting(
        leaf.der(),
        &[],
        &trust,
        AnchorPurpose::ClaimSigning,
        Some(datetime!(2026-01-01 0:00 UTC)),
        |anchor| anchor.cawg_source == CawgTrustSource::CallerSupplied,
    );
    assert!(result.trusted, "{:?}", result.reason);
    assert_eq!(result.anchor, Some(1));
}

#[test]
fn self_issued_v3_end_entity_without_basic_constraints_stays_a_direct_match() {
    let key = KeyPair::generate().expect("key");
    let mut params = CertificateParams::new(vec!["actor.example".to_string()]).expect("params");
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Self-issued CAWG Actor");
    params.distinguished_name = name;
    params.not_before = datetime!(2025-01-01 0:00 UTC);
    params.not_after = datetime!(2027-01-01 0:00 UTC);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let certificate = params.self_signed(&key).expect("self-issued certificate");
    let der = certificate.der().to_vec();
    let parsed = Certificate::from_der(&der).expect("certificate");
    assert_eq!(
        parsed.tbs_certificate.version,
        x509_cert::certificate::Version::V3
    );
    assert!(!has_extension(&parsed, OID_EXT_BASIC_CONSTRAINTS));

    let (anchors, direct) =
        TrustList::from_certificates(AnchorPurpose::CawgIdentity, [der.clone()])
            .split_certificate_authorities();
    assert!(anchors.anchors.is_empty());
    assert!(direct.contains_certificate(&der));
}

#[test]
fn validation_time_before_not_before_is_untrusted() {
    let (der, _) = make_cert(|_| {});
    let trust = claim_signing_anchors([der.clone()]);
    // 2020 is before the cert's notBefore (2025) -> not valid at that instant.
    let before = Some(datetime!(2020-06-01 0:00 UTC));
    let result = validate_chain(&der, &[], &trust, AnchorPurpose::ClaimSigning, before);
    assert!(!result.trusted);
    assert!(result
        .reason
        .unwrap()
        .contains("outside its validity window"));
    assert_eq!(result.validated_at, datetime!(2020-06-01 0:00 UTC));
}

#[test]
fn validation_time_within_window_is_trusted() {
    let (der, _) = make_cert(|_| {});
    let trust = claim_signing_anchors([der.clone()]);
    let within = Some(datetime!(2026-06-01 0:00 UTC));
    let result = validate_chain(&der, &[], &trust, AnchorPurpose::ClaimSigning, within);
    assert!(
        result.trusted,
        "should be trusted within validity: {:?}",
        result.reason
    );
    assert_eq!(result.validated_at, datetime!(2026-06-01 0:00 UTC));
}

#[test]
fn validation_time_after_not_after_is_untrusted() {
    let (der, _) = make_cert(|_| {});
    let trust = claim_signing_anchors([der.clone()]);
    let after = Some(datetime!(2030-01-01 0:00 UTC));
    let result = validate_chain(&der, &[], &trust, AnchorPurpose::ClaimSigning, after);
    assert!(!result.trusted);
    assert!(result
        .reason
        .unwrap()
        .contains("outside its validity window"));
}

#[test]
fn eku_policy_accepts_claim_signing_oid() {
    let (der, _) = make_cert(|p| {
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            eku_value(OID_C2PA_CLAIM_SIGNING),
        ));
    });
    let policy = EkuPolicy::default();
    assert!(policy.cert_has_required_eku(&der));
}

#[test]
fn eku_policy_rejects_cert_without_allowed_oid() {
    // ServerAuth (1.3.6.1.5.5.7.3.1) is not in the default allowed set.
    let (der, _) = make_cert(|p| {
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    });
    let policy = EkuPolicy::default();
    assert!(!policy.cert_has_required_eku(&der));
}

#[test]
fn eku_policy_rejects_cert_without_eku_extension() {
    let (der, _) = make_cert(|_| {});
    let policy = EkuPolicy::default();
    assert!(!policy.cert_has_required_eku(&der));
}

#[test]
fn revocation_denylist_matches_by_serial() {
    let (der, _) = make_cert(|p| {
        p.serial_number = Some(SerialNumber::from(0x1234u64));
    });
    let denylist = RevocationDenylist::new(["1234".to_string()], std::iter::empty());
    assert!(denylist.is_revoked(&der));

    let empty = RevocationDenylist::default();
    assert!(!empty.is_revoked(&der));

    let other = RevocationDenylist::new(["dead".to_string()], std::iter::empty());
    assert!(!other.is_revoked(&der));
}

#[test]
fn revocation_denylist_matches_by_fingerprint() {
    let (der, _) = make_cert(|_| {});
    let fp = hex::encode(Sha256::digest(&der));
    let denylist = RevocationDenylist::new(std::iter::empty(), [fp.to_uppercase()]);
    // Normalization lowercases tokens, so an uppercase fingerprint still matches.
    assert!(denylist.is_revoked(&der));
}
