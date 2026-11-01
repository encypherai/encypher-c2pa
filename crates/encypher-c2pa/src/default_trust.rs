// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use crate::c2pa_trust::{AnchorPurpose, CawgTrustSource, TrustList, TrustSource};

pub const SNAPSHOT_DATE: &str = "2026-09-24";

const C2PA_TRUST_PEM: &str = include_str!("default_trust/c2pa-trust.pem");
const C2PA_TSA_TRUST_PEM: &str = include_str!("default_trust/c2pa-tsa-trust.pem");
const IPTC_VNPL_END_ENTITY_PEM: &str = include_str!("default_trust/iptc-vnpl-end-entity.pem");
const IPTC_VNPL_ANCHORS_PEM: &str = include_str!("default_trust/iptc-vnpl-anchors.pem");
const CAWG_MOZILLA_EMAIL_ROOTS_PEM: &str =
    include_str!("default_trust/cawg-mozilla-email-roots.pem");
const ENCYPHER_C2PA_ROOT_PEM: &str = include_str!("default_trust/encypher-c2pa-root.pem");
const ENCYPHER_TSA_ISSUING_CA_PEM: &str = include_str!("default_trust/encypher-tsa-issuing-ca.pem");
const ENCYPHER_IDENTITY_ROOT_PEM: &str = include_str!("default_trust/encypher-identity-root.pem");

static CLAIM_SIGNING: LazyLock<TrustList> = LazyLock::new(|| {
    let mut trust = parse(
        AnchorPurpose::ClaimSigning,
        "C2PA claim-signing",
        C2PA_TRUST_PEM,
    )
    .with_source(TrustSource::new(
        "https://c2pa.org/trustlist",
        "c2pa.trustList",
    ));
    append_bundled(
        &mut trust,
        parse(
            AnchorPurpose::ClaimSigning,
            "Encypher claim-signing",
            ENCYPHER_C2PA_ROOT_PEM,
        )
        .anchors,
    );
    trust
});
static TIMESTAMP_AUTHORITIES: LazyLock<TrustList> = LazyLock::new(|| {
    let mut trust = parse(
        AnchorPurpose::TimeStamping,
        "C2PA timestamp-authority",
        C2PA_TSA_TRUST_PEM,
    )
    .with_source(TrustSource::new(
        "https://c2pa.org/trustlist-tsa",
        "c2pa.tsaTrustList",
    ));
    append_bundled(
        &mut trust,
        parse(
            AnchorPurpose::TimeStamping,
            "Encypher timestamp-authority",
            ENCYPHER_TSA_ISSUING_CA_PEM,
        )
        .anchors,
    );
    trust
});
static ALLOWED_CLAIM_SIGNERS: LazyLock<TrustList> = LazyLock::new(|| {
    parse(
        AnchorPurpose::ClaimSigning,
        "IPTC VNPL end-entity",
        IPTC_VNPL_END_ENTITY_PEM,
    )
});
/// The packaged CAWG trust configuration.
///
/// Two entries, and they are not interchangeable. The Mozilla email root
/// store and the IPTC anchor list are the sources CAWG Identity 1.3 names in
/// its interim S/MIME additions, so a credential they accept still needs a
/// trusted time stamp and a validation time on or before 31 March 2027. The
/// Encypher Verified Organizations root is an entry Encypher configures as the
/// validator, under the base trust model, so it carries no interim condition.
static CAWG_IDENTITY: LazyLock<TrustList> = LazyLock::new(|| {
    let mut identity = merge(
        AnchorPurpose::CawgIdentity,
        "CAWG identity interim",
        &[CAWG_MOZILLA_EMAIL_ROOTS_PEM, IPTC_VNPL_ANCHORS_PEM],
    )
    .with_cawg_source(CawgTrustSource::SmimeInterim);
    identity.anchors.extend(
        parse(
            AnchorPurpose::CawgIdentity,
            "Encypher Verified Organizations identity root",
            ENCYPHER_IDENTITY_ROOT_PEM,
        )
        .with_cawg_source(CawgTrustSource::EncypherVerifiedOrganizations)
        .anchors,
    );
    identity
});
/// The IPTC Verified News Publishers end-entity list, which the interim
/// additions name alongside the anchor list.
static CAWG_ALLOWED_IDENTITIES: LazyLock<TrustList> = LazyLock::new(|| {
    parse(
        AnchorPurpose::CawgIdentity,
        "IPTC VNPL end-entity",
        IPTC_VNPL_END_ENTITY_PEM,
    )
    .with_cawg_source(CawgTrustSource::SmimeInterim)
});

fn parse(purpose: AnchorPurpose, label: &str, pem: &str) -> TrustList {
    TrustList::from_pem_for(purpose, pem)
        .unwrap_or_else(|error| panic!("invalid bundled {label} trust list: {error}"))
}

fn merge(purpose: AnchorPurpose, label: &str, bundles: &[&str]) -> TrustList {
    let mut anchors = Vec::new();
    for pem in bundles {
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            continue;
        }
        anchors.extend(parse(purpose, label, pem).anchors);
    }
    assert!(!anchors.is_empty(), "bundled {label} trust list is empty");
    TrustList { anchors }
}

pub(crate) fn claim_signing() -> &'static TrustList {
    &CLAIM_SIGNING
}

pub(crate) fn timestamp_authorities() -> &'static TrustList {
    &TIMESTAMP_AUTHORITIES
}

pub(crate) fn allowed_claim_signers() -> &'static TrustList {
    &ALLOWED_CLAIM_SIGNERS
}

pub(crate) fn cawg_identity() -> &'static TrustList {
    &CAWG_IDENTITY
}

pub(crate) fn cawg_allowed_identities() -> &'static TrustList {
    &CAWG_ALLOWED_IDENTITIES
}
/// A certificate also present in the published list retains that attribution
/// even when a supplemental bundle supplies another copy.
fn append_bundled(trust: &mut TrustList, anchors: Vec<crate::c2pa_trust::TrustAnchor>) {
    for mut anchor in anchors {
        if let Some(listed) = trust
            .anchors
            .iter()
            .find(|listed| listed.certificate == anchor.certificate)
        {
            anchor.source.clone_from(&listed.source);
        }
        trust.anchors.push(anchor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_store_reports_only_the_source_of_the_matching_anchor() {
        use crate::c2pa_cbor::{encode, Profile, Value};
        use crate::c2pa_core::jumbf::{
            assertion_box, build_manifest, build_manifest_store, superbox_content,
        };
        use crate::c2pa_validate::signature_conformance_tests::Signer;
        use sha2::{Digest, Sha256};

        let signer = Signer::conformant();
        let map = |entries: Vec<(&str, Value)>| {
            Value::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (Value::Text(key.into()), value))
                    .collect(),
            )
        };
        let enc = |value: &Value| encode(value, Profile::LegacyPipelineBDefinite).unwrap();
        let binding = enc(&map(vec![
            ("exclusions", Value::Array(vec![])),
            ("alg", Value::Text("sha256".into())),
            (
                "hash",
                Value::Bytes(Sha256::digest(b"fixture asset").to_vec()),
            ),
        ]));
        let actions = enc(&map(vec![(
            "actions",
            Value::Array(vec![map(vec![
                ("action", Value::Text("c2pa.created".into())),
                (
                    "digitalSourceType",
                    Value::Text(
                        "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into(),
                    ),
                ),
            ])]),
        )]));
        let assertions = [
            assertion_box("c2pa.hash.data", &binding, None),
            assertion_box("c2pa.actions.v2", &actions, None),
        ];
        let references = ["c2pa.hash.data", "c2pa.actions.v2"]
            .into_iter()
            .zip(&assertions)
            .map(|(label, stored)| {
                map(vec![
                    (
                        "url",
                        Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                    ),
                    ("alg", Value::Text("sha256".into())),
                    (
                        "hash",
                        Value::Bytes(Sha256::digest(superbox_content(stored).unwrap()).to_vec()),
                    ),
                ])
            })
            .collect();
        let claim = encode(
            &Value::Map(vec![
                (
                    Value::Text("instanceID".into()),
                    Value::Text("xmp:iid:trust-source".into()),
                ),
                (
                    Value::Text("claim_generator_info".into()),
                    Value::Map(vec![(
                        Value::Text("name".into()),
                        Value::Text("Trust source fixture".into()),
                    )]),
                ),
                (
                    Value::Text("created_assertions".into()),
                    Value::Array(references),
                ),
                (
                    Value::Text("signature".into()),
                    Value::Text("self#jumbf=c2pa.signature".into()),
                ),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap();
        let signature = signer.sign(&claim);
        let store = build_manifest_store(&[build_manifest(
            "urn:c2pa:trust-source",
            &assertions,
            &claim,
            &signature,
        )]);
        for sourced in [false, true] {
            let mut options = crate::VerifyOptions {
                spec_version: Some("2.5".into()),
                no_default_trust: true,
                validation_time: Some("2026-06-01T00:00:00Z".into()),
                strict_conformance: true,
                ..Default::default()
            };
            if sourced {
                options.claim_trust_sources =
                    Some(vec![serde_json::from_value(serde_json::json!({
                        "uri": "urn:fixture:trust-list",
                        "type": "c2pa.trustList",
                        "certificates_pem": signer.root_pem(),
                    }))
                    .unwrap()]);
            } else {
                options.trust_pem = Some(signer.root_pem());
            }
            let report = crate::verify_manifest_store_only(&store, &options)
                .unwrap()
                .report;
            assert_eq!(report.signature, "valid");
            let reader = serde_json::to_value(&report).unwrap();
            let sources = &reader["validation_results"]["trust_list_sources"];
            let credentials = report.content_credentials.as_ref().unwrap();
            let uris = &credentials["manifests"][0]["validationResults"]["trustListUris"];
            if sourced {
                let expected = serde_json::json!([{
                    "uri": "urn:fixture:trust-list", "type": "c2pa.trustList"
                }]);
                assert_eq!(sources, &expected);
                assert_eq!(uris, &expected);
            } else {
                assert!(sources.is_null());
                assert!(uris.is_null());
            }
            options.strict_conformance = false;
            let regular = crate::verify_manifest_store_only(&store, &options)
                .unwrap()
                .report;
            let regular = serde_json::to_value(regular).unwrap();
            assert_eq!(
                regular["validation_results"]["trust_list_sources"],
                reader["validation_results"]["trust_list_sources"],
                "reader attribution must not depend on debug/crJSON rendering",
            );
        }
    }

    #[test]
    fn reader_report_serializes_matching_sources_without_a_snapshot_identifier() {
        let source = claim_signing().anchors[0].source.as_ref().unwrap();
        let results = crate::c2pa_validate::ValidationResults {
            trust_list_sources: vec![source.as_ref().clone()],
            ..Default::default()
        };
        let json = serde_json::to_value(results).unwrap();
        assert_eq!(
            json["trust_list_sources"],
            serde_json::json!([{
                "uri": "https://c2pa.org/trustlist",
                "type": "c2pa.trustList"
            }])
        );
        let empty =
            serde_json::to_value(crate::c2pa_validate::ValidationResults::default()).unwrap();
        assert!(empty.get("trust_list_sources").is_none());
    }

    #[test]
    fn bundled_sources_describe_only_the_pem_that_supplied_each_anchor() {
        for (trust, pem, uri, kind) in [
            (
                claim_signing(),
                C2PA_TRUST_PEM,
                "https://c2pa.org/trustlist",
                "c2pa.trustList",
            ),
            (
                timestamp_authorities(),
                C2PA_TSA_TRUST_PEM,
                "https://c2pa.org/trustlist-tsa",
                "c2pa.tsaTrustList",
            ),
        ] {
            let listed = parse(trust.anchors[0].purpose, "listed", pem);
            for anchor in &trust.anchors {
                let expected = listed
                    .anchors
                    .iter()
                    .any(|listed| listed.certificate == anchor.certificate);
                assert_eq!(anchor.source.is_some(), expected);
                if let Some(source) = &anchor.source {
                    assert_eq!(source.uri, uri);
                    assert_eq!(source.source_type, kind);
                    assert_eq!(source.identifier, None);
                }
            }
        }
    }

    #[test]
    fn packaged_snapshot_contains_each_default_trust_source() {
        let sources: serde_json::Value =
            serde_json::from_str(include_str!("default_trust/sources.json"))
                .expect("valid trust source metadata");
        assert_eq!(sources["snapshot_date"], SNAPSHOT_DATE);
        assert_eq!(claim_signing().anchors.len(), 31);
        assert_eq!(timestamp_authorities().anchors.len(), 23);
        assert_eq!(allowed_claim_signers().anchors.len(), 20);
        assert_eq!(cawg_identity().anchors.len(), 92);
        assert_eq!(cawg_allowed_identities().anchors.len(), 20);
    }

    #[test]
    fn caller_trust_extends_the_packaged_snapshot_and_takes_the_configured_window() {
        let not_after = time::macros::datetime!(2027-01-01 0:00 UTC);
        let resolved = crate::resolve_trust(
            Some(ENCYPHER_C2PA_ROOT_PEM),
            None,
            Some(claim_signing()),
            AnchorPurpose::ClaimSigning,
            (None, Some(not_after)),
        )
        .unwrap()
        .unwrap();
        let anchors = &resolved.get().anchors;
        let bundled = claim_signing().anchors.len();
        assert_eq!(anchors.len(), bundled + 1);
        // The bundled snapshot stays unbounded; only the caller's anchor
        // carries the configured window.
        assert!(anchors[..bundled]
            .iter()
            .all(|anchor| anchor.not_after.is_none()));
        assert_eq!(anchors[bundled].not_after, Some(not_after));
    }

    /// The packaged CAWG trust configuration keeps the Encypher Verified
    /// Organizations root out of the interim S/MIME entry: an identity it
    /// issues is accepted under the base 1.3 trust model, with no cutoff and
    /// no trusted-time-stamp condition. Everything else the snapshot carries
    /// is one of the two sources the interim section names.
    #[test]
    fn the_bundled_encypher_identity_root_is_not_an_interim_source() {
        let encypher: Vec<_> = cawg_identity()
            .anchors
            .iter()
            .filter(|anchor| anchor.cawg_source == CawgTrustSource::EncypherVerifiedOrganizations)
            .collect();
        assert_eq!(encypher.len(), 1);
        assert!(!encypher[0].cawg_source.interim());
        assert_eq!(
            encypher[0].certificate,
            parse(
                AnchorPurpose::CawgIdentity,
                "Encypher Verified Organizations identity root",
                ENCYPHER_IDENTITY_ROOT_PEM,
            )
            .anchors[0]
                .certificate
        );
        assert!(cawg_identity()
            .anchors
            .iter()
            .filter(|anchor| {
                anchor.cawg_source != CawgTrustSource::EncypherVerifiedOrganizations
            })
            .all(|anchor| anchor.cawg_source == CawgTrustSource::SmimeInterim));
        assert!(cawg_allowed_identities()
            .anchors
            .iter()
            .all(|anchor| anchor.cawg_source.interim()));
    }

    /// Caller-supplied CAWG material is a validator-configured entry, not an
    /// interim source.
    #[test]
    fn caller_supplied_cawg_material_is_a_configured_entry() {
        let resolved = crate::resolve_trust(
            Some(ENCYPHER_IDENTITY_ROOT_PEM),
            None,
            None,
            AnchorPurpose::CawgIdentity,
            (None, None),
        )
        .unwrap()
        .unwrap();
        assert!(resolved
            .get()
            .anchors
            .iter()
            .all(|anchor| anchor.cawg_source == CawgTrustSource::CallerSupplied));
    }
}
