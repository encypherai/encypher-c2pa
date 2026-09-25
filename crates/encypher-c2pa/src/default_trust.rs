// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use crate::c2pa_trust::{AnchorPurpose, CawgTrustSource, TrustList};

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
    merge(
        AnchorPurpose::ClaimSigning,
        "claim-signing",
        &[C2PA_TRUST_PEM, ENCYPHER_C2PA_ROOT_PEM],
    )
});
static TIMESTAMP_AUTHORITIES: LazyLock<TrustList> = LazyLock::new(|| {
    merge(
        AnchorPurpose::TimeStamping,
        "timestamp-authority",
        &[C2PA_TSA_TRUST_PEM, ENCYPHER_TSA_ISSUING_CA_PEM],
    )
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

#[cfg(test)]
mod tests {
    use super::*;

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
