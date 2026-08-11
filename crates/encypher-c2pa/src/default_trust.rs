use std::sync::LazyLock;

use crate::c2pa_trust::TrustList;

pub const SNAPSHOT_DATE: &str = "2026-08-11";

const C2PA_TRUST_PEM: &str = include_str!("default_trust/c2pa-trust.pem");
const C2PA_TSA_TRUST_PEM: &str = include_str!("default_trust/c2pa-tsa-trust.pem");
const IPTC_VNPL_END_ENTITY_PEM: &str = include_str!("default_trust/iptc-vnpl-end-entity.pem");
const IPTC_VNPL_ANCHORS_PEM: &str = include_str!("default_trust/iptc-vnpl-anchors.pem");
const CAWG_MOZILLA_EMAIL_ROOTS_PEM: &str =
    include_str!("default_trust/cawg-mozilla-email-roots.pem");
const ENCYPHER_C2PA_ROOT_PEM: &str = include_str!("default_trust/encypher-c2pa-root.pem");
const ENCYPHER_TSA_ISSUING_CA_PEM: &str = include_str!("default_trust/encypher-tsa-issuing-ca.pem");
const ENCYPHER_IDENTITY_ROOT_PEM: &str = include_str!("default_trust/encypher-identity-root.pem");

static CLAIM_SIGNING: LazyLock<TrustList> =
    LazyLock::new(|| merge("claim-signing", &[C2PA_TRUST_PEM, ENCYPHER_C2PA_ROOT_PEM]));
static TIMESTAMP_AUTHORITIES: LazyLock<TrustList> = LazyLock::new(|| {
    merge(
        "timestamp-authority",
        &[C2PA_TSA_TRUST_PEM, ENCYPHER_TSA_ISSUING_CA_PEM],
    )
});
static ALLOWED_CLAIM_SIGNERS: LazyLock<TrustList> =
    LazyLock::new(|| parse("IPTC VNPL end-entity", IPTC_VNPL_END_ENTITY_PEM));
static CAWG_IDENTITY: LazyLock<TrustList> = LazyLock::new(|| {
    merge(
        "CAWG identity",
        &[
            CAWG_MOZILLA_EMAIL_ROOTS_PEM,
            IPTC_VNPL_ANCHORS_PEM,
            ENCYPHER_IDENTITY_ROOT_PEM,
        ],
    )
});
static CAWG_ALLOWED_IDENTITIES: LazyLock<TrustList> =
    LazyLock::new(|| parse("IPTC VNPL end-entity", IPTC_VNPL_END_ENTITY_PEM));

fn parse(label: &str, pem: &str) -> TrustList {
    TrustList::from_pem(pem)
        .unwrap_or_else(|error| panic!("invalid bundled {label} trust list: {error}"))
}

fn merge(label: &str, bundles: &[&str]) -> TrustList {
    let mut anchors = Vec::new();
    for pem in bundles {
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            continue;
        }
        anchors.extend(parse(label, pem).anchors);
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
        assert_eq!(SNAPSHOT_DATE, "2026-08-11");
        assert_eq!(claim_signing().anchors.len(), 30);
        assert_eq!(timestamp_authorities().anchors.len(), 22);
        assert_eq!(allowed_claim_signers().anchors.len(), 20);
        assert_eq!(cawg_identity().anchors.len(), 92);
        assert_eq!(cawg_allowed_identities().anchors.len(), 20);
    }

    #[test]
    fn caller_trust_extends_the_packaged_snapshot() {
        let resolved = crate::resolve_trust(Some(ENCYPHER_C2PA_ROOT_PEM), Some(claim_signing()))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.get().anchors.len(), 31);
    }
}
