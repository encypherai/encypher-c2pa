// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! What an offline verification could not settle without the network.
//!
//! The verification kernel is pure and offline. Wherever it reports that a
//! check was skipped or a resource was inaccessible, it also records the
//! request that would have answered the question. Nothing here opens a socket:
//! a need is a description, and the fetcher that acts on one lives outside the
//! kernel and runs only with the user's permission.
//!
//! The same description serves two audiences. An SDK caller who fetches the
//! material itself feeds it back through the evidence options on
//! [`VerifyInput`](super::VerifyInput); the report shows the user exactly which
//! hosts a fetch would contact and why, whether or not fetching is enabled.

use serde_json::{json, Value as Json};

/// Which certificate an OCSP query would be about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OcspPurpose {
    /// The C2PA claim signer's certificate chain.
    ClaimSigner,
    /// A CAWG identity assertion's X.509 certificate chain.
    CawgIdentity { assertion_label: String },
}

impl OcspPurpose {
    /// The stable `purpose` string used in the report.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::ClaimSigner => "claim_signer",
            Self::CawgIdentity { .. } => "cawg_identity",
        }
    }
}

/// One network request that would settle a check this verification skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkNeed {
    /// The asset names a manifest store stored elsewhere.
    RemoteManifest { uri: String },
    /// A certificate's issuer publishes an OCSP responder, and no embedded
    /// response settled that certificate's revocation status.
    Ocsp {
        purpose: OcspPurpose,
        /// The `id-ad-ocsp` access location from the certificate's Authority
        /// Information Access extension.
        responder_url: String,
        /// The DER `OCSPRequest` that asks about this certificate.
        request_der: Vec<u8>,
        /// Lowercase hex SHA-256 over the subject certificate's DER. The key
        /// a caller uses to hand the response back as evidence.
        certificate_sha256_hex: String,
    },
    /// A CAWG ICA issuer is a `did:web` DID, which resolves over the network.
    DidDocument { did: String, url: String },
    /// A cloud-data or hashed external-reference assertion stores its content
    /// elsewhere.
    ExternalData {
        uri: String,
        /// The label of the assertion the external content carries.
        assertion_label: String,
    },
}

impl NetworkNeed {
    /// The report shape, reproduced verbatim under `network.needed`.
    ///
    /// `request_der` stays out: it is fetch plumbing, not something a reader
    /// of the report can act on, and it is available on the value itself to
    /// the fetcher that needs it.
    pub(crate) fn to_json(&self) -> Json {
        match self {
            Self::RemoteManifest { uri } => json!({
                "kind": "remote_manifest",
                "uri": uri,
            }),
            Self::Ocsp {
                purpose,
                responder_url,
                certificate_sha256_hex,
                ..
            } => {
                let mut value = json!({
                    "kind": "ocsp",
                    "purpose": purpose.as_str(),
                    "responder_url": responder_url,
                    "certificate_sha256": certificate_sha256_hex,
                });
                if let OcspPurpose::CawgIdentity { assertion_label } = purpose {
                    value["assertion_label"] = json!(assertion_label);
                }
                value
            }
            Self::DidDocument { did, url } => json!({
                "kind": "did_document",
                "did": did,
                "url": url,
            }),
            Self::ExternalData {
                uri,
                assertion_label,
            } => json!({
                "kind": "external_data",
                "uri": uri,
                "assertion_label": assertion_label,
            }),
        }
    }
}

/// Append `need` unless an identical one is already recorded.
///
/// Two manifests in one store can reference the same responder, and a caller
/// must not be asked to approve the same request twice.
pub(super) fn push_unique(needs: &mut Vec<NetworkNeed>, need: NetworkNeed) {
    /// A verification records at most this many distinct needs. The fetcher
    /// applies its own per-run request budget; this bound keeps an adversarial
    /// store from growing the report without limit.
    const MAX_NETWORK_NEEDS: usize = 64;

    if needs.len() >= MAX_NETWORK_NEEDS || needs.contains(&need) {
        return;
    }
    needs.push(need);
}

/// The `did:web` URL an issuer DID resolves to.
///
/// Per the `did:web` method: the method-specific identifier is a percent-
/// encoded host (with `%3A` separating an optional port) optionally followed
/// by colon-separated path segments. A bare host resolves to
/// `/.well-known/did.json`; a path resolves to `<path>/did.json`.
pub(super) fn did_web_url(did: &str) -> Option<String> {
    let identifier = did.strip_prefix("did:web:")?;
    let identifier = identifier.split('#').next().unwrap_or_default();
    let identifier = identifier.split('?').next().unwrap_or_default();
    if identifier.is_empty() {
        return None;
    }
    let mut segments = identifier.split(':');
    let host = segments.next()?.replace("%3A", ":").replace("%3a", ":");
    if host.is_empty() || host.contains('/') {
        return None;
    }
    let path: Vec<&str> = segments.filter(|segment| !segment.is_empty()).collect();
    if path.is_empty() {
        return Some(format!("https://{host}/.well-known/did.json"));
    }
    Some(format!("https://{host}/{}/did.json", path.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_resolves_to_the_well_known_document() {
        assert_eq!(
            did_web_url("did:web:example.com").as_deref(),
            Some("https://example.com/.well-known/did.json")
        );
    }

    #[test]
    fn a_port_and_path_travel_into_the_url() {
        assert_eq!(
            did_web_url("did:web:example.com%3A8443:user:alice").as_deref(),
            Some("https://example.com:8443/user/alice/did.json")
        );
    }

    #[test]
    fn a_fragment_names_a_key_inside_the_same_document() {
        assert_eq!(
            did_web_url("did:web:example.com:issuers:1#key-0").as_deref(),
            Some("https://example.com/issuers/1/did.json")
        );
    }

    #[test]
    fn a_non_web_did_has_no_url() {
        assert_eq!(did_web_url("did:key:z6Mk"), None);
        assert_eq!(did_web_url("did:web:"), None);
    }

    #[test]
    fn the_cawg_ocsp_shape_names_the_assertion_it_came_from() {
        let need = NetworkNeed::Ocsp {
            purpose: OcspPurpose::CawgIdentity {
                assertion_label: "cawg.identity".into(),
            },
            responder_url: "http://ocsp.example/r".into(),
            request_der: vec![0x30, 0x00],
            certificate_sha256_hex: "ab".repeat(32),
        };
        assert_eq!(
            need.to_json(),
            json!({
                "kind": "ocsp",
                "purpose": "cawg_identity",
                "assertion_label": "cawg.identity",
                "responder_url": "http://ocsp.example/r",
                "certificate_sha256": "ab".repeat(32),
            })
        );
    }

    #[test]
    fn the_claim_signer_ocsp_shape_carries_no_assertion_label() {
        let need = NetworkNeed::Ocsp {
            purpose: OcspPurpose::ClaimSigner,
            responder_url: "http://ocsp.example/r".into(),
            request_der: Vec::new(),
            certificate_sha256_hex: "cd".repeat(32),
        };
        assert_eq!(
            need.to_json(),
            json!({
                "kind": "ocsp",
                "purpose": "claim_signer",
                "responder_url": "http://ocsp.example/r",
                "certificate_sha256": "cd".repeat(32),
            })
        );
    }

    #[test]
    fn the_same_need_is_never_recorded_twice() {
        let mut needs = Vec::new();
        for _ in 0..3 {
            push_unique(
                &mut needs,
                NetworkNeed::RemoteManifest {
                    uri: "https://example.com/store.c2pa".into(),
                },
            );
        }
        push_unique(
            &mut needs,
            NetworkNeed::RemoteManifest {
                uri: "https://other.example/store.c2pa".into(),
            },
        );
        assert_eq!(needs.len(), 2);
    }
}
