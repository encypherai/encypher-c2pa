// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! `redacted_assertions` resolution and enforcement (C2PA 2.4 Validation,
//! "Preparing the list of redacted assertions", Assertion Validation, and
//! Validate the Ingredients; Architecture, "Redaction of Assertions").
//!
//! Redaction is a claim stating that an assertion in an INGREDIENT's manifest
//! was removed from the store. The redacting claim carries the JUMBF URI; the
//! target manifest's assertion store either no longer carries the box or
//! carries an emptied one, while that manifest's own claim still references it.
//!
//! That is a powerful primitive, so the declaration itself is validated:
//!
//! - A claim may not redact its own assertions ("A claim's
//!   `redacted_assertions` field shall never include a JUMBF URI to any of its
//!   own assertions"; "if the URI points into the claim's own manifest, the
//!   claim shall be rejected with a failure code of `assertion.selfRedacted`").
//! - "Claim generators shall not redact assertions with a label of
//!   `c2pa.actions` or `c2pa.actions.v2` as this assertion type represents
//!   essential information in understanding the history of an asset"
//!   (`assertion.action.redacted`).
//! - A hard binding is what ties a manifest to its bytes, and the claim
//!   generator "shall not redact the hard binding to content assertion"
//!   (`assertion.hardBinding.redacted`, which supersedes the deprecated
//!   `assertion.dataHash.redacted`).
//! - "if the referenced assertion is present and any JUMBF Content box or
//!   padding box within it contains anything other than zero or more `0x00`
//!   bytes, the claim shall be rejected with a failure code of
//!   `assertion.notRedacted`".
//!
//! The same legality test gates the ingredient side. A redaction changes the
//! ingredient manifest's bytes, so its `activeManifest` hash legitimately no
//! longer matches and the validator must fall back to the claim-signature hash
//! validation method (Validation, "Validate the Ingredients": "If one or more
//! matching redacted assertions are found ... validate the ingredient using
//! the claim signature hash validation method"). Only a LAWFUL redaction earns
//! that fallback: otherwise a claim could excuse any ingredient-manifest
//! mismatch by declaring a redaction the spec forbids.
//!
//! A target manifest that is absent from the store is not a defect. When the
//! last reference to an ingredient manifest is redacted, Architecture requires
//! that manifest to be removed from the store, so the dangling URI is the
//! expected outcome rather than something to report.

use super::{
    ValidationResults, ASSERTION_ACTION_REDACTED, ASSERTION_HARD_BINDING_REDACTED,
    ASSERTION_NOT_REDACTED, ASSERTION_SELF_REDACTED, CLAIM_MALFORMED,
};
use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::ParsedManifest;

/// Ceiling on `redacted_assertions` entries examined for one claim. A claim may
/// not declare more assertions than [`super::MAX_CLAIM_ASSERTION_REFERENCES`],
/// and it cannot lawfully redact more assertions than a store can hold.
const MAX_REDACTED_ASSERTIONS: usize = 4_096;

/// A parsed `redacted_assertions` entry.
struct Target<'a> {
    manifest: &'a str,
    assertion: &'a str,
}

/// How a `redacted_assertions` entry reads.
enum Entry<'a> {
    /// An absolute URI naming an assertion box in another manifest.
    Absolute(Target<'a>),
    /// A URI that can only mean the declaring manifest's own assertion store.
    SelfScoped,
    /// Not a JUMBF assertion URI at all.
    Malformed,
}

/// Read one `redacted_assertions` entry.
///
/// The lawful form is the ABSOLUTE assertion URI: a redaction names a box in
/// another manifest. A relative `self#jumbf=c2pa.assertions/...` URI can only
/// mean the declaring manifest's own store, which is the self-redaction the
/// spec prohibits rather than something to reinterpret.
fn read_entry<'a>(url: &'a str, declaring_label: &str) -> Entry<'a> {
    let Some(rest) = url.strip_prefix("self#jumbf=") else {
        return Entry::Malformed;
    };
    let Some(absolute) = rest.strip_prefix("/c2pa/") else {
        return match rest.strip_prefix("c2pa.assertions/") {
            Some(assertion) if !assertion.is_empty() && !assertion.contains('/') => {
                Entry::SelfScoped
            }
            _ => Entry::Malformed,
        };
    };
    let Some((manifest, assertion)) = absolute.split_once("/c2pa.assertions/") else {
        return Entry::Malformed;
    };
    if manifest.is_empty() || assertion.is_empty() || assertion.contains('/') {
        return Entry::Malformed;
    }
    if manifest == declaring_label {
        return Entry::SelfScoped;
    }
    Entry::Absolute(Target {
        manifest,
        assertion,
    })
}

/// The failure code for an assertion type that may never be redacted, if any.
fn non_redactable(alabel: &str) -> Option<&'static str> {
    let base = super::refs::base_label(alabel);
    if base == "c2pa.actions" || base == "c2pa.actions.v2" {
        return Some(ASSERTION_ACTION_REDACTED);
    }
    if base.starts_with("c2pa.hash.") {
        return Some(ASSERTION_HARD_BINDING_REDACTED);
    }
    None
}

/// The textual JUMBF URI of a `redacted_assertions` entry.
///
/// A bare text URI is the schema form. A hashed-URI map in the position is
/// tolerated for its `url`, because the entry still identifies exactly one
/// assertion box and refusing to read it would silently drop the redaction.
fn entry_url(entry: &Value) -> Option<&str> {
    entry
        .as_text()
        .or_else(|| entry.get("url").and_then(Value::as_text))
}

/// Validate one claim's `redacted_assertions` field.
///
/// Codes land on the DECLARING manifest's status set: it is that claim which
/// is rejected when a redaction is illegal.
pub(super) fn verify_claim_redactions(
    declaring_label: &str,
    claim: &Value,
    manifests: &[ParsedManifest<'_>],
    results: &mut ValidationResults,
) {
    let Some(Value::Array(entries)) = claim.get("redacted_assertions") else {
        return;
    };
    let claim_url = format!("self#jumbf=/c2pa/{declaring_label}/c2pa.claim.v2");
    if entries.len() > MAX_REDACTED_ASSERTIONS {
        results.push_failure(
            CLAIM_MALFORMED,
            claim_url,
            format!("redacted_assertions count exceeds verifier bound ({MAX_REDACTED_ASSERTIONS})"),
        );
        return;
    }
    for entry in entries {
        let Some(url) = entry_url(entry) else {
            results.push_failure(
                CLAIM_MALFORMED,
                claim_url.clone(),
                "redacted_assertions entry is not a JUMBF URI".into(),
            );
            continue;
        };
        let target = match read_entry(url, declaring_label) {
            Entry::Absolute(target) => target,
            Entry::SelfScoped => {
                results.push_failure(
                    ASSERTION_SELF_REDACTED,
                    claim_url.clone(),
                    format!("claim redacts an assertion of its own manifest: '{url}'"),
                );
                continue;
            }
            Entry::Malformed => {
                results.push_failure(
                    CLAIM_MALFORMED,
                    claim_url.clone(),
                    format!(
                        "redacted_assertions entry '{url}' is not an absolute JUMBF assertion URI"
                    ),
                );
                continue;
            }
        };
        if let Some(code) = non_redactable(target.assertion) {
            results.push_failure(
                code,
                url.to_string(),
                format!(
                    "assertion '{}' in manifest '{}' may not be redacted",
                    target.assertion, target.manifest
                ),
            );
            continue;
        }
        // A target manifest the store no longer carries is the lawful outcome
        // of redacting the last reference to it, not a defect.
        let Some(manifest) = manifests
            .iter()
            .find(|manifest| manifest.label == target.manifest)
        else {
            continue;
        };
        if manifest.assertion_content_is_zeroed(target.assertion) == Some(false) {
            results.push_failure(
                ASSERTION_NOT_REDACTED,
                url.to_string(),
                format!(
                    "assertion '{}' is declared redacted but is still present in manifest '{}'",
                    target.assertion, target.manifest
                ),
            );
        }
    }
}

/// Whether `claim` lawfully redacts at least one assertion of `manifest_label`.
///
/// This is the switch C2PA 2.4 Validation, Validate the Ingredients, uses to
/// select the claim-signature hash validation method for an ingredient whose
/// manifest bytes a redaction has changed. An unlawful declaration
/// (self-redaction, an actions assertion, a hard binding) is not a redaction
/// and never excuses an ingredient-manifest hash mismatch.
pub(super) fn redacts_manifest(claim: &Value, manifest_label: &str) -> bool {
    let Some(Value::Array(entries)) = claim.get("redacted_assertions") else {
        return false;
    };
    entries
        .iter()
        .take(MAX_REDACTED_ASSERTIONS)
        .filter_map(entry_url)
        // The declaring label is unknown here, and it does not matter: a
        // self-scoped entry can never name a DIFFERENT manifest, so passing
        // `manifest_label` as the declaring label rejects exactly the entries
        // that would have named it while redacting their own store.
        .any(|url| match read_entry(url, "") {
            Entry::Absolute(target) => {
                target.manifest == manifest_label && non_redactable(target.assertion).is_none()
            }
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{encode, Profile};
    use crate::c2pa_core::jumbf::{assertion_box, redacted_assertion_box, superbox_content};

    const PARENT: &str = "urn:c2pa:parent";
    const CHILD: &str = "urn:c2pa:child";

    fn vmap(fields: Vec<(&str, Value)>) -> Value {
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }

    fn claim_redacting(urls: &[String]) -> Value {
        vmap(vec![(
            "redacted_assertions",
            Value::Array(urls.iter().map(|url| Value::Text(url.clone())).collect()),
        )])
    }

    fn uri(manifest: &str, assertion: &str) -> String {
        format!("self#jumbf=/c2pa/{manifest}/c2pa.assertions/{assertion}")
    }

    /// A child manifest whose assertion store carries `boxes`.
    struct Store {
        boxes: Vec<(String, Vec<u8>)>,
    }

    impl Store {
        fn new(entries: Vec<(String, Vec<u8>)>) -> Self {
            Self {
                boxes: entries
                    .into_iter()
                    .map(|(label, raw)| {
                        (
                            label,
                            superbox_content(&raw).expect("superbox content").to_vec(),
                        )
                    })
                    .collect(),
            }
        }

        fn child(&self) -> ParsedManifest<'_> {
            ParsedManifest {
                label: CHILD.into(),
                manifest_jumbf: &[],
                assertions: Vec::new(),
                assertion_jumbf: self
                    .boxes
                    .iter()
                    .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
                    .collect(),
                claim_cbor: None,
                signature_cose: None,
                claim_count: 1,
                claim_box_label: None,
            }
        }
    }

    fn intact(label: &str) -> (String, Vec<u8>) {
        let cbor = encode(
            &vmap(vec![("v", Value::Bytes(vec![1, 2, 3]))]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("encode");
        (label.to_string(), assertion_box(label, &cbor, None))
    }

    fn emptied(label: &str) -> (String, Vec<u8>) {
        (label.to_string(), redacted_assertion_box(label, 32))
    }

    fn run(claim: &Value, store: &Store) -> ValidationResults {
        let manifests = [store.child()];
        let mut results = ValidationResults::default();
        verify_claim_redactions(PARENT, claim, &manifests, &mut results);
        results
    }

    /// A claim may not redact an assertion of its own manifest, in either the
    /// absolute or the relative spelling.
    #[test]
    fn self_redaction_is_rejected() {
        let store = Store::new(vec![intact("c2pa.metadata")]);
        for url in [
            uri(PARENT, "c2pa.metadata"),
            "self#jumbf=c2pa.assertions/c2pa.metadata".to_string(),
        ] {
            let results = run(&claim_redacting(&[url.clone()]), &store);
            assert!(
                results.has_failure(ASSERTION_SELF_REDACTED),
                "{url}: {:?}",
                results.failure
            );
        }
    }

    /// An actions assertion and a hard binding may never be redacted; each has
    /// its own registered failure code.
    #[test]
    fn actions_and_hard_bindings_may_not_be_redacted() {
        let store = Store::new(vec![]);
        for (label, code) in [
            ("c2pa.actions", ASSERTION_ACTION_REDACTED),
            ("c2pa.actions.v2__1", ASSERTION_ACTION_REDACTED),
            ("c2pa.hash.data", ASSERTION_HARD_BINDING_REDACTED),
            ("c2pa.hash.bmff.v3", ASSERTION_HARD_BINDING_REDACTED),
        ] {
            let results = run(&claim_redacting(&[uri(CHILD, label)]), &store);
            assert!(results.has_failure(code), "{label}: {:?}", results.failure);
        }
        // An ordinary assertion the store no longer carries is lawful.
        let results = run(&claim_redacting(&[uri(CHILD, "c2pa.metadata")]), &store);
        assert!(results.failure.is_empty(), "{:?}", results.failure);
    }

    /// A declared redaction whose target still carries content is
    /// `assertion.notRedacted`; an emptied-in-place box is lawful.
    #[test]
    fn declared_redaction_must_have_happened() {
        let still_there = Store::new(vec![intact("c2pa.metadata")]);
        let results = run(
            &claim_redacting(&[uri(CHILD, "c2pa.metadata")]),
            &still_there,
        );
        assert!(results.has_failure(ASSERTION_NOT_REDACTED));

        let zeroed = Store::new(vec![emptied("c2pa.metadata")]);
        let results = run(&claim_redacting(&[uri(CHILD, "c2pa.metadata")]), &zeroed);
        assert!(results.failure.is_empty(), "{:?}", results.failure);
    }

    /// An entry that is not a JUMBF assertion URI is a malformed claim.
    #[test]
    fn malformed_entries_are_rejected() {
        let store = Store::new(vec![]);
        for url in [
            "https://example.com/assertion".to_string(),
            format!("self#jumbf=/c2pa/{CHILD}"),
            format!("self#jumbf=/c2pa/{CHILD}/c2pa.assertions/"),
            format!("self#jumbf=/c2pa/{CHILD}/c2pa.signature"),
        ] {
            let results = run(&claim_redacting(&[url.clone()]), &store);
            assert!(
                results.has_failure(CLAIM_MALFORMED),
                "{url}: {:?}",
                results.failure
            );
        }
    }

    /// Only a lawful redaction lets an ingredient fall back to the
    /// claim-signature hash validation method.
    #[test]
    fn only_lawful_redactions_switch_the_ingredient_method() {
        assert!(redacts_manifest(
            &claim_redacting(&[uri(CHILD, "c2pa.metadata")]),
            CHILD
        ));
        assert!(!redacts_manifest(
            &claim_redacting(&[uri(CHILD, "c2pa.actions")]),
            CHILD
        ));
        assert!(!redacts_manifest(
            &claim_redacting(&[uri(CHILD, "c2pa.hash.data")]),
            CHILD
        ));
        assert!(!redacts_manifest(
            &claim_redacting(&[uri("urn:c2pa:other", "c2pa.metadata")]),
            CHILD
        ));
        // A hashed-URI map in the entry position still identifies the box.
        let mapped = vmap(vec![(
            "redacted_assertions",
            Value::Array(vec![vmap(vec![(
                "url",
                Value::Text(uri(CHILD, "c2pa.metadata")),
            )])]),
        )]);
        assert!(redacts_manifest(&mapped, CHILD));
    }

    /// A self-redaction must reach a consumer's report from the verification
    /// pipeline, in the default (generous) posture.
    #[test]
    fn a_self_redaction_reaches_the_verification_report() {
        use super::super::{
            verify_manifest, CawgTrustInputs, StoreContext, VerifyInput,
            MAX_REPORT_DECODED_VALUE_NODES,
        };
        use crate::c2pa_core::EngineProfile;
        use crate::c2pa_formats::AssetFormat;

        let claim = claim_redacting(&[uri(PARENT, "c2pa.metadata")]);
        let claim_cbor =
            encode(&claim, Profile::CanonicalForHashedSubstructures).expect("encode claim");
        let manifest = ParsedManifest {
            label: PARENT.into(),
            manifest_jumbf: &[],
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim_cbor),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let manifest_hashes = std::collections::HashMap::new();
        let input = VerifyInput {
            data: &[],
            mime: "application/c2pa",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        let out = verify_manifest(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &manifest_hashes,
            },
            &input,
            AssetFormat::C2paStore,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        );
        assert!(
            out.results.has_failure(ASSERTION_SELF_REDACTED),
            "{:?}",
            out.results.failure
        );
    }
}
