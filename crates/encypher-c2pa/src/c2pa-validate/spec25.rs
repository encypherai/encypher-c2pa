// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Validation rules that first apply under the proposed C2PA 2.5 policy.
//!
//! The source is the proposed 2.5 draft (specs-core `cd61a4d1`), compared
//! clause by clause with C2PA 2.4. Every rule here runs only when the caller
//! explicitly selected the 2.5 policy ([`applies`]); the default 2.4 policy
//! never reaches this module except through the gate functions, which return
//! the 2.4 behaviour for it. Rules shared by both revisions stay in the shared
//! validator; only the differences live here.
//!
//! What a manifest declares about itself (`claim_generator_info.specVersion`)
//! never selects these rules: an untrusted generator cannot choose the policy
//! it is judged by.

use std::collections::HashSet;

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    base_assertion_label, is_allowed_hash_algorithm, ClaimAssertionRefs, EngineProfile,
    SpecVersion, ValidationResults, Value, ALGORITHM_UNSUPPORTED,
};
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_crypto::ClaimAlgorithmList;
use crate::c2pa_formats::TextLocatorRules;

/// Failure: a standard manifest carries no actions assertion (2.5 Validate the
/// Assertions, Standard Manifest Assertions).
pub(super) const CLAIM_ACTIONS_MISSING: &str = "claim.actions.missing";
/// Informational: an ingredient referenced by `c2pa.opened`/`c2pa.placed` is
/// declared in a different claim field than the actions assertion.
pub(super) const ASSERTION_ACTION_INGREDIENT_LOCATION_MISMATCH: &str =
    "assertion.action.ingredientLocationMismatch";
/// Informational: a referenced assertion has been redacted.
pub(super) const ASSERTION_REDACTED: &str = "assertion.redacted";
/// Failure: assertion metadata `processStart` is later than `processEnd`.
pub(super) const ASSERTION_METADATA_MALFORMED: &str = "assertion.metadata.malformed";
/// Failure: the located manifest store cannot be interpreted as a C2PA
/// Manifest Store (2.5 Locating the Active Manifest).
pub(super) const MANIFEST_INACCESSIBLE_MALFORMED: &str = "manifest.inaccessible.malformed";
/// Failure: a `c2pa.linked-resource-integrity` assertion is not in
/// `created_assertions`.
pub(super) const LINKED_RESOURCE_NOT_CREATED: &str = "assertion.linkedResourceIntegrity.notCreated";
/// Failure: a `c2pa.linked-resource-integrity` assertion is malformed.
pub(super) const LINKED_RESOURCE_MALFORMED: &str = "assertion.linkedResourceIntegrity.malformed";
/// Failure: a relative linked resource URI traverses with a `..` segment.
pub(super) const LINKED_RESOURCE_INVALID_URI: &str =
    "assertion.linkedResourceIntegrity.invalidURI";
/// Informational: a linked resource was not retrieved.
pub(super) const LINKED_RESOURCE_SKIPPED: &str = "assertion.linkedResourceIntegrity.skipped";
/// Failure extension: the sole hard binding is a 2.5 `c2pa.hash.segment`
/// (append-only text), which this verifier does not evaluate. No registered
/// code says "unevaluated binding", and a manifest whose content binding was
/// never checked must not read as valid, so the verifier fails closed under
/// this extension code, as it does for an unevaluable general box hash.
pub(super) const ASSERTION_SEGMENT_HASH_UNEVALUATED: &str =
    "com.encypher.assertion.segmentHash.unevaluated";

/// Whether the caller selected the proposed 2.5 validation policy.
pub(super) fn applies(profile: EngineProfile) -> bool {
    profile.version >= SpecVersion::V2_5
}

/// The claim-signature algorithm list the selected policy applies.
pub(super) fn claim_algorithms(profile: EngineProfile) -> ClaimAlgorithmList {
    if applies(profile) {
        ClaimAlgorithmList::V2_5
    } else {
        ClaimAlgorithmList::V2_4
    }
}

/// The text-carrier locator the selected policy applies.
pub(super) fn text_rules(profile: EngineProfile) -> TextLocatorRules {
    if applies(profile) {
        TextLocatorRules::V2_5
    } else {
        TextLocatorRules::V2_4
    }
}

/// Whether `label` names a `c2pa.hash.segment` assertion (2.5 append-only
/// text hard binding), counting multi-instance spellings.
pub(super) fn is_segment_hash_label(label: &str) -> bool {
    base_assertion_label(label) == "c2pa.hash.segment"
}

/// Parse a claim-generator time (Specifications of time in assertions).
///
/// The value is a `tdate` (CBOR tag 0 over RFC 3339 text; untagged text is
/// read too, because generators commonly omit the tag) or a map whose `value`
/// is one and whose optional `timeStampType` is `absolute` or the bound kind
/// this field allows (`lowerBound` for a start, `upperBound` for an end).
fn parse_generator_time(value: &Value, upper: bool) -> Option<OffsetDateTime> {
    let parse_tdate = |value: &Value| -> Option<OffsetDateTime> {
        let text = match value {
            Value::Tag(0, inner) => inner.as_text()?,
            Value::Text(text) => text.as_str(),
            _ => return None,
        };
        OffsetDateTime::parse(text, &Rfc3339).ok()
    };
    match value {
        Value::Map(_) => {
            let allowed_bound = if upper { "upperBound" } else { "lowerBound" };
            match value.get("timeStampType") {
                None => {}
                Some(kind) if matches!(kind.as_text(), Some("absolute")) => {}
                Some(kind) if kind.as_text() == Some(allowed_bound) => {}
                Some(_) => return None,
            }
            parse_tdate(value.get("value")?)
        }
        other => parse_tdate(other),
    }
}

/// 2.5 `c2pa.actions` validation, action times: in `c2pa.actions.v2`, `when`
/// shall not appear with `whenStart`/`whenEnd`, and `whenStart` shall not be
/// later than `whenEnd`. The fields are never compared with an external clock.
/// A start or end that cannot be read as a generator time cannot be checked
/// for order, so it fails closed.
pub(super) fn action_time_errors(action: &Value, actions_v2: bool) -> Vec<String> {
    if !actions_v2 {
        return Vec::new();
    }
    let mut errors = Vec::new();
    let start = action.get("whenStart");
    let end = action.get("whenEnd");
    if action.get("when").is_some() && (start.is_some() || end.is_some()) {
        errors.push("action combines when with whenStart or whenEnd".into());
    }
    if let (Some(start), Some(end)) = (start, end) {
        match (
            parse_generator_time(start, false),
            parse_generator_time(end, true),
        ) {
            (Some(start), Some(end)) if start <= end => {}
            (Some(_), Some(_)) => errors.push("action whenStart is later than whenEnd".into()),
            _ => errors.push("action whenStart or whenEnd is not a valid generator time".into()),
        }
    }
    errors
}

/// 2.5 Assertion Validation, General: when an assertion's `metadata` carries
/// both `processStart` and `processEnd`, the start shall not be later than the
/// end. Nothing else in `metadata` is validated.
pub(super) fn verify_metadata_process_windows(
    manifest_label: &str,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    let mut seen = HashSet::new();
    for label in claim_refs
        .references
        .iter()
        .filter_map(|reference| reference.label)
    {
        if !seen.insert(label) {
            continue;
        }
        let Some(metadata) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
            .and_then(|assertion| assertion.get("metadata"))
        else {
            continue;
        };
        let (Some(start), Some(end)) = (metadata.get("processStart"), metadata.get("processEnd"))
        else {
            continue;
        };
        let explanation = match (
            parse_generator_time(start, false),
            parse_generator_time(end, true),
        ) {
            (Some(start), Some(end)) if start <= end => continue,
            (Some(_), Some(_)) => "assertion metadata processStart is later than processEnd",
            _ => "assertion metadata processStart or processEnd is not a valid generator time",
        };
        results.push_failure(
            ASSERTION_METADATA_MALFORMED,
            format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}"),
            explanation.into(),
        );
    }
}

/// Percent-decode `uri`, returning `None` for a malformed escape or a result
/// that is not UTF-8.
fn percent_decode(uri: &str) -> Option<String> {
    let bytes = uri.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// 2.5 `c2pa.linked-resource-integrity` validation.
///
/// Structure, placement, the shared `alg`, and relative-URI traversal are
/// checked and fail the claim as the clause directs. Every well-formed entry
/// then receives exactly one terminal code. This verifier does not retrieve
/// linked resources, so that code is always
/// `assertion.linkedResourceIntegrity.skipped`, carrying the entry's URI as
/// `details.resourceUrl`; per the clause it never rejects the claim.
pub(super) fn verify_linked_resource_integrity(
    manifest_label: &str,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| base_assertion_label(label) == "c2pa.linked-resource-integrity")
        else {
            continue;
        };
        let url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}");
        if reference.field != "created_assertions" {
            results.push_failure(
                LINKED_RESOURCE_NOT_CREATED,
                url.clone(),
                "linked resource integrity assertion is not in created_assertions".into(),
            );
        }
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            // Undecodable payloads already carry assertion.cbor.invalid.
            continue;
        };
        let resources = assertion.get("resources");
        let external = match resources.and_then(|value| value.get("externalResources")) {
            Some(Value::Array(entries)) if !entries.is_empty() => Some(entries),
            _ => None,
        };
        let relative = match resources.and_then(|value| value.get("relativeResources")) {
            Some(Value::Array(entries)) if !entries.is_empty() => Some(entries),
            _ => None,
        };
        let shared_alg = resources
            .and_then(|value| value.get("alg"))
            .and_then(Value::as_text);
        let relative_shape = relative.is_some() && shared_alg.is_some();
        if !matches!(resources, Some(Value::Map(_))) || (external.is_none() && !relative_shape) {
            results.push_failure(
                LINKED_RESOURCE_MALFORMED,
                url,
                "resources is not an object with non-empty externalResources, or non-empty relativeResources with alg".into(),
            );
            continue;
        }
        let mut skipped: Vec<String> = Vec::new();
        for entry in external.into_iter().flatten() {
            let entry_url = entry.get("url").and_then(Value::as_text);
            let complete = entry_url.is_some()
                && entry.get("alg").and_then(Value::as_text).is_some()
                && entry.get("hash").and_then(Value::as_bytes).is_some();
            match entry_url.filter(|_| complete) {
                Some(entry_url) => skipped.push(entry_url.to_string()),
                None => results.push_failure(
                    LINKED_RESOURCE_MALFORMED,
                    url.clone(),
                    "externalResources entry lacks url, alg, or hash".into(),
                ),
            }
        }
        if let Some(entries) = relative.filter(|_| relative_shape) {
            let alg = shared_alg.unwrap_or_default();
            if !is_allowed_hash_algorithm(alg) {
                results.push_failure(
                    ALGORITHM_UNSUPPORTED,
                    url.clone(),
                    format!("linked resource integrity alg '{alg}' is not on the C2PA allowed list"),
                );
            }
            for entry in entries {
                let uri = entry.get("uri").and_then(Value::as_text);
                let (Some(uri), Some(_)) = (uri, entry.get("hash").and_then(Value::as_bytes))
                else {
                    results.push_failure(
                        LINKED_RESOURCE_MALFORMED,
                        url.clone(),
                        "relativeResources entry lacks uri or hash".into(),
                    );
                    continue;
                };
                let traverses = percent_decode(uri)
                    .is_none_or(|decoded| decoded.split('/').any(|segment| segment == ".."));
                if traverses {
                    results.push_failure_with_details(
                        LINKED_RESOURCE_INVALID_URI,
                        url.clone(),
                        "relative linked resource URI contains a '..' path segment or an invalid escape".into(),
                        serde_json::json!({ "resourceUrl": uri }),
                    );
                    continue;
                }
                skipped.push(uri.to_string());
            }
        }
        for resource in skipped {
            results.push_informational_with_details(
                LINKED_RESOURCE_SKIPPED,
                url.clone(),
                "linked resource was not retrieved; this verifier does not fetch linked resources"
                    .into(),
                serde_json::json!({ "resourceUrl": resource }),
            );
        }
    }
}

/// Every assertion named in any claim's `redacted_assertions` across the
/// store, as `(manifest label, assertion label)` (2.5 Preparing the list of
/// redacted assertions: the list spans the asset's whole lineage).
pub(super) fn store_redactions(manifests: &[ParsedManifest<'_>]) -> HashSet<(String, String)> {
    let mut redacted = HashSet::new();
    for manifest in manifests {
        let Some(claim) = manifest
            .claim_cbor
            .and_then(|bytes| crate::c2pa_cbor::decode(bytes).ok())
        else {
            continue;
        };
        let Some(Value::Array(entries)) = claim.get("redacted_assertions") else {
            continue;
        };
        for entry in entries {
            let url = match entry {
                Value::Text(url) => Some(url.as_str()),
                other => other.get("url").and_then(Value::as_text),
            };
            if let Some(target) = url.and_then(absolute_assertion_target) {
                redacted.insert(target);
            }
        }
    }
    redacted
}

/// `(manifest, assertion)` named by an absolute assertion JUMBF URI.
fn absolute_assertion_target(url: &str) -> Option<(String, String)> {
    let (manifest, label) = url
        .strip_prefix("self#jumbf=/c2pa/")?
        .split_once("/c2pa.assertions/")?;
    (!manifest.is_empty() && !label.is_empty() && !label.contains('/'))
        .then(|| (manifest.to_string(), label.to_string()))
}

/// An assertion reference whose target appears in the list of redacted
/// assertions.
pub(super) struct RedactedTarget<'v> {
    /// Whether the target lives in the manifest being validated.
    pub(super) same_manifest: bool,
    /// The target assertion's label.
    pub(super) label: String,
    /// The reference's JUMBF URL, for the status record.
    pub(super) url: &'v str,
}

/// When `reference` names an assertion in the list of redacted assertions,
/// where it lives. A relative URI names the manifest being validated.
///
/// 2.5 lets an action's ingredient references (and `relatedAssertions`)
/// resolve to a redacted assertion, recording `assertion.redacted`; 2.4
/// requires every such reference to resolve to a present assertion.
pub(super) fn redacted_reference_target<'v>(
    reference: &'v Value,
    manifest_label: &str,
    redactions: &HashSet<(String, String)>,
) -> Option<RedactedTarget<'v>> {
    let url = reference.get("url").and_then(Value::as_text)?;
    let (manifest, label) = match absolute_assertion_target(url) {
        Some(target) => target,
        None => (
            manifest_label.to_string(),
            url.strip_prefix("self#jumbf=c2pa.assertions/")?.to_string(),
        ),
    };
    let same_manifest = manifest == manifest_label;
    redactions
        .contains(&(manifest, label.clone()))
        .then_some(RedactedTarget {
            same_manifest,
            label,
            url,
        })
}

/// Whether a related-assertion target label is one 2.5 forbids an ingredient
/// assertion to reference: an ingredient or actions assertion, or a label that
/// does not end with `.ingredient` once any multi-instance suffix is removed.
pub(super) fn ingredient_related_target_error(target: &str) -> Option<&'static str> {
    let base = base_assertion_label(target);
    if matches!(
        base,
        "c2pa.ingredient"
            | "c2pa.ingredient.v2"
            | "c2pa.ingredient.v3"
            | "c2pa.actions"
            | "c2pa.actions.v2"
    ) {
        return Some("relatedAssertions references an ingredient or actions assertion");
    }
    (!base.ends_with(".ingredient"))
        .then_some("relatedAssertions references an assertion whose label does not end with .ingredient")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::map_from_pairs;

    fn tdate(text: &str) -> Value {
        Value::Tag(0, Box::new(Value::Text(text.into())))
    }

    fn action(pairs: Vec<(&str, Value)>) -> Value {
        map_from_pairs(
            std::iter::once(("action".to_string(), Value::Text("c2pa.edited".into())))
                .chain(pairs.into_iter().map(|(key, value)| (key.to_string(), value))),
        )
    }

    #[test]
    fn action_time_rules_apply_to_actions_v2_only() {
        let reversed = action(vec![
            ("whenStart", tdate("2026-05-02T00:00:00Z")),
            ("whenEnd", tdate("2026-05-01T00:00:00Z")),
        ]);
        assert_eq!(action_time_errors(&reversed, true).len(), 1);
        assert!(action_time_errors(&reversed, false).is_empty());

        let ordered = action(vec![
            ("whenStart", tdate("2026-05-01T00:00:00Z")),
            (
                "whenEnd",
                map_from_pairs([
                    ("value".to_string(), tdate("2026-05-01T00:00:00Z")),
                    (
                        "timeStampType".to_string(),
                        Value::Text("upperBound".into()),
                    ),
                ]),
            ),
        ]);
        assert!(action_time_errors(&ordered, true).is_empty());

        let combined = action(vec![
            ("when", tdate("2026-05-01T00:00:00Z")),
            ("whenEnd", tdate("2026-05-02T00:00:00Z")),
        ]);
        assert_eq!(action_time_errors(&combined, true).len(), 1);

        // A start may not declare itself an upper bound.
        let wrong_bound = action(vec![
            (
                "whenStart",
                map_from_pairs([
                    ("value".to_string(), tdate("2026-05-01T00:00:00Z")),
                    (
                        "timeStampType".to_string(),
                        Value::Text("upperBound".into()),
                    ),
                ]),
            ),
            ("whenEnd", tdate("2026-05-02T00:00:00Z")),
        ]);
        assert_eq!(action_time_errors(&wrong_bound, true).len(), 1);
    }

    #[test]
    fn related_target_rules_follow_the_2_5_ingredient_clause() {
        assert!(ingredient_related_target_error("c2pa.ingredient.v3__2").is_some());
        assert!(ingredient_related_target_error("c2pa.actions.v2").is_some());
        assert!(ingredient_related_target_error("c2pa.thumbnail.ingredient.jpeg").is_some());
        assert!(ingredient_related_target_error("c2pa.thumbnail.ingredient").is_none());
        assert!(ingredient_related_target_error("com.example.ingredient__1").is_none());
    }

    #[test]
    fn percent_decoding_exposes_encoded_traversal() {
        assert_eq!(percent_decode("a/%2E%2E/b").as_deref(), Some("a/../b"));
        assert_eq!(percent_decode("bad%zz"), None);
        assert_eq!(percent_decode("./x").as_deref(), Some("./x"));
    }

    #[test]
    fn gates_follow_the_selected_policy_only() {
        use crate::c2pa_core::OperatingMode;
        let v24 = EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular);
        let v25 = EngineProfile::new(SpecVersion::V2_5, OperatingMode::Regular);
        assert!(!applies(v24) && applies(v25));
        assert_eq!(claim_algorithms(v24), ClaimAlgorithmList::V2_4);
        assert_eq!(claim_algorithms(v25), ClaimAlgorithmList::V2_5);
        assert_eq!(text_rules(v24), TextLocatorRules::V2_4);
        assert_eq!(text_rules(v25), TextLocatorRules::V2_5);
        assert!(!applies(EngineProfile::GENEROUS));
    }
}
