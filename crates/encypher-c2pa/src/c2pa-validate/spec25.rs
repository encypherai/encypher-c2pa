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
    base_assertion_label, hash_bytes, is_allowed_hash_algorithm,
    network_needs::{push_unique, NetworkNeed},
    ClaimAssertionRefs, EngineProfile, OnlineEvidence, SpecVersion, ValidationResults, Value,
    ALGORITHM_UNSUPPORTED,
};
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_crypto::ClaimAlgorithmList;
use crate::c2pa_formats::{AppendOnlyFlavor, AssetFormat, TextLocatorRules};

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
pub(super) const LINKED_RESOURCE_INVALID_URI: &str = "assertion.linkedResourceIntegrity.invalidURI";
/// Informational: a linked resource was not retrieved.
pub(super) const LINKED_RESOURCE_SKIPPED: &str = "assertion.linkedResourceIntegrity.skipped";
/// Success: every applicable linked-resource check matched.
pub(super) const LINKED_RESOURCE_MATCH: &str = "assertion.linkedResourceIntegrity.match";
/// Informational: retrieval was attempted but no usable body was obtained.
pub(super) const LINKED_RESOURCE_INACCESSIBLE: &str =
    "assertion.linkedResourceIntegrity.inaccessible";
/// Informational: retrieved size differs from the assertion.
pub(super) const LINKED_RESOURCE_SIZE_MISMATCH: &str =
    "assertion.linkedResourceIntegrity.sizeMismatch";
/// Informational: retrieved media type differs from the assertion.
pub(super) const LINKED_RESOURCE_FORMAT_MISMATCH: &str =
    "assertion.linkedResourceIntegrity.formatMismatch";
/// Informational: retrieved bytes differ from the assertion digest.
pub(super) const LINKED_RESOURCE_HASH_MISMATCH: &str =
    "assertion.linkedResourceIntegrity.hashMismatch";

/// Whether the caller selected the proposed 2.5 validation policy.
pub(super) fn applies(profile: EngineProfile) -> bool {
    profile.version == SpecVersion::V2_5
}

/// The claim-signature algorithm list the selected policy applies.
pub(super) fn claim_algorithms(profile: EngineProfile) -> ClaimAlgorithmList {
    match profile.version {
        SpecVersion::V2_2 => ClaimAlgorithmList::V2_2,
        SpecVersion::V2_5 => ClaimAlgorithmList::V2_5,
        _ => ClaimAlgorithmList::V2_4,
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

/// The carrier the selected policy reads an asset with.
///
/// 2.5 distinguishes the two `text/plain` methods by their delimiters alone
/// (Embedding manifests into append-only text files, Applicability): a plain
/// text file carrying complete `-----BEGIN C2PA CHECKPOINT-----` lines is an
/// append-only file, not unstructured text. The 2.4 policy keeps reading
/// every `text/plain` asset as unstructured text.
pub(super) fn select_format(
    format: AssetFormat,
    mime: &str,
    data: &[u8],
    profile: EngineProfile,
) -> AssetFormat {
    if applies(profile)
        && format == AssetFormat::TextUnstructured
        && crate::c2pa_core::spec::canonicalize_mime(mime) == "text/plain"
        && crate::c2pa_formats::declares_checkpoints(data, AppendOnlyFlavor::PlainText)
    {
        AssetFormat::AppendOnlyText {
            flavor: AppendOnlyFlavor::PlainText,
        }
    } else {
        format
    }
}

/// A claim-generator instant, ordered exactly.
///
/// RFC 3339 places no limit on fractional-second digits, but `OffsetDateTime`
/// keeps nanoseconds, so two instants that differ only past the ninth digit
/// would compare equal and a reversed range could pass. The whole-second
/// instant (offset applied) is compared first and the fraction second, as its
/// decimal digits with trailing zeros removed, which orders lexicographically
/// exactly as the decimal values do.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GeneratorTime {
    unix_seconds: i64,
    fraction: Vec<u8>,
}

/// Parse RFC 3339 text into a [`GeneratorTime`] without losing precision.
fn parse_rfc3339_exact(text: &str) -> Option<GeneratorTime> {
    let time_start = text.find(['T', 't'])?;
    let (whole_seconds, fraction) = match text[time_start..].find('.') {
        Some(relative) => {
            let dot = time_start + relative;
            let digits = text[dot + 1..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
            if digits == 0 {
                return None;
            }
            let fraction = text[dot + 1..dot + 1 + digits]
                .trim_end_matches('0')
                .as_bytes()
                .to_vec();
            (
                format!("{}{}", &text[..dot], &text[dot + 1 + digits..]),
                fraction,
            )
        }
        None => (text.to_string(), Vec::new()),
    };
    let instant = OffsetDateTime::parse(&whole_seconds, &Rfc3339).ok()?;
    Some(GeneratorTime {
        unix_seconds: instant.unix_timestamp(),
        fraction,
    })
}

/// Parse a claim-generator time (Specifications of time in assertions).
///
/// The value is a `tdate` (CBOR tag 0 over RFC 3339 text; untagged text is
/// read too, because generators commonly omit the tag) or a map whose `value`
/// is one and whose optional `timeStampType` is `absolute` or the bound kind
/// this field allows (`lowerBound` for a start, `upperBound` for an end).
fn parse_generator_time(value: &Value, upper: bool) -> Option<GeneratorTime> {
    let parse_tdate = |value: &Value| -> Option<GeneratorTime> {
        let text = match value {
            Value::Tag(0, inner) => inner.as_text()?,
            Value::Text(text) => text.as_str(),
            _ => return None,
        };
        parse_rfc3339_exact(text)
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
    match (start, end) {
        (Some(start), Some(end)) => match (
            parse_generator_time(start, false),
            parse_generator_time(end, true),
        ) {
            (Some(start), Some(end)) if start <= end => {}
            (Some(_), Some(_)) => errors.push("action whenStart is later than whenEnd".into()),
            _ => errors.push("action whenStart or whenEnd is not a valid generator time".into()),
        },
        // A bound may stand alone; it must still be a valid generator time
        // of the kind its field allows (`lowerBound` start, `upperBound` end).
        (Some(start), None) if parse_generator_time(start, false).is_none() => {
            errors.push("action whenStart is not a valid generator time".into())
        }
        (None, Some(end)) if parse_generator_time(end, true).is_none() => {
            errors.push("action whenEnd is not a valid generator time".into())
        }
        _ => {}
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
/// Retrieval remains optional. Caller-supplied or consent-gated online evidence
/// is checked when present; otherwise each well-formed entry gets the required
/// non-rejecting `skipped` terminal result and an absolute external URL records
/// a network need.
pub(super) fn verify_linked_resource_integrity(
    manifest_label: &str,
    claim_refs: &ClaimAssertionRefs<'_>,
    evidence: OnlineEvidence<'_>,
    resources: &mut super::refs::ResourceCache<'_>,
    reference_budget: usize,
    results: &mut ValidationResults,
) -> super::refs::ReferenceWalk {
    let mut examined = 0usize;
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| base_assertion_label(label) == "c2pa.linked-resource-integrity")
        else {
            continue;
        };
        let assertion_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}");
        if reference.field != "created_assertions" {
            results.push_failure(
                LINKED_RESOURCE_NOT_CREATED,
                assertion_url.clone(),
                "linked resource integrity assertion is not in created_assertions".into(),
            );
        }
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let Some(resource_map) = assertion.get("resources").and_then(Value::as_map) else {
            results.push_failure(
                LINKED_RESOURCE_MALFORMED,
                assertion_url,
                "resources is not an object".into(),
            );
            continue;
        };
        let external_field = unique_map_field(resource_map, "externalResources");
        let relative_field = unique_map_field(resource_map, "relativeResources");
        let external = match external_field {
            Some(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        };
        let relative = match relative_field {
            Some(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        };
        let shared_alg = unique_map_field(resource_map, "alg").and_then(Value::as_text);

        let external_valid = external.is_some_and(|entries| !entries.is_empty());
        let relative_valid =
            relative.is_some_and(|entries| !entries.is_empty()) && shared_alg.is_some();
        let malformed_external = external_field.is_some() && !external_valid;
        let malformed_relative = relative_field.is_some() && !relative_valid;
        if (!external_valid && !relative_valid) || malformed_external || malformed_relative {
            results.push_failure(
                LINKED_RESOURCE_MALFORMED,
                assertion_url.clone(),
                "resources must contain non-empty externalResources, or non-empty relativeResources with alg; any present list must have that shape".into(),
            );
        }

        if let Some(entries) = external.filter(|entries| !entries.is_empty()) {
            for entry in entries {
                if examined >= reference_budget {
                    return super::refs::ReferenceWalk {
                        examined,
                        truncated: true,
                    };
                }
                examined += 1;
                let resource_url = entry.get("url").and_then(Value::as_text);
                let alg = entry.get("alg").and_then(Value::as_text);
                let expected = entry.get("hash").and_then(Value::as_bytes);
                let Some(resource_url) = resource_url else {
                    results.push_failure(
                        LINKED_RESOURCE_MALFORMED,
                        assertion_url.clone(),
                        "externalResources entry lacks url".into(),
                    );
                    continue;
                };
                if alg.is_none() || expected.is_none() {
                    results.push_failure_with_details(
                        LINKED_RESOURCE_MALFORMED,
                        assertion_url.clone(),
                        "externalResources entry lacks alg or hash".into(),
                        serde_json::json!({ "resourceUrl": resource_url }),
                    );
                    continue;
                }
                if !is_allowed_hash_algorithm(alg.unwrap_or_default()) {
                    results.push_failure(
                        ALGORITHM_UNSUPPORTED,
                        assertion_url.clone(),
                        format!(
                            "linked resource integrity alg {:?} is not on the C2PA allowed list",
                            alg.unwrap_or_default()
                        ),
                    );
                    continue;
                }
                terminal_linked_resource(
                    resource_url,
                    alg.unwrap_or_default(),
                    expected.unwrap_or_default(),
                    entry,
                    label,
                    &assertion_url,
                    true,
                    evidence,
                    resources,
                    results,
                );
            }
        }

        if let Some(entries) = relative.filter(|entries| !entries.is_empty()) {
            let alg = shared_alg.unwrap_or_default();
            if !is_allowed_hash_algorithm(alg) {
                results.push_failure(
                    ALGORITHM_UNSUPPORTED,
                    assertion_url.clone(),
                    format!(
                        "linked resource integrity alg '{alg}' is not on the C2PA allowed list"
                    ),
                );
                continue;
            }
            for entry in entries {
                if examined >= reference_budget {
                    return super::refs::ReferenceWalk {
                        examined,
                        truncated: true,
                    };
                }
                examined += 1;
                let resource_url = entry.get("uri").and_then(Value::as_text);
                let expected = entry.get("hash").and_then(Value::as_bytes);
                let Some(resource_url) = resource_url else {
                    results.push_failure(
                        LINKED_RESOURCE_MALFORMED,
                        assertion_url.clone(),
                        "relativeResources entry lacks uri".into(),
                    );
                    continue;
                };
                if expected.is_none() {
                    results.push_failure_with_details(
                        LINKED_RESOURCE_MALFORMED,
                        assertion_url.clone(),
                        "relativeResources entry lacks hash".into(),
                        serde_json::json!({ "resourceUrl": resource_url }),
                    );
                    continue;
                }
                let traverses = percent_decode(resource_url)
                    .is_none_or(|decoded| decoded.split('/').any(|segment| segment == ".."));
                if traverses {
                    results.push_failure_with_details(
                        LINKED_RESOURCE_INVALID_URI,
                        assertion_url.clone(),
                        "relative linked resource URI contains a '..' path segment or an invalid escape".into(),
                        serde_json::json!({ "resourceUrl": resource_url }),
                    );
                    continue;
                }
                terminal_linked_resource(
                    resource_url,
                    alg,
                    expected.unwrap_or_default(),
                    entry,
                    label,
                    &assertion_url,
                    false,
                    evidence,
                    resources,
                    results,
                );
            }
        }
    }
    super::refs::ReferenceWalk {
        examined,
        truncated: false,
    }
}

/// Locate well-formed absolute LRI resources without retrieving or validating
/// them. Relative resources still count toward the shared reference budget.
pub(super) fn locate_linked_resources(
    claim_refs: &ClaimAssertionRefs<'_>,
    reference_budget: usize,
) -> (Vec<String>, super::refs::ReferenceWalk) {
    let mut urls = Vec::new();
    let mut examined = 0usize;
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| base_assertion_label(label) == "c2pa.linked-resource-integrity")
        else {
            continue;
        };
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let Some(resources) = assertion.get("resources").and_then(Value::as_map) else {
            continue;
        };
        let external = match unique_map_field(resources, "externalResources") {
            Some(Value::Array(entries)) if !entries.is_empty() => Some(entries.as_slice()),
            _ => None,
        };
        let relative = match unique_map_field(resources, "relativeResources") {
            Some(Value::Array(entries)) if !entries.is_empty() => Some(entries.as_slice()),
            _ => None,
        };
        if let Some(entries) = external {
            for entry in entries {
                if examined >= reference_budget {
                    return (
                        urls,
                        super::refs::ReferenceWalk {
                            examined,
                            truncated: true,
                        },
                    );
                }
                examined += 1;
                let url = entry.get("url").and_then(Value::as_text);
                let alg = entry.get("alg").and_then(Value::as_text);
                let hash = entry.get("hash").and_then(Value::as_bytes);
                if let (Some(url), Some(alg), Some(_)) = (url, alg, hash) {
                    if is_allowed_hash_algorithm(alg)
                        && (url.starts_with("https://") || url.starts_with("http://"))
                    {
                        urls.push(url.to_string());
                    }
                }
            }
        }
        if let Some(entries) = relative {
            for _ in entries {
                if examined >= reference_budget {
                    return (
                        urls,
                        super::refs::ReferenceWalk {
                            examined,
                            truncated: true,
                        },
                    );
                }
                examined += 1;
            }
        }
    }
    (
        urls,
        super::refs::ReferenceWalk {
            examined,
            truncated: false,
        },
    )
}

fn unique_map_field<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut values = map
        .iter()
        .filter(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

#[allow(clippy::too_many_arguments)]
fn terminal_linked_resource(
    resource_url: &str,
    alg: &str,
    expected_hash: &[u8],
    entry: &Value,
    assertion_label: &str,
    assertion_url: &str,
    network_resolvable: bool,
    evidence: OnlineEvidence<'_>,
    resources: &mut super::refs::ResourceCache<'_>,
    results: &mut ValidationResults,
) {
    let details = || serde_json::json!({ "resourceUrl": resource_url });
    let supplied = evidence
        .external_data
        .and_then(|resources| resources.get(resource_url))
        .map(|bytes| (bytes.as_slice(), evidence.external_media_type(resource_url)));
    let (bytes, media_type) = match supplied {
        Some(content) => content,
        None if network_resolvable => match resources.resolve(resource_url) {
            super::refs::ResolvedResource::Retrieved { bytes, media_type } => (bytes, media_type),
            super::refs::ResolvedResource::Unavailable => {
                results.push_informational_with_details(
                    LINKED_RESOURCE_INACCESSIBLE,
                    assertion_url.to_string(),
                    "linked resource retrieval produced no usable body".into(),
                    details(),
                );
                return;
            }
            super::refs::ResolvedResource::NotAttempted => {
                results.push_informational_with_details(
                    LINKED_RESOURCE_SKIPPED,
                    assertion_url.to_string(),
                    "linked resource was not retrieved".into(),
                    details(),
                );
                push_unique(
                    &mut results.network_needs,
                    NetworkNeed::ExternalData {
                        uri: resource_url.to_string(),
                        assertion_label: assertion_label.to_string(),
                    },
                );
                return;
            }
        },
        None => {
            if evidence.external_is_unreachable(resource_url) {
                results.push_informational_with_details(
                    LINKED_RESOURCE_INACCESSIBLE,
                    assertion_url.to_string(),
                    "linked resource retrieval produced no usable body".into(),
                    details(),
                );
            } else {
                results.push_informational_with_details(
                    LINKED_RESOURCE_SKIPPED,
                    assertion_url.to_string(),
                    "linked resource was not retrieved".into(),
                    details(),
                );
            }
            return;
        }
    };

    if let Some(size) = entry.get("size").and_then(|value| match value {
        Value::Integer(size) if *size >= 0 => usize::try_from(*size).ok(),
        _ => None,
    }) {
        if size != bytes.len() {
            results.push_informational_with_details(
                LINKED_RESOURCE_SIZE_MISMATCH,
                assertion_url.to_string(),
                "retrieved linked resource size differs from the assertion".into(),
                details(),
            );
            return;
        }
    }
    if let Some(expected_format) = entry.get("dc:format").and_then(Value::as_text) {
        let observed = media_type;
        if observed.is_none_or(|observed| {
            crate::c2pa_core::spec::canonicalize_mime(observed)
                != crate::c2pa_core::spec::canonicalize_mime(expected_format)
        }) {
            results.push_informational_with_details(
                LINKED_RESOURCE_FORMAT_MISMATCH,
                assertion_url.to_string(),
                "retrieved linked resource media type differs from the assertion".into(),
                details(),
            );
            return;
        }
    }
    if hash_bytes(alg, bytes).as_deref() != Some(expected_hash) {
        results.push_informational_with_details(
            LINKED_RESOURCE_HASH_MISMATCH,
            assertion_url.to_string(),
            "retrieved linked resource hash differs from the assertion".into(),
            details(),
        );
        return;
    }
    results.push_success_with_details(
        LINKED_RESOURCE_MATCH,
        assertion_url.to_string(),
        "linked resource integrity matched".into(),
        details(),
    );
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
    (!base.ends_with(".ingredient")).then_some(
        "relatedAssertions references an assertion whose label does not end with .ingredient",
    )
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
            std::iter::once(("action".to_string(), Value::Text("c2pa.edited".into()))).chain(
                pairs
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value)),
            ),
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

        // A lone bound is still checked for syntax and bound kind.
        let lone_ok = action(vec![("whenStart", tdate("2026-05-01T00:00:00Z"))]);
        assert!(action_time_errors(&lone_ok, true).is_empty());
        let lone_bad_start = action(vec![("whenStart", tdate("yesterday"))]);
        assert_eq!(action_time_errors(&lone_bad_start, true).len(), 1);
        let lone_wrong_end = action(vec![(
            "whenEnd",
            map_from_pairs([
                ("value".to_string(), tdate("2026-05-02T00:00:00Z")),
                (
                    "timeStampType".to_string(),
                    Value::Text("lowerBound".into()),
                ),
            ]),
        )]);
        assert_eq!(action_time_errors(&lone_wrong_end, true).len(), 1);
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
    fn generator_times_order_past_nanosecond_precision() {
        // Equal to nine digits; the start is later at the tenth.
        let reversed = action(vec![
            ("whenStart", tdate("2026-05-01T00:00:00.0000000002Z")),
            ("whenEnd", tdate("2026-05-01T00:00:00.0000000001Z")),
        ]);
        assert_eq!(action_time_errors(&reversed, true).len(), 1);
        let equal = action(vec![
            ("whenStart", tdate("2026-05-01T00:00:00.50Z")),
            ("whenEnd", tdate("2026-05-01T02:00:00.5+02:00")),
        ]);
        assert!(action_time_errors(&equal, true).is_empty());
        assert!(
            parse_rfc3339_exact("2026-05-01T00:00:00.45Z")
                < parse_rfc3339_exact("2026-05-01T00:00:00.5Z")
        );
        assert_eq!(parse_rfc3339_exact("2026-05-01T00:00:00.Z"), None);
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
        let v22 = EngineProfile::new(SpecVersion::V2_2, OperatingMode::Regular);
        let v25 = EngineProfile::new(SpecVersion::V2_5, OperatingMode::Regular);
        assert!(!applies(v24) && applies(v25));
        assert_eq!(claim_algorithms(v22), ClaimAlgorithmList::V2_2);
        assert_eq!(claim_algorithms(v24), ClaimAlgorithmList::V2_4);
        assert_eq!(claim_algorithms(v25), ClaimAlgorithmList::V2_5);
        assert_eq!(text_rules(v24), TextLocatorRules::V2_4);
        assert_eq!(text_rules(v25), TextLocatorRules::V2_5);
        assert!(!applies(EngineProfile::GENEROUS));
    }

    #[test]
    fn linked_resources_use_one_borrowed_provider_result_per_uri() {
        use std::cell::Cell;

        const URL: &str = "https://example.test/resource";
        const BODY: &[u8] = b"linked resource";

        struct Provider {
            calls: Cell<usize>,
        }

        impl super::super::refs::ExternalResources for Provider {
            fn resolve(&self, url: &str) -> super::super::refs::ExternalResource<'_> {
                assert_eq!(url, URL);
                self.calls.set(self.calls.get() + 1);
                super::super::refs::ExternalResource::Retrieved {
                    bytes: BODY,
                    media_type: Some("text/plain"),
                }
            }
        }

        let entry = map_from_pairs([
            ("url".to_string(), Value::Text(URL.into())),
            ("alg".to_string(), Value::Text("sha256".into())),
            (
                "hash".to_string(),
                Value::Bytes(hash_bytes("sha256", BODY).expect("digest")),
            ),
            ("dc:format".to_string(), Value::Text("text/plain".into())),
        ]);
        let provider = Provider {
            calls: Cell::new(0),
        };
        let mut resources = super::super::refs::ResourceCache::with_evidence(
            Some(&provider),
            OnlineEvidence::default(),
        );
        let mut results = ValidationResults::default();
        for _ in 0..2 {
            terminal_linked_resource(
                URL,
                "sha256",
                entry.get("hash").and_then(Value::as_bytes).unwrap(),
                &entry,
                "c2pa.linked-resource-integrity",
                "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.linked-resource-integrity",
                true,
                OnlineEvidence::default(),
                &mut resources,
                &mut results,
            );
        }
        assert_eq!(provider.calls.get(), 1);
        assert_eq!(
            results
                .success
                .iter()
                .filter(|status| status.code == LINKED_RESOURCE_MATCH)
                .count(),
            2
        );
    }
}
