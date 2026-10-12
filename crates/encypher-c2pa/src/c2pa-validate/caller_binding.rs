// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Content-binding outcomes that do not come from hashing asset bytes here.
//!
//! Two passes use this module, and both run the complete per-manifest
//! pipeline: claim structure, the selected policy's assertion, action,
//! ingredient and redaction rules, hashed-URI bindings, the claim signature,
//! time stamps, revocation, trust and CAWG identity.
//!
//! - Caller-verified binding. A trusted caller's own engine has compared the
//!   asset's bytes with one hard-binding assertion. The caller hands back that
//!   verdict together with the exact identity it evaluated: the submitted
//!   store's SHA-256, the active manifest's label and expanded-domain digest,
//!   the binding assertion's owning manifest, label, and the claim's
//!   hashed-URI algorithm and digest for it. The kernel re-derives that
//!   identity from the same store bytes and refuses a verdict about anything
//!   else. The verdict replaces only the byte comparison: the binding
//!   assertion's own schema (required fields, ranges, algorithm, the 2.5
//!   exclusion rules) is still checked here, and a match never removes a
//!   claim, reference, trust or ingredient failure.
//! - Store-only. Nothing about the asset is known. The binding is recorded as
//!   not evaluated, and the facade reports that instead of an asset verdict.

use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    assertion_label_for_manifest, base_assertion_label, bmff_exclusion_maps,
    bmff_has_additional_exclusions, canonical_collection_uri_member,
    canonical_collection_uri_member_for_policy, decode, enforce_primary_binding_label, exclusions,
    inherited_hard_binding, is_allowed_hash_algorithm, is_supported_bmff_hash_label,
    resolved_hash_algorithm, segment_hash, spec25, versions, AssetFormat, ClaimAssertionReference,
    ClaimAssertionRefs, EngineProfile, ManifestKind, ParsedManifest, SpecVersion, StoreContext,
    ValidationResults, Value, ALGORITHM_UNSUPPORTED,
    ASSERTION_BMFF_HASH_ADDITIONAL_EXCLUSIONS_PRESENT, ASSERTION_BMFF_HASH_MALFORMED,
    ASSERTION_BMFF_HASH_MATCH, ASSERTION_BMFF_HASH_MISMATCH, ASSERTION_BOXES_HASH_MALFORMED,
    ASSERTION_BOXES_HASH_MATCH, ASSERTION_BOXES_HASH_MISMATCH,
    ASSERTION_COLLECTION_HASH_INVALID_URI, ASSERTION_COLLECTION_HASH_MALFORMED,
    ASSERTION_COLLECTION_HASH_MATCH, ASSERTION_COLLECTION_HASH_MISMATCH,
    ASSERTION_COMPOUND_CONTENT_MALFORMED, ASSERTION_COMPOUND_CONTENT_MATCH,
    ASSERTION_COMPOUND_CONTENT_MISMATCH, ASSERTION_DATA_HASH_MALFORMED, ASSERTION_DATA_HASH_MATCH,
    ASSERTION_DATA_HASH_MISMATCH, ASSERTION_HASHED_URI_MISMATCH, COMPOUND_CONTENT_LABEL,
    HASHED_URI_MISSING,
};

/// Informational extension: the hard binding's byte comparison was made by
/// the caller's own engine, named in `details.engine`.
pub const HARD_BINDING_CALLER_VERIFIED: &str = "com.encypher.hardBinding.callerVerified";
/// Failure extension: caller binding evidence names a store, manifest or
/// binding assertion other than the one this store's active claim binds.
pub const HARD_BINDING_CALLER_EVIDENCE_MISMATCH: &str =
    "com.encypher.hardBinding.callerEvidenceMismatch";
/// Informational extension: no asset was supplied, so the content binding was
/// not evaluated.
pub const HARD_BINDING_NOT_EVALUATED: &str = "com.encypher.hardBinding.notEvaluated";

/// The hard binding a store's active manifest is validated against, and the
/// exact store bytes it was derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindingTarget {
    pub(crate) manifest_store_sha256: [u8; 32],
    pub(crate) active_manifest_label: String,
    pub(crate) active_manifest_sha256: [u8; 32],
    pub(crate) binding_manifest_label: String,
    pub(crate) binding_assertion_label: String,
    pub(crate) binding_reference_alg: String,
    pub(crate) binding_reference_hash: Vec<u8>,
}

/// A caller engine's verdict over one binding target.
#[derive(Debug, Clone)]
pub(crate) struct CallerBinding {
    pub(crate) target: BindingTarget,
    /// `None` for a match; the caller's explanation for a mismatch.
    pub(crate) mismatch: Option<String>,
    pub(crate) engine: String,
}

/// SHA-256 of the exact submitted store bytes.
pub(crate) fn store_sha256(manifest_store: &[u8]) -> [u8; 32] {
    Sha256::digest(manifest_store).into()
}

/// The operative binding reference of a standard claim: its sole primary
/// hard binding, or, under the 2.5 policy, its sole `c2pa.hash.segment`.
pub(super) fn operative_reference<'i, 'c>(
    claim_refs: &'i ClaimAssertionRefs<'c>,
    compound_ok: bool,
    profile: EngineProfile,
) -> Option<&'i ClaimAssertionReference<'c>> {
    let plan = claim_refs.binding_plan(compound_ok);
    if let Some(primary) = plan.primary() {
        return Some(primary);
    }
    if plan.primary_count != 0 || !spec25::applies(profile) {
        return None;
    }
    let mut segments = claim_refs
        .references
        .iter()
        .filter(|reference| reference.label.is_some_and(spec25::is_segment_hash_label));
    match (segments.next(), segments.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// Derive the binding target of `active` from the store it was parsed from.
pub(super) fn derive_target(
    manifest_store_sha256: [u8; 32],
    active: &ParsedManifest<'_>,
    store: StoreContext<'_>,
    compound_ok: bool,
    profile: EngineProfile,
) -> Option<BindingTarget> {
    let active_manifest_sha256 = store
        .manifest_hashes
        .get(&active.label)
        .and_then(|digests| <[u8; 32]>::try_from(digests.expanded_sha256.as_slice()).ok())?;
    let (owner, reference, claim_alg) = if active.kind() == ManifestKind::Update {
        inherited_hard_binding(active, store)?
    } else {
        let claim = decode(active.claim_cbor?).ok()?;
        let generation = versions::claim_generation(active, &claim);
        let claim_refs = ClaimAssertionRefs::build(active, &claim, generation);
        let reference = operative_reference(&claim_refs, compound_ok, profile)?
            .value
            .clone();
        let claim_alg = claim
            .get("alg")
            .and_then(Value::as_text)
            .map(str::to_string);
        (active.label.clone(), reference, claim_alg)
    };
    let url = reference.get("url").and_then(Value::as_text)?;
    let binding_assertion_label = assertion_label_for_manifest(url, &owner)?.to_string();
    let binding_reference_hash = reference.get("hash").and_then(Value::as_bytes)?.to_vec();
    let binding_reference_alg = reference
        .get("alg")
        .and_then(Value::as_text)
        .map(str::to_string)
        .or(claim_alg)?;
    Some(BindingTarget {
        manifest_store_sha256,
        active_manifest_label: active.label.clone(),
        active_manifest_sha256,
        binding_manifest_label: owner,
        binding_assertion_label,
        binding_reference_alg,
        binding_reference_hash,
    })
}

/// The registered match and mismatch codes of one binding label.
fn binding_codes(label: &str) -> (&'static str, &'static str) {
    match base_assertion_label(label) {
        "c2pa.hash.boxes" => (ASSERTION_BOXES_HASH_MATCH, ASSERTION_BOXES_HASH_MISMATCH),
        "c2pa.hash.collection.data" => (
            ASSERTION_COLLECTION_HASH_MATCH,
            ASSERTION_COLLECTION_HASH_MISMATCH,
        ),
        "c2pa.hash.segment" => (
            segment_hash::ASSERTION_SEGMENT_HASH_MATCH,
            segment_hash::ASSERTION_SEGMENT_HASH_MISMATCH,
        ),
        COMPOUND_CONTENT_LABEL => (
            ASSERTION_COMPOUND_CONTENT_MATCH,
            ASSERTION_COMPOUND_CONTENT_MISMATCH,
        ),
        base if is_supported_bmff_hash_label(base) => {
            (ASSERTION_BMFF_HASH_MATCH, ASSERTION_BMFF_HASH_MISMATCH)
        }
        _ => (ASSERTION_DATA_HASH_MATCH, ASSERTION_DATA_HASH_MISMATCH),
    }
}

/// The binding assertion's own schema, checked without asset bytes: required
/// fields, the hash algorithm, range structure and the selected policy's
/// exclusion rules. Returns the first defect as `(code, explanation)`;
/// informational findings are pushed directly.
#[allow(clippy::too_many_lines)]
fn schema_defect(
    label: &str,
    assertion: Option<&Value>,
    claim: &Value,
    format: Option<AssetFormat>,
    profile: EngineProfile,
    url: &str,
    results: &mut ValidationResults,
) -> Option<(&'static str, String)> {
    let base = base_assertion_label(label);
    let (_, mismatch) = binding_codes(base);
    let malformed = match base {
        "c2pa.hash.boxes" => ASSERTION_BOXES_HASH_MALFORMED,
        "c2pa.hash.collection.data" => ASSERTION_COLLECTION_HASH_MALFORMED,
        "c2pa.hash.segment" => segment_hash::ASSERTION_SEGMENT_HASH_MALFORMED,
        COMPOUND_CONTENT_LABEL => ASSERTION_COMPOUND_CONTENT_MALFORMED,
        b if is_supported_bmff_hash_label(b) => ASSERTION_BMFF_HASH_MALFORMED,
        _ => ASSERTION_DATA_HASH_MALFORMED,
    };
    let Some(assertion) = assertion else {
        return Some((mismatch, "hard-binding assertion CBOR invalid".into()));
    };
    if base == "c2pa.hash.segment" {
        return segment_hash::schema_defect(assertion, claim);
    }
    if base == COMPOUND_CONTENT_LABEL {
        return match assertion.get("components") {
            Some(Value::Array(components)) if !components.is_empty() => None,
            _ => Some((malformed, "compound content has no components".into())),
        };
    }
    // Every byte-hash binding names an allowed algorithm.
    let algorithm_defect = |alg: Option<&str>| match alg {
        None => Some((
            ALGORITHM_UNSUPPORTED,
            "hard-binding assertion has no hash algorithm".to_string(),
        )),
        Some(alg) if !is_allowed_hash_algorithm(alg) => Some((
            ALGORITHM_UNSUPPORTED,
            format!("hard-binding assertion uses unsupported hash algorithm '{alg}'"),
        )),
        Some(_) => None,
    };
    match base {
        "c2pa.hash.boxes" => {
            let Some(Value::Array(entries)) = assertion.get("boxes") else {
                return Some((malformed, "no boxes field".into()));
            };
            let default_alg = resolved_hash_algorithm(assertion, claim);
            for entry in entries {
                let names_ok = matches!(entry.get("names"), Some(Value::Array(names))
                    if !names.is_empty() && names.iter().all(|name| name.as_text().is_some()));
                if !names_ok || entry.get("hash").and_then(Value::as_bytes).is_none() {
                    return Some((malformed, "box entry lacks names or hash".into()));
                }
                if let Some(defect) =
                    algorithm_defect(entry.get("alg").and_then(Value::as_text).or(default_alg))
                {
                    return Some(defect);
                }
            }
            None
        }
        "c2pa.hash.collection.data" => {
            let Some(Value::Array(uris)) = assertion.get("uris") else {
                return Some((malformed, "no uris field".into()));
            };
            if profile.version == SpecVersion::V2_5 && uris.is_empty() {
                return Some((malformed, "collection must contain at least one URI".into()));
            }
            if let Some(defect) = algorithm_defect(resolved_hash_algorithm(assertion, claim)) {
                return Some(defect);
            }
            for entry in uris {
                let (Some(uri), Some(_)) = (
                    entry.get("uri").and_then(Value::as_text),
                    entry.get("hash").and_then(Value::as_bytes),
                ) else {
                    return Some((malformed, "uri entry missing uri or hash".into()));
                };
                let invalid = match format {
                    Some(AssetFormat::Warc) => {
                        uri.is_empty()
                            || uri.contains('?')
                            || uri.split('/').any(|s| s == "." || s == "..")
                    }
                    Some(AssetFormat::Zip) if profile.version == SpecVersion::V2_5 => {
                        canonical_collection_uri_member_for_policy(uri, true).is_none()
                    }
                    _ => canonical_collection_uri_member(uri).is_none(),
                };
                if invalid {
                    return Some((
                        ASSERTION_COLLECTION_HASH_INVALID_URI,
                        format!("uri '{uri}' is not a valid collection URI"),
                    ));
                }
            }
            if format == Some(AssetFormat::Zip)
                && assertion
                    .get("zip_central_directory_hash")
                    .and_then(Value::as_bytes)
                    .is_none()
            {
                return Some((malformed, "zip_central_directory_hash missing".into()));
            }
            None
        }
        b if is_supported_bmff_hash_label(b) => {
            if let Some(defect) = algorithm_defect(resolved_hash_algorithm(assertion, claim)) {
                return Some(defect);
            }
            let exclusion_maps = match bmff_exclusion_maps(assertion) {
                Ok(maps) => maps,
                Err(why) => return Some((malformed, why.into())),
            };
            let merkle_present = assertion.get("merkle").is_some();
            if !merkle_present && assertion.get("hash").and_then(Value::as_bytes).is_none() {
                return Some((malformed, "hard-binding assertion missing hash".into()));
            }
            if bmff_has_additional_exclusions(
                &exclusion_maps,
                merkle_present,
                !spec25::applies(profile),
            ) {
                results.push_informational(
                    ASSERTION_BMFF_HASH_ADDITIONAL_EXCLUSIONS_PRESENT,
                    url.to_string(),
                    "BMFF hash assertion contains optional or additional exclusions".into(),
                );
            }
            None
        }
        _ => {
            if let Some(defect) = algorithm_defect(resolved_hash_algorithm(assertion, claim)) {
                return Some(defect);
            }
            if assertion.get("hash").and_then(Value::as_bytes).is_none() {
                return Some((mismatch, "hard-binding assertion missing hash".into()));
            }
            // Without the asset, ranges can be checked for structure and
            // order but not against the asset's length.
            match exclusions::parse_data(assertion.get("exclusions"), usize::MAX) {
                Ok(_) => None,
                Err(_) => Some((
                    malformed,
                    "data-hash exclusions are malformed, unsorted, or overlapping".into(),
                )),
            }
        }
    }
}

/// Apply caller evidence to one manifest pass.
///
/// `claim`/`claim_refs` are the claim that declares the binding (the active
/// standard manifest, or the first standard manifest of an update chain).
#[allow(clippy::too_many_arguments)]
pub(super) fn apply(
    manifest_store_sha256: [u8; 32],
    active: &ParsedManifest<'_>,
    store: StoreContext<'_>,
    evidence: &CallerBinding,
    compound_ok: bool,
    format: Option<AssetFormat>,
    profile: EngineProfile,
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    let derived = derive_target(manifest_store_sha256, active, store, compound_ok, profile);
    let Some(target) = derived.filter(|target| *target == evidence.target) else {
        results.push_failure_with_details(
            HARD_BINDING_CALLER_EVIDENCE_MISMATCH,
            format!("self#jumbf=/c2pa/{}", active.label),
            "caller binding evidence does not name this store's active manifest and hard binding; it was not used".into(),
            json!({ "engine": evidence.engine }),
        );
        return;
    };
    if !enforce_primary_binding_label(
        &target.binding_assertion_label,
        format,
        profile,
        &target.binding_manifest_label,
        results,
    ) {
        return;
    }
    let url = format!(
        "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
        target.binding_manifest_label, target.binding_assertion_label
    );
    let assertion = claim_refs
        .indexed(&target.binding_assertion_label)
        .and_then(|indexed| indexed.decoded.as_ref());
    if let Some((code, explanation)) = schema_defect(
        &target.binding_assertion_label,
        assertion,
        claim,
        format,
        profile,
        &url,
        results,
    ) {
        results.push_failure(code, url, explanation);
        return;
    }
    let (match_code, mismatch_code) = binding_codes(&target.binding_assertion_label);
    match &evidence.mismatch {
        None => {
            // A tampered assertion breaks its hashed-URI binding; a caller's
            // comparison against it then proves nothing about the claim.
            if results.has_failure(ASSERTION_HASHED_URI_MISMATCH)
                || results.has_failure(HASHED_URI_MISSING)
            {
                return;
            }
            results.push_success(
                match_code,
                url.clone(),
                format!(
                    "hard binding verified by the caller's engine ({})",
                    evidence.engine
                ),
            );
        }
        Some(explanation) => results.push_failure(mismatch_code, url.clone(), explanation.clone()),
    }
    results.push_informational_with_details(
        HARD_BINDING_CALLER_VERIFIED,
        url,
        "the asset's bytes were compared by the caller's engine, not by this verifier".into(),
        json!({ "engine": evidence.engine }),
    );
}

/// Record a store-only pass: the content binding exists but was not checked.
pub(super) fn record_not_evaluated(
    active: &ParsedManifest<'_>,
    store: StoreContext<'_>,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    let url = derive_target([0; 32], active, store, false, profile).map_or_else(
        || format!("self#jumbf=/c2pa/{}", active.label),
        |target| {
            format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
                target.binding_manifest_label, target.binding_assertion_label
            )
        },
    );
    results.push_informational(
        HARD_BINDING_NOT_EVALUATED,
        url,
        "no asset was supplied; the hard binding was not evaluated".into(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_core::OperatingMode;

    fn collection_assertion(uri: &str) -> Value {
        Value::Map(vec![
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (
                Value::Text("uris".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("uri".into()), Value::Text(uri.into())),
                    (Value::Text("hash".into()), Value::Bytes(vec![0; 32])),
                ])]),
            ),
            (
                Value::Text("zip_central_directory_hash".into()),
                Value::Bytes(vec![0; 32]),
            ),
        ])
    }

    #[test]
    fn caller_verified_zip_directory_matches_only_at_exact_2_5() {
        let assertion = collection_assertion("_rels/");
        let claim = Value::Map(Vec::new());
        let mut results = ValidationResults::default();
        let v25 = EngineProfile::new(SpecVersion::V2_5, OperatingMode::Regular);
        assert_eq!(
            schema_defect(
                "c2pa.hash.collection.data",
                Some(&assertion),
                &claim,
                Some(AssetFormat::Zip),
                v25,
                "self#collection",
                &mut results,
            ),
            None,
        );
        assert!(results.failure.is_empty());

        let v24 = EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular);
        assert_eq!(
            schema_defect(
                "c2pa.hash.collection.data",
                Some(&assertion),
                &claim,
                Some(AssetFormat::Zip),
                v24,
                "self#collection",
                &mut ValidationResults::default(),
            ),
            Some((
                ASSERTION_COLLECTION_HASH_INVALID_URI,
                "uri '_rels/' is not a valid collection URI".into(),
            )),
        );
    }

    #[test]
    fn exact_2_5_rejects_empty_collection_caller_evidence() {
        let assertion = Value::Map(vec![
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (Value::Text("uris".into()), Value::Array(Vec::new())),
            (
                Value::Text("zip_central_directory_hash".into()),
                Value::Bytes(vec![0; 32]),
            ),
        ]);
        let defect = schema_defect(
            "c2pa.hash.collection.data",
            Some(&assertion),
            &Value::Map(Vec::new()),
            Some(AssetFormat::Zip),
            EngineProfile::new(SpecVersion::V2_5, OperatingMode::Regular),
            "self#collection",
            &mut ValidationResults::default(),
        );
        assert_eq!(
            defect.map(|(code, _)| code),
            Some(ASSERTION_COLLECTION_HASH_MALFORMED)
        );
    }
}
