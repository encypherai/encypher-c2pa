// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Bounded recursive ingredient validation (C2PA 2.4 Validation, "Validate the
//! Ingredients").
//!
//! The active manifest's ingredient assertions name other manifests in the same
//! store, and those manifests may name further ones. This module walks that
//! graph once, under explicit ceilings, and reports two things:
//!
//! - the codes the walk observed for the ACTIVE manifest's own ingredient
//!   assertions (today only `ingredient.unknownProvenance`, raised where the
//!   assertion carries no manifest link at all);
//! - one `ingredientDeltas` entry per ingredient assertion whose manifest the
//!   walk reached: the difference between the verdict the signer recorded in
//!   that assertion's `validationResults` and the verdict this validation
//!   derived, in the shape the spec's `ingredient-delta-validation-result-map`
//!   prescribes.
//!
//! An ingredient manifest's defects are never folded into the active
//! manifest's verdict. The asset in hand is not inauthentic because a manifest
//! in its history is: the spec reports an ingredient's outcome per manifest and
//! as a delta against the recorded verdict, which is exactly what
//! `validation_results.ingredientDeltas` carries.
//!
//! What a reached ingredient manifest is validated against is bounded by what
//! the store alone can prove: its claim (present, decodable), its claim
//! signature's cryptography, its claim-to-assertion hashed-URI bindings, and
//! its own ingredient links. The spec's claim-signature hash validation method
//! excludes content bindings for ingredients ("except for the hard binding
//! assertions, which cannot be validated for ingredients") because the
//! ingredient's own bytes are not present. Signer trust and revocation are also
//! not re-derived: the caller's trust material describes the asset in hand, and
//! the ingredient's trust verdict is what its own signer recorded. Nothing here
//! emits a code claiming more than was checked.
//!
//! ## Ceilings
//!
//! A manifest store is attacker-supplied. The walk is bounded on depth and on
//! the number of manifests validated, and it never re-enters a manifest it has
//! already reached, so a cycle terminates. Exhausting a ceiling stops the walk
//! and records `com.encypher.ingredient.graphLimitExceeded` as informational:
//! running out of budget says nothing about authenticity and must never be
//! confusable with a hash or signature failure.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Value as Json};

use super::versions::{self, ClaimGeneration};
use super::{
    decode, is_generous, status_array, verify_assertion_bindings, verify_ingredient_references,
    ClaimAssertionRefs, EngineProfile, IngredientManifestDigestCache, StatusCode, StoreContext,
    ValidationResults, ALGORITHM_UNSUPPORTED, ASSERTION_INGREDIENT_MALFORMED, CLAIM_CBOR_INVALID,
    CLAIM_MISSING, CLAIM_SIGNATURE_MISMATCH, CLAIM_SIGNATURE_MISSING, CLAIM_SIGNATURE_VALIDATED,
};
use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_crypto::{extract_x5chain, verify_claim, CryptoError};

/// Maximum ingredient edges followed away from the active manifest.
const MAX_DEPTH: usize = 16;
/// Maximum manifests validated in one walk, the active manifest included.
const MAX_MANIFESTS: usize = 64;

/// Informational: a ceiling stopped the ingredient walk. Entity-namespaced
/// because it is a resource outcome, not a C2PA validation outcome.
pub(super) const GRAPH_LIMIT_EXCEEDED: &str = "com.encypher.ingredient.graphLimitExceeded";

/// One `validation_results.ingredientDeltas` entry.
pub(super) struct IngredientDelta {
    /// JUMBF URI of the ingredient assertion the delta describes.
    assertion_uri: String,
    deltas: ValidationResults,
}

/// One manifest the walk reached, with the claim it was validated from.
///
/// CAWG identity validation resolves `referenced_assertions` against these:
/// an identity may reference an assertion in a recursively reachable
/// ingredient claim, and only a claim the walk actually reached counts.
pub(super) struct ReachedManifest {
    pub(super) label: String,
    pub(super) claim: Value,
}

/// The walked ingredient graph.
pub(super) struct IngredientGraph {
    /// Codes the walk observed for the active manifest itself. Merged into the
    /// active verdict by the caller.
    pub(super) active: ValidationResults,
    /// Per-ingredient deltas, in walk order.
    pub(super) deltas: Vec<IngredientDelta>,
    /// Ingredient manifests the walk reached, excluding the active manifest.
    pub(super) reached: Vec<ReachedManifest>,
}

/// One ingredient assertion's edge into the store.
struct Edge {
    /// JUMBF URI of the ingredient assertion that carries the link.
    assertion_uri: String,
    /// Manifest the `activeManifest` (or v1/v2 `c2pa_manifest`) link names.
    target: String,
    /// The verdict the signer recorded for that manifest, if any.
    recorded: Option<Value>,
}

/// Walk the active manifest's ingredient graph.
///
/// `active_label` must name a manifest in `store`; anything else yields an
/// empty graph rather than a guess.
pub(super) fn build<'a>(
    active_label: &str,
    store: StoreContext<'a>,
    profile: EngineProfile,
) -> IngredientGraph {
    let mut graph = IngredientGraph {
        active: ValidationResults::default(),
        deltas: Vec::new(),
        reached: Vec::new(),
    };
    let index_of: HashMap<&str, usize> = store
        .manifests
        .iter()
        .enumerate()
        .map(|(index, manifest)| (manifest.label.as_str(), index))
        .collect();
    let Some(active) = index_of.get(active_label).copied() else {
        return graph;
    };
    // Every claim decoded once, in a stable allocation the walk borrows from.
    let mut claims: Vec<Option<Value>> = store
        .manifests
        .iter()
        .map(|manifest| manifest.claim_cbor.and_then(|cbor| decode(cbor).ok()))
        .collect();

    let mut results: Vec<ValidationResults> = store
        .manifests
        .iter()
        .map(|_| ValidationResults::default())
        .collect();
    let mut reached: Vec<bool> = vec![false; store.manifests.len()];
    let mut pending: Vec<(usize, Edge)> = Vec::new();
    let mut cache = IngredientManifestDigestCache::new(store);
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    let mut visited = 0usize;
    let mut limits: HashSet<&'static str> = HashSet::new();

    queue.push_back((active, 0));
    reached[active] = true;
    while let Some((index, depth)) = queue.pop_front() {
        visited += 1;
        let manifest = &store.manifests[index];
        let is_active = index == active;
        let Some(claim) = claims[index].as_ref() else {
            if !is_active {
                record_missing_claim(manifest, &mut results[index]);
            }
            continue;
        };
        let generation = versions::claim_generation(manifest, claim);
        let mut claim_refs = ClaimAssertionRefs::build(manifest, claim, generation);
        // A time-stamp manifest reached through an ingredient "shall be
        // ignored" (C2PA 2.4, Time-Stamp Manifests in an ingredient).
        if !is_active && is_time_stamp_manifest(&claim_refs) {
            continue;
        }
        if !is_active {
            validate_reached_manifest(
                manifest,
                claim,
                generation,
                &mut claim_refs,
                &mut cache,
                profile,
                &mut results[index],
            );
        }
        for edge in edges(
            manifest,
            &claim_refs,
            generation,
            profile,
            &mut results[index],
        ) {
            let Some(target) = index_of.get(edge.target.as_str()).copied() else {
                // The link named a manifest the store does not carry;
                // `verify_ingredient_references` already reported it.
                continue;
            };
            pending.push((target, edge));
            if reached[target] {
                // A diamond (the same ingredient reached twice) or a forged
                // label loop whose link hash has already failed. Either way the
                // manifest is validated once and the walk does not re-enter it.
                continue;
            }
            if depth + 1 > MAX_DEPTH {
                limits.insert("depth");
                continue;
            }
            if visited + queue.len() >= MAX_MANIFESTS {
                limits.insert("manifests");
                continue;
            }
            reached[target] = true;
            queue.push_back((target, depth + 1));
        }
    }
    for limit in limits {
        let ceiling = if limit == "depth" {
            MAX_DEPTH
        } else {
            MAX_MANIFESTS
        };
        graph.active.informational.push(StatusCode {
            code: GRAPH_LIMIT_EXCEEDED.into(),
            url: format!("self#jumbf=/c2pa/{active_label}"),
            explanation: format!(
                "ingredient graph {limit} ceiling reached ({ceiling}); traversal stopped there. \
                 This is a resource outcome and does not affect manifest validity."
            ),
            details: Some(json!({ "limit": limit, "ceiling": ceiling })),
        });
    }

    // Deltas last: both sides of every edge are computed by now.
    for (target, edge) in pending {
        let deltas = validation_deltas(edge.recorded.as_ref(), &results[target]);
        if deltas.success.is_empty() && deltas.informational.is_empty() && deltas.failure.is_empty()
        {
            continue;
        }
        graph.deltas.push(IngredientDelta {
            assertion_uri: edge.assertion_uri,
            deltas,
        });
    }
    graph.active.success.append(&mut results[active].success);
    graph
        .active
        .informational
        .append(&mut results[active].informational);
    graph.active.failure.append(&mut results[active].failure);
    for (index, claim) in claims.iter_mut().enumerate() {
        if index == active || !reached[index] {
            continue;
        }
        if let Some(claim) = claim.take() {
            graph.reached.push(ReachedManifest {
                label: store.manifests[index].label.clone(),
                claim,
            });
        }
    }
    graph
}

/// Attach `validation_results.ingredientDeltas` to a reader report.
///
/// Additive: the report's existing `validation_results.activeManifest` object,
/// the flat status fields, and the verdict are untouched, and the block is
/// absent when the walk produced no delta.
pub(super) fn attach(report: &mut Json, deltas: &[IngredientDelta]) {
    if deltas.is_empty() {
        return;
    }
    let Some(results) = report
        .get_mut("validation_results")
        .and_then(Json::as_object_mut)
    else {
        return;
    };
    results.insert("ingredientDeltas".into(), deltas_json(deltas));
}

/// Serialize the delta list in the spec's
/// `ingredient-delta-validation-result-map` shape.
pub(super) fn deltas_json(deltas: &[IngredientDelta]) -> Json {
    Json::Array(
        deltas
            .iter()
            .map(|delta| {
                json!({
                    "ingredientAssertionURI": delta.assertion_uri,
                    "validationDeltas": {
                        "success": status_array(&delta.deltas.success),
                        "informational": status_array(&delta.deltas.informational),
                        "failure": status_array(&delta.deltas.failure),
                    },
                })
            })
            .collect(),
    )
}

/// A manifest whose claim box is absent or undecodable cannot be validated at
/// all (C2PA 2.4: "Locate the claim ... If unable to, reject claim with a
/// `claim.missing` failure code").
fn record_missing_claim(manifest: &ParsedManifest<'_>, results: &mut ValidationResults) {
    let url = format!("self#jumbf=/c2pa/{}/c2pa.signature", manifest.label);
    if manifest.claim_cbor.is_none() {
        results.push_failure(
            CLAIM_MISSING,
            url,
            "no claim found in ingredient manifest".into(),
        );
    } else {
        results.push_failure(
            CLAIM_CBOR_INVALID,
            url,
            "ingredient manifest claim CBOR could not be decoded".into(),
        );
    }
}

/// A time-stamp manifest carries a time-stamp assertion and ingredient
/// assertions, and nothing else.
fn is_time_stamp_manifest(claim_refs: &ClaimAssertionRefs<'_>) -> bool {
    let mut timestamps = false;
    for label in &claim_refs.declaration_labels {
        let base = label.split("__").next().unwrap_or(label);
        match base {
            "c2pa.time-stamp" => timestamps = true,
            "c2pa.ingredient" | "c2pa.ingredient.v2" | "c2pa.ingredient.v3" => {}
            _ => return false,
        }
    }
    timestamps
}

/// Validate one reached ingredient manifest with what the store alone proves.
fn validate_reached_manifest<'a>(
    manifest: &'a ParsedManifest<'a>,
    claim: &Value,
    generation: ClaimGeneration,
    claim_refs: &mut ClaimAssertionRefs<'_>,
    cache: &mut IngredientManifestDigestCache<'a>,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    let sig_url = format!("self#jumbf=/c2pa/{}/c2pa.signature", manifest.label);
    verify_assertion_bindings(
        claim,
        claim_refs,
        generation,
        &manifest.label,
        profile,
        results,
    );
    verify_ingredient_references(
        &manifest.label,
        claim_refs,
        claim,
        cache,
        &sig_url,
        profile,
        results,
    );
    let (Some(cose), Some(claim_cbor)) = (manifest.signature_cose, manifest.claim_cbor) else {
        results.push_failure(
            CLAIM_SIGNATURE_MISSING,
            sig_url,
            "ingredient manifest has no claim signature".into(),
        );
        return;
    };
    let leaf = extract_x5chain(cose)
        .ok()
        .and_then(|chain| chain.into_iter().next())
        .filter(|leaf: &Vec<u8>| !leaf.is_empty());
    let Some(leaf) = leaf else {
        results.push_failure(
            CLAIM_SIGNATURE_MISSING,
            sig_url,
            "ingredient manifest claim signature carries no certificate".into(),
        );
        return;
    };
    match verify_claim(cose, claim_cbor, &leaf) {
        Ok(()) => results.push_success(
            CLAIM_SIGNATURE_VALIDATED,
            sig_url,
            "ingredient manifest claim signature verified".into(),
        ),
        Err(CryptoError::UnsupportedAlg(id)) => results.push_failure(
            ALGORITHM_UNSUPPORTED,
            sig_url,
            format!("ingredient manifest claim signature algorithm {id} is not on the C2PA allowed list"),
        ),
        Err(error) => results.push_failure(
            CLAIM_SIGNATURE_MISMATCH,
            sig_url,
            format!("ingredient manifest claim signature invalid: {error}"),
        ),
    }
}

/// The ingredient edges one manifest's claim declares.
///
/// Only a claim-declared ingredient assertion is an edge: reading a link out of
/// an assertion box the claim never referenced would let an injected box extend
/// the graph with the claim signature untouched.
fn edges(
    manifest: &ParsedManifest<'_>,
    claim_refs: &ClaimAssertionRefs<'_>,
    generation: ClaimGeneration,
    profile: EngineProfile,
    results: &mut ValidationResults,
) -> Vec<Edge> {
    let mut edges = Vec::new();
    for reference in &claim_refs.references {
        let Some(label) = reference.label else {
            continue;
        };
        if !label.starts_with("c2pa.ingredient") {
            continue;
        }
        let Some(ingredient) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let assertion_uri = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
            manifest.label
        );
        let link = ingredient
            .get("activeManifest")
            .or_else(|| ingredient.get("c2pa_manifest"));
        let Some(target) = link
            .and_then(|link| link.get("url"))
            .and_then(Value::as_text)
            .and_then(super::extract_manifest_label)
        else {
            continue;
        };
        let recorded = ingredient.get("validationResults").cloned();
        // "If no `validationResults` field is present and the ingredient
        // assertion is a v3 ingredient assertion with the `activeManifest`
        // field present, then return the failure code
        // `assertion.ingredient.malformed`." A recorded verdict the generator
        // omitted costs the validator nothing it can re-derive, so the rule is
        // applied where the spec is the bar (strict/conformance) and the
        // default posture keeps reading the manifest.
        if recorded.is_none()
            && !is_generous(profile)
            && generation == ClaimGeneration::V2
            && label.starts_with("c2pa.ingredient.v3")
            && ingredient.get("activeManifest").is_some()
        {
            results.push_failure(
                ASSERTION_INGREDIENT_MALFORMED,
                assertion_uri.clone(),
                format!("ingredient '{label}' links a manifest but records no validationResults"),
            );
        }
        edges.push(Edge {
            assertion_uri,
            target: target.to_string(),
            recorded,
        });
    }
    edges
}

/// The difference between the verdict a signer recorded for an ingredient's
/// manifest and the verdict this validation derived for it.
///
/// C2PA 2.4 defines it in both directions: a recorded entry this validation did
/// not produce is a delta, and an entry this validation produced that the
/// recorded verdict does not carry is a delta. Both matter, and they mean
/// different things. An entry only this validation produced is the
/// security-relevant one: the ingredient's manifest has changed since it was
/// ingested, or its signer's verdict was optimistic. An entry only the signer
/// recorded is usually something offline validation cannot re-derive - the
/// ingredient's own hard binding, its trust or revocation state - so it is
/// carried through marked `source: "recorded"` rather than presented as
/// something this validator checked.
///
/// Two entries are equivalent when their `code` and `url` agree; `explanation`
/// is human text and two validators will word it differently. The recorded side
/// includes the nested `ingredientDeltas` the signer stored, so an entry it
/// recorded one level down is not reported here as newly observed.
fn validation_deltas(recorded: Option<&Value>, observed: &ValidationResults) -> ValidationResults {
    let mut recorded_entries: Vec<(&'static str, StatusCode)> = Vec::new();
    if let Some(recorded) = recorded {
        collect_recorded(recorded.get("activeManifest"), &mut recorded_entries);
        if let Some(Value::Array(nested)) = recorded.get("ingredientDeltas") {
            for entry in nested {
                collect_recorded(entry.get("validationDeltas"), &mut recorded_entries);
            }
        }
    }
    let recorded_keys: HashSet<(&str, &str)> = recorded_entries
        .iter()
        .map(|(_, status)| (status.code.as_str(), status.url.as_str()))
        .collect();
    let observed_keys: HashSet<(&str, &str)> = observed
        .success
        .iter()
        .chain(&observed.informational)
        .chain(&observed.failure)
        .map(|status| (status.code.as_str(), status.url.as_str()))
        .collect();

    let mut deltas = ValidationResults::default();
    let new_codes = |codes: &[StatusCode]| -> Vec<StatusCode> {
        codes
            .iter()
            .filter(|status| !recorded_keys.contains(&(status.code.as_str(), status.url.as_str())))
            .cloned()
            .collect()
    };
    deltas.success = new_codes(&observed.success);
    deltas.informational = new_codes(&observed.informational);
    deltas.failure = new_codes(&observed.failure);
    for (bucket, status) in recorded_entries {
        if observed_keys.contains(&(status.code.as_str(), status.url.as_str())) {
            continue;
        }
        let status = StatusCode {
            details: Some(json!({ "source": "recorded" })),
            ..status
        };
        match bucket {
            "success" => deltas.success.push(status),
            "informational" => deltas.informational.push(status),
            _ => deltas.failure.push(status),
        }
    }
    deltas
}

/// Read one recorded `status-codes-map` into `(bucket, status)` pairs.
fn collect_recorded(codes: Option<&Value>, into: &mut Vec<(&'static str, StatusCode)>) {
    let Some(codes) = codes else {
        return;
    };
    for bucket in ["success", "informational", "failure"] {
        let Some(Value::Array(entries)) = codes.get(bucket) else {
            continue;
        };
        for entry in entries {
            let Some(code) = entry.get("code").and_then(Value::as_text) else {
                continue;
            };
            into.push((
                bucket,
                StatusCode {
                    code: code.to_string(),
                    url: entry
                        .get("url")
                        .and_then(Value::as_text)
                        .unwrap_or_default()
                        .to_string(),
                    explanation: entry
                        .get("explanation")
                        .and_then(Value::as_text)
                        .unwrap_or("recorded by the ingredient's claim generator")
                        .to_string(),
                    details: None,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sha2::{Digest, Sha256};
    use time::macros::datetime;
    use time::OffsetDateTime;

    use super::super::signature_conformance_tests::Signer;
    use super::super::{
        hash_claim_signature_box, manifest_hashes, verify_manifest, CawgTrustInputs, CrjsonContext,
        StoreContext, VerifyInput, VerifyOutput, MAX_REPORT_DECODED_VALUE_NODES,
    };
    use crate::c2pa_cbor::{encode, Profile, Value};
    use crate::c2pa_core::jumbf::{
        assertion_box, build_manifest, build_manifest_store, cbor_box, expand_store,
        parse_manifest_store, superbox, superbox_content, UUID_ASSERTION_STORE, UUID_CLAIM,
        UUID_CLAIM_SIGNATURE, UUID_UPDATE_MANIFEST,
    };
    use crate::c2pa_core::EngineProfile;
    use crate::c2pa_formats::AssetFormat;
    use serde_json::Value as Json;

    const INGREDIENT: &str = "urn:c2pa:00000000-0000-4000-8000-000000000001";
    const ACTIVE: &str = "urn:c2pa:00000000-0000-4000-8000-000000000002";
    const NOW: OffsetDateTime = datetime!(2026-06-01 0:00 UTC);

    fn enc(value: &Value) -> Vec<u8> {
        encode(value, Profile::LegacyPipelineBDefinite).expect("encode")
    }

    fn vmap(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(
            pairs
                .into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }

    /// An assertion box plus the hashed-URI a claim in the same manifest uses
    /// to reference it. The claim hash covers the JUMBF superbox content, the
    /// domain [`super::super::verify_assertion_bindings`] recomputes.
    #[derive(Clone)]
    struct Assertion {
        label: String,
        jumbf: Vec<u8>,
    }

    impl Assertion {
        fn new(label: &str, value: &Value) -> Self {
            Self {
                label: label.to_string(),
                jumbf: assertion_box(label, &enc(value), None),
            }
        }

        fn reference(&self) -> Value {
            let content = superbox_content(&self.jumbf).expect("assertion content");
            vmap(vec![
                (
                    "url",
                    Value::Text(format!("self#jumbf=c2pa.assertions/{}", self.label)),
                ),
                ("alg", Value::Text("sha256".into())),
                ("hash", Value::Bytes(Sha256::digest(content).to_vec())),
            ])
        }

        /// A reference whose hash does not match the stored bytes: an assertion
        /// that changed after its claim was signed.
        fn tampered_reference(&self) -> Value {
            vmap(vec![
                (
                    "url",
                    Value::Text(format!("self#jumbf=c2pa.assertions/{}", self.label)),
                ),
                ("alg", Value::Text("sha256".into())),
                ("hash", Value::Bytes(vec![0x00; 32])),
            ])
        }
    }

    fn data_hash() -> Value {
        vmap(vec![
            ("exclusions", Value::Array(Vec::new())),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0x11; 32])),
        ])
    }

    fn created_actions() -> Value {
        vmap(vec![(
            "actions",
            Value::Array(vec![vmap(vec![
                ("action", Value::Text("c2pa.created".into())),
                (
                    "digitalSourceType",
                    Value::Text(
                        "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into(),
                    ),
                ),
            ])]),
        )])
    }

    fn claim(references: Vec<Value>) -> Value {
        vmap(vec![
            ("instanceID", Value::Text("xmp:iid:fixture".into())),
            (
                "claim_generator_info",
                vmap(vec![("name", Value::Text("Encypher Fixture".into()))]),
            ),
            ("created_assertions", Value::Array(references)),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
        ])
    }

    /// One ingredient assertion: the link to `target`, the claim-signature
    /// link, and the verdict the signer recorded at ingest.
    fn ingredient(
        target_label: &str,
        target_manifest: &[u8],
        target_cose: &[u8],
        relationship: &str,
        recorded: Option<Value>,
    ) -> Value {
        let content = superbox_content(target_manifest).expect("manifest content");
        let mut fields = vec![
            ("relationship", Value::Text(relationship.into())),
            ("dc:title", Value::Text("ingredient.jpg".into())),
            (
                "activeManifest",
                vmap(vec![
                    (
                        "url",
                        Value::Text(format!("self#jumbf=/c2pa/{target_label}")),
                    ),
                    ("alg", Value::Text("sha256".into())),
                    ("hash", Value::Bytes(Sha256::digest(content).to_vec())),
                ]),
            ),
            (
                "claimSignature",
                vmap(vec![
                    (
                        "url",
                        Value::Text(format!("self#jumbf=/c2pa/{target_label}/c2pa.signature")),
                    ),
                    ("alg", Value::Text("sha256".into())),
                    (
                        "hash",
                        Value::Bytes(
                            hash_claim_signature_box("sha256", target_cose)
                                .expect("signature hash"),
                        ),
                    ),
                ]),
            ),
        ];
        if let Some(recorded) = recorded {
            fields.push(("validationResults", recorded));
        }
        vmap(fields)
    }

    /// An ingredient assertion with no manifest link at all.
    fn unlinked_ingredient(relationship: &str) -> Value {
        vmap(vec![
            ("relationship", Value::Text(relationship.into())),
            ("dc:title", Value::Text("no-provenance.jpg".into())),
        ])
    }

    /// The `validationResults` shape a claim generator records for an
    /// ingredient it validated at ingest.
    fn recorded_results(codes: Vec<(&str, &str, &str)>) -> Value {
        let mut success = Vec::new();
        let mut informational = Vec::new();
        let mut failure = Vec::new();
        for (bucket, code, url) in codes {
            let entry = vmap(vec![
                ("code", Value::Text(code.into())),
                ("url", Value::Text(url.into())),
            ]);
            match bucket {
                "success" => success.push(entry),
                "informational" => informational.push(entry),
                _ => failure.push(entry),
            }
        }
        vmap(vec![(
            "activeManifest",
            vmap(vec![
                ("success", Value::Array(success)),
                ("informational", Value::Array(informational)),
                ("failure", Value::Array(failure)),
            ]),
        )])
    }

    /// Assemble one manifest box from its assertions and a claim signed by
    /// `signer`. Returns the box and the COSE signature bytes.
    fn manifest_box(
        signer: &Signer,
        label: &str,
        assertions: &[Assertion],
        references: Vec<Value>,
    ) -> (Vec<u8>, Vec<u8>) {
        let claim_cbor = enc(&claim(references));
        let cose = signer.sign(&claim_cbor);
        let boxes: Vec<Vec<u8>> = assertions
            .iter()
            .map(|assertion| assertion.jumbf.clone())
            .collect();
        (
            build_manifest(label, &boxes, &claim_cbor, &cose),
            cose.clone(),
        )
    }

    /// The same manifest, wrapped as an update manifest (`c2um`).
    fn update_manifest_box(
        signer: &Signer,
        label: &str,
        assertions: &[Assertion],
        references: Vec<Value>,
    ) -> Vec<u8> {
        let claim_cbor = enc(&claim(references));
        let cose = signer.sign(&claim_cbor);
        superbox(
            &UUID_UPDATE_MANIFEST,
            label,
            &[
                superbox(
                    &UUID_ASSERTION_STORE,
                    "c2pa.assertions",
                    &assertions
                        .iter()
                        .map(|assertion| assertion.jumbf.clone())
                        .collect::<Vec<_>>(),
                    None,
                ),
                superbox(&UUID_CLAIM, "c2pa.claim.v2", &[cbor_box(&claim_cbor)], None),
                superbox(
                    &UUID_CLAIM_SIGNATURE,
                    "c2pa.signature",
                    &[cbor_box(&cose)],
                    None,
                ),
            ],
            None,
        )
    }

    /// Verify the last manifest in `boxes` as the active manifest.
    fn verify_store(boxes: &[Vec<u8>]) -> VerifyOutput {
        verify_store_under(boxes, EngineProfile::GENEROUS)
    }

    /// The same, under an explicit posture.
    fn verify_store_under(boxes: &[Vec<u8>], profile: EngineProfile) -> VerifyOutput {
        let store = build_manifest_store(boxes);
        let expanded = expand_store(&store).expect("expand store");
        let parsed = parse_manifest_store(expanded.bytes()).expect("parse store");
        let hashes = manifest_hashes(&expanded, &parsed.manifests).expect("manifest hashes");
        let active = parsed.manifests.last().expect("active manifest");
        let input = VerifyInput {
            data: &[],
            mime: "application/c2pa",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: Some(NOW),
            profile,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        verify_manifest(
            active,
            StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &input,
            AssetFormat::C2paStore,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        )
    }

    fn deltas(out: &VerifyOutput) -> Vec<&Json> {
        out.report_json
            .pointer("/validation_results/ingredientDeltas")
            .and_then(Json::as_array)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    fn delta_codes<'a>(delta: &'a Json, bucket: &str) -> Vec<&'a str> {
        delta
            .pointer(&format!("/validationDeltas/{bucket}"))
            .and_then(Json::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("code").and_then(Json::as_str))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A signed store whose ingredient manifest no longer binds its own
    /// assertions. The active manifest's link to that ingredient still matches
    /// (the link was computed over the store as it stands), so only recursive
    /// validation of the ingredient manifest can see the defect.
    fn tampered_ingredient_store() -> Vec<Vec<u8>> {
        let signer = Signer::conformant();
        let ingredient_binding = Assertion::new("c2pa.hash.data", &data_hash());
        let ingredient_actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let (ingredient_manifest, ingredient_cose) = manifest_box(
            &signer,
            INGREDIENT,
            &[ingredient_binding.clone(), ingredient_actions.clone()],
            vec![
                ingredient_binding.tampered_reference(),
                ingredient_actions.reference(),
            ],
        );

        let active_binding = Assertion::new("c2pa.hash.data", &data_hash());
        let active_actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let active_ingredient = Assertion::new(
            "c2pa.ingredient.v3",
            &ingredient(
                INGREDIENT,
                &ingredient_manifest,
                &ingredient_cose,
                "componentOf",
                Some(recorded_results(vec![(
                    "success",
                    "claimSignature.validated",
                    &format!("self#jumbf=/c2pa/{INGREDIENT}/c2pa.signature"),
                )])),
            ),
        );
        let (active_manifest, _) = manifest_box(
            &signer,
            ACTIVE,
            &[
                active_binding.clone(),
                active_actions.clone(),
                active_ingredient.clone(),
            ],
            vec![
                active_binding.reference(),
                active_actions.reference(),
                active_ingredient.reference(),
            ],
        );
        vec![ingredient_manifest, active_manifest]
    }

    #[test]
    fn ingredient_manifest_defect_is_reported_as_a_delta_and_not_as_an_active_failure() {
        let out = verify_store(&tampered_ingredient_store());

        let deltas = deltas(&out);
        assert_eq!(deltas.len(), 1, "report: {}", out.report_json);
        assert_eq!(
            deltas[0]
                .get("ingredientAssertionURI")
                .and_then(Json::as_str),
            Some(format!("self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3").as_str())
        );
        assert!(
            delta_codes(deltas[0], "failure").contains(&"assertion.hashedURI.mismatch"),
            "delta: {}",
            deltas[0]
        );
        // The ingredient's defect never becomes the active manifest's failure.
        assert!(
            !out.results
                .failure
                .iter()
                .any(|status| status.url.contains(INGREDIENT)),
            "active failures: {:?}",
            out.results.failure
        );
    }

    #[test]
    fn an_ingredient_without_a_manifest_link_reports_unknown_provenance() {
        let signer = Signer::conformant();
        let binding = Assertion::new("c2pa.hash.data", &data_hash());
        let actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let parent = Assertion::new("c2pa.ingredient.v3", &unlinked_ingredient("componentOf"));
        let (manifest, _) = manifest_box(
            &signer,
            ACTIVE,
            &[binding.clone(), actions.clone(), parent.clone()],
            vec![binding.reference(), actions.reference(), parent.reference()],
        );

        let out = verify_store(&[manifest]);

        let status = out
            .results
            .informational
            .iter()
            .find(|status| status.code == "ingredient.unknownProvenance")
            .expect("unknownProvenance informational");
        assert_eq!(
            status.url,
            format!("self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3")
        );
    }

    #[test]
    fn an_input_only_ingredient_without_provenance_is_silent() {
        let signer = Signer::conformant();
        let binding = Assertion::new("c2pa.hash.data", &data_hash());
        let actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let input = Assertion::new("c2pa.ingredient.v3", &unlinked_ingredient("inputTo"));
        let (manifest, _) = manifest_box(
            &signer,
            ACTIVE,
            &[binding.clone(), actions.clone(), input.clone()],
            vec![binding.reference(), actions.reference(), input.reference()],
        );

        let out = verify_store(&[manifest]);

        assert!(
            !out.results
                .informational
                .iter()
                .any(|status| status.code == "ingredient.unknownProvenance"),
            "informational: {:?}",
            out.results.informational
        );
    }

    /// Two manifests naming each other. Neither link hash can be valid (each
    /// claim would have to commit to the other's digest), but the walk must
    /// terminate and validate each manifest once.
    #[test]
    fn a_label_cycle_terminates_and_validates_each_manifest_once() {
        let signer = Signer::conformant();
        let link = |label: &str| {
            vmap(vec![
                ("relationship", Value::Text("componentOf".into())),
                (
                    "activeManifest",
                    vmap(vec![
                        ("url", Value::Text(format!("self#jumbf=/c2pa/{label}"))),
                        ("alg", Value::Text("sha256".into())),
                        ("hash", Value::Bytes(vec![0x00; 32])),
                    ]),
                ),
            ])
        };
        let first_binding = Assertion::new("c2pa.hash.data", &data_hash());
        let first_ingredient = Assertion::new("c2pa.ingredient.v3", &link(ACTIVE));
        let (first, _) = manifest_box(
            &signer,
            INGREDIENT,
            &[first_binding.clone(), first_ingredient.clone()],
            vec![first_binding.reference(), first_ingredient.reference()],
        );
        let second_binding = Assertion::new("c2pa.hash.data", &data_hash());
        let second_ingredient = Assertion::new("c2pa.ingredient.v3", &link(INGREDIENT));
        let (second, _) = manifest_box(
            &signer,
            ACTIVE,
            &[second_binding.clone(), second_ingredient.clone()],
            vec![second_binding.reference(), second_ingredient.reference()],
        );

        let out = verify_store(&[first, second]);

        // Exactly one delta: the walk validated the ingredient manifest once
        // and did not re-enter the active manifest its ingredient names back.
        // The ingredient's own broken link is reported inside that delta, which
        // is only possible if the walk validated the ingredient's own
        // ingredient references.
        let deltas = deltas(&out);
        assert_eq!(deltas.len(), 1, "report: {}", out.report_json);
        assert_eq!(
            deltas[0]
                .get("ingredientAssertionURI")
                .and_then(Json::as_str),
            Some(format!("self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3").as_str())
        );
        assert!(
            delta_codes(deltas[0], "failure").contains(&"ingredient.manifest.mismatch"),
            "delta: {}",
            deltas[0]
        );
    }

    /// The Content Credentials document carries the deltas the report produced,
    /// on the manifest whose assertion each one describes.
    #[test]
    fn crjson_carries_the_ingredient_deltas() {
        let boxes = tampered_ingredient_store();
        let out = verify_store(&boxes);
        let store_bytes = build_manifest_store(&boxes);
        let expanded = expand_store(&store_bytes).expect("expand store");
        let parsed = parse_manifest_store(expanded.bytes()).expect("parse store");

        let document = super::super::crjson::to_crjson(
            &parsed,
            &super::super::CrjsonContext {
                report: &out.report_json,
                validation_time: NOW,
                profile: EngineProfile::GENEROUS,
            },
        );

        let active = document["manifests"]
            .as_array()
            .and_then(|manifests| {
                manifests
                    .iter()
                    .find(|manifest| manifest["label"] == Json::String(ACTIVE.into()))
            })
            .expect("active manifest entry");
        assert_eq!(
            active["ingredientDeltas"][0]["ingredientAssertionURI"],
            Json::String(format!(
                "self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3"
            ))
        );
        // The ingredient manifest's own entry carries the verdict the walk
        // derived for it, resolved through the `activeManifest` link.
        let ingredient = document["manifests"]
            .as_array()
            .and_then(|manifests| {
                manifests
                    .iter()
                    .find(|manifest| manifest["label"] == Json::String(INGREDIENT.into()))
            })
            .expect("ingredient manifest entry");
        let failures: Vec<&str> = ingredient["validationResults"]["failure"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry["code"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            failures.contains(&"assertion.hashedURI.mismatch"),
            "ingredient entry: {ingredient}"
        );
    }

    /// An update manifest inherits the hard binding of the first standard
    /// manifest in its parentOf chain, which is what a CAWG identity inside it
    /// references (C2PA 2.4 Validation, "Validate the Asset's Content").
    #[test]
    fn an_update_manifest_inherits_its_parents_hard_binding() {
        let signer = Signer::conformant();
        let binding = Assertion::new("c2pa.hash.data", &data_hash());
        let actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let (standard, standard_cose) = manifest_box(
            &signer,
            INGREDIENT,
            &[binding.clone(), actions.clone()],
            vec![binding.reference(), actions.reference()],
        );
        let parent = Assertion::new(
            "c2pa.ingredient.v3",
            &ingredient(
                INGREDIENT,
                &standard,
                &standard_cose,
                "parentOf",
                Some(recorded_results(Vec::new())),
            ),
        );
        let update =
            update_manifest_box(&signer, ACTIVE, &[parent.clone()], vec![parent.reference()]);

        let store_bytes = build_manifest_store(&[standard, update]);
        let expanded = expand_store(&store_bytes).expect("expand store");
        let parsed = parse_manifest_store(expanded.bytes()).expect("parse store");
        let hashes = manifest_hashes(&expanded, &parsed.manifests).expect("manifest hashes");
        let active = parsed.manifests.last().expect("active manifest");

        let inherited = super::super::inherited_hard_binding(
            active,
            StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
        )
        .expect("update manifest inherits a hard binding");

        assert_eq!(inherited.0, INGREDIENT);
        assert_eq!(
            inherited.1.get("url").and_then(Value::as_text),
            Some("self#jumbf=c2pa.assertions/c2pa.hash.data")
        );
    }

    /// A v3 ingredient that links a manifest but records no `validationResults`
    /// is rejected where the spec is the bar, and read as before by default: a
    /// missing recorded verdict costs the validator nothing it cannot re-derive
    /// from the store itself.
    #[test]
    fn a_v3_ingredient_without_recorded_results_is_a_strict_only_failure() {
        let signer = Signer::conformant();
        let binding = Assertion::new("c2pa.hash.data", &data_hash());
        let actions = Assertion::new("c2pa.actions.v2", &created_actions());
        let (child, child_cose) = manifest_box(
            &signer,
            INGREDIENT,
            &[binding.clone(), actions.clone()],
            vec![binding.reference(), actions.reference()],
        );
        let link = Assertion::new(
            "c2pa.ingredient.v3",
            &ingredient(INGREDIENT, &child, &child_cose, "componentOf", None),
        );
        let active_binding = Assertion::new("c2pa.hash.data", &data_hash());
        let (active, _) = manifest_box(
            &signer,
            ACTIVE,
            &[active_binding.clone(), link.clone()],
            vec![active_binding.reference(), link.reference()],
        );
        let boxes = vec![child, active];

        let strict = verify_store_under(
            &boxes,
            EngineProfile::strict(crate::c2pa_core::SpecVersion::V2_4),
        );
        let generous = verify_store(&boxes);

        assert!(
            strict.results.failure.iter().any(|status| {
                status.code == "assertion.ingredient.malformed"
                    && status.url
                        == format!("self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3")
            }),
            "strict failures: {:?}",
            strict.results.failure
        );
        assert!(
            !generous
                .results
                .failure
                .iter()
                .any(|status| status.code == "assertion.ingredient.malformed"),
            "default failures: {:?}",
            generous.results.failure
        );
    }

    /// A store deeper than the walk's ceiling stops at it and says so, without
    /// touching the verdict: running out of budget is a resource outcome.
    #[test]
    fn a_chain_deeper_than_the_ceiling_stops_and_reports_the_limit() {
        let signer = Signer::conformant();
        let depth = super::MAX_DEPTH + 2;
        let mut boxes: Vec<Vec<u8>> = Vec::with_capacity(depth);
        let mut previous: Option<(String, Vec<u8>, Vec<u8>)> = None;
        for index in 0..depth {
            let label = format!("urn:c2pa:00000000-0000-4000-8000-{index:012}");
            let binding = Assertion::new("c2pa.hash.data", &data_hash());
            let mut assertions = vec![binding.clone()];
            let mut references = vec![binding.reference()];
            if let Some((parent_label, parent_manifest, parent_cose)) = &previous {
                let link = Assertion::new(
                    "c2pa.ingredient.v3",
                    &ingredient(
                        parent_label,
                        parent_manifest,
                        parent_cose,
                        "componentOf",
                        None,
                    ),
                );
                references.push(link.reference());
                assertions.push(link);
            }
            let (manifest, cose) = manifest_box(&signer, &label, &assertions, references);
            previous = Some((label, manifest.clone(), cose));
            boxes.push(manifest);
        }
        // The last manifest built is the active one, and each step down the
        // chain is one more ingredient edge away from it.
        let out = verify_store(&boxes);

        let limit = out
            .results
            .informational
            .iter()
            .find(|status| status.code == "com.encypher.ingredient.graphLimitExceeded")
            .expect("graph ceiling reported");
        assert_eq!(
            limit
                .details
                .as_ref()
                .and_then(|details| details.get("limit").and_then(serde_json::Value::as_str)),
            Some("depth")
        );
        // The ceiling is informational: it never adds a failure of its own.
        assert!(!out
            .results
            .failure
            .iter()
            .any(|status| status.code.starts_with("com.encypher.ingredient.")));
    }
}
