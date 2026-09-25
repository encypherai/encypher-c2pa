// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Generic hashed-URI validation for the reference FIELDS of standard
//! assertions (C2PA 2.4 Validation, "Validation of References").
//!
//! The claim's own `created_assertions` / `gathered_assertions` walk lives in
//! the crate root ([`super::verify_assertion_bindings`]). This module covers
//! the other direction the spec requires: "If the value of any field of a
//! standard assertion is a `hashed_uri` or `hashed_ext_uri`, the validator
//! shall perform the steps described in Validation of References, except for
//! the `activeManifest` field in `c2pa.ingredient.v3`."
//!
//! Four properties are load-bearing.
//!
//! 1. **Schema-driven, not shape-guessing.** [`ref_fields`] is derived from the
//!    2.4 CDDL: every property whose declared type is `$hashed-uri-map` (or the
//!    `$hashed-uri-map / $hashed-ext-uri-map` union). A map is walked because
//!    the spec says that field is a reference, never because some map happened
//!    to carry `{url, hash}`. An unknown or vendor assertion contributes no
//!    reference and is never touched.
//! 2. **The `metadata` subtree is skipped.** `$assertion-metadata-map` carries
//!    its own `reference` hashed URI, but C2PA 2.4 Validation, Assertion
//!    Validation, General is explicit: "For those assertions that support
//!    assertion metadata (via a `metadata` field), if the `metadata` field is
//!    present, the validator shall not perform any validation on the contents
//!    of that structure." So no path in this module descends into `metadata`.
//! 3. **No network, and no external references.** Only `self#jumbf=` URIs are
//!    resolved here. A field whose CDDL type is the internal/external union
//!    (`c2pa.ingredient.v2`/`v3`'s `data`) is validated only when its `url` is
//!    a `self#jumbf=` reference; an `http(s)` URL is external data, which
//!    C2PA 2.4 External Data Validation keeps out of standard validation
//!    entirely and routes through the cloud-data / external-reference rules.
//! 4. **Store-scoped, exact-label resolution.** The procedure is scoped to the
//!    C2PA Manifest Store: an ingredient `thumbnail` commonly names the
//!    thumbnail already sitting in the INGREDIENT's manifest rather than
//!    copying those bytes forward. Resolution is by exact manifest label and
//!    exact assertion label, never by suffix or best effort, so a signed URI
//!    can never silently re-target another manifest's bytes. Reaching another
//!    manifest is not a trust escalation: the reference carries the hash the
//!    referring claim committed to, so those bytes are the referrer's own
//!    statement about itself.
//!
//! Fields that already have their own dedicated procedure and status codes are
//! deliberately absent from the tables, so no defect is reported twice under
//! two codes:
//!
//! - `c2pa.ingredient.v3.activeManifest` and `claimSignature`, and the v1/v2
//!   `c2pa_manifest` field: graph edges carrying `ingredient.manifest.*` and
//!   `ingredient.claimSignature.*` (Validation, Validate the Ingredients).
//!   `activeManifest` is carved out of this procedure by name.
//! - `c2pa.hash.multi-asset`'s `parts[].hashAssertion`: resolved and digested
//!   by [`super::verify_multi_asset`] under `assertion.multiAssetHash.*`.
//! - `c2pa.alternative-content-representation`'s
//!   `embeddedOriginalPreservationImage`: resolved and digested by
//!   [`super::verify_alternative_content`] under
//!   `assertion.alternativeContentRepresentation.*`.
//!
//! An action's `parameters.ingredient(s)` and `parameters.relatedAssertions`
//! ARE walked here. Those are checked by the `c2pa.actions` rules too, but only
//! for the action kinds those rules name, and only as a precondition of an
//! `assertion.action.*` verdict. The blanket reference rule applies to every
//! action kind, so walking them here closes the gap for the rest; where both
//! apply, the two codes describe two different true facts about the same
//! defect.

use super::{
    hash_bytes, is_allowed_hash_algorithm, is_generous, ClaimAssertionRefs, ClaimGeneration,
    EngineProfile, ValidationResults, ALGORITHM_UNSUPPORTED, CLAIM_MALFORMED, HASHED_URI_MISMATCH,
    HASHED_URI_MISSING,
};
use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::ParsedManifest;

/// Ceiling on the number of nested references one manifest walk examines.
///
/// Matches [`super::MAX_CLAIM_ASSERTION_REFERENCES`]: a claim may not declare
/// more assertions than that, and no honest assertion set carries more nested
/// references than the store carries assertions. Input beyond the bound is
/// rejected rather than hashed.
const MAX_NESTED_REFERENCES: usize = 4_096;

/// Ceiling on `related` action nesting. `action-item-map-v2.related` is a list
/// of action items, so it recurses; the bound keeps a hostile assertion from
/// turning that recursion into unbounded work.
const MAX_RELATED_DEPTH: usize = 8;

/// One step of a path from an assertion's root to a reference-bearing field.
#[derive(Clone, Copy)]
enum Step {
    /// Descend into a map field.
    Field(&'static str),
    /// Iterate every element of an array.
    Each,
    /// Apply the remaining steps at this action item and at every action item
    /// reachable through nested `related` arrays.
    EachRelated,
}

/// Which reference flavor the 2.4 CDDL declares for a field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `$hashed-uri-map`: a `self#jumbf=` URI.
    Internal,
    /// `$hashed-uri-map / $hashed-ext-uri-map`: the URL's own scheme decides.
    /// An external URL is left to the external-data procedure.
    Either,
}

/// A reference-bearing field of a standard assertion.
struct RefField {
    path: &'static [Step],
    kind: Kind,
}

const fn field(path: &'static [Step], kind: Kind) -> RefField {
    RefField { path, kind }
}

/// `c2pa.ingredient` (v1, deprecated): `ingredient-map`.
const INGREDIENT_V1: &[RefField] = &[field(&[Step::Field("thumbnail")], Kind::Internal)];

/// `c2pa.ingredient.v2` (deprecated): `ingredient-map-v2`.
const INGREDIENT_V2: &[RefField] = &[
    field(&[Step::Field("thumbnail")], Kind::Internal),
    field(&[Step::Field("data")], Kind::Either),
];

/// `c2pa.ingredient.v3`: `ingredient-map-v3`.
const INGREDIENT_V3: &[RefField] = &[
    field(&[Step::Field("thumbnail")], Kind::Internal),
    field(&[Step::Field("data")], Kind::Either),
];

/// `c2pa.actions` / `c2pa.actions.v2`: `actions-map`, `actions-map-v2`,
/// `action-common-map-v2`, `action-template-map-v2`, `parameters-map`, and
/// `parameters-map-v2`.
const ACTIONS: &[RefField] = &[
    field(
        &[
            Step::Field("actions"),
            Step::Each,
            Step::EachRelated,
            Step::Field("parameters"),
            Step::Field("ingredient"),
        ],
        Kind::Internal,
    ),
    field(
        &[
            Step::Field("actions"),
            Step::Each,
            Step::EachRelated,
            Step::Field("parameters"),
            Step::Field("ingredients"),
            Step::Each,
        ],
        Kind::Internal,
    ),
    field(
        &[
            Step::Field("actions"),
            Step::Each,
            Step::EachRelated,
            Step::Field("parameters"),
            Step::Field("relatedAssertions"),
            Step::Each,
        ],
        Kind::Internal,
    ),
    field(
        &[
            Step::Field("actions"),
            Step::Each,
            Step::EachRelated,
            Step::Field("softwareAgent"),
            Step::Field("icon"),
        ],
        Kind::Either,
    ),
    field(
        &[
            Step::Field("softwareAgents"),
            Step::Each,
            Step::Field("icon"),
        ],
        Kind::Either,
    ),
    field(
        &[Step::Field("templates"), Step::Each, Step::Field("icon")],
        Kind::Internal,
    ),
];

/// The reference-bearing fields the 2.4 CDDL declares for `label`.
///
/// Multi-instance labels (`c2pa.ingredient.v3__2`) resolve to their base. A
/// label with no entry contributes nothing: an unknown assertion is never
/// walked speculatively.
fn ref_fields(label: &str) -> &'static [RefField] {
    match base_label(label) {
        "c2pa.ingredient" => INGREDIENT_V1,
        "c2pa.ingredient.v2" => INGREDIENT_V2,
        "c2pa.ingredient.v3" => INGREDIENT_V3,
        "c2pa.actions" | "c2pa.actions.v2" => ACTIONS,
        _ => &[],
    }
}

/// Strip the `__N` multi-instance suffix a store uses for repeated assertions.
pub(super) fn base_label(label: &str) -> &str {
    match label.split_once("__") {
        Some((base, instance))
            if !instance.is_empty() && instance.bytes().all(|b| b.is_ascii_digit()) =>
        {
            base
        }
        _ => label,
    }
}

/// One located reference: its schema flavor, its value, and a readable path.
struct Located<'v> {
    kind: Kind,
    value: &'v Value,
    path: String,
}

/// Walk `steps` through `value`, collecting references until `limit` is hit.
///
/// Returns true when the cap was reached, which the caller treats as a
/// resource ceiling rather than first materializing an attacker-sized array.
fn locate<'v>(
    value: &'v Value,
    kind: Kind,
    steps: &[Step],
    depth: usize,
    path: &mut String,
    out: &mut Vec<Located<'v>>,
    limit: usize,
) -> bool {
    if out.len() >= limit {
        return true;
    }
    match steps.split_first() {
        None => {
            out.push(Located {
                kind,
                value,
                path: path.clone(),
            });
            out.len() >= limit
        }
        Some((Step::Field(name), rest)) => {
            let Some(child) = value.get(name) else {
                return false;
            };
            let mark = path.len();
            if !path.is_empty() {
                path.push('.');
            }
            path.push_str(name);
            let capped = locate(child, kind, rest, depth, path, out, limit);
            path.truncate(mark);
            capped
        }
        Some((Step::Each, rest)) => {
            let Value::Array(items) = value else {
                return false;
            };
            for (index, item) in items.iter().enumerate() {
                let mark = path.len();
                path.push('[');
                path.push_str(&index.to_string());
                path.push(']');
                let capped = locate(item, kind, rest, depth, path, out, limit);
                path.truncate(mark);
                if capped {
                    return true;
                }
            }
            false
        }
        Some((Step::EachRelated, rest)) => {
            if locate(value, kind, rest, depth, path, out, limit) {
                return true;
            }
            if depth >= MAX_RELATED_DEPTH {
                return false;
            }
            let Some(Value::Array(items)) = value.get("related") else {
                return false;
            };
            for (index, item) in items.iter().enumerate() {
                let mark = path.len();
                path.push_str(".related[");
                path.push_str(&index.to_string());
                path.push(']');
                let capped = locate(item, kind, steps, depth + 1, path, out, limit);
                path.truncate(mark);
                if capped {
                    return true;
                }
            }
            false
        }
    }
}

/// Validate every schema-declared `hashed_uri` field of every standard
/// assertion the claim declares.
///
/// `manifests` is the whole parsed store, because a nested reference may name
/// a box in another manifest; `manifest_label` is the manifest being walked,
/// which a relative `self#jumbf=c2pa.assertions/...` URI resolves against.
/// Assertion values come from the claim's own bounded index, so nothing is
/// decoded twice and nothing undeclared is walked.
pub(super) fn verify_assertion_references(
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    generation: ClaimGeneration,
    profile: EngineProfile,
    manifest_label: &str,
    manifests: &[ParsedManifest<'_>],
    results: &mut ValidationResults,
) {
    // The blanket reference rule is a 2.x requirement that 1.x-era generators
    // could not follow: they wrote an action's `parameters.ingredient` hash
    // before the assertion it names was final, so the digest in that position
    // routinely disagrees with the assertion the claim itself binds correctly.
    // A v1 claim is therefore held to this rule only under strict conformance,
    // exactly as it is held to the `c2pa.actions` ingredient-resolution rules
    // in [`super::verify_action_assertions`].
    if generation == ClaimGeneration::V1 && is_generous(profile) {
        return;
    }
    let claim_alg = claim.get("alg").and_then(Value::as_text);
    let mut seen: Vec<&str> = Vec::new();
    let mut examined = 0usize;
    for reference in &claim_refs.references {
        let Some(alabel) = reference.label else {
            continue;
        };
        if seen.contains(&alabel) {
            continue;
        }
        seen.push(alabel);
        let fields = ref_fields(alabel);
        if fields.is_empty() {
            continue;
        }
        let Some(assertion) = claim_refs
            .indexed(alabel)
            .and_then(|indexed| indexed.decoded.as_ref())
        else {
            continue;
        };
        let assertion_url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{alabel}");
        let assertion_alg = assertion.get("alg").and_then(Value::as_text);
        let mut located = Vec::new();
        let mut capped = false;
        for field in fields {
            let remaining = MAX_NESTED_REFERENCES.saturating_sub(examined + located.len());
            if remaining == 0 {
                capped = true;
                break;
            }
            let mut path = String::new();
            if locate(
                assertion,
                field.kind,
                field.path,
                0,
                &mut path,
                &mut located,
                remaining,
            ) {
                capped = true;
                break;
            }
        }
        examined += located.len();
        for located in &located {
            validate_reference(
                located,
                alabel,
                &assertion_url,
                generation,
                manifest_label,
                manifests,
                assertion_alg.or(claim_alg),
                results,
            );
        }
        if capped {
            results.push_failure(
                CLAIM_MALFORMED,
                assertion_url,
                format!(
                    "assertion reference count exceeds verifier bound ({MAX_NESTED_REFERENCES})"
                ),
            );
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)] // one reference's full context; splitting it hides the flow
fn validate_reference(
    located: &Located<'_>,
    alabel: &str,
    assertion_url: &str,
    generation: ClaimGeneration,
    manifest_label: &str,
    manifests: &[ParsedManifest<'_>],
    inherited_alg: Option<&str>,
    results: &mut ValidationResults,
) {
    let path = &located.path;
    // "The destination of a `hashed_uri` is found in its `url` field. If the
    // field is not present or the destination cannot be located [...] then it
    // shall be treated as a validation failure with code `hashedURI.missing`."
    let Some(url) = located.value.get("url").and_then(Value::as_text) else {
        results.push_failure(
            HASHED_URI_MISSING,
            assertion_url.to_string(),
            format!("{alabel} field '{path}' is not a hashed URI: no url"),
        );
        return;
    };
    if located.kind == Kind::Either && !url.starts_with("self#jumbf=") {
        // A `hashed_ext_uri` in the union position. External data is not part
        // of standard validation (C2PA 2.4 External Data Validation), so this
        // procedure has nothing to say about it.
        return;
    }
    let Some(destination) = resolve(url, manifest_label, manifests) else {
        results.push_failure(
            HASHED_URI_MISSING,
            url.to_string(),
            format!("{alabel} field '{path}' references '{url}', which cannot be located"),
        );
        return;
    };

    // "If there is an `alg` field in the `hashed_uri` structure, it shall be
    // used [...] otherwise the nearest enclosing structure that contains an
    // `alg` field [...] otherwise the `alg` field in the claim. If no `alg`
    // field is present in any of these locations, the claim shall be rejected
    // with a failure code of `algorithm.unsupported`."
    let algorithm = located
        .value
        .get("alg")
        .and_then(Value::as_text)
        .or(inherited_alg);
    let Some(algorithm) = algorithm else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("{alabel} field '{path}' has no hash algorithm"),
        );
        return;
    };
    if !is_allowed_hash_algorithm(algorithm) {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("{alabel} field '{path}' uses unsupported hash algorithm '{algorithm}'"),
        );
        return;
    }

    // "Ensure that the `hash` field is present [...] If it is not, the claim
    // shall be rejected with a failure code of `hashedURI.mismatch`." The same
    // code covers a digest that does not match.
    //
    // The hashing domain is the assertion's JUMBF content, per Hashing JUMBF
    // Boxes. 1.x-era claim generators hashed the bare assertion payload in
    // this position instead, so a v1 claim also accepts that domain - the same
    // legacy tolerance [`super::verify_assertion_bindings`] applies to the
    // claim's own assertion list. A v2 claim gets no such latitude.
    let expected = located.value.get("hash").and_then(Value::as_bytes);
    let matches_domain = |bytes: Option<&[u8]>| {
        matches!(
            (bytes.and_then(|bytes| hash_bytes(algorithm, bytes)), expected),
            (Some(actual), Some(expected)) if actual.as_slice() == expected
        )
    };
    let matched = matches_domain(Some(destination.jumbf))
        || (generation == ClaimGeneration::V1 && matches_domain(destination.payload));
    if !matched {
        results.push_failure(
            HASHED_URI_MISMATCH,
            url.to_string(),
            format!("{alabel} field '{path}' hashed uri mismatch: {url}"),
        );
    }
}

/// The bytes a `self#jumbf=` assertion URI names, resolved by exact manifest
/// label and exact assertion label.
///
/// Only assertion boxes resolve here: the manifest box and the claim-signature
/// box are named exclusively by the ingredient graph fields, which this module
/// does not walk, and each of those has its own hashing domain.
struct Destination<'a> {
    /// The assertion's JUMBF content: description box plus content boxes,
    /// without the superbox header. The domain C2PA hashes.
    jumbf: &'a [u8],
    /// The assertion's bare serialized payload, when it has one. Only a v1
    /// claim may be satisfied by this domain.
    payload: Option<&'a [u8]>,
}

fn resolve<'a>(
    url: &str,
    manifest_label: &str,
    manifests: &'a [ParsedManifest<'_>],
) -> Option<Destination<'a>> {
    let rest = url.strip_prefix("self#jumbf=")?;
    let (target_manifest, alabel) = match rest.strip_prefix("/c2pa/") {
        Some(absolute) => absolute.split_once("/c2pa.assertions/")?,
        None => (manifest_label, rest.strip_prefix("c2pa.assertions/")?),
    };
    if alabel.is_empty() || alabel.contains('/') {
        return None;
    }
    let manifest = unique(manifests, |manifest| manifest.label == target_manifest)?;
    let (_, jumbf) = unique(&manifest.assertion_jumbf, |(label, _)| label == alabel)?;
    Some(Destination {
        jumbf,
        payload: unique(&manifest.assertions, |(label, _)| label == alabel)
            .map(|(_, payload)| *payload),
    })
}

/// The single matching entry, or `None` when there is none or more than one.
/// An ambiguous label cannot be resolved to bytes a signature committed to.
fn unique<T>(items: &[T], mut matches: impl FnMut(&T) -> bool) -> Option<&T> {
    let mut found = items.iter().filter(|item| matches(item));
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{encode, Profile};
    use crate::c2pa_core::jumbf::{assertion_box, superbox_content};
    use sha2::{Digest, Sha256};

    fn enc(value: &Value) -> Vec<u8> {
        encode(value, Profile::CanonicalForHashedSubstructures).expect("encode")
    }

    fn vmap(fields: Vec<(&str, Value)>) -> Value {
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }

    fn sha(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }

    const MANIFEST: &str = "urn:c2pa:active";

    /// One manifest carrying `boxes` as its assertion store, and a claim that
    /// declares every one of them.
    struct Fixture {
        jumbf: Vec<(String, Vec<u8>)>,
        payloads: Vec<(String, Vec<u8>)>,
    }

    impl Fixture {
        fn new(assertions: &[(&str, Value)]) -> Self {
            let mut jumbf = Vec::new();
            let mut payloads = Vec::new();
            for (label, value) in assertions {
                let cbor = enc(value);
                let boxed = assertion_box(label, &cbor, None);
                let content = superbox_content(&boxed).expect("content").to_vec();
                jumbf.push(((*label).to_string(), content));
                payloads.push(((*label).to_string(), cbor));
            }
            Self { jumbf, payloads }
        }

        fn manifest(&self) -> ParsedManifest<'_> {
            ParsedManifest {
                label: MANIFEST.into(),
                manifest_jumbf: &[],
                assertions: self
                    .payloads
                    .iter()
                    .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
                    .collect(),
                assertion_jumbf: self
                    .jumbf
                    .iter()
                    .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
                    .collect(),
                claim_cbor: None,
                signature_cose: None,
                claim_count: 1,
                claim_box_label: None,
            }
        }

        fn content(&self, label: &str) -> &[u8] {
            self.jumbf
                .iter()
                .find(|(candidate, _)| candidate == label)
                .map(|(_, bytes)| bytes.as_slice())
                .expect("assertion")
        }
    }

    fn claim_for(labels: &[&str]) -> Value {
        vmap(vec![(
            "created_assertions",
            Value::Array(
                labels
                    .iter()
                    .map(|label| {
                        vmap(vec![
                            (
                                "url",
                                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                            ),
                            ("hash", Value::Bytes(vec![0; 32])),
                        ])
                    })
                    .collect(),
            ),
        )])
    }

    fn run(fixture: &Fixture, claim: &Value) -> ValidationResults {
        run_as(fixture, claim, ClaimGeneration::V2, EngineProfile::GENEROUS)
    }

    fn run_as(
        fixture: &Fixture,
        claim: &Value,
        generation: ClaimGeneration,
        profile: EngineProfile,
    ) -> ValidationResults {
        let manifests = [fixture.manifest()];
        let refs = ClaimAssertionRefs::build(&manifests[0], claim, generation);
        let mut results = ValidationResults::default();
        verify_assertion_references(
            claim,
            &refs,
            generation,
            profile,
            MANIFEST,
            &manifests,
            &mut results,
        );
        results
    }

    fn hashed_uri(label: &str, hash: Vec<u8>) -> Value {
        vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            ),
            ("hash", Value::Bytes(hash)),
            ("alg", Value::Text("sha256".into())),
        ])
    }

    /// An ingredient thumbnail reference whose digest matches the thumbnail
    /// assertion in the store is silent; one that does not is
    /// `hashedURI.mismatch`. Nothing else in the pipeline reads this field, so
    /// without this walk a tampered thumbnail reference reads as valid.
    #[test]
    fn ingredient_thumbnail_reference_digest_is_enforced() {
        let thumb = vmap(vec![("data", Value::Bytes(vec![7; 16]))]);
        let staged = Fixture::new(&[("c2pa.thumbnail.ingredient", thumb.clone())]);
        let digest = sha(staged.content("c2pa.thumbnail.ingredient"));

        let good = Fixture::new(&[
            ("c2pa.thumbnail.ingredient", thumb.clone()),
            (
                "c2pa.ingredient.v3",
                vmap(vec![
                    ("relationship", Value::Text("parentOf".into())),
                    (
                        "thumbnail",
                        hashed_uri("c2pa.thumbnail.ingredient", digest.clone()),
                    ),
                ]),
            ),
        ]);
        let results = run(
            &good,
            &claim_for(&["c2pa.thumbnail.ingredient", "c2pa.ingredient.v3"]),
        );
        assert!(!results.has_failure(HASHED_URI_MISMATCH));
        assert!(!results.has_failure(HASHED_URI_MISSING));

        let tampered = Fixture::new(&[
            ("c2pa.thumbnail.ingredient", thumb),
            (
                "c2pa.ingredient.v3",
                vmap(vec![
                    ("relationship", Value::Text("parentOf".into())),
                    (
                        "thumbnail",
                        hashed_uri("c2pa.thumbnail.ingredient", vec![0xAB; 32]),
                    ),
                ]),
            ),
        ]);
        let results = run(
            &tampered,
            &claim_for(&["c2pa.thumbnail.ingredient", "c2pa.ingredient.v3"]),
        );
        assert!(results.has_failure(HASHED_URI_MISMATCH));
    }

    /// A reference naming a box the store does not carry is
    /// `hashedURI.missing`, and an `activeManifest` link is NOT walked here:
    /// C2PA 2.4 carves it out of this procedure by name.
    #[test]
    fn unresolvable_reference_reports_missing_and_active_manifest_is_exempt() {
        let fixture = Fixture::new(&[(
            "c2pa.ingredient.v3",
            vmap(vec![
                ("relationship", Value::Text("parentOf".into())),
                (
                    "thumbnail",
                    hashed_uri("c2pa.thumbnail.absent", vec![1; 32]),
                ),
                (
                    "activeManifest",
                    vmap(vec![
                        ("url", Value::Text("self#jumbf=/c2pa/urn:c2pa:gone".into())),
                        ("hash", Value::Bytes(vec![2; 32])),
                        ("alg", Value::Text("sha256".into())),
                    ]),
                ),
            ]),
        )]);
        let results = run(&fixture, &claim_for(&["c2pa.ingredient.v3"]));
        assert_eq!(
            results
                .failure
                .iter()
                .filter(|status| status.code == HASHED_URI_MISSING)
                .count(),
            1
        );
        assert!(results
            .failure
            .iter()
            .all(|status| !status.explanation.contains("activeManifest")));
    }

    /// A `softwareAgent.icon` inside a nested `related` action is still a
    /// reference field of a standard assertion, so a tampered one fails.
    #[test]
    fn nested_related_action_icon_is_walked() {
        let icon = vmap(vec![("data", Value::Bytes(vec![3; 8]))]);
        let related_action = vmap(vec![
            ("action", Value::Text("c2pa.edited".into())),
            (
                "softwareAgent",
                vmap(vec![
                    ("name", Value::Text("agent".into())),
                    ("icon", hashed_uri("c2pa.icon", vec![0xCD; 32])),
                ]),
            ),
        ]);
        let actions = vmap(vec![(
            "actions",
            Value::Array(vec![vmap(vec![
                ("action", Value::Text("c2pa.created".into())),
                ("related", Value::Array(vec![related_action])),
            ])]),
        )]);
        let fixture = Fixture::new(&[("c2pa.icon", icon), ("c2pa.actions.v2", actions)]);
        let results = run(&fixture, &claim_for(&["c2pa.icon", "c2pa.actions.v2"]));
        assert!(results.has_failure(HASHED_URI_MISMATCH));
    }

    /// The `metadata` subtree carries its own `reference` hashed URI, and
    /// C2PA 2.4 forbids validating anything inside it. A deliberately broken
    /// one must stay silent.
    #[test]
    fn metadata_subtree_is_never_validated() {
        let fixture = Fixture::new(&[(
            "c2pa.ingredient.v3",
            vmap(vec![
                ("relationship", Value::Text("parentOf".into())),
                (
                    "metadata",
                    vmap(vec![("reference", hashed_uri("c2pa.absent", vec![9; 32]))]),
                ),
            ]),
        )]);
        let results = run(&fixture, &claim_for(&["c2pa.ingredient.v3"]));
        assert!(results.failure.is_empty(), "{:?}", results.failure);
    }

    /// An ingredient `data` field may be a `hashed_ext_uri`. External data is
    /// outside standard validation, so an http(s) URL yields nothing here,
    /// while a same-manifest `data` reference is enforced.
    #[test]
    fn external_data_reference_is_left_to_external_validation() {
        let external = Fixture::new(&[(
            "c2pa.ingredient.v3",
            vmap(vec![
                ("relationship", Value::Text("inputTo".into())),
                (
                    "data",
                    vmap(vec![
                        ("url", Value::Text("https://example.com/data.bin".into())),
                        ("hash", Value::Bytes(vec![4; 32])),
                        ("alg", Value::Text("sha256".into())),
                    ]),
                ),
            ]),
        )]);
        let results = run(&external, &claim_for(&["c2pa.ingredient.v3"]));
        assert!(results.failure.is_empty(), "{:?}", results.failure);

        let internal = Fixture::new(&[
            (
                "c2pa.embedded-data",
                vmap(vec![("v", Value::Bytes(vec![5]))]),
            ),
            (
                "c2pa.ingredient.v3",
                vmap(vec![
                    ("relationship", Value::Text("inputTo".into())),
                    ("data", hashed_uri("c2pa.embedded-data", vec![6; 32])),
                ]),
            ),
        ]);
        let results = run(
            &internal,
            &claim_for(&["c2pa.embedded-data", "c2pa.ingredient.v3"]),
        );
        assert!(results.has_failure(HASHED_URI_MISMATCH));
    }

    /// The reference's own `alg` wins; otherwise the assertion's, otherwise
    /// the claim's. An algorithm this engine cannot recompute is
    /// `algorithm.unsupported`, never a silent pass.
    #[test]
    fn hash_algorithm_is_inherited_then_checked() {
        let thumb = vmap(vec![("data", Value::Bytes(vec![8; 4]))]);
        let staged = Fixture::new(&[("c2pa.thumbnail.ingredient", thumb.clone())]);
        let digest = sha(staged.content("c2pa.thumbnail.ingredient"));
        let inherited = |alg: Option<&str>, claim_alg: Option<&str>| {
            let mut reference = vec![
                (
                    "url",
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.thumbnail.ingredient".into()),
                ),
                ("hash", Value::Bytes(digest.clone())),
            ];
            if let Some(alg) = alg {
                reference.push(("alg", Value::Text(alg.into())));
            }
            let fixture = Fixture::new(&[
                ("c2pa.thumbnail.ingredient", thumb.clone()),
                (
                    "c2pa.ingredient.v3",
                    vmap(vec![
                        ("relationship", Value::Text("parentOf".into())),
                        ("thumbnail", vmap(reference)),
                    ]),
                ),
            ]);
            let mut claim = claim_for(&["c2pa.thumbnail.ingredient", "c2pa.ingredient.v3"]);
            if let (Some(alg), Value::Map(entries)) = (claim_alg, &mut claim) {
                entries.push((Value::Text("alg".into()), Value::Text(alg.into())));
            }
            run(&fixture, &claim)
        };

        // Inherited from the claim: matches, so nothing is reported.
        let results = inherited(None, Some("sha256"));
        assert!(results.failure.is_empty(), "{:?}", results.failure);
        // No `alg` anywhere: the structure is invalid, there is no default.
        let results = inherited(None, None);
        assert!(results.has_failure(ALGORITHM_UNSUPPORTED));
        // An algorithm outside the allowed list never passes silently.
        let results = inherited(Some("md5"), Some("sha256"));
        assert!(results.has_failure(ALGORITHM_UNSUPPORTED));
        assert!(!results.has_failure(HASHED_URI_MISMATCH));
    }

    /// Multi-instance labels resolve to their base schema entry, and a
    /// vendor assertion carrying a `{url, hash}` map is never walked.
    #[test]
    fn schema_lookup_handles_instances_and_ignores_vendor_assertions() {
        assert!(!ref_fields("c2pa.ingredient.v3__2").is_empty());
        assert!(ref_fields("c2pa.ingredient.v3__x").is_empty());
        assert!(ref_fields("com.example.thing").is_empty());

        let fixture = Fixture::new(&[(
            "com.example.thing",
            vmap(vec![("thumbnail", hashed_uri("c2pa.absent", vec![1; 32]))]),
        )]);
        let results = run(&fixture, &claim_for(&["com.example.thing"]));
        assert!(results.failure.is_empty(), "{:?}", results.failure);
    }

    /// 1.x-era generators wrote an action's `parameters.ingredient` digest
    /// before the assertion it names was final, so that reference routinely
    /// disagrees with an assertion the claim itself binds correctly (the
    /// c2pa-rs `legacy_ingredient_hash.jpg` fixture is exactly this). A v1
    /// claim is therefore held to the blanket reference rule only under the
    /// strict conformance posture, matching the existing v1 action-ingredient
    /// policy. A v2 claim is held to it in both postures.
    #[test]
    fn a_v1_claim_is_held_to_the_reference_rule_only_under_strict_conformance() {
        let ingredient = vmap(vec![("relationship", Value::Text("parentOf".into()))]);
        let actions = vmap(vec![(
            "actions",
            Value::Array(vec![vmap(vec![
                ("action", Value::Text("c2pa.opened".into())),
                (
                    "parameters",
                    vmap(vec![(
                        "ingredient",
                        hashed_uri("c2pa.ingredient", vec![0xEE; 32]),
                    )]),
                ),
            ])]),
        )]);
        let fixture = Fixture::new(&[("c2pa.ingredient", ingredient), ("c2pa.actions", actions)]);
        let claim = vmap(vec![(
            "assertions",
            Value::Array(
                ["c2pa.ingredient", "c2pa.actions"]
                    .iter()
                    .map(|label| {
                        vmap(vec![
                            (
                                "url",
                                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                            ),
                            ("hash", Value::Bytes(vec![0; 32])),
                        ])
                    })
                    .collect(),
            ),
        )]);

        let generous = run_as(
            &fixture,
            &claim,
            ClaimGeneration::V1,
            EngineProfile::GENEROUS,
        );
        assert!(generous.failure.is_empty(), "{:?}", generous.failure);

        let strict = run_as(
            &fixture,
            &claim,
            ClaimGeneration::V1,
            EngineProfile::CONFORMANCE_V2_2,
        );
        assert!(strict.has_failure(HASHED_URI_MISMATCH));
    }

    /// The whole point of the walk is that a consumer sees it. A manifest
    /// whose ingredient thumbnail reference has been retargeted must come back
    /// from the verification pipeline carrying `hashedURI.mismatch`, in the
    /// default (generous) posture.
    #[test]
    fn a_retargeted_nested_reference_reaches_the_verification_report() {
        use super::super::{
            verify_manifest, CawgTrustInputs, StoreContext, VerifyInput,
            MAX_REPORT_DECODED_VALUE_NODES,
        };
        use crate::c2pa_core::EngineProfile;
        use crate::c2pa_formats::AssetFormat;

        let thumb = vmap(vec![("data", Value::Bytes(vec![7; 16]))]);
        let fixture = Fixture::new(&[
            ("c2pa.thumbnail.ingredient", thumb),
            (
                "c2pa.ingredient.v3",
                vmap(vec![
                    ("relationship", Value::Text("parentOf".into())),
                    (
                        "thumbnail",
                        hashed_uri("c2pa.thumbnail.ingredient", vec![0xAB; 32]),
                    ),
                ]),
            ),
        ]);
        let claim = claim_for(&["c2pa.thumbnail.ingredient", "c2pa.ingredient.v3"]);
        let claim_cbor = enc(&claim);
        let mut manifest = fixture.manifest();
        manifest.claim_cbor = Some(&claim_cbor);
        manifest.claim_box_label = Some("c2pa.claim.v2".into());
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
            out.results.has_failure(HASHED_URI_MISMATCH),
            "{:?}",
            out.results.failure
        );
    }
}
