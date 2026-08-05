//! Spec-version classification of a parsed manifest — the version ladder.
//!
//! Given a parsed manifest and its decoded claim, [`evaluate`] determines, for
//! every [`SpecVersion`] the engine knows, whether the manifest's
//! validator-observable structure conforms to that revision's creation rules,
//! and picks the revision the manifest *validated under*:
//!
//! - the **declared** revision (`claim_generator_info.specVersion`) when it is
//!   among the conformant set, else
//! - the **highest** conformant revision, else `None`.
//!
//! The ladder is purely structural: claim generation (v1 vs v2), per-revision
//! required claim fields, and feature-introduction minimums for assertions and
//! embedding methods. Cryptographic verdicts (signature, hash bindings, trust)
//! are revision-invariant and are NOT re-evaluated per revision — the caller
//! clears `validated_under` when the overall validation state is `Invalid`.
//!
//! Feature-introduction data is grounded in the C2PA knowledge graph
//! (entity presence per spec version, KG tags v1.1.4–v1.2.4):
//!
//! | feature                          | introduced |
//! |----------------------------------|------------|
//! | claim v2 (`ClaimMapV2`)          | 2.0        |
//! | `c2pa.ingredient.v3`             | 2.1        |
//! | `c2pa.hash.collection.*`         | 2.1        |
//! | `c2pa.hash.multi-asset` (+parts) | 2.2        |
//! | text embedding (A.7/A.8/A.9)     | 2.4        |
//!
//! Claim v1 (`ClaimMap`) is *defined* in every revision through 2.4 (validators
//! must still read v1 stores), but a v1 claim is only *creatable* under 1.x —
//! so a v1-claim manifest conforms to the 1.x rule set alone.

use c2pa_cbor::Value;
use c2pa_core::jumbf::ParsedManifest;
use c2pa_core::SpecVersion;
use c2pa_formats::AssetFormat;
use serde_json::{json, Value as Json};

/// Claim generation: the 1.x claim v1 shape vs the 2.x claim v2 shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimGeneration {
    /// `c2pa.claim` box; `claim_generator` string, `assertions` array,
    /// `dc:format`.
    V1,
    /// `c2pa.claim.v2` box; `claim_generator_info`, `created_assertions` /
    /// `gathered_assertions`.
    V2,
}

impl ClaimGeneration {
    /// Numeric form for reports.
    pub fn as_u8(self) -> u8 {
        match self {
            ClaimGeneration::V1 => 1,
            ClaimGeneration::V2 => 2,
        }
    }
}

/// Detect the claim generation. The claim box label is authoritative
/// (`c2pa.claim` vs `c2pa.claim.v2`); claim field shape is the fallback for
/// stores with a deviant label. Unrecognizable claims default to V2 (the
/// stricter, current generation).
pub fn claim_generation(manifest: &ParsedManifest, claim: &Value) -> ClaimGeneration {
    match manifest.claim_box_label.as_deref() {
        Some("c2pa.claim.v2") => return ClaimGeneration::V2,
        Some("c2pa.claim") => return ClaimGeneration::V1,
        _ => {}
    }
    if claim.get("created_assertions").is_some() || claim.get("gathered_assertions").is_some() {
        ClaimGeneration::V2
    } else if claim.get("assertions").is_some() || claim.get("claim_generator").is_some() {
        ClaimGeneration::V1
    } else {
        ClaimGeneration::V2
    }
}

/// The spec version the generator declared, from
/// `claim_generator_info.specVersion`. Handles both shapes: a single map (the
/// v2 claim) and an array of maps (the v1 claim).
pub fn declared_spec_version(claim: &Value) -> Option<String> {
    let info = claim.get("claim_generator_info")?;
    let entry = match info {
        Value::Array(items) => items.first()?,
        other => other,
    };
    entry
        .get("specVersion")
        .and_then(Value::as_text)
        .map(str::to_string)
}

/// Required claim-v1 fields absent from `claim` (empty = well-formed v1).
pub fn v1_missing_fields(claim: &Value) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if claim.get("instanceID").and_then(Value::as_text).is_none() {
        missing.push("instanceID");
    }
    if claim
        .get("claim_generator")
        .and_then(Value::as_text)
        .is_none()
    {
        missing.push("claim_generator");
    }
    if claim.get("dc:format").and_then(Value::as_text).is_none() {
        missing.push("dc:format");
    }
    if !matches!(claim.get("assertions"), Some(Value::Array(a)) if !a.is_empty()) {
        missing.push("assertions");
    }
    missing
}

/// Required claim-v2 fields absent from `claim` (empty = well-formed v2).
pub fn v2_missing_fields(claim: &Value) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if claim.get("instanceID").and_then(Value::as_text).is_none() {
        missing.push("instanceID");
    }
    if !matches!(claim.get("created_assertions"), Some(Value::Array(a)) if !a.is_empty()) {
        missing.push("created_assertions");
    }
    missing
}

/// The earliest spec revision that defines assertion `label`. `None` when the
/// label is defined across every revision the engine knows (or is external to
/// the C2PA spec, e.g. `cawg.*`, vendor assertions).
fn assertion_min_version(label: &str) -> Option<SpecVersion> {
    if label.starts_with("c2pa.hash.multi-asset") || label.starts_with("c2pa.hash.data.part") {
        Some(SpecVersion::V2_2)
    } else if label.starts_with("c2pa.ingredient.v3") || label.starts_with("c2pa.hash.collection") {
        Some(SpecVersion::V2_1)
    } else {
        None
    }
}

/// The earliest spec revision whose embedding annex covers `format`.
fn format_min_version(format: AssetFormat) -> Option<SpecVersion> {
    match format {
        AssetFormat::Ogg
        | AssetFormat::TextUnstructured
        | AssetFormat::TextStructured { .. }
        | AssetFormat::TextHtml => Some(SpecVersion::V2_4),
        _ => None,
    }
}

/// The earliest spec revision that DEPRECATES assertion `label` (the assertion
/// remains defined and conforming; usage is discouraged). Grounded in the KG's
/// structured `deprecated` flags: only ingredient v1/v2 are deprecated, as of
/// 2.4. No assertion has ever been *removed* across 1.4–2.4 (verified against
/// KG entity sets), so deprecation is informational and never gates
/// conformance.
fn assertion_deprecated_in(label: &str) -> Option<SpecVersion> {
    // Exact base or a multi-instance suffix (`c2pa.ingredient__1`); the bare
    // prefix test would wrongly match `c2pa.ingredient.v3`.
    let is = |base: &str| label == base || label.starts_with(&format!("{base}__"));
    if is("c2pa.ingredient") || is("c2pa.ingredient.v2") {
        Some(SpecVersion::V2_4)
    } else {
        None
    }
}

/// One rung of the ladder: a revision and whether the manifest's structure
/// conforms to it.
#[derive(Debug, Clone)]
pub struct VersionEvaluation {
    /// The spec revision evaluated.
    pub version: SpecVersion,
    /// Whether the manifest's validator-observable structure conforms to this
    /// revision's creation rules.
    pub structure_conformant: bool,
    /// Why it does not conform (empty when conformant).
    pub reasons: Vec<String>,
    /// Assertions deprecated as of this revision (still conforming; flagged
    /// for internal analysis). Empty when none.
    pub deprecations: Vec<String>,
}

/// The version ladder's verdict for one manifest.
#[derive(Debug, Clone)]
pub struct VersionVerdict {
    /// Detected claim generation (1 = claim v1, 2 = claim v2).
    pub claim_generation: ClaimGeneration,
    /// `claim_generator_info.specVersion` as declared by the generator, if any.
    pub declared_spec_version: Option<String>,
    /// The revision the manifest validated under: the declared revision when
    /// structurally conformant to it, else the highest conformant revision.
    /// `None` when no revision fits — or when overall validation failed (the
    /// caller clears it: a cryptographically broken manifest verified under
    /// nothing).
    pub validated_under: Option<SpecVersion>,
    /// Every revision evaluated, ascending.
    pub evaluations: Vec<VersionEvaluation>,
}

impl VersionVerdict {
    /// Render as report JSON (`version_verdict` object).
    pub fn to_json(&self) -> Json {
        json!({
            "claim_generation": self.claim_generation.as_u8(),
            "declared_spec_version": self.declared_spec_version,
            "validated_under": self.validated_under.map(SpecVersion::version_str),
            "evaluations": self.evaluations.iter().map(|e| {
                json!({
                    "version": e.version.version_str(),
                    "structure_conformant": e.structure_conformant,
                    "reasons": e.reasons,
                    "deprecations": e.deprecations,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Run the version ladder over a parsed manifest and its decoded claim.
pub fn evaluate(manifest: &ParsedManifest, claim: &Value, format: AssetFormat) -> VersionVerdict {
    let generation = claim_generation(manifest, claim);
    let declared = declared_spec_version(claim);

    // Generation-specific required-field defects (apply to every revision of
    // that generation).
    let field_defects: Vec<String> = match generation {
        ClaimGeneration::V1 => v1_missing_fields(claim)
            .iter()
            .map(|f| format!("claim missing required v1 field: {f}"))
            .collect(),
        ClaimGeneration::V2 => v2_missing_fields(claim)
            .iter()
            .map(|f| format!("claim missing required v2 field: {f}"))
            .collect(),
    };

    // Feature-introduction minimums observed in this manifest.
    let mut minimums: Vec<(SpecVersion, String)> = Vec::new();
    for (label, _) in &manifest.assertions {
        if let Some(min) = assertion_min_version(label) {
            minimums.push((
                min,
                format!("assertion '{label}' requires >= {}", min.version_str()),
            ));
        }
    }
    if let Some(min) = format_min_version(format) {
        minimums.push((
            min,
            format!(
                "text embedding (A.7/A.8/A.9) requires >= {}",
                min.version_str()
            ),
        ));
    }

    // Deprecation notes observed in this manifest (informational; never gate).
    let mut deprecated: Vec<(SpecVersion, String)> = Vec::new();
    for (label, _) in &manifest.assertions {
        if let Some(since) = assertion_deprecated_in(label) {
            deprecated.push((
                since,
                format!(
                    "assertion '{label}' is deprecated as of {}",
                    since.version_str()
                ),
            ));
        }
    }

    let evaluations: Vec<VersionEvaluation> = SpecVersion::ALL
        .iter()
        .map(|&version| {
            let mut reasons: Vec<String> = Vec::new();
            match (generation, version) {
                (ClaimGeneration::V1, v) if v >= SpecVersion::V2_0 => {
                    reasons.push("claim is v1 (c2pa.claim); 2.x manifests require claim v2".into());
                }
                (ClaimGeneration::V2, v) if v < SpecVersion::V2_0 => {
                    reasons.push("claim is v2 (c2pa.claim.v2); introduced in 2.0".into());
                }
                _ => {}
            }
            reasons.extend(field_defects.iter().cloned());
            for (min, why) in &minimums {
                if version < *min {
                    reasons.push(why.clone());
                }
            }
            let deprecations: Vec<String> = deprecated
                .iter()
                .filter(|(since, _)| version >= *since)
                .map(|(_, note)| note.clone())
                .collect();
            VersionEvaluation {
                version,
                structure_conformant: reasons.is_empty(),
                reasons,
                deprecations,
            }
        })
        .collect();

    let declared_version = declared.as_deref().and_then(SpecVersion::from_str);
    let passes = |v: SpecVersion| {
        evaluations
            .iter()
            .any(|e| e.version == v && e.structure_conformant)
    };
    let validated_under = match declared_version {
        Some(dv) if passes(dv) => Some(dv),
        _ => evaluations
            .iter()
            .rev()
            .find(|e| e.structure_conformant)
            .map(|e| e.version),
    };

    VersionVerdict {
        claim_generation: generation,
        declared_spec_version: declared,
        validated_under,
        evaluations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_cbor::map_from_pairs;

    fn manifest_with_label(label: Option<&str>) -> ParsedManifest<'static> {
        ParsedManifest {
            label: "urn:c2pa:test".into(),
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: label.map(str::to_string),
        }
    }

    fn v2_claim() -> Value {
        map_from_pairs([
            ("instanceID".to_string(), Value::Text("urn:uuid:x".into())),
            (
                "created_assertions".to_string(),
                Value::Array(vec![map_from_pairs([(
                    "url".to_string(),
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                )])]),
            ),
            (
                "claim_generator_info".to_string(),
                map_from_pairs([
                    ("name".to_string(), Value::Text("t".into())),
                    ("specVersion".to_string(), Value::Text("2.2".into())),
                ]),
            ),
        ])
    }

    fn v1_claim() -> Value {
        map_from_pairs([
            ("instanceID".to_string(), Value::Text("xmp:iid:x".into())),
            (
                "claim_generator".to_string(),
                Value::Text("legacy/1.0".into()),
            ),
            ("dc:format".to_string(), Value::Text("image/jpeg".into())),
            (
                "assertions".to_string(),
                Value::Array(vec![map_from_pairs([(
                    "url".to_string(),
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                )])]),
            ),
        ])
    }

    #[test]
    fn detects_generation_from_box_label() {
        let m1 = manifest_with_label(Some("c2pa.claim"));
        let m2 = manifest_with_label(Some("c2pa.claim.v2"));
        // Label wins even against a contradictory field shape.
        assert_eq!(claim_generation(&m1, &v2_claim()), ClaimGeneration::V1);
        assert_eq!(claim_generation(&m2, &v1_claim()), ClaimGeneration::V2);
    }

    #[test]
    fn detects_generation_from_field_shape_without_label() {
        let m = manifest_with_label(None);
        assert_eq!(claim_generation(&m, &v1_claim()), ClaimGeneration::V1);
        assert_eq!(claim_generation(&m, &v2_claim()), ClaimGeneration::V2);
    }

    #[test]
    fn v1_claim_validates_under_1x_only() {
        let m = manifest_with_label(Some("c2pa.claim"));
        let v = evaluate(&m, &v1_claim(), AssetFormat::Jpeg);
        assert_eq!(v.claim_generation, ClaimGeneration::V1);
        assert_eq!(v.validated_under, Some(SpecVersion::V1_4));
        for e in &v.evaluations {
            assert_eq!(
                e.structure_conformant,
                e.version == SpecVersion::V1_4,
                "version {}",
                e.version.version_str()
            );
        }
    }

    #[test]
    fn v2_claim_prefers_declared_version() {
        let m = manifest_with_label(Some("c2pa.claim.v2"));
        let v = evaluate(&m, &v2_claim(), AssetFormat::Jpeg);
        assert_eq!(v.declared_spec_version.as_deref(), Some("2.2"));
        // Declared 2.2 is conformant, so it wins over the highest (2.4).
        assert_eq!(v.validated_under, Some(SpecVersion::V2_2));
        // 1.4 must fail (claim v2 didn't exist); 2.0..2.4 pass.
        let v14 = v
            .evaluations
            .iter()
            .find(|e| e.version == SpecVersion::V1_4)
            .unwrap();
        assert!(!v14.structure_conformant);
        assert!(
            v.evaluations
                .iter()
                .filter(|e| e.structure_conformant)
                .count()
                == 5
        );
    }

    #[test]
    fn multi_asset_assertion_raises_minimum_to_2_2() {
        let mut m = manifest_with_label(Some("c2pa.claim.v2"));
        m.assertions
            .push(("c2pa.hash.multi-asset".to_string(), &[0xa0][..]));
        let mut claim = v2_claim();
        // Declare a version BELOW the feature minimum: declared must lose.
        if let Value::Map(pairs) = &mut claim {
            for (k, val) in pairs.iter_mut() {
                if matches!(k, Value::Text(t) if t == "claim_generator_info") {
                    *val = map_from_pairs([
                        ("name".to_string(), Value::Text("t".into())),
                        ("specVersion".to_string(), Value::Text("2.0".into())),
                    ]);
                }
            }
        }
        let v = evaluate(&m, &claim, AssetFormat::Jpeg);
        for e in &v.evaluations {
            assert_eq!(e.structure_conformant, e.version >= SpecVersion::V2_2);
        }
        // Declared 2.0 is non-conformant -> highest conformant (2.4) wins.
        assert_eq!(v.validated_under, Some(SpecVersion::V2_4));
    }

    #[test]
    fn text_format_requires_2_4() {
        let m = manifest_with_label(Some("c2pa.claim.v2"));
        let v = evaluate(&m, &v2_claim(), AssetFormat::TextUnstructured);
        for e in &v.evaluations {
            assert_eq!(e.structure_conformant, e.version == SpecVersion::V2_4);
        }
        assert_eq!(v.validated_under, Some(SpecVersion::V2_4));
    }

    #[test]
    fn malformed_v2_claim_fits_nothing() {
        let m = manifest_with_label(Some("c2pa.claim.v2"));
        let claim = map_from_pairs([("instanceID".to_string(), Value::Text("urn:uuid:x".into()))]);
        let v = evaluate(&m, &claim, AssetFormat::Jpeg);
        assert_eq!(v.validated_under, None);
        assert!(v.evaluations.iter().all(|e| !e.structure_conformant));
    }

    #[test]
    fn deprecated_ingredient_v2_is_flagged_but_conformant() {
        let mut m = manifest_with_label(Some("c2pa.claim.v2"));
        m.assertions
            .push(("c2pa.ingredient.v2".to_string(), &[0xa0][..]));
        let v = evaluate(&m, &v2_claim(), AssetFormat::Jpeg);
        for e in &v.evaluations {
            // Deprecation never gates conformance.
            assert_eq!(e.structure_conformant, e.version >= SpecVersion::V2_0);
            assert_eq!(
                !e.deprecations.is_empty(),
                e.version >= SpecVersion::V2_4,
                "deprecation note wrong at {}",
                e.version.version_str()
            );
        }
        // ingredient.v3 must NOT be flagged (prefix trap: `.v3` is current).
        let mut m3 = manifest_with_label(Some("c2pa.claim.v2"));
        m3.assertions
            .push(("c2pa.ingredient.v3".to_string(), &[0xa0][..]));
        let v3 = evaluate(&m3, &v2_claim(), AssetFormat::Jpeg);
        assert!(v3.evaluations.iter().all(|e| e.deprecations.is_empty()));
    }
}
