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

use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_core::SpecVersion;
use crate::c2pa_formats::AssetFormat;
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

fn optional_text_member_is_valid(map: &Value, key: &str) -> bool {
    map.get(key).is_none() || map.get(key).and_then(Value::as_text).is_some()
}

fn hashed_uri_map_is_valid(value: &Value) -> bool {
    matches!(value, Value::Map(_))
        && value
            .get("url")
            .and_then(Value::as_text)
            .is_some_and(|url| !url.is_empty())
        && value
            .get("hash")
            .and_then(Value::as_bytes)
            .is_some_and(|hash| !hash.is_empty())
        && optional_text_member_is_valid(value, "alg")
}

fn generator_info_map_is_valid(value: &Value) -> bool {
    matches!(value, Value::Map(_))
        && value
            .get("name")
            .and_then(Value::as_text)
            .is_some_and(|name| !name.is_empty())
        && optional_text_member_is_valid(value, "version")
        && optional_text_member_is_valid(value, "operating_system")
        && optional_text_member_is_valid(value, "specVersion")
        && value.get("icon").is_none_or(hashed_uri_map_is_valid)
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
    if !matches!(
        claim.get("claim_generator_info"),
        Some(Value::Array(entries))
            if !entries.is_empty() && entries.iter().all(generator_info_map_is_valid)
    ) {
        missing.push("claim_generator_info");
    }
    missing
}

/// Required claim-v2 fields absent or malformed in `claim` (empty =
/// well-formed v2).
///
/// Unlike claim v1, claim v2 encodes `claim_generator_info` as one
/// `GeneratorInfoMap`. Every present member is checked against its schema,
/// including the required non-empty text `name` and optional hashed-URI icon.
pub fn v2_missing_fields(claim: &Value) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if claim.get("instanceID").and_then(Value::as_text).is_none() {
        missing.push("instanceID");
    }
    if !claim
        .get("claim_generator_info")
        .is_some_and(generator_info_map_is_valid)
    {
        missing.push("claim_generator_info");
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
    use crate::c2pa_cbor::{map_from_pairs, Profile};
    use crate::c2pa_core::claim::{
        build_claim_value, AssertionRef, ClaimGeneratorInfo, ClaimOptions, HASH_ALG_SHA256,
    };

    fn manifest_with_label(label: Option<&str>) -> ParsedManifest<'static> {
        ParsedManifest {
            label: "urn:c2pa:test".into(),
            manifest_jumbf: &[],
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
                "claim_generator_info".to_string(),
                Value::Array(vec![map_from_pairs([(
                    "name".to_string(),
                    Value::Text("legacy".into()),
                )])]),
            ),
            (
                "assertions".to_string(),
                Value::Array(vec![map_from_pairs([(
                    "url".to_string(),
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                )])]),
            ),
        ])
    }

    fn v2_claim_with_generator_info(info: Option<Value>) -> Value {
        let mut fields = vec![
            ("instanceID".to_string(), Value::Text("urn:uuid:x".into())),
            (
                "created_assertions".to_string(),
                Value::Array(vec![map_from_pairs([(
                    "url".to_string(),
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                )])]),
            ),
        ];
        if let Some(info) = info {
            fields.push(("claim_generator_info".to_string(), info));
        }
        map_from_pairs(fields)
    }

    #[test]
    fn canonical_builder_output_has_valid_v2_generator_info() {
        let generator = ClaimGeneratorInfo {
            name: "Encypher Engine".into(),
            version: "1.0".into(),
            spec_version: Some("2.4".into()),
            c2pa_rs: None,
        };
        let options = ClaimOptions {
            manifest_label: "urn:c2pa:test",
            instance_id: "urn:uuid:test",
            generator: &generator,
            title: None,
            alg: HASH_ALG_SHA256,
            profile: Profile::LegacyPipelineBDefinite,
        };
        let claim = build_claim_value(
            &options,
            &[AssertionRef {
                label: "c2pa.hash.data",
                jumbf_content: b"assertion",
            }],
        );

        assert!(v2_missing_fields(&claim).is_empty());
    }

    #[test]
    fn v1_generator_info_requires_non_empty_array_of_named_maps() {
        let valid = Value::Array(vec![
            map_from_pairs([("name".to_string(), Value::Text("first".into()))]),
            map_from_pairs([
                ("name".to_string(), Value::Text("second".into())),
                ("version".to_string(), Value::Text("1.0".into())),
            ]),
        ]);
        let malformed = [
            ("absent", None),
            ("empty array", Some(Value::Array(Vec::new()))),
            ("wrong outer type", Some(Value::Map(Vec::new()))),
            (
                "non-map entry",
                Some(Value::Array(vec![Value::Text("generator".into())])),
            ),
            (
                "missing name",
                Some(Value::Array(vec![map_from_pairs([(
                    "version".to_string(),
                    Value::Text("1.0".into()),
                )])])),
            ),
            (
                "empty name",
                Some(Value::Array(vec![map_from_pairs([(
                    "name".to_string(),
                    Value::Text(String::new()),
                )])])),
            ),
            (
                "one malformed entry",
                Some(Value::Array(vec![
                    map_from_pairs([("name".to_string(), Value::Text("valid".into()))]),
                    map_from_pairs([("name".to_string(), Value::Integer(1.into()))]),
                ])),
            ),
        ];

        let mut valid_claim = v1_claim();
        if let Value::Map(entries) = &mut valid_claim {
            let generator_info = entries
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some("claim_generator_info"))
                .expect("fixture has generator info");
            generator_info.1 = valid;
        }
        assert!(v1_missing_fields(&valid_claim).is_empty());

        for (case, info) in malformed {
            let mut claim = v1_claim();
            if let Value::Map(entries) = &mut claim {
                entries.retain(|(key, _)| key.as_text() != Some("claim_generator_info"));
                if let Some(info) = info {
                    entries.push((Value::Text("claim_generator_info".into()), info));
                }
            }
            assert!(
                v1_missing_fields(&claim).contains(&"claim_generator_info"),
                "{case}"
            );
        }
    }

    #[test]
    fn generator_info_optional_members_follow_schema() {
        let valid_icon = map_from_pairs([
            (
                "url".to_string(),
                Value::Text("self#jumbf=c2pa.assertions/c2pa.thumbnail.claim.jpeg".into()),
            ),
            ("alg".to_string(), Value::Text("sha256".into())),
            ("hash".to_string(), Value::Bytes(vec![7; 32])),
        ]);
        let valid = map_from_pairs([
            ("name".to_string(), Value::Text("generator".into())),
            ("version".to_string(), Value::Text("1.0".into())),
            (
                "operating_system".to_string(),
                Value::Text("Example OS".into()),
            ),
            ("specVersion".to_string(), Value::Text("2.4".into())),
            ("icon".to_string(), valid_icon),
        ]);
        assert!(v2_missing_fields(&v2_claim_with_generator_info(Some(valid))).is_empty());

        let malformed_icons = [
            ("wrong icon type", Value::Text("icon".into())),
            (
                "missing icon url",
                map_from_pairs([("hash".to_string(), Value::Bytes(vec![7; 32]))]),
            ),
            (
                "missing icon hash",
                map_from_pairs([(
                    "url".to_string(),
                    Value::Text("self#jumbf=c2pa.assertions/icon".into()),
                )]),
            ),
        ];
        for (case, icon) in malformed_icons {
            let info = map_from_pairs([
                ("name".to_string(), Value::Text("generator".into())),
                ("icon".to_string(), icon),
            ]);
            assert_eq!(
                v2_missing_fields(&v2_claim_with_generator_info(Some(info))),
                vec!["claim_generator_info"],
                "{case}"
            );
        }

        for key in ["version", "operating_system", "specVersion"] {
            let info = map_from_pairs([
                ("name".to_string(), Value::Text("generator".into())),
                (key.to_string(), Value::Integer(1.into())),
            ]);
            assert_eq!(
                v2_missing_fields(&v2_claim_with_generator_info(Some(info))),
                vec!["claim_generator_info"],
                "{key}"
            );
        }
    }

    #[test]
    fn malformed_v2_generator_info_is_required_field_failure() {
        let malformed = [
            ("absent", None),
            ("wrong outer type", Some(Value::Text("generator".into()))),
            ("empty value", Some(Value::Map(Vec::new()))),
            ("empty array", Some(Value::Array(Vec::new()))),
            (
                "legacy array-of-maps shape",
                Some(Value::Array(vec![map_from_pairs([(
                    "name".to_string(),
                    Value::Text("generator".into()),
                )])])),
            ),
            (
                "non-map array entry",
                Some(Value::Array(vec![Value::Text("generator".into())])),
            ),
            (
                "missing name",
                Some(map_from_pairs([(
                    "version".to_string(),
                    Value::Text("1.0".into()),
                )])),
            ),
            (
                "non-text name",
                Some(map_from_pairs([(
                    "name".to_string(),
                    Value::Integer(1.into()),
                )])),
            ),
        ];

        for (case, info) in malformed {
            assert_eq!(
                v2_missing_fields(&v2_claim_with_generator_info(info)),
                vec!["claim_generator_info"],
                "{case}"
            );
        }
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
