// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA 2.4 update-manifest shape and parent-chain handling.

use std::collections::{HashMap, HashSet};

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::jumbf::{AssertionContentType, ManifestKind, ParsedManifest};
use crate::c2pa_formats::DataHashExclusion;

const MAX_CHAIN_DEPTH: usize = 1_024;

/// Shape result for one update manifest.
pub(super) struct Inspection {
    pub wrong_parents: bool,
    pub invalid: bool,
    pub parent_label: Option<String>,
}

/// Why an update chain could not reach a standard manifest.
pub(super) enum ResolveError {
    WrongParents(String),
    Invalid(String),
    MissingParent(String),
    Cycle(String),
    TooDeep,
}

/// Whether the asset's C2PA Manifest Store is still the one the standard claim
/// signed its `c2pa.hash.data` exclusions against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreRendition {
    /// No update manifest stands between the claim and the asset.
    AsSigned,
    /// Update manifests were appended to the store after it was signed.
    WithUpdates,
}

/// Re-derive a signed data-hash exclusion plan for a store that update
/// manifests have grown.
///
/// C2PA 2.4, Validating a data hash: "If any update manifests were encountered
/// then the `length` value of the exclusion range whose `start` value is the
/// offset of the start of the entire C2PA Manifest Store shall be treated as
/// the current length of the entire C2PA Manifest Store plus any file format
/// specific extras. The difference between this new length and the length
/// specified in the exclusion represents an adjustment value ... the `start`
/// value of each subsequent exclusion range must be incremented by the
/// adjustment value."
///
/// `carrier` is the manifest-store span the container reports for the asset as
/// it stands now, which is exactly "the current length ... plus any file format
/// specific extras". An update manifest may not move the store, so the range to
/// re-size is the one starting at the carrier's offset; without such a range
/// there is nothing to adjust and the signed plan is returned unchanged.
///
/// Only the in-memory plan changes. The signed assertion bytes are untouched,
/// so the claim's hashed-URI binding over this assertion still verifies against
/// what the claim generator signed.
///
/// Returns `None` when the adjusted plan overflows, unsorts, or leaves the
/// asset; the caller reports that as `assertion.dataHash.mismatch`.
pub(super) fn adjust_exclusions_for_updates(
    signed: &[(usize, usize)],
    carrier: &[DataHashExclusion],
    asset_len: usize,
) -> Option<Vec<(usize, usize)>> {
    let Some((index, current_length)) =
        signed.iter().enumerate().find_map(|(index, (start, _))| {
            carrier
                .iter()
                .find(|span| span.start == *start)
                .map(|span| (index, span.length))
        })
    else {
        return Some(signed.to_vec());
    };

    let mut adjusted = signed.to_vec();
    let signed_length = adjusted[index].1;
    adjusted[index].1 = current_length;
    for (start, _) in adjusted.iter_mut().skip(index + 1) {
        *start = if current_length >= signed_length {
            start.checked_add(current_length - signed_length)?
        } else {
            start.checked_sub(signed_length - current_length)?
        };
    }

    let mut previous_end = 0usize;
    for (start, length) in &adjusted {
        if *start < previous_end {
            return None;
        }
        previous_end = start.checked_add(*length)?;
        if previous_end > asset_len {
            return None;
        }
    }
    Some(adjusted)
}

fn label_is(label: &str, base: &str) -> bool {
    label == base
        || label
            .strip_prefix(base)
            .and_then(|suffix| suffix.strip_prefix("__"))
            .and_then(|suffix| suffix.parse::<usize>().ok())
            .is_some_and(|instance| instance > 0)
}

fn is_ingredient(label: &str) -> bool {
    [
        "c2pa.ingredient",
        "c2pa.ingredient.v2",
        "c2pa.ingredient.v3",
    ]
    .iter()
    .any(|base| label_is(label, base))
}

fn is_forbidden_label(label: &str) -> bool {
    [
        "c2pa.hash.data",
        "c2pa.hash.boxes",
        "c2pa.hash.collection.data",
        "c2pa.hash.bmff.v2",
        "c2pa.hash.bmff.v3",
        "c2pa.hash.multi-asset",
    ]
    .iter()
    .any(|base| label_is(label, base))
        || label.starts_with("c2pa.thumbnail.")
}

fn local_manifest_label(reference: &Value, signature: bool) -> Option<String> {
    let url = reference.get("url")?.as_text()?;
    let rest = url.strip_prefix("self#jumbf=/c2pa/")?;
    let label = if signature {
        rest.strip_suffix("/c2pa.signature")?
    } else {
        rest
    };
    (!label.is_empty() && !label.contains('/')).then(|| label.to_string())
}

fn allowed_actions(value: &Value) -> bool {
    const ALLOWED: [&str; 4] = [
        "c2pa.edited.metadata",
        "c2pa.opened",
        "c2pa.published",
        "c2pa.redacted",
    ];
    let Some(Value::Array(actions)) = value.get("actions") else {
        return false;
    };
    !actions.is_empty()
        && actions.iter().all(|action| {
            action
                .get("action")
                .and_then(Value::as_text)
                .is_some_and(|name| ALLOWED.contains(&name))
        })
}

fn allowed_action_payload(manifest: &ParsedManifest<'_>, label: &str, payload: &[u8]) -> bool {
    const ALLOWED: [&str; 4] = [
        "c2pa.edited.metadata",
        "c2pa.opened",
        "c2pa.published",
        "c2pa.redacted",
    ];
    match manifest.assertion_content_type(label) {
        Some(AssertionContentType::Cbor) => {
            decode(payload).ok().as_ref().is_some_and(allowed_actions)
        }
        Some(AssertionContentType::Json) => serde_json::from_slice::<serde_json::Value>(payload)
            .ok()
            .is_some_and(|value| {
                value
                    .get("actions")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|actions| {
                        !actions.is_empty()
                            && actions.iter().all(|action| {
                                action
                                    .get("action")
                                    .and_then(serde_json::Value::as_str)
                                    .is_some_and(|name| ALLOWED.contains(&name))
                            })
                    })
            }),
        _ => false,
    }
}

/// Check the C2PA 2.4 shape of one update manifest.
pub(super) fn inspect<'a>(
    manifest: &ParsedManifest<'_>,
    declared_labels: impl IntoIterator<Item = &'a str>,
) -> Inspection {
    let payloads: HashMap<&str, &[u8]> = manifest
        .assertions
        .iter()
        .map(|(label, payload)| (label.as_str(), *payload))
        .collect();
    let mut parents = Vec::new();
    let mut invalid = false;

    for label in declared_labels {
        if is_forbidden_label(label) {
            invalid = true;
        }
        let Some(payload) = payloads.get(label).copied() else {
            continue;
        };
        let is_actions = label_is(label, "c2pa.actions") || label_is(label, "c2pa.actions.v2");
        if is_actions && !allowed_action_payload(manifest, label, payload) {
            invalid = true;
        }
        let Ok(value) = decode(payload) else {
            if is_ingredient(label) {
                invalid = true;
            }
            continue;
        };
        if !is_ingredient(label)
            || value.get("relationship").and_then(Value::as_text) != Some("parentOf")
        {
            continue;
        }

        let parent_label = if label_is(label, "c2pa.ingredient.v3") {
            let active = value
                .get("activeManifest")
                .and_then(|reference| local_manifest_label(reference, false));
            let signature = value
                .get("claimSignature")
                .and_then(|reference| local_manifest_label(reference, true));
            if active.is_none() || signature.as_deref() != active.as_deref() {
                invalid = true;
            }
            active
        } else {
            value
                .get("c2pa_manifest")
                .and_then(|reference| local_manifest_label(reference, false))
        };
        if parent_label.is_none() {
            invalid = true;
        }
        parents.push(parent_label);
    }

    // C2PA 2.4 Validation, Update Manifest Assertions: "Validate that exactly
    // one ingredient assertion is present and that its `relationship` is
    // `parentOf`." Counting only the `parentOf` ingredients would let a second
    // `componentOf` or `inputTo` ingredient ride along beside a good parent.
    let ingredients = manifest
        .assertions
        .iter()
        .filter(|(label, _)| is_ingredient(label))
        .count();
    let one_parent = ingredients == 1 && parents.len() == 1;

    Inspection {
        wrong_parents: !one_parent,
        invalid,
        parent_label: one_parent.then(|| parents.remove(0)).flatten(),
    }
}

fn declared_labels(manifest: &ParsedManifest<'_>) -> Option<HashSet<String>> {
    let claim = decode(manifest.claim_cbor?).ok()?;
    let mut labels = HashSet::new();
    for field in ["assertions", "created_assertions", "gathered_assertions"] {
        let Some(Value::Array(references)) = claim.get(field) else {
            continue;
        };
        for reference in references {
            let url = reference.get("url").and_then(Value::as_text)?;
            let label = url
                .strip_prefix("self#jumbf=c2pa.assertions/")
                .or_else(|| {
                    url.strip_prefix("self#jumbf=/c2pa/")
                        .and_then(|rest| rest.split_once("/c2pa.assertions/"))
                        .map(|(_, label)| label)
                })?;
            labels.insert(label.to_string());
        }
    }
    Some(labels)
}

pub(super) fn resolve_parent<'a>(
    update: &'a ParsedManifest<'a>,
    manifests: &'a [ParsedManifest<'a>],
) -> Result<&'a ParsedManifest<'a>, ResolveError> {
    let labels =
        declared_labels(update).ok_or_else(|| ResolveError::Invalid(update.label.clone()))?;
    let inspection = inspect(update, labels.iter().map(String::as_str));
    if inspection.wrong_parents {
        return Err(ResolveError::WrongParents(update.label.clone()));
    }
    if inspection.invalid {
        return Err(ResolveError::Invalid(update.label.clone()));
    }
    let parent = inspection
        .parent_label
        .ok_or_else(|| ResolveError::Invalid(update.label.clone()))?;
    manifests
        .iter()
        .find(|manifest| manifest.label == parent)
        .ok_or(ResolveError::MissingParent(parent))
}

/// Follow `parentOf` through update manifests to the first standard manifest.
pub(super) fn resolve_standard<'a>(
    active: &'a ParsedManifest<'a>,
    manifests: &'a [ParsedManifest<'a>],
) -> Result<&'a ParsedManifest<'a>, ResolveError> {
    let mut current = active;
    let mut visited = HashSet::new();
    for _ in 0..manifests.len().min(MAX_CHAIN_DEPTH).saturating_add(1) {
        if current.kind() == ManifestKind::Standard {
            return Ok(current);
        }
        if !visited.insert(current.label.as_str()) {
            return Err(ResolveError::Cycle(current.label.clone()));
        }
        current = resolve_parent(current, manifests)?;
    }
    Err(ResolveError::TooDeep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{encode, Profile, Value};
    use crate::c2pa_core::jumbf::{
        assertion_box, build_manifest, build_manifest_store, parse_manifest_store, superbox,
        superbox_content, UUID_UPDATE_MANIFEST,
    };
    use crate::c2pa_formats::AssetFormat;
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};

    fn enc(value: &Value) -> Vec<u8> {
        encode(value, Profile::LegacyPipelineBDefinite).expect("encode")
    }

    fn hashed_ref(manifest: &str, label: &str, payload: &[u8]) -> Value {
        let assertion = assertion_box(label, payload, None);
        Value::Map(vec![
            (
                Value::Text("url".into()),
                Value::Text(format!(
                    "self#jumbf=/c2pa/{manifest}/c2pa.assertions/{label}"
                )),
            ),
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (
                Value::Text("hash".into()),
                Value::Bytes(
                    Sha256::digest(superbox_content(&assertion).expect("assertion content"))
                        .to_vec(),
                ),
            ),
        ])
    }

    fn update_manifest(assertions: &[(String, Vec<u8>)]) -> Vec<u8> {
        let label = "urn:c2pa:00000000-0000-4000-8000-000000000002";
        let boxes: Vec<Vec<u8>> = assertions
            .iter()
            .map(|(name, payload)| assertion_box(name, payload, None))
            .collect();
        let claim = enc(&Value::Map(vec![
            (
                Value::Text("instanceID".into()),
                Value::Text("xmp:iid:update".into()),
            ),
            (
                Value::Text("claim_generator_info".into()),
                Value::Map(vec![(
                    Value::Text("name".into()),
                    Value::Text("fixture".into()),
                )]),
            ),
            (
                Value::Text("created_assertions".into()),
                Value::Array(
                    assertions
                        .iter()
                        .map(|(name, payload)| hashed_ref(label, name, payload))
                        .collect(),
                ),
            ),
            (
                Value::Text("signature".into()),
                Value::Text("self#jumbf=c2pa.signature".into()),
            ),
        ]));
        let standard = build_manifest(label, &boxes, &claim, &[0xd2, 0x84]);
        let parsed = crate::c2pa_core::jumbf::parse_superbox(&standard).unwrap();
        let children = parsed
            .content
            .iter()
            .map(|(kind, payload)| {
                let mut bytes = Vec::with_capacity(payload.len() + 8);
                bytes.extend_from_slice(&((payload.len() + 8) as u32).to_be_bytes());
                bytes.extend_from_slice(kind);
                bytes.extend_from_slice(payload);
                bytes
            })
            .collect::<Vec<_>>();
        superbox(&UUID_UPDATE_MANIFEST, label, &children, None)
    }

    fn parent(label: &str) -> (String, Vec<u8>) {
        (
            label.into(),
            enc(&Value::Map(vec![
                (
                    Value::Text("relationship".into()),
                    Value::Text("parentOf".into()),
                ),
                (
                    Value::Text("activeManifest".into()),
                    Value::Map(vec![(
                        Value::Text("url".into()),
                        Value::Text("self#jumbf=/c2pa/urn:c2pa:parent".into()),
                    )]),
                ),
                (
                    Value::Text("claimSignature".into()),
                    Value::Map(vec![(
                        Value::Text("url".into()),
                        Value::Text("self#jumbf=/c2pa/urn:c2pa:parent/c2pa.signature".into()),
                    )]),
                ),
            ])),
        )
    }

    /// A non-parent ingredient assertion: legal in a standard manifest, and
    /// the extra ingredient C2PA 2.4 forbids in an update manifest.
    fn component(label: &str) -> (String, Vec<u8>) {
        (
            label.into(),
            enc(&Value::Map(vec![
                (
                    Value::Text("relationship".into()),
                    Value::Text("componentOf".into()),
                ),
                (
                    Value::Text("activeManifest".into()),
                    Value::Map(vec![(
                        Value::Text("url".into()),
                        Value::Text("self#jumbf=/c2pa/urn:c2pa:other".into()),
                    )]),
                ),
                (
                    Value::Text("claimSignature".into()),
                    Value::Map(vec![(
                        Value::Text("url".into()),
                        Value::Text("self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature".into()),
                    )]),
                ),
            ])),
        )
    }

    fn structure_results(store: &[u8]) -> super::super::ValidationResults {
        let parsed = parse_manifest_store(store).expect("manifest store");
        let manifest = parsed.manifests.last().expect("active manifest");
        let claim = decode(manifest.claim_cbor.expect("claim")).expect("claim CBOR");
        let generation = super::super::versions::claim_generation(manifest, &claim);
        let refs = super::super::ClaimAssertionRefs::build(manifest, &claim, generation);
        let hashes = HashMap::new();
        let mut results = super::super::ValidationResults::default();
        super::super::verify_claim_structure(
            manifest,
            super::super::StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            generation,
            &refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/test/c2pa.signature",
            crate::c2pa_core::EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    fn standard_manifest_with_data_hash(digest: &[u8]) -> Vec<u8> {
        standard_manifest_with_exclusions(digest, &[])
    }

    fn standard_manifest_with_exclusions(digest: &[u8], exclusions: &[(usize, usize)]) -> Vec<u8> {
        let label = "urn:c2pa:parent";
        let mut fields = vec![
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (Value::Text("hash".into()), Value::Bytes(digest.to_vec())),
        ];
        if !exclusions.is_empty() {
            fields.push((
                Value::Text("exclusions".into()),
                Value::Array(
                    exclusions
                        .iter()
                        .map(|(start, length)| {
                            Value::Map(vec![
                                (Value::Text("start".into()), Value::Integer(*start as i128)),
                                (
                                    Value::Text("length".into()),
                                    Value::Integer(*length as i128),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        let data_hash = enc(&Value::Map(fields));
        let claim = enc(&Value::Map(vec![
            (
                Value::Text("instanceID".into()),
                Value::Text("xmp:iid:parent".into()),
            ),
            (
                Value::Text("claim_generator_info".into()),
                Value::Map(vec![(
                    Value::Text("name".into()),
                    Value::Text("fixture".into()),
                )]),
            ),
            (
                Value::Text("created_assertions".into()),
                Value::Array(vec![hashed_ref(label, "c2pa.hash.data", &data_hash)]),
            ),
            (
                Value::Text("signature".into()),
                Value::Text("self#jumbf=c2pa.signature".into()),
            ),
        ]));
        build_manifest(
            label,
            &[assertion_box("c2pa.hash.data", &data_hash, None)],
            &claim,
            &[0xd2, 0x84],
        )
    }

    #[test]
    fn structure_emits_registered_wrong_parents_status() {
        let assertions = vec![
            parent("c2pa.ingredient.v3"),
            parent("c2pa.ingredient.v3__1"),
        ];
        let store = build_manifest_store(&[update_manifest(&assertions)]);

        assert!(structure_results(&store).has_failure(super::super::MANIFEST_UPDATE_WRONG_PARENTS));
    }

    /// C2PA 2.4 Validation, Update Manifest Assertions: "Validate that exactly
    /// one ingredient assertion is present and that its `relationship` is
    /// `parentOf`." One good parent plus any second ingredient is rejected.
    #[test]
    fn extra_non_parent_ingredient_is_wrong_parents() {
        let assertions = vec![
            parent("c2pa.ingredient.v3"),
            component("c2pa.ingredient.v3__1"),
        ];
        let store = build_manifest_store(&[update_manifest(&assertions)]);

        assert!(structure_results(&store).has_failure(super::super::MANIFEST_UPDATE_WRONG_PARENTS));
    }
    #[test]
    fn structure_rejects_disallowed_update_action() {
        let mut assertions = vec![parent("c2pa.ingredient.v3")];
        assertions.push((
            "c2pa.actions.v2".into(),
            enc(&Value::Map(vec![(
                Value::Text("actions".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("action".into()),
                    Value::Text("c2pa.created".into()),
                )])]),
            )])),
        ));
        let store = build_manifest_store(&[update_manifest(&assertions)]);

        assert!(structure_results(&store).has_failure(super::super::MANIFEST_UPDATE_INVALID));
    }

    #[test]
    fn structure_emits_registered_invalid_status_for_forbidden_binding() {
        let mut assertions = vec![parent("c2pa.ingredient.v3")];
        assertions.push((
            "c2pa.hash.data".into(),
            enc(&Value::Map(vec![
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (Value::Text("hash".into()), Value::Bytes(vec![0; 32])),
            ])),
        ));
        let store = build_manifest_store(&[update_manifest(&assertions)]);

        assert!(structure_results(&store).has_failure(super::super::MANIFEST_UPDATE_INVALID));
    }

    #[test]
    fn update_inherits_first_standard_manifests_data_hash() {
        let asset_digest = Sha256::digest(b"historical asset bytes");
        let standard = standard_manifest_with_data_hash(&asset_digest);
        let update = update_manifest(&[parent("c2pa.ingredient.v3")]);
        let store_bytes = build_manifest_store(&[standard, update]);
        let parsed = parse_manifest_store(&store_bytes).expect("manifest store");
        let active = parsed.manifests.last().expect("update manifest");
        let hashes = HashMap::new();
        let mut results = super::super::ValidationResults::default();
        results.push_success(
            super::super::INGREDIENT_MANIFEST_VALIDATED,
            "self#jumbf=/c2pa/urn:c2pa:parent".into(),
            "parent manifest hash matched".into(),
        );

        super::super::verify_update_hard_binding(
            active,
            super::super::StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &[],
            AssetFormat::Jpeg,
            &[],
            Some(&asset_digest),
            crate::c2pa_core::EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(results.has_success(super::super::ASSERTION_HASHED_URI_MATCH));
        assert!(results.has_success(super::super::ASSERTION_DATA_HASH_MATCH));
        assert!(!results.has_failure(super::super::ASSERTION_DATA_HASH_MISMATCH));
    }

    #[test]
    fn two_parent_of_ingredients_are_wrong_parents() {
        let assertions = vec![
            parent("c2pa.ingredient.v3"),
            parent("c2pa.ingredient.v3__1"),
        ];
        let store = build_manifest_store(&[update_manifest(&assertions)]);
        let parsed = parse_manifest_store(&store).unwrap();
        let manifest = &parsed.manifests[0];
        let declared = assertions
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<HashSet<_>>();

        assert!(inspect(manifest, declared.iter().copied()).wrong_parents);
    }

    #[test]
    fn hard_binding_is_invalid_update_content() {
        let mut assertions = vec![parent("c2pa.ingredient.v3")];
        assertions.push((
            "c2pa.hash.data".into(),
            enc(&Value::Map(vec![
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (Value::Text("hash".into()), Value::Bytes(vec![0; 32])),
            ])),
        ));

        let store = build_manifest_store(&[update_manifest(&assertions)]);
        let parsed = parse_manifest_store(&store).unwrap();
        let manifest = &parsed.manifests[0];
        let declared = assertions
            .iter()
            .map(|(label, _)| label.as_str())
            .collect::<HashSet<_>>();

        assert!(inspect(manifest, declared.iter().copied()).invalid);
    }

    #[test]
    fn unauthenticated_parent_never_supplies_an_update_hard_binding() {
        let asset_digest = Sha256::digest(b"historical asset bytes");
        let standard = standard_manifest_with_data_hash(&asset_digest);
        let update = update_manifest(&[parent("c2pa.ingredient.v3")]);
        let store_bytes = build_manifest_store(&[standard, update]);
        let parsed = parse_manifest_store(&store_bytes).expect("manifest store");
        let active = parsed.manifests.last().expect("update manifest");
        let hashes = HashMap::new();
        let mut results = super::super::ValidationResults::default();

        super::super::verify_update_hard_binding(
            active,
            super::super::StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &[],
            AssetFormat::Jpeg,
            &[],
            Some(&asset_digest),
            crate::c2pa_core::EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(!results.has_success(super::super::ASSERTION_DATA_HASH_MATCH));
    }

    /// A JPEG carrying one metadata segment after the manifest insertion
    /// point, so an exclusion range sits *after* the C2PA Manifest Store and
    /// has to move when the store grows.
    fn jpeg_with_metadata_segment() -> Vec<u8> {
        let mut asset = vec![0xFF, 0xD8];
        asset.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        asset.extend_from_slice(b"JFIF\0");
        asset.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        asset.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x0B]);
        asset.extend_from_slice(b"EXCLUDEME");
        asset.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C]);
        asset.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]);
        asset.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        asset.extend_from_slice(&[0xFF, 0xD9]);
        asset
    }

    /// The metadata segment's byte span in an embedded asset.
    fn metadata_span(asset: &[u8]) -> (usize, usize) {
        let payload = asset
            .windows(9)
            .position(|window| window == b"EXCLUDEME")
            .expect("metadata segment");
        (payload - 4, 13)
    }

    /// Sign `base` the way a two-pass claim generator does: embed the store,
    /// read back the carrier span, hash the asset without the carrier or the
    /// metadata segment, then re-embed until the plan stops moving (the CBOR
    /// width of an offset can change the store's own length).
    fn signed_standard_jpeg(base: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut exclusions = vec![(20usize, 1024usize), (1044usize, 13usize)];
        let mut digest = vec![0u8; 32];
        for _ in 0..8 {
            let manifest = standard_manifest_with_exclusions(&digest, &exclusions);
            let store = build_manifest_store(&[manifest.clone()]);
            let asset = crate::c2pa_formats::embed_manifest(AssetFormat::Jpeg, base, &store)
                .expect("embed");
            let carrier =
                crate::c2pa_formats::compute_data_hash_exclusions(AssetFormat::Jpeg, &asset)
                    .expect("carrier span");
            assert_eq!(carrier.len(), 1, "one contiguous C2PA carrier");
            let plan = vec![(carrier[0].start, carrier[0].length), metadata_span(&asset)];
            let hash = super::super::hash_with_exclusions("sha256", &asset, &plan).expect("hash");
            if plan == exclusions && hash == digest {
                return (asset, manifest);
            }
            exclusions = plan;
            digest = hash;
        }
        panic!("two-pass signing did not converge");
    }

    /// C2PA 2.4, Validating a data hash: with update manifests present the
    /// store exclusion takes the store's current length and later exclusion
    /// starts move by the difference. Without that, appending a conforming
    /// update manifest breaks the parent's data hash.
    #[test]
    fn update_manifest_growth_keeps_the_parent_data_hash_valid() {
        let base = jpeg_with_metadata_segment();
        let (signed, standard) = signed_standard_jpeg(&base);
        let update = update_manifest(&[parent("c2pa.ingredient.v3")]);
        let updated_store = build_manifest_store(&[standard, update]);
        let updated = crate::c2pa_formats::embed_manifest(AssetFormat::Jpeg, &base, &updated_store)
            .expect("embed");
        assert!(
            updated.len() > signed.len(),
            "the update manifest must grow the store"
        );
        let parsed = parse_manifest_store(&updated_store).expect("manifest store");
        let active = parsed.manifests.last().expect("update manifest");
        let hashes = HashMap::new();
        let mut results = super::super::ValidationResults::default();
        results.push_success(
            super::super::INGREDIENT_MANIFEST_VALIDATED,
            "self#jumbf=/c2pa/urn:c2pa:parent".into(),
            "parent manifest hash matched".into(),
        );

        super::super::verify_update_hard_binding(
            active,
            super::super::StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &updated,
            AssetFormat::Jpeg,
            &[],
            None,
            crate::c2pa_core::EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(results.has_success(super::super::ASSERTION_DATA_HASH_MATCH));
        assert!(!results.has_failure(super::super::ASSERTION_DATA_HASH_MISMATCH));
    }

    /// The adjustment widens the manifest-store exclusion, never the hashed
    /// content: a byte changed outside the exclusions still fails.
    #[test]
    fn adjusted_exclusions_still_detect_tampering_outside_the_store() {
        let base = jpeg_with_metadata_segment();
        let (_, standard) = signed_standard_jpeg(&base);
        let update = update_manifest(&[parent("c2pa.ingredient.v3")]);
        let updated_store = build_manifest_store(&[standard, update]);
        let mut updated =
            crate::c2pa_formats::embed_manifest(AssetFormat::Jpeg, &base, &updated_store)
                .expect("embed");
        let tampered = updated.len() - 3;
        updated[tampered] ^= 0xFF;
        let parsed = parse_manifest_store(&updated_store).expect("manifest store");
        let active = parsed.manifests.last().expect("update manifest");
        let hashes = HashMap::new();
        let mut results = super::super::ValidationResults::default();
        results.push_success(
            super::super::INGREDIENT_MANIFEST_VALIDATED,
            "self#jumbf=/c2pa/urn:c2pa:parent".into(),
            "parent manifest hash matched".into(),
        );

        super::super::verify_update_hard_binding(
            active,
            super::super::StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &updated,
            AssetFormat::Jpeg,
            &[],
            None,
            crate::c2pa_core::EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(results.has_failure(super::super::ASSERTION_DATA_HASH_MISMATCH));
        assert!(!results.has_success(super::super::ASSERTION_DATA_HASH_MATCH));
    }

    #[test]
    fn exclusion_adjustment_shifts_only_ranges_after_the_store() {
        let carrier = [crate::c2pa_formats::DataHashExclusion {
            start: 20,
            length: 900,
        }];
        let signed = [(2usize, 4usize), (20, 500), (600, 10)];

        let adjusted = adjust_exclusions_for_updates(&signed, &carrier, 4096).expect("adjusted");

        assert_eq!(adjusted, [(2, 4), (20, 900), (1000, 10)]);
    }

    #[test]
    fn exclusion_adjustment_rejects_ranges_pushed_past_the_asset() {
        let carrier = [crate::c2pa_formats::DataHashExclusion {
            start: 20,
            length: 900,
        }];
        let signed = [(20usize, 500usize), (600, 10)];

        assert!(adjust_exclusions_for_updates(&signed, &carrier, 1005).is_none());
    }
}
