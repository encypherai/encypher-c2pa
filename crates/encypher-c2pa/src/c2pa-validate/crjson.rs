//! Content Credentials JSON (crJSON) rendering of a C2PA manifest store.
//!
//! The conformance-program shape uses a `manifests` array. Each entry exposes
//! assertions as a label-keyed object, the decoded `claim.v2`, and, when a
//! validation report is available, `validationResults`.

use crate::c2pa_cbor::decode;
use crate::c2pa_core::jumbf::ParsedStore;
use crate::c2pa_validate::report::cbor_to_json;
use serde_json::{json, Map, Value as Json};

/// Render the Content Credentials JSON for a signed asset's embedded manifest
/// store, given its bytes and MIME type. Returns `None` when the asset carries
/// no manifest or cannot be parsed. This is the diagnostics side-output the
/// engine emits in strict-debug mode on the **sign** path (after signing) and is
/// also usable standalone.
pub fn crjson_from_asset(mime: &str, data: &[u8]) -> Option<Json> {
    let format = crate::c2pa_formats::AssetFormat::from_mime(mime)?;
    let store_bytes = crate::c2pa_formats::extract_manifest(format, data).ok()??;
    let store = crate::c2pa_core::jumbf::parse_manifest_store(&store_bytes).ok()?;
    Some(to_crjson(&store))
}

/// Render a parsed manifest store as Content Credentials JSON.
///
/// The active manifest is the last in store order (the C2PA rule). Each
/// manifest's claim fields and assertions are decoded from CBOR. Manifests with
/// an undecodable claim still appear with whatever assertions decode, so the
/// view is useful even for partially-malformed stores.
pub fn to_crjson(store: &ParsedStore) -> Json {
    render_crjson(store, None)
}

/// Render conformance-ready crJSON and attach the verifier's active-manifest
/// validation results.
pub(crate) fn to_crjson_with_report(store: &ParsedStore, report: &Json) -> Json {
    render_crjson(store, Some(report))
}

fn render_crjson(store: &ParsedStore, report: Option<&Json>) -> Json {
    let active_label = store
        .manifests
        .last()
        .map(|manifest| manifest.label.as_str());
    let active_results = report
        .and_then(|value| value.get("validation_results"))
        .and_then(|value| value.get("activeManifest"));
    let mut manifests = Vec::with_capacity(store.manifests.len());

    for manifest in &store.manifests {
        let claim = manifest.claim_cbor.and_then(|bytes| decode(bytes).ok());
        let mut claim_json = claim
            .as_ref()
            .map(cbor_to_json)
            .unwrap_or_else(|| json!({}));
        // crJSON flattens the claim's generator-info array to its first map.
        // The C2PA claim itself retains the normative array representation.
        if let Some(first) = claim_json
            .get("claim_generator_info")
            .and_then(Json::as_array)
            .and_then(|items| items.first())
            .cloned()
        {
            claim_json["claim_generator_info"] = first;
        }

        let mut assertions = Map::new();
        for (label, cbor) in &manifest.assertions {
            let data = decode(cbor)
                .map(|value| cbor_to_json(&value))
                .unwrap_or_else(|_| json!({}));
            assertions.insert(label.clone(), data);
        }

        let mut entry = Map::new();
        entry.insert("label".into(), Json::String(manifest.label.clone()));
        entry.insert("assertions".into(), Json::Object(assertions));
        entry.insert("claim.v2".into(), claim_json);
        if active_label == Some(manifest.label.as_str()) {
            if let Some(results) = active_results {
                entry.insert("validationResults".into(), results.clone());
            }
        }
        manifests.push(Json::Object(entry));
    }

    json!({
        "@context": {
            "@vocab": "https://contentcredentials.org/crjson",
            "extras": "https://contentcredentials.org/crjson/extras"
        },
        "manifests": manifests,
        "jsonGenerator": {
            "name": "Encypher Engine",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{map_from_pairs, Profile, Value};
    use crate::c2pa_core::jumbf::{
        assertion_box, build_manifest, build_manifest_store, parse_manifest_store,
    };

    /// Build a one-manifest store with a claim + a single actions assertion.
    fn store_bytes() -> Vec<u8> {
        let claim = map_from_pairs([
            ("dc:format".into(), Value::Text("image/jpeg".into())),
            ("dc:title".into(), Value::Text("photo.jpg".into())),
            ("instanceID".into(), Value::Text("urn:uuid:abc".into())),
            (
                "claim_generator_info".into(),
                Value::Array(vec![map_from_pairs([
                    ("name".into(), Value::Text("Encypher Engine".into())),
                    ("version".into(), Value::Text("1.0".into())),
                ])]),
            ),
        ]);
        let claim_cbor =
            crate::c2pa_cbor::encode(&claim, Profile::LegacyPipelineBDefinite).unwrap();
        let actions = map_from_pairs([(
            "actions".into(),
            Value::Array(vec![map_from_pairs([(
                "action".into(),
                Value::Text("c2pa.created".into()),
            )])]),
        )]);
        let actions_cbor =
            crate::c2pa_cbor::encode(&actions, Profile::LegacyPipelineBDefinite).unwrap();
        let abox = assertion_box("c2pa.actions.v2", &actions_cbor, None);
        let manifest = build_manifest("urn:c2pa:test:1", &[abox], &claim_cbor, &[0xd2, 0x84]);
        build_manifest_store(&[manifest])
    }

    #[test]
    fn renders_content_credentials_json() {
        let bytes = store_bytes();
        let store = parse_manifest_store(&bytes).unwrap();
        let cr = to_crjson(&store);

        let m = &cr["manifests"][0];
        assert_eq!(m["label"], "urn:c2pa:test:1");
        assert_eq!(m["claim.v2"]["dc:format"], "image/jpeg");
        assert_eq!(m["claim.v2"]["dc:title"], "photo.jpg");
        assert_eq!(m["claim.v2"]["instanceID"], "urn:uuid:abc");
        assert_eq!(
            m["claim.v2"]["claim_generator_info"]["name"],
            "Encypher Engine"
        );
        assert_eq!(
            m["assertions"]["c2pa.actions.v2"]["actions"][0]["action"],
            "c2pa.created"
        );
    }

    #[test]
    fn attaches_active_manifest_validation_results() {
        let bytes = store_bytes();
        let store = parse_manifest_store(&bytes).unwrap();
        let report = json!({
            "validation_results": {
                "activeManifest": {
                    "success": [{ "code": "claimSignature.validated" }],
                    "failure": []
                }
            }
        });
        let cr = to_crjson_with_report(&store, &report);
        assert_eq!(
            cr["manifests"][0]["validationResults"]["success"][0]["code"],
            "claimSignature.validated"
        );
    }

    #[test]
    fn empty_store_has_null_active() {
        let store = ParsedStore {
            manifests: Vec::new(),
        };
        let cr = to_crjson(&store);
        assert_eq!(cr["manifests"], json!([]));
    }
}
