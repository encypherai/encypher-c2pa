// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Content Credentials JSON (crJSON) rendering of a C2PA manifest store.
//!
//! The document follows the C2PA 2.4 crJSON format specification
//! (`docs/modules/crJSON/pages/crjson-format.adoc`) and its schema
//! (`docs/modules/crJSON/partials/crJSON.schema.json`):
//!
//! - `manifests` is in reverse store order, so the active manifest is
//!   `manifests[0]`, which is where a conformance rubric looks for it.
//! - the claim is keyed after its JUMBF claim box: `claim` for `c2pa.claim`
//!   (v1), `claim.v2` for `c2pa.claim.v2`.
//! - every manifest carries a `signature` object and a `validationResults`
//!   object, including `validationTime` and `specVersion`.
//! - CBOR byte strings render as `b64'<base64>'`, unlike the reader report,
//!   which uses bare base64.
//!
//! crJSON is a derived view, not a source of cryptographic truth. It is
//! produced only in strict-conformance (debug) mode.

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::jumbf::{AssertionContentType, ParsedManifest, ParsedStore};
use crate::c2pa_core::EngineProfile;
use crate::c2pa_crypto::{
    extract_claim_tsa_tokens, extract_cose_alg, extract_x5chain, CryptoError,
};
use crate::c2pa_trust::{
    describe_timestamp_token, token_from_timestamp_response, TokenDescription,
};
use const_oid::ObjectIdentifier;
use der::Decode;
use serde_json::{json, Map, Value as Json};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use x509_cert::Certificate;

/// JUMBF label of a claim-v1 box. Any other claim box label is a v2 claim.
const CLAIM_V1_BOX_LABEL: &str = "c2pa.claim";
/// Prefix of a JUMBF URI that addresses a manifest in this store.
const MANIFEST_URI_PREFIX: &str = "self#jumbf=/c2pa/";
/// Separator between a manifest label and its assertion store in a JUMBF URI.
const ASSERTION_STORE_SEGMENT: &str = "/c2pa.assertions/";

/// The claim fields crJSON renders for a v1 claim (`claimV1` in the schema),
/// in schema order. The schema forbids additional properties, so anything a
/// claim carries beyond this set is dropped from the rendering.
const CLAIM_V1_KEYS: &[&str] = &[
    "claim_generator",
    "claim_generator_info",
    "signature",
    "assertions",
    "dc:format",
    "instanceID",
    "dc:title",
    "redacted_assertions",
    "alg",
    "alg_soft",
    "metadata",
];

/// The claim fields crJSON renders for a v2 claim (`claim` in the schema).
const CLAIM_V2_KEYS: &[&str] = &[
    "instanceID",
    "claim_generator_info",
    "signature",
    "created_assertions",
    "gathered_assertions",
    "dc:title",
    "redacted_assertions",
    "alg",
    "alg_soft",
    "specVersion",
    "metadata",
];

/// Claim fields whose value is an array of hashed-URI maps.
const HASHED_URI_LISTS: &[&str] = &["assertions", "created_assertions", "gathered_assertions"];

/// What the renderer needs from the verification that produced this document.
pub(crate) struct CrjsonContext<'a> {
    /// Reader-shape validation report (`validation_results`, and
    /// `validation_results.ingredientDeltas` when the verifier produced any).
    pub report: &'a Json,
    /// The instant the engine validated against.
    pub validation_time: OffsetDateTime,
    /// Engine profile, which names the spec revision validation ran under.
    pub profile: EngineProfile,
}

/// Render a parsed manifest store as Content Credentials JSON.
pub(crate) fn to_crjson(store: &ParsedStore, context: &CrjsonContext) -> Json {
    let validation_time = context
        .validation_time
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    let spec_version = format!("{}.0", context.profile.version_str());
    let active_label = store
        .manifests
        .last()
        .map(|manifest| manifest.label.as_str());
    let active_results = context
        .report
        .pointer("/validation_results/activeManifest")
        .map(status_codes);
    let deltas = ingredient_deltas(context.report);
    let delta_targets = if deltas.is_empty() {
        Vec::new()
    } else {
        ingredient_manifest_targets(store, &deltas)
    };

    let mut manifests = Vec::with_capacity(store.manifests.len());
    for manifest in store.manifests.iter().rev() {
        let label = manifest.label.as_str();
        let codes = if active_label == Some(label) {
            active_results.clone()
        } else {
            delta_targets
                .iter()
                .find(|(target, _)| target == label)
                .map(|(_, index)| status_codes(&deltas[*index].1))
        };

        let mut entry = Map::new();
        entry.insert("label".into(), Json::String(manifest.label.clone()));
        entry.insert("assertions".into(), assertions(manifest));
        let (claim_key, claim) = claim(manifest);
        entry.insert(claim_key.into(), claim);
        entry.insert("signature".into(), signature(manifest));
        entry.insert(
            "validationResults".into(),
            validation_results(codes, &validation_time, &spec_version),
        );
        let owned_deltas: Vec<Json> = deltas
            .iter()
            .filter(|(uri, _)| manifest_label_from_uri(uri).as_deref() == Some(label))
            .map(|(uri, codes)| {
                json!({
                    "ingredientAssertionURI": uri,
                    "validationDeltas": status_codes_json(&status_codes(codes)),
                })
            })
            .collect();
        if !owned_deltas.is_empty() {
            entry.insert("ingredientDeltas".into(), Json::Array(owned_deltas));
        }
        manifests.push(Json::Object(entry));
    }

    json!({
        "@context": {
            "@vocab": "https://c2pa.org/crjson",
            "extras": "https://c2pa.org/crjson/extras"
        },
        "manifests": manifests,
        "jsonGenerator": {
            "name": "Encypher Engine",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Render the manifest's assertion store as a label-keyed object.
///
/// Every assertion in the store gets a key, in store order. CBOR and JSON
/// assertions are decoded; anything else (a binary or embedded-file assertion,
/// or an undecodable payload) renders as an empty object, which is what the
/// spec prescribes when no information can be derived.
fn assertions(manifest: &ParsedManifest) -> Json {
    let payloads: std::collections::HashMap<&str, &[u8]> = manifest
        .assertions
        .iter()
        .map(|(label, payload)| (label.as_str(), *payload))
        .collect();
    let mut assertions = Map::new();
    for (label, _) in &manifest.assertion_jumbf {
        let value = match (
            manifest.assertion_content_type(label),
            payloads.get(label.as_str()),
        ) {
            (Some(AssertionContentType::Json), Some(payload)) => {
                serde_json::from_slice(payload).unwrap_or_else(|_| json!({}))
            }
            (Some(AssertionContentType::Cbor), Some(payload)) => decode(*payload)
                .map(|value| cbor_to_crjson(&value))
                .unwrap_or_else(|_| json!({})),
            _ => json!({}),
        };
        assertions.insert(label.clone(), value);
    }
    Json::Object(assertions)
}

/// Convert decoded CBOR to the crJSON value model.
///
/// Identical to the reader report's conversion except for byte strings, which
/// crJSON marks with the `b64'` prefix so a consumer can tell an encoded byte
/// string from a text field that happens to look like base64.
fn cbor_to_crjson(value: &Value) -> Json {
    match value {
        Value::Bytes(bytes) => Json::String(base64_marked(bytes)),
        Value::Array(items) => Json::Array(items.iter().map(cbor_to_crjson).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                map.insert(cbor_key(key), cbor_to_crjson(value));
            }
            Json::Object(map)
        }
        Value::Tag(_, inner) => cbor_to_crjson(inner),
        other => crate::c2pa_validate::report::cbor_to_json(other),
    }
}

/// Render a CBOR map key as a JSON object key.
fn cbor_key(key: &Value) -> String {
    match key {
        Value::Text(text) => text.clone(),
        Value::Integer(number) => number.to_string(),
        other => format!("{other:?}"),
    }
}

/// Encode bytes as the crJSON `b64'<base64>'` byte-string form.
fn base64_marked(bytes: &[u8]) -> String {
    format!(
        "b64'{}'",
        crate::c2pa_validate::report::base64_encode(bytes)
    )
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

/// Render the manifest's claim and the key it belongs under.
///
/// The key follows the JUMBF claim box label, as the spec requires: `claim`
/// for a v1 claim box, `claim.v2` otherwise. Only the fields the schema
/// defines for that claim generation are carried over, since the schema
/// forbids additional properties on both claim objects.
fn claim(manifest: &ParsedManifest) -> (&'static str, Json) {
    let is_v1 = manifest.claim_box_label.as_deref() == Some(CLAIM_V1_BOX_LABEL);
    let key = if is_v1 { "claim" } else { "claim.v2" };
    let decoded = manifest
        .claim_cbor
        .and_then(|bytes| decode(bytes).ok())
        .map(|value| cbor_to_crjson(&value));
    let Some(Json::Object(source)) = decoded else {
        return (key, json!({}));
    };

    let keys = if is_v1 { CLAIM_V1_KEYS } else { CLAIM_V2_KEYS };
    let mut claim = Map::new();
    for name in keys {
        if *name == "claim_generator_info" {
            claim.insert((*name).to_string(), generator_info(&source, is_v1));
            continue;
        }
        let Some(value) = source.get(*name) else {
            continue;
        };
        let value = if HASHED_URI_LISTS.contains(name) {
            hashed_uri_list(value)
        } else {
            value.clone()
        };
        claim.insert((*name).to_string(), value);
    }
    // The spec requires the optional assertion-reference lists to be present
    // as empty arrays when the claim omits them.
    if !is_v1 {
        claim
            .entry("gathered_assertions".to_string())
            .or_insert_with(|| Json::Array(Vec::new()));
    }
    claim
        .entry("redacted_assertions".to_string())
        .or_insert_with(|| Json::Array(Vec::new()));
    (key, Json::Object(claim))
}

/// Project a hashed-URI array onto the `{url, hash, alg}` triple the schema
/// allows.
fn hashed_uri_list(value: &Json) -> Json {
    let Some(items) = value.as_array() else {
        return value.clone();
    };
    Json::Array(
        items
            .iter()
            .map(|item| {
                let Some(object) = item.as_object() else {
                    return item.clone();
                };
                let mut entry = Map::new();
                for name in ["url", "hash", "alg"] {
                    if let Some(field) = object.get(name) {
                        entry.insert(name.to_string(), field.clone());
                    }
                }
                Json::Object(entry)
            })
            .collect(),
    )
}

/// Shape `claim_generator_info` for the claim generation: an array of
/// generator-info maps for v1, a single map for v2.
///
/// A 1.x claim may legitimately omit the field, which the crJSON schema still
/// requires. Rather than emit a hole, the generator name is then taken from
/// the claim's `claim_generator` User-Agent string, which is the same
/// information in the form that claim generation recorded it. The reference
/// implementation derives it the same way.
fn generator_info(claim: &Map<String, Json>, is_v1: bool) -> Json {
    let agents: Vec<Json> = match claim.get("claim_generator_info") {
        Some(Json::Array(items)) => items
            .iter()
            .filter(|item| item.is_object())
            .cloned()
            .collect(),
        Some(single @ Json::Object(_)) => vec![single.clone()],
        _ => Vec::new(),
    };
    let agents = if agents.is_empty() {
        let name = claim
            .get("claim_generator")
            .and_then(Json::as_str)
            .unwrap_or("Unknown");
        vec![json!({ "name": name })]
    } else {
        agents
    };
    if is_v1 {
        Json::Array(agents)
    } else {
        agents.into_iter().next().unwrap_or_else(|| json!({}))
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// `id-at-countryName` and the rest of the distinguished-name attributes the
/// schema's `distinguishedName` object allows, in schema order.
const DN_ATTRIBUTES: &[(&str, &str)] = &[
    ("2.5.4.6", "C"),
    ("2.5.4.8", "ST"),
    ("2.5.4.7", "L"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.3", "CN"),
    ("1.2.840.113549.1.9.1", "E"),
    ("2.5.4.97", "2.5.4.97"),
];

/// Render the manifest's claim signature: algorithm, signing certificate, and
/// the timestamp when the signature carries one.
///
/// An unreadable or absent signature renders as an empty object, which is what
/// the spec prescribes when signature information is unavailable.
fn signature(manifest: &ParsedManifest) -> Json {
    let Some(cose) = manifest.signature_cose else {
        return json!({});
    };
    let mut signature = Map::new();
    match extract_cose_alg(cose) {
        Ok(alg) => {
            signature.insert("algorithm".into(), Json::String(alg_name(alg)));
        }
        Err(CryptoError::UnsupportedAlg(_)) => {
            signature.insert("algorithm".into(), Json::String("Unknown".into()));
        }
        Err(_) => {}
    }
    if let Some(info) = extract_x5chain(cose)
        .ok()
        .and_then(|chain| chain.first().and_then(|der| certificate_info(der)))
    {
        signature.insert("certificateInfo".into(), info);
    }
    if let Some(info) = timestamp_info(cose) {
        signature.insert("timeStampInfo".into(), info);
    }
    Json::Object(signature)
}

/// The C2PA clause 13.2.1 name of a signature algorithm.
fn alg_name(alg: crate::c2pa_crypto::CoseAlg) -> String {
    use crate::c2pa_crypto::CoseAlg;
    match alg {
        CoseAlg::Es256 => "ES256",
        CoseAlg::Es384 => "ES384",
        CoseAlg::Es512 => "ES512",
        CoseAlg::Ps256 => "PS256",
        CoseAlg::Ps384 => "PS384",
        CoseAlg::Ps512 => "PS512",
        CoseAlg::EdDsa => "Ed25519",
    }
    .to_string()
}

/// Render an X.509 certificate as the schema's `certificateInfo` object.
fn certificate_info(der: &[u8]) -> Option<Json> {
    let cert = Certificate::from_der(der).ok()?;
    let validity = &cert.tbs_certificate.validity;
    Some(json!({
        "serialNumber": serial_hex(cert.tbs_certificate.serial_number.as_bytes()),
        "issuer": distinguished_name(&cert, false),
        "subject": distinguished_name(&cert, true),
        "validity": {
            "notBefore": rfc3339(validity.not_before.to_unix_duration().as_secs() as i64),
            "notAfter": rfc3339(validity.not_after.to_unix_duration().as_secs() as i64),
        },
    }))
}

/// Render the subject or issuer distinguished name, keeping only the
/// attributes the schema defines.
fn distinguished_name(cert: &Certificate, subject: bool) -> Json {
    let name = if subject {
        &cert.tbs_certificate.subject
    } else {
        &cert.tbs_certificate.issuer
    };
    let mut components = Map::new();
    for (oid, key) in DN_ATTRIBUTES {
        let Ok(oid) = ObjectIdentifier::new(oid) else {
            continue;
        };
        for rdn in name.0.iter() {
            for atav in rdn.0.iter() {
                if atav.oid != oid {
                    continue;
                }
                let value = String::from_utf8_lossy(atav.value.value()).into_owned();
                components.insert((*key).to_string(), Json::String(value));
            }
        }
    }
    Json::Object(components)
}

/// Render a certificate serial number as lowercase hex without leading zeros,
/// the form certificate tooling prints.
fn serial_hex(be_bytes: &[u8]) -> Json {
    let trimmed = be_bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|start| &be_bytes[start..])
        .unwrap_or(&[]);
    if trimmed.is_empty() {
        return Json::String("0".into());
    }
    let mut hex = String::with_capacity(trimmed.len() * 2);
    for (index, byte) in trimmed.iter().enumerate() {
        if index == 0 {
            hex.push_str(&format!("{byte:x}"));
        } else {
            hex.push_str(&format!("{byte:02x}"));
        }
    }
    Json::String(hex)
}

/// Render the claim signature's timestamp, when it carries a readable RFC 3161
/// token. Descriptive only: the timestamp's validity is decided by the
/// validation status codes, not by its presence here.
fn timestamp_info(cose: &[u8]) -> Option<Json> {
    let (_, tokens) = extract_claim_tsa_tokens(cose)?;
    let description = tokens
        .iter()
        .flatten()
        .find_map(|token| describe_token(token))?;
    let mut info = Map::new();
    info.insert(
        "timestamp".into(),
        Json::String(rfc3339(description.generated_at.unix_timestamp())),
    );
    if let Some(cert) = description
        .signer_cert_der
        .as_deref()
        .and_then(certificate_info)
    {
        info.insert("certificateInfo".into(), cert);
    }
    Some(Json::Object(info))
}

/// Describe one `tstTokens` entry, accepting both forms found in the wild: a
/// bare RFC 3161 `TimeStampToken`, and the legacy `sigTst` form that stores
/// the whole `TimeStampResp` the authority returned.
fn describe_token(token: &[u8]) -> Option<TokenDescription> {
    describe_timestamp_token(token).or_else(|| {
        token_from_timestamp_response(token)
            .ok()
            .and_then(|inner| describe_timestamp_token(&inner))
    })
}

/// Render a Unix timestamp as an RFC 3339 date-time string.
fn rfc3339(unix_seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Validation results
// ---------------------------------------------------------------------------

/// Status codes grouped the way the schema's `statusCodes` object groups them.
#[derive(Clone, Default)]
struct StatusCodes {
    success: Vec<Json>,
    informational: Vec<Json>,
    failure: Vec<Json>,
}

/// Read one reader-report status-code group.
fn status_codes(value: &Json) -> StatusCodes {
    StatusCodes {
        success: status_entries(value.get("success")),
        informational: status_entries(value.get("informational")),
        failure: status_entries(value.get("failure")),
    }
}

/// Project reader-report status entries onto the `{code, url, explanation}`
/// triple the schema allows. The report's `details` payload is dropped: the
/// schema forbids additional properties on a status entry.
fn status_entries(value: Option<&Json>) -> Vec<Json> {
    let Some(entries) = value.and_then(Json::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let object = entry.as_object()?;
            let code = object.get("code")?.as_str()?;
            let mut status = Map::new();
            status.insert("code".into(), Json::String(code.to_string()));
            for name in ["url", "explanation"] {
                if let Some(text) = object.get(name).and_then(Json::as_str) {
                    status.insert(name.to_string(), Json::String(text.to_string()));
                }
            }
            Some(Json::Object(status))
        })
        .collect()
}

/// Render a `statusCodes` object.
fn status_codes_json(codes: &StatusCodes) -> Json {
    json!({
        "success": codes.success,
        "informational": codes.informational,
        "failure": codes.failure,
    })
}

/// Render one manifest's `validationResults`. A manifest the verifier produced
/// no assessment for still carries the object, with empty groups.
fn validation_results(
    codes: Option<StatusCodes>,
    validation_time: &str,
    spec_version: &str,
) -> Json {
    let codes = codes.unwrap_or_default();
    json!({
        "success": codes.success,
        "informational": codes.informational,
        "failure": codes.failure,
        "specVersion": spec_version,
        "validationTime": validation_time,
    })
}

/// Read `validation_results.ingredientDeltas` as `(assertion URI, status codes)`
/// pairs.
fn ingredient_deltas(report: &Json) -> Vec<(String, Json)> {
    let Some(deltas) = report
        .pointer("/validation_results/ingredientDeltas")
        .and_then(Json::as_array)
    else {
        return Vec::new();
    };
    deltas
        .iter()
        .filter_map(|delta| {
            let uri = delta.get("ingredientAssertionURI")?.as_str()?.to_string();
            let codes = delta.get("validationDeltas")?.clone();
            Some((uri, codes))
        })
        .collect()
}

/// Match each ingredient delta to the manifest it describes.
///
/// A delta names the ingredient *assertion* that points at the ingredient
/// manifest, so that assertion's manifest link - `activeManifest` in a v3
/// ingredient, `c2pa_manifest` in a v1 or v2 one - is what resolves it to a
/// manifest label. Returns `(manifest label, delta index)`.
fn ingredient_manifest_targets(
    store: &ParsedStore,
    deltas: &[(String, Json)],
) -> Vec<(String, usize)> {
    let mut targets = Vec::new();
    for (index, (uri, _)) in deltas.iter().enumerate() {
        let Some(owner) = manifest_label_from_uri(uri) else {
            continue;
        };
        let Some(manifest) = store
            .manifests
            .iter()
            .find(|manifest| manifest.label == owner)
        else {
            continue;
        };
        for (label, payload) in &manifest.assertions {
            if !label.starts_with("c2pa.ingredient") {
                continue;
            }
            if assertion_uri(&owner, label) != *uri {
                continue;
            }
            let Ok(ingredient) = decode(payload) else {
                continue;
            };
            if let Some(target) = ingredient
                .get("activeManifest")
                .or_else(|| ingredient.get("c2pa_manifest"))
                .and_then(|link| link.get("url"))
                .and_then(Value::as_text)
                .and_then(manifest_label_from_uri)
            {
                targets.push((target, index));
            }
        }
    }
    targets
}

/// The absolute JUMBF URI of an assertion inside a manifest.
fn assertion_uri(manifest_label: &str, assertion_label: &str) -> String {
    format!("{MANIFEST_URI_PREFIX}{manifest_label}{ASSERTION_STORE_SEGMENT}{assertion_label}")
}

/// The manifest label a JUMBF URI addresses, if any.
fn manifest_label_from_uri(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix(MANIFEST_URI_PREFIX)?;
    let label = match rest.find(ASSERTION_STORE_SEGMENT) {
        Some(end) => &rest[..end],
        None => rest.split('/').next().unwrap_or(rest),
    };
    (!label.is_empty()).then(|| label.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{map_from_pairs, Profile, Value};
    use crate::c2pa_core::jumbf::{
        assertion_box, build_manifest, build_manifest_store, build_manifest_with_claim_label,
        parse_manifest_store,
    };
    use crate::c2pa_core::SpecVersion;

    fn claim_cbor(generator_info: Value, extra: Vec<(String, Value)>) -> Vec<u8> {
        let mut pairs = vec![
            ("dc:format".to_string(), Value::Text("image/jpeg".into())),
            ("dc:title".to_string(), Value::Text("photo.jpg".into())),
            ("instanceID".to_string(), Value::Text("urn:uuid:abc".into())),
            ("claim_generator_info".to_string(), generator_info),
        ];
        pairs.extend(extra);
        let claim = map_from_pairs(pairs);
        crate::c2pa_cbor::encode(&claim, Profile::LegacyPipelineBDefinite).unwrap()
    }

    fn generator_array() -> Value {
        Value::Array(vec![
            map_from_pairs([
                ("name".into(), Value::Text("Encypher Engine".into())),
                ("version".into(), Value::Text("1.0".into())),
            ]),
            map_from_pairs([("name".into(), Value::Text("Second Agent".into()))]),
        ])
    }

    fn actions_cbor() -> Vec<u8> {
        let actions = map_from_pairs([(
            "actions".into(),
            Value::Array(vec![map_from_pairs([(
                "action".into(),
                Value::Text("c2pa.created".into()),
            )])]),
        )]);
        crate::c2pa_cbor::encode(&actions, Profile::LegacyPipelineBDefinite).unwrap()
    }

    /// One manifest with a claim, an actions assertion, and a hash assertion
    /// whose byte-string hash exercises crJSON's byte encoding.
    fn manifest_bytes(label: &str, claim_box: &str, claim: &[u8]) -> Vec<u8> {
        let hash = map_from_pairs([
            ("alg".into(), Value::Text("sha256".into())),
            ("hash".into(), Value::Bytes(vec![0x01, 0x02, 0x03])),
        ]);
        let hash_cbor = crate::c2pa_cbor::encode(&hash, Profile::LegacyPipelineBDefinite).unwrap();
        let boxes = [
            assertion_box("c2pa.actions.v2", &actions_cbor(), None),
            assertion_box("c2pa.hash.data", &hash_cbor, None),
        ];
        build_manifest_with_claim_label(label, &boxes, claim, &[0xd2, 0x84], claim_box)
    }

    fn manifest_bytes_with_signature(
        label: &str,
        claim_box: &str,
        claim: &[u8],
        signature: &[u8],
    ) -> Vec<u8> {
        let hash = map_from_pairs([
            ("alg".into(), Value::Text("sha256".into())),
            ("hash".into(), Value::Bytes(vec![0x01, 0x02, 0x03])),
        ]);
        let hash_cbor = crate::c2pa_cbor::encode(&hash, Profile::LegacyPipelineBDefinite).unwrap();
        let boxes = [
            assertion_box("c2pa.actions.v2", &actions_cbor(), None),
            assertion_box("c2pa.hash.data", &hash_cbor, None),
        ];
        build_manifest_with_claim_label(label, &boxes, claim, signature, claim_box)
    }

    fn unsupported_cose_with_certificate(certificate: &[u8]) -> Vec<u8> {
        let protected = crate::c2pa_cbor::encode(
            &Value::Map(vec![(Value::Integer(1), Value::Integer(-65535))]),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap();
        crate::c2pa_cbor::encode(
            &Value::Tag(
                18,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(vec![(
                        Value::Integer(33),
                        Value::Bytes(certificate.to_vec()),
                    )]),
                    Value::Null,
                    Value::Bytes(Vec::new()),
                ])),
            ),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap()
    }

    fn context(report: &Json) -> CrjsonContext<'_> {
        CrjsonContext {
            report,
            validation_time: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            profile: EngineProfile::strict(SpecVersion::V2_4),
        }
    }

    fn empty_report() -> Json {
        json!({ "validation_results": { "activeManifest": {
            "success": [], "informational": [], "failure": []
        }}})
    }

    #[test]
    fn active_manifest_is_first_in_a_multi_manifest_store() {
        let claim = claim_cbor(generator_array(), Vec::new());
        let bytes = build_manifest_store(&[
            manifest_bytes("urn:c2pa:ingredient", "c2pa.claim.v2", &claim),
            manifest_bytes("urn:c2pa:active", "c2pa.claim.v2", &claim),
        ]);
        let store = parse_manifest_store(&bytes).unwrap();
        let report = empty_report();

        let cr = to_crjson(&store, &context(&report));

        assert_eq!(cr["manifests"][0]["label"], "urn:c2pa:active");
        assert_eq!(cr["manifests"][1]["label"], "urn:c2pa:ingredient");
    }

    #[test]
    fn claim_key_and_generator_info_follow_the_claim_box_label() {
        let claim = claim_cbor(generator_array(), Vec::new());
        let v2_bytes =
            build_manifest_store(&[manifest_bytes("urn:c2pa:v2", "c2pa.claim.v2", &claim)]);
        let v2_store = parse_manifest_store(&v2_bytes).unwrap();
        let report = empty_report();
        let v2 = to_crjson(&v2_store, &context(&report));

        assert!(v2["manifests"][0].get("claim").is_none());
        assert_eq!(
            v2["manifests"][0]["claim.v2"]["claim_generator_info"]["name"], "Encypher Engine",
            "a v2 claim carries a single generator-info map"
        );

        let v1_claim = claim_cbor(
            generator_array(),
            vec![(
                "claim_generator".to_string(),
                Value::Text("agent/1.0".into()),
            )],
        );
        let v1_bytes =
            build_manifest_store(&[manifest_bytes("urn:c2pa:v1", CLAIM_V1_BOX_LABEL, &v1_claim)]);
        let v1_store = parse_manifest_store(&v1_bytes).unwrap();
        let v1 = to_crjson(&v1_store, &context(&report));

        assert!(v1["manifests"][0].get("claim.v2").is_none());
        assert_eq!(
            v1["manifests"][0]["claim"]["claim_generator_info"][1]["name"], "Second Agent",
            "a v1 claim keeps the full generator-info array"
        );
        assert_eq!(v1["manifests"][0]["claim"]["claim_generator"], "agent/1.0");
    }

    #[test]
    fn every_manifest_carries_signature_and_validation_results() {
        let claim = claim_cbor(generator_array(), Vec::new());
        let bytes = build_manifest_store(&[
            manifest_bytes("urn:c2pa:ingredient", "c2pa.claim.v2", &claim),
            manifest_bytes("urn:c2pa:active", "c2pa.claim.v2", &claim),
        ]);
        let store = parse_manifest_store(&bytes).unwrap();
        let report = json!({ "validation_results": { "activeManifest": {
            "success": [{
                "code": "claimSignature.validated",
                "url": "self#jumbf=/c2pa/urn:c2pa:active/c2pa.signature",
                "explanation": "claim signature valid",
                "details": { "internal": true }
            }],
            "informational": [],
            "failure": []
        }}});

        let cr = to_crjson(&store, &context(&report));

        for manifest in cr["manifests"].as_array().unwrap() {
            assert_eq!(
                manifest["signature"],
                json!({}),
                "an unreadable signature must remain the specified empty object"
            );
            let results = &manifest["validationResults"];
            assert_eq!(results["validationTime"], "2023-11-14T22:13:20Z");
            assert_eq!(results["specVersion"], "2.4.0");
            for group in ["success", "informational", "failure"] {
                assert!(results[group].is_array());
            }
        }
        let active = &cr["manifests"][0]["validationResults"]["success"][0];
        assert_eq!(active["code"], "claimSignature.validated");
        assert!(
            active.get("details").is_none(),
            "the schema forbids extra fields on a status entry"
        );
        assert_eq!(
            cr["manifests"][1]["validationResults"]["success"],
            json!([]),
            "a manifest with no assessment still carries empty groups"
        );
    }

    #[test]
    fn byte_strings_render_with_the_crjson_prefix() {
        let claim = claim_cbor(generator_array(), Vec::new());
        let bytes = build_manifest_store(&[manifest_bytes("urn:c2pa:1", "c2pa.claim.v2", &claim)]);
        let store = parse_manifest_store(&bytes).unwrap();
        let report = empty_report();

        let cr = to_crjson(&store, &context(&report));

        assert_eq!(
            cr["manifests"][0]["assertions"]["c2pa.hash.data"]["hash"],
            "b64'AQID'"
        );
    }

    #[test]
    fn readable_unsupported_signature_algorithm_renders_unknown() {
        const CERTIFICATE: &[u8] = include_bytes!("../c2pa-crypto/fixtures/pss_spki_cert.der");
        let claim = claim_cbor(generator_array(), Vec::new());
        let signature = unsupported_cose_with_certificate(CERTIFICATE);
        let bytes = build_manifest_store(&[manifest_bytes_with_signature(
            "urn:c2pa:unsupported-alg",
            "c2pa.claim.v2",
            &claim,
            &signature,
        )]);
        let store = parse_manifest_store(&bytes).unwrap();
        let report = empty_report();

        let cr = to_crjson(&store, &context(&report));

        assert_eq!(
            cr["manifests"][0]["signature"]["algorithm"], "Unknown",
            "a readable COSE algorithm outside the C2PA set must not look unavailable"
        );
        assert!(
            cr["manifests"][0]["signature"]["certificateInfo"].is_object(),
            "the fixture must exercise a readable signature rather than the empty-object case"
        );
    }

    #[test]
    fn ingredient_deltas_reach_the_owning_and_the_ingredient_manifest() {
        let ingredient_uri =
            "self#jumbf=/c2pa/urn:c2pa:active/c2pa.assertions/c2pa.ingredient.v3".to_string();
        let ingredient_assertion = map_from_pairs([
            ("relationship".into(), Value::Text("parentOf".into())),
            (
                "c2pa_manifest".into(),
                map_from_pairs([(
                    "url".into(),
                    Value::Text("self#jumbf=/c2pa/urn:c2pa:ingredient".into()),
                )]),
            ),
        ]);
        let ingredient_cbor =
            crate::c2pa_cbor::encode(&ingredient_assertion, Profile::LegacyPipelineBDefinite)
                .unwrap();
        let claim = claim_cbor(generator_array(), Vec::new());
        let active = build_manifest(
            "urn:c2pa:active",
            &[assertion_box("c2pa.ingredient.v3", &ingredient_cbor, None)],
            &claim,
            &[0xd2, 0x84],
        );
        let bytes = build_manifest_store(&[
            manifest_bytes("urn:c2pa:ingredient", "c2pa.claim.v2", &claim),
            active,
        ]);
        let store = parse_manifest_store(&bytes).unwrap();
        let report = json!({ "validation_results": {
            "activeManifest": { "success": [], "informational": [], "failure": [] },
            "ingredientDeltas": [{
                "ingredientAssertionURI": ingredient_uri,
                "validationDeltas": {
                    "success": [{ "code": "ingredient.manifest.validated" }],
                    "informational": [],
                    "failure": []
                }
            }]
        }});

        let cr = to_crjson(&store, &context(&report));

        let active = &cr["manifests"][0];
        assert_eq!(active["label"], "urn:c2pa:active");
        assert_eq!(
            active["ingredientDeltas"][0]["ingredientAssertionURI"],
            ingredient_uri
        );
        assert_eq!(
            active["ingredientDeltas"][0]["validationDeltas"]["success"][0]["code"],
            "ingredient.manifest.validated"
        );
        assert_eq!(
            cr["manifests"][1]["validationResults"]["success"][0]["code"],
            "ingredient.manifest.validated",
            "the ingredient manifest reports the delta as its own result"
        );
        assert!(cr["manifests"][1].get("ingredientDeltas").is_none());
    }

    #[test]
    fn empty_store_renders_no_manifests() {
        let store = ParsedStore {
            manifests: Vec::new(),
        };
        let report = empty_report();
        let cr = to_crjson(&store, &context(&report));
        assert_eq!(cr["manifests"], json!([]));
        assert_eq!(cr["jsonGenerator"]["name"], "Encypher Engine");
    }
}
