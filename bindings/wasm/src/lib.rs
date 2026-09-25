#![forbid(unsafe_code)]
// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use encypher_c2pa::{
    supported_mime_types, validation_failure_telemetry, verify_fragmented_with_options,
    verify_stream_with_options, verify_with_manifest_store, verify_with_options, NetworkReport,
    NetworkRequest, StreamEncapsulation, StreamMethod, VerifyOptions,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(inline_js = r#"
const KEY = "encypher-c2pa.telemetry-enabled";
export function postValidationFailure(endpoint, payload) {
  try { fetch(endpoint, { method: "POST", headers: { "content-type": "text/plain;charset=UTF-8" }, body: payload, credentials: "omit", keepalive: true }).catch(() => {}); } catch (_) {}
}
export function savedTelemetryPreference() {
  try {
    const value = globalThis.localStorage?.getItem(KEY);
    return value === "true" ? true : value === "false" ? false : null;
  } catch (_) { return null; }
}
export function saveTelemetryPreference(enabled) {
  try { globalThis.localStorage?.setItem(KEY, enabled ? "true" : "false"); } catch (_) {}
}
export function resolveTelemetryPreference() {
  const saved = savedTelemetryPreference();
  if (saved !== null) return saved;
  const enabled = typeof globalThis.confirm === "function"
    ? globalThis.confirm("Help improve Encypher C2PA verification? Send anonymous failure codes when validation fails. No asset, manifest, path, key, certificate, trust material, or account data is sent.")
    : false;
  saveTelemetryPreference(enabled);
  return enabled;
}
const LIMITS = {
  remote_manifest: 64 * 1024 * 1024,
  did_document: 256 * 1024,
  external_data: 64 * 1024 * 1024,
};
const MAX_REQUESTS = 16;
// The page's own network policy applies here: same-origin rules, CORS, mixed
// content, and any Content-Security-Policy the site sets. The address filter
// the native SDK applies does not, and cannot: a browser will not tell a
// script which address a name resolved to.
export async function fetchOnlineNeeds(needed) {
  const requests = [];
  const result = { requests, manifestStore: null, didDocuments: {}, externalData: {} };
  let budget = MAX_REQUESTS;
  for (const need of needed) {
    const purpose = need.kind === "ocsp" ? `ocsp.${need.purpose}` : need.kind;
    const url = need.uri ?? need.responder_url ?? need.url;
    if (need.kind === "ocsp") {
      requests.push({ purpose, url, outcome: "skipped", detail: "a browser cannot make an OCSP request" });
      continue;
    }
    if (budget <= 0) {
      requests.push({ purpose, url, outcome: "skipped", detail: `the ${MAX_REQUESTS} request budget for one verification is spent` });
      continue;
    }
    budget -= 1;
    if (!/^https:\/\//i.test(url)) {
      requests.push({ purpose, url, outcome: "blocked", detail: "https is required" });
      continue;
    }
    try {
      const response = await fetch(url, { credentials: "omit", redirect: "follow", mode: "cors" });
      if (!response.ok) {
        requests.push({ purpose, url, outcome: "failed", detail: `the server answered HTTP ${response.status}` });
        continue;
      }
      const bytes = new Uint8Array(await response.arrayBuffer());
      const limit = LIMITS[need.kind] ?? LIMITS.external_data;
      if (bytes.byteLength > limit) {
        requests.push({ purpose, url, outcome: "blocked", detail: `the response is larger than the ${limit} byte limit` });
        continue;
      }
      if (need.kind === "remote_manifest") {
        result.manifestStore = bytes;
      } else if (need.kind === "did_document") {
        try {
          result.didDocuments[need.did] = JSON.parse(new TextDecoder().decode(bytes));
        } catch (error) {
          requests.push({ purpose, url, outcome: "failed", detail: `the DID document is not JSON: ${error}` });
          continue;
        }
      } else {
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        result.externalData[need.uri] = btoa(binary);
      }
      requests.push({ purpose, url, outcome: "fetched", detail: `${bytes.byteLength} bytes` });
    } catch (error) {
      // A cross-origin refusal arrives here as an opaque TypeError. It is a
      // failure of the request, not a refusal by this SDK.
      requests.push({ purpose, url, outcome: "failed", detail: `${error}` });
    }
  }
  return result;
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = postValidationFailure)]
    fn post_validation_failure(endpoint: &str, payload: &str);
    #[wasm_bindgen(js_name = savedTelemetryPreference)]
    fn saved_telemetry_preference() -> JsValue;
    #[wasm_bindgen(js_name = saveTelemetryPreference)]
    fn save_telemetry_preference(enabled: bool);
    #[wasm_bindgen(js_name = resolveTelemetryPreference)]
    fn resolve_telemetry_preference() -> bool;
    #[wasm_bindgen(js_name = fetchOnlineNeeds)]
    fn fetch_online_needs(needed: JsValue) -> js_sys::Promise;
}

#[wasm_bindgen(js_name = verify)]
pub fn verify_js(
    asset: &[u8],
    mime_type: &str,
    options: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let mut options = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    if options.telemetry.enabled.is_none() {
        options.telemetry.enabled = Some(resolve_telemetry_preference());
    }
    if options.telemetry.enabled == Some(true) {
        options.telemetry.sdk_name = Some("browser".to_string());
    }
    let result = verify_with_options(asset, mime_type, &options);
    if let Some(event) = validation_failure_telemetry(mime_type, &result, &options.telemetry) {
        if let Ok(payload) = event.to_json() {
            post_validation_failure(options.telemetry.endpoint(), &payload);
        }
    }
    let report = result.map_err(|error| js_error(error.code(), error.to_string()))?;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

/// Verify an asset, fetching what it references.
///
/// `verify` is synchronous and never touches the network. This entry point
/// does the same verification, then fetches the resources the report listed
/// under `network.needed`, then verifies again with what it got. The verdict
/// still comes from the same offline checks; the network only supplies
/// evidence.
///
/// Fetching happens through the page's own `fetch`, so the page's network
/// policy applies: same-origin rules, CORS, mixed-content blocking, and any
/// Content-Security-Policy the site sets. A server that does not send CORS
/// headers is reported as a `failed` request with the browser's message. The
/// address filter the native SDK applies is absent here, because a browser
/// does not tell a script which address a name resolved to; the browser's own
/// private-network rules take its place.
///
/// OCSP is not attempted from a browser. The request bytes are not exposed to
/// the page, and responders do not serve CORS headers, so those needs are
/// reported as `skipped`.
#[wasm_bindgen(js_name = verifyOnline)]
pub async fn verify_online_js(
    asset: Vec<u8>,
    mime_type: String,
    options: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let mut options = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    if options.telemetry.enabled.is_none() {
        options.telemetry.enabled = Some(resolve_telemetry_preference());
    }
    if options.telemetry.enabled == Some(true) {
        options.telemetry.sdk_name = Some("browser".to_string());
    }
    // The fetching is done here, in the page, not by the kernel.
    options.online = Some(false);

    let first = verify_with_options(&asset, &mime_type, &options)
        .map_err(|error| js_error(error.code(), error.to_string()))?;
    let needed = first.network.needed.clone();
    if needed.is_empty() {
        return first
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|error| js_error("serialization_error", error.to_string()));
    }

    let needed_js = serde_wasm_bindgen::to_value(&needed)
        .map_err(|error| js_error("serialization_error", error.to_string()))?;
    let fetched = JsFuture::from(fetch_online_needs(needed_js)).await?;
    let requests: Vec<NetworkRequest> =
        serde_wasm_bindgen::from_value(js_sys::Reflect::get(&fetched, &"requests".into())?)
            .map_err(|error| js_error("serialization_error", error.to_string()))?;
    let documents: HashMap<String, serde_json::Value> =
        serde_wasm_bindgen::from_value(js_sys::Reflect::get(&fetched, &"didDocuments".into())?)
            .map_err(|error| js_error("serialization_error", error.to_string()))?;
    let store = js_sys::Reflect::get(&fetched, &"manifestStore".into())?;
    let store = (!store.is_null() && !store.is_undefined())
        .then(|| js_sys::Uint8Array::new(&store).to_vec());

    if !documents.is_empty() {
        let mut pinned = options.cawg_did_documents.take().unwrap_or_default();
        pinned.extend(documents);
        options.cawg_did_documents = Some(pinned);
    }
    // SLICE A SEAM: externally stored assertion content comes back from the
    // page under `externalData` as uri -> base64. At merge, put it into
    // `options.external_data`, which is slice A's field on `VerifyOptions`.

    let mut second = match &store {
        Some(store) => verify_with_manifest_store(&asset, store, &mime_type, &options),
        None => verify_with_options(&asset, &mime_type, &options),
    }
    .unwrap_or(first);
    second.network = NetworkReport {
        enabled: true,
        needed,
        requests,
    };
    second
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

/// Verify an asset against a C2PA Manifest Store supplied separately.
///
/// Use this for a `.c2pa` sidecar, or for a store the page fetched itself from
/// the URI the asset declares in its XMP `dcterms:provenance` key. This module
/// never fetches it. `mimeType` describes the asset, not the store.
#[wasm_bindgen(js_name = verifyWithManifestStore)]
pub fn verify_with_manifest_store_js(
    asset: &[u8],
    manifest_store: &[u8],
    mime_type: &str,
    options: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let mut options = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    if options.telemetry.enabled.is_none() {
        options.telemetry.enabled = Some(resolve_telemetry_preference());
    }
    if options.telemetry.enabled == Some(true) {
        options.telemetry.sdk_name = Some("browser".to_string());
    }
    let result = verify_with_manifest_store(asset, manifest_store, mime_type, &options);
    if let Some(event) = validation_failure_telemetry(mime_type, &result, &options.telemetry) {
        if let Ok(payload) = event.to_json() {
            post_validation_failure(options.telemetry.endpoint(), &payload);
        }
    }
    let report = result.map_err(|error| js_error(error.code(), error.to_string()))?;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

#[wasm_bindgen(js_name = verifyFragmented)]
pub fn verify_fragmented_js(
    init_segment: &[u8],
    fragments: js_sys::Array,
    mime_type: &str,
    options: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let mut options = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    if options.telemetry.enabled.is_none() {
        options.telemetry.enabled = Some(resolve_telemetry_preference());
    }
    if options.telemetry.enabled == Some(true) {
        options.telemetry.sdk_name = Some("browser".to_string());
    }

    let fragment_bytes: Vec<Vec<u8>> = fragments
        .iter()
        .map(|value| {
            value
                .dyn_into::<js_sys::Uint8Array>()
                .map(|bytes| bytes.to_vec())
                .map_err(|_| {
                    js_error(
                        "invalid_argument",
                        "each fragment must be a Uint8Array".to_string(),
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    let fragment_refs: Vec<&[u8]> = fragment_bytes.iter().map(Vec::as_slice).collect();
    let result = verify_fragmented_with_options(init_segment, &fragment_refs, mime_type, &options);
    if let Some(event) = validation_failure_telemetry(mime_type, &result, &options.telemetry) {
        if let Ok(payload) = event.to_json() {
            post_validation_failure(options.telemetry.endpoint(), &payload);
        }
    }
    let report = result.map_err(|error| js_error(error.code(), error.to_string()))?;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

/// Verify a declared fMP4/CMAF stream.
///
/// `segments` is an array of `Uint8Array` media segments in playback order.
/// `encapsulation` is `"fMP4"` or `"CMAF"` and `method` is
/// `"verifiable-segment-info"` or `"per-segment"`, both ASCII
/// case-insensitive. Which binding a `verifiable-segment-info` stream used is
/// read from the init manifest, never taken from the caller.
#[wasm_bindgen(js_name = verifyStream)]
pub fn verify_stream_js(
    init_segment: &[u8],
    segments: js_sys::Array,
    mime_type: &str,
    encapsulation: &str,
    method: &str,
    options: Option<JsValue>,
) -> Result<JsValue, JsValue> {
    let mut options = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    if options.telemetry.enabled.is_none() {
        options.telemetry.enabled = Some(resolve_telemetry_preference());
    }
    if options.telemetry.enabled == Some(true) {
        options.telemetry.sdk_name = Some("browser".to_string());
    }

    let encapsulation = StreamEncapsulation::from_token(encapsulation).ok_or_else(|| {
        js_error(
            "invalid_argument",
            format!("unknown encapsulation: {encapsulation} (expected fMP4 or CMAF)"),
        )
    })?;
    let method = StreamMethod::from_token(method).ok_or_else(|| {
        js_error(
            "invalid_argument",
            format!("unknown method: {method} (expected verifiable-segment-info or per-segment)"),
        )
    })?;
    let segment_bytes: Vec<Vec<u8>> = segments
        .iter()
        .map(|value| {
            value
                .dyn_into::<js_sys::Uint8Array>()
                .map(|bytes| bytes.to_vec())
                .map_err(|_| {
                    js_error(
                        "invalid_argument",
                        "each segment must be a Uint8Array".to_string(),
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    let segment_refs: Vec<&[u8]> = segment_bytes.iter().map(Vec::as_slice).collect();
    let report = verify_stream_with_options(
        init_segment,
        &segment_refs,
        mime_type,
        encapsulation,
        method,
        &options,
    )
    .map_err(|error| js_error(error.code(), error.to_string()))?;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

#[wasm_bindgen(js_name = configureTelemetry)]
pub fn configure_telemetry(enabled: bool) {
    save_telemetry_preference(enabled);
}

#[wasm_bindgen(js_name = telemetryEnabled)]
pub fn telemetry_enabled() -> JsValue {
    saved_telemetry_preference()
}

#[wasm_bindgen(js_name = supportedMimeTypes)]
pub fn supported_mime_types_js() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&supported_mime_types())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

fn js_error(code: &str, message: String) -> JsValue {
    JsValue::from_str(&format!("{code}: {message}"))
}
