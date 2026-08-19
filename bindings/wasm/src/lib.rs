#![forbid(unsafe_code)]

use encypher_c2pa::{
    supported_mime_types, validation_failure_telemetry, verify_fragmented_with_options,
    verify_with_options, VerifyOptions,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

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
