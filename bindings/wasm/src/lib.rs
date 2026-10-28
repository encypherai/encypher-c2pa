#![forbid(unsafe_code)]
// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use encypher_c2pa::{
    local_evidence_with_options, locate_external_resources, supported_mime_types,
    validation_failure_telemetry, verify_ertmp_with_options, verify_fragmented_with_options,
    verify_stream_with_options, verify_with_graph_inputs, verify_with_manifest_store,
    verify_with_options, Error, ErtmpInput, ExternalResource, ExternalResourceKind,
    ExternalResources, GraphInputs, GraphLimits, NetworkReport, NetworkRequest,
    SoftBindingHttpMethod, SoftBindingQuery, SoftBindingReceiptVerificationSession,
    SoftBindingResolverOptions, SoftBindingResolverSession, StreamEncapsulation, StreamMethod,
    ValidatedExternalData, VerificationReport, VerifyOptions,
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
export async function fetchOnlineResource(url, maxBytes, accept) {
  if (!/^https:\/\//i.test(url)) {
    return {
      outcome: "blocked",
      detail: "https is required",
      bytes: null,
      mediaType: null,
      consumedBytes: 0,
    };
  }
  let consumedBytes = 0;
  let reader = null;
  try {
    const headers = accept === null ? undefined : { accept };
    const response = await fetch(url, {
      method: "GET",
      headers,
      credentials: "omit",
      redirect: "error",
      mode: "cors",
    });
    if (!response.ok) {
      await response.body?.cancel();
      return {
        outcome: "failed",
        detail: `the server answered HTTP ${response.status}`,
        bytes: null,
        mediaType: null,
        consumedBytes,
      };
    }
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maxBytes) {
      await response.body?.cancel();
      return {
        outcome: "blocked",
        detail: `the response is larger than the ${maxBytes} byte remaining limit`,
        bytes: null,
        mediaType: null,
        consumedBytes,
      };
    }
    if (!response.body) {
      return {
        outcome: "blocked",
        detail: "the response body is not available as a bounded stream",
        bytes: null,
        mediaType: null,
        consumedBytes,
      };
    }
    reader = response.body.getReader();
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      consumedBytes += value.byteLength;
      if (consumedBytes > maxBytes) {
        await reader.cancel();
        return {
          outcome: "blocked",
          detail: `the response is larger than the ${maxBytes} byte remaining limit`,
          bytes: null,
          mediaType: null,
          consumedBytes,
        };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(consumedBytes);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const mediaType = response.headers.get("content-type")
      ?.split(";", 1)[0].trim().toLowerCase() || null;
    return {
      outcome: "fetched",
      detail: `${bytes.byteLength} bytes`,
      bytes,
      mediaType,
      consumedBytes,
    };
  } catch (error) {
    try { await reader?.cancel(); } catch (_) {}
    // Redirect refusal, CORS refusal, CSP, mixed content, and transport
    // failures are deliberately indistinguishable to browser script.
    return {
      outcome: "failed",
      detail: `${error}`,
      bytes: null,
      mediaType: null,
      consumedBytes,
    };
  }
}
export function softBindingHost(url) {
  return new URL(url).hostname;
}
export async function fetchSoftBinding(url, method, contentType, accept, body, maxBytes) {
  const headers = { accept };
  if (contentType !== null) headers["content-type"] = contentType;
  const response = await fetch(url, {
    method,
    headers,
    body: body === null ? undefined : body,
    credentials: "omit",
    redirect: "error",
    mode: "cors",
  });
  if (!response.ok) throw new Error("soft-binding request failed");
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length > maxBytes) {
    throw new Error("soft-binding response exceeds limit");
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) throw new Error("soft-binding response exceeds limit");
    return { finalUrl: response.url, bytes };
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("soft-binding response exceeds limit");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { finalUrl: response.url, bytes };
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
    #[wasm_bindgen(js_name = fetchOnlineResource)]
    fn fetch_online_resource(url: &str, max_bytes: usize, accept: JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_name = softBindingHost)]
    fn soft_binding_host(url: &str) -> String;
    #[wasm_bindgen(js_name = fetchSoftBinding)]
    fn fetch_soft_binding(
        url: &str,
        method: &str,
        content_type: JsValue,
        accept: &str,
        body: JsValue,
        max_bytes: usize,
    ) -> js_sys::Promise;
}

const ONLINE_MAX_REQUESTS: usize = 16;
const ONLINE_MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;
const ONLINE_MAX_DID_BYTES: usize = 256 * 1024;

enum BrowserResource {
    CallerSupplied {
        bytes: Vec<u8>,
        media_type: Option<String>,
    },
    Fetched {
        bytes: Vec<u8>,
        media_type: Option<String>,
    },
    CallerUnavailable,
    Unavailable,
    NotAttempted,
}

#[derive(Default)]
struct BrowserResources {
    entries: HashMap<String, BrowserResource>,
}

impl BrowserResources {
    fn from_evidence(mut evidence: ValidatedExternalData) -> Self {
        let mut resources = Self::default();
        for uri in evidence.unreachable {
            resources
                .entries
                .entry(uri)
                .or_insert(BrowserResource::CallerUnavailable);
        }
        for (uri, bytes) in evidence.data {
            let media_type = evidence.media_types.remove(&uri);
            resources
                .entries
                .insert(uri, BrowserResource::CallerSupplied { bytes, media_type });
        }
        resources
    }

    fn contains(&self, uri: &str) -> bool {
        self.entries.contains_key(uri)
    }

    fn is_caller_supplied(&self, uri: &str) -> bool {
        matches!(
            self.entries.get(uri),
            Some(BrowserResource::CallerSupplied { .. })
        )
    }

    fn is_caller_evidence(&self, uri: &str) -> bool {
        matches!(
            self.entries.get(uri),
            Some(BrowserResource::CallerSupplied { .. } | BrowserResource::CallerUnavailable)
        )
    }

    fn bytes(&self, uri: &str) -> Option<&[u8]> {
        match self.entries.get(uri) {
            Some(
                BrowserResource::CallerSupplied { bytes, .. }
                | BrowserResource::Fetched { bytes, .. },
            ) => Some(bytes),
            Some(
                BrowserResource::CallerUnavailable
                | BrowserResource::Unavailable
                | BrowserResource::NotAttempted,
            )
            | None => None,
        }
    }
}

impl ExternalResources for BrowserResources {
    fn resolve(&self, url: &str) -> ExternalResource<'_> {
        match self.entries.get(url) {
            Some(
                BrowserResource::CallerSupplied { bytes, media_type }
                | BrowserResource::Fetched { bytes, media_type },
            ) => ExternalResource::Retrieved {
                bytes,
                media_type: media_type.as_deref(),
            },
            Some(BrowserResource::CallerUnavailable | BrowserResource::Unavailable) => {
                ExternalResource::Unavailable
            }
            Some(BrowserResource::NotAttempted) | None => ExternalResource::NotAttempted,
        }
    }
}

struct BrowserOnlineState {
    resources: BrowserResources,
    requests: Vec<NetworkRequest>,
    attempted: HashSet<String>,
    attempts_left: usize,
    evidence_bytes_left: usize,
}

impl BrowserOnlineState {
    fn new(evidence: ValidatedExternalData) -> Self {
        Self {
            resources: BrowserResources::from_evidence(evidence),
            requests: Vec::new(),
            attempted: HashSet::new(),
            attempts_left: ONLINE_MAX_REQUESTS,
            evidence_bytes_left: ONLINE_MAX_EVIDENCE_BYTES,
        }
    }

    fn debit_evidence(&mut self, consumed: usize) {
        self.evidence_bytes_left = self.evidence_bytes_left.saturating_sub(consumed);
    }

    async fn ensure_resource(
        &mut self,
        uri: &str,
        purpose: &str,
        per_body_limit: usize,
        accept: Option<&str>,
    ) -> Result<Option<usize>, JsValue> {
        if self.resources.contains(uri) || self.attempted.contains(uri) {
            return Ok(None);
        }
        self.attempted.insert(uri.to_string());
        if self.attempts_left == 0 {
            self.resources
                .entries
                .insert(uri.to_string(), BrowserResource::NotAttempted);
            self.requests.push(NetworkRequest {
                purpose: purpose.to_string(),
                url: uri.to_string(),
                outcome: "skipped".to_string(),
                detail: format!(
                    "the {ONLINE_MAX_REQUESTS} request budget for one verification is spent"
                ),
            });
            return Ok(Some(self.requests.len() - 1));
        }
        self.attempts_left -= 1;
        if self.evidence_bytes_left == 0 {
            self.resources
                .entries
                .insert(uri.to_string(), BrowserResource::NotAttempted);
            self.requests.push(NetworkRequest {
                purpose: purpose.to_string(),
                url: uri.to_string(),
                outcome: "blocked".to_string(),
                detail: format!(
                    "the {ONLINE_MAX_EVIDENCE_BYTES} byte cumulative evidence budget is spent"
                ),
            });
            return Ok(Some(self.requests.len() - 1));
        }

        let limit = per_body_limit.min(self.evidence_bytes_left);
        let accept = accept.map(JsValue::from_str).unwrap_or(JsValue::NULL);
        let response = JsFuture::from(fetch_online_resource(uri, limit, accept))
            .await
            .map_err(|_| {
                js_error(
                    "verification_error",
                    "browser network request failed".to_string(),
                )
            })?;
        let outcome = reflected_string(&response, "outcome")?;
        let detail = reflected_string(&response, "detail")?;
        let consumed = reflected_usize(&response, "consumedBytes")?;
        self.debit_evidence(consumed);
        let request_index = self.requests.len();
        self.requests.push(NetworkRequest {
            purpose: purpose.to_string(),
            url: uri.to_string(),
            outcome: outcome.clone(),
            detail,
        });
        if outcome == "fetched" {
            let bytes_value = js_sys::Reflect::get(&response, &"bytes".into())?;
            let bytes = js_sys::Uint8Array::new(&bytes_value).to_vec();
            let media_type = js_sys::Reflect::get(&response, &"mediaType".into())?.as_string();
            self.resources.entries.insert(
                uri.to_string(),
                BrowserResource::Fetched { bytes, media_type },
            );
        } else {
            let attempted = uri.starts_with("https://");
            self.resources.entries.insert(
                uri.to_string(),
                if attempted {
                    BrowserResource::Unavailable
                } else {
                    BrowserResource::NotAttempted
                },
            );
        }
        Ok(Some(request_index))
    }

    fn mark_failed(&mut self, request: Option<usize>, detail: String) {
        if let Some(request) = request.and_then(|index| self.requests.get_mut(index)) {
            request.outcome = "failed".to_string();
            request.detail = detail;
        }
    }
}

#[cfg(test)]
mod online_state_tests {
    use super::*;

    #[test]
    fn failed_stream_bytes_spend_the_shared_evidence_budget() {
        let mut state = BrowserOnlineState::new(ValidatedExternalData::default());
        state.debit_evidence(ONLINE_MAX_EVIDENCE_BYTES - 1);
        assert_eq!(state.evidence_bytes_left, 1);

        // A final chunk may cross the remaining bound. Saturation closes the
        // budget instead of allowing another response after a failed read.
        state.debit_evidence(8 * 1024);
        assert_eq!(state.evidence_bytes_left, 0);
    }

    #[test]
    fn caller_body_overrides_unreachable_state_without_copying_provider_bytes() {
        let uri = "https://evidence.example/assertion".to_string();
        let evidence = ValidatedExternalData {
            data: HashMap::from([(uri.clone(), vec![1, 2, 3])]),
            media_types: HashMap::from([(uri.clone(), "application/cbor".to_string())]),
            unreachable: vec![uri.clone()],
        };
        let resources = BrowserResources::from_evidence(evidence);
        assert!(resources.is_caller_supplied(&uri));
        match resources.resolve(&uri) {
            ExternalResource::Retrieved { bytes, media_type } => {
                assert_eq!(bytes, [1, 2, 3]);
                assert_eq!(media_type, Some("application/cbor"));
            }
            ExternalResource::NotAttempted | ExternalResource::Unavailable => {
                panic!("caller bytes must be authoritative")
            }
        }
    }

    #[test]
    fn caller_unreachable_is_authoritative_without_becoming_a_fresh_need() {
        let uri = "https://evidence.example/terminal.c2pa".to_string();
        let resources = BrowserResources::from_evidence(ValidatedExternalData {
            data: HashMap::new(),
            media_types: HashMap::new(),
            unreachable: vec![uri.clone()],
        });
        assert!(resources.is_caller_evidence(&uri));
        assert!(matches!(
            resources.resolve(&uri),
            ExternalResource::Unavailable
        ));
    }
}

fn reflected_string(value: &JsValue, field: &str) -> Result<String, JsValue> {
    js_sys::Reflect::get(value, &JsValue::from_str(field))?
        .as_string()
        .ok_or_else(|| {
            js_error(
                "serialization_error",
                format!("browser transport returned no {field}"),
            )
        })
}

fn reflected_usize(value: &JsValue, field: &str) -> Result<usize, JsValue> {
    let value = js_sys::Reflect::get(value, &JsValue::from_str(field))?
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= usize::MAX as f64)
        .ok_or_else(|| {
            js_error(
                "serialization_error",
                format!("browser transport returned invalid {field}"),
            )
        })?;
    Ok(value as usize)
}

struct BrowserSoftBindingRequest {
    method: &'static str,
    url: String,
    content_type: Option<String>,
    accept: &'static str,
    body: Option<Vec<u8>>,
    max_bytes: usize,
}

async fn browser_soft_binding_fetch(
    request: BrowserSoftBindingRequest,
    allow_private_networks: bool,
) -> Result<(String, Vec<u8>), JsValue> {
    require_browser_destination(&request.url, allow_private_networks)?;
    let content_type = request
        .content_type
        .as_deref()
        .map(JsValue::from_str)
        .unwrap_or(JsValue::NULL);
    let body = request
        .body
        .as_deref()
        .map(|bytes| js_sys::Uint8Array::from(bytes).into())
        .unwrap_or(JsValue::NULL);
    let response = JsFuture::from(fetch_soft_binding(
        &request.url,
        request.method,
        content_type,
        request.accept,
        body,
        request.max_bytes,
    ))
    .await
    .map_err(|_| {
        js_error(
            "verification_error",
            "soft-binding network request failed".to_string(),
        )
    })?;
    let final_url = js_sys::Reflect::get(&response, &"finalUrl".into())?
        .as_string()
        .ok_or_else(|| {
            js_error(
                "serialization_error",
                "soft-binding transport returned no final URL".to_string(),
            )
        })?;
    let bytes =
        js_sys::Uint8Array::new(&js_sys::Reflect::get(&response, &"bytes".into())?).to_vec();
    Ok((final_url, bytes))
}

fn copy_soft_binding_request(
    request: encypher_c2pa::SoftBindingFetchRequest<'_>,
) -> BrowserSoftBindingRequest {
    BrowserSoftBindingRequest {
        method: match request.method {
            SoftBindingHttpMethod::Get => "GET",
            SoftBindingHttpMethod::Post => "POST",
        },
        url: request.url.to_owned(),
        content_type: request.content_type.map(str::to_owned),
        accept: request.accept,
        body: request.body.map(<[u8]>::to_vec),
        max_bytes: request.max_response_bytes,
    }
}

fn require_browser_destination(url: &str, allow_private_networks: bool) -> Result<(), JsValue> {
    if allow_private_networks {
        return Ok(());
    }
    if !url.starts_with("https://") {
        return Err(js_error(
            "verification_error",
            "soft-binding browser requests require HTTPS".to_string(),
        ));
    }
    let host = soft_binding_host(url);
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(&host);
    let address: IpAddr = host.parse().map_err(|_| {
        js_error(
            "verification_error",
            "soft-binding browser requests to DNS hosts require allow_private_networks=true"
                .to_string(),
        )
    })?;
    if public_literal_ip(address) {
        Ok(())
    } else {
        Err(js_error(
            "verification_error",
            "soft-binding destination is blocked by network policy".to_string(),
        ))
    }
}

fn public_literal_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_ipv4(address),
        IpAddr::V6(address) => public_ipv6(address),
    }
}

fn public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_documentation()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && matches!(b, 18 | 19)))
}

fn public_ipv6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    if let Some(mapped) = address.to_ipv4_mapped() {
        return public_ipv4(mapped);
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (octets[0] & 0xfe) == 0xfc
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0xc0)
        || (octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8)
        || (octets[..8] == [0x01, 0x00, 0, 0, 0, 0, 0, 0]))
}

/// Resolve soft bindings with Fetch while keeping protocol state in Rust.
#[wasm_bindgen(js_name = resolveSoftBinding)]
pub async fn resolve_soft_binding_js(
    asset: Vec<u8>,
    mime_type: String,
    service_root: String,
    query: JsValue,
    options: Option<JsValue>,
    resolver_options: JsValue,
) -> Result<JsValue, JsValue> {
    let query: SoftBindingQuery = serde_wasm_bindgen::from_value(query)
        .map_err(|error| js_error("invalid_soft_binding_query", error.to_string()))?;
    let mut verify_options: VerifyOptions = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if verify_options.validation_time.is_none() {
        verify_options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    let resolver_options: SoftBindingResolverOptions =
        serde_wasm_bindgen::from_value(resolver_options).map_err(|error| {
            js_error("invalid_soft_binding_resolver_options", error.to_string())
        })?;
    let mut session = SoftBindingResolverSession::new(
        &asset,
        &mime_type,
        &service_root,
        &query,
        &verify_options,
        &resolver_options,
    )
    .map_err(|error| js_error(error.code(), error.to_string()))?;
    while let Some(request) = session.next_request() {
        let request = copy_soft_binding_request(request);
        let (final_url, bytes) =
            browser_soft_binding_fetch(request, resolver_options.allow_private_networks).await?;
        session
            .accept_response(&final_url, bytes)
            .map_err(|error| js_error(error.code(), error.to_string()))?;
    }
    session
        .finish()
        .map_err(|error| js_error(error.code(), error.to_string()))?
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

/// Submit a receipt for a repository-reported verification result.
#[wasm_bindgen(js_name = requestSoftBindingReceiptVerification)]
pub async fn request_soft_binding_receipt_verification_js(
    service_root: String,
    manifest_id: String,
    receipt: JsValue,
    options: Option<JsValue>,
    resolver_options: JsValue,
) -> Result<JsValue, JsValue> {
    let receipt: serde_json::Value = serde_wasm_bindgen::from_value(receipt)
        .map_err(|error| js_error("invalid_soft_binding_receipt", error.to_string()))?;
    let mut verify_options: VerifyOptions = match options {
        None => VerifyOptions::default(),
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions::default(),
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if verify_options.validation_time.is_none() {
        verify_options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    let resolver_options: SoftBindingResolverOptions =
        serde_wasm_bindgen::from_value(resolver_options).map_err(|error| {
            js_error("invalid_soft_binding_resolver_options", error.to_string())
        })?;
    let mut session = SoftBindingReceiptVerificationSession::new(
        &service_root,
        &manifest_id,
        receipt,
        &verify_options,
        &resolver_options,
    )
    .map_err(|error| js_error(error.code(), error.to_string()))?;
    while let Some(request) = session.next_request() {
        let request = copy_soft_binding_request(request);
        let (final_url, bytes) =
            browser_soft_binding_fetch(request, resolver_options.allow_private_networks).await?;
        session
            .accept_response(&final_url, bytes)
            .map_err(|error| js_error(error.code(), error.to_string()))?;
    }
    session
        .finish()
        .map_err(|error| js_error(error.code(), error.to_string()))?
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
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
    post_failure_telemetry(mime_type, &result, &options);
    let report = result.map_err(|error| js_error(error.code(), error.to_string()))?;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

#[wasm_bindgen(typescript_custom_section)]
const LOCAL_EVIDENCE_TS: &str = r#"
/** Result of `localEvidence`. `report` is exactly what `verify` returns. */
export interface LocalEvidence {
  report: any;
  manifest_store: Uint8Array | null;
  manifest_store_sha256: string | null;
  asset_sha256: string;
  hard_binding: {
    algorithm: string | null;
    status: "match" | "mismatch" | "unknown";
  };
  /** Label of the store's active manifest, or null without a readable store. */
  active_manifest_label: string | null;
  /** Every manifest of the store with its expanded-domain SHA-256 (hex). */
  store_manifests: { label: string; sha256: string }[];
}
"#;

/// Verify an asset exactly as `verify` does and return what a service needs to
/// re-verify the same manifest store without the asset.
///
/// The result carries the `verify` report, the embedded manifest-store bytes
/// that report was computed over (a `Uint8Array`, or `null` when the asset has
/// no embedded store), their SHA-256, the SHA-256 of the asset, and the active
/// manifest's hard-binding label with this verification's verdict on it. One
/// verification pass produces all of it. Like `verify`, this never touches
/// the network apart from opt-in failure telemetry.
#[wasm_bindgen(js_name = localEvidence, unchecked_return_type = "LocalEvidence")]
pub fn local_evidence_js(
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
    let evidence = match local_evidence_with_options(asset, mime_type, &options) {
        Ok(evidence) => evidence,
        Err(error) => {
            let thrown = js_error(error.code(), error.to_string());
            post_failure_telemetry(mime_type, &Err(error), &options);
            return Err(thrown);
        }
    };
    // JSON-compatible like `verify`, except that `manifest_store` stays a
    // `Uint8Array` instead of an array of numbers.
    let value = evidence.serialize(
        &serde_wasm_bindgen::Serializer::json_compatible().serialize_bytes_as_arrays(false),
    );
    post_failure_telemetry(mime_type, &Ok(evidence.report), &options);
    value.map_err(|error| js_error("serialization_error", error.to_string()))
}

fn post_failure_telemetry(
    mime_type: &str,
    result: &Result<VerificationReport, Error>,
    options: &VerifyOptions,
) {
    if let Some(event) = validation_failure_telemetry(mime_type, result, &options.telemetry) {
        if let Ok(payload) = event.to_json() {
            post_validation_failure(options.telemetry.endpoint(), &payload);
        }
    }
}

fn push_unique_need(needs: &mut Vec<serde_json::Value>, need: serde_json::Value) {
    if !needs.contains(&need) {
        needs.push(need);
    }
}

async fn verify_online_v25(
    asset: Vec<u8>,
    mime_type: String,
    mut options: VerifyOptions,
) -> Result<JsValue, JsValue> {
    let evidence = options
        .validate_with_external_data()
        .map_err(|error| js_error(error.code(), error.to_string()))?;
    let mut plan = locate_external_resources(asset, &mime_type, &options, GraphLimits::default())
        .map_err(|error| js_error(error.code(), error.to_string()))?;
    let terminal_uri = (!plan.manifest_store_present)
        .then(|| {
            plan.resources
                .iter()
                .find(|request| request.kind == ExternalResourceKind::SegmentManifestStore)
                .map(|request| request.uri.clone())
        })
        .flatten();
    let mut online = BrowserOnlineState::new(evidence);
    // BrowserResources owns the caller evidence decoded during option
    // validation, so final verification reads the same bytes without another
    // base64 decode or provider allocation.
    options.external_data = None;
    options.external_data_media_types = None;
    options.external_data_unreachable = None;
    let mut discovered_needs = Vec::new();

    while !plan.resources.is_empty() {
        let frontier = plan.resources.clone();
        for request in &frontier {
            let terminal = terminal_uri.as_deref() == Some(request.uri.as_str());
            if !online.resources.is_caller_evidence(&request.uri) {
                let need = if terminal {
                    serde_json::json!({
                        "kind": "remote_manifest",
                        "uri": request.uri,
                    })
                } else if request.kind == ExternalResourceKind::SegmentManifestStore {
                    serde_json::json!({
                        "kind": "external_data",
                        "uri": request.uri,
                        "assertion_label": "c2pa.hash.segment",
                    })
                } else {
                    // ExternalResourcePlan deliberately exposes opaque URI
                    // identity without guessing which assertion schema found
                    // it. Final verification supplies exact labels for any
                    // unresolved resource.
                    serde_json::json!({
                        "kind": "external_data",
                        "uri": request.uri,
                    })
                };
                push_unique_need(&mut discovered_needs, need);
            }
            let purpose = if terminal {
                "remote_manifest"
            } else {
                "external_data"
            };
            let accept = (request.kind == ExternalResourceKind::SegmentManifestStore)
                .then_some("application/c2pa");
            online
                .ensure_resource(&request.uri, purpose, ONLINE_MAX_EVIDENCE_BYTES, accept)
                .await?;
        }
        plan.continue_with(&online.resources)
            .map_err(|error| js_error(error.code(), error.to_string()))?;
    }

    let pinned_dids: HashSet<String> = options
        .cawg_did_documents
        .as_ref()
        .map(|documents| documents.keys().cloned().collect())
        .unwrap_or_default();
    let mut fetched_dids = HashMap::new();
    for request in plan.did_documents() {
        if pinned_dids.contains(&request.did) {
            continue;
        }
        let caller_supplied = online.resources.is_caller_supplied(&request.url);
        if !caller_supplied {
            push_unique_need(
                &mut discovered_needs,
                serde_json::json!({
                    "kind": "did_document",
                    "did": request.did,
                    "url": request.url,
                }),
            );
        }
        let network_request = online
            .ensure_resource(
                &request.url,
                "did_document",
                ONLINE_MAX_DID_BYTES,
                Some("application/did+json, application/json"),
            )
            .await?;
        let Some(bytes) = online.resources.bytes(&request.url) else {
            continue;
        };
        if bytes.len() > ONLINE_MAX_DID_BYTES {
            online.mark_failed(
                network_request,
                format!("the DID document is larger than the {ONLINE_MAX_DID_BYTES} byte limit"),
            );
            continue;
        }
        match serde_json::from_slice(bytes) {
            Ok(document) => {
                fetched_dids.insert(request.did.clone(), document);
            }
            Err(error) => online.mark_failed(
                network_request,
                format!("the DID document is not JSON: {error}"),
            ),
        }
    }
    if !fetched_dids.is_empty() {
        let pinned = options.cawg_did_documents.get_or_insert_with(HashMap::new);
        for (did, document) in fetched_dids {
            pinned.entry(did).or_insert(document);
        }
    }

    let graph_inputs = GraphInputs {
        external: Some(&online.resources),
        limits: GraphLimits::default(),
    };
    let result = verify_with_graph_inputs(plan.asset(), &mime_type, &options, graph_inputs);
    let mut report = result.map_err(|error| js_error(error.code(), error.to_string()))?;
    let mut needed = report.network.needed;
    for need in discovered_needs {
        push_unique_need(&mut needed, need);
    }
    for need in &needed {
        if need.get("kind").and_then(serde_json::Value::as_str) != Some("ocsp") {
            continue;
        }
        let purpose = format!(
            "ocsp.{}",
            need.get("purpose")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("claim_signer")
        );
        let Some(url) = need
            .get("responder_url")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if !online
            .requests
            .iter()
            .any(|request| request.purpose == purpose && request.url == url)
        {
            online.requests.push(NetworkRequest {
                purpose,
                url: url.to_string(),
                outcome: "skipped".to_string(),
                detail: "a browser cannot make an OCSP request".to_string(),
            });
        }
    }
    report.network = NetworkReport {
        enabled: true,
        needed,
        requests: online.requests,
    };
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| js_error("serialization_error", error.to_string()))
}

/// Verify an asset, fetching what it references.
///
/// Under the exact C2PA 2.5 policy, parse-only discovery resolves the complete
/// external-resource frontier before one authoritative verification. Older
/// policies retain their established two-pass behavior.
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
    if options.spec_version.as_deref() == Some("2.5") {
        return verify_online_v25(asset, mime_type, options).await;
    }

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
    // Exact 2.5 routes external bytes through the owned provider above.
    // Legacy policies retain their published two-pass report behavior.

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
    post_failure_telemetry(mime_type, &result, &options);
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
    post_failure_telemetry(mime_type, &result, &options);
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
///
/// `options.stream_presentation_times` takes one trusted RFC 3339 instant per
/// segment, in order, for checking each session-key segment's key window.
/// It is never filled from the browser clock: when absent, every segment is
/// assessed at `validation_time`, which defaults to `Date` captured here.
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

/// Verify caller-parsed Enhanced RTMP events in exact transmission order.
///
/// The input carries bilateral capsEx, objectEncoding and the ordered events.
/// Aggregate timestamps must already be normalized and Multitrack events must
/// contain only the selected packet.
#[wasm_bindgen(js_name = verifyErtmp)]
pub fn verify_ertmp_js(input: JsValue, options: Option<JsValue>) -> Result<JsValue, JsValue> {
    let input: ErtmpInput = serde_wasm_bindgen::from_value(input)
        .map_err(|error| js_error("invalid_ertmp_input", error.to_string()))?;
    let mut options = match options {
        None => VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        },
        Some(value) if value.is_null() || value.is_undefined() => VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        },
        Some(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| js_error("invalid_options", error.to_string()))?,
    };
    if options.validation_time.is_none() {
        options.validation_time = js_sys::Date::new_0().to_iso_string().as_string();
    }
    let report = verify_ertmp_with_options(&input, &options)
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
