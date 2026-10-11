// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use encypher_c2pa::{
    binding_target, request_soft_binding_receipt_verification, resolve_soft_binding,
    set_telemetry_enabled, telemetry_preference, verify_ertmp_with_options,
    verify_fragmented_with_options, verify_manifest_store_only, verify_stream_with_options,
    verify_with_caller_verified_binding, verify_with_manifest_store, verify_with_options,
    CallerBindingEvidence, CallerBindingVerdict, CawgStoreHost, ErtmpInput, ManifestBindingTarget,
    SoftBindingQuery, SoftBindingResolverOptions, StreamEncapsulation, StreamMethod, VerifyOptions,
};
use serde_json::json;

/// Parse and resolve verification options without reading an asset.
///
/// The result is `{"ok":true}` or
/// `{"ok":false,"error":{"code":...,"message":...}}`. The caller owns the
/// returned string and must release it with [`encypher_c2pa_free_string`].
/// `options_json` may be null, which validates the default options.
///
/// # Safety
/// A non-null `options_json` must point to a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_validate_options(
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let options = if options_json.is_null() {
            VerifyOptions::default()
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };

        match options.validate() {
            Ok(()) => json!({ "ok": true }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "option validation aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Verify one in-memory asset and return an allocated UTF-8 JSON envelope.
///
/// The result is `{"ok":true,"report":...}` or
/// `{"ok":false,"error":{"code":...,"message":...}}`. The caller owns the
/// returned string and must release it with [`encypher_c2pa_free_string`].
/// `options_json` may be null or a JSON object matching `VerifyOptions`.
///
/// # Safety
/// `asset` must point to `asset_len` readable bytes. `mime_type` and a non-null
/// `options_json` must point to NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify(
    asset: *const u8,
    asset_len: usize,
    mime_type: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract above guarantees these pointer ranges.
        let bytes = if asset_len == 0 {
            &[]
        } else if asset.is_null() {
            return error_json(
                "invalid_argument",
                "asset is null but asset_len is non-zero",
            );
        } else {
            unsafe { slice::from_raw_parts(asset, asset_len) }
        };
        if mime_type.is_null() {
            return error_json("invalid_argument", "mime_type is null");
        }
        // SAFETY: The caller guarantees a NUL-terminated string.
        let mime = match unsafe { CStr::from_ptr(mime_type) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                return error_json(
                    "invalid_argument",
                    &format!("mime_type is not UTF-8: {error}"),
                )
            }
        };
        let options = if options_json.is_null() {
            VerifyOptions::default()
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };

        match verify_with_options(bytes, mime, &options) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "verification aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Verify one in-memory asset against a manifest store supplied separately.
///
/// Use this when the C2PA Manifest Store does not travel inside the asset: a
/// `.c2pa` sidecar, or a store the caller fetched from the URI the asset
/// declares. This library never fetches it. The envelope and ownership rules
/// match [`encypher_c2pa_verify`].
///
/// # Safety
/// `asset` must point to `asset_len` readable bytes and `manifest_store` to
/// `manifest_store_len` readable bytes. String pointers follow
/// [`encypher_c2pa_verify`].
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify_with_manifest_store(
    asset: *const u8,
    asset_len: usize,
    manifest_store: *const u8,
    manifest_store_len: usize,
    mime_type: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = if asset_len == 0 {
            &[]
        } else if asset.is_null() {
            return error_json(
                "invalid_argument",
                "asset is null but asset_len is non-zero",
            );
        } else {
            // SAFETY: The caller contract above guarantees this pointer range.
            unsafe { slice::from_raw_parts(asset, asset_len) }
        };
        if manifest_store.is_null() || manifest_store_len == 0 {
            return error_json("invalid_argument", "manifest_store is null or empty");
        }
        // SAFETY: The caller contract above guarantees this pointer range.
        let store = unsafe { slice::from_raw_parts(manifest_store, manifest_store_len) };
        if mime_type.is_null() {
            return error_json("invalid_argument", "mime_type is null");
        }
        // SAFETY: The caller guarantees a NUL-terminated string.
        let mime = match unsafe { CStr::from_ptr(mime_type) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                return error_json(
                    "invalid_argument",
                    &format!("mime_type is not UTF-8: {error}"),
                )
            }
        };
        let options = if options_json.is_null() {
            VerifyOptions::default()
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };

        match verify_with_manifest_store(bytes, store, mime, &options) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "verification aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Validate a manifest store without claiming that any asset content matched.
///
/// # Safety
/// `manifest_store` must point to `manifest_store_len` readable bytes.
/// `options_json` follows [`encypher_c2pa_verify`].
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify_manifest_store_only(
    manifest_store: *const u8,
    manifest_store_len: usize,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if manifest_store.is_null() || manifest_store_len == 0 {
            return error_json("invalid_argument", "manifest_store is null or empty");
        }
        // SAFETY: The caller contract guarantees this pointer range.
        let store = unsafe { slice::from_raw_parts(manifest_store, manifest_store_len) };
        // SAFETY: The caller contract guarantees a null or NUL-terminated argument.
        let options = match unsafe { optional_str(options_json) } {
            Ok(None) => VerifyOptions::default(),
            Ok(Some(raw)) => match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            },
            Err(error) => return error_json("invalid_options", &error),
        };
        match verify_manifest_store_only(store, &options) {
            Ok(report) => json!({ "ok": true, "result": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));
    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "store-only validation aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Derive the exact hard-binding target a caller must independently compare.
///
/// # Safety
/// Byte and string pointers follow [`encypher_c2pa_verify_manifest_store_only`].
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_binding_target(
    manifest_store: *const u8,
    manifest_store_len: usize,
    hostless: bool,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if manifest_store.is_null() || manifest_store_len == 0 {
            return error_json("invalid_argument", "manifest_store is null or empty");
        }
        let store = unsafe { slice::from_raw_parts(manifest_store, manifest_store_len) };
        let options = match unsafe { optional_str(options_json) } {
            Ok(None) => VerifyOptions::default(),
            Ok(Some(raw)) => match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            },
            Err(error) => return error_json("invalid_options", &error),
        };
        match binding_target(
            store,
            if hostless {
                CawgStoreHost::HostLess
            } else {
                CawgStoreHost::Asset
            },
            &options,
        ) {
            Ok(target) => json!({ "ok": true, "target": target }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));
    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "binding-target derivation aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Validate a store using a content-comparison verdict made by the caller.
///
/// # Safety
/// Byte and string pointers follow [`encypher_c2pa_verify_manifest_store_only`].
/// `target_json`, `verdict_json`, `engine`, and `content_mime` are required.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn encypher_c2pa_verify_with_caller_binding(
    manifest_store: *const u8,
    manifest_store_len: usize,
    content_mime: *const c_char,
    hostless: bool,
    target_json: *const c_char,
    verdict_json: *const c_char,
    engine: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if manifest_store.is_null() || manifest_store_len == 0 {
            return error_json("invalid_argument", "manifest_store is null or empty");
        }
        let store = unsafe { slice::from_raw_parts(manifest_store, manifest_store_len) };
        let content_mime = match unsafe { required_str(content_mime, "content_mime") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let target_raw = match unsafe { required_str(target_json, "target_json") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let verdict_raw = match unsafe { required_str(verdict_json, "verdict_json") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let engine = match unsafe { required_str(engine, "engine") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let target: ManifestBindingTarget = match serde_json::from_str(target_raw) {
            Ok(value) => value,
            Err(error) => return error_json("invalid_binding_target", &error.to_string()),
        };
        let verdict: CallerBindingVerdict = match serde_json::from_str(verdict_raw) {
            Ok(value) => value,
            Err(error) => return error_json("invalid_binding_verdict", &error.to_string()),
        };
        let evidence = match CallerBindingEvidence::new(target, verdict, engine) {
            Ok(value) => value,
            Err(error) => return error_json(error.code(), &error.to_string()),
        };
        let options = match unsafe { optional_str(options_json) } {
            Ok(None) => VerifyOptions::default(),
            Ok(Some(raw)) => match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            },
            Err(error) => return error_json("invalid_options", &error),
        };
        match verify_with_caller_verified_binding(
            store,
            content_mime,
            if hostless {
                CawgStoreHost::HostLess
            } else {
                CawgStoreHost::Asset
            },
            &evidence,
            &options,
        ) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));
    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "caller-binding validation aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Verify a fragmented ISO BMFF stream and return an allocated UTF-8 JSON envelope.
///
/// `asset` is the initialization segment carrying the manifest. `fragments`
/// and `fragment_lengths` are parallel arrays with `fragment_count` entries.
///
/// # Safety
/// All non-empty byte ranges must be readable. When `fragment_count` is
/// non-zero, both arrays must be non-null and each non-empty fragment pointer
/// must be non-null. String pointers follow [`encypher_c2pa_verify`].
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify_fragmented(
    asset: *const u8,
    asset_len: usize,
    fragments: *const *const u8,
    fragment_lengths: *const usize,
    fragment_count: usize,
    mime_type: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = if asset_len == 0 {
            &[]
        } else if asset.is_null() {
            return error_json(
                "invalid_argument",
                "asset is null but asset_len is non-zero",
            );
        } else {
            // SAFETY: The caller contract guarantees this pointer range.
            unsafe { slice::from_raw_parts(asset, asset_len) }
        };
        if fragment_count != 0 && (fragments.is_null() || fragment_lengths.is_null()) {
            return error_json(
                "invalid_argument",
                "fragment arrays are null but fragment_count is non-zero",
            );
        }
        let pointers = if fragment_count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller contract guarantees both parallel arrays.
            unsafe { slice::from_raw_parts(fragments, fragment_count) }
        };
        let lengths = if fragment_count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller contract guarantees both parallel arrays.
            unsafe { slice::from_raw_parts(fragment_lengths, fragment_count) }
        };
        let mut fragment_refs = Vec::with_capacity(fragment_count);
        for (&pointer, &length) in pointers.iter().zip(lengths) {
            if length == 0 {
                fragment_refs.push(&[][..]);
            } else if pointer.is_null() {
                return error_json(
                    "invalid_argument",
                    "fragment is null but its length is non-zero",
                );
            } else {
                // SAFETY: The caller contract guarantees this fragment range.
                fragment_refs.push(unsafe { slice::from_raw_parts(pointer, length) });
            }
        }
        if mime_type.is_null() {
            return error_json("invalid_argument", "mime_type is null");
        }
        // SAFETY: The caller guarantees a NUL-terminated string.
        let mime = match unsafe { CStr::from_ptr(mime_type) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                return error_json(
                    "invalid_argument",
                    &format!("mime_type is not UTF-8: {error}"),
                )
            }
        };
        let options = if options_json.is_null() {
            VerifyOptions::default()
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };

        match verify_fragmented_with_options(bytes, &fragment_refs, mime, &options) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "verification aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Verify a declared fMP4/CMAF stream and return an allocated UTF-8 JSON envelope.
///
/// `asset` is the initialization segment; `segments` and `segment_lengths` are
/// parallel arrays with `segment_count` entries, in playback order.
/// `encapsulation` is `"fMP4"` or `"CMAF"`; `method` is
/// `"verifiable-segment-info"` or `"per-segment"`. Both are matched ASCII
/// case-insensitively, and both may be null to take the defaults (`"fMP4"`,
/// `"verifiable-segment-info"`).
///
/// The report is the stream report, not the single-asset one: it carries a
/// top-level `integrity`, the init manifest's report under `stream`, and, for
/// a per-segment stream, `segments` plus `chain_valid`.
///
/// # Safety
/// All non-empty byte ranges must be readable. When `segment_count` is
/// non-zero, both arrays must be non-null and each non-empty segment pointer
/// must be non-null. String pointers follow [`encypher_c2pa_verify`].
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify_stream(
    asset: *const u8,
    asset_len: usize,
    segments: *const *const u8,
    segment_lengths: *const usize,
    segment_count: usize,
    mime_type: *const c_char,
    encapsulation: *const c_char,
    method: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = if asset_len == 0 {
            &[]
        } else if asset.is_null() {
            return error_json(
                "invalid_argument",
                "asset is null but asset_len is non-zero",
            );
        } else {
            // SAFETY: The caller contract guarantees this pointer range.
            unsafe { slice::from_raw_parts(asset, asset_len) }
        };
        if segment_count != 0 && (segments.is_null() || segment_lengths.is_null()) {
            return error_json(
                "invalid_argument",
                "segment arrays are null but segment_count is non-zero",
            );
        }
        let pointers = if segment_count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller contract guarantees both parallel arrays.
            unsafe { slice::from_raw_parts(segments, segment_count) }
        };
        let lengths = if segment_count == 0 {
            &[][..]
        } else {
            // SAFETY: The caller contract guarantees both parallel arrays.
            unsafe { slice::from_raw_parts(segment_lengths, segment_count) }
        };
        let mut segment_refs = Vec::with_capacity(segment_count);
        for (&pointer, &length) in pointers.iter().zip(lengths) {
            if length == 0 {
                segment_refs.push(&[][..]);
            } else if pointer.is_null() {
                return error_json(
                    "invalid_argument",
                    "segment is null but its length is non-zero",
                );
            } else {
                // SAFETY: The caller contract guarantees this segment range.
                segment_refs.push(unsafe { slice::from_raw_parts(pointer, length) });
            }
        }
        if mime_type.is_null() {
            return error_json("invalid_argument", "mime_type is null");
        }
        // SAFETY: The caller guarantees a NUL-terminated string.
        let mime = match unsafe { CStr::from_ptr(mime_type) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                return error_json(
                    "invalid_argument",
                    &format!("mime_type is not UTF-8: {error}"),
                )
            }
        };
        // SAFETY: The caller guarantees a NUL-terminated string when non-null.
        let encapsulation = match unsafe { optional_str(encapsulation) } {
            Ok(value) => value.unwrap_or("fMP4"),
            Err(message) => return error_json("invalid_argument", &message),
        };
        let Some(encapsulation) = StreamEncapsulation::from_token(encapsulation) else {
            return error_json(
                "invalid_argument",
                &format!("unknown encapsulation: {encapsulation} (expected fMP4 or CMAF)"),
            );
        };
        // SAFETY: The caller guarantees a NUL-terminated string when non-null.
        let method = match unsafe { optional_str(method) } {
            Ok(value) => value.unwrap_or("verifiable-segment-info"),
            Err(message) => return error_json("invalid_argument", &message),
        };
        let Some(method) = StreamMethod::from_token(method) else {
            return error_json(
                "invalid_argument",
                &format!(
                    "unknown method: {method} \
                     (expected verifiable-segment-info or per-segment)"
                ),
            );
        };
        let options = if options_json.is_null() {
            VerifyOptions::default()
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };

        match verify_stream_with_options(
            bytes,
            &segment_refs,
            mime,
            encapsulation,
            method,
            &options,
        ) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "verification aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Verify caller-parsed Enhanced RTMP events in wire order.
///
/// `input_json` must match `ErtmpInput`. `options_json` may be null, in which
/// case the required 2.5 policy is selected automatically.
///
/// # Safety
/// Both non-null arguments must point to NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_verify_ertmp(
    input_json: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if input_json.is_null() {
            return error_json("invalid_argument", "input_json is null");
        }
        // SAFETY: The caller guarantees a NUL-terminated string.
        let input_json = match unsafe { CStr::from_ptr(input_json) }.to_str() {
            Ok(value) => value,
            Err(error) => {
                return error_json(
                    "invalid_ertmp_input",
                    &format!("input_json is not UTF-8: {error}"),
                )
            }
        };
        let input: ErtmpInput = match serde_json::from_str(input_json) {
            Ok(value) => value,
            Err(error) => return error_json("invalid_ertmp_input", &error.to_string()),
        };
        let options = if options_json.is_null() {
            VerifyOptions {
                spec_version: Some("2.5".into()),
                ..VerifyOptions::default()
            }
        } else {
            // SAFETY: The caller guarantees a NUL-terminated string.
            let raw = match unsafe { CStr::from_ptr(options_json) }.to_str() {
                Ok(value) => value,
                Err(error) => {
                    return error_json(
                        "invalid_options",
                        &format!("options_json is not UTF-8: {error}"),
                    )
                }
            };
            match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            }
        };
        match verify_ertmp_with_options(&input, &options) {
            Ok(report) => json!({ "ok": true, "report": report }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));

    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "E-RTMP verification aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Resolve a caller-extracted soft binding and verify every recovered store.
///
/// Network access is denied unless every endpoint origin appears in
/// `resolver_options_json.allowed_origins`. Redirects are always refused.
///
/// # Safety
/// `asset` must point to `asset_len` readable bytes. All string arguments
/// except `options_json` are required NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_resolve_soft_binding(
    asset: *const u8,
    asset_len: usize,
    mime_type: *const c_char,
    service_root: *const c_char,
    query_json: *const c_char,
    options_json: *const c_char,
    resolver_options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let bytes = if asset_len == 0 {
            &[]
        } else if asset.is_null() {
            return error_json(
                "invalid_argument",
                "asset is null but asset_len is non-zero",
            );
        } else {
            // SAFETY: The caller contract guarantees this pointer range.
            unsafe { slice::from_raw_parts(asset, asset_len) }
        };
        // SAFETY: The caller contract guarantees NUL-terminated arguments.
        let mime = match unsafe { required_str(mime_type, "mime_type") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let service_root = match unsafe { required_str(service_root, "service_root") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let query_raw = match unsafe { required_str(query_json, "query_json") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let resolver_raw =
            match unsafe { required_str(resolver_options_json, "resolver_options_json") } {
                Ok(value) => value,
                Err(error) => return error_json("invalid_argument", &error),
            };
        let query: SoftBindingQuery = match serde_json::from_str(query_raw) {
            Ok(value) => value,
            Err(error) => return error_json("invalid_soft_binding_query", &error.to_string()),
        };
        let resolver_options: SoftBindingResolverOptions = match serde_json::from_str(resolver_raw)
        {
            Ok(value) => value,
            Err(error) => {
                return error_json("invalid_soft_binding_resolver_options", &error.to_string())
            }
        };
        // SAFETY: The caller contract guarantees a null or NUL-terminated argument.
        let options = match unsafe { optional_str(options_json) } {
            Ok(None) => VerifyOptions::default(),
            Ok(Some(raw)) => match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            },
            Err(error) => return error_json("invalid_options", &error),
        };
        match resolve_soft_binding(
            bytes,
            mime,
            service_root,
            &query,
            &options,
            &resolver_options,
        ) {
            Ok(resolution) => json!({ "ok": true, "resolution": resolution }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));
    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json("internal_panic", "soft-binding resolution aborted safely"),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Submit a receipt to a soft-binding repository for its reported result.
///
/// The returned `server_reported_verified` value is not a local cryptographic
/// receipt verdict. All arguments are required NUL-terminated UTF-8 JSON or
/// strings except `options_json`, which may be null.
///
/// # Safety
/// Every non-null argument must remain readable for this call.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_request_soft_binding_receipt_verification(
    service_root: *const c_char,
    manifest_id: *const c_char,
    receipt_json: *const c_char,
    options_json: *const c_char,
    resolver_options_json: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller contract guarantees NUL-terminated arguments.
        let service_root = match unsafe { required_str(service_root, "service_root") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let manifest_id = match unsafe { required_str(manifest_id, "manifest_id") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let receipt_raw = match unsafe { required_str(receipt_json, "receipt_json") } {
            Ok(value) => value,
            Err(error) => return error_json("invalid_argument", &error),
        };
        let resolver_raw =
            match unsafe { required_str(resolver_options_json, "resolver_options_json") } {
                Ok(value) => value,
                Err(error) => return error_json("invalid_argument", &error),
            };
        let receipt = match serde_json::from_str(receipt_raw) {
            Ok(value) => value,
            Err(error) => return error_json("invalid_soft_binding_receipt", &error.to_string()),
        };
        let resolver_options: SoftBindingResolverOptions = match serde_json::from_str(resolver_raw)
        {
            Ok(value) => value,
            Err(error) => {
                return error_json("invalid_soft_binding_resolver_options", &error.to_string())
            }
        };
        let options = match unsafe { optional_str(options_json) } {
            Ok(None) => VerifyOptions::default(),
            Ok(Some(raw)) => match serde_json::from_str(raw) {
                Ok(value) => value,
                Err(error) => return error_json("invalid_options", &error.to_string()),
            },
            Err(error) => return error_json("invalid_options", &error),
        };
        match request_soft_binding_receipt_verification(
            service_root,
            manifest_id,
            receipt,
            &options,
            &resolver_options,
        ) {
            Ok(evidence) => json!({ "ok": true, "evidence": evidence }).to_string(),
            Err(error) => error_json(error.code(), &error.to_string()),
        }
    }));
    let payload = match result {
        Ok(payload) => payload,
        Err(_) => error_json(
            "internal_panic",
            "soft-binding receipt verification aborted safely",
        ),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Borrow an optional NUL-terminated argument as UTF-8.
///
/// # Safety
/// `value` must be null or point to a NUL-terminated string.
unsafe fn optional_str<'a>(value: *const c_char) -> Result<Option<&'a str>, String> {
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: The caller guarantees a NUL-terminated string.
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(Some)
        .map_err(|error| format!("argument is not UTF-8: {error}"))
}

/// Borrow a required NUL-terminated argument as UTF-8.
///
/// # Safety
/// `value` must point to a NUL-terminated string valid for the returned borrow.
unsafe fn required_str<'a>(value: *const c_char, name: &str) -> Result<&'a str, String> {
    // SAFETY: The caller guarantees the pointer contract.
    match unsafe { optional_str(value) } {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err(format!("{name} is null")),
        Err(error) => Err(format!("{name}: {error}")),
    }
}

/// Persist failure telemetry consent for all native bindings used by this user.
#[no_mangle]
pub extern "C" fn encypher_c2pa_set_telemetry_enabled(enabled: bool) -> *mut c_char {
    let payload = match set_telemetry_enabled(enabled) {
        Ok(()) => json!({ "ok": true }).to_string(),
        Err(error) => error_json("telemetry_preference_error", &error.to_string()),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Return the saved preference as `{\"ok\":true,\"enabled\":true|false|null}`.
#[no_mangle]
pub extern "C" fn encypher_c2pa_telemetry_preference() -> *mut c_char {
    let payload = match telemetry_preference() {
        Ok(enabled) => json!({ "ok": true, "enabled": enabled }).to_string(),
        Err(error) => error_json("telemetry_preference_error", &error.to_string()),
    };
    CString::new(payload)
        .expect("JSON serialization never emits an interior NUL")
        .into_raw()
}

/// Release any string returned by this library.
///
/// # Safety
/// `value` must be null or a pointer returned by this library that has not yet
/// been released.
#[no_mangle]
pub unsafe extern "C" fn encypher_c2pa_free_string(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: The caller contract guarantees ownership and one-time release.
        drop(unsafe { CString::from_raw(value) });
    }
}

fn error_json(code: &str, message: &str) -> String {
    json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message,
        }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::{encypher_c2pa_free_string, encypher_c2pa_verify, encypher_c2pa_verify_fragmented};
    use std::ffi::{CStr, CString};

    #[test]
    fn null_asset_is_a_structured_error() {
        let mime = CString::new("image/jpeg").unwrap();
        // SAFETY: All pointers satisfy the public ABI contract.
        let ptr =
            unsafe { encypher_c2pa_verify(std::ptr::null(), 1, mime.as_ptr(), std::ptr::null()) };
        // SAFETY: `ptr` came from the function above and remains owned here.
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        assert!(result.contains("invalid_argument"));
        // SAFETY: This is the one release of the returned pointer.
        unsafe { encypher_c2pa_free_string(ptr) };
    }

    #[test]
    fn null_fragment_arrays_are_a_structured_error() {
        let mime = CString::new("video/mp4").unwrap();
        // SAFETY: The null arrays deliberately exercise the checked invalid contract.
        let ptr = unsafe {
            encypher_c2pa_verify_fragmented(
                std::ptr::null(),
                0,
                std::ptr::null(),
                std::ptr::null(),
                1,
                mime.as_ptr(),
                std::ptr::null(),
            )
        };
        // SAFETY: `ptr` came from the function above and remains owned here.
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        assert!(result.contains("invalid_argument"));
        // SAFETY: This is the one release of the returned pointer.
        unsafe { encypher_c2pa_free_string(ptr) };
    }

    #[test]
    fn fragmented_entry_point_rejects_non_bmff_mime() {
        let asset = b"asset";
        let fragment = b"fragment";
        let fragment_pointers = [fragment.as_ptr()];
        let fragment_lengths = [fragment.len()];
        let mime = CString::new("image/jpeg").unwrap();
        // SAFETY: All pointers satisfy the public ABI contract.
        let ptr = unsafe {
            encypher_c2pa_verify_fragmented(
                asset.as_ptr(),
                asset.len(),
                fragment_pointers.as_ptr(),
                fragment_lengths.as_ptr(),
                1,
                mime.as_ptr(),
                std::ptr::null(),
            )
        };
        // SAFETY: `ptr` came from the function above and remains owned here.
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        assert!(result.contains("\"code\":\"unsupported_mime\""));
        // SAFETY: This is the one release of the returned pointer.
        unsafe { encypher_c2pa_free_string(ptr) };
    }

    #[test]
    fn fragmented_entry_point_returns_the_public_report() {
        let asset = include_bytes!("../../../tests/fixtures/signed_test.mp4");
        let mime = CString::new("video/mp4").unwrap();
        // SAFETY: All pointers satisfy the public ABI contract.
        let ptr = unsafe {
            encypher_c2pa_verify_fragmented(
                asset.as_ptr(),
                asset.len(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                mime.as_ptr(),
                std::ptr::null(),
            )
        };
        // SAFETY: `ptr` came from the function above and remains owned here.
        let result = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        assert!(result.contains("\"ok\":true"));
        assert!(result.contains("\"integrity\":\"valid\""));
        // SAFETY: This is the one release of the returned pointer.
        unsafe { encypher_c2pa_free_string(ptr) };
    }
}
