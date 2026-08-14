use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use encypher_c2pa::{
    set_telemetry_enabled, telemetry_preference, verify_fragmented_with_options,
    verify_with_options, VerifyOptions,
};
use serde_json::json;

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
