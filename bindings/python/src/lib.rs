#![forbid(unsafe_code)]
// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use encypher_c2pa::{
    binding_target, request_soft_binding_receipt_verification, resolve_soft_binding,
    set_telemetry_enabled, supported_mime_types, telemetry_preference, verify_ertmp_with_options,
    verify_fragmented_with_options, verify_manifest_store_only, verify_stream_with_options,
    verify_with_caller_verified_binding, verify_with_manifest_store, verify_with_options,
    CallerBindingEvidence, CallerBindingVerdict, CawgStoreHost, ErtmpInput, ManifestBindingTarget,
    SoftBindingQuery, SoftBindingResolverOptions, StreamEncapsulation, StreamMethod, VerifyOptions,
    SUPPORTED_EXTENSIONS,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn validate_options(options_json: String) -> PyResult<()> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    options
        .validate()
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
}

#[pyfunction]
fn verify_bytes(
    py: Python<'_>,
    asset: Vec<u8>,
    mime_type: String,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        verify_with_options(&asset, &mime_type, &options)
            .and_then(|report| report.to_json())
            .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn verify_detached_bytes(
    py: Python<'_>,
    asset: Vec<u8>,
    manifest_store: Vec<u8>,
    mime_type: String,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        verify_with_manifest_store(&asset, &manifest_store, &mime_type, &options)
            .and_then(|report| report.to_json())
            .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn verify_manifest_store_only_bytes(
    py: Python<'_>,
    manifest_store: Vec<u8>,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        verify_manifest_store_only(&manifest_store, &options)
            .and_then(|result| {
                serde_json::to_string(&result).map_err(encypher_c2pa::Error::Serialize)
            })
            .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn binding_target_bytes(
    py: Python<'_>,
    manifest_store: Vec<u8>,
    hostless: bool,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        binding_target(
            &manifest_store,
            if hostless {
                CawgStoreHost::HostLess
            } else {
                CawgStoreHost::Asset
            },
            &options,
        )
        .and_then(|target| serde_json::to_string(&target).map_err(encypher_c2pa::Error::Serialize))
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn verify_caller_binding_bytes(
    py: Python<'_>,
    manifest_store: Vec<u8>,
    content_mime: String,
    hostless: bool,
    target_json: String,
    verdict_json: String,
    engine: String,
    options_json: String,
) -> PyResult<String> {
    let target: ManifestBindingTarget = serde_json::from_str(&target_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_binding_target: {error}")))?;
    let verdict: CallerBindingVerdict = serde_json::from_str(&verdict_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_binding_verdict: {error}")))?;
    let evidence = CallerBindingEvidence::new(target, verdict, &engine)
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))?;
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        verify_with_caller_verified_binding(
            &manifest_store,
            &content_mime,
            if hostless {
                CawgStoreHost::HostLess
            } else {
                CawgStoreHost::Asset
            },
            &evidence,
            &options,
        )
        .and_then(|report| report.to_json())
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}
#[pyfunction]
fn verify_fragmented_bytes(
    py: Python<'_>,
    init_segment: Vec<u8>,
    fragments: Vec<Vec<u8>>,
    mime_type: String,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        let fragment_refs: Vec<&[u8]> = fragments.iter().map(Vec::as_slice).collect();
        verify_fragmented_with_options(&init_segment, &fragment_refs, &mime_type, &options)
            .and_then(|report| report.to_json())
            .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn verify_stream_bytes(
    py: Python<'_>,
    init_segment: Vec<u8>,
    segments: Vec<Vec<u8>>,
    mime_type: String,
    encapsulation: String,
    method: String,
    options_json: String,
) -> PyResult<String> {
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    let encapsulation = StreamEncapsulation::from_token(&encapsulation).ok_or_else(|| {
        PyValueError::new_err(format!(
            "invalid_argument: unknown encapsulation {encapsulation:?} (expected fMP4 or CMAF)"
        ))
    })?;
    let method = StreamMethod::from_token(&method).ok_or_else(|| {
        PyValueError::new_err(format!(
            "invalid_argument: unknown method {method:?} \
             (expected verifiable-segment-info or per-segment)"
        ))
    })?;
    py.detach(|| {
        let segment_refs: Vec<&[u8]> = segments.iter().map(Vec::as_slice).collect();
        verify_stream_with_options(
            &init_segment,
            &segment_refs,
            &mime_type,
            encapsulation,
            method,
            &options,
        )
        .and_then(|report| report.to_json())
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn verify_ertmp_events(
    py: Python<'_>,
    input_json: String,
    options_json: String,
) -> PyResult<String> {
    let input: ErtmpInput = serde_json::from_str(&input_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_ertmp_input: {error}")))?;
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    py.detach(|| {
        verify_ertmp_with_options(&input, &options)
            .and_then(|report| report.to_json())
            .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn resolve_soft_binding_bytes(
    py: Python<'_>,
    asset: Vec<u8>,
    mime_type: String,
    service_root: String,
    query_json: String,
    options_json: String,
    resolver_options_json: String,
) -> PyResult<String> {
    let query: SoftBindingQuery = serde_json::from_str(&query_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_soft_binding_query: {error}")))?;
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    let resolver_options: SoftBindingResolverOptions = serde_json::from_str(&resolver_options_json)
        .map_err(|error| {
            PyValueError::new_err(format!("invalid_soft_binding_resolver_options: {error}"))
        })?;
    py.detach(|| {
        resolve_soft_binding(
            &asset,
            &mime_type,
            &service_root,
            &query,
            &options,
            &resolver_options,
        )
        .and_then(|resolution| {
            serde_json::to_string(&resolution).map_err(encypher_c2pa::Error::Serialize)
        })
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn request_soft_binding_receipt_verification_json(
    py: Python<'_>,
    service_root: String,
    manifest_id: String,
    receipt_json: String,
    options_json: String,
    resolver_options_json: String,
) -> PyResult<String> {
    let receipt = serde_json::from_str(&receipt_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_soft_binding_receipt: {error}")))?;
    let options: VerifyOptions = serde_json::from_str(&options_json)
        .map_err(|error| PyValueError::new_err(format!("invalid_options: {error}")))?;
    let resolver_options: SoftBindingResolverOptions = serde_json::from_str(&resolver_options_json)
        .map_err(|error| {
            PyValueError::new_err(format!("invalid_soft_binding_resolver_options: {error}"))
        })?;
    py.detach(|| {
        request_soft_binding_receipt_verification(
            &service_root,
            &manifest_id,
            receipt,
            &options,
            &resolver_options,
        )
        .and_then(|evidence| {
            serde_json::to_string(&evidence).map_err(encypher_c2pa::Error::Serialize)
        })
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    })
}

#[pyfunction]
fn set_telemetry_preference(enabled: bool) -> PyResult<()> {
    set_telemetry_enabled(enabled).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn get_telemetry_preference() -> PyResult<Option<bool>> {
    telemetry_preference().map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn formats_json() -> PyResult<String> {
    serde_json::to_string(&supported_mime_types())
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn extensions_json() -> PyResult<String> {
    serde_json::to_string(SUPPORTED_EXTENSIONS)
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(validate_options, module)?)?;
    module.add_function(wrap_pyfunction!(verify_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_detached_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_manifest_store_only_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(binding_target_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_caller_binding_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_fragmented_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_stream_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_ertmp_events, module)?)?;
    module.add_function(wrap_pyfunction!(resolve_soft_binding_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(
        request_soft_binding_receipt_verification_json,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(formats_json, module)?)?;
    module.add_function(wrap_pyfunction!(extensions_json, module)?)?;
    module.add_function(wrap_pyfunction!(set_telemetry_preference, module)?)?;
    module.add_function(wrap_pyfunction!(get_telemetry_preference, module)?)?;
    Ok(())
}
