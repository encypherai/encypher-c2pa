#![forbid(unsafe_code)]

use encypher_c2pa::{
    set_telemetry_enabled, supported_mime_types, telemetry_preference,
    verify_fragmented_with_options, verify_with_options, VerifyOptions, SUPPORTED_EXTENSIONS,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

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
    module.add_function(wrap_pyfunction!(verify_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(verify_fragmented_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(formats_json, module)?)?;
    module.add_function(wrap_pyfunction!(extensions_json, module)?)?;
    module.add_function(wrap_pyfunction!(set_telemetry_preference, module)?)?;
    module.add_function(wrap_pyfunction!(get_telemetry_preference, module)?)?;
    Ok(())
}
