//! Local-first, verification-only C2PA SDK.
//!
//! The public facade reads caller-provided bytes and reports integrity separately
//! from trust. Network access occurs only after saved failure telemetry consent
//! or an explicit per-call override.

#![forbid(unsafe_code)]
// The six modules below are the verification kernel: the same engine that runs
// in Encypher's production signing service, kept as six crate-named directories
// so the two copies stay comparable file-for-file.
//
// A private drift gate compares them against the production copy. It has NOT
// yet been updated for this layout - it still expects the pre-consolidation
// crate paths - so at the time of writing the two trees are not being
// automatically compared. Landing that projection is a prerequisite for the
// next release; until it does, treat the parity claim as an intention rather
// than an enforced property.
//
// They were separate published crates until this change. That made 22,890 lines
// of implementation into semver-bound public API with no consumer - 81% of the
// reviewed public surface - and it is why manifest construction needed a Cargo
// feature to hide it. As private modules they are unreachable by construction,
// so the writers are simply `cfg(test)` and no feature can expose them.
//
// Suppressing `dead_code`/`unused_imports` here is deliberate and narrow to
// these mirrors.
// The public verifier exercises a subset of the kernel: the rest is reached by
// the production signer (`c2pa-sign`, `c2pa-cli` on the private side). Deleting
// what this crate happens not to call would fork the shared source and destroy
// the property the mirror exists for.
//
// `allow` rather than `expect`, which would be preferable: the dead set differs
// between the two compilations of this crate. Under `cargo build` the writers
// are absent and much of the kernel is unused; under `cargo test` the
// `cfg(test)` code exercises them. A single `expect` cannot be fulfilled in
// both, so it fails the `--all-targets` lint run. `allow` is scoped to these
// six mirrors and to these two lints only; nothing else in the crate is
// exempted, and the surface gate is what actually holds the boundary.
#[path = "c2pa-cbor/lib.rs"]
#[allow(dead_code, reason = "production kernel mirror")]
mod c2pa_cbor;
#[path = "c2pa-core/lib.rs"]
#[allow(dead_code, unused_imports, reason = "production kernel mirror")]
mod c2pa_core;
#[path = "c2pa-crypto/lib.rs"]
#[allow(dead_code, unused_imports, reason = "production kernel mirror")]
mod c2pa_crypto;
#[path = "c2pa-formats/lib.rs"]
#[allow(dead_code, unused_imports, reason = "production kernel mirror")]
mod c2pa_formats;
#[path = "c2pa-trust/lib.rs"]
#[allow(dead_code, unused_imports, reason = "production kernel mirror")]
mod c2pa_trust;
#[path = "c2pa-validate/lib.rs"]
#[allow(dead_code, unused_imports, reason = "production kernel mirror")]
mod c2pa_validate;
mod telemetry;
mod telemetry_consent;

pub use telemetry::{
    validation_failure_telemetry, TelemetryOptions, ValidationFailureTelemetry,
    DEFAULT_TELEMETRY_ENDPOINT,
};
pub use telemetry_consent::{
    prompt_for_telemetry_consent, set_telemetry_enabled, telemetry_preference,
    TelemetryPreferenceError,
};

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::c2pa_core::{
    spec::{canonicalize_mime, mimes_for_version},
    EngineProfile, SpecVersion,
};
use crate::c2pa_trust::TrustList;
use crate::c2pa_validate::{
    verify_with_cawg_trust_policy_did_documents_and_strict_encoding_safe as verify_safe,
    StatusCode as CoreStatus, ValidationResults as CoreResults, VerifyInput,
    ASSERTION_BMFF_HASH_MALFORMED, ASSERTION_BMFF_HASH_MATCH, ASSERTION_BMFF_HASH_MISMATCH,
    ASSERTION_BOXES_HASH_MALFORMED, ASSERTION_BOXES_HASH_MATCH, ASSERTION_BOXES_HASH_MISMATCH,
    ASSERTION_COLLECTION_HASH_MALFORMED, ASSERTION_COLLECTION_HASH_MATCH,
    ASSERTION_COLLECTION_HASH_MISMATCH, ASSERTION_DATA_HASH_MATCH, ASSERTION_DATA_HASH_MISMATCH,
    ASSERTION_MULTI_ASSET_HASH_MALFORMED, ASSERTION_MULTI_ASSET_HASH_MATCH,
    ASSERTION_MULTI_ASSET_HASH_MISMATCH, CLAIM_HARD_BINDINGS_MISSING, CLAIM_SIGNATURE_MISMATCH,
    CLAIM_SIGNATURE_MISSING, CLAIM_SIGNATURE_VALIDATED, SIGNING_CREDENTIAL_INVALID,
    SIGNING_CREDENTIAL_OCSP_NOT_REVOKED, SIGNING_CREDENTIAL_OCSP_REVOKED,
    SIGNING_CREDENTIAL_TRUSTED, SIGNING_CREDENTIAL_UNTRUSTED,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const REPORT_SCHEMA_VERSION: &str = "1.0";
pub const C2PA_PROFILE: &str = "c2pa-2.4";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifyOptions {
    /// PEM bundle of claim-signing trust anchors.
    pub trust_pem: Option<String>,
    /// PEM bundle of timestamp-authority trust anchors.
    pub tsa_trust_pem: Option<String>,
    /// PEM bundle of directly allowed end-entity certificates.
    pub allowed_list_pem: Option<String>,
    /// PEM bundle of trust anchors for CAWG named-actor (identity) X.509
    /// credentials. `None` leaves identity signers untrusted (their
    /// well-formedness is still validated).
    pub cawg_trust_pem: Option<String>,
    /// PEM bundle of directly allowed CAWG end-entity certificates.
    pub cawg_allowed_certs_pem: Option<String>,
    /// Require a CAWG document-signing credential to chain to a supplied
    /// anchor (or match the allowed list) instead of being accepted on its
    /// certificate profile alone.
    pub cawg_document_signing_require_anchor: bool,
    /// Pinned offline `did:web` DID-document store for CAWG ICA issuers,
    /// keyed by primary DID (no fragment). Resolution never touches the
    /// network: an issuer absent from the store fails closed with
    /// `cawg.ica.did_unavailable`.
    pub cawg_did_documents: Option<HashMap<String, Value>>,
    /// Refuse CAWG 1.1-era legacy encodings (field-order `signer_payload`,
    /// 1.1 ICA context, byte-array `c2paAsset` hashes): only the CAWG 1.2
    /// canonical shapes are attempted. When unset, legacy shapes verify and
    /// are surfaced via the informational `com.encypher.cawg.legacyProfile`
    /// status.
    pub cawg_strict_encoding: bool,
    /// RFC 3339 validation instant. Current UTC time is used when omitted.
    pub validation_time: Option<String>,
    /// Failure telemetry override. `None` uses the saved per-user preference.
    pub telemetry: TelemetryOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationStatus {
    pub code: String,
    pub url: String,
    pub explanation: String,
    /// Machine-readable evidence for extension status codes (e.g. the CAWG
    /// `payload_encoding` detail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationResults {
    pub success: Vec<VerificationStatus>,
    pub informational: Vec<VerificationStatus>,
    pub failure: Vec<VerificationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationReport {
    pub status: String,
    pub source: String,
    pub responder_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FreshnessReport {
    pub status: String,
    pub as_of: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustReport {
    pub status: String,
    pub basis: String,
    pub validation_time: String,
    pub revocation: RevocationReport,
    pub freshness: FreshnessReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub schema_version: String,
    pub profile: String,
    pub mime_type: String,
    pub present: bool,
    pub integrity: String,
    pub signature: String,
    pub hard_binding: String,
    pub trust: TrustReport,
    pub policy: Option<Value>,
    pub managed_receipt: Option<Value>,
    pub validation_state: String,
    pub validation_results: ValidationResults,
    pub manifest_report: Value,
    pub content_credentials: Option<Value>,
}

impl VerificationReport {
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(Error::Serialize)
    }

    pub fn to_pretty_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(Error::Serialize)
    }

    /// All CAWG identity / ICA credential statuses (`cawg.*` codes), across
    /// the success, informational, and failure sections. CAWG failures are
    /// assertion-scoped: they never invalidate C2PA manifest integrity.
    pub fn cawg_statuses(&self) -> Vec<&VerificationStatus> {
        self.validation_results
            .success
            .iter()
            .chain(&self.validation_results.informational)
            .chain(&self.validation_results.failure)
            .filter(|status| status.code.starts_with("cawg."))
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported MIME type: {0}")]
    UnsupportedMime(String),
    #[error("invalid trust material: {0}")]
    InvalidTrust(String),
    #[error("invalid validation time: {0}")]
    InvalidValidationTime(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("could not read asset: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    TelemetryPreference(#[from] TelemetryPreferenceError),
    #[error("could not serialize report: {0}")]
    Serialize(serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedMime(_) => "unsupported_mime",
            Self::InvalidTrust(_) => "invalid_trust_material",
            Self::InvalidValidationTime(_) => "invalid_validation_time",
            Self::Verification(_) => "verification_error",
            Self::Io(_) => "io_error",
            Self::TelemetryPreference(_) => "telemetry_preference_error",
            Self::Serialize(_) => "serialization_error",
        }
    }
}

/// Verify asset bytes without network access.
pub fn verify(data: &[u8], mime_type: &str) -> Result<VerificationReport, Error> {
    verify_with_options(data, mime_type, &VerifyOptions::default())
}

/// Verify asset bytes with caller-supplied static trust material. Failure
/// telemetry follows the explicit override or saved per-user preference.
pub fn verify_with_options(
    data: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let telemetry_enabled = telemetry_consent::resolve_telemetry_enabled(options.telemetry.enabled);
    let result = verify_with_options_inner(data, mime_type, options);
    if let Some(event) = telemetry::validation_failure_telemetry_with_enabled(
        mime_type,
        &result,
        &options.telemetry,
        telemetry_enabled,
    ) {
        telemetry::enqueue(options.telemetry.endpoint(), event);
    }
    result
}

fn verify_with_options_inner(
    data: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let mime = canonicalize_mime(mime_type);
    if !mimes_for_version(SpecVersion::V2_4).contains(&mime.as_str())
        || crate::c2pa_formats::AssetFormat::from_mime(&mime).is_none()
    {
        return Err(Error::UnsupportedMime(mime));
    }

    let claim_trust = parse_trust(options.trust_pem.as_deref())?;
    let tsa_trust = parse_trust(options.tsa_trust_pem.as_deref())?;
    let allowed_certs = parse_trust(options.allowed_list_pem.as_deref())?;
    let cawg_trust = parse_trust(options.cawg_trust_pem.as_deref())?;
    let cawg_allowed_certs = parse_trust(options.cawg_allowed_certs_pem.as_deref())?;
    let validation_time = parse_validation_time(options.validation_time.as_deref())?;
    let validation_time_text = validation_time
        .format(&Rfc3339)
        .map_err(|error| Error::InvalidValidationTime(error.to_string()))?;

    let output = verify_safe(
        &VerifyInput {
            data,
            mime: &mime,
            claim_signer_trust: claim_trust.as_ref(),
            tsa_trust: tsa_trust.as_ref(),
            allowed_certs: allowed_certs.as_ref(),
            validation_time: Some(validation_time),
            profile: EngineProfile::GENEROUS,
        },
        cawg_trust.as_ref(),
        cawg_allowed_certs.as_ref(),
        options.cawg_document_signing_require_anchor,
        options.cawg_did_documents.as_ref(),
        options.cawg_strict_encoding,
    )
    .map_err(|error| match error {
        crate::c2pa_validate::ValidateError::UnsupportedMime(value) => {
            Error::UnsupportedMime(value)
        }
        other => Error::Verification(other.to_string()),
    })?;

    let present = output
        .report_json
        .pointer("/provenance_verdict/present")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let integrity = output
        .report_json
        .pointer("/provenance_verdict/integrity")
        .and_then(Value::as_str)
        .unwrap_or(if present { "invalid" } else { "absent" })
        .to_string();
    let signature = signature_status(&output.results);
    let hard_binding = hard_binding_status(&output.results);
    let trust = trust_report(
        &output.results,
        present,
        claim_trust.is_some() || allowed_certs.is_some(),
        validation_time_text,
    );

    Ok(VerificationReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        profile: C2PA_PROFILE.to_string(),
        mime_type: mime,
        present,
        integrity,
        signature,
        hard_binding,
        trust,
        policy: None,
        managed_receipt: None,
        validation_state: output.validation_state.as_str().to_string(),
        validation_results: copy_results(&output.results),
        manifest_report: output.report_json,
        content_credentials: output.crjson,
    })
}

/// Read and verify one local asset.
pub fn verify_file(
    path: impl AsRef<Path>,
    mime_type: Option<&str>,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let path = path.as_ref();
    let mime = match mime_type {
        Some(value) => value.to_string(),
        None => mime_from_path(path)
            .ok_or_else(|| Error::UnsupportedMime(path.display().to_string()))?
            .to_string(),
    };
    let data = fs::read(path)?;
    verify_with_options(&data, &mime, options)
}

/// Canonical MIME types covered by the C2PA 2.4 profile and readable by this build.
pub fn supported_mime_types() -> Vec<&'static str> {
    let mut mimes: Vec<_> = mimes_for_version(SpecVersion::V2_4)
        .into_iter()
        .filter(|mime| crate::c2pa_formats::AssetFormat::from_mime(mime).is_some())
        .collect();
    mimes.sort_unstable();
    mimes.dedup();
    mimes
}

/// Infer a canonical MIME type from a local filename.
pub fn mime_from_path(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    Some(match extension.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "tif" | "tiff" => "image/tiff",
        "dng" => "image/x-adobe-dng",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "avif" => "image/avif",
        "jxl" => "image/jxl",
        "svg" => "image/svg+xml",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "pdf" => "application/pdf",
        "epub" => "application/epub+zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        _ => return None,
    })
}

fn parse_trust(value: Option<&str>) -> Result<Option<TrustList>, Error> {
    value
        .map(TrustList::from_pem)
        .transpose()
        .map_err(|error| Error::InvalidTrust(error.to_string()))
}

fn parse_validation_time(value: Option<&str>) -> Result<OffsetDateTime, Error> {
    match value {
        Some(raw) => OffsetDateTime::parse(raw, &Rfc3339)
            .map_err(|error| Error::InvalidValidationTime(error.to_string())),
        None => Ok(OffsetDateTime::now_utc()),
    }
}

fn copy_status(status: &CoreStatus) -> VerificationStatus {
    VerificationStatus {
        code: status.code.clone(),
        url: status.url.clone(),
        explanation: status.explanation.clone(),
        details: status.details.clone(),
    }
}

fn copy_results(results: &CoreResults) -> ValidationResults {
    ValidationResults {
        success: results.success.iter().map(copy_status).collect(),
        informational: results.informational.iter().map(copy_status).collect(),
        failure: results.failure.iter().map(copy_status).collect(),
    }
}

fn signature_status(results: &CoreResults) -> String {
    if results.has_success(CLAIM_SIGNATURE_VALIDATED) {
        "valid"
    } else if results.has_failure(CLAIM_SIGNATURE_MISMATCH) {
        "invalid"
    } else if results.has_failure(CLAIM_SIGNATURE_MISSING) {
        "missing"
    } else {
        "unknown"
    }
    .to_string()
}

fn hard_binding_status(results: &CoreResults) -> String {
    const MATCHES: &[&str] = &[
        ASSERTION_DATA_HASH_MATCH,
        ASSERTION_BMFF_HASH_MATCH,
        ASSERTION_BOXES_HASH_MATCH,
        ASSERTION_COLLECTION_HASH_MATCH,
        ASSERTION_MULTI_ASSET_HASH_MATCH,
    ];
    const FAILURES: &[&str] = &[
        ASSERTION_DATA_HASH_MISMATCH,
        ASSERTION_BMFF_HASH_MISMATCH,
        ASSERTION_BMFF_HASH_MALFORMED,
        ASSERTION_BOXES_HASH_MISMATCH,
        ASSERTION_BOXES_HASH_MALFORMED,
        ASSERTION_COLLECTION_HASH_MISMATCH,
        ASSERTION_COLLECTION_HASH_MALFORMED,
        ASSERTION_MULTI_ASSET_HASH_MISMATCH,
        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
    ];
    if MATCHES.iter().any(|code| results.has_success(code)) {
        "match"
    } else if FAILURES.iter().any(|code| results.has_failure(code)) {
        "mismatch"
    } else if results.has_failure(CLAIM_HARD_BINDINGS_MISSING) {
        "missing"
    } else {
        "unknown"
    }
    .to_string()
}

fn trust_report(
    results: &CoreResults,
    present: bool,
    supplied: bool,
    validation_time: String,
) -> TrustReport {
    let trusted = results.has_success(SIGNING_CREDENTIAL_TRUSTED);
    let rejected = results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED)
        || results.has_failure(SIGNING_CREDENTIAL_INVALID);
    let revoked = results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED);
    let not_revoked = results.has_success(SIGNING_CREDENTIAL_OCSP_NOT_REVOKED);
    TrustReport {
        status: if trusted && !revoked {
            "valid_for_supplied_material"
        } else if present && supplied && (rejected || revoked) {
            "not_valid_for_supplied_material"
        } else {
            "not_evaluated"
        }
        .to_string(),
        basis: if supplied {
            "caller_supplied_static_material"
        } else {
            "none"
        }
        .to_string(),
        validation_time,
        revocation: RevocationReport {
            status: if revoked {
                "revoked"
            } else if not_revoked {
                "not_revoked"
            } else {
                "not_checked"
            }
            .to_string(),
            source: if revoked || not_revoked {
                "embedded_ocsp"
            } else {
                "none"
            }
            .to_string(),
            responder_signature: if revoked || not_revoked {
                "valid"
            } else {
                "not_applicable"
            }
            .to_string(),
        },
        freshness: FreshnessReport {
            status: "unknown".to_string(),
            as_of: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{mime_from_path, supported_mime_types, verify, Error};
    use std::path::Path;

    #[test]
    fn known_filename_maps_to_mime() {
        assert_eq!(
            mime_from_path(Path::new("composition.MP4")),
            Some("video/mp4")
        );
    }

    #[test]
    fn format_list_is_sorted_and_contains_composition_formats() {
        let formats = supported_mime_types();
        assert!(formats.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(formats.contains(&"video/mp4"));
        assert!(formats.contains(&"image/jpeg"));
    }

    #[test]
    fn input_alias_is_reported_as_canonical_mime() {
        let asset = b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00";
        let report = verify(asset, "audio/aac; codecs=mp4a.40.2").unwrap();
        assert_eq!(report.mime_type, "audio/mp4");
        assert!(!report.present);
    }

    #[test]
    fn unratified_hostless_store_is_not_in_public_profile() {
        let error = verify(b"jumb", "application/c2pa").unwrap_err();
        assert!(matches!(error, Error::UnsupportedMime(_)));
    }

    #[test]
    fn unsupported_mime_has_stable_error_code() {
        let error = verify(b"not an asset", "application/x-unknown").unwrap_err();
        assert!(matches!(error, Error::UnsupportedMime(_)));
        assert_eq!(error.code(), "unsupported_mime");
    }
}
