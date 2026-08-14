//! Local-first, verification-only C2PA SDK.
//!
//! The public facade reads caller-provided bytes and reports integrity separately
//! from trust. Network access occurs only after saved failure telemetry consent
//! or an explicit per-call override.

#![forbid(unsafe_code)]
// The six modules below are the verification kernel. They derive from the
// engine that runs in Encypher's production signing service, and are kept as
// six crate-named directories so the two trees stay readable side by side.
//
// They are a derivative, not a copy, and the difference is the point of this
// repository: the production tree carries manifest construction and container
// writing, and this one does not. The line counts differ accordingly and by
// design - production `c2pa-formats` is roughly twice this one.
//
// No automated comparison exists between the two trees. An earlier version of
// this comment said a private drift gate compared them; there is no such gate
// in the monorepo, and saying otherwise credited this code with a control
// nobody had written. Divergence is currently caught by review alone. If that
// is not good enough - and for a security boundary it probably is not - the
// thing to build is a projection that maps production paths onto this layout
// and diffs the shared functions, which would have to model the intended
// removals rather than expect equality.
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
mod default_trust;
mod telemetry;
mod telemetry_consent;
pub use default_trust::SNAPSHOT_DATE as DEFAULT_TRUST_SNAPSHOT_DATE;

pub use telemetry::{
    validation_failure_telemetry, TelemetryOptions, ValidationFailureTelemetry,
    DEFAULT_TELEMETRY_ENDPOINT,
};
pub use telemetry_consent::{
    prompt_for_telemetry_consent, set_telemetry_enabled, telemetry_preference,
    TelemetryPreferenceError,
};

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::c2pa_core::{
    spec::{canonicalize_mime, mimes_for_version},
    EngineProfile, SpecVersion,
};
use crate::c2pa_trust::TrustList;
use crate::c2pa_validate::{
    verify_fragmented_with_cawg_trust_policy_did_documents_and_strict_encoding_safe as verify_fragmented_safe,
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
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const REPORT_SCHEMA_VERSION: &str = "1.0";
pub const C2PA_PROFILE: &str = "c2pa-2.4";
const MAX_MANIFEST_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATH_ASSET_BYTES: u64 = 128 * 1024 * 1024;

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
    /// Disable the bundled C2PA, IPTC, and Encypher trust snapshots. By
    /// default, caller-supplied PEM bundles extend those snapshots; setting
    /// this to `true` evaluates only caller-supplied trust material.
    pub no_default_trust: bool,
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
/// Raw, read-only evidence needed to validate an embedded manifest remotely
/// without uploading the host asset.
///
/// `carrier` is the single contiguous format carrier that contains
/// `manifest_store`. Formats whose manifest spans multiple disjoint carriers
/// return no detached evidence; local verification still covers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedManifestEvidence {
    pub manifest_store: Vec<u8>,
    pub manifest_store_sha256: String,
    pub carrier: Vec<u8>,
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

/// Verify asset bytes with default options. Parsing and validation stay offline;
/// saved failure-telemetry consent may emit one bounded request. For guaranteed
/// no egress, disable the `telemetry` feature or call [`verify_with_options`]
/// with `telemetry.enabled` set to `Some(false)`.
pub fn verify(data: &[u8], mime_type: &str) -> Result<VerificationReport, Error> {
    verify_with_options(data, mime_type, &VerifyOptions::default())
}

/// Verify a fragmented ISO BMFF stream with default options.
///
/// `init_segment` carries the manifest. Each entry in `fragments` is one media
/// segment (`.m4s`). A subset may be supplied: each segment carries its own
/// Merkle-tree location and is checked independently.
pub fn verify_fragmented(
    init_segment: &[u8],
    fragments: &[&[u8]],
    mime_type: &str,
) -> Result<VerificationReport, Error> {
    verify_fragmented_with_options(
        init_segment,
        fragments,
        mime_type,
        &VerifyOptions::default(),
    )
}
/// Extract the signed manifest store and its contiguous carrier for detached
/// server validation.
///
/// This is read-only. It never performs network I/O and never constructs or
/// writes a manifest. `Ok(None)` means the asset has no embedded manifest or
/// its format cannot represent the manifest as one contiguous carrier.
pub fn detached_manifest_evidence(
    data: &[u8],
    mime_type: &str,
) -> Result<Option<DetachedManifestEvidence>, Error> {
    let mime = canonicalize_mime(mime_type);
    let format = crate::c2pa_formats::AssetFormat::from_mime(&mime)
        .ok_or_else(|| Error::UnsupportedMime(mime.clone()))?;
    if !crate::c2pa_formats::supports_hash_mode(&mime) {
        return Ok(None);
    }
    let Some(manifest_store) = crate::c2pa_formats::extract_manifest(format, data)
        .map_err(|error| Error::Verification(error.to_string()))?
    else {
        return Ok(None);
    };
    let spans = crate::c2pa_formats::compute_data_hash_exclusions(format, data)
        .map_err(|error| Error::Verification(error.to_string()))?;
    let [span] = spans.as_slice() else {
        return Ok(None);
    };
    let end = span
        .start
        .checked_add(span.length)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| Error::Verification("manifest carrier exceeds asset bounds".into()))?;
    let manifest_store_sha256 = hex::encode(Sha256::digest(&manifest_store));
    Ok(Some(DetachedManifestEvidence {
        manifest_store,
        manifest_store_sha256,
        carrier: data[span.start..end].to_vec(),
    }))
}

/// Verify asset bytes against the bundled trust snapshots plus any static
/// trust material supplied by the caller. Failure telemetry follows the
/// explicit override or saved per-user preference.
pub fn verify_with_options(
    data: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let telemetry_enabled = telemetry_consent::resolve_telemetry_enabled(options.telemetry.enabled);
    let result = verify_with_options_inner(data, None, mime_type, options);
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

/// Verify a fragmented ISO BMFF stream with explicit trust, validation-time,
/// CAWG, and telemetry options.
///
/// `init_segment` carries the C2PA manifest. `fragments` may be the complete
/// stream or any available subset; validation covers every supplied fragment.
pub fn verify_fragmented_with_options(
    init_segment: &[u8],
    fragments: &[&[u8]],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let telemetry_enabled = telemetry_consent::resolve_telemetry_enabled(options.telemetry.enabled);
    let result = verify_with_options_inner(init_segment, Some(fragments), mime_type, options);
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
    fragments: Option<&[&[u8]]>,
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let mime = canonicalize_mime(mime_type);
    if !mimes_for_version(SpecVersion::V2_4).contains(&mime.as_str())
        || crate::c2pa_formats::AssetFormat::from_mime(&mime).is_none()
    {
        return Err(Error::UnsupportedMime(mime));
    }

    let use_defaults = !options.no_default_trust;
    let claim_trust = resolve_trust(
        options.trust_pem.as_deref(),
        use_defaults.then(default_trust::claim_signing),
    )?;
    let tsa_trust = resolve_trust(
        options.tsa_trust_pem.as_deref(),
        use_defaults.then(default_trust::timestamp_authorities),
    )?;
    let allowed_certs = resolve_trust(
        options.allowed_list_pem.as_deref(),
        use_defaults.then(default_trust::allowed_claim_signers),
    )?;
    let cawg_trust = resolve_trust(
        options.cawg_trust_pem.as_deref(),
        use_defaults.then(default_trust::cawg_identity),
    )?;
    let cawg_allowed_certs = resolve_trust(
        options.cawg_allowed_certs_pem.as_deref(),
        use_defaults.then(default_trust::cawg_allowed_identities),
    )?;
    let validation_time = parse_validation_time(options.validation_time.as_deref())?;
    let validation_time_text = validation_time
        .format(&Rfc3339)
        .map_err(|error| Error::InvalidValidationTime(error.to_string()))?;

    let input = VerifyInput {
        data,
        mime: &mime,
        claim_signer_trust: claim_trust.as_ref().map(ResolvedTrust::get),
        tsa_trust: tsa_trust.as_ref().map(ResolvedTrust::get),
        allowed_certs: allowed_certs.as_ref().map(ResolvedTrust::get),
        validation_time: Some(validation_time),
        profile: EngineProfile::GENEROUS,
    };
    let cawg_trust = cawg_trust.as_ref().map(ResolvedTrust::get);
    let cawg_allowed_certs = cawg_allowed_certs.as_ref().map(ResolvedTrust::get);
    let output = match fragments {
        Some(fragments) => verify_fragmented_safe(
            &input,
            fragments,
            cawg_trust,
            cawg_allowed_certs,
            true,
            options.cawg_did_documents.as_ref(),
            options.cawg_strict_encoding,
        ),
        None => verify_safe(
            &input,
            cawg_trust,
            cawg_allowed_certs,
            true,
            options.cawg_did_documents.as_ref(),
            options.cawg_strict_encoding,
        ),
    }
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
    let custom_claim_trust = options.trust_pem.is_some() || options.allowed_list_pem.is_some();
    let trust_basis = match (use_defaults, custom_claim_trust) {
        (true, true) => "bundled_and_caller_supplied_static_material",
        (true, false) => "bundled_static_material",
        (false, true) => "caller_supplied_static_material",
        (false, false) => "none",
    };
    let trust = trust_report(&output.results, present, trust_basis, validation_time_text);

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
///
/// Path-based verification accepts regular files up to 128 MiB. Byte-slice
/// verification remains bounded only by caller memory.
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
    let data = read_path_asset(path, MAX_PATH_ASSET_BYTES)?;
    verify_with_options(&data, &mime, options)
}

fn read_path_asset(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);

    // Open once, then validate that exact handle. On Unix O_NONBLOCK prevents
    // a FIFO substituted for the path from blocking before it can be rejected.
    let mut file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    validate_path_asset(path, &opened_metadata, limit)?;
    read_bounded_file(&mut file, opened_metadata.len(), limit)
}

fn validate_path_asset(path: &Path, metadata: &fs::Metadata, limit: u64) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("asset path is not a regular file: {}", path.display()),
        ));
    }
    if metadata.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("asset exceeds the 128 MiB path limit: {}", path.display()),
        ));
    }
    Ok(())
}

fn read_bounded_file<R: Read>(file: &mut R, expected_len: u64, limit: u64) -> io::Result<Vec<u8>> {
    if expected_len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "asset exceeds the path size limit",
        ));
    }
    let expected_len = usize::try_from(expected_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "asset size is not addressable"))?;
    let mut data = vec![0_u8; expected_len + 1];
    let mut used = 0;
    while used < expected_len {
        let read = file.read(&mut data[used..expected_len])?;
        if read == 0 {
            break;
        }
        used += read;
    }
    if used == expected_len && file.read(&mut data[expected_len..expected_len + 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "asset grew while being read",
        ));
    }
    data.truncate(used);
    Ok(data)
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

/// Every filename extension the SDK maps to a MIME type, with its mapping.
///
/// This is the single source of truth for extension inference. It is public so
/// that callers can discover it and so that the non-mutation contract tests
/// iterate the real table rather than a hand-copied list: a reviewer hid a
/// writer in the `.dng` branch precisely because the test's own copy had
/// drifted and omitted it.
pub const SUPPORTED_EXTENSIONS: &[(&str, &str)] = &[
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
    ("webp", "image/webp"),
    ("gif", "image/gif"),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("dng", "image/x-adobe-dng"),
    ("heic", "image/heic"),
    ("heif", "image/heif"),
    ("avif", "image/avif"),
    ("jxl", "image/jxl"),
    ("svg", "image/svg+xml"),
    ("mp4", "video/mp4"),
    ("m4v", "video/mp4"),
    ("mov", "video/quicktime"),
    ("avi", "video/x-msvideo"),
    ("wav", "audio/wav"),
    ("mp3", "audio/mpeg"),
    ("m4a", "audio/mp4"),
    ("aac", "audio/aac"),
    ("flac", "audio/flac"),
    ("ogg", "audio/ogg"),
    ("oga", "audio/ogg"),
    ("pdf", "application/pdf"),
    ("epub", "application/epub+zip"),
    (
        "docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (
        "pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    ("odt", "application/vnd.oasis.opendocument.text"),
    ("odg", "application/vnd.oasis.opendocument.graphics"),
    ("ttf", "font/ttf"),
    ("otf", "font/otf"),
    ("txt", "text/plain"),
    ("tsv", "text/tab-separated-values"),
];

/// Infer a MIME type from a filename extension, case-insensitively.
pub fn mime_from_path(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    SUPPORTED_EXTENSIONS
        .iter()
        .find(|(candidate, _)| *candidate == extension)
        .map(|(_, mime)| *mime)
}

enum ResolvedTrust {
    Bundled(&'static TrustList),
    Owned(TrustList),
}

impl ResolvedTrust {
    fn get(&self) -> &TrustList {
        match self {
            Self::Bundled(trust) => trust,
            Self::Owned(trust) => trust,
        }
    }
}

fn resolve_trust(
    custom_pem: Option<&str>,
    bundled: Option<&'static TrustList>,
) -> Result<Option<ResolvedTrust>, Error> {
    let custom = custom_pem
        .map(TrustList::from_pem)
        .transpose()
        .map_err(|error| Error::InvalidTrust(error.to_string()))?;
    match (bundled, custom) {
        (None, None) => Ok(None),
        (Some(trust), None) => Ok(Some(ResolvedTrust::Bundled(trust))),
        (None, Some(trust)) => Ok(Some(ResolvedTrust::Owned(trust))),
        (Some(bundled), Some(custom)) => {
            let mut merged = bundled.clone();
            merged.anchors.extend(custom.anchors);
            Ok(Some(ResolvedTrust::Owned(merged)))
        }
    }
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
    basis: &str,
    validation_time: String,
) -> TrustReport {
    let supplied = basis != "none";
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
        basis: basis.to_string(),
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
    use super::{mime_from_path, read_bounded_file, supported_mime_types, verify, Error};
    use std::{io::Cursor, path::Path};

    #[test]
    fn known_filename_maps_to_mime() {
        assert_eq!(
            mime_from_path(Path::new("composition.MP4")),
            Some("video/mp4")
        );

        assert_eq!(
            mime_from_path(Path::new("drawing.odg")),
            Some("application/vnd.oasis.opendocument.graphics")
        );
        assert_eq!(
            mime_from_path(Path::new("data.tsv")),
            Some("text/tab-separated-values")
        );
    }

    #[test]
    fn format_list_is_sorted_and_contains_composition_formats() {
        let formats = supported_mime_types();
        assert_eq!(formats.len(), 71);
        assert!(formats.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(formats.contains(&"video/mp4"));
        assert!(formats.contains(&"image/jpeg"));
        assert!(formats.contains(&"text/tab-separated-values"));
        assert!(formats.contains(&"application/vnd.oasis.opendocument.graphics"));
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
    fn bounded_reader_accepts_exact_limit_without_large_allocation() {
        let mut input = Cursor::new(b"1234");
        assert_eq!(read_bounded_file(&mut input, 4, 4).unwrap(), b"1234");
    }

    #[test]
    fn bounded_reader_detects_growth_at_limit_plus_one() {
        let mut input = Cursor::new(b"12345");
        let error = read_bounded_file(&mut input, 4, 4).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("grew while being read"));
    }

    #[test]
    fn unsupported_mime_has_stable_error_code() {
        let error = verify(b"not an asset", "application/x-unknown").unwrap_err();
        assert!(matches!(error, Error::UnsupportedMime(_)));
        assert_eq!(error.code(), "unsupported_mime");
    }
}
