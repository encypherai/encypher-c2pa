// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

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
mod config_dir;
mod default_trust;
mod online;
mod online_consent;
mod stream;
pub use stream::{
    verify_stream, verify_stream_with_options, SegmentReport, StreamEncapsulation, StreamMethod,
    StreamVerificationReport,
};
mod telemetry;
mod telemetry_consent;
pub use config_dir::config_directory;
pub use default_trust::SNAPSHOT_DATE as DEFAULT_TRUST_SNAPSHOT_DATE;

pub use online::{NetworkReport, NetworkRequest};
pub use online_consent::{
    allow_interactive_online_consent, online_preference, set_online_preference, OnlinePreference,
    OnlinePreferenceError,
};
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
use crate::c2pa_trust::{AnchorPurpose, CawgTrustSource, TrustList};
use crate::c2pa_validate::{
    verify_fragmented_with_cawg_options_and_expected_seeks_safe as verify_fragmented_safe,
    verify_with_cawg_options_safe as verify_safe, StatusCode as CoreStatus,
    ValidationResults as CoreResults, VerifyInput, ASSERTION_BMFF_HASH_MALFORMED,
    ASSERTION_BMFF_HASH_MATCH, ASSERTION_BMFF_HASH_MISMATCH, ASSERTION_BOXES_HASH_MALFORMED,
    ASSERTION_BOXES_HASH_MATCH, ASSERTION_BOXES_HASH_MISMATCH, ASSERTION_COLLECTION_HASH_MALFORMED,
    ASSERTION_COLLECTION_HASH_MATCH, ASSERTION_COLLECTION_HASH_MISMATCH, ASSERTION_DATA_HASH_MATCH,
    ASSERTION_DATA_HASH_MISMATCH, ASSERTION_MULTI_ASSET_HASH_MALFORMED,
    ASSERTION_MULTI_ASSET_HASH_MATCH, ASSERTION_MULTI_ASSET_HASH_MISMATCH,
    CLAIM_HARD_BINDINGS_MISSING, CLAIM_SIGNATURE_MISMATCH, CLAIM_SIGNATURE_MISSING,
    CLAIM_SIGNATURE_VALIDATED, SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
    SIGNING_CREDENTIAL_OCSP_REVOKED, SIGNING_CREDENTIAL_TRUSTED, SIGNING_CREDENTIAL_UNTRUSTED,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const REPORT_SCHEMA_VERSION: &str = "1.0";
pub const C2PA_PROFILE: &str = "c2pa-2.4";
const MAX_MANIFEST_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PATH_ASSET_BYTES: u64 = 128 * 1024 * 1024;
/// Largest DER `OCSPResponse` accepted as caller-supplied evidence.
const MAX_OCSP_EVIDENCE_BYTES: usize = 64 * 1024;
/// Largest external-data payload accepted as caller-supplied evidence.
const MAX_EXTERNAL_DATA_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

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
    /// RFC 3339 start of trust for every caller-supplied trust anchor. Before
    /// this instant the caller's anchors do not validate a signature, whatever
    /// the anchor certificate's own `notBefore` says. Bundled snapshots are
    /// unaffected.
    pub trust_anchor_not_before: Option<String>,
    /// RFC 3339 end of trust for every caller-supplied trust anchor. After this
    /// instant the caller's anchors no longer validate a signature. Bundled
    /// snapshots are unaffected.
    pub trust_anchor_not_after: Option<String>,
    /// Disable the bundled C2PA, IPTC, and Encypher trust snapshots. By
    /// default, caller-supplied PEM bundles extend those snapshots; setting
    /// this to `true` evaluates only caller-supplied trust material.
    pub no_default_trust: bool,
    /// Pinned offline DID-document store for CAWG ICA issuers, keyed by
    /// primary DID (no fragment). Resolution never touches the network.
    pub cawg_did_documents: Option<HashMap<String, Value>>,
    /// ICA issuer DIDs trusted directly by the caller.
    pub cawg_ica_trusted_issuers: Option<Vec<String>>,
    /// Trusted DID controller anchors. Issuers may trace to these anchors
    /// through `controller` links in caller-pinned DID documents.
    pub cawg_ica_trust_anchors: Option<Vec<String>>,
    /// Offline, decompressed revocation bitstrings keyed by
    /// `credentialStatus.statusListCredential` URI and encoded as standard
    /// base64. Missing lists fail closed without network access.
    pub cawg_ica_status_lists: Option<HashMap<String, String>>,
    /// OCSP responses a caller obtained online, keyed by the lowercase hex
    /// SHA-256 of the certificate's DER and encoded as standard base64 of the
    /// DER `OCSPResponse`.
    ///
    /// The SDK never fetches these for you at this layer: supply them from
    /// your own OCSP client, or let the SDK's consent-gated fetcher do it. A
    /// response is trusted no further than any other input - it must still be
    /// signed by an authorized responder for the certificate in question, and
    /// it is evaluated under the C2PA 2.4 and CAWG 1.3 online rules.
    pub ocsp_responses: Option<HashMap<String, String>>,
    /// Certificates whose OCSP responder was queried without a usable answer,
    /// by the same lowercase hex SHA-256 key.
    ///
    /// Each entry registers the `signingCredential.ocsp.inaccessible` (or
    /// `cawg.x509.ocsp.inaccessible`) informational code in place of the
    /// `ocsp.skipped` code a purely offline run reports.
    pub ocsp_unreachable: Option<Vec<String>>,
    /// Content of cloud-data and hashed external-reference assertions, keyed
    /// by the URI the assertion declares and encoded as standard base64.
    ///
    /// The bytes are hashed against the assertion's own `alg`/`hash` pair
    /// before anything else is done with them.
    pub external_data: Option<HashMap<String, String>>,
    /// Zero-based indexes into supplied fragments or stream segments where the
    /// player expects a discontinuity. Values must be unique, strictly
    /// increasing, and in bounds. Ignored by single-asset verification.
    pub expected_seek_positions: Vec<usize>,
    /// Apply the C2PA 2.4 Conformance Program posture instead of the default
    /// generous core-spec read. This raises applicable SHOULD requirements to
    /// the conformance bar and emits strict diagnostics in the reader report.
    /// It also requires CAWG Identity 1.3 deterministic `signer_payload` CBOR;
    /// the default accepts the CAWG 1.1 field order with
    /// `com.encypher.cawg.legacyProfile`.
    pub strict_conformance: bool,
    /// Refuse the CAWG field-order `signer_payload` encoding that c2pa-rs
    /// writes, without applying the rest of the conformance posture. When
    /// unset, the default accepts it with the informational
    /// `com.encypher.cawg.legacyProfile`; `strict_conformance` refuses it
    /// either way.
    pub cawg_strict_encoding: bool,
    /// RFC 3339 validation instant. Current UTC time is used when omitted.
    pub validation_time: Option<String>,
    /// Failure telemetry override. `None` uses the saved per-user preference.
    pub telemetry: TelemetryOptions,
    /// Allow this verification to fetch what the asset references: a manifest
    /// store held elsewhere, certificate revocation status, a `did:web`
    /// document, externally stored assertion content. `None` reads the
    /// `ENCYPHER_C2PA_ONLINE` environment variable and otherwise stays
    /// offline.
    ///
    /// A library call never consults the saved per-user choice and never
    /// prompts: the caller decides here, or the operator decides through the
    /// environment. Whatever is fetched is used as evidence only. The verdict
    /// is still reached by the same offline kernel.
    pub online: Option<bool>,
    /// Intranet mode: let online checks contact loopback, private, and
    /// link-local addresses, and accept plaintext `http` for every purpose
    /// rather than for OCSP alone.
    ///
    /// Off by default: a file that names an internal host would otherwise turn
    /// this verifier into a probe of the network it runs on. Turn it on for a
    /// deployment whose manifest repository or OCSP responder lives on a
    /// private address, and for tests that serve from `127.0.0.1`. Setting it
    /// declares that this machine's own network is trusted; do not set it on a
    /// host that verifies files sent in by strangers.
    pub online_allow_private_networks: bool,
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
    /// What this verification did, or could have done, on the network.
    #[serde(default)]
    pub network: NetworkReport,
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
    #[error(transparent)]
    OnlinePreference(#[from] OnlinePreferenceError),
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
            Self::OnlinePreference(_) => "online_preference_error",
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
/// segment (`.m4s`). Any contiguous subset may be supplied: each segment's
/// Merkle-tree location is authenticated and adjacency is enforced.
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

/// Verify one asset against a manifest store the caller supplies separately.
///
/// This is the entry point for provenance that does not travel inside the
/// asset: a `.c2pa` sidecar, a manifest fetched from the URI an asset declares
/// in its XMP `dcterms:provenance` key, or a store held in a repository. The
/// SDK never fetches any of those. It reads what the caller hands it.
///
/// The manifest binds to `asset` through its ordinary hard binding, evaluated
/// exactly as it would be for an embedded manifest, so a store paired with the
/// wrong or altered asset fails on the hash rather than on a weaker check.
/// Trust material, validation instant, CAWG identity configuration, and the
/// conformance posture all come from `options`, as they do for
/// [`verify_with_options`].
///
/// `mime_type` describes `asset`, not the store. `application/c2pa` is
/// rejected: the content side must be a real asset.
pub fn verify_with_manifest_store(
    asset: &[u8],
    manifest_store: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let telemetry_enabled = telemetry_consent::resolve_telemetry_enabled(options.telemetry.enabled);
    let result = verify_with_manifest_store_inner(asset, manifest_store, mime_type, options);
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

fn verify_with_manifest_store_inner(
    asset: &[u8],
    manifest_store: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let mime = resolve_mime(mime_type)?;
    let (mut report, needs) = detached_pass(asset, manifest_store, &mime, options)?;
    let (network, evidence) = online::gather(options, &needs);
    if evidence.is_empty() {
        report.network = network;
        return Ok(report);
    }
    // The store the caller supplied is the one that binds this asset. Pass 2
    // re-reads it with the fetched evidence; it never swaps in another store.
    let next = online::apply_evidence(options, &evidence);
    let (mut report, _) = detached_pass(asset, manifest_store, &mime, &next)?;
    report.network = network;
    Ok(report)
}

/// One offline verification of an asset against a separately held store, with
/// the network needs it recorded.
fn detached_pass(
    asset: &[u8],
    manifest_store: &[u8],
    mime: &str,
    options: &VerifyOptions,
) -> Result<(VerificationReport, Vec<online::NetworkNeed>), Error> {
    if manifest_store.is_empty() {
        return Err(Error::Verification("manifest store is empty".into()));
    }
    if manifest_store.len() > MAX_MANIFEST_STORE_BYTES {
        return Err(Error::Verification(format!(
            "manifest store exceeds the {MAX_MANIFEST_STORE_BYTES} byte limit"
        )));
    }
    let resolved = ResolvedOptions::resolve(options)?;
    let input = resolved.input(asset, mime);
    let output = crate::c2pa_validate::verify_detached_safe(
        manifest_store,
        asset,
        mime,
        &input,
        resolved.cawg_trust(),
        resolved.cawg_allowed_certs(),
        true,
        options.cawg_did_documents.as_ref(),
        options.cawg_ica_trusted_issuers.as_deref(),
        options.cawg_ica_trust_anchors.as_deref(),
        options.cawg_ica_status_lists.as_ref(),
    )
    .map_err(map_validate_error)?;
    let needs = online::network_needs(&output);
    Ok((
        report_from_output(output, mime.to_string(), &resolved),
        needs,
    ))
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
/// stream or any contiguous available subset; missing trailing fragments are
/// not a failure. Mark each intentional discontinuity by its zero-based index
/// in [`VerifyOptions::expected_seek_positions`].
pub fn verify_fragmented_with_options(
    init_segment: &[u8],
    fragments: &[&[u8]],
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let telemetry_enabled = telemetry_consent::resolve_telemetry_enabled(options.telemetry.enabled);
    let mime = canonicalize_mime(mime_type);
    let result = if crate::c2pa_formats::AssetFormat::from_mime(&mime)
        == Some(crate::c2pa_formats::AssetFormat::Bmff)
    {
        verify_with_options_inner(init_segment, Some(fragments), &mime, options)
    } else {
        Err(Error::UnsupportedMime(mime))
    };
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

/// Trust material, validation instant, and engine profile resolved once from
/// [`VerifyOptions`].
///
/// Every entry point - asset, fragmented, and stream - resolves its inputs
/// here, so a stream can never be verified against different trust material
/// than a single asset would be.
pub(crate) struct ResolvedOptions {
    claim_trust: Option<ResolvedTrust>,
    tsa_trust: Option<ResolvedTrust>,
    allowed_certs: Option<ResolvedTrust>,
    cawg_trust: Option<ResolvedTrust>,
    cawg_allowed_certs: Option<ResolvedTrust>,
    validation_time: OffsetDateTime,
    validation_time_text: String,
    trust_basis: &'static str,
    profile: EngineProfile,
    cawg_strict_encoding: bool,
    /// Caller-supplied online evidence, base64-decoded once.
    ocsp_responses: HashMap<String, Vec<u8>>,
    ocsp_unreachable: Vec<String>,
    external_data: HashMap<String, Vec<u8>>,
}

impl ResolvedOptions {
    pub(crate) fn resolve(options: &VerifyOptions) -> Result<Self, Error> {
        let use_defaults = !options.no_default_trust;
        let validation_time = parse_validation_time(options.validation_time.as_deref())?;
        let custom_claim_trust = options.trust_pem.is_some() || options.allowed_list_pem.is_some();
        let bounds = (
            parse_optional_instant(
                options.trust_anchor_not_before.as_deref(),
                "trust_anchor_not_before",
            )?,
            parse_optional_instant(
                options.trust_anchor_not_after.as_deref(),
                "trust_anchor_not_after",
            )?,
        );
        Ok(Self {
            claim_trust: resolve_trust(
                options.trust_pem.as_deref(),
                use_defaults.then(default_trust::claim_signing),
                AnchorPurpose::ClaimSigning,
                bounds,
            )?,
            tsa_trust: resolve_trust(
                options.tsa_trust_pem.as_deref(),
                use_defaults.then(default_trust::timestamp_authorities),
                AnchorPurpose::TimeStamping,
                bounds,
            )?,
            allowed_certs: resolve_trust(
                options.allowed_list_pem.as_deref(),
                use_defaults.then(default_trust::allowed_claim_signers),
                AnchorPurpose::ClaimSigning,
                bounds,
            )?,
            cawg_trust: resolve_trust(
                options.cawg_trust_pem.as_deref(),
                use_defaults.then(default_trust::cawg_identity),
                AnchorPurpose::CawgIdentity,
                bounds,
            )?,
            cawg_allowed_certs: resolve_trust(
                options.cawg_allowed_certs_pem.as_deref(),
                use_defaults.then(default_trust::cawg_allowed_identities),
                AnchorPurpose::CawgIdentity,
                bounds,
            )?,
            validation_time,
            validation_time_text: validation_time
                .format(&Rfc3339)
                .map_err(|error| Error::InvalidValidationTime(error.to_string()))?,
            trust_basis: match (use_defaults, custom_claim_trust) {
                (true, true) => "bundled_and_caller_supplied_static_material",
                (true, false) => "bundled_static_material",
                (false, true) => "caller_supplied_static_material",
                (false, false) => "none",
            },
            profile: if options.strict_conformance {
                EngineProfile::strict(SpecVersion::V2_4)
            } else {
                EngineProfile::GENEROUS
            },
            cawg_strict_encoding: options.cawg_strict_encoding,
            ocsp_responses: decode_base64_map(
                options.ocsp_responses.as_ref(),
                "ocsp_responses",
                MAX_OCSP_EVIDENCE_BYTES,
            )?,
            ocsp_unreachable: options.ocsp_unreachable.clone().unwrap_or_default(),
            external_data: decode_base64_map(
                options.external_data.as_ref(),
                "external_data",
                MAX_EXTERNAL_DATA_EVIDENCE_BYTES,
            )?,
        })
    }

    pub(crate) fn input<'a>(&'a self, data: &'a [u8], mime: &'a str) -> VerifyInput<'a> {
        VerifyInput {
            data,
            mime,
            claim_signer_trust: self.claim_trust.as_ref().map(ResolvedTrust::get),
            tsa_trust: self.tsa_trust.as_ref().map(ResolvedTrust::get),
            allowed_certs: self.allowed_certs.as_ref().map(ResolvedTrust::get),
            validation_time: Some(self.validation_time),
            profile: self.profile,
            cawg_strict_encoding: self.cawg_strict_encoding,
            evidence: crate::c2pa_validate::OnlineEvidence {
                ocsp_responses: (!self.ocsp_responses.is_empty()).then_some(&self.ocsp_responses),
                ocsp_unreachable: (!self.ocsp_unreachable.is_empty())
                    .then_some(self.ocsp_unreachable.as_slice()),
                external_data: (!self.external_data.is_empty()).then_some(&self.external_data),
            },
        }
    }

    pub(crate) fn cawg_trust(&self) -> Option<&TrustList> {
        self.cawg_trust.as_ref().map(ResolvedTrust::get)
    }

    pub(crate) fn cawg_allowed_certs(&self) -> Option<&TrustList> {
        self.cawg_allowed_certs.as_ref().map(ResolvedTrust::get)
    }
}

/// Decode a map of standard-base64 evidence values, rejecting anything
/// malformed or over `max_bytes` rather than silently ignoring it.
///
/// A caller who hands the SDK evidence deserves to hear that it was unusable;
/// dropping it would show up much later as an unexplained `ocsp.skipped`.
fn decode_base64_map(
    values: Option<&HashMap<String, String>>,
    field: &str,
    max_bytes: usize,
) -> Result<HashMap<String, Vec<u8>>, Error> {
    let Some(values) = values else {
        return Ok(HashMap::new());
    };
    let mut decoded = HashMap::with_capacity(values.len());
    for (key, encoded) in values {
        let bytes = crate::c2pa_formats::util::base64_decode(encoded)
            .ok_or_else(|| Error::Verification(format!("{field}[{key}] is not standard base64")))?;
        if bytes.len() > max_bytes {
            return Err(Error::Verification(format!(
                "{field}[{key}] exceeds the {max_bytes} byte limit"
            )));
        }
        decoded.insert(key.clone(), bytes);
    }
    Ok(decoded)
}

/// Canonicalize `mime_type` and reject one the C2PA 2.4 profile cannot read.
pub(crate) fn resolve_mime(mime_type: &str) -> Result<String, Error> {
    let mime = canonicalize_mime(mime_type);
    if !mimes_for_version(SpecVersion::V2_4).contains(&mime.as_str())
        || crate::c2pa_formats::AssetFormat::from_mime(&mime).is_none()
    {
        return Err(Error::UnsupportedMime(mime));
    }
    Ok(mime)
}

pub(crate) fn map_validate_error(error: crate::c2pa_validate::ValidateError) -> Error {
    match error {
        crate::c2pa_validate::ValidateError::UnsupportedMime(value) => {
            Error::UnsupportedMime(value)
        }
        other => Error::Verification(other.to_string()),
    }
}

/// Assemble the caller-facing report from one kernel verification.
pub(crate) fn report_from_output(
    output: crate::c2pa_validate::VerifyOutput,
    mime: String,
    resolved: &ResolvedOptions,
) -> VerificationReport {
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
    let trust = trust_report(
        &output.results,
        present,
        resolved.trust_basis,
        resolved.validation_time_text.clone(),
    );
    VerificationReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        profile: C2PA_PROFILE.to_string(),
        mime_type: mime,
        present,
        integrity,
        signature: signature_status(&output.results),
        hard_binding: hard_binding_status(&output.results),
        trust,
        policy: None,
        managed_receipt: None,
        validation_state: output.validation_state.as_str().to_string(),
        validation_results: copy_results(&output.results),
        manifest_report: output.report_json,
        content_credentials: output.crjson,
        network: NetworkReport::default(),
    }
}

fn verify_with_options_inner(
    data: &[u8],
    fragments: Option<&[&[u8]]>,
    mime_type: &str,
    options: &VerifyOptions,
) -> Result<VerificationReport, Error> {
    let mime = resolve_mime(mime_type)?;
    let (mut report, needs) = embedded_pass(data, fragments, &mime, options)?;
    let (mut network, evidence) = online::gather(options, &needs);
    if evidence.is_empty() {
        report.network = network;
        return Ok(report);
    }
    let next = online::apply_evidence(options, &evidence);
    let second = match (evidence.manifest_store.as_deref(), fragments) {
        // The asset said where its manifest store lives and the store was
        // fetched. Pass 2 verifies the asset against it exactly as it would
        // against a sidecar handed in by the caller, hard binding and all.
        (Some(store), None) => detached_pass(data, store, &mime, &next),
        _ => embedded_pass(data, fragments, &mime, &next),
    };
    match second {
        Ok((mut second, _)) => {
            second.network = network;
            Ok(second)
        }
        // What the server returned is not a manifest store this asset can be
        // verified against. That is an answer about the file, not a failure of
        // this SDK, so the offline verdict stands and the reason is recorded.
        Err(error) => {
            network.mark_unusable("remote_manifest", error.to_string());
            report.network = network;
            Ok(report)
        }
    }
}

/// One offline verification of an asset's own bytes, with the network needs it
/// recorded.
fn embedded_pass(
    data: &[u8],
    fragments: Option<&[&[u8]]>,
    mime: &str,
    options: &VerifyOptions,
) -> Result<(VerificationReport, Vec<online::NetworkNeed>), Error> {
    let resolved = ResolvedOptions::resolve(options)?;
    let input = resolved.input(data, mime);
    let output = match fragments {
        Some(fragments) => verify_fragmented_safe(
            &input,
            fragments,
            &options.expected_seek_positions,
            resolved.cawg_trust(),
            resolved.cawg_allowed_certs(),
            true,
            options.cawg_did_documents.as_ref(),
            options.cawg_ica_trusted_issuers.as_deref(),
            options.cawg_ica_trust_anchors.as_deref(),
            options.cawg_ica_status_lists.as_ref(),
        ),
        None => verify_safe(
            &input,
            resolved.cawg_trust(),
            resolved.cawg_allowed_certs(),
            true,
            options.cawg_did_documents.as_ref(),
            options.cawg_ica_trusted_issuers.as_deref(),
            options.cawg_ica_trust_anchors.as_deref(),
            options.cawg_ica_status_lists.as_ref(),
        ),
    }
    .map_err(map_validate_error)?;
    let needs = online::network_needs(&output);
    Ok((
        report_from_output(output, mime.to_string(), &resolved),
        needs,
    ))
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
    ("heics", "image/heic-sequence"),
    ("heif", "image/heif"),
    ("heifs", "image/heif-sequence"),
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
    (
        "dotx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ),
    ("docm", "application/vnd.ms-word.document.macroenabled.12"),
    ("dotm", "application/vnd.ms-word.template.macroenabled.12"),
    (
        "xltx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    ),
    ("xlsm", "application/vnd.ms-excel.sheet.macroenabled.12"),
    ("xltm", "application/vnd.ms-excel.template.macroenabled.12"),
    (
        "xlsb",
        "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    ),
    (
        "ppsx",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    ),
    (
        "potx",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
    ),
    (
        "pptm",
        "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    ),
    (
        "ppsm",
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    ),
    (
        "potm",
        "application/vnd.ms-powerpoint.template.macroenabled.12",
    ),
    ("vsdx", "application/vnd.ms-visio.drawing"),
    ("vsdm", "application/vnd.ms-visio.drawing.macroenabled.12"),
    ("vssx", "application/vnd.ms-visio.stencil"),
    ("vssm", "application/vnd.ms-visio.stencil.macroenabled.12"),
    ("vstx", "application/vnd.ms-visio.template"),
    ("vstm", "application/vnd.ms-visio.template.macroenabled.12"),
    ("oxps", "application/oxps"),
    ("xps", "application/vnd.ms-xpsdocument"),
    ("odt", "application/vnd.oasis.opendocument.text"),
    ("ods", "application/vnd.oasis.opendocument.spreadsheet"),
    ("odp", "application/vnd.oasis.opendocument.presentation"),
    ("odg", "application/vnd.oasis.opendocument.graphics"),
    ("ttf", "font/ttf"),
    ("otf", "font/otf"),
    ("sfnt", "font/sfnt"),
    ("txt", "text/plain"),
    ("tsv", "text/tab-separated-values"),
    ("csv", "text/csv"),
    ("md", "text/markdown"),
    ("markdown", "text/markdown"),
    ("html", "text/html"),
    ("htm", "text/html"),
    ("xhtml", "application/xhtml+xml"),
    ("xml", "application/xml"),
    ("css", "text/css"),
    ("js", "application/javascript"),
    ("mjs", "application/javascript"),
    ("json", "application/json"),
    ("yaml", "application/yaml"),
    ("yml", "application/yaml"),
    ("toml", "application/toml"),
    ("py", "text/x-python"),
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

/// Resolve one purpose's trust store: the bundled snapshot, the caller's PEM
/// bundle, or the snapshot extended by it.
///
/// Caller-supplied anchors take the configured `bounds`; bundled snapshots stay
/// unbounded, because their trust window is the snapshot itself.
///
/// CAWG identity material a caller supplies is an entry that caller configured
/// as the validator, so it is accepted under the CAWG Identity 1.3 base trust
/// model rather than under the interim S/MIME additions, which belong to the
/// two root stores that section names.
fn resolve_trust(
    custom_pem: Option<&str>,
    bundled: Option<&'static TrustList>,
    purpose: AnchorPurpose,
    bounds: (Option<OffsetDateTime>, Option<OffsetDateTime>),
) -> Result<Option<ResolvedTrust>, Error> {
    let custom = custom_pem
        .map(|pem| TrustList::from_pem_for(purpose, pem))
        .transpose()
        .map_err(|error| Error::InvalidTrust(error.to_string()))?
        .map(|trust| trust.with_bounds(bounds.0, bounds.1))
        .map(|trust| match purpose {
            AnchorPurpose::CawgIdentity => trust.with_cawg_source(CawgTrustSource::CallerSupplied),
            _ => trust,
        });
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

/// Parse an optional RFC 3339 trust-anchor bound, naming the field in the error
/// so a caller can tell which of the two bounds it mistyped.
fn parse_optional_instant(
    value: Option<&str>,
    field: &str,
) -> Result<Option<OffsetDateTime>, Error> {
    value
        .map(|raw| {
            OffsetDateTime::parse(raw, &Rfc3339)
                .map_err(|error| Error::InvalidValidationTime(format!("{field}: {error}")))
        })
        .transpose()
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
    // Checked before the match set, and it has to be: a manifest that binds
    // only its init segment DOES produce `assertion.bmffHash.match` over those
    // bytes, so a match-first read would answer "match" for a stream whose
    // media segments nothing covered. The axis answers "is every byte the
    // caller presented bound?", so an unbound or unauthenticated segment is a
    // mismatch no matter what else matched (PRD 1.1.1).
    if results.has_failure(crate::c2pa_validate::live_video::LIVEVIDEO_SEGMENT_INVALID) {
        "mismatch"
    } else if MATCHES.iter().any(|code| results.has_success(code)) {
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
            source: if !(revoked || not_revoked) {
                "none"
            } else if results
                .success
                .iter()
                .chain(&results.failure)
                .filter(|status| {
                    status.code == SIGNING_CREDENTIAL_OCSP_REVOKED
                        || status.code == SIGNING_CREDENTIAL_OCSP_NOT_REVOKED
                })
                .any(|status| {
                    status
                        .details
                        .as_ref()
                        .and_then(|details| details.get("source"))
                        .and_then(Value::as_str)
                        == Some("online_ocsp")
                })
            {
                "online_ocsp"
            } else {
                "embedded_ocsp"
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
    use super::{
        mime_from_path, read_bounded_file, supported_mime_types, verify, verify_fragmented,
        verify_with_options, Error, VerifyOptions,
    };
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

    /// A supported format with no extension can only be verified by passing
    /// its MIME type by hand, so a file named `report.oxps` failed on the
    /// command line as unsupported. Only alias names of a mapped type are exempt.
    #[test]
    fn every_supported_format_is_reachable_from_an_extension() {
        const ALIASES: &[&str] = &[
            "application/font-sfnt",
            "application/x-font-ttf",
            "application/mp4",
            "video/x-m4v",
            "text/xml",
        ];
        let unreachable: Vec<_> = supported_mime_types()
            .into_iter()
            .filter(|mime| !ALIASES.contains(mime))
            .filter(|mime| !super::SUPPORTED_EXTENSIONS.iter().any(|(_, m)| m == mime))
            .collect();
        assert!(
            unreachable.is_empty(),
            "no extension maps to {unreachable:?}"
        );
        assert_eq!(
            mime_from_path(Path::new("report.OXPS")),
            Some("application/oxps")
        );
    }

    /// The trust block names where a revocation answer came from, so a reader
    /// can tell a stapled response from one fetched with the user's consent.
    #[test]
    fn revocation_source_distinguishes_online_from_embedded_ocsp() {
        use crate::c2pa_validate::{StatusCode, ValidationResults};
        let status = |source: Option<&str>| StatusCode {
            code: crate::c2pa_validate::SIGNING_CREDENTIAL_OCSP_NOT_REVOKED.into(),
            url: "self#jumbf=/c2pa/urn:c2pa:x/c2pa.signature".into(),
            explanation: "not revoked".into(),
            details: source.map(|source| serde_json::json!({ "source": source })),
        };
        let report = |source: Option<&str>| {
            let results = ValidationResults {
                success: vec![status(source)],
                ..ValidationResults::default()
            };
            super::trust_report(&results, true, "bundled_static_material", String::new())
                .revocation
                .source
        };
        assert_eq!(report(Some("online_ocsp")), "online_ocsp");
        assert_eq!(report(None), "embedded_ocsp");
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
    fn strict_conformance_option_selects_the_program_profile() {
        let asset = include_bytes!("../../../tests/fixtures/signed_test.jpg");
        let report = verify_with_options(
            asset,
            "image/jpeg",
            &VerifyOptions {
                strict_conformance: true,
                ..VerifyOptions::default()
            },
        )
        .unwrap();
        assert_eq!(
            report.manifest_report["engine_profile"]["operating_mode"],
            "conformance"
        );
        assert_eq!(
            report.manifest_report["engine_profile"]["compliance_level"],
            "conformance-program"
        );
    }

    #[test]
    fn fragmented_entry_point_rejects_non_bmff_mime() {
        let error = verify_fragmented(
            include_bytes!("../../../tests/fixtures/signed_test.jpg"),
            &[b"ignored fragment"],
            "image/jpeg",
        )
        .unwrap_err();
        assert!(matches!(error, Error::UnsupportedMime(mime) if mime == "image/jpeg"));
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
