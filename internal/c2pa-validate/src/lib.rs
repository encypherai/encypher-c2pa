//! C2PA manifest verification pipeline.
//!
//! Given asset bytes, a MIME type, optional trust configuration, and an optional
//! validation time, [`verify`] reproduces the reference verifier semantics and
//! the C2PA status-code model:
//!
//! 1. Extract the JUMBF manifest store for the asset's format (via
//!    [`c2pa_formats`]).
//! 2. Parse the store ([`c2pa_core::jumbf::parse_manifest_store`]); the active
//!    manifest is the last in store order.
//! 3. Decode the claim CBOR.
//! 4. Verify the COSE claim signature against the leaf certificate.
//! 5. Recompute each created/gathered assertion's hashed-URI binding.
//! 6. Verify the `c2pa.hash.data` hard binding against the asset bytes
//!    (honoring the assertion's exclusion ranges).
//! 7. Validate the signing certificate chain against the supplied trust list,
//!    honoring an explicit `validation_time`.
//! 8. Record any attached RFC 3161 timestamp.
//! 9. Check the signing certificate's validity window at the validation time.
//!
//! The result is a [`ValidationResults`] partitioned into success /
//! informational / failure status codes, a [`ValidationState`], and a JSON
//! report matching the reader-report SSOT shape.
//!
//! The validation state is posture-dependent. In the strict / conformance
//! posture an untrusted signing credential does **not** invalidate a manifest
//! (it only prevents [`ValidationState::Trusted`]); every other failure
//! (signature mismatch, hash mismatch, missing claim) yields
//! [`ValidationState::Invalid`]. In the generous regular/core-spec posture the
//! full non-invalidating set ([`REGULAR_INTEGRITY_CAVEATS`]: cert-time, trust,
//! OCSP, timestamp, and conformance-policy codes) is treated as surfaced
//! caveats, so only a construction-integrity failure yields `Invalid`.

mod cache;
mod cawg;
pub use cawg::{
    CAWG_ICA_DID_UNAVAILABLE, CAWG_IDENTITY_ASSERTION_DUPLICATE, CAWG_IDENTITY_ASSERTION_MISMATCH,
    CAWG_IDENTITY_CBOR_INVALID, CAWG_IDENTITY_EXPECTED_CLAIM_GENERATOR_MISMATCH,
    CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISMATCH, CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING,
    CAWG_IDENTITY_EXPECTED_PARTIAL_CLAIM_MISMATCH, CAWG_IDENTITY_HARD_BINDING_INCORRECT,
    CAWG_IDENTITY_HARD_BINDING_MISSING, CAWG_IDENTITY_PAD_INVALID, CAWG_IDENTITY_SIG_TYPE_UNKNOWN,
    CAWG_IDENTITY_TRUSTED, CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER, CAWG_IDENTITY_WELL_FORMED,
    CAWG_LEGACY_PROFILE,
};
mod cawg_ica;
pub use cawg_ica::{
    CAWG_ICA_CREDENTIAL_VALID, CAWG_ICA_DID_UNSUPPORTED_METHOD, CAWG_ICA_INVALID_ALG,
    CAWG_ICA_INVALID_CONTENT_TYPE, CAWG_ICA_INVALID_COSE_SIGN1, CAWG_ICA_INVALID_DID_DOCUMENT,
    CAWG_ICA_INVALID_ISSUER, CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL, CAWG_ICA_SIGNATURE_MISMATCH,
    CAWG_ICA_SIGNER_PAYLOAD_MISMATCH, CAWG_ICA_TIME_STAMP_INVALID, CAWG_ICA_TIME_STAMP_VALIDATED,
    CAWG_ICA_VALID_FROM_INVALID, CAWG_ICA_VALID_FROM_MISSING, CAWG_ICA_VALID_UNTIL_INVALID,
};
mod cert;
mod crjson;
mod observe;
mod report;
pub mod versions;
pub use crjson::{crjson_from_asset, to_crjson};
pub use versions::{ClaimGeneration, VersionEvaluation, VersionVerdict};

pub use cache::{CachedResult, VerifyCache};
pub use observe::{global as global_metrics, Metrics, MetricsSnapshot};

use c2pa_cbor::{decode, Value};
use c2pa_core::jumbf::{
    manifest_superboxes_from_store, parse_manifest_store, superbox_content, ParsedManifest,
    ParsedStore,
};
pub use c2pa_core::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
use c2pa_crypto::{extract_tsa_token, extract_x5chain, timestamp_input, verify_claim};
use c2pa_formats::{text_standard, AssetFormat};
use c2pa_trust::{validate_chain, TrustList};
use serde::Serialize;
use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Status code constants (C2PA 2.x validation status codes)
// ---------------------------------------------------------------------------

/// Claim signature cryptographically verified.
pub const CLAIM_SIGNATURE_VALIDATED: &str = "claimSignature.validated";
/// Claim signature failed to verify.
pub const CLAIM_SIGNATURE_MISMATCH: &str = "claimSignature.mismatch";
/// The claim signature box is absent or unreadable (e.g. mislabeled box,
/// invalid signature URI).
pub const CLAIM_SIGNATURE_MISSING: &str = "claimSignature.missing";
/// Signing certificate valid at the validation time.
pub const CLAIM_SIGNATURE_INSIDE_VALIDITY: &str = "claimSignature.insideValidity";
/// The signing certificate was outside its validity window at validation time.
pub const CLAIM_SIGNATURE_OUTSIDE_VALIDITY: &str = "claimSignature.outsideValidity";
/// Assertion hashed-URI binding matched.
pub const ASSERTION_HASHED_URI_MATCH: &str = "assertion.hashedURI.match";
/// Assertion hashed-URI binding mismatched (or assertion absent).
pub const ASSERTION_HASHED_URI_MISMATCH: &str = "assertion.hashedURI.mismatch";
/// `c2pa.hash.data` hard binding matched the asset.
pub const ASSERTION_DATA_HASH_MATCH: &str = "assertion.dataHash.match";
/// `c2pa.hash.data` hard binding did not match the asset.
pub const ASSERTION_DATA_HASH_MISMATCH: &str = "assertion.dataHash.mismatch";
/// Informational: a C2PA 2.4 data-hash binding excludes bytes beyond its
/// manifest carrier.
pub const ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT: &str =
    "assertion.dataHash.additionalExclusionsPresent";
/// Success: a `c2pa.hash.bmff*` box-based hard binding matched the asset.
pub const ASSERTION_BMFF_HASH_MATCH: &str = "assertion.bmffHash.match";
/// Failure: a `c2pa.hash.bmff*` box-based hard binding did not match.
pub const ASSERTION_BMFF_HASH_MISMATCH: &str = "assertion.bmffHash.mismatch";
/// Failure: a `c2pa.hash.bmff*` merkle structure (or a fragment's auxiliary
/// C2PA `merkle` box) is structurally invalid per spec 15.12.2.2 / A.5.4.
pub const ASSERTION_BMFF_HASH_MALFORMED: &str = "assertion.bmffHash.malformed";
/// Success: every general box hash range matched (`c2pa.hash.boxes`).
pub const ASSERTION_BOXES_HASH_MATCH: &str = "assertion.boxesHash.match";
/// Failure: a box-hash range did not match, or boxes appeared out of order.
pub const ASSERTION_BOXES_HASH_MISMATCH: &str = "assertion.boxesHash.mismatch";
/// Failure: the `c2pa.hash.boxes` assertion is structurally invalid.
pub const ASSERTION_BOXES_HASH_MALFORMED: &str = "assertion.boxesHash.malformed";
/// Failure: the asset contains boxes not covered by the assertion.
pub const ASSERTION_BOXES_HASH_UNKNOWN_BOX: &str = "assertion.boxesHash.unknownBox";
/// Success: every collection URI hash (and the ZIP central directory) matched.
pub const ASSERTION_COLLECTION_HASH_MATCH: &str = "assertion.collectionHash.match";
/// Failure: a collection entry's bytes (or the ZIP central directory) did not
/// match its recorded hash.
pub const ASSERTION_COLLECTION_HASH_MISMATCH: &str = "assertion.collectionHash.mismatch";
/// Failure: the `c2pa.hash.collection.data` assertion is structurally invalid.
pub const ASSERTION_COLLECTION_HASH_MALFORMED: &str = "assertion.collectionHash.malformed";
/// Failure: a collection URI contains `.` or `..` path segments.
pub const ASSERTION_COLLECTION_HASH_INVALID_URI: &str = "assertion.collectionHash.invalidURI";
/// Failure: a file listed in the collection assertion is absent from the archive.
pub const ASSERTION_COLLECTION_HASH_INCORRECT_FILE_COUNT: &str =
    "assertion.collectionHash.incorrectFileCount";
/// Success: every required multi-asset part matched its part hash.
pub const ASSERTION_MULTI_ASSET_HASH_MATCH: &str = "assertion.multiAssetHash.match";
/// Failure: a multi-asset part's bytes did not match its part hash.
pub const ASSERTION_MULTI_ASSET_HASH_MISMATCH: &str = "assertion.multiAssetHash.mismatch";
/// Failure: a required multi-asset part is absent/truncated.
pub const ASSERTION_MULTI_ASSET_HASH_MISSING_PART: &str = "assertion.multiAssetHash.missingPart";
/// Failure: the multi-asset hash assertion is structurally malformed.
pub const ASSERTION_MULTI_ASSET_HASH_MALFORMED: &str = "assertion.multiAssetHash.malformed";
/// Signing certificate chained to a trust anchor.
pub const SIGNING_CREDENTIAL_TRUSTED: &str = "signingCredential.trusted";
/// Signing certificate did not chain to a trust anchor (or was invalid at the
/// validation time). Never invalidates integrity: in the strict posture it is
/// the only non-invalidating failure, and in the generous posture it is one of
/// the [`REGULAR_INTEGRITY_CAVEATS`] (the trust axis carries it, not `caveats[]`).
pub const SIGNING_CREDENTIAL_UNTRUSTED: &str = "signingCredential.untrusted";
/// Signing certificate structurally invalid or absent.
pub const SIGNING_CREDENTIAL_INVALID: &str = "signingCredential.invalid";
/// Stapled OCSP response says the signing certificate is not revoked.
pub const SIGNING_CREDENTIAL_OCSP_NOT_REVOKED: &str = "signingCredential.ocsp.notRevoked";
/// Stapled OCSP response says the signing certificate is revoked.
pub const SIGNING_CREDENTIAL_OCSP_REVOKED: &str = "signingCredential.ocsp.revoked";
/// No usable OCSP staple; revocation check skipped (informational).
pub const SIGNING_CREDENTIAL_OCSP_SKIPPED: &str = "signingCredential.ocsp.skipped";
/// RFC 3161 timestamp token present and message digest matched.
pub const TIME_STAMP_VALIDATED: &str = "timeStamp.validated";
/// RFC 3161 timestamp present but the TSA certificate is untrusted.
pub const TIME_STAMP_UNTRUSTED: &str = "timeStamp.untrusted";
/// RFC 3161 timestamp present and the TSA certificate chains to the TSA trust list.
pub const TIME_STAMP_TRUSTED: &str = "timeStamp.trusted";
/// RFC 3161 timestamp genTime fell outside the TSA certificate's validity window.
pub const TIME_STAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";
/// No trusted RFC 3161 timestamp present. Informational under the core spec
/// (timestamping is a SHOULD); a hard failure under the conformance program,
/// which upgrades it to a SHALL.
pub const TIME_STAMP_MISSING: &str = "timeStamp.missing";
/// No claim (or no manifest) found.
pub const CLAIM_MISSING: &str = "claim.missing";
/// Claim CBOR could not be decoded.
pub const CLAIM_CBOR_INVALID: &str = "claim.cbor.invalid";
/// More than one claim box present in a single manifest.
pub const CLAIM_MULTIPLE: &str = "claim.multiple";
/// Claim is missing a required v2 field (e.g. `instanceID`, `created_assertions`).
pub const CLAIM_MALFORMED: &str = "claim.malformed";
/// Claim references no hard-binding (`c2pa.hash.*`) assertion.
pub const CLAIM_HARD_BINDINGS_MISSING: &str = "claim.hardBindings.missing";
/// A referenced assertion uses an unsupported hash algorithm.
pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";
/// An assertion's CBOR could not be decoded.
pub const ASSERTION_CBOR_INVALID: &str = "assertion.cbor.invalid";
/// A claim referenced an assertion that is not present in the manifest store.
pub const HASHED_URI_MISSING: &str = "hashedURI.missing";
/// An ingredient references a manifest not present in the manifest store.
pub const INGREDIENT_MANIFEST_MISSING: &str = "ingredient.manifest.missing";
/// Informational (conformance mode only): the asset's format is outside the
/// certified conformance scope for the active spec version. Verification still
/// proceeds and reports normally; this records the scope observation for
/// conformance evidence. Never emitted in regular/generous verification.
pub const CONFORMANCE_OUT_OF_SCOPE: &str = "conformanceScope.outOfScope";
/// Conformance-mode-only: the manifest's structure does not conform to the
/// profile's *target* spec revision (per the version ladder). Informational
/// under [`ComplianceLevel::CoreSpec`] (records the observation), a hard
/// failure under [`ComplianceLevel::ConformanceProgram`] (the strict internal
/// conformance-analysis bar). Never emitted in regular/generous verification —
/// the public verify posture reports the ladder via `version_verdict` without
/// judging against a target. A policy code: it does not clear
/// `version_verdict.validated_under` (the manifest may conform perfectly to a
/// *different* revision — that is exactly the diagnostic).
pub const CONFORMANCE_SPEC_VERSION_NONCONFORMANT: &str =
    "conformanceScope.specVersion.nonConformant";
/// EXPERIMENTAL (PR #2058 compound): the host-less `c2pa.compound.content`
/// binding verified — every component's `ingredientRef` hashed-URI resolved to a
/// present `c2pa.ingredient.v3` assertion whose JUMBF content hash matched.
/// This is the compound parent's hard-binding success (it has no host asset).
pub const ASSERTION_COMPOUND_CONTENT_MATCH: &str = "assertion.compoundContent.match";
/// EXPERIMENTAL (PR #2058 compound): a component's `ingredientRef` hashed-URI
/// did not resolve to a present assertion, or its content hash mismatched. The
/// compound binding is broken. Failure.
pub const ASSERTION_COMPOUND_CONTENT_MISMATCH: &str = "assertion.compoundContent.mismatch";
/// EXPERIMENTAL (PR #2058 compound): the `c2pa.compound.content` assertion is
/// structurally invalid (undecodable, no `components`, or a component missing a
/// well-formed `ingredientRef` {url, hash, alg}). Failure.
pub const ASSERTION_COMPOUND_CONTENT_MALFORMED: &str = "assertion.compoundContent.malformed";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that prevent the verifier from producing a validation result.
///
/// A missing manifest is **not** an error — it yields a graceful result: the
/// generous posture reports [`ValidationState::None`] (no provenance), while the
/// strict posture reports [`ValidationState::Invalid`] + [`CLAIM_MISSING`].
#[derive(Debug, Error)]
pub enum ValidateError {
    /// The MIME type does not map to a supported asset format.
    #[error("unsupported MIME type: {0}")]
    UnsupportedMime(String),
    /// The asset's container could not be parsed to locate a manifest store.
    #[error("format extraction failed: {0}")]
    Format(#[from] c2pa_formats::FormatError),
    /// The manifest store JUMBF structure could not be parsed.
    #[error("manifest store parse failed: {0}")]
    Jumbf(#[from] c2pa_core::jumbf::JumbfError),
    /// A prepared manifest did not carry one canonical SHA-256 hard binding.
    #[error("prepared hard binding invalid: {0}")]
    PreparedBinding(String),
    /// Verification panicked internally; contained at the API boundary so it
    /// never crosses an FFI/gRPC edge as an abort.
    #[error("internal verification panic (contained)")]
    Panic,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Overall validation state of the active manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ValidationState {
    /// Manifest integrity intact but the signer is not trusted.
    Valid,
    /// A failure broke manifest integrity (signature/hash/claim).
    Invalid,
    /// Integrity intact and the signing credential chained to a trust anchor.
    Trusted,
    /// No provenance to judge: the asset carries no C2PA manifest at all. Only
    /// emitted in the generous (regular/core-spec) posture; the strict posture
    /// keeps an absent manifest as `Invalid` + `claim.missing`.
    None,
}

impl ValidationState {
    /// The state's canonical string form (`"Valid"`, `"Invalid"`, `"Trusted"`, `"None"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationState::Valid => "Valid",
            ValidationState::Invalid => "Invalid",
            ValidationState::Trusted => "Trusted",
            ValidationState::None => "None",
        }
    }
}

/// A single validation status code with its JUMBF URL and human explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusCode {
    /// The C2PA status code, e.g. `"claimSignature.validated"`.
    pub code: String,
    /// The JUMBF URI the status applies to.
    pub url: String,
    /// Human-readable explanation.
    pub explanation: String,
    /// Machine-readable evidence for extension status codes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Json>,
}

/// Validation status codes partitioned by severity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValidationResults {
    /// Codes for checks that passed.
    pub success: Vec<StatusCode>,
    /// Advisory codes that do not affect validity (e.g. `timeStamp.untrusted`,
    /// `signingCredential.ocsp.skipped`). Reserved: emitting these requires RFC
    /// 3161 timestamp-token and OCSP verification, which the workspace crates do
    /// not yet provide, so this bucket is currently always empty.
    pub informational: Vec<StatusCode>,
    /// Codes for checks that failed.
    pub failure: Vec<StatusCode>,
}

impl ValidationResults {
    /// True when `code` appears in the success bucket.
    pub fn has_success(&self, code: &str) -> bool {
        self.success.iter().any(|s| s.code == code)
    }
    /// True when `code` appears in the failure bucket.
    pub fn has_failure(&self, code: &str) -> bool {
        self.failure.iter().any(|s| s.code == code)
    }
    /// True when `code` appears in the informational bucket.
    pub fn has_informational(&self, code: &str) -> bool {
        self.informational.iter().any(|s| s.code == code)
    }

    fn push_success(&mut self, code: &str, url: String, explanation: String) {
        self.success.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: None,
        });
    }
    fn push_success_with_details(
        &mut self,
        code: &str,
        url: String,
        explanation: String,
        details: Json,
    ) {
        self.success.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: Some(details),
        });
    }
    fn push_failure(&mut self, code: &str, url: String, explanation: String) {
        self.failure.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: None,
        });
    }
    fn push_informational(&mut self, code: &str, url: String, explanation: String) {
        self.informational.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: None,
        });
    }
}

/// Inputs to [`verify`].
pub struct VerifyInput<'a> {
    /// Raw asset bytes (the full file).
    pub data: &'a [u8],
    /// Asset MIME type, used to select the container format.
    pub mime: &'a str,
    /// Trust list for the claim-signing certificate. `None` disables the trust
    /// check (no `signingCredential.*` status is emitted).
    pub claim_signer_trust: Option<&'a TrustList>,
    /// Trust anchors for RFC 3161 timestamp authority certificates.
    pub tsa_trust: Option<&'a TrustList>,
    /// End-entity certificates trusted directly (the C2PA "allowed list"):
    /// a leaf that byte-matches an entry is trusted without chaining to an
    /// anchor, provided it is an acceptable claim signer and valid at the
    /// effective time. `None` disables the allowed-list check.
    pub allowed_certs: Option<&'a TrustList>,
    /// Instant to validate certificate windows against. `None` uses the current
    /// UTC time.
    pub validation_time: Option<OffsetDateTime>,
    /// Engine profile: spec version + conformance/regular mode, gating which
    /// formats are in scope. Defaults to the certified
    /// [`EngineProfile::CONFORMANCE_V2_2`]; a MIME type outside the profile's
    /// scope is rejected with [`ValidateError::UnsupportedMime`].
    pub profile: c2pa_core::EngineProfile,
}

#[derive(Clone, Copy, Default)]
struct CawgTrustInputs<'a> {
    trust: Option<&'a TrustList>,
    allowed_certs: Option<&'a TrustList>,
    document_signing_require_anchor: bool,
    /// Pinned offline `did:web` DID-document store for ICA issuers, keyed by
    /// primary DID (no fragment). `None` fails did:web resolution closed.
    did_documents: Option<&'a std::collections::HashMap<String, Json>>,
    /// Refuse CAWG 1.1-era legacy shapes (field-order `signer_payload`
    /// encoding, 1.1 ICA context, byte-array `c2paAsset` hashes): only the
    /// CAWG 1.2 canonical shapes are attempted.
    strict_encoding: bool,
}
fn manifest_hashes(
    store_bytes: &[u8],
    manifests: &[ParsedManifest<'_>],
) -> std::collections::HashMap<String, Vec<u8>> {
    manifest_superboxes_from_store(store_bytes)
        .map(|boxes| {
            boxes
                .iter()
                .zip(manifests)
                .filter_map(|(manifest_box, manifest)| {
                    hash_bytes("sha256", superbox_content(manifest_box))
                        .map(|hash| (manifest.label.clone(), hash))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Output of [`verify`].
pub struct VerifyOutput {
    /// Overall validation state of the active manifest.
    pub validation_state: ValidationState,
    /// Status codes partitioned by severity.
    pub results: ValidationResults,
    /// Reader-report JSON matching the SSOT shape.
    pub report_json: Json,
    /// Content Credentials JSON (crJSON): the decoded manifest-store contents.
    /// Populated by default under [`ComplianceLevel::ConformanceProgram`] (the
    /// conformance posture wants the full manifest rendering for evidence) and
    /// `None` otherwise. Distinct from `report_json`, which is the validation
    /// outcome, not the manifest contents.
    pub crjson: Option<Json>,
    /// Spec-version classification: which C2PA revision the manifest's
    /// structure conforms to and which it validated under. `None` when no
    /// claim could be decoded.
    pub version_verdict: Option<VersionVerdict>,
}

/// Signed hard-binding facts extracted from the active manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrehashedBinding {
    pub algorithm: String,
    pub digest: Vec<u8>,
    pub exclusions: Json,
}
/// Verify the C2PA manifest embedded in an asset.
///
/// **Verification is generous by default**: any asset whose MIME type maps to a
/// container the engine can read is verified, regardless of the active spec
/// profile's format scope. Only a MIME type that maps to *no* known container
/// produces [`ValidateError::UnsupportedMime`] (genuinely unreadable) — a format
/// being outside the certified set is NOT a read failure.
///
/// In [`OperatingMode::Conformance`], if the format is outside the certified
/// scope for the active [`SpecVersion`], an informational
/// [`CONFORMANCE_OUT_OF_SCOPE`] code is recorded — verification still proceeds
/// and reports the full status-code set. In [`OperatingMode::Regular`] no such
/// code is emitted. An asset with no manifest yields a graceful result rather
/// than an error: [`ValidationState::None`] in the generous posture,
/// [`ValidationState::Invalid`] + [`CLAIM_MISSING`] in the strict posture.
pub fn verify(input: &VerifyInput) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(input, &[], CawgTrustInputs::default())
}

/// Verify with trust material dedicated to CAWG named-actor credentials.
pub fn verify_with_cawg_trust(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_cawg_trust_policy(input, cawg_trust, cawg_allowed_certs, false)
}

/// Verify with CAWG trust material and document-signing anchor policy.
pub fn verify_with_cawg_trust_policy(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        &[],
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: None,
            strict_encoding: false,
        },
    )
}

/// Verify with CAWG trust material, document-signing anchor policy, and a
/// pinned offline DID-document store for `did:web` ICA issuers.
///
/// `cawg_did_documents` maps a primary DID (fragment stripped, e.g.
/// `did:web:example.com`) to its DID document JSON. Resolution never touches
/// the network: an issuer absent from the store fails closed with
/// `cawg.ica.did_unavailable`.
pub fn verify_with_cawg_trust_policy_and_did_documents(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        &[],
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            strict_encoding: false,
        },
    )
}

/// Fragmented verification with CAWG trust, document-signing anchor policy,
/// and a pinned offline DID-document store for `did:web` ICA issuers (see
/// [`verify_with_cawg_trust_policy_and_did_documents`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_fragmented_with_cawg_trust_policy_and_did_documents(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        fragments,
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            strict_encoding: false,
        },
    )
}

/// [`verify_with_cawg_trust_policy_and_did_documents`] plus the CAWG strict
/// encoding switch.
///
/// With `cawg_strict_encoding` set, CAWG 1.1-era legacy shapes are refused:
/// only the canonical RFC 8949 §4.2 `signer_payload` encoding is attempted for
/// X.509 identity signatures, and only CAWG 1.2 ICA credential shapes (the 1.2
/// JSON-LD context, base64-string `c2paAsset` hashes) are accepted. A
/// 1.1-only asset then fails with the existing mismatch/invalid codes. When
/// unset, legacy shapes verify as before and are surfaced via the
/// informational `com.encypher.cawg.legacyProfile` status.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_cawg_trust_policy_did_documents_and_strict_encoding(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_strict_encoding: bool,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        &[],
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            strict_encoding: cawg_strict_encoding,
        },
    )
}

/// Fragmented variant of
/// [`verify_with_cawg_trust_policy_did_documents_and_strict_encoding`].
#[allow(clippy::too_many_arguments)]
pub fn verify_fragmented_with_cawg_trust_policy_did_documents_and_strict_encoding(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_strict_encoding: bool,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        fragments,
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            strict_encoding: cawg_strict_encoding,
        },
    )
}
/// [`verify`] for FRAGMENTED BMFF assets (DASH/HLS): `input.data` is the
/// initialization segment carrying the manifest; `fragments` are the fragment
/// files (`.m4s`) to validate against the manifest's merkle trees. Each
/// fragment's leaf hash is recomputed per spec A.5.4.1.2 and climbed to the
/// stored Merkle row using the proof in the fragment's auxiliary C2PA
/// `merkle` box. Fragment order is irrelevant (each carries its own leaf
/// index); absent fragments are NOT a failure (streaming semantics — validate
/// what is available).
pub fn verify_fragmented(
    input: &VerifyInput,
    fragments: &[&[u8]],
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(input, fragments, CawgTrustInputs::default())
}

/// Fragmented verification with CAWG-specific trust material.
pub fn verify_fragmented_with_cawg_trust(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
) -> Result<VerifyOutput, ValidateError> {
    verify_fragmented_with_cawg_trust_policy(
        input,
        fragments,
        cawg_trust,
        cawg_allowed_certs,
        false,
    )
}

/// Fragmented verification with CAWG trust and document-signing anchor policy.
pub fn verify_fragmented_with_cawg_trust_policy(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        fragments,
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: None,
            strict_encoding: false,
        },
    )
}
fn verify_with_fragments(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    // scope. Unreadable MIME (maps to no format) is the only hard error.
    let format = AssetFormat::from_mime(input.mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(input.mime.to_string()))?;

    // Conformance-mode scope observation: recorded as informational, never a
    // hard failure, so strict internal validation captures it for evidence
    // while still verifying the asset fully.
    let out_of_scope =
        input.profile.mode == OperatingMode::Conformance && !input.profile.permits_mime(input.mime);

    let store_bytes = match c2pa_formats::extract_manifest(format, input.data)? {
        Some(bytes) => bytes,
        None => {
            let mut out = no_manifest_output("no C2PA manifest found", input.profile, false);
            if out_of_scope {
                note_out_of_scope(&mut out, input.mime);
            }
            return Ok(out);
        }
    };

    let store = parse_manifest_store(&store_bytes)?;
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, &store_bytes);
        if out_of_scope {
            note_out_of_scope(&mut out, input.mime);
        }
        return Ok(out);
    };
    // In regular mode every data-hash exclusion must describe bytes inside the
    // resolved manifest carrier. This prevents a signed assertion from making
    // host bytes mutable while retaining spec-compatible additional-exclusion
    // behavior in conformance mode.
    if input.profile.mode == OperatingMode::Regular && c2pa_formats::supports_hash_mode(input.mime)
    {
        if let Some(exclusions) = regular_data_hash_exclusions(manifest)? {
            let spans = c2pa_formats::compute_data_hash_exclusions(format, input.data)?;
            let [carrier] = spans.as_slice() else {
                return Err(ValidateError::PreparedBinding(format!(
                    "expected one resolved manifest carrier, found {}",
                    spans.len()
                )));
            };
            validate_regular_exclusion_geometry(&exclusions, carrier.start, carrier.length)?;
        }
    }
    let additional_exclusions_present = input.profile.mode == OperatingMode::Conformance
        && input.profile.version_str() == "2.4"
        && c2pa_formats::supports_hash_mode(input.mime)
        && has_conformance_additional_exclusions(manifest, format, input.data);

    // Labels of every manifest in the store, so ingredient references can be
    // checked for presence.
    let store_labels: std::collections::HashSet<String> =
        store.manifests.iter().map(|m| m.label.clone()).collect();
    // SHA-256 over each manifest JUMBF superbox, used to authenticate
    // ingredient links and compound child bindings.
    let manifest_hashes = manifest_hashes(&store_bytes, &store.manifests);
    let mut out = verify_manifest(
        manifest,
        &store.manifests,
        input,
        format,
        fragments,
        &store_labels,
        &manifest_hashes,
        None,
        cawg_inputs,
    );
    // Reader-shape parity: list every manifest in the store (ingredient
    // parents included), with `active_manifest` as the pointer.
    append_store_manifests(&mut out.report_json, &store, &manifest.label);
    stamp_manifest_store_hash(&mut out, &store_bytes);
    if additional_exclusions_present {
        note_additional_exclusions(&mut out, &manifest.label);
    }
    if out_of_scope {
        note_out_of_scope(&mut out, input.mime);
    }
    // crJSON is emitted only in strict-debug mode. Attach the active
    // manifest's validation results so the document can be evaluated directly
    // by the C2PA conformance-program rubrics.
    if input.profile.debug {
        out.crjson = Some(crjson::to_crjson_with_report(&store, &out.report_json));
    }
    stamp_profile(&mut out, input.profile);
    Ok(out)
}

/// Record the active engine profile (spec version, mode, compliance level) in
/// the report JSON, so a consumer can tell which spec version and which
/// compliance bar (core spec vs conformance program) produced this result.
fn stamp_profile(out: &mut VerifyOutput, profile: EngineProfile) {
    if let Some(obj) = out.report_json.as_object_mut() {
        obj.insert(
            "engine_profile".to_string(),
            json!({
                "spec_version": profile.version_str(),
                "operating_mode": match profile.mode {
                    OperatingMode::Conformance => "conformance",
                    OperatingMode::Regular => "regular",
                },
                "compliance_level": match profile.compliance {
                    ComplianceLevel::CoreSpec => "core-spec",
                    ComplianceLevel::ConformanceProgram => "conformance-program",
                },
            }),
        );
    }
}

/// Bind the report to the exact extracted or caller-supplied manifest-store
/// bytes, rather than to a decoded or reserialized representation.
fn stamp_manifest_store_hash(out: &mut VerifyOutput, manifest_store: &[u8]) {
    use std::fmt::Write as _;

    let digest = Sha256::digest(manifest_store);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    if let Some(obj) = out.report_json.as_object_mut() {
        obj.insert("manifest_store_sha256".to_string(), Json::String(encoded));
    }
}

/// Record the conformance out-of-scope observation as an informational code on
/// both the structured results and the report JSON.
fn note_out_of_scope(out: &mut VerifyOutput, mime: &str) {
    out.results.push_informational(
        CONFORMANCE_OUT_OF_SCOPE,
        String::new(),
        format!("format {mime} is outside the certified conformance scope"),
    );
    // Rebuild the validation_results block from the updated results so the
    // informational code appears in the report JSON too. `validation_results`
    // is a pure function of `results`, so this stays consistent with finish().
    if let Some(obj) = out.report_json.as_object_mut() {
        obj.insert(
            "validation_results".to_string(),
            validation_results_json(&out.results),
        );
        // The out-of-scope code is also a surfaced caveat, so recompute the
        // structured verdict too, preserving the existing `present` value.
        let present = obj
            .get("provenance_verdict")
            .and_then(|v| v.get("present"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        obj.insert(
            "provenance_verdict".to_string(),
            provenance_verdict_json(&out.results, present),
        );
    }
}

fn note_additional_exclusions(out: &mut VerifyOutput, manifest_label: &str) {
    out.results.push_informational(
        ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT,
        format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/c2pa.hash.data"),
        "extra data hash exclusions found".into(),
    );
    if let Some(obj) = out.report_json.as_object_mut() {
        obj.insert(
            "validation_results".to_string(),
            validation_results_json(&out.results),
        );
    }
}

/// Panic-containment wrapper around [`verify`] for FFI/gRPC boundaries.
///
/// A verifier must never abort the host process on malformed input. The parsers
/// are written to return errors rather than panic (and are fuzzed); this wraps
/// [`verify`] in [`std::panic::catch_unwind`] as defence in depth so an
/// unexpected panic surfaces as [`ValidateError::Panic`] instead of crossing an
/// FFI edge as an abort.
pub fn verify_safe(input: &VerifyInput) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify(input))) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Panic-containment wrapper for [`verify_with_cawg_trust`].
pub fn verify_with_cawg_trust_safe(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_cawg_trust(input, cawg_trust, cawg_allowed_certs)
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}
/// Panic-containment wrapper with explicit CAWG document-signing policy.
pub fn verify_with_cawg_trust_policy_safe(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_cawg_trust_policy(
            input,
            cawg_trust,
            cawg_allowed_certs,
            document_signing_require_anchor,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Panic-containment wrapper for
/// [`verify_with_cawg_trust_policy_did_documents_and_strict_encoding`].
#[allow(clippy::too_many_arguments)]
pub fn verify_with_cawg_trust_policy_did_documents_and_strict_encoding_safe(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_strict_encoding: bool,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_cawg_trust_policy_did_documents_and_strict_encoding(
            input,
            cawg_trust,
            cawg_allowed_certs,
            document_signing_require_anchor,
            cawg_did_documents,
            cawg_strict_encoding,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Panic-containment wrapper around [`verify_fragmented`] (see [`verify_safe`]).
pub fn verify_fragmented_safe(
    input: &VerifyInput,
    fragments: &[&[u8]],
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_fragmented(input, fragments)
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Panic-containment wrapper for [`verify_fragmented_with_cawg_trust`].
pub fn verify_fragmented_with_cawg_trust_safe(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_fragmented_with_cawg_trust(input, fragments, cawg_trust, cawg_allowed_certs)
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}
/// Panic-containment wrapper for fragmented CAWG verification with policy.
pub fn verify_fragmented_with_cawg_trust_policy_safe(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_fragmented_with_cawg_trust_policy(
            input,
            fragments,
            cawg_trust,
            cawg_allowed_certs,
            document_signing_require_anchor,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Verify a DETACHED / sidecar C2PA manifest store against its external content.
///
/// C2PA 2.4 sidecar discovery (cross-cutting predicate: a `.c2pa` file alongside
/// an asset) carries the manifest store out-of-band; the manifest still binds to
/// the asset through its ordinary hard binding (a data hash over the content).
/// `manifest_store` is the sidecar store bytes, `content` is the asset the
/// manifest describes, and `content_mime` selects the asset's container format.
/// The hard binding is evaluated against `content` exactly as for an embedded
/// manifest, with the assertion's own exclusions applied (none, for a true
/// sidecar, so the whole asset is hashed).
///
/// `input.data` / `input.mime` are ignored (the store and content are passed
/// explicitly); trust lists, `validation_time` and `profile` are honored. The
/// content side must be a real asset: `application/c2pa` (the host-less compound
/// store) is rejected, and this path never touches the compound `C2paStore`
/// verification flow.
pub fn verify_detached<'a>(
    manifest_store: &'a [u8],
    content: &'a [u8],
    content_mime: &'a str,
    input: &VerifyInput<'a>,
) -> Result<VerifyOutput, ValidateError> {
    let format = AssetFormat::from_mime(content_mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(content_mime.to_string()))?;
    if format == AssetFormat::C2paStore {
        // The content side cannot itself be a host-less manifest store.
        return Err(ValidateError::UnsupportedMime(content_mime.to_string()));
    }

    let out_of_scope = input.profile.mode == OperatingMode::Conformance
        && !input.profile.permits_mime(content_mime);

    let store = parse_manifest_store(manifest_store)?;
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, manifest_store);
        if out_of_scope {
            note_out_of_scope(&mut out, content_mime);
        }
        return Ok(out);
    };

    let store_labels: std::collections::HashSet<String> =
        store.manifests.iter().map(|m| m.label.clone()).collect();
    let manifest_hashes = manifest_hashes(manifest_store, &store.manifests);

    // Present the external content as the asset under verification, then run the
    // standard per-manifest pipeline (origin's exact-label hard-binding checks).
    let content_input = VerifyInput {
        data: content,
        mime: content_mime,
        ..*input
    };
    let mut out = verify_manifest(
        manifest,
        &store.manifests,
        &content_input,
        format,
        &[],
        &store_labels,
        &manifest_hashes,
        None,
        CawgTrustInputs::default(),
    );
    append_store_manifests(&mut out.report_json, &store, &manifest.label);
    stamp_manifest_store_hash(&mut out, manifest_store);
    if out_of_scope {
        note_out_of_scope(&mut out, content_mime);
    }
    if input.profile.debug {
        out.crjson = Some(crjson::to_crjson_with_report(&store, &out.report_json));
    }
    stamp_profile(&mut out, input.profile);
    Ok(out)
}

/// Verify a detached manifest against a caller-computed hard-binding digest.
///
/// This validates the same claim structure, assertion hashed-URI bindings,
/// COSE signature, certificate chain, timestamp, and CAWG identity as
/// [`verify`]. Only the asset hashing step is replaced: the supplied digest is
/// compared to the active manifest's sole `c2pa.hash.data` or
/// `c2pa.hash.bmff*` assertion. The caller remains responsible for computing
/// the format-specific digest from locally parsed and authorized container geometry.
pub fn verify_prehashed_manifest<'a>(
    manifest_store: &'a [u8],
    content_mime: &'a str,
    hard_binding_digest: &'a [u8],
    input: &VerifyInput<'a>,
) -> Result<VerifyOutput, ValidateError> {
    let format = AssetFormat::from_mime(content_mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(content_mime.to_string()))?;
    if format == AssetFormat::C2paStore {
        return Err(ValidateError::UnsupportedMime(content_mime.to_string()));
    }

    let store = parse_manifest_store(manifest_store)?;
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, manifest_store);
        return Ok(out);
    };
    let store_labels = store
        .manifests
        .iter()
        .map(|m| m.label.clone())
        .collect::<std::collections::HashSet<_>>();
    let manifest_hashes = manifest_hashes(manifest_store, &store.manifests);
    let digest_input = VerifyInput {
        data: &[],
        mime: content_mime,
        ..*input
    };
    let mut out = verify_manifest(
        manifest,
        &store.manifests,
        &digest_input,
        format,
        &[],
        &store_labels,
        &manifest_hashes,
        Some(hard_binding_digest),
        CawgTrustInputs::default(),
    );
    append_store_manifests(&mut out.report_json, &store, &manifest.label);
    stamp_manifest_store_hash(&mut out, manifest_store);
    if input.profile.debug {
        out.crjson = Some(crjson::to_crjson_with_report(&store, &out.report_json));
    }
    stamp_profile(&mut out, input.profile);
    Ok(out)
}

// Parse the active data-hash assertion without the prepared-signing
// restriction that its exclusion list contain exactly one range.
fn regular_data_hash_exclusions(
    manifest: &ParsedManifest<'_>,
) -> Result<Option<Vec<(usize, usize)>>, ValidateError> {
    let bindings = manifest
        .assertions
        .iter()
        .filter(|(label, _)| label == "c2pa.hash.data")
        .collect::<Vec<_>>();
    let cbor = match bindings.as_slice() {
        [] => return Ok(None),
        [binding] => binding.1,
        _ => {
            return Err(ValidateError::PreparedBinding(
                "regular verification requires exactly one c2pa.hash.data binding".into(),
            ));
        }
    };
    let assertion = decode(cbor).map_err(|_| {
        ValidateError::PreparedBinding("hard-binding assertion CBOR is invalid".into())
    })?;
    let exclusions = match assertion.get("exclusions") {
        Some(Value::Array(exclusions)) if !exclusions.is_empty() => exclusions,
        _ => {
            return Err(ValidateError::PreparedBinding(
                "signed data-hash exclusion list must contain at least one range".into(),
            ));
        }
    };
    if exclusions.len() > MAX_DATA_HASH_EXCLUSIONS {
        return Err(ValidateError::PreparedBinding(format!(
            "exclusion list exceeds the verifier cap ({} > {MAX_DATA_HASH_EXCLUSIONS})",
            exclusions.len()
        )));
    }

    exclusions
        .iter()
        .map(|exclusion| {
            let start = exclusion
                .get("start")
                .and_then(|value| match value {
                    Value::Integer(value) => usize::try_from(*value).ok(),
                    _ => None,
                })
                .ok_or_else(|| {
                    ValidateError::PreparedBinding(
                        "signed data-hash exclusion start is invalid".into(),
                    )
                })?;
            let length = exclusion
                .get("length")
                .and_then(|value| match value {
                    Value::Integer(value) => usize::try_from(*value).ok(),
                    _ => None,
                })
                .filter(|length| *length > 0)
                .ok_or_else(|| {
                    ValidateError::PreparedBinding(
                        "signed data-hash exclusion length is invalid".into(),
                    )
                })?;
            Ok((start, length))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn has_conformance_additional_exclusions(
    manifest: &ParsedManifest<'_>,
    format: AssetFormat,
    data: &[u8],
) -> bool {
    let Some(exclusions) = regular_data_hash_exclusions(manifest).ok().flatten() else {
        return false;
    };
    let Ok(spans) = c2pa_formats::compute_data_hash_exclusions(format, data) else {
        return false;
    };
    let [carrier] = spans.as_slice() else {
        return false;
    };
    let Some(carrier_end) = carrier.start.checked_add(carrier.length) else {
        return false;
    };
    exclusions.iter().any(|(start, length)| {
        start
            .checked_add(*length)
            .is_none_or(|end| *start < carrier.start || end > carrier_end)
    })
}

fn validate_regular_exclusion_geometry(
    exclusions: &[(usize, usize)],
    carrier_start: usize,
    carrier_length: usize,
) -> Result<(), ValidateError> {
    let carrier_end = carrier_start.checked_add(carrier_length).ok_or_else(|| {
        ValidateError::PreparedBinding("resolved carrier output span overflows".into())
    })?;
    let mut sorted = exclusions.to_vec();
    sorted.sort_unstable_by_key(|(start, _)| *start);
    let mut previous_end = None;
    for (start, length) in sorted {
        let end = start.checked_add(length).ok_or_else(|| {
            ValidateError::PreparedBinding(
                "signed exclusion does not fit within resolved carrier output span".into(),
            )
        })?;
        if previous_end.is_some_and(|prior| start < prior)
            || start < carrier_start
            || end > carrier_end
        {
            return Err(ValidateError::PreparedBinding(
                "signed exclusion does not fit within resolved carrier output span".into(),
            ));
        }
        previous_end = Some(end);
    }
    Ok(())
}

/// Extract and validate the active manifest's sole prepared hard binding.
///
/// This is the claim-only half of hash-mode verification. The caller still
/// validates the submitted carrier and compares this signed digest with its
/// locally computed digest before writing any bytes.
pub fn prehashed_binding(manifest_store: &[u8]) -> Result<PrehashedBinding, ValidateError> {
    let store = parse_manifest_store(manifest_store)?;
    let manifest = store.manifests.last().ok_or_else(|| {
        ValidateError::PreparedBinding("manifest store contained no manifests".into())
    })?;
    let bindings = manifest
        .assertions
        .iter()
        .filter(|(label, _)| label == "c2pa.hash.data" || label.starts_with("c2pa.hash.bmff"))
        .collect::<Vec<_>>();
    let (label, cbor) = match bindings.as_slice() {
        [binding] => (binding.0.as_str(), binding.1),
        _ => {
            return Err(ValidateError::PreparedBinding(
                "exactly one c2pa.hash.data or c2pa.hash.bmff binding is required".into(),
            ));
        }
    };
    let assertion = decode(cbor).map_err(|_| {
        ValidateError::PreparedBinding("hard-binding assertion CBOR is invalid".into())
    })?;
    if assertion
        .get("alg")
        .and_then(Value::as_text)
        .unwrap_or("sha256")
        != "sha256"
        || assertion.get("merkle").is_some()
    {
        return Err(ValidateError::PreparedBinding(
            "only a non-merkle SHA-256 hard binding is supported".into(),
        ));
    }
    let digest = assertion
        .get("hash")
        .and_then(Value::as_bytes)
        .filter(|value| value.len() == 32)
        .ok_or_else(|| ValidateError::PreparedBinding("hard-binding hash must be 32 bytes".into()))?
        .to_vec();
    let exclusions = match assertion.get("exclusions") {
        Some(Value::Array(values)) => values,
        _ => {
            return Err(ValidateError::PreparedBinding(
                "hard-binding exclusions are missing".into(),
            ));
        }
    };
    let normalized_exclusions = if label == "c2pa.hash.data" {
        let mut rows = Vec::with_capacity(exclusions.len());
        for exclusion in exclusions {
            let start = exclusion
                .get("start")
                .and_then(|value| match value {
                    Value::Integer(value) => u64::try_from(*value).ok(),
                    _ => None,
                })
                .ok_or_else(|| {
                    ValidateError::PreparedBinding("data-hash exclusion start is invalid".into())
                })?;
            let length = exclusion
                .get("length")
                .and_then(|value| match value {
                    Value::Integer(value) => u64::try_from(*value).ok(),
                    _ => None,
                })
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    ValidateError::PreparedBinding("data-hash exclusion length is invalid".into())
                })?;
            rows.push(json!([start, length]));
        }
        if rows.len() != 1 {
            return Err(ValidateError::PreparedBinding(
                "prepared data hash requires exactly one carrier exclusion".into(),
            ));
        }
        Json::Array(rows)
    } else {
        if label != "c2pa.hash.bmff.v3" {
            return Err(ValidateError::PreparedBinding(
                "prepared BMFF binding must use c2pa.hash.bmff.v3".into(),
            ));
        }
        let uuid_exclusion = exclusions.first().ok_or_else(|| {
            ValidateError::PreparedBinding("BMFF C2PA UUID exclusion is missing".into())
        })?;
        let uuid_match = uuid_exclusion.get("data").and_then(|value| match value {
            Value::Array(values) if values.len() == 1 => values.first(),
            _ => None,
        });
        let uuid_offset = uuid_match
            .and_then(|value| value.get("offset"))
            .and_then(|value| match value {
                Value::Integer(value) => u64::try_from(*value).ok(),
                _ => None,
            });
        let uuid_value = uuid_match
            .and_then(|value| value.get("value"))
            .and_then(Value::as_bytes);
        if uuid_offset != Some(8) || uuid_value != Some(c2pa_formats::C2PA_BMFF_UUID.as_slice()) {
            return Err(ValidateError::PreparedBinding(
                "BMFF /uuid exclusion must uniquely match the C2PA carrier".into(),
            ));
        }
        let mut paths = Vec::with_capacity(exclusions.len());
        for exclusion in exclusions {
            let xpath = exclusion
                .get("xpath")
                .and_then(Value::as_text)
                .ok_or_else(|| {
                    ValidateError::PreparedBinding("BMFF exclusion xpath is invalid".into())
                })?;
            paths.push(xpath);
        }
        if paths.as_slice() != c2pa_formats::BMFF_HASH_EXCLUSION_PATHS {
            return Err(ValidateError::PreparedBinding(
                "prepared BMFF exclusions do not match the canonical v3 set".into(),
            ));
        }
        Json::Array(
            paths
                .into_iter()
                .map(|xpath| Json::String(xpath.to_string()))
                .collect(),
        )
    };
    Ok(PrehashedBinding {
        algorithm: label.to_string(),
        digest,
        exclusions: normalized_exclusions,
    })
}

/// Run the per-manifest verification steps and assemble the output.
fn verify_manifest<'a>(
    manifest: &'a ParsedManifest<'a>,
    manifests: &'a [ParsedManifest<'a>],
    input: &VerifyInput,
    format: AssetFormat,
    fragments: &[&[u8]],
    store_labels: &std::collections::HashSet<String>,
    manifest_hashes: &std::collections::HashMap<String, Vec<u8>>,
    prehashed_digest: Option<&[u8]>,
    cawg_inputs: CawgTrustInputs<'_>,
) -> VerifyOutput {
    let label = manifest.label.clone();
    let sig_url = format!("self#jumbf=/c2pa/{label}/c2pa.signature");
    let mut results = ValidationResults::default();

    // --- Claim + signature presence ---
    let Some(claim_cbor) = manifest.claim_cbor else {
        results.push_failure(CLAIM_MISSING, sig_url, "no claim found in manifest".into());
        return finish(
            label,
            manifest,
            None,
            &[],
            None,
            results,
            None,
            input.profile,
        );
    };
    let claim = match decode(claim_cbor) {
        Ok(c) => c,
        Err(_) => {
            results.push_failure(
                CLAIM_CBOR_INVALID,
                sig_url,
                "claim CBOR could not be decoded".into(),
            );
            return finish(
                label,
                manifest,
                None,
                &[],
                None,
                results,
                None,
                input.profile,
            );
        }
    };

    // Spec-version classification: claim generation (v1 vs v2) drives the
    // generation-aware structural checks below; the ladder verdict rides on
    // the output and is finalized in `finish` (cleared when Invalid).
    let generation = versions::claim_generation(manifest, &claim);
    let verdict = versions::evaluate(manifest, &claim, format);

    // Strict target-version control (internal conformance analysis): in
    // Conformance mode the manifest is additionally held to the profile's
    // target spec revision. Informational under the core-spec bar; a hard
    // failure under the conformance program. Regular mode stays silent — the
    // ladder verdict carries the classification without judgment.
    if input.profile.mode == OperatingMode::Conformance {
        if let Some(eval) = verdict
            .evaluations
            .iter()
            .find(|e| e.version == input.profile.version)
        {
            if !eval.structure_conformant {
                let explanation = format!(
                    "manifest does not conform to target spec {}: {}",
                    input.profile.version.version_str(),
                    eval.reasons.join("; "),
                );
                match input.profile.compliance {
                    ComplianceLevel::ConformanceProgram => results.push_failure(
                        CONFORMANCE_SPEC_VERSION_NONCONFORMANT,
                        sig_url.clone(),
                        explanation,
                    ),
                    ComplianceLevel::CoreSpec => results.push_informational(
                        CONFORMANCE_SPEC_VERSION_NONCONFORMANT,
                        sig_url.clone(),
                        explanation,
                    ),
                }
            }
        }
    }

    // --- Structural claim/assertion validation (detection of malformed input) ---
    let structure_ok =
        !verify_claim_structure(manifest, &claim, generation, format, &sig_url, &mut results);
    verify_ingredient_references(manifest, store_labels, &sig_url, &mut results);

    let Some(cose) = manifest.signature_cose else {
        results.push_failure(
            CLAIM_SIGNATURE_MISSING,
            sig_url,
            "no claim signature present".into(),
        );
        return finish(
            label,
            manifest,
            Some(&claim),
            &[],
            None,
            results,
            Some(verdict),
            input.profile,
        );
    };

    // The claim's `signature` field must reference the manifest's
    // `c2pa.signature` box. A claim pointing at any other label (e.g.
    // `c2pa.signature/c2pa.wrong-signature-label`) has no usable signature.
    let sig_ref_ok = claim
        .get("signature")
        .and_then(Value::as_text)
        .map(|uri| {
            let target = uri.rsplit(['/', '=']).next().unwrap_or(uri);
            target == "c2pa.signature"
        })
        .unwrap_or(false);
    if !sig_ref_ok {
        results.push_failure(
            CLAIM_SIGNATURE_MISSING,
            sig_url.clone(),
            "claim signature reference does not resolve to c2pa.signature".into(),
        );
        return finish(
            label,
            manifest,
            Some(&claim),
            &[],
            None,
            results,
            Some(verdict),
            input.profile,
        );
    }

    // --- Signing certificate chain ---
    let chain = extract_x5chain(cose).unwrap_or_default();
    let leaf = chain.first().map(|c| c.as_slice());

    // Step 8 (computed early): a fully verified RFC 3161 token establishes the
    // validation instant for the claim-signing chain. Unverified token bytes
    // never influence certificate validity.
    let timestamp_token = extract_tsa_token(cose);
    let trusted_timestamp = timestamp_token.as_ref().and_then(|token| {
        let verification = match (input.tsa_trust, timestamp_input(cose)) {
            (Some(trust), Ok(timestamp_payload)) => {
                c2pa_trust::verify_timestamp_token(token, &timestamp_payload, trust)
            }
            (None, _) => {
                results.push_informational(
                    TIME_STAMP_UNTRUSTED,
                    sig_url.clone(),
                    "timestamp token present but no TSA trust anchors were supplied".into(),
                );
                return None;
            }
            (Some(_), Err(_)) => {
                results.push_informational(
                    TIME_STAMP_UNTRUSTED,
                    sig_url.clone(),
                    "timestamp token present but its C2PA CounterSignature input is malformed"
                        .into(),
                );
                return None;
            }
        };
        if verification.verified {
            results.push_success(
                TIME_STAMP_VALIDATED,
                sig_url.clone(),
                "RFC 3161 timestamp signature and message imprint validated".into(),
            );
            results.push_success(
                TIME_STAMP_TRUSTED,
                sig_url.clone(),
                "timestamp authority chains to a supplied TSA trust anchor".into(),
            );
            verification.time
        } else {
            let error = verification
                .error
                .unwrap_or("timestamp_verification_failed");
            if error == "timestamp_tsa_outside_validity" {
                results.push_informational(
                    TIME_STAMP_OUTSIDE_VALIDITY,
                    sig_url.clone(),
                    "timestamp authority certificate was outside its validity window at genTime"
                        .into(),
                );
            }
            results.push_informational(
                TIME_STAMP_UNTRUSTED,
                sig_url.clone(),
                format!("RFC 3161 timestamp verification failed: {error}"),
            );
            None
        }
    });

    // Step 4: a trusted timestamp takes precedence over caller/system time.
    let at = trusted_timestamp
        .or(input.validation_time)
        .unwrap_or_else(OffsetDateTime::now_utc);

    // Evaluate the signing-certificate chain up front (when a trust list is
    // supplied) so the validity decision can span the whole chain, not just the
    // leaf, and so leaf acceptability (EKU / keyUsage / CA constraints) can gate
    // the credential. Without a trust list, fall back to a leaf-only validity
    // check and treat the leaf as acceptable (no policy to apply).
    let chain_result = match (input.claim_signer_trust, leaf) {
        (Some(trust), Some(leaf_der)) => {
            let intermediates: Vec<Vec<u8>> = chain.iter().skip(1).cloned().collect();
            Some(validate_chain(leaf_der, &intermediates, trust, Some(at)))
        }
        _ => None,
    };
    // Whole-chain validity at `at`. With a trust list this reflects every cert
    // in the chain; without one it is the leaf's own validity window.
    let in_validity = match &chain_result {
        Some(cr) => cr.chain_validity_ok && leaf.map(|d| cert::valid_at(d, at)).unwrap_or(false),
        None => leaf.map(|d| cert::valid_at(d, at)).unwrap_or(false),
    };
    // Leaf acceptable as a claim signer (EKU/keyUsage/not-CA). Only enforced
    // when a trust list drove a chain evaluation.
    let leaf_acceptable = chain_result
        .as_ref()
        .map(|cr| cr.leaf_acceptable)
        .unwrap_or(true);

    // Cryptographic verification of the claim signature against the leaf.
    let sig_ok = leaf
        .map(|d| verify_claim(cose, claim_cbor, d).is_ok())
        .unwrap_or(false);

    let generous = is_generous(input.profile);
    // Construction-only signature soundness: the signature verifies and the
    // claim structure is well-formed. Leaf claim-signer acceptability
    // (EKU/keyUsage/CA) is NOT folded in: a credential-profile failure emits
    // `signingCredential.invalid` and CONTINUES — the reference implementation
    // still runs and reports signature verification, hashed-URI checks, and
    // hard-binding checks. Cert-time validity is likewise excluded — it is a
    // trust/time signal, not a construction signal. The strict posture still
    // folds `in_validity` into the gates below; the generous posture treats
    // cert-time as a non-invalidating caveat.
    let sig_constructed = sig_ok && structure_ok;

    match leaf {
        Some(_leaf_der) => {
            // An unacceptable claim signer (CA cert, keyCertSign, wrong/any
            // EKU) is reported as `signingCredential.invalid` — an
            // invalidating failure in both postures — but it never suppresses
            // the downstream checks: signature verification, hashed-URI, and
            // hard-binding results are still evaluated and reported.
            if !leaf_acceptable {
                results.push_failure(
                    SIGNING_CREDENTIAL_INVALID,
                    sig_url.clone(),
                    "signing certificate is not a valid claim-signing credential".into(),
                );
            }
            // Generous posture validates on construction soundness alone;
            // strict keeps the cert-validity-window requirement.
            let validated = if generous {
                sig_constructed
            } else {
                sig_constructed && in_validity
            };
            if validated {
                results.push_success(
                    CLAIM_SIGNATURE_VALIDATED,
                    sig_url.clone(),
                    "claim signature valid".into(),
                );
            } else if !sig_ok {
                results.push_failure(
                    CLAIM_SIGNATURE_MISMATCH,
                    sig_url.clone(),
                    "claim signature invalid".into(),
                );
            }
            // When sig_ok but outside validity, claimSignature.validated is
            // intentionally suppressed; the outsideValidity failure below
            // carries the verdict.
        }
        None => {
            results.push_failure(
                SIGNING_CREDENTIAL_INVALID,
                sig_url.clone(),
                "no signing certificate in signature".into(),
            );
            results.push_failure(
                CLAIM_SIGNATURE_MISMATCH,
                sig_url.clone(),
                "claim signature could not be verified".into(),
            );
        }
    }

    if leaf.is_some() {
        if in_validity {
            results.push_success(
                CLAIM_SIGNATURE_INSIDE_VALIDITY,
                sig_url.clone(),
                "claim signature valid".into(),
            );
        } else {
            results.push_failure(
                CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
                sig_url.clone(),
                "signing certificate outside its validity window".into(),
            );
        }
    }

    // Steps 5-6: assertion hashed-URI bindings and the asset hard binding.
    // The hashedURI + dataHash bindings run when the signature is usable.
    // Strict keeps the cert-validity-window requirement (sig_ok &&
    // in_validity); generous gates on construction soundness alone so an
    // expired-but-intact manifest still reports its bindings. Leaf
    // claim-signer acceptability never gates these checks: a
    // credential-profile failure reports its own code and the binding checks
    // still run (matching the reference implementation).
    let sig_usable = if generous {
        sig_constructed
    } else {
        sig_ok && in_validity
    };
    if sig_usable {
        // Step 5: assertion hashed-URI bindings.
        verify_assertion_bindings(&claim, manifest, generation, &label, &mut results);
        // Step 6: c2pa.hash.data hard binding.
        if let Some(digest) = prehashed_digest {
            verify_prehashed_hard_binding(manifest, digest, &label, &mut results);
        } else {
            verify_data_hash(
                &claim,
                manifest,
                input.data,
                format,
                fragments,
                &label,
                &mut results,
            );
        }
        // Step 6a (EXPERIMENTAL, PR #2058): host-less compound binding. ONLY for
        // application/c2pa (C2paStore). Ordinary host-bearing formats require a
        // real c2pa.hash.* binding (verify_data_hash) and never treat
        // c2pa.compound.content as a hard binding.
        if format == AssetFormat::C2paStore {
            verify_compound_content(manifest, &label, manifest_hashes, &mut results);
        }
        // Named-actor trust is evaluated only when this exact asset and claim
        // are valid and every referenced assertion still matches its stored
        // bytes. A valid identity COSE inside any invalid manifest must never
        // produce `cawg.identity.trusted`.
        if results.failure.is_empty() {
            cawg::verify_identity_assertions(&mut cawg::IdentityContext {
                manifest,
                manifests,
                manifest_hashes,
                claim: &claim,
                generation,
                validation_time: at,
                claim_timestamp: trusted_timestamp,
                cawg_trust: cawg_inputs.trust,
                cawg_allowed_certs: cawg_inputs.allowed_certs,
                document_signing_require_anchor: cawg_inputs.document_signing_require_anchor,
                tsa_trust: input.tsa_trust,
                did_documents: cawg_inputs.did_documents,
                strict_encoding: cawg_inputs.strict_encoding,
                results: &mut results,
            });
        }
    }

    // Step 7a: stapled OCSP revocation status, evaluated against validation time.
    // Computed before trust so a revoked credential cannot be reported trusted.
    // The staple is fully verified: the OCSP responder's signature over
    // tbsResponseData, its id-kp-OCSPSigning EKU (for delegated responders), its
    // authorization by the signing certificate's issuer, and its validity at the
    // effective time are all checked. A staple that fails any of these (or is
    // stale/future/undecodable) is reported as skipped, not as a positive
    // not-revoked result.
    // OCSP freshness reference: the effective time `at` (the trusted timestamp's
    // genTime when present, else validationTime), matching the signer-cert
    // validity anchor — a staple valid at signing remains acceptable.
    let ocsp_at = at;
    // The OCSP responder for any cert must be authorized by that cert's issuer.
    // Issuers may be trust anchors outside the x5chain, so search the chain plus
    // the supplied anchors.
    let mut issuer_candidates: Vec<Vec<u8>> = chain.iter().skip(1).cloned().collect();
    if let Some(trust) = input.claim_signer_trust {
        issuer_candidates.extend(trust.anchors.iter().cloned());
    }
    let staples = c2pa_crypto::extract_ocsp_staples(cose);
    // Evaluate every stapled response against every certificate in the signing
    // chain (leaf and intermediates). A verified staple whose CertID matches a
    // chain cert decides that cert's revocation status; the responder signature,
    // EKU, authorization, CertID-serial, and freshness are all enforced by
    // `evaluate_ocsp_verified`. The leaf's own result drives the emitted
    // notRevoked/skipped code; a revoked status anywhere in the chain is fatal.
    let mut ocsp_revoked = false;
    let mut leaf_status: Option<c2pa_trust::OcspStatus> = None;
    for subject in &chain {
        let Some(issuer_der) = c2pa_trust::resolve_issuer(subject, &issuer_candidates) else {
            continue;
        };
        let is_leaf = leaf == Some(subject.as_slice());
        for staple in &staples {
            let Some(eval) =
                c2pa_trust::evaluate_ocsp_verified(staple, &issuer_der, Some(subject), ocsp_at)
            else {
                continue; // staple not for this subject (or failed verification)
            };
            if !eval.is_fresh_at(ocsp_at) {
                continue;
            }
            if eval.status == c2pa_trust::OcspStatus::Revoked {
                ocsp_revoked = true;
                results.push_failure(
                    SIGNING_CREDENTIAL_OCSP_REVOKED,
                    sig_url.clone(),
                    "stapled OCSP response: certificate revoked".into(),
                );
            }
            if is_leaf {
                leaf_status = Some(eval.status);
            }
        }
    }
    match leaf_status {
        Some(c2pa_trust::OcspStatus::Good) => results.push_success(
            SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
            sig_url.clone(),
            "stapled OCSP response: certificate not revoked".into(),
        ),
        Some(c2pa_trust::OcspStatus::Revoked) => { /* failure already recorded */ }
        _ => results.push_informational(
            SIGNING_CREDENTIAL_OCSP_SKIPPED,
            sig_url.clone(),
            "no usable/fresh OCSP staple for the leaf; revocation check skipped".into(),
        ),
    }

    // Step 7b: trust evaluation (when a trust list and/or allowed list is
    // supplied). Reuses the chain result computed at `at` in step 4. A revoked
    // OCSP status or a fatal structural defect prevents a trusted verdict. An
    // allowed-list match trusts the end-entity certificate directly — no
    // chain-to-anchor required — but the leaf must still be an acceptable
    // claim signer and valid at `at`.
    let leaf_allowed = match (input.allowed_certs, leaf) {
        (Some(allowed), Some(leaf_der)) => {
            allowed.anchors.iter().any(|a| a.as_slice() == leaf_der)
                && c2pa_trust::leaf_acceptable_der(leaf_der)
                && cert::valid_at(leaf_der, at)
        }
        _ => false,
    };
    if chain_result.is_some() || (input.allowed_certs.is_some() && leaf.is_some()) {
        let chain_trusted = chain_result
            .as_ref()
            .map(|cr| cr.trusted && cr.leaf_acceptable)
            .unwrap_or(false);
        if (chain_trusted || leaf_allowed) && structure_ok && !ocsp_revoked {
            results.push_success(
                SIGNING_CREDENTIAL_TRUSTED,
                sig_url.clone(),
                "signing certificate trusted".into(),
            );
        } else {
            results.push_failure(
                SIGNING_CREDENTIAL_UNTRUSTED,
                sig_url.clone(),
                "signing certificate untrusted".into(),
            );
        }
    }

    // Conformance-program SHOULD->SHALL upgrades, applied on the full-evaluation
    // path (structural-failure early exits above are already failures).
    apply_compliance_upgrades(&mut results, input.profile.compliance, &sig_url);
    finish(
        label,
        manifest,
        Some(&claim),
        &chain,
        Some(cose),
        results,
        Some(verdict),
        input.profile,
    )
}

/// Structural validation of the claim and assertions: detect malformed or
/// non-conforming input (the verifier's adversarial-input responsibility).
///
/// Emits, as failures: `claim.multiple` (>1 claim box), `claim.malformed`
/// (missing fields required by the detected claim generation),
/// `claim.hardBindings.missing` (no `c2pa.hash.*`
fn verify_claim_structure(
    manifest: &ParsedManifest,
    claim: &Value,
    generation: ClaimGeneration,
    format: AssetFormat,
    sig_url: &str,
    results: &mut ValidationResults,
) -> bool {
    // Returns false when a fatal structural defect (multiple claims / malformed
    // claim) means the signature must not be reported as validated/trusted.
    let mut fatal = false;
    // claim.multiple: more than one claim box in the manifest.
    if manifest.claim_count > 1 {
        results.push_failure(
            CLAIM_MULTIPLE,
            sig_url.to_string(),
            format!(
                "{} claim boxes in manifest (expected 1)",
                manifest.claim_count
            ),
        );
        fatal = true;
    }

    // claim.malformed: fields required by the detected claim generation must
    // be present (claim v1: instanceID/claim_generator/dc:format/assertions;
    // claim v2: instanceID/created_assertions).
    let missing = match generation {
        ClaimGeneration::V1 => versions::v1_missing_fields(claim),
        ClaimGeneration::V2 => versions::v2_missing_fields(claim),
    };
    if !missing.is_empty() {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!("claim missing required field(s): {}", missing.join(", ")),
        );
        fatal = true;
    }

    // claim.malformed: v2 manifest labels must follow the C2PA 2.x grammar
    // `urn:c2pa:<guid>[:vendor[:version[_reason]]]` (or a legacy v1-shaped
    // label, which the reference implementation also tolerates). Matches
    // upstream `verify_claim`, which logs `claim box label invalid` as a
    // claim.malformed failure while continuing validation (non-fatal).
    if generation == ClaimGeneration::V2 && !manifest_label_conformant(&manifest.label) {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!("claim box label invalid: {}", manifest.label),
        );
    }

    // Collect referenced assertions for binding + alg checks: `assertions` for
    // the v1 generation, `created_assertions` + `gathered_assertions` for v2.
    let mut refs: Vec<&Value> = Vec::new();
    for field in ref_fields(generation) {
        if let Some(Value::Array(items)) = claim.get(field) {
            refs.extend(items.iter());
        }
    }

    // claim.hardBindings.missing: at least one referenced assertion must be a
    // hard binding (`c2pa.hash.*`). The EXPERIMENTAL PR #2058 host-less compound
    // binding (`c2pa.compound.content`) satisfies this ONLY for the host-less
    // `application/c2pa` (C2paStore) format; for any host-bearing format a real
    // `c2pa.hash.*` is required, so an attacker cannot strip the data hash and
    // substitute a compound.content to bypass content binding.
    // Match the EXACT recognized hard-binding assertion label (parsed from the
    // local hashed-URI), never a substring: a fake label like `c2pa.hash.fake`
    // or `c2pa.compound.content.x` must NOT satisfy the requirement. The compound
    // binding counts only for the host-less C2paStore format.
    let compound_ok = format == AssetFormat::C2paStore;
    let has_hard_binding = refs.iter().any(|r| {
        let Some(u) = r.get("url").and_then(Value::as_text) else {
            return false;
        };
        let alabel = u.rsplit("c2pa.assertions/").next().unwrap_or("");
        // NOTE: `c2pa.hash.data.part*` is intentionally NOT a stand-alone hard
        // binding. Part hashes are operative only through a present, claim-bound
        // `c2pa.hash.multi-asset` assertion (verify_multi_asset); a part0-only
        // re-sign with no whole-asset hash must NOT validate.
        alabel == "c2pa.hash.data"
            || alabel == "c2pa.hash.bmff"
            || alabel.starts_with("c2pa.hash.bmff.")
            || alabel == "c2pa.hash.boxes"
            || alabel == "c2pa.hash.collection.data"
            || alabel == "c2pa.hash.multi-asset"
            || (compound_ok && alabel == "c2pa.compound.content")
    });
    if !has_hard_binding {
        results.push_failure(
            CLAIM_HARD_BINDINGS_MISSING,
            sig_url.to_string(),
            "claim references no c2pa.hash.* hard binding".into(),
        );
    }

    // algorithm.unsupported: referenced-assertion hash alg must be SHA-2.
    const SUPPORTED_ALGS: [&str; 3] = ["sha256", "sha384", "sha512"];
    for r in &refs {
        if let Some(alg) = r.get("alg").and_then(Value::as_text) {
            if !SUPPORTED_ALGS.contains(&alg) {
                results.push_failure(
                    ALGORITHM_UNSUPPORTED,
                    sig_url.to_string(),
                    format!("unsupported hash algorithm in hashed-URI reference: {alg}"),
                );
            }
        }
    }

    // assertion.cbor.invalid: every assertion box's CBOR must decode.
    for (alabel, cbor) in &manifest.assertions {
        if decode(cbor).is_err() {
            results.push_failure(
                ASSERTION_CBOR_INVALID,
                format!(
                    "self#jumbf=/c2pa/{}/c2pa.assertions/{alabel}",
                    manifest.label
                ),
                format!("assertion '{alabel}' CBOR could not be decoded"),
            );
        }
    }

    fatal
}

/// C2PA manifest-label grammar check, mirroring the reference
/// implementation's `manifest_label_to_parts`:
/// - `urn:uuid:<guid>` (legacy v1 shape) is accepted;
/// - `urn:c2pa:<guid>[:vendor[:version[_reason]]]` with at most 5 parts,
///   vendor <= 32 printable ASCII characters without whitespace, and numeric
///   version/reason;
/// - `<vendor>:urn:uuid:<guid>` (v1 vendor-prefixed, exactly 4 parts).
fn manifest_label_conformant(label: &str) -> bool {
    let parts: Vec<&str> = label.split(':').collect();
    if parts.len() < 3 {
        return false;
    }
    if parts[0] == "urn" {
        if parts[1] == "uuid" {
            return true;
        }
        if parts[1] != "c2pa" {
            return false;
        }
        if parts.len() > 5 {
            return false;
        }
        if parts.len() > 3 && !parts[3].is_empty() {
            let vendor = parts[3];
            if vendor.len() > 32 || !vendor.is_ascii() || vendor.chars().any(char::is_whitespace) {
                return false;
            }
        }
        if parts.len() > 4 && !parts[4].is_empty() {
            let mut version_parts = parts[4].split('_');
            let Some(version) = version_parts.next() else {
                return false;
            };
            if version.parse::<usize>().is_err() {
                return false;
            }
            if let Some(reason) = version_parts.next() {
                if reason.parse::<usize>().is_err() {
                    return false;
                }
            }
        }
        return true;
    }
    // Legacy v1 vendor-prefixed shape: `<vendor>:urn:uuid:<guid>`.
    parts.len() == 4 && parts[1] == "urn" && parts[2] == "uuid"
}

/// Check that every `c2pa.ingredient*` assertion's referenced manifest is
/// present in the manifest store; emit `ingredient.manifest.missing` otherwise.
///
/// An ingredient (`c2pa.ingredient.v2`/`v3`) carries an `activeManifest` and/or
/// `claimSignature` hashed-URI of the form
/// `self#jumbf=/c2pa/urn:c2pa:<label>/...`. The referenced manifest label must
/// exist in the store.
fn verify_ingredient_references(
    manifest: &ParsedManifest,
    store_labels: &std::collections::HashSet<String>,
    sig_url: &str,
    results: &mut ValidationResults,
) {
    for (alabel, cbor) in &manifest.assertions {
        if !alabel.starts_with("c2pa.ingredient") {
            continue;
        }
        let Ok(data) = decode(cbor) else { continue };
        // The referenced manifest URL may live under activeManifest or
        // claimSignature; extract the urn:c2pa:<label> segment.
        let referenced = ["activeManifest", "claimSignature"]
            .iter()
            .filter_map(|k| data.get(k))
            .filter_map(|v| v.get("url").and_then(Value::as_text))
            .filter_map(extract_manifest_label)
            .next();
        if let Some(ref_label) = referenced {
            if !store_labels.contains(&ref_label) {
                results.push_failure(
                    INGREDIENT_MANIFEST_MISSING,
                    sig_url.to_string(),
                    format!("ingredient references manifest '{ref_label}' not in store"),
                );
            }
        }
    }
}

/// Extract the `urn:c2pa:<...>` manifest label from a `self#jumbf=/c2pa/<label>/...`
/// hashed-URI, if present.
fn extract_manifest_label(url: &str) -> Option<String> {
    let rest = url.strip_prefix("self#jumbf=/c2pa/")?;
    let label = rest.split('/').next()?;
    if label.starts_with("urn:c2pa:") {
        Some(label.to_string())
    } else {
        None
    }
}
/// The claim fields that carry hashed-URI assertion references for a claim
/// generation.
fn ref_fields(generation: ClaimGeneration) -> &'static [&'static str] {
    match generation {
        ClaimGeneration::V1 => &["assertions"],
        ClaimGeneration::V2 => &["created_assertions", "gathered_assertions"],
    }
}

fn assertion_label_for_manifest<'a>(url: &'a str, manifest_label: &str) -> Option<&'a str> {
    if let Some(label) = url.strip_prefix("self#jumbf=c2pa.assertions/") {
        return (!label.is_empty() && !label.contains('/')).then_some(label);
    }
    let prefix = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/");
    url.strip_prefix(&prefix)
        .filter(|label| !label.is_empty() && !label.contains('/'))
}

/// Recompute and compare each hashed-URI assertion binding in the claim.
///
/// The reference bytes are the assertion's JUMBF content (description +
/// content boxes, without the superbox header). For legacy claim v1, a
/// tolerant fallback also accepts a hash over the assertion CBOR payload.
/// Absolute references must name this manifest exactly; suffix-only
/// cross-manifest resolution would let a signed URI target different bytes.
fn verify_assertion_bindings(
    claim: &Value,
    manifest: &ParsedManifest,
    generation: ClaimGeneration,
    label: &str,
    results: &mut ValidationResults,
) {
    for field in ref_fields(generation) {
        let Some(Value::Array(refs)) = claim.get(field) else {
            continue;
        };
        for reference in refs {
            let Some(url) = reference.get("url").and_then(Value::as_text) else {
                continue;
            };
            let Some(assertion_label) = assertion_label_for_manifest(url, label) else {
                results.push_failure(
                    HASHED_URI_MISSING,
                    url.to_string(),
                    "assertion reference does not resolve inside the current manifest".into(),
                );
                continue;
            };
            let assertion_url =
                format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{assertion_label}");
            let expected = reference.get("hash").and_then(Value::as_bytes);
            let algorithm = reference
                .get("alg")
                .and_then(Value::as_text)
                .unwrap_or("sha256");
            let content = manifest
                .assertion_jumbf
                .iter()
                .find(|(candidate, _)| candidate == assertion_label)
                .map(|(_, content)| *content);
            let content_matches = matches!(
                (content, expected),
                (Some(bytes), Some(expected_hash))
                    if hash_bytes(algorithm, bytes).as_deref() == Some(expected_hash)
            );
            let legacy_payload_matches = !content_matches
                && generation == ClaimGeneration::V1
                && matches!(
                    (
                        manifest
                            .assertions
                            .iter()
                            .find(|(candidate, _)| candidate == assertion_label)
                            .map(|(_, payload)| *payload),
                        expected,
                    ),
                    (Some(payload), Some(expected_hash))
                        if hash_bytes(algorithm, payload).as_deref() == Some(expected_hash)
                );
            if content_matches || legacy_payload_matches {
                results.push_success(
                    ASSERTION_HASHED_URI_MATCH,
                    assertion_url,
                    format!("hashed uri matched: self#jumbf=c2pa.assertions/{assertion_label}"),
                );
            } else if content.is_none() {
                results.push_failure(
                    HASHED_URI_MISSING,
                    assertion_url,
                    format!("referenced assertion '{assertion_label}' not found in manifest"),
                );
            } else {
                results.push_failure(
                    ASSERTION_HASHED_URI_MISMATCH,
                    assertion_url,
                    format!("hashed uri mismatch: self#jumbf=c2pa.assertions/{assertion_label}"),
                );
            }
        }
    }
}

/// EXPERIMENTAL: host-less compound-content binding label.
const COMPOUND_CONTENT_LABEL: &str = "c2pa.compound.content";

/// EXPERIMENTAL (PR #2058 compound): verify the host-less
/// `c2pa.compound.content` hard binding.
///
/// A compound parent manifest has no host asset; it binds to its `componentOf`
/// children through a `c2pa.compound.content` assertion. Each
/// `components[].ingredientRef` is a hashed-URI {url, hash, alg} to that child's
/// `c2pa.ingredient.v3` assertion *in this manifest*. This recomputes each
/// ingredient assertion's JUMBF-content hash (same domain as
/// [`verify_assertion_bindings`]) and matches it. Because the claim binds
/// compound.content (step 5), compound.content binds each ingredient assertion
/// here, and each ingredient assertion binds its child manifest by
/// `activeManifest` hash ([`verify_ingredient_references`]), the parent is
/// cryptographically bound to its children with no host asset.
///
/// No-op for ordinary manifests (those without a `c2pa.compound.content`
/// assertion), so it is safe to call on every manifest.
fn verify_compound_content(
    manifest: &ParsedManifest,
    label: &str,
    manifest_hashes: &std::collections::HashMap<String, Vec<u8>>,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{COMPOUND_CONTENT_LABEL}");
    let Some((_, cbor)) = manifest
        .assertions
        .iter()
        .find(|(l, _)| l == COMPOUND_CONTENT_LABEL)
    else {
        return; // not a compound manifest
    };
    let Ok(data) = decode(cbor) else {
        results.push_failure(
            ASSERTION_COMPOUND_CONTENT_MALFORMED,
            url,
            "c2pa.compound.content CBOR could not be decoded".into(),
        );
        return;
    };
    let Some(Value::Array(components)) = data.get("components") else {
        results.push_failure(
            ASSERTION_COMPOUND_CONTENT_MALFORMED,
            url,
            "c2pa.compound.content has no components array".into(),
        );
        return;
    };
    if components.is_empty() {
        results.push_failure(
            ASSERTION_COMPOUND_CONTENT_MALFORMED,
            url,
            "c2pa.compound.content components array is empty".into(),
        );
        return;
    }
    // Exact local-assertion ref prefix; reject anything that merely CONTAINS the
    // label or points outside this manifest's assertion store.
    let prefix = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/");
    for (idx, component) in components.iter().enumerate() {
        let Some(ingredient_ref) = component.get("ingredientRef") else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} has no ingredientRef"),
            );
            return;
        };
        // Strict: url, hash, AND alg must all be present; alg pinned to sha256.
        let (Some(ref_url), Some(expected), Some(alg)) = (
            ingredient_ref.get("url").and_then(Value::as_text),
            ingredient_ref.get("hash").and_then(Value::as_bytes),
            ingredient_ref.get("alg").and_then(Value::as_text),
        ) else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} ingredientRef missing url/hash/alg"),
            );
            return;
        };
        if alg != "sha256" {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} ingredientRef unsupported alg {alg:?}"),
            );
            return;
        }
        let Some(alabel) = ref_url.strip_prefix(&prefix) else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} ingredientRef url is not a local assertion ref"),
            );
            return;
        };
        // The component MUST reference the base c2pa.ingredient.v3 assertion or
        // a standard `__N` instance, not a different assertion or version label.
        let is_instance = alabel
            .strip_prefix("c2pa.ingredient.v3__")
            .and_then(|suffix| suffix.parse::<usize>().ok())
            .is_some_and(|instance| instance > 0);
        if alabel != "c2pa.ingredient.v3" && !is_instance {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} does not reference a c2pa.ingredient.v3 assertion ({alabel})"),
            );
            return;
        }
        // 1) The component binds the ingredient assertion's exact JUMBF content.
        let Some(ing_content) = manifest
            .assertion_jumbf
            .iter()
            .find(|(l, _)| l == alabel)
            .map(|(_, c)| *c)
        else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!("compound component {idx} ingredient assertion '{alabel}' not present"),
            );
            return;
        };
        if hash_bytes(alg, ing_content).as_deref() != Some(expected) {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!("compound component {idx} ingredientRef hash did not match '{alabel}'"),
            );
            return;
        }
        // 2) The ingredient assertion must be a componentOf with an activeManifest.
        let Some(ing) = manifest
            .assertions
            .iter()
            .find(|(l, _)| l == alabel)
            .map(|(_, c)| *c)
            .and_then(|c| decode(c).ok())
        else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} ingredient '{alabel}' CBOR invalid"),
            );
            return;
        };
        if ing.get("relationship").and_then(Value::as_text) != Some("componentOf") {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!("compound component {idx} ingredient '{alabel}' is not componentOf"),
            );
            return;
        }
        // 3) The ingredient's activeManifest hash MUST match the actual child
        // manifest present in the store (closes the child-swap gap: the child
        // manifest bytes live OUTSIDE the parent's signed claim).
        let (Some(child_url), Some(child_hash), Some(child_alg)) = ing
            .get("activeManifest")
            .map(|a| {
                (
                    a.get("url").and_then(Value::as_text),
                    a.get("hash").and_then(Value::as_bytes),
                    a.get("alg").and_then(Value::as_text),
                )
            })
            .unwrap_or((None, None, None))
        else {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!(
                    "compound component {idx} ingredient '{alabel}' has no valid activeManifest"
                ),
            );
            return;
        };
        if child_alg != "sha256" {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MALFORMED,
                url.clone(),
                format!("compound component {idx} activeManifest unsupported alg {child_alg:?}"),
            );
            return;
        }
        let child_ok = extract_manifest_label(child_url)
            .and_then(|cl| manifest_hashes.get(&cl).cloned())
            .map(|computed| computed.as_slice() == child_hash)
            .unwrap_or(false);
        if !child_ok {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!(
                    "compound component {idx} child manifest absent or hash mismatch (tampered/substituted child)"
                ),
            );
            return;
        }
    }
    results.push_success(
        ASSERTION_COMPOUND_CONTENT_MATCH,
        url,
        format!(
            "compound binding verified: {} component(s)",
            components.len()
        ),
    );
}

/// Confirm that a caller-computed digest is the active claim's sole supported
/// hard binding. This path never accepts generalized box, collection,
/// multi-asset, or merkle bindings because the prepared protocol does not
/// expose enough source bytes to verify those forms independently.
fn verify_prehashed_hard_binding(
    manifest: &ParsedManifest,
    digest: &[u8],
    label: &str,
    results: &mut ValidationResults,
) {
    let bindings = manifest
        .assertions
        .iter()
        .filter(|(assertion_label, _)| {
            assertion_label.as_str() == "c2pa.hash.data"
                || assertion_label.as_str() == "c2pa.hash.bmff"
                || assertion_label.starts_with("c2pa.hash.bmff.")
        })
        .collect::<Vec<_>>();
    let (assertion_label, assertion_cbor) = match bindings.as_slice() {
        [binding] => (binding.0.as_str(), binding.1),
        _ => {
            results.push_failure(
                ASSERTION_DATA_HASH_MISMATCH,
                format!("self#jumbf=/c2pa/{label}/c2pa.assertions"),
                "prepared verification requires exactly one supported hard binding".into(),
            );
            return;
        }
    };
    let is_bmff = assertion_label.starts_with("c2pa.hash.bmff");
    let match_code = if is_bmff {
        ASSERTION_BMFF_HASH_MATCH
    } else {
        ASSERTION_DATA_HASH_MATCH
    };
    let mismatch_code = if is_bmff {
        ASSERTION_BMFF_HASH_MISMATCH
    } else {
        ASSERTION_DATA_HASH_MISMATCH
    };
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{assertion_label}");
    let Ok(assertion) = decode(assertion_cbor) else {
        results.push_failure(
            mismatch_code,
            url,
            "hard-binding assertion CBOR invalid".into(),
        );
        return;
    };
    let algorithm = assertion
        .get("alg")
        .and_then(Value::as_text)
        .unwrap_or("sha256");
    if algorithm != "sha256" || assertion.get("merkle").is_some() || digest.len() != 32 {
        results.push_failure(
            mismatch_code,
            url,
            "prepared verification supports one non-merkle SHA-256 hard binding".into(),
        );
        return;
    }
    let expected = assertion.get("hash").and_then(Value::as_bytes);
    if expected == Some(digest)
        && !results.has_failure(ASSERTION_HASHED_URI_MISMATCH)
        && !results.has_failure(HASHED_URI_MISSING)
    {
        results.push_success(
            match_code,
            url,
            "caller-computed hard-binding digest valid".into(),
        );
    } else if expected != Some(digest) {
        results.push_failure(mismatch_code, url, "hard-binding digest mismatch".into());
    }
}

/// Verify the `c2pa.hash.data` hard binding against the asset bytes.
///
/// Verify the asset hard binding (`c2pa.hash.data` or `c2pa.hash.bmff*`).
///
/// `c2pa.hash.data` excludes byte ranges given as `{start, length}`. BMFF hash
/// assertions (`c2pa.hash.bmff`, `.v2`, `.v3`) instead exclude whole boxes by
/// `xpath` and, in the merkle variant, carry a `merkle` array of per-chunk
/// hashes. The simple (non-merkle) BMFF case is verified by resolving the box
/// paths to byte ranges; the merkle variant verifies the `initHash` over this
/// asset and, when `fragments` are supplied, every fragment's Merkle leaf.
fn verify_data_hash(
    claim: &Value,
    manifest: &ParsedManifest,
    data: &[u8],
    format: AssetFormat,
    fragments: &[&[u8]],
    label: &str,
    results: &mut ValidationResults,
) {
    let _ = claim;
    // A `c2pa.hash.multi-asset` (byte-offset multipart) assertion, when present,
    // becomes the operative hard binding once the whole-file `c2pa.hash.data` no
    // longer matches — an optional part may have been legitimately removed,
    // shortening the file. It is located here so the single-asset path can fall
    // back to it. Collection hashes (`c2pa.hash.collection.*`) are URI-based
    // OPC/ZIP digests, NOT byte-offset parts, and are intentionally not routed
    // through the multipart verifier.
    let multi_asset = manifest
        .assertions
        .iter()
        .find(|(l, _)| l == "c2pa.hash.multi-asset")
        .map(|(_, c)| *c);
    // A tampered assertion breaks the claim's hashed-URI binding to it
    // (`assertion.hashedURI.mismatch`, already recorded by
    // `verify_assertion_bindings`). The asset bytes can still hash correctly
    // because every assertion lives inside the (data-hash-excluded) manifest,
    // but the manifest's integrity is compromised; a positive hard binding MUST
    // NOT then be reported — the hashed-URI failure carries the verdict.
    let binding_compromised = results.has_failure(ASSERTION_HASHED_URI_MISMATCH)
        || results.has_failure(HASHED_URI_MISSING);
    // Single-asset binding: prefer the whole-asset hash assertion (not a part).
    let Some((alabel, cbor)) = manifest
        .assertions
        .iter()
        .find(|(l, _)| {
            l.as_str() == "c2pa.hash.data"
                || l.as_str() == "c2pa.hash.bmff"
                || l.starts_with("c2pa.hash.bmff.")
        })
        .map(|(l, c)| (l.clone(), *c))
    else {
        // No whole-asset data/BMFF binding. The hard binding may instead be a
        // general box hash (box-structured formats), a collection data hash
        // (ZIP/OPC archives), or pure multi-asset parts.
        if let Some((_, bcbor)) = manifest
            .assertions
            .iter()
            .find(|(l, _)| l.as_str() == "c2pa.hash.boxes")
        {
            verify_boxes_hash(
                bcbor,
                format,
                data,
                multi_asset,
                manifest,
                binding_compromised,
                label,
                results,
            );
            return;
        }
        if let Some((_, ccbor)) = manifest
            .assertions
            .iter()
            .find(|(l, _)| l.as_str() == "c2pa.hash.collection.data")
        {
            verify_collection_hash(ccbor, data, binding_compromised, label, results);
            return;
        }
        if let Some(ma_cbor) = multi_asset {
            verify_multi_asset(manifest, ma_cbor, data, label, results);
        }
        return;
    };
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{alabel}");
    let is_bmff = alabel == "c2pa.hash.bmff" || alabel.starts_with("c2pa.hash.bmff.");
    let mismatch_code = if is_bmff {
        ASSERTION_BMFF_HASH_MISMATCH
    } else {
        ASSERTION_DATA_HASH_MISMATCH
    };
    let match_code = if is_bmff {
        ASSERTION_BMFF_HASH_MATCH
    } else {
        ASSERTION_DATA_HASH_MATCH
    };
    let Ok(hash_data) = decode(cbor) else {
        results.push_failure(mismatch_code, url, "hash assertion CBOR invalid".into());
        return;
    };
    let expected = hash_data.get("hash").and_then(Value::as_bytes);
    let alg = hash_data
        .get("alg")
        .and_then(Value::as_text)
        .unwrap_or("sha256");
    // Merkle BMFF binding (fragmented DASH/HLS or chunked mdat). What is
    // verifiable from a single asset is the merkle `initHash` over the init
    // segment; per-fragment merkle roots need the fragment files themselves
    // and are reported informational (never a false mismatch).
    if is_bmff && hash_data.get("merkle").is_some() {
        verify_bmff_merkle_init(
            &hash_data,
            data,
            fragments,
            &url,
            binding_compromised,
            results,
        );
        return;
    }
    // BMFF hard bindings are computed structurally (box-offset markers), not as
    // a plain file-minus-exclusions digest; delegate to the format crate so
    // sign and verify share byte-exact semantics. `c2pa.hash.data` excludes
    // explicit byte ranges.
    let actual: Option<Vec<u8>> = if is_bmff {
        let xpaths = bmff_exclusion_xpaths(&hash_data);
        c2pa_formats::bmff_hash(data, alg, &xpaths).ok()
    } else {
        // Reject pathological exclusion lists before parsing or hashing any
        // ranges. This is a resource-exhaustion guard, not a policy limit.
        if let Some(Value::Array(items)) = hash_data.get("exclusions") {
            if items.len() > MAX_DATA_HASH_EXCLUSIONS {
                results.push_failure(
                    mismatch_code,
                    url,
                    format!(
                        "exclusion list exceeds the verifier cap ({} > {MAX_DATA_HASH_EXCLUSIONS}); manifest rejected",
                        items.len()
                    ),
                );
                return;
            }
        }
        let exclusions = parse_exclusions(hash_data.get("exclusions"));
        hash_with_exclusions(alg, data, &exclusions)
    };
    let matched = matches!((&actual, expected), (Some(a), Some(e)) if a.as_slice() == e);
    if matched {
        // Whole asset present and intact: this is the hard binding. A
        // multi-asset assertion (if any) describes the same intact bytes, so its
        // per-part success is not separately reported — the reference verifier
        // emits only `dataHash.match` in this scenario.
        if !binding_compromised {
            results.push_success(match_code, url, "asset hash valid".into());
        }
        return;
    }
    // Region-anchored locate-and-lift: a signed text snippet may have been
    // pasted into a larger document (e.g. a full web page). When the manifest
    // records the signed region length (`com.encypher.region`), reconstruct the
    // original signed asset from the surrounding bytes and re-check the standard
    // hard binding over just that region, so the snippet still validates and a
    // tamper to it (but not to the surrounding text) is still caught.
    if !is_bmff {
        if let Some(lifted) = lift_signed_region(manifest, data) {
            let exclusions = parse_exclusions(hash_data.get("exclusions"));
            let region_actual = hash_with_exclusions(alg, &lifted, &exclusions);
            if matches!((&region_actual, expected), (Some(a), Some(e)) if a.as_slice() == e) {
                if !binding_compromised {
                    results.push_success(
                        match_code,
                        url,
                        "asset hash valid (signed region lifted from larger asset)".into(),
                    );
                }
                return;
            }
        }
    }
    // Whole-file hash did not match. When a multipart assertion is present the
    // per-part hashes are the operative binding (a removed optional part
    // legitimately shortens the file); defer to it and suppress the whole-file
    // mismatch so a valid post-removal asset is not falsely invalidated.
    if let Some(ma_cbor) = multi_asset {
        verify_multi_asset(manifest, ma_cbor, data, label, results);
        return;
    }
    results.push_failure(mismatch_code, url, "asset hash mismatch".into());
}

/// Verify a merkle `c2pa.hash.bmff*` binding.
///
/// A merkle BMFF binding covers a fragmented asset (DASH/HLS init segment +
/// fragment files) or a chunked monolithic `mdat`. From the primary asset the
/// merkle `initHash` — the BMFF-structural hash of the init segment with the
/// assertion's exclusions applied — is checked with the same
/// box-offset-marker hashing the non-merkle path uses
/// ([`c2pa_formats::bmff_hash`]).
///
/// When `fragments` are supplied (spec 15.12.2.2 / A.5.4), each fragment's
/// Merkle leaf hash is recomputed (plain digest minus exclusions, no offset
/// markers) and climbed to the row stored in the assertion using the proof in
/// the fragment's auxiliary C2PA `merkle` box; mismatches fail with
/// `assertion.bmffHash.mismatch`, structural defects with
/// `assertion.bmffHash.malformed`. Without fragments, fragment trees are
/// reported informational. A monolithic merkle binding (no `initHash`) stays
/// informational — never a false verdict in either direction.
fn verify_bmff_merkle_init(
    hash_data: &Value,
    data: &[u8],
    fragments: &[&[u8]],
    url: &str,
    binding_compromised: bool,
    results: &mut ValidationResults,
) {
    let Some(Value::Array(entries)) = hash_data.get("merkle") else {
        results.push_failure(
            ASSERTION_BMFF_HASH_MISMATCH,
            url.to_string(),
            "merkle field is not an array".into(),
        );
        return;
    };
    let assertion_alg = hash_data
        .get("alg")
        .and_then(Value::as_text)
        .unwrap_or("sha256");
    let xpaths = bmff_exclusion_xpaths(hash_data);

    // Cache the computed init-segment hash per algorithm (entries for multiple
    // tracks almost always share one).
    let mut cached: Option<(String, Option<Vec<u8>>)> = None;
    let mut init_tracks = 0usize;
    let mut fragment_trees = 0usize;
    let mut mono_entries = 0usize;
    let mut mono_ok = 0usize;
    for entry in entries {
        if entry.get("hashes").is_some() {
            fragment_trees += 1;
        }
        let Some(expected_init) = entry.get("initHash").and_then(Value::as_bytes) else {
            // Monolithic (chunked-mdat) merkle entry: validated per spec
            // 15.12.2.1 against this asset's own mdat payload(s).
            mono_entries += 1;
            if verify_bmff_monolithic_entry(entry, assertion_alg, data, url, results) {
                mono_ok += 1;
            }
            continue;
        };
        let alg = entry
            .get("alg")
            .and_then(Value::as_text)
            .unwrap_or(assertion_alg);
        let actual = match &cached {
            Some((a, h)) if a == alg => h.clone(),
            _ => {
                let h = c2pa_formats::bmff_hash(data, alg, &xpaths).ok();
                cached = Some((alg.to_string(), h.clone()));
                h
            }
        };
        if actual.as_deref() != Some(expected_init) {
            results.push_failure(
                ASSERTION_BMFF_HASH_MISMATCH,
                url.to_string(),
                "merkle initHash mismatch: init segment bytes altered".into(),
            );
            return;
        }
        init_tracks += 1;
    }

    if init_tracks > 0 {
        if !binding_compromised {
            results.push_success(
                ASSERTION_BMFF_HASH_MATCH,
                url.to_string(),
                format!("merkle initHash valid over init segment ({init_tracks} track(s))"),
            );
        }
        if fragments.is_empty() {
            if fragment_trees > 0 {
                results.push_informational(
                    ASSERTION_BMFF_HASH_MATCH,
                    url.to_string(),
                    format!(
                        "{fragment_trees} fragment merkle tree(s) not evaluated: fragment files not provided (use fragmented verification)"
                    ),
                );
            }
        } else {
            verify_bmff_fragments(entries, assertion_alg, &xpaths, fragments, url, results);
        }
    } else if mono_entries > 0 {
        if mono_ok == mono_entries && !binding_compromised {
            results.push_success(
                ASSERTION_BMFF_HASH_MATCH,
                url.to_string(),
                format!("monolithic merkle mdat tree(s) valid ({mono_ok} of {mono_entries})"),
            );
        }
    } else {
        results.push_failure(
            ASSERTION_BMFF_HASH_MALFORMED,
            url.to_string(),
            "merkle array has no usable entries".into(),
        );
    }
}

/// Validate one monolithic (chunked-mdat) merkle entry per spec 15.12.2.1.
///
/// `localId` is the zero-based index of the `mdat` box this tree covers. The
/// payload is chunked by `fixedBlockSize` XOR `variableBlockSizes` (both
/// present = malformed; neither = the whole payload is a single leaf). When
/// the assertion stores the leaf row (`count == hashes.len()`), leaves are
/// compared directly; when it stores a higher row (`count > hashes.len()`),
/// each leaf's auxiliary C2PA `merkle` box in this same file supplies the
/// proof to climb. Returns `true` when the entry validated (failures are
/// pushed otherwise).
fn verify_bmff_monolithic_entry(
    entry: &Value,
    assertion_alg: &str,
    data: &[u8],
    url: &str,
    results: &mut ValidationResults,
) -> bool {
    let malformed = |results: &mut ValidationResults, why: String| {
        results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why);
        false
    };
    let alg = entry
        .get("alg")
        .and_then(Value::as_text)
        .unwrap_or(assertion_alg);
    let int = |k: &str| match entry.get(k) {
        Some(Value::Integer(n)) => usize::try_from(*n).ok(),
        _ => None,
    };
    let Some(local_id) = int("localId") else {
        return malformed(results, "monolithic merkle entry missing localId".into());
    };
    let Some(count) = int("count") else {
        return malformed(results, "monolithic merkle entry missing count".into());
    };
    let Some(Value::Array(row_vals)) = entry.get("hashes") else {
        return malformed(results, "monolithic merkle entry missing hashes row".into());
    };
    let row: Vec<&[u8]> = row_vals.iter().filter_map(Value::as_bytes).collect();

    let Ok(mdats) = c2pa_formats::bmff_mdat_payloads(data) else {
        return malformed(results, "asset not parseable as BMFF".into());
    };
    let Some(&(pstart, plen)) = mdats.get(local_id) else {
        return malformed(results, format!("no mdat with index {local_id}"));
    };
    let payload = &data[pstart..pstart + plen];

    // Chunking (spec 15.12.2.1): fixedBlockSize XOR variableBlockSizes.
    let fixed = int("fixedBlockSize");
    let variable: Option<Vec<usize>> = match entry.get("variableBlockSizes") {
        Some(Value::Array(items)) => {
            let v: Option<Vec<usize>> = items
                .iter()
                .map(|i| match i {
                    Value::Integer(n) => usize::try_from(*n).ok(),
                    _ => None,
                })
                .collect();
            match v {
                Some(v) => Some(v),
                None => {
                    return malformed(results, "variableBlockSizes entry not an integer".into())
                }
            }
        }
        Some(_) => return malformed(results, "variableBlockSizes is not an array".into()),
        None => None,
    };
    let chunks: Vec<&[u8]> = match (fixed, variable) {
        (Some(_), Some(_)) => {
            return malformed(
                results,
                "fixedBlockSize and variableBlockSizes are mutually exclusive".into(),
            )
        }
        (Some(0), None) => return malformed(results, "fixedBlockSize is zero".into()),
        (Some(size), None) => payload.chunks(size).collect(),
        (None, Some(sizes)) => {
            if sizes.len() != count || sizes.iter().sum::<usize>() != plen {
                return malformed(
                    results,
                    "variableBlockSizes do not tile the mdat payload".into(),
                );
            }
            let mut out = Vec::with_capacity(sizes.len());
            let mut off = 0usize;
            for s in sizes {
                out.push(&payload[off..off + s]);
                off += s;
            }
            out
        }
        (None, None) => vec![payload],
    };
    if chunks.len() != count {
        return malformed(
            results,
            format!(
                "count {count} does not match {} mdat chunk(s)",
                chunks.len()
            ),
        );
    }
    if count < row.len() {
        return malformed(results, "count smaller than stored hashes row".into());
    }

    if count == row.len() {
        // The manifest stores the leaf row: compare leaves directly.
        for (i, chunk) in chunks.iter().enumerate() {
            let Some(leaf) = hash_bytes(alg, chunk) else {
                return malformed(results, format!("unsupported hash algorithm '{alg}'"));
            };
            if row.get(i).copied() != Some(leaf.as_slice()) {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!("mdat {local_id} chunk {i}: merkle leaf hash mismatch"),
                );
                return false;
            }
        }
        return true;
    }

    // The manifest stores a higher row: each leaf needs its auxiliary C2PA
    // merkle box (in this same file) for the proof climb.
    let Ok(aux_boxes) = c2pa_formats::bmff_merkle_boxes(data) else {
        return malformed(results, "asset not parseable as BMFF".into());
    };
    let unique_id = match entry.get("uniqueId") {
        Some(Value::Integer(n)) => *n,
        _ => return malformed(results, "monolithic merkle entry missing uniqueId".into()),
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let mb = aux_boxes.iter().find(|b| {
            b.as_ref()
                .map(|m| {
                    m.unique_id == unique_id && m.local_id == local_id as i128 && m.location == i
                })
                .unwrap_or(false)
        });
        let Some(Ok(mb)) = mb else {
            return malformed(
                results,
                format!("mdat {local_id} chunk {i}: auxiliary C2PA merkle box missing"),
            );
        };
        let Some(leaf) = hash_bytes(alg, chunk) else {
            return malformed(results, format!("unsupported hash algorithm '{alg}'"));
        };
        match merkle_climb(leaf, i, count, &mb.proof, row.len(), alg) {
            Some((idx, derived)) if row.get(idx).copied() == Some(derived.as_slice()) => {}
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!("mdat {local_id} chunk {i}: merkle leaf does not derive the stored row hash"),
                );
                return false;
            }
            None => {
                return malformed(
                    results,
                    format!("mdat {local_id} chunk {i}: merkle proof inconsistent"),
                );
            }
        }
    }
    true
}

/// Validate supplied fragment files against the assertion's Merkle trees
/// (spec A.5.4.1.2 + 18.6.6.1).
fn verify_bmff_fragments(
    entries: &[Value],
    assertion_alg: &str,
    xpaths: &[String],
    fragments: &[&[u8]],
    url: &str,
    results: &mut ValidationResults,
) {
    let mut matched = 0usize;
    for (i, fragment) in fragments.iter().enumerate() {
        // 1. The fragment's auxiliary C2PA merkle box (required: A.5.4.1.2).
        let boxes = match c2pa_formats::bmff_merkle_boxes(fragment) {
            Ok(b) => b,
            Err(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {i}: not parseable as BMFF"),
                );
                continue;
            }
        };
        let mb = match boxes.into_iter().next() {
            Some(Ok(mb)) => mb,
            Some(Err(why)) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {i}: {why}"),
                );
                continue;
            }
            None => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {i}: auxiliary C2PA merkle box missing"),
                );
                continue;
            }
        };
        // 2. Match (uniqueId, localId) to a merkle entry in the assertion.
        let entry = entries.iter().find(|e| {
            let f = |k: &str| match e.get(k) {
                Some(Value::Integer(n)) => Some(*n),
                _ => None,
            };
            f("uniqueId") == Some(mb.unique_id) && f("localId") == Some(mb.local_id)
        });
        let Some(entry) = entry else {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!(
                    "fragment {i}: no merkle entry for uniqueId={} localId={}",
                    mb.unique_id, mb.local_id
                ),
            );
            continue;
        };
        let alg = entry
            .get("alg")
            .and_then(Value::as_text)
            .unwrap_or(assertion_alg);
        let Some(Value::Array(row)) = entry.get("hashes") else {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!("fragment {i}: merkle entry has no hashes row"),
            );
            continue;
        };
        let row: Vec<&[u8]> = row.iter().filter_map(Value::as_bytes).collect();
        let count = match entry.get("count") {
            Some(Value::Integer(n)) => *n as usize,
            _ => row.len(),
        };
        // 3. Leaf hash over the fragment bytes minus exclusions (no markers).
        let Ok(leaf) = c2pa_formats::bmff_fragment_leaf_hash(fragment, alg, xpaths) else {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!("fragment {i}: unsupported hash algorithm '{alg}'"),
            );
            continue;
        };
        // 4. Climb the proof to the stored row and compare.
        match merkle_climb(leaf, mb.location, count, &mb.proof, row.len(), alg) {
            Some((idx, derived)) if row.get(idx).copied() == Some(derived.as_slice()) => {
                matched += 1;
            }
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!("fragment {i}: merkle leaf does not derive the stored row hash"),
                );
            }
            None => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!(
                        "fragment {i}: merkle proof inconsistent with location {} / count {count} / row {}",
                        mb.location,
                        row.len()
                    ),
                );
            }
        }
    }
    if matched > 0 && matched == fragments.len() {
        results.push_success(
            ASSERTION_BMFF_HASH_MATCH,
            url.to_string(),
            format!("{matched} fragment merkle leaf hash(es) valid"),
        );
    }
}

/// Climb a Merkle proof from a leaf to the row stored in the manifest.
///
/// Standard binary tree with C2PA's null-node rule (spec A.5.4): row sizes
/// shrink as `n -> ceil(n/2)`; a node whose sibling would be a null node (the
/// lone last node of an odd-sized row) is PROMOTED unchanged and consumes no
/// proof hash ("null hashes are not included"). At each level with a real
/// sibling, the next proof hash is combined left||right by index parity.
/// Returns the derived hash and its index in the stored row, or `None` when
/// the proof length does not fit the distance between the leaf row (`count`
/// nodes) and the stored row (`row_len` nodes).
fn merkle_climb(
    leaf: Vec<u8>,
    location: usize,
    count: usize,
    proof: &[Vec<u8>],
    row_len: usize,
    alg: &str,
) -> Option<(usize, Vec<u8>)> {
    if row_len == 0 || count == 0 || location >= count {
        return None;
    }
    let mut h = leaf;
    let mut idx = location;
    let mut n = count;
    let mut proof_iter = proof.iter();
    while n > row_len {
        let sibling = idx ^ 1;
        if sibling < n {
            let s = proof_iter.next()?;
            let mut buf = Vec::with_capacity(h.len() + s.len());
            if idx.is_multiple_of(2) {
                buf.extend_from_slice(&h);
                buf.extend_from_slice(s);
            } else {
                buf.extend_from_slice(s);
                buf.extend_from_slice(&h);
            }
            h = hash_bytes(alg, &buf)?;
        }
        idx /= 2;
        n = n.div_ceil(2);
    }
    // The whole proof must be consumed and the final row must match in size.
    if n != row_len || proof_iter.next().is_some() {
        return None;
    }
    Some((idx, h))
}

/// Verify a general box hash (`c2pa.hash.boxes`, spec 15.12.3).
///
/// The asset is segmented into named spans ([`c2pa_formats::box_spans`]) and
/// the assertion's `boxes` entries are consumed in order: each entry's
/// `names` must match the next spans exactly (out-of-order or missing →
/// `assertion.boxesHash.mismatch`), its hash is computed from the start of
/// the first named span through the end of the last (inter-box bytes
/// included), and compared unless the entry is `excluded` or is the `C2PA`
/// manifest run (structurally checked; its hash is the placeholder the
/// two-pass creation cannot make self-consistent). Asset spans left over
/// after all entries → `assertion.boxesHash.unknownBox`. On a hash mismatch
/// the multi-asset fallback applies (15.12.4), mirroring the data/BMFF paths.
#[allow(clippy::too_many_arguments)]
fn verify_boxes_hash(
    cbor: &[u8],
    format: AssetFormat,
    data: &[u8],
    multi_asset: Option<&[u8]>,
    manifest: &ParsedManifest,
    binding_compromised: bool,
    label: &str,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.hash.boxes");
    let Ok(box_map) = decode(cbor) else {
        results.push_failure(
            ASSERTION_BOXES_HASH_MALFORMED,
            url,
            "boxes hash assertion CBOR invalid".into(),
        );
        return;
    };
    let Some(Value::Array(entries)) = box_map.get("boxes") else {
        results.push_failure(ASSERTION_BOXES_HASH_MALFORMED, url, "no boxes field".into());
        return;
    };
    let default_alg = box_map.get("alg").and_then(Value::as_text);

    let spans = match c2pa_formats::box_spans(format, data) {
        Ok(Some(s)) => s,
        Ok(None) => {
            results.push_informational(
                ASSERTION_BOXES_HASH_MATCH,
                url,
                "general box hash not evaluated: segmentation for this container is not implemented".into(),
            );
            return;
        }
        Err(e) => {
            results.push_failure(
                ASSERTION_BOXES_HASH_MALFORMED,
                url,
                format!("asset segmentation failed: {e}"),
            );
            return;
        }
    };

    let mut idx = 0usize;
    let mut mismatched = false;
    let mut c2pa_seen = false;
    for entry in entries {
        let Some(Value::Array(names)) = entry.get("names") else {
            results.push_failure(
                ASSERTION_BOXES_HASH_MALFORMED,
                url,
                "box entry missing names".into(),
            );
            return;
        };
        let names: Vec<&str> = names.iter().filter_map(Value::as_text).collect();
        if names.is_empty() {
            results.push_failure(
                ASSERTION_BOXES_HASH_MALFORMED,
                url,
                "empty names array".into(),
            );
            return;
        }
        let Some(alg) = entry.get("alg").and_then(Value::as_text).or(default_alg) else {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url,
                "no hash algorithm in box entry or box map".into(),
            );
            return;
        };
        let first = idx;
        for name in &names {
            match spans.get(idx) {
                Some(s) if s.name == *name => idx += 1,
                Some(s) => {
                    results.push_failure(
                        ASSERTION_BOXES_HASH_MISMATCH,
                        url,
                        format!(
                            "expected box '{name}' but found '{}' (out of order or missing)",
                            s.name
                        ),
                    );
                    return;
                }
                None => {
                    results.push_failure(
                        ASSERTION_BOXES_HASH_MISMATCH,
                        url,
                        format!("asset ended before box '{name}'"),
                    );
                    return;
                }
            }
        }
        let excluded = matches!(entry.get("excluded"), Some(Value::Bool(true)));
        let is_c2pa_run = names == ["C2PA"];
        if is_c2pa_run {
            c2pa_seen = true;
            continue; // structurally consumed; hash is the creation placeholder
        }
        if excluded {
            continue;
        }
        let Some(expected) = entry.get("hash").and_then(Value::as_bytes) else {
            results.push_failure(
                ASSERTION_BOXES_HASH_MISMATCH,
                url,
                "box entry missing hash".into(),
            );
            return;
        };
        let range = &data[spans[first].start..spans[idx - 1].end];
        let Some(actual) = hash_bytes(alg, range) else {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url,
                format!("unsupported hash algorithm '{alg}'"),
            );
            return;
        };
        if actual.as_slice() != expected {
            mismatched = true;
        }
    }
    if idx != spans.len() {
        results.push_failure(
            ASSERTION_BOXES_HASH_UNKNOWN_BOX,
            url,
            format!(
                "asset contains {} box(es) not covered by the assertion (first: '{}')",
                spans.len() - idx,
                spans[idx].name
            ),
        );
        return;
    }
    if mismatched {
        // 15.12.3: on mismatch fall back to the multi-asset hash if present.
        if let Some(ma_cbor) = multi_asset {
            verify_multi_asset(manifest, ma_cbor, data, label, results);
        } else {
            results.push_failure(
                ASSERTION_BOXES_HASH_MISMATCH,
                url,
                "box hash mismatch: asset bytes altered".into(),
            );
        }
        return;
    }
    if !c2pa_seen {
        results.push_failure(
            ASSERTION_BOXES_HASH_MALFORMED,
            url,
            "assertion does not cover the C2PA manifest box".into(),
        );
        return;
    }
    if !binding_compromised {
        results.push_success(
            ASSERTION_BOXES_HASH_MATCH,
            url,
            format!(
                "all box hashes valid ({} entries over {} boxes)",
                entries.len(),
                spans.len()
            ),
        );
    }
}

/// Verify a collection data hash (`c2pa.hash.collection.data`, spec 15.12.5).
///
/// Per-URI hashing primarily covers the exact A.6.2.1 span: the local file
/// header followed by compressed/encrypted content. The c2pa-org public ZIP
/// vector's broader local span is accepted as a compatibility convention.
/// URIs with `.`/`..` path segments are rejected (`invalidURI`);
/// listed-but-absent files are `incorrectFileCount`.
///
/// `zip_central_directory_hash` covers all central headers and the EOCD while
/// skipping the manifest entry's four-byte CRC-32 field, exactly as A.6.2.2
/// requires. A mismatch is always a hard binding failure.
fn verify_collection_hash(
    cbor: &[u8],
    data: &[u8],
    binding_compromised: bool,
    label: &str,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.hash.collection.data");
    let malformed = |results: &mut ValidationResults, why: String| {
        results.push_failure(ASSERTION_COLLECTION_HASH_MALFORMED, url.clone(), why);
    };
    let Ok(map) = decode(cbor) else {
        malformed(results, "collection hash assertion CBOR invalid".into());
        return;
    };
    let Some(Value::Array(uris)) = map.get("uris") else {
        malformed(results, "no uris field".into());
        return;
    };
    let Some(alg) = map.get("alg").and_then(Value::as_text) else {
        malformed(results, "no alg field".into());
        return;
    };

    // Parse the central directory up front, both as a structural check and to
    // obtain the exact A.6.2.2 byte slices.
    let Ok(cd_parts) = c2pa_formats::zip_central_directory_hash_parts(data) else {
        malformed(results, "asset is not a readable ZIP archive".into());
        return;
    };
    let Some(expected_cd) = map
        .get("zip_central_directory_hash")
        .and_then(Value::as_bytes)
    else {
        malformed(results, "zip_central_directory_hash missing".into());
        return;
    };

    for u in uris {
        let (Some(uri), Some(expected)) = (
            u.get("uri").and_then(Value::as_text),
            u.get("hash").and_then(Value::as_bytes),
        ) else {
            malformed(results, "uri entry missing uri or hash".into());
            return;
        };
        if uri.split('/').any(|seg| seg == "." || seg == "..") {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_INVALID_URI,
                url,
                format!("uri '{uri}' contains a relative path segment"),
            );
            return;
        }
        // Primary: exact A.6.2.1 header-plus-content span. Compatibility:
        // c2pa-org's published ZIP vector includes the trailing descriptor.
        let span = match c2pa_formats::zip_entry_hash_span(data, uri) {
            Ok(s) => s,
            Err(e) => {
                malformed(results, format!("entry '{uri}' unreadable: {e}"));
                return;
            }
        };
        let Some((es, ee)) = span else {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_INCORRECT_FILE_COUNT,
                url,
                format!("listed file '{uri}' not found in archive"),
            );
            return;
        };
        let exact_match = hash_bytes(alg, &data[es..ee]).is_some_and(|h| h.as_slice() == expected);
        let public_vector_match = !exact_match
            && matches!(
                c2pa_formats::zip_entry_local_span(data, uri),
                Ok(Some((start, end)))
                    if hash_bytes(alg, &data[start..end])
                        .is_some_and(|h| h.as_slice() == expected)
            );
        if !(exact_match || public_vector_match) {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_MISMATCH,
                url.clone(),
                format!("collection entry '{uri}' hash mismatch"),
            );
            return;
        }
    }

    let cd_ok = hash_parts(alg, &cd_parts).is_some_and(|h| h.as_slice() == expected_cd);
    if !cd_ok {
        results.push_failure(
            ASSERTION_COLLECTION_HASH_MISMATCH,
            url,
            "ZIP central directory hash mismatch".into(),
        );
        return;
    }
    if !binding_compromised {
        results.push_success(
            ASSERTION_COLLECTION_HASH_MATCH,
            url,
            format!(
                "collection hashes valid ({} entries; central directory checked)",
                uris.len()
            ),
        );
    }
}

/// Maximum number of `c2pa.hash.data` exclusion ranges the verifier accepts.
///
/// Inputs beyond this bound are rejected before the exclusion list is parsed
/// or any asset bytes are hashed.
const MAX_DATA_HASH_EXCLUSIONS: usize = 32_768;

/// A.8 text-wrapper header size: 8 (magic) + 1 (version) + 4 (manifest length).
const TEXT_WRAPPER_HEADER: usize = 13;

/// The deterministic UTF-8 byte length of a PADDED A.8 wrapper for a manifest
/// of `manifest_len` bytes (mirrors `c2pa_text::worst_case_wrapper_byte_length`,
/// the padding target the engine's text embed always uses):
/// `3 (U+FEFF) + (13 + manifest_len) * 4 + 6`.
fn padded_wrapper_byte_length(manifest_len: usize) -> usize {
    3 + (TEXT_WRAPPER_HEADER + manifest_len) * 4 + 6
}

/// Length-bounded C2PA A.8 text-wrapper measurement.
///
/// Returns the byte span `(start, length)` of the first valid wrapper in
/// `text`, measured from the wrapper's own four-byte length field — never by
/// consume-all-VS scanning — so a foreign selector run adjacent to the wrapper
/// is never absorbed into the measured span:
///
/// 1. after `U+FEFF`, decode exactly `13 + manifest_len` payload selectors
///    (header validated: magic, version, length);
/// 2. then consume PADDING selectors only — byte values `0x00`/`0xFF`, the
///    deterministic padded-wrapper alphabet — and only while the total span
///    stays within [`padded_wrapper_byte_length`] for that manifest length.
///
/// An unpadded wrapper measures as header + manifest exactly; the engine's
/// padded wrapper measures as its exact padded length, leaving any adjacent
/// foreign run outside the span.
fn locate_text_wrapper(text: &str) -> Option<(usize, usize)> {
    const MAGIC: &[u8; 8] = b"C2PATXT\0";
    const VERSION: u8 = 1;
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find('\u{feff}') {
        let start = search_from + rel;
        let mut pos = start + 3; // U+FEFF is 3 UTF-8 bytes
        let mut payload: Vec<u8> = Vec::with_capacity(TEXT_WRAPPER_HEADER);
        let mut manifest_len: Option<usize> = None;
        let mut chars = text[pos..].chars();
        // Phase 1+2: header, then exactly `manifest_len` manifest selectors.
        loop {
            match manifest_len {
                Some(len) if payload.len() == TEXT_WRAPPER_HEADER + len => break,
                _ => {}
            }
            let Some(b) = chars.next().and_then(text_standard::vs_to_byte) else {
                // Selector run ends before the declared payload: not a valid
                // wrapper at this U+FEFF; keep searching.
                manifest_len = None;
                break;
            };
            pos += text_standard::byte_to_vs(b).len_utf8();
            payload.push(b);
            if payload.len() == TEXT_WRAPPER_HEADER {
                if &payload[0..8] != MAGIC || payload[8] != VERSION {
                    manifest_len = None;
                    break;
                }
                manifest_len =
                    Some(
                        u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]])
                            as usize,
                    );
            }
        }
        if let Some(len) = manifest_len {
            // Phase 3: padding selectors (0x00/0xFF), bounded by the
            // deterministic padded-wrapper length. A foreign selector run
            // beyond that bound is NOT part of the wrapper.
            let bound = start + padded_wrapper_byte_length(len);
            for c in text[pos..].chars() {
                match text_standard::vs_to_byte(c) {
                    Some(b) if (b == 0x00 || b == 0xFF) && pos + c.len_utf8() <= bound => {
                        pos += c.len_utf8();
                    }
                    _ => break,
                }
            }
            return Some((start, pos - start));
        }
        search_from = start + 3;
    }
    None
}

/// Public character-offset view of the C2PA A.8 text-wrapper locator.
///
/// Returns the half-open `[start, end)` scalar span of the first valid wrapper,
/// or `None` when the text carries none.
pub fn text_wrapper_char_span(text: &str) -> Option<(usize, usize)> {
    let (start_b, len_b) = locate_text_wrapper(text)?;
    let start_c = text[..start_b].chars().count();
    let span_c = text[start_b..start_b + len_b].chars().count();
    Some((start_c, start_c + span_c))
}

/// Reconstruct the original signed text asset when a signed snippet has been
/// embedded inside a larger document (e.g. pasted into a full web page).
///
/// When the manifest carries a `com.encypher.region` assertion recording the
/// signed region's byte length L, locate the A.8 variation-selector wrapper in
/// `data` and lift the bytes `[wrapper_start - L, wrapper_end]`: the L content
/// bytes the wrapper was appended to, plus the wrapper itself. That slice is a
/// byte-for-byte copy of the original standalone signed asset, so the stored
/// `c2pa.hash.data` exclusion (the wrapper span at offset L) and hash apply to
/// it unchanged.
///
/// Returns `None` when no region assertion is present, the asset is not text /
/// carries no wrapper, or the offsets are inconsistent (a tampered length, or a
/// wrapper closer to the start than L), so the caller falls through to a normal
/// mismatch.
fn lift_signed_region(manifest: &ParsedManifest, data: &[u8]) -> Option<Vec<u8>> {
    let (_, region_cbor) = manifest
        .assertions
        .iter()
        .find(|(l, _)| l == "com.encypher.region")?;
    let length = match decode(region_cbor).ok()?.get("length") {
        Some(Value::Integer(n)) if *n >= 0 => *n as usize,
        _ => return None,
    };
    // Locate the text variation-selector wrapper within the (possibly larger)
    // asset with the LENGTH-BOUNDED scanner. Non-text bytes or a wrapper-less
    // asset yield no span, so no lift is attempted.
    let text = std::str::from_utf8(data).ok()?;
    let (wrapper_start, wrapper_len) = locate_text_wrapper(text)?;
    let region_start = wrapper_start.checked_sub(length)?;
    let wrapper_end = wrapper_start.checked_add(wrapper_len)?;
    if wrapper_end > data.len() {
        return None;
    }
    Some(data[region_start..wrapper_end].to_vec())
}
/// Verify a `c2pa.hash.multi-asset` (multipart) hard binding.
///
/// Each `parts[]` entry has a `location {byteOffset, length}`, a `hashAssertion`
/// hashed-URI to a per-part hash assertion (`c2pa.hash.data.part*`), and an
/// `optional` flag. The declared parts must tile the asset contiguously from
/// offset 0 with no gaps or overlaps; a break is a structural defect
/// (`malformed`). For every part that is fully present, its byte range is hashed
/// (honoring that part assertion's own exclusions) and compared to the stored
/// per-part hash; a difference is a `mismatch`. A required part that is absent,
/// or any part that is only partially present (truncated), is a `missingPart`;
/// an optional part that is cleanly and entirely absent is acceptable. Trailing
/// bytes beyond the last declared part are uncovered data (`malformed`).
///
/// On full success the binding emits NO code here: when this path runs the
/// whole-file `c2pa.hash.data` has already failed to match, and the reference
/// verifier reports the surviving multipart binding as `multiAssetHash.match`
/// only for the post-removal case — which is exactly the `!any_failure` branch.
fn verify_multi_asset(
    manifest: &ParsedManifest,
    ma_cbor: &[u8],
    data: &[u8],
    label: &str,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.hash.multi-asset");
    let Ok(ma) = decode(ma_cbor) else {
        results.push_failure(
            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
            url,
            "multi-asset CBOR invalid".into(),
        );
        return;
    };
    let Some(Value::Array(parts)) = ma.get("parts") else {
        results.push_failure(
            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
            url,
            "multi-asset has no parts array".into(),
        );
        return;
    };
    if parts.is_empty() {
        results.push_failure(
            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
            url,
            "multi-asset parts array is empty".into(),
        );
        return;
    }
    // A part's declared layout plus its (eagerly resolved) expected hash.
    struct Part {
        off: usize,
        len: usize,
        optional: bool,
        plabel: String,
        alg: String,
        expected: Option<Vec<u8>>,
        exclusions: Vec<(usize, usize)>,
    }
    let mut collected: Vec<Part> = Vec::with_capacity(parts.len());
    for part in parts {
        let optional = matches!(part.get("optional"), Some(Value::Bool(true)));
        let location = part.get("location");
        let byte_offset = location
            .and_then(|l| l.get("byteOffset"))
            .and_then(int_usize);
        let length = location.and_then(|l| l.get("length")).and_then(int_usize);
        let part_url = part
            .get("hashAssertion")
            .and_then(|h| h.get("url"))
            .and_then(Value::as_text);
        let (Some(off), Some(len), Some(purl)) = (byte_offset, length, part_url) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                "multi-asset part missing location/hashAssertion".into(),
            );
            return;
        };
        let plabel = purl
            .rsplit("c2pa.assertions/")
            .next()
            .unwrap_or(purl)
            .to_string();
        // The referenced part-hash assertion supplies the expected hash + alg +
        // exclusions.
        let Some((_, part_cbor)) = manifest.assertions.iter().find(|(l, _)| *l == plabel) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MISSING_PART,
                url,
                format!("part hash assertion '{plabel}' not found"),
            );
            return;
        };
        let Ok(part_hash) = decode(part_cbor) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part '{plabel}' CBOR invalid"),
            );
            return;
        };
        let expected = part_hash
            .get("hash")
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec);
        let alg = part_hash
            .get("alg")
            .and_then(Value::as_text)
            .unwrap_or("sha256")
            .to_string();
        let exclusions = parse_exclusions(part_hash.get("exclusions"));
        collected.push(Part {
            off,
            len,
            optional,
            plabel,
            alg,
            expected,
            exclusions,
        });
    }
    // Structural contiguity: the declared parts must tile the asset from offset
    // 0 with no gaps and no overlaps. A break is a malformed structure (e.g. a
    // 1-byte gap inserted between parts), independent of any byte content.
    collected.sort_by_key(|p| p.off);
    let mut expected_off = 0usize;
    for p in &collected {
        if p.off != expected_off {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("multi-asset parts not contiguous: part '{}' starts at {} (expected {expected_off})", p.plabel, p.off),
            );
            return;
        }
        let Some(end) = p.off.checked_add(p.len) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                "multi-asset part length overflow".into(),
            );
            return;
        };
        expected_off = end;
    }
    let declared_end = expected_off;
    // Content + coverage pass over the contiguous layout.
    let mut any_failure = false;
    for p in &collected {
        let end = p.off + p.len; // no overflow: validated above
        if p.off >= data.len() {
            // Part lies entirely beyond the asset: cleanly absent.
            if !p.optional {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MISSING_PART,
                    url.clone(),
                    format!("required part '{}' is absent", p.plabel),
                );
                any_failure = true;
            }
            continue;
        }
        if end > data.len() {
            // Part is only partially present (truncated): its full-length hash
            // can never be satisfied, whether the part is optional or required.
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MISSING_PART,
                url.clone(),
                format!(
                    "part '{}' is truncated: range [{},{end}) exceeds asset length {}",
                    p.plabel,
                    p.off,
                    data.len()
                ),
            );
            any_failure = true;
            continue;
        }
        // Fully present: hash the slice (the part assertion's exclusions are
        // absolute asset offsets, so rebase them into the part window).
        let slice = &data[p.off..end];
        let local_excl: Vec<(usize, usize)> = p
            .exclusions
            .iter()
            .filter_map(|&(s, l)| {
                let s2 = s.checked_sub(p.off)?;
                if s2 < slice.len() {
                    Some((s2, l.min(slice.len() - s2)))
                } else {
                    None
                }
            })
            .collect();
        let actual = hash_with_exclusions(&p.alg, slice, &local_excl);
        match (actual, &p.expected) {
            (Some(a), Some(e)) if &a == e => {}
            _ => {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MISMATCH,
                    url.clone(),
                    format!("part '{}' hash mismatch", p.plabel),
                );
                any_failure = true;
            }
        }
    }
    // Coverage: the declared parts must account for the whole asset. Bytes
    // beyond the last declared part are uncovered (e.g. data appended past the
    // end of the file) => malformed.
    if declared_end < data.len() {
        results.push_failure(
            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
            url.clone(),
            format!(
                "asset has {} uncovered trailing bytes beyond declared parts",
                data.len() - declared_end
            ),
        );
        any_failure = true;
    }
    if !any_failure {
        results.push_success(
            ASSERTION_MULTI_ASSET_HASH_MATCH,
            url,
            "all required multi-asset parts valid".into(),
        );
    }
}
/// Extract a BMFF hash assertion's `exclusions[].xpath` box paths in order.
///
/// The per-entry `data`/`offset` qualifier on the `/uuid` exclusion (the C2PA
/// manifest box match) is honored inside [`c2pa_formats::bmff_hash`], which
/// excludes only the C2PA manifest `uuid` box.
fn bmff_exclusion_xpaths(hash_data: &Value) -> Vec<String> {
    let mut xpaths = Vec::new();
    if let Some(Value::Array(items)) = hash_data.get("exclusions") {
        for item in items {
            if let Some(xp) = item.get("xpath").and_then(Value::as_text) {
                xpaths.push(xp.to_string());
            }
        }
    }
    xpaths
}

/// Parse the `exclusions` array into sorted `(start, length)` ranges.
fn parse_exclusions(value: Option<&Value>) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    if let Some(Value::Array(items)) = value {
        for item in items {
            let start = item.get("start").and_then(int_usize);
            let length = item.get("length").and_then(int_usize);
            if let (Some(start), Some(length)) = (start, length) {
                ranges.push((start, length));
            }
        }
    }
    ranges.sort_by_key(|(s, _)| *s);
    ranges
}

/// Interpret a CBOR integer as a `usize`, rejecting negatives.
fn int_usize(value: &Value) -> Option<usize> {
    match value {
        Value::Integer(n) if *n >= 0 => usize::try_from(*n).ok(),
        _ => None,
    }
}

/// Hash `data` skipping the given byte ranges, per the C2PA data-hash binding.
fn hash_with_exclusions(alg: &str, data: &[u8], exclusions: &[(usize, usize)]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    let mut pos = 0usize;
    for &(start, length) in exclusions {
        let start = start.min(data.len());
        if pos < start {
            hasher.update(&data[pos..start]);
        }
        pos = start.saturating_add(length).min(data.len()).max(pos);
    }
    if pos < data.len() {
        hasher.update(&data[pos..]);
    }
    Some(hasher.finalize())
}

/// Compute the digest of `data` under the named algorithm.
fn hash_bytes(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    hasher.update(data);
    Some(hasher.finalize())
}

/// Compute one digest over a sequence of discontiguous byte slices.
fn hash_parts(alg: &str, parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    for part in parts {
        hasher.update(part);
    }
    Some(hasher.finalize())
}

/// A dynamically-dispatched SHA-2 hasher selected by algorithm name.
enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(alg: &str) -> Option<Self> {
        match alg {
            "sha256" => Some(Hasher::Sha256(Sha256::new())),
            "sha384" => Some(Hasher::Sha384(Sha384::new())),
            "sha512" => Some(Hasher::Sha512(Sha512::new())),
            _ => None,
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(bytes),
            Hasher::Sha384(h) => h.update(bytes),
            Hasher::Sha512(h) => h.update(bytes),
        }
    }
    fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// State + report assembly
// ---------------------------------------------------------------------------

/// Codes that are non-invalidating *caveats* in the generous (regular/core-spec)
/// posture: cert-time and trust/revocation signals that do not break manifest
/// *construction* integrity. Subtracted from the integrity-failure set in the
/// generous [`compute_state`]. `signingCredential.untrusted` is included here
/// (it never invalidated, in either posture) but is surfaced via the trust axis,
/// not the report's `caveats[]` (see [`is_surfaced_caveat`]).
const REGULAR_INTEGRITY_CAVEATS: &[&str] = &[
    SIGNING_CREDENTIAL_UNTRUSTED,
    CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
    SIGNING_CREDENTIAL_OCSP_SKIPPED,
    SIGNING_CREDENTIAL_OCSP_REVOKED,
    TIME_STAMP_UNTRUSTED,
    TIME_STAMP_OUTSIDE_VALIDITY,
    TIME_STAMP_MISSING,
    // Conformance-mode policy observations: never emitted in the generous posture,
    // and non-invalidating for the construction/integrity axis (they are spec-version
    // policy signals, not integrity failures). Including them here keeps
    // provenance_verdict.integrity a true integrity axis in conformance mode too;
    // strict validation_state is unaffected (is_integrity_invalidating's strict
    // branch does not consult this set).
    CONFORMANCE_OUT_OF_SCOPE,
    CONFORMANCE_SPEC_VERSION_NONCONFORMANT,
];

/// True for the GENEROUS posture: regular operating mode AND the core-spec
/// compliance bar. Every other profile (conformance mode, or the conformance-
/// program bar) stays strict/unchanged — this is the single mode-gating boundary.
fn is_generous(profile: EngineProfile) -> bool {
    profile.mode == OperatingMode::Regular && profile.compliance == ComplianceLevel::CoreSpec
}

/// Identity-assertion-scoped failure test: `cawg.*` codes report the outcome of
/// validating a CAWG identity (or ICA credential) assertion, a consumer role the
/// CAWG Identity 1.2 specification layers ON TOP of the C2PA Manifest Consumer
/// (§3.1.7/§3.1.9; §9.4.6 gates identity interpretation on manifest validity,
/// never the reverse). They therefore NEVER break C2PA manifest integrity in
/// either posture: a tampered identity assertion still sinks the manifest via
/// the C2PA-level `assertion.hashedURI.mismatch`, while an unverifiable or
/// untrusted identity credential leaves the manifest verdict intact and is
/// reported on the assertion itself. Matches the reference implementation,
/// which tracks CAWG outcomes in a separate status section.
fn is_identity_assertion_scoped(code: &str) -> bool {
    code.starts_with("cawg.")
}

/// Construction-integrity failure test (posture-independent): a failure code
/// breaks construction integrity unless it is one of the surfaced, non-
/// invalidating caveats ([`REGULAR_INTEGRITY_CAVEATS`]) or an identity-
/// assertion-scoped `cawg.*` code. Single source of truth behind the generous
/// `validation_state`, the `provenance_verdict.integrity` axis, and the
/// `validated_under` clearing, so those cannot drift apart.
fn is_construction_integrity_invalidating(code: &str) -> bool {
    !REGULAR_INTEGRITY_CAVEATS.contains(&code) && !is_identity_assertion_scoped(code)
}

/// True when failure `code` invalidates manifest *integrity* under `profile`.
/// Unknown/new failure codes default to invalidating in both postures.
fn is_integrity_invalidating(code: &str, profile: EngineProfile) -> bool {
    if is_generous(profile) {
        is_construction_integrity_invalidating(code)
    } else {
        // Strict: every failure invalidates except the always-non-invalidating
        // untrusted-signer signal (byte-for-byte the prior rule) and the
        // identity-assertion-scoped CAWG codes.
        code != SIGNING_CREDENTIAL_UNTRUSTED && !is_identity_assertion_scoped(code)
    }
}

/// The surfaced caveat set for `provenance_verdict.caveats[]`: the generous
/// caveat codes EXCEPT `signingCredential.untrusted`, which the trust axis
/// carries instead of duplicating here.
fn is_surfaced_caveat(code: &str) -> bool {
    code != SIGNING_CREDENTIAL_UNTRUSTED && REGULAR_INTEGRITY_CAVEATS.contains(&code)
}

/// Compute the legacy [`ValidationState`] from the accumulated results under the
/// active `profile`.
///
/// Strict posture: `signingCredential.untrusted` is the only failure that does
/// not invalidate (it merely prevents `Trusted`). Generous posture: the full
/// caveat set ([`REGULAR_INTEGRITY_CAVEATS`]) is non-invalidating, so an
/// expired/untrusted-but-structurally-intact manifest is `Valid`, not `Invalid`.
fn compute_state(results: &ValidationResults, profile: EngineProfile) -> ValidationState {
    let integrity_failure = results
        .failure
        .iter()
        .any(|s| is_integrity_invalidating(&s.code, profile));
    if integrity_failure {
        ValidationState::Invalid
    } else if results.has_success(SIGNING_CREDENTIAL_TRUSTED) {
        ValidationState::Trusted
    } else {
        ValidationState::Valid
    }
}

/// Build the additive two-axis `provenance_verdict` object, reported in BOTH
/// postures (the legacy `validation_state` retains the posture-specific verdict).
/// `present` is a fact about the asset — does it carry a manifest at all —
/// independent of posture.
///
/// Precedence (per the verdict spec):
/// - integrity-Invalid beats everything; integrity is construction-only and is
///   never gated on cert-time or trust. Absent provenance is integrity `invalid`.
/// - `trust=trusted` only when integrity is valid AND a trusted credential was
///   established AND it was not revoked. `ocsp.revoked` forces `untrusted`.
/// - `trust=unknown` only when there is no provenance; otherwise a present
///   credential that is not positively trusted is `untrusted` (default-deny).
fn provenance_verdict_json(results: &ValidationResults, present: bool) -> Json {
    let integrity_invalid = !present
        || results
            .failure
            .iter()
            .any(|s| is_construction_integrity_invalidating(&s.code));
    let credential_trusted = results.has_success(SIGNING_CREDENTIAL_TRUSTED)
        && !results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED);
    let trust = if !present {
        "unknown"
    } else if !integrity_invalid && credential_trusted {
        "trusted"
    } else {
        "untrusted"
    };
    let mut caveats: Vec<&str> = Vec::new();
    for bucket in [&results.failure, &results.informational] {
        for s in bucket {
            if is_surfaced_caveat(&s.code) && !caveats.contains(&s.code.as_str()) {
                caveats.push(s.code.as_str());
            }
        }
    }
    json!({
        "present": present,
        "integrity": if integrity_invalid { "invalid" } else { "valid" },
        "trust": trust,
        "caveats": caveats,
    })
}

/// Apply the conformance-program SHOULD→SHALL upgrades.
///
/// The C2PA core technical specification makes certain checks recommendations
/// (SHOULDs); the conformance program turns them into requirements (SHALLs).
/// Under [`ComplianceLevel::ConformanceProgram`] this reclassifies those checks
/// from informational/absent to hard failures. Under
/// [`ComplianceLevel::CoreSpec`] it is a no-op, so core-spec validation is
/// strictly more permissive — the two levels are directly comparable on the same
/// manifest.
///
/// Currently upgraded (the program SHALLs our verifier observes):
/// - **Revocation information**: a skipped OCSP check
///   (`signingCredential.ocsp.skipped`, informational under core) becomes a
///   failure — the program requires usable revocation information.
/// - **Trusted timestamp**: absence of `timeStamp.trusted` adds a
///   `timeStamp.missing` failure — the program requires a trusted timestamp.
///
/// Only applied once the manifest is otherwise well-formed (the caller invokes
/// this on the full-evaluation path, not on early structural-failure exits).
fn apply_compliance_upgrades(
    results: &mut ValidationResults,
    compliance: ComplianceLevel,
    sig_url: &str,
) {
    if compliance != ComplianceLevel::ConformanceProgram {
        return;
    }
    // OCSP skipped (informational) -> failure under the program.
    if results.has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED) {
        results.push_failure(
            SIGNING_CREDENTIAL_OCSP_SKIPPED,
            sig_url.to_string(),
            "conformance program requires usable revocation information (SHALL)".into(),
        );
    }
    // No trusted timestamp -> failure under the program.
    if !results.has_success(TIME_STAMP_TRUSTED) {
        results.push_failure(
            TIME_STAMP_MISSING,
            sig_url.to_string(),
            "conformance program requires a trusted timestamp (SHALL)".into(),
        );
    }
}

/// Assemble the final [`VerifyOutput`] including the reader-report JSON.
#[allow(clippy::too_many_arguments)] // internal report assembler; a params struct adds noise
fn finish(
    label: String,
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
    results: ValidationResults,
    verdict: Option<VersionVerdict>,
    profile: EngineProfile,
) -> VerifyOutput {
    let state = compute_state(&results, profile);
    // Clear `validated_under` only when manifest *integrity* is broken (a
    // cryptographically broken manifest verified under no spec revision; the
    // structural ladder is kept for diagnostics). Policy-bar failures —
    // untrusted signer, conformance-program SHALL upgrades, target-version
    // nonconformance — do not change what revision the manifest validated
    // under, so they leave the verdict intact.
    let integrity_broken = if is_generous(profile) {
        // Generous: construction integrity uses the same predicate as the
        // two-axis verdict. Cert-time, trust, OCSP, timestamp, and
        // conformance-policy caveats are NOT construction-integrity failures,
        // so they must not clear `validated_under`.
        results
            .failure
            .iter()
            .any(|s| is_construction_integrity_invalidating(&s.code))
    } else {
        // Strict / conformance: byte-for-byte the prior POLICY_CODES rule.
        const POLICY_CODES: [&str; 4] = [
            SIGNING_CREDENTIAL_UNTRUSTED,
            SIGNING_CREDENTIAL_OCSP_SKIPPED,
            TIME_STAMP_MISSING,
            CONFORMANCE_SPEC_VERSION_NONCONFORMANT,
        ];
        results
            .failure
            .iter()
            .any(|s| !POLICY_CODES.contains(&s.code.as_str()))
    };
    let mut verdict = verdict;
    if integrity_broken {
        if let Some(v) = verdict.as_mut() {
            v.validated_under = None;
        }
    }
    let mut report_json = build_report(&label, manifest, claim, chain, cose, &results, state);
    if let Some(obj) = report_json.as_object_mut() {
        // A manifest reached `finish`, so provenance is present.
        obj.insert(
            "provenance_verdict".to_string(),
            provenance_verdict_json(&results, true),
        );
    }
    if let Some(v) = &verdict {
        if let Some(obj) = report_json.as_object_mut() {
            obj.insert("version_verdict".to_string(), v.to_json());
        }
    }
    VerifyOutput {
        validation_state: state,
        results,
        report_json,
        crjson: None,
        version_verdict: verdict,
    }
}

/// Build the graceful no-manifest output.
///
/// `present` is whether the asset carries *any* C2PA structure: `false` for an
/// asset with no manifest extracted at all, `true` for a manifest store that
/// parsed but contained no manifests. In the generous posture an asset with no
/// provenance (`present == false`) is [`ValidationState::None`] with an empty
/// status set; every other case (and every strict-posture case) stays
/// `Invalid` + `claim.missing`.
fn no_manifest_output(explanation: &str, profile: EngineProfile, present: bool) -> VerifyOutput {
    let mut results = ValidationResults::default();
    let state = if is_generous(profile) && !present {
        ValidationState::None
    } else {
        results.push_failure(CLAIM_MISSING, String::new(), explanation.into());
        ValidationState::Invalid
    };
    let report_json = json!({
        "active_manifest": Json::Null,
        "manifests": Json::Object(Map::new()),
        "validation_status": status_array(&results.failure),
        "validation_results": validation_results_json(&results),
        "validation_state": state.as_str(),
        "provenance_verdict": provenance_verdict_json(&results, present),
    });
    VerifyOutput {
        validation_state: state,
        results,
        report_json,
        crjson: None,
        version_verdict: None,
    }
}

/// Serialize a slice of status codes for the reader report.
fn status_array(codes: &[StatusCode]) -> Json {
    Json::Array(
        codes
            .iter()
            .map(|status| {
                let mut value = json!({
                    "code": status.code,
                    "explanation": status.explanation,
                    "url": status.url,
                });
                if let (Some(object), Some(details)) =
                    (value.as_object_mut(), status.details.as_ref())
                {
                    object.insert("details".into(), details.clone());
                }
                value
            })
            .collect(),
    )
}

/// Build the `validation_results.activeManifest` object.
fn validation_results_json(results: &ValidationResults) -> Json {
    json!({
        "activeManifest": {
            "success": status_array(&results.success),
            "informational": status_array(&results.informational),
            "failure": status_array(&results.failure),
        }
    })
}

/// Build one reader-report manifest entry (the per-label value in the
/// `manifests` map) from a parsed manifest and its decoded claim.
fn manifest_entry_json(
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
) -> Json {
    let mut assertions = Vec::with_capacity(manifest.assertions.len());
    for (alabel, cbor) in &manifest.assertions {
        let data = decode(cbor)
            .map(|v| report::cbor_to_json(&v))
            .unwrap_or_else(|_| json!({}));
        assertions.push(json!({ "label": alabel, "data": data }));
    }

    let claim_generator_info = claim
        .and_then(|c| c.get("claim_generator_info"))
        .map(report::cbor_to_json)
        .unwrap_or_else(|| Json::Array(Vec::new()));
    let title = claim
        .and_then(|c| c.get("dc:title"))
        .and_then(Value::as_text)
        .unwrap_or("")
        .to_string();
    let instance_id = claim
        .and_then(|c| c.get("instanceID"))
        .and_then(Value::as_text)
        .unwrap_or("")
        .to_string();

    let mut sig_info = Map::new();
    if let (Some(leaf), Some(cose)) = (chain.first(), cose) {
        let info = cert::signature_info(leaf, cose);
        if let Some(alg) = info.alg {
            sig_info.insert("alg".into(), Json::String(alg));
        }
        if let Some(cn) = info.common_name {
            sig_info.insert("common_name".into(), Json::String(cn));
        }
        if let Some(issuer) = info.issuer {
            sig_info.insert("issuer".into(), Json::String(issuer));
        }
        if let Some(serial) = info.cert_serial_number {
            sig_info.insert("cert_serial_number".into(), Json::String(serial));
        }
    }

    json!({
        "claim_generator_info": claim_generator_info,
        "title": title,
        "instance_id": instance_id,
        "assertions": assertions,
        "signature_info": Json::Object(sig_info),
        "claim_version": 2,
    })
}

/// Append every non-active manifest in the store (ingredient parents) to the
/// report's `manifests` map, mirroring the c2pa-python Reader shape: the full
/// store is listed keyed by label with `active_manifest` as the pointer.
/// Parent manifests are decoded structurally only — `validation_results`,
/// `validation_status`, and `validation_state` remain scoped to the active
/// manifest, exactly like the Reader (parent validation is recorded by the
/// signer in the ingredient assertion's `validationResults`, not recomputed).
fn append_store_manifests(report: &mut Json, store: &ParsedStore<'_>, active_label: &str) {
    let Some(manifests) = report
        .as_object_mut()
        .and_then(|o| o.get_mut("manifests"))
        .and_then(Json::as_object_mut)
    else {
        return;
    };
    for manifest in &store.manifests {
        if manifest.label == active_label || manifests.contains_key(&manifest.label) {
            continue;
        }
        let claim = manifest.claim_cbor.and_then(|c| decode(c).ok());
        let chain = manifest
            .signature_cose
            .and_then(|cose| extract_x5chain(cose).ok())
            .unwrap_or_default();
        manifests.insert(
            manifest.label.clone(),
            manifest_entry_json(manifest, claim.as_ref(), &chain, manifest.signature_cose),
        );
    }
}

/// Build the full reader-report JSON for an active manifest.
fn build_report(
    label: &str,
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
    results: &ValidationResults,
    state: ValidationState,
) -> Json {
    let mut manifests = Map::new();
    manifests.insert(
        label.to_string(),
        manifest_entry_json(manifest, claim, chain, cose),
    );

    json!({
        "active_manifest": label,
        "manifests": Json::Object(manifests),
        "validation_status": status_array(&results.failure),
        "validation_results": validation_results_json(results),
        "validation_state": state.as_str(),
    })
}

#[cfg(test)]
mod tests {
    //! Unit tests for the multipart (`c2pa.hash.multi-asset`) contiguity /
    //! coverage / part-presence logic and the tampered-assertion suppression of
    //! `dataHash.match`. These build synthetic CBOR assertions so the rules are
    //! exercised independently of the on-disk corpus.
    use super::*;
    use c2pa_cbor::{encode, Profile};
    use sha2::{Digest, Sha256};

    fn vmap(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect(),
        )
    }

    fn enc(v: &Value) -> Vec<u8> {
        encode(v, Profile::LegacyPipelineBDefinite).expect("encode")
    }

    fn sha(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    /// CAWG identity/ICA failure codes are assertion-scoped per the CAWG 1.2
    /// consumer layering: they never break C2PA manifest integrity in either
    /// posture, while unknown and C2PA failure codes keep invalidating.
    #[test]
    fn cawg_failure_codes_are_assertion_scoped_not_integrity_invalidating() {
        for code in [
            "cawg.ica.did_unavailable",
            "cawg.ica.signature_mismatch",
            "cawg.identity.cbor.invalid",
        ] {
            assert!(!is_construction_integrity_invalidating(code), "{code}");
            assert!(
                !is_integrity_invalidating(code, EngineProfile::CONFORMANCE_V2_2),
                "{code} (strict)"
            );
        }
        assert!(is_construction_integrity_invalidating(
            ASSERTION_HASHED_URI_MISMATCH
        ));
        assert!(is_construction_integrity_invalidating("some.future.code"));

        let mut results = ValidationResults::default();
        results.push_failure(
            "cawg.ica.did_unavailable",
            String::new(),
            "unresolvable".into(),
        );
        assert_eq!(
            compute_state(&results, EngineProfile::CONFORMANCE_V2_2),
            ValidationState::Valid
        );
    }

    /// Build a `c2pa.hash.multi-asset` value from `(byteOffset, length, part
    /// label, optional)` tuples.
    fn multi_asset(parts: &[(usize, usize, &str, bool)]) -> Value {
        let arr = parts
            .iter()
            .map(|&(off, len, plabel, optional)| {
                vmap(vec![
                    (
                        "location",
                        vmap(vec![
                            ("byteOffset", Value::Integer(off as i128)),
                            ("length", Value::Integer(len as i128)),
                        ]),
                    ),
                    (
                        "hashAssertion",
                        vmap(vec![(
                            "url",
                            Value::Text(format!("self#jumbf=c2pa.assertions/{plabel}")),
                        )]),
                    ),
                    ("optional", Value::Bool(optional)),
                ])
            })
            .collect();
        vmap(vec![("parts", Value::Array(arr))])
    }

    fn part_assertion(hash: &[u8]) -> Value {
        vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(hash.to_vec())),
        ])
    }

    /// Run [`verify_multi_asset`] over `data` with the given multi-asset value
    /// and named part-hash assertions, returning the accumulated results.
    fn run_multi(data: &[u8], ma: &Value, part_assertions: &[(&str, Value)]) -> ValidationResults {
        let ma_cbor = enc(ma);
        let owned: Vec<(String, Vec<u8>)> = part_assertions
            .iter()
            .map(|(l, v)| (l.to_string(), enc(v)))
            .collect();
        let assertions: Vec<(String, &[u8])> = owned
            .iter()
            .map(|(l, b)| (l.clone(), b.as_slice()))
            .collect();
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let mut results = ValidationResults::default();
        verify_multi_asset(&manifest, &ma_cbor, data, "urn:test", &mut results);
        results
    }

    // A 30-byte asset partitioned into three contiguous 10-byte parts.
    fn fixture_data() -> Vec<u8> {
        (0u8..30).collect()
    }

    fn part_for(data: &[u8], off: usize, len: usize) -> Value {
        part_assertion(&sha(&data[off..off + len]))
    }

    #[test]
    fn intact_full_coverage_emits_match() {
        let data = fixture_data();
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", true),
            (20, 10, "p2", true),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 10, 10)),
            ("p2", part_for(&data, 20, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(r.failure.is_empty(), "unexpected failures: {:?}", r.failure);
    }

    #[test]
    fn gap_between_parts_is_malformed() {
        let data = fixture_data();
        // part p1 starts at 11, leaving a 1-byte gap after p0 [0,10).
        let ma = multi_asset(&[(0, 10, "p0", false), (11, 10, "p1", false)]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 11, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn overlapping_parts_are_malformed() {
        let data = fixture_data();
        // p1 starts at 8, overlapping p0 [0,10).
        let ma = multi_asset(&[(0, 10, "p0", false), (8, 10, "p1", false)]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 8, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn non_zero_start_is_malformed() {
        let data = fixture_data();
        let ma = multi_asset(&[(2, 10, "p0", false)]);
        let parts = [("p0", part_for(&data, 2, 10))];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
    }

    #[test]
    fn extra_trailing_data_is_malformed() {
        let mut data = fixture_data();
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 bytes beyond declared parts
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", false),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 10, 10)),
            ("p2", part_for(&data, 20, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn required_part_absent_is_missing_part() {
        let data: Vec<u8> = (0u8..20).collect(); // covers only p0 and p1
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", false),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 10, 10)),
            ("p2", part_assertion(&sha(&[0u8; 10]))),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISSING_PART));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn optional_part_cleanly_absent_emits_match() {
        let data: Vec<u8> = (0u8..20).collect(); // p2 [20,30) cleanly removed
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", true),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 10, 10)),
            ("p2", part_assertion(&sha(&[0u8; 10]))),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(r.failure.is_empty(), "unexpected failures: {:?}", r.failure);
    }

    #[test]
    fn optional_part_truncated_is_missing_part() {
        let data: Vec<u8> = (0u8..25).collect(); // p2 [20,30) only half present
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", true),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_for(&data, 10, 10)),
            ("p2", part_assertion(&sha(&[0u8; 10]))),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISSING_PART));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn part_content_mismatch_is_mismatch() {
        let data = fixture_data();
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", false),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", part_assertion(&sha(b"wrong content"))), // bad hash
            ("p2", part_for(&data, 20, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISMATCH));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn missing_referenced_part_assertion_is_missing_part() {
        let data = fixture_data();
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "absent", false),
            (20, 10, "p2", false),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p2", part_for(&data, 20, 10)),
        ];
        let r = run_multi(&data, &ma, &parts);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISSING_PART));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn empty_parts_array_is_malformed() {
        let data = fixture_data();
        let ma = multi_asset(&[]);
        let r = run_multi(&data, &ma, &[]);
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!r.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    /// Helper: run [`verify_data_hash`] over `data` against a whole-file
    /// `c2pa.hash.data` assertion whose hash equals `sha(data)`, with `results`
    /// optionally pre-seeded with a hashed-URI failure.
    fn run_data_hash(data: &[u8], preseed_tamper: bool) -> ValidationResults {
        let dh = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(data))),
        ]);
        let owned = enc(&dh);
        let assertions: Vec<(String, &[u8])> = vec![("c2pa.hash.data".into(), owned.as_slice())];
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let mut results = ValidationResults::default();
        if preseed_tamper {
            results.push_failure(
                ASSERTION_HASHED_URI_MISMATCH,
                "self#jumbf=/c2pa/urn:test/c2pa.assertions/c2pa.actions.v2".into(),
                "tampered assertion".into(),
            );
        }
        verify_data_hash(
            &Value::Null,
            &manifest,
            data,
            AssetFormat::Jpeg,
            &[],
            "urn:test",
            &mut results,
        );
        results
    }

    #[test]
    fn data_hash_matches_when_intact() {
        let data = b"the quick brown fox";
        let r = run_data_hash(data, false);
        assert!(r.has_success(ASSERTION_DATA_HASH_MATCH));
    }

    #[test]
    fn data_hash_match_suppressed_when_assertion_tampered() {
        // The asset bytes still hash correctly, but a referenced assertion was
        // tampered (hashedURI.mismatch). dataHash.match MUST NOT be emitted.
        let data = b"the quick brown fox";
        let r = run_data_hash(data, true);
        assert!(!r.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(r.has_failure(ASSERTION_HASHED_URI_MISMATCH));
    }
    // ---- length-bounded C2PA A.8 wrapper measurement ----

    fn padded_text_with_wrapper(carrier: &str) -> String {
        let manifest: Vec<u8> = (0u8..64)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let embedded = c2pa_formats::embed_manifest(
            AssetFormat::TextUnstructured,
            carrier.as_bytes(),
            &manifest,
        )
        .expect("embed");
        String::from_utf8(embedded).expect("utf8")
    }

    #[test]
    fn locate_text_wrapper_measures_padded_engine_wrapper_exactly() {
        let text = padded_text_with_wrapper("hello world");
        let (start, len) = locate_text_wrapper(&text).expect("wrapper found");
        assert_eq!(start, "hello world".len());
        assert_eq!(
            start + len,
            text.len(),
            "the padded wrapper spans to the end of the standalone text"
        );
    }

    #[test]
    fn locate_text_wrapper_never_absorbs_adjacent_foreign_run() {
        // Exercise foreign selector runs adjacent to the wrapper. Arbitrary
        // selectors and padding-look-alike selectors must remain outside the
        // length-derived wrapper bound.
        let text = padded_text_with_wrapper("hello world");
        let baseline = locate_text_wrapper(&text).expect("wrapper found");
        for run_bytes in [[0x01u8, 0x82, 0x33, 0xC4], [0x00u8, 0xFF, 0x00, 0xFF]] {
            let run: String = run_bytes
                .iter()
                .map(|&b| text_standard::byte_to_vs(b))
                .collect();
            let doc = format!("{text}{run} une suite.");
            assert_eq!(
                locate_text_wrapper(&doc).expect("wrapper still found"),
                baseline,
                "adjacent foreign run {run_bytes:02x?} must not shift the measured span"
            );
        }
        // Prefix adjacency: a foreign run immediately BEFORE the wrapper's
        // U+FEFF shifts the start but never leaks into the measured length.
        let run: String = [0x11u8, 0x22, 0x33, 0x44]
            .iter()
            .map(|&b| text_standard::byte_to_vs(b))
            .collect();
        let carrier_len = "hello world".len();
        let doc = format!("{}{}{}", &text[..carrier_len], run, &text[carrier_len..]);
        let (start, len) = locate_text_wrapper(&doc).expect("wrapper found");
        assert_eq!(start, carrier_len + run.len());
        assert_eq!(len, baseline.1, "prefix run must not change the length");
    }

    #[test]
    fn locate_text_wrapper_absent_or_truncated_is_none() {
        assert!(locate_text_wrapper("plain text, no wrapper").is_none());
        assert!(locate_text_wrapper("bom \u{feff} but no selectors").is_none());
        // Truncation: the declared manifest length is not satisfiable, so the
        // candidate is rejected (no partial wrapper measurement).
        let text = padded_text_with_wrapper("txt");
        let (start, len) = locate_text_wrapper(&text).expect("wrapper found");
        let mut cut_at = start + len / 2;
        while !text.is_char_boundary(cut_at) {
            cut_at -= 1;
        }
        assert!(locate_text_wrapper(&text[..cut_at]).is_none());
    }
}
