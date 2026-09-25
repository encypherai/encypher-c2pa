// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA manifest verification pipeline.
//!
//! Given asset bytes, a MIME type, optional trust configuration, and an optional
//! validation time, [`verify`] reproduces the reference verifier semantics and
//! the C2PA status-code model:
//!
//! 1. Extract the JUMBF manifest store for the asset's format (via
//!    [`c2pa_formats`]).
//! 2. Parse the store ([`crate::c2pa_core::jumbf::parse_manifest_store`]); the active
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

mod assertion_semantics;
mod cache;
mod cawg;
mod cawg_metadata;
mod cawg_training_mining;
mod exclusions;
pub(crate) use cawg::{
    CAWG_ICA_DID_UNAVAILABLE, CAWG_IDENTITY_ASSERTION_DUPLICATE, CAWG_IDENTITY_ASSERTION_MISMATCH,
    CAWG_IDENTITY_CBOR_INVALID, CAWG_IDENTITY_CREDENTIAL_REVOKED,
    CAWG_IDENTITY_HARD_BINDING_INCORRECT, CAWG_IDENTITY_HARD_BINDING_MISSING,
    CAWG_IDENTITY_NETWORK_TRAFFIC_BLOCKED, CAWG_IDENTITY_PAD_INVALID,
    CAWG_IDENTITY_SIG_TYPE_UNKNOWN, CAWG_IDENTITY_TRUSTED, CAWG_IDENTITY_WELL_FORMED,
    CAWG_LEGACY_PROFILE, CAWG_X509_ALGORITHM_UNSUPPORTED, CAWG_X509_CREDENTIAL_TRUSTED,
    CAWG_X509_CREDENTIAL_UNTRUSTED, CAWG_X509_OCSP_NOT_REVOKED, CAWG_X509_OCSP_SKIPPED,
    CAWG_X509_SIGNATURE_INSIDE_VALIDITY, CAWG_X509_SIGNATURE_MISMATCH,
    CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY, CAWG_X509_SIGNATURE_VALIDATED,
    CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY, CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY,
    CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID, CAWG_X509_TIME_STAMP_MALFORMED,
    CAWG_X509_TIME_STAMP_MISMATCH, CAWG_X509_TIME_STAMP_OUTSIDE_VALIDITY,
    CAWG_X509_TIME_STAMP_TRUSTED, CAWG_X509_TIME_STAMP_UNTRUSTED, CAWG_X509_TIME_STAMP_VALIDATED,
};
mod cawg_ica;
pub(crate) use cawg_ica::{
    CAWG_ICA_CREDENTIAL_VALID, CAWG_ICA_DID_UNSUPPORTED_METHOD, CAWG_ICA_INVALID_ALG,
    CAWG_ICA_INVALID_CONTENT_TYPE, CAWG_ICA_INVALID_COSE_SIGN1, CAWG_ICA_INVALID_DID_DOCUMENT,
    CAWG_ICA_INVALID_ISSUER, CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL, CAWG_ICA_SIGNATURE_MISMATCH,
    CAWG_ICA_SIGNER_PAYLOAD_MISMATCH, CAWG_ICA_TIME_STAMP_INVALID, CAWG_ICA_TIME_STAMP_VALIDATED,
    CAWG_ICA_VALID_FROM_INVALID, CAWG_ICA_VALID_FROM_MISSING, CAWG_ICA_VALID_UNTIL_INVALID,
};
mod cert;
mod crjson;
mod ingredient_graph;
pub(crate) mod live_video;
mod network_needs;
pub(crate) use network_needs::{NetworkNeed, OcspPurpose};
mod observe;
mod pdf_history;
mod program;
pub(crate) use program::{apply_compliance_upgrades, PROGRAM_FAILURE_CODES};
pub(crate) use program::{CONFORMANCE_OUT_OF_SCOPE, CONFORMANCE_SPEC_VERSION_NONCONFORMANT};
mod redaction;
mod refs;
mod report;
mod revocation;
#[cfg(test)]
mod signature_conformance_tests;
pub(crate) mod stream;
mod timestamp_assertion;
mod update_manifest;
pub(crate) mod versions;
pub(crate) use crjson::CrjsonContext;
pub(crate) use versions::{ClaimGeneration, VersionEvaluation, VersionVerdict};

pub(crate) use cache::{CachedResult, VerifyCache};
pub(crate) use observe::{global as global_metrics, Metrics, MetricsSnapshot};

use crate::c2pa_cbor::{decode, DecodeError, Value};
use crate::c2pa_core::jumbf::{
    expand_store, manifest_superboxes_from_store, parse_manifest_store, superbox_content,
    AssertionContentType, ExpandedStore, JumbfError, ManifestKind, ParsedManifest, ParsedStore,
};
pub(crate) use crate::c2pa_core::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
use crate::c2pa_crypto::{extract_x5chain, verify_claim, visit_ocsp_staples, CryptoError};
use crate::c2pa_formats::{text_standard, AssetFormat};
use crate::c2pa_trust::{validate_chain, OnlineOcspVerdict, TrustList, MAX_OCSP_RESPONSE_BYTES};
use serde::Serialize;
use serde_json::{json, Map, Value as Json};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use time::OffsetDateTime;
use unicode_normalization::UnicodeNormalization;

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
/// `c2pa.hash.data` exclusion structure is invalid.
pub const ASSERTION_DATA_HASH_MALFORMED: &str = "assertion.dataHash.malformed";
/// Informational: a C2PA 2.4 data-hash binding excludes bytes beyond its
/// manifest carrier.
pub const ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT: &str =
    "assertion.dataHash.additionalExclusionsPresent";
/// Informational: a BMFF binding excludes non-required boxes.
pub const ASSERTION_BMFF_HASH_ADDITIONAL_EXCLUSIONS_PRESENT: &str =
    "assertion.bmffHash.additionalExclusionsPresent";
/// Success: a `c2pa.hash.bmff.v2` or `c2pa.hash.bmff.v3` box-based hard binding matched the asset.
pub const ASSERTION_BMFF_HASH_MATCH: &str = "assertion.bmffHash.match";
/// Failure: a `c2pa.hash.bmff.v2` or `c2pa.hash.bmff.v3` box-based hard binding did not match.
pub const ASSERTION_BMFF_HASH_MISMATCH: &str = "assertion.bmffHash.mismatch";
/// Failure: a BMFF hash merkle structure (or a fragment's auxiliary
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
/// Informational: a general box hash uses additional byte exclusions.
pub const ASSERTION_BOXES_HASH_ADDITIONAL_EXCLUSIONS_PRESENT: &str =
    "assertion.boxesHash.additionalExclusionsPresent";
/// Informational: default posture accepted the historical c2pa-rs JPEG layout
/// in which `SOS` overlaps separately hashed two-byte restart markers.
pub const ASSERTION_BOXES_HASH_OVERLAPPING_RESTART_SEGMENTS: &str =
    "com.encypher.assertion.boxesHash.overlappingRestartSegments";
/// Failure extension: the sole hard binding is a general box hash over a
/// container for which C2PA 2.4 defines no box segmentation, so the binding
/// could not be evaluated. No registered code says "unevaluable binding", and
/// a manifest whose content binding was never checked must not read as valid,
/// so the verifier fails closed under this extension code.
pub const ASSERTION_BOXES_HASH_UNEVALUATED: &str = "com.encypher.assertion.boxesHash.unevaluated";
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
/// Failure: a required multi-asset part cannot be located.
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
/// A verified OCSP response says the signing certificate is not revoked.
pub const SIGNING_CREDENTIAL_OCSP_NOT_REVOKED: &str = "signingCredential.ocsp.notRevoked";
/// A verified OCSP response says the signing certificate is revoked.
pub const SIGNING_CREDENTIAL_OCSP_REVOKED: &str = "signingCredential.ocsp.revoked";
/// No usable OCSP evidence and no online check; revocation check skipped.
pub const SIGNING_CREDENTIAL_OCSP_SKIPPED: &str = "signingCredential.ocsp.skipped";
/// An online OCSP check was attempted but no usable response came back.
pub const SIGNING_CREDENTIAL_OCSP_INACCESSIBLE: &str = "signingCredential.ocsp.inaccessible";
/// An OCSP response reported `unknown` for the signing certificate.
pub const SIGNING_CREDENTIAL_OCSP_UNKNOWN: &str = "signingCredential.ocsp.unknown";
/// RFC 3161 timestamp token present and message digest matched.
pub const TIME_STAMP_VALIDATED: &str = "timeStamp.validated";
/// RFC 3161 timestamp present but the TSA certificate is untrusted.
pub const TIME_STAMP_UNTRUSTED: &str = "timeStamp.untrusted";
/// RFC 3161 timestamp present and the TSA certificate chains to the TSA trust list.
pub const TIME_STAMP_TRUSTED: &str = "timeStamp.trusted";
/// RFC 3161 timestamp genTime fell outside the TSA certificate's validity window.
pub const TIME_STAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";
/// A timestamp header is present but does not contain exactly one usable token,
/// or a token is structurally malformed.
pub const TIME_STAMP_MALFORMED: &str = "timeStamp.malformed";
/// No claim (or no manifest) found.
pub const CLAIM_MISSING: &str = "claim.missing";
/// Claim CBOR could not be decoded.
pub const CLAIM_CBOR_INVALID: &str = "claim.cbor.invalid";
/// More than one claim box present in a single manifest.
pub const CLAIM_MULTIPLE: &str = "claim.multiple";
/// Claim is missing a required v2 field (e.g. `instanceID`, `created_assertions`).
pub const CLAIM_MALFORMED: &str = "claim.malformed";
/// Advisory: a legacy claim-v1 claim supplies `claim_generator` but omits the
/// later `claim_generator_info` array.
pub const CLAIM_GENERATOR_INFO_MISSING: &str = "com.encypher.claim.generatorInfoMissing";
/// A manifest contains more than one ingredient with a `parentOf` relationship.
pub const MANIFEST_MULTIPLE_PARENTS: &str = "manifest.multipleParents";
/// A compressed manifest cannot be decoded or violates the compressed-manifest shape.
pub const MANIFEST_COMPRESSED_INVALID: &str = "manifest.compressed.invalid";
/// An update manifest contains a disallowed assertion or malformed parent link.
pub const MANIFEST_UPDATE_INVALID: &str = "manifest.update.invalid";
/// An update manifest does not contain exactly one `parentOf` ingredient.
pub const MANIFEST_UPDATE_WRONG_PARENTS: &str = "manifest.update.wrongParents";
/// A manifest store declared by its container cannot be accessed.
pub const MANIFEST_INACCESSIBLE: &str = "manifest.inaccessible";
/// Advisory: `claim_generator_info.specVersion` is not a SemVer value.
pub const CLAIM_SPEC_VERSION_NOT_SEMVER: &str = "com.encypher.claim.specVersionNotSemver";
/// Claim references no hard-binding (`c2pa.hash.*`) assertion.
pub const CLAIM_HARD_BINDINGS_MISSING: &str = "claim.hardBindings.missing";
/// More than one supported hard binding is declared by the claim.
pub const ASSERTION_MULTIPLE_HARD_BINDINGS: &str = "assertion.multipleHardBindings";
/// A referenced assertion uses an unsupported hash algorithm.
pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";
/// A deprecated hash algorithm was verified.
pub const ALGORITHM_DEPRECATED: &str = "algorithm.deprecated";
/// An assertion's CBOR could not be decoded.
pub const ASSERTION_CBOR_INVALID: &str = "assertion.cbor.invalid";
/// A JSON or JSON-LD assertion cannot be parsed as JSON.
pub const ASSERTION_JSON_INVALID: &str = "assertion.json.invalid";
/// JUMBF framing or structure is malformed before a more specific code applies.
pub const GENERAL_ERROR: &str = "general.error";
/// An assertion-store box is not declared by any claim assertion reference.
pub const ASSERTION_UNDECLARED: &str = "assertion.undeclared";
/// An actions assertion is absent or violates the required action ordering.
pub const ASSERTION_ACTION_MALFORMED: &str = "assertion.action.malformed";
/// An action's required ingredient cannot be resolved.
pub const ASSERTION_ACTION_INGREDIENT_MISMATCH: &str = "assertion.action.ingredientMismatch";
/// A redacted action does not resolve the named assertion.
pub const ASSERTION_ACTION_REDACTION_MISMATCH: &str = "assertion.action.redactionMismatch";
/// A watermark action has no accompanying `c2pa.soft-binding` assertion.
pub const ASSERTION_ACTION_SOFT_BINDING_MISSING: &str = "assertion.action.softBindingMissing";
/// An ingredient assertion violates its required structure.
pub const ASSERTION_INGREDIENT_MALFORMED: &str = "assertion.ingredient.malformed";
/// A cloud data assertion omits `label`, `size`, or `location`, or names an
/// assertion type the spec forbids referencing remotely.
pub const ASSERTION_CLOUD_DATA_MALFORMED: &str = "assertion.cloud-data.malformed";
/// A cloud data assertion references a hard-binding assertion.
pub const ASSERTION_CLOUD_DATA_HARD_BINDING: &str = "assertion.cloud-data.hardBinding";
/// An update manifest's cloud data assertion references an actions assertion.
pub const ASSERTION_CLOUD_DATA_ACTIONS: &str = "assertion.cloud-data.actions";
/// An external reference assertion omits `location`/`url`, carries half a hash
/// pair, or names an assertion type the spec forbids referencing externally.
pub const ASSERTION_EXTERNAL_REFERENCE_MALFORMED: &str = "assertion.external-reference.malformed";
/// An external reference assertion was declared in `created_assertions`.
pub const ASSERTION_EXTERNAL_REFERENCE_CREATED: &str = "assertion.external-reference.created";
/// A non-embedded (remote) assertion was accessible at validation time.
pub const ASSERTION_ACCESSIBLE: &str = "assertion.accessible";
/// A remotely stored assertion could not be read at validation time.
pub const ASSERTION_INACCESSIBLE: &str = "assertion.inaccessible";
/// Advisory: externally referenced non-assertion data was not retrieved.
pub const EXTERNAL_REFERENCE_NOT_RETRIEVED: &str =
    "com.encypher.assertion.externalReference.notRetrieved";
/// Advisory: a cloud data `location` repeats `size` or `dc:format`, which the
/// C2PA 2.4 cloud data assertion definition says shall not be present there.
pub const CLOUD_DATA_REDUNDANT_LOCATION_FIELD: &str =
    "com.encypher.assertion.cloudData.redundantLocationField";
/// An alternative-content representation is malformed.
pub const ASSERTION_ALTERNATIVE_CONTENT_MALFORMED: &str =
    "assertion.alternativeContentRepresentation.malformed";
/// An embedded alternative-content representation hash mismatched.
pub const ASSERTION_ALTERNATIVE_CONTENT_HASH_MISMATCH: &str =
    "assertion.alternativeContentRepresentation.hashMismatch";
/// An alternative-content representation validated.
pub const ASSERTION_ALTERNATIVE_CONTENT_MATCH: &str =
    "assertion.alternativeContentRepresentation.match";
/// A claim referenced an assertion that is not present in the manifest store.
pub const HASHED_URI_MISSING: &str = "hashedURI.missing";
/// The destination of a nested `hashed_uri` field does not hash to the value
/// the reference records (or the reference carries no `hash` at all). Distinct
/// from [`ASSERTION_HASHED_URI_MISMATCH`], which is the claim's own binding to
/// an assertion box.
pub const HASHED_URI_MISMATCH: &str = "hashedURI.mismatch";
/// A claim declared one of its own assertions redacted.
pub const ASSERTION_SELF_REDACTED: &str = "assertion.selfRedacted";
/// An assertion declared redacted is still present, with content, in the
/// manifest it was supposedly removed from.
pub const ASSERTION_NOT_REDACTED: &str = "assertion.notRedacted";
/// An actions assertion was redacted, which C2PA forbids.
pub const ASSERTION_ACTION_REDACTED: &str = "assertion.action.redacted";
/// A hard binding assertion was redacted, which C2PA forbids. Supersedes the
/// deprecated `assertion.dataHash.redacted`.
pub const ASSERTION_HARD_BINDING_REDACTED: &str = "assertion.hardBinding.redacted";
/// A claim assertion URI names a location outside its own manifest.
pub const ASSERTION_OUTSIDE_MANIFEST: &str = "assertion.outsideManifest";
/// A locally addressed assertion was absent.
pub const ASSERTION_MISSING: &str = "assertion.missing";
/// An ingredient references a manifest not present in the manifest store.
pub const INGREDIENT_MANIFEST_MISSING: &str = "ingredient.manifest.missing";
/// An ingredient's active-manifest hash matched the referenced manifest box.
pub const INGREDIENT_MANIFEST_VALIDATED: &str = "ingredient.manifest.validated";
/// An ingredient's active-manifest hash did not match the referenced manifest box.
pub const INGREDIENT_MANIFEST_MISMATCH: &str = "ingredient.manifest.mismatch";
/// An ingredient's claim-signature hash matched the referenced signature box.
pub const INGREDIENT_CLAIM_SIGNATURE_VALIDATED: &str = "ingredient.claimSignature.validated";
/// An ingredient references a claim-signature box that is not present.
pub const INGREDIENT_CLAIM_SIGNATURE_MISSING: &str = "ingredient.claimSignature.missing";
/// An ingredient's claim-signature hash did not match the referenced signature box.
pub const INGREDIENT_CLAIM_SIGNATURE_MISMATCH: &str = "ingredient.claimSignature.mismatch";
/// Informational: an ingredient assertion carries no manifest link, so the
/// ingredient's provenance is unknown.
pub const INGREDIENT_UNKNOWN_PROVENANCE: &str = "ingredient.unknownProvenance";
/// Informational extension: a legacy `c2pa_manifest` ingredient link matched
/// the C2PA 1.0 hash over the ingredient's claim bytes rather than the
/// manifest-box hash. Accepted in the default posture only.
pub const INGREDIENT_LEGACY_CLAIM_HASH: &str = "com.encypher.ingredient.legacyClaimHash";
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
    Format(#[from] crate::c2pa_formats::FormatError),
    /// The manifest store JUMBF structure could not be parsed.
    #[error("manifest store parse failed: {0}")]
    Jumbf(#[from] crate::c2pa_core::jumbf::JumbfError),
    /// The active manifest's hard-binding assertion is malformed or unsupported.
    #[error("hard binding invalid: {0}")]
    HardBinding(String),
    /// A declared fragmented stream could not be verified as presented: a file
    /// does not declare the encapsulation's brands, or the init segment does
    /// not carry the binding the requested method needs.
    #[error("stream verification failed: {0}")]
    Stream(String),
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
    /// `signingCredential.ocsp.skipped`).
    pub informational: Vec<StatusCode>,
    /// Codes for checks that failed.
    pub failure: Vec<StatusCode>,
    /// Requests that would settle a check this verification could not make
    /// offline, recorded wherever the corresponding status code is emitted.
    ///
    /// It travels with the status codes because it is produced at exactly the
    /// same points and by the same evidence, and threading a second sink
    /// through every emitter would let the two drift apart. It is moved out
    /// into [`VerifyOutput::network_needs`] when the output is assembled, and
    /// is never serialized as part of the status codes.
    #[serde(skip)]
    pub(crate) network_needs: Vec<NetworkNeed>,
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
    fn push_failure_with_details(
        &mut self,
        code: &str,
        url: String,
        explanation: String,
        details: Json,
    ) {
        self.failure.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: Some(details),
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

    fn push_informational_with_details(
        &mut self,
        code: &str,
        url: String,
        explanation: String,
        details: Json,
    ) {
        self.informational.push(StatusCode {
            code: code.into(),
            url,
            explanation,
            details: Some(details),
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
    pub profile: crate::c2pa_core::EngineProfile,
    /// Material a caller obtained over the network and is supplying as
    /// evidence. Empty by default: the kernel itself never fetches.
    pub evidence: OnlineEvidence<'a>,
    /// Refuse the CAWG field-order `signer_payload` encoding even under the
    /// generous posture. The conformance posture refuses it regardless.
    pub cawg_strict_encoding: bool,
}

/// Network-obtained material a caller supplies to a verification.
///
/// The kernel opens no sockets. Everything here was fetched by someone else -
/// the SDK's own consent-gated fetcher, or a caller with its own network
/// policy - and is verified here exactly as any other untrusted input is: an
/// OCSP response must still be signed by an authorized responder, and external
/// data must still hash to the value its assertion declares.
///
/// Keys come from the [`NetworkNeed`] values the previous offline pass
/// recorded, so a caller never has to derive them.
#[derive(Clone, Copy, Default)]
pub struct OnlineEvidence<'a> {
    /// OCSP responses, keyed by the lowercase hex SHA-256 of the subject
    /// certificate's DER, with the DER `OCSPResponse` as the value.
    pub ocsp_responses: Option<&'a std::collections::HashMap<String, Vec<u8>>>,
    /// Certificates whose responder was queried without a usable answer, by
    /// the same hex SHA-256 key. Each one registers the `ocsp.inaccessible`
    /// informational code instead of `ocsp.skipped`.
    pub ocsp_unreachable: Option<&'a [String]>,
    /// External assertion content, keyed by the URI the assertion declares.
    pub external_data: Option<&'a std::collections::HashMap<String, Vec<u8>>>,
}

impl OnlineEvidence<'_> {
    /// True when nothing was supplied, which is the offline default.
    fn is_empty(&self) -> bool {
        self.ocsp_responses.is_none_or(|map| map.is_empty())
            && self.ocsp_unreachable.is_none_or(|list| list.is_empty())
            && self.external_data.is_none_or(|map| map.is_empty())
    }

    /// The OCSP response supplied for `certificate_sha256_hex`, if any.
    fn ocsp_response(&self, certificate_sha256_hex: &str) -> Option<&[u8]> {
        self.ocsp_responses?
            .get(certificate_sha256_hex)
            .map(Vec::as_slice)
    }

    /// True when the responder for `certificate_sha256_hex` was tried and gave
    /// no usable answer.
    fn ocsp_is_unreachable(&self, certificate_sha256_hex: &str) -> bool {
        self.ocsp_unreachable
            .is_some_and(|list| list.iter().any(|entry| entry == certificate_sha256_hex))
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct CawgTrustInputs<'a> {
    trust: Option<&'a TrustList>,
    allowed_certs: Option<&'a TrustList>,
    document_signing_require_anchor: bool,
    /// Pinned offline DID-document store for ICA issuers, keyed by primary DID.
    did_documents: Option<&'a std::collections::HashMap<String, Json>>,
    ica_trusted_issuers: Option<&'a [String]>,
    ica_trust_anchors: Option<&'a [String]>,
    /// Offline decompressed bitstrings, standard-base64 encoded and keyed by
    /// the credentialStatus statusListCredential URI.
    ica_status_lists: Option<&'a std::collections::HashMap<String, String>>,
}
/// The store-wide facts one manifest's verification needs: its sibling
/// manifests and the per-manifest hashed-URI digests. Both are derived from the
/// same parsed store, so they travel together rather than as separate parameters.
struct ManifestDigests {
    expanded_sha256: Vec<u8>,
    stored: Option<[Vec<u8>; 3]>,
}

impl ManifestDigests {
    fn expanded(expanded_sha256: Vec<u8>) -> Self {
        Self {
            expanded_sha256,
            stored: None,
        }
    }

    fn matches(&self, algorithm_index: usize, expanded: &[u8], expected: &[u8]) -> bool {
        expanded == expected
            || self
                .stored
                .as_ref()
                .is_some_and(|digests| digests[algorithm_index].as_slice() == expected)
    }
}

#[derive(Clone, Copy)]
struct StoreContext<'a> {
    manifests: &'a [ParsedManifest<'a>],
    manifest_hashes: &'a std::collections::HashMap<String, ManifestDigests>,
}

fn manifest_hashes(
    store: &ExpandedStore<'_>,
    manifests: &[ParsedManifest<'_>],
) -> Result<std::collections::HashMap<String, ManifestDigests>, JumbfError> {
    let boxes = manifest_superboxes_from_store(store.bytes())?;
    let mut hashes = std::collections::HashMap::with_capacity(boxes.len().min(manifests.len()));
    for (index, (manifest_box, manifest)) in boxes.into_iter().zip(manifests).enumerate() {
        let expanded = superbox_content(manifest_box)?;
        let mut digests = ManifestDigests::expanded(Sha256::digest(expanded).to_vec());
        if let Some(stored) = store.stored_content(index) {
            digests.stored = Some([
                Sha256::digest(stored).to_vec(),
                Sha384::digest(stored).to_vec(),
                Sha512::digest(stored).to_vec(),
            ]);
        }
        hashes.insert(manifest.label.clone(), digests);
    }
    Ok(hashes)
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
    /// Requests that would settle a check this verification could not make
    /// offline. Always populated, whether or not fetching is enabled, so a
    /// caller can tell the user what turning it on would contact.
    pub(crate) network_needs: Vec<NetworkNeed>,
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
            ..CawgTrustInputs::default()
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
            ..CawgTrustInputs::default()
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
            ..CawgTrustInputs::default()
        },
    )
}

/// Full CAWG trust and offline-resolution option set used by the public facade.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_cawg_options(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        &[],
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            ica_trusted_issuers: cawg_ica_trusted_issuers,
            ica_trust_anchors: cawg_ica_trust_anchors,
            ica_status_lists: cawg_ica_status_lists,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_fragmented_with_cawg_options(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments(
        input,
        fragments,
        CawgTrustInputs {
            trust: cawg_trust,
            allowed_certs: cawg_allowed_certs,
            document_signing_require_anchor,
            did_documents: cawg_did_documents,
            ica_trusted_issuers: cawg_ica_trusted_issuers,
            ica_trust_anchors: cawg_ica_trust_anchors,
            ica_status_lists: cawg_ica_status_lists,
        },
    )
}
/// [`verify`] for FRAGMENTED BMFF assets (DASH/HLS): `input.data` is the
/// initialization segment carrying the manifest; `fragments` are the fragment
/// files (`.m4s`) in playback order. Each fragment's leaf hash is recomputed
/// per spec A.5.4.1.2 and climbed to the stored Merkle row using its auxiliary
/// C2PA `merkle` box. Duplicate identities and unexpected sequence
/// discontinuities are rejected. Not-yet-available future fragments remain
/// non-failures.
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
            ..CawgTrustInputs::default()
        },
    )
}
fn verify_with_fragments(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments_mode_and_expected_seeks(input, fragments, &[], cawg_inputs, true)
}

fn verify_with_fragments_and_expected_seeks(
    input: &VerifyInput,
    fragments: &[&[u8]],
    expected_seek_positions: &[usize],
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    stream::validate_expected_seek_positions(expected_seek_positions, fragments.len())?;
    verify_with_fragments_mode_and_expected_seeks(
        input,
        fragments,
        expected_seek_positions,
        cawg_inputs,
        true,
    )
}

fn verify_with_fragments_mode(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_inputs: CawgTrustInputs<'_>,
    include_pdf_history: bool,
) -> Result<VerifyOutput, ValidateError> {
    verify_with_fragments_mode_and_expected_seeks(
        input,
        fragments,
        &[],
        cawg_inputs,
        include_pdf_history,
    )
}

fn verify_with_fragments_mode_and_expected_seeks(
    input: &VerifyInput,
    fragments: &[&[u8]],
    expected_seek_positions: &[usize],
    cawg_inputs: CawgTrustInputs<'_>,
    include_pdf_history: bool,
) -> Result<VerifyOutput, ValidateError> {
    // scope. Unreadable MIME (maps to no format) is the only hard error.
    let format = AssetFormat::from_mime(input.mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(input.mime.to_string()))?;

    // Conformance-mode scope observation: recorded as informational, never a
    // hard failure, so strict internal validation captures it for evidence
    // while still verifying the asset fully.
    let out_of_scope =
        input.profile.mode == OperatingMode::Conformance && !input.profile.permits_mime(input.mime);
    let (pdf_sections, pdf_inventory_error) = if include_pdf_history && format == AssetFormat::Pdf {
        match crate::c2pa_formats::pdf_manifest_store_sections(input.data) {
            Ok(sections) => (sections, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        }
    } else {
        (Vec::new(), None)
    };

    if let Some(diagnostic) = crate::c2pa_formats::text_diagnostic(format, input.data) {
        let mut out = container_failure_output(
            diagnostic.code(),
            "text manifest carrier is malformed or cannot be resolved",
            input.profile,
        );
        if out_of_scope {
            note_out_of_scope(&mut out, input.mime, input.profile);
        }
        return Ok(out);
    }

    if input.profile.mode == OperatingMode::Conformance {
        match crate::c2pa_formats::carrier_placement_error(format, input.data) {
            Ok(Some(detail)) => {
                let mut out = container_failure_output(GENERAL_ERROR, detail, input.profile);
                if out_of_scope {
                    note_out_of_scope(&mut out, input.mime, input.profile);
                }
                return Ok(out);
            }
            Ok(None) => {}
            Err(error) => {
                let mut out =
                    container_failure_output(GENERAL_ERROR, &error.to_string(), input.profile);
                if out_of_scope {
                    note_out_of_scope(&mut out, input.mime, input.profile);
                }
                return Ok(out);
            }
        }
    }

    let store_bytes = match crate::c2pa_formats::extract_manifest(format, input.data) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            // C2PA 2.4 Validation, By Reference: with no embedded store, a
            // documented remote declaration is the next place to look. An
            // offline validator cannot look there, and the spec names the
            // outcome: "If a manifest was documented to exist in a remote
            // location, but is not present there, or the location is not
            // currently available (such as in an offline scenario), the
            // `manifest.inaccessible` error code shall be used to report the
            // situation." The URI travels in `details` so a caller can fetch
            // the store itself and re-verify it detached, and as a network
            // need so the SDK can offer to fetch it.
            if let Ok(Some(remote)) = crate::c2pa_formats::remote_manifest_uri(format, input.data) {
                let mut out = failure_only_output_with_details(
                    MANIFEST_INACCESSIBLE,
                    remote.uri.clone(),
                    "the asset declares a remote manifest; this verifier does not fetch".into(),
                    Some(json!({
                        "remote_manifest_uri": remote.uri,
                        "declared_in": remote.source,
                    })),
                    input.profile,
                );
                network_needs::push_unique(
                    &mut out.network_needs,
                    NetworkNeed::RemoteManifest { uri: remote.uri },
                );
                if out_of_scope {
                    note_out_of_scope(&mut out, input.mime, input.profile);
                }
                return Ok(out);
            }
            let mut out = no_manifest_output("no C2PA manifest found", input.profile, false);
            if out_of_scope {
                note_out_of_scope(&mut out, input.mime, input.profile);
            }
            pdf_history::attach(
                &mut out,
                input,
                cawg_inputs,
                &pdf_sections,
                pdf_inventory_error.as_deref(),
            )?;
            return Ok(out);
        }
        Err(error) if format == AssetFormat::Pdf => {
            let mut out = failure_only_output(
                MANIFEST_INACCESSIBLE,
                "self#jumbf".into(),
                error.to_string(),
                input.profile,
            );
            pdf_history::attach(
                &mut out,
                input,
                cawg_inputs,
                &pdf_sections,
                pdf_inventory_error.as_deref(),
            )?;
            return Ok(out);
        }
        Err(error) => return Err(error.into()),
    };

    let expanded = match expand_for_validation(&store_bytes, input.profile) {
        Ok(expanded) => expanded,
        Err(output) => {
            let mut out = *output;
            pdf_history::attach(
                &mut out,
                input,
                cawg_inputs,
                &pdf_sections,
                pdf_inventory_error.as_deref(),
            )?;
            return Ok(out);
        }
    };
    let store = match parse_manifest_store(expanded.bytes()) {
        Ok(store) => store,
        Err(error) => {
            if matches!(&error, JumbfError::UnsupportedManifestType(_)) {
                return Err(error.into());
            }
            let mut out = jumbf_failure_output(&error, &store_bytes, input.profile);
            pdf_history::attach(
                &mut out,
                input,
                cawg_inputs,
                &pdf_sections,
                pdf_inventory_error.as_deref(),
            )?;
            return Ok(out);
        }
    };
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, &store_bytes);
        if out_of_scope {
            note_out_of_scope(&mut out, input.mime, input.profile);
        }
        pdf_history::attach(
            &mut out,
            input,
            cawg_inputs,
            &pdf_sections,
            pdf_inventory_error.as_deref(),
        )?;
        return Ok(out);
    };

    let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
    // SHA-256 over each manifest JUMBF superbox, used to authenticate
    // ingredient links and compound child bindings.
    let manifest_hashes = manifest_hashes(&expanded, &store.manifests)?;
    let mut out = verify_manifest(
        manifest,
        StoreContext {
            manifests: &store.manifests,
            manifest_hashes: &manifest_hashes,
        },
        input,
        format,
        fragments,
        None,
        cawg_inputs,
        &mut report_decode_nodes,
    );
    // Reader-shape parity: list every manifest in the store (ingredient
    // parents included), with `active_manifest` as the pointer.
    append_store_manifests(
        &mut out.report_json,
        &store,
        &manifest.label,
        &mut report_decode_nodes,
    );
    stamp_manifest_store_hash(&mut out, &store_bytes);
    if out_of_scope {
        note_out_of_scope(&mut out, input.mime, input.profile);
    }
    // crJSON is emitted only in strict-debug mode. It carries the validation
    // results so the document can be evaluated directly by the C2PA
    // conformance-program rubrics.
    if input.profile.debug {
        let crjson = crjson::to_crjson(&store, &crjson_context(input, &out));
        out.crjson = Some(crjson);
    }
    stamp_profile(&mut out, input.profile);
    pdf_history::attach(
        &mut out,
        input,
        cawg_inputs,
        &pdf_sections,
        pdf_inventory_error.as_deref(),
    )?;
    // Fail closed on unbound fragments. Must run after the report exists and
    // after `stamp_profile`, because it restates every validity-derived field.
    stream::require_fragments_bound(&mut out, manifest, fragments, input.profile);
    stream::validate_fragment_sequence(
        &mut out,
        manifest,
        fragments,
        expected_seek_positions,
        input.profile,
    );
    Ok(out)
}

/// Bundle what the crJSON renderer needs from this verification: the report it
/// carries into `validationResults`, the instant the engine validated against,
/// and the profile naming the spec revision that validation ran under.
fn crjson_context<'a>(input: &VerifyInput<'_>, out: &'a VerifyOutput) -> CrjsonContext<'a> {
    CrjsonContext {
        report: &out.report_json,
        validation_time: input
            .validation_time
            .unwrap_or_else(OffsetDateTime::now_utc),
        profile: input.profile,
    }
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
fn note_out_of_scope(out: &mut VerifyOutput, mime: &str, profile: EngineProfile) {
    out.results.push_informational(
        CONFORMANCE_OUT_OF_SCOPE,
        String::new(),
        format!("format {mime} is outside the certified conformance scope"),
    );
    // Rebuild the validation_results block from the updated results so the
    // informational code appears in the report JSON too. `validation_results`
    // is a pure function of `results`, so this stays consistent with finish().
    if let Some(obj) = out.report_json.as_object_mut() {
        restate_validation_results(obj, &out.results);
        // The out-of-scope code is also a surfaced caveat, so recompute the
        // structured verdict too, preserving the existing `present` value.
        let present = obj
            .get("provenance_verdict")
            .and_then(|v| v.get("present"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        obj.insert(
            "provenance_verdict".to_string(),
            provenance_verdict_json(&out.results, present, profile),
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
/// [`verify_with_cawg_options`].
#[allow(clippy::too_many_arguments)]
pub fn verify_with_cawg_options_safe(
    input: &VerifyInput,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_cawg_options(
            input,
            cawg_trust,
            cawg_allowed_certs,
            document_signing_require_anchor,
            cawg_did_documents,
            cawg_ica_trusted_issuers,
            cawg_ica_trust_anchors,
            cawg_ica_status_lists,
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
/// Panic-containment wrapper for fragmented verification with the full CAWG
/// trust, policy, pinned DID-document, and encoding option set.
#[allow(clippy::too_many_arguments)]
pub fn verify_fragmented_with_cawg_options_safe(
    input: &VerifyInput,
    fragments: &[&[u8]],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_fragmented_with_cawg_options(
            input,
            fragments,
            cawg_trust,
            cawg_allowed_certs,
            document_signing_require_anchor,
            cawg_did_documents,
            cawg_ica_trusted_issuers,
            cawg_ica_trust_anchors,
            cawg_ica_status_lists,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Panic-containment wrapper for fragmented verification with explicit seek
/// boundaries and the full CAWG option set.
#[allow(clippy::too_many_arguments)]
pub fn verify_fragmented_with_cawg_options_and_expected_seeks_safe(
    input: &VerifyInput,
    fragments: &[&[u8]],
    expected_seek_positions: &[usize],
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_with_fragments_and_expected_seeks(
            input,
            fragments,
            expected_seek_positions,
            CawgTrustInputs {
                trust: cawg_trust,
                allowed_certs: cawg_allowed_certs,
                document_signing_require_anchor,
                did_documents: cawg_did_documents,
                ica_trusted_issuers: cawg_ica_trusted_issuers,
                ica_trust_anchors: cawg_ica_trust_anchors,
                ica_status_lists: cawg_ica_status_lists,
            },
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
    verify_detached_with_cawg_options(
        manifest_store,
        content,
        content_mime,
        input,
        CawgTrustInputs::default(),
    )
}

/// [`verify_detached`] with the caller's CAWG identity trust configuration.
///
/// A sidecar store carries the same `cawg.identity` assertions an embedded one
/// would, so it gets the same identity evaluation: verifying out-of-band must
/// not silently drop a validation axis.
pub(crate) fn verify_detached_with_cawg_options<'a>(
    manifest_store: &'a [u8],
    content: &'a [u8],
    content_mime: &'a str,
    input: &VerifyInput<'a>,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    let format = AssetFormat::from_mime(content_mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(content_mime.to_string()))?;
    if format == AssetFormat::C2paStore {
        // The content side cannot itself be a host-less manifest store.
        return Err(ValidateError::UnsupportedMime(content_mime.to_string()));
    }

    let out_of_scope = input.profile.mode == OperatingMode::Conformance
        && !input.profile.permits_mime(content_mime);

    let expanded = match expand_for_validation(manifest_store, input.profile) {
        Ok(expanded) => expanded,
        Err(output) => return Ok(*output),
    };
    let store = match parse_manifest_store(expanded.bytes()) {
        Ok(store) => store,
        Err(error) => {
            if matches!(&error, JumbfError::UnsupportedManifestType(_)) {
                return Err(error.into());
            }
            return Ok(jumbf_failure_output(&error, manifest_store, input.profile));
        }
    };
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, manifest_store);
        if out_of_scope {
            note_out_of_scope(&mut out, content_mime, input.profile);
        }
        return Ok(out);
    };

    let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
    let manifest_hashes = manifest_hashes(&expanded, &store.manifests)?;

    // Present the external content as the asset under verification, then run the
    // standard per-manifest pipeline (origin's exact-label hard-binding checks).
    let content_input = VerifyInput {
        data: content,
        mime: content_mime,
        ..*input
    };
    let mut out = verify_manifest(
        manifest,
        StoreContext {
            manifests: &store.manifests,
            manifest_hashes: &manifest_hashes,
        },
        &content_input,
        format,
        &[],
        None,
        cawg_inputs,
        &mut report_decode_nodes,
    );
    append_store_manifests(
        &mut out.report_json,
        &store,
        &manifest.label,
        &mut report_decode_nodes,
    );
    stamp_manifest_store_hash(&mut out, manifest_store);
    if out_of_scope {
        note_out_of_scope(&mut out, content_mime, input.profile);
    }
    if input.profile.debug {
        let crjson = crjson::to_crjson(&store, &crjson_context(input, &out));
        out.crjson = Some(crjson);
    }
    stamp_profile(&mut out, input.profile);
    Ok(out)
}

/// Panic-containment wrapper for detached verification with the full CAWG
/// trust, policy, pinned DID-document, and status-list option set
/// (see [`verify_safe`]).
#[allow(clippy::too_many_arguments)]
pub fn verify_detached_safe<'a>(
    manifest_store: &'a [u8],
    content: &'a [u8],
    content_mime: &'a str,
    input: &VerifyInput<'a>,
    cawg_trust: Option<&TrustList>,
    cawg_allowed_certs: Option<&TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<VerifyOutput, ValidateError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_detached_with_cawg_options(
            manifest_store,
            content,
            content_mime,
            input,
            CawgTrustInputs {
                trust: cawg_trust,
                allowed_certs: cawg_allowed_certs,
                document_signing_require_anchor,
                did_documents: cawg_did_documents,
                ica_trusted_issuers: cawg_ica_trusted_issuers,
                ica_trust_anchors: cawg_ica_trust_anchors,
                ica_status_lists: cawg_ica_status_lists,
            },
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Verify a detached manifest against a caller-computed hard-binding digest.
///
/// This validates the same claim structure, assertion hashed-URI bindings,
/// COSE signature, certificate chain, timestamp, and CAWG identity as
/// [`verify`]. Only the asset hashing step is replaced: the supplied digest is
/// compared to the active manifest's sole `c2pa.hash.data`,
/// `c2pa.hash.bmff.v2`, or `c2pa.hash.bmff.v3` assertion. The caller remains
/// responsible for computing the format-specific digest from locally parsed and authorized container geometry.
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

    let expanded = match expand_for_validation(manifest_store, input.profile) {
        Ok(expanded) => expanded,
        Err(output) => return Ok(*output),
    };
    let store = match parse_manifest_store(expanded.bytes()) {
        Ok(store) => store,
        Err(error) => {
            if matches!(&error, JumbfError::UnsupportedManifestType(_)) {
                return Err(error.into());
            }
            return Ok(jumbf_failure_output(&error, manifest_store, input.profile));
        }
    };
    let Some(manifest) = store.manifests.last() else {
        let mut out =
            no_manifest_output("manifest store contained no manifests", input.profile, true);
        stamp_manifest_store_hash(&mut out, manifest_store);
        return Ok(out);
    };
    let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
    let manifest_hashes = manifest_hashes(&expanded, &store.manifests)?;
    let digest_input = VerifyInput {
        data: &[],
        mime: content_mime,
        ..*input
    };
    let mut out = verify_manifest(
        manifest,
        StoreContext {
            manifests: &store.manifests,
            manifest_hashes: &manifest_hashes,
        },
        &digest_input,
        format,
        &[],
        Some(hard_binding_digest),
        CawgTrustInputs::default(),
        &mut report_decode_nodes,
    );
    append_store_manifests(
        &mut out.report_json,
        &store,
        &manifest.label,
        &mut report_decode_nodes,
    );
    stamp_manifest_store_hash(&mut out, manifest_store);
    if input.profile.debug {
        let crjson = crjson::to_crjson(&store, &crjson_context(input, &out));
        out.crjson = Some(crjson);
    }
    stamp_profile(&mut out, input.profile);
    Ok(out)
}

const MAX_EMBEDDED_OCSP_RESPONSES: usize = 32;
const MAX_EMBEDDED_OCSP_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_EMBEDDED_OCSP_COLLECTION_DEPTH: usize = 4;
const MAX_EMBEDDED_OCSP_COLLECTION_NODES: usize = 4096;
const MAX_OCSP_STATUS_ASSERTION_BYTES: usize = 1024 * 1024;
const MAX_EMBEDDED_OCSP_CHAIN_CERTIFICATES: usize = 20;
const MAX_CERTIFICATE_STATUS_ASSERTIONS: usize = 32;
const MAX_CERTIFICATE_STATUS_TOTAL_BYTES: usize = 1024 * 1024;

struct CertificateStatusPayloads<'a> {
    payloads: Vec<&'a [u8]>,
    rejected: bool,
}

fn is_certificate_status_label(label: &str) -> bool {
    label == "c2pa.certificate-status"
        || label
            .strip_prefix("c2pa.certificate-status__")
            .and_then(|instance| instance.parse::<usize>().ok())
            .is_some_and(|instance| instance > 0)
}

/// Visit each individually well-formed certificate-status reference declared
/// by one bounded claim. A malformed unrelated reference cannot hide valid
/// sibling evidence, while duplicate, cross-manifest, and undeclared status
/// assertions remain excluded.
fn visit_declared_certificate_status_payloads<'a>(
    manifest: &'a ParsedManifest<'a>,
    mut visit: impl FnMut(&'a [u8]),
) -> bool {
    let Some(claim_cbor) = manifest.claim_cbor else {
        return false;
    };
    let Ok(claim) = decode(claim_cbor) else {
        return false;
    };
    let generation = versions::claim_generation(manifest, &claim);
    let mut total = 0usize;
    for field in ref_fields(generation) {
        let Some(Value::Array(references)) = claim.get(field) else {
            continue;
        };
        let Some(next) = total.checked_add(references.len()) else {
            return false;
        };
        if next > MAX_CLAIM_ASSERTION_REFERENCES {
            return false;
        }
        total = next;
    }

    // Count every locally resolvable declaration by URL before checking its
    // other HashedUri fields. A malformed duplicate of a status label must not
    // make that declaration look unique.
    let mut declaration_counts = std::collections::HashMap::<&str, usize>::new();
    for field in ref_fields(generation) {
        let Some(Value::Array(references)) = claim.get(field) else {
            continue;
        };
        for reference in references {
            let Some(label) = reference
                .get("url")
                .and_then(Value::as_text)
                .and_then(|url| assertion_label_for_manifest(url, &manifest.label))
            else {
                continue;
            };
            *declaration_counts.entry(label).or_default() += 1;
        }
    }

    for field in ref_fields(generation) {
        let Some(Value::Array(references)) = claim.get(field) else {
            continue;
        };
        for reference in references {
            let (Some(url), Some(_hash), Some(algorithm)) = (
                reference.get("url").and_then(Value::as_text),
                reference.get("hash").and_then(Value::as_bytes),
                resolved_hash_algorithm(reference, &claim),
            ) else {
                continue;
            };
            if bmff_algorithm_index(algorithm).is_none() {
                continue;
            }
            let Some(label) = assertion_label_for_manifest(url, &manifest.label) else {
                continue;
            };
            if declaration_counts.get(label) != Some(&1) || !is_certificate_status_label(label) {
                continue;
            }
            let mut payloads = manifest
                .assertions
                .iter()
                .filter(|(assertion_label, _)| assertion_label == label)
                .map(|(_, payload)| *payload);
            if let (Some(payload), None) = (payloads.next(), payloads.next()) {
                visit(payload);
            }
        }
    }
    true
}

/// Build the bounded store-wide evidence view required by C2PA 2.4. The first
/// pass caps assertion count and raw bytes before the output vector is
/// allocated or any certificate-status payload is decoded. The second pass
/// decodes only candidate status assertions, never unrelated sibling payloads.
fn certificate_status_payloads<'a>(
    manifests: &'a [ParsedManifest<'a>],
) -> CertificateStatusPayloads<'a> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    let mut rejected = false;
    for manifest in manifests {
        visit_declared_certificate_status_payloads(manifest, |payload| {
            let Some(next_count) = count.checked_add(1) else {
                rejected = true;
                return;
            };
            let Some(next_bytes) = bytes.checked_add(payload.len()) else {
                rejected = true;
                return;
            };
            if next_count > MAX_CERTIFICATE_STATUS_ASSERTIONS
                || next_bytes > MAX_CERTIFICATE_STATUS_TOTAL_BYTES
                || payload.len() > MAX_OCSP_STATUS_ASSERTION_BYTES
            {
                rejected = true;
                return;
            }
            count = next_count;
            bytes = next_bytes;
        });
        if rejected {
            return CertificateStatusPayloads {
                payloads: Vec::new(),
                rejected: true,
            };
        }
    }

    let mut payloads = Vec::with_capacity(count);
    for manifest in manifests {
        visit_declared_certificate_status_payloads(manifest, |payload| {
            if decode(payload).is_ok() {
                payloads.push(payload);
            }
        });
    }
    CertificateStatusPayloads {
        payloads,
        rejected: false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EmbeddedOcspStatus {
    NotChecked,
    NotRevoked,
    LeafRevoked,
    CaRevoked,
    LeafAndCaRevoked,
    Skipped,
}

impl EmbeddedOcspStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NotRevoked => "not_revoked",
            Self::LeafRevoked => "leaf_revoked",
            Self::CaRevoked => "ca_revoked",
            Self::LeafAndCaRevoked => "leaf_and_ca_revoked",
            Self::Skipped => "skipped",
        }
    }

    fn blocks_trust(self) -> bool {
        matches!(
            self,
            Self::LeafRevoked | Self::CaRevoked | Self::LeafAndCaRevoked
        )
    }
}

#[derive(Default)]
struct OcspEvidenceBudget {
    responses: usize,
    total_bytes: usize,
    collection_nodes: usize,
    rejected: bool,
}

impl OcspEvidenceBudget {
    fn remaining_responses(&self) -> usize {
        MAX_EMBEDDED_OCSP_RESPONSES.saturating_sub(self.responses)
    }

    fn visit_collection_node(&mut self) -> bool {
        if self.collection_nodes >= MAX_EMBEDDED_OCSP_COLLECTION_NODES {
            self.rejected = true;
            return false;
        }
        self.collection_nodes += 1;
        true
    }

    fn accept_response(&mut self, response: &[u8]) -> bool {
        if self.responses >= MAX_EMBEDDED_OCSP_RESPONSES || response.len() > MAX_OCSP_RESPONSE_BYTES
        {
            self.rejected = true;
            return false;
        }
        let Some(total_bytes) = self.total_bytes.checked_add(response.len()) else {
            self.rejected = true;
            return false;
        };
        if total_bytes > MAX_EMBEDDED_OCSP_TOTAL_BYTES {
            self.rejected = true;
            return false;
        }
        self.responses += 1;
        self.total_bytes = total_bytes;
        true
    }
}

fn visit_ocsp_values(
    value: &Value,
    depth: usize,
    budget: &mut OcspEvidenceBudget,
    visit: &mut impl FnMut(&[u8]),
) {
    if budget.rejected {
        return;
    }
    if depth > MAX_EMBEDDED_OCSP_COLLECTION_DEPTH {
        budget.rejected = true;
        return;
    }
    if !budget.visit_collection_node() {
        return;
    }

    match value {
        Value::Map(entries) => {
            for (key, nested) in entries {
                if budget.rejected {
                    return;
                }
                if key.as_text() == Some("ocspVals") {
                    if !budget.visit_collection_node() {
                        return;
                    }
                    let Value::Array(values) = nested else {
                        continue;
                    };
                    if values.len() > budget.remaining_responses() {
                        budget.rejected = true;
                        return;
                    }
                    for value in values {
                        if !budget.visit_collection_node() {
                            return;
                        }
                        if let Some(response) = value.as_bytes() {
                            if budget.accept_response(response) {
                                visit(response);
                            }
                            if budget.rejected {
                                return;
                            }
                        }
                    }
                } else {
                    visit_ocsp_values(nested, depth + 1, budget, visit);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                visit_ocsp_values(nested, depth + 1, budget, visit);
                if budget.rejected {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn scan_embedded_ocsp_evidence(
    signature: &[u8],
    certificate_status_assertions: &[&[u8]],
    mut visit: impl FnMut(&[u8]),
) -> OcspEvidenceBudget {
    let mut budget = OcspEvidenceBudget::default();
    let signature_within_limit =
        visit_ocsp_staples(signature, budget.remaining_responses(), |response| {
            if budget.accept_response(response) {
                visit(response);
            }
        });
    if !signature_within_limit || budget.rejected {
        budget.rejected = true;
        return budget;
    }

    for bytes in certificate_status_assertions {
        if bytes.len() > MAX_OCSP_STATUS_ASSERTION_BYTES {
            budget.rejected = true;
            return budget;
        }
        if let Ok(assertion) = decode(bytes) {
            visit_ocsp_values(&assertion, 0, &mut budget, &mut visit);
        }
        if budget.rejected {
            return budget;
        }
    }
    budget
}

fn ocsp_chain_pairs<'a>(
    chain: &'a [Vec<u8>],
    trust: Option<&'a TrustList>,
) -> Option<Vec<(&'a [u8], &'a [u8])>> {
    if chain.len() > MAX_EMBEDDED_OCSP_CHAIN_CERTIFICATES {
        return None;
    }
    let Some(mut subject) = chain.first().map(Vec::as_slice) else {
        return Some(Vec::new());
    };
    let mut pairs = Vec::with_capacity(chain.len());
    for _ in 0..MAX_EMBEDDED_OCSP_CHAIN_CERTIFICATES {
        let candidates = chain
            .iter()
            .skip(1)
            .map(Vec::as_slice)
            .chain(trust.into_iter().flat_map(TrustList::certificates));
        let Some(issuer) = crate::c2pa_trust::resolve_issuer(subject, candidates) else {
            break;
        };
        if issuer == subject
            || pairs
                .iter()
                .any(|(prior_subject, _)| *prior_subject == issuer)
        {
            break;
        }
        pairs.push((subject, issuer));
        if trust.is_some_and(|trust| trust.contains_certificate(issuer)) {
            break;
        }
        subject = issuer;
    }
    Some(pairs)
}

/// The resolved embedded-OCSP outcome for a signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct EmbeddedOcspOutcome {
    pub status: EmbeddedOcspStatus,
    /// A verified revoked response was outranked by a qualifying good one
    /// (conformance posture only). Reported informationally, never silently.
    pub conflicting_revoked: bool,
}

impl EmbeddedOcspOutcome {
    fn plain(status: EmbeddedOcspStatus) -> Self {
        Self {
            status,
            conflicting_revoked: false,
        }
    }
}

/// Evaluate every stapled OCSP response against each certificate of the chain.
///
/// `any_good_wins` selects the conformance reading of VAL-STRU-0027 and
/// `details` for a revocation status settled by a response fetched online,
/// so a report can tell it apart from a stapled one.
pub(crate) fn online_ocsp_details() -> Json {
    serde_json::json!({ "source": "online_ocsp" })
}

/// VAL-CRYP-0034 (see [`revocation`]); the default posture stays fail-closed.
pub(super) fn evaluate_embedded_ocsp(
    signature: &[u8],
    certificate_status_assertions: &[&[u8]],
    chain: &[Vec<u8>],
    signed_at: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    trust: Option<&TrustList>,
    any_good_wins: bool,
) -> EmbeddedOcspOutcome {
    let preflight = scan_embedded_ocsp_evidence(signature, certificate_status_assertions, |_| {});
    if preflight.rejected {
        return EmbeddedOcspOutcome::plain(EmbeddedOcspStatus::Skipped);
    }
    if preflight.responses == 0 {
        return EmbeddedOcspOutcome::plain(EmbeddedOcspStatus::NotChecked);
    }
    let Some(pairs) = ocsp_chain_pairs(chain, trust) else {
        return EmbeddedOcspOutcome::plain(EmbeddedOcspStatus::Skipped);
    };
    let mut accumulated = vec![revocation::CertificateEvidence::default(); pairs.len()];
    let evidence =
        scan_embedded_ocsp_evidence(signature, certificate_status_assertions, |staple| {
            for (certificate, (subject, issuer)) in accumulated.iter_mut().zip(&pairs) {
                certificate.absorb(crate::c2pa_trust::evaluate_ocsp_verified(
                    staple,
                    issuer,
                    subject,
                    signed_at,
                    verification_time,
                ));
            }
        });
    if evidence.rejected {
        return EmbeddedOcspOutcome::plain(EmbeddedOcspStatus::Skipped);
    }

    let mut conflicting_revoked = false;
    let statuses: Vec<_> = accumulated
        .into_iter()
        .map(|certificate| {
            let (status, outranked) = certificate.resolve(any_good_wins);
            conflicting_revoked |= outranked;
            status
        })
        .collect();
    EmbeddedOcspOutcome {
        status: embedded_ocsp_status_from_certificate_statuses(&statuses),
        conflicting_revoked,
    }
}

fn embedded_ocsp_status_from_certificate_statuses(
    statuses: &[Option<crate::c2pa_trust::OcspStatus>],
) -> EmbeddedOcspStatus {
    let leaf_revoked = statuses.first().is_some_and(|status| {
        matches!(status, Some(crate::c2pa_trust::OcspStatus::Revoked { .. }))
    });
    let ca_revoked = statuses
        .iter()
        .skip(1)
        .any(|status| matches!(status, Some(crate::c2pa_trust::OcspStatus::Revoked { .. })));
    match (leaf_revoked, ca_revoked) {
        (true, true) => EmbeddedOcspStatus::LeafAndCaRevoked,
        (true, false) => EmbeddedOcspStatus::LeafRevoked,
        (false, true) => EmbeddedOcspStatus::CaRevoked,
        (false, false)
            if statuses
                .first()
                .is_some_and(|status| *status == Some(crate::c2pa_trust::OcspStatus::Good)) =>
        {
            EmbeddedOcspStatus::NotRevoked
        }
        (false, false) => EmbeddedOcspStatus::Skipped,
    }
}

/// One certificate an OCSP query could ask about, with the issuer whose key
/// authorizes the answer.
pub(super) struct OcspTarget<'a> {
    subject: &'a [u8],
    issuer: &'a [u8],
    /// Lowercase hex SHA-256 over `subject`, the evidence key a caller uses.
    certificate_sha256_hex: String,
    /// The `id-ad-ocsp` access location from the subject's AIA extension.
    responder_url: Option<String>,
}

/// The chain positions an OCSP query is possible for, leaf first.
///
/// Certificates with no AIA OCSP entry are kept: C2PA 2.4 treats them as not
/// revoked, and they still carry evidence keys a caller may supply.
pub(super) fn ocsp_targets<'a>(
    chain: &'a [Vec<u8>],
    trust: Option<&'a TrustList>,
) -> Vec<OcspTarget<'a>> {
    ocsp_chain_pairs(chain, trust)
        .unwrap_or_default()
        .into_iter()
        .map(|(subject, issuer)| OcspTarget {
            subject,
            issuer,
            certificate_sha256_hex: hex::encode(Sha256::digest(subject)),
            responder_url: crate::c2pa_trust::ocsp_responder_url(subject),
        })
        .collect()
}

/// Record the OCSP queries that would settle these certificates.
///
/// Only certificates whose issuer published a responder produce a need: C2PA
/// 2.4 says a credential whose issuer "did not provide a method to query its
/// revocation status" is treated as not revoked, so there is nothing to ask.
pub(super) fn record_ocsp_needs(
    targets: &[OcspTarget<'_>],
    purpose: &OcspPurpose,
    needs: &mut Vec<NetworkNeed>,
) {
    for target in targets {
        let Some(responder_url) = target.responder_url.as_ref() else {
            continue;
        };
        let Some(request_der) =
            crate::c2pa_trust::build_ocsp_request(target.issuer, target.subject)
        else {
            continue;
        };
        network_needs::push_unique(
            needs,
            NetworkNeed::Ocsp {
                purpose: purpose.clone(),
                responder_url: responder_url.clone(),
                request_der,
                certificate_sha256_hex: target.certificate_sha256_hex.clone(),
            },
        );
    }
}

/// What caller-supplied online OCSP evidence established for a chain.
#[derive(Default)]
pub(super) struct OnlineOcspOutcome {
    /// The leaf's verdict, when online evidence covered the leaf at all.
    leaf: Option<OnlineOcspVerdict>,
    /// A CA certificate in the chain was reported revoked.
    ca_revoked: bool,
}

impl OnlineOcspOutcome {
    /// True when nothing online covered any certificate in the chain.
    fn is_empty(&self) -> bool {
        self.leaf.is_none() && !self.ca_revoked
    }
}

/// Evaluate caller-supplied OCSP evidence for each certificate of a chain
/// under the C2PA 2.4 / CAWG 1.3 online rules.
///
/// `attested` is the time from a trusted time-stamp, or `None` when the
/// signature has no usable one.
pub(super) fn evaluate_online_ocsp(
    targets: &[OcspTarget<'_>],
    evidence: OnlineEvidence<'_>,
    attested: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
) -> OnlineOcspOutcome {
    let mut outcome = OnlineOcspOutcome::default();
    for (position, target) in targets.iter().enumerate() {
        let verdict = match evidence.ocsp_response(&target.certificate_sha256_hex) {
            Some(der) => crate::c2pa_trust::evaluate_ocsp_online(
                der,
                target.issuer,
                target.subject,
                attested,
                verification_time,
            ),
            None if evidence.ocsp_is_unreachable(&target.certificate_sha256_hex) => {
                OnlineOcspVerdict::Unusable
            }
            None => continue,
        };
        if position == 0 {
            outcome.leaf = Some(verdict);
        } else if verdict == OnlineOcspVerdict::Revoked {
            // C2PA 2.4: a CA revoked at the effective time rejects the claim
            // signature with `signingCredential.untrusted`.
            outcome.ca_revoked = true;
        }
    }
    outcome
}

/// Report the claim signer's revocation outcome from embedded and online
/// evidence, and record the queries that would settle what neither did.
///
/// Online evidence wins for a certificate it covers: it is the fresher answer
/// to the same question, and C2PA 2.4 offers the online check as the
/// "additional assurance" step after the stapled one.
fn record_ocsp_status(
    embedded: EmbeddedOcspOutcome,
    online: &OnlineOcspOutcome,
    targets: &[OcspTarget<'_>],
    sig_url: &str,
    results: &mut ValidationResults,
) {
    if embedded.conflicting_revoked {
        results.push_informational(
            revocation::OCSP_CONFLICTING_REVOKED_RESPONSE,
            sig_url.into(),
            "a verified revoked OCSP response was outranked by a qualifying good response \
             for the same certificate"
                .into(),
        );
    }

    let ca_revoked = online.ca_revoked
        || matches!(
            embedded.status,
            EmbeddedOcspStatus::CaRevoked | EmbeddedOcspStatus::LeafAndCaRevoked
        );
    match online.leaf {
        Some(OnlineOcspVerdict::NotRevoked) => results.push_success_with_details(
            SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
            sig_url.into(),
            "online OCSP response: signing certificate not revoked at signing".into(),
            online_ocsp_details(),
        ),
        Some(OnlineOcspVerdict::Revoked) => results.push_failure_with_details(
            SIGNING_CREDENTIAL_OCSP_REVOKED,
            sig_url.into(),
            "online OCSP response: signing certificate revoked".into(),
            online_ocsp_details(),
        ),
        Some(OnlineOcspVerdict::Unknown) => results.push_informational_with_details(
            SIGNING_CREDENTIAL_OCSP_UNKNOWN,
            sig_url.into(),
            "online OCSP response reports an unknown status for the signing certificate".into(),
            online_ocsp_details(),
        ),
        Some(OnlineOcspVerdict::Unusable) => results.push_informational_with_details(
            SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
            sig_url.into(),
            "the OCSP responder for the signing certificate returned no usable response".into(),
            online_ocsp_details(),
        ),
        None => match embedded.status {
            EmbeddedOcspStatus::NotRevoked => results.push_success(
                SIGNING_CREDENTIAL_OCSP_NOT_REVOKED,
                sig_url.into(),
                "embedded OCSP response: signing certificate not revoked at signing".into(),
            ),
            EmbeddedOcspStatus::LeafRevoked | EmbeddedOcspStatus::LeafAndCaRevoked => results
                .push_failure(
                    SIGNING_CREDENTIAL_OCSP_REVOKED,
                    sig_url.into(),
                    "embedded OCSP response: signing certificate revoked at signing".into(),
                ),
            EmbeddedOcspStatus::CaRevoked => {}
            EmbeddedOcspStatus::NotChecked | EmbeddedOcspStatus::Skipped => {
                results.push_informational(
                    SIGNING_CREDENTIAL_OCSP_SKIPPED,
                    sig_url.into(),
                    "no usable embedded OCSP response for the leaf, and no online check was \
                     performed; revocation check skipped"
                        .into(),
                );
                record_ocsp_needs(
                    targets,
                    &OcspPurpose::ClaimSigner,
                    &mut results.network_needs,
                );
            }
        },
    }
    if ca_revoked {
        results.push_failure(
            SIGNING_CREDENTIAL_UNTRUSTED,
            sig_url.into(),
            "verified OCSP response: CA certificate revoked".into(),
        );
    }
}

/// Run the per-manifest verification steps and assemble the output.
#[allow(clippy::too_many_arguments)] // one internal pass threads shared store/report budgets
fn verify_manifest<'a>(
    manifest: &'a ParsedManifest<'a>,
    store: StoreContext<'a>,
    input: &VerifyInput,
    format: AssetFormat,
    fragments: &[&[u8]],
    prehashed_digest: Option<&[u8]>,
    cawg_inputs: CawgTrustInputs<'_>,
    report_decode_nodes: &mut usize,
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
            None,
            &[],
            None,
            results,
            None,
            input.profile,
            report_decode_nodes,
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
                None,
                &[],
                None,
                results,
                None,
                input.profile,
                report_decode_nodes,
            );
        }
    };

    // Spec-version classification: claim generation (v1 vs v2) drives the
    // generation-aware structural checks below; the ladder verdict rides on
    // the output and is finalized in `finish` (cleared when Invalid).
    let generation = versions::claim_generation(manifest, &claim);
    let mut claim_refs = ClaimAssertionRefs::build(manifest, &claim, generation);
    let verdict = versions::evaluate(manifest, &claim, format);

    // Strict target-version control (internal conformance analysis): in
    // Conformance mode the manifest is additionally held to the profile's
    // target spec revision. Informational under the core-spec bar; a hard
    // failure under the conformance program. Regular mode stays silent — the
    // ladder verdict carries the classification without judgment.
    if input.profile.mode == OperatingMode::Conformance && claim_refs.undeclared_labels.is_empty() {
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
    let certificate_statuses = certificate_status_payloads(store.manifests);
    let mut structure_ok = !verify_claim_structure(
        manifest,
        store,
        &claim,
        generation,
        &claim_refs,
        format,
        &sig_url,
        input.profile,
        &mut results,
    );
    // Runs alongside the structural gate rather than inside it: the external
    // data checks are the only ones that consult caller-supplied network
    // evidence, which the structural gate has no business knowing about.
    verify_external_data_assertions(
        &claim_refs,
        generation,
        manifest.kind(),
        &manifest.label,
        input.profile,
        input.evidence,
        &mut results,
    );
    // C2PA 2.4 Validation, Validation of References: every schema-declared
    // `hashed_uri` FIELD of a standard assertion is resolved and digested, not
    // only the claim's own assertion list.
    refs::verify_assertion_references(
        &claim,
        &claim_refs,
        generation,
        input.profile,
        &manifest.label,
        store.manifests,
        &mut results,
    );
    // C2PA 2.4 Validation, Preparing the list of redacted assertions: the
    // claim's `redacted_assertions` declarations are legal, and the assertions
    // they name really are gone.
    redaction::verify_claim_redactions(&manifest.label, &claim, store.manifests, &mut results);
    if verify_spec_version_metadata(&claim, input.profile, &sig_url, &mut results) {
        structure_ok = false;
    }
    if certificate_statuses.rejected {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.clone(),
            "store-wide certificate-status evidence exceeds verifier bounds".into(),
        );
        structure_ok = false;
    }

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
            Some(&claim_refs.declared_labels),
            &[],
            None,
            results,
            Some(verdict),
            input.profile,
            report_decode_nodes,
        );
    };

    // The accepted relative URI resolves inside the current manifest. The
    // absolute form must name this manifest exactly; cross-manifest and deeper
    // paths never resolve to the current signature box.
    let sig_ref_ok = claim
        .get("signature")
        .and_then(Value::as_text)
        .is_some_and(|uri| claim_signature_uri_is_local(uri, &label));
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
            Some(&claim_refs.declared_labels),
            &[],
            None,
            results,
            Some(verdict),
            input.profile,
            report_decode_nodes,
        );
    }

    // --- Signing certificate chain ---
    let (chain, chain_error) = match extract_x5chain(cose) {
        Ok(chain) => (chain, None),
        Err(error) => (Vec::new(), Some(error.to_string())),
    };
    let leaf = chain.first().map(|c| c.as_slice());

    // Step 8 (computed early): a fully verified RFC 3161 token establishes the
    // validation instant for the claim-signing chain. Unverified token bytes
    // never influence certificate validity. Evidence order (header first, then
    // the `c2pa.time-stamp` assertion fallback), status placement, and the
    // legacy-`sigTst` caveat live in [`timestamp_assertion`].
    let ocsp_verification_time = input
        .validation_time
        .unwrap_or_else(OffsetDateTime::now_utc);
    let timestamp_index = timestamp_assertion::index_store_timestamp_assertions(
        store.manifests,
        &ingredient_manifest_labels(store.manifests),
        &mut results,
    );
    let trusted_timestamp = timestamp_assertion::validate_timestamp_evidence(
        cose,
        claim_cbor,
        &label,
        &timestamp_index,
        input.tsa_trust,
        ocsp_verification_time,
        &mut results,
        &sig_url,
    );
    // The claimed time of signing is the generator's own unattested statement;
    // it is reported informationally and never moves `at`.
    timestamp_assertion::validate_optional_iat(
        cose,
        &chain,
        trusted_timestamp.as_ref(),
        &mut results,
        &sig_url,
    );

    // Step 4: a trusted timestamp takes precedence for certificate validity,
    // while OCSP freshness still uses the caller's current verification time.
    let signing_time = trusted_timestamp.map(|timestamp| timestamp.generated_at);
    let at = signing_time.unwrap_or(ocsp_verification_time);

    // Evaluate the signing-certificate chain up front when a trust list is
    // supplied. The leaf's claim-signing profile (EKU, key usage, and CA
    // constraints) is intrinsic to the credential and is enforced even when
    // no trust policy was supplied.
    let chain_result = match (input.claim_signer_trust, leaf) {
        (Some(trust), Some(leaf_der)) => Some(validate_chain(
            leaf_der,
            &chain[1..],
            trust,
            crate::c2pa_trust::AnchorPurpose::ClaimSigning,
            Some(at),
        )),
        _ => None,
    };
    // Whole-chain validity at `at`. With a trust list this reflects every cert
    // in the chain; without one it is the leaf's own validity window.
    let in_validity = match &chain_result {
        Some(cr) => cr.chain_validity_ok && leaf.map(|d| cert::valid_at(d, at)).unwrap_or(false),
        None => leaf.map(|d| cert::valid_at(d, at)).unwrap_or(false),
    };
    let leaf_acceptable = chain_result
        .as_ref()
        .map(|cr| cr.leaf_acceptable)
        .unwrap_or_else(|| {
            leaf.map(crate::c2pa_trust::leaf_acceptable_der)
                .unwrap_or(false)
        });

    // Cryptographic verification of the claim signature against the leaf.
    let sig_verification = leaf.map(|d| verify_claim(cose, claim_cbor, d));
    let sig_ok = matches!(sig_verification, Some(Ok(())));

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
                // VAL-CRYP-0007 gives an algorithm outside the allowed list
                // its own failure code; VAL-CRYP-0014's
                // `claimSignature.mismatch` covers every other way the
                // signature fails to validate, including a payload that is
                // not `nil` (detached content mode is mandatory for claims,
                // and no registered code is more specific).
                let (code, explanation) = match &sig_verification {
                    Some(Err(CryptoError::UnsupportedAlg(id))) => (
                        ALGORITHM_UNSUPPORTED,
                        format!("claim signature algorithm {id} is not on the C2PA allowed list"),
                    ),
                    Some(Err(error)) => (
                        CLAIM_SIGNATURE_MISMATCH,
                        format!("claim signature invalid: {error}"),
                    ),
                    _ => (CLAIM_SIGNATURE_MISMATCH, "claim signature invalid".into()),
                };
                results.push_failure(code, sig_url.clone(), explanation);
            }
            // When sig_ok but outside validity, claimSignature.validated is
            // intentionally suppressed; the outsideValidity failure below
            // carries the verdict.
        }
        None => {
            let explanation = chain_error.clone().unwrap_or_else(|| {
                "no integrity-protected signing certificate in signature".into()
            });
            results.push_failure(SIGNING_CREDENTIAL_INVALID, sig_url.clone(), explanation);
            results.push_failure(
                CLAIM_SIGNATURE_MISMATCH,
                sig_url.clone(),
                "claim signature could not be verified without an integrity-protected signing certificate".into(),
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
    // Filled by the ingredient walk below and read when the report is
    // assembled: the additive per-ingredient deltas.
    let mut ingredient_deltas = Vec::new();
    let sig_usable = if generous {
        sig_constructed
    } else {
        sig_constructed && in_validity
    };
    if sig_usable {
        // Step 5: assertion hashed-URI bindings.
        verify_assertion_bindings(
            &claim,
            &mut claim_refs,
            generation,
            &label,
            input.profile,
            &mut results,
        );
        // Ingredient manifest and signature hashes are semantic work. Defer
        // them until the active claim signature is usable, then cache each
        // child-manifest/algorithm digest for this verification.
        let mut ingredient_digests = IngredientManifestDigestCache::new(store);
        verify_ingredient_references(
            &label,
            &claim_refs,
            &claim,
            &mut ingredient_digests,
            &sig_url,
            input.profile,
            &mut results,
        );
        // Recursive ingredient validation (C2PA 2.4, "Validate the
        // Ingredients"). The walk reports per-ingredient deltas additively and
        // contributes only its own informational codes to this manifest's
        // verdict; an ingredient manifest's defects never invalidate the asset
        // in hand.
        let mut graph = ingredient_graph::build(&label, store, input.profile);
        results.success.append(&mut graph.active.success);
        results
            .informational
            .append(&mut graph.active.informational);
        results.failure.append(&mut graph.active.failure);
        ingredient_deltas = graph.deltas;
        // The claims CAWG identity validation may resolve
        // `referenced_assertions` against.
        let reached_ingredients = graph.reached;
        // Step 6: an update inherits the hard binding from the first standard
        // manifest in its authenticated parent chain. Standard manifests use
        // their own binding as before.
        if manifest.kind() == ManifestKind::Update {
            verify_update_hard_binding(
                manifest,
                store,
                input.data,
                format,
                fragments,
                prehashed_digest,
                input.profile,
                &mut results,
            );
        } else if let Some(digest) = prehashed_digest {
            let _ =
                verify_prehashed_hard_binding(&claim, &claim_refs, digest, &label, &mut results);
        } else {
            let _ = verify_data_hash(
                &claim,
                &claim_refs,
                input.data,
                format,
                fragments,
                update_manifest::StoreRendition::AsSigned,
                &label,
                input.profile,
                &mut results,
            );
        }
        // Step 6a (EXPERIMENTAL, PR #2058): host-less compound binding. ONLY for
        // application/c2pa (C2paStore). Ordinary host-bearing formats require a
        // real c2pa.hash.* binding (verify_data_hash) and never treat
        // c2pa.compound.content as a hard binding.
        if format == AssetFormat::C2paStore {
            verify_compound_content(&claim_refs, &label, store.manifest_hashes, &mut results);
        }
        // An update manifest carries no hard binding of its own, so an identity
        // inside one references the binding in the first standard manifest of
        // its parentOf chain (C2PA 2.4 Validation, "Validate the Asset's
        // Content").
        let inherited_binding = inherited_hard_binding(manifest, store);
        // Named-actor trust is evaluated only when this exact asset and claim
        // have no C2PA-level failure and every referenced assertion still
        // matches its stored bytes. CAWG assertion failures are consumer-layer
        // results and do not invalidate the manifest or suppress identity
        // validation.
        if results
            .failure
            .iter()
            .all(|status| is_identity_assertion_scoped(&status.code))
        {
            cawg::verify_identity_assertions(
                &mut cawg::IdentityContext {
                    manifest,
                    claim: &claim,
                    validation_time: at,
                    claim_timestamp: signing_time,
                    cawg_trust: cawg_inputs.trust,
                    cawg_allowed_certs: cawg_inputs.allowed_certs,
                    ocsp_verification_time,
                    document_signing_require_anchor: cawg_inputs.document_signing_require_anchor,
                    tsa_trust: input.tsa_trust,
                    timestamp_index: &timestamp_index,
                    did_documents: cawg_inputs.did_documents,
                    evidence: input.evidence,
                    // CAWG 1.3 requires deterministic signer_payload CBOR;
                    // the generous posture still accepts the CAWG 1.1 field
                    // order that c2pa-rs writes, with an informational status.
                    allow_legacy_encoding: is_generous(input.profile)
                        && !input.cawg_strict_encoding,
                    ica_trusted_issuers: cawg_inputs.ica_trusted_issuers,
                    ica_trust_anchors: cawg_inputs.ica_trust_anchors,
                    ica_status_lists: cawg_inputs.ica_status_lists,
                    ingredients: cawg::IngredientResolution {
                        claims: &reached_ingredients,
                        inherited_binding: inherited_binding.as_ref().map(
                            |(label, binding, alg)| cawg::InheritedBinding {
                                manifest: label.as_str(),
                                reference: binding,
                                claim_alg: alg.as_deref(),
                            },
                        ),
                    },
                    results: &mut results,
                },
                &claim_refs,
                claim_refs
                    .binding_plan(format == AssetFormat::C2paStore)
                    .primary(),
                &certificate_statuses.payloads,
            );
        }
    }

    // Step 7a: evaluate OCSP evidence before trust so a revoked leaf or CA
    // certificate cannot be reported trusted. Embedded staples first (the
    // shared evaluator also serves CAWG identity validation), then any online
    // response a caller supplied, which takes precedence for the certificate
    // it covers.
    let ocsp_outcome = evaluate_embedded_ocsp(
        cose,
        &certificate_statuses.payloads,
        &chain,
        signing_time,
        ocsp_verification_time,
        input.claim_signer_trust,
        !generous,
    );
    let ocsp_targets = ocsp_targets(&chain, input.claim_signer_trust);
    let online_ocsp = evaluate_online_ocsp(
        &ocsp_targets,
        input.evidence,
        signing_time,
        ocsp_verification_time,
    );
    let ocsp_blocks_trust = ocsp_outcome.status.blocks_trust()
        || online_ocsp.ca_revoked
        || online_ocsp.leaf == Some(OnlineOcspVerdict::Revoked);
    record_ocsp_status(
        ocsp_outcome,
        &online_ocsp,
        &ocsp_targets,
        &sig_url,
        &mut results,
    );

    // Step 7b: trust evaluation (when a trust list and/or allowed list is
    // supplied). Reuses the chain result computed at `at` in step 4. A revoked
    // OCSP status or a fatal structural defect prevents a trusted verdict. An
    // allowed-list match trusts the end-entity certificate directly — no
    // chain-to-anchor required — but the leaf must still be an acceptable
    // claim signer and valid at `at`.
    let leaf_allowed = match (input.allowed_certs, leaf) {
        (Some(allowed), Some(leaf_der)) => {
            allowed.contains_certificate(leaf_der)
                && crate::c2pa_trust::leaf_acceptable_der(leaf_der)
                && cert::valid_at(leaf_der, at)
        }
        _ => false,
    };
    if chain_result.is_some() || (input.allowed_certs.is_some() && leaf.is_some()) {
        let chain_trusted = chain_result
            .as_ref()
            .map(|cr| cr.trusted && cr.leaf_acceptable)
            .unwrap_or(false);
        if (chain_trusted || leaf_allowed) && structure_ok && !ocsp_blocks_trust {
            results.push_success(
                SIGNING_CREDENTIAL_TRUSTED,
                sig_url.clone(),
                "signing certificate trusted".into(),
            );
        } else if !results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED) {
            results.push_failure(
                SIGNING_CREDENTIAL_UNTRUSTED,
                sig_url.clone(),
                "signing certificate untrusted".into(),
            );
        }
    } else if !generous && leaf.is_some() && !results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED) {
        // No claim-signing anchors or allowed certificates are configured. The
        // default posture reports trust as not evaluated; the conformance
        // posture applies the spec literally: a credential absent from the
        // (empty) trust list is untrusted.
        results.push_failure(
            SIGNING_CREDENTIAL_UNTRUSTED,
            sig_url.clone(),
            "signing certificate untrusted: no claim-signing trust anchors are configured".into(),
        );
    }

    // Conformance-program SHOULD->SHALL upgrades, applied on the full-evaluation
    // path (structural-failure early exits above are already failures).
    apply_compliance_upgrades(&mut results, input.profile.compliance, &sig_url);
    let mut output = finish(
        label,
        manifest,
        Some(&claim),
        Some(&claim_refs.declared_labels),
        &chain,
        Some(cose),
        results,
        Some(verdict),
        input.profile,
        report_decode_nodes,
    );
    ingredient_graph::attach(&mut output.report_json, &ingredient_deltas);
    output
}

/// Structural validation of the claim and assertions: detect malformed or
/// non-conforming input (the verifier's adversarial-input responsibility).
///
/// Emits, as failures: `claim.multiple` (>1 claim box), `claim.malformed`
/// (missing fields required by the detected claim generation),
/// `claim.hardBindings.missing` (no `c2pa.hash.*`
const MAX_CLAIM_ASSERTION_REFERENCES: usize = 4_096;
const MAX_ASSERTION_HASH_WORK_BYTES: usize = 256 * 1024 * 1024;
const MAX_ASSERTION_DECODED_VALUE_NODES: usize = 1 << 20;
// One verifier-call budget spans the active manifest and every ingredient
// parent. No report assertion or parent receives a fresh decoder allowance.
const MAX_REPORT_DECODED_VALUE_NODES: usize = 1 << 20;

fn checked_hash_work_total(lengths: impl IntoIterator<Item = usize>) -> Option<usize> {
    lengths.into_iter().try_fold(0usize, |total, length| {
        total
            .checked_add(length)
            .filter(|next| *next <= MAX_ASSERTION_HASH_WORK_BYTES)
    })
}

fn is_supported_bmff_hash_label(label: &str) -> bool {
    matches!(label, "c2pa.hash.bmff.v2" | "c2pa.hash.bmff.v3")
}

fn is_supported_whole_asset_hash_label(label: &str) -> bool {
    label == "c2pa.hash.data" || is_supported_bmff_hash_label(label)
}

/// Compatibility name used by the CAWG consumer. This predicate describes
/// primary bindings only; `c2pa.hash.multi-asset` is a supplemental fallback.
fn is_supported_hard_binding_label(label: &str, compound_ok: bool) -> bool {
    is_supported_whole_asset_hash_label(label)
        || label == "c2pa.hash.boxes"
        || label == "c2pa.hash.collection.data"
        || (compound_ok && label == "c2pa.compound.content")
}

fn is_multi_asset_binding_label(label: &str) -> bool {
    label == "c2pa.hash.multi-asset"
}

struct IndexedAssertion<'a> {
    jumbf: Option<&'a [u8]>,
    payload: Option<&'a [u8]>,
    decoded: Option<Value>,
    jumbf_digests: [Option<Vec<u8>>; 3],
}

struct ClaimAssertionReference<'a> {
    field: &'static str,
    value: &'a Value,
    label: Option<&'a str>,
}
#[derive(Clone, Copy)]
enum OperativeBinding<'index, 'claim> {
    Primary(&'index ClaimAssertionReference<'claim>),
    MultiAsset(&'index ClaimAssertionReference<'claim>),
}

impl<'index, 'claim> OperativeBinding<'index, 'claim> {
    fn reference(self) -> &'index ClaimAssertionReference<'claim> {
        match self {
            Self::Primary(reference) | Self::MultiAsset(reference) => reference,
        }
    }
}

#[derive(Clone, Copy)]
struct BindingPlan<'index, 'claim> {
    primary_candidate: Option<&'index ClaimAssertionReference<'claim>>,
    primary_count: usize,
    multi_asset_candidate: Option<&'index ClaimAssertionReference<'claim>>,
    multi_asset_count: usize,
}

impl<'index, 'claim> BindingPlan<'index, 'claim> {
    fn primary(self) -> Option<&'index ClaimAssertionReference<'claim>> {
        (self.primary_count == 1)
            .then_some(self.primary_candidate)
            .flatten()
    }

    fn multi_asset(self) -> Option<&'index ClaimAssertionReference<'claim>> {
        (self.multi_asset_count == 1)
            .then_some(self.multi_asset_candidate)
            .flatten()
    }
}

const GENERATOR_ICON_REFERENCE_FIELD: &str = "claim_generator_info.icon";

/// Identity of the binding a hashed-URI reference asserts: the assertion it
/// resolves to, the algorithm it names (absent means the claim's `alg`, which
/// is the same for every reference in one claim), and the digest it expects.
/// References sharing this key are interchangeable during validation.
fn hashed_uri_binding_key<'a>(
    value: &'a Value,
    label: &'a str,
) -> Option<(&'a str, Option<&'a str>, &'a [u8])> {
    let hash = value.get("hash").and_then(Value::as_bytes)?;
    Some((label, value.get("alg").and_then(Value::as_text), hash))
}

fn visit_generator_icon_references<'a>(
    claim: &'a Value,
    generation: ClaimGeneration,
    mut visit: impl FnMut(&'a Value),
) {
    let Some(info) = claim.get("claim_generator_info") else {
        return;
    };
    match generation {
        ClaimGeneration::V1 => {
            if let Value::Array(entries) = info {
                for entry in entries {
                    if let Some(icon) = entry.get("icon") {
                        visit(icon);
                    }
                }
            }
        }
        ClaimGeneration::V2 => {
            if let Some(icon) = info.get("icon") {
                visit(icon);
            }
        }
    }
}

/// One bounded, exact-resolution view of a claim's assertion declarations.
///
/// Every downstream validation phase uses this view. References are kept once
/// in claim order, assertion payloads are indexed once, and only declared
/// assertion-store boxes are decoded or exposed to semantic validation.
struct ClaimAssertionRefs<'a> {
    complete: bool,
    /// A label declared more than once by the claim's assertion lists
    /// (`assertions` / `created_assertions` / `gathered_assertions`). A
    /// `claim_generator_info` icon pointing at an already-declared assertion is
    /// not a second declaration and never lands here.
    duplicate_label: Option<&'a str>,
    references: Vec<ClaimAssertionReference<'a>>,
    binding_labels: Vec<&'a str>,
    /// Coverage set: every assertion label the claim reaches, from an assertion
    /// list or a `claim_generator_info` icon. Drives payload indexing, digest
    /// work, and report filtering.
    declared_labels: std::collections::HashSet<&'a str>,
    /// Declaration set: assertion lists only. C2PA 2.4 Validation, Validate the
    /// Assertions, makes membership of `created_assertions`/`gathered_assertions`
    /// (or v1 `assertions`) the sole test for `assertion.undeclared`; an icon is
    /// a pointer, not a declaration.
    declaration_labels: std::collections::HashSet<&'a str>,
    assertions: std::collections::HashMap<&'a str, IndexedAssertion<'a>>,
    undeclared_labels: Vec<&'a str>,
    invalid_cbor_labels: Vec<&'a str>,
    invalid_json_labels: Vec<&'a str>,
    hash_work_bytes: Option<usize>,
    decode_budget_exhausted: bool,
    decoded_value_nodes: usize,
}

impl<'a> ClaimAssertionRefs<'a> {
    fn build(
        manifest: &'a ParsedManifest<'_>,
        claim: &'a Value,
        generation: ClaimGeneration,
    ) -> Self {
        let mut total = 0usize;
        for field in ref_fields(generation) {
            let Some(Value::Array(items)) = claim.get(field) else {
                continue;
            };
            let Some(next) = total.checked_add(items.len()) else {
                return Self::incomplete();
            };
            if next > MAX_CLAIM_ASSERTION_REFERENCES {
                return Self::incomplete();
            }
            total = next;
        }
        let mut icon_overflow = false;
        visit_generator_icon_references(claim, generation, |value| {
            let local = value
                .get("url")
                .and_then(Value::as_text)
                .is_some_and(|url| url.starts_with("self#jumbf="));
            if local {
                total = match total.checked_add(1) {
                    Some(next) if next <= MAX_CLAIM_ASSERTION_REFERENCES => next,
                    _ => {
                        icon_overflow = true;
                        total
                    }
                };
            }
        });
        if icon_overflow {
            return Self::incomplete();
        }

        let mut references = Vec::with_capacity(total);
        // Coverage set: every assertion label the claim reaches, from either an
        // assertion list or a `claim_generator_info` icon. Drives payload
        // indexing and digest-work accounting, never the undeclared sweep.
        let mut declared_labels = std::collections::HashSet::with_capacity(total);
        // Declaration set: assertion lists only. A label may be declared once.
        let mut declaration_labels = std::collections::HashSet::with_capacity(total);
        // Every distinct hashed-URI binding the claim asserts. Two references
        // sharing a key resolve the same assertion bytes under the same
        // algorithm against the same expected digest, so the second can only
        // restate the first's verdict.
        let mut binding_keys = std::collections::HashSet::with_capacity(total);
        let mut duplicate_label = None;
        let mut binding_labels = Vec::new();
        for field in ref_fields(generation) {
            let Some(Value::Array(items)) = claim.get(field) else {
                continue;
            };
            for value in items {
                let label = value
                    .get("url")
                    .and_then(Value::as_text)
                    .and_then(|url| assertion_label_for_manifest(url, &manifest.label));
                if let Some(label) = label {
                    if is_supported_hard_binding_label(label, true)
                        || is_multi_asset_binding_label(label)
                    {
                        binding_labels.push(label);
                    }
                }
                if let Some(label) = label {
                    if !declaration_labels.insert(label) {
                        duplicate_label.get_or_insert(label);
                        continue;
                    }
                    declared_labels.insert(label);
                    if let Some(key) = hashed_uri_binding_key(value, label) {
                        binding_keys.insert(key);
                    }
                }
                references.push(ClaimAssertionReference {
                    field,
                    value,
                    label,
                });
            }
        }
        // A `claim_generator_info` icon is a hashed-URI *pointer* to an assertion,
        // not an assertion declaration: C2PA requires the icon assertion to also
        // appear in the claim's assertion list, and claim v1 allows several
        // `claim_generator_info` entries to share one icon. Both shapes are
        // lawful, so an icon reference never raises `duplicate_label`. Each icon
        // hashed-URI is still resolved and hash-verified on its own.
        visit_generator_icon_references(claim, generation, |value| {
            let url = value.get("url").and_then(Value::as_text);
            let label = url.and_then(|url| assertion_label_for_manifest(url, &manifest.label));
            if label.is_none() && url.is_some_and(|url| !url.starts_with("self#jumbf=")) {
                return;
            }
            if let Some(label) = label {
                declared_labels.insert(label);
                if let Some(key) = hashed_uri_binding_key(value, label) {
                    if !binding_keys.insert(key) {
                        return;
                    }
                }
            }
            references.push(ClaimAssertionReference {
                field: GENERATOR_ICON_REFERENCE_FIELD,
                value,
                label,
            });
        });

        let payloads: std::collections::HashMap<&str, &[u8]> = manifest
            .assertions
            .iter()
            .map(|(label, payload)| (label.as_str(), *payload))
            .collect();
        let jumbf: std::collections::HashMap<&str, &[u8]> = manifest
            .assertion_jumbf
            .iter()
            .map(|(label, bytes)| (label.as_str(), *bytes))
            .collect();
        // Preflight every byte domain that may be decoded or hashed before any
        // assertion payload becomes a `Value`. JUMBF content is counted twice
        // for the claim and optional compound digest slots; raw payload bytes
        // are counted independently for semantic decoding.
        let hash_work_bytes = checked_hash_work_total(declared_labels.iter().flat_map(|label| {
            let jumbf_len = jumbf.get(label).map_or(0, |bytes| bytes.len());
            let payload_len = payloads.get(label).map_or(0, |bytes| bytes.len());
            [jumbf_len, jumbf_len, payload_len]
        }));
        let decode_payloads = hash_work_bytes.is_some();
        let mut remaining_nodes = MAX_ASSERTION_DECODED_VALUE_NODES;
        let mut decode_budget_exhausted = false;
        let mut assertions = std::collections::HashMap::with_capacity(declared_labels.len());
        let mut invalid_cbor_labels = Vec::new();
        let mut invalid_json_labels = Vec::new();
        // Index (and decode) each label once even when two references reach it.
        // A `claim_generator_info` icon and its assertion-list declaration share
        // one payload, so the decoder budget is charged for it once.
        for reference in references.iter().filter_map(|reference| reference.label) {
            if assertions.contains_key(reference) {
                continue;
            }
            let payload = payloads.get(reference).copied();
            let decoded = if decode_payloads && !decode_budget_exhausted {
                match (payload, manifest.assertion_content_type(reference)) {
                    (Some(bytes), Some(AssertionContentType::Json)) => {
                        // C2PA 2.4 Validation, Specific Assertion Validation,
                        // dispatches on the assertion's label, not on the JUMBF
                        // content type it arrived in. A JSON-serialized
                        // `c2pa.ingredient.v3` or `c2pa.actions.v2` owes the same
                        // semantic checks, so JSON is projected into the one
                        // value model the semantic phase reads, on the same
                        // decode budget.
                        match serde_json::from_slice::<Json>(bytes) {
                            Ok(json) => {
                                match assertion_semantics::value_from_json(
                                    &json,
                                    &mut remaining_nodes,
                                ) {
                                    Some(value) => Some(value),
                                    None => {
                                        decode_budget_exhausted = true;
                                        None
                                    }
                                }
                            }
                            Err(_) => {
                                invalid_json_labels.push(reference);
                                None
                            }
                        }
                    }
                    (Some(bytes), _) => match decode((bytes, &mut remaining_nodes)) {
                        Ok(value) => Some(value),
                        Err(DecodeError::NodeLimitExceeded(_)) => {
                            decode_budget_exhausted = true;
                            None
                        }
                        Err(_) => {
                            invalid_cbor_labels.push(reference);
                            None
                        }
                    },
                    (None, _) => None,
                }
            } else {
                None
            };
            assertions.insert(
                reference,
                IndexedAssertion {
                    jumbf: jumbf.get(reference).copied(),
                    payload,
                    decoded,
                    jumbf_digests: [None, None, None],
                },
            );
        }
        // C2PA 2.4 Validation, Validate the Assertions: an assertion present in
        // the store but not referenced by an element of the claim's assertion
        // lists is `assertion.undeclared`. A `claim_generator_info` icon reaches
        // the assertion without declaring it, so the declaration set decides.
        let undeclared_labels = manifest
            .assertion_jumbf
            .iter()
            .filter_map(|(label, _)| {
                (!declaration_labels.contains(label.as_str())).then_some(label.as_str())
            })
            .collect();

        Self {
            complete: true,
            duplicate_label,
            references,
            binding_labels,
            declared_labels,
            declaration_labels,
            assertions,
            undeclared_labels,
            invalid_cbor_labels,
            invalid_json_labels,
            hash_work_bytes,
            decode_budget_exhausted,
            decoded_value_nodes: MAX_ASSERTION_DECODED_VALUE_NODES - remaining_nodes,
        }
    }

    fn incomplete() -> Self {
        Self {
            complete: false,
            duplicate_label: None,
            references: Vec::new(),
            binding_labels: Vec::new(),
            declared_labels: std::collections::HashSet::new(),
            declaration_labels: std::collections::HashSet::new(),
            assertions: std::collections::HashMap::new(),
            undeclared_labels: Vec::new(),
            invalid_cbor_labels: Vec::new(),
            invalid_json_labels: Vec::new(),
            hash_work_bytes: None,
            decode_budget_exhausted: false,
            decoded_value_nodes: 0,
        }
    }

    fn indexed(&self, label: &str) -> Option<&IndexedAssertion<'a>> {
        self.assertions.get(label)
    }

    /// Whether the claim declares a `c2pa.soft-binding` assertion, counting the
    /// multi-instance spellings (`c2pa.soft-binding__1`).
    fn declares_soft_binding(&self) -> bool {
        self.declaration_labels
            .iter()
            .any(|label| *label == "c2pa.soft-binding" || label.starts_with("c2pa.soft-binding__"))
    }

    fn jumbf_digest(&self, label: &str, algorithm: &str) -> Option<&[u8]> {
        let index = bmff_algorithm_index(algorithm)?;
        self.indexed(label)?.jumbf_digests[index].as_deref()
    }

    fn binding_plan(&self, compound_ok: bool) -> BindingPlan<'_, 'a> {
        let primary_count = self
            .binding_labels
            .iter()
            .filter(|label| is_supported_hard_binding_label(label, compound_ok))
            .count();
        let multi_asset_count = self
            .binding_labels
            .iter()
            .filter(|label| is_multi_asset_binding_label(label))
            .count();
        BindingPlan {
            primary_candidate: self.references.iter().find(|reference| {
                reference
                    .label
                    .is_some_and(|label| is_supported_hard_binding_label(label, compound_ok))
            }),
            primary_count,
            multi_asset_candidate: self
                .references
                .iter()
                .find(|reference| reference.label.is_some_and(is_multi_asset_binding_label)),
            multi_asset_count,
        }
    }

    fn hash_work_bytes(&self, _generation: ClaimGeneration) -> Option<usize> {
        self.hash_work_bytes
    }
}

fn verify_spec_version_metadata(
    claim: &Value,
    profile: EngineProfile,
    sig_url: &str,
    results: &mut ValidationResults,
) -> bool {
    let Some(version) = versions::non_semver_declared_spec_version(claim) else {
        return false;
    };
    let explanation = format!("claim_generator_info.specVersion '{version}' is not a SemVer value");
    if profile.compliance == ComplianceLevel::ConformanceProgram {
        results.push_failure(CLAIM_MALFORMED, sig_url.to_string(), explanation);
        true
    } else {
        results.push_informational(
            CLAIM_SPEC_VERSION_NOT_SEMVER,
            sig_url.to_string(),
            explanation,
        );
        false
    }
}

#[allow(clippy::too_many_arguments)] // internal structural gate; grouping obscures inputs
fn verify_claim_structure(
    manifest: &ParsedManifest,
    store: StoreContext<'_>,
    claim: &Value,
    generation: ClaimGeneration,
    claim_refs: &ClaimAssertionRefs<'_>,
    format: AssetFormat,
    sig_url: &str,
    profile: EngineProfile,
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

    // Defense in depth for in-crate direct callers; the production JUMBF parser rejects both duplicate forms before this function.
    let mut manifest_labels = std::collections::BTreeSet::new();
    if store
        .manifests
        .iter()
        .any(|item| !manifest_labels.insert(item.label.as_str()))
    {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            "manifest store contains duplicate labels; internal JUMBF references are ambiguous"
                .into(),
        );
        fatal = true;
    }
    let mut assertion_labels = std::collections::BTreeSet::new();
    if manifest
        .assertion_jumbf
        .iter()
        .any(|(label, _)| !assertion_labels.insert(label.as_str()))
    {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            "manifest contains duplicate assertion labels; internal JUMBF references are ambiguous"
                .into(),
        );
        fatal = true;
    }

    // claim.malformed: fields required by the detected claim generation must
    // be present and have their required shape. A legacy claim-v1 claim that
    // predates `claim_generator_info` remains readable in the default posture
    // when its `claim_generator` string is present. Strict conformance applies
    // the current claim-map CDDL literally.
    let mut missing = match generation {
        ClaimGeneration::V1 => versions::v1_missing_fields(claim),
        ClaimGeneration::V2 => versions::v2_missing_fields(claim),
    };
    let generator_info_missing = claim
        .get("claim_generator_info")
        .is_none_or(|info| match info {
            Value::Null => true,
            Value::Array(entries) => entries.is_empty(),
            _ => false,
        });
    let legacy_generator_only = generation == ClaimGeneration::V1
        && generator_info_missing
        && claim
            .get("claim_generator")
            .and_then(Value::as_text)
            .is_some();
    if legacy_generator_only && profile.compliance == ComplianceLevel::CoreSpec {
        missing.retain(|field| *field != "claim_generator_info");
        results.push_informational(
            CLAIM_GENERATOR_INFO_MISSING,
            sig_url.to_string(),
            "legacy claim-v1 supplies claim_generator but omits usable claim_generator_info".into(),
        );
    }
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

    if !claim_refs.complete {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!(
                "claim assertion-reference count exceeds verifier bound ({MAX_CLAIM_ASSERTION_REFERENCES})"
            ),
        );
        return true;
    }
    for reference in &claim_refs.references {
        let malformed = !matches!(reference.value, Value::Map(_))
            || reference
                .value
                .get("url")
                .and_then(Value::as_text)
                .is_none()
            || reference
                .value
                .get("hash")
                .and_then(Value::as_bytes)
                .is_none();
        if malformed {
            results.push_failure(
                CLAIM_MALFORMED,
                sig_url.to_string(),
                "claim assertion reference is not a complete HashedUriMap".into(),
            );
            fatal = true;
        }
        if reference.field == GENERATOR_ICON_REFERENCE_FIELD
            && !reference.label.is_some_and(is_generator_icon_label)
        {
            results.push_failure(
                CLAIM_MALFORMED,
                sig_url.to_string(),
                "claim generator icon must reference a c2pa.icon assertion".into(),
            );
            fatal = true;
        }
    }
    if let Some(label) = claim_refs.duplicate_label {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!("claim declares assertion '{label}' more than once"),
        );
        fatal = true;
    }
    let is_update = manifest.kind() == ManifestKind::Update;
    if is_update {
        let inspection =
            update_manifest::inspect(manifest, claim_refs.declared_labels.iter().copied());
        if inspection.wrong_parents {
            results.push_failure(
                MANIFEST_UPDATE_WRONG_PARENTS,
                format!("self#jumbf=/c2pa/{}", manifest.label),
                "update manifest must declare exactly one parentOf ingredient".into(),
            );
            fatal = true;
        }
        if inspection.invalid {
            results.push_failure(
                MANIFEST_UPDATE_INVALID,
                format!("self#jumbf=/c2pa/{}", manifest.label),
                "update manifest contains forbidden content or an incomplete parent link".into(),
            );
            fatal = true;
        }
        if !inspection.wrong_parents && !inspection.invalid {
            match update_manifest::resolve_standard(manifest, store.manifests) {
                Ok(standard) => match standard.claim_cbor.and_then(|bytes| decode(bytes).ok()) {
                    Some(parent_claim) => {
                        let parent_generation = versions::claim_generation(standard, &parent_claim);
                        let parent_refs =
                            ClaimAssertionRefs::build(standard, &parent_claim, parent_generation);
                        match parent_refs.binding_plan(false).primary_count {
                            0 => results.push_failure(
                                CLAIM_HARD_BINDINGS_MISSING,
                                sig_url.to_string(),
                                "update chain does not reach a standard manifest with a hard binding"
                                    .into(),
                            ),
                            1 => {}
                            _ => {
                                results.push_failure(
                                    ASSERTION_MULTIPLE_HARD_BINDINGS,
                                    format!(
                                        "self#jumbf=/c2pa/{}/c2pa.assertions",
                                        standard.label
                                    ),
                                    "parent standard manifest declares more than one supported primary hard binding"
                                        .into(),
                                );
                                fatal = true;
                            }
                        }
                    }
                    None => {
                        results.push_failure(
                            CLAIM_HARD_BINDINGS_MISSING,
                            sig_url.to_string(),
                            "update chain parent claim could not be decoded".into(),
                        );
                        fatal = true;
                    }
                },
                Err(update_manifest::ResolveError::WrongParents(label)) => {
                    results.push_failure(
                        MANIFEST_UPDATE_WRONG_PARENTS,
                        format!("self#jumbf=/c2pa/{label}"),
                        "update manifest in parent chain must declare exactly one parentOf ingredient"
                            .into(),
                    );
                    fatal = true;
                }
                Err(update_manifest::ResolveError::Invalid(label)) => {
                    results.push_failure(
                        MANIFEST_UPDATE_INVALID,
                        format!("self#jumbf=/c2pa/{label}"),
                        "update manifest in parent chain contains forbidden content or an incomplete parent link"
                            .into(),
                    );
                    fatal = true;
                }
                Err(update_manifest::ResolveError::MissingParent(label)) => {
                    results.push_failure(
                        CLAIM_HARD_BINDINGS_MISSING,
                        sig_url.to_string(),
                        format!("update chain parent manifest '{label}' is absent"),
                    );
                    fatal = true;
                }
                Err(update_manifest::ResolveError::Cycle(label)) => {
                    results.push_failure(
                        CLAIM_HARD_BINDINGS_MISSING,
                        sig_url.to_string(),
                        format!("update manifest parent chain cycles at '{label}'"),
                    );
                    fatal = true;
                }
                Err(update_manifest::ResolveError::TooDeep) => {
                    results.push_failure(
                        CLAIM_HARD_BINDINGS_MISSING,
                        sig_url.to_string(),
                        "update manifest parent chain exceeds the verifier bound".into(),
                    );
                    fatal = true;
                }
            }
        }
    } else {
        let parent_count = claim_refs
            .references
            .iter()
            .filter_map(|reference| reference.label)
            .filter(|label| label.starts_with("c2pa.ingredient"))
            .filter(|label| {
                claim_refs
                    .indexed(label)
                    .and_then(|assertion| assertion.decoded.as_ref())
                    .and_then(|ingredient| ingredient.get("relationship"))
                    .and_then(Value::as_text)
                    == Some("parentOf")
            })
            .count();
        if parent_count > 1 {
            results.push_failure(
                MANIFEST_MULTIPLE_PARENTS,
                format!("self#jumbf=/c2pa/{}", manifest.label),
                "manifest declares more than one parent ingredient".into(),
            );
            fatal = true;
        }
    }

    // Every assertion-store box must be declared by exactly one local claim
    // reference. Undeclared payloads are never decoded or exposed to semantic
    // consumers through the index.
    for label in &claim_refs.undeclared_labels {
        results.push_failure(
            ASSERTION_UNDECLARED,
            format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                manifest.label
            ),
            format!(
                "assertion '{label}' is present in the assertion store but absent from the claim"
            ),
        );
        fatal = true;
    }

    if claim_refs.hash_work_bytes(generation).is_none() {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!(
                "aggregate assertion digest work exceeds verifier bound ({MAX_ASSERTION_HASH_WORK_BYTES} bytes)"
            ),
        );
        fatal = true;
    }
    if claim_refs.decode_budget_exhausted {
        results.push_failure(
            CLAIM_MALFORMED,
            sig_url.to_string(),
            format!(
                "aggregate decoded assertion values exceed verifier bound ({MAX_ASSERTION_DECODED_VALUE_NODES} nodes; {} nodes consumed)",
                claim_refs.decoded_value_nodes
            ),
        );
        fatal = true;
    }

    // Update manifests inherit their sole operative binding from the first
    // standard manifest in their parent chain. Their own assertion set was
    // checked above for forbidden bindings and multi-asset assertions.
    if !is_update {
        let binding_plan = claim_refs.binding_plan(format == AssetFormat::C2paStore);
        match binding_plan.primary_count {
            0 => results.push_failure(
                CLAIM_HARD_BINDINGS_MISSING,
                sig_url.to_string(),
                "claim references no supported primary hard binding".into(),
            ),
            1 => {}
            _ => {
                results.push_failure(
                    ASSERTION_MULTIPLE_HARD_BINDINGS,
                    format!("self#jumbf=/c2pa/{}/c2pa.assertions", manifest.label),
                    "claim declares more than one supported primary hard binding".into(),
                );
                fatal = true;
            }
        }
        if binding_plan.multi_asset_count > 1 {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                format!(
                    "self#jumbf=/c2pa/{}/c2pa.assertions/c2pa.hash.multi-asset",
                    manifest.label
                ),
                "claim declares more than one c2pa.hash.multi-asset fallback".into(),
            );
            fatal = true;
        }
    }

    // Decode only declared assertions, once, when building the index.
    for label in &claim_refs.invalid_cbor_labels {
        results.push_failure(
            ASSERTION_CBOR_INVALID,
            format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                manifest.label
            ),
            format!("assertion '{label}' CBOR could not be decoded"),
        );
    }
    for label in &claim_refs.invalid_json_labels {
        results.push_failure(
            ASSERTION_JSON_INVALID,
            format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                manifest.label
            ),
            format!("assertion '{label}' JSON could not be decoded"),
        );
    }
    verify_cawg_content_assertions(manifest, claim_refs, results);

    verify_ingredient_shapes(manifest, claim_refs, results);
    verify_alternative_content(manifest, claim, claim_refs, results);

    verify_action_assertions(
        claim_refs,
        claim,
        generation,
        manifest.kind(),
        store,
        &manifest.label,
        sig_url,
        profile,
        results,
    );
    fatal
}
fn is_cawg_assertion_instance(label: &str, base: &str) -> bool {
    if label == base {
        return true;
    }
    let Some(instance) = label
        .strip_prefix(base)
        .and_then(|suffix| suffix.strip_prefix("__"))
    else {
        return false;
    };
    !instance.is_empty()
        && !instance.starts_with('0')
        && instance.bytes().all(|byte| byte.is_ascii_digit())
}

fn verify_cawg_content_assertions(
    manifest: &ParsedManifest<'_>,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    for (label, _) in &manifest.assertion_jumbf {
        if !claim_refs.declaration_labels.contains(label.as_str()) {
            continue;
        }
        let Some(assertion) = claim_refs.indexed(label) else {
            continue;
        };
        let url = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
            manifest.label
        );
        if is_cawg_assertion_instance(label, "cawg.metadata") {
            cawg_metadata::validate_and_report(
                manifest.assertion_content_type(label),
                assertion.jumbf,
                assertion.decoded.as_ref(),
                url,
                results,
            );
        } else if is_cawg_assertion_instance(label, "cawg.training-mining") {
            cawg_training_mining::validate_and_report(
                manifest.assertion_content_type(label),
                assertion.decoded.as_ref(),
                url,
                results,
            );
        }
    }
}

/// Assertion labels a cloud data assertion may not reference because they are
/// hard bindings (C2PA 2.4 Validation, `c2pa.cloud-data` validation, step 2).
/// `c2pa.action` is the spec's spelling: the very first, singular actions
/// label, distinct from the deprecated `c2pa.actions` caught one step later.
const CLOUD_DATA_HARD_BINDING_LABELS: &[&str] = &[
    "c2pa.cloud-data",
    "c2pa.action",
    "c2pa.actions.v2",
    "c2pa.hash.data",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.multi-asset",
];

/// Assertion labels a cloud data assertion may not reference at all
/// (C2PA 2.4 Validation, `c2pa.cloud-data` validation, step 4).
const CLOUD_DATA_FORBIDDEN_LABELS: &[&str] = &[
    "c2pa.actions",
    "c2pa.actions.v2",
    "c2pa.cloud-data",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.data",
    "c2pa.hash.multi-asset",
    "c2pa.ingredient",
    "c2pa.ingredient.v2",
    "c2pa.ingredient.v3",
];

/// Assertion labels an external reference assertion may not reference
/// (C2PA 2.4 Validation, `c2pa.external-reference` validation, step 4).
const EXTERNAL_REFERENCE_FORBIDDEN_LABELS: &[&str] = &[
    "c2pa.actions",
    "c2pa.actions.v2",
    "c2pa.external-reference",
    "c2pa.hash.bmff.v2",
    "c2pa.hash.bmff.v3",
    "c2pa.hash.boxes",
    "c2pa.hash.collection.data",
    "c2pa.hash.data",
    "c2pa.hash.multi-asset",
    "c2pa.ingredient",
    "c2pa.ingredient.v2",
    "c2pa.ingredient.v3",
];

/// Strip the `__<n>` disambiguation suffix a manifest adds when it stores more
/// than one assertion of a type, leaving the assertion type itself.
fn base_assertion_label(label: &str) -> &str {
    match label.rsplit_once("__") {
        Some((base, index)) if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) => {
            base
        }
        _ => label,
    }
}

/// C2PA 2.4 Validation, Specific Assertion Validation: `c2pa.cloud-data` and
/// `c2pa.external-reference`.
///
/// Both assertions point at data stored somewhere else. Everything the spec
/// makes checkable without going to get that data - the required fields, the
/// shape of the `location` map, and the assertion types the spec forbids
/// storing remotely - is checked here and rejects the claim exactly as the
/// spec says. Everything that would need the bytes - the retrieved size, the
/// `Content-Type`, the hash, the retrieved JUMBF box's label - is not checked,
/// because this verifier does not fetch on its own.
///
/// The distinction is the spec's own, not a shortcut: C2PA 2.4 Validation,
/// External Data Validation, General, says those references "are not retrieved
/// and validated as part of standard validation", that retrieval is optional,
/// and that "the inability to retrieve or validate external data shall not
/// cause a claim to be rejected". So the unread remote assertion is reported
/// with the registered `assertion.inaccessible` code and its URI, and that code
/// is carved out of the integrity verdict in both postures.
///
/// When a caller supplies the bytes in [`OnlineEvidence::external_data`], the
/// procedure in External Data Validation, Validation of External References,
/// runs for real: the content is hashed against the assertion's own `alg` and
/// `hash`, producing `assertion.accessible` plus `assertion.hashedURI.match`,
/// or `assertion.hashedURI.mismatch`.
#[allow(clippy::too_many_arguments)] // one assertion pass; grouping obscures inputs
fn verify_external_data_assertions(
    claim_refs: &ClaimAssertionRefs<'_>,
    generation: ClaimGeneration,
    manifest_kind: ManifestKind,
    manifest_label: &str,
    profile: EngineProfile,
    evidence: OnlineEvidence<'_>,
    results: &mut ValidationResults,
) {
    for reference in &claim_refs.references {
        let Some(label) = reference.label else {
            continue;
        };
        let kind = base_assertion_label(label);
        if kind != "c2pa.cloud-data" && kind != "c2pa.external-reference" {
            continue;
        }
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|indexed| indexed.decoded.as_ref())
        else {
            continue;
        };
        let url = format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}");
        if kind == "c2pa.cloud-data" {
            verify_cloud_data_assertion(assertion, manifest_kind, &url, profile, evidence, results);
        } else {
            verify_external_reference_assertion(
                assertion,
                reference.field,
                generation,
                &url,
                profile,
                evidence,
                results,
            );
        }
    }
}

fn verify_cloud_data_assertion(
    assertion: &Value,
    manifest_kind: ManifestKind,
    url: &str,
    profile: EngineProfile,
    evidence: OnlineEvidence<'_>,
    results: &mut ValidationResults,
) {
    let malformed = |results: &mut ValidationResults, detail: &str| {
        results.push_failure(
            ASSERTION_CLOUD_DATA_MALFORMED,
            url.to_string(),
            detail.to_string(),
        );
    };
    let (Some(referenced), Some(_), Some(location)) = (
        assertion.get("label").and_then(Value::as_text),
        assertion.get("size"),
        assertion.get("location"),
    ) else {
        malformed(
            results,
            "cloud data assertion omits label, size, or location",
        );
        return;
    };
    let referenced_kind = base_assertion_label(referenced);
    if CLOUD_DATA_HARD_BINDING_LABELS.contains(&referenced_kind) {
        results.push_failure(
            ASSERTION_CLOUD_DATA_HARD_BINDING,
            url.to_string(),
            format!("cloud data assertion references the hard binding {referenced}"),
        );
        return;
    }
    if manifest_kind == ManifestKind::Update
        && matches!(referenced_kind, "c2pa.actions" | "c2pa.actions.v2")
    {
        results.push_failure(
            ASSERTION_CLOUD_DATA_ACTIONS,
            url.to_string(),
            format!("update manifest's cloud data assertion references {referenced}"),
        );
        return;
    }
    if CLOUD_DATA_FORBIDDEN_LABELS.contains(&referenced_kind) {
        malformed(
            results,
            &format!("cloud data assertion may not reference {referenced}"),
        );
        return;
    }
    // `location` is a `hashed-ext-uri-map`, whose `url`, `alg` and `hash` are
    // all mandatory. Without them nothing could ever resolve or be checked, so
    // the assertion is incomplete.
    let Some(uri) = location.get("url").and_then(Value::as_text) else {
        malformed(results, "cloud data location has no url");
        return;
    };
    if location.get("alg").and_then(Value::as_text).is_none()
        || location.get("hash").and_then(Value::as_bytes).is_none()
    {
        malformed(results, "cloud data location has no alg/hash pair");
        return;
    }
    // C2PA 2.4 Standard Assertions, Cloud Data: because the assertion's own
    // `size` is required, "the optional `size` field in the hashed external URI
    // map shall not be present. Similarly, the optional `dc:format` field ...
    // shall not be present." No failure code is registered for it, so it is a
    // conformance-posture observation under an Encypher extension code.
    if !is_generous(profile) {
        for field in ["size", "dc:format"] {
            if location.get(field).is_some() {
                results.push_informational(
                    CLOUD_DATA_REDUNDANT_LOCATION_FIELD,
                    url.to_string(),
                    format!("cloud data location repeats the {field} field"),
                );
            }
        }
    }
    resolve_external_assertion(referenced, location, uri, url, evidence, results);
}

fn verify_external_reference_assertion(
    assertion: &Value,
    field: &'static str,
    generation: ClaimGeneration,
    url: &str,
    profile: EngineProfile,
    evidence: OnlineEvidence<'_>,
    results: &mut ValidationResults,
) {
    let malformed = |results: &mut ValidationResults, detail: &str| {
        results.push_failure(
            ASSERTION_EXTERNAL_REFERENCE_MALFORMED,
            url.to_string(),
            detail.to_string(),
        );
    };
    let Some(uri) = assertion
        .get("location")
        .and_then(|location| location.get("url"))
        .and_then(Value::as_text)
    else {
        malformed(results, "external reference has no location url");
        return;
    };
    let location = assertion.get("location").expect("location was just read");
    if location.get("alg").is_some() != location.get("hash").is_some() {
        malformed(
            results,
            "external reference location carries alg without hash, or hash without alg",
        );
        return;
    }
    let referenced = assertion.get("label").and_then(Value::as_text);
    if let Some(referenced) = referenced {
        if EXTERNAL_REFERENCE_FORBIDDEN_LABELS.contains(&base_assertion_label(referenced)) {
            malformed(
                results,
                &format!("external reference may not reference {referenced}"),
            );
            return;
        }
    }
    // C2PA 2.4 Standard Assertions, External Reference: the assertion "should
    // appear in `gathered_assertions`", because declaring it in
    // `created_assertions` is the signer taking responsibility for data it does
    // not carry. `assertion.external-reference.created` is the registered code
    // for that, and a SHOULD is raised to a failure only under the conformance
    // posture. A v1 claim has one undifferentiated list, so the rule cannot
    // apply to it.
    if !is_generous(profile) && generation == ClaimGeneration::V2 && field == "created_assertions" {
        results.push_failure(
            ASSERTION_EXTERNAL_REFERENCE_CREATED,
            url.to_string(),
            "external reference assertion is declared in created_assertions".into(),
        );
    }
    match referenced {
        Some(referenced) => {
            resolve_external_assertion(referenced, location, uri, url, evidence, results)
        }
        // No `label` means the reference points at arbitrary data, not at an
        // assertion, so the registered assertion code does not describe it.
        None => results.push_informational_with_details(
            EXTERNAL_REFERENCE_NOT_RETRIEVED,
            url.to_string(),
            "externally referenced data was not retrieved".into(),
            json!({ "uri": uri, "retrieval": "not_attempted" }),
        ),
    }
}

/// Report a remotely stored assertion, checking its content when a caller has
/// supplied it.
///
/// Without the bytes this records the registered `assertion.inaccessible`
/// failure plus the network need that would retrieve them. With the bytes it
/// runs C2PA 2.4 Validation, External Data Validation, Validation of External
/// References: the content is hashed with the `location` map's own algorithm
/// and compared to its `hash`.
///
/// Every status carries `external_data: true` in its details. C2PA 2.4 is
/// explicit that "the inability to retrieve or validate external data shall
/// not cause a claim to be rejected", and `assertion.hashedURI.mismatch` is
/// also the code for a claim's own broken binding, which very much does.
/// [`is_external_data_scoped`] reads the marker to tell the two apart.
fn resolve_external_assertion(
    referenced: &str,
    location: &Value,
    uri: &str,
    url: &str,
    evidence: OnlineEvidence<'_>,
    results: &mut ValidationResults,
) {
    let Some(content) = evidence
        .external_data
        .and_then(|supplied| supplied.get(uri))
    else {
        results.push_failure_with_details(
            ASSERTION_INACCESSIBLE,
            url.to_string(),
            format!("remotely stored assertion {referenced} was not retrieved"),
            json!({
                "assertion_label": referenced,
                "uri": uri,
                "retrieval": "not_attempted",
                "external_data": true,
            }),
        );
        network_needs::push_unique(
            &mut results.network_needs,
            NetworkNeed::ExternalData {
                uri: uri.to_string(),
                assertion_label: referenced.to_string(),
            },
        );
        return;
    };

    results.push_success_with_details(
        ASSERTION_ACCESSIBLE,
        url.to_string(),
        format!("remotely stored assertion {referenced} was retrieved"),
        json!({
            "assertion_label": referenced,
            "uri": uri,
            "retrieval": "caller_supplied",
            "external_data": true,
        }),
    );

    let algorithm = location.get("alg").and_then(Value::as_text);
    let expected = location.get("hash").and_then(Value::as_bytes);
    let computed = algorithm
        .filter(|algorithm| is_allowed_hash_algorithm(algorithm))
        .and_then(|algorithm| hash_bytes(algorithm, content));
    let details = json!({
        "assertion_label": referenced,
        "uri": uri,
        "external_data": true,
    });
    // Step 4b of the procedure: an absent `hash`, an algorithm this verifier
    // will not compute, and a real digest disagreement are one outcome - the
    // retrieved data is not provided to the application.
    match (computed, expected) {
        (Some(computed), Some(expected)) if computed == expected => {
            results.push_success_with_details(
                ASSERTION_HASHED_URI_MATCH,
                url.to_string(),
                format!("retrieved content for {referenced} matches its declared hash"),
                details,
            );
        }
        _ => results.push_failure_with_details(
            ASSERTION_HASHED_URI_MISMATCH,
            url.to_string(),
            format!("retrieved content for {referenced} does not match its declared hash"),
            details,
        ),
    }
}

fn referenced_action_assertions<'index, 'claim>(
    claim_refs: &'index ClaimAssertionRefs<'claim>,
    field: &str,
) -> Vec<(&'claim str, &'index Value)> {
    claim_refs
        .references
        .iter()
        .filter(|reference| reference.field == field)
        .filter_map(|reference| {
            let label = reference.label?;
            if !label.starts_with("c2pa.actions") {
                return None;
            }
            let assertion = claim_refs.indexed(label)?.decoded.as_ref()?;
            Some((label, assertion))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)] // internal assertion gate; mirrors verify_claim_structure
fn verify_action_assertions(
    claim_refs: &ClaimAssertionRefs<'_>,
    claim: &Value,
    generation: ClaimGeneration,
    manifest_kind: ManifestKind,
    store: StoreContext<'_>,
    manifest_label: &str,
    sig_url: &str,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    let created = referenced_action_assertions(
        claim_refs,
        if generation == ClaimGeneration::V1 {
            "assertions"
        } else {
            "created_assertions"
        },
    );
    let gathered = if generation == ClaimGeneration::V1 {
        Vec::new()
    } else {
        referenced_action_assertions(claim_refs, "gathered_assertions")
    };
    let fail = |results: &mut ValidationResults, code: &str, explanation: String| {
        results.push_failure(code, sig_url.to_string(), explanation);
    };

    for (label, assertion) in created.iter().chain(gathered.iter()) {
        let software_agent_count = match assertion.get("softwareAgents") {
            Some(Value::Array(values)) => values.len(),
            _ => 0,
        };
        let Some(Value::Array(actions)) = assertion.get("actions") else {
            fail(
                results,
                ASSERTION_ACTION_MALFORMED,
                format!("{label} has no actions array"),
            );
            continue;
        };
        if actions.is_empty() {
            fail(
                results,
                ASSERTION_ACTION_MALFORMED,
                format!("{label} has an empty actions array"),
            );
            continue;
        }
        for (action_index, action) in actions.iter().enumerate() {
            let Some(kind) = action.get("action").and_then(Value::as_text) else {
                fail(
                    results,
                    ASSERTION_ACTION_MALFORMED,
                    format!("{label} action {action_index} has no action"),
                );
                continue;
            };
            for error in assertion_semantics::action_shape_errors(
                action,
                software_agent_count,
                generation == ClaimGeneration::V2,
            ) {
                fail(results, ASSERTION_ACTION_MALFORMED, error);
            }

            let parameters = action.get("parameters");
            // 1.x-era v1 claims predate the ingredient-reference rules, so they
            // are held to them only under strict conformance (c2pa-rs likewise
            // skips them unless `strict_v1_validation` is set).
            let ingredient_rule = ActionIngredientRule::for_action(kind)
                .filter(|_| generation == ClaimGeneration::V2 || !is_generous(profile));
            if let Some(rule) = ingredient_rule {
                // `c2pa.actions.v2` names the field `ingredients`. `c2pa.actions`
                // names it `ingredient`, but c2pa-rs writes `ingredients` there
                // too; either spelling must still resolve and hash-match. The
                // assertion label decides, not the claim generation.
                let field = if label.starts_with("c2pa.actions.v2") {
                    parameters.and_then(|value| value.get("ingredients"))
                } else {
                    parameters.and_then(|value| {
                        value.get("ingredient").or_else(|| value.get("ingredients"))
                    })
                };
                let references: Vec<&Value> = match field {
                    Some(Value::Array(values)) => values.iter().collect(),
                    Some(value @ Value::Map(_)) if !label.starts_with("c2pa.actions.v2") => {
                        vec![value]
                    }
                    _ => Vec::new(),
                };
                let count_ok = match rule {
                    ActionIngredientRule::Opened => references.len() == 1,
                    ActionIngredientRule::Placed | ActionIngredientRule::Removed => {
                        !references.is_empty()
                    }
                    ActionIngredientRule::Derived => true,
                };
                let resolves = references.iter().all(|reference| {
                    let relationship = if rule == ActionIngredientRule::Removed {
                        foreign_ingredient_relationship(
                            reference,
                            claim,
                            store,
                            manifest_label,
                            profile,
                            results,
                        )
                    } else {
                        nested_assertion_reference_label(
                            reference,
                            claim,
                            claim_refs,
                            manifest_label,
                            profile,
                            results,
                        )
                        .filter(|target| target.starts_with("c2pa.ingredient"))
                        .and_then(|target| claim_refs.indexed(target))
                        .and_then(|assertion| assertion.decoded.as_ref())
                        .and_then(|ingredient| ingredient.get("relationship"))
                        .and_then(Value::as_text)
                        .map(str::to_string)
                    };
                    relationship.as_deref() == Some(rule.relationship())
                });
                if !(count_ok && resolves) {
                    fail(
                        results,
                        ASSERTION_ACTION_INGREDIENT_MISMATCH,
                        format!(
                            "{kind} does not resolve its {} ingredient",
                            rule.relationship()
                        ),
                    );
                }
            }

            if kind == "c2pa.redacted" {
                let has_reason = action
                    .get("reason")
                    .and_then(Value::as_text)
                    .is_some_and(|reason| !reason.is_empty());
                let redacted_resolves = parameters
                    .and_then(|value| value.get("redacted"))
                    .and_then(Value::as_text)
                    .and_then(|url| assertion_label_for_manifest(url, manifest_label))
                    .is_some_and(|target| claim_refs.indexed(target).is_some());
                if !has_reason || !redacted_resolves {
                    fail(
                        results,
                        ASSERTION_ACTION_REDACTION_MISMATCH,
                        "c2pa.redacted does not resolve its redacted assertion".into(),
                    );
                }
            }

            // C2PA 2.4 Validation, `c2pa.actions` validation: a
            // `c2pa.watermarked` or `c2pa.watermarked.bound` action requires a
            // `c2pa.soft-binding` assertion in the same manifest. Presence of
            // the assertion is the whole test; no watermark is extracted and no
            // soft binding is compared against asset content.
            if matches!(kind, "c2pa.watermarked" | "c2pa.watermarked.bound")
                && !claim_refs.declares_soft_binding()
            {
                fail(
                    results,
                    ASSERTION_ACTION_SOFT_BINDING_MISSING,
                    format!("{kind} has no c2pa.soft-binding assertion in this manifest"),
                );
            }

            if let Some(related) = parameters.and_then(|value| value.get("relatedAssertions")) {
                let valid = matches!(related, Value::Array(values) if !values.is_empty()
                && values.iter().all(|reference| {
                    nested_assertion_reference_label(
                        reference,
                        claim,
                        claim_refs,
                        manifest_label,
                        profile,
                        results,
                    )
                    .is_some_and(|target| {
                        !target.starts_with("c2pa.actions")
                            && !target.starts_with("c2pa.ingredient")
                    })
                }));
                if !valid {
                    fail(
                        results,
                        ASSERTION_ACTION_MALFORMED,
                        "relatedAssertions does not resolve eligible assertions".into(),
                    );
                }
            }
        }
    }

    // C2PA 2.4 splits the inception rules by audience. Placement and
    // cardinality are validator requirements: Validation, `c2pa.actions`
    // validation, rejects a `c2pa.created`/`c2pa.opened` that is not the first
    // element of the first actions assertion with `assertion.action.malformed`,
    // and Validation, Standard Manifest Assertions, requires the inception
    // action in exactly one actions assertion. Both hold in the default posture.
    // 1.x-era v1 claims predate them and are held to them only under strict
    // conformance, the same policy the v1 ingredient rules above use.
    if generation == ClaimGeneration::V1 && is_generous(profile) {
        return;
    }
    let is_inception = |action: &Value| {
        matches!(
            action.get("action").and_then(Value::as_text),
            Some("c2pa.created" | "c2pa.opened")
        )
    };
    let mut inception_assertions = 0usize;
    let mut inception_action = None;
    // "the first actions assertion in the `created_assertions` or
    // `gathered_assertions` array (of a v2 claim), or the first actions
    // assertion in the `assertions` array of a v1 claim" - each list is
    // indexed on its own, so either list's first actions assertion may open
    // the manifest. Carrying one in both is then caught by the cardinality
    // rule below.
    for list in [&created, &gathered] {
        for (assertion_index, (label, assertion)) in list.iter().enumerate() {
            let Some(Value::Array(actions)) = assertion.get("actions") else {
                continue;
            };
            let mut carries_inception = false;
            for (action_index, action) in actions.iter().enumerate() {
                if !is_inception(action) {
                    continue;
                }
                carries_inception = true;
                if assertion_index == 0 && action_index == 0 {
                    inception_action = Some(action);
                } else {
                    fail(
                        results,
                        ASSERTION_ACTION_MALFORMED,
                        format!(
                            "{label} places c2pa.created or c2pa.opened outside the first action of the first actions assertion"
                        ),
                    );
                }
            }
            if carries_inception {
                inception_assertions += 1;
            }
        }
    }
    // Update manifests are exempt. C2PA 2.4 Validation states the inception
    // requirement under Standard Manifest Assertions only, and Manifests,
    // Update Manifests, permits an update to carry just `c2pa.edited.metadata`,
    // `c2pa.opened`, `c2pa.published` or `c2pa.redacted`. Whatever actions an
    // update does carry are still checked against that allowlist elsewhere.
    if manifest_kind == ManifestKind::Standard && inception_assertions != 1 {
        fail(
            results,
            ASSERTION_ACTION_MALFORMED,
            format!(
                "standard manifest carries a c2pa.created or c2pa.opened action in {inception_assertions} actions assertions, expected exactly one"
            ),
        );
    }

    // A claim-generator requirement rather than a validator step: C2PA 2.4
    // Actions requires a `digitalSourceType` on the `c2pa.created` action, and
    // the Validation chapter never asks a validator to check it. Strict
    // conformance only.
    if is_generous(profile) || generation == ClaimGeneration::V1 {
        return;
    }
    if let Some(action) = inception_action {
        if action.get("action").and_then(Value::as_text) == Some("c2pa.created")
            && action
                .get("digitalSourceType")
                .and_then(Value::as_text)
                .is_none()
        {
            fail(
                results,
                ASSERTION_ACTION_MALFORMED,
                "c2pa.created action has no digitalSourceType".into(),
            );
        }
    }
}

/// The ingredient an action must (or may) reference, per the C2PA 2.4
/// `c2pa.actions` validation rules.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionIngredientRule {
    /// Exactly one parentOf ingredient in this manifest.
    Opened,
    /// One or more componentOf ingredients in this manifest.
    Placed,
    /// One or more componentOf ingredients in another manifest.
    Removed,
    /// `c2pa.transcoded`/`c2pa.repackaged`: optional parentOf ingredients.
    Derived,
}

impl ActionIngredientRule {
    fn for_action(kind: &str) -> Option<Self> {
        match kind {
            "c2pa.opened" => Some(Self::Opened),
            "c2pa.placed" => Some(Self::Placed),
            "c2pa.removed" => Some(Self::Removed),
            "c2pa.transcoded" | "c2pa.repackaged" => Some(Self::Derived),
            _ => None,
        }
    }

    fn relationship(self) -> &'static str {
        match self {
            Self::Opened | Self::Derived => "parentOf",
            Self::Placed | Self::Removed => "componentOf",
        }
    }
}

/// The `relationship` of the ingredient assertion a hashed URI names in a
/// manifest other than `manifest_label`, once the URI's hash matches that
/// assertion's JUMBF content.
fn foreign_ingredient_relationship(
    reference: &Value,
    claim: &Value,
    store: StoreContext<'_>,
    manifest_label: &str,
    _profile: EngineProfile,
    results: &mut ValidationResults,
) -> Option<String> {
    let url = reference.get("url").and_then(Value::as_text)?;
    let (target_manifest, label) = url
        .strip_prefix("self#jumbf=/c2pa/")?
        .split_once("/c2pa.assertions/")?;
    if target_manifest == manifest_label
        || !label.starts_with("c2pa.ingredient")
        || label.contains('/')
    {
        return None;
    }
    let manifest = store
        .manifests
        .iter()
        .find(|manifest| manifest.label == target_manifest)?;
    // A label that occurs twice cannot be resolved unambiguously.
    fn unique<'a>(entries: &[(String, &'a [u8])], label: &str) -> Option<&'a [u8]> {
        let mut matches = entries.iter().filter(|(name, _)| name == label);
        let (_, bytes) = matches.next()?;
        matches.next().is_none().then_some(*bytes)
    }
    let content = unique(&manifest.assertion_jumbf, label)?;
    let expected = reference.get("hash").and_then(Value::as_bytes)?;
    let Some(algorithm) = resolved_hash_algorithm(reference, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            "nested ingredient reference has no hash algorithm".into(),
        );
        return None;
    };
    if !is_allowed_hash_algorithm(algorithm) {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("nested ingredient reference uses unsupported hash algorithm '{algorithm}'"),
        );
        return None;
    }
    if hash_bytes(algorithm, content)?.as_slice() != expected {
        return None;
    }
    decode(unique(&manifest.assertions, label)?)
        .ok()?
        .get("relationship")
        .and_then(Value::as_text)
        .map(str::to_string)
}

fn nested_assertion_reference_label<'a>(
    reference: &'a Value,
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    manifest_label: &str,
    _profile: EngineProfile,
    results: &mut ValidationResults,
) -> Option<&'a str> {
    let url = reference.get("url").and_then(Value::as_text)?;
    let label = assertion_label_for_manifest(url, manifest_label)?;
    let assertion = claim_refs.indexed(label)?;
    let content = assertion.jumbf?;
    let expected = reference.get("hash").and_then(Value::as_bytes)?;
    let Some(algorithm) = resolved_hash_algorithm(reference, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            "nested assertion reference has no hash algorithm".into(),
        );
        return None;
    };
    if !is_allowed_hash_algorithm(algorithm) {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("nested assertion reference uses unsupported hash algorithm '{algorithm}'"),
        );
        return None;
    }
    hash_bytes(algorithm, content)
        .is_some_and(|actual| actual.as_slice() == expected)
        .then_some(label)
}

fn verify_ingredient_shapes(
    manifest: &ParsedManifest<'_>,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| label.starts_with("c2pa.ingredient"))
        else {
            continue;
        };
        let Some(ingredient) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        if let Some(error) = assertion_semantics::ingredient_shape_error(ingredient) {
            results.push_failure(
                ASSERTION_INGREDIENT_MALFORMED,
                format!(
                    "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                    manifest.label
                ),
                error,
            );
        }
    }
}

fn verify_alternative_content(
    manifest: &ParsedManifest<'_>,
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    let representations: Vec<(&str, &Value)> = claim_refs
        .references
        .iter()
        .filter_map(|reference| {
            let label = reference
                .label
                .filter(|label| label.starts_with("c2pa.alternative-content-representation"))?;
            let assertion = claim_refs.indexed(label)?.decoded.as_ref()?;
            (assertion.get("type").and_then(Value::as_text)
                == Some("exif.originalPreservationImage"))
            .then_some((label, assertion))
        })
        .collect();
    if representations.is_empty() {
        return;
    }
    let multi_asset_part_count = claim_refs.references.iter().find_map(|reference| {
        let label = reference
            .label
            .filter(|label| label.starts_with("c2pa.hash.multi-asset"))?;
        match claim_refs.indexed(label)?.decoded.as_ref()?.get("parts")? {
            Value::Array(parts) => Some(parts.len()),
            _ => None,
        }
    });
    for (label, assertion) in &representations {
        let url = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
            manifest.label
        );
        if representations.len() > 1 {
            results.push_failure(
                ASSERTION_ALTERNATIVE_CONTENT_MALFORMED,
                url,
                "manifest contains more than one original preservation representation".into(),
            );
            continue;
        }
        let Some(parameters) = assertion.get("parameters") else {
            results.push_failure(
                ASSERTION_ALTERNATIVE_CONTENT_MALFORMED,
                url,
                "alternative content representation has no parameters".into(),
            );
            continue;
        };
        if let Some(error) =
            assertion_semantics::alternative_content_shape_error(parameters, multi_asset_part_count)
        {
            results.push_failure(ASSERTION_ALTERNATIVE_CONTENT_MALFORMED, url, error);
            continue;
        }
        if let Some(embedded) = parameters.get("embeddedOriginalPreservationImage") {
            let target = embedded
                .get("url")
                .and_then(Value::as_text)
                .and_then(|target| assertion_label_for_manifest(target, &manifest.label))
                .and_then(|target| claim_refs.indexed(target));
            let Some(content) = target.and_then(|assertion| assertion.jumbf) else {
                results.push_failure(
                    ASSERTION_ALTERNATIVE_CONTENT_MALFORMED,
                    url,
                    "embedded representation does not resolve inside the manifest".into(),
                );
                continue;
            };
            let expected = embedded.get("hash").and_then(Value::as_bytes);
            let Some(algorithm) = resolved_hash_algorithm(embedded, claim) else {
                results.push_failure(
                    ALGORITHM_UNSUPPORTED,
                    url,
                    "embedded representation has no hash algorithm".into(),
                );
                continue;
            };
            if !is_allowed_hash_algorithm(algorithm) {
                results.push_failure(
                    ALGORITHM_UNSUPPORTED,
                    url,
                    format!(
                        "embedded representation uses unsupported hash algorithm '{algorithm}'"
                    ),
                );
                continue;
            }
            let actual = hash_bytes(algorithm, content);
            if !matches!((actual, expected), (Some(actual), Some(expected)) if actual.as_slice() == expected)
            {
                results.push_failure(
                    ASSERTION_ALTERNATIVE_CONTENT_HASH_MISMATCH,
                    url,
                    "embedded representation hash does not match".into(),
                );
                continue;
            }
        }
        results.push_success(
            ASSERTION_ALTERNATIVE_CONTENT_MATCH,
            url,
            "alternative content representation validated".into(),
        );
    }
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

fn resolved_hash_algorithm<'a>(value: &'a Value, enclosing: &'a Value) -> Option<&'a str> {
    value
        .get("alg")
        .and_then(Value::as_text)
        .or_else(|| enclosing.get("alg").and_then(Value::as_text))
}

struct IngredientManifestDigestCache<'a> {
    store: StoreContext<'a>,
    digests: std::collections::HashMap<(&'a str, usize), Vec<u8>>,
}

impl<'a> IngredientManifestDigestCache<'a> {
    fn new(store: StoreContext<'a>) -> Self {
        Self {
            store,
            digests: std::collections::HashMap::new(),
        }
    }

    fn matches(
        &mut self,
        manifest: &'a ParsedManifest<'a>,
        algorithm_index: usize,
        expected: &[u8],
    ) -> bool {
        if algorithm_index == 0 {
            return self
                .store
                .manifest_hashes
                .get(&manifest.label)
                .is_some_and(|digests| digests.matches(0, &digests.expanded_sha256, expected));
        }
        let digest = self
            .digests
            .entry((manifest.label.as_str(), algorithm_index))
            .or_insert_with(|| match algorithm_index {
                1 => Sha384::digest(manifest.manifest_jumbf).to_vec(),
                2 => Sha512::digest(manifest.manifest_jumbf).to_vec(),
                _ => unreachable!("algorithm index prevalidated"),
            });
        self.store
            .manifest_hashes
            .get(&manifest.label)
            .is_some_and(|digests| digests.matches(algorithm_index, digest, expected))
    }
}

/// Authenticate embedded provenance references carried by ingredient assertions.
///
/// An exact `activeManifest` hash authenticates the complete child manifest and
/// short-circuits `claimSignature`, matching the C2PA validation procedure. If
/// the parent claim redacts assertions from that child, the full manifest must
/// differ and `claimSignature` becomes the required fallback binding.
fn verify_ingredient_references<'a>(
    manifest_label: &str,
    claim_refs: &ClaimAssertionRefs<'_>,
    claim: &Value,
    digest_cache: &mut IngredientManifestDigestCache<'a>,
    sig_url: &str,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    for reference in &claim_refs.references {
        let Some(assertion_label) = reference.label else {
            continue;
        };
        if !assertion_label.starts_with("c2pa.ingredient") {
            continue;
        }
        let Some(ingredient) = claim_refs
            .indexed(assertion_label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let active_manifest = ingredient.get("activeManifest");
        let legacy_manifest = ingredient.get("c2pa_manifest");
        let Some(manifest_reference) = active_manifest.or(legacy_manifest) else {
            // C2PA 2.4, "Performing recursive validation": an ingredient with
            // no `activeManifest` (or v1/v2 `c2pa_manifest`) link has no
            // provenance to validate, which is recorded informationally unless
            // the ingredient is only an input to this manifest.
            if ingredient.get("relationship").and_then(Value::as_text) != Some("inputTo") {
                results.push_informational(
                    INGREDIENT_UNKNOWN_PROVENANCE,
                    format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{assertion_label}"),
                    format!("ingredient '{assertion_label}' has no C2PA manifest"),
                );
            }
            continue;
        };
        let supports_signature_fallback = active_manifest.is_some();
        // Only the legacy `c2pa_manifest` link may carry the C2PA 1.0 claim
        // hash, and only the default posture reads it (1.x content rule).
        let accept_legacy_claim_hash = active_manifest.is_none() && is_generous(profile);
        if verify_ingredient_manifest_reference(
            manifest_reference,
            claim,
            digest_cache,
            sig_url,
            supports_signature_fallback,
            accept_legacy_claim_hash,
            results,
        ) {
            if let Some(claim_signature) = ingredient.get("claimSignature") {
                verify_ingredient_signature_reference(
                    claim_signature,
                    claim,
                    digest_cache.store,
                    sig_url,
                    results,
                );
            } else {
                results.push_failure(
                    INGREDIENT_CLAIM_SIGNATURE_MISSING,
                    sig_url.to_string(),
                    "redacted ingredient is missing claimSignature".into(),
                );
            }
        }
    }
}

/// Validate `activeManifest`; return true only when redaction requires the
/// caller to authenticate the child through `claimSignature` instead.
fn verify_ingredient_manifest_reference<'a>(
    reference: &Value,
    claim: &Value,
    digest_cache: &mut IngredientManifestDigestCache<'a>,
    fallback_url: &str,
    allow_signature_fallback: bool,
    accept_legacy_claim_hash: bool,
    results: &mut ValidationResults,
) -> bool {
    let url = reference
        .get("url")
        .and_then(Value::as_text)
        .unwrap_or(fallback_url);
    let Some(label) = ingredient_manifest_label(url, None) else {
        results.push_failure(
            INGREDIENT_MANIFEST_MISSING,
            url.to_string(),
            "ingredient activeManifest does not resolve to a manifest".into(),
        );
        return false;
    };
    let store = digest_cache.store;
    let actual_manifest = store
        .manifests
        .iter()
        .find(|manifest| manifest.label == label);
    let Some(actual_manifest) = actual_manifest else {
        results.push_failure(
            INGREDIENT_MANIFEST_MISSING,
            url.to_string(),
            format!("ingredient references manifest '{label}' not in store"),
        );
        return false;
    };
    let Some(algorithm) = resolved_hash_algorithm(reference, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            "ingredient manifest reference has no hash algorithm".into(),
        );
        return false;
    };
    let Some(algorithm_index) = bmff_algorithm_index(algorithm) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("ingredient manifest uses unsupported hash algorithm '{algorithm}'"),
        );
        return false;
    };
    let expected = reference.get("hash").and_then(Value::as_bytes);
    if expected
        .is_some_and(|expected| digest_cache.matches(actual_manifest, algorithm_index, expected))
    {
        results.push_success(
            INGREDIENT_MANIFEST_VALIDATED,
            url.to_string(),
            "ingredient manifest hash matched".into(),
        );
        return false;
    }
    if allow_signature_fallback && claim_redacts_manifest(claim, label) {
        return true;
    }
    // C2PA 1.0 hashed the ingredient link over the ingredient's claim bytes.
    // Those bytes are authenticated by the ingredient's own claim signature,
    // which recursive ingredient validation checks, so the weaker link is
    // accepted and reported, never upgraded to `ingredient.manifest.validated`.
    if accept_legacy_claim_hash
        && actual_manifest
            .claim_cbor
            .and_then(|claim_bytes| hash_bytes(algorithm, claim_bytes))
            .is_some_and(|actual| expected == Some(actual.as_slice()))
    {
        results.push_informational(
            INGREDIENT_LEGACY_CLAIM_HASH,
            url.to_string(),
            "ingredient link matches the C2PA 1.0 claim hash, not the manifest-box hash".into(),
        );
        return false;
    }
    results.push_failure(
        INGREDIENT_MANIFEST_MISMATCH,
        url.to_string(),
        "ingredient manifest hash mismatch".into(),
    );
    false
}

/// Whether a redaction the claim lawfully declared removed an assertion from
/// `manifest_label`, which selects the claim-signature hash validation method
/// for that ingredient. Unlawful declarations do not count: see
/// [`redaction::redacts_manifest`].
fn claim_redacts_manifest(claim: &Value, manifest_label: &str) -> bool {
    redaction::redacts_manifest(claim, manifest_label)
}

fn verify_ingredient_signature_reference(
    reference: &Value,
    claim: &Value,
    store: StoreContext<'_>,
    fallback_url: &str,
    results: &mut ValidationResults,
) {
    let url = reference
        .get("url")
        .and_then(Value::as_text)
        .unwrap_or(fallback_url);
    let Some(label) = ingredient_manifest_label(url, Some("/c2pa.signature")) else {
        results.push_failure(
            INGREDIENT_CLAIM_SIGNATURE_MISSING,
            url.to_string(),
            "ingredient claimSignature does not resolve to a claim-signature box".into(),
        );
        return;
    };
    let signature = store
        .manifests
        .iter()
        .find(|manifest| manifest.label == label)
        .and_then(|manifest| manifest.signature_cose);
    let Some(actual) = signature else {
        results.push_failure(
            INGREDIENT_CLAIM_SIGNATURE_MISSING,
            url.to_string(),
            format!("ingredient references missing claim signature in manifest '{label}'"),
        );
        return;
    };
    let Some(algorithm) = resolved_hash_algorithm(reference, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            "ingredient claim signature reference has no hash algorithm".into(),
        );
        return;
    };
    let Some(digest) = hash_claim_signature_box(algorithm, actual) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url.to_string(),
            format!("ingredient claim signature uses unsupported hash algorithm '{algorithm}'"),
        );
        return;
    };
    if reference.get("hash").and_then(Value::as_bytes) == Some(digest.as_slice()) {
        results.push_success(
            INGREDIENT_CLAIM_SIGNATURE_VALIDATED,
            url.to_string(),
            "ingredient claim signature hash matched".into(),
        );
    } else {
        results.push_failure(
            INGREDIENT_CLAIM_SIGNATURE_MISMATCH,
            url.to_string(),
            "ingredient claim signature hash mismatch".into(),
        );
    }
}

fn claim_signature_uri_is_local(uri: &str, manifest_label: &str) -> bool {
    uri == "self#jumbf=c2pa.signature"
        || uri
            .strip_prefix("self#jumbf=/c2pa/")
            .and_then(|target| target.strip_suffix("/c2pa.signature"))
            .is_some_and(|target| target == manifest_label && !target.contains('/'))
}

/// Return the exact manifest label from an absolute ingredient hashed URI.
/// Legacy vendor-prefixed UUID labels remain valid input, so the store lookup,
/// not a `urn:c2pa:` prefix test, decides whether the label is known.
fn ingredient_manifest_label<'a>(url: &'a str, suffix: Option<&str>) -> Option<&'a str> {
    let rest = url.strip_prefix("self#jumbf=/c2pa/")?;
    let label = match suffix {
        Some(suffix) => rest.strip_suffix(suffix)?,
        None => rest,
    };
    (!label.is_empty() && !label.contains('/')).then_some(label)
}

/// Extract a manifest label from an absolute JUMBF URI that may name one of
/// the manifest's child boxes.
fn extract_manifest_label(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("self#jumbf=/c2pa/")?;
    let label = rest.split('/').next()?;
    (!label.is_empty()).then_some(label)
}

/// Every manifest label the store's ingredient assertions point at.
///
/// Used by VAL-TIME-0008 to decide which manifests sit in an ingredient
/// position: a time-stamp manifest is never itself an ingredient, while a
/// time-stamp manifest reached through an ingredient always is.
fn ingredient_manifest_labels(
    manifests: &[ParsedManifest<'_>],
) -> std::collections::HashSet<String> {
    let mut labels = std::collections::HashSet::new();
    for manifest in manifests {
        for (assertion_label, payload) in &manifest.assertions {
            if !assertion_label.starts_with("c2pa.ingredient") {
                continue;
            }
            let Ok(ingredient) = decode(payload) else {
                continue;
            };
            for field in ["activeManifest", "c2pa_manifest"] {
                let url = ingredient
                    .get(field)
                    .and_then(|reference| reference.get("url"))
                    .and_then(Value::as_text);
                if let Some(label) = url.and_then(extract_manifest_label) {
                    labels.insert(label.to_string());
                }
            }
        }
    }
    labels
}

/// The claim fields that carry hashed-URI assertion references for a claim
/// generation.
fn ref_fields(generation: ClaimGeneration) -> &'static [&'static str] {
    match generation {
        ClaimGeneration::V1 => &["assertions"],
        ClaimGeneration::V2 => &["created_assertions", "gathered_assertions"],
    }
}
fn is_generator_icon_label(label: &str) -> bool {
    label == "c2pa.icon"
        || label
            .strip_prefix("c2pa.icon__")
            .and_then(|suffix| suffix.parse::<usize>().ok())
            .is_some_and(|instance| instance > 0)
}

fn assertion_label_for_manifest<'a>(url: &'a str, manifest_label: &str) -> Option<&'a str> {
    if let Some(label) = url.strip_prefix("self#jumbf=c2pa.assertions/") {
        return (!label.is_empty() && !label.contains('/')).then_some(label);
    }
    let rest = url.strip_prefix("self#jumbf=/c2pa/")?;
    let rest = rest.strip_prefix(manifest_label)?;
    let label = rest.strip_prefix("/c2pa.assertions/")?;
    (!label.is_empty() && !label.contains('/')).then_some(label)
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
    claim_refs: &mut ClaimAssertionRefs<'_>,
    generation: ClaimGeneration,
    label: &str,
    _profile: EngineProfile,
    results: &mut ValidationResults,
) {
    let references = &claim_refs.references;
    let assertions = &mut claim_refs.assertions;
    for indexed_reference in references {
        let reference = indexed_reference.value;
        let resolved_label = indexed_reference.label;
        let Some(url) = reference.get("url").and_then(Value::as_text) else {
            results.push_failure(
                CLAIM_MALFORMED,
                format!("self#jumbf=/c2pa/{label}/c2pa.claim"),
                "claim assertion reference has no textual url".into(),
            );
            continue;
        };
        let Some(assertion_label) = resolved_label else {
            results.push_failure(
                ASSERTION_OUTSIDE_MANIFEST,
                url.to_string(),
                "assertion reference names a location outside the current manifest".into(),
            );
            continue;
        };
        let assertion_url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{assertion_label}");
        let expected = reference.get("hash").and_then(Value::as_bytes);
        let Some(algorithm) = resolved_hash_algorithm(reference, claim) else {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                assertion_url,
                "hashed-URI reference has no hash algorithm".into(),
            );
            continue;
        };
        if !is_allowed_hash_algorithm(algorithm) {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                assertion_url,
                format!("hashed-URI reference uses unsupported hash algorithm '{algorithm}'"),
            );
            continue;
        }
        let content_matches = match (
            bmff_algorithm_index(algorithm),
            assertions.get_mut(assertion_label),
            expected,
        ) {
            (Some(index), Some(assertion), Some(expected_hash)) => {
                if assertion.jumbf_digests[index].is_none() {
                    assertion.jumbf_digests[index] = assertion
                        .jumbf
                        .and_then(|bytes| hash_bytes(algorithm, bytes));
                }
                assertion.jumbf_digests[index].as_deref() == Some(expected_hash)
            }
            _ => false,
        };
        let (content, legacy_payload) = assertions
            .get(assertion_label)
            .map(|assertion| (assertion.jumbf, assertion.payload))
            .unwrap_or((None, None));
        let legacy_payload_matches = !content_matches
            && generation == ClaimGeneration::V1
            && matches!(
                (
                    legacy_payload.and_then(|payload| hash_bytes(algorithm, payload)),
                    expected,
                ),
                (Some(actual), Some(expected_hash)) if actual.as_slice() == expected_hash
            );
        if content_matches || legacy_payload_matches {
            results.push_success(
                ASSERTION_HASHED_URI_MATCH,
                assertion_url,
                format!("hashed uri matched: self#jumbf=c2pa.assertions/{assertion_label}"),
            );
        } else if content.is_none() {
            results.push_failure(
                ASSERTION_MISSING,
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
    claim_refs: &ClaimAssertionRefs<'_>,
    label: &str,
    manifest_hashes: &std::collections::HashMap<String, ManifestDigests>,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{COMPOUND_CONTENT_LABEL}");
    if claim_refs
        .binding_plan(true)
        .primary()
        .and_then(|reference| reference.label)
        != Some(COMPOUND_CONTENT_LABEL)
    {
        return;
    }
    let Some(data) = claim_refs
        .indexed(COMPOUND_CONTENT_LABEL)
        .and_then(|assertion| assertion.decoded.as_ref())
    else {
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
    let mut local_digests = std::collections::HashMap::<&str, Vec<u8>>::new();
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
        let Some(alabel) = assertion_label_for_manifest(ref_url, label) else {
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
        // 1) The component binds the ingredient assertion's exact JUMBF
        // content. Reuse the claim-binding digest when the algorithm matches;
        // otherwise hash this label+algorithm once for all components.
        let digest = if let Some(digest) = claim_refs.jumbf_digest(alabel, alg) {
            Some(digest)
        } else if let Some(digest) = local_digests.get(alabel) {
            Some(digest.as_slice())
        } else {
            let Some(content) = claim_refs
                .indexed(alabel)
                .and_then(|assertion| assertion.jumbf)
            else {
                results.push_failure(
                    ASSERTION_COMPOUND_CONTENT_MISMATCH,
                    url.clone(),
                    format!("compound component {idx} ingredient assertion '{alabel}' not present"),
                );
                return;
            };
            let Some(computed) = hash_bytes(alg, content) else {
                results.push_failure(
                    ASSERTION_COMPOUND_CONTENT_MALFORMED,
                    url.clone(),
                    format!("compound component {idx} ingredientRef uses unsupported alg {alg:?}"),
                );
                return;
            };
            Some(local_digests.entry(alabel).or_insert(computed).as_slice())
        };
        if digest != Some(expected) {
            results.push_failure(
                ASSERTION_COMPOUND_CONTENT_MISMATCH,
                url.clone(),
                format!("compound component {idx} ingredientRef hash did not match '{alabel}'"),
            );
            return;
        }
        // 2) The ingredient assertion must be a componentOf with an activeManifest.
        let Some(ing) = claim_refs
            .indexed(alabel)
            .and_then(|assertion| assertion.decoded.as_ref())
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
            .and_then(|cl| manifest_hashes.get(cl))
            .is_some_and(|digests| digests.matches(0, &digests.expanded_sha256, child_hash));
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

fn parent_reference_validated(
    results: &ValidationResults,
    success_start: usize,
    parent_label: &str,
) -> bool {
    results.success[success_start..].iter().any(|status| {
        (status.code == INGREDIENT_MANIFEST_VALIDATED
            && ingredient_manifest_label(&status.url, None) == Some(parent_label))
            || (status.code == INGREDIENT_CLAIM_SIGNATURE_VALIDATED
                && ingredient_manifest_label(&status.url, Some("/c2pa.signature"))
                    == Some(parent_label))
    })
}

/// The hard binding an update manifest is validated against: the one declared
/// by the first standard manifest in its `parentOf` chain.
///
/// C2PA 2.4 Validation, "Validate the Asset's Content": "If the active manifest
/// is an update manifest, the hard binding shall be found in the `parentOf`
/// ingredient's manifest, or if that manifest is also an update manifest, by
/// following the chain of `parentOf` ingredients to the first standard
/// manifest." A CAWG identity inside an update manifest references that
/// binding, because the update manifest is forbidden to carry one of its own.
///
/// `None` for a standard manifest, and for any update manifest whose chain does
/// not reach exactly one hard binding; the chain's own defects are reported by
/// [`verify_claim_structure`] and [`verify_update_hard_binding`].
fn inherited_hard_binding(
    active: &ParsedManifest<'_>,
    store: StoreContext<'_>,
) -> Option<(String, Value, Option<String>)> {
    if active.kind() != ManifestKind::Update {
        return None;
    }
    let standard = update_manifest::resolve_standard(active, store.manifests).ok()?;
    let claim = standard.claim_cbor.and_then(|bytes| decode(bytes).ok())?;
    let generation = versions::claim_generation(standard, &claim);
    let claim_refs = ClaimAssertionRefs::build(standard, &claim, generation);
    let binding = claim_refs.binding_plan(false).primary()?;
    let claim_alg = claim
        .get("alg")
        .and_then(Value::as_text)
        .map(str::to_string);
    Some((standard.label.clone(), binding.value.clone(), claim_alg))
}

/// Validate an update manifest's inherited hard binding.
///
/// The active update authenticates its `parentOf` manifest before this runs.
/// The parent standard claim then authenticates its own hard-binding assertion,
/// whose exclusions are evaluated against the current asset rendition.
#[allow(clippy::too_many_arguments)]
fn verify_update_hard_binding(
    active: &ParsedManifest<'_>,
    store: StoreContext<'_>,
    data: &[u8],
    format: AssetFormat,
    fragments: &[&[u8]],
    prehashed_digest: Option<&[u8]>,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    let Ok(direct_parent) = update_manifest::resolve_parent(active, store.manifests) else {
        return;
    };
    if !parent_reference_validated(results, 0, &direct_parent.label) {
        return;
    }
    let Ok(standard) = update_manifest::resolve_standard(active, store.manifests) else {
        return;
    };
    let mut current = active;
    let mut digest_cache = IngredientManifestDigestCache::new(store);
    while let Ok(parent) = update_manifest::resolve_parent(current, store.manifests) {
        if parent.label == standard.label {
            break;
        }
        let Some(parent_claim) = parent.claim_cbor.and_then(|bytes| decode(bytes).ok()) else {
            return;
        };
        let parent_generation = versions::claim_generation(parent, &parent_claim);
        let mut parent_refs = ClaimAssertionRefs::build(parent, &parent_claim, parent_generation);
        let failures_before = results.failure.len();
        let successes_before = results.success.len();
        verify_assertion_bindings(
            &parent_claim,
            &mut parent_refs,
            parent_generation,
            &parent.label,
            profile,
            results,
        );
        verify_ingredient_references(
            &parent.label,
            &parent_refs,
            &parent_claim,
            &mut digest_cache,
            &format!("self#jumbf=/c2pa/{}/c2pa.signature", parent.label),
            profile,
            results,
        );
        let Ok(next_parent) = update_manifest::resolve_parent(parent, store.manifests) else {
            return;
        };
        if results.failure.len() != failures_before
            || !parent_reference_validated(results, successes_before, &next_parent.label)
        {
            return;
        }
        current = parent;
    }
    let Some(claim) = standard.claim_cbor.and_then(|bytes| decode(bytes).ok()) else {
        return;
    };
    let generation = versions::claim_generation(standard, &claim);
    let mut claim_refs = ClaimAssertionRefs::build(standard, &claim, generation);
    verify_assertion_bindings(
        &claim,
        &mut claim_refs,
        generation,
        &standard.label,
        profile,
        results,
    );
    if let Some(digest) = prehashed_digest {
        let _ =
            verify_prehashed_hard_binding(&claim, &claim_refs, digest, &standard.label, results);
    } else {
        // The active manifest is an update, so the store the standard claim
        // signed its exclusions against has since grown (C2PA 2.4, Validating
        // a data hash).
        let _ = verify_data_hash(
            &claim,
            &claim_refs,
            data,
            format,
            fragments,
            update_manifest::StoreRendition::WithUpdates,
            &standard.label,
            profile,
            results,
        );
    }
}

/// Confirm that a caller-computed digest is the active claim's sole supported
/// hard binding. Generalized box, collection, multi-asset, and merkle bindings
/// require source bytes that this detached verification entry point does not
/// accept, so it rejects those forms.
fn verify_prehashed_hard_binding<'index, 'claim>(
    claim: &Value,
    claim_refs: &'index ClaimAssertionRefs<'claim>,
    digest: &[u8],
    label: &str,
    results: &mut ValidationResults,
) -> Option<OperativeBinding<'index, 'claim>> {
    let Some(binding) = claim_refs.binding_plan(false).primary() else {
        results.push_failure(
            ASSERTION_DATA_HASH_MISMATCH,
            format!("self#jumbf=/c2pa/{label}/c2pa.assertions"),
            "detached verification requires exactly one supported hard binding".into(),
        );
        return None;
    };
    let assertion_label = binding.label?;
    if !is_supported_whole_asset_hash_label(assertion_label) {
        results.push_failure(
            ASSERTION_DATA_HASH_MISMATCH,
            format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{assertion_label}"),
            "detached verification requires a data or BMFF hard binding".into(),
        );
        return None;
    }
    let is_bmff = is_supported_bmff_hash_label(assertion_label);
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
    let Some(assertion) = claim_refs
        .indexed(assertion_label)
        .and_then(|assertion| assertion.decoded.as_ref())
    else {
        results.push_failure(
            mismatch_code,
            url,
            "hard-binding assertion CBOR invalid".into(),
        );
        return None;
    };
    let Some(algorithm) = resolved_hash_algorithm(assertion, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            "hard-binding assertion has no hash algorithm".into(),
        );
        return None;
    };
    if bmff_algorithm_index(algorithm).is_none() {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            format!("hard-binding assertion uses unsupported hash algorithm '{algorithm}'"),
        );
        return None;
    }
    if algorithm != "sha256" || assertion.get("merkle").is_some() || digest.len() != 32 {
        results.push_failure(
            mismatch_code,
            url,
            "detached verification supports one non-merkle SHA-256 hard binding; multi-asset parts are unavailable on this entry point".into(),
        );
        return None;
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
        Some(OperativeBinding::Primary(binding))
    } else {
        if expected != Some(digest) {
            results.push_failure(mismatch_code, url, "hard-binding digest mismatch".into());
        }
        None
    }
}

/// Verify the `c2pa.hash.data` hard binding against the asset bytes.
///
/// Verify the asset hard binding (`c2pa.hash.data`, `c2pa.hash.bmff.v2`, or
/// `c2pa.hash.bmff.v3`).
///
/// `c2pa.hash.data` excludes byte ranges given as `{start, length}`. BMFF hash
/// assertions exclude whole boxes by `xpath` and, in the merkle variant, carry
/// a `merkle` array of per-chunk hashes. The simple (non-merkle) BMFF case is
/// verified by resolving the box paths to byte ranges; the merkle variant
/// verifies the `initHash` over this asset and, when `fragments` are supplied,
/// every fragment's Merkle leaf.
fn is_standard_primary_mismatch(label: &str, status: &StatusCode) -> bool {
    match label {
        "c2pa.hash.data" => {
            status.code == ASSERTION_DATA_HASH_MISMATCH
                && status.explanation == "asset hash mismatch"
        }
        "c2pa.hash.boxes" => {
            status.code == ASSERTION_BOXES_HASH_MISMATCH
                && status.explanation != "box entry missing hash"
        }
        "c2pa.hash.collection.data" => status.code == ASSERTION_COLLECTION_HASH_MISMATCH,
        _ if is_supported_bmff_hash_label(label) => status.code == ASSERTION_BMFF_HASH_MISMATCH,
        _ => false,
    }
}
fn is_primary_binding_match(label: &str, status: &StatusCode) -> bool {
    match label {
        "c2pa.hash.data" => status.code == ASSERTION_DATA_HASH_MATCH,
        "c2pa.hash.boxes" => status.code == ASSERTION_BOXES_HASH_MATCH,
        "c2pa.hash.collection.data" => status.code == ASSERTION_COLLECTION_HASH_MATCH,
        _ if is_supported_bmff_hash_label(label) => status.code == ASSERTION_BMFF_HASH_MATCH,
        _ => false,
    }
}

/// Execute the one primary binding first. A single multi-asset assertion is a
/// fallback, never a peer hard binding: it is evaluated only after an ordinary
/// byte mismatch. Structural, malformed, missing, and unsupported failures
/// remain attached to the primary and do not activate the fallback.
#[allow(clippy::too_many_arguments)]
fn verify_data_hash<'index, 'claim>(
    claim: &Value,
    claim_refs: &'index ClaimAssertionRefs<'claim>,
    data: &[u8],
    format: AssetFormat,
    fragments: &[&[u8]],
    rendition: update_manifest::StoreRendition,
    label: &str,
    profile: EngineProfile,
    results: &mut ValidationResults,
) -> Option<OperativeBinding<'index, 'claim>> {
    let plan = claim_refs.binding_plan(format == AssetFormat::C2paStore);
    let primary = plan.primary()?;
    let primary_label = primary.label?;
    if primary_label == COMPOUND_CONTENT_LABEL {
        return None;
    }

    let binding_compromised = results.has_failure(ASSERTION_HASHED_URI_MISMATCH)
        || results.has_failure(HASHED_URI_MISSING);
    let failure_start = results.failure.len();
    let success_start = results.success.len();
    verify_primary_hard_binding(
        claim, claim_refs, data, format, fragments, rendition, label, profile, results,
    );
    let added_failures = &results.failure[failure_start..];
    if !binding_compromised
        && added_failures.is_empty()
        && results.success[success_start..]
            .iter()
            .any(|status| is_primary_binding_match(primary_label, status))
    {
        return Some(OperativeBinding::Primary(primary));
    }

    let fallback = plan.multi_asset()?;
    if added_failures.is_empty()
        || !added_failures
            .iter()
            .all(|status| is_standard_primary_mismatch(primary_label, status))
    {
        return None;
    }

    let fallback_label = fallback.label?;
    let cbor = claim_refs
        .indexed(fallback_label)
        .and_then(|assertion| assertion.payload)?;
    // C2PA 2.4 suppresses only the failed primary byte-match status when the
    // usable multi-asset fallback applies. All earlier failures stay.
    results.failure.truncate(failure_start);
    let success_start = results.success.len();
    verify_multi_asset(
        claim, claim_refs, cbor, data, format, label, profile, results,
    );
    let fallback_matched = results.failure.len() == failure_start
        && results.success[success_start..]
            .iter()
            .any(|status| status.code == ASSERTION_MULTI_ASSET_HASH_MATCH);
    if binding_compromised {
        results.success.truncate(success_start);
        return None;
    }
    fallback_matched.then_some(OperativeBinding::MultiAsset(fallback))
}

#[allow(clippy::too_many_arguments)]
fn verify_primary_hard_binding(
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    data: &[u8],
    format: AssetFormat,
    fragments: &[&[u8]],
    rendition: update_manifest::StoreRendition,
    label: &str,
    profile: EngineProfile,
    results: &mut ValidationResults,
) {
    // A tampered assertion breaks the claim's hashed-URI binding to it. The
    // asset bytes can still hash correctly because assertions live inside the
    // excluded manifest carrier, so never report a positive hard binding after
    // that failure.
    let binding_compromised = results.has_failure(ASSERTION_HASHED_URI_MISMATCH)
        || results.has_failure(HASHED_URI_MISSING);
    let Some(binding) = claim_refs
        .binding_plan(format == AssetFormat::C2paStore)
        .primary()
    else {
        return;
    };
    let Some(alabel) = binding.label else {
        return;
    };
    if alabel == COMPOUND_CONTENT_LABEL {
        return;
    }
    let Some(indexed) = claim_refs.indexed(alabel) else {
        return;
    };
    match alabel {
        "c2pa.hash.boxes" => {
            if let Some(cbor) = indexed.payload {
                verify_boxes_hash(
                    cbor,
                    claim,
                    format,
                    data,
                    binding_compromised,
                    label,
                    profile,
                    results,
                );
            }
            return;
        }
        "c2pa.hash.collection.data" => {
            if let Some(cbor) = indexed.payload {
                verify_collection_hash(cbor, claim, data, binding_compromised, label, results);
            }
            return;
        }
        "c2pa.hash.multi-asset" => return,
        _ if !is_supported_whole_asset_hash_label(alabel) => return,
        _ => {}
    }
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/{alabel}");
    let is_bmff = is_supported_bmff_hash_label(alabel);
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
    let Some(hash_data) = indexed.decoded.as_ref() else {
        results.push_failure(mismatch_code, url, "hash assertion CBOR invalid".into());
        return;
    };
    let expected = hash_data.get("hash").and_then(Value::as_bytes);
    let Some(alg) = resolved_hash_algorithm(hash_data, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            "hard-binding assertion has no hash algorithm".into(),
        );
        return;
    };
    if bmff_algorithm_index(alg).is_none() {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            format!("hard-binding assertion uses unsupported hash algorithm '{alg}'"),
        );
        return;
    }
    let bmff_exclusions = if is_bmff {
        match bmff_exclusion_maps(hash_data) {
            Ok(exclusions) => exclusions,
            Err(error) => {
                results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url, error.to_string());
                return;
            }
        }
    } else {
        Vec::new()
    };
    // Merkle BMFF binding (fragmented DASH/HLS or chunked mdat). When the
    // assertion also carries a top-level `hash`, that signed value must match
    // before any merkle success can be emitted.
    let merkle_present = is_bmff && hash_data.get("merkle").is_some();
    if is_bmff && bmff_has_additional_exclusions(&bmff_exclusions, merkle_present) {
        results.push_informational(
            ASSERTION_BMFF_HASH_ADDITIONAL_EXCLUSIONS_PRESENT,
            url.clone(),
            "BMFF hash assertion contains optional or additional exclusions".into(),
        );
    }
    if !merkle_present && expected.is_none() {
        let code = if is_bmff {
            ASSERTION_BMFF_HASH_MALFORMED
        } else {
            ASSERTION_DATA_HASH_MISMATCH
        };
        results.push_failure(code, url, "hard-binding assertion missing hash".into());
        return;
    }
    if merkle_present {
        if let Some(expected_hash) = expected {
            let actual =
                match crate::c2pa_formats::bmff_hash_with_exclusions(data, alg, &bmff_exclusions) {
                    Ok(hash) => hash,
                    Err(_) => {
                        results.push_failure(
                            ASSERTION_BMFF_HASH_MALFORMED,
                            url.clone(),
                            "BMFF top-level hash or exclusions are malformed".into(),
                        );
                        return;
                    }
                };
            if actual.as_slice() != expected_hash {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.clone(),
                    "BMFF top-level hash mismatch".into(),
                );
                return;
            }
        }
        verify_bmff_merkle_init(
            BmffMerkleInput {
                hash_data,
                assertion_alg: alg,
                exclusions: &bmff_exclusions,
                data,
                fragments,
                url: &url,
                binding_compromised,
            },
            results,
        );
        return;
    }
    // BMFF hard bindings are computed structurally (box-offset markers), not as
    // a plain file-minus-exclusions digest; delegate to the format crate so
    // sign and verify share byte-exact semantics. `c2pa.hash.data` excludes
    // explicit byte ranges.
    let actual: Option<Vec<u8>> = if is_bmff {
        crate::c2pa_formats::bmff_hash_with_exclusions(data, alg, &bmff_exclusions).ok()
    } else {
        let exclusions = match exclusions::parse_data(hash_data.get("exclusions"), data.len()) {
            Ok(exclusions) => exclusions,
            Err(exclusions::RangeError::Malformed) => {
                results.push_failure(
                    ASSERTION_DATA_HASH_MALFORMED,
                    url,
                    "data-hash exclusions are malformed, unsorted, or overlapping".into(),
                );
                return;
            }
            Err(exclusions::RangeError::Mismatch) => {
                results.push_failure(
                    ASSERTION_DATA_HASH_MISMATCH,
                    url,
                    "data-hash exclusion extends beyond the asset".into(),
                );
                return;
            }
        };
        let carrier = crate::c2pa_formats::compute_data_hash_exclusions(format, data).ok();
        // C2PA 2.4, Validating a data hash: an update manifest grows the store
        // the standard claim signed around, so the store exclusion takes the
        // store's current length and later exclusions shift by the difference.
        let exclusions = match rendition {
            update_manifest::StoreRendition::AsSigned => exclusions,
            update_manifest::StoreRendition::WithUpdates => {
                let adjusted = carrier.as_deref().and_then(|carrier| {
                    update_manifest::adjust_exclusions_for_updates(&exclusions, carrier, data.len())
                });
                let Some(adjusted) = adjusted else {
                    results.push_failure(
                        ASSERTION_DATA_HASH_MISMATCH,
                        url,
                        "data-hash exclusions cannot be adjusted for the updated manifest store"
                            .into(),
                    );
                    return;
                };
                adjusted
            }
        };
        if !exclusions.is_empty() {
            if let Some(carrier) = carrier.as_deref() {
                match inspect_data_hash_exclusions(format, data, &exclusions, carrier) {
                    Ok(has_additional) => {
                        if has_additional {
                            results.push_informational(
                                ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT,
                                url.clone(),
                                "data-hash assertion excludes bytes outside the manifest carrier"
                                    .into(),
                            );
                        }
                    }
                    Err(why) => {
                        results.push_failure(ASSERTION_DATA_HASH_MISMATCH, url, why);
                        return;
                    }
                }
            }
        }
        if format == AssetFormat::TextUnstructured {
            let wrappers = match crate::c2pa_formats::unstructured_text_wrapper_spans(data) {
                Ok(wrappers) => wrappers,
                Err(_) => {
                    results.push_failure(
                        ASSERTION_DATA_HASH_MALFORMED,
                        url,
                        "unstructured text is not valid UTF-8".into(),
                    );
                    return;
                }
            };
            let matching_wrappers = wrappers
                .iter()
                .filter(|wrapper| exclusions.contains(&(wrapper.start, wrapper.length)))
                .count();
            if matching_wrappers == 0 {
                results.push_failure(
                    ASSERTION_DATA_HASH_MALFORMED,
                    url,
                    "data-hash exclusions do not exactly match a text manifest wrapper".into(),
                );
                return;
            }
            if matching_wrappers > 1 {
                results.push_failure(
                    "manifest.text.multipleWrappers",
                    url,
                    "more than one text manifest wrapper matches the data-hash exclusions".into(),
                );
                return;
            }
            match hash_normalized_unstructured_text(alg, data, &exclusions) {
                Ok(hash) => hash,
                Err(detail) => {
                    results.push_failure(ASSERTION_DATA_HASH_MALFORMED, url, detail.into());
                    return;
                }
            }
        } else {
            hash_with_exclusions(alg, data, &exclusions)
        }
    };
    let matched = matches!((&actual, expected), (Some(a), Some(e)) if a.as_slice() == e);
    if matched {
        // Exactly one hard binding is operative, so a match completes content
        // validation for this claim.
        if !binding_compromised {
            results.push_success(match_code, url, "asset hash valid".into());
        }
        return;
    }
    // The sole operative hard binding did not match.
    results.push_failure(mismatch_code, url, "asset hash mismatch".into());
}

/// Inspect the declared `c2pa.hash.data` exclusion ranges against the asset's
/// real manifest carrier.
///
/// C2PA 2.4 Validation, "Validating a data hash": the exclusion range holding
/// the C2PA Manifest Store "consists of only the C2PA Manifest Store and any
/// appropriate padding (e.g., zero'd data)"; anything else rejects the
/// manifest with `assertion.dataHash.mismatch`. Without this check a signer,
/// or anyone who can rewrite the file afterwards, can park arbitrary bytes
/// inside the signed exclusion and still present a matching hard binding.
///
/// "Hashing of JPEG 1 files" adds an exact-length rule for that container,
/// because the `APP11` segment lengths live inside the exclusion: the total
/// excluded length must equal the total length of the C2PA `APP11` segments.
///
/// Ranges that do not touch the carrier are the asset-metadata case and only
/// raise the informational `assertion.dataHash.additionalExclusionsPresent`,
/// reported through the `Ok(true)` result.
fn inspect_data_hash_exclusions(
    format: AssetFormat,
    data: &[u8],
    exclusions: &[(usize, usize)],
    carrier: &[crate::c2pa_formats::DataHashExclusion],
) -> Result<bool, String> {
    let mut carrier_ranges: Vec<(usize, usize)> = carrier
        .iter()
        .filter_map(|span| Some((span.start, span.start.checked_add(span.length)?)))
        .collect();
    carrier_ranges.sort_unstable();
    let mut has_additional = false;
    let mut excluded_carrier_bytes = 0usize;
    // Every byte of a carrier-overlapping exclusion that the store itself does
    // not occupy has to be zeroed padding.
    let padding_only = |from: usize, to: usize| -> Result<(), String> {
        let Some(window) = data.get(from..to) else {
            return Ok(());
        };
        match window.iter().position(|byte| *byte != 0) {
            Some(offset) => Err(format!(
                "data-hash exclusion covering the manifest store contains non-padding data at offset {}",
                from + offset
            )),
            None => Ok(()),
        }
    };
    for &(start, length) in exclusions {
        let Some(end) = start.checked_add(length) else {
            return Err("data-hash exclusion range overflows the asset".into());
        };
        if !carrier_ranges
            .iter()
            .any(|&(carrier_start, carrier_end)| carrier_start < end && start < carrier_end)
        {
            has_additional = true;
            continue;
        }
        excluded_carrier_bytes = excluded_carrier_bytes.saturating_add(length);
        let mut cursor = start;
        for &(carrier_start, carrier_end) in &carrier_ranges {
            if carrier_end <= cursor || carrier_start >= end {
                continue;
            }
            padding_only(cursor, carrier_start.min(end))?;
            cursor = cursor.max(carrier_end);
        }
        padding_only(cursor, end)?;
    }
    let carrier_bytes: usize = carrier.iter().map(|span| span.length).sum();
    if format == AssetFormat::Jpeg
        && excluded_carrier_bytes > 0
        && excluded_carrier_bytes != carrier_bytes
    {
        return Err(format!(
            "data-hash exclusion length {excluded_carrier_bytes} does not equal the {carrier_bytes}-byte total of the C2PA APP11 segments"
        ));
    }
    Ok(has_additional)
}

const MAX_BMFF_MERKLE_ENTRIES: usize = 4_096;
const MAX_BMFF_MERKLE_LEAVES: usize = 262_144;
const MAX_BMFF_MERKLE_TOTAL_HASH_BYTES: usize = 1 << 30;
const MAX_BMFF_MERKLE_TOTAL_CHUNKS: usize = MAX_BMFF_MERKLE_LEAVES;
const MAX_BMFF_EXCLUSION_DATA_QUALIFIERS: usize = 4_096;
const MAX_BMFF_EXCLUSION_DATA_BYTES: usize = 1 << 20;
const MAX_BMFF_EXCLUSION_SUBSETS: usize = 4_096;
const MAX_BMFF_EXCLUSION_XPATH_BYTES: usize = 1024;

type BmffMerkleProofKey = (i128, i128, usize);
type BmffMerkleProofIndex =
    std::collections::HashMap<BmffMerkleProofKey, crate::c2pa_formats::BmffMerkleBox>;

fn checked_bmff_merkle_work(
    total_bytes: &mut usize,
    total_chunks: &mut usize,
    payload_bytes: usize,
    chunks: usize,
) -> Result<(), &'static str> {
    let new_bytes = total_bytes
        .checked_add(payload_bytes)
        .filter(|total| *total <= MAX_BMFF_MERKLE_TOTAL_HASH_BYTES)
        .ok_or("aggregate monolithic merkle payload bytes exceed the verifier bound")?;
    let new_chunks = total_chunks
        .checked_add(chunks)
        .filter(|total| *total <= MAX_BMFF_MERKLE_TOTAL_CHUNKS)
        .ok_or("aggregate monolithic merkle chunks exceed the verifier bound")?;
    *total_bytes = new_bytes;
    *total_chunks = new_chunks;
    Ok(())
}

fn bmff_digest_len(alg: &str) -> Option<usize> {
    content_hash_algorithm(alg).map(ContentHashAlgorithm::digest_len)
}

fn bmff_algorithm_index(alg: &str) -> Option<usize> {
    content_hash_algorithm(alg).map(ContentHashAlgorithm::cache_index)
}

fn bmff_merkle_row<'a>(
    entry: &'a Value,
    alg: &str,
) -> Result<(usize, &'a [Value], usize), &'static str> {
    let digest_len = bmff_digest_len(alg).ok_or("unsupported merkle hash algorithm")?;
    if !matches!(entry.get("uniqueId"), Some(Value::Integer(_)))
        || !matches!(entry.get("localId"), Some(Value::Integer(_)))
    {
        return Err("merkle entry is missing integer uniqueId or localId");
    }
    let Some(Value::Array(row)) = entry.get("hashes") else {
        return Err("merkle entry is missing a hashes row");
    };
    if row.is_empty() || row.len() > MAX_BMFF_MERKLE_LEAVES {
        return Err("merkle hashes row is empty or exceeds the verifier bound");
    }
    if row
        .iter()
        .any(|value| value.as_bytes().is_none_or(|hash| hash.len() != digest_len))
    {
        return Err("merkle hashes row contains a non-byte value or wrong digest width");
    }
    let count = match entry.get("count") {
        Some(Value::Integer(count)) => usize::try_from(*count).ok().filter(|count| *count > 0),
        _ => None,
    }
    .ok_or("merkle count is missing or not positive")?;
    if count < row.len() {
        return Err("merkle count is smaller than the stored row");
    }
    Ok((count, row, digest_len))
}

fn bmff_fragment_merkle_row<'a>(
    entry: &'a Value,
    alg: &str,
) -> Result<(usize, &'a [Value], usize), &'static str> {
    if entry.get("fixedBlockSize").is_some() || entry.get("variableBlockSizes").is_some() {
        return Err("fragment merkle entry contains a block-size descriptor");
    }
    bmff_merkle_row(entry, alg)
}

/// Select the bytes covered by a Merkle `initHash`.
///
/// A standalone initialization segment has no top-level `moof`, so its whole
/// file is covered. A flat fragmented MP4 covers only bytes before the first
/// top-level `moof` (C2PA 2.4, `merkle-map.initHash`).
fn bmff_initialization_scope(data: &[u8]) -> Result<&[u8], &'static str> {
    let mut offset = 0usize;
    while offset < data.len() {
        let header = data
            .get(offset..offset.checked_add(8).ok_or("BMFF box offset overflows")?)
            .ok_or("BMFF top-level box header is truncated")?;
        let size32 = u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| "BMFF top-level box size is truncated")?,
        );
        let (header_len, size) = match size32 {
            0 => (8usize, data.len() - offset),
            1 => {
                let extended = data
                    .get(offset..offset.checked_add(16).ok_or("BMFF box offset overflows")?)
                    .ok_or("BMFF extended box header is truncated")?;
                let size = usize::try_from(u64::from_be_bytes(
                    extended[8..16]
                        .try_into()
                        .map_err(|_| "BMFF extended box size is truncated")?,
                ))
                .map_err(|_| "BMFF box size exceeds platform limits")?;
                (16, size)
            }
            size => (8, size as usize),
        };
        if size < header_len {
            return Err("BMFF top-level box size is smaller than its header");
        }
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= data.len())
            .ok_or("BMFF top-level box lies outside the asset")?;
        if &header[4..8] == b"moof" {
            return Ok(&data[..offset]);
        }
        offset = end;
    }
    Ok(data)
}

fn bmff_merkle_proof_index(data: &[u8]) -> Result<BmffMerkleProofIndex, &'static str> {
    let boxes =
        crate::c2pa_formats::bmff_merkle_boxes(data).map_err(|_| "asset not parseable as BMFF")?;
    let mut index = BmffMerkleProofIndex::with_capacity(boxes.len());
    for parsed in boxes {
        let merkle_box = parsed?;
        let key = (
            merkle_box.unique_id,
            merkle_box.local_id,
            merkle_box.location,
        );
        if index.insert(key, merkle_box).is_some() {
            return Err("duplicate auxiliary C2PA merkle proof key");
        }
    }
    Ok(index)
}

enum BmffMonolithicPlanLayout<'a> {
    Fixed(usize),
    Variable(&'a [Value]),
    Whole,
}

struct BmffMonolithicPlan<'entry, 'data> {
    alg: &'entry str,
    count: usize,
    row_values: &'entry [Value],
    local_id: usize,
    unique_id: i128,
    payload: &'data [u8],
    layout: BmffMonolithicPlanLayout<'entry>,
}

/// Parse and bound every monolithic Merkle entry before hashing any `mdat`.
///
/// `mdat` spans are parsed once. A payload may be targeted by only one
/// monolithic entry, so aggregate hashing remains linear in unique selected
/// payload bytes rather than entries times asset size.
fn preflight_bmff_monolithic_entries<'entry, 'data>(
    entries: &'entry [Value],
    assertion_alg: &'entry str,
    data: &'data [u8],
) -> Result<Vec<BmffMonolithicPlan<'entry, 'data>>, String> {
    let monolithic_count = entries
        .iter()
        .filter(|entry| entry.get("initHash").is_none())
        .count();
    if monolithic_count == 0 {
        return Ok(Vec::new());
    }
    let mdats = crate::c2pa_formats::bmff_mdat_payloads(data)
        .map_err(|_| "asset not parseable as BMFF".to_string())?;
    let mut plans = Vec::with_capacity(monolithic_count);
    let mut seen_tree_targets = std::collections::HashSet::with_capacity(monolithic_count);
    let mut seen_local_ids = std::collections::HashSet::with_capacity(monolithic_count);
    let mut total_bytes = 0usize;
    let mut total_chunks = 0usize;

    for entry in entries
        .iter()
        .filter(|entry| entry.get("initHash").is_none())
    {
        let alg = match entry.get("alg") {
            None => assertion_alg,
            Some(Value::Text(alg)) => alg.as_str(),
            Some(_) => return Err("monolithic merkle alg is not a string".into()),
        };
        let (count, row_values, _) = bmff_merkle_row(entry, alg).map_err(str::to_string)?;
        if count > MAX_BMFF_MERKLE_LEAVES {
            return Err("monolithic merkle leaf count exceeds the verifier bound".into());
        }
        let local_id = match entry.get("localId") {
            Some(Value::Integer(id)) => {
                usize::try_from(*id).map_err(|_| "monolithic merkle localId is not non-negative")?
            }
            _ => return Err("monolithic merkle entry missing localId".into()),
        };
        let unique_id = match entry.get("uniqueId") {
            Some(Value::Integer(id)) => *id,
            _ => return Err("monolithic merkle entry missing uniqueId".into()),
        };
        if !seen_tree_targets.insert((unique_id, local_id)) || !seen_local_ids.insert(local_id) {
            return Err(format!(
                "duplicate monolithic merkle tree/localId/layout target for mdat {local_id}"
            ));
        }

        let Some(&(payload_start, payload_len)) = mdats.get(local_id) else {
            return Err(format!("no mdat with index {local_id}"));
        };
        let payload = payload_start
            .checked_add(payload_len)
            .and_then(|end| data.get(payload_start..end))
            .ok_or_else(|| "mdat payload lies outside the asset".to_string())?;

        let fixed = match entry.get("fixedBlockSize") {
            None => None,
            Some(Value::Integer(size)) => match usize::try_from(*size) {
                Ok(size) if size > 0 => Some(size),
                _ => return Err("fixedBlockSize is not positive".into()),
            },
            Some(_) => return Err("fixedBlockSize is not an integer".into()),
        };
        let variable = match entry.get("variableBlockSizes") {
            None => None,
            Some(Value::Array(sizes)) if sizes.is_empty() => {
                return Err("variableBlockSizes is empty".into())
            }
            Some(Value::Array(sizes)) => Some(sizes.as_slice()),
            Some(_) => return Err("variableBlockSizes is not an array".into()),
        };
        if fixed.is_some() && variable.is_some() {
            return Err("fixedBlockSize and variableBlockSizes are mutually exclusive".into());
        }

        let (chunk_count, layout) = if let Some(size) = fixed {
            (
                payload_len.div_ceil(size),
                BmffMonolithicPlanLayout::Fixed(size),
            )
        } else if let Some(sizes) = variable {
            if sizes.len() != count {
                return Err("variableBlockSizes count does not match the merkle count".into());
            }
            let mut offset = 0usize;
            for value in sizes {
                let size = match value {
                    Value::Integer(size) => usize::try_from(*size)
                        .map_err(|_| "variableBlockSizes entry is not a non-negative integer")?,
                    _ => return Err("variableBlockSizes entry is not an integer".into()),
                };
                offset = offset
                    .checked_add(size)
                    .filter(|end| *end <= payload_len)
                    .ok_or_else(|| "variableBlockSizes do not tile the mdat payload".to_string())?;
            }
            if offset != payload_len {
                return Err("variableBlockSizes do not tile the mdat payload".into());
            }
            (sizes.len(), BmffMonolithicPlanLayout::Variable(sizes))
        } else {
            (1, BmffMonolithicPlanLayout::Whole)
        };
        if chunk_count != count {
            return Err(format!(
                "count {count} does not match {chunk_count} mdat chunk(s)"
            ));
        }
        checked_bmff_merkle_work(
            &mut total_bytes,
            &mut total_chunks,
            payload_len,
            chunk_count,
        )
        .map_err(str::to_string)?;

        plans.push(BmffMonolithicPlan {
            alg,
            count,
            row_values,
            local_id,
            unique_id,
            payload,
            layout,
        });
    }
    Ok(plans)
}

struct BmffMerkleInput<'a, 'b> {
    hash_data: &'a Value,
    assertion_alg: &'a str,
    exclusions: &'a [crate::c2pa_formats::BmffExclusionMap],
    data: &'a [u8],
    fragments: &'a [&'b [u8]],
    url: &'a str,
    binding_compromised: bool,
}

/// Verify a `c2pa.hash.bmff.v2` or `c2pa.hash.bmff.v3` merkle binding.
///
/// A merkle BMFF binding covers a fragmented asset (DASH/HLS init segment +
/// fragment files) or a chunked monolithic `mdat`. From the primary asset the
/// merkle `initHash` — the BMFF-structural hash of the init segment with the
/// assertion's exclusions applied — is checked with the same
/// box-offset-marker hashing the non-merkle path uses
/// ([`crate::c2pa_formats::bmff_hash`]).
///
/// When `fragments` are supplied (spec 15.12.2.2 / A.5.4), each fragment's
/// Merkle leaf hash is recomputed (plain digest minus exclusions, no offset
/// markers) and climbed to the row stored in the assertion using the proof in
/// the fragment's auxiliary C2PA `merkle` box; mismatches fail with
/// `assertion.bmffHash.mismatch`, structural defects with
/// `assertion.bmffHash.malformed`. Without supplied fragments, fragmented trees
/// are reported informational. Monolithic trees are streamed over their
/// corresponding top-level `mdat` payload and validated immediately.
fn verify_bmff_merkle_init(input: BmffMerkleInput<'_, '_>, results: &mut ValidationResults) {
    let BmffMerkleInput {
        hash_data,
        assertion_alg,
        exclusions,
        data,
        fragments,
        url,
        binding_compromised,
    } = input;
    let Some(Value::Array(entries)) = hash_data.get("merkle") else {
        results.push_failure(
            ASSERTION_BMFF_HASH_MALFORMED,
            url.to_string(),
            "merkle field is not an array".into(),
        );
        return;
    };
    if entries.is_empty() || entries.len() > MAX_BMFF_MERKLE_ENTRIES {
        results.push_failure(
            ASSERTION_BMFF_HASH_MALFORMED,
            url.to_string(),
            "merkle entry count is empty or exceeds the verifier bound".into(),
        );
        return;
    }
    for entry in entries {
        let alg = match entry.get("alg") {
            None => assertion_alg,
            Some(Value::Text(alg)) => alg.as_str(),
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    "merkle alg is not a string".into(),
                );
                return;
            }
        };
        if !is_allowed_hash_algorithm(alg) {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url.to_string(),
                format!("merkle entry uses unsupported hash algorithm '{alg}'"),
            );
            return;
        }
    }

    let monolithic_plans = match preflight_bmff_monolithic_entries(entries, assertion_alg, data) {
        Ok(plans) => plans,
        Err(why) => {
            results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why);
            return;
        }
    };

    let needs_auxiliary_proofs = entries.iter().any(|entry| {
        entry.get("initHash").is_none()
            && match (entry.get("count"), entry.get("hashes")) {
                (Some(Value::Integer(count)), Some(Value::Array(row))) => {
                    usize::try_from(*count).is_ok_and(|count| count > row.len())
                }
                _ => false,
            }
    });
    let proof_index = if needs_auxiliary_proofs {
        match bmff_merkle_proof_index(data) {
            Ok(index) => Some(index),
            Err(why) => {
                results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why.into());
                return;
            }
        }
    } else {
        None
    };
    let init_scope = if entries.iter().any(|entry| entry.get("initHash").is_some()) {
        match bmff_initialization_scope(data) {
            Ok(scope) => scope,
            Err(why) => {
                results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why.into());
                return;
            }
        }
    } else {
        data
    };

    // Three fixed cache slots prevent alternating per-entry algorithms from
    // rehashing the attacker-sized initialization scope.
    let mut cached: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut init_tracks = 0usize;
    let mut fragment_trees = 0usize;
    let mut mono_entries = 0usize;
    let mut mono_ok = 0usize;
    let mut monolithic_plans = monolithic_plans.iter();
    for entry in entries {
        let expected_init = match entry.get("initHash") {
            None => {
                mono_entries += 1;
                let Some(plan) = monolithic_plans.next() else {
                    results.push_failure(
                        ASSERTION_BMFF_HASH_MALFORMED,
                        url.to_string(),
                        "monolithic merkle preflight plan is incomplete".into(),
                    );
                    return;
                };
                if verify_bmff_monolithic_entry(plan, proof_index.as_ref(), url, results) {
                    mono_ok += 1;
                }
                continue;
            }
            Some(Value::Bytes(hash)) => {
                fragment_trees += 1;
                hash.as_slice()
            }
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    "merkle initHash is not a byte string".into(),
                );
                return;
            }
        };
        let alg = match entry.get("alg") {
            None => assertion_alg,
            Some(Value::Text(alg)) => alg.as_str(),
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    "merkle alg is not a string".into(),
                );
                return;
            }
        };
        let (Some(cache_index), Ok((_, _, digest_len))) = (
            bmff_algorithm_index(alg),
            bmff_fragment_merkle_row(entry, alg),
        ) else {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                "merkle row or hash algorithm is malformed".into(),
            );
            return;
        };
        if expected_init.len() != digest_len {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                "merkle initHash has the wrong digest width".into(),
            );
            return;
        }
        if cached[cache_index].is_none() {
            let actual =
                match crate::c2pa_formats::bmff_hash_with_exclusions(init_scope, alg, exclusions) {
                    Ok(hash) => hash,
                    Err(_) => {
                        results.push_failure(
                            ASSERTION_BMFF_HASH_MALFORMED,
                            url.to_string(),
                            "merkle initialization scope or exclusions are malformed".into(),
                        );
                        return;
                    }
                };
            cached[cache_index] = Some(actual);
        }
        let actual = cached[cache_index].as_deref();
        if actual != Some(expected_init) {
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
        if fragments.is_empty() {
            if !binding_compromised {
                results.push_success(
                    ASSERTION_BMFF_HASH_MATCH,
                    url.to_string(),
                    format!("merkle initHash valid over init segment ({init_tracks} track(s))"),
                );
            }
            if fragment_trees > 0 {
                // NEVER the success code: nothing about these trees was
                // checked, and `assertion.bmffHash.match` asserts the opposite
                // (PRD 5.9).
                results.push_informational(
                    stream::BMFF_FRAGMENTS_NOT_EVALUATED,
                    url.to_string(),
                    format!(
                        "{fragment_trees} fragment merkle tree(s) not evaluated: fragment files not provided (use stream verification)"
                    ),
                );
            }
        } else if verify_bmff_fragments(entries, assertion_alg, exclusions, fragments, url, results)
            && !binding_compromised
        {
            results.push_success(
                ASSERTION_BMFF_HASH_MATCH,
                url.to_string(),
                format!(
                    "merkle initHash and {} fragment merkle leaf hash(es) valid",
                    fragments.len()
                ),
            );
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

/// Allocation-free cursor over the chunks described by a Merkle map.
///
/// Variable block sizes remain borrowed from decoded CBOR. The iterator keeps
/// only the current byte offset, so verifier memory does not scale with the
/// attacker-controlled leaf count.
enum BmffChunkLayout<'a> {
    Fixed { size: usize, offset: usize },
    Variable { sizes: &'a [Value], offset: usize },
    Whole(Option<&'a [u8]>),
}

struct BmffChunkIter<'a> {
    payload: &'a [u8],
    layout: BmffChunkLayout<'a>,
}

impl<'a> Iterator for BmffChunkIter<'a> {
    type Item = Result<&'a [u8], &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.layout {
            BmffChunkLayout::Fixed { size, offset } => {
                if *offset >= self.payload.len() {
                    return None;
                }
                let start = *offset;
                let end = start.saturating_add(*size).min(self.payload.len());
                *offset = end;
                Some(Ok(&self.payload[start..end]))
            }
            BmffChunkLayout::Variable { sizes, offset } => {
                let (next, rest) = sizes.split_first()?;
                *sizes = rest;
                let size = match next {
                    Value::Integer(size) => match usize::try_from(*size) {
                        Ok(size) => size,
                        Err(_) => {
                            return Some(Err(
                                "variableBlockSizes entry is not a non-negative integer",
                            ))
                        }
                    },
                    _ => return Some(Err("variableBlockSizes entry is not an integer")),
                };
                let start = *offset;
                let Some(end) = start.checked_add(size) else {
                    return Some(Err("variableBlockSizes total overflows"));
                };
                let Some(chunk) = self.payload.get(start..end) else {
                    return Some(Err("variableBlockSizes do not tile the mdat payload"));
                };
                *offset = end;
                Some(Ok(chunk))
            }
            BmffChunkLayout::Whole(chunk) => chunk.take().map(Ok),
        }
    }
}

/// Validate one monolithic (chunked-mdat) merkle entry per spec 15.12.2.1.
///
/// `localId` is the zero-based index of the `mdat` box this tree covers. The
/// payload is chunked by `fixedBlockSize` XOR `variableBlockSizes` (both
/// present = malformed; neither = the whole payload is a single leaf). When
/// the assertion stores the leaf row (`count == hashes.len()`), leaves are
/// compared directly; when it stores a higher row (`count > hashes.len()`),
/// each leaf's indexed auxiliary C2PA `merkle` proof is climbed to that row.
fn verify_bmff_monolithic_entry(
    plan: &BmffMonolithicPlan<'_, '_>,
    proof_index: Option<&BmffMerkleProofIndex>,
    url: &str,
    results: &mut ValidationResults,
) -> bool {
    let malformed = |results: &mut ValidationResults, why: String| {
        results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why);
        false
    };
    let Some(digest_len) = bmff_digest_len(plan.alg) else {
        return malformed(
            results,
            format!("unsupported hash algorithm '{}'", plan.alg),
        );
    };
    let chunks = BmffChunkIter {
        payload: plan.payload,
        layout: match &plan.layout {
            BmffMonolithicPlanLayout::Fixed(size) => BmffChunkLayout::Fixed {
                size: *size,
                offset: 0,
            },
            BmffMonolithicPlanLayout::Variable(sizes) => {
                BmffChunkLayout::Variable { sizes, offset: 0 }
            }
            BmffMonolithicPlanLayout::Whole => BmffChunkLayout::Whole(Some(plan.payload)),
        },
    };
    let mut visited = 0usize;
    for (index, chunk) in chunks.enumerate() {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(why) => return malformed(results, why.into()),
        };
        visited += 1;
        let Some(leaf) = hash_bytes(plan.alg, chunk) else {
            return malformed(
                results,
                format!("unsupported hash algorithm '{}'", plan.alg),
            );
        };
        if plan.count == plan.row_values.len() {
            if plan.row_values.get(index).and_then(Value::as_bytes) != Some(leaf.as_slice()) {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!(
                        "mdat {} chunk {index}: merkle leaf hash mismatch",
                        plan.local_id
                    ),
                );
                return false;
            }
            continue;
        }

        let Some(proof_index) = proof_index else {
            return malformed(results, "auxiliary C2PA merkle proof index missing".into());
        };
        let key = (plan.unique_id, plan.local_id as i128, index);
        let Some(merkle_box) = proof_index.get(&key) else {
            return malformed(
                results,
                format!(
                    "mdat {} chunk {index}: auxiliary C2PA merkle box missing",
                    plan.local_id
                ),
            );
        };
        if merkle_box.proof.iter().any(|hash| hash.len() != digest_len) {
            return malformed(
                results,
                format!(
                    "mdat {} chunk {index}: merkle proof has the wrong digest width",
                    plan.local_id
                ),
            );
        }
        match merkle_climb(
            leaf,
            index,
            plan.count,
            &merkle_box.proof,
            plan.row_values.len(),
            plan.alg,
        ) {
            Some((row_index, derived))
                if plan.row_values.get(row_index).and_then(Value::as_bytes)
                    == Some(derived.as_slice()) => {}
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!(
                        "mdat {} chunk {index}: merkle leaf does not derive the stored row hash",
                        plan.local_id
                    ),
                );
                return false;
            }
            None => {
                return malformed(
                    results,
                    format!(
                        "mdat {} chunk {index}: merkle proof inconsistent",
                        plan.local_id
                    ),
                )
            }
        }
    }
    if visited != plan.count {
        return malformed(
            results,
            format!(
                "count {} does not match {visited} streamed mdat chunk(s)",
                plan.count
            ),
        );
    }
    true
}

/// Validate supplied fragment files against the assertion's Merkle trees
/// (spec A.5.4.1.2 + 18.6.6.1).
fn verify_bmff_fragments(
    entries: &[Value],
    assertion_alg: &str,
    exclusions: &[crate::c2pa_formats::BmffExclusionMap],
    fragments: &[&[u8]],
    url: &str,
    results: &mut ValidationResults,
) -> bool {
    let mut tree_index =
        std::collections::HashMap::<(i128, i128), &Value>::with_capacity(entries.len());
    for entry in entries
        .iter()
        .filter(|entry| entry.get("initHash").is_some())
    {
        let key = match (entry.get("uniqueId"), entry.get("localId")) {
            (Some(Value::Integer(unique_id)), Some(Value::Integer(local_id))) => {
                (*unique_id, *local_id)
            }
            _ => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    "fragment merkle entry is missing integer uniqueId or localId".into(),
                );
                return false;
            }
        };
        if tree_index.insert(key, entry).is_some() {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                "duplicate fragment merkle entry key".into(),
            );
            return false;
        }
    }

    let mut matched = 0usize;
    let mut seen_identities =
        std::collections::HashSet::<(i128, i128, usize)>::with_capacity(fragments.len());
    for (index, fragment) in fragments.iter().enumerate() {
        let boxes = match crate::c2pa_formats::bmff_merkle_boxes(fragment) {
            Ok(boxes) => boxes,
            Err(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: not parseable as BMFF"),
                );
                continue;
            }
        };
        if boxes.len() != 1 {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!(
                    "fragment {index}: expected one auxiliary C2PA merkle box, found {}",
                    boxes.len()
                ),
            );
            continue;
        }
        let merkle_box = match boxes.into_iter().next() {
            Some(Ok(merkle_box)) => merkle_box,
            Some(Err(why)) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: {why}"),
                );
                continue;
            }
            None => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: auxiliary C2PA merkle box missing"),
                );
                continue;
            }
        };
        let identity = (
            merkle_box.unique_id,
            merkle_box.local_id,
            merkle_box.location,
        );
        if !seen_identities.insert(identity) {
            results.push_failure(
                ASSERTION_BMFF_HASH_MISMATCH,
                url.to_string(),
                format!(
                    "fragment {index}: duplicate fragment identity uniqueId={} localId={} location={}",
                    merkle_box.unique_id, merkle_box.local_id, merkle_box.location
                ),
            );
            return false;
        }
        let Some(entry) = tree_index.get(&(merkle_box.unique_id, merkle_box.local_id)) else {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!(
                    "fragment {index}: no merkle entry for uniqueId={} localId={}",
                    merkle_box.unique_id, merkle_box.local_id
                ),
            );
            continue;
        };
        let alg = match entry.get("alg") {
            None => assertion_alg,
            Some(Value::Text(alg)) => alg.as_str(),
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: merkle alg is not a string"),
                );
                continue;
            }
        };
        let (count, row_values, digest_len) = match bmff_fragment_merkle_row(entry, alg) {
            Ok(row) => row,
            Err(why) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: {why}"),
                );
                continue;
            }
        };
        if merkle_box.proof.iter().any(|hash| hash.len() != digest_len) {
            results.push_failure(
                ASSERTION_BMFF_HASH_MALFORMED,
                url.to_string(),
                format!("fragment {index}: merkle proof has the wrong digest width"),
            );
            continue;
        }

        let leaf = match crate::c2pa_formats::bmff_fragment_leaf_hash(fragment, alg, exclusions) {
            Ok(leaf) => leaf,
            Err(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!("fragment {index}: BMFF exclusions or hash algorithm are invalid"),
                );
                continue;
            }
        };
        match merkle_climb(
            leaf,
            merkle_box.location,
            count,
            &merkle_box.proof,
            row_values.len(),
            alg,
        ) {
            Some((row_index, derived))
                if row_values.get(row_index).and_then(Value::as_bytes)
                    == Some(derived.as_slice()) =>
            {
                matched += 1;
            }
            Some(_) => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MISMATCH,
                    url.to_string(),
                    format!("fragment {index}: merkle leaf does not derive the stored row hash"),
                );
            }
            None => {
                results.push_failure(
                    ASSERTION_BMFF_HASH_MALFORMED,
                    url.to_string(),
                    format!(
                        "fragment {index}: merkle proof inconsistent with location {} / count {count} / row {}",
                        merkle_box.location,
                        row_values.len()
                    ),
                );
            }
        }
    }
    matched > 0 && matched == fragments.len()
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

fn update_normalized_box_bytes(
    hasher: &mut Hasher,
    data: &[u8],
    mut start: usize,
    end: usize,
    spans: &[crate::c2pa_formats::BoxSpan],
    format: AssetFormat,
) {
    if format != AssetFormat::Font {
        hasher.update(&data[start..end]);
        return;
    }
    for span in spans.iter().filter(|span| span.name == "head") {
        let zero_start = span.start().saturating_add(8);
        let zero_end = zero_start.saturating_add(4).min(span.end());
        if zero_end <= start || zero_start >= end {
            continue;
        }
        let before_end = zero_start.max(start).min(end);
        if start < before_end {
            hasher.update(&data[start..before_end]);
        }
        let normalized_start = start.max(zero_start);
        let normalized_end = end.min(zero_end);
        if normalized_start < normalized_end {
            hasher.update(&[0; 4][..normalized_end - normalized_start]);
        }
        start = normalized_end;
    }
    if start < end {
        hasher.update(&data[start..end]);
    }
}

/// The byte ranges an entry's `names` run hashes, plus the logical offset at
/// which each named box begins within that run.
///
/// For contiguous boxes the run is one range from the first box's start to the
/// last box's end, so any bytes lying between the named boxes are hashed too,
/// as C2PA 2.4 BoxesHash requires ("This would include any arbitrary bytes
/// that may be present between boxes"). An Ogg logical bitstream is a box of
/// interleaved pages, which has no such envelope: those runs hash each page
/// range in file order and nothing else.
struct BoxEntryLayout {
    ranges: Vec<(usize, usize)>,
    box_offsets: Vec<usize>,
    total: usize,
}

impl BoxEntryLayout {
    fn new(spans: &[crate::c2pa_formats::BoxSpan]) -> Option<Self> {
        let first = spans.first()?;
        if spans
            .iter()
            .all(crate::c2pa_formats::BoxSpan::is_contiguous)
        {
            let start = first.start();
            let end = spans.last()?.end();
            return Some(Self {
                ranges: vec![(start, end)],
                box_offsets: spans
                    .iter()
                    .map(|span| span.start().saturating_sub(start))
                    .collect(),
                total: end.saturating_sub(start),
            });
        }
        let mut ranges = Vec::new();
        let mut box_offsets = Vec::with_capacity(spans.len());
        let mut total = 0usize;
        for span in spans {
            box_offsets.push(total);
            for &(start, end) in span.ranges() {
                total = total.checked_add(end.checked_sub(start)?)?;
                ranges.push((start, end));
            }
        }
        Some(Self {
            ranges,
            box_offsets,
            total,
        })
    }

    /// Hash the logical window `[from, to)` of the run by mapping it back onto
    /// the asset's byte ranges.
    fn update(
        &self,
        hasher: &mut Hasher,
        data: &[u8],
        from: usize,
        to: usize,
        spans: &[crate::c2pa_formats::BoxSpan],
        format: AssetFormat,
    ) {
        let mut logical = 0usize;
        for &(start, end) in &self.ranges {
            let len = end.saturating_sub(start);
            let range_from = from.max(logical);
            let range_to = to.min(logical + len);
            if range_from < range_to {
                update_normalized_box_bytes(
                    hasher,
                    data,
                    start + (range_from - logical),
                    start + (range_to - logical),
                    spans,
                    format,
                );
            }
            logical += len;
        }
    }
}

fn hash_box_entry(
    alg: &str,
    data: &[u8],
    spans: &[crate::c2pa_formats::BoxSpan],
    exclusions: &[exclusions::BoxExclusion],
    format: AssetFormat,
) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    let layout = BoxEntryLayout::new(spans)?;
    let mut cursor = 0usize;
    for exclusion in exclusions {
        let start = layout
            .box_offsets
            .get(exclusion.box_index)?
            .checked_add(exclusion.start)?;
        let end = start.checked_add(exclusion.length)?;
        layout.update(&mut hasher, data, cursor, start, spans, format);
        cursor = cursor.max(end);
    }
    layout.update(&mut hasher, data, cursor, layout.total, spans, format);
    Some(hasher.finalize())
}

/// Verify a general box hash (`c2pa.hash.boxes`, spec 15.12.3).
///
/// The asset is segmented into named spans ([`crate::c2pa_formats::box_spans`]) and
/// the assertion's `boxes` entries are consumed in order: each entry's
/// `names` must match the next spans exactly (out-of-order or missing →
/// `assertion.boxesHash.mismatch`), its hash is computed from the start of
/// the first named span through the end of the last (inter-box bytes
/// included), and compared unless the entry is `excluded` or is the `C2PA`
/// manifest run (structurally checked; its hash is the placeholder the
/// two-pass creation cannot make self-consistent). Asset spans left over
/// after all entries yields `assertion.boxesHash.unknownBox`.
fn append_box_hash_results(
    results: &mut ValidationResults,
    mut outcome: ValidationResults,
    binding_compromised: bool,
) {
    if binding_compromised {
        outcome
            .success
            .retain(|status| status.code != ASSERTION_BOXES_HASH_MATCH);
    }
    results.success.extend(outcome.success);
    results.informational.extend(outcome.informational);
    results.failure.extend(outcome.failure);
}

#[allow(clippy::too_many_arguments)] // binding verifier inputs are independent security context
fn verify_boxes_hash(
    cbor: &[u8],
    claim: &Value,
    format: AssetFormat,
    data: &[u8],
    binding_compromised: bool,
    label: &str,
    profile: EngineProfile,
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
    let default_alg = resolved_hash_algorithm(&box_map, claim);
    for entry in entries {
        let Some(alg) = entry.get("alg").and_then(Value::as_text).or(default_alg) else {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url,
                "no hash algorithm in box entry, box map, or claim".into(),
            );
            return;
        };
        if !is_allowed_hash_algorithm(alg) {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url,
                format!("box entry uses unsupported hash algorithm '{alg}'"),
            );
            return;
        }
    }
    let spans = match crate::c2pa_formats::box_spans(format, data) {
        Ok(Some(spans)) => spans,
        // The general box hash is the claim's sole hard binding, and C2PA 2.4
        // has no box convention for this container, so the binding cannot be
        // evaluated at all. Reporting that informationally left the manifest
        // Valid with no content binding checked; fail closed instead.
        Ok(None) => {
            results.push_failure(
                ASSERTION_BOXES_HASH_UNEVALUATED,
                url,
                "general box hash not evaluated: C2PA 2.4 defines no box segmentation for this container".into(),
            );
            return;
        }
        Err(error) => {
            results.push_failure(
                ASSERTION_BOXES_HASH_MALFORMED,
                url,
                format!("asset segmentation failed: {error}"),
            );
            return;
        }
    };

    let mut strict = ValidationResults::default();
    verify_boxes_hash_with_spans(
        entries,
        default_alg,
        format,
        data,
        &spans,
        label,
        &mut strict,
    );
    let strict_mismatch = !strict.failure.is_empty()
        && strict
            .failure
            .iter()
            .all(|status| status.code == ASSERTION_BOXES_HASH_MISMATCH);
    if format == AssetFormat::Jpeg
        && profile.compliance == ComplianceLevel::CoreSpec
        && strict_mismatch
    {
        if let Ok(compat_spans) =
            crate::c2pa_formats::jpeg_box_spans_with_overlapping_restart_segments(data)
        {
            let mut compatibility = ValidationResults::default();
            verify_boxes_hash_with_spans(
                entries,
                default_alg,
                format,
                data,
                &compat_spans,
                label,
                &mut compatibility,
            );
            if compatibility.failure.is_empty()
                && compatibility.has_success(ASSERTION_BOXES_HASH_MATCH)
            {
                compatibility.push_informational(
                    ASSERTION_BOXES_HASH_OVERLAPPING_RESTART_SEGMENTS,
                    format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.hash.boxes"),
                    "JPEG box hashes use the historical overlapping c2pa-rs restart-marker layout"
                        .into(),
                );
                append_box_hash_results(results, compatibility, binding_compromised);
                return;
            }
        }
    }
    append_box_hash_results(results, strict, binding_compromised);
}

fn verify_boxes_hash_with_spans(
    entries: &[Value],
    default_alg: Option<&str>,
    format: AssetFormat,
    data: &[u8],
    spans: &[crate::c2pa_formats::BoxSpan],
    label: &str,
    results: &mut ValidationResults,
) {
    let url = format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.hash.boxes");

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
        }
        // `excluded` takes precedence: its optional exclusions and hash are not
        // evaluated.
        if excluded {
            continue;
        }
        let selected = &spans[first..idx];
        let box_lengths: Vec<usize> = selected
            .iter()
            .map(crate::c2pa_formats::BoxSpan::byte_len)
            .collect();
        let box_exclusions = match exclusions::parse_boxes(entry.get("exclusions"), &box_lengths) {
            Ok(exclusions) => exclusions,
            Err(exclusions::RangeError::Malformed) => {
                results.push_failure(
                    ASSERTION_BOXES_HASH_MALFORMED,
                    url,
                    "box exclusions are malformed, unsorted, or use an invalid boxIndex".into(),
                );
                return;
            }
            Err(exclusions::RangeError::Mismatch) => {
                results.push_failure(
                    ASSERTION_BOXES_HASH_MISMATCH,
                    url,
                    "box exclusion extends beyond its named box".into(),
                );
                return;
            }
        };
        if is_c2pa_run {
            continue; // structurally consumed; hash is the creation placeholder
        }
        if !box_exclusions.is_empty() {
            results.push_informational(
                ASSERTION_BOXES_HASH_ADDITIONAL_EXCLUSIONS_PRESENT,
                url.clone(),
                "box hash entry contains additional byte exclusions".into(),
            );
        }
        let Some(expected) = entry.get("hash").and_then(Value::as_bytes) else {
            results.push_failure(
                ASSERTION_BOXES_HASH_MISMATCH,
                url,
                "box entry missing hash".into(),
            );
            return;
        };
        let Some(actual) = hash_box_entry(alg, data, selected, &box_exclusions, format) else {
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
        results.push_failure(
            ASSERTION_BOXES_HASH_MISMATCH,
            url,
            "box hash mismatch: asset bytes altered".into(),
        );
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
    claim: &Value,
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
    let Some(alg) = resolved_hash_algorithm(&map, claim) else {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            "collection hash assertion and claim have no hash algorithm".into(),
        );
        return;
    };
    if !is_allowed_hash_algorithm(alg) {
        results.push_failure(
            ALGORITHM_UNSUPPORTED,
            url,
            format!("collection hash assertion uses unsupported hash algorithm '{alg}'"),
        );
        return;
    }

    let index = match crate::c2pa_formats::zip_index(data) {
        Ok(index) => index,
        Err(error) => {
            malformed(
                results,
                format!("asset is not a readable ZIP archive: {error}"),
            );
            return;
        }
    };
    let cd_parts = index.central_directory_hash_parts();
    let Some(expected_cd) = map
        .get("zip_central_directory_hash")
        .and_then(Value::as_bytes)
    else {
        malformed(results, "zip_central_directory_hash missing".into());
        return;
    };

    let mut declared = std::collections::HashSet::with_capacity(uris.len());

    for u in uris {
        let (Some(uri), Some(expected)) = (
            u.get("uri").and_then(Value::as_text),
            u.get("hash").and_then(Value::as_bytes),
        ) else {
            malformed(results, "uri entry missing uri or hash".into());
            return;
        };
        let Some(member_name) = canonical_collection_uri_member(uri) else {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_INVALID_URI,
                url,
                format!("uri '{uri}' is not a canonical relative collection URI"),
            );
            return;
        };
        if !declared.insert(uri.to_string()) {
            malformed(results, format!("duplicate collection URI '{uri}'"));
            return;
        }
        let Some(member) = index.get(member_name.as_bytes()) else {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_INCORRECT_FILE_COUNT,
                url,
                format!("listed file '{member_name}' not found in archive"),
            );
            return;
        };
        let (start, end) = member.hash_span();
        let exact_match =
            hash_bytes(alg, &data[start..end]).is_some_and(|hash| hash.as_slice() == expected);
        let public_vector_match = !exact_match && {
            let (local_start, local_end) = member.local_span();
            hash_bytes(alg, &data[local_start..local_end])
                .is_some_and(|hash| hash.as_slice() == expected)
        };
        if !(exact_match || public_vector_match) {
            results.push_failure(
                ASSERTION_COLLECTION_HASH_MISMATCH,
                url,
                format!("collection entry '{member_name}' hash mismatch"),
            );
            return;
        }
    }

    let cd_ok = hash_parts(alg, cd_parts).is_some_and(|h| h.as_slice() == expected_cd);
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

fn canonical_collection_member_uri(member: &str) -> Option<String> {
    if member.is_empty()
        || member.starts_with('/')
        || member.contains('\\')
        || member.bytes().any(|byte| byte.is_ascii_control())
        || member
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return None;
    }
    let mut uri = String::with_capacity(member.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in member.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[(byte >> 4) as usize]));
            uri.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    Some(uri)
}

fn canonical_collection_uri_member(uri: &str) -> Option<String> {
    let bytes = uri.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                let nibble = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'A'..=b'F' => Some(byte - b'A' + 10),
                    _ => None,
                };
                decoded.push((nibble(high)? << 4) | nibble(low)?);
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') =>
            {
                decoded.push(byte);
                index += 1;
            }
            _ => return None,
        }
    }
    let member = String::from_utf8(decoded).ok()?;
    (canonical_collection_member_uri(&member).as_deref() == Some(uri)).then_some(member)
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

/// Maximum number of parts in one multi-asset assertion.
const MAX_MULTI_ASSET_PARTS: usize = 4_096;

/// Verify a `c2pa.hash.multi-asset` fallback binding using the locator and
/// hard-binding methodology declared for each part.
///
/// A byte-offset locator hashes its declared range. A `bmffBox` locator uses
/// the bounded BMFF path resolver for coverage, then hashes only the selected
/// box payload, excluding its box header as required by C2PA 2.4 section
/// 18.9.2. Part assertions remain typed as data, BMFF, or general-box hashes;
/// unsupported labels and malformed methodology fail closed.
fn multi_asset_part_label_is(label: &str, base: &str) -> bool {
    label == base
        || label
            .strip_prefix(base)
            .and_then(|suffix| suffix.strip_prefix("__"))
            .is_some_and(|instance| !instance.is_empty())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MultiAssetPartMethod {
    Data,
    Bmff,
    Boxes,
}

fn multi_asset_part_method(label: &str) -> Option<MultiAssetPartMethod> {
    if multi_asset_part_label_is(label, "c2pa.hash.data.part") {
        Some(MultiAssetPartMethod::Data)
    } else if multi_asset_part_label_is(label, "c2pa.hash.bmff.v2.part")
        || multi_asset_part_label_is(label, "c2pa.hash.bmff.v3.part")
    {
        Some(MultiAssetPartMethod::Bmff)
    } else if multi_asset_part_label_is(label, "c2pa.hash.boxes.part") {
        Some(MultiAssetPartMethod::Boxes)
    } else {
        None
    }
}

/// Convert a full BMFF box span into its content span. ISO base box fields and
/// the UUID user type are box-header bytes, not part content.
fn bmff_box_payload_bounds(
    data: &[u8],
    box_start: usize,
    box_length: usize,
) -> Option<(usize, usize)> {
    let box_end = box_start.checked_add(box_length)?;
    let header = data.get(box_start..box_start.checked_add(8)?)?;
    if box_end > data.len() {
        return None;
    }
    let size32 = u32::from_be_bytes(header[..4].try_into().ok()?);
    let mut header_length: usize = match size32 {
        0 => 8,
        1 => {
            let extended = data.get(box_start..box_start.checked_add(16)?)?;
            let declared =
                usize::try_from(u64::from_be_bytes(extended[8..16].try_into().ok()?)).ok()?;
            if declared != box_length {
                return None;
            }
            16
        }
        declared => {
            if declared as usize != box_length {
                return None;
            }
            8
        }
    };
    if &header[4..8] == b"uuid" {
        header_length = header_length.checked_add(16)?;
    }
    if header_length > box_length {
        return None;
    }
    Some((
        box_start.checked_add(header_length)?,
        box_length - header_length,
    ))
}

fn multi_asset_general_box_format(data: &[u8]) -> Option<AssetFormat> {
    [AssetFormat::Jpeg, AssetFormat::Png]
        .into_iter()
        .find(|format| matches!(crate::c2pa_formats::box_spans(*format, data), Ok(Some(_))))
}

#[allow(clippy::too_many_arguments)] // multi-asset validation carries the parent verification context
fn verify_multi_asset(
    claim: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    ma_cbor: &[u8],
    data: &[u8],
    format: AssetFormat,
    label: &str,
    profile: EngineProfile,
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
    if parts.len() > MAX_MULTI_ASSET_PARTS {
        results.push_failure(
            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
            url,
            format!("multi-asset part count exceeds verifier bound ({MAX_MULTI_ASSET_PARTS})"),
        );
        return;
    }
    let bmff_paths: Vec<&str> = parts
        .iter()
        .filter_map(|part| {
            part.get("location")?
                .get("bmffBox")?
                .as_text()
                .filter(|path| !path.is_empty())
        })
        .collect();
    let bmff_locator_ranges = if format == AssetFormat::Bmff && !bmff_paths.is_empty() {
        match crate::c2pa_formats::bmff_box_ranges(data, &bmff_paths) {
            Ok(ranges) => ranges,
            Err(error) => {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                    url,
                    format!("BMFF locator plan is invalid: {error}"),
                );
                return;
            }
        }
    } else {
        Vec::new()
    };
    let mut bmff_locator_index = 0usize;

    enum Locator<'a> {
        ByteOffset {
            start: usize,
            length: usize,
        },
        BmffBox {
            path: &'a str,
            box_start: usize,
            box_length: usize,
            content_start: usize,
            content_length: usize,
        },
    }

    impl Locator<'_> {
        fn coverage_bounds(&self) -> (usize, usize) {
            match self {
                Self::ByteOffset { start, length } => (*start, *length),
                Self::BmffBox {
                    box_start,
                    box_length,
                    ..
                } => (*box_start, *box_length),
            }
        }

        fn content_bounds(&self) -> (usize, usize) {
            match self {
                Self::ByteOffset { start, length } => (*start, *length),
                Self::BmffBox {
                    content_start,
                    content_length,
                    ..
                } => (*content_start, *content_length),
            }
        }

        fn description(&self) -> String {
            match self {
                Self::ByteOffset { start, length } => {
                    format!("byte range [{start}, {})", start.saturating_add(*length))
                }
                Self::BmffBox { path, .. } => format!("BMFF box '{path}'"),
            }
        }
    }

    enum Method<'a> {
        Data {
            algorithm: &'a str,
            expected: &'a [u8],
            exclusions: Vec<(usize, usize)>,
        },
        Bmff {
            hash_data: &'a Value,
            algorithm: &'a str,
            expected: Option<&'a [u8]>,
            exclusions: Vec<crate::c2pa_formats::BmffExclusionMap>,
            merkle: bool,
        },
        Boxes {
            cbor: &'a [u8],
        },
    }

    struct Part<'a> {
        locator: Locator<'a>,
        optional: bool,
        label: &'a str,
        method: Method<'a>,
    }

    let mut collected = Vec::with_capacity(parts.len());
    for part in parts {
        let optional = match part.get("optional") {
            None => false,
            Some(Value::Bool(optional)) => *optional,
            Some(_) => {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                    url,
                    "multi-asset part optional flag is not a boolean".into(),
                );
                return;
            }
        };
        let Some(location) = part.get("location") else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                "multi-asset part has no locator".into(),
            );
            return;
        };
        let has_byte_offset = location.get("byteOffset").is_some();
        let has_length = location.get("length").is_some();
        let has_bmff_box = location.get("bmffBox").is_some();
        let locator = match (has_byte_offset, has_length, has_bmff_box) {
            (true, true, false) => {
                let (Some(start), Some(length)) = (
                    location.get("byteOffset").and_then(int_usize),
                    location.get("length").and_then(int_usize),
                ) else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        "byte-offset locator has a negative or non-integer bound".into(),
                    );
                    return;
                };
                Locator::ByteOffset { start, length }
            }
            (false, false, true) => {
                let Some(path) = location
                    .get("bmffBox")
                    .and_then(Value::as_text)
                    .filter(|path| !path.is_empty())
                else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        "bmffBox locator is not a non-empty string".into(),
                    );
                    return;
                };
                if format != AssetFormat::Bmff {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        "bmffBox locator used for a non-BMFF asset".into(),
                    );
                    return;
                }
                let ranges = &bmff_locator_ranges[bmff_locator_index];
                bmff_locator_index += 1;
                let [(box_start, box_length)] = ranges.as_slice() else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        format!("bmffBox locator '{path}' must resolve to exactly one box"),
                    );
                    return;
                };
                let Some((content_start, content_length)) =
                    bmff_box_payload_bounds(data, *box_start, *box_length)
                else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        format!("bmffBox locator '{path}' resolved to malformed bounds"),
                    );
                    return;
                };
                Locator::BmffBox {
                    path,
                    box_start: *box_start,
                    box_length: *box_length,
                    content_start,
                    content_length,
                }
            }
            _ => {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                    url,
                    "locator must contain exactly byteOffset+length or bmffBox".into(),
                );
                return;
            }
        };

        let Some(hash_assertion) = part.get("hashAssertion") else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                "multi-asset part has no hashAssertion".into(),
            );
            return;
        };
        let Some(part_url) = hash_assertion.get("url").and_then(Value::as_text) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                "part hashAssertion is not a HashedUri".into(),
            );
            return;
        };
        let Some(part_label) = assertion_label_for_manifest(part_url, label) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hash assertion URI '{part_url}' is not local to the claim"),
            );
            return;
        };
        let Some(method_kind) = multi_asset_part_method(part_label) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hash assertion '{part_label}' is not a supported .part method"),
            );
            return;
        };

        let nested_hash = hash_assertion.get("hash").and_then(Value::as_bytes);
        let nested_algorithm = resolved_hash_algorithm(hash_assertion, claim);
        let exact_declaration = claim_refs.references.iter().find(|reference| {
            reference.label == Some(part_label)
                && nested_hash.is_some()
                && reference.value.get("hash").and_then(Value::as_bytes) == nested_hash
                && resolved_hash_algorithm(reference.value, claim) == nested_algorithm
        });
        let (Some(nested_hash), Some(nested_algorithm), Some(_)) =
            (nested_hash, nested_algorithm, exact_declaration)
        else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hashAssertion '{part_label}' is not an exact declared HashedUri"),
            );
            return;
        };
        if !is_allowed_hash_algorithm(nested_algorithm) {
            results.push_failure(
                ALGORITHM_UNSUPPORTED,
                url,
                format!(
                    "part hashAssertion '{part_label}' uses unsupported hash algorithm '{nested_algorithm}'"
                ),
            );
            return;
        }
        if bmff_digest_len(nested_algorithm) != Some(nested_hash.len()) {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hashAssertion '{part_label}' has an invalid digest"),
            );
            return;
        }
        let Some(indexed) = claim_refs.indexed(part_label) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hash assertion '{part_label}' is not indexed"),
            );
            return;
        };
        let Some(part_hash) = indexed.decoded.as_ref() else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("part hash assertion '{part_label}' is missing or invalid CBOR"),
            );
            return;
        };
        let (_, part_content_length) = locator.content_bounds();
        let method = match method_kind {
            MultiAssetPartMethod::Data => {
                let Some(expected) = part_hash.get("hash").and_then(Value::as_bytes) else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        format!("data hash part assertion '{part_label}' has no hash"),
                    );
                    return;
                };
                let Some(algorithm) = resolved_hash_algorithm(part_hash, &ma)
                    .or_else(|| claim.get("alg").and_then(Value::as_text))
                else {
                    results.push_failure(
                        ALGORITHM_UNSUPPORTED,
                        url,
                        format!("data hash part '{part_label}' has no hash algorithm"),
                    );
                    return;
                };
                if bmff_digest_len(algorithm) != Some(expected.len()) {
                    results.push_failure(
                        ALGORITHM_UNSUPPORTED,
                        url,
                        format!("data hash part '{part_label}' has an unsupported algorithm or digest width"),
                    );
                    return;
                }
                let exclusions = match parse_local_part_exclusions(
                    part_hash.get("exclusions"),
                    part_content_length,
                ) {
                    Ok(exclusions) => exclusions,
                    Err(error) => {
                        results.push_failure(
                                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                                url,
                                format!(
                                    "data hash part assertion '{part_label}' has invalid exclusions: {error}"
                                ),
                            );
                        return;
                    }
                };
                Method::Data {
                    algorithm,
                    expected,
                    exclusions,
                }
            }
            MultiAssetPartMethod::Bmff => {
                let merkle = part_hash.get("merkle").is_some();
                let expected = part_hash.get("hash").and_then(Value::as_bytes);
                if !merkle && expected.is_none() {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        format!("BMFF part assertion '{part_label}' has no hash or merkle tree"),
                    );
                    return;
                }
                let Some(algorithm) = resolved_hash_algorithm(part_hash, &ma)
                    .or_else(|| claim.get("alg").and_then(Value::as_text))
                else {
                    results.push_failure(
                        ALGORITHM_UNSUPPORTED,
                        url,
                        format!("BMFF part '{part_label}' has no hash algorithm"),
                    );
                    return;
                };
                if bmff_algorithm_index(algorithm).is_none()
                    || expected.is_some_and(|hash| bmff_digest_len(algorithm) != Some(hash.len()))
                {
                    results.push_failure(
                        ALGORITHM_UNSUPPORTED,
                        url,
                        format!(
                            "BMFF part '{part_label}' has an unsupported algorithm or digest width"
                        ),
                    );
                    return;
                }
                let exclusions = match bmff_exclusion_maps(part_hash) {
                    Ok(exclusions) => exclusions,
                    Err(error) => {
                        results.push_failure(
                            ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                            url,
                            format!(
                                "BMFF part assertion '{part_label}' has invalid exclusions: {error}"
                            ),
                        );
                        return;
                    }
                };
                Method::Bmff {
                    hash_data: part_hash,
                    algorithm,
                    expected,
                    exclusions,
                    merkle,
                }
            }
            MultiAssetPartMethod::Boxes => {
                let Some(cbor) = indexed.payload else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url,
                        format!("general-box part assertion '{part_label}' has no payload"),
                    );
                    return;
                };
                Method::Boxes { cbor }
            }
        };
        collected.push(Part {
            locator,
            optional,
            label: part_label,
            method,
        });
    }

    let mut expected_start = 0usize;
    for part in &collected {
        let (start, length) = part.locator.coverage_bounds();
        if start != expected_start {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!(
                    "multi-asset parts are not contiguous and ordered: '{}' starts at {start} (expected {expected_start})",
                    part.label
                ),
            );
            return;
        }
        let Some(end) = start.checked_add(length) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url,
                format!("multi-asset part '{}' bounds overflow", part.label),
            );
            return;
        };
        expected_start = end;
    }
    let declared_end = expected_start;

    let mut any_failure = false;
    for part in &collected {
        let (content_start, content_length) = part.locator.content_bounds();
        let Some(content_end) = content_start.checked_add(content_length) else {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                url.clone(),
                format!("multi-asset part '{}' content bounds overflow", part.label),
            );
            any_failure = true;
            continue;
        };
        if content_start > data.len() || (content_start == data.len() && content_length != 0) {
            if !part.optional {
                results.push_failure(
                    ASSERTION_MULTI_ASSET_HASH_MISSING_PART,
                    url.clone(),
                    format!("required part '{}' is absent", part.label),
                );
                any_failure = true;
            }
            continue;
        }
        if content_end > data.len() {
            results.push_failure(
                ASSERTION_MULTI_ASSET_HASH_MISMATCH,
                url.clone(),
                format!(
                    "part '{}' is truncated: {} exceeds asset length {}",
                    part.label,
                    part.locator.description(),
                    data.len()
                ),
            );
            any_failure = true;
            continue;
        }

        let content = &data[content_start..content_end];
        let outcome = match &part.method {
            Method::Data {
                algorithm,
                expected,
                exclusions,
            } => match hash_with_exclusions(algorithm, content, exclusions) {
                Some(actual) if actual.as_slice() == *expected => Ok(()),
                Some(_) => Err((false, "data hash mismatch".to_string())),
                None => Err((true, "data hash algorithm is unsupported".to_string())),
            },
            Method::Bmff {
                hash_data,
                algorithm,
                expected,
                exclusions,
                merkle,
            } => {
                let top_level = match expected {
                    Some(expected) => match crate::c2pa_formats::bmff_hash_with_exclusions(
                        content, algorithm, exclusions,
                    ) {
                        Ok(actual) if actual.as_slice() == *expected => Ok(()),
                        Ok(_) => Err((false, "BMFF structural hash mismatch".to_string())),
                        Err(error) => Err((true, format!("BMFF part hashing failed: {error}"))),
                    },
                    None => Ok(()),
                };
                if top_level.is_err() || !merkle {
                    top_level
                } else {
                    let mut part_results = ValidationResults::default();
                    verify_bmff_merkle_init(
                        BmffMerkleInput {
                            hash_data,
                            assertion_alg: algorithm,
                            exclusions,
                            data: content,
                            fragments: &[],
                            url: &url,
                            binding_compromised: false,
                        },
                        &mut part_results,
                    );
                    if part_results.failure.is_empty()
                        && part_results.has_success(ASSERTION_BMFF_HASH_MATCH)
                    {
                        Ok(())
                    } else {
                        let malformed = part_results
                            .failure
                            .iter()
                            .any(|status| status.code == ASSERTION_BMFF_HASH_MALFORMED);
                        let explanation = part_results
                            .failure
                            .first()
                            .map(|status| status.explanation.clone())
                            .unwrap_or_else(|| "BMFF merkle methodology did not validate".into());
                        Err((malformed, explanation))
                    }
                }
            }
            Method::Boxes { cbor } => {
                let Some(part_format) = multi_asset_general_box_format(content) else {
                    results.push_failure(
                        ASSERTION_MULTI_ASSET_HASH_MALFORMED,
                        url.clone(),
                        format!(
                            "general-box part '{}' is not a supported JPEG or PNG part",
                            part.label
                        ),
                    );
                    any_failure = true;
                    continue;
                };
                let mut part_results = ValidationResults::default();
                verify_boxes_hash(
                    cbor,
                    claim,
                    part_format,
                    content,
                    false,
                    label,
                    profile,
                    &mut part_results,
                );
                if part_results.failure.is_empty()
                    && part_results.has_success(ASSERTION_BOXES_HASH_MATCH)
                {
                    Ok(())
                } else {
                    let malformed = part_results.failure.iter().any(|status| {
                        status.code == ASSERTION_BOXES_HASH_MALFORMED
                            || status.code == ALGORITHM_UNSUPPORTED
                    });
                    let explanation = part_results
                        .failure
                        .first()
                        .map(|status| status.explanation.clone())
                        .unwrap_or_else(|| "general-box methodology did not validate".into());
                    Err((malformed, explanation))
                }
            }
        };
        if let Err((malformed, explanation)) = outcome {
            results.push_failure(
                if malformed {
                    ASSERTION_MULTI_ASSET_HASH_MALFORMED
                } else {
                    ASSERTION_MULTI_ASSET_HASH_MISMATCH
                },
                url.clone(),
                format!("part '{}' failed: {explanation}", part.label),
            );
            any_failure = true;
        }
    }

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
fn bmff_has_additional_exclusions(
    exclusions: &[crate::c2pa_formats::BmffExclusionMap],
    merkle_present: bool,
) -> bool {
    exclusions.iter().any(|exclusion| {
        let path = exclusion.xpath.as_str();
        let c2pa_uuid = path == "/uuid"
            || (path.starts_with("/uuid[")
                && ["type=c2pa", "type='c2pa'", "type=\"c2pa\""]
                    .iter()
                    .any(|selector| path.contains(selector)));
        let mandatory = c2pa_uuid
            || path == "/ftyp"
            || path.starts_with("/ftyp[")
            || path == "/mfra"
            || path.starts_with("/mfra[")
            || (merkle_present && (path == "/mdat" || path.starts_with("/mdat[")));
        !mandatory
    })
}

/// Normalize every field of a BMFF v2/v3 exclusion map.
fn bmff_exclusion_maps(
    hash_data: &Value,
) -> Result<Vec<crate::c2pa_formats::BmffExclusionMap>, &'static str> {
    let Some(Value::Array(items)) = hash_data.get("exclusions") else {
        return Err("BMFF hash assertion has no exclusions array");
    };
    if items.is_empty() {
        return Err("BMFF exclusion list is empty");
    }
    if items.len() > MAX_DATA_HASH_EXCLUSIONS {
        return Err("BMFF exclusion list exceeds the verifier cap");
    }

    let mut total_data_qualifiers = 0usize;
    let mut total_data_bytes = 0usize;
    let mut total_subsets = 0usize;
    let mut exclusions = Vec::with_capacity(items.len());
    for item in items {
        let xpath = item
            .get("xpath")
            .and_then(Value::as_text)
            .filter(|xpath| !xpath.is_empty())
            .ok_or("BMFF exclusion is missing xpath")?;
        if xpath.len() > MAX_BMFF_EXCLUSION_XPATH_BYTES {
            return Err("BMFF exclusion xpath exceeds the verifier cap");
        }
        let xpath = xpath.to_string();
        let length = match item.get("length") {
            Some(Value::Null) | None => None,
            Some(value) => Some(int_usize(value).ok_or("BMFF exclusion length is invalid")?),
        };
        let version = match item.get("version") {
            Some(Value::Null) | None => None,
            Some(value) => Some(
                u8::try_from(int_usize(value).ok_or("BMFF exclusion version is invalid")?)
                    .map_err(|_| "BMFF exclusion version is invalid")?,
            ),
        };
        let flags = match item.get("flags") {
            Some(Value::Null) | None => None,
            Some(Value::Bytes(bytes)) if bytes.len() == 3 => {
                Some(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
            }
            Some(_) => return Err("BMFF exclusion flags must be a three-byte string"),
        };
        let exact = match item.get("exact") {
            Some(Value::Null) | None => true,
            Some(Value::Bool(value)) => *value,
            Some(_) => return Err("BMFF exclusion exact field is not a boolean"),
        };
        if !matches!(item.get("exact"), None | Some(Value::Null)) && flags.is_none() {
            return Err("BMFF exclusion exact field requires flags");
        }
        let data = match item.get("data") {
            Some(Value::Array(maps)) if maps.is_empty() => {
                return Err("BMFF exclusion data field is empty")
            }
            Some(Value::Array(maps)) => {
                total_data_qualifiers = total_data_qualifiers
                    .checked_add(maps.len())
                    .filter(|count| *count <= MAX_BMFF_EXCLUSION_DATA_QUALIFIERS)
                    .ok_or("BMFF exclusion data qualifiers exceed the verifier cap")?;
                let mut normalized = Vec::with_capacity(maps.len());
                for map in maps {
                    let value = map
                        .get("value")
                        .and_then(Value::as_bytes)
                        .ok_or("BMFF exclusion data value is invalid")?;
                    total_data_bytes = total_data_bytes
                        .checked_add(value.len())
                        .filter(|bytes| *bytes <= MAX_BMFF_EXCLUSION_DATA_BYTES)
                        .ok_or("BMFF exclusion data bytes exceed the verifier cap")?;
                    normalized.push(crate::c2pa_formats::BmffDataMap {
                        offset: map
                            .get("offset")
                            .and_then(int_usize)
                            .ok_or("BMFF exclusion data offset is invalid")?,
                        value: value.to_vec(),
                    });
                }
                normalized
            }
            Some(Value::Null) | None => Vec::new(),
            Some(_) => return Err("BMFF exclusion data field is not an array"),
        };
        let subset = match item.get("subset") {
            Some(Value::Array(maps)) if maps.is_empty() => {
                return Err("BMFF exclusion subset field is empty")
            }
            Some(Value::Array(maps)) => {
                total_subsets = total_subsets
                    .checked_add(maps.len())
                    .filter(|count| *count <= MAX_BMFF_EXCLUSION_SUBSETS)
                    .ok_or("BMFF exclusion subsets exceed the verifier cap")?;
                let mut normalized = Vec::with_capacity(maps.len());
                let mut previous_end = None;
                for (index, map) in maps.iter().enumerate() {
                    let offset = map
                        .get("offset")
                        .and_then(int_usize)
                        .ok_or("BMFF exclusion subset offset is invalid")?;
                    let length = map
                        .get("length")
                        .and_then(int_usize)
                        .ok_or("BMFF exclusion subset length is invalid")?;
                    if length == 0 && index + 1 != maps.len() {
                        return Err("only the final BMFF exclusion subset may have zero length");
                    }
                    if previous_end.is_some_and(|end| offset < end) {
                        return Err("BMFF exclusion subsets overlap or are not sorted");
                    }
                    previous_end = Some(offset.saturating_add(length));
                    normalized.push(crate::c2pa_formats::BmffSubsetMap { offset, length });
                }
                normalized
            }
            Some(Value::Null) | None => Vec::new(),
            Some(_) => return Err("BMFF exclusion subset field is not an array"),
        };
        exclusions.push(crate::c2pa_formats::BmffExclusionMap {
            xpath,
            length,
            data,
            subset,
            version,
            flags,
            exact,
        });
    }
    Ok(exclusions)
}
fn parse_local_part_exclusions(
    value: Option<&Value>,
    part_len: usize,
) -> Result<Vec<(usize, usize)>, &'static str> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err("exclusions is not an array");
    };
    if items.len() > MAX_DATA_HASH_EXCLUSIONS {
        return Err("exclusion list exceeds the verifier cap");
    }
    let mut ranges = Vec::with_capacity(items.len());
    for item in items {
        let start = item
            .get("start")
            .and_then(int_usize)
            .ok_or("exclusion start is missing or invalid")?;
        let length = item
            .get("length")
            .and_then(int_usize)
            .ok_or("exclusion length is missing or invalid")?;
        let end = start
            .checked_add(length)
            .ok_or("exclusion range overflows")?;
        if end > part_len {
            return Err("exclusion range extends beyond the located part");
        }
        ranges.push((start, length));
    }
    ranges.sort_by_key(|(start, _)| *start);
    Ok(ranges)
}

/// Interpret a CBOR integer as a `usize`, rejecting negatives.
fn int_usize(value: &Value) -> Option<usize> {
    match value {
        Value::Integer(n) if *n >= 0 => usize::try_from(*n).ok(),
        _ => None,
    }
}

fn hash_normalized_unstructured_text(
    alg: &str,
    data: &[u8],
    exclusions: &[(usize, usize)],
) -> Result<Option<Vec<u8>>, &'static str> {
    if let [(start, length)] = exclusions {
        let end = start
            .checked_add(*length)
            .ok_or("text wrapper exclusion range overflows")?;
        let remainder = if *start == 0 {
            &data[end..]
        } else if end == data.len() {
            &data[..*start]
        } else {
            &[]
        };
        if !remainder.is_empty() || data.len() == *length {
            let text = std::str::from_utf8(remainder)
                .map_err(|_| "text outside the wrapper is not valid UTF-8")?;
            if text.chars().eq(text.nfc()) {
                return Ok(hash_bytes(alg, remainder));
            }
            let normalized: String = text.nfc().collect();
            return Ok(hash_bytes(alg, normalized.as_bytes()));
        }
    }

    let excluded_bytes = exclusions
        .iter()
        .try_fold(0usize, |total, (_, length)| total.checked_add(*length))
        .ok_or("aggregate text exclusion length overflows")?;
    let mut clean = Vec::with_capacity(data.len().saturating_sub(excluded_bytes));
    let mut position = 0usize;
    for &(start, length) in exclusions {
        let end = start
            .checked_add(length)
            .ok_or("text wrapper exclusion range overflows")?;
        clean.extend_from_slice(
            data.get(position..start)
                .ok_or("text wrapper exclusions are out of order")?,
        );
        position = end;
    }
    clean.extend_from_slice(
        data.get(position..)
            .ok_or("text wrapper exclusion extends beyond the asset")?,
    );
    let text =
        std::str::from_utf8(&clean).map_err(|_| "text outside the wrapper is not valid UTF-8")?;
    if text.chars().eq(text.nfc()) {
        return Ok(hash_bytes(alg, &clean));
    }
    let normalized: String = text.nfc().collect();
    Ok(hash_bytes(alg, normalized.as_bytes()))
}

/// Hash `data` skipping the given byte ranges, per the C2PA data-hash binding.
fn hash_with_exclusions(alg: &str, data: &[u8], exclusions: &[(usize, usize)]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    let mut pos = 0usize;
    for &(start, length) in exclusions {
        let end = start.checked_add(length)?;
        if pos < start {
            hasher.update(&data[pos..start]);
        }
        pos = end.max(pos);
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

/// Hash the canonical Claim Signature superbox payload used by ingredient v3.
///
/// C2PA hashes the payload written by JUMBF `write_box_payload`: the `jumd`
/// description box followed by the `cbor` content box, without the outer
/// `jumb` header. Stream the encoding into the digest to avoid copying COSE.
fn hash_claim_signature_box(alg: &str, cose: &[u8]) -> Option<Vec<u8>> {
    const LABEL: &[u8] = b"c2pa.signature";
    let mut hasher = Hasher::new(alg)?;
    update_box_header(&mut hasher, b"jumd", 16 + 1 + LABEL.len() + 1)?;
    hasher.update(&crate::c2pa_core::jumbf::UUID_CLAIM_SIGNATURE);
    hasher.update(&[0x03]); // label present + requestable
    hasher.update(LABEL);
    hasher.update(&[0]);
    update_box_header(&mut hasher, b"cbor", cose.len())?;
    hasher.update(cose);
    Some(hasher.finalize())
}

fn update_box_header(hasher: &mut Hasher, box_type: &[u8; 4], payload_len: usize) -> Option<()> {
    let short_size = payload_len.checked_add(8)?;
    if u32::try_from(short_size).is_ok() {
        hasher.update(&(short_size as u32).to_be_bytes());
        hasher.update(box_type);
    } else {
        let extended_size = u64::try_from(short_size.checked_add(8)?).ok()?;
        hasher.update(&1u32.to_be_bytes());
        hasher.update(box_type);
        hasher.update(&extended_size.to_be_bytes());
    }
    Some(())
}

/// Compute one digest over a sequence of discontiguous byte slices.
fn hash_parts(alg: &str, parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut hasher = Hasher::new(alg)?;
    for part in parts {
        hasher.update(part);
    }
    Some(hasher.finalize())
}

/// The hash algorithms C2PA 2.4 permits for content hashing.
#[derive(Clone, Copy)]
enum ContentHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ContentHashAlgorithm {
    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn cache_index(self) -> usize {
        match self {
            Self::Sha256 => 0,
            Self::Sha384 => 1,
            Self::Sha512 => 2,
        }
    }
}

fn content_hash_algorithm(algorithm: &str) -> Option<ContentHashAlgorithm> {
    match algorithm {
        "sha256" => Some(ContentHashAlgorithm::Sha256),
        "sha384" => Some(ContentHashAlgorithm::Sha384),
        "sha512" => Some(ContentHashAlgorithm::Sha512),
        _ => None,
    }
}

fn is_allowed_hash_algorithm(algorithm: &str) -> bool {
    content_hash_algorithm(algorithm).is_some()
}

/// A dynamically-dispatched hash implementation selected by algorithm name.
enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn new(alg: &str) -> Option<Self> {
        Some(match content_hash_algorithm(alg)? {
            ContentHashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            ContentHashAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            ContentHashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
        })
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha384(hasher) => hasher.update(bytes),
            Self::Sha512(hasher) => hasher.update(bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
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
    program::PROGRAM_REVOCATION_INFORMATION_MISSING,
    program::PROGRAM_TRUSTED_TIMESTAMP_MISSING,
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
/// CAWG Identity 1.3 specification layers ON TOP of the C2PA Manifest Consumer
/// (§3.1.7/§3.1.9; §9.4.6 gates identity interpretation on manifest validity,
/// never the reverse). They therefore NEVER break C2PA manifest integrity in
/// either posture: a tampered identity assertion still sinks the manifest via
/// the C2PA-level `assertion.hashedURI.mismatch`, while an unverifiable or
/// untrusted identity credential leaves the manifest verdict intact and is
/// reported on the assertion itself. Matches the reference implementation,
/// which tracks CAWG outcomes in a separate status section.
fn is_identity_assertion_scoped(code: &str) -> bool {
    code.starts_with("cawg.") || code.starts_with("com.encypher.cawg.")
}

/// External-data-scoped failure test. C2PA 2.4 Validation, External Data
/// Validation, General is explicit that retrieval is optional and that "the
/// inability to retrieve or validate external data shall not cause a claim to
/// be rejected", so these codes are reported at their registered severity but
/// never invalidate a manifest - in either posture, because the spec draws no
/// posture distinction here.
///
/// `assertion.inaccessible` is external data by definition.
/// `assertion.hashedURI.mismatch` is not: it is also how a claim's own broken
/// binding to an embedded assertion is reported, which does invalidate. The
/// external-data emitters mark their statuses with `external_data: true`, and
/// only a marked status is carved out.
fn is_external_data_scoped(status: &StatusCode) -> bool {
    if status.code == ASSERTION_INACCESSIBLE {
        return true;
    }
    status.code == ASSERTION_HASHED_URI_MISMATCH
        && status
            .details
            .as_ref()
            .and_then(|details| details.get("external_data"))
            .and_then(Json::as_bool)
            == Some(true)
}

/// Construction-integrity failure test (posture-independent): a failure
/// breaks construction integrity unless it is one of the surfaced, non-
/// invalidating caveats ([`REGULAR_INTEGRITY_CAVEATS`]), an identity-
/// assertion-scoped `cawg.*` code, or an external-data outcome. Single source
/// of truth behind the generous `validation_state`, the
/// `provenance_verdict.integrity` axis, and the `validated_under` clearing, so
/// those cannot drift apart.
fn is_construction_integrity_invalidating(status: &StatusCode) -> bool {
    !REGULAR_INTEGRITY_CAVEATS.contains(&status.code.as_str())
        && !is_identity_assertion_scoped(&status.code)
        && !is_external_data_scoped(status)
}

/// True when `status` invalidates manifest *integrity* under `profile`.
/// Unknown/new failure codes default to invalidating in both postures.
fn is_integrity_invalidating(status: &StatusCode, profile: EngineProfile) -> bool {
    if is_generous(profile) {
        is_construction_integrity_invalidating(status)
    } else {
        // Strict: every failure invalidates except the always-non-invalidating
        // untrusted-signer signal (byte-for-byte the prior rule) and the
        // identity-assertion-scoped CAWG codes.
        status.code != SIGNING_CREDENTIAL_UNTRUSTED
            && !is_identity_assertion_scoped(&status.code)
            && !is_external_data_scoped(status)
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
        .any(|status| is_integrity_invalidating(status, profile));
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
fn provenance_verdict_json(
    results: &ValidationResults,
    present: bool,
    profile: EngineProfile,
) -> Json {
    let strict_credential_failure = !is_generous(profile)
        && results.failure.iter().any(|status| {
            matches!(
                status.code.as_str(),
                SIGNING_CREDENTIAL_OCSP_REVOKED | CLAIM_SIGNATURE_OUTSIDE_VALIDITY
            )
        });
    let integrity_invalid = !present
        || strict_credential_failure
        || results
            .failure
            .iter()
            .any(is_construction_integrity_invalidating);
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

/// Assemble the final [`VerifyOutput`] including the reader-report JSON.
#[allow(clippy::too_many_arguments)] // internal report assembler; a params struct adds noise
fn finish(
    label: String,
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    declared_assertions: Option<&std::collections::HashSet<&str>>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
    mut results: ValidationResults,
    verdict: Option<VersionVerdict>,
    profile: EngineProfile,
    report_decode_nodes: &mut usize,
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
            .any(is_construction_integrity_invalidating)
    } else {
        // Strict / conformance: policy-bar failures leave `validated_under`
        // intact; only a real construction defect clears it.
        const POLICY_CODES: [&str; 3] = [
            SIGNING_CREDENTIAL_UNTRUSTED,
            SIGNING_CREDENTIAL_OCSP_SKIPPED,
            CONFORMANCE_SPEC_VERSION_NONCONFORMANT,
        ];
        results.failure.iter().any(|s| {
            !POLICY_CODES.contains(&s.code.as_str())
                && !PROGRAM_FAILURE_CODES.contains(&s.code.as_str())
                && !is_identity_assertion_scoped(&s.code)
        })
    };
    let mut verdict = verdict;
    if integrity_broken {
        if let Some(v) = verdict.as_mut() {
            v.validated_under = None;
        }
    }
    let mut report_json = build_report(
        &label,
        manifest,
        claim,
        declared_assertions,
        chain,
        cose,
        &results,
        state,
        report_decode_nodes,
    );
    if let Some(obj) = report_json.as_object_mut() {
        // A manifest reached `finish`, so provenance is present.
        obj.insert(
            "provenance_verdict".to_string(),
            provenance_verdict_json(&results, true, profile),
        );
    }
    if let Some(v) = &verdict {
        if let Some(obj) = report_json.as_object_mut() {
            obj.insert("version_verdict".to_string(), v.to_json());
        }
    }
    VerifyOutput {
        validation_state: state,
        network_needs: std::mem::take(&mut results.network_needs),
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
        "provenance_verdict": provenance_verdict_json(&results, present, profile),
    });
    VerifyOutput {
        validation_state: state,
        network_needs: Vec::new(),
        results,
        report_json,
        crjson: None,
        version_verdict: None,
    }
}
fn failure_only_output(
    code: &'static str,
    url: String,
    explanation: String,
    profile: EngineProfile,
) -> VerifyOutput {
    failure_only_output_with_details(code, url, explanation, None, profile)
}

/// [`failure_only_output`] carrying machine-readable evidence on the status.
fn failure_only_output_with_details(
    code: &'static str,
    url: String,
    explanation: String,
    details: Option<Json>,
    profile: EngineProfile,
) -> VerifyOutput {
    let mut results = ValidationResults::default();
    match details {
        Some(details) => results.push_failure_with_details(code, url, explanation, details),
        None => results.push_failure(code, url, explanation),
    }
    let mut output = VerifyOutput {
        validation_state: ValidationState::Invalid,
        report_json: json!({
            "active_manifest": Json::Null,
            "manifests": Json::Object(Map::new()),
            "validation_status": status_array(&results.failure),
            "validation_results": validation_results_json(&results),
            "validation_state": ValidationState::Invalid.as_str(),
            "provenance_verdict": provenance_verdict_json(&results, true, profile),
        }),
        network_needs: std::mem::take(&mut results.network_needs),
        results,
        crjson: None,
        version_verdict: None,
    };
    stamp_profile(&mut output, profile);
    output
}

fn jumbf_failure_output(
    error: &JumbfError,
    manifest_store: &[u8],
    profile: EngineProfile,
) -> VerifyOutput {
    let (code, url) = match error {
        JumbfError::CompressedManifestInvalid { label, .. } => (
            MANIFEST_COMPRESSED_INVALID,
            format!("self#jumbf=/c2pa/{label}"),
        ),
        JumbfError::UnexpectedLabel { expected, .. } if *expected == "c2pa.signature" => (
            CLAIM_SIGNATURE_MISSING,
            "self#jumbf=/c2pa/c2pa.signature".to_string(),
        ),
        JumbfError::UnexpectedLabel { .. }
        | JumbfError::InvalidStructure(_)
        | JumbfError::AmbiguousLabel(_) => (CLAIM_MALFORMED, "self#jumbf=/c2pa".to_string()),
        _ => (GENERAL_ERROR, "self#jumbf=/c2pa".to_string()),
    };
    let mut output = failure_only_output(code, url, error.to_string(), profile);
    stamp_manifest_store_hash(&mut output, manifest_store);
    output
}

fn expand_for_validation<'a>(
    manifest_store: &'a [u8],
    profile: EngineProfile,
) -> Result<ExpandedStore<'a>, Box<VerifyOutput>> {
    expand_store(manifest_store)
        .map_err(|error| Box::new(jumbf_failure_output(&error, manifest_store, profile)))
}
fn container_failure_output(code: &str, explanation: &str, profile: EngineProfile) -> VerifyOutput {
    let mut results = ValidationResults::default();
    results.push_failure(code, String::new(), explanation.into());
    let state = ValidationState::Invalid;
    let report_json = json!({
        "active_manifest": Json::Null,
        "manifests": Json::Object(Map::new()),
        "validation_status": status_array(&results.failure),
        "validation_results": validation_results_json(&results),
        "validation_state": state.as_str(),
        "provenance_verdict": provenance_verdict_json(&results, true, profile),
    });
    VerifyOutput {
        validation_state: state,
        network_needs: Vec::new(),
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

/// Recompute `validation_results` from `results` in a report that already has
/// one, preserving the additive `ingredientDeltas` block.
///
/// The active manifest's status codes are a pure function of `results`, but the
/// per-ingredient deltas are not: they record what the ingredient walk derived
/// for other manifests, which no later change to this manifest's verdict can
/// restate.
fn restate_validation_results(report: &mut Map<String, Json>, results: &ValidationResults) {
    let deltas = report
        .get("validation_results")
        .and_then(|value| value.get("ingredientDeltas"))
        .cloned();
    let mut restated = validation_results_json(results);
    if let (Some(object), Some(deltas)) = (restated.as_object_mut(), deltas) {
        object.insert("ingredientDeltas".into(), deltas);
    }
    report.insert("validation_results".to_string(), restated);
}

/// Build one reader-report manifest entry (the per-label value in the
/// `manifests` map) from a parsed manifest and its decoded claim.
fn manifest_entry_json(
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    claim_decode_budget_exhausted: bool,
    declared_assertions: Option<&std::collections::HashSet<&str>>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
    report_decode_nodes: &mut usize,
) -> Json {
    let mut assertions = Vec::with_capacity(manifest.assertions.len());
    for (alabel, payload) in &manifest.assertions {
        if declared_assertions.is_some_and(|labels| !labels.contains(alabel.as_str())) {
            continue;
        }
        let data = match manifest.assertion_content_type(alabel) {
            Some(AssertionContentType::Json) => {
                serde_json::from_slice(payload).unwrap_or_else(|_| json!({}))
            }
            _ => match decode((*payload, &mut *report_decode_nodes)) {
                Ok(value) => report::cbor_to_json(&value),
                Err(DecodeError::NodeLimitExceeded(_)) => {
                    json!({ "_encypher_omitted": "decoded assertion report node budget exceeded" })
                }
                Err(_) => json!({}),
            },
        };
        assertions.push(json!({ "label": alabel, "data": data }));
    }

    let claim_generator_info = if claim_decode_budget_exhausted {
        Json::Array(vec![
            json!({ "_encypher_omitted": "decoded claim report node budget exceeded" }),
        ])
    } else {
        claim
            .and_then(|c| c.get("claim_generator_info"))
            .map(report::cbor_to_json)
            .unwrap_or_else(|| Json::Array(Vec::new()))
    };
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
fn append_store_manifests(
    report: &mut Json,
    store: &ParsedStore<'_>,
    active_label: &str,
    report_decode_nodes: &mut usize,
) {
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
        let (claim, claim_decode_budget_exhausted) = match manifest.claim_cbor {
            Some(cbor) => match decode((cbor, &mut *report_decode_nodes)) {
                Ok(value) => (Some(value), false),
                Err(DecodeError::NodeLimitExceeded(_)) => (None, true),
                Err(_) => (None, false),
            },
            None => (None, false),
        };
        let chain = manifest
            .signature_cose
            .and_then(|cose| extract_x5chain(cose).ok())
            .unwrap_or_default();
        manifests.insert(
            manifest.label.clone(),
            manifest_entry_json(
                manifest,
                claim.as_ref(),
                claim_decode_budget_exhausted,
                None,
                &chain,
                manifest.signature_cose,
                report_decode_nodes,
            ),
        );
    }
}

/// Build the full reader-report JSON for an active manifest.
#[allow(clippy::too_many_arguments)] // internal report assembler; a params struct adds noise
fn build_report(
    label: &str,
    manifest: &ParsedManifest,
    claim: Option<&Value>,
    declared_assertions: Option<&std::collections::HashSet<&str>>,
    chain: &[Vec<u8>],
    cose: Option<&[u8]>,
    results: &ValidationResults,
    state: ValidationState,
    report_decode_nodes: &mut usize,
) -> Json {
    let mut manifests = Map::new();
    manifests.insert(
        label.to_string(),
        manifest_entry_json(
            manifest,
            claim,
            false,
            declared_assertions,
            chain,
            cose,
            report_decode_nodes,
        ),
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
    //! Unit tests for ingredient provenance bindings, multipart
    //! (`c2pa.hash.multi-asset`) coverage, and tampered-assertion suppression
    //! of `dataHash.match`. Synthetic CBOR assertions isolate each rule from
    //! the on-disk interoperability corpus.
    use super::*;
    use crate::c2pa_cbor::{encode, Profile};
    use crate::c2pa_core::jumbf::{
        build_manifest, build_manifest_store, compress_manifest, parse_manifest_store, superbox,
        superbox_content, UUID_COMPRESSED_MANIFEST, UUID_JSON_CONTENT,
    };
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

    fn cose_with_unprotected_x5chain() -> Vec<u8> {
        let protected = enc(&Value::Map(Vec::new()));
        let unprotected = Value::Map(vec![(
            Value::Text("x5chain".into()),
            Value::Bytes(vec![0x30, 0x01, 0x00]),
        )]);
        encode(
            &Value::Tag(
                18,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    unprotected,
                    Value::Null,
                    Value::Bytes(vec![0x01]),
                ])),
            ),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode cose")
    }

    fn sha(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    fn extended_jumbf_box(ordinary: &[u8]) -> Vec<u8> {
        assert_eq!(&ordinary[4..8], b"jumb");
        let declared = u32::from_be_bytes(ordinary[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, ordinary.len());
        let extended_size = u64::try_from(ordinary.len().checked_add(8).unwrap()).unwrap();
        let mut extended = Vec::with_capacity(ordinary.len() + 8);
        extended.extend_from_slice(&1u32.to_be_bytes());
        extended.extend_from_slice(b"jumb");
        extended.extend_from_slice(&extended_size.to_be_bytes());
        extended.extend_from_slice(&ordinary[8..]);
        extended
    }

    #[test]
    fn manifest_hashes_hash_extended_superbox_payload() {
        let label = "urn:c2pa:extended-child";
        let ordinary = build_manifest(label, &[], &[0xa0], &[0xd2, 0x84]);
        let expected = Sha256::digest(&ordinary[8..]).to_vec();
        let store = build_manifest_store(&[extended_jumbf_box(&ordinary)]);
        let expanded = expand_store(&store).unwrap();
        let parsed = parse_manifest_store(expanded.bytes()).unwrap();

        let hashes = manifest_hashes(&expanded, &parsed.manifests).unwrap();

        assert_eq!(
            hashes
                .get(label)
                .map(|digests| digests.expanded_sha256.as_slice()),
            Some(expected.as_slice())
        );
    }
    #[test]
    fn compressed_manifest_hashes_accept_stored_and_expanded_domains() {
        let manifest = build_manifest("urn:c2pa:hash-domains", &[], &[0xa0], &[0xd2, 0x84]);
        let compressed = compress_manifest(&manifest).unwrap();
        let stored_content = superbox_content(&compressed).unwrap().to_vec();
        let store = build_manifest_store(&[compressed]);
        let expanded = expand_store(&store).unwrap();
        let parsed = parse_manifest_store(expanded.bytes()).unwrap();
        let hashes = manifest_hashes(&expanded, &parsed.manifests).unwrap();
        let mut cache = IngredientManifestDigestCache::new(StoreContext {
            manifests: &parsed.manifests,
            manifest_hashes: &hashes,
        });
        let parsed_manifest = &parsed.manifests[0];

        assert!(cache.matches(
            parsed_manifest,
            0,
            &Sha256::digest(parsed_manifest.manifest_jumbf)
        ));
        assert!(cache.matches(parsed_manifest, 0, &Sha256::digest(&stored_content)));
        assert!(cache.matches(parsed_manifest, 1, &Sha384::digest(&stored_content)));
        assert!(cache.matches(parsed_manifest, 2, &Sha512::digest(&stored_content)));
    }

    fn ingredient_reference(url: String, hash: Vec<u8>) -> Value {
        vmap(vec![
            ("url", Value::Text(url)),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(hash)),
        ])
    }

    fn run_ingredient_bindings(
        actual_manifest: &[u8],
        expected_manifest: &[u8],
        actual_signature: &[u8],
        expected_signature: &[u8],
        redacted: bool,
        link_field: &str,
        generation: ClaimGeneration,
    ) -> ValidationResults {
        let child_label = "urn:c2pa:child";
        let ingredient_label = match generation {
            ClaimGeneration::V1 => "c2pa.ingredient",
            ClaimGeneration::V2 => "c2pa.ingredient.v3",
        };
        let ingredient = vmap(vec![
            (
                link_field,
                ingredient_reference(
                    format!("self#jumbf=/c2pa/{child_label}"),
                    sha(expected_manifest),
                ),
            ),
            (
                "claimSignature",
                ingredient_reference(
                    format!("self#jumbf=/c2pa/{child_label}/c2pa.signature"),
                    hash_claim_signature_box("sha256", expected_signature).expect("hash"),
                ),
            ),
        ]);
        let ingredient_cbor = enc(&ingredient);
        let parent = ParsedManifest {
            label: "urn:c2pa:parent".into(),
            manifest_jumbf: &[],
            assertions: vec![(ingredient_label.into(), ingredient_cbor.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let child = ParsedManifest {
            label: child_label.into(),
            manifest_jumbf: actual_manifest,
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: Some(actual_signature),
            claim_count: 1,
            claim_box_label: None,
        };
        let reference_field = match generation {
            ClaimGeneration::V1 => "assertions",
            ClaimGeneration::V2 => "created_assertions",
        };
        let mut claim_fields = vec![(
            reference_field,
            Value::Array(vec![vmap(vec![(
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{ingredient_label}")),
            )])]),
        )];
        if redacted {
            claim_fields.push((
                "redacted_assertions",
                Value::Array(vec![Value::Text(format!(
                    // `c2pa.actions` may never be redacted, so a redaction
                    // that selects the claim-signature method must name an
                    // assertion the spec allows a claim to remove.
                    "self#jumbf=/c2pa/{child_label}/c2pa.assertions/c2pa.metadata"
                ))]),
            ));
        }
        let claim = vmap(claim_fields);
        let manifests = [child];
        let mut manifest_hashes = std::collections::HashMap::new();
        manifest_hashes.insert(
            child_label.to_string(),
            ManifestDigests::expanded(sha(actual_manifest)),
        );
        let claim_refs = ClaimAssertionRefs::build(&parent, &claim, generation);
        let mut results = ValidationResults::default();
        let mut digest_cache = IngredientManifestDigestCache::new(StoreContext {
            manifests: &manifests,
            manifest_hashes: &manifest_hashes,
        });
        verify_ingredient_references(
            "urn:c2pa:parent",
            &claim_refs,
            &claim,
            &mut digest_cache,
            "self#jumbf=/c2pa/urn:c2pa:parent/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    /// C2PA 1.0 generators hashed a `c2pa_manifest` ingredient link over the
    /// ingredient's claim bytes, not its manifest box (c2pa-rs keeps reading
    /// them as "the 1.0 version"). The default posture accepts that legacy hash
    /// on the legacy link only; strict conformance and `activeManifest` links
    /// still require the manifest-box hash.
    #[test]
    fn legacy_c2pa_manifest_link_accepts_a_claim_hash_by_default_only() {
        let child_label = "urn:c2pa:child";
        let child_claim = enc(&vmap(vec![("instanceID", Value::Text("xmp:iid:c".into()))]));
        let child_box = b"child manifest superbox content".as_slice();
        let run = |field: &str, profile: EngineProfile| {
            let ingredient = enc(&vmap(vec![(
                field,
                ingredient_reference(format!("self#jumbf=/c2pa/{child_label}"), sha(&child_claim)),
            )]));
            let parent = ParsedManifest {
                label: "urn:c2pa:parent".into(),
                manifest_jumbf: &[],
                assertions: vec![("c2pa.ingredient".into(), ingredient.as_slice())],
                assertion_jumbf: Vec::new(),
                claim_cbor: None,
                signature_cose: None,
                claim_count: 1,
                claim_box_label: Some("c2pa.claim".into()),
            };
            let manifests = [ParsedManifest {
                label: child_label.into(),
                manifest_jumbf: child_box,
                assertions: Vec::new(),
                assertion_jumbf: Vec::new(),
                claim_cbor: Some(&child_claim),
                signature_cose: None,
                claim_count: 1,
                claim_box_label: Some("c2pa.claim".into()),
            }];
            let claim = vmap(vec![(
                "assertions",
                Value::Array(vec![vmap(vec![(
                    "url",
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.ingredient".into()),
                )])]),
            )]);
            let mut hashes = std::collections::HashMap::new();
            hashes.insert(
                child_label.to_string(),
                ManifestDigests::expanded(sha(child_box)),
            );
            let refs = ClaimAssertionRefs::build(&parent, &claim, ClaimGeneration::V1);
            let mut results = ValidationResults::default();
            let mut cache = IngredientManifestDigestCache::new(StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            });
            verify_ingredient_references(
                "urn:c2pa:parent",
                &refs,
                &claim,
                &mut cache,
                "self#jumbf=/c2pa/urn:c2pa:parent/c2pa.signature",
                profile,
                &mut results,
            );
            results
        };
        let strict = EngineProfile::strict(SpecVersion::V2_4);

        let default_legacy = run("c2pa_manifest", EngineProfile::GENEROUS);
        assert!(!default_legacy.has_failure(INGREDIENT_MANIFEST_MISMATCH));
        assert!(!default_legacy.has_success(INGREDIENT_MANIFEST_VALIDATED));
        assert!(default_legacy.has_informational(INGREDIENT_LEGACY_CLAIM_HASH));
        assert!(run("c2pa_manifest", strict).has_failure(INGREDIENT_MANIFEST_MISMATCH));
        assert!(run("activeManifest", EngineProfile::GENEROUS)
            .has_failure(INGREDIENT_MANIFEST_MISMATCH));
    }

    #[test]
    fn main_claim_accepts_unprotected_x5chain_as_credential_source() {
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![vmap(vec![(
                    "url",
                    Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                )])]),
            ),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
        ]);
        let claim_cbor = enc(&claim);
        let cose = cose_with_unprotected_x5chain();
        let manifest = ParsedManifest {
            label: "urn:uuid:123e4567-e89b-12d3-a456-426614174000".into(),
            manifest_jumbf: &[],
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim_cbor),
            signature_cose: Some(&cose),
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifest_hashes = std::collections::HashMap::new();
        let input = VerifyInput {
            data: &[],
            mime: "application/c2pa",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };

        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        let out = verify_manifest(
            &manifest,
            StoreContext {
                manifests: std::slice::from_ref(&manifest),
                manifest_hashes: &manifest_hashes,
            },
            &input,
            AssetFormat::C2paStore,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        );

        // The synthetic DER is not a real certificate, so credential validation
        // still fails. It must fail after extraction, not because the compatible
        // unprotected bucket was rejected.
        assert!(out.results.has_failure(SIGNING_CREDENTIAL_INVALID));
        assert!(!out
            .results
            .failure
            .iter()
            .any(|status| status.explanation.contains("no x5chain")));
        assert!(!out.results.has_success(CLAIM_SIGNATURE_VALIDATED));
        assert_eq!(out.validation_state, ValidationState::Invalid);
    }

    #[test]
    fn matching_ingredient_manifest_short_circuits_signature_fallback() {
        let results = run_ingredient_bindings(
            b"child manifest",
            b"child manifest",
            b"swapped signature",
            b"expected signature",
            false,
            "activeManifest",
            ClaimGeneration::V2,
        );
        assert!(results.has_success(INGREDIENT_MANIFEST_VALIDATED));
        assert!(!results.has_success(INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
        assert!(results.failure.is_empty());
    }

    #[test]
    fn swapped_ingredient_manifest_is_rejected_without_redaction() {
        let results = run_ingredient_bindings(
            b"swapped manifest",
            b"expected manifest",
            b"child signature",
            b"child signature",
            false,
            "activeManifest",
            ClaimGeneration::V2,
        );
        assert!(results.has_failure(INGREDIENT_MANIFEST_MISMATCH));
        assert!(!results.has_success(INGREDIENT_MANIFEST_VALIDATED));
    }

    #[test]
    fn redacted_ingredient_uses_signature_fallback() {
        let results = run_ingredient_bindings(
            b"redacted manifest",
            b"original manifest",
            b"child signature",
            b"child signature",
            true,
            "activeManifest",
            ClaimGeneration::V2,
        );
        assert!(results.has_success(INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
        assert!(!results.has_failure(INGREDIENT_MANIFEST_MISMATCH));
    }

    #[test]
    fn swapped_redacted_ingredient_signature_is_rejected() {
        let results = run_ingredient_bindings(
            b"redacted manifest",
            b"original manifest",
            b"swapped signature",
            b"expected signature",
            true,
            "activeManifest",
            ClaimGeneration::V2,
        );
        assert!(results.has_failure(INGREDIENT_CLAIM_SIGNATURE_MISMATCH));
        assert!(!results.has_success(INGREDIENT_CLAIM_SIGNATURE_VALIDATED));
    }
    #[test]
    fn legacy_c2pa_manifest_link_is_validated() {
        for generation in [ClaimGeneration::V1, ClaimGeneration::V2] {
            let results = run_ingredient_bindings(
                b"child manifest",
                b"child manifest",
                b"child signature",
                b"child signature",
                false,
                "c2pa_manifest",
                generation,
            );
            assert!(
                results.has_success(INGREDIENT_MANIFEST_VALIDATED),
                "{generation:?}"
            );
            assert!(results.failure.is_empty(), "{generation:?}");
        }
    }

    /// CAWG identity/ICA failure codes are assertion-scoped per the CAWG 1.3
    /// consumer layering: they never break C2PA manifest integrity in either
    /// posture, while unknown and C2PA failure codes keep invalidating.
    #[test]
    fn cawg_failure_codes_are_assertion_scoped_not_integrity_invalidating() {
        let status = |code: &str, details: Option<Json>| StatusCode {
            code: code.into(),
            url: String::new(),
            explanation: String::new(),
            details,
        };
        for code in [
            "cawg.ica.did_unavailable",
            "cawg.ica.signature_mismatch",
            "cawg.identity.cbor.invalid",
            "cawg.x509.signature.mismatch",
        ] {
            assert!(
                !is_construction_integrity_invalidating(&status(code, None)),
                "{code}"
            );
            assert!(
                !is_integrity_invalidating(&status(code, None), EngineProfile::CONFORMANCE_V2_2),
                "{code} (strict)"
            );
        }
        assert!(is_construction_integrity_invalidating(&status(
            ASSERTION_HASHED_URI_MISMATCH,
            None
        )));
        assert!(is_construction_integrity_invalidating(&status(
            "some.future.code",
            None
        )));
        // The same code from the external-data procedure is carved out: C2PA
        // 2.4 forbids rejecting a claim over unretrievable external data.
        assert!(!is_construction_integrity_invalidating(&status(
            ASSERTION_HASHED_URI_MISMATCH,
            Some(json!({ "external_data": true }))
        )));
        assert!(!is_integrity_invalidating(
            &status(
                ASSERTION_HASHED_URI_MISMATCH,
                Some(json!({ "external_data": true }))
            ),
            EngineProfile::CONFORMANCE_V2_2
        ));

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

    #[test]
    fn revoked_and_outside_validity_invalidate_only_the_strict_verdict() {
        for code in [
            SIGNING_CREDENTIAL_OCSP_REVOKED,
            CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
        ] {
            let mut results = ValidationResults::default();
            results.push_failure(code, String::new(), "test".into());
            assert_eq!(
                provenance_verdict_json(&results, true, EngineProfile::GENEROUS)["integrity"],
                "valid"
            );
            assert_eq!(
                provenance_verdict_json(&results, true, EngineProfile::strict(SpecVersion::V2_4),)
                    ["integrity"],
                "invalid"
            );
        }
    }

    #[test]
    fn text_container_failures_are_statuses_not_api_errors() {
        let malformed = b"-----BEGIN C2PA MANIFEST----- not-a-uri -----END C2PA MANIFEST-----";
        let output = verify(&VerifyInput {
            data: malformed,
            mime: "text/yaml",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        })
        .expect("container defects are validation results");
        assert!(output
            .results
            .has_failure("manifest.structuredText.malformedReference"));
        assert_eq!(output.validation_state, ValidationState::Invalid);
    }

    fn canonical_test_part_label(label: &str) -> String {
        match label {
            "p0" => "c2pa.hash.data.part".into(),
            "p1" => "c2pa.hash.data.part__1".into(),
            "p2" => "c2pa.hash.data.part__2".into(),
            "absent" => "c2pa.hash.data.part__99".into(),
            label => label.into(),
        }
    }

    /// Build a `c2pa.hash.multi-asset` value from `(byteOffset, length, part
    /// label, optional)` tuples.
    fn multi_asset(parts: &[(usize, usize, &str, bool)]) -> Value {
        let arr = parts
            .iter()
            .map(|&(off, len, plabel, optional)| {
                let plabel = canonical_test_part_label(plabel);
                vmap(vec![
                    (
                        "location",
                        vmap(vec![
                            ("byteOffset", Value::Integer(off as i128)),
                            ("length", Value::Integer(len as i128)),
                        ]),
                    ),
                    ("hashAssertion", hashed_uri_for_assertion(&plabel)),
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
        run_multi_for_format(data, ma, part_assertions, AssetFormat::Jpeg)
    }

    fn run_multi_for_format(
        data: &[u8],
        ma: &Value,
        part_assertions: &[(&str, Value)],
        format: AssetFormat,
    ) -> ValidationResults {
        let ma_cbor = enc(ma);
        let owned: Vec<(String, Vec<u8>)> = part_assertions
            .iter()
            .map(|(label, value)| (canonical_test_part_label(label), enc(value)))
            .collect();
        let assertions: Vec<(String, &[u8])> = owned
            .iter()
            .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
            .collect();
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(
                owned
                    .iter()
                    .map(|(label, _)| hashed_uri_for_assertion(label))
                    .collect(),
            ),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_multi_asset(
            &claim,
            &claim_refs,
            &ma_cbor,
            data,
            format,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
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
    fn part_exclusions_are_local_at_nonzero_asset_offset() {
        let data = fixture_data();
        let ma = multi_asset(&[
            (0, 10, "p0", false),
            (10, 10, "p1", false),
            (20, 10, "p2", false),
        ]);
        let p1_digest = hash_with_exclusions("sha256", &data[10..20], &[(1, 1)]).unwrap();
        let p1 = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(p1_digest)),
            (
                "exclusions",
                Value::Array(vec![vmap(vec![
                    ("start", Value::Integer(1)),
                    ("length", Value::Integer(1)),
                ])]),
            ),
        ]);
        let parts = [
            ("p0", part_for(&data, 0, 10)),
            ("p1", p1),
            ("p2", part_for(&data, 20, 10)),
        ];
        let results = run_multi(&data, &ma, &parts);
        assert!(results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(results.failure.is_empty());
    }

    #[test]
    fn part_exclusion_outside_local_part_is_malformed() {
        let data = fixture_data();
        let ma = multi_asset(&[(0, 30, "p0", false)]);
        let p0 = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(&data))),
            (
                "exclusions",
                Value::Array(vec![vmap(vec![
                    ("start", Value::Integer(29)),
                    ("length", Value::Integer(2)),
                ])]),
            ),
        ]);
        let results = run_multi(&data, &ma, &[("p0", p0)]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
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
    fn optional_part_truncated_is_mismatch_not_missing_part() {
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
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISMATCH));
        assert!(!r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISSING_PART));
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
    fn missing_referenced_part_assertion_is_malformed() {
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
        assert!(r.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!r.has_failure(ASSERTION_MULTI_ASSET_HASH_MISSING_PART));
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
    #[test]
    fn excessive_multi_asset_part_count_is_rejected_before_resolution() {
        let part = vmap(vec![(
            "location",
            vmap(vec![
                ("byteOffset", Value::Integer(0)),
                ("length", Value::Integer(0)),
            ]),
        )]);
        let ma = vmap(vec![(
            "parts",
            Value::Array(vec![part; MAX_MULTI_ASSET_PARTS + 1]),
        )]);
        let results = run_multi(&[], &ma, &[]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    fn single_part_multi_asset(location: Value, part_label: &str) -> Value {
        vmap(vec![(
            "parts",
            Value::Array(vec![vmap(vec![
                ("location", location),
                ("hashAssertion", hashed_uri_for_assertion(part_label)),
                ("optional", Value::Bool(false)),
            ])]),
        )])
    }

    fn png_chunk(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(12 + payload.len());
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(box_type);
        chunk.extend_from_slice(payload);
        chunk.extend_from_slice(&[0; 4]);
        chunk
    }

    #[test]
    fn byte_offset_part_validates_with_data_hash_methodology() {
        let data = fixture_data();
        let label = "c2pa.hash.data.part";
        let ma = single_part_multi_asset(
            vmap(vec![
                ("byteOffset", Value::Integer(0)),
                ("length", Value::Integer(data.len() as i128)),
            ]),
            label,
        );
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(results.failure.is_empty());
    }

    #[test]
    fn bmff_box_payload_validates_with_bmff_structural_methodology() {
        let inner_bmff = test_box(b"ftyp", b"isom");
        let outer_bmff = test_box(b"mpvd", &inner_bmff);
        let label = "c2pa.hash.bmff.v2.part";
        let digest =
            crate::c2pa_formats::bmff_hash_with_exclusions(&inner_bmff, "sha256", &[]).unwrap();
        let assertion = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(digest)),
            (
                "exclusions",
                Value::Array(vec![vmap(vec![("xpath", Value::Text("/uuid".into()))])]),
            ),
        ]);
        let ma =
            single_part_multi_asset(vmap(vec![("bmffBox", Value::Text("/mpvd".into()))]), label);
        let results =
            run_multi_for_format(&outer_bmff, &ma, &[(label, assertion)], AssetFormat::Bmff);
        assert!(results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(results.failure.is_empty());
    }

    #[test]
    fn bmff_part_rejects_a_plain_digest_for_bmff_methodology() {
        let inner_bmff = test_box(b"ftyp", b"isom");
        let outer_bmff = test_box(b"mpvd", &inner_bmff);
        let label = "c2pa.hash.bmff.v3.part";
        let assertion = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(&inner_bmff))),
            (
                "exclusions",
                Value::Array(vec![vmap(vec![("xpath", Value::Text("/uuid".into()))])]),
            ),
        ]);
        let ma =
            single_part_multi_asset(vmap(vec![("bmffBox", Value::Text("/mpvd".into()))]), label);
        let results =
            run_multi_for_format(&outer_bmff, &ma, &[(label, assertion)], AssetFormat::Bmff);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MISMATCH));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn bmff_box_payload_validates_with_general_box_methodology() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&png_chunk(b"caBX", &[]));
        png.extend_from_slice(&png_chunk(b"IEND", &[]));
        let outer_bmff = test_box(b"mpvd", &png);
        let label = "c2pa.hash.boxes.part";
        let assertion = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            (
                "boxes",
                Value::Array(vec![
                    vmap(vec![
                        ("names", Value::Array(vec![Value::Text("PNGh".into())])),
                        ("hash", Value::Bytes(sha(&png[..8]))),
                    ]),
                    vmap(vec![(
                        "names",
                        Value::Array(vec![Value::Text("C2PA".into())]),
                    )]),
                    vmap(vec![
                        ("names", Value::Array(vec![Value::Text("IEND".into())])),
                        ("hash", Value::Bytes(sha(&png[20..]))),
                    ]),
                ]),
            ),
        ]);
        let ma =
            single_part_multi_asset(vmap(vec![("bmffBox", Value::Text("/mpvd".into()))]), label);
        let results =
            run_multi_for_format(&outer_bmff, &ma, &[(label, assertion)], AssetFormat::Bmff);
        assert!(results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
        assert!(results.failure.is_empty());
    }

    #[test]
    fn mixed_locator_choice_is_malformed() {
        let data = fixture_data();
        let label = "c2pa.hash.data.part";
        let ma = single_part_multi_asset(
            vmap(vec![
                ("byteOffset", Value::Integer(0)),
                ("length", Value::Integer(data.len() as i128)),
                ("bmffBox", Value::Text("/mpvd".into())),
            ]),
            label,
        );
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn non_part_hash_method_is_malformed_instead_of_plain_hashed() {
        let data = fixture_data();
        let label = "c2pa.thumbnail.claim";
        let ma = single_part_multi_asset(
            vmap(vec![
                ("byteOffset", Value::Integer(0)),
                ("length", Value::Integer(data.len() as i128)),
            ]),
            label,
        );
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn negative_byte_offset_locator_bound_is_malformed() {
        let data = fixture_data();
        let label = "c2pa.hash.data.part";
        let ma = single_part_multi_asset(
            vmap(vec![
                ("byteOffset", Value::Integer(-1)),
                ("length", Value::Integer(data.len() as i128)),
            ]),
            label,
        );
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn overflowing_byte_offset_locator_bounds_are_malformed() {
        let data = fixture_data();
        let label = "c2pa.hash.data.part";
        let ma = single_part_multi_asset(
            vmap(vec![
                ("byteOffset", Value::Integer(usize::MAX as i128)),
                ("length", Value::Integer(1)),
            ]),
            label,
        );
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn nested_part_hashed_uri_must_match_the_exact_claim_declaration() {
        let data = fixture_data();
        let label = "c2pa.hash.data.part";
        let nested = vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![1; 32])),
        ]);
        let ma = vmap(vec![(
            "parts",
            Value::Array(vec![vmap(vec![
                (
                    "location",
                    vmap(vec![
                        ("byteOffset", Value::Integer(0)),
                        ("length", Value::Integer(data.len() as i128)),
                    ]),
                ),
                ("hashAssertion", nested),
            ])]),
        )]);
        let results = run_multi(&data, &ma, &[(label, part_assertion(&sha(&data)))]);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
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
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        if preseed_tamper {
            results.push_failure(
                ASSERTION_HASHED_URI_MISMATCH,
                "self#jumbf=/c2pa/urn:test/c2pa.assertions/c2pa.actions.v2".into(),
                "tampered assertion".into(),
            );
        }
        let _operative_binding = verify_data_hash(
            &claim,
            &claim_refs,
            data,
            AssetFormat::Jpeg,
            &[],
            update_manifest::StoreRendition::AsSigned,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    fn run_text_data_hash(
        data: &[u8],
        expected: Vec<u8>,
        exclusions: &[(usize, usize)],
    ) -> ValidationResults {
        let exclusions = Value::Array(
            exclusions
                .iter()
                .map(|(start, length)| {
                    vmap(vec![
                        ("start", Value::Integer(*start as i128)),
                        ("length", Value::Integer(*length as i128)),
                    ])
                })
                .collect(),
        );
        let dh = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(expected)),
            ("exclusions", exclusions),
        ]);
        let owned = enc(&dh);
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.hash.data".into(), owned.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let _ = verify_data_hash(
            &claim,
            &claim_refs,
            data,
            AssetFormat::TextUnstructured,
            &[],
            update_manifest::StoreRendition::AsSigned,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    #[test]
    fn unstructured_text_hash_removes_wrapper_then_normalizes_to_nfc() {
        let carrier_nfd = "Cafe\u{301}";
        let wrapper = c2pa_text::encode_wrapper(b"manifest");
        let asset = format!("{carrier_nfd}{wrapper}");
        let expected = sha("Caf\u{e9}".as_bytes());
        let results = run_text_data_hash(
            asset.as_bytes(),
            expected,
            &[(carrier_nfd.len(), wrapper.len())],
        );

        assert!(results.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(!results.has_failure(ASSERTION_DATA_HASH_MISMATCH));
    }

    #[test]
    fn unstructured_text_exclusion_must_match_a_wrapper_exactly() {
        let carrier = "signed text";
        let wrapper = c2pa_text::encode_wrapper(b"manifest");
        let asset = format!("{carrier}{wrapper}");
        let results = run_text_data_hash(asset.as_bytes(), sha(carrier.as_bytes()), &[(0, 1)]);

        assert!(results.has_failure(ASSERTION_DATA_HASH_MALFORMED));
        assert!(!results.has_failure(ASSERTION_DATA_HASH_MISMATCH));
    }

    #[test]
    fn unstructured_text_rejects_multiple_excluded_wrappers() {
        let first = c2pa_text::encode_wrapper(b"first");
        let second = c2pa_text::encode_wrapper(b"second");
        let asset = format!("signed{first} text{second}");
        let second_start = "signed".len() + first.len() + " text".len();
        let results = run_text_data_hash(
            asset.as_bytes(),
            sha(b"signed text"),
            &[("signed".len(), first.len()), (second_start, second.len())],
        );

        assert!(results.has_failure("manifest.text.multipleWrappers"));
        assert!(!results.has_success(ASSERTION_DATA_HASH_MATCH));
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
        let embedded = crate::c2pa_formats::embed_manifest(
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

    fn structural_manifest_for(generation: ClaimGeneration) -> ParsedManifest<'static> {
        ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some(
                match generation {
                    ClaimGeneration::V1 => "c2pa.claim",
                    ClaimGeneration::V2 => "c2pa.claim.v2",
                }
                .into(),
            ),
        }
    }
    fn structural_manifest() -> ParsedManifest<'static> {
        structural_manifest_for(ClaimGeneration::V2)
    }

    fn hashed_uri_for_assertion(label: &str) -> Value {
        vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
        ])
    }

    fn valid_hashed_uri() -> Value {
        hashed_uri_for_assertion("c2pa.hash.data")
    }

    fn run_structure_with(
        claim: &Value,
        generation: ClaimGeneration,
        profile: EngineProfile,
    ) -> (bool, ValidationResults) {
        let manifests = [structural_manifest_for(generation)];
        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();
        let claim_refs = ClaimAssertionRefs::build(&manifests[0], claim, generation);
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            claim,
            generation,
            &claim_refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/test/c2pa.signature",
            profile,
            &mut results,
        );
        (fatal, results)
    }

    fn run_structure(claim: &Value) -> (bool, ValidationResults) {
        run_structure_with(claim, ClaimGeneration::V2, EngineProfile::GENEROUS)
    }

    #[test]
    fn legacy_v1_generator_string_without_generator_info_is_posture_sensitive() {
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            ("claim_generator", Value::Text("legacy/1.0".into())),
            ("dc:format", Value::Text("image/jpeg".into())),
            ("assertions", Value::Array(vec![valid_hashed_uri()])),
        ]);

        let (default_fatal, default_results) =
            run_structure_with(&claim, ClaimGeneration::V1, EngineProfile::GENEROUS);
        assert!(!default_fatal, "{default_results:?}");
        assert!(!default_results.has_failure(CLAIM_MALFORMED));
        assert!(
            default_results.has_informational(CLAIM_GENERATOR_INFO_MISSING),
            "{default_results:?}"
        );
        let claim_with_empty_info = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            ("claim_generator", Value::Text("legacy/1.0".into())),
            ("claim_generator_info", Value::Array(Vec::new())),
            ("dc:format", Value::Text("image/jpeg".into())),
            ("assertions", Value::Array(vec![valid_hashed_uri()])),
        ]);
        let (empty_default_fatal, empty_default_results) = run_structure_with(
            &claim_with_empty_info,
            ClaimGeneration::V1,
            EngineProfile::GENEROUS,
        );
        assert!(!empty_default_fatal, "{empty_default_results:?}");
        assert!(!empty_default_results.has_failure(CLAIM_MALFORMED));
        assert!(empty_default_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));
        let mut claim_with_null_info = claim_with_empty_info.clone();
        if let Value::Map(fields) = &mut claim_with_null_info {
            fields
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some("claim_generator_info"))
                .expect("claim carries generator info")
                .1 = Value::Null;
        }
        let (null_default_fatal, null_default_results) = run_structure_with(
            &claim_with_null_info,
            ClaimGeneration::V1,
            EngineProfile::GENEROUS,
        );
        assert!(!null_default_fatal, "{null_default_results:?}");
        assert!(!null_default_results.has_failure(CLAIM_MALFORMED));
        assert!(null_default_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));

        let (strict_fatal, strict_results) = run_structure_with(
            &claim,
            ClaimGeneration::V1,
            EngineProfile::strict(SpecVersion::V2_4),
        );
        assert!(strict_fatal);
        assert!(strict_results.has_failure(CLAIM_MALFORMED));
        assert!(!strict_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));

        let (empty_strict_fatal, empty_strict_results) = run_structure_with(
            &claim_with_empty_info,
            ClaimGeneration::V1,
            EngineProfile::strict(SpecVersion::V2_4),
        );
        assert!(empty_strict_fatal);
        assert!(empty_strict_results.has_failure(CLAIM_MALFORMED));
        assert!(!empty_strict_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));
        let (null_strict_fatal, null_strict_results) = run_structure_with(
            &claim_with_null_info,
            ClaimGeneration::V1,
            EngineProfile::strict(SpecVersion::V2_4),
        );
        assert!(null_strict_fatal);
        assert!(null_strict_results.has_failure(CLAIM_MALFORMED));
        assert!(!null_strict_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));

        let without_legacy_generator = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            ("dc:format", Value::Text("image/jpeg".into())),
            ("assertions", Value::Array(vec![valid_hashed_uri()])),
        ]);
        let (missing_both_fatal, missing_both_results) = run_structure_with(
            &without_legacy_generator,
            ClaimGeneration::V1,
            EngineProfile::GENEROUS,
        );
        assert!(missing_both_fatal);
        assert!(missing_both_results.has_failure(CLAIM_MALFORMED));
        assert!(!missing_both_results.has_informational(CLAIM_GENERATOR_INFO_MISSING));
    }

    #[test]
    fn malformed_v2_generator_info_is_fatal_claim_malformed() {
        let malformed = [
            ("absent", None),
            ("wrong outer type", Some(Value::Text("generator".into()))),
            ("empty value", Some(Value::Map(Vec::new()))),
            ("empty array", Some(Value::Array(Vec::new()))),
            (
                "legacy array-of-maps shape",
                Some(Value::Array(vec![vmap(vec![(
                    "name",
                    Value::Text("generator".into()),
                )])])),
            ),
            (
                "non-map array entry",
                Some(Value::Array(vec![Value::Text("generator".into())])),
            ),
            (
                "missing name",
                Some(vmap(vec![("version", Value::Text("1.0".into()))])),
            ),
            (
                "non-text name",
                Some(vmap(vec![("name", Value::Integer(1.into()))])),
            ),
            (
                "empty name",
                Some(vmap(vec![("name", Value::Text(String::new()))])),
            ),
            (
                "icon wrong type",
                Some(vmap(vec![
                    ("name", Value::Text("generator".into())),
                    ("icon", Value::Text("icon".into())),
                ])),
            ),
            (
                "icon missing url",
                Some(vmap(vec![
                    ("name", Value::Text("generator".into())),
                    ("icon", vmap(vec![("hash", Value::Bytes(vec![7; 32]))])),
                ])),
            ),
            (
                "icon missing hash",
                Some(vmap(vec![
                    ("name", Value::Text("generator".into())),
                    (
                        "icon",
                        vmap(vec![(
                            "url",
                            Value::Text("self#jumbf=c2pa.assertions/icon".into()),
                        )]),
                    ),
                ])),
            ),
        ];

        for (case, info) in malformed {
            let mut fields = vec![
                ("instanceID", Value::Text("urn:uuid:test".into())),
                ("created_assertions", Value::Array(vec![valid_hashed_uri()])),
            ];
            if let Some(info) = info {
                fields.push(("claim_generator_info", info));
            }
            let (fatal, results) = run_structure(&vmap(fields));
            assert!(fatal, "{case}");
            assert!(results.has_failure(CLAIM_MALFORMED), "{case}");
            assert!(
                !results.has_success(ASSERTION_DATA_HASH_MATCH),
                "{case} reached a valid integrity verdict"
            );
        }
    }

    fn run_generator_icon_binding(
        generation: ClaimGeneration,
        icon_label: &str,
        expected_icon_hash: Vec<u8>,
        stored_icon_jumbf: Option<&[u8]>,
        declare_icon: bool,
    ) -> (bool, ValidationResults) {
        let hard_label = "c2pa.hash.data";
        let hard_jumbf = b"hard-binding assertion jumbf";
        let assertion_payload = enc(&vmap(vec![("data", Value::Bytes(vec![1]))]));
        let icon_reference = vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{icon_label}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(expected_icon_hash)),
        ]);
        let icon_declarations = if declare_icon {
            vec![icon_reference.clone()]
        } else {
            Vec::new()
        };
        let generator = vmap(vec![
            ("name", Value::Text("generator".into())),
            ("icon", icon_reference),
        ]);
        let hard_reference = vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{hard_label}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(hard_jumbf))),
        ]);
        // An icon hashed URI reaches an assertion without declaring it, so a
        // store box reachable only from the icon is `assertion.undeclared`
        // (C2PA 2.4 Validation, Validate the Assertions). `declare_icon` selects
        // between the lawful shape, where the claim declares the icon as well,
        // and the shape that must fail closed.
        let declarations = |hard: Value| {
            let mut list = vec![hard];
            list.extend(icon_declarations);
            Value::Array(list)
        };
        let claim = match generation {
            ClaimGeneration::V1 => vmap(vec![
                ("instanceID", Value::Text("xmp:iid:test".into())),
                ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
                ("claim_generator", Value::Text("generator/1.0".into())),
                ("claim_generator_info", Value::Array(vec![generator])),
                ("dc:format", Value::Text("image/jpeg".into())),
                ("assertions", declarations(hard_reference)),
            ]),
            ClaimGeneration::V2 => vmap(vec![
                ("instanceID", Value::Text("urn:uuid:test".into())),
                ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
                ("claim_generator_info", generator),
                ("created_assertions", declarations(hard_reference)),
            ]),
        };
        let mut assertions = vec![(hard_label.into(), assertion_payload.as_slice())];
        let mut assertion_jumbf = vec![(hard_label.into(), hard_jumbf.as_slice())];
        if let Some(icon_jumbf) = stored_icon_jumbf {
            assertions.push((icon_label.into(), assertion_payload.as_slice()));
            assertion_jumbf.push((icon_label.into(), icon_jumbf));
        }
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf,
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some(
                match generation {
                    ClaimGeneration::V1 => "c2pa.claim",
                    ClaimGeneration::V2 => "c2pa.claim.v2",
                }
                .into(),
            ),
        };
        let manifests = [manifest];
        let hashes = std::collections::HashMap::new();
        let mut claim_refs = ClaimAssertionRefs::build(&manifests[0], &claim, generation);
        let mut results = ValidationResults::default();
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            generation,
            &claim_refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/test/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );
        if !fatal {
            verify_assertion_bindings(
                &claim,
                &mut claim_refs,
                generation,
                &manifests[0].label,
                EngineProfile::GENEROUS,
                &mut results,
            );
        }
        (fatal, results)
    }

    #[test]
    fn generator_icon_references_are_indexed_and_bound_for_both_claim_generations() {
        let icon_jumbf = b"embedded c2pa.icon assertion jumbf";
        for (generation, label) in [
            (ClaimGeneration::V1, "c2pa.icon__1"),
            (ClaimGeneration::V2, "c2pa.icon"),
        ] {
            let (fatal, results) = run_generator_icon_binding(
                generation,
                label,
                sha(icon_jumbf),
                Some(icon_jumbf),
                true,
            );
            assert!(!fatal, "{generation:?}");
            assert!(
                results.has_success(ASSERTION_HASHED_URI_MATCH),
                "{generation:?}"
            );
            assert!(!results.has_failure(HASHED_URI_MISSING), "{generation:?}");
            assert!(
                !results.has_failure(ASSERTION_HASHED_URI_MISMATCH),
                "{generation:?}"
            );
        }
    }

    #[test]
    fn generator_icon_missing_mismatch_and_wrong_label_fail_closed() {
        let icon_jumbf = b"embedded c2pa.icon assertion jumbf";
        let (fatal, missing) = run_generator_icon_binding(
            ClaimGeneration::V2,
            "c2pa.icon",
            sha(icon_jumbf),
            None,
            false,
        );
        assert!(!fatal);
        assert!(missing.has_failure(ASSERTION_MISSING));

        let (fatal, mismatch) = run_generator_icon_binding(
            ClaimGeneration::V2,
            "c2pa.icon",
            sha(b"different icon assertion"),
            Some(icon_jumbf),
            true,
        );
        assert!(!fatal);
        assert!(mismatch.has_failure(ASSERTION_HASHED_URI_MISMATCH));

        // A wrongly labelled icon target is left undeclared: declaring it with
        // the same hashed URI would collapse the icon reference into the
        // declaration's binding and skip the icon-label rule under test.
        for label in ["c2pa.thumbnail.claim.jpeg", "c2pa.icon__0", "c2pa.icon__x"] {
            let (fatal, wrong_label) = run_generator_icon_binding(
                ClaimGeneration::V2,
                label,
                sha(icon_jumbf),
                Some(icon_jumbf),
                false,
            );
            assert!(fatal, "{label}");
            assert!(wrong_label.has_failure(CLAIM_MALFORMED), "{label}");
            assert!(
                !wrong_label.has_success(ASSERTION_HASHED_URI_MATCH),
                "{label}"
            );
        }
    }

    #[test]
    fn cross_manifest_assertion_reference_reports_outside_manifest() {
        let manifest = structural_manifest();
        let reference = vmap(vec![
            (
                "url",
                Value::Text(
                    "self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/c2pa.hash.data".into(),
                ),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
        ]);
        let claim = vmap(vec![
            ("instanceID", Value::Text("urn:uuid:test".into())),
            (
                "claim_generator_info",
                vmap(vec![("name", Value::Text("generator".into()))]),
            ),
            ("created_assertions", Value::Array(vec![reference])),
        ]);
        let mut claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_assertion_bindings(
            &claim,
            &mut claim_refs,
            ClaimGeneration::V2,
            &manifest.label,
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(results.has_failure(ASSERTION_OUTSIDE_MANIFEST));
        assert!(!results.has_failure(HASHED_URI_MISSING));
    }

    #[test]
    fn sha1_assertion_binding_is_rejected_in_both_postures() {
        let assertion_jumbf = b"sha1 assertion jumbf";
        let assertion_payload = enc(&vmap(vec![("data", Value::Bytes(vec![1]))]));
        let label = "c2pa.hash.data";
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: vec![(label.into(), assertion_payload.as_slice())],
            assertion_jumbf: vec![(label.into(), assertion_jumbf.as_slice())],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let reference = vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            ),
            ("alg", Value::Text("sha1".into())),
            (
                "hash",
                Value::Bytes(
                    hex::decode("b1097bad25d72460ebc5fdfef3f195a6c29148c4")
                        .expect("valid SHA-1 fixture digest"),
                ),
            ),
        ]);
        let claim = vmap(vec![
            ("instanceID", Value::Text("urn:uuid:test".into())),
            (
                "claim_generator_info",
                vmap(vec![("name", Value::Text("generator".into()))]),
            ),
            ("created_assertions", Value::Array(vec![reference])),
        ]);

        for profile in [
            EngineProfile::strict(SpecVersion::V2_4),
            EngineProfile::GENEROUS,
        ] {
            let mut refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
            let mut results = ValidationResults::default();
            verify_assertion_bindings(
                &claim,
                &mut refs,
                ClaimGeneration::V2,
                &manifest.label,
                profile,
                &mut results,
            );
            assert!(results.has_failure(ALGORITHM_UNSUPPORTED));
            assert!(!results.has_informational(ALGORITHM_DEPRECATED));
            assert!(!results.has_success(ASSERTION_HASHED_URI_MATCH));
            assert!(!results.has_failure(ASSERTION_HASHED_URI_MISMATCH));
        }
    }

    #[test]
    fn v1_generator_icons_share_the_claim_reference_bound() {
        let generator_info = (1..=MAX_CLAIM_ASSERTION_REFERENCES)
            .map(|instance| {
                vmap(vec![
                    ("name", Value::Text(format!("generator {instance}"))),
                    (
                        "icon",
                        hashed_uri_for_assertion(&format!("c2pa.icon__{instance}")),
                    ),
                ])
            })
            .collect();
        let claim = vmap(vec![
            (
                "assertions",
                Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
            ),
            ("claim_generator_info", Value::Array(generator_info)),
        ]);
        let manifest = structural_manifest();
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V1);
        assert!(!claim_refs.complete);
    }

    #[test]
    fn malformed_hashed_uri_map_is_fatal() {
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![
                    valid_hashed_uri(),
                    vmap(vec![("hash", Value::Bytes(vec![0; 32]))]),
                ]),
            ),
        ]);
        let (fatal, results) = run_structure(&claim);
        assert!(fatal);
        assert!(results.has_failure(CLAIM_MALFORMED));
    }

    #[test]
    fn assertion_reference_count_is_bounded() {
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![valid_hashed_uri(); MAX_CLAIM_ASSERTION_REFERENCES + 1]),
            ),
        ]);
        let (fatal, results) = run_structure(&claim);
        assert!(fatal);
        assert!(results.has_failure(CLAIM_MALFORMED));
    }

    #[test]
    fn supported_bmff_hard_binding_labels_are_exact_v2_v3() {
        assert!(is_supported_bmff_hash_label("c2pa.hash.bmff.v2"));
        assert!(is_supported_bmff_hash_label("c2pa.hash.bmff.v3"));
        assert!(!is_supported_bmff_hash_label("c2pa.hash.bmff"));
        assert!(!is_supported_bmff_hash_label("c2pa.hash.bmff.experimental"));

        for label in ["c2pa.hash.bmff", "c2pa.hash.bmff.experimental"] {
            let claim = vmap(vec![
                ("instanceID", Value::Text("xmp:iid:test".into())),
                (
                    "created_assertions",
                    Value::Array(vec![hashed_uri_for_assertion(label)]),
                ),
            ]);
            let (_, results) = run_structure(&claim);
            assert!(results.has_failure(CLAIM_HARD_BINDINGS_MISSING), "{label}");
        }

        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.bmff.v3")]),
            ),
        ]);
        let (_, results) = run_structure(&claim);
        assert!(!results.has_failure(CLAIM_HARD_BINDINGS_MISSING));
    }

    #[test]
    fn duplicate_declaration_reference_is_fatal() {
        let assertion_payload = enc(&vmap(vec![("actions", Value::Array(Vec::new()))]));
        let assertion_jumbf = b"bounded assertion jumbf content";
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.actions".into(), assertion_payload.as_slice())],
            assertion_jumbf: vec![("c2pa.actions".into(), assertion_jumbf.as_slice())],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let duplicate = hashed_uri_for_assertion("c2pa.actions");
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![duplicate.clone(), duplicate]),
            ),
        ]);
        let claim_refs = ClaimAssertionRefs::build(&manifests[0], &claim, ClaimGeneration::V2);

        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            ClaimGeneration::V2,
            &claim_refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/test/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(fatal);
        assert!(results.has_failure(CLAIM_MALFORMED));
    }

    // Regression fixtures for the `claim_generator_info` icon: the generator
    // icon is a hashed-URI *pointer* to an assertion the claim also declares,
    // never a second declaration of it.
    const ICON_LABEL: &str = "c2pa.icon";
    const ICON_JUMBF: &[u8] = b"icon assertion jumbf content";
    const ACTIONS_JUMBF: &[u8] = b"actions assertion jumbf content";
    const HASH_DATA_JUMBF: &[u8] = b"hash data assertion jumbf content";
    const ICON_MANIFEST_LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-000000000001";
    const ICON_SIG_URL: &str =
        "self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000001/c2pa.signature";

    /// The one `c2pa.created` actions payload the fixture's semantic phase
    /// needs. Encoded once so the manifest can borrow it for `'static`.
    static ICON_ACTIONS_PAYLOAD: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
        enc(&vmap(vec![(
            "actions",
            Value::Array(vec![vmap(vec![
                ("action", Value::Text("c2pa.created".into())),
                (
                    "digitalSourceType",
                    Value::Text(
                        "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
                            .into(),
                    ),
                ),
            ])]),
        )]))
    });

    fn icon_manifest() -> ParsedManifest<'static> {
        ParsedManifest {
            label: ICON_MANIFEST_LABEL.into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.actions.v2".into(), ICON_ACTIONS_PAYLOAD.as_slice())],
            assertion_jumbf: vec![
                (ICON_LABEL.into(), ICON_JUMBF),
                ("c2pa.actions.v2".into(), ACTIONS_JUMBF),
                ("c2pa.hash.data".into(), HASH_DATA_JUMBF),
            ],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        }
    }

    fn bound_hashed_uri(label: &str, jumbf: &[u8]) -> Value {
        vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(jumbf))),
        ])
    }

    /// Structure gate plus every hashed-URI binding, the two phases the
    /// generator icon flows through.
    fn run_icon_manifest(
        claim: &Value,
        generation: ClaimGeneration,
    ) -> (bool, Option<String>, ValidationResults) {
        let manifests = [icon_manifest()];
        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();
        let mut claim_refs = ClaimAssertionRefs::build(&manifests[0], claim, generation);
        let duplicate = claim_refs.duplicate_label.map(str::to_string);
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            claim,
            generation,
            &claim_refs,
            AssetFormat::Jpeg,
            ICON_SIG_URL,
            EngineProfile::GENEROUS,
            &mut results,
        );
        verify_assertion_bindings(
            claim,
            &mut claim_refs,
            generation,
            ICON_MANIFEST_LABEL,
            EngineProfile::GENEROUS,
            &mut results,
        );
        (fatal, duplicate, results)
    }

    fn icon_statuses(results: &ValidationResults) -> (usize, usize) {
        let matched = results
            .success
            .iter()
            .filter(|status| {
                status.code == ASSERTION_HASHED_URI_MATCH && status.url.ends_with(ICON_LABEL)
            })
            .count();
        let mismatched = results
            .failure
            .iter()
            .filter(|status| {
                status.code == ASSERTION_HASHED_URI_MISMATCH && status.url.ends_with(ICON_LABEL)
            })
            .count();
        (matched, mismatched)
    }

    /// The shape shipped by OpenAI's image service (claim v2, generator icon
    /// plus three hashed assertions). The icon is declared once in
    /// `created_assertions` and pointed at once from `claim_generator_info`;
    /// neither C2PA 2.x nor the icon's own schema forbids that, so the manifest
    /// must stay valid instead of failing `claim.malformed`.
    #[test]
    fn v2_generator_icon_pointing_at_its_own_declaration_is_not_a_duplicate() {
        let icon = bound_hashed_uri(ICON_LABEL, ICON_JUMBF);
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            (
                "claim_generator_info",
                vmap(vec![
                    ("name", Value::Text("OpenAI Media Service API".into())),
                    ("icon", icon.clone()),
                ]),
            ),
            (
                "created_assertions",
                Value::Array(vec![
                    icon,
                    bound_hashed_uri("c2pa.actions.v2", ACTIONS_JUMBF),
                    bound_hashed_uri("c2pa.hash.data", HASH_DATA_JUMBF),
                ]),
            ),
        ]);

        let (fatal, duplicate, results) = run_icon_manifest(&claim, ClaimGeneration::V2);
        assert_eq!(duplicate, None);
        assert!(!fatal);
        assert_eq!(results.failure, Vec::new());
        assert_eq!(icon_statuses(&results), (1, 0));
        assert!(results.has_success(ASSERTION_HASHED_URI_MATCH));
    }

    /// Claim v1 carries `claim_generator_info` as an array of 1..* entries,
    /// each with an optional icon. Nothing requires those icons to differ, so
    /// two entries reusing one icon assertion is lawful.
    #[test]
    fn v1_generator_info_entries_may_share_one_icon() {
        let icon = bound_hashed_uri(ICON_LABEL, ICON_JUMBF);
        let generator_entry = |name: &str| {
            vmap(vec![
                ("name", Value::Text(name.into())),
                ("icon", icon.clone()),
            ])
        };
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            ("claim_generator", Value::Text("test/1.0".into())),
            ("dc:format", Value::Text("image/jpeg".into())),
            (
                "claim_generator_info",
                Value::Array(vec![generator_entry("first"), generator_entry("second")]),
            ),
            (
                "assertions",
                Value::Array(vec![
                    icon.clone(),
                    bound_hashed_uri("c2pa.actions.v2", ACTIONS_JUMBF),
                    bound_hashed_uri("c2pa.hash.data", HASH_DATA_JUMBF),
                ]),
            ),
        ]);

        let (fatal, duplicate, results) = run_icon_manifest(&claim, ClaimGeneration::V1);
        assert_eq!(duplicate, None);
        assert!(!fatal);
        assert_eq!(results.failure, Vec::new());
        assert_eq!(icon_statuses(&results), (1, 0));
    }

    /// The strictness this fix must not spend: declaring one assertion twice in
    /// the claim's own assertion list stays a fatal `claim.malformed`, icon or
    /// not, because the two declarations make internal references ambiguous.
    #[test]
    fn duplicate_icon_declaration_in_the_assertion_list_is_still_fatal() {
        let icon = bound_hashed_uri(ICON_LABEL, ICON_JUMBF);
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "claim_generator_info",
                vmap(vec![
                    ("name", Value::Text("test".into())),
                    ("icon", icon.clone()),
                ]),
            ),
            (
                "created_assertions",
                Value::Array(vec![
                    icon.clone(),
                    icon,
                    bound_hashed_uri("c2pa.hash.data", HASH_DATA_JUMBF),
                ]),
            ),
        ]);

        let (fatal, duplicate, results) = run_icon_manifest(&claim, ClaimGeneration::V2);
        assert_eq!(duplicate.as_deref(), Some(ICON_LABEL));
        assert!(fatal);
        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CLAIM_MALFORMED
                && status.explanation
                    == format!("claim declares assertion '{ICON_LABEL}' more than once")));
    }

    /// An icon reference is only interchangeable with a declaration that binds
    /// the same bytes. A generator icon whose signed digest diverges from the
    /// declared one is still resolved and still fails.
    #[test]
    fn generator_icon_with_a_divergent_hash_is_still_verified() {
        let declared_icon = bound_hashed_uri(ICON_LABEL, ICON_JUMBF);
        let substituted_icon = vmap(vec![
            (
                "url",
                Value::Text(format!("self#jumbf=c2pa.assertions/{ICON_LABEL}")),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0xab; 32])),
        ]);
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "claim_generator_info",
                vmap(vec![
                    ("name", Value::Text("test".into())),
                    ("icon", substituted_icon),
                ]),
            ),
            (
                "created_assertions",
                Value::Array(vec![
                    declared_icon,
                    bound_hashed_uri("c2pa.hash.data", HASH_DATA_JUMBF),
                    bound_hashed_uri("c2pa.actions.v2", ACTIONS_JUMBF),
                ]),
            ),
        ]);

        let (_, duplicate, results) = run_icon_manifest(&claim, ClaimGeneration::V2);
        assert_eq!(duplicate, None);
        assert_eq!(icon_statuses(&results), (1, 1));
    }

    #[test]
    fn assertion_digest_work_is_unique_by_resolved_label_and_algorithm() {
        let assertion_jumbf = b"bounded assertion jumbf content";
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: Vec::new(),
            assertion_jumbf: vec![("com.example.payload".into(), assertion_jumbf.as_slice())],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let duplicate = hashed_uri_for_assertion("com.example.payload");
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![duplicate.clone(), duplicate]),
            ),
        ]);
        let mut claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        assert_eq!(
            claim_refs.hash_work_bytes(ClaimGeneration::V2),
            Some(assertion_jumbf.len() * 2)
        );

        let mut results = ValidationResults::default();
        for _ in 0..2 {
            verify_assertion_bindings(
                &claim,
                &mut claim_refs,
                ClaimGeneration::V2,
                "urn:test",
                EngineProfile::GENEROUS,
                &mut results,
            );
        }
        let expected_digest = sha(assertion_jumbf);
        assert_eq!(
            claim_refs.jumbf_digest("com.example.payload", "sha256"),
            Some(expected_digest.as_slice())
        );
        assert_eq!(
            claim_refs
                .indexed("com.example.payload")
                .expect("indexed assertion")
                .jumbf_digests
                .iter()
                .flatten()
                .count(),
            1
        );
    }

    #[test]
    fn multiple_supported_hard_bindings_are_fatal() {
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.hash.data"),
                    hashed_uri_for_assertion("c2pa.hash.boxes"),
                ]),
            ),
        ]);
        let (fatal, results) = run_structure(&claim);
        assert!(fatal);
        assert!(results.has_failure(ASSERTION_MULTIPLE_HARD_BINDINGS));
        assert!(!results.has_failure(CLAIM_HARD_BINDINGS_MISSING));
    }

    #[test]
    fn undeclared_assertions_are_fatal_and_excluded_from_semantics_and_report() {
        let certificate_status = enc(&vmap(vec![("ocspVals", Value::Array(Vec::new()))]));
        let actions = enc(&vmap(vec![("actions", Value::Array(Vec::new()))]));
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: vec![
                (
                    "c2pa.certificate-status".into(),
                    certificate_status.as_slice(),
                ),
                ("c2pa.actions".into(), actions.as_slice()),
            ],
            assertion_jumbf: vec![
                (
                    "c2pa.certificate-status".into(),
                    certificate_status.as_slice(),
                ),
                ("c2pa.actions".into(), actions.as_slice()),
            ],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("created_assertions", Value::Array(Vec::new())),
        ]);
        let claim_refs = ClaimAssertionRefs::build(&manifests[0], &claim, ClaimGeneration::V2);

        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            ClaimGeneration::V2,
            &claim_refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/test/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(fatal);
        assert_eq!(
            results
                .failure
                .iter()
                .filter(|status| status.code == ASSERTION_UNDECLARED)
                .count(),
            2
        );
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        let report = manifest_entry_json(
            &manifests[0],
            Some(&claim),
            false,
            Some(&claim_refs.declared_labels),
            &[],
            None,
            &mut report_decode_nodes,
        );
        assert!(report["assertions"].as_array().is_some_and(Vec::is_empty));
    }

    #[test]
    fn report_assertions_share_one_decode_budget() {
        let payload = enc(&Value::Array(vec![Value::Null, Value::Null]));
        let manifest = ParsedManifest {
            label: "urn:c2pa:report-budget".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("com.example.first".into(), payload.as_slice()),
                ("com.example.second".into(), payload.as_slice()),
                ("com.example.third".into(), payload.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let mut report_decode_nodes = 4;

        let report = manifest_entry_json(
            &manifest,
            None,
            false,
            None,
            &[],
            None,
            &mut report_decode_nodes,
        );
        let assertions = report["assertions"].as_array().unwrap();

        assert_eq!(assertions[0]["data"], json!([null, null]));
        assert_eq!(
            assertions[1]["data"],
            json!({
                "_encypher_omitted": "decoded assertion report node budget exceeded"
            })
        );
        assert_eq!(assertions[2]["data"], assertions[1]["data"]);
        assert_eq!(report_decode_nodes, 0);
    }

    #[test]
    fn report_assertion_data_is_unchanged_within_budget() {
        let payload = enc(&vmap(vec![
            ("name", Value::Text("example".into())),
            ("enabled", Value::Bool(true)),
        ]));
        let manifest = ParsedManifest {
            label: "urn:c2pa:normal-report".into(),
            manifest_jumbf: &[],
            assertions: vec![("com.example.normal".into(), payload.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;

        let report = manifest_entry_json(
            &manifest,
            None,
            false,
            None,
            &[],
            None,
            &mut report_decode_nodes,
        );

        assert_eq!(
            report["assertions"],
            json!([{
                "label": "com.example.normal",
                "data": {
                    "name": "example",
                    "enabled": true,
                },
            }])
        );
    }

    fn mdat(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        out.extend_from_slice(b"mdat");
        out.extend_from_slice(payload);
        out
    }

    fn test_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    fn run_bmff_data_hash(label: &str, hash_data: &Value, data: &[u8]) -> ValidationResults {
        let assertion_cbor = enc(hash_data);
        let assertions: Vec<(String, &[u8])> = vec![(label.into(), assertion_cbor.as_slice())];
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion(label)]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let _operative_binding = verify_data_hash(
            &claim,
            &claim_refs,
            data,
            AssetFormat::Bmff,
            &[],
            update_manifest::StoreRendition::AsSigned,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    fn run_prehashed_label(label: &str, digest: &[u8]) -> ValidationResults {
        let assertion = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(digest.to_vec())),
        ]);
        let assertion_cbor = enc(&assertion);
        let assertions: Vec<(String, &[u8])> = vec![(label.into(), assertion_cbor.as_slice())];
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion(label)]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let _operative_binding =
            verify_prehashed_hard_binding(&claim, &claim_refs, digest, "urn:test", &mut results);
        results
    }

    fn bmff_noop_exclusions() -> Value {
        Value::Array(vec![vmap(vec![("xpath", Value::Text("/uuid".into()))])])
    }

    #[test]
    fn data_hash_verifier_ignores_removed_or_experimental_bmff_labels() {
        let data = test_box(b"ftyp", b"isom");
        let digest = crate::c2pa_formats::bmff_hash_with_exclusions(&data, "sha256", &[]).unwrap();
        let hash_data = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(digest)),
            ("exclusions", bmff_noop_exclusions()),
        ]);

        let accepted = run_bmff_data_hash("c2pa.hash.bmff.v3", &hash_data, &data);
        assert!(accepted.has_success(ASSERTION_BMFF_HASH_MATCH));

        for label in ["c2pa.hash.bmff", "c2pa.hash.bmff.experimental"] {
            let ignored = run_bmff_data_hash(label, &hash_data, &data);
            assert!(!ignored.has_success(ASSERTION_BMFF_HASH_MATCH), "{label}");
            assert!(ignored.failure.is_empty(), "{label}: {:?}", ignored.failure);
        }
    }

    #[test]
    fn detached_hash_verifier_accepts_only_v2_v3_bmff_labels() {
        let digest = vec![7; 32];
        let accepted = run_prehashed_label("c2pa.hash.bmff.v2", &digest);
        assert!(accepted.has_success(ASSERTION_BMFF_HASH_MATCH));

        for label in ["c2pa.hash.bmff", "c2pa.hash.bmff.experimental"] {
            let ignored = run_prehashed_label(label, &digest);
            assert!(ignored.has_failure(ASSERTION_DATA_HASH_MISMATCH), "{label}");
            assert!(!ignored.has_success(ASSERTION_BMFF_HASH_MATCH), "{label}");
        }
    }

    #[test]
    fn bmff_hash_and_merkle_must_both_match() {
        let data = test_box(b"ftyp", b"isom");
        let digest = crate::c2pa_formats::bmff_hash_with_exclusions(&data, "sha256", &[]).unwrap();
        let merkle_entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(1)),
            ("count", Value::Integer(1)),
            ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ("initHash", Value::Bytes(digest.clone())),
        ]);
        let bad_top_hash = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
            ("exclusions", bmff_noop_exclusions()),
            ("merkle", Value::Array(vec![merkle_entry.clone()])),
        ]);
        let bad = run_bmff_data_hash("c2pa.hash.bmff.v3", &bad_top_hash, &data);
        assert!(bad.has_failure(ASSERTION_BMFF_HASH_MISMATCH));
        assert!(!bad.has_success(ASSERTION_BMFF_HASH_MATCH));

        let good_hash_and_merkle = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(digest)),
            ("exclusions", bmff_noop_exclusions()),
            ("merkle", Value::Array(vec![merkle_entry])),
        ]);
        let good = run_bmff_data_hash("c2pa.hash.bmff.v3", &good_hash_and_merkle, &data);
        assert!(good.has_success(ASSERTION_BMFF_HASH_MATCH));
        assert!(!good.has_failure(ASSERTION_BMFF_HASH_MISMATCH));
    }
    fn auxiliary_merkle_box(
        unique_id: i128,
        local_id: i128,
        location: usize,
        proof: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let map = vmap(vec![
            ("uniqueId", Value::Integer(unique_id)),
            ("localId", Value::Integer(local_id)),
            ("location", Value::Integer(location as i128)),
            (
                "hashes",
                Value::Array(proof.into_iter().map(Value::Bytes).collect()),
            ),
        ]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&crate::c2pa_formats::C2PA_BMFF_UUID);
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(b"merkle\0");
        payload.extend_from_slice(&enc(&map));
        test_box(b"uuid", &payload)
    }

    fn verify_test_bmff_monolithic_entry(
        entry: &Value,
        assertion_alg: &str,
        data: &[u8],
        proof_index: Option<&BmffMerkleProofIndex>,
        url: &str,
        results: &mut ValidationResults,
    ) -> bool {
        let plans = match preflight_bmff_monolithic_entries(
            std::slice::from_ref(entry),
            assertion_alg,
            data,
        ) {
            Ok(plans) => plans,
            Err(why) => {
                results.push_failure(ASSERTION_BMFF_HASH_MALFORMED, url.to_string(), why);
                return false;
            }
        };
        verify_bmff_monolithic_entry(&plans[0], proof_index, url, results)
    }

    #[test]
    fn fixed_merkle_chunks_validate_without_descriptor_collection() {
        let data = mdat(b"abcd");
        let hashes = b"abcd"
            .iter()
            .map(|byte| Value::Bytes(sha(&[*byte])))
            .collect();
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(0)),
            ("count", Value::Integer(4)),
            ("fixedBlockSize", Value::Integer(1)),
            ("hashes", Value::Array(hashes)),
        ]);
        let mut results = ValidationResults::default();
        assert!(verify_test_bmff_monolithic_entry(
            &entry,
            "sha256",
            &data,
            None,
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
    }

    #[test]
    fn variable_merkle_chunk_sizes_cannot_overflow() {
        let data = mdat(b"abcd");
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(0)),
            ("count", Value::Integer(2)),
            (
                "variableBlockSizes",
                Value::Array(vec![Value::Integer(usize::MAX as i128), Value::Integer(1)]),
            ),
            (
                "hashes",
                Value::Array(vec![Value::Bytes(vec![0; 32]), Value::Bytes(vec![0; 32])]),
            ),
        ]);
        let mut results = ValidationResults::default();
        assert!(!verify_test_bmff_monolithic_entry(
            &entry,
            "sha256",
            &data,
            None,
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
        assert!(results.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn variable_merkle_chunks_validate_without_size_or_range_vectors() {
        let data = mdat(b"abcd");
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(0)),
            ("count", Value::Integer(2)),
            (
                "variableBlockSizes",
                Value::Array(vec![Value::Integer(1), Value::Integer(3)]),
            ),
            (
                "hashes",
                Value::Array(vec![Value::Bytes(sha(b"a")), Value::Bytes(sha(b"bcd"))]),
            ),
        ]);
        let mut results = ValidationResults::default();
        assert!(verify_test_bmff_monolithic_entry(
            &entry,
            "sha256",
            &data,
            None,
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
    }

    #[test]
    fn monolithic_merkle_leaf_count_is_bounded() {
        let data = mdat(&[]);
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(0)),
            (
                "count",
                Value::Integer((MAX_BMFF_MERKLE_LEAVES as i128) + 1),
            ),
            (
                "variableBlockSizes",
                Value::Array(vec![Value::Integer(0); MAX_BMFF_MERKLE_LEAVES + 1]),
            ),
            ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
        ]);
        let mut results = ValidationResults::default();
        assert!(!verify_test_bmff_monolithic_entry(
            &entry,
            "sha256",
            &data,
            None,
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
        assert!(results.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn monolithic_merkle_rejects_duplicate_mdat_targeting_across_trees() {
        let data = mdat(b"abcd");
        let entry = |unique_id| {
            vmap(vec![
                ("uniqueId", Value::Integer(unique_id)),
                ("localId", Value::Integer(0)),
                ("count", Value::Integer(1)),
                ("hashes", Value::Array(vec![Value::Bytes(sha(b"abcd"))])),
            ])
        };
        let entries = [entry(1), entry(2)];
        let error = match preflight_bmff_monolithic_entries(&entries, "sha256", &data) {
            Err(error) => error,
            Ok(_) => panic!("the same mdat cannot be targeted twice"),
        };
        assert!(error.contains("duplicate monolithic merkle"));
    }

    #[test]
    fn aggregate_monolithic_merkle_work_is_checked_and_bounded() {
        let mut bytes = MAX_BMFF_MERKLE_TOTAL_HASH_BYTES - 1;
        let mut chunks = MAX_BMFF_MERKLE_TOTAL_CHUNKS - 1;
        assert!(checked_bmff_merkle_work(&mut bytes, &mut chunks, 1, 1).is_ok());
        assert_eq!(bytes, MAX_BMFF_MERKLE_TOTAL_HASH_BYTES);
        assert_eq!(chunks, MAX_BMFF_MERKLE_TOTAL_CHUNKS);
        assert!(checked_bmff_merkle_work(&mut bytes, &mut chunks, 1, 0).is_err());

        let mut bytes = 0;
        let mut chunks = MAX_BMFF_MERKLE_TOTAL_CHUNKS;
        assert!(checked_bmff_merkle_work(&mut bytes, &mut chunks, 0, 1).is_err());
    }

    #[test]
    fn flat_fragmented_init_hash_stops_before_the_first_top_level_moof() {
        let mut init = test_box(b"ftyp", b"isom");
        init.extend_from_slice(&test_box(b"moov", &test_box(b"moof", &[])));
        let mut flat = init.clone();
        flat.extend_from_slice(&test_box(b"moof", &[]));
        flat.extend_from_slice(&mdat(b"media"));
        let expected =
            crate::c2pa_formats::bmff_hash_with_exclusions(&init, "sha256", &[]).unwrap();
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(1)),
            ("count", Value::Integer(1)),
            ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ("initHash", Value::Bytes(expected.clone())),
        ]);
        let hash_data = vmap(vec![("merkle", Value::Array(vec![entry.clone()]))]);
        let mut results = ValidationResults::default();
        verify_bmff_merkle_init(
            BmffMerkleInput {
                hash_data: &hash_data,
                assertion_alg: "sha256",
                exclusions: &[],
                data: &flat,
                fragments: &[],
                url: "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
                binding_compromised: false,
            },
            &mut results,
        );
        assert!(results.has_success(ASSERTION_BMFF_HASH_MATCH));
        assert!(!results.has_failure(ASSERTION_BMFF_HASH_MISMATCH));

        let standalone_hash_data = vmap(vec![("merkle", Value::Array(vec![entry]))]);
        let mut standalone_results = ValidationResults::default();
        verify_bmff_merkle_init(
            BmffMerkleInput {
                hash_data: &standalone_hash_data,
                assertion_alg: "sha256",
                exclusions: &[],
                data: &init,
                fragments: &[],
                url: "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
                binding_compromised: false,
            },
            &mut standalone_results,
        );
        assert!(standalone_results.has_success(ASSERTION_BMFF_HASH_MATCH));
    }

    #[test]
    fn fragmented_merkle_rejects_wrong_init_hash_width() {
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(1)),
            ("localId", Value::Integer(1)),
            ("count", Value::Integer(1)),
            ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ("initHash", Value::Bytes(vec![0; 31])),
        ]);
        let hash_data = vmap(vec![("merkle", Value::Array(vec![entry]))]);
        let data = test_box(b"ftyp", b"isom");
        let mut results = ValidationResults::default();
        verify_bmff_merkle_init(
            BmffMerkleInput {
                hash_data: &hash_data,
                assertion_alg: "sha256",
                exclusions: &[],
                data: &data,
                fragments: &[],
                url: "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
                binding_compromised: false,
            },
            &mut results,
        );
        assert!(results.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    fn run_fragment_merkle(entry: Value, proof: Vec<Vec<u8>>) -> ValidationResults {
        let fragment = auxiliary_merkle_box(7, 9, 0, proof);
        let mut results = ValidationResults::default();
        verify_bmff_fragments(
            &[entry],
            "sha256",
            &[],
            &[fragment.as_slice()],
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        );
        results
    }

    fn fragment_merkle_entry(count: i128, hashes: Vec<Value>) -> Value {
        vmap(vec![
            ("uniqueId", Value::Integer(7)),
            ("localId", Value::Integer(9)),
            ("count", Value::Integer(count)),
            ("hashes", Value::Array(hashes)),
            ("initHash", Value::Bytes(vec![0; 32])),
        ])
    }

    #[test]
    fn fragment_merkle_rejects_non_byte_rows() {
        let non_byte = run_fragment_merkle(
            fragment_merkle_entry(1, vec![Value::Bytes(vec![0; 32]), Value::Integer(7)]),
            Vec::new(),
        );
        assert!(non_byte.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn fragment_merkle_rejects_block_size_descriptors() {
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(7)),
            ("localId", Value::Integer(9)),
            ("count", Value::Integer(1)),
            ("fixedBlockSize", Value::Integer(1)),
            ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
            ("initHash", Value::Bytes(vec![0; 32])),
        ]);
        let results = run_fragment_merkle(entry, Vec::new());
        assert!(results.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn fragment_merkle_rejects_missing_negative_zero_and_out_of_range_counts() {
        for count in [-1, 0, i128::MAX] {
            let invalid_count = run_fragment_merkle(
                fragment_merkle_entry(count, vec![Value::Bytes(vec![0; 32])]),
                Vec::new(),
            );
            assert!(invalid_count.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
        }
        let missing_count = run_fragment_merkle(
            vmap(vec![
                ("uniqueId", Value::Integer(7)),
                ("localId", Value::Integer(9)),
                ("hashes", Value::Array(vec![Value::Bytes(vec![0; 32])])),
                ("initHash", Value::Bytes(vec![0; 32])),
            ]),
            Vec::new(),
        );
        assert!(missing_count.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn fragment_merkle_rejects_wrong_row_digest_width() {
        let bad_row = run_fragment_merkle(
            fragment_merkle_entry(1, vec![Value::Bytes(vec![0; 31])]),
            Vec::new(),
        );
        assert!(bad_row.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn fragment_merkle_rejects_wrong_proof_digest_width() {
        let bad_proof = run_fragment_merkle(
            fragment_merkle_entry(2, vec![Value::Bytes(vec![0; 32])]),
            vec![vec![0; 31]],
        );
        assert!(bad_proof.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
    }

    #[test]
    fn fragment_merkle_rejects_duplicate_fragment_identities() {
        let fragment = auxiliary_merkle_box(7, 9, 0, Vec::new());
        let leaf = crate::c2pa_formats::bmff_fragment_leaf_hash(&fragment, "sha256", &[]).unwrap();
        let entry = fragment_merkle_entry(1, vec![Value::Bytes(leaf)]);
        let mut results = ValidationResults::default();
        assert!(!verify_bmff_fragments(
            &[entry],
            "sha256",
            &[],
            &[fragment.as_slice(), fragment.as_slice()],
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
        assert!(results.has_failure(ASSERTION_BMFF_HASH_MISMATCH));
        assert!(!results.has_success(ASSERTION_BMFF_HASH_MATCH));
    }

    #[test]
    fn monolithic_merkle_uses_indexed_auxiliary_proofs() {
        let left = sha(b"a");
        let right = sha(b"b");
        let mut pair = left.clone();
        pair.extend_from_slice(&right);
        let root = sha(&pair);
        let entry = vmap(vec![
            ("uniqueId", Value::Integer(3)),
            ("localId", Value::Integer(0)),
            ("count", Value::Integer(2)),
            ("fixedBlockSize", Value::Integer(1)),
            ("hashes", Value::Array(vec![Value::Bytes(root)])),
        ]);
        let mut proofs = auxiliary_merkle_box(3, 0, 0, vec![right]);
        proofs.extend_from_slice(&auxiliary_merkle_box(3, 0, 1, vec![left]));
        let index = bmff_merkle_proof_index(&proofs).unwrap();
        let mut results = ValidationResults::default();
        assert!(verify_test_bmff_monolithic_entry(
            &entry,
            "sha256",
            &mdat(b"ab"),
            Some(&index),
            "self#jumbf=c2pa.assertions/c2pa.hash.bmff.v3",
            &mut results,
        ));
        assert!(!results.has_failure(ASSERTION_BMFF_HASH_MALFORMED));
        assert!(!results.has_failure(ASSERTION_BMFF_HASH_MISMATCH));
    }

    #[test]
    fn auxiliary_merkle_proof_index_rejects_duplicate_keys() {
        let first = auxiliary_merkle_box(3, 0, 0, vec![vec![0; 32]]);
        let second = auxiliary_merkle_box(3, 0, 0, vec![vec![1; 32]]);
        let mut data = first;
        data.extend_from_slice(&second);
        assert_eq!(
            bmff_merkle_proof_index(&data),
            Err("duplicate auxiliary C2PA merkle proof key")
        );
    }

    #[test]
    fn bmff_exclusion_parser_treats_null_optionals_as_absent() {
        let hash_data = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                ("length", Value::Null),
                ("version", Value::Null),
                ("flags", Value::Null),
                ("exact", Value::Null),
                ("data", Value::Null),
                ("subset", Value::Null),
            ])]),
        )]);
        let exclusions = bmff_exclusion_maps(&hash_data).unwrap();
        assert_eq!(exclusions.len(), 1);
        let exclusion = &exclusions[0];
        assert_eq!(exclusion.xpath, "/free");
        assert_eq!(exclusion.length, None);
        assert_eq!(exclusion.version, None);
        assert_eq!(exclusion.flags, None);
        assert!(exclusion.exact);
        assert!(exclusion.data.is_empty());
        assert!(exclusion.subset.is_empty());
    }

    #[test]
    fn bmff_exclusion_parser_rejects_wrong_non_null_optional_types() {
        for (field, value) in [
            ("length", Value::Bool(false)),
            ("version", Value::Text("zero".into())),
            ("flags", Value::Integer(0)),
            ("exact", Value::Integer(0)),
            ("data", Value::Text("none".into())),
            ("subset", Value::Text("none".into())),
        ] {
            let hash_data = vmap(vec![(
                "exclusions",
                Value::Array(vec![vmap(vec![
                    ("xpath", Value::Text("/free".into())),
                    (field, value),
                ])]),
            )]);
            assert!(bmff_exclusion_maps(&hash_data).is_err(), "{field}");
        }
    }

    #[test]
    fn bmff_exclusion_parser_bounds_qualifier_entries_and_bytes() {
        let data_map = vmap(vec![
            ("offset", Value::Integer(0)),
            ("value", Value::Bytes(Vec::new())),
        ]);
        let too_many = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                (
                    "data",
                    Value::Array(vec![data_map; MAX_BMFF_EXCLUSION_DATA_QUALIFIERS + 1]),
                ),
            ])]),
        )]);
        assert!(bmff_exclusion_maps(&too_many).is_err());

        let too_many_bytes = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                (
                    "data",
                    Value::Array(vec![vmap(vec![
                        ("offset", Value::Integer(0)),
                        (
                            "value",
                            Value::Bytes(vec![0; MAX_BMFF_EXCLUSION_DATA_BYTES + 1]),
                        ),
                    ])]),
                ),
            ])]),
        )]);
        assert!(bmff_exclusion_maps(&too_many_bytes).is_err());
    }

    #[test]
    fn bmff_exclusion_parser_bounds_and_orders_subsets() {
        let subset_map = vmap(vec![
            ("offset", Value::Integer(0)),
            ("length", Value::Integer(1)),
        ]);
        let too_many = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                (
                    "subset",
                    Value::Array(vec![subset_map; MAX_BMFF_EXCLUSION_SUBSETS + 1]),
                ),
            ])]),
        )]);
        assert!(bmff_exclusion_maps(&too_many).is_err());

        let overlapping = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                (
                    "subset",
                    Value::Array(vec![
                        vmap(vec![
                            ("offset", Value::Integer(4)),
                            ("length", Value::Integer(4)),
                        ]),
                        vmap(vec![
                            ("offset", Value::Integer(7)),
                            ("length", Value::Integer(1)),
                        ]),
                    ]),
                ),
            ])]),
        )]);
        assert!(bmff_exclusion_maps(&overlapping).is_err());

        let overflowing_end = vmap(vec![(
            "exclusions",
            Value::Array(vec![vmap(vec![
                ("xpath", Value::Text("/free".into())),
                (
                    "subset",
                    Value::Array(vec![vmap(vec![
                        ("offset", Value::Integer(4)),
                        ("length", Value::Integer(usize::MAX as i128)),
                    ])]),
                ),
            ])]),
        )]);
        let exclusions = bmff_exclusion_maps(&overflowing_end).unwrap();
        assert_eq!(exclusions[0].subset[0].length, usize::MAX);
    }

    fn cose_with_ocsp_values(values: &[&[u8]]) -> Vec<u8> {
        let protected = enc(&Value::Map(Vec::new()));
        let unprotected = vmap(vec![(
            "rVals",
            vmap(vec![(
                "ocspVals",
                Value::Array(
                    values
                        .iter()
                        .map(|value| Value::Bytes(value.to_vec()))
                        .collect(),
                ),
            )]),
        )]);
        encode(
            &Value::Tag(
                18,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    unprotected,
                    Value::Null,
                    Value::Bytes(vec![0x01]),
                ])),
            ),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode COSE")
    }

    #[test]
    fn embedded_ocsp_visitor_preserves_rvals_and_assertion_order_without_cloning() {
        let signature = cose_with_ocsp_values(&[b"rval-1", b"rval-2"]);
        let first_assertion = enc(&vmap(vec![(
            "revocationValues",
            vmap(vec![(
                "ocspVals",
                Value::Array(vec![Value::Bytes(b"assertion-1".to_vec())]),
            )]),
        )]));
        let second_assertion = enc(&vmap(vec![(
            "ocspVals",
            Value::Array(vec![Value::Bytes(b"assertion-2".to_vec())]),
        )]));

        let mut visited = Vec::new();
        let evidence = scan_embedded_ocsp_evidence(
            &signature,
            &[first_assertion.as_slice(), second_assertion.as_slice()],
            |response| {
                visited.push(response.to_vec());
            },
        );
        assert!(!evidence.rejected);
        assert_eq!(evidence.responses, 4);
        assert_eq!(
            visited,
            vec![
                b"rval-1".to_vec(),
                b"rval-2".to_vec(),
                b"assertion-1".to_vec(),
                b"assertion-2".to_vec(),
            ]
        );
    }

    #[test]
    fn embedded_ocsp_limits_accept_boundaries_and_reject_excess_before_evaluation() {
        let at_limit: Vec<Vec<u8>> = (0..MAX_EMBEDDED_OCSP_RESPONSES)
            .map(|index| vec![index as u8])
            .collect();
        let at_limit_refs: Vec<&[u8]> = at_limit.iter().map(Vec::as_slice).collect();
        let signature = cose_with_ocsp_values(&at_limit_refs);
        let mut visits = 0usize;
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| visits += 1);
        assert!(!evidence.rejected);
        assert_eq!(evidence.responses, MAX_EMBEDDED_OCSP_RESPONSES);
        assert_eq!(visits, MAX_EMBEDDED_OCSP_RESPONSES);

        let over_limit: Vec<Vec<u8>> = (0..=MAX_EMBEDDED_OCSP_RESPONSES)
            .map(|index| vec![index as u8])
            .collect();
        let over_limit_refs: Vec<&[u8]> = over_limit.iter().map(Vec::as_slice).collect();
        let signature = cose_with_ocsp_values(&over_limit_refs);
        let mut visits = 0usize;
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| visits += 1);
        assert!(evidence.rejected);
        assert_eq!(visits, 0);

        let at_response_limit = vec![0; MAX_OCSP_RESPONSE_BYTES];
        let signature = cose_with_ocsp_values(&[&at_response_limit]);
        let mut visits = 0usize;
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| visits += 1);
        assert!(!evidence.rejected);
        assert_eq!(evidence.total_bytes, MAX_OCSP_RESPONSE_BYTES);
        assert_eq!(visits, 1);

        assert_eq!(MAX_EMBEDDED_OCSP_TOTAL_BYTES % MAX_OCSP_RESPONSE_BYTES, 0);
        let total_response_count = MAX_EMBEDDED_OCSP_TOTAL_BYTES / MAX_OCSP_RESPONSE_BYTES;
        let responses: Vec<Vec<u8>> = (0..total_response_count)
            .map(|_| vec![0; MAX_OCSP_RESPONSE_BYTES])
            .collect();
        let response_refs: Vec<&[u8]> = responses.iter().map(Vec::as_slice).collect();
        let signature = cose_with_ocsp_values(&response_refs);
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| {});
        assert!(!evidence.rejected);
        assert_eq!(evidence.total_bytes, MAX_EMBEDDED_OCSP_TOTAL_BYTES);

        let oversized = vec![0; MAX_OCSP_RESPONSE_BYTES + 1];
        let signature = cose_with_ocsp_values(&[&oversized]);
        let mut visits = 0usize;
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| visits += 1);
        assert!(evidence.rejected);
        assert_eq!(visits, 0);

        let response_bytes = MAX_EMBEDDED_OCSP_TOTAL_BYTES / 5 + 1;
        assert!(response_bytes <= MAX_OCSP_RESPONSE_BYTES);
        let responses: Vec<Vec<u8>> = (0..5).map(|_| vec![0; response_bytes]).collect();
        let response_refs: Vec<&[u8]> = responses.iter().map(Vec::as_slice).collect();
        let signature = cose_with_ocsp_values(&response_refs);
        let evidence = scan_embedded_ocsp_evidence(&signature, &[], |_| {});
        assert!(evidence.rejected);

        let mut too_deep = vmap(vec![(
            "ocspVals",
            Value::Array(vec![Value::Bytes(b"hidden".to_vec())]),
        )]);
        for _ in 0..=MAX_EMBEDDED_OCSP_COLLECTION_DEPTH {
            too_deep = Value::Array(vec![too_deep]);
        }
        let assertion = enc(&too_deep);
        let evidence = scan_embedded_ocsp_evidence(
            &cose_with_ocsp_values(&[]),
            &[assertion.as_slice()],
            |_| {},
        );
        assert!(evidence.rejected);

        let excessive_nodes = enc(&Value::Array(
            (0..=MAX_EMBEDDED_OCSP_COLLECTION_NODES)
                .map(|_| Value::Null)
                .collect(),
        ));
        let evidence = scan_embedded_ocsp_evidence(
            &cose_with_ocsp_values(&[]),
            &[excessive_nodes.as_slice()],
            |_| {},
        );
        assert!(evidence.rejected);
    }

    #[test]
    fn leaf_and_ca_revocation_emit_distinct_c2pa_status_codes() {
        let revoked = crate::c2pa_trust::OcspStatus::Revoked {
            revocation_time: OffsetDateTime::UNIX_EPOCH,
            reason: None,
        };
        let good = crate::c2pa_trust::OcspStatus::Good;
        let cases = [
            (
                vec![Some(revoked), Some(good)],
                EmbeddedOcspStatus::LeafRevoked,
                true,
                false,
                1usize,
            ),
            (
                vec![Some(good), Some(revoked)],
                EmbeddedOcspStatus::CaRevoked,
                false,
                true,
                1usize,
            ),
            (
                vec![Some(revoked), Some(revoked)],
                EmbeddedOcspStatus::LeafAndCaRevoked,
                true,
                true,
                2usize,
            ),
        ];
        for (statuses, expected_status, leaf_revoked, ca_untrusted, failure_count) in cases {
            let status = embedded_ocsp_status_from_certificate_statuses(&statuses);
            assert!(status == expected_status);
            let mut results = ValidationResults::default();
            record_ocsp_status(
                EmbeddedOcspOutcome::plain(status),
                &OnlineOcspOutcome::default(),
                &[],
                "self#jumbf=/c2pa/test",
                &mut results,
            );
            assert_eq!(
                results.has_failure(SIGNING_CREDENTIAL_OCSP_REVOKED),
                leaf_revoked
            );
            assert_eq!(
                results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED),
                ca_untrusted
            );
            assert_eq!(results.failure.len(), failure_count);
            assert!(status.blocks_trust());
        }
    }

    #[test]
    fn good_before_revoked_evidence_blocks_trust() {
        let good = crate::c2pa_trust::OcspStatus::Good;
        let revoked = crate::c2pa_trust::OcspStatus::Revoked {
            revocation_time: OffsetDateTime::UNIX_EPOCH,
            reason: None,
        };
        let status = [Some(good), Some(revoked)]
            .into_iter()
            .fold(None, crate::c2pa_trust::OcspStatus::merge);

        assert!(matches!(
            status,
            Some(crate::c2pa_trust::OcspStatus::Revoked { .. })
        ));
        assert!(
            embedded_ocsp_status_from_certificate_statuses(&[status])
                == EmbeddedOcspStatus::LeafRevoked
        );
    }

    #[test]
    fn revoked_before_good_evidence_blocks_trust() {
        let good = crate::c2pa_trust::OcspStatus::Good;
        let revoked = crate::c2pa_trust::OcspStatus::Revoked {
            revocation_time: OffsetDateTime::UNIX_EPOCH,
            reason: None,
        };
        let status = [Some(revoked), Some(good)]
            .into_iter()
            .fold(None, crate::c2pa_trust::OcspStatus::merge);

        assert!(matches!(
            status,
            Some(crate::c2pa_trust::OcspStatus::Revoked { .. })
        ));
        assert!(
            embedded_ocsp_status_from_certificate_statuses(&[status])
                == EmbeddedOcspStatus::LeafRevoked
        );
    }

    fn run_primary_multi_binding(
        data: &[u8],
        primary_expected: Vec<u8>,
    ) -> (ValidationResults, &'static str) {
        let primary = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(primary_expected)),
        ]);
        let fallback = multi_asset(&[(0, data.len(), "c2pa.hash.data.part", false)]);
        let part = part_assertion(&sha(data));
        let encoded = [
            ("c2pa.hash.data", enc(&primary)),
            ("c2pa.hash.multi-asset", enc(&fallback)),
            ("c2pa.hash.data.part", enc(&part)),
        ];
        let assertions = encoded
            .iter()
            .map(|(label, bytes)| ((*label).to_string(), bytes.as_slice()))
            .collect();
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![
                hashed_uri_for_assertion("c2pa.hash.data"),
                hashed_uri_for_assertion("c2pa.hash.multi-asset"),
                hashed_uri_for_assertion("c2pa.hash.data.part"),
            ]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let operative_binding = verify_data_hash(
            &claim,
            &claim_refs,
            data,
            AssetFormat::Jpeg,
            &[],
            update_manifest::StoreRendition::AsSigned,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        let kind = match operative_binding {
            Some(OperativeBinding::Primary(_)) => "primary",
            Some(OperativeBinding::MultiAsset(_)) => "multi-asset",
            None => "none",
        };
        (results, kind)
    }

    #[test]
    fn primary_and_multi_asset_are_one_plan_and_fallback_only_after_mismatch() {
        let data = fixture_data();
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            (
                "claim_generator_info",
                vmap(vec![("name", Value::Text("test".into()))]),
            ),
            (
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.hash.data"),
                    hashed_uri_for_assertion("c2pa.hash.multi-asset"),
                ]),
            ),
        ]);
        let (fatal, structure) = run_structure(&claim);
        assert!(!fatal);
        assert!(!structure.has_failure(ASSERTION_MULTIPLE_HARD_BINDINGS));
        assert!(!structure.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));

        let (primary_match, primary_kind) = run_primary_multi_binding(&data, sha(&data));
        assert_eq!(primary_kind, "primary");
        assert!(primary_match.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(!primary_match.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));

        let (fallback_match, fallback_kind) = run_primary_multi_binding(&data, vec![0; 32]);
        assert_eq!(fallback_kind, "multi-asset");
        assert!(!fallback_match.has_failure(ASSERTION_DATA_HASH_MISMATCH));
        assert!(!fallback_match.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(fallback_match.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn prehashed_verification_uses_primary_when_multi_asset_parts_are_unavailable() {
        let expected = sha(b"asset");
        let primary = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(expected.clone())),
        ]));
        let fallback = enc(&multi_asset(&[(0, 5, "c2pa.hash.data.part", false)]));
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("c2pa.hash.data".into(), primary.as_slice()),
                ("c2pa.hash.multi-asset".into(), fallback.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![
                hashed_uri_for_assertion("c2pa.hash.data"),
                hashed_uri_for_assertion("c2pa.hash.multi-asset"),
            ]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);

        let mut matched = ValidationResults::default();
        let operative =
            verify_prehashed_hard_binding(&claim, &claim_refs, &expected, "urn:test", &mut matched);
        assert!(matches!(operative, Some(OperativeBinding::Primary(_))));
        assert!(matched.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(!matched.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));

        let mut mismatched = ValidationResults::default();
        let operative = verify_prehashed_hard_binding(
            &claim,
            &claim_refs,
            &[0; 32],
            "urn:test",
            &mut mismatched,
        );
        assert!(operative.is_none());
        assert!(mismatched.has_failure(ASSERTION_DATA_HASH_MISMATCH));
        assert!(!mismatched.has_success(ASSERTION_MULTI_ASSET_HASH_MATCH));
    }

    #[test]
    fn two_multi_asset_fallbacks_are_malformed_not_multiple_primary_bindings() {
        let duplicate = hashed_uri_for_assertion("c2pa.hash.multi-asset");
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.hash.data"),
                    duplicate.clone(),
                    duplicate,
                ]),
            ),
        ]);
        let (fatal, results) = run_structure(&claim);
        assert!(fatal);
        assert!(results.has_failure(ASSERTION_MULTI_ASSET_HASH_MALFORMED));
        assert!(!results.has_failure(ASSERTION_MULTIPLE_HARD_BINDINGS));
    }

    #[test]
    fn appended_bytes_fail_whole_asset_hash_despite_region_metadata() {
        let carrier = "signed text";
        let signed = padded_text_with_wrapper(carrier);
        let mut modified = signed.as_bytes().to_vec();
        modified.extend_from_slice(b" appended");
        let (wrapper_start, wrapper_length) =
            locate_text_wrapper(&signed).expect("embedded wrapper");
        let primary = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(carrier.as_bytes()))),
            (
                "exclusions",
                Value::Array(vec![vmap(vec![
                    ("start", Value::Integer(wrapper_start as i128)),
                    ("length", Value::Integer(wrapper_length as i128)),
                ])]),
            ),
        ]));
        let region = enc(&vmap(vec![(
            "length",
            Value::Integer(carrier.len() as i128),
        )]));
        let manifest = ParsedManifest {
            label: "urn:test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("c2pa.hash.data".into(), primary.as_slice()),
                ("com.encypher.region".into(), region.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![
                hashed_uri_for_assertion("c2pa.hash.data"),
                hashed_uri_for_assertion("com.encypher.region"),
            ]),
        )]);
        let claim_refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let operative_binding = verify_data_hash(
            &claim,
            &claim_refs,
            &modified,
            AssetFormat::TextUnstructured,
            &[],
            update_manifest::StoreRendition::AsSigned,
            "urn:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(operative_binding.is_none());
        assert!(results.has_failure(ASSERTION_DATA_HASH_MISMATCH));
        assert!(!results.has_success(ASSERTION_DATA_HASH_MATCH));
    }

    #[test]
    fn claim_signature_uri_rejects_cross_manifest_and_deeper_targets() {
        let current = "urn:c2pa:00000000-0000-4000-8000-000000000001";
        assert!(claim_signature_uri_is_local(
            "self#jumbf=c2pa.signature",
            current
        ));
        assert!(claim_signature_uri_is_local(
            "self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000001/c2pa.signature",
            current
        ));
        assert!(!claim_signature_uri_is_local(
            "self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000002/c2pa.signature",
            current
        ));
        assert!(!claim_signature_uri_is_local(
            "self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000001/child/c2pa.signature",
            current
        ));
    }

    #[test]
    fn cross_manifest_signature_reference_reports_claim_signature_missing() {
        let current = "urn:c2pa:00000000-0000-4000-8000-000000000001";
        let primary = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
        ]));
        let claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
            ),
            (
                "signature",
                Value::Text(
                    "self#jumbf=/c2pa/urn:c2pa:00000000-0000-4000-8000-000000000002/c2pa.signature"
                        .into(),
                ),
            ),
        ]));
        let dummy_signature = [0xa0];
        let manifest = ParsedManifest {
            label: current.into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.hash.data".into(), primary.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim),
            signature_cose: Some(&dummy_signature),
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let hashes = std::collections::HashMap::new();
        let input = VerifyInput {
            data: b"asset",
            mime: "image/jpeg",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        let output = verify_manifest(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &input,
            AssetFormat::Jpeg,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        );
        assert!(output.results.has_failure(CLAIM_SIGNATURE_MISSING));
        assert!(!output.results.has_failure(CLAIM_SIGNATURE_MISMATCH));
    }

    #[test]
    fn ingredient_manifest_digests_are_cached_once_per_child_and_algorithm() {
        let child_bytes = b"child manifest content";
        let child = ParsedManifest {
            label: "urn:c2pa:child".into(),
            manifest_jumbf: child_bytes,
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: None,
        };
        let manifests = [child];
        let mut sha256_hashes = std::collections::HashMap::new();
        sha256_hashes.insert(
            "urn:c2pa:child".to_string(),
            ManifestDigests::expanded(sha(child_bytes)),
        );
        let mut cache = IngredientManifestDigestCache::new(StoreContext {
            manifests: &manifests,
            manifest_hashes: &sha256_hashes,
        });
        let sha384 = Sha384::digest(child_bytes).to_vec();
        let sha512 = Sha512::digest(child_bytes).to_vec();

        for _ in 0..2 {
            assert!(cache.matches(&manifests[0], 0, &sha(child_bytes)));
            assert!(cache.matches(&manifests[0], 1, &sha384));
            assert!(cache.matches(&manifests[0], 2, &sha512));
        }
        assert_eq!(cache.digests.len(), 2);
    }

    #[test]
    fn ingredient_semantic_hashing_is_deferred_until_signature_is_usable() {
        let primary = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
        ]));
        let ingredient = enc(&vmap(vec![(
            "activeManifest",
            ingredient_reference(
                "self#jumbf=/c2pa/urn:c2pa:missing-child".into(),
                vec![0; 32],
            ),
        )]));
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:test".into())),
            (
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.hash.data"),
                    hashed_uri_for_assertion("c2pa.ingredient.v3"),
                ]),
            ),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
        ]);
        let claim_cbor = enc(&claim);
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("c2pa.hash.data".into(), primary.as_slice()),
                ("c2pa.ingredient.v3".into(), ingredient.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim_cbor),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let hashes = std::collections::HashMap::new();
        let input = VerifyInput {
            data: b"asset",
            mime: "image/jpeg",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };
        let mut report_decode_nodes = MAX_REPORT_DECODED_VALUE_NODES;
        let output = verify_manifest(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &input,
            AssetFormat::Jpeg,
            &[],
            None,
            CawgTrustInputs::default(),
            &mut report_decode_nodes,
        );
        assert!(output.results.has_failure(CLAIM_SIGNATURE_MISSING));
        assert!(!output.results.has_failure(INGREDIENT_MANIFEST_MISSING));
        assert!(!output.results.has_failure(INGREDIENT_MANIFEST_MISMATCH));
        assert!(!output.results.has_success(INGREDIENT_MANIFEST_VALIDATED));
    }

    #[test]
    fn assertion_raw_work_is_preflighted_before_payload_decoding() {
        let half_plus_one = MAX_ASSERTION_HASH_WORK_BYTES / 2 + 1;
        assert!(checked_hash_work_total([half_plus_one, half_plus_one]).is_none());
    }
    #[test]
    fn assertion_value_nodes_share_one_claim_wide_budget() {
        let mut wide_payload = vec![0x99, 0x01, 0x00]; // definite array(256)
        wide_payload.extend(std::iter::repeat_n(0xf6, 256));
        let primary_payload = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
        ]));
        let mut labels = Vec::with_capacity(MAX_CLAIM_ASSERTION_REFERENCES);
        labels.push("c2pa.hash.data".to_string());
        labels.extend(
            (1..MAX_CLAIM_ASSERTION_REFERENCES).map(|index| format!("com.example.custom__{index}")),
        );
        let assertions = labels
            .iter()
            .map(|label| {
                let payload = if label == "c2pa.hash.data" {
                    primary_payload.as_slice()
                } else {
                    wide_payload.as_slice()
                };
                (label.clone(), payload)
            })
            .collect();
        let claim = vmap(vec![
            ("instanceID", Value::Text("xmp:iid:node-budget".into())),
            (
                "created_assertions",
                Value::Array(
                    labels
                        .iter()
                        .map(|label| hashed_uri_for_assertion(label))
                        .collect(),
                ),
            ),
        ]);
        let manifest = ParsedManifest {
            label: "urn:c2pa:node-budget".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [manifest];
        let claim_refs = ClaimAssertionRefs::build(&manifests[0], &claim, ClaimGeneration::V2);
        assert!(claim_refs.decode_budget_exhausted);
        assert_eq!(
            claim_refs.decoded_value_nodes,
            MAX_ASSERTION_DECODED_VALUE_NODES
        );
        assert!(
            claim_refs
                .assertions
                .values()
                .filter(|assertion| assertion.decoded.is_some())
                .count()
                < labels.len()
        );

        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();
        let fatal = verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            ClaimGeneration::V2,
            &claim_refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/urn:c2pa:node-budget/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(fatal);
        assert!(results.failure.iter().any(|status| {
            status.code == CLAIM_MALFORMED
                && status
                    .explanation
                    .contains("aggregate decoded assertion values")
        }));
    }

    #[test]
    fn store_wide_declared_sibling_status_survives_unrelated_malformed_reference() {
        let active_claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:active".into())),
            ("created_assertions", Value::Array(Vec::new())),
        ]));
        let sibling_claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:sibling".into())),
            (
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.certificate-status"),
                    vmap(vec![(
                        "url",
                        Value::Text("self#jumbf=c2pa.assertions/com.example.unrelated".into()),
                    )]),
                ]),
            ),
        ]));
        let status = enc(&vmap(vec![(
            "ocspVals",
            Value::Array(vec![Value::Bytes(b"sibling-revoked".to_vec())]),
        )]));
        let unrelated_malformed = [0xff];
        let active = ParsedManifest {
            label: "urn:c2pa:active".into(),
            manifest_jumbf: &[],
            assertions: Vec::new(),
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&active_claim),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let sibling = ParsedManifest {
            label: "urn:c2pa:sibling".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("c2pa.certificate-status".into(), status.as_slice()),
                (
                    "com.example.unrelated".into(),
                    unrelated_malformed.as_slice(),
                ),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&sibling_claim),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [active, sibling];
        let view = certificate_status_payloads(&manifests);
        assert!(!view.rejected);
        assert_eq!(view.payloads, vec![status.as_slice()]);

        let mut visited = Vec::new();
        let evidence =
            scan_embedded_ocsp_evidence(&cose_with_ocsp_values(&[]), &view.payloads, |response| {
                visited.push(response.to_vec())
            });
        assert!(!evidence.rejected);
        assert_eq!(visited, vec![b"sibling-revoked".to_vec()]);
    }

    #[test]
    fn store_wide_status_excludes_undeclared_and_cross_manifest_sources() {
        let empty_claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:empty".into())),
            ("created_assertions", Value::Array(Vec::new())),
        ]));
        let cross_claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:cross".into())),
            (
                "created_assertions",
                Value::Array(vec![vmap(vec![
                    (
                        "url",
                        Value::Text(
                            "self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/c2pa.certificate-status"
                                .into(),
                        ),
                    ),
                    ("alg", Value::Text("sha256".into())),
                    ("hash", Value::Bytes(vec![0; 32])),
                ])]),
            ),
        ]));
        let status = enc(&vmap(vec![("ocspVals", Value::Array(Vec::new()))]));
        let undeclared = ParsedManifest {
            label: "urn:c2pa:undeclared".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.certificate-status".into(), status.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&empty_claim),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let cross = ParsedManifest {
            label: "urn:c2pa:cross".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.certificate-status".into(), status.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&cross_claim),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests = [undeclared, cross];
        let view = certificate_status_payloads(&manifests);
        assert!(!view.rejected);
        assert!(view.payloads.is_empty());
    }

    #[test]
    fn store_wide_status_count_is_capped_before_payload_collection() {
        let labels: Vec<String> = (0..=MAX_CERTIFICATE_STATUS_ASSERTIONS)
            .map(|index| {
                if index == 0 {
                    "c2pa.certificate-status".into()
                } else {
                    format!("c2pa.certificate-status__{index}")
                }
            })
            .collect();
        let claim = enc(&vmap(vec![
            ("instanceID", Value::Text("xmp:iid:status-cap".into())),
            (
                "created_assertions",
                Value::Array(
                    labels
                        .iter()
                        .map(|label| hashed_uri_for_assertion(label))
                        .collect(),
                ),
            ),
        ]));
        let status = enc(&vmap(vec![("ocspVals", Value::Array(Vec::new()))]));
        let assertions = labels
            .iter()
            .map(|label| (label.clone(), status.as_slice()))
            .collect();
        let manifest = ParsedManifest {
            label: "urn:c2pa:status-cap".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: Some(&claim),
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let view = certificate_status_payloads(std::slice::from_ref(&manifest));
        assert!(view.rejected);
        assert!(view.payloads.is_empty());
    }
    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        const LOCAL: u32 = 0x0403_4b50;
        const CENTRAL: u32 = 0x0201_4b50;
        const EOCD: u32 = 0x0605_4b50;
        let mut body = Vec::new();
        let mut central = Vec::new();
        for &(name, content) in entries {
            let size = content.len() as u32;
            let local_offset = body.len() as u32;
            body.extend_from_slice(&LOCAL.to_le_bytes());
            body.extend_from_slice(&20u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&size.to_le_bytes());
            body.extend_from_slice(&size.to_le_bytes());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(content);

            central.extend_from_slice(&CENTRAL.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = body.len() as u32;
        let cd_size = central.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(&EOCD.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    #[test]
    fn collection_hash_allows_members_not_listed_in_uris() {
        let archive = stored_zip(&[
            ("listed.txt", b"signed member"),
            ("unlisted.txt", b"bound only by the central directory"),
        ]);
        let index = crate::c2pa_formats::zip_index(&archive).unwrap();
        let listed = index.get(b"listed.txt").unwrap();
        let (start, end) = listed.hash_span();
        let assertion = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            (
                "uris",
                Value::Array(vec![vmap(vec![
                    ("uri", Value::Text("listed.txt".into())),
                    ("hash", Value::Bytes(sha(&archive[start..end]))),
                ])]),
            ),
            (
                "zip_central_directory_hash",
                Value::Bytes(hash_parts("sha256", index.central_directory_hash_parts()).unwrap()),
            ),
        ]);
        let mut results = ValidationResults::default();
        verify_collection_hash(
            &enc(&assertion),
            &vmap(Vec::new()),
            &archive,
            false,
            "urn:test",
            &mut results,
        );

        assert!(results.has_success(ASSERTION_COLLECTION_HASH_MATCH));
        assert!(!results.has_failure(ASSERTION_COLLECTION_HASH_INCORRECT_FILE_COUNT));
    }

    fn remote_only_font(uri: &str) -> Vec<u8> {
        let mut table = Vec::new();
        table.extend_from_slice(&1u16.to_be_bytes());
        table.extend_from_slice(&0u16.to_be_bytes());
        table.extend_from_slice(&20u32.to_be_bytes());
        table.extend_from_slice(&(uri.len() as u16).to_be_bytes());
        table.extend_from_slice(&0u16.to_be_bytes());
        table.extend_from_slice(&0u32.to_be_bytes());
        table.extend_from_slice(&0u32.to_be_bytes());
        table.extend_from_slice(uri.as_bytes());

        let mut font = Vec::new();
        font.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        font.extend_from_slice(&1u16.to_be_bytes());
        font.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        font.extend_from_slice(b"C2PA");
        font.extend_from_slice(&0u32.to_be_bytes());
        font.extend_from_slice(&28u32.to_be_bytes());
        font.extend_from_slice(&(table.len() as u32).to_be_bytes());
        font.extend_from_slice(&table);
        font
    }

    #[test]
    fn remote_only_font_reports_manifest_inaccessible_without_fetching() {
        let font = remote_only_font("https://example.test/active.c2pa");
        let output = verify(&regular_input(&font, "font/ttf", SpecVersion::V2_4)).unwrap();
        assert!(output.results.has_failure(MANIFEST_INACCESSIBLE));
        assert!(output.results.failure.iter().any(|status| {
            status.code == MANIFEST_INACCESSIBLE && status.url == "https://example.test/active.c2pa"
        }));
    }

    /// An SVG carries its XMP inline, so the documented `dcterms:provenance`
    /// declaration of a remote manifest store sits in the asset itself.
    fn svg_with_provenance(uri: &str) -> Vec<u8> {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" \
             xmlns:dcterms=\"http://purl.org/dc/terms/\" \
             dcterms:provenance=\"{uri}\"><rect width=\"1\" height=\"1\"/></svg>"
        )
        .into_bytes()
    }

    #[test]
    fn a_declared_remote_manifest_records_the_fetch_that_would_settle_it() {
        let uri = "https://store.test/active.c2pa";
        let svg = svg_with_provenance(uri);
        let output = verify(&regular_input(&svg, "image/svg+xml", SpecVersion::V2_4)).unwrap();

        assert!(
            output
                .results
                .failure
                .iter()
                .any(|status| status.code == MANIFEST_INACCESSIBLE && status.url == uri),
            "{:?}",
            output.results.failure
        );
        assert_eq!(
            output
                .network_needs
                .iter()
                .map(NetworkNeed::to_json)
                .collect::<Vec<_>>(),
            vec![serde_json::json!({
                "kind": "remote_manifest",
                "uri": uri,
            })]
        );
    }

    /// The remote declaration is only consulted when no store is embedded, so
    /// an asset that carries its own store has nothing to fetch.
    #[test]
    fn an_embedded_store_leaves_the_remote_declaration_nothing_to_fetch() {
        let assertion = crate::c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:remote",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let svg = crate::c2pa_formats::embed_manifest(
            AssetFormat::Svg,
            &svg_with_provenance("https://store.test/active.c2pa"),
            &store,
        )
        .expect("embed");
        let output = verify(&regular_input(&svg, "image/svg+xml", SpecVersion::V2_4)).unwrap();

        assert!(!output.results.has_failure(MANIFEST_INACCESSIBLE));
        assert!(
            output.network_needs.is_empty(),
            "{:?}",
            output.network_needs
        );
    }

    #[test]
    fn carrier_placement_is_enforced_only_in_conformance_mode() {
        let mut gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b".to_vec();
        let assertion = crate::c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:placement",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
        gif = crate::c2pa_formats::embed_manifest(AssetFormat::Gif, &gif, &store).unwrap();
        let exclusion =
            crate::c2pa_formats::compute_data_hash_exclusions(AssetFormat::Gif, &gif).unwrap()[0];
        let extension = gif[exclusion.start..exclusion.start + exclusion.length].to_vec();
        gif.drain(exclusion.start..exclusion.start + exclusion.length);
        let trailer = gif.len() - 1;
        gif.splice(trailer..trailer, extension);

        let generous = verify(&regular_input(&gif, "image/gif", SpecVersion::V2_4)).unwrap();
        assert!(!generous.results.failure.iter().any(|status| {
            status.explanation
                == "GIF C2PA Application Extension follows the first image descriptor"
        }));

        let strict_input = VerifyInput {
            data: &gif,
            mime: "image/gif",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::strict(SpecVersion::V2_4),
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };
        let strict = verify(&strict_input).unwrap();
        assert!(strict.results.failure.iter().any(|status| {
            status.code == GENERAL_ERROR
                && status.explanation
                    == "GIF C2PA Application Extension follows the first image descriptor"
        }));
    }

    #[test]
    fn collection_uri_round_trips_reserved_docx_member_bytes() {
        let member = "[Content_Types].xml";
        let uri = canonical_collection_member_uri(member).expect("canonical URI");
        assert_eq!(uri, "%5BContent_Types%5D.xml");
        assert_eq!(
            canonical_collection_uri_member(&uri).as_deref(),
            Some(member),
        );
    }

    #[test]
    fn collection_uri_rejects_noncanonical_and_traversal_forms() {
        for uri in [
            "%5bContent_Types%5d.xml",
            "%2E%2E/word/document.xml",
            "%41.xml",
            "../word/document.xml",
            "https://example.test/document.xml",
        ] {
            assert!(canonical_collection_uri_member(uri).is_none(), "{uri}");
        }
    }

    fn raw_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&u32::try_from(8 + payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
        out
    }

    fn regular_input<'a>(data: &'a [u8], mime: &'a str, version: SpecVersion) -> VerifyInput<'a> {
        VerifyInput {
            data,
            mime,
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::new(version, OperatingMode::Regular),
            evidence: Default::default(),
            cawg_strict_encoding: false,
        }
    }

    #[test]
    fn strict_out_of_scope_status_uses_the_entity_namespace() {
        let output = verify(&VerifyInput {
            profile: EngineProfile::strict(SpecVersion::V2_2),
            ..regular_input(b"", "text/plain", SpecVersion::V2_2)
        })
        .expect("out-of-scope text must still produce a report");

        assert!(
            output
                .results
                .informational
                .iter()
                .any(|status| status.code == "com.encypher.conformance.outOfScope"),
            "{:?}",
            output.results.informational
        );
        assert!(
            output
                .results
                .informational
                .iter()
                .all(|status| !status.code.starts_with("conformanceScope.")),
            "{:?}",
            output.results.informational
        );
    }

    #[test]
    fn strict_spec_version_status_uses_the_entity_namespace() {
        const JPEG: &[u8] =
            include_bytes!("tests/fixtures/c2pa-rs-compressed/compressed_boxhash.jpg");
        let output = verify(&VerifyInput {
            profile: EngineProfile::strict(SpecVersion::V1_4),
            ..regular_input(JPEG, "image/jpeg", SpecVersion::V1_4)
        })
        .expect("v2 manifest must still produce a v1.4-targeted strict report");

        assert!(
            output.results.failure.iter().any(|status| {
                status.code == "com.encypher.conformance.specVersionNonConformant"
            }),
            "{:?}",
            output.results.failure
        );
        assert!(
            output
                .results
                .failure
                .iter()
                .all(|status| !status.code.starts_with("conformanceScope.")),
            "{:?}",
            output.results.failure
        );
    }

    /// A signer that no configured anchor accepts is `signingCredential.untrusted`
    /// under strict conformance even when no anchors are configured at all: an
    /// empty trust list contains nothing, and a silent report would read as
    /// trusted to a crJSON consumer. The default posture keeps "not evaluated".
    #[test]
    fn strict_reports_an_untrusted_signer_when_no_anchors_are_configured() {
        const JPEG: &[u8] =
            include_bytes!("tests/fixtures/c2pa-rs-compressed/compressed_boxhash.jpg");
        let generous =
            verify(&regular_input(JPEG, "image/jpeg", SpecVersion::V2_4)).expect("default report");
        assert!(!generous.results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED));
        assert!(!generous.results.has_success(SIGNING_CREDENTIAL_TRUSTED));

        let strict = verify(&VerifyInput {
            profile: EngineProfile::strict(SpecVersion::V2_4),
            ..regular_input(JPEG, "image/jpeg", SpecVersion::V2_4)
        })
        .expect("strict report");
        assert!(
            strict.results.has_failure(SIGNING_CREDENTIAL_UNTRUSTED),
            "{:?}",
            strict.results.failure
        );
    }

    #[test]
    fn c2pa_rs_compressed_vectors_verify_at_2_2_and_2_4() {
        const JPEG: &[u8] =
            include_bytes!("tests/fixtures/c2pa-rs-compressed/compressed_boxhash.jpg");
        const PNG: &[u8] =
            include_bytes!("tests/fixtures/c2pa-rs-compressed/compressed_boxhash.png");

        for (name, data, mime) in [("jpeg", JPEG, "image/jpeg"), ("png", PNG, "image/png")] {
            for version in [SpecVersion::V2_2, SpecVersion::V2_4] {
                let out = verify(&regular_input(data, mime, version))
                    .unwrap_or_else(|error| panic!("{name} at {version:?}: {error}"));
                assert_eq!(
                    out.validation_state,
                    ValidationState::Valid,
                    "{name} at {version:?}: {:?}",
                    out.results.failure
                );
                assert!(
                    out.results.has_success(CLAIM_SIGNATURE_VALIDATED),
                    "{name} at {version:?}: {:?}",
                    out.results.success
                );
                assert!(
                    out.results.has_success(ASSERTION_BOXES_HASH_MATCH),
                    "{name} at {version:?}: {:?}",
                    out.results.success
                );
            }
        }
    }

    #[test]
    fn private_compressed_epub_fixture_verifies() {
        const EPUB: &[u8] =
            include_bytes!("tests/fixtures/compressed-epub/application_epub_zip.epub");
        let out = verify(&regular_input(
            EPUB,
            "application/epub+zip",
            SpecVersion::V2_4,
        ))
        .expect("compressed EPUB must produce a report");

        assert_eq!(
            out.validation_state,
            ValidationState::Valid,
            "{:?}",
            out.results.failure
        );
        assert!(!out.results.has_failure("manifest.compressed.invalid"));
    }

    #[test]
    fn corrupt_compressed_manifest_is_a_report_failure_not_an_api_error() {
        let corrupt = superbox(
            &UUID_COMPRESSED_MANIFEST,
            "urn:c2pa:corrupt",
            &[raw_box(b"brob", b"not brotli")],
            None,
        );
        let store = build_manifest_store(&[corrupt]);
        let out = verify(&regular_input(
            &store,
            "application/c2pa",
            SpecVersion::V2_4,
        ))
        .expect("asset-supplied corrupt compression must produce a report");

        assert_eq!(out.validation_state, ValidationState::Invalid);
        let status = out
            .results
            .failure
            .iter()
            .find(|status| status.code == "manifest.compressed.invalid")
            .expect("compressed status");
        assert_eq!(status.url, "self#jumbf=/c2pa/urn:c2pa:corrupt");
    }

    #[test]
    fn malformed_jumbf_is_general_error_not_an_api_error() {
        let out = verify(&regular_input(
            b"malformed store bytes",
            "application/c2pa",
            SpecVersion::V2_4,
        ))
        .expect("asset-supplied malformed framing must produce a report");

        assert_eq!(out.validation_state, ValidationState::Invalid);
        assert!(out.results.has_failure("general.error"));
    }

    #[test]
    fn malformed_json_assertion_emits_registered_status() {
        let assertion = superbox(
            &UUID_JSON_CONTENT,
            "c2pa.metadata",
            &[raw_box(b"json", br#"{"broken":"#)],
            None,
        );
        let assertion_content = superbox_content(&assertion).unwrap();
        let claim = enc(&vmap(vec![
            ("instanceID", Value::Text("urn:uuid:json".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            (
                "claim_generator_info",
                vmap(vec![
                    ("name", Value::Text("test".into())),
                    ("specVersion", Value::Text("2.4.0".into())),
                ]),
            ),
            (
                "created_assertions",
                Value::Array(vec![vmap(vec![
                    (
                        "url",
                        Value::Text("self#jumbf=c2pa.assertions/c2pa.metadata".into()),
                    ),
                    ("alg", Value::Text("sha256".into())),
                    ("hash", Value::Bytes(sha(assertion_content))),
                ])]),
            ),
        ]));
        let manifest = build_manifest("urn:c2pa:json", &[assertion], &claim, &[0xd2, 0x84]);
        let store = build_manifest_store(&[manifest]);
        let parsed = parse_manifest_store(&store).unwrap();
        let manifest = &parsed.manifests[0];
        let claim = decode(manifest.claim_cbor.unwrap()).unwrap();
        let refs = ClaimAssertionRefs::build(manifest, &claim, ClaimGeneration::V2);
        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();

        verify_claim_structure(
            manifest,
            StoreContext {
                manifests: &parsed.manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            ClaimGeneration::V2,
            &refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/urn:c2pa:json/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(results.has_failure("assertion.json.invalid"));
        assert!(!results.has_failure(ASSERTION_CBOR_INVALID));
    }

    #[test]
    fn standard_manifest_with_two_parent_ingredients_emits_multiple_parents() {
        let parent = |label: &str| {
            (
                label.to_string(),
                enc(&vmap(vec![(
                    "relationship",
                    Value::Text("parentOf".into()),
                )])),
            )
        };
        let owned = [
            parent("c2pa.ingredient.v3"),
            parent("c2pa.ingredient.v3__1"),
        ];
        let manifest = ParsedManifest {
            label: "urn:c2pa:parents".into(),
            manifest_jumbf: &[],
            assertions: owned
                .iter()
                .map(|(label, payload)| (label.clone(), payload.as_slice()))
                .collect(),
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![
            ("instanceID", Value::Text("urn:uuid:parents".into())),
            ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
            (
                "claim_generator_info",
                vmap(vec![
                    ("name", Value::Text("test".into())),
                    ("specVersion", Value::Text("2.4.0".into())),
                ]),
            ),
            (
                "created_assertions",
                Value::Array(
                    owned
                        .iter()
                        .map(|(label, _)| hashed_uri_for_assertion(label))
                        .collect(),
                ),
            ),
        ]);
        let manifests = [manifest];
        let refs = ClaimAssertionRefs::build(&manifests[0], &claim, ClaimGeneration::V2);
        let hashes = std::collections::HashMap::new();
        let mut results = ValidationResults::default();

        verify_claim_structure(
            &manifests[0],
            StoreContext {
                manifests: &manifests,
                manifest_hashes: &hashes,
            },
            &claim,
            ClaimGeneration::V2,
            &refs,
            AssetFormat::Jpeg,
            "self#jumbf=/c2pa/urn:c2pa:parents/c2pa.signature",
            EngineProfile::GENEROUS,
            &mut results,
        );

        assert!(results.has_failure("manifest.multipleParents"));
    }
    #[test]
    fn non_semver_spec_version_is_advisory_by_default_and_fails_strict() {
        let claim = vmap(vec![(
            "claim_generator_info",
            vmap(vec![
                ("name", Value::Text("legacy generator".into())),
                ("specVersion", Value::Text("2.4".into())),
            ]),
        )]);
        let url = "self#jumbf=/c2pa/test/c2pa.signature";

        let mut generous = ValidationResults::default();
        assert!(!verify_spec_version_metadata(
            &claim,
            EngineProfile::GENEROUS,
            url,
            &mut generous,
        ));
        assert!(generous
            .informational
            .iter()
            .any(|status| status.code == CLAIM_SPEC_VERSION_NOT_SEMVER));
        assert!(!generous.has_failure(CLAIM_MALFORMED));

        let mut strict = ValidationResults::default();
        assert!(verify_spec_version_metadata(
            &claim,
            EngineProfile::strict(SpecVersion::V2_4),
            url,
            &mut strict,
        ));
        assert!(strict.has_failure(CLAIM_MALFORMED));
    }

    /// C2PA 2.4 Validation, Standard Manifest Assertions: "Validate that either
    /// a `c2pa.created` or `c2pa.opened` action is contained in exactly one
    /// actions assertion." That is a validator rule, so a v2 standard manifest
    /// without one fails in the default posture. `c2pa.actions` validation
    /// allows that assertion to be the first one of either the
    /// `created_assertions` or the `gathered_assertions` array. Update
    /// manifests are exempt: the requirement is stated for standard manifests
    /// only, and C2PA 2.4 Manifests, Update Manifests, lets an update carry
    /// just `c2pa.edited.metadata`. v1 claims keep the strict-only policy.
    #[test]
    fn inception_action_is_required_of_standard_manifests_only() {
        // Every fixture here declares its single actions assertion in the
        // gathered array (in the v1 claim's `assertions` array), never in
        // `created_assertions`.
        let gathered_only =
            |only_action: &str, generation: ClaimGeneration, kind: ManifestKind, profile| {
                let label = if generation == ClaimGeneration::V1 {
                    "c2pa.actions"
                } else {
                    "c2pa.actions.v2"
                };
                let actions = enc(&vmap(vec![(
                    "actions",
                    Value::Array(vec![vmap(vec![(
                        "action",
                        Value::Text(only_action.into()),
                    )])]),
                )]));
                let manifest = ParsedManifest {
                    label: "urn:c2pa:00000000-0000-4000-8000-000000000001".into(),
                    manifest_jumbf: &[],
                    assertions: vec![(label.into(), actions.as_slice())],
                    assertion_jumbf: Vec::new(),
                    claim_cbor: None,
                    signature_cose: None,
                    claim_count: 1,
                    claim_box_label: Some("c2pa.claim.v2".into()),
                };
                let field = if generation == ClaimGeneration::V1 {
                    "assertions"
                } else {
                    "gathered_assertions"
                };
                let claim = vmap(vec![(
                    field,
                    Value::Array(vec![hashed_uri_for_assertion(label)]),
                )]);
                let refs = ClaimAssertionRefs::build(&manifest, &claim, generation);
                let mut results = ValidationResults::default();
                verify_action_assertions(
                    &refs,
                    &claim,
                    generation,
                    kind,
                    StoreContext {
                        manifests: std::slice::from_ref(&manifest),
                        manifest_hashes: &std::collections::HashMap::new(),
                    },
                    &manifest.label,
                    "self#jumbf=/c2pa/test/c2pa.signature",
                    profile,
                    &mut results,
                );
                results.has_failure(ASSERTION_ACTION_MALFORMED)
            };
        let strict = EngineProfile::strict(SpecVersion::V2_4);

        assert!(gathered_only(
            "c2pa.edited.metadata",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::GENEROUS
        ));
        // An inception action in the first gathered actions assertion satisfies
        // the requirement even with no `created_assertions` actions assertion.
        assert!(!gathered_only(
            "c2pa.opened",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::GENEROUS
        ));
        assert!(!gathered_only(
            "c2pa.edited.metadata",
            ClaimGeneration::V2,
            ManifestKind::Update,
            EngineProfile::GENEROUS
        ));
        assert!(!gathered_only(
            "c2pa.edited.metadata",
            ClaimGeneration::V2,
            ManifestKind::Update,
            strict
        ));
        assert!(!gathered_only(
            "c2pa.edited.metadata",
            ClaimGeneration::V1,
            ManifestKind::Standard,
            EngineProfile::GENEROUS
        ));
        assert!(gathered_only(
            "c2pa.edited.metadata",
            ClaimGeneration::V1,
            ManifestKind::Standard,
            strict
        ));
    }

    /// Build a v2 standard manifest carrying the given actions assertions and
    /// extra declared assertion labels, then run the action validator over it.
    fn run_actions(
        assertions: &[(&str, Vec<Value>)],
        extra_labels: &[&str],
        generation: ClaimGeneration,
        profile: EngineProfile,
    ) -> ValidationResults {
        const LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-0000000000ac";
        let payload = enc(&vmap(vec![("data", Value::Bytes(vec![1]))]));
        let encoded: Vec<(String, Vec<u8>)> = assertions
            .iter()
            .map(|(label, actions)| {
                (
                    (*label).to_string(),
                    enc(&vmap(vec![("actions", Value::Array(actions.clone()))])),
                )
            })
            .collect();
        let mut stored: Vec<(String, &[u8])> = encoded
            .iter()
            .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
            .collect();
        stored.extend(
            extra_labels
                .iter()
                .map(|label| ((*label).to_string(), payload.as_slice())),
        );
        let manifest = ParsedManifest {
            label: LABEL.into(),
            manifest_jumbf: &[],
            assertions: stored,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let field = if generation == ClaimGeneration::V1 {
            "assertions"
        } else {
            "created_assertions"
        };
        let claim = vmap(vec![(
            field,
            Value::Array(
                assertions
                    .iter()
                    .map(|(label, _)| *label)
                    .chain(extra_labels.iter().copied())
                    .map(hashed_uri_for_assertion)
                    .collect(),
            ),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, generation);
        let mut results = ValidationResults::default();
        verify_action_assertions(
            &refs,
            &claim,
            generation,
            ManifestKind::Standard,
            StoreContext {
                manifests: std::slice::from_ref(&manifest),
                manifest_hashes: &std::collections::HashMap::new(),
            },
            &manifest.label,
            "self#jumbf=/c2pa/test/c2pa.signature",
            profile,
            &mut results,
        );
        results
    }

    fn action(kind: &str) -> Value {
        vmap(vec![("action", Value::Text(kind.into()))])
    }

    /// C2PA 2.4 Validation, `c2pa.actions` validation: a `c2pa.created` or
    /// `c2pa.opened` action is `assertion.action.malformed` "unless" its
    /// assertion is the first actions assertion of the claim's array and the
    /// action is the first element of that assertion's `actions` array. That is
    /// a validator step, so it holds in the default posture for v2 claims; v1
    /// claims keep the strict-only policy.
    #[test]
    fn misplaced_inception_actions_are_malformed_in_the_default_posture() {
        let created = || {
            vmap(vec![
                ("action", Value::Text("c2pa.created".into())),
                (
                    "digitalSourceType",
                    Value::Text(
                        "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into(),
                    ),
                ),
            ])
        };
        let malformed = |assertions: &[(&str, Vec<Value>)], generation, profile| {
            run_actions(assertions, &[], generation, profile)
                .has_failure(ASSERTION_ACTION_MALFORMED)
        };
        let default = EngineProfile::GENEROUS;

        // Well-formed: one inception action, first element of the only assertion.
        assert!(!malformed(
            &[("c2pa.actions.v2", vec![created(), action("c2pa.edited")])],
            ClaimGeneration::V2,
            default
        ));
        // Not the first element of its assertion.
        assert!(malformed(
            &[("c2pa.actions.v2", vec![action("c2pa.edited"), created()])],
            ClaimGeneration::V2,
            default
        ));
        // Not the first actions assertion of the array.
        assert!(malformed(
            &[
                ("c2pa.actions.v2", vec![created()]),
                ("c2pa.actions.v2__1", vec![action("c2pa.opened")]),
            ],
            ClaimGeneration::V2,
            default
        ));
        // v1 keeps the existing policy: strict conformance only.
        let v1 = [("c2pa.actions", vec![action("c2pa.edited"), created()])];
        assert!(!malformed(&v1, ClaimGeneration::V1, default));
        assert!(malformed(
            &v1,
            ClaimGeneration::V1,
            EngineProfile::strict(SpecVersion::V2_4)
        ));
    }

    /// C2PA 2.4 Validation, `c2pa.actions` validation: for `c2pa.watermarked`
    /// (deprecated) or `c2pa.watermarked.bound`, "Verify that there is also a
    /// `c2pa.soft-binding` assertion present in the manifest. If there is not,
    /// the claim shall be rejected with a failure code of
    /// `assertion.action.softBindingMissing`."
    #[test]
    fn watermark_actions_require_a_soft_binding_assertion() {
        let missing = |kind: &str, extra_labels: &[&str]| {
            run_actions(
                &[(
                    "c2pa.actions.v2",
                    vec![action("c2pa.created"), action(kind)],
                )],
                extra_labels,
                ClaimGeneration::V2,
                EngineProfile::GENEROUS,
            )
            .has_failure(ASSERTION_ACTION_SOFT_BINDING_MISSING)
        };

        assert!(missing("c2pa.watermarked.bound", &[]));
        assert!(missing("c2pa.watermarked", &[]));
        assert!(!missing("c2pa.watermarked.bound", &["c2pa.soft-binding"]));
        assert!(!missing("c2pa.watermarked", &["c2pa.soft-binding__1"]));
        assert!(!missing("c2pa.edited", &[]));
        // Only a `c2pa.soft-binding` assertion satisfies the requirement.
        assert!(missing("c2pa.watermarked.bound", &["c2pa.thumbnail.claim"]));
    }

    /// C2PA 2.4 Validation, Validate the Assertions: an assertion present in
    /// the assertion store but not referenced by an element of the claim's
    /// `created_assertions`/`gathered_assertions` (or v1 `assertions`) "shall be
    /// rejected with a failure code of `assertion.undeclared`". A
    /// `claim_generator_info` icon reaches an assertion; it does not declare it.
    #[test]
    fn an_assertion_reachable_only_through_the_generator_icon_is_undeclared() {
        let icon_jumbf = b"embedded c2pa.icon assertion jumbf";

        let (fatal, icon_only) = run_generator_icon_binding(
            ClaimGeneration::V2,
            "c2pa.icon",
            sha(icon_jumbf),
            Some(icon_jumbf),
            false,
        );
        assert!(fatal);
        assert!(
            icon_only
                .failure
                .iter()
                .any(|status| status.code == ASSERTION_UNDECLARED
                    && status.url.ends_with("c2pa.icon"))
        );

        let (fatal, declared) = run_generator_icon_binding(
            ClaimGeneration::V2,
            "c2pa.icon",
            sha(icon_jumbf),
            Some(icon_jumbf),
            true,
        );
        assert!(!fatal);
        assert!(!declared.has_failure(ASSERTION_UNDECLARED));
        assert!(declared.has_success(ASSERTION_HASHED_URI_MATCH));
    }

    /// C2PA 2.4 Validation, Specific Assertion Validation, selects an
    /// assertion's checks from its label. A known label delivered in a JSON
    /// JUMBF content box owes the same checks as the CBOR spelling, so the
    /// payload is projected into one value model instead of being skipped.
    #[test]
    fn json_content_assertions_of_known_labels_are_semantically_validated() {
        let run = |label: &str, json: &[u8]| {
            let assertion = superbox(&UUID_JSON_CONTENT, label, &[raw_box(b"json", json)], None);
            let assertion_content = superbox_content(&assertion).unwrap();
            let claim = enc(&vmap(vec![
                ("instanceID", Value::Text("urn:uuid:json-semantics".into())),
                ("signature", Value::Text("self#jumbf=c2pa.signature".into())),
                (
                    "claim_generator_info",
                    vmap(vec![
                        ("name", Value::Text("test".into())),
                        ("specVersion", Value::Text("2.4.0".into())),
                    ]),
                ),
                (
                    "created_assertions",
                    Value::Array(vec![vmap(vec![
                        (
                            "url",
                            Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                        ),
                        ("alg", Value::Text("sha256".into())),
                        ("hash", Value::Bytes(sha(assertion_content))),
                    ])]),
                ),
            ]));
            let store = build_manifest_store(&[build_manifest(
                "urn:c2pa:json-semantics",
                &[assertion.clone()],
                &claim,
                &[0xd2, 0x84],
            )]);
            let parsed = parse_manifest_store(&store).unwrap();
            let manifest = &parsed.manifests[0];
            let claim = decode(manifest.claim_cbor.unwrap()).unwrap();
            let refs = ClaimAssertionRefs::build(manifest, &claim, ClaimGeneration::V2);
            let hashes = std::collections::HashMap::new();
            let mut results = ValidationResults::default();
            verify_claim_structure(
                manifest,
                StoreContext {
                    manifests: &parsed.manifests,
                    manifest_hashes: &hashes,
                },
                &claim,
                ClaimGeneration::V2,
                &refs,
                AssetFormat::Jpeg,
                "self#jumbf=/c2pa/urn:c2pa:json-semantics/c2pa.signature",
                EngineProfile::GENEROUS,
                &mut results,
            );
            results
        };

        // An ingredient with no `relationship` is `assertion.ingredient.malformed`
        // whichever content type carried it.
        let empty_ingredient = run("c2pa.ingredient.v3", b"{}");
        assert!(empty_ingredient.has_failure(ASSERTION_INGREDIENT_MALFORMED));
        assert!(!empty_ingredient.has_failure(ASSERTION_JSON_INVALID));
        assert!(
            !run("c2pa.ingredient.v3", br#"{"relationship":"parentOf"}"#)
                .has_failure(ASSERTION_INGREDIENT_MALFORMED)
        );

        // An actions assertion with no `actions` field is
        // `assertion.action.malformed`, and its actions are otherwise checked.
        assert!(run("c2pa.actions.v2", b"{}").has_failure(ASSERTION_ACTION_MALFORMED));
        assert!(run(
            "c2pa.actions.v2",
            br#"{"actions":[{"action":"c2pa.created"},{"action":"c2pa.watermarked.bound"}]}"#
        )
        .has_failure(ASSERTION_ACTION_SOFT_BINDING_MISSING));
    }

    /// C2PA 2.4 `c2pa.actions` validation: `c2pa.opened` resolves exactly one
    /// parentOf ingredient in this manifest, `c2pa.placed` componentOf
    /// ingredients in this manifest, `c2pa.removed` componentOf ingredients in
    /// another manifest, and `c2pa.transcoded`/`c2pa.repackaged` optional
    /// parentOf ingredients.
    #[test]
    fn action_ingredient_references_follow_the_relationship_each_action_requires() {
        const CURRENT: &str = "urn:c2pa:00000000-0000-4000-8000-00000000000c";
        const PRIOR: &str = "urn:c2pa:00000000-0000-4000-8000-00000000000p";
        let ingredient = |relationship: &str| {
            enc(&vmap(vec![(
                "relationship",
                Value::Text(relationship.into()),
            )]))
        };
        let component = ingredient("componentOf");
        let parent = ingredient("parentOf");
        let prior_component = ingredient("componentOf");
        let (component_box, parent_box, prior_box) = (
            b"component ingredient box".as_slice(),
            b"parent ingredient box".as_slice(),
            b"prior component ingredient box".as_slice(),
        );
        let href = |manifest: &str, label: &str, jumbf: &[u8]| {
            vmap(vec![
                (
                    "url",
                    Value::Text(format!(
                        "self#jumbf=/c2pa/{manifest}/c2pa.assertions/{label}"
                    )),
                ),
                ("alg", Value::Text("sha256".into())),
                ("hash", Value::Bytes(sha(jumbf))),
            ])
        };
        let component_ref = href(CURRENT, "c2pa.ingredient.v3", component_box);
        let parent_ref = href(CURRENT, "c2pa.ingredient.v3__1", parent_box);
        let prior_ref = href(PRIOR, "c2pa.ingredient.v3", prior_box);

        let prior = || ParsedManifest {
            label: PRIOR.into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.ingredient.v3".into(), prior_component.as_slice())],
            assertion_jumbf: vec![("c2pa.ingredient.v3".into(), prior_box)],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let mismatch = |action: Value| {
            let actions = enc(&vmap(vec![("actions", Value::Array(vec![action]))]));
            let manifest = ParsedManifest {
                label: CURRENT.into(),
                manifest_jumbf: &[],
                assertions: vec![
                    ("c2pa.ingredient.v3".into(), component.as_slice()),
                    ("c2pa.ingredient.v3__1".into(), parent.as_slice()),
                    ("c2pa.actions.v2".into(), actions.as_slice()),
                ],
                assertion_jumbf: vec![
                    ("c2pa.ingredient.v3".into(), component_box),
                    ("c2pa.ingredient.v3__1".into(), parent_box),
                ],
                claim_cbor: None,
                signature_cose: None,
                claim_count: 1,
                claim_box_label: Some("c2pa.claim.v2".into()),
            };
            let claim = vmap(vec![(
                "created_assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.ingredient.v3"),
                    hashed_uri_for_assertion("c2pa.ingredient.v3__1"),
                    hashed_uri_for_assertion("c2pa.actions.v2"),
                ]),
            )]);
            let manifests = [prior(), manifest];
            let refs = ClaimAssertionRefs::build(&manifests[1], &claim, ClaimGeneration::V2);
            let hashes = std::collections::HashMap::new();
            let mut results = ValidationResults::default();
            verify_action_assertions(
                &refs,
                &claim,
                ClaimGeneration::V2,
                ManifestKind::Standard,
                StoreContext {
                    manifests: &manifests,
                    manifest_hashes: &hashes,
                },
                CURRENT,
                "self#jumbf=/c2pa/test/c2pa.signature",
                EngineProfile::GENEROUS,
                &mut results,
            );
            results.has_failure(ASSERTION_ACTION_INGREDIENT_MISMATCH)
        };
        let action = |kind: &str, ingredients: Option<Vec<Value>>| {
            let mut fields = vec![("action", Value::Text(kind.into()))];
            if let Some(ingredients) = ingredients {
                fields.push((
                    "parameters",
                    vmap(vec![("ingredients", Value::Array(ingredients))]),
                ));
            }
            vmap(fields)
        };

        assert!(!mismatch(action(
            "c2pa.opened",
            Some(vec![parent_ref.clone()])
        )));
        assert!(mismatch(action(
            "c2pa.opened",
            Some(vec![component_ref.clone()])
        )));
        assert!(mismatch(action("c2pa.opened", None)));
        assert!(!mismatch(action(
            "c2pa.placed",
            Some(vec![component_ref.clone()])
        )));
        assert!(mismatch(action(
            "c2pa.placed",
            Some(vec![parent_ref.clone()])
        )));
        assert!(mismatch(action("c2pa.placed", Some(Vec::new()))));
        assert!(!mismatch(action(
            "c2pa.removed",
            Some(vec![prior_ref.clone()])
        )));
        assert!(mismatch(action(
            "c2pa.removed",
            Some(vec![component_ref.clone()])
        )));
        assert!(mismatch(action("c2pa.removed", None)));
        assert!(!mismatch(action("c2pa.transcoded", None)));
        assert!(!mismatch(action("c2pa.repackaged", Some(vec![parent_ref]))));
        assert!(mismatch(action(
            "c2pa.transcoded",
            Some(vec![component_ref])
        )));

        let mut tampered = prior_ref;
        if let Value::Map(fields) = &mut tampered {
            for (key, value) in fields.iter_mut() {
                if key.as_text() == Some("hash") {
                    *value = Value::Bytes(vec![0; 32]);
                }
            }
        }
        assert!(mismatch(action("c2pa.removed", Some(vec![tampered]))));
    }
    /// v1 claims are held to the ingredient-reference rules only under strict
    /// conformance, and a v1 `c2pa.actions` assertion may spell the field
    /// `ingredients` (as c2pa-rs writes it) as long as it resolves.
    #[test]
    fn v1_action_ingredient_rules_are_strict_only_and_accept_either_spelling() {
        const LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-0000000000v1";
        let parent = enc(&vmap(vec![(
            "relationship",
            Value::Text("parentOf".into()),
        )]));
        let parent_box = b"v1 parent ingredient box".as_slice();
        let parent_ref = vmap(vec![
            (
                "url",
                Value::Text("self#jumbf=c2pa.assertions/c2pa.ingredient".into()),
            ),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(sha(parent_box))),
        ]);
        let mismatch = |parameters: Option<Value>, profile: EngineProfile| {
            let mut opened = vec![("action", Value::Text("c2pa.opened".into()))];
            if let Some(parameters) = parameters {
                opened.push(("parameters", parameters));
            }
            let actions = enc(&vmap(vec![("actions", Value::Array(vec![vmap(opened)]))]));
            let manifests = [ParsedManifest {
                label: LABEL.into(),
                manifest_jumbf: &[],
                assertions: vec![
                    ("c2pa.ingredient".into(), parent.as_slice()),
                    ("c2pa.actions".into(), actions.as_slice()),
                ],
                assertion_jumbf: vec![("c2pa.ingredient".into(), parent_box)],
                claim_cbor: None,
                signature_cose: None,
                claim_count: 1,
                claim_box_label: Some("c2pa.claim".into()),
            }];
            let claim = vmap(vec![(
                "assertions",
                Value::Array(vec![
                    hashed_uri_for_assertion("c2pa.ingredient"),
                    hashed_uri_for_assertion("c2pa.actions"),
                ]),
            )]);
            let refs = ClaimAssertionRefs::build(&manifests[0], &claim, ClaimGeneration::V1);
            let hashes = std::collections::HashMap::new();
            let mut results = ValidationResults::default();
            verify_action_assertions(
                &refs,
                &claim,
                ClaimGeneration::V1,
                ManifestKind::Standard,
                StoreContext {
                    manifests: &manifests,
                    manifest_hashes: &hashes,
                },
                LABEL,
                "self#jumbf=/c2pa/test/c2pa.signature",
                profile,
                &mut results,
            );
            results.has_failure(ASSERTION_ACTION_INGREDIENT_MISMATCH)
        };
        let strict = EngineProfile::strict(SpecVersion::V2_4);

        assert!(!mismatch(None, EngineProfile::GENEROUS));
        assert!(mismatch(None, strict));
        assert!(!mismatch(
            Some(vmap(vec![("ingredient", parent_ref.clone())])),
            strict
        ));
        assert!(!mismatch(
            Some(vmap(vec![("ingredients", Value::Array(vec![parent_ref]))])),
            strict
        ));
    }

    fn data_hash_exclusion_result(exclusions: Value, data_len: usize) -> ValidationResults {
        let hash_data = vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![0; 32])),
            ("exclusions", exclusions),
        ]);
        let cbor = enc(&hash_data);
        let manifest = ParsedManifest {
            label: "urn:c2pa:test".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.hash.data".into(), cbor.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        let data = vec![0; data_len];
        verify_primary_hard_binding(
            &claim,
            &refs,
            &data,
            AssetFormat::Jpeg,
            &[],
            update_manifest::StoreRendition::AsSigned,
            &manifest.label,
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    #[test]
    fn malformed_data_exclusions_emit_validation_statuses() {
        let malformed = data_hash_exclusion_result(
            Value::Array(vec![vmap(vec![
                ("start", Value::Integer((-1).into())),
                ("length", Value::Integer(1.into())),
            ])]),
            10,
        );
        assert!(malformed.has_failure(ASSERTION_DATA_HASH_MALFORMED));

        let outside = data_hash_exclusion_result(
            Value::Array(vec![vmap(vec![
                ("start", Value::Integer(9.into())),
                ("length", Value::Integer(2.into())),
            ])]),
            10,
        );
        assert!(outside.has_failure(ASSERTION_DATA_HASH_MISMATCH));
    }

    #[test]
    fn box_entry_exclusions_and_font_normalization_are_hashed_exactly() {
        let data: Vec<u8> = (0..20).collect();
        let spans = vec![
            crate::c2pa_formats::BoxSpan::contiguous("A", 0, 5),
            crate::c2pa_formats::BoxSpan::contiguous("B", 10, 20),
        ];
        let exclusions = [exclusions::BoxExclusion {
            box_index: 1,
            start: 2,
            length: 3,
        }];
        let mut expected = data[..12].to_vec();
        expected.extend_from_slice(&data[15..]);
        assert_eq!(
            hash_box_entry("sha256", &data, &spans, &exclusions, AssetFormat::Jpeg),
            hash_bytes("sha256", &expected)
        );

        let head = [9u8; 16];
        let head_span = [crate::c2pa_formats::BoxSpan::contiguous(
            "head",
            0,
            head.len(),
        )];
        let mut normalized = head;
        normalized[8..12].fill(0);
        assert_eq!(
            hash_box_entry("sha256", &head, &head_span, &[], AssetFormat::Font),
            hash_bytes("sha256", &normalized)
        );
    }

    /// A general box hash over a container the spec gives no box convention
    /// for is the claim's only hard binding and cannot be evaluated, so the
    /// verifier must fail closed rather than leave the manifest valid with no
    /// content binding checked.
    #[test]
    fn boxes_hash_without_segmentation_fails_closed() {
        let cbor = enc(&vmap(vec![("boxes", Value::Array(Vec::new()))]));
        let mut results = ValidationResults::default();
        verify_boxes_hash(
            &cbor,
            &vmap(Vec::new()),
            AssetFormat::C2paStore,
            &[],
            false,
            "urn:c2pa:test",
            EngineProfile::GENEROUS,
            &mut results,
        );
        assert!(results.has_failure(ASSERTION_BOXES_HASH_UNEVALUATED));
        assert!(!results.has_success(ASSERTION_BOXES_HASH_MATCH));
        assert_eq!(
            compute_state(&results, EngineProfile::GENEROUS),
            ValidationState::Invalid,
        );
    }

    /// An Ogg logical bitstream is one box even when its pages interleave with
    /// another stream's, so the entry hashes that stream's pages and nothing
    /// in between.
    #[test]
    fn scattered_box_entries_hash_only_their_own_ranges() {
        let data: Vec<u8> = (0..40).collect();
        let spans = [crate::c2pa_formats::BoxSpan::scattered(
            "Stream-1",
            vec![(0, 10), (20, 30)],
        )];
        let mut expected = data[..10].to_vec();
        expected.extend_from_slice(&data[20..30]);
        assert_eq!(
            hash_box_entry("sha256", &data, &spans, &[], AssetFormat::Ogg),
            hash_bytes("sha256", &expected)
        );

        // An exclusion offset is measured within the box's own content, so
        // bytes 8..12 of the box span the seam between its two ranges.
        let exclusions = [exclusions::BoxExclusion {
            box_index: 0,
            start: 8,
            length: 4,
        }];
        let mut expected = data[..8].to_vec();
        expected.extend_from_slice(&data[22..30]);
        assert_eq!(
            hash_box_entry("sha256", &data, &spans, &exclusions, AssetFormat::Ogg),
            hash_bytes("sha256", &expected)
        );
    }

    #[test]
    fn sha1_box_and_collection_hashes_are_rejected_before_hashing() {
        let boxes = enc(&vmap(vec![(
            "boxes",
            Value::Array(vec![vmap(vec![
                ("names", Value::Array(vec![Value::Text("C2PA".into())])),
                ("alg", Value::Text("sha1".into())),
                ("hash", Value::Bytes(vec![0; 20])),
            ])]),
        )]));
        let mut box_results = ValidationResults::default();
        verify_boxes_hash(
            &boxes,
            &vmap(Vec::new()),
            AssetFormat::C2paStore,
            &[],
            false,
            "urn:c2pa:test",
            EngineProfile::GENEROUS,
            &mut box_results,
        );
        assert!(box_results.has_failure(ALGORITHM_UNSUPPORTED));
        assert!(!box_results.has_success(ASSERTION_BOXES_HASH_MATCH));

        let collection = enc(&vmap(vec![
            ("uris", Value::Array(Vec::new())),
            ("alg", Value::Text("sha1".into())),
            ("zip_central_directory_hash", Value::Bytes(vec![0; 20])),
        ]));
        let mut collection_results = ValidationResults::default();
        verify_collection_hash(
            &collection,
            &vmap(Vec::new()),
            &[],
            false,
            "urn:c2pa:test",
            &mut collection_results,
        );
        assert!(collection_results.has_failure(ALGORITHM_UNSUPPORTED));
        assert!(!collection_results.has_failure(ASSERTION_COLLECTION_HASH_MISMATCH));
        assert!(!collection_results.has_success(ASSERTION_COLLECTION_HASH_MATCH));

        let missing_algorithm = enc(&vmap(vec![
            ("uris", Value::Array(Vec::new())),
            ("zip_central_directory_hash", Value::Bytes(vec![0; 32])),
        ]));
        let mut missing_results = ValidationResults::default();
        verify_collection_hash(
            &missing_algorithm,
            &vmap(Vec::new()),
            &[],
            false,
            "urn:c2pa:test",
            &mut missing_results,
        );
        assert!(missing_results.has_failure(ALGORITHM_UNSUPPORTED));
        assert!(!missing_results.has_failure(ASSERTION_COLLECTION_HASH_MALFORMED));
    }

    #[test]
    fn collection_hash_falls_back_to_claim_algorithm() {
        let empty_zip = [
            0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let collection = enc(&vmap(vec![
            ("uris", Value::Array(Vec::new())),
            (
                "zip_central_directory_hash",
                Value::Bytes(hash_bytes("sha256", &empty_zip).expect("allowed hash")),
            ),
        ]));
        let claim = vmap(vec![("alg", Value::Text("sha256".into()))]);
        let mut results = ValidationResults::default();
        verify_collection_hash(
            &collection,
            &claim,
            &empty_zip,
            false,
            "urn:c2pa:test",
            &mut results,
        );
        assert!(results.has_success(ASSERTION_COLLECTION_HASH_MATCH));
        assert!(!results.has_failure(ALGORITHM_UNSUPPORTED));
        assert!(!results.has_failure(ASSERTION_COLLECTION_HASH_MALFORMED));
    }

    #[test]
    fn bmff_optional_boxes_are_reported_as_additional_exclusions() {
        let map = |xpath: &str| crate::c2pa_formats::BmffExclusionMap {
            xpath: xpath.into(),
            length: None,
            data: Vec::new(),
            subset: Vec::new(),
            version: None,
            flags: None,
            exact: false,
        };
        assert!(!bmff_has_additional_exclusions(
            &[map("/uuid"), map("/ftyp"), map("/mfra")],
            false,
        ));
        assert!(bmff_has_additional_exclusions(&[map("/free")], false));
        assert!(!bmff_has_additional_exclusions(&[map("/mdat")], true));
    }

    #[test]
    fn malformed_ingredient_emits_registered_status() {
        let ingredient = enc(&vmap(Vec::new()));
        let manifest = ParsedManifest {
            label: "urn:c2pa:test".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.ingredient.v2".into(), ingredient.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion("c2pa.ingredient.v2")]),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_ingredient_shapes(&manifest, &refs, &mut results);
        assert!(results.has_failure(ASSERTION_INGREDIENT_MALFORMED));
    }

    #[test]
    fn embedded_alternative_content_hash_emits_match() {
        let embedded_jumbf = b"embedded original preservation image";
        let embedded_cbor = enc(&vmap(vec![("data", Value::Bytes(vec![1]))]));
        let representation = vmap(vec![
            ("type", Value::Text("exif.originalPreservationImage".into())),
            (
                "parameters",
                vmap(vec![(
                    "embeddedOriginalPreservationImage",
                    vmap(vec![
                        (
                            "url",
                            Value::Text("self#jumbf=c2pa.assertions/c2pa.embedded-data".into()),
                        ),
                        ("alg", Value::Text("sha256".into())),
                        ("hash", Value::Bytes(sha(embedded_jumbf))),
                    ]),
                )]),
            ),
        ]);
        let representation_cbor = enc(&representation);
        let manifest = ParsedManifest {
            label: "urn:c2pa:test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                (
                    "c2pa.alternative-content-representation".into(),
                    representation_cbor.as_slice(),
                ),
                ("c2pa.embedded-data".into(), embedded_cbor.as_slice()),
            ],
            assertion_jumbf: vec![
                (
                    "c2pa.alternative-content-representation".into(),
                    representation_cbor.as_slice(),
                ),
                ("c2pa.embedded-data".into(), embedded_jumbf.as_slice()),
            ],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![
                hashed_uri_for_assertion("c2pa.alternative-content-representation"),
                hashed_uri_for_assertion("c2pa.embedded-data"),
            ]),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_alternative_content(&manifest, &claim, &refs, &mut results);
        assert!(results.has_success(ASSERTION_ALTERNATIVE_CONTENT_MATCH));
        assert!(results.failure.is_empty());
    }

    // ---- data-hash exclusion content (C2PA 2.4 "Validating a data hash") ----

    /// Run the sole `c2pa.hash.data` hard binding over `data` with the given
    /// exclusion ranges and a `hash` computed over exactly those ranges, so the
    /// byte hash always matches and only the exclusion rules can reject it.
    fn data_hash_binding(
        format: AssetFormat,
        data: &[u8],
        exclusions: &[(usize, usize)],
    ) -> ValidationResults {
        let declared = Value::Array(
            exclusions
                .iter()
                .map(|(start, length)| {
                    vmap(vec![
                        ("start", Value::Integer(*start as i128)),
                        ("length", Value::Integer(*length as i128)),
                    ])
                })
                .collect(),
        );
        let hash = hash_with_exclusions("sha256", data, exclusions).expect("hash");
        let cbor = enc(&vmap(vec![
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(hash)),
            ("exclusions", declared),
        ]));
        let manifest = ParsedManifest {
            label: "urn:c2pa:test".into(),
            manifest_jumbf: &[],
            assertions: vec![("c2pa.hash.data".into(), cbor.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![(
            "created_assertions",
            Value::Array(vec![hashed_uri_for_assertion("c2pa.hash.data")]),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_primary_hard_binding(
            &claim,
            &refs,
            data,
            format,
            &[],
            update_manifest::StoreRendition::AsSigned,
            &manifest.label,
            EngineProfile::GENEROUS,
            &mut results,
        );
        results
    }

    /// A JPEG carrying a real manifest store, with the byte span of its C2PA
    /// `APP11` run.
    fn signed_jpeg() -> (Vec<u8>, crate::c2pa_formats::DataHashExclusion) {
        let store = build_manifest_store(&[build_manifest(
            "urn:c2pa:test:0001",
            &[],
            &[0xa0],
            &[0xd2, 0x84],
        )]);
        let asset = crate::c2pa_formats::embed_manifest(
            AssetFormat::Jpeg,
            include_bytes!("../../../../tests/fixtures/signed_test.jpg"),
            &store,
        )
        .expect("embed");
        let carrier = crate::c2pa_formats::compute_data_hash_exclusions(AssetFormat::Jpeg, &asset)
            .expect("carrier");
        assert_eq!(carrier.len(), 1, "one contiguous APP11 run");
        (asset, carrier[0])
    }

    #[test]
    fn an_exact_manifest_carrier_exclusion_matches_without_caveat() {
        let (asset, carrier) = signed_jpeg();
        let results = data_hash_binding(
            AssetFormat::Jpeg,
            &asset,
            &[(carrier.start, carrier.length)],
        );
        assert!(
            results.has_success(ASSERTION_DATA_HASH_MATCH),
            "{results:?}"
        );
        assert!(!results.has_informational(ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT));
    }

    /// C2PA 2.4: "A validator shall ensure that the data contained within the
    /// exclusion range containing the C2PA Manifest Store consists of only the
    /// C2PA Manifest Store and any appropriate padding ... If a validator
    /// encounters any data other than what is permitted, then the manifest
    /// shall be rejected with a failure code of assertion.dataHash.mismatch."
    /// The hash still matches, so only this rule can catch the smuggled bytes.
    #[test]
    fn asset_bytes_hidden_inside_the_manifest_exclusion_are_rejected() {
        let (asset, carrier) = signed_jpeg();
        let widened = (carrier.start, carrier.length + 16);
        assert!(
            asset[carrier.start + carrier.length..][..16]
                .iter()
                .any(|byte| *byte != 0),
            "the widened bytes must be real asset content, not padding"
        );
        let results = data_hash_binding(AssetFormat::Jpeg, &asset, &[widened]);
        assert!(
            results.has_failure(ASSERTION_DATA_HASH_MISMATCH),
            "{results:?}"
        );
        assert!(!results.has_success(ASSERTION_DATA_HASH_MATCH));
    }

    /// C2PA 2.4 "Hashing of JPEG 1 files": "a validator shall match the total
    /// length of the exclusion range with that of the total length of all
    /// APP11 segments representing the C2PA Manifest to ensure that the length
    /// was not tampered with."
    #[test]
    fn a_jpeg_exclusion_shorter_than_the_app11_run_is_rejected() {
        let (asset, carrier) = signed_jpeg();
        let results = data_hash_binding(
            AssetFormat::Jpeg,
            &asset,
            &[(carrier.start, carrier.length - 8)],
        );
        assert!(
            results.has_failure(ASSERTION_DATA_HASH_MISMATCH),
            "{results:?}"
        );
        assert!(!results.has_success(ASSERTION_DATA_HASH_MATCH));
    }

    /// Zeroed padding beside the store is explicitly permitted, and metadata
    /// ranges away from the store stay informational rather than fatal.
    #[test]
    fn zero_padding_and_metadata_exclusions_remain_acceptable() {
        let mut asset =
            crate::c2pa_formats::embed_manifest(AssetFormat::Png, &minimal_png(), &[0xAA; 64])
                .expect("embed");
        let carrier = crate::c2pa_formats::compute_data_hash_exclusions(AssetFormat::Png, &asset)
            .expect("carrier")[0];
        // A zero-length, zero-typed PNG chunk: twelve bytes of pure padding
        // directly after the manifest carrier.
        let pad_at = carrier.start + carrier.length;
        asset.splice(pad_at..pad_at, [0u8; 12]);

        let padded = data_hash_binding(
            AssetFormat::Png,
            &asset,
            &[(carrier.start, carrier.length + 12)],
        );
        assert!(padded.has_success(ASSERTION_DATA_HASH_MATCH), "{padded:?}");

        let with_metadata = data_hash_binding(
            AssetFormat::Png,
            &asset,
            &[(0, 8), (carrier.start, carrier.length)],
        );
        assert!(with_metadata.has_success(ASSERTION_DATA_HASH_MATCH));
        assert!(
            with_metadata.has_informational(ASSERTION_DATA_HASH_ADDITIONAL_EXCLUSIONS_PRESENT),
            "a range away from the carrier is the additional-exclusions case"
        );
    }

    fn minimal_png() -> Vec<u8> {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let chunk = |png: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]| {
            png.extend_from_slice(&(body.len() as u32).to_be_bytes());
            png.extend_from_slice(kind);
            png.extend_from_slice(body);
            let mut crc_input = kind.to_vec();
            crc_input.extend_from_slice(body);
            png.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        };
        chunk(&mut png, b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
        chunk(&mut png, b"IDAT", &[0x78, 0x9C, 0x01, 0x02]);
        chunk(&mut png, b"IEND", &[]);
        png
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    // ---- general box hash on GIF, RIFF, and Ogg (C2PA 2.4 BoxesHash) ----

    /// Build a `c2pa.hash.boxes` assertion over `spans`, hashing each box
    /// independently of the verifier, then run it over `data`.
    fn boxes_hash_binding_for_spans(
        format: AssetFormat,
        signed: &[u8],
        data: &[u8],
        spans: &[crate::c2pa_formats::BoxSpan],
        profile: EngineProfile,
    ) -> ValidationResults {
        let entries: Vec<Value> = spans
            .iter()
            .map(|span| {
                let hash = if span.name == "C2PA" {
                    vec![0x00]
                } else {
                    let mut content = Vec::new();
                    for &(start, end) in span.ranges() {
                        content.extend_from_slice(&signed[start..end]);
                    }
                    sha(&content)
                };
                vmap(vec![
                    ("names", Value::Array(vec![Value::Text(span.name.clone())])),
                    ("alg", Value::Text("sha256".into())),
                    ("hash", Value::Bytes(hash)),
                ])
            })
            .collect();
        let cbor = enc(&vmap(vec![("boxes", Value::Array(entries))]));
        let mut results = ValidationResults::default();
        verify_boxes_hash(
            &cbor,
            &vmap(Vec::new()),
            format,
            data,
            false,
            "urn:c2pa:test",
            profile,
            &mut results,
        );
        results
    }

    fn boxes_hash_binding(format: AssetFormat, signed: &[u8], data: &[u8]) -> ValidationResults {
        let spans = crate::c2pa_formats::box_spans(format, signed)
            .expect("segmentation")
            .expect("a segmentable container");
        boxes_hash_binding_for_spans(format, signed, data, &spans, EngineProfile::GENEROUS)
    }

    fn restart_interval_jpeg() -> Vec<u8> {
        vec![
            0xFF, 0xD8, // SOI
            0xFF, 0xDA, 0x00, 0x02, // SOS with an empty synthetic header
            0x11, 0x22, // first entropy-coded segment
            0xFF, 0xD0, 0x33, 0xFF, 0x00, 0x44, // RST0 + stuffed entropy bytes
            0xFF, 0xD1, 0x55, // RST1 + final entropy-coded segment
            0xFF, 0xD9, // EOI
        ]
    }

    /// C2PA 2.4 BoxesHash, JPEG-specific handling: "The Start of Scan box and
    /// Restart boxes ... will include the entropy coded segments following the
    /// respective marker." Strict accepts only that reading. Default also
    /// reads historical c2pa-rs output, where SOS covers the full scan and each
    /// restart box covers only its marker. Both layouts still bind every byte.
    #[test]
    fn jpeg_restart_box_hash_layout_is_posture_sensitive_and_tamper_evident() {
        let store = build_manifest_store(&[build_manifest(
            "urn:c2pa:test:0001",
            &[],
            &[0xa0],
            &[0xd2, 0x84],
        )]);
        let signed = crate::c2pa_formats::embed_manifest(
            AssetFormat::Jpeg,
            &restart_interval_jpeg(),
            &store,
        )
        .expect("embed");
        let strict_spans = crate::c2pa_formats::box_spans(AssetFormat::Jpeg, &signed)
            .expect("segmentation")
            .expect("JPEG spans");
        let overlapping_spans =
            crate::c2pa_formats::jpeg_box_spans_with_overlapping_restart_segments(&signed)
                .expect("compatibility segmentation");

        let entropy_byte = strict_spans
            .iter()
            .find(|span| span.name == "RST0")
            .expect("RST0")
            .start()
            + 2;
        let mut tampered = signed.clone();
        tampered[entropy_byte] ^= 0xFF;
        let strict_profile = EngineProfile::strict(SpecVersion::V2_4);

        for profile in [EngineProfile::GENEROUS, strict_profile] {
            let intact = boxes_hash_binding_for_spans(
                AssetFormat::Jpeg,
                &signed,
                &signed,
                &strict_spans,
                profile,
            );
            assert!(intact.has_success(ASSERTION_BOXES_HASH_MATCH), "{intact:?}");
            assert!(!intact.has_informational(ASSERTION_BOXES_HASH_OVERLAPPING_RESTART_SEGMENTS));

            let edited = boxes_hash_binding_for_spans(
                AssetFormat::Jpeg,
                &signed,
                &tampered,
                &strict_spans,
                profile,
            );
            assert!(
                edited.has_failure(ASSERTION_BOXES_HASH_MISMATCH),
                "{edited:?}"
            );
            assert!(!edited.has_success(ASSERTION_BOXES_HASH_MATCH));
        }

        let default_compat = boxes_hash_binding_for_spans(
            AssetFormat::Jpeg,
            &signed,
            &signed,
            &overlapping_spans,
            EngineProfile::GENEROUS,
        );
        assert!(
            default_compat.has_success(ASSERTION_BOXES_HASH_MATCH),
            "{default_compat:?}"
        );
        assert!(default_compat.has_informational(ASSERTION_BOXES_HASH_OVERLAPPING_RESTART_SEGMENTS));

        let strict_compat = boxes_hash_binding_for_spans(
            AssetFormat::Jpeg,
            &signed,
            &signed,
            &overlapping_spans,
            strict_profile,
        );
        assert!(
            strict_compat.has_failure(ASSERTION_BOXES_HASH_MISMATCH),
            "{strict_compat:?}"
        );
        assert!(!strict_compat.has_success(ASSERTION_BOXES_HASH_MATCH));

        for profile in [EngineProfile::GENEROUS, strict_profile] {
            let edited = boxes_hash_binding_for_spans(
                AssetFormat::Jpeg,
                &signed,
                &tampered,
                &overlapping_spans,
                profile,
            );
            assert!(
                edited.has_failure(ASSERTION_BOXES_HASH_MISMATCH),
                "{edited:?}"
            );
            assert!(!edited.has_success(ASSERTION_BOXES_HASH_MATCH));
        }
    }

    /// C2PA 2.4 Validation, "Validating a general box hash": "If the hash
    /// value for any box does not match ... the manifest shall be rejected
    /// with a failure code of assertion.boxesHash.mismatch." These containers
    /// were never segmented, so a box-hash-signed GIF, WAV, or Ogg stayed
    /// valid no matter how its content was edited.
    #[test]
    fn box_hash_signed_gif_riff_and_ogg_detect_content_tampering() {
        let store = build_manifest_store(&[build_manifest(
            "urn:c2pa:test:0001",
            &[],
            &[0xa0],
            &[0xd2, 0x84],
        )]);
        // Each case names a payload byte pattern that lies in rendered
        // content, outside the manifest carrier.
        let cases: [(AssetFormat, Vec<u8>, &[u8]); 3] = [
            (
                AssetFormat::Gif,
                crate::c2pa_formats::sample_gif(),
                &[0x44, 0x01],
            ),
            (
                AssetFormat::Riff,
                crate::c2pa_formats::sample_riff(),
                &[0x88, 0x58],
            ),
            (
                AssetFormat::Ogg,
                crate::c2pa_formats::sample_ogg(),
                b"fixture",
            ),
        ];
        for (format, asset, payload) in cases {
            let signed =
                crate::c2pa_formats::embed_manifest(format, &asset, &store).expect("embed");
            let intact = boxes_hash_binding(format, &signed, &signed);
            assert!(
                intact.has_success(ASSERTION_BOXES_HASH_MATCH),
                "{format:?}: {intact:?}"
            );

            // Edit one byte of rendered content, leaving the container itself
            // well-formed, which is exactly what a content binding must catch.
            let target = signed
                .windows(payload.len())
                .position(|window| window == payload)
                .expect("payload present");
            let mut tampered = signed.clone();
            if format == AssetFormat::Ogg {
                crate::c2pa_formats::tamper_ogg_page_byte(&mut tampered, target);
            } else {
                tampered[target] ^= 0xFF;
            }
            let edited = boxes_hash_binding(format, &signed, &tampered);
            assert!(
                edited.has_failure(ASSERTION_BOXES_HASH_MISMATCH),
                "{format:?}: {edited:?}"
            );
            assert!(!edited.has_success(ASSERTION_BOXES_HASH_MATCH));
            assert_eq!(
                compute_state(&edited, EngineProfile::GENEROUS),
                ValidationState::Invalid,
                "{format:?}"
            );
        }
    }

    /// "If there are any other boxes present in the asset, then the manifest
    /// shall be rejected with a failure code of assertion.boxesHash.unknownBox."
    /// Data appended after the GIF trailer is such a box (BoxesHash names it
    /// `c2pa.after`), so it can never ride along unhashed.
    #[test]
    fn gif_data_outside_the_signed_block_stream_is_an_unknown_box() {
        let asset = crate::c2pa_formats::sample_gif();
        let mut appended = asset.clone();
        appended.extend_from_slice(b"payload the claim never covered");
        let results = boxes_hash_binding(AssetFormat::Gif, &asset, &appended);
        assert!(
            results.has_failure(ASSERTION_BOXES_HASH_UNKNOWN_BOX),
            "{results:?}"
        );
        assert!(!results.has_success(ASSERTION_BOXES_HASH_MATCH));
    }

    /// Build one manifest carrying `label` -> `assertion`, declare it in
    /// `field`, and run only the external-data assertion rules over it.
    fn run_external_data(
        label: &str,
        assertion: &Value,
        field: &'static str,
        generation: ClaimGeneration,
        manifest_kind: ManifestKind,
        profile: EngineProfile,
    ) -> ValidationResults {
        run_external_data_with_evidence(
            label,
            assertion,
            field,
            generation,
            manifest_kind,
            profile,
            OnlineEvidence::default(),
        )
    }

    /// [`run_external_data`] with caller-supplied content for the referenced
    /// URI.
    #[allow(clippy::too_many_arguments)]
    fn run_external_data_with_evidence(
        label: &str,
        assertion: &Value,
        field: &'static str,
        generation: ClaimGeneration,
        manifest_kind: ManifestKind,
        profile: EngineProfile,
        evidence: OnlineEvidence<'_>,
    ) -> ValidationResults {
        let payload = enc(assertion);
        let manifest = ParsedManifest {
            label: "urn:c2pa:00000000-0000-4000-8000-0000000000ed".into(),
            manifest_jumbf: &[],
            assertions: vec![(label.into(), payload.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = vmap(vec![(
            field,
            Value::Array(vec![hashed_uri_for_assertion(label)]),
        )]);
        let refs = ClaimAssertionRefs::build(&manifest, &claim, generation);
        let mut results = ValidationResults::default();
        verify_external_data_assertions(
            &refs,
            generation,
            manifest_kind,
            &manifest.label,
            profile,
            evidence,
            &mut results,
        );
        results
    }

    fn cloud_location() -> Value {
        vmap(vec![
            ("url", Value::Text("https://store.test/a".into())),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(vec![7; 32])),
        ])
    }

    fn cloud_data(referenced: &str) -> Value {
        vmap(vec![
            ("label", Value::Text(referenced.into())),
            ("size", Value::Integer(4321)),
            ("location", cloud_location()),
        ])
    }

    fn gathered_cloud_data(referenced: &str, kind: ManifestKind) -> ValidationResults {
        run_external_data(
            "c2pa.cloud-data",
            &cloud_data(referenced),
            "gathered_assertions",
            ClaimGeneration::V2,
            kind,
            EngineProfile::GENEROUS,
        )
    }

    /// Offline, the unread cloud-data content is reported inaccessible and
    /// recorded as the fetch that would read it.
    #[test]
    fn unread_cloud_data_records_the_fetch_that_would_read_it() {
        let results = gathered_cloud_data("c2pa.metadata", ManifestKind::Standard);
        assert!(results.has_failure(ASSERTION_INACCESSIBLE));
        assert_eq!(
            results
                .network_needs
                .iter()
                .map(NetworkNeed::to_json)
                .collect::<Vec<_>>(),
            vec![json!({
                "kind": "external_data",
                "uri": "https://store.test/a",
                "assertion_label": "c2pa.metadata",
            })]
        );
    }

    /// C2PA 2.4 Validation, Validation of External References: supplied
    /// content is hashed against the `location` map's own `alg` and `hash`.
    #[test]
    fn supplied_cloud_data_is_checked_against_its_declared_hash() {
        let content = b"the externally stored assertion".to_vec();
        let location = vmap(vec![
            ("url", Value::Text("https://store.test/a".into())),
            ("alg", Value::Text("sha256".into())),
            ("hash", Value::Bytes(Sha256::digest(&content).to_vec())),
        ]);
        let assertion = vmap(vec![
            ("label", Value::Text("c2pa.metadata".into())),
            ("size", Value::Integer(content.len() as i128)),
            ("location", location),
        ]);
        let supplied =
            std::collections::HashMap::from([("https://store.test/a".to_string(), content)]);
        let evidence = OnlineEvidence {
            external_data: Some(&supplied),
            ..OnlineEvidence::default()
        };
        let results = run_external_data_with_evidence(
            "c2pa.cloud-data",
            &assertion,
            "gathered_assertions",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::GENEROUS,
            evidence,
        );
        assert!(results.has_success(ASSERTION_ACCESSIBLE));
        assert!(results.has_success(ASSERTION_HASHED_URI_MATCH));
        assert!(!results.has_failure(ASSERTION_INACCESSIBLE));
        assert!(results.network_needs.is_empty());

        // Content that does not hash to the declared value is reported, and
        // still does not reject the claim.
        let tampered = std::collections::HashMap::from([(
            "https://store.test/a".to_string(),
            b"something else entirely".to_vec(),
        )]);
        let mismatch = run_external_data_with_evidence(
            "c2pa.cloud-data",
            &assertion,
            "gathered_assertions",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::GENEROUS,
            OnlineEvidence {
                external_data: Some(&tampered),
                ..OnlineEvidence::default()
            },
        );
        assert!(mismatch.has_success(ASSERTION_ACCESSIBLE));
        assert!(mismatch.has_failure(ASSERTION_HASHED_URI_MISMATCH));
        assert_eq!(
            compute_state(&mismatch, EngineProfile::CONFORMANCE_V2_2),
            ValidationState::Valid,
            "external data must never reject a claim"
        );
    }

    /// C2PA 2.4 Validation, `c2pa.cloud-data` validation, steps 1-4.
    #[test]
    fn cloud_data_structure_and_referenced_label_rules_are_enforced_offline() {
        // Step 1: label, size and location are all required.
        for missing in ["label", "size", "location"] {
            let mut fields = vec![
                ("label", Value::Text("c2pa.metadata".into())),
                ("size", Value::Integer(4321)),
                ("location", cloud_location()),
            ];
            fields.retain(|(name, _)| *name != missing);
            let results = run_external_data(
                "c2pa.cloud-data",
                &vmap(fields),
                "gathered_assertions",
                ClaimGeneration::V2,
                ManifestKind::Standard,
                EngineProfile::GENEROUS,
            );
            assert!(
                results.has_failure(ASSERTION_CLOUD_DATA_MALFORMED),
                "missing {missing}: {results:?}"
            );
        }

        // Step 2: a hard binding may never live in the cloud.
        for binding in [
            "c2pa.hash.data",
            "c2pa.hash.bmff.v3",
            "c2pa.hash.multi-asset",
        ] {
            let results = gathered_cloud_data(binding, ManifestKind::Standard);
            assert!(
                results.has_failure(ASSERTION_CLOUD_DATA_HARD_BINDING),
                "{binding}: {results:?}"
            );
        }

        // Step 3: an update manifest may not point at a remote actions
        // assertion. Step 4 catches the same label in a standard manifest.
        let update = gathered_cloud_data("c2pa.actions", ManifestKind::Update);
        assert!(
            update.has_failure(ASSERTION_CLOUD_DATA_ACTIONS),
            "{update:?}"
        );
        let standard = gathered_cloud_data("c2pa.actions", ManifestKind::Standard);
        assert!(
            standard.has_failure(ASSERTION_CLOUD_DATA_MALFORMED),
            "{standard:?}"
        );
        assert!(!standard.has_failure(ASSERTION_CLOUD_DATA_ACTIONS));

        // Step 4: ingredients may not be stored remotely either. The `__1`
        // storage suffix does not let a forbidden type through.
        let ingredient = gathered_cloud_data("c2pa.ingredient.v3__1", ManifestKind::Standard);
        assert!(
            ingredient.has_failure(ASSERTION_CLOUD_DATA_MALFORMED),
            "{ingredient:?}"
        );

        // A `location` that could never resolve or be checked is incomplete.
        let no_hash = vmap(vec![
            ("label", Value::Text("c2pa.metadata".into())),
            ("size", Value::Integer(4321)),
            (
                "location",
                vmap(vec![("url", Value::Text("https://store.test/a".into()))]),
            ),
        ]);
        let results = run_external_data(
            "c2pa.cloud-data",
            &no_hash,
            "gathered_assertions",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::GENEROUS,
        );
        assert!(
            results.has_failure(ASSERTION_CLOUD_DATA_MALFORMED),
            "{results:?}"
        );
    }

    /// A well-formed cloud data assertion is reported as unread, not rejected:
    /// C2PA 2.4 Validation, External Data Validation, General.
    #[test]
    fn an_unread_cloud_assertion_is_reported_with_its_uri_and_does_not_reject_the_claim() {
        let results = gathered_cloud_data("c2pa.metadata", ManifestKind::Standard);

        let status = results
            .failure
            .iter()
            .find(|status| status.code == ASSERTION_INACCESSIBLE)
            .unwrap_or_else(|| panic!("{results:?}"));
        assert_eq!(
            status.details.as_ref().and_then(|d| d.get("uri")),
            Some(&Json::from("https://store.test/a"))
        );
        assert_eq!(
            status
                .details
                .as_ref()
                .and_then(|d| d.get("assertion_label")),
            Some(&Json::from("c2pa.metadata"))
        );
        assert!(!results.has_failure(ASSERTION_CLOUD_DATA_MALFORMED));

        for profile in [
            EngineProfile::GENEROUS,
            EngineProfile::strict(SpecVersion::V2_4),
        ] {
            assert_eq!(
                compute_state(&results, profile),
                ValidationState::Valid,
                "{profile:?}"
            );
        }
    }

    /// C2PA 2.4 Validation, `c2pa.external-reference` validation, steps 1-4.
    #[test]
    fn external_reference_structure_rules_are_enforced_offline() {
        let run = |assertion: &Value| {
            run_external_data(
                "c2pa.external-reference",
                assertion,
                "gathered_assertions",
                ClaimGeneration::V2,
                ManifestKind::Standard,
                EngineProfile::GENEROUS,
            )
        };

        // Step 1: a location with a url is required.
        assert!(run(&vmap(vec![("description", Value::Text("x".into()))]))
            .has_failure(ASSERTION_EXTERNAL_REFERENCE_MALFORMED));
        assert!(run(&vmap(vec![(
            "location",
            vmap(vec![("dc:format", Value::Text("application/json".into()))]),
        )]))
        .has_failure(ASSERTION_EXTERNAL_REFERENCE_MALFORMED));

        // Step 2: alg and hash travel together or not at all.
        let half_hashed = vmap(vec![(
            "location",
            vmap(vec![
                ("url", Value::Text("https://store.test/b".into())),
                ("alg", Value::Text("sha256".into())),
            ]),
        )]);
        assert!(run(&half_hashed).has_failure(ASSERTION_EXTERNAL_REFERENCE_MALFORMED));

        // Step 4: forbidden referenced assertion types.
        let forbidden = vmap(vec![
            ("label", Value::Text("c2pa.actions.v2".into())),
            (
                "location",
                vmap(vec![("url", Value::Text("https://store.test/b".into()))]),
            ),
        ]);
        assert!(run(&forbidden).has_failure(ASSERTION_EXTERNAL_REFERENCE_MALFORMED));

        // An unhashed reference to arbitrary data is well formed. It carries no
        // assertion, so it is advisory rather than a remote assertion.
        let blob = vmap(vec![(
            "location",
            vmap(vec![
                ("url", Value::Text("https://store.test/blob".into())),
                ("dc:format", Value::Text("application/octet-stream".into())),
            ]),
        )]);
        let results = run(&blob);
        assert!(!results.has_failure(ASSERTION_EXTERNAL_REFERENCE_MALFORMED));
        assert!(!results.has_failure(ASSERTION_INACCESSIBLE));
        assert!(results
            .informational
            .iter()
            .any(|status| status.code == EXTERNAL_REFERENCE_NOT_RETRIEVED));
    }

    /// C2PA 2.4 Standard Assertions, External Reference: the assertion "should
    /// appear in `gathered_assertions`". A SHOULD is raised to the registered
    /// failure only under the conformance posture.
    #[test]
    fn an_external_reference_in_created_assertions_fails_strict_only() {
        let assertion = vmap(vec![
            ("label", Value::Text("c2pa.metadata".into())),
            (
                "location",
                vmap(vec![("url", Value::Text("https://store.test/b".into()))]),
            ),
        ]);
        let created = |profile| {
            run_external_data(
                "c2pa.external-reference",
                &assertion,
                "created_assertions",
                ClaimGeneration::V2,
                ManifestKind::Standard,
                profile,
            )
        };

        assert!(!created(EngineProfile::GENEROUS).has_failure(ASSERTION_EXTERNAL_REFERENCE_CREATED));
        assert!(created(EngineProfile::strict(SpecVersion::V2_4))
            .has_failure(ASSERTION_EXTERNAL_REFERENCE_CREATED));
        assert!(!run_external_data(
            "c2pa.external-reference",
            &assertion,
            "gathered_assertions",
            ClaimGeneration::V2,
            ManifestKind::Standard,
            EngineProfile::strict(SpecVersion::V2_4),
        )
        .has_failure(ASSERTION_EXTERNAL_REFERENCE_CREATED));
    }
}
