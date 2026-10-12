// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Verification for a trusted caller that checks an asset's content binding
//! with its own engine, compiled only with the non-default
//! `caller-verified-binding` feature.
//!
//! Every other entry point in this crate compares the asset's bytes with the
//! manifest's hard binding itself. The entry points here do not, and they are
//! for one kind of caller only: an engine that has independently compared the
//! exact asset bytes with the exact binding assertion this crate names.
//!
//! - [`CawgEvaluator::evaluate_with_caller_verified_binding`] runs only the
//!   CAWG identity step.
//! - [`verify_with_caller_verified_binding`] (and its `_and_cawg` form) runs
//!   the complete standard validation - claim structure, the selected
//!   policy's assertion, action, ingredient and redaction rules, hashed-URI
//!   bindings, the binding assertion's own schema, the signature, time
//!   stamps, revocation, trust and CAWG identity - and takes from the caller
//!   only the asset byte comparison. [`binding_target`] names what that
//!   comparison must cover; [`CallerBindingEvidence`] carries the verdict
//!   back, tied to the exact store bytes, active manifest and binding
//!   reference. This crate re-derives that identity from the same store and
//!   refuses a verdict about anything else.
//! - [`verify_with_cawg`], [`verify_with_manifest_store_and_cawg`] and
//!   [`verify_fragmented_with_cawg`] are the ordinary asset verifications,
//!   with the CAWG configuration, policy and instant taken from one
//!   [`CawgEvaluator`] so a caller holding one does not rebuild it.
//!
//! None of these entry points fetches, and none sends telemetry.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::c2pa_core::spec::canonicalize_mime;
use crate::c2pa_core::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
use crate::c2pa_formats::AssetFormat;
use crate::c2pa_validate::{
    binding_target as kernel_binding_target, verify_detached_safe,
    verify_fragmented_with_cawg_options_and_expected_seeks_safe,
    verify_identity_with_caller_verified_binding, verify_store_binding,
    verify_with_cawg_options_and_graph_inputs_safe, BindingTarget, CallerBinding, CawgTrustInputs,
    StoreBinding, VerifyOutput,
};
use crate::{
    copy_status, finish_store_only_validation, map_validate_error, parse_validation_time,
    report_from_output, require_embedded_mime, resolve_detached_mime, resolve_mime,
    resolve_profile, Error, GraphInputs, ManifestDigest, ResolvedOptions, StoreOnlyValidation,
    ValidationResults, VerificationReport, VerifyOptions, MAX_MANIFEST_STORE_BYTES,
};

/// The caller's engine profile: spec revision, operating mode, and compliance
/// bar. The evaluator takes the profile explicitly; public option selectors
/// supplied to a pass are checked for consistency and never override it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CawgProfile {
    profile: EngineProfile,
}

impl CawgProfile {
    /// `spec_version` is one of "1.4", "2.0", "2.1", "2.2", "2.3", "2.4", or
    /// "2.5". `conformance_mode` selects the conformance operating mode, and
    /// `compliance_program` the Conformance Program compliance bar. The 2.5
    /// technical profile accepts regular/core or conformance/core. It refuses
    /// Conformance Program because no 2.5 program profile is published.
    pub fn new(
        spec_version: &str,
        conformance_mode: bool,
        compliance_program: bool,
    ) -> Result<Self, Error> {
        let version = SpecVersion::from_str(spec_version).ok_or_else(|| {
            Error::Verification(format!(
                "spec_version {spec_version:?} is not one of {}",
                SpecVersion::ALL
                    .iter()
                    .map(|version| version.version_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        if version == SpecVersion::V2_5 && compliance_program {
            return Err(Error::Verification(
                "spec_version \"2.5\" has no Conformance Program profile; compliance_program must be false".into(),
            ));
        }
        let mode = if conformance_mode {
            OperatingMode::Conformance
        } else {
            OperatingMode::Regular
        };
        let compliance = if compliance_program {
            ComplianceLevel::ConformanceProgram
        } else {
            ComplianceLevel::CoreSpec
        };
        Ok(Self {
            profile: EngineProfile::new(version, mode).with_compliance(compliance),
        })
    }
}

/// The binding context the caller's carrier fixes. It decides whether
/// `c2pa.compound.content` counts as a primary binding; it never selects a
/// content hash to compute.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CawgStoreHost {
    /// The store travels with, or binds to, a host asset.
    Asset,
    /// A host-less `application/c2pa` store.
    HostLess,
}

/// The outcome of one evaluation.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CawgEvaluation {
    /// The identity step ran on the active manifest.
    #[non_exhaustive]
    Evaluated {
        /// Label of the active manifest.
        manifest_label: String,
        /// Every manifest in store order, with the expanded-domain SHA-256 an
        /// ingredient reference uses. The caller compares this list with its
        /// own parse before using the statuses.
        store_manifests: Vec<ManifestDigest>,
        /// Exactly the statuses the identity step appended.
        validation_results: ValidationResults,
    },
    /// The identity step could not run.
    #[non_exhaustive]
    StoreGateClosed {
        /// Label of the active manifest, if the store has one.
        manifest_label: Option<String>,
        /// The status that kept the identity step from running.
        code: String,
    },
}

/// Resolved CAWG evaluation policy. Construction validates every trust and
/// evidence input once, so one evaluator can serve many evaluations. Its
/// validation instant is fixed: `options.validation_time` is required.
pub struct CawgEvaluator {
    resolved: ResolvedOptions,
    did_documents: Option<HashMap<String, serde_json::Value>>,
    ica_trusted_issuers: Option<Vec<String>>,
    ica_trust_anchors: Option<Vec<String>>,
    ica_status_lists: Option<HashMap<String, String>>,
}

impl std::fmt::Debug for CawgEvaluator {
    /// Trust material stays out of logs; only the posture is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CawgEvaluator")
            .field("profile", &self.resolved.profile)
            .finish_non_exhaustive()
    }
}

impl CawgEvaluator {
    /// Posture comes only from `profile`. `strict_conformance: true`, any
    /// `spec_version`, `online: Some(true)`, and a non-empty `external_data`
    /// are rejected: this evaluator never fetches, and a posture flag that
    /// disagreed with `profile` would be ambiguous.
    ///
    /// `validation_time` is required. Every evaluation judges certificate
    /// validity, time stamps, and OCSP freshness at that instant, so an
    /// omitted value would silently freeze the clock at construction for as
    /// long as the evaluator lives.
    pub fn new(options: &VerifyOptions, profile: &CawgProfile) -> Result<Self, Error> {
        if options.strict_conformance {
            return Err(Error::Verification(
                "strict_conformance must be false: the evaluator takes its posture from CawgProfile"
                    .into(),
            ));
        }
        if options.spec_version.is_some() {
            return Err(Error::Verification(
                "spec_version must be None: the evaluator takes its spec revision from CawgProfile"
                    .into(),
            ));
        }
        if options.online == Some(true) {
            return Err(Error::Verification(
                "online must not be Some(true): the evaluator never fetches".into(),
            ));
        }
        if options
            .external_data
            .as_ref()
            .is_some_and(|data| !data.is_empty())
        {
            return Err(Error::Verification(
                "external_data must be empty: the evaluator never reads external content".into(),
            ));
        }
        if options.validation_time.is_none() {
            return Err(Error::Verification(
                "validation_time is required: the evaluator judges every evaluation at one fixed instant"
                    .into(),
            ));
        }
        let mut resolved = ResolvedOptions::resolve(options)?;
        resolved.profile = profile.profile;
        Ok(Self {
            resolved,
            did_documents: options.cawg_did_documents.clone(),
            ica_trusted_issuers: options.cawg_ica_trusted_issuers.clone(),
            ica_trust_anchors: options.cawg_ica_trust_anchors.clone(),
            ica_status_lists: options.cawg_ica_status_lists.clone(),
        })
    }

    /// Evaluate the CAWG identity assertions of the store's active manifest.
    ///
    /// PRECONDITION: the caller has already verified the asset's hard binding
    /// and every other C2PA check for this exact store, and found the manifest
    /// intact. This function hashes no asset content and can return
    /// `cawg.identity.trusted` for a store whose content nobody checked.
    ///
    /// `manifest_store` is the store exactly as extracted, compressed
    /// manifests included, and at most 64 MiB.
    pub fn evaluate_with_caller_verified_binding(
        &self,
        manifest_store: &[u8],
        host: CawgStoreHost,
    ) -> Result<CawgEvaluation, Error> {
        if manifest_store.len() > MAX_MANIFEST_STORE_BYTES {
            return Err(Error::Verification(format!(
                "manifest store exceeds the {MAX_MANIFEST_STORE_BYTES} byte limit"
            )));
        }
        let input = self.resolved.input(&[], "");
        let cawg_inputs = self.cawg_inputs(GraphInputs::default());
        let output = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_identity_with_caller_verified_binding(
                manifest_store,
                host == CawgStoreHost::HostLess,
                &input,
                cawg_inputs,
            )
        }))
        .map_err(|_| Error::Verification("CAWG evaluation panicked".into()))?
        .map_err(map_validate_error)?;
        Ok(match (output.identity, output.manifest_label) {
            (Some(identity), Some(manifest_label)) => CawgEvaluation::Evaluated {
                manifest_label,
                store_manifests: output
                    .store_manifest_sha256
                    .into_iter()
                    .map(|digest| ManifestDigest {
                        label: digest.label,
                        sha256: hex::encode(digest.sha256),
                    })
                    .collect(),
                validation_results: ValidationResults {
                    success: identity.success.iter().map(copy_status).collect(),
                    informational: identity.informational.iter().map(copy_status).collect(),
                    failure: identity.failure.iter().map(copy_status).collect(),
                },
            },
            (_, manifest_label) => CawgEvaluation::StoreGateClosed {
                manifest_label,
                code: output.gate_code.ok_or_else(|| {
                    Error::Verification(
                        "the identity step neither ran nor recorded a gate status".into(),
                    )
                })?,
            },
        })
    }
}

impl CawgEvaluator {
    /// The engine profile every evaluation and evaluator-driven verification
    /// runs under.
    pub fn profile(&self) -> CawgProfile {
        CawgProfile {
            profile: self.resolved.profile,
        }
    }

    /// The CAWG trust, evidence, and graph inputs for one verification.
    fn cawg_inputs<'a>(&'a self, graph_inputs: GraphInputs<'a>) -> CawgTrustInputs<'a> {
        CawgTrustInputs::new(
            self.resolved.cawg_trust(),
            self.resolved.cawg_allowed_certs(),
            self.resolved.cawg_document_signing_require_anchor,
            self.did_documents.as_ref(),
            self.ica_trusted_issuers.as_deref(),
            self.ica_trust_anchors.as_deref(),
            self.ica_status_lists.as_ref(),
            graph_inputs,
        )
    }

    /// Resolve `options` for one evaluator-driven pass. `options` contributes
    /// only C2PA trust material and offline evidence; the policy, the
    /// validation instant and every CAWG input come from the evaluator.
    ///
    /// A setting that would contradict the evaluator is refused rather than
    /// silently overridden: a `spec_version` other than the evaluator's
    /// revision, `strict_conformance` with a regular-mode evaluator, a
    /// different `validation_time`, any CAWG field, or `online: Some(true)`.
    fn pass_options(&self, options: &VerifyOptions) -> Result<ResolvedOptions, Error> {
        let profile = self.resolved.profile;
        if let Some(version) = options.spec_version.as_deref() {
            if version != profile.version_str() {
                return Err(Error::Verification(format!(
                    "spec_version {version:?} differs from the evaluator's revision {:?}",
                    profile.version_str()
                )));
            }
        }
        if options.strict_conformance {
            let expected_compliance = if profile.version == SpecVersion::V2_5 {
                ComplianceLevel::CoreSpec
            } else {
                ComplianceLevel::ConformanceProgram
            };
            if profile.mode != OperatingMode::Conformance
                || profile.compliance != expected_compliance
            {
                return Err(Error::Verification(
                    "strict_conformance does not match the evaluator's exact technical posture"
                        .into(),
                ));
            }
        }
        let cawg_fields_set = options.cawg_trust_pem.is_some()
            || options.cawg_allowed_certs_pem.is_some()
            || options.cawg_document_signing_require_anchor.is_some()
            || options.cawg_trust_configurations.is_some()
            || options.cawg_did_documents.is_some()
            || options.cawg_ica_trusted_issuers.is_some()
            || options.cawg_ica_trust_anchors.is_some()
            || options.cawg_ica_status_lists.is_some()
            || options.cawg_strict_encoding;
        if cawg_fields_set {
            return Err(Error::Verification(
                "CAWG settings come from the evaluator; options must not set any cawg_* field"
                    .into(),
            ));
        }
        if options.online == Some(true) {
            return Err(Error::Verification(
                "online must not be Some(true): evaluator-driven verification never fetches".into(),
            ));
        }
        if options.validation_time.is_some()
            && parse_validation_time(options.validation_time.as_deref())?
                != self.resolved.validation_time
        {
            return Err(Error::Verification(
                "validation_time differs from the evaluator's fixed validation instant".into(),
            ));
        }
        // Resolve the C2PA trust material and evidence under a selector the
        // resolver accepts, then install the evaluator's policy and instant.
        let c2pa_only = VerifyOptions {
            spec_version: None,
            strict_conformance: false,
            validation_time: None,
            ..options.clone()
        };
        let mut resolved = ResolvedOptions::resolve(&c2pa_only)?;
        resolved.profile = profile;
        resolved.validation_time = self.resolved.validation_time;
        resolved.validation_time_text = self.resolved.validation_time_text.clone();
        resolved.cawg_strict_encoding = self.resolved.cawg_strict_encoding;
        Ok(resolved)
    }
}

/// Run one kernel verification with panic containment.
fn contained(
    run: impl FnOnce() -> Result<VerifyOutput, crate::c2pa_validate::ValidateError>,
) -> Result<VerifyOutput, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
        .map_err(|_| Error::Verification("verification panicked".into()))?
        .map_err(map_validate_error)
}

fn check_store_size(manifest_store: &[u8]) -> Result<(), Error> {
    if manifest_store.is_empty() {
        return Err(Error::Verification("manifest store is empty".into()));
    }
    if manifest_store.len() > MAX_MANIFEST_STORE_BYTES {
        return Err(Error::Verification(format!(
            "manifest store exceeds the {MAX_MANIFEST_STORE_BYTES} byte limit"
        )));
    }
    Ok(())
}

/// Validate a manifest store without asset bytes, using the exact policy,
/// validation instant, and CAWG trust/evidence configuration of `evaluator`.
///
/// The store remains unbound: this runs no content comparison and reports
/// `hard_binding` as `not_evaluated`. `options` supplies only C2PA trust
/// material and offline evidence under the same consistency checks as the
/// other evaluator-driven entry points. The identity step runs at most once.
pub fn verify_manifest_store_only_with_cawg(
    manifest_store: &[u8],
    options: &VerifyOptions,
    evaluator: &CawgEvaluator,
    graph_inputs: GraphInputs<'_>,
) -> Result<StoreOnlyValidation, Error> {
    check_store_size(manifest_store)?;
    let resolved = evaluator.pass_options(options)?;
    let input = resolved.input(&[], "application/c2pa");
    let output = contained(|| {
        verify_store_binding(
            manifest_store,
            StoreBinding::StoreOnly,
            &input,
            evaluator.cawg_inputs(graph_inputs),
        )
    })?;
    Ok(finish_store_only_validation(
        manifest_store,
        output,
        &resolved,
    ))
}

/// The hard binding a caller's engine must compare the asset's bytes with,
/// together with the exact identity of the store it came from.
///
/// Every field is derived by this crate from the submitted store bytes; a
/// caller copies the value into [`CallerBindingEvidence`] unchanged. A field
/// that later disagrees with a fresh derivation from the same store makes the
/// verification refuse the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBindingTarget {
    /// SHA-256 of the exact submitted manifest-store bytes, so evidence cannot
    /// be replayed against another representation (compressed or with other
    /// manifests) of the same active claim.
    pub manifest_store_sha256: [u8; 32],
    /// Label of the store's active manifest.
    pub active_manifest_label: String,
    /// Expanded-domain SHA-256 of the active manifest, as
    /// [`CawgEvaluation::Evaluated`] reports it.
    pub active_manifest_sha256: [u8; 32],
    /// Label of the manifest that declares the binding: the active manifest
    /// for a standard manifest, the first standard manifest of the
    /// authenticated `parentOf` chain for an update manifest.
    pub binding_manifest_label: String,
    /// Exact label of the binding assertion, instance suffix included.
    pub binding_assertion_label: String,
    /// Hash algorithm of the claim's hashed-URI reference to that assertion.
    pub binding_reference_alg: String,
    /// The claim's hashed-URI digest of that assertion.
    pub binding_reference_hash: Vec<u8>,
}

impl From<BindingTarget> for ManifestBindingTarget {
    fn from(target: BindingTarget) -> Self {
        Self {
            manifest_store_sha256: target.manifest_store_sha256,
            active_manifest_label: target.active_manifest_label,
            active_manifest_sha256: target.active_manifest_sha256,
            binding_manifest_label: target.binding_manifest_label,
            binding_assertion_label: target.binding_assertion_label,
            binding_reference_alg: target.binding_reference_alg,
            binding_reference_hash: target.binding_reference_hash,
        }
    }
}

impl From<&ManifestBindingTarget> for BindingTarget {
    fn from(target: &ManifestBindingTarget) -> Self {
        Self {
            manifest_store_sha256: target.manifest_store_sha256,
            active_manifest_label: target.active_manifest_label.clone(),
            active_manifest_sha256: target.active_manifest_sha256,
            binding_manifest_label: target.binding_manifest_label.clone(),
            binding_assertion_label: target.binding_assertion_label.clone(),
            binding_reference_alg: target.binding_reference_alg.clone(),
            binding_reference_hash: target.binding_reference_hash.clone(),
        }
    }
}

/// The caller engine's result of comparing the asset's bytes with the
/// target's binding assertion.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallerBindingVerdict {
    /// The asset's bytes matched the binding assertion.
    Match,
    /// The asset's bytes did not match; `explanation` is reported verbatim.
    Mismatch {
        /// Why the caller's engine rejected the binding.
        explanation: String,
    },
}

/// A caller engine's assertion that it compared the asset's bytes with one
/// exact binding target.
///
/// This is a statement by the caller, not proof: this crate never reads the
/// asset on these paths, so it cannot check the comparison itself. Construct
/// it only in an engine that has independently compared the exact asset
/// bytes with the binding assertion [`binding_target`] named. What this crate
/// does check is that the evidence is about this store: the target must equal
/// a fresh derivation from the submitted bytes, or the evidence is refused.
#[derive(Debug, Clone)]
pub struct CallerBindingEvidence {
    target: ManifestBindingTarget,
    verdict: CallerBindingVerdict,
    engine: String,
}

impl CallerBindingEvidence {
    /// `engine` names the comparing engine in reports (1-128 printable ASCII
    /// characters).
    pub fn new(
        target: ManifestBindingTarget,
        verdict: CallerBindingVerdict,
        engine: &str,
    ) -> Result<Self, Error> {
        if engine.is_empty()
            || engine.len() > 128
            || !engine
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        {
            return Err(Error::Verification(
                "engine must be 1-128 printable ASCII characters".into(),
            ));
        }
        Ok(Self {
            target,
            verdict,
            engine: engine.to_string(),
        })
    }

    /// The binding target this evidence is about.
    pub fn target(&self) -> &ManifestBindingTarget {
        &self.target
    }

    /// The caller engine's verdict.
    pub fn verdict(&self) -> &CallerBindingVerdict {
        &self.verdict
    }

    fn kernel(&self) -> CallerBinding {
        CallerBinding {
            target: BindingTarget::from(&self.target),
            mismatch: match &self.verdict {
                CallerBindingVerdict::Match => None,
                CallerBindingVerdict::Mismatch { explanation } => Some(explanation.clone()),
            },
            engine: self.engine.clone(),
        }
    }
}

/// The binding target of `manifest_store` under the policy `options`
/// selects (`spec_version`/`strict_conformance` only). `Ok(None)` when the
/// active claim has no unique operative hard binding. A `c2pa.compound.content`
/// binding is a target only for a [`CawgStoreHost::HostLess`] store.
pub fn binding_target(
    manifest_store: &[u8],
    host: CawgStoreHost,
    options: &VerifyOptions,
) -> Result<Option<ManifestBindingTarget>, Error> {
    let profile = resolve_profile(options.spec_version.as_deref(), options.strict_conformance)?;
    check_store_size(manifest_store)?;
    let target = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kernel_binding_target(manifest_store, host == CawgStoreHost::HostLess, profile)
    }))
    .map_err(|_| Error::Verification("binding target derivation panicked".into()))?
    .map_err(map_validate_error)?;
    Ok(target.map(ManifestBindingTarget::from))
}

/// The carrier format a content MIME type names, for the binding
/// assertion's format-specific schema rules. `None` for opaque bytes.
fn content_format(content_mime: &str) -> (String, Option<AssetFormat>) {
    let mime = canonicalize_mime(content_mime);
    let format = AssetFormat::from_mime(&mime);
    (mime, format)
}

fn verify_caller_binding(
    manifest_store: &[u8],
    content_mime: &str,
    host: CawgStoreHost,
    evidence: &CallerBindingEvidence,
    resolved: &ResolvedOptions,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerificationReport, Error> {
    check_store_size(manifest_store)?;
    let (mime, format) = content_format(content_mime);
    let kernel_evidence = evidence.kernel();
    let input = resolved.input(&[], &mime);
    let output = contained(|| {
        verify_store_binding(
            manifest_store,
            StoreBinding::Caller {
                evidence: &kernel_evidence,
                host_less: host == CawgStoreHost::HostLess,
                format,
            },
            &input,
            cawg_inputs,
        )
    })?;
    Ok(report_from_output(output, mime, resolved))
}

/// Full standard validation of `manifest_store` with the asset byte
/// comparison supplied by a trusted caller's engine.
///
/// PRECONDITION: the caller's own engine compared the exact asset bytes with
/// the binding assertion `evidence.target()` names. This function never
/// reads the asset and cannot detect a false [`CallerBindingVerdict::Match`].
///
/// Everything else runs exactly as for an embedded manifest, under the policy
/// `options.spec_version` selects: claim structure, assertion, action,
/// ingredient and redaction rules, hashed-URI bindings, the binding
/// assertion's own schema, the claim signature, time stamps, revocation,
/// trust and CAWG identity. A match never removes another failure. Evidence
/// whose target differs from this store's derived target is refused with
/// `com.encypher.hardBinding.callerEvidenceMismatch`, and every evidence-based
/// result carries the informational `com.encypher.hardBinding.callerVerified`
/// naming the engine. `content_mime` is the asset's media type; it selects
/// format-specific schema rules only. Never fetches; `online: Some(true)` is
/// refused.
pub fn verify_with_caller_verified_binding(
    manifest_store: &[u8],
    content_mime: &str,
    host: CawgStoreHost,
    evidence: &CallerBindingEvidence,
    options: &VerifyOptions,
    graph_inputs: GraphInputs<'_>,
) -> Result<VerificationReport, Error> {
    if options.online == Some(true) {
        return Err(Error::Verification(
            "online must not be Some(true): caller-verified binding never fetches".into(),
        ));
    }
    let resolved = ResolvedOptions::resolve(options)?;
    let cawg_inputs = CawgTrustInputs::new(
        resolved.cawg_trust(),
        resolved.cawg_allowed_certs(),
        resolved.cawg_document_signing_require_anchor,
        options.cawg_did_documents.as_ref(),
        options.cawg_ica_trusted_issuers.as_deref(),
        options.cawg_ica_trust_anchors.as_deref(),
        options.cawg_ica_status_lists.as_ref(),
        graph_inputs,
    );
    verify_caller_binding(
        manifest_store,
        content_mime,
        host,
        evidence,
        &resolved,
        cawg_inputs,
    )
}

/// [`verify_with_caller_verified_binding`] with the policy, validation instant
/// and every CAWG input taken from `evaluator`; `options` supplies only C2PA
/// trust material and offline evidence (see the evaluator's option rules).
/// The CAWG identity step runs once, inside the single pass.
pub fn verify_with_caller_verified_binding_and_cawg(
    manifest_store: &[u8],
    content_mime: &str,
    host: CawgStoreHost,
    evidence: &CallerBindingEvidence,
    options: &VerifyOptions,
    evaluator: &CawgEvaluator,
    graph_inputs: GraphInputs<'_>,
) -> Result<VerificationReport, Error> {
    let resolved = evaluator.pass_options(options)?;
    verify_caller_binding(
        manifest_store,
        content_mime,
        host,
        evidence,
        &resolved,
        evaluator.cawg_inputs(graph_inputs),
    )
}

/// Verify an asset's embedded manifest with the policy, validation instant
/// and CAWG configuration of `evaluator`. `options` supplies only C2PA trust
/// material and offline evidence. Never fetches; sends no telemetry.
pub fn verify_with_cawg(
    data: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
    evaluator: &CawgEvaluator,
    graph_inputs: GraphInputs<'_>,
) -> Result<VerificationReport, Error> {
    let resolved = evaluator.pass_options(options)?;
    let mime = resolve_mime(mime_type, resolved.profile)?;
    require_embedded_mime(&mime, resolved.profile)?;
    let input = resolved.input(data, &mime);
    let output = contained(|| {
        verify_with_cawg_options_and_graph_inputs_safe(
            &input,
            evaluator.resolved.cawg_trust(),
            evaluator.resolved.cawg_allowed_certs(),
            evaluator.resolved.cawg_document_signing_require_anchor,
            evaluator.did_documents.as_ref(),
            evaluator.ica_trusted_issuers.as_deref(),
            evaluator.ica_trust_anchors.as_deref(),
            evaluator.ica_status_lists.as_ref(),
            graph_inputs,
        )
    })?;
    Ok(report_from_output(output, mime, &resolved))
}

/// Verify an asset against a separately supplied manifest store with the
/// policy, validation instant and CAWG configuration of `evaluator`. Any
/// well-formed media type is accepted; one without an embedded carrier is
/// hashed as opaque bytes. Never fetches; sends no telemetry.
pub fn verify_with_manifest_store_and_cawg(
    asset: &[u8],
    manifest_store: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
    evaluator: &CawgEvaluator,
    graph_inputs: GraphInputs<'_>,
) -> Result<VerificationReport, Error> {
    let resolved = evaluator.pass_options(options)?;
    let mime = resolve_detached_mime(mime_type, resolved.profile)?;
    check_store_size(manifest_store)?;
    let input = resolved.input(asset, &mime);
    let output = contained(|| {
        verify_detached_safe(
            manifest_store,
            asset,
            &mime,
            &input,
            evaluator.resolved.cawg_trust(),
            evaluator.resolved.cawg_allowed_certs(),
            evaluator.resolved.cawg_document_signing_require_anchor,
            evaluator.did_documents.as_ref(),
            evaluator.ica_trusted_issuers.as_deref(),
            evaluator.ica_trust_anchors.as_deref(),
            evaluator.ica_status_lists.as_ref(),
            graph_inputs,
        )
    })?;
    Ok(report_from_output(output, mime, &resolved))
}

/// Verify a fragmented BMFF stream with the policy, validation instant and
/// CAWG configuration of `evaluator`. `options.expected_seek_positions` marks
/// intentional discontinuities. Never fetches; sends no telemetry.
pub fn verify_fragmented_with_cawg(
    init_segment: &[u8],
    fragments: &[&[u8]],
    mime_type: &str,
    options: &VerifyOptions,
    evaluator: &CawgEvaluator,
    graph_inputs: GraphInputs<'_>,
) -> Result<VerificationReport, Error> {
    let resolved = evaluator.pass_options(options)?;
    let mime = resolve_mime(mime_type, resolved.profile)?;
    if AssetFormat::from_mime(&mime) != Some(AssetFormat::Bmff) {
        return Err(Error::UnsupportedMime(mime));
    }
    let input = resolved.input(init_segment, &mime);
    let output = contained(|| {
        verify_fragmented_with_cawg_options_and_expected_seeks_safe(
            &input,
            fragments,
            &options.expected_seek_positions,
            evaluator.resolved.cawg_trust(),
            evaluator.resolved.cawg_allowed_certs(),
            evaluator.resolved.cawg_document_signing_require_anchor,
            evaluator.did_documents.as_ref(),
            evaluator.ica_trusted_issuers.as_deref(),
            evaluator.ica_trust_anchors.as_deref(),
            evaluator.ica_status_lists.as_ref(),
            graph_inputs,
        )
    })?;
    Ok(report_from_output(output, mime, &resolved))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cawg_profile_accepts_strict_25_core_and_refuses_program() {
        let strict_core = CawgProfile::new("2.5", true, false).unwrap();
        assert_eq!(strict_core.profile.mode, OperatingMode::Conformance);
        assert_eq!(strict_core.profile.compliance, ComplianceLevel::CoreSpec);
        assert!(CawgProfile::new("2.5", true, true).is_err());
        assert!(CawgProfile::new("2.5", false, true).is_err());
    }
}
