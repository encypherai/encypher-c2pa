// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Store-level CAWG identity evaluation for a caller that verifies the
//! asset's content binding with its own engine.
//!
//! Every other entry point in this crate binds the manifest to the asset
//! before it reports an identity. This one does not: it hashes no asset
//! content, so it can report `cawg.identity.trusted` for a store whose content
//! nobody checked. It exists for a caller that has already verified the hard
//! binding and every other C2PA check for the exact same store bytes, and it
//! is compiled only with the non-default `caller-verified-binding` feature.

use crate::c2pa_core::{ComplianceLevel, EngineProfile, OperatingMode, SpecVersion};
use crate::c2pa_validate::{verify_identity_with_caller_verified_binding, CawgTrustInputs};
use crate::{
    copy_status, map_validate_error, Error, ResolvedOptions, ValidationResults, VerifyOptions,
    MAX_MANIFEST_STORE_BYTES,
};

/// Spec revisions the evaluator accepts, as the private CLI spells them.
const SPEC_VERSIONS: [&str; 6] = ["1.4", "2.0", "2.1", "2.2", "2.3", "2.4"];

/// The caller's engine profile: spec revision, operating mode, and
/// compliance bar. `VerifyOptions::strict_conformance` can only express 2.4
/// generous or 2.4 strict, so the evaluator takes the profile explicitly.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CawgProfile {
    profile: EngineProfile,
}

impl CawgProfile {
    /// `spec_version` is one of "1.4", "2.0", "2.1", "2.2", "2.3", "2.4".
    /// `conformance_mode` selects the conformance operating mode, and
    /// `compliance_program` the conformance-program compliance bar.
    pub fn new(
        spec_version: &str,
        conformance_mode: bool,
        compliance_program: bool,
    ) -> Result<Self, Error> {
        let version = SPEC_VERSIONS
            .contains(&spec_version)
            .then(|| SpecVersion::from_str(spec_version))
            .flatten()
            .ok_or_else(|| {
                Error::Verification(format!(
                    "spec_version {spec_version:?} is not one of {}",
                    SPEC_VERSIONS.join(", ")
                ))
            })?;
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
        /// Expanded-domain SHA-256 of every manifest in the store, keyed by
        /// label, in store order. The caller compares the whole map with its
        /// own parse before using the statuses.
        store_manifest_sha256: Vec<(String, [u8; 32])>,
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
/// evidence input once.
pub struct CawgEvaluator {
    resolved: ResolvedOptions,
    options: VerifyOptions,
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
    /// Posture comes only from `profile`. `strict_conformance: true`,
    /// `online: Some(true)`, and a non-empty `external_data` are rejected:
    /// this evaluator never fetches, and a posture flag that disagreed with
    /// `profile` would be ambiguous.
    pub fn new(options: &VerifyOptions, profile: &CawgProfile) -> Result<Self, Error> {
        if options.strict_conformance {
            return Err(Error::Verification(
                "strict_conformance must be false: the evaluator takes its posture from CawgProfile"
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
        let mut resolved = ResolvedOptions::resolve(options)?;
        resolved.profile = profile.profile;
        Ok(Self {
            resolved,
            options: options.clone(),
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
        let cawg_inputs = CawgTrustInputs::new(
            self.resolved.cawg_trust(),
            self.resolved.cawg_allowed_certs(),
            self.resolved.cawg_document_signing_require_anchor,
            self.options.cawg_did_documents.as_ref(),
            self.options.cawg_ica_trusted_issuers.as_deref(),
            self.options.cawg_ica_trust_anchors.as_deref(),
            self.options.cawg_ica_status_lists.as_ref(),
        );
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
                store_manifest_sha256: output.store_manifest_sha256,
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
