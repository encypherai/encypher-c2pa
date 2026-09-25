// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Conformance-program SHOULD-to-SHALL upgrades.
//!
//! The C2PA core technical specification makes usable revocation information
//! and a trusted time-stamp recommendations. The 2.4 Conformance Program turns
//! both into requirements. Neither outcome has a registered C2PA status code -
//! `timeStamp.missing` in particular is not in the 2.4 registry - so each is
//! reported under an entity-namespaced `com.encypher.*` code, which VAL-STRU-0002
//! permits and which keeps the public report free of invented `c2pa`-style
//! codes.
//!
//! The registered informational codes (`signingCredential.ocsp.skipped`) stay
//! exactly where the core spec puts them; the program code is an additional
//! failure, never a duplicate of a registered code in the wrong bucket.

use super::{
    ComplianceLevel, ValidationResults, SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
    SIGNING_CREDENTIAL_OCSP_SKIPPED, SIGNING_CREDENTIAL_OCSP_UNKNOWN, TIME_STAMP_TRUSTED,
};

/// Conformance-mode only: the asset format is outside the certified scope.
pub const CONFORMANCE_OUT_OF_SCOPE: &str = "com.encypher.conformance.outOfScope";
/// Conformance-mode only: the manifest does not conform to the target spec.
pub const CONFORMANCE_SPEC_VERSION_NONCONFORMANT: &str =
    "com.encypher.conformance.specVersionNonConformant";

/// Conformance program only: no usable revocation information was available,
/// which the core spec reports as the informational
/// `signingCredential.ocsp.skipped`.
pub const PROGRAM_REVOCATION_INFORMATION_MISSING: &str =
    "com.encypher.conformance.revocationInformationMissing";
/// Conformance program only: no trusted RFC 3161 time-stamp was established.
pub const PROGRAM_TRUSTED_TIMESTAMP_MISSING: &str =
    "com.encypher.conformance.trustedTimeStampMissing";

/// Every conformance-program-only failure code, in the order they are emitted.
///
/// The verdict layer consults this set so program policy outcomes are treated
/// as policy, not as construction-integrity defects.
pub const PROGRAM_FAILURE_CODES: &[&str] = &[
    PROGRAM_REVOCATION_INFORMATION_MISSING,
    PROGRAM_TRUSTED_TIMESTAMP_MISSING,
];

/// Apply the conformance-program upgrades to an otherwise fully evaluated
/// manifest. A no-op under [`ComplianceLevel::CoreSpec`], so core-spec
/// validation stays strictly more permissive and the two levels remain
/// directly comparable on the same manifest.
pub fn apply_compliance_upgrades(
    results: &mut ValidationResults,
    compliance: ComplianceLevel,
    sig_url: &str,
) {
    if compliance != ComplianceLevel::ConformanceProgram {
        return;
    }
    // The program bar asks for *usable* revocation information. A `good`
    // online response supplies it, and suppresses `ocsp.skipped` entirely. An
    // `unknown` or `inaccessible` answer is a query that happened and settled
    // nothing, so it fails the same bar as never asking.
    if results.has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED)
        || results.has_informational(SIGNING_CREDENTIAL_OCSP_UNKNOWN)
        || results.has_informational(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
    {
        results.push_failure(
            PROGRAM_REVOCATION_INFORMATION_MISSING,
            sig_url.to_string(),
            "conformance program requires usable revocation information (SHALL); the core spec reports this as signingCredential.ocsp.skipped, .unknown, or .inaccessible".into(),
        );
    }
    if !results.has_success(TIME_STAMP_TRUSTED) {
        results.push_failure(
            PROGRAM_TRUSTED_TIMESTAMP_MISSING,
            sig_url.to_string(),
            "conformance program requires a trusted time-stamp (SHALL)".into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_validate::{EngineProfile, SpecVersion};

    fn with_skipped_ocsp() -> ValidationResults {
        let mut results = ValidationResults::default();
        results.push_informational(
            SIGNING_CREDENTIAL_OCSP_SKIPPED,
            "url".into(),
            "no staple".into(),
        );
        results
    }

    fn codes(results: &ValidationResults) -> Vec<&str> {
        results
            .failure
            .iter()
            .map(|status| status.code.as_str())
            .collect()
    }

    #[test]
    fn core_spec_validation_adds_no_program_failures() {
        let mut results = with_skipped_ocsp();
        apply_compliance_upgrades(&mut results, ComplianceLevel::CoreSpec, "url");
        assert!(results.failure.is_empty());
    }

    #[test]
    fn program_outcomes_use_entity_namespaced_codes_only() {
        let mut results = with_skipped_ocsp();
        apply_compliance_upgrades(&mut results, ComplianceLevel::ConformanceProgram, "url");

        // `timeStamp.missing` is not in the C2PA 2.4 status registry, and
        // duplicating the registered informational `signingCredential.ocsp.skipped`
        // into the failure bucket would report a registered code in a category
        // the registry does not define for it.
        assert_eq!(
            codes(&results),
            vec![
                PROGRAM_REVOCATION_INFORMATION_MISSING,
                PROGRAM_TRUSTED_TIMESTAMP_MISSING
            ]
        );
        assert!(!results.has_failure(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        assert!(results.has_informational(SIGNING_CREDENTIAL_OCSP_SKIPPED));
        for status in &results.failure {
            assert!(
                status.code.starts_with("com.encypher."),
                "program-only outcome {} must be entity-namespaced",
                status.code
            );
        }
    }

    #[test]
    fn a_trusted_timestamp_clears_the_timestamp_requirement() {
        let mut results = ValidationResults::default();
        results.push_success(TIME_STAMP_TRUSTED, "url".into(), "trusted".into());
        apply_compliance_upgrades(&mut results, ComplianceLevel::ConformanceProgram, "url");
        assert!(results.failure.is_empty());
    }

    #[test]
    fn program_failures_still_invalidate_under_the_strict_verdict() {
        let mut results = with_skipped_ocsp();
        apply_compliance_upgrades(&mut results, ComplianceLevel::ConformanceProgram, "url");
        // Renaming the codes must not soften the program bar.
        assert_eq!(
            super::super::compute_state(&results, EngineProfile::strict(SpecVersion::V2_4)),
            super::super::ValidationState::Invalid
        );
    }
}
