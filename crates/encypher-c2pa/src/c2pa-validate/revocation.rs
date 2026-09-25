// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Resolving embedded OCSP evidence when stapled responses disagree.
//!
//! A manifest store may staple several OCSP responses for the same certificate.
//! VAL-STRU-0027 tells a validator to "try each one until one successfully
//! passes validation (and then should ignore the others)", and VAL-CRYP-0034
//! issues `signingCredential.ocsp.notRevoked` when the conditions hold "for any
//! OCSP response in the C2PA Manifest Store". Read literally, one qualifying
//! `good` response settles the question even when another response says
//! `revoked`.
//!
//! That reading is applied under the conformance posture only. The default
//! posture stays fail-closed: a signer who staples a revoked response is
//! describing a revoked certificate, and no C2PA rule obliges a verifier to
//! ignore evidence it has already verified. Whenever the two postures would
//! disagree, the conformance posture reports the outranked revoked response
//! under [`OCSP_CONFLICTING_REVOKED_RESPONSE`] so the deviation is visible.

use crate::c2pa_trust::OcspStatus;

/// Informational: a verified revoked OCSP response was outranked by a
/// qualifying good response for the same certificate.
///
/// Entity-namespaced because C2PA 2.4 registers no code for the conflict;
/// VAL-STRU-0002 permits `com.<entity>.` codes.
pub const OCSP_CONFLICTING_REVOKED_RESPONSE: &str = "com.encypher.ocsp.conflictingRevokedResponse";

/// Evidence accumulated for one certificate across every stapled response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CertificateEvidence {
    /// Order-independent, fail-closed merge of every qualifying response.
    merged: Option<OcspStatus>,
    /// At least one qualifying response established `good`.
    any_good: bool,
}

impl CertificateEvidence {
    /// Fold one response's verified status into this certificate's evidence.
    pub(super) fn absorb(&mut self, candidate: Option<OcspStatus>) {
        // `merge` is what decides whether a status is affirmative evidence of
        // non-revocation, so `removeFromCRL` counts as good here exactly as it
        // does there.
        self.any_good |= OcspStatus::merge(None, candidate) == Some(OcspStatus::Good);
        self.merged = OcspStatus::merge(self.merged, candidate);
    }

    /// The status to act on, and whether a revoked response was outranked.
    pub(super) fn resolve(self, any_good_wins: bool) -> (Option<OcspStatus>, bool) {
        let outranked = any_good_wins
            && self.any_good
            && matches!(self.merged, Some(OcspStatus::Revoked { .. }));
        if outranked {
            (Some(OcspStatus::Good), true)
        } else {
            (self.merged, false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn revoked() -> OcspStatus {
        OcspStatus::Revoked {
            revocation_time: OffsetDateTime::UNIX_EPOCH,
            reason: Some(crate::c2pa_trust::ocsp::OcspRevocationReason::KeyCompromise),
        }
    }

    fn evidence(statuses: impl IntoIterator<Item = Option<OcspStatus>>) -> CertificateEvidence {
        let mut evidence = CertificateEvidence::default();
        for status in statuses {
            evidence.absorb(status);
        }
        evidence
    }

    #[test]
    fn a_good_response_outranks_a_revoked_one_only_under_the_conformance_posture() {
        // Order must not matter: the same pair of responses in either sequence
        // resolves the same way.
        for pair in [
            [Some(revoked()), Some(OcspStatus::Good)],
            [Some(OcspStatus::Good), Some(revoked())],
        ] {
            let evidence = evidence(pair);
            assert_eq!(
                evidence.resolve(false),
                (Some(revoked()), false),
                "the default posture stays fail-closed"
            );
            assert_eq!(
                evidence.resolve(true),
                (Some(OcspStatus::Good), true),
                "VAL-STRU-0027: any qualifying good response settles the status"
            );
        }
    }

    #[test]
    fn a_lone_revoked_response_is_revoked_under_both_postures() {
        let evidence = evidence([Some(revoked()), Some(OcspStatus::Unknown), None]);
        assert_eq!(evidence.resolve(false), (Some(revoked()), false));
        assert_eq!(
            evidence.resolve(true),
            (Some(revoked()), false),
            "with no good response there is nothing to outrank and no conflict to report"
        );
    }

    #[test]
    fn a_lone_good_response_reports_no_conflict() {
        let evidence = evidence([Some(OcspStatus::Good), Some(OcspStatus::Unknown)]);
        for posture in [false, true] {
            assert_eq!(evidence.resolve(posture), (Some(OcspStatus::Good), false));
        }
    }
}
