// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! CAWG Identity 1.3 assertion validation.
//!
//! The validator is deliberately offline. It fully validates the X.509/COSE
//! profile (`cawg.x509.cose`) and the identity-claims-aggregation profile
//! (`cawg.identity_claims_aggregation`, see [`super::cawg_ica`]). ICA `did:web`
//! issuers resolve only against a caller-pinned DID-document store; anything
//! needing live resolution fails closed rather than being presented as trusted.

use std::collections::{HashMap, HashSet};

use crate::c2pa_cbor::{encode, Profile, Value};
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_crypto::{
    extract_claim_tsa_tokens, extract_x5chain, protected_iat, timestamp_assertion_input,
    timestamp_input, verify_claim, ClaimTimestampVersion, CryptoError,
};
use crate::c2pa_trust::{
    certificate_eku_oids_der, certificate_policy_oids_der, certificate_valid_at,
    leaf_profile_acceptable_der, validate_chain, AnchorPurpose, CawgTrustSource, TrustAnchor,
    TrustList,
};
use serde_json::json;
use time::OffsetDateTime;

use super::ingredient_graph::ReachedManifest;
use super::timestamp_assertion::{
    numeric_date_to_time, validate_token, TimestampAssertionIndex, TokenFailure, TokenOutcome,
};
use super::{
    evaluate_embedded_ocsp, is_supported_hard_binding_label, ClaimAssertionReference,
    ClaimAssertionRefs, EmbeddedOcspStatus as IdentityRevocationStatus, OnlineOcspVerdict,
    ValidationResults,
};

pub const CAWG_IDENTITY_TRUSTED: &str = "cawg.identity.trusted";
pub const CAWG_IDENTITY_WELL_FORMED: &str = "cawg.identity.well-formed";
pub const CAWG_IDENTITY_CBOR_INVALID: &str = "cawg.identity.cbor.invalid";
pub const CAWG_IDENTITY_ASSERTION_MISMATCH: &str = "cawg.identity.assertion.mismatch";
pub const CAWG_IDENTITY_ASSERTION_DUPLICATE: &str = "cawg.identity.assertion.duplicate";
pub const CAWG_IDENTITY_HARD_BINDING_MISSING: &str = "cawg.identity.hard_binding_missing";
pub const CAWG_IDENTITY_HARD_BINDING_INCORRECT: &str = "cawg.identity.hard_binding_incorrect";
pub const CAWG_IDENTITY_SIG_TYPE_UNKNOWN: &str = "cawg.identity.sig_type.unknown";
pub const CAWG_IDENTITY_PAD_INVALID: &str = "cawg.identity.pad.invalid";
pub const CAWG_IDENTITY_CREDENTIAL_REVOKED: &str = "cawg.identity.credential_revoked";
/// Validation could not complete without network access this verifier never
/// performs. The 1.3 status-code table registers `network_traffic_blocked`;
/// the non-normative note in the credential-types overview says
/// `network_traffic_required`, and the normative table wins.
pub const CAWG_IDENTITY_NETWORK_TRAFFIC_BLOCKED: &str = "cawg.identity.network_traffic_blocked";
pub const CAWG_ICA_DID_UNAVAILABLE: &str = "cawg.ica.did_unavailable";
pub const CAWG_X509_ALGORITHM_UNSUPPORTED: &str = "cawg.x509.algorithm.unsupported";
pub const CAWG_X509_CREDENTIAL_TRUSTED: &str = "cawg.x509.credential.trusted";
pub const CAWG_X509_CREDENTIAL_UNTRUSTED: &str = "cawg.x509.credential.untrusted";
pub const CAWG_X509_SIGNATURE_VALIDATED: &str = "cawg.x509.signature.validated";
pub const CAWG_X509_SIGNATURE_MISMATCH: &str = "cawg.x509.signature.mismatch";
pub const CAWG_X509_SIGNATURE_INSIDE_VALIDITY: &str = "cawg.x509.signature.inside_validity";
pub const CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY: &str = "cawg.x509.signature.outside_validity";
pub const CAWG_X509_TIME_STAMP_TRUSTED: &str = "cawg.x509.time_stamp.trusted";
pub const CAWG_X509_TIME_STAMP_VALIDATED: &str = "cawg.x509.time_stamp.validated";
pub const CAWG_X509_TIME_STAMP_MALFORMED: &str = "cawg.x509.time_stamp.malformed";
pub const CAWG_X509_TIME_STAMP_MISMATCH: &str = "cawg.x509.time_stamp.mismatch";
pub const CAWG_X509_TIME_STAMP_UNTRUSTED: &str = "cawg.x509.time_stamp.untrusted";
pub const CAWG_X509_TIME_STAMP_OUTSIDE_VALIDITY: &str = "cawg.x509.time_stamp.outside_validity";
pub const CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID: &str = "cawg.x509.time_stamp.credential_invalid";
pub const CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY: &str =
    "cawg.x509.time_of_signing.inside_validity";
pub const CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY: &str =
    "cawg.x509.time_of_signing.outside_validity";
pub const CAWG_X509_OCSP_NOT_REVOKED: &str = "cawg.x509.ocsp.not_revoked";
pub const CAWG_X509_OCSP_SKIPPED: &str = "cawg.x509.ocsp.skipped";
/// An online OCSP query for the identity certificate returned no usable answer.
pub const CAWG_X509_OCSP_INACCESSIBLE: &str = "cawg.x509.ocsp.inaccessible";
/// An OCSP response reported `unknown` for the identity certificate.
pub const CAWG_X509_OCSP_UNKNOWN: &str = "cawg.x509.ocsp.unknown";
/// Vendor-namespaced informational status for an explicitly enabled legacy
/// field-order signer-payload retry.
pub const CAWG_LEGACY_PROFILE: &str = "com.encypher.cawg.legacyProfile";

const CAWG_X509_COSE: &str = "cawg.x509.cose";
const CAWG_ICA_COSE: &str = "cawg.identity_claims_aggregation";
const OID_KP_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";
const OID_KP_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
const MAX_IDENTITY_ASSERTIONS: usize = 64;

fn is_identity_assertion_label(label: &str) -> bool {
    label == "cawg.identity"
        || label
            .strip_prefix("cawg.identity__")
            .is_some_and(|instance| !instance.is_empty())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IdentityWorkCounts {
    identity_evaluations: usize,
    cryptographic_evaluations: usize,
    ocsp_evaluations: usize,
}

#[cfg(test)]
std::thread_local! {
    static IDENTITY_WORK_COUNTS: std::cell::Cell<IdentityWorkCounts> =
        std::cell::Cell::new(IdentityWorkCounts::default());
}

#[cfg(test)]
fn record_identity_work(update: impl FnOnce(&mut IdentityWorkCounts)) {
    IDENTITY_WORK_COUNTS.with(|counts| {
        let mut current = counts.get();
        update(&mut current);
        counts.set(current);
    });
}

#[cfg(test)]
fn reset_identity_work_counts() {
    IDENTITY_WORK_COUNTS.with(|counts| counts.set(IdentityWorkCounts::default()));
}

#[cfg(test)]
fn identity_work_counts() -> IdentityWorkCounts {
    IDENTITY_WORK_COUNTS.with(std::cell::Cell::get)
}
const S_MIME_INTERIM_CUTOFF_UNIX: i64 = 1_806_537_600;
const CAWG_SMIME_POLICY_OIDS: [&str; 6] = [
    "2.23.140.1.5.2.2",
    "2.23.140.1.5.2.3",
    "2.23.140.1.5.3.2",
    "2.23.140.1.5.3.3",
    "2.23.140.1.5.4.2",
    "2.23.140.1.5.4.3",
];

/// What the recursive ingredient walk contributes to identity validation.
///
/// Both members describe assertions that live outside the manifest carrying
/// the identity, and both are needed because CAWG identity signs C2PA
/// hashed-URIs, not labels: an identity may reference an assertion in a
/// manifest the active claim reached through its ingredients, and an identity
/// inside an update manifest references a hard binding that update manifest is
/// forbidden to carry itself.
#[derive(Default, Clone, Copy)]
pub(super) struct IngredientResolution<'a> {
    /// Claims of the ingredient manifests the recursive walk reached. A
    /// manifest the walk did not reach is not in this list, so a store
    /// passenger no claim vouches for can never satisfy a reference.
    pub claims: &'a [ReachedManifest],
    /// The hard binding an update manifest inherits through its `parentOf`
    /// chain, when the active manifest is one (C2PA 2.4 Validation, "Validate
    /// the Asset's Content").
    pub inherited_binding: Option<InheritedBinding<'a>>,
}

/// The hard binding an update manifest inherits: the standard manifest that
/// declares it, that manifest's claim reference to it, and the claim's own
/// hash algorithm, which the reference inherits when it omits `alg`.
#[derive(Clone, Copy)]
pub(super) struct InheritedBinding<'a> {
    pub manifest: &'a str,
    pub reference: &'a Value,
    pub claim_alg: Option<&'a str>,
}

pub(super) struct IdentityContext<'a> {
    pub manifest: &'a ParsedManifest<'a>,
    pub claim: &'a Value,
    pub validation_time: OffsetDateTime,
    pub claim_timestamp: Option<OffsetDateTime>,
    pub cawg_trust: Option<&'a TrustList>,
    pub cawg_allowed_certs: Option<&'a TrustList>,
    /// Current time used for embedded OCSP response freshness.
    pub ocsp_verification_time: OffsetDateTime,
    pub document_signing_require_anchor: bool,
    pub tsa_trust: Option<&'a TrustList>,
    /// Store-wide `c2pa.time-stamp` assertions, keyed by C2PA Manifest
    /// identifier. CAWG 1.3 consults this mapping for the manifest that
    /// contains the identity assertion.
    pub timestamp_index: &'a TimestampAssertionIndex,
    pub did_documents: Option<&'a HashMap<String, serde_json::Value>>,
    /// Explicit compatibility opt-in for non-deterministic field-order CBOR.
    pub allow_legacy_encoding: bool,
    pub ica_trusted_issuers: Option<&'a [String]>,
    pub ica_trust_anchors: Option<&'a [String]>,
    pub ica_status_lists: Option<&'a HashMap<String, String>>,
    /// Network-obtained material the caller supplied, used here for online
    /// OCSP responses about identity certificates.
    pub evidence: super::OnlineEvidence<'a>,
    /// Ingredient-scoped resolution inputs from the recursive walk.
    pub ingredients: IngredientResolution<'a>,
    pub results: &'a mut ValidationResults,
}

/// Validate every CAWG identity assertion in the active manifest.
pub(super) fn verify_identity_assertions(
    ctx: &mut IdentityContext<'_>,
    claim_refs: &ClaimAssertionRefs<'_>,
    primary_binding: Option<&ClaimAssertionReference<'_>>,
    certificate_status_assertions: &[&[u8]],
) {
    let identity_count = claim_refs
        .references
        .iter()
        .filter(|reference| reference.label.is_some_and(is_identity_assertion_label))
        .count();
    if identity_count > MAX_IDENTITY_ASSERTIONS {
        ctx.results.push_failure(
            CAWG_IDENTITY_CBOR_INVALID,
            format!("self#jumbf=/c2pa/{}", ctx.manifest.label),
            format!(
                "manifest has {identity_count} CAWG identities; maximum is {MAX_IDENTITY_ASSERTIONS}"
            ),
        );
        return;
    }

    for reference in &claim_refs.references {
        let Some(label) = reference.label else {
            continue;
        };
        if !is_identity_assertion_label(label) {
            continue;
        }
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        verify_identity_assertion(
            ctx,
            assertion,
            claim_refs,
            primary_binding,
            certificate_status_assertions,
            label,
        );
    }
}

/// Validate one CAWG identity assertion.
///
/// `url` is the `url` field every status this function reports carries. CAWG
/// Identity 1.3 status-codes: "The `url` field for a status code MUST always
/// be the label of the identity assertion", so it is the assertion label
/// (`cawg.identity`, `cawg.identity__1`, ...) and not a JUMBF URI. The claim
/// references the assertion by URI, which is rebuilt where that comparison is
/// made.
fn verify_identity_assertion(
    ctx: &mut IdentityContext<'_>,
    assertion: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    primary_binding: Option<&ClaimAssertionReference<'_>>,
    certificate_status_assertions: &[&[u8]],
    url: &str,
) {
    #[cfg(test)]
    record_identity_work(|counts| counts.identity_evaluations += 1);
    if !map_keys_are_unique(assertion) {
        invalid_cbor(
            ctx.results,
            url,
            "identity assertion contains a duplicate CBOR map key",
        );
        return;
    }
    let identity_uri = format!(
        "self#jumbf=/c2pa/{}/c2pa.assertions/{url}",
        ctx.manifest.label
    );
    let claim_binds_identity = claim_refs.references.iter().any(|reference| {
        reference
            .value
            .get("url")
            .and_then(Value::as_text)
            .is_some_and(|reference_url| reference_targets_identity(reference_url, &identity_uri))
    });
    if !claim_binds_identity {
        ctx.results.push_failure(
            CAWG_IDENTITY_ASSERTION_MISMATCH,
            url.into(),
            "identity assertion is not referenced by the claim".into(),
        );
        return;
    }
    let Some(signer_payload) = assertion.get("signer_payload") else {
        invalid_cbor(ctx.results, url, "signer_payload is missing");
        return;
    };
    let Some(referenced) = valid_signer_payload(signer_payload) else {
        invalid_cbor(
            ctx.results,
            url,
            "signer_payload violates the CAWG Identity 1.3 CDDL",
        );
        return;
    };
    let Some(signature) = assertion.get("signature").and_then(Value::as_bytes) else {
        invalid_cbor(
            ctx.results,
            url,
            "signature is missing or is not a byte string",
        );
        return;
    };
    if signature.is_empty() {
        invalid_cbor(ctx.results, url, "signature is empty");
        return;
    }
    if !valid_padding(assertion.get("pad1"), true) || !valid_padding(assertion.get("pad2"), false) {
        ctx.results.push_failure(
            CAWG_IDENTITY_PAD_INVALID,
            url.into(),
            "pad1 or pad2 is missing, not a byte string, or contains non-zero bytes".into(),
        );
        return;
    }
    let sig_type = signer_payload
        .get("sig_type")
        .and_then(Value::as_text)
        .expect("shape validator guarantees sig_type");
    let referenced_identity = referenced.iter().any(|reference| {
        reference
            .get("url")
            .and_then(Value::as_text)
            .and_then(|url| super::assertion_label_for_manifest(url, &ctx.manifest.label))
            .is_some_and(is_identity_assertion_label)
    });
    let reference_cycle = identity_reference_cycle(claim_refs, &ctx.manifest.label, url);

    // The hash algorithm a referenced assertion inherits when it omits `alg`.
    let claim_alg = ctx.claim.get("alg").and_then(Value::as_text);
    let mut unique = HashSet::with_capacity(referenced.len());
    let mut duplicate = false;
    let mut mismatch = false;
    for reference in referenced {
        let encoded =
            encode(reference, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
        duplicate |= !unique.insert(encoded);
        // A referenced assertion lives in this manifest's claim, or - because
        // the identity signs hashed-URIs and C2PA 2.4 validates the ingredient
        // manifests recursively - in the claim of a manifest the ingredient
        // walk reached.
        mismatch |= !claim_refs
            .references
            .iter()
            .any(|claim_ref| same_hashed_uri(reference, claim_ref.value, claim_alg))
            && !referenced_in_reached_claim(reference, claim_alg, ctx.ingredients.claims);
    }
    if duplicate {
        ctx.results.push_failure(
            CAWG_IDENTITY_ASSERTION_DUPLICATE,
            url.into(),
            "referenced_assertions contains a duplicate".into(),
        );
    }
    if mismatch || referenced_identity {
        let (explanation, reason) = if reference_cycle {
            (
                "referenced_assertions creates a CAWG identity reference cycle",
                "reference_cycle",
            )
        } else if referenced_identity {
            (
                "referenced_assertions contains another CAWG identity assertion",
                "identity_assertion_reference",
            )
        } else {
            (
                "a referenced assertion is not present in the claim",
                "missing_assertion",
            )
        };
        ctx.results.push_failure_with_details(
            CAWG_IDENTITY_ASSERTION_MISMATCH,
            url.into(),
            explanation.into(),
            json!({"reason": reason}),
        );
    }

    // An update manifest is forbidden to carry a hard binding, so an identity
    // inside one references the binding of the standard manifest its parentOf
    // chain reaches (C2PA 2.4 Validation, "Validate the Asset's Content"). The
    // inherited binding is used only when this manifest has none of its own: a
    // manifest that declares a hard binding is always judged against that one.
    let inherited = ctx
        .ingredients
        .inherited_binding
        .filter(|_| primary_binding.is_none());
    let binding_owner = match inherited {
        Some(inherited) => inherited.manifest,
        None => ctx.manifest.label.as_str(),
    };
    // Deduplicate before the hard-binding comparison: a duplicated reference is
    // reported once as `cawg.identity.assertion.duplicate` (terminal for this
    // assertion) and must not also trip the hard-binding count. Upstream
    // (c2pa-rs @ d7f13829, signer_payload.rs) judges hard-binding presence by
    // label only; per-reference hash equality is the mismatch check above.
    let mut unique_hard_bindings = HashSet::new();
    let signer_hard_bindings: Vec<&Value> = referenced
        .iter()
        .filter(|reference| {
            reference
                .get("url")
                .and_then(Value::as_text)
                .and_then(|url| {
                    super::assertion_label_for_manifest(url, &ctx.manifest.label)
                        .or_else(|| super::assertion_label_for_manifest(url, binding_owner))
                })
                .is_some_and(|label| is_supported_hard_binding_label(label, false))
        })
        .filter(|reference| {
            let encoded =
                encode(reference, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
            unique_hard_bindings.insert(encoded)
        })
        .collect();
    let hard_binding_valid = signer_hard_bindings.len() == 1
        && match (primary_binding, inherited) {
            (Some(binding), _) => {
                same_hashed_uri(signer_hard_bindings[0], binding.value, claim_alg)
            }
            // The inherited reference sits under the parent's claim, so each
            // side resolves its URI and its algorithm against its own manifest.
            (None, Some(inherited)) => {
                same_hashed_uri_across_manifests(signer_hard_bindings[0], claim_alg, inherited)
            }
            (None, None) => false,
        };
    if signer_hard_bindings.is_empty() {
        ctx.results.push_failure(
            CAWG_IDENTITY_HARD_BINDING_MISSING,
            url.into(),
            "referenced_assertions contains no hard binding".into(),
        );
    } else if !hard_binding_valid {
        ctx.results.push_failure(
            CAWG_IDENTITY_HARD_BINDING_INCORRECT,
            url.into(),
            "referenced_assertions does not contain exactly the primary hard binding".into(),
        );
    }
    if duplicate || mismatch || referenced_identity || !hard_binding_valid {
        return;
    }

    #[cfg(test)]
    record_identity_work(|counts| counts.cryptographic_evaluations += 1);

    if sig_type == CAWG_ICA_COSE {
        super::cawg_ica::verify_ica_assertion(
            signer_payload,
            signature,
            url,
            ctx.validation_time,
            ctx.claim_timestamp,
            ctx.tsa_trust,
            ctx.did_documents,
            ctx.ica_trusted_issuers,
            ctx.ica_trust_anchors,
            ctx.ica_status_lists,
            ctx.results,
        );
        return;
    }
    if sig_type != CAWG_X509_COSE {
        ctx.results.push_failure(
            CAWG_IDENTITY_SIG_TYPE_UNKNOWN,
            url.into(),
            format!("unsupported identity signature type: {sig_type}"),
        );
        return;
    }

    // CAWG Identity 1.3 requires RFC 8949 core deterministic encoding of the
    // signed `signer_payload`. A field-order retry exists only behind the
    // explicit compatibility opt-in.
    let stored_order = encode(signer_payload, Profile::LegacyPipelineBDefinite);
    let canonical = encode(signer_payload, Profile::CanonicalForHashedSubstructures);
    let (Ok(stored_order), Ok(canonical)) = (stored_order, canonical) else {
        invalid_cbor(ctx.results, url, "signer_payload cannot be re-encoded");
        return;
    };
    let chain = extract_x5chain(signature).unwrap_or_default();
    let Some(leaf) = chain.first() else {
        invalid_cbor(
            ctx.results,
            url,
            "COSE signature has no X.509 certificate chain",
        );
        return;
    };
    let mut payload_encoding = "canonical";
    let verified = verify_claim(signature, &canonical, leaf).or_else(|error| match error {
        CryptoError::UnsupportedAlg(_) => Err(error),
        _ if ctx.allow_legacy_encoding && stored_order != canonical => {
            verify_claim(signature, &stored_order, leaf)
                .map(|()| payload_encoding = "legacy-field-order")
                .map_err(|_| error)
        }
        _ => Err(error),
    });
    // 1.3 x509/validating checks the signature algorithm before anything
    // else, and an unsupported one rejects the assertion outright.
    if matches!(&verified, Err(CryptoError::UnsupportedAlg(_))) {
        ctx.results.push_failure(
            CAWG_X509_ALGORITHM_UNSUPPORTED,
            url.into(),
            "CAWG identity COSE signature uses an unsupported algorithm".into(),
        );
        return;
    }

    let attested = identity_timestamp(
        signature,
        &ctx.manifest.label,
        ctx.timestamp_index,
        ctx.tsa_trust,
        ctx.claim_timestamp,
        ctx.validation_time,
        ctx.results,
        url,
    );
    let at = attested.unwrap_or(ctx.validation_time);
    let timestamp_trusted = attested.is_some();

    #[cfg(test)]
    record_identity_work(|counts| counts.ocsp_evaluations += 1);

    // CAWG identity revocation stays fail-closed in both postures: the
    // conformance reading of VAL-STRU-0027 is a C2PA claim-signer rule, and
    // CAWG registers no code for an outranked revoked response.
    let revocation_status = evaluate_embedded_ocsp(
        signature,
        certificate_status_assertions,
        &chain,
        timestamp_trusted.then_some(at),
        ctx.ocsp_verification_time,
        ctx.cawg_trust,
        false,
    )
    .status;
    // CAWG 1.3 "Determining revocation from online OCSP response" is the same
    // procedure the C2PA claim signer follows, with CAWG's own status codes.
    let targets = super::ocsp_targets(&chain, ctx.cawg_trust);
    let online = super::evaluate_online_ocsp(
        &targets,
        ctx.evidence,
        timestamp_trusted.then_some(at),
        ctx.ocsp_verification_time,
    );
    let purpose = super::OcspPurpose::CawgIdentity {
        assertion_label: url.rsplit('/').next().unwrap_or(url).to_string(),
    };
    let leaf_revoked = match online.leaf {
        Some(OnlineOcspVerdict::NotRevoked) => {
            ctx.results.push_success(
                CAWG_X509_OCSP_NOT_REVOKED,
                url.into(),
                "online OCSP response reports the identity leaf not revoked".into(),
            );
            false
        }
        Some(OnlineOcspVerdict::Revoked) => true,
        Some(OnlineOcspVerdict::Unknown) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_UNKNOWN,
                url.into(),
                "the OCSP responder reports an unknown status for the identity certificate".into(),
            );
            false
        }
        Some(OnlineOcspVerdict::Unusable) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_INACCESSIBLE,
                url.into(),
                "the OCSP responder for the identity certificate returned no usable response"
                    .into(),
            );
            false
        }
        None => {
            match revocation_status {
                IdentityRevocationStatus::NotRevoked => ctx.results.push_success(
                    CAWG_X509_OCSP_NOT_REVOKED,
                    url.into(),
                    "verified OCSP evidence reports the identity leaf not revoked".into(),
                ),
                // No online check was made, which 1.3 reports as
                // `ocsp.skipped`, alongside the query that would settle it.
                IdentityRevocationStatus::Skipped | IdentityRevocationStatus::NotChecked => {
                    ctx.results.push_informational(
                        CAWG_X509_OCSP_SKIPPED,
                        url.into(),
                        "no online OCSP check was performed, and stapled evidence did not establish the identity leaf status"
                            .into(),
                    );
                    super::record_ocsp_needs(&targets, &purpose, &mut ctx.results.network_needs);
                }
                _ => {}
            }
            matches!(
                revocation_status,
                IdentityRevocationStatus::LeafRevoked | IdentityRevocationStatus::LeafAndCaRevoked
            )
        }
    };
    // CAWG 1.3: a revoked CA in the identity chain rejects the assertion with
    // `cawg.x509.credential.untrusted`.
    if online.ca_revoked {
        ctx.results.push_failure(
            CAWG_X509_CREDENTIAL_UNTRUSTED,
            url.into(),
            "online OCSP response reports a CA certificate in the identity chain revoked".into(),
        );
        return;
    }
    if leaf_revoked {
        ctx.results.push_failure(
            CAWG_IDENTITY_CREDENTIAL_REVOKED,
            url.into(),
            "verified OCSP evidence reports the identity signing certificate revoked".into(),
        );
        return;
    }

    // 1.3 orders the chain-of-trust rejection ahead of signature validation.
    // The cryptographic result is reported first anyway, so a consumer can
    // tell an untrusted credential that did sign these bytes from one that did
    // not. The rejection itself is unchanged: an untrusted credential still
    // stops validation and issues no identity-level success code.
    if verified.is_err() {
        ctx.results.push_failure(
            CAWG_X509_SIGNATURE_MISMATCH,
            url.into(),
            "CAWG identity COSE signature does not match signer_payload".into(),
        );
        return;
    }
    ctx.results.push_success(
        CAWG_X509_SIGNATURE_VALIDATED,
        url.into(),
        "the identity COSE signature validated against the signing certificate".into(),
    );
    if payload_encoding == "legacy-field-order" {
        ctx.results.push_informational(
            CAWG_LEGACY_PROFILE,
            url.into(),
            "identity signature verifies over the CAWG 1.1 field-order encoding, not the CAWG 1.3 canonical encoding"
                .into(),
        );
    }

    let evidence = match identity_trust_outcome(
        leaf,
        &chain,
        at,
        ctx.validation_time,
        ctx.cawg_trust,
        ctx.cawg_allowed_certs,
        ctx.document_signing_require_anchor,
        timestamp_trusted,
        revocation_status,
    ) {
        IdentityTrust::Untrusted(reason) => {
            ctx.results.push_failure_with_details(
                CAWG_X509_CREDENTIAL_UNTRUSTED,
                url.into(),
                "no chain of trust reaches a configured CAWG trust anchor for this identity credential"
                    .into(),
                json!({"reason": reason}),
            );
            return;
        }
        IdentityTrust::Trusted(evidence) => {
            ctx.results.push_success(
                CAWG_X509_CREDENTIAL_TRUSTED,
                url.into(),
                "the identity signing certificate satisfies the CAWG X.509 trust model".into(),
            );
            Ok(evidence)
        }
        IdentityTrust::NoRootOfTrust(reason) => Err(reason),
    };

    if !chain
        .iter()
        .all(|certificate| certificate_valid_at(certificate, at))
    {
        ctx.results.push_failure(
            CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY,
            url.into(),
            "the time of signing falls outside the validity window of the identity certificate chain"
                .into(),
        );
        return;
    }
    if !timestamp_trusted {
        ctx.results.push_success(
            CAWG_X509_SIGNATURE_INSIDE_VALIDITY,
            url.into(),
            "no trusted time stamp was available, and the current time falls inside the identity certificate chain's validity window"
                .into(),
        );
    }
    report_time_of_signing(signature, &chain, attested, ctx.results, url);

    match evidence {
        Ok(trust) => ctx.results.push_success_with_details(
            CAWG_IDENTITY_TRUSTED,
            url.into(),
            "CAWG identity signature and X.509 trust policy validated".into(),
            json!({
                "trust_source": trust.source,
                "accepted_eku": trust.accepted_eku,
                "certificate_policy": trust.certificate_policy,
                "anchor_fingerprint": trust.anchor_fingerprint,
                "trusted_at": at.to_string(),
                "timestamp_trusted": timestamp_trusted,
                "revocation_status": revocation_status.as_str(),
                "payload_encoding": payload_encoding,
            }),
        ),
        Err(trust_failure) => {
            let (accepted_eku, certificate_policy) = identity_trust_rejection(leaf);
            ctx.results.push_success_with_details(
                CAWG_IDENTITY_WELL_FORMED,
                url.into(),
                "CAWG identity signature validated but no configured trust root accepted the credential"
                    .into(),
                json!({
                    "trust_source": "none",
                    "accepted_eku": accepted_eku,
                    "certificate_policy": certificate_policy,
                    "trusted_at": null,
                    "timestamp_trusted": timestamp_trusted,
                    "revocation_status": revocation_status.as_str(),
                    "trust_failure": trust_failure,
                    "payload_encoding": payload_encoding,
                }),
            );
        }
    }
}

fn reference_targets_identity(reference_url: &str, identity_url: &str) -> bool {
    if reference_url == identity_url {
        return true;
    }
    let identity_label = identity_url.rsplit('/').next().unwrap_or("cawg.identity");
    reference_url == format!("self#jumbf=c2pa.assertions/{identity_label}")
}
fn valid_signer_payload(signer_payload: &Value) -> Option<&Vec<Value>> {
    let Value::Map(_) = signer_payload else {
        return None;
    };
    let referenced = match signer_payload.get("referenced_assertions") {
        Some(Value::Array(references))
            if !references.is_empty() && references.iter().all(valid_hashed_uri) =>
        {
            references
        }
        _ => return None,
    };
    if signer_payload
        .get("sig_type")
        .and_then(Value::as_text)
        .is_none_or(str::is_empty)
    {
        return None;
    }
    if !signer_payload.get("role").is_none_or(|value| match value {
        Value::Array(roles) => {
            !roles.is_empty()
                && roles
                    .iter()
                    .all(|role| role.as_text().is_some_and(|role| !role.is_empty()))
        }
        _ => false,
    }) {
        return None;
    }
    Some(referenced)
}

fn valid_hashed_uri(value: &Value) -> bool {
    matches!(value, Value::Map(_))
        && value
            .get("url")
            .and_then(Value::as_text)
            .is_some_and(|url| !url.is_empty())
        && value
            .get("hash")
            .and_then(Value::as_bytes)
            .is_some_and(|hash| !hash.is_empty())
        && value
            .get("alg")
            .is_none_or(|alg| alg.as_text().is_some_and(|alg| !alg.is_empty()))
}

fn identity_reference_cycle(
    claim_refs: &ClaimAssertionRefs<'_>,
    manifest_label: &str,
    start_label: &str,
) -> bool {
    fn visit(
        claim_refs: &ClaimAssertionRefs<'_>,
        manifest_label: &str,
        label: &str,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if !visiting.insert(label.to_string()) {
            return true;
        }
        if visited.contains(label) {
            visiting.remove(label);
            return false;
        }
        let cycle = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
            .and_then(|assertion| assertion.get("signer_payload"))
            .and_then(|payload| payload.get("referenced_assertions"))
            .and_then(|references| match references {
                Value::Array(references) => Some(references),
                _ => None,
            })
            .is_some_and(|references| {
                references.iter().any(|reference| {
                    reference
                        .get("url")
                        .and_then(Value::as_text)
                        .and_then(|url| super::assertion_label_for_manifest(url, manifest_label))
                        .filter(|target| is_identity_assertion_label(target))
                        .is_some_and(|target| {
                            visit(claim_refs, manifest_label, target, visiting, visited)
                        })
                })
            });
        visiting.remove(label);
        visited.insert(label.to_string());
        cycle
    }

    visit(
        claim_refs,
        manifest_label,
        start_label,
        &mut HashSet::new(),
        &mut HashSet::new(),
    )
}

fn map_keys_are_unique(value: &Value) -> bool {
    match value {
        Value::Map(entries) => {
            let mut keys = HashSet::with_capacity(entries.len());
            entries.iter().all(|(key, value)| {
                map_keys_are_unique(key)
                    && map_keys_are_unique(value)
                    && encode(key, Profile::CanonicalForHashedSubstructures)
                        .is_ok_and(|encoded| keys.insert(encoded))
            })
        }
        Value::Array(values) => values.iter().all(map_keys_are_unique),
        Value::Tag(_, value) => map_keys_are_unique(value),
        _ => true,
    }
}

/// Compare two hashed-URIs that both sit under the same claim.
///
/// The C2PA hashed-URI CDDL makes `alg` optional: "If this field is absent,
/// the hash algorithm is taken from an enclosing structure ... If both are
/// present, the field in this structure is used." Both sides are therefore
/// resolved against the claim's own `alg` first: a reference that spells the
/// algorithm out and one that inherits the same algorithm name the same
/// assertion.
fn same_hashed_uri(left: &Value, right: &Value, claim_alg: Option<&str>) -> bool {
    left.get("url").and_then(Value::as_text) == right.get("url").and_then(Value::as_text)
        && left.get("hash").and_then(Value::as_bytes) == right.get("hash").and_then(Value::as_bytes)
        && resolved_alg(left, claim_alg) == resolved_alg(right, claim_alg)
}

/// Compare a hashed-URI signed by an identity with one declared by a claim in
/// ANOTHER manifest.
///
/// The two sides are written differently by construction: the claim that owns
/// the assertion may reference it relatively (`self#jumbf=c2pa.assertions/X`,
/// which C2PA "URI References" defines as naming the enclosing manifest),
/// while an identity in a different manifest can only name it absolutely. Both
/// URIs are therefore resolved to the absolute form before comparison, and each
/// side inherits the hash algorithm of the claim it sits under.
fn same_hashed_uri_across_manifests(
    signed: &Value,
    signed_claim_alg: Option<&str>,
    declared: InheritedBinding<'_>,
) -> bool {
    let signed_url = signed
        .get("url")
        .and_then(Value::as_text)
        .and_then(|url| absolute_assertion_uri(url, declared.manifest));
    let declared_url = declared
        .reference
        .get("url")
        .and_then(Value::as_text)
        .and_then(|url| absolute_assertion_uri(url, declared.manifest));
    signed_url.is_some()
        && signed_url == declared_url
        && signed.get("hash").and_then(Value::as_bytes)
            == declared.reference.get("hash").and_then(Value::as_bytes)
        && resolved_alg(signed, signed_claim_alg)
            == resolved_alg(declared.reference, declared.claim_alg)
}

/// Resolve an assertion hashed-URI to its absolute form.
///
/// A relative URI resolves against `manifest_label`; an absolute one is
/// returned as written, so it can only ever name the manifest it spells out.
fn absolute_assertion_uri(url: &str, manifest_label: &str) -> Option<String> {
    if let Some(label) = url.strip_prefix("self#jumbf=c2pa.assertions/") {
        return (!label.is_empty() && !label.contains('/'))
            .then(|| format!("self#jumbf=/c2pa/{manifest_label}/c2pa.assertions/{label}"));
    }
    url.starts_with("self#jumbf=/c2pa/")
        .then(|| url.to_string())
}

/// Resolve one `referenced_assertions` entry against the claims of the
/// manifests the recursive ingredient walk reached.
///
/// The entry must name the reached manifest explicitly, and that manifest's own
/// claim must declare the same assertion with the same hash: the identity is
/// bound to an assertion a signed ingredient claim vouches for, never to loose
/// bytes in the store.
fn referenced_in_reached_claim(
    reference: &Value,
    claim_alg: Option<&str>,
    reached: &[ReachedManifest],
) -> bool {
    let Some(url) = reference.get("url").and_then(Value::as_text) else {
        return false;
    };
    let Some(label) = super::extract_manifest_label(url) else {
        return false;
    };
    let Some(manifest) = reached.iter().find(|reached| reached.label == label) else {
        return false;
    };
    let target_alg = manifest.claim.get("alg").and_then(Value::as_text);
    claim_assertion_references(&manifest.claim).any(|declared| {
        same_hashed_uri_across_manifests(
            reference,
            claim_alg,
            InheritedBinding {
                manifest: &manifest.label,
                reference: declared,
                claim_alg: target_alg,
            },
        )
    })
}

/// Every hashed-URI a claim declares in its assertion lists, across claim
/// generations.
fn claim_assertion_references(claim: &Value) -> impl Iterator<Item = &Value> + '_ {
    ["created_assertions", "gathered_assertions", "assertions"]
        .into_iter()
        .filter_map(move |field| match claim.get(field) {
            Some(Value::Array(items)) => Some(items.iter()),
            _ => None,
        })
        .flatten()
}

fn resolved_alg<'a>(hashed_uri: &'a Value, claim_alg: Option<&'a str>) -> Option<&'a str> {
    hashed_uri.get("alg").and_then(Value::as_text).or(claim_alg)
}

fn valid_padding(value: Option<&Value>, required: bool) -> bool {
    match value {
        Some(Value::Bytes(bytes)) => bytes.iter().all(|byte| *byte == 0),
        None => !required,
        _ => false,
    }
}

fn invalid_cbor(results: &mut ValidationResults, url: &str, explanation: &str) {
    results.push_failure(CAWG_IDENTITY_CBOR_INVALID, url.into(), explanation.into());
}

/// Resolve the attested signing time for one identity assertion in the CAWG
/// 1.3 source order: the assertion's own `sigTst2` header, then the
/// `c2pa.time-stamp` assertions recorded for the containing C2PA Manifest,
/// then the C2PA claim signature's own trusted time stamp.
///
/// Every time-stamp defect is informational and makes the validator ignore
/// that token, never reject the assertion. The `cawg.x509.time_stamp.*`
/// success codes are issued only for a token this procedure validated against
/// the identity signature; a time from the claim signature is already reported
/// under the claim signature's own `timeStamp.*` codes.
#[allow(clippy::too_many_arguments)]
fn identity_timestamp(
    signature: &[u8],
    manifest_label: &str,
    timestamp_index: &TimestampAssertionIndex,
    tsa_trust: Option<&TrustList>,
    claim_timestamp: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    results: &mut ValidationResults,
    url: &str,
) -> Option<OffsetDateTime> {
    let mut defect: Option<(TokenFailure, &'static str)> = None;
    match extract_claim_tsa_tokens(signature) {
        // 1.3 x509/generating forbids a v1 time stamp in an identity assertion
        // and 1.3 x509/validating tells a validator to consider one invalid.
        Some((ClaimTimestampVersion::V1, _)) => {
            defect = Some((TokenFailure::Malformed, "identity_sig_tst_v1"));
        }
        Some((ClaimTimestampVersion::V2, tokens)) => {
            match (tokens.as_slice(), timestamp_input(signature)) {
                ([Some(token)], Ok(input)) => {
                    match validate_token(token, &input, tsa_trust, verification_time) {
                        TokenOutcome::Trusted(generated_at) => {
                            report_identity_timestamp_trusted(results, url);
                            return Some(generated_at);
                        }
                        TokenOutcome::Failed(failure, reason) => defect = Some((failure, reason)),
                    }
                }
                // The `tstTokens` array is expected to hold exactly one token.
                _ => defect = Some((TokenFailure::Malformed, "identity_sig_tst2_token_count")),
            }
        }
        None => {}
    }

    let candidates = timestamp_index.candidates(manifest_label);
    if !candidates.is_empty() {
        if let Ok(input) = timestamp_assertion_input(signature) {
            let mut assertion_defect = None;
            for token in candidates {
                match validate_token(token, &input, tsa_trust, verification_time) {
                    TokenOutcome::Trusted(generated_at) => {
                        report_identity_timestamp_trusted(results, url);
                        return Some(generated_at);
                    }
                    TokenOutcome::Failed(failure, reason) => {
                        assertion_defect.get_or_insert((failure, reason));
                    }
                }
            }
            defect = assertion_defect.or(defect);
        }
    }
    if let Some((failure, reason)) = defect {
        report_identity_timestamp_defect(failure, reason, results, url);
    }
    claim_timestamp
}

fn report_identity_timestamp_trusted(results: &mut ValidationResults, url: &str) {
    results.push_success(
        CAWG_X509_TIME_STAMP_VALIDATED,
        url.into(),
        "the RFC 3161 token's signature and message imprint validated against the identity signature"
            .into(),
    );
    results.push_success(
        CAWG_X509_TIME_STAMP_TRUSTED,
        url.into(),
        "the time stamping authority chains to a supplied TSA trust anchor".into(),
    );
}

fn report_identity_timestamp_defect(
    failure: TokenFailure,
    reason: &str,
    results: &mut ValidationResults,
    url: &str,
) {
    let (code, explanation) = match failure {
        TokenFailure::Malformed => (
            CAWG_X509_TIME_STAMP_MALFORMED,
            format!("the identity time stamp is malformed and is ignored ({reason})"),
        ),
        TokenFailure::Mismatch => (
            CAWG_X509_TIME_STAMP_MISMATCH,
            format!(
                "the identity time stamp's signature or message imprint did not match and is ignored ({reason})"
            ),
        ),
        TokenFailure::Untrusted => (
            CAWG_X509_TIME_STAMP_UNTRUSTED,
            format!(
                "the identity time stamping authority is untrusted or used an algorithm outside the allowed list, and is ignored ({reason})"
            ),
        ),
        TokenFailure::CredentialInvalid => {
            // 1.3 allows the validator to add this code alongside untrusted.
            results.push_informational(
                CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID,
                url.into(),
                format!("the identity time stamping authority's certificate is invalid ({reason})"),
            );
            (
                CAWG_X509_TIME_STAMP_UNTRUSTED,
                "a trust chain to a TSA anchor could not be built from an invalid credential"
                    .to_string(),
            )
        }
        TokenFailure::OutsideValidity => (
            CAWG_X509_TIME_STAMP_OUTSIDE_VALIDITY,
            format!(
                "the attested time falls outside the TSA chain's validity window and is ignored ({reason})"
            ),
        ),
    };
    results.push_informational(code, url.into(), explanation);
}

/// The optional "claimed time of signing" from the protected `iat` header.
/// Absence produces no status; presence yields exactly one informational code.
fn report_time_of_signing(
    signature: &[u8],
    chain: &[Vec<u8>],
    attested: Option<OffsetDateTime>,
    results: &mut ValidationResults,
    url: &str,
) {
    let signed_at = match protected_iat(signature) {
        Ok(None) => return,
        Ok(Some(iat)) => numeric_date_to_time(iat),
        Err(_) => None,
    };
    let inside = signed_at.is_some_and(|signed_at| {
        chain
            .iter()
            .all(|certificate| certificate_valid_at(certificate, signed_at))
            && attested.is_none_or(|attested| signed_at <= attested)
    });
    if inside {
        results.push_informational(
            CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY,
            url.into(),
            "the claimed time of signing falls inside the identity certificate chain's validity"
                .into(),
        );
    } else {
        results.push_informational(
            CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY,
            url.into(),
            "the claimed time of signing falls outside the identity certificate chain's validity, is later than the attested time, or is not a usable NumericDate"
                .into(),
        );
    }
}

/// How the CAWG X.509 trust model resolved for one identity credential.
enum IdentityTrust {
    Trusted(IdentityTrustEvidence),
    /// No CAWG trust material is configured, so there is no root of trust to
    /// reach. 1.3 rejects a chain that cannot be verified "to any configured
    /// trust anchor"; with nothing configured there is no anchor to have
    /// failed against, which is the "could not identify any root of trust"
    /// case the 1.3 status table still reports as `cawg.identity.well-formed`.
    /// The payload explains what the credential would have needed.
    NoRootOfTrust(&'static str),
    /// Trust material is configured and the credential does not satisfy it.
    /// 1.3 rejects the assertion with `cawg.x509.credential.untrusted`, so no
    /// identity-level success code is issued.
    Untrusted(&'static str),
}

#[allow(clippy::too_many_arguments)]
fn identity_trust_outcome(
    leaf: &[u8],
    chain: &[Vec<u8>],
    at: OffsetDateTime,
    validation_time: OffsetDateTime,
    trust: Option<&TrustList>,
    allowed: Option<&TrustList>,
    document_signing_require_anchor: bool,
    timestamp_trusted: bool,
    revocation_status: IdentityRevocationStatus,
) -> IdentityTrust {
    // A C2PA leaf-credential profile violation has no 1.3 status code of its
    // own. The 1.3 trust model requires the generator to sign with a compliant
    // certificate, and a CA certificate or one without digital-signature key
    // usage cannot anchor a chain of trust for this signature, so it is
    // reported as `cawg.x509.credential.untrusted` rather than as an Encypher
    // extension code.
    if !leaf_profile_acceptable_der(leaf) {
        return IdentityTrust::Untrusted("leaf_profile_unacceptable");
    }
    // 1.3: a revoked CA certificate in the chain is an untrusted credential,
    // not a revoked named actor. A revoked leaf has already been rejected with
    // `cawg.identity.credential_revoked`.
    if matches!(revocation_status, IdentityRevocationStatus::CaRevoked) {
        return IdentityTrust::Untrusted("ca_revoked");
    }
    match identity_certificate_trust(
        leaf,
        &chain[1..],
        at,
        validation_time,
        trust,
        allowed,
        document_signing_require_anchor,
        timestamp_trusted,
    ) {
        Ok(evidence) => IdentityTrust::Trusted(evidence),
        Err(reason) if trust.is_none() && allowed.is_none() => IdentityTrust::NoRootOfTrust(reason),
        Err(reason) => IdentityTrust::Untrusted(reason),
    }
}

struct IdentityTrustEvidence {
    source: &'static str,
    accepted_eku: Option<&'static str>,
    certificate_policy: Option<String>,
    /// SHA-256 of the configured certificate that accepted the credential: the
    /// anchor its chain terminates at, or the allowed certificate it matched.
    anchor_fingerprint: Option<String>,
}

/// Evaluate one identity credential against the CAWG trust configuration.
///
/// 1.3 x509/trust-model has the validator keep a list of accepted EKUs, each
/// with its own accepted certificate policies and trust anchors. This verifier
/// carries that configuration on the anchors themselves: every CAWG anchor and
/// allowed certificate declares the entry that supplied it
/// ([`CawgTrustSource`]), and the entry decides which rules it is accepted
/// under.
///
/// - `id-kp-documentSigning` is the mandatory accepted EKU, and 1.3 requires
///   no certificate policy or trust anchor for it. Strict conformance still
///   asks for an anchor, which is what `document_signing_require_anchor`
///   carries.
/// - `id-kp-emailProtection` is accepted with one of the six CA/Browser Forum
///   S/MIME policies, under the extra conditions of the interim trust model
///   additions. Those conditions belong to the two sources that section
///   names, the Mozilla email root store and the IPTC lists. An entry the
///   validator configured itself, such as the Encypher Verified Organizations
///   root or a caller's own anchors, is a plain trust configuration entry and
///   carries no interim condition.
///
/// The interim time condition is disjunctive: "the time of validation is on
/// or before 31 March 2027 *or* a trusted time stamp establishes that the
/// identity assertion was issued on or before 31 March 2027". A time stamp is
/// therefore required only once the validation instant is past the cutoff.
/// `at` is the attested instant when one was established and the validation
/// instant otherwise, so both disjuncts are evaluated from it plus
/// `validation_time`.
///
/// Returns the entry that accepted the credential, or the reason no entry did.
#[allow(clippy::too_many_arguments)]
fn identity_certificate_trust(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    at: OffsetDateTime,
    validation_time: OffsetDateTime,
    trust: Option<&TrustList>,
    allowed: Option<&TrustList>,
    document_signing_require_anchor: bool,
    identity_timestamp_trusted: bool,
) -> Result<IdentityTrustEvidence, &'static str> {
    let ekus = certificate_eku_oids_der(leaf).unwrap_or_default();
    let chain_anchor = || chain_trust_anchor(leaf, intermediates, at, trust);

    if ekus.iter().any(|oid| oid == OID_KP_DOCUMENT_SIGNING) {
        if let Some(entry) = allowed.and_then(|list| list.find_certificate(leaf)) {
            return Ok(IdentityTrustEvidence {
                source: "allowed_list",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
                anchor_fingerprint: Some(entry.fingerprint()),
            });
        }
        let anchor = chain_anchor();
        if !document_signing_require_anchor || anchor.is_some() {
            return Ok(IdentityTrustEvidence {
                source: "document_signing",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
                anchor_fingerprint: anchor.map(TrustAnchor::fingerprint),
            });
        }
        return Err("document_signing_anchor_required");
    }

    if !ekus.iter().any(|oid| oid == OID_KP_EMAIL_PROTECTION) {
        return Err("eku_not_accepted");
    }
    // Every entry that accepts emailProtection accepts it only with one of the
    // six approved policies, so this check precedes the entry search.
    let Some(policy) = approved_smime_policy(leaf) else {
        return Err("smime_policy_not_accepted");
    };
    let before_cutoff =
        |instant: OffsetDateTime| instant.unix_timestamp() < S_MIME_INTERIM_CUTOFF_UNIX;
    let interim_satisfied =
        before_cutoff(validation_time) || (identity_timestamp_trusted && before_cutoff(at));

    // A credential can match more than one entry: it may sit in the private
    // credential store and also chain to an anchor. Each match is offered its
    // own rules, and only if every match is an interim source that the interim
    // conditions refuse does the reason become an interim one.
    let direct = allowed
        .and_then(|list| list.find_certificate(leaf))
        .map(|anchor| ("allowed_list", anchor));
    let chained = chain_anchor().map(|anchor| (anchor.cawg_source.label(), anchor));
    let mut refused = None;
    for (label, anchor) in direct.into_iter().chain(chained) {
        if anchor.cawg_source.interim() && !interim_satisfied {
            // Past the cutoff, the only surviving disjunct is a trusted time
            // stamp attesting an earlier signature: absent one, that is what
            // the credential lacked; present one, it attested too late.
            refused = Some(if identity_timestamp_trusted {
                "smime_interim_expired"
            } else {
                "trusted_timestamp_required"
            });
            continue;
        }
        return Ok(IdentityTrustEvidence {
            source: label,
            accepted_eku: Some(OID_KP_EMAIL_PROTECTION),
            certificate_policy: Some(policy),
            anchor_fingerprint: Some(anchor.fingerprint()),
        });
    }
    Err(refused.unwrap_or("credential_untrusted"))
}

/// The configured anchor a chain from `leaf` terminates at.
fn chain_trust_anchor<'a>(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    at: OffsetDateTime,
    trust: Option<&'a TrustList>,
) -> Option<&'a TrustAnchor> {
    let anchors = trust?;
    let result = validate_chain(
        leaf,
        intermediates,
        anchors,
        AnchorPurpose::CawgIdentity,
        Some(at),
    );
    result
        .trusted
        .then(|| result.terminating_anchor(anchors))
        .flatten()
}

/// The accepted EKU and certificate policy a credential presents, for the
/// evidence reported when no configured entry accepted it.
fn identity_trust_rejection(leaf: &[u8]) -> (Option<&'static str>, Option<String>) {
    let ekus = certificate_eku_oids_der(leaf).unwrap_or_default();
    if ekus.iter().any(|oid| oid == OID_KP_DOCUMENT_SIGNING) {
        return (Some(OID_KP_DOCUMENT_SIGNING), None);
    }
    if ekus.iter().any(|oid| oid == OID_KP_EMAIL_PROTECTION) {
        return (Some(OID_KP_EMAIL_PROTECTION), approved_smime_policy(leaf));
    }
    (None, None)
}

fn approved_smime_policy(cert: &[u8]) -> Option<String> {
    certificate_policy_oids_der(cert)
        .unwrap_or_default()
        .into_iter()
        .find(|oid| CAWG_SMIME_POLICY_OIDS.contains(&oid.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_trust::timestamp_fixture::TestTsa;
    use const_oid::ObjectIdentifier;
    use der::Encode;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
    };
    use time::macros::datetime;

    fn der_sequence(content: Vec<u8>) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut encoded = vec![0x30, content.len() as u8];
        encoded.extend(content);
        encoded
    }

    fn certificate_policies_value(oid: &str) -> Vec<u8> {
        let oid = ObjectIdentifier::new_unwrap(oid)
            .to_der()
            .expect("encode policy oid");
        der_sequence(der_sequence(oid))
    }

    fn actor_certificate(eku: &str, policy: Option<&str>, is_ca: bool) -> Vec<u8> {
        let key = KeyPair::generate().expect("actor key");
        let mut params = CertificateParams::new(vec!["actor.example".to_string()]).expect("params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "CAWG Actor");
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = if is_ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(
            eku.split('.')
                .map(|part| part.parse::<u64>().expect("oid component"))
                .collect(),
        )];
        if let Some(policy) = policy {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 32],
                    certificate_policies_value(policy),
                ));
        }
        params
            .self_signed(&key)
            .expect("actor certificate")
            .der()
            .as_ref()
            .to_vec()
    }

    fn hashed_uri(url: &str, hash: u8) -> Value {
        Value::Map(vec![
            ("url".into(), Value::Text(url.into())),
            ("alg".into(), Value::Text("sha256".into())),
            ("hash".into(), Value::Bytes(vec![hash; 32])),
        ])
    }

    #[test]
    fn hashed_uri_match_requires_the_exact_url() {
        let full = hashed_uri(
            "self#jumbf=/c2pa/manifest-a/c2pa.assertions/c2pa.hash.data",
            0x11,
        );
        let substituted = hashed_uri(
            "self#jumbf=/c2pa/manifest-b/c2pa.assertions/c2pa.hash.data",
            0x11,
        );
        assert!(!same_hashed_uri(&full, &substituted, Some("sha256")));
        assert!(same_hashed_uri(&full, &full, Some("sha256")));
        // A different resolved algorithm is still a different reference.
        let sha512 = Value::Map(vec![
            (
                "url".into(),
                Value::Text("self#jumbf=/c2pa/manifest-a/c2pa.assertions/c2pa.hash.data".into()),
            ),
            ("alg".into(), Value::Text("sha512".into())),
            ("hash".into(), Value::Bytes(vec![0x11; 32])),
        ]);
        assert!(!same_hashed_uri(&full, &sha512, Some("sha256")));
    }

    #[test]
    fn document_signing_requires_the_imported_leaf_profile() {
        let valid = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, false);
        let ca_leaf = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, true);
        assert!(leaf_profile_acceptable_der(&valid));
        assert!(!leaf_profile_acceptable_der(&ca_leaf));
        let at = datetime!(2026-01-01 0:00 UTC);
        assert!(identity_certificate_trust(&valid, &[], at, at, None, None, false, false).is_ok());
    }

    #[test]
    fn smime_accepts_only_the_six_exact_policy_oids_before_cutoff() {
        let before_cutoff =
            OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX - 1).unwrap();
        for policy in CAWG_SMIME_POLICY_OIDS {
            let leaf = actor_certificate(OID_KP_EMAIL_PROTECTION, Some(policy), false);
            let allowed = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()]);
            let evidence = identity_certificate_trust(
                &leaf,
                &[],
                before_cutoff,
                before_cutoff,
                None,
                Some(&allowed),
                false,
                true,
            )
            .expect("approved S/MIME policy");
            assert_eq!(evidence.accepted_eku, Some(OID_KP_EMAIL_PROTECTION));
            assert_eq!(evidence.certificate_policy.as_deref(), Some(policy));
        }

        for rejected in ["2.23.140.1.5.1.1", "2.23.140.1.5.2", "1.2.3.4"] {
            let leaf = actor_certificate(OID_KP_EMAIL_PROTECTION, Some(rejected), false);
            let allowed = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()]);
            assert_eq!(
                identity_certificate_trust(
                    &leaf,
                    &[],
                    before_cutoff,
                    before_cutoff,
                    None,
                    Some(&allowed),
                    false,
                    true,
                )
                .err(),
                Some("smime_policy_not_accepted")
            );
        }
    }

    /// Interim condition 1 disjunctively accepts a validation instant on or
    /// before 31 March 2027, so a time stamp is needed only past the cutoff,
    /// and then only one attesting a signature from before it.
    #[test]
    fn smime_cutoff_and_trusted_timestamp_boundaries_are_exact() {
        let leaf = actor_certificate(
            OID_KP_EMAIL_PROTECTION,
            Some(CAWG_SMIME_POLICY_OIDS[0]),
            false,
        );
        let allowed = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()]);
        let accepted = OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX - 1).unwrap();
        let rejected = OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX).unwrap();
        let trust = |at, validation_time, timestamp_trusted| {
            identity_certificate_trust(
                &leaf,
                &[],
                at,
                validation_time,
                None,
                Some(&allowed),
                false,
                timestamp_trusted,
            )
            .err()
        };
        // First disjunct: the validation instant itself, with or without a
        // time stamp.
        assert_eq!(trust(accepted, accepted, true), None);
        assert_eq!(trust(accepted, accepted, false), None);
        // Past the cutoff, only an attested earlier signature survives.
        assert_eq!(trust(accepted, rejected, true), None);
        assert_eq!(
            trust(rejected, rejected, false),
            Some("trusted_timestamp_required")
        );
        assert_eq!(
            trust(rejected, rejected, true),
            Some("smime_interim_expired")
        );
    }

    fn identity_payload(role: &str, expected: Option<Vec<Value>>) -> Value {
        identity_payload_with_binding(
            role,
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22),
            expected,
        )
    }

    fn identity_payload_with_binding(
        role: &str,
        binding: Value,
        expected: Option<Vec<Value>>,
    ) -> Value {
        let mut fields = vec![
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(vec![binding]),
            ),
            (
                Value::Text("sig_type".into()),
                Value::Text(CAWG_X509_COSE.into()),
            ),
            (
                Value::Text("role".into()),
                Value::Array(vec![Value::Text(role.into())]),
            ),
        ];
        if let Some(expected) = expected {
            fields.push((
                Value::Text("expected_countersigners".into()),
                Value::Array(expected),
            ));
        }
        Value::Map(fields)
    }

    fn countersigner_description(partial_payload: Value) -> Value {
        Value::Map(vec![(
            Value::Text("partial_signer_payload".into()),
            partial_payload,
        )])
    }

    fn identity_bytes(payload: Value) -> Vec<u8> {
        encode(
            &Value::Map(vec![
                (Value::Text("signer_payload".into()), payload),
                (Value::Text("signature".into()), Value::Bytes(vec![1])),
            ]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("encode identity")
    }
    fn identity_bytes_with_padding(payload: Value) -> Vec<u8> {
        encode(
            &Value::Map(vec![
                (Value::Text("signer_payload".into()), payload),
                (Value::Text("signature".into()), Value::Bytes(vec![1])),
                (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
            ]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("encode identity")
    }

    /// A claim carries the hash algorithm its hashed-URIs inherit when they
    /// omit `alg` of their own.
    fn claim_with_references(references: Vec<Value>) -> Value {
        Value::Map(vec![
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (
                Value::Text("created_assertions".into()),
                Value::Array(references),
            ),
        ])
    }

    #[test]
    fn duplicate_signer_payload_keys_fail_before_semantic_or_signature_checks() {
        let expected_binding =
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22);
        let substituted_binding =
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x33);
        let signer_payload = Value::Map(vec![
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(vec![substituted_binding]),
            ),
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(vec![expected_binding.clone()]),
            ),
            (
                Value::Text("sig_type".into()),
                Value::Text(CAWG_X509_COSE.into()),
            ),
            (
                Value::Text("role".into()),
                Value::Array(vec![Value::Text("cawg.publisher:primary".into())]),
            ),
        ]);
        let identity_bytes = encode(
            &Value::Map(vec![
                (Value::Text("signer_payload".into()), signer_payload),
                (Value::Text("signature".into()), Value::Bytes(vec![1])),
                (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode ambiguous identity");
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![("cawg.identity".into(), identity_bytes.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            expected_binding,
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let primary_binding = claim_refs
            .references
            .iter()
            .find(|reference| reference.label == Some("c2pa.hash.data"));
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: datetime!(2025-05-01 0:00 UTC),
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
                document_signing_require_anchor: true,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients: IngredientResolution::default(),
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, primary_binding, &[]);
        }
        let failures: Vec<_> = results
            .failure
            .iter()
            .filter(|status| status.code == CAWG_IDENTITY_CBOR_INVALID)
            .collect();
        assert_eq!(failures.len(), 1);
        assert!(failures[0].explanation.contains("duplicate CBOR map key"));
        assert!(!results
            .success
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_TRUSTED));
    }

    #[test]
    fn fallback_hard_binding_is_reported_on_its_own_identity() {
        let primary_binding =
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22);
        let fallback_binding = hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.multi-asset",
            0x33,
        );
        let secondary = identity_payload_with_binding(
            "cawg.publisher:secondary",
            primary_binding.clone(),
            None,
        );
        let primary = identity_payload_with_binding(
            "cawg.publisher:primary",
            fallback_binding.clone(),
            Some(vec![countersigner_description(secondary.clone())]),
        );
        let primary_bytes = identity_bytes_with_padding(primary);
        let secondary_bytes = identity_bytes_with_padding(secondary);
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.identity".into(), primary_bytes.as_slice()),
                ("cawg.identity__1".into(), secondary_bytes.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 1),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__1", 2),
            primary_binding,
            fallback_binding,
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let primary_reference = claim_refs
            .references
            .iter()
            .find(|reference| reference.label == Some("c2pa.hash.data"))
            .unwrap();
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: datetime!(2025-05-01 0:00 UTC),
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
                document_signing_require_anchor: false,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients: IngredientResolution::default(),
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, Some(primary_reference), &[]);
        }

        assert!(!results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_ASSERTION_DUPLICATE));
        let missing: Vec<_> = results
            .failure
            .iter()
            .filter(|status| status.code == CAWG_IDENTITY_HARD_BINDING_MISSING)
            .collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].url, "cawg.identity");
    }

    /// A `signer_payload` over an explicit list of referenced assertions.
    fn identity_payload_over(references: Vec<Value>) -> Value {
        Value::Map(vec![
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(references),
            ),
            (
                Value::Text("sig_type".into()),
                Value::Text(CAWG_X509_COSE.into()),
            ),
            (
                Value::Text("role".into()),
                Value::Array(vec![Value::Text("cawg.publisher:primary".into())]),
            ),
        ])
    }

    /// A claim as an ingredient manifest writes it: `created_assertions`
    /// references are relative to that manifest.
    fn ingredient_claim(references: Vec<Value>) -> Value {
        claim_with_references(references)
    }

    /// Run one identity assertion through the identity validator with explicit
    /// ingredient-resolution inputs, and return the statuses it recorded.
    fn run_identity(
        manifest_label: &str,
        payload: Value,
        claim: &Value,
        primary_label: Option<&str>,
        ingredients: IngredientResolution<'_>,
    ) -> ValidationResults {
        let identity = identity_bytes_with_padding(payload);
        let manifest = ParsedManifest {
            label: manifest_label.into(),
            manifest_jumbf: &[],
            assertions: vec![("cawg.identity".into(), identity.as_slice())],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, claim, super::super::ClaimGeneration::V2);
        let primary = primary_label.and_then(|label| {
            claim_refs
                .references
                .iter()
                .find(|reference| reference.label == Some(label))
        });
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim,
                validation_time: datetime!(2025-05-01 0:00 UTC),
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
                document_signing_require_anchor: false,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients,
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, primary, &[]);
        }
        results
    }

    /// C2PA 2.4 lets an identity reference an assertion in a manifest the
    /// active claim reaches through its ingredients: the identity signs
    /// hashed-URIs, and a URI into a reachable ingredient claim resolves.
    #[test]
    fn a_referenced_assertion_in_a_reachable_ingredient_claim_resolves() {
        let binding = hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", 0x22);
        let in_ingredient = hashed_uri(
            "self#jumbf=/c2pa/urn:c2pa:ingredient/c2pa.assertions/c2pa.actions.v2",
            0x44,
        );
        let payload = identity_payload_over(vec![binding.clone(), in_ingredient]);
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            binding,
        ]);
        let reached = [ReachedManifest {
            label: "urn:c2pa:ingredient".into(),
            claim: ingredient_claim(vec![hashed_uri(
                "self#jumbf=c2pa.assertions/c2pa.actions.v2",
                0x44,
            )]),
        }];

        let results = run_identity(
            "test",
            payload,
            &claim,
            Some("c2pa.hash.data"),
            IngredientResolution {
                claims: &reached,
                inherited_binding: None,
            },
        );

        assert!(
            !results
                .failure
                .iter()
                .any(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH),
            "failures: {:?}",
            results.failure
        );
    }

    /// The same reference with no reachable ingredient claim behind it stays a
    /// mismatch: only a claim the ingredient walk actually reached counts, so a
    /// store passenger cannot satisfy a signed reference.
    #[test]
    fn a_referenced_assertion_outside_every_reached_claim_is_still_a_mismatch() {
        let binding = hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", 0x22);
        let elsewhere = hashed_uri(
            "self#jumbf=/c2pa/urn:c2pa:ingredient/c2pa.assertions/c2pa.actions.v2",
            0x44,
        );
        let payload = identity_payload_over(vec![binding.clone(), elsewhere]);
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            binding,
        ]);

        let results = run_identity(
            "test",
            payload,
            &claim,
            Some("c2pa.hash.data"),
            IngredientResolution::default(),
        );

        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH));
    }

    /// A reachable ingredient claim that does not declare the referenced
    /// assertion, or declares it with a different hash, does not resolve it.
    #[test]
    fn a_reachable_ingredient_claim_with_a_different_hash_does_not_resolve() {
        let binding = hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", 0x22);
        let in_ingredient = hashed_uri(
            "self#jumbf=/c2pa/urn:c2pa:ingredient/c2pa.assertions/c2pa.actions.v2",
            0x44,
        );
        let payload = identity_payload_over(vec![binding.clone(), in_ingredient]);
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            binding,
        ]);
        let reached = [ReachedManifest {
            label: "urn:c2pa:ingredient".into(),
            claim: ingredient_claim(vec![hashed_uri(
                "self#jumbf=c2pa.assertions/c2pa.actions.v2",
                0x55,
            )]),
        }];

        let results = run_identity(
            "test",
            payload,
            &claim,
            Some("c2pa.hash.data"),
            IngredientResolution {
                claims: &reached,
                inherited_binding: None,
            },
        );

        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH));
    }

    /// An identity inside an update manifest references the hard binding of the
    /// standard manifest its parentOf chain reaches, because an update manifest
    /// is forbidden to carry a hard binding of its own.
    #[test]
    fn an_identity_in_an_update_manifest_resolves_the_inherited_hard_binding() {
        let parent_binding = hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", 0x22);
        let signed_binding = hashed_uri(
            "self#jumbf=/c2pa/urn:c2pa:parent/c2pa.assertions/c2pa.hash.data",
            0x22,
        );
        let payload = identity_payload_over(vec![signed_binding]);
        let claim = claim_with_references(vec![hashed_uri(
            "self#jumbf=c2pa.assertions/cawg.identity",
            0x01,
        )]);

        let results = run_identity(
            "urn:c2pa:update",
            payload,
            &claim,
            None,
            IngredientResolution {
                claims: &[],
                inherited_binding: Some(InheritedBinding {
                    manifest: "urn:c2pa:parent",
                    reference: &parent_binding,
                    claim_alg: Some("sha256"),
                }),
            },
        );

        assert!(
            !results.failure.iter().any(|status| {
                status.code == CAWG_IDENTITY_HARD_BINDING_MISSING
                    || status.code == CAWG_IDENTITY_HARD_BINDING_INCORRECT
            }),
            "failures: {:?}",
            results.failure
        );
    }

    /// The inherited binding is the one the parentOf chain reaches, not any
    /// hard binding an attacker names.
    #[test]
    fn an_update_identity_naming_another_manifests_binding_is_rejected() {
        let parent_binding = hashed_uri("self#jumbf=c2pa.assertions/c2pa.hash.data", 0x22);
        let foreign_binding = hashed_uri(
            "self#jumbf=/c2pa/urn:c2pa:elsewhere/c2pa.assertions/c2pa.hash.data",
            0x22,
        );
        let payload = identity_payload_over(vec![foreign_binding]);
        let claim = claim_with_references(vec![hashed_uri(
            "self#jumbf=c2pa.assertions/cawg.identity",
            0x01,
        )]);

        let results = run_identity(
            "urn:c2pa:update",
            payload,
            &claim,
            None,
            IngredientResolution {
                claims: &[],
                inherited_binding: Some(InheritedBinding {
                    manifest: "urn:c2pa:parent",
                    reference: &parent_binding,
                    claim_alg: Some("sha256"),
                }),
            },
        );

        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_HARD_BINDING_MISSING
                || status.code == CAWG_IDENTITY_HARD_BINDING_INCORRECT));
    }

    #[test]
    fn identity_cap_stops_before_evaluation_cryptography_and_ocsp() {
        reset_identity_work_counts();
        let labels: Vec<String> = (0..=MAX_IDENTITY_ASSERTIONS)
            .map(|index| {
                if index == 0 {
                    "cawg.identity".to_string()
                } else {
                    format!("cawg.identity__{index}")
                }
            })
            .collect();
        let payloads: Vec<Vec<u8>> = labels
            .iter()
            .map(|_| identity_bytes(identity_payload("cawg.publisher:primary", None)))
            .collect();
        let assertions = labels
            .iter()
            .zip(&payloads)
            .map(|(label, payload)| (label.clone(), payload.as_slice()))
            .collect();
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions,
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let mut references: Vec<Value> = labels
            .iter()
            .map(|label| hashed_uri(&format!("self#jumbf=c2pa.assertions/{label}"), 0x01))
            .collect();
        references.push(hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data",
            0x22,
        ));
        let claim = claim_with_references(references);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let binding = claim_refs
            .references
            .iter()
            .find(|reference| reference.label == Some("c2pa.hash.data"))
            .expect("test hard binding reference");
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: datetime!(2025-05-01 0:00 UTC),
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
                document_signing_require_anchor: false,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients: IngredientResolution::default(),
                results: &mut results,
            };
            verify_identity_assertions(
                &mut ctx,
                &claim_refs,
                Some(binding),
                &[b"must not be inspected"],
            );
        }

        assert_eq!(identity_work_counts(), IdentityWorkCounts::default());
        assert_eq!(results.failure.len(), 1);
        assert_eq!(results.failure[0].code, CAWG_IDENTITY_CBOR_INVALID);
        assert!(results.failure[0].explanation.contains("maximum is 64"));
        assert!(results.success.is_empty());
        assert!(results.informational.is_empty());
    }
    fn identity_assertion_map(referenced: Vec<Value>) -> Value {
        Value::Map(vec![
            (
                Value::Text("signer_payload".into()),
                Value::Map(vec![
                    (
                        Value::Text("referenced_assertions".into()),
                        Value::Array(referenced),
                    ),
                    (
                        Value::Text("sig_type".into()),
                        Value::Text(CAWG_X509_COSE.into()),
                    ),
                ]),
            ),
            (Value::Text("signature".into()), Value::Bytes(vec![1])),
            (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
        ])
    }

    /// Run `verify_identity_assertion` against a minimal single-assertion
    /// manifest and return the recorded results.
    fn identity_verdict(assertion: &Value, claim_refs: &[Value]) -> ValidationResults {
        identity_verdict_for_binding(assertion, claim_refs, "c2pa.hash.data")
    }

    fn identity_verdict_for_binding(
        assertion: &Value,
        claim_refs: &[Value],
        primary_label: &str,
    ) -> ValidationResults {
        let bytes =
            encode(assertion, Profile::CanonicalForHashedSubstructures).expect("encode assertion");
        identity_verdict_bytes_for_binding(&bytes, claim_refs, false, primary_label)
    }

    /// Run `verify_identity_assertion` on raw assertion bytes (preserving any
    /// non-canonical field order) with the legacy-encoding retry controlled by
    /// `allow_legacy_encoding`.
    fn identity_verdict_bytes(
        bytes: &[u8],
        claim_refs: &[Value],
        allow_legacy_encoding: bool,
    ) -> ValidationResults {
        identity_verdict_bytes_for_binding(
            bytes,
            claim_refs,
            allow_legacy_encoding,
            "c2pa.hash.data",
        )
    }

    fn identity_verdict_bytes_for_binding(
        bytes: &[u8],
        claim_refs: &[Value],
        allow_legacy_encoding: bool,
        primary_label: &str,
    ) -> ValidationResults {
        identity_verdict_full(
            bytes,
            claim_refs,
            allow_legacy_encoding,
            primary_label,
            None,
            None,
            false,
            None,
            &TimestampAssertionIndex::default(),
            IDENTITY_VALIDATION_TIME,
            None,
            Default::default(),
        )
    }

    /// Run one identity assertion against caller-supplied CAWG trust material.
    fn identity_verdict_with_trust(
        bytes: &[u8],
        cawg_allowed_certs: Option<&TrustList>,
        document_signing_require_anchor: bool,
    ) -> ValidationResults {
        identity_verdict_full(
            bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            cawg_allowed_certs,
            document_signing_require_anchor,
            None,
            &TimestampAssertionIndex::default(),
            IDENTITY_VALIDATION_TIME,
            None,
            Default::default(),
        )
    }

    /// Run one identity assertion with `c2pa.time-stamp` evidence indexed for
    /// the containing manifest.
    fn identity_verdict_with_timestamp(
        bytes: &[u8],
        tsa_trust: Option<&TrustList>,
        timestamp_index: &TimestampAssertionIndex,
    ) -> ValidationResults {
        identity_verdict_full(
            bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            None,
            false,
            tsa_trust,
            timestamp_index,
            IDENTITY_VALIDATION_TIME,
            None,
            Default::default(),
        )
    }

    /// The instant the scaffolding validates at unless a case names another.
    const IDENTITY_VALIDATION_TIME: OffsetDateTime = datetime!(2025-05-01 0:00 UTC);

    #[allow(clippy::too_many_arguments)]
    fn identity_verdict_full(
        bytes: &[u8],
        claim_refs: &[Value],
        allow_legacy_encoding: bool,
        primary_label: &str,
        cawg_trust: Option<&TrustList>,
        cawg_allowed_certs: Option<&TrustList>,
        document_signing_require_anchor: bool,
        tsa_trust: Option<&TrustList>,
        timestamp_index: &TimestampAssertionIndex,
        validation_time: OffsetDateTime,
        claim_timestamp: Option<OffsetDateTime>,
        evidence: super::super::OnlineEvidence<'_>,
    ) -> ValidationResults {
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![("cawg.identity".into(), bytes)],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = claim_with_references(claim_refs.to_vec());
        let indexed_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let primary_binding = indexed_refs
            .references
            .iter()
            .find(|reference| reference.label == Some(primary_label))
            .expect("primary binding must be declared by the test claim");
        let assertion =
            crate::c2pa_cbor::decode(bytes).expect("identity assertion fixture must decode");
        let mut results = ValidationResults::default();
        let mut ctx = IdentityContext {
            manifest: &manifest,
            claim: &claim,
            validation_time,
            claim_timestamp,
            cawg_trust,
            cawg_allowed_certs,
            ocsp_verification_time: validation_time,
            document_signing_require_anchor,
            tsa_trust,
            timestamp_index,
            did_documents: None,
            allow_legacy_encoding,
            ica_trusted_issuers: None,
            ica_trust_anchors: None,
            ica_status_lists: None,
            evidence,
            ingredients: IngredientResolution::default(),
            results: &mut results,
        };
        verify_identity_assertion(
            &mut ctx,
            &assertion,
            &indexed_refs,
            Some(primary_binding),
            &[],
            "cawg.identity",
        );
        results
    }

    fn failure_codes(results: &ValidationResults) -> Vec<&str> {
        results
            .failure
            .iter()
            .map(|status| status.code.as_str())
            .collect()
    }

    fn binding_claim_refs(hard_binding_hash: u8) -> Vec<Value> {
        vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            hashed_uri(
                "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data",
                hard_binding_hash,
            ),
        ]
    }
    #[test]
    fn identity_requires_the_primary_hard_binding_when_fallback_validates_content() {
        let primary = hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22);
        let fallback = hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.multi-asset",
            0x33,
        );
        let claim_refs = vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            primary.clone(),
            fallback.clone(),
        ];

        let primary_identity = identity_assertion_map(vec![primary]);
        let primary_result =
            identity_verdict_for_binding(&primary_identity, &claim_refs, "c2pa.hash.data");
        assert!(!primary_result.has_failure(CAWG_IDENTITY_HARD_BINDING_INCORRECT));

        let fallback_identity = identity_assertion_map(vec![fallback]);
        let fallback_result =
            identity_verdict_for_binding(&fallback_identity, &claim_refs, "c2pa.hash.data");
        assert!(fallback_result.has_failure(CAWG_IDENTITY_HARD_BINDING_MISSING));
    }

    #[test]
    fn empty_sig_type_is_rejected_by_signer_payload_schema() {
        let payload = Value::Map(vec![
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(binding_claim_refs(0x22)),
            ),
            (Value::Text("sig_type".into()), Value::Text(String::new())),
        ]);
        let results =
            identity_verdict_bytes(&identity_bytes(payload), &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CBOR_INVALID]);
    }

    #[test]
    fn empty_role_is_rejected_by_signer_payload_schema() {
        let payload = identity_payload("", None);
        let results =
            identity_verdict_bytes(&identity_bytes(payload), &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CBOR_INVALID]);
    }

    #[test]
    fn malformed_hashed_uri_is_rejected_by_signer_payload_schema() {
        let payload = identity_payload_with_binding("cawg.creator", Value::Map(Vec::new()), None);
        let results =
            identity_verdict_bytes(&identity_bytes(payload), &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CBOR_INVALID]);
    }

    #[test]
    fn empty_referenced_assertions_is_rejected_by_signer_payload_schema() {
        let assertion = identity_assertion_map(Vec::new());
        let results = identity_verdict(&assertion, &binding_claim_refs(0x22));
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CBOR_INVALID]);
    }

    #[test]
    fn missing_referenced_assertions_stays_cbor_invalid() {
        let assertion = Value::Map(vec![
            (
                Value::Text("signer_payload".into()),
                Value::Map(vec![(
                    Value::Text("sig_type".into()),
                    Value::Text(CAWG_X509_COSE.into()),
                )]),
            ),
            (Value::Text("signature".into()), Value::Bytes(vec![1])),
            (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
        ]);
        let results = identity_verdict(&assertion, &binding_claim_refs(0x22));
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CBOR_INVALID]);
    }
    #[test]
    fn referenced_identity_assertion_is_rejected() {
        let reference = hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/cawg.identity__secondary",
            0x44,
        );
        let assertion = identity_assertion_map(vec![reference.clone()]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(reference);
        let results = identity_verdict(&assertion, &claim_refs);
        let failure = results
            .failure
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH)
            .expect("identity reference must fail");
        assert_eq!(
            failure
                .details
                .as_ref()
                .and_then(|details| details["reason"].as_str()),
            Some("identity_assertion_reference")
        );
    }

    #[test]
    fn self_reference_cycle_is_rejected_with_machine_readable_reason() {
        let reference = hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/cawg.identity", 0x44);
        let assertion = identity_assertion_map(vec![reference.clone()]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(reference);
        let results = identity_verdict(&assertion, &claim_refs);
        let failure = results
            .failure
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH)
            .expect("identity cycle must fail");
        assert_eq!(
            failure
                .details
                .as_ref()
                .and_then(|details| details["reason"].as_str()),
            Some("reference_cycle")
        );
    }

    #[test]
    fn duplicated_reference_is_terminal_without_hard_binding_incorrect() {
        // Upstream precedence (c2pa-rs @ d7f13829, signer_payload.rs): a
        // duplicated reference is reported once as assertion.duplicate; the
        // hard-binding presence check runs on labels and does not also fire.
        let hard_binding = hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22);
        let assertion = identity_assertion_map(vec![hard_binding.clone(), hard_binding]);
        let results = identity_verdict(&assertion, &binding_claim_refs(0x22));
        assert_eq!(failure_codes(&results), [CAWG_IDENTITY_ASSERTION_DUPLICATE]);
    }

    #[test]
    fn two_distinct_hard_bindings_still_report_hard_binding_incorrect() {
        let assertion = identity_assertion_map(vec![
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22),
            hashed_uri(
                "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.boxes",
                0x33,
            ),
        ]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.boxes",
            0x33,
        ));
        let results = identity_verdict(&assertion, &claim_refs);
        assert_eq!(
            failure_codes(&results),
            [CAWG_IDENTITY_HARD_BINDING_INCORRECT]
        );
    }

    #[test]
    fn legacy_bmff_reference_cannot_transplant_the_claim_hard_binding() {
        let legacy = hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.bmff", 0x33);
        let assertion = identity_assertion_map(vec![legacy.clone()]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(legacy);
        let results = identity_verdict(&assertion, &claim_refs);
        assert_eq!(
            failure_codes(&results),
            [CAWG_IDENTITY_HARD_BINDING_MISSING]
        );
    }

    /// Prebuilt identity assertions whose COSE signature covers
    /// `signer_payload` encoded with the named profile, signed by a
    /// self-signed ES256 documentSigning leaf with a fixed 2025-2030 validity
    /// window. The assertion bytes preserve the stored field order
    /// (referenced_assertions, sig_type, role — NOT canonical).
    ///
    /// The fixtures are PREBUILT: this repository intentionally carries no
    /// COSE signing code, so they were generated once from the commercial
    /// engine's signer and vendored as bytes. The COSE embeds its own
    /// certificate chain, so verification is fully self-contained.
    fn signed_identity_assertion_bytes(profile: Profile) -> Vec<u8> {
        let hex_text = match profile {
            Profile::CanonicalForHashedSubstructures => {
                include_str!("tests/fixtures/cawg_identity_canonical.hex")
            }
            _ => include_str!("tests/fixtures/cawg_identity_legacy_field_order.hex"),
        };
        let hex_text = hex_text.trim();
        (0..hex_text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_text[i..i + 2], 16).expect("fixture hex"))
            .collect()
    }

    fn payload_encoding_detail(results: &ValidationResults) -> Option<String> {
        results
            .success
            .iter()
            .find(|status| {
                status.code == CAWG_IDENTITY_TRUSTED || status.code == CAWG_IDENTITY_WELL_FORMED
            })
            .and_then(|status| status.details.as_ref())
            .and_then(|details| details.get("payload_encoding"))
            .and_then(|value| value.as_str())
            .map(str::to_owned)
    }

    #[test]
    fn legacy_field_order_signature_verifies_when_explicitly_enabled() {
        let bytes = signed_identity_assertion_bytes(Profile::LegacyPipelineBDefinite);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), true);
        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(
            results.has_informational(CAWG_LEGACY_PROFILE),
            "legacy field-order verification must surface com.encypher.cawg.legacyProfile: {:?}",
            results.informational
        );
        assert_eq!(
            payload_encoding_detail(&results).as_deref(),
            Some("legacy-field-order")
        );
    }

    #[test]
    fn legacy_field_order_signature_fails_by_default() {
        let bytes = signed_identity_assertion_bytes(Profile::LegacyPipelineBDefinite);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), [CAWG_X509_SIGNATURE_MISMATCH]);
        assert!(!results.has_informational(CAWG_LEGACY_PROFILE));
    }

    #[test]
    fn canonical_signature_never_emits_the_legacy_signal() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        for strict in [false, true] {
            let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), strict);
            assert_eq!(
                failure_codes(&results),
                Vec::<&str>::new(),
                "strict={strict}"
            );
            assert!(!results.has_informational(CAWG_LEGACY_PROFILE));
            assert_eq!(
                payload_encoding_detail(&results).as_deref(),
                Some("canonical")
            );
        }
    }

    /// CAWG Identity 1.3 deletes `expected_countersigners` from the CDDL and
    /// forbids a validator from considering undocumented fields, so a payload
    /// that still carries one raises no countersigner status of any kind.
    #[test]
    fn expected_countersigners_are_no_longer_validated() {
        let secondary = identity_payload("cawg.publisher:secondary", None);
        let primary = identity_payload(
            "cawg.publisher:primary",
            Some(vec![countersigner_description(secondary.clone())]),
        );
        let primary_bytes = identity_bytes_with_padding(primary);
        let secondary_bytes = identity_bytes_with_padding(secondary);
        let unexpected_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:unexpected", None));
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.identity".into(), primary_bytes.as_slice()),
                ("cawg.identity__1".into(), secondary_bytes.as_slice()),
                ("cawg.identity__2".into(), unexpected_bytes.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let binding = hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22);
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 1),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__1", 2),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__2", 3),
            binding,
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let primary_binding = claim_refs
            .references
            .iter()
            .find(|reference| reference.label == Some("c2pa.hash.data"))
            .expect("hard binding");
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: datetime!(2025-05-01 0:00 UTC),
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
                document_signing_require_anchor: false,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients: IngredientResolution::default(),
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, Some(primary_binding), &[]);
        }
        assert!(
            !results
                .failure
                .iter()
                .any(|status| status.code.contains("countersigner")),
            "1.3 raises no countersigner status: {:?}",
            failure_codes(&results)
        );
    }

    /// CAWG Identity 1.3 status-codes: "The `url` field for a status code
    /// MUST always be the label of the identity assertion." Two identities in
    /// one manifest each report their own label, suffix included, rather than
    /// a JUMBF URI.
    #[test]
    fn every_identity_status_reports_the_assertion_label_as_its_url() {
        let primary_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:primary", None));
        let secondary_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:secondary", None));
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.identity".into(), primary_bytes.as_slice()),
                ("cawg.identity__1".into(), secondary_bytes.as_slice()),
            ],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 1),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__1", 2),
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x22),
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let primary_binding = claim_refs
            .references
            .iter()
            .find(|reference| reference.label == Some("c2pa.hash.data"))
            .expect("hard binding");
        let mut results = ValidationResults::default();
        let timestamp_index = TimestampAssertionIndex::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: IDENTITY_VALIDATION_TIME,
                claim_timestamp: None,
                cawg_trust: None,
                cawg_allowed_certs: None,
                ocsp_verification_time: IDENTITY_VALIDATION_TIME,
                document_signing_require_anchor: false,
                tsa_trust: None,
                timestamp_index: &timestamp_index,
                did_documents: None,
                allow_legacy_encoding: false,
                ica_trusted_issuers: None,
                ica_trust_anchors: None,
                ica_status_lists: None,
                evidence: Default::default(),
                ingredients: IngredientResolution::default(),
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, Some(primary_binding), &[]);
        }
        let urls: HashSet<&str> = results
            .success
            .iter()
            .chain(&results.informational)
            .chain(&results.failure)
            .map(|status| status.url.as_str())
            .collect();
        assert_eq!(
            urls,
            HashSet::from(["cawg.identity", "cawg.identity__1"]),
            "every CAWG status carries its assertion label"
        );
    }

    /// 1.3 validation-method: a validator SHALL NOT consider fields the
    /// `identity` rule does not document. A leftover `expected_partial_claim`
    /// is therefore neither schema-checked nor compared; validation proceeds to
    /// the signature, which no longer covers these bytes.
    #[test]
    fn undocumented_expected_fields_are_not_schema_checked() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let Ok(Value::Map(mut assertion)) = crate::c2pa_cbor::decode(&bytes) else {
            panic!("fixture must decode as a map");
        };
        for (key, value) in &mut assertion {
            if key.as_text() != Some("signer_payload") {
                continue;
            }
            let Value::Map(payload) = value else {
                panic!("signer_payload must be a map");
            };
            payload.push((
                Value::Text("expected_partial_claim".into()),
                Value::Text("not a hash map".into()),
            ));
        }
        let mutated = encode(
            &Value::Map(assertion),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("re-encode mutated assertion");
        let results = identity_verdict_bytes(&mutated, &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), ["cawg.x509.signature.mismatch"]);
    }

    /// The X.509 lane reports the registered `cawg.x509.*` set from the 1.3
    /// status-code table, with no Encypher-scoped substitutes.
    #[test]
    fn x509_validation_reports_registered_1_3_codes() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        let success: Vec<&str> = results
            .success
            .iter()
            .map(|status| status.code.as_str())
            .collect();
        for code in [
            "cawg.x509.signature.validated",
            "cawg.x509.credential.trusted",
            "cawg.x509.signature.inside_validity",
            "cawg.identity.trusted",
        ] {
            assert!(success.contains(&code), "missing {code}: {success:?}");
        }
        assert!(
            results.has_informational("cawg.x509.ocsp.skipped"),
            "offline validation declines the online OCSP check: {:?}",
            results.informational
        );
        assert!(
            !results
                .success
                .iter()
                .chain(&results.informational)
                .chain(&results.failure)
                .any(|status| {
                    status.code.starts_with("com.encypher.cawg.")
                        && status.code != CAWG_LEGACY_PROFILE
                }),
            "the legacy-profile signal is the only Encypher-scoped CAWG code left after the 1.3 cutover"
        );
    }

    /// 1.3: a chain that cannot be verified against configured trust material
    /// is a rejection, not a well-formed observation.
    #[test]
    fn configured_trust_that_the_chain_cannot_reach_is_a_rejection() {
        let unrelated = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, false);
        let allowed = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [unrelated]);
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let results = identity_verdict_with_trust(&bytes, Some(&allowed), true);
        assert!(
            results.has_failure("cawg.x509.credential.untrusted"),
            "expected a rejection: {:?}",
            failure_codes(&results)
        );
        assert!(!results.has_success(CAWG_IDENTITY_WELL_FORMED));
        assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// With no CAWG trust material at all there is no root of trust to reach,
    /// which the 1.3 status table still reports as `cawg.identity.well-formed`.
    #[test]
    fn absent_trust_configuration_stays_well_formed() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let results = identity_verdict_with_trust(&bytes, None, true);
        assert!(
            results.has_success(CAWG_IDENTITY_WELL_FORMED),
            "expected well-formed: {:?}",
            results.success
        );
        assert!(!results.has_failure("cawg.x509.credential.untrusted"));
    }

    /// The COSE signature bytes of the vendored identity fixture.
    fn fixture_identity_cose(bytes: &[u8]) -> Vec<u8> {
        crate::c2pa_cbor::decode(bytes)
            .expect("fixture decodes")
            .get("signature")
            .and_then(Value::as_bytes)
            .expect("fixture carries a COSE signature")
            .to_vec()
    }

    /// Index one `c2pa.time-stamp` assertion mapping the test manifest to
    /// `token`.
    fn timestamp_assertion_index(token: Vec<u8>) -> TimestampAssertionIndex {
        let payload = encode(
            &Value::Map(vec![(Value::Text("test".into()), Value::Bytes(token))]),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode time-stamp assertion");
        let mut index = TimestampAssertionIndex::default();
        let mut results = ValidationResults::default();
        assert!(
            super::super::timestamp_assertion::index_timestamp_assertion(
                &mut index,
                super::super::timestamp_assertion::TimestampAssertionScope::Manifest,
                &payload,
                &mut results,
                "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.time-stamp",
            )
        );
        index
    }

    /// CAWG 1.3 source order: with no `sigTst2` header, a `c2pa.time-stamp`
    /// assertion keyed to the containing manifest supplies the attested time.
    #[test]
    fn time_stamp_assertion_establishes_the_attested_signing_time() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let cose = fixture_identity_cose(&bytes);
        let tsa = crate::c2pa_trust::timestamp_fixture::TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_assertion_input(&cose).expect("time-stamp assertion input");
        let token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        let index = timestamp_assertion_index(token);
        let results = identity_verdict_with_timestamp(&bytes, Some(&tsa.trust_list()), &index);

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(results.has_success("cawg.x509.time_stamp.validated"));
        assert!(results.has_success("cawg.x509.time_stamp.trusted"));
        // An attested time replaces the current time, so the no-time-stamp
        // success code is not issued.
        assert!(!results.has_success("cawg.x509.signature.inside_validity"));
        let trusted = results
            .success
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_TRUSTED)
            .expect("identity trusted");
        let details = trusted.details.as_ref().expect("trust details");
        assert_eq!(details["timestamp_trusted"], true);
        assert_eq!(details["trusted_at"], "2025-04-01 0:00:00.0 +00:00:00");
    }

    /// A time stamp the validator cannot validate is informational, and the
    /// assertion keeps its identity verdict rather than being rejected.
    #[test]
    fn unusable_time_stamp_is_informational_and_ignored() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let index = timestamp_assertion_index(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        let results = identity_verdict_with_timestamp(&bytes, None, &index);

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(
            results.has_informational("cawg.x509.time_stamp.malformed"),
            "{:?}",
            results.informational
        );
        assert!(results.has_success("cawg.x509.signature.inside_validity"));
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    // -----------------------------------------------------------------
    // Encypher-issued CAWG identities
    //
    // Signing tests mint their P-384 hierarchy in memory. The certificate-only
    // fixtures remain below for acceptance testing against the exact output of
    // the production `encypher_pki.cawg_identity` issuance profile.
    // -----------------------------------------------------------------

    const ENCYPHER_ROOT_PEM: &str = include_str!("tests/fixtures/encypher_cawg/root.pem");
    const ENCYPHER_ISSUING_PEM: &str = include_str!("tests/fixtures/encypher_cawg/issuing-ca.pem");
    const ENCYPHER_LEAF_PEM: &str = include_str!("tests/fixtures/encypher_cawg/leaf.pem");
    const ORGANIZATION_VALIDATED_STRICT_POLICY: &str = "2.23.140.1.5.2.3";
    const MAILBOX_VALIDATED_POLICY: &str = "2.23.140.1.5.1.1";

    /// Inside the fixture chain's validity and past the 31 March 2027 cutoff
    /// of the interim S/MIME additions.
    const AFTER_INTERIM_CUTOFF: OffsetDateTime = datetime!(2027-06-01 0:00 UTC);
    /// Before that cutoff, for a time stamp that has to rescue the interim
    /// lane at a later validation time.
    const BEFORE_INTERIM_CUTOFF: OffsetDateTime = datetime!(2027-03-01 0:00 UTC);

    fn fixture_der(pem: &str) -> Vec<u8> {
        TrustList::from_pem_for(AnchorPurpose::CawgIdentity, pem)
            .expect("fixture certificate")
            .anchors
            .into_iter()
            .next()
            .expect("fixture certificate")
            .certificate
    }

    struct RuntimeEncypherChain {
        root_pem: String,
        issuing_der: Vec<u8>,
        leaf_der: Vec<u8>,
        leaf_key_pem: String,
    }

    /// Mint the material needed to sign a test assertion without persisting a
    /// private key. The hierarchy matches the production profile's
    /// cryptographic constraints: P-384 throughout, root pathlen 1, issuing
    /// pathlen 0, emailProtection on the issuing and leaf certificates,
    /// keyCertSign+cRLSign on both CAs, digitalSignature+contentCommitment on
    /// the leaf, the production S/MIME policy on both CAs, and the selected
    /// S/MIME policy on the leaf.
    fn runtime_encypher_chain(policy: &str) -> RuntimeEncypherChain {
        fn name(common_name: &str) -> DistinguishedName {
            let mut name = DistinguishedName::new();
            name.push(DnType::CountryName, "US");
            name.push(DnType::OrganizationName, "Encypher Corporation");
            name.push(DnType::CommonName, common_name);
            name
        }

        fn add_policy(params: &mut CertificateParams, policy: &str) {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 32],
                    certificate_policies_value(policy),
                ));
        }

        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 root key");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params.distinguished_name = name("Encypher CAWG Runtime Root");
        root_params.not_before = datetime!(2026-12-31 23:55 UTC);
        root_params.not_after = datetime!(2047-01-01 0:00 UTC);
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root_params.use_authority_key_identifier_extension = true;
        add_policy(&mut root_params, ORGANIZATION_VALIDATED_STRICT_POLICY);
        let root = root_params.self_signed(&root_key).expect("runtime root");

        let issuing_key =
            KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 issuing key");
        let mut issuing_params =
            CertificateParams::new(Vec::<String>::new()).expect("issuing params");
        issuing_params.distinguished_name = name("Encypher CAWG Runtime Issuing CA");
        issuing_params.not_before = datetime!(2026-12-31 23:55 UTC);
        issuing_params.not_after = datetime!(2032-01-02 0:00 UTC);
        issuing_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        issuing_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        issuing_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        issuing_params.use_authority_key_identifier_extension = true;
        add_policy(&mut issuing_params, ORGANIZATION_VALIDATED_STRICT_POLICY);
        let issuing = issuing_params
            .signed_by(&issuing_key, &root, &root_key)
            .expect("runtime issuing CA");

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 leaf key");
        let mut leaf_params = CertificateParams::new(vec!["identity.fixture.encypher.test".into()])
            .expect("leaf params");
        leaf_params.distinguished_name = name("Encypher CAWG Runtime Publisher");
        leaf_params.not_before = datetime!(2026-12-31 23:55 UTC);
        leaf_params.not_after = datetime!(2028-01-02 0:00 UTC);
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        leaf_params.use_authority_key_identifier_extension = true;
        add_policy(&mut leaf_params, policy);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuing, &issuing_key)
            .expect("runtime identity leaf");

        RuntimeEncypherChain {
            root_pem: root.pem(),
            issuing_der: issuing.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    fn encypher_root_trust(root_pem: &str, source: CawgTrustSource) -> TrustList {
        TrustList::from_pem_for(AnchorPurpose::CawgIdentity, root_pem)
            .expect("runtime root")
            .with_cawg_source(source)
    }

    /// Sign a CAWG identity assertion with an in-memory ES384 leaf, optionally
    /// counter-signed by `tsa` at `attested`.
    fn encypher_identity_assertion(
        chain: &RuntimeEncypherChain,
        timestamp: Option<(&TestTsa, OffsetDateTime)>,
    ) -> Vec<u8> {
        encypher_identity_assertion_for(
            identity_payload("cawg.publisher:primary", None),
            chain,
            timestamp,
        )
    }

    /// The same, over a caller-supplied `signer_payload`.
    fn encypher_identity_assertion_for(
        payload: Value,
        chain: &RuntimeEncypherChain,
        timestamp: Option<(&TestTsa, OffsetDateTime)>,
    ) -> Vec<u8> {
        use p384::ecdsa::signature::Signer as _;
        use p384::pkcs8::DecodePrivateKey as _;

        let canonical = encode(&payload, Profile::CanonicalForHashedSubstructures)
            .expect("encode signer_payload");
        let protected = encode(
            &Value::Map(vec![
                (Value::Integer(1), Value::Integer(-35)),
                (
                    Value::Integer(33),
                    Value::Array(vec![
                        Value::Bytes(chain.leaf_der.clone()),
                        Value::Bytes(chain.issuing_der.clone()),
                    ]),
                ),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode protected header");
        let sig_input = encode(
            &Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(protected.clone()),
                Value::Bytes(Vec::new()),
                Value::Bytes(canonical),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode Sig_structure");
        let key =
            p384::ecdsa::SigningKey::from_pkcs8_pem(&chain.leaf_key_pem).expect("runtime leaf key");
        let signature: p384::ecdsa::Signature = key.sign(&sig_input);
        let cose = |unprotected: Vec<(Value, Value)>| {
            encode(
                &Value::Tag(
                    18,
                    Box::new(Value::Array(vec![
                        Value::Bytes(protected.clone()),
                        Value::Map(unprotected),
                        Value::Null,
                        Value::Bytes(signature.to_der().as_bytes().to_vec()),
                    ])),
                ),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode COSE_Sign1")
        };
        let signed = match timestamp {
            None => cose(Vec::new()),
            Some((tsa, attested)) => {
                let input = timestamp_input(&cose(Vec::new())).expect("time-stamp input");
                let token = tsa.token(&input, attested);
                cose(vec![(
                    Value::Text("sigTst2".into()),
                    Value::Map(vec![(
                        Value::Text("tstTokens".into()),
                        Value::Array(vec![Value::Map(vec![(
                            Value::Text("val".into()),
                            Value::Bytes(token),
                        )])]),
                    )]),
                )])
            }
        };
        encode(
            &Value::Map(vec![
                (Value::Text("signer_payload".into()), payload),
                (Value::Text("signature".into()), Value::Bytes(signed)),
                (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
            ]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("encode identity assertion")
    }

    /// The C2PA hashed-URI CDDL: "If this field is absent, the hash algorithm
    /// is taken from an enclosing structure". A claim reference that inherits
    /// the claim's `alg` and an identity reference that spells the same
    /// algorithm out name the same assertion, so comparing the raw fields
    /// reports a mismatch that does not exist.
    #[test]
    fn a_referenced_assertion_inherits_the_claim_hash_algorithm_before_comparison() {
        let url = "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data";
        let inherited = Value::Map(vec![
            ("url".into(), Value::Text(url.into())),
            ("hash".into(), Value::Bytes(vec![0x22; 32])),
        ]);
        let payload =
            identity_payload_with_binding("cawg.publisher:primary", hashed_uri(url, 0x22), None);
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion_for(payload, &chain, None);
        let claim_refs = vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 0x01),
            inherited,
        ];
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let results = identity_verdict_full(
            &bytes,
            &claim_refs,
            false,
            "c2pa.hash.data",
            Some(&trust),
            None,
            true,
            None,
            &TimestampAssertionIndex::default(),
            AFTER_INTERIM_CUTOFF,
            None,
            Default::default(),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    #[allow(clippy::too_many_arguments)]
    fn encypher_verdict(
        bytes: &[u8],
        trust: &TrustList,
        at: OffsetDateTime,
        tsa_trust: Option<&TrustList>,
        claim_timestamp: Option<OffsetDateTime>,
    ) -> ValidationResults {
        identity_verdict_full(
            bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            Some(trust),
            None,
            true,
            tsa_trust,
            &TimestampAssertionIndex::default(),
            at,
            claim_timestamp,
            Default::default(),
        )
    }

    fn trusted_details(results: &ValidationResults) -> &serde_json::Value {
        results
            .success
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_TRUSTED)
            .expect("identity trusted")
            .details
            .as_ref()
            .expect("trust details")
    }

    fn untrusted_reason(results: &ValidationResults) -> String {
        results
            .failure
            .iter()
            .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
            .expect("credential untrusted")
            .details
            .as_ref()
            .and_then(|details| details["reason"].as_str())
            .expect("rejection reason")
            .to_string()
    }

    /// An identity issued under an Encypher trust configuration entry is
    /// trusted after 31 March 2027 with no time stamp at all. CAWG Identity
    /// 1.3 ties the interim conditions to the Mozilla and IPTC lists; an
    /// anchor the validator configured itself is a base-model entry.
    #[test]
    fn an_encypher_configured_anchor_trusts_an_identity_past_the_interim_cutoff() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(results.has_success(CAWG_X509_CREDENTIAL_TRUSTED));
        let details = trusted_details(&results);
        assert_eq!(details["trust_source"], "caller_supplied");
        // The anchor that accepted the chain, so a consumer can tell one root
        // from another inside the same configuration entry.
        let root_der = trust.certificates().next().expect("one anchor");
        assert_eq!(
            details["anchor_fingerprint"],
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(root_der))
        );
        assert_eq!(details["accepted_eku"], OID_KP_EMAIL_PROTECTION);
        assert_eq!(details["certificate_policy"], "2.23.140.1.5.2.3");
        assert_eq!(details["timestamp_trusted"], false);
    }

    /// The same leaf, the same chain, the same instant: configured as an
    /// interim S/MIME source the entry keeps the interim conditions, and past
    /// the cutoff only a trusted time stamp could still satisfy them.
    #[test]
    fn the_interim_entry_still_binds_the_cutoff_for_the_same_chain() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::SmimeInterim);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

        assert!(results.has_failure(CAWG_X509_CREDENTIAL_UNTRUSTED));
        assert_eq!(untrusted_reason(&results), "trusted_timestamp_required");
        assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// An Encypher-configured entry accepts `emailProtection` only with one of
    /// the six approved policies. Mailbox-validated is not one of them.
    #[test]
    fn a_configured_entry_still_requires_an_approved_certificate_policy() {
        let chain = runtime_encypher_chain(MAILBOX_VALIDATED_POLICY);
        let trust = encypher_root_trust(
            &chain.root_pem,
            CawgTrustSource::EncypherVerifiedOrganizations,
        );
        let bytes = encypher_identity_assertion(&chain, None);
        let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

        assert!(results.has_failure(CAWG_X509_CREDENTIAL_UNTRUSTED));
        assert_eq!(untrusted_reason(&results), "smime_policy_not_accepted");
        assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// Interim condition 1 is disjunctive: the time of validation is on or
    /// before 31 March 2027 *or* a trusted time stamp establishes that the
    /// identity assertion was issued by then. A validator that demands the
    /// time stamp in both arms rejects credentials 1.3 requires it to accept.
    #[test]
    fn the_interim_entry_accepts_an_untimestamped_credential_before_the_cutoff() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::SmimeInterim);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = encypher_verdict(&bytes, &trust, BEFORE_INTERIM_CUTOFF, None, None);

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        let details = trusted_details(&results);
        assert_eq!(details["trust_source"], "smime_interim");
        assert_eq!(details["timestamp_trusted"], false);
    }

    /// 1.3 source order, first source: the identity assertion's own `sigTst2`
    /// token. Its attested time is what the interim cutoff is measured
    /// against, so a credential validated in June 2027 is still accepted by
    /// the interim entry when the token proves a March 2027 signature.
    #[test]
    fn an_identity_sig_tst2_establishes_the_interim_signing_time() {
        let tsa = TestTsa::new(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::SmimeInterim);
        let bytes = encypher_identity_assertion(&chain, Some((&tsa, BEFORE_INTERIM_CUTOFF)));
        let results = encypher_verdict(
            &bytes,
            &trust,
            AFTER_INTERIM_CUTOFF,
            Some(&tsa.trust_list()),
            None,
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(results.has_success("cawg.x509.time_stamp.trusted"));
        let details = trusted_details(&results);
        assert_eq!(details["trust_source"], "smime_interim");
        assert_eq!(details["timestamp_trusted"], true);
        assert_eq!(details["trusted_at"], BEFORE_INTERIM_CUTOFF.to_string());
    }

    /// 1.3 source order, last source: with no identity time stamp and no
    /// `c2pa.time-stamp` assertion, the claim signature's own trusted time
    /// stamp supplies the attested time, and it too satisfies the interim
    /// condition.
    #[test]
    fn the_claim_signature_time_stamp_is_the_last_interim_source() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::SmimeInterim);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = encypher_verdict(
            &bytes,
            &trust,
            AFTER_INTERIM_CUTOFF,
            None,
            Some(BEFORE_INTERIM_CUTOFF),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        let details = trusted_details(&results);
        assert_eq!(details["trust_source"], "smime_interim");
        assert_eq!(details["timestamp_trusted"], true);
        assert_eq!(details["trusted_at"], BEFORE_INTERIM_CUTOFF.to_string());
    }

    /// The Encypher chain is offered to the C2PA certificate profile and the
    /// RFC 5280 path checks exactly as `encypher_pki` emits it: an EKU on the
    /// issuing CA, AIA, CRL distribution points, and a policy with a CPS
    /// qualifier are all accepted.
    #[test]
    fn the_encypher_issuance_profile_satisfies_the_certificate_path_checks() {
        let leaf = fixture_der(ENCYPHER_LEAF_PEM);
        assert!(leaf_profile_acceptable_der(&leaf));
        let trust = encypher_root_trust(
            ENCYPHER_ROOT_PEM,
            CawgTrustSource::EncypherVerifiedOrganizations,
        );
        let result = validate_chain(
            &leaf,
            &[fixture_der(ENCYPHER_ISSUING_PEM)],
            &trust,
            AnchorPurpose::CawgIdentity,
            Some(AFTER_INTERIM_CUTOFF),
        );
        assert!(result.trusted, "{:?}", result.reason);
        assert_eq!(
            result
                .terminating_anchor(&trust)
                .map(|anchor| anchor.cawg_source),
            Some(CawgTrustSource::EncypherVerifiedOrganizations)
        );
    }

    /// CAWG Identity 1.3, "Determining revocation from online OCSP response".
    ///
    /// The identity lane runs the same procedure as the C2PA claim signer and
    /// reports it with the `cawg.x509.*` codes, scoped to the assertion that
    /// carried the credential. Every response is minted in process: no test
    /// here opens a socket.
    mod online_ocsp {
        use std::collections::HashMap;

        use sha2::Digest as _;

        use super::*;
        use crate::c2pa_trust::ocsp::fixture::{response, FixtureStatus, Responder, ResponseSpec};
        use crate::c2pa_validate::signature_conformance_tests::aia_extension;
        use crate::c2pa_validate::{NetworkNeed, OnlineEvidence};

        /// The responder the identity leaf publishes in its AIA extension.
        const RESPONDER_URL: &str = "http://ocsp.cawg.test/responder";
        /// The label of the assertion every status and need here is scoped to.
        const ASSERTION_LABEL: &str = "cawg.identity";
        /// A revocation that precedes the instant these tests validate at.
        const REVOKED_AT: &[u8] = b"20270201000000Z";
        /// A freshness window inside the chain's validity: RFC 6960 authorizes
        /// a responder only if its certificate is valid at `producedAt`, and
        /// this chain is issued for 2027 onward.
        const WINDOW: ResponseSpec = ResponseSpec {
            status: FixtureStatus::Good,
            produced_at: b"20270101000000Z",
            this_update: b"20270101000000Z",
            next_update: Some(b"20280101000000Z"),
        };

        /// A CAWG identity chain minted on P-256, the curve the RFC 6960
        /// fixture responder signs with, so the issuing CA can answer for the
        /// leaf and the root can answer for the issuing CA. The leaf carries
        /// the same emailProtection and S/MIME policy profile as
        /// `runtime_encypher_chain`, plus an AIA OCSP access location.
        struct OcspChain {
            root_der: Vec<u8>,
            root_pem: String,
            root_key: KeyPair,
            issuing_der: Vec<u8>,
            issuing_key: KeyPair,
            leaf_der: Vec<u8>,
            leaf_key_pem: String,
        }

        fn ocsp_chain() -> OcspChain {
            fn name(common_name: &str) -> DistinguishedName {
                let mut name = DistinguishedName::new();
                name.push(DnType::CountryName, "US");
                name.push(DnType::OrganizationName, "Encypher Corporation");
                name.push(DnType::CommonName, common_name);
                name
            }

            fn add_policy(params: &mut CertificateParams) {
                params
                    .custom_extensions
                    .push(CustomExtension::from_oid_content(
                        &[2, 5, 29, 32],
                        certificate_policies_value(ORGANIZATION_VALIDATED_STRICT_POLICY),
                    ));
            }

            let root_key = KeyPair::generate().expect("P-256 root key");
            let mut root_params =
                CertificateParams::new(Vec::<String>::new()).expect("root params");
            root_params.distinguished_name = name("Encypher CAWG OCSP Root");
            root_params.not_before = datetime!(2026-12-31 23:55 UTC);
            root_params.not_after = datetime!(2047-01-01 0:00 UTC);
            root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            root_params.use_authority_key_identifier_extension = true;
            add_policy(&mut root_params);
            let root = root_params.self_signed(&root_key).expect("runtime root");

            let issuing_key = KeyPair::generate().expect("P-256 issuing key");
            let mut issuing_params =
                CertificateParams::new(Vec::<String>::new()).expect("issuing params");
            issuing_params.distinguished_name = name("Encypher CAWG OCSP Issuing CA");
            issuing_params.not_before = datetime!(2026-12-31 23:55 UTC);
            issuing_params.not_after = datetime!(2032-01-02 0:00 UTC);
            issuing_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            issuing_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            issuing_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            issuing_params.use_authority_key_identifier_extension = true;
            add_policy(&mut issuing_params);
            let issuing = issuing_params
                .signed_by(&issuing_key, &root, &root_key)
                .expect("runtime issuing CA");

            let leaf_key = KeyPair::generate().expect("P-256 leaf key");
            let mut leaf_params =
                CertificateParams::new(vec!["identity.ocsp.encypher.test".into()])
                    .expect("leaf params");
            leaf_params.distinguished_name = name("Encypher CAWG OCSP Publisher");
            leaf_params.not_before = datetime!(2026-12-31 23:55 UTC);
            leaf_params.not_after = datetime!(2028-01-02 0:00 UTC);
            leaf_params.is_ca = IsCa::ExplicitNoCa;
            leaf_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::ContentCommitment,
            ];
            leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            leaf_params.use_authority_key_identifier_extension = true;
            add_policy(&mut leaf_params);
            leaf_params
                .custom_extensions
                .push(aia_extension(RESPONDER_URL));
            let leaf = leaf_params
                .signed_by(&leaf_key, &issuing, &issuing_key)
                .expect("runtime identity leaf");

            OcspChain {
                root_der: root.der().to_vec(),
                root_pem: root.pem(),
                root_key,
                issuing_der: issuing.der().to_vec(),
                issuing_key,
                leaf_der: leaf.der().to_vec(),
                leaf_key_pem: leaf_key.serialize_pem(),
            }
        }

        /// The evidence key a caller supplies a response under.
        fn evidence_key(certificate_der: &[u8]) -> String {
            hex::encode(sha2::Sha256::digest(certificate_der))
        }

        /// Sign a CAWG identity assertion with the chain's ES256 leaf.
        fn identity_assertion(chain: &OcspChain) -> Vec<u8> {
            use p256::ecdsa::signature::Signer as _;
            use p256::pkcs8::DecodePrivateKey as _;

            let payload = identity_payload("cawg.publisher:primary", None);
            let canonical = encode(&payload, Profile::CanonicalForHashedSubstructures)
                .expect("encode signer_payload");
            let protected = encode(
                &Value::Map(vec![
                    (Value::Integer(1), Value::Integer(-7)),
                    (
                        Value::Integer(33),
                        Value::Array(vec![
                            Value::Bytes(chain.leaf_der.clone()),
                            Value::Bytes(chain.issuing_der.clone()),
                        ]),
                    ),
                ]),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode protected header");
            let sig_input = encode(
                &Value::Array(vec![
                    Value::Text("Signature1".into()),
                    Value::Bytes(protected.clone()),
                    Value::Bytes(Vec::new()),
                    Value::Bytes(canonical),
                ]),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode Sig_structure");
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&chain.leaf_key_pem)
                .expect("runtime leaf key");
            let signature: p256::ecdsa::Signature = key.sign(&sig_input);
            let cose = encode(
                &Value::Tag(
                    18,
                    Box::new(Value::Array(vec![
                        Value::Bytes(protected),
                        Value::Map(Vec::new()),
                        Value::Null,
                        Value::Bytes(signature.to_der().as_bytes().to_vec()),
                    ])),
                ),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode COSE_Sign1");
            encode(
                &Value::Map(vec![
                    (Value::Text("signer_payload".into()), payload),
                    (Value::Text("signature".into()), Value::Bytes(cose)),
                    (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
                ]),
                Profile::CanonicalForHashedSubstructures,
            )
            .expect("encode identity assertion")
        }

        /// Verify one identity assertion from `chain` against caller-supplied
        /// online evidence, at an instant inside every certificate validity
        /// window and inside every minted response's freshness interval.
        fn verdict(chain: &OcspChain, evidence: OnlineEvidence<'_>) -> ValidationResults {
            let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
            identity_verdict_full(
                &identity_assertion(chain),
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&trust),
                None,
                true,
                None,
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                evidence,
            )
        }

        /// Verify with one minted response per certificate.
        fn verdict_with_responses(
            chain: &OcspChain,
            responses: HashMap<String, Vec<u8>>,
        ) -> ValidationResults {
            verdict(
                chain,
                OnlineEvidence {
                    ocsp_responses: Some(&responses),
                    ..OnlineEvidence::default()
                },
            )
        }

        /// A response about `subject`, signed directly by its `issuer`, which
        /// RFC 6960 4.2.2.2 authorizes without a delegated responder.
        fn answer(
            issuer_der: &[u8],
            issuer_key: &KeyPair,
            subject_der: &[u8],
            status: FixtureStatus,
        ) -> Vec<u8> {
            response(
                issuer_der,
                subject_der,
                &Responder {
                    certificate_der: issuer_der,
                    key: issuer_key,
                    embed_certificate: false,
                },
                ResponseSpec { status, ..WINDOW },
            )
        }

        /// A response about the identity leaf, signed by its issuing CA.
        fn leaf_response(chain: &OcspChain, status: FixtureStatus) -> (String, Vec<u8>) {
            (
                evidence_key(&chain.leaf_der),
                answer(
                    &chain.issuing_der,
                    &chain.issuing_key,
                    &chain.leaf_der,
                    status,
                ),
            )
        }

        /// A response about the issuing CA, signed by the root.
        fn issuing_response(chain: &OcspChain, status: FixtureStatus) -> (String, Vec<u8>) {
            (
                evidence_key(&chain.issuing_der),
                answer(&chain.root_der, &chain.root_key, &chain.issuing_der, status),
            )
        }

        #[test]
        fn an_offline_identity_run_records_the_query_that_would_settle_revocation() {
            let chain = ocsp_chain();
            let results = verdict(&chain, OnlineEvidence::default());

            assert!(
                results.has_informational(CAWG_X509_OCSP_SKIPPED),
                "{:?}",
                results.informational
            );
            assert_eq!(
                results
                    .network_needs
                    .iter()
                    .map(NetworkNeed::to_json)
                    .collect::<Vec<_>>(),
                vec![json!({
                    "kind": "ocsp",
                    "purpose": "cawg_identity",
                    "assertion_label": ASSERTION_LABEL,
                    "responder_url": RESPONDER_URL,
                    "certificate_sha256": evidence_key(&chain.leaf_der),
                })]
            );
            let Some(NetworkNeed::Ocsp { request_der, .. }) = results.network_needs.first() else {
                panic!("the recorded identity need is an OCSP query");
            };
            assert!(
                !request_der.is_empty() && request_der[0] == 0x30,
                "the need carries the DER OCSPRequest a fetcher would POST"
            );
        }

        #[test]
        fn a_good_online_identity_response_replaces_the_skipped_code() {
            let chain = ocsp_chain();
            let results = verdict_with_responses(
                &chain,
                HashMap::from([leaf_response(&chain, FixtureStatus::Good)]),
            );

            assert!(
                results.has_success(CAWG_X509_OCSP_NOT_REVOKED),
                "{:?}",
                results.success
            );
            assert!(!results.has_informational(CAWG_X509_OCSP_SKIPPED));
            assert!(
                results.network_needs.is_empty(),
                "an answered question asks nothing: {:?}",
                results.network_needs
            );
            assert_eq!(failure_codes(&results), Vec::<&str>::new());
            assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
        }

        #[test]
        fn a_revoked_identity_leaf_is_a_revoked_credential() {
            let chain = ocsp_chain();
            let results = verdict_with_responses(
                &chain,
                HashMap::from([leaf_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT))]),
            );

            assert_eq!(failure_codes(&results), [CAWG_IDENTITY_CREDENTIAL_REVOKED]);
            assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
        }

        /// 1.3 separates the two rejections: a revoked CA in the chain is an
        /// untrusted credential, not a revoked named actor.
        #[test]
        fn a_revoked_ca_in_the_identity_chain_is_an_untrusted_credential() {
            let chain = ocsp_chain();
            let results = verdict_with_responses(
                &chain,
                HashMap::from([
                    leaf_response(&chain, FixtureStatus::Good),
                    issuing_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT)),
                ]),
            );

            assert_eq!(failure_codes(&results), [CAWG_X509_CREDENTIAL_UNTRUSTED]);
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
        }

        #[test]
        fn an_unknown_identity_response_is_informational_and_leaves_trust_intact() {
            let chain = ocsp_chain();
            let results = verdict_with_responses(
                &chain,
                HashMap::from([leaf_response(&chain, FixtureStatus::Unknown)]),
            );

            assert!(
                results.has_informational(CAWG_X509_OCSP_UNKNOWN),
                "{:?}",
                results.informational
            );
            assert!(!results.has_informational(CAWG_X509_OCSP_SKIPPED));
            assert_eq!(failure_codes(&results), Vec::<&str>::new());
            assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
        }

        /// A responder the caller tried and could not reach is a different
        /// outcome from one that was never asked: the query has already been
        /// made, so it is not recorded again as a need.
        #[test]
        fn an_identity_responder_that_was_tried_and_failed_reports_inaccessible() {
            let chain = ocsp_chain();
            let unreachable = vec![evidence_key(&chain.leaf_der)];
            let results = verdict(
                &chain,
                OnlineEvidence {
                    ocsp_unreachable: Some(&unreachable),
                    ..OnlineEvidence::default()
                },
            );

            assert!(
                results.has_informational(CAWG_X509_OCSP_INACCESSIBLE),
                "{:?}",
                results.informational
            );
            assert!(!results.has_informational(CAWG_X509_OCSP_SKIPPED));
            assert!(results.network_needs.is_empty());
        }

        /// The identity credential is the assertion's, not the claim's. Every
        /// status a revoked identity produces names the assertion, and none of
        /// them is a C2PA claim-signature code: the manifest's own integrity
        /// and signing credential are judged separately and stay untouched.
        #[test]
        fn identity_revocation_is_scoped_to_the_assertion() {
            let chain = ocsp_chain();
            let results = verdict_with_responses(
                &chain,
                HashMap::from([leaf_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT))]),
            );

            for status in results
                .success
                .iter()
                .chain(&results.informational)
                .chain(&results.failure)
            {
                assert_eq!(status.url, ASSERTION_LABEL, "{status:?}");
                assert!(
                    status.code.starts_with("cawg."),
                    "an identity verdict reports only CAWG codes: {status:?}"
                );
            }
        }
    }
}
