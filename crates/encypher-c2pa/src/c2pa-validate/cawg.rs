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
    leaf_profile_acceptable_der, validate_chain_admitting, AnchorPurpose, CawgTrustSource,
    TrustAnchor, TrustList,
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
/// The protected `iat` is inside the credential validity window but later
/// than the trusted time-stamp used for signature validation.
pub const CAWG_X509_TIME_OF_SIGNING_AFTER_TIMESTAMP: &str =
    "com.encypher.cawg.x509.time_of_signing.afterTimestamp";
pub const CAWG_X509_OCSP_NOT_REVOKED: &str = "cawg.x509.ocsp.not_revoked";
pub const CAWG_X509_OCSP_SKIPPED: &str = "cawg.x509.ocsp.skipped";
/// An online OCSP query was attempted, but the responder or transport returned
/// no response.
pub const CAWG_X509_OCSP_INACCESSIBLE: &str = "cawg.x509.ocsp.inaccessible";
/// An accepted response did not cover the effective validation instant.
pub const CAWG_X509_OCSP_OUTSIDE_WINDOW: &str = "com.encypher.cawg.x509.ocsp.outsideWindow";
/// Response bytes arrived but could not establish a usable OCSP answer.
pub const CAWG_X509_OCSP_UNUSABLE_RESPONSE: &str = "com.encypher.cawg.x509.ocsp.unusableResponse";
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
    super::is_cawg_assertion_instance(label, "cawg.identity")
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IdentityWorkCounts {
    identity_evaluations: usize,
    cryptographic_evaluations: usize,
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
    let reference_cycles = identity_reference_cycles(claim_refs, &ctx.manifest.label);

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
            reference_cycles.contains(label),
        );
    }
}

#[derive(Clone, Copy)]
enum IdentityShapeDefect {
    DuplicateKey,
    SignerPayloadMissing,
    SignerPayloadInvalid,
    SignatureMissing,
    SignatureEmpty,
    Padding,
}

struct IdentityShape<'a> {
    signer_payload: &'a Value,
    referenced: &'a Vec<Value>,
    signature: &'a [u8],
}

fn identity_shape(assertion: &Value) -> Result<IdentityShape<'_>, IdentityShapeDefect> {
    if !map_keys_are_unique(assertion) {
        return Err(IdentityShapeDefect::DuplicateKey);
    }
    let signer_payload = assertion
        .get("signer_payload")
        .ok_or(IdentityShapeDefect::SignerPayloadMissing)?;
    let referenced =
        valid_signer_payload(signer_payload).ok_or(IdentityShapeDefect::SignerPayloadInvalid)?;
    let signature = assertion
        .get("signature")
        .and_then(Value::as_bytes)
        .ok_or(IdentityShapeDefect::SignatureMissing)?;
    if signature.is_empty() {
        return Err(IdentityShapeDefect::SignatureEmpty);
    }
    if !valid_padding(assertion.get("pad1"), true) || !valid_padding(assertion.get("pad2"), false) {
        return Err(IdentityShapeDefect::Padding);
    }
    Ok(IdentityShape {
        signer_payload,
        referenced,
        signature,
    })
}

fn report_identity_shape_defect(
    results: &mut ValidationResults,
    url: &str,
    defect: IdentityShapeDefect,
) {
    match defect {
        IdentityShapeDefect::DuplicateKey => invalid_cbor(
            results,
            url,
            "identity assertion contains a duplicate CBOR map key",
        ),
        IdentityShapeDefect::SignerPayloadMissing => {
            invalid_cbor(results, url, "signer_payload is missing");
        }
        IdentityShapeDefect::SignerPayloadInvalid => invalid_cbor(
            results,
            url,
            "signer_payload violates the CAWG Identity 1.3 CDDL",
        ),
        IdentityShapeDefect::SignatureMissing => {
            invalid_cbor(results, url, "signature is missing or is not a byte string")
        }
        IdentityShapeDefect::SignatureEmpty => invalid_cbor(results, url, "signature is empty"),
        IdentityShapeDefect::Padding => results.push_failure(
            CAWG_IDENTITY_PAD_INVALID,
            url.into(),
            "pad1 or pad2 is missing, not a byte string, or contains non-zero bytes".into(),
        ),
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
    reference_cycle: bool,
) {
    #[cfg(test)]
    record_identity_work(|counts| counts.identity_evaluations += 1);
    let shape = identity_shape(assertion);
    if matches!(&shape, Err(IdentityShapeDefect::DuplicateKey)) {
        report_identity_shape_defect(ctx.results, url, IdentityShapeDefect::DuplicateKey);
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
    let IdentityShape {
        signer_payload,
        referenced,
        signature,
    } = match shape {
        Ok(shape) => shape,
        Err(defect) => {
            report_identity_shape_defect(ctx.results, url, defect);
            return;
        }
    };
    let sig_type = signer_payload
        .get("sig_type")
        .and_then(Value::as_text)
        .expect("shape validator guarantees sig_type");

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
    if mismatch || reference_cycle {
        let (explanation, reason) = if reference_cycle {
            (
                "referenced_assertions creates a CAWG identity reference cycle",
                "reference_cycle",
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
    if duplicate || mismatch || reference_cycle || !hard_binding_valid {
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

    // CAWG Identity 1.3 x509/validating.adoc establishes the credential trust
    // outcome before signature validation, then evaluates revocation only for
    // an assertion that survived both stages.
    let trust = match identity_trust_outcome(
        leaf,
        &chain,
        at,
        ctx.validation_time,
        ctx.cawg_trust,
        ctx.cawg_allowed_certs,
        ctx.document_signing_require_anchor,
        timestamp_trusted,
    ) {
        IdentityTrust::Untrusted(reason) => {
            let revocation_status = identity_embedded_revocation_status(
                signature,
                certificate_status_assertions,
                &chain,
                timestamp_trusted.then_some(at),
                ctx.ocsp_verification_time,
                ctx.cawg_trust,
            );
            if revocation_status.ca_revoked() {
                report_identity_ca_revoked(ctx.results, url, revocation_status, false, reason);
            } else {
                ctx.results.push_failure_with_details(
                    CAWG_X509_CREDENTIAL_UNTRUSTED,
                    url.into(),
                    "no chain of trust reaches a configured CAWG trust anchor for this identity credential"
                        .into(),
                    json!({
                        "reason": reason,
                        "chain_trusted": false,
                        "revocation_status": revocation_status.as_str(),
                    }),
                );
            }
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
        IdentityTrust::NoRootOfTrust(trust_failure) => Err(trust_failure),
    };

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

    let trust = match trust {
        Ok(evidence) => evidence,
        Err(trust_failure) => {
            if !report_identity_signing_validity(signature, &chain, at, attested, ctx.results, url)
            {
                return;
            }
            let revocation_status = identity_embedded_revocation_status(
                signature,
                certificate_status_assertions,
                &chain,
                timestamp_trusted.then_some(at),
                ctx.ocsp_verification_time,
                ctx.cawg_trust,
            );
            if revocation_status.ca_revoked() {
                report_identity_ca_revoked(
                    ctx.results,
                    url,
                    revocation_status,
                    false,
                    "ca_revoked",
                );
                return;
            }
            let (accepted_eku, certificate_policy) = identity_trust_rejection(leaf);
            ctx.results.push_success_with_details(
                CAWG_IDENTITY_WELL_FORMED,
                url.into(),
                "CAWG identity signature validated but no configured trust root accepted the credential"
                    .into(),
                terminal_identity_details(
                    leaf,
                    false,
                    json!({
                        "trust_source": "none",
                        "accepted_eku": accepted_eku,
                        "certificate_policy": certificate_policy,
                        "trusted_at": null,
                        "timestamp_trusted": timestamp_trusted,
                        "chain_trusted": false,
                        "revocation_status": revocation_status.as_str(),
                        "trust_failure": trust_failure,
                        "payload_encoding": payload_encoding,
                    }),
                ),
            );
            return;
        }
    };

    if !report_identity_signing_validity(signature, &chain, at, attested, ctx.results, url) {
        return;
    }

    // CAWG identity revocation stays fail-closed in both postures: the
    // conformance reading of VAL-STRU-0027 is a C2PA claim-signer rule, and
    // CAWG registers no code for an outranked revoked response.
    let revocation_status = identity_embedded_revocation_status(
        signature,
        certificate_status_assertions,
        &chain,
        timestamp_trusted.then_some(at),
        ctx.ocsp_verification_time,
        ctx.cawg_trust,
    );
    let embedded_leaf_revoked = matches!(
        revocation_status,
        IdentityRevocationStatus::LeafRevoked | IdentityRevocationStatus::LeafAndCaRevoked
    );
    if revocation_status.ca_revoked() {
        report_identity_ca_revoked(
            ctx.results,
            url,
            revocation_status,
            trust.anchor_fingerprint.is_some(),
            "ca_revoked",
        );
        return;
    }
    if embedded_leaf_revoked {
        let targets = super::ocsp_targets(&chain, ctx.cawg_trust);
        if super::any_online_ca_revoked(
            &targets,
            ctx.evidence,
            timestamp_trusted.then_some(at),
            ctx.ocsp_verification_time,
        ) {
            report_identity_ca_revoked(
                ctx.results,
                url,
                IdentityRevocationStatus::CaRevoked,
                trust.anchor_fingerprint.is_some(),
                "ca_revoked",
            );
            return;
        }
        ctx.results.push_failure_with_details(
            CAWG_IDENTITY_CREDENTIAL_REVOKED,
            url.into(),
            "verified stapled OCSP evidence reports the identity signing certificate revoked"
                .into(),
            json!({
                "chain_trusted": trust.anchor_fingerprint.is_some(),
                "trust_source": trust.source,
                "anchor_fingerprint": trust.anchor_fingerprint,
            }),
        );
        return;
    }
    // CAWG 1.3 "Determining revocation from online OCSP response" is the same
    // procedure the C2PA claim signer follows, with CAWG's own status codes.
    let targets = super::ocsp_targets(&chain, ctx.cawg_trust);
    let online = super::evaluate_online_ocsp(
        &targets,
        ctx.evidence,
        timestamp_trusted.then_some(at),
        ctx.ocsp_verification_time,
        crate::c2pa_trust::OnlineOcspPolicy::CawgIdentity,
    );
    if online.ca_revoked {
        report_identity_ca_revoked(
            ctx.results,
            url,
            IdentityRevocationStatus::CaRevoked,
            trust.anchor_fingerprint.is_some(),
            "ca_revoked",
        );
        return;
    }

    let purpose = super::OcspPurpose::CawgIdentity {
        assertion_label: url.rsplit('/').next().unwrap_or(url).to_string(),
    };
    let leaf_targets = &targets[..targets.len().min(1)];
    let embedded_good = revocation_status == IdentityRevocationStatus::NotRevoked;

    let (leaf_revoked, online_settled) = match online.leaf {
        Some(super::OnlineOcspLeafOutcome::Received(OnlineOcspVerdict::NotRevoked)) => {
            ctx.results.push_success(
                CAWG_X509_OCSP_NOT_REVOKED,
                url.into(),
                "online OCSP response reports the identity leaf not revoked".into(),
            );
            (false, true)
        }
        Some(super::OnlineOcspLeafOutcome::Received(OnlineOcspVerdict::Revoked)) => (true, true),
        Some(super::OnlineOcspLeafOutcome::Received(OnlineOcspVerdict::Unknown)) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_UNKNOWN,
                url.into(),
                "the OCSP responder reports an unknown status for the identity certificate".into(),
            );
            (false, false)
        }
        Some(super::OnlineOcspLeafOutcome::Received(OnlineOcspVerdict::Unusable)) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_UNUSABLE_RESPONSE,
                url.into(),
                "received OCSP bytes did not contain a usable answer for the identity certificate"
                    .into(),
            );
            super::record_ocsp_needs(leaf_targets, &purpose, &mut ctx.results.network_needs);
            (false, false)
        }
        Some(super::OnlineOcspLeafOutcome::Received(OnlineOcspVerdict::OutsideWindow {
            refresh_may_cover,
        })) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_OUTSIDE_WINDOW,
                url.into(),
                "the OCSP response does not cover the identity's effective validation time".into(),
            );
            if refresh_may_cover {
                super::record_ocsp_needs(leaf_targets, &purpose, &mut ctx.results.network_needs);
            }
            (false, false)
        }
        Some(super::OnlineOcspLeafOutcome::Unreachable) => {
            ctx.results.push_informational(
                CAWG_X509_OCSP_INACCESSIBLE,
                url.into(),
                "the OCSP responder for the identity certificate returned no response".into(),
            );
            (false, false)
        }
        None => {
            if !embedded_good {
                ctx.results.push_informational(
                    CAWG_X509_OCSP_SKIPPED,
                    url.into(),
                    "no online OCSP check was performed, and stapled evidence did not establish the identity leaf status"
                        .into(),
                );
                super::record_ocsp_needs(&targets, &purpose, &mut ctx.results.network_needs);
            }
            (false, false)
        }
    };
    if embedded_good && !online_settled {
        ctx.results.push_success(
            CAWG_X509_OCSP_NOT_REVOKED,
            url.into(),
            "verified stapled OCSP evidence reports the identity leaf not revoked".into(),
        );
    }
    if leaf_revoked {
        ctx.results.push_failure_with_details(
            CAWG_IDENTITY_CREDENTIAL_REVOKED,
            url.into(),
            "verified OCSP evidence reports the identity signing certificate revoked".into(),
            json!({
                "chain_trusted": trust.anchor_fingerprint.is_some(),
                "trust_source": trust.source,
                "anchor_fingerprint": trust.anchor_fingerprint,
            }),
        );
        return;
    }

    ctx.results.push_success_with_details(
        CAWG_IDENTITY_TRUSTED,
        url.into(),
        "CAWG identity signature and X.509 trust policy validated".into(),
        terminal_identity_details(
            leaf,
            true,
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
    );
}

/// Attach bounded display names to an X.509 identity's terminal status.
///
/// The explicit boolean keeps the trust outcome beside the subject even when a
/// consumer retains only `details`. This helper is never called for configured
/// untrusted chains or ICA credentials.
fn terminal_identity_details(
    leaf: &[u8],
    certificate_trusted: bool,
    mut details: serde_json::Value,
) -> serde_json::Value {
    use der::Decode as _;

    let Some(object) = details.as_object_mut() else {
        return details;
    };
    object.insert(
        "certificate_trusted".into(),
        serde_json::Value::Bool(certificate_trusted),
    );
    let Ok(certificate) = x509_cert::Certificate::from_der(leaf) else {
        return details;
    };
    if let Some(organization) = super::cert::name_attribute(
        &certificate.tbs_certificate.subject,
        super::cert::OID_AT_ORGANIZATION,
    ) {
        object.insert(
            "subject_organization".into(),
            serde_json::Value::String(organization),
        );
    }
    if let Some(common_name) = super::cert::name_attribute(
        &certificate.tbs_certificate.subject,
        super::cert::OID_AT_COMMON_NAME,
    ) {
        object.insert(
            "subject_common_name".into(),
            serde_json::Value::String(common_name),
        );
    }
    details
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

struct IdentityReferenceCycles<'a> {
    labels: [&'a str; MAX_IDENTITY_ASSERTIONS],
    len: usize,
    members: u64,
}

impl IdentityReferenceCycles<'_> {
    fn contains(&self, label: &str) -> bool {
        self.labels[..self.len]
            .iter()
            .position(|candidate| *candidate == label)
            .is_some_and(|index| self.members & (1_u64 << index) != 0)
    }
}

/// Compute cycle membership once for every local identity assertion.
///
/// The caller enforces the 64-identity cap before this runs. Each row is a
/// fixed-width reachability bitset, so adversarial graphs cannot recurse or
/// allocate work proportional to attacker-selected path depth.
fn identity_reference_cycles<'a>(
    claim_refs: &'a ClaimAssertionRefs<'_>,
    manifest_label: &str,
) -> IdentityReferenceCycles<'a> {
    let mut graph = IdentityReferenceCycles {
        labels: [""; MAX_IDENTITY_ASSERTIONS],
        len: 0,
        members: 0,
    };
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| is_identity_assertion_label(label))
        else {
            continue;
        };
        if graph.labels[..graph.len].contains(&label) {
            continue;
        }
        if graph.len == MAX_IDENTITY_ASSERTIONS {
            break;
        }
        graph.labels[graph.len] = label;
        graph.len += 1;
    }

    let mut reach = [0_u64; MAX_IDENTITY_ASSERTIONS];
    for (source, label) in graph.labels[..graph.len].iter().copied().enumerate() {
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let Ok(shape) = identity_shape(assertion) else {
            continue;
        };
        let references = shape.referenced;
        for reference in references {
            let Some(target) = reference
                .get("url")
                .and_then(Value::as_text)
                .and_then(|url| super::assertion_label_for_manifest(url, manifest_label))
                .filter(|target| is_identity_assertion_label(target))
            else {
                continue;
            };
            if let Some(destination) = graph.labels[..graph.len]
                .iter()
                .position(|candidate| *candidate == target)
            {
                reach[source] |= 1_u64 << destination;
            }
        }
    }

    for intermediate in 0..graph.len {
        let through = reach[intermediate];
        for row in &mut reach[..graph.len] {
            if *row & (1_u64 << intermediate) != 0 {
                *row |= through;
            }
        }
    }
    for (index, row) in reach[..graph.len].iter().enumerate() {
        if row & (1_u64 << index) != 0 {
            graph.members |= 1_u64 << index;
        }
    }
    graph
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
/// Absence or a malformed NumericDate produces no status. A usable value is
/// judged against certificate validity; chronology relative to an attested
/// time is reported separately.
fn report_time_of_signing(
    signature: &[u8],
    chain: &[Vec<u8>],
    attested: Option<OffsetDateTime>,
    results: &mut ValidationResults,
    url: &str,
) {
    let Ok(Some(iat)) = protected_iat(signature) else {
        return;
    };
    let Some(signed_at) = numeric_date_to_time(iat) else {
        return;
    };
    let inside = chain
        .iter()
        .all(|certificate| certificate_valid_at(certificate, signed_at));
    if inside {
        results.push_informational(
            CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY,
            url.into(),
            "the claimed time of signing falls inside the identity certificate chain's validity"
                .into(),
        );
        if attested.is_some_and(|attested| signed_at > attested) {
            results.push_informational(
                CAWG_X509_TIME_OF_SIGNING_AFTER_TIMESTAMP,
                url.into(),
                "the claimed time of signing is later than the trusted time stamp".into(),
            );
        }
    } else {
        results.push_informational(
            CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY,
            url.into(),
            "the claimed time of signing falls outside the identity certificate chain's validity"
                .into(),
        );
    }
}

fn identity_embedded_revocation_status(
    signature: &[u8],
    certificate_status_assertions: &[&[u8]],
    chain: &[Vec<u8>],
    signed_at: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    trust: Option<&TrustList>,
) -> IdentityRevocationStatus {
    evaluate_embedded_ocsp(
        signature,
        certificate_status_assertions,
        chain,
        signed_at,
        verification_time,
        trust,
        false,
    )
    .status
}

fn report_identity_ca_revoked(
    results: &mut ValidationResults,
    url: &str,
    revocation_status: IdentityRevocationStatus,
    chain_trusted: bool,
    reason: &str,
) {
    debug_assert!(revocation_status.ca_revoked());
    results.push_failure_with_details(
        CAWG_X509_CREDENTIAL_UNTRUSTED,
        url.into(),
        "verified OCSP evidence reports a CA certificate in the identity chain revoked".into(),
        json!({
            "reason": reason,
            "chain_trusted": chain_trusted,
            "revocation_status": revocation_status.as_str(),
        }),
    );
}

fn report_identity_signing_validity(
    signature: &[u8],
    chain: &[Vec<u8>],
    at: OffsetDateTime,
    attested: Option<OffsetDateTime>,
    results: &mut ValidationResults,
    url: &str,
) -> bool {
    if !chain
        .iter()
        .all(|certificate| certificate_valid_at(certificate, at))
    {
        results.push_failure(
            CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY,
            url.into(),
            "the time of signing falls outside the validity window of the identity certificate chain"
                .into(),
        );
        return false;
    }
    if attested.is_none() {
        results.push_success(
            CAWG_X509_SIGNATURE_INSIDE_VALIDITY,
            url.into(),
            "no trusted time stamp was available, and the current time falls inside the identity certificate chain's validity window"
                .into(),
        );
    }
    report_time_of_signing(signature, chain, attested, results, url);
    true
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
///   carries. Only a base-eligible entry (one that is not an interim source)
///   can supply it: the interim sources are configured for
///   `id-kp-emailProtection` alone.
/// - `id-kp-emailProtection` is accepted with one of the six CA/Browser Forum
///   S/MIME policies, under the extra conditions of the interim trust model
///   additions. Those conditions belong to the two sources that section
///   names, the Mozilla email root store and the IPTC lists. An entry the
///   validator configured itself, such as the Encypher Verified Organizations
///   root or a caller's own anchors, is a plain trust configuration entry and
///   carries no interim condition; accepting emailProtection there is local
///   validator policy.
///
/// Each EKU is its own entry, so a credential carrying both that the
/// documentSigning entry cannot anchor is still offered to the
/// emailProtection entry. Eligible entries are chosen before the chain is
/// searched: base entries first, interim entries only if no base entry
/// accepts, so a refused interim path never hides a valid base path.
///
/// Every entry is in force only inside its configured window, measured at
/// `at` (x509/validating: the time stamp, or the current time without one).
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
    let has_eku = |eku: &str| ekus.iter().any(|oid| oid == eku);
    let base = |entry: &TrustAnchor| !entry.cawg_source.interim();
    let interim = |entry: &TrustAnchor| entry.cawg_source.interim();
    let policy = has_eku(OID_KP_EMAIL_PROTECTION)
        .then(|| approved_smime_policy(leaf))
        .flatten();
    let base_direct = direct_match(leaf, at, allowed, base);
    let base_chain = std::cell::OnceCell::new();
    let base_chain =
        || *base_chain.get_or_init(|| chain_trust_anchor(leaf, intermediates, at, trust, base));

    if has_eku(OID_KP_DOCUMENT_SIGNING) {
        if let Some(entry) = base_direct {
            return Ok(IdentityTrustEvidence {
                source: "allowed_list",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
                anchor_fingerprint: Some(entry.fingerprint()),
            });
        }
        let anchor = base_chain();
        if !document_signing_require_anchor || anchor.is_some() {
            return Ok(IdentityTrustEvidence {
                source: "document_signing",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
                anchor_fingerprint: anchor.map(TrustAnchor::fingerprint),
            });
        }
        if policy.is_none() {
            return Err("document_signing_anchor_required");
        }
    }

    if !has_eku(OID_KP_EMAIL_PROTECTION) {
        return Err("eku_not_accepted");
    }
    // Every entry that accepts emailProtection accepts it only with one of the
    // six approved policies, so this check precedes the entry search.
    let Some(policy) = policy else {
        return Err("smime_policy_not_accepted");
    };
    let accepted = move |source, entry: &TrustAnchor| IdentityTrustEvidence {
        source,
        accepted_eku: Some(OID_KP_EMAIL_PROTECTION),
        certificate_policy: Some(policy),
        anchor_fingerprint: Some(entry.fingerprint()),
    };

    // A credential can match more than one entry: it may sit in the private
    // credential store and also chain to an anchor, and a chain may reach
    // both a base and an interim anchor. Base entries carry no time
    // condition, so they are offered the credential first.
    if let Some(entry) = base_direct {
        return Ok(accepted("allowed_list", entry));
    }
    if let Some(anchor) = base_chain() {
        return Ok(accepted(anchor.cawg_source.label(), anchor));
    }
    let Some((source, entry)) = direct_match(leaf, at, allowed, interim)
        .map(|entry| ("allowed_list", entry))
        .or_else(|| {
            chain_trust_anchor(leaf, intermediates, at, trust, interim)
                .map(|anchor| (anchor.cawg_source.label(), anchor))
        })
    else {
        return Err("credential_untrusted");
    };
    let before_cutoff =
        |instant: OffsetDateTime| instant.unix_timestamp() < S_MIME_INTERIM_CUTOFF_UNIX;
    if before_cutoff(validation_time) || (identity_timestamp_trusted && before_cutoff(at)) {
        return Ok(accepted(source, entry));
    }
    // Past the cutoff, the only surviving disjunct is a trusted time stamp
    // attesting an earlier signature: absent one, that is what the credential
    // lacked; present one, it attested too late.
    Err(if identity_timestamp_trusted {
        "smime_interim_expired"
    } else {
        "trusted_timestamp_required"
    })
}

/// The first configured certificate equal to `leaf` that is in force at `at`
/// and eligible under `admit`: the private credential store's direct match.
fn direct_match<'a>(
    leaf: &[u8],
    at: OffsetDateTime,
    allowed: Option<&'a TrustList>,
    admit: impl Fn(&TrustAnchor) -> bool,
) -> Option<&'a TrustAnchor> {
    allowed?
        .anchors
        .iter()
        .find(|entry| entry.certificate == leaf && entry.active_at(at) && admit(entry))
}

/// The configured anchor, among those eligible under `admit`, that a chain
/// from `leaf` terminates at.
fn chain_trust_anchor<'a>(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    at: OffsetDateTime,
    trust: Option<&'a TrustList>,
    admit: impl Fn(&TrustAnchor) -> bool,
) -> Option<&'a TrustAnchor> {
    let anchors = trust?;
    let result = validate_chain_admitting(
        leaf,
        intermediates,
        anchors,
        AnchorPurpose::CawgIdentity,
        Some(at),
        admit,
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

/// CAWG Identity 1.3 labels ABNF (labels.adoc): two or more period-separated
/// components, each `1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )`,
/// without the repeated underscore (`__`) reserved for multiple-assertion
/// suffixes. The labels prose says a component starts with a letter; the
/// ABNF, followed here, also allows a digit (`com.3m`).
pub(super) fn is_cawg_label(label: &str) -> bool {
    let valid_component = |component: &str| {
        let mut bytes = component.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    label.contains('.') && !label.contains("__") && label.split('.').all(valid_component)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::c2pa_trust::{timestamp_fixture::TestTsa, validate_chain};
    use const_oid::ObjectIdentifier;
    use der::{Decode, Encode, EncodePem};
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P384_SHA384,
    };
    use sha2::Digest as _;
    use time::macros::datetime;
    use x509_cert::Certificate;

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
        actor_certificate_with_ekus(&[eku], policy, is_ca)
    }

    fn actor_certificate_with_ekus(ekus: &[&str], policy: Option<&str>, is_ca: bool) -> Vec<u8> {
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
        params.extended_key_usages = ekus
            .iter()
            .map(|eku| {
                ExtendedKeyUsagePurpose::Other(
                    eku.split('.')
                        .map(|part| part.parse::<u64>().expect("oid component"))
                        .collect(),
                )
            })
            .collect();
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

    /// CAWG-ID13-ASSERTION-CREATION-011; C2PA 2.4 section 6.4: uniqueness is
    /// "accomplished by adding a double-underscore and a monotonically
    /// increasing index to the label" (`cawg.identity`, `__1`, `__2`, ...).
    #[test]
    fn identity_labels_follow_c2pa_instance_numbers() {
        for label in ["cawg.identity", "cawg.identity__1", "cawg.identity__24"] {
            assert!(is_identity_assertion_label(label), "{label}");
        }
        for label in [
            "cawg.identity__",
            "cawg.identity__0",
            "cawg.identity__01",
            "cawg.identity__secondary",
            "cawg.identity__-1",
            "cawg.identity_1",
        ] {
            assert!(!is_identity_assertion_label(label), "{label}");
        }
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

    /// CAWG-ID13-X509PROFILE-018: the trust configuration keeps its anchors
    /// per accepted EKU. The interim sources are configured for
    /// `id-kp-emailProtection` only, so neither a certificate they list nor an
    /// anchor they supply can be the anchor `id-kp-documentSigning` requires.
    /// A validator-configured (base) entry can.
    #[test]
    fn an_interim_source_is_not_a_document_signing_anchor() {
        let leaf = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, false);
        let at = datetime!(2026-01-01 0:00 UTC);
        let list = |source| {
            TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()])
                .with_cawg_source(source)
        };
        let interim = list(CawgTrustSource::SmimeInterim);
        let base = list(CawgTrustSource::CallerSupplied);
        let verdict = |trust: Option<&TrustList>, allowed: Option<&TrustList>| {
            identity_certificate_trust(&leaf, &[], at, at, trust, allowed, true, false)
                .map(|evidence| evidence.accepted_eku)
        };

        assert_eq!(
            verdict(Some(&interim), None).err(),
            Some("document_signing_anchor_required")
        );
        assert_eq!(
            verdict(None, Some(&interim)).err(),
            Some("document_signing_anchor_required")
        );
        assert_eq!(
            verdict(Some(&base), None),
            Ok(Some(OID_KP_DOCUMENT_SIGNING))
        );
        assert_eq!(
            verdict(None, Some(&base)),
            Ok(Some(OID_KP_DOCUMENT_SIGNING))
        );
    }

    /// CAWG-ID13-X509PROFILE-018/026: each accepted EKU is its own entry. A
    /// credential carrying both EKUs that the documentSigning entry cannot
    /// anchor is still offered to the emailProtection entry, which an interim
    /// source accepts before the cutoff.
    #[test]
    fn a_credential_refused_as_document_signing_is_offered_to_email_protection() {
        let leaf = actor_certificate_with_ekus(
            &[OID_KP_DOCUMENT_SIGNING, OID_KP_EMAIL_PROTECTION],
            Some(CAWG_SMIME_POLICY_OIDS[0]),
            false,
        );
        let at = OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX - 1).unwrap();
        let interim = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()])
            .with_cawg_source(CawgTrustSource::SmimeInterim);
        let evidence =
            identity_certificate_trust(&leaf, &[], at, at, None, Some(&interim), true, false)
                .expect("interim emailProtection entry");
        assert_eq!(evidence.accepted_eku, Some(OID_KP_EMAIL_PROTECTION));
    }

    /// CAWG-ID13-DELTA-009 (x509/validating): a trust configuration carrying
    /// `notBefore`/`notAfter` MUST NOT validate a signature whose time stamp
    /// (or the current time) lies outside them. That holds for a certificate
    /// the configuration lists directly, not only for a chain anchor.
    #[test]
    fn a_configuration_window_bounds_a_directly_listed_certificate() {
        let leaf = actor_certificate(
            OID_KP_EMAIL_PROTECTION,
            Some(CAWG_SMIME_POLICY_OIDS[0]),
            false,
        );
        let at = datetime!(2026-06-01 0:00 UTC);
        let second = time::Duration::seconds(1);
        let verdict = |not_before, not_after| {
            let allowed = TrustList::from_certificates(AnchorPurpose::CawgIdentity, [leaf.clone()])
                .with_cawg_source(CawgTrustSource::CallerSupplied)
                .with_bounds(not_before, not_after);
            identity_certificate_trust(&leaf, &[], at, at, None, Some(&allowed), false, false).err()
        };

        assert_eq!(
            verdict(None, Some(at - second)),
            Some("credential_untrusted")
        );
        assert_eq!(
            verdict(Some(at + second), None),
            Some("credential_untrusted")
        );
        assert_eq!(verdict(Some(at), Some(at)), None);
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
        identity_assertion_map_with_sig_type(referenced, CAWG_X509_COSE)
    }

    fn identity_assertion_map_with_sig_type(referenced: Vec<Value>, sig_type: &str) -> Value {
        Value::Map(vec![
            (
                Value::Text("signer_payload".into()),
                Value::Map(vec![
                    (
                        Value::Text("referenced_assertions".into()),
                        Value::Array(referenced),
                    ),
                    (Value::Text("sig_type".into()), Value::Text(sig_type.into())),
                ]),
            ),
            (Value::Text("signature".into()), Value::Bytes(vec![1])),
            (Value::Text("pad1".into()), Value::Bytes(Vec::new())),
        ])
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum GraphIdentityMalformation {
        DuplicateKey,
        Signature,
        Padding,
        SignerPayload,
    }

    fn reference_graph_members(
        edges: &[Vec<usize>],
        malformed_identity: Option<(usize, GraphIdentityMalformation)>,
    ) -> Vec<bool> {
        assert!(edges.len() <= MAX_IDENTITY_ASSERTIONS);
        let labels: Vec<String> = (0..edges.len())
            .map(|index| {
                if index == 0 {
                    "cawg.identity".to_string()
                } else {
                    format!("cawg.identity__{index}")
                }
            })
            .collect();
        let assertion_values: Vec<Value> = edges
            .iter()
            .enumerate()
            .map(|(index, targets)| {
                let malformation = malformed_identity
                    .filter(|(malformed, _)| *malformed == index)
                    .map(|(_, malformation)| malformation);
                let mut assertion = identity_assertion_map_with_sig_type(
                    targets
                        .iter()
                        .map(|target| {
                            hashed_uri(
                                &format!(
                                    "self#jumbf=/c2pa/test/c2pa.assertions/{}",
                                    labels[*target]
                                ),
                                0x44,
                            )
                        })
                        .collect(),
                    if malformation == Some(GraphIdentityMalformation::SignerPayload) {
                        ""
                    } else {
                        CAWG_X509_COSE
                    },
                );
                let Value::Map(fields) = &mut assertion else {
                    unreachable!("identity fixture is a map");
                };
                match malformation {
                    Some(GraphIdentityMalformation::DuplicateKey) => {
                        fields.push((Value::Text("signature".into()), Value::Bytes(vec![2])))
                    }
                    Some(GraphIdentityMalformation::Signature) => {
                        fields
                            .iter_mut()
                            .find(|(key, _)| key.as_text() == Some("signature"))
                            .expect("signature field")
                            .1 = Value::Bytes(Vec::new());
                    }
                    Some(GraphIdentityMalformation::Padding) => {
                        fields
                            .iter_mut()
                            .find(|(key, _)| key.as_text() == Some("pad1"))
                            .expect("pad1 field")
                            .1 = Value::Bytes(vec![1]);
                    }
                    Some(GraphIdentityMalformation::SignerPayload) | None => {}
                }
                assertion
            })
            .collect();
        let assertion_bytes: Vec<Vec<u8>> = assertion_values
            .iter()
            .map(|assertion| {
                encode(assertion, Profile::LegacyPipelineBDefinite).expect("encode graph identity")
            })
            .collect();
        let assertions = labels
            .iter()
            .zip(&assertion_bytes)
            .map(|(label, bytes)| (label.clone(), bytes.as_slice()))
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
        let claim = claim_with_references(
            labels
                .iter()
                .map(|label| {
                    hashed_uri(
                        &format!("self#jumbf=/c2pa/test/c2pa.assertions/{label}"),
                        0x44,
                    )
                })
                .collect(),
        );
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let cycles = identity_reference_cycles(&claim_refs, "test");
        labels.iter().map(|label| cycles.contains(label)).collect()
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
            &[],
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
            &[],
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
            &[],
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
        certificate_status_assertions: &[&[u8]],
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
        let reference_cycle =
            identity_reference_cycles(&indexed_refs, "test").contains("cawg.identity");
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
            certificate_status_assertions,
            "cawg.identity",
            reference_cycle,
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
    /// CAWG-ID13-ASSERTION-CREATION-017: an acyclic identity-to-identity
    /// reference is in scope and is checked like any other hashed URI.
    #[test]
    fn referenced_identity_assertion_is_allowed_when_acyclic() {
        let reference = hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/cawg.identity__1",
            0x44,
        );
        let assertion = identity_assertion_map(vec![reference.clone()]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(reference);
        let results = identity_verdict(&assertion, &claim_refs);

        assert!(
            !results
                .failure
                .iter()
                .any(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH),
            "{:?}",
            results.failure
        );
    }
    /// CAWG-ID13-ASSERTION-CREATION-017: every member of a multi-node cycle is
    /// rejected, while a parent that merely reaches a separate cycle is not a
    /// cycle member itself.
    #[test]
    fn identity_reference_cycles_mark_only_cycle_members() {
        assert_eq!(
            reference_graph_members(&[vec![1], vec![0]], None),
            vec![true, true]
        );
        assert_eq!(
            reference_graph_members(&[vec![1], vec![2], vec![1]], None),
            vec![false, true, true]
        );
        assert_eq!(
            reference_graph_members(&[vec![1], vec![2], vec![]], None),
            vec![false, false, false]
        );
        assert_eq!(
            reference_graph_members(&[vec![1, 2], vec![3], vec![3], vec![]], None),
            vec![false, false, false, false],
            "a shared-descendant diamond is a DAG"
        );
        for malformation in [
            GraphIdentityMalformation::DuplicateKey,
            GraphIdentityMalformation::Signature,
            GraphIdentityMalformation::Padding,
            GraphIdentityMalformation::SignerPayload,
        ] {
            assert_eq!(
                reference_graph_members(&[vec![1], vec![0]], Some((1, malformation))),
                vec![false, false],
                "{malformation:?} B cannot make valid A a cycle member"
            );
        }
    }

    /// CAWG-ID13-ASSERTION-CREATION-017: the maximum permitted acyclic chain
    /// is evaluated iteratively without recursion or false cycle membership.
    #[test]
    fn sixty_four_identity_reference_chain_is_acyclic() {
        let mut edges = vec![Vec::new(); MAX_IDENTITY_ASSERTIONS];
        for (index, edge) in edges
            .iter_mut()
            .enumerate()
            .take(MAX_IDENTITY_ASSERTIONS - 1)
        {
            edge.push(index + 1);
        }
        assert_eq!(
            reference_graph_members(&edges, None),
            vec![false; MAX_IDENTITY_ASSERTIONS]
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

    /// CAWG-ID13-TRUST-MODEL-009: a signature mismatch stops identity
    /// interpretation before either trusted or well-formed can be issued.
    #[test]
    fn legacy_field_order_signature_fails_by_default() {
        let bytes = signed_identity_assertion_bytes(Profile::LegacyPipelineBDefinite);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), false);
        assert_eq!(failure_codes(&results), [CAWG_X509_SIGNATURE_MISMATCH]);
        assert!(!results.has_informational(CAWG_LEGACY_PROFILE));
        assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
        assert!(!results.has_success(CAWG_IDENTITY_WELL_FORMED));
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

    /// CAWG-ID13-ASSERTION-CREATION-010/011: multiple valid identity labels
    /// are each interpreted and retain their instance suffix in every status.
    /// A claim-referenced `cawg.identity__0` assertion is not an identity and
    /// produces no `cawg.*` status.
    #[test]
    fn every_identity_status_reports_the_assertion_label_as_its_url() {
        let primary_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:primary", None));
        let secondary_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:secondary", None));
        let invalid_instance_bytes =
            identity_bytes_with_padding(identity_payload("cawg.publisher:invalid", None));
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.identity".into(), primary_bytes.as_slice()),
                ("cawg.identity__1".into(), secondary_bytes.as_slice()),
                ("cawg.identity__0".into(), invalid_instance_bytes.as_slice()),
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
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__0", 3),
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

    /// CAWG-ID13-TRUST-MODEL-061 and CAWG-ID13-DELTA-020: valid signatures
    /// over each deleted `expected_*` field remain trusted. Legacy-shaped
    /// values that disagree with the enclosing claim are ignored.
    #[test]
    fn removed_expected_fields_are_ignored_after_signature_validation() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let removed_fields = [
            (
                "expected_partial_claim",
                Value::Map(vec![
                    (Value::Text("alg".into()), Value::Text("sha512".into())),
                    (Value::Text("hash".into()), Value::Bytes(vec![0x99; 64])),
                ]),
            ),
            (
                "expected_claim_generator",
                Value::Text("legacy-generator-that-does-not-match".into()),
            ),
            (
                "expected_countersigners",
                Value::Array(vec![countersigner_description(identity_payload(
                    "cawg.publisher:unexpected",
                    None,
                ))]),
            ),
        ];

        for (field, legacy_value) in removed_fields {
            let Value::Map(mut payload) = identity_payload("cawg.publisher:primary", None) else {
                unreachable!("identity payload is a map");
            };
            payload.push((Value::Text(field.into()), legacy_value));
            let bytes = encypher_identity_assertion_for(Value::Map(payload), &chain, None);
            let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

            assert_eq!(failure_codes(&results), Vec::<&str>::new(), "{field}");
            assert!(results.has_success(CAWG_IDENTITY_TRUSTED), "{field}");
            assert!(
                !results
                    .failure
                    .iter()
                    .chain(&results.informational)
                    .any(|status| status.code.contains("expected")),
                "{field}: {results:?}"
            );
        }
    }

    /// CAWG-ID13-TRUST-MODEL-061 and CAWG-ID13-DELTA-020: Identity 1.3
    /// removes all three `expected_*` fields and requires consumers to ignore
    /// them. Even a value that violates the deleted 1.2 shape reaches signature
    /// validation instead of being rejected as malformed identity CBOR.
    #[test]
    fn removed_expected_fields_are_not_schema_checked() {
        for field in [
            "expected_partial_claim",
            "expected_claim_generator",
            "expected_countersigners",
        ] {
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
                    Value::Text(field.into()),
                    Value::Text("not the deleted 1.2 field shape".into()),
                ));
            }
            let mutated = encode(
                &Value::Map(assertion),
                Profile::CanonicalForHashedSubstructures,
            )
            .expect("re-encode mutated assertion");
            let results = identity_verdict_bytes(&mutated, &binding_claim_refs(0x22), false);
            assert_eq!(
                failure_codes(&results),
                [CAWG_X509_SIGNATURE_MISMATCH],
                "{field}"
            );
            assert!(!results.has_failure(CAWG_IDENTITY_CBOR_INVALID), "{field}");
        }
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
        let rejection = results
            .failure
            .iter()
            .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
            .and_then(|status| status.details.as_ref())
            .expect("untrusted details");
        assert!(rejection.get("subject_organization").is_none());
        assert!(rejection.get("subject_common_name").is_none());
        assert!(rejection.get("certificate_trusted").is_none());
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

    /// Add one identity COSE unprotected header. COSE `Sig_structure` excludes
    /// this bucket, so the identity signature remains valid while a test
    /// controls timestamp or revocation evidence.
    fn with_unprotected_header(bytes: &[u8], label: &str, value: Value) -> Vec<u8> {
        let Ok(Value::Map(mut identity)) = crate::c2pa_cbor::decode(bytes) else {
            panic!("identity fixture must decode as a map");
        };
        let signature = identity
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("signature"))
            .and_then(|(_, value)| match value {
                Value::Bytes(bytes) => Some(bytes),
                _ => None,
            })
            .expect("identity fixture carries signature bytes");
        let Value::Tag(18, mut cose) =
            crate::c2pa_cbor::decode(signature.as_slice()).expect("identity COSE decodes")
        else {
            panic!("identity signature must be a tagged COSE_Sign1");
        };
        let Value::Array(parts) = cose.as_mut() else {
            panic!("identity COSE tag must wrap an array");
        };
        let Value::Map(unprotected) = &mut parts[1] else {
            panic!("identity COSE unprotected header must be a map");
        };
        unprotected.retain(|(key, _)| key.as_text() != Some(label));
        unprotected.push((Value::Text(label.into()), value));
        *signature = encode(
            &Value::Tag(18, cose),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("re-encode identity COSE");
        encode(
            &Value::Map(identity),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("re-encode identity assertion")
    }

    fn with_timestamp_tokens(bytes: &[u8], label: &str, tokens: Vec<Vec<u8>>) -> Vec<u8> {
        with_unprotected_header(
            bytes,
            label,
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(
                    tokens
                        .into_iter()
                        .map(|token| {
                            Value::Map(vec![(Value::Text("val".into()), Value::Bytes(token))])
                        })
                        .collect(),
                ),
            )]),
        )
    }

    fn timestamp_token_without_certificates(token: &[u8]) -> Vec<u8> {
        let mut content =
            cms::content_info::ContentInfo::from_der(token).expect("timestamp ContentInfo");
        let mut signed = content
            .content
            .decode_as::<cms::signed_data::SignedData>()
            .expect("timestamp SignedData");
        signed.certificates = None;
        content.content = der::Any::encode_from(&signed).expect("re-encode SignedData");
        content.to_der().expect("re-encode TimeStampToken")
    }

    fn timestamp_token_without_message_imprint(token: &[u8]) -> Vec<u8> {
        let mut content =
            cms::content_info::ContentInfo::from_der(token).expect("timestamp ContentInfo");
        let mut signed = content
            .content
            .decode_as::<cms::signed_data::SignedData>()
            .expect("timestamp SignedData");
        let mut tst_info = vec![0x02, 0x01, 0x01];
        tst_info.extend(
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.62558.9.1")
                .to_der()
                .expect("policy OID"),
        );
        // RFC 3161 requires messageImprint between policy and serialNumber.
        // The surrounding CMS remains well formed, but this TSTInfo omits it.
        tst_info.extend([0x02, 0x01, 0x01]);
        tst_info.extend([0x18, 0x0f]);
        tst_info.extend(b"20250401000000Z");
        let malformed = der_sequence(tst_info);
        let octets = der::asn1::OctetString::new(malformed).expect("TSTInfo octets");
        signed.encap_content_info.econtent = Some(
            der::Any::new(der::Tag::OctetString, octets.as_bytes().to_vec())
                .expect("TSTInfo eContent"),
        );
        content.content = der::Any::encode_from(&signed).expect("re-encode SignedData");
        content.to_der().expect("re-encode TimeStampToken")
    }

    /// Add one `c2pa.time-stamp` assertion entry to the store-wide index.
    fn add_timestamp_assertion(
        index: &mut TimestampAssertionIndex,
        manifest: &str,
        token: Vec<u8>,
    ) {
        let payload = encode(
            &Value::Map(vec![(Value::Text(manifest.into()), Value::Bytes(token))]),
            Profile::LegacyPipelineBDefinite,
        )
        .expect("encode time-stamp assertion");
        let mut results = ValidationResults::default();
        assert!(
            super::super::timestamp_assertion::index_timestamp_assertion(
                index,
                super::super::timestamp_assertion::TimestampAssertionScope::Manifest,
                &payload,
                &mut results,
                "self#jumbf=/c2pa/timestamp/c2pa.assertions/c2pa.time-stamp",
            )
        );
    }

    /// Index one `c2pa.time-stamp` assertion mapping the test manifest to
    /// `token`.
    fn timestamp_assertion_index(token: Vec<u8>) -> TimestampAssertionIndex {
        let mut index = TimestampAssertionIndex::default();
        add_timestamp_assertion(&mut index, "test", token);
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

    /// CAWG-ID13-DELTA-010 and CAWG-ID13-X509-VALIDATING-A-016:
    /// Identity 1.3 says a v1 timestamp "SHALL" be considered invalid and only
    /// `sigTst2` is acceptable. The legacy header cannot establish signing time.
    #[test]
    fn a_legacy_identity_sig_tst_is_invalid_and_ignored() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_input(&fixture_identity_cose(&bytes)).expect("timestamp input");
        let token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        let trust = tsa.trust_list();

        let with_v1 = with_timestamp_tokens(&bytes, "sigTst", vec![token.clone()]);
        let v1 = identity_verdict_with_timestamp(
            &with_v1,
            Some(&trust),
            &TimestampAssertionIndex::default(),
        );
        assert!(v1.has_informational(CAWG_X509_TIME_STAMP_MALFORMED));
        assert!(!v1.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(!v1.has_success(CAWG_X509_TIME_STAMP_TRUSTED));
        assert!(v1.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));

        let with_v2 = with_timestamp_tokens(&bytes, "sigTst2", vec![token]);
        let v2 = identity_verdict_with_timestamp(
            &with_v2,
            Some(&trust),
            &TimestampAssertionIndex::default(),
        );
        assert!(v2.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(v2.has_success(CAWG_X509_TIME_STAMP_TRUSTED));
        assert!(!v2.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509-VALIDATING-A-030: an invalid CMS signature reports the
    /// CAWG mismatch code and cannot establish an attested signing time.
    #[test]
    fn an_invalid_identity_timestamp_signature_is_mismatch_and_ignored() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_input(&fixture_identity_cose(&bytes)).expect("timestamp input");
        let mut token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        *token.last_mut().expect("non-empty token") ^= 1;
        let with_bad_signature = with_timestamp_tokens(&bytes, "sigTst2", vec![token]);
        let results = identity_verdict_with_timestamp(
            &with_bad_signature,
            Some(&tsa.trust_list()),
            &TimestampAssertionIndex::default(),
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_MISMATCH));
        assert!(!results.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(results.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509-VALIDATING-A-031: a structurally valid CMS token whose
    /// TSTInfo omits the required messageImprint is malformed and ignored.
    #[test]
    fn an_identity_timestamp_without_message_imprint_is_malformed() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_input(&fixture_identity_cose(&bytes)).expect("timestamp input");
        let token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        let without_imprint = timestamp_token_without_message_imprint(&token);
        let assertion = with_timestamp_tokens(&bytes, "sigTst2", vec![without_imprint]);
        let results = identity_verdict_with_timestamp(
            &assertion,
            Some(&tsa.trust_list()),
            &TimestampAssertionIndex::default(),
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_MALFORMED));
        assert!(!results.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(results.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509-VALIDATING-A-036: a sound token without a chain to
    /// configured TSA trust reports untrusted and is ignored.
    #[test]
    fn an_identity_timestamp_without_tsa_trust_is_untrusted() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_input(&fixture_identity_cose(&bytes)).expect("timestamp input");
        let token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        let assertion = with_timestamp_tokens(&bytes, "sigTst2", vec![token]);
        let results =
            identity_verdict_with_timestamp(&assertion, None, &TimestampAssertionIndex::default());

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_UNTRUSTED));
        assert!(!results.has_informational(CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID));
        assert!(!results.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(results.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509-VALIDATING-A-037: Encypher consistently elects to emit
    /// the optional credential_invalid code when a token omits its signer
    /// certificate, alongside the required untrusted result.
    #[test]
    fn an_identity_timestamp_without_its_signer_certificate_is_invalid() {
        let bytes = signed_identity_assertion_bytes(Profile::CanonicalForHashedSubstructures);
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2029-01-01 0:00 UTC),
        );
        let input = timestamp_input(&fixture_identity_cose(&bytes)).expect("timestamp input");
        let token = tsa.token(&input, datetime!(2025-04-01 0:00 UTC));
        let without_certificate = timestamp_token_without_certificates(&token);
        let assertion = with_timestamp_tokens(&bytes, "sigTst2", vec![without_certificate]);
        let results = identity_verdict_with_timestamp(
            &assertion,
            Some(&tsa.trust_list()),
            &TimestampAssertionIndex::default(),
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID));
        assert!(results.has_informational(CAWG_X509_TIME_STAMP_UNTRUSTED));
        assert!(!results.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
        assert!(results.has_success(CAWG_X509_SIGNATURE_INSIDE_VALIDITY));
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
        leaf_pem: String,
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
        runtime_encypher_chain_named(
            policy,
            "Encypher Corporation",
            "Encypher CAWG Runtime Publisher",
        )
    }

    fn runtime_encypher_chain_named(
        policy: &str,
        leaf_organization: &str,
        leaf_common_name: &str,
    ) -> RuntimeEncypherChain {
        fn name(common_name: &str) -> DistinguishedName {
            let mut name = DistinguishedName::new();
            name.push(DnType::CountryName, "US");
            name.push(DnType::OrganizationName, "Encypher Corporation");
            name.push(DnType::CommonName, common_name);
            name
        }

        fn leaf_name(organization: &str, common_name: &str) -> DistinguishedName {
            let mut name = DistinguishedName::new();
            name.push(DnType::CountryName, "US");
            name.push(DnType::OrganizationName, organization);
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
        leaf_params.distinguished_name = leaf_name(leaf_organization, leaf_common_name);
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
            leaf_pem: leaf.pem(),
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
        encypher_identity_assertion_with_protected_headers(payload, chain, timestamp, -35, None)
    }

    /// Sign an identity while controlling the protected algorithm and `iat`.
    ///
    /// Tests use the same complete X.509 path for unsupported-algorithm and
    /// claimed-signing-time requirements rather than bypassing identity
    /// validation through a lower-level helper.
    fn encypher_identity_assertion_with_protected_headers(
        payload: Value,
        chain: &RuntimeEncypherChain,
        timestamp: Option<(&TestTsa, OffsetDateTime)>,
        algorithm: i128,
        iat: Option<Value>,
    ) -> Vec<u8> {
        use p384::ecdsa::signature::Signer as _;
        use p384::pkcs8::DecodePrivateKey as _;

        let canonical = encode(&payload, Profile::CanonicalForHashedSubstructures)
            .expect("encode signer_payload");
        let mut protected_headers = vec![
            (Value::Integer(1), Value::Integer(algorithm)),
            (
                Value::Integer(33),
                Value::Array(vec![
                    Value::Bytes(chain.leaf_der.clone()),
                    Value::Bytes(chain.issuing_der.clone()),
                ]),
            ),
        ];
        if let Some(iat) = iat {
            protected_headers.push((Value::Integer(6), iat));
        }
        let protected = encode(
            &Value::Map(protected_headers),
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

    /// Replace only the COSE unprotected bucket. It is outside the identity
    /// signature input, so the assertion remains cryptographically valid.
    fn with_unprotected_headers(bytes: &[u8], headers: Vec<(Value, Value)>) -> Vec<u8> {
        let mut assertion = crate::c2pa_cbor::decode(bytes).expect("identity assertion");
        let Value::Map(assertion_fields) = &mut assertion else {
            panic!("identity assertion map");
        };
        let signature = assertion_fields
            .iter_mut()
            .find_map(|(key, value)| (key.as_text() == Some("signature")).then_some(value))
            .expect("signature field");
        let Value::Bytes(cose_bytes) = signature else {
            panic!("signature bytes");
        };
        let mut cose = crate::c2pa_cbor::decode(cose_bytes.as_slice()).expect("COSE Sign1");
        let Value::Tag(18, tagged) = &mut cose else {
            panic!("tagged COSE Sign1");
        };
        let Value::Array(parts) = tagged.as_mut() else {
            panic!("COSE Sign1 array");
        };
        parts[1] = Value::Map(headers);
        *cose_bytes =
            encode(&cose, Profile::LegacyPipelineBDefinite).expect("re-encode COSE Sign1");
        encode(&assertion, Profile::CanonicalForHashedSubstructures)
            .expect("re-encode identity assertion")
    }

    fn sig_tst_header(version: &str, tokens: Vec<Value>) -> Vec<(Value, Value)> {
        vec![(
            Value::Text(version.into()),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(tokens),
            )]),
        )]
    }

    fn timestamp_token_entry(token: Vec<u8>) -> Value {
        Value::Map(vec![(Value::Text("val".into()), Value::Bytes(token))])
    }

    /// CAWG-ID13-X509-VALIDATING-A-003 / CAWG-ID13-X509VALB-014:
    /// an identity COSE algorithm outside the C2PA lists is terminal.
    #[test]
    fn an_unsupported_identity_algorithm_reports_the_registered_failure() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let bytes = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            None,
            -999,
            None,
        );
        let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

        assert_eq!(failure_codes(&results), [CAWG_X509_ALGORITHM_UNSUPPORTED]);
        assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// CAWG-ID13-X509-VALIDATING-A-017..019 / CAWG-ID13-X509VALB-023:
    /// identity assertions accept only v2 and exactly one `tstToken`.
    #[test]
    fn identity_timestamp_version_and_cardinality_are_exact() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let base = encypher_identity_assertion(&chain, None);
        let cases = [
            with_unprotected_headers(
                &base,
                sig_tst_header("sigTst", vec![timestamp_token_entry(vec![0x01])]),
            ),
            with_unprotected_headers(&base, sig_tst_header("sigTst2", Vec::new())),
            with_unprotected_headers(
                &base,
                sig_tst_header(
                    "sigTst2",
                    vec![
                        timestamp_token_entry(vec![0x01]),
                        timestamp_token_entry(vec![0x02]),
                    ],
                ),
            ),
        ];

        for bytes in cases {
            let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);
            assert!(
                results.has_informational(CAWG_X509_TIME_STAMP_MALFORMED),
                "{:?}",
                results.informational
            );
            assert!(!results.has_success(CAWG_X509_TIME_STAMP_VALIDATED));
            assert!(!results.has_success(CAWG_X509_TIME_STAMP_TRUSTED));
            assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
        }
    }

    /// CAWG-ID13-X509-VALIDATING-A-021: a valid identity `sigTst2` wins over
    /// a different valid token from the later manifest-assertion source.
    #[test]
    fn identity_sig_tst2_precedes_a_valid_time_stamp_assertion() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let header_time = datetime!(2027-03-01 0:00 UTC);
        let later_time = datetime!(2027-05-01 0:00 UTC);
        let bytes = encypher_identity_assertion(&chain, Some((&tsa, header_time)));
        let assertion_input =
            timestamp_assertion_input(&fixture_identity_cose(&bytes)).expect("assertion input");
        let index = timestamp_assertion_index(tsa.token(&assertion_input, later_time));
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            Some(&trust),
            None,
            true,
            Some(&tsa.trust_list()),
            &index,
            AFTER_INTERIM_CUTOFF,
            None,
            &[],
            Default::default(),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert_eq!(
            trusted_details(&results)["trusted_at"],
            header_time.to_string()
        );
    }

    /// CAWG-ID13-X509-VALIDATING-A-025: mapped tokens are tried in encounter
    /// order until one validates.
    #[test]
    fn a_valid_later_time_stamp_candidate_is_selected() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let bytes = encypher_identity_assertion(&chain, None);
        let input =
            timestamp_assertion_input(&fixture_identity_cose(&bytes)).expect("assertion input");
        let accepted_time = datetime!(2027-04-01 0:00 UTC);
        let mut index = TimestampAssertionIndex::default();
        add_timestamp_assertion(&mut index, "test", vec![0x30, 0x00]);
        add_timestamp_assertion(&mut index, "test", tsa.token(&input, accepted_time));
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            Some(&trust),
            None,
            true,
            Some(&tsa.trust_list()),
            &index,
            AFTER_INTERIM_CUTOFF,
            None,
            &[],
            Default::default(),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert_eq!(
            trusted_details(&results)["trusted_at"],
            accepted_time.to_string()
        );
        assert!(!results.has_informational(CAWG_X509_TIME_STAMP_MALFORMED));
    }

    /// CAWG-ID13-X509-VALIDATING-A-026: a mapping for another manifest is not
    /// evidence and raises no CAWG time-stamp error.
    #[test]
    fn a_time_stamp_mapping_for_another_manifest_is_ignored() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let bytes = encypher_identity_assertion(&chain, None);
        let mut index = TimestampAssertionIndex::default();
        add_timestamp_assertion(&mut index, "different-manifest", vec![0xff]);
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            Some(&trust),
            None,
            true,
            None,
            &index,
            AFTER_INTERIM_CUTOFF,
            None,
            &[],
            Default::default(),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(!results
            .informational
            .iter()
            .any(|status| status.code.starts_with("cawg.x509.time_stamp.")));
    }

    /// CAWG-ID13-X509-VALIDATING-A-034 / CAWG-ID13-X509VALB-024: a valid CMS
    /// token over different bytes maps to the CAWG mismatch code.
    #[test]
    fn an_identity_time_stamp_with_the_wrong_imprint_reports_mismatch() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let wrong = tsa.token(b"different identity signature", BEFORE_INTERIM_CUTOFF);
        let bytes = with_unprotected_headers(
            &encypher_identity_assertion(&chain, None),
            sig_tst_header("sigTst2", vec![timestamp_token_entry(wrong)]),
        );
        let results = encypher_verdict(
            &bytes,
            &trust,
            AFTER_INTERIM_CUTOFF,
            Some(&tsa.trust_list()),
            None,
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_MISMATCH));
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// CAWG-ID13-X509-VALIDATING-A-028,032 / CAWG-ID13-X509VALB-025:
    /// a cryptographically sound token without an accepted TSA chain is
    /// ignored with the CAWG untrusted code.
    #[test]
    fn an_identity_time_stamp_without_tsa_trust_reports_untrusted() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let base = encypher_identity_assertion(&chain, None);
        let input = timestamp_input(&fixture_identity_cose(&base)).expect("timestamp input");
        let bytes = with_unprotected_headers(
            &base,
            sig_tst_header(
                "sigTst2",
                vec![timestamp_token_entry(
                    tsa.token(&input, BEFORE_INTERIM_CUTOFF),
                )],
            ),
        );
        let results = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_UNTRUSTED));
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// CAWG-ID13-X509-VALIDATING-A-039 / CAWG-ID13-X509VALB-026: a trusted
    /// TSA token whose `genTime` is outside the TSA chain is ignored.
    #[test]
    fn identity_time_stamp_outside_tsa_validity_has_its_own_code() {
        let tsa = TestTsa::new(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let base = encypher_identity_assertion(&chain, None);
        let input = timestamp_input(&fixture_identity_cose(&base)).expect("timestamp input");
        let bytes = with_unprotected_headers(
            &base,
            sig_tst_header(
                "sigTst2",
                vec![timestamp_token_entry(
                    tsa.token(&input, datetime!(2025-12-01 0:00 UTC)),
                )],
            ),
        );
        let results = encypher_verdict(
            &bytes,
            &trust,
            AFTER_INTERIM_CUTOFF,
            Some(&tsa.trust_list()),
            None,
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_OUTSIDE_VALIDITY));
        assert!(!results.has_informational(CAWG_X509_TIME_STAMP_UNTRUSTED));
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    /// CAWG-ID13-X509VALB-027: an invalid TSA path reports the optional
    /// credential diagnostic alongside the required untrusted result.
    #[test]
    fn invalid_tsa_credential_reports_both_registered_codes() {
        let mut results = ValidationResults::default();
        report_identity_timestamp_defect(
            TokenFailure::CredentialInvalid,
            "certificate profile rejected",
            &mut results,
            "cawg.identity",
        );

        assert!(results.has_informational(CAWG_X509_TIME_STAMP_CREDENTIAL_INVALID));
        assert!(results.has_informational(CAWG_X509_TIME_STAMP_UNTRUSTED));
    }

    /// CAWG-ID13-X509-VALIDATING-A-041,043: a trusted `genTime`, rather than
    /// current validation time, controls every identity-chain certificate.
    #[test]
    fn an_expired_now_identity_chain_is_valid_at_trusted_gen_time() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2031-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let allowed =
            TrustList::from_certificates(AnchorPurpose::CawgIdentity, [chain.leaf_der.clone()])
                .with_cawg_source(CawgTrustSource::CallerSupplied);
        let signed_at = datetime!(2027-06-01 0:00 UTC);
        let bytes = encypher_identity_assertion(&chain, Some((&tsa, signed_at)));
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            Some(&allowed),
            false,
            Some(&tsa.trust_list()),
            &TimestampAssertionIndex::default(),
            datetime!(2029-01-01 0:00 UTC),
            None,
            &[],
            Default::default(),
        );

        assert_eq!(
            failure_codes(&results),
            Vec::<&str>::new(),
            "{:?}",
            results.failure
        );
        assert_eq!(
            trusted_details(&results)["trusted_at"],
            signed_at.to_string()
        );
    }

    /// CAWG-ID13-X509-VALIDATING-A-042 / CAWG-ID13-X509VALB-020: a trusted
    /// `genTime` outside the identity chain rejects with the registered code.
    #[test]
    fn trusted_gen_time_outside_identity_chain_validity_is_rejected() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let allowed =
            TrustList::from_certificates(AnchorPurpose::CawgIdentity, [chain.leaf_der.clone()])
                .with_cawg_source(CawgTrustSource::CallerSupplied);
        let bytes =
            encypher_identity_assertion(&chain, Some((&tsa, datetime!(2026-06-01 0:00 UTC))));
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            Some(&allowed),
            false,
            Some(&tsa.trust_list()),
            &TimestampAssertionIndex::default(),
            AFTER_INTERIM_CUTOFF,
            None,
            &[],
            Default::default(),
        );

        assert_eq!(
            failure_codes(&results),
            [CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY],
            "{:?}",
            results.failure
        );
    }

    /// CAWG-ID13-X509-VALIDATING-A-044,046 / CAWG-ID13-X509VALB-020: without
    /// usable time-stamp evidence, current time controls the entire chain.
    #[test]
    fn current_time_outside_identity_chain_validity_is_rejected() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let allowed =
            TrustList::from_certificates(AnchorPurpose::CawgIdentity, [chain.leaf_der.clone()])
                .with_cawg_source(CawgTrustSource::CallerSupplied);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            Some(&allowed),
            false,
            None,
            &TimestampAssertionIndex::default(),
            datetime!(2029-01-01 0:00 UTC),
            None,
            &[],
            Default::default(),
        );

        assert_eq!(
            failure_codes(&results),
            [CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY],
            "{:?}",
            results.failure
        );
    }

    /// CAWG-ID13-X509-VALIDATING-A-047..049 /
    /// CAWG-ID13-X509VALB-028..029: protected claimed times map to CAWG codes
    /// according to the identity certificate chain's validity.
    #[test]
    fn protected_identity_iat_reports_chain_validity() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let inside = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            None,
            -35,
            Some(Value::Integer(
                datetime!(2027-03-01 0:00 UTC).unix_timestamp().into(),
            )),
        );
        let outside = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            None,
            -35,
            Some(Value::Integer(
                datetime!(2026-06-01 0:00 UTC).unix_timestamp().into(),
            )),
        );

        let inside_results = encypher_verdict(&inside, &trust, AFTER_INTERIM_CUTOFF, None, None);
        assert!(inside_results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY));
        assert!(!inside_results.has_informational(CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY));

        let outside_results = encypher_verdict(&outside, &trust, AFTER_INTERIM_CUTOFF, None, None);
        assert!(outside_results.has_informational(CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY));
        assert!(!outside_results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509-VALIDATING-A-049 / CAWG-ID13-X509VALB-029: chronology
    /// does not replace the mandatory certificate-validity result, and an
    /// unusable protected `iat` produces no validity code.
    #[test]
    fn protected_identity_iat_reports_chronology_separately() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        let tsa = TestTsa::new(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let later = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            Some((&tsa, datetime!(2027-03-01 0:00 UTC))),
            -35,
            Some(Value::Integer(
                datetime!(2027-04-01 0:00 UTC).unix_timestamp().into(),
            )),
        );
        let later_results = encypher_verdict(
            &later,
            &trust,
            AFTER_INTERIM_CUTOFF,
            Some(&tsa.trust_list()),
            None,
        );
        assert!(later_results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY));
        assert!(later_results.has_informational(CAWG_X509_TIME_OF_SIGNING_AFTER_TIMESTAMP));
        assert!(!later_results.has_informational(CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY));

        let malformed = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            None,
            -35,
            Some(Value::Text("not a NumericDate".into())),
        );
        let malformed_results =
            encypher_verdict(&malformed, &trust, AFTER_INTERIM_CUTOFF, None, None);
        assert!(!malformed_results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY));
        assert!(!malformed_results.has_informational(CAWG_X509_TIME_OF_SIGNING_OUTSIDE_VALIDITY));
    }

    /// CAWG-ID13-X509VALB-028..029: certificate validity boundaries are
    /// inclusive, and `iat == genTime` is not a chronology defect.
    #[test]
    fn protected_identity_iat_accepts_validity_and_timestamp_equality() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
        for boundary in [
            datetime!(2026-12-31 23:55 UTC),
            datetime!(2028-01-02 0:00 UTC),
        ] {
            let assertion = encypher_identity_assertion_with_protected_headers(
                identity_payload("cawg.publisher:primary", None),
                &chain,
                None,
                -35,
                Some(Value::Integer(boundary.unix_timestamp().into())),
            );
            let results = encypher_verdict(&assertion, &trust, AFTER_INTERIM_CUTOFF, None, None);
            assert!(
                results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY),
                "{boundary}: {:?}",
                results.informational
            );
        }

        let tsa = TestTsa::new(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let equal = datetime!(2027-03-01 0:00 UTC);
        let assertion = encypher_identity_assertion_with_protected_headers(
            identity_payload("cawg.publisher:primary", None),
            &chain,
            Some((&tsa, equal)),
            -35,
            Some(Value::Integer(equal.unix_timestamp().into())),
        );
        let results = encypher_verdict(
            &assertion,
            &trust,
            AFTER_INTERIM_CUTOFF,
            Some(&tsa.trust_list()),
            None,
        );
        assert!(results.has_informational(CAWG_X509_TIME_OF_SIGNING_INSIDE_VALIDITY));
        assert!(!results.has_informational(CAWG_X509_TIME_OF_SIGNING_AFTER_TIMESTAMP));
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
            &[],
            Default::default(),
        );

        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
    }

    pub(crate) struct SdkOnlineManifestFixture {
        pub(crate) asset: Vec<u8>,
        pub(crate) store: Vec<u8>,
        pub(crate) options: crate::VerifyOptions,
        pub(crate) claim_leaf_sha256: String,
        pub(crate) identity_leaf_sha256: String,
    }

    pub(crate) fn sdk_online_manifest_fixture() -> SdkOnlineManifestFixture {
        const MANIFEST_LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-000000000462";
        let asset = vec![
            0xff, 0xd8, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xff,
            0xd9,
        ];
        let hard_label = "c2pa.hash.data";
        let hard_payload = encode(
            &Value::Map(vec![
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (
                    Value::Text("hash".into()),
                    Value::Bytes(sha2::Sha256::digest(&asset).to_vec()),
                ),
                (Value::Text("exclusions".into()), Value::Array(Vec::new())),
            ]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("hard binding");
        let actions_label = "c2pa.actions.v2";
        let actions_payload = encode(
            &Value::Map(vec![(
                Value::Text("actions".into()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("action".into()),
                        Value::Text("c2pa.created".into()),
                    ),
                    (
                        Value::Text("digitalSourceType".into()),
                        Value::Text(
                            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into(),
                        ),
                    ),
                ])]),
            )]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("actions");
        let hard_box = crate::c2pa_core::jumbf::assertion_box(hard_label, &hard_payload, None);
        let actions_box =
            crate::c2pa_core::jumbf::assertion_box(actions_label, &actions_payload, None);
        let assertion_reference = |label: &str, assertion_box: &[u8]| {
            let content = crate::c2pa_core::jumbf::superbox_content(assertion_box)
                .expect("assertion-box content");
            Value::Map(vec![
                (
                    Value::Text("url".into()),
                    Value::Text(format!(
                        "self#jumbf=/c2pa/{MANIFEST_LABEL}/c2pa.assertions/{label}"
                    )),
                ),
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (
                    Value::Text("hash".into()),
                    Value::Bytes(sha2::Sha256::digest(content).to_vec()),
                ),
            ])
        };
        let hard_reference = assertion_reference(hard_label, &hard_box);
        let identity = online_ocsp::sdk_online_identity(hard_reference.clone());
        let identity_label = "cawg.identity";
        let identity_box =
            crate::c2pa_core::jumbf::assertion_box(identity_label, &identity.assertion, None);
        let references = vec![
            assertion_reference(identity_label, &identity_box),
            hard_reference,
            assertion_reference(actions_label, &actions_box),
        ];
        let claim = Value::Map(vec![
            (
                Value::Text("instanceID".into()),
                Value::Text("xmp:iid:team-461-online-second-pass".into()),
            ),
            (
                Value::Text("claim_generator_info".into()),
                Value::Map(vec![(
                    Value::Text("name".into()),
                    Value::Text("Encypher TEAM_461 online fixture".into()),
                )]),
            ),
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (
                Value::Text("created_assertions".into()),
                Value::Array(references),
            ),
            (
                Value::Text("signature".into()),
                Value::Text(format!("self#jumbf=/c2pa/{MANIFEST_LABEL}/c2pa.signature")),
            ),
        ]);
        let claim_cbor = encode(&claim, Profile::LegacyPipelineBDefinite).expect("claim");
        let claim_signer = super::super::signature_conformance_tests::Signer::online();
        let claim_leaf_sha256 = claim_signer.leaf_sha256();
        let claim_signature = claim_signer.sign(&claim_cbor);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            MANIFEST_LABEL,
            &[hard_box, actions_box, identity_box],
            &claim_cbor,
            &claim_signature,
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let options = crate::VerifyOptions {
            trust_pem: Some(claim_signer.root_pem()),
            cawg_trust_pem: Some(identity.root_pem),
            no_default_trust: true,
            validation_time: Some("2027-06-01T00:00:00Z".into()),
            telemetry: crate::TelemetryOptions {
                enabled: Some(false),
                ..Default::default()
            },
            online: Some(false),
            ..Default::default()
        };
        SdkOnlineManifestFixture {
            asset,
            store,
            options,
            claim_leaf_sha256,
            identity_leaf_sha256: identity.leaf_sha256,
        }
    }

    /// CAWG-ID13-ASSERTION-CREATION-017: a fully signed manifest store binds
    /// both signed identities through their real assertion-box hashes. The
    /// public detached-store verifier accepts A -> B, while a changed B fails
    /// its claim binding.
    #[test]
    fn signed_identity_reference_is_accepted_when_hash_bound_and_acyclic() {
        const MANIFEST_LABEL: &str = "urn:c2pa:00000000-0000-4000-8000-000000000461";
        let asset = [
            0xff, 0xd8, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xff,
            0xd9,
        ];
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let hard_label = "c2pa.hash.data";
        let hard_payload = encode(
            &Value::Map(vec![
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (
                    Value::Text("hash".into()),
                    Value::Bytes(sha2::Sha256::digest(asset).to_vec()),
                ),
                (Value::Text("exclusions".into()), Value::Array(Vec::new())),
            ]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("hard binding");
        let actions_label = "c2pa.actions.v2";
        let actions_payload = encode(
            &Value::Map(vec![(
                Value::Text("actions".into()),
                Value::Array(vec![Value::Map(vec![
                    (
                        Value::Text("action".into()),
                        Value::Text("c2pa.created".into()),
                    ),
                    (
                        Value::Text("digitalSourceType".into()),
                        Value::Text(
                            "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture".into(),
                        ),
                    ),
                ])]),
            )]),
            Profile::CanonicalForHashedSubstructures,
        )
        .expect("actions");
        let hard_box = crate::c2pa_core::jumbf::assertion_box(hard_label, &hard_payload, None);
        let actions_box =
            crate::c2pa_core::jumbf::assertion_box(actions_label, &actions_payload, None);
        let assertion_reference = |label: &str, assertion_box: &[u8]| {
            let content = crate::c2pa_core::jumbf::superbox_content(assertion_box)
                .expect("assertion-box content");
            Value::Map(vec![
                (
                    Value::Text("url".into()),
                    Value::Text(format!(
                        "self#jumbf=/c2pa/{MANIFEST_LABEL}/c2pa.assertions/{label}"
                    )),
                ),
                (Value::Text("alg".into()), Value::Text("sha256".into())),
                (
                    Value::Text("hash".into()),
                    Value::Bytes(sha2::Sha256::digest(content).to_vec()),
                ),
            ])
        };
        let hard_reference = assertion_reference(hard_label, &hard_box);

        let b_label = "cawg.identity__1";
        let b_bytes = encypher_identity_assertion_for(
            identity_payload_over(vec![hard_reference.clone()]),
            &chain,
            None,
        );
        let b_box = crate::c2pa_core::jumbf::assertion_box(b_label, &b_bytes, None);
        let b_reference = assertion_reference(b_label, &b_box);

        let a_label = "cawg.identity";
        let a_bytes = encypher_identity_assertion_for(
            identity_payload_over(vec![hard_reference.clone(), b_reference.clone()]),
            &chain,
            None,
        );
        let a_box = crate::c2pa_core::jumbf::assertion_box(a_label, &a_bytes, None);
        let references = vec![
            assertion_reference(a_label, &a_box),
            b_reference,
            hard_reference,
            assertion_reference(actions_label, &actions_box),
        ];
        let claim = Value::Map(vec![
            (
                Value::Text("instanceID".into()),
                Value::Text("xmp:iid:team-461-a-to-b".into()),
            ),
            (
                Value::Text("claim_generator_info".into()),
                Value::Map(vec![(
                    Value::Text("name".into()),
                    Value::Text("Encypher TEAM_461 fixture".into()),
                )]),
            ),
            (Value::Text("alg".into()), Value::Text("sha256".into())),
            (
                Value::Text("created_assertions".into()),
                Value::Array(references),
            ),
            (
                Value::Text("signature".into()),
                Value::Text(format!("self#jumbf=/c2pa/{MANIFEST_LABEL}/c2pa.signature")),
            ),
        ]);
        let claim_cbor = encode(&claim, Profile::LegacyPipelineBDefinite).expect("claim");
        let claim_signer = super::super::signature_conformance_tests::Signer::conformant();
        let claim_signature = claim_signer.sign(&claim_cbor);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            MANIFEST_LABEL,
            &[
                hard_box.clone(),
                actions_box.clone(),
                b_box.clone(),
                a_box.clone(),
            ],
            &claim_cbor,
            &claim_signature,
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let options = crate::VerifyOptions {
            cawg_trust_pem: Some(chain.root_pem.clone()),
            no_default_trust: true,
            validation_time: Some("2027-06-01T00:00:00Z".into()),
            telemetry: crate::TelemetryOptions {
                enabled: Some(false),
                ..Default::default()
            },
            online: Some(false),
            ..Default::default()
        };

        let report = crate::verify_with_manifest_store(&asset, &store, "image/jpeg", &options)
            .expect("public verification");
        assert_eq!(report.integrity, "valid", "{report:#?}");
        assert_eq!(report.signature, "valid", "{report:#?}");
        assert_eq!(report.hard_binding, "match", "{report:#?}");
        assert_eq!(
            report
                .validation_results
                .success
                .iter()
                .filter(|status| status.code == CAWG_IDENTITY_TRUSTED)
                .count(),
            2,
            "{report:#?}"
        );
        assert!(!report
            .validation_results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_ASSERTION_MISMATCH));

        let mut tampered_b = b_bytes;
        *tampered_b.last_mut().expect("B content byte") ^= 1;
        let tampered_b_box = crate::c2pa_core::jumbf::assertion_box(b_label, &tampered_b, None);
        let tampered_manifest = crate::c2pa_core::jumbf::build_manifest(
            MANIFEST_LABEL,
            &[hard_box, actions_box, tampered_b_box, a_box],
            &claim_cbor,
            &claim_signature,
        );
        let tampered_store = crate::c2pa_core::jumbf::build_manifest_store(&[tampered_manifest]);
        let tampered =
            crate::verify_with_manifest_store(&asset, &tampered_store, "image/jpeg", &options)
                .expect("tampered verification report");
        assert_ne!(tampered.integrity, "valid", "{tampered:#?}");
        assert!(tampered
            .validation_results
            .failure
            .iter()
            .any(|status| status.code == super::super::ASSERTION_HASHED_URI_MISMATCH));
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
            &[],
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

    #[test]
    fn terminal_identity_details_bind_subject_to_the_trust_outcome() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion(&chain, None);
        let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);

        let trusted = encypher_verdict(&bytes, &trust, AFTER_INTERIM_CUTOFF, None, None);
        let trusted = trusted_details(&trusted);
        assert_eq!(trusted["subject_organization"], "Encypher Corporation");
        assert_eq!(
            trusted["subject_common_name"],
            "Encypher CAWG Runtime Publisher"
        );
        assert_eq!(trusted["certificate_trusted"], true);

        let well_formed = identity_verdict_full(
            &bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            None,
            None,
            true,
            None,
            &TimestampAssertionIndex::default(),
            AFTER_INTERIM_CUTOFF,
            None,
            Default::default(),
        );
        let well_formed = well_formed
            .success
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_WELL_FORMED)
            .and_then(|status| status.details.as_ref())
            .expect("well-formed details");
        assert_eq!(well_formed["subject_organization"], "Encypher Corporation");
        assert_eq!(
            well_formed["subject_common_name"],
            "Encypher CAWG Runtime Publisher"
        );
        assert_eq!(well_formed["certificate_trusted"], false);
    }

    #[test]
    fn multiple_x509_identities_keep_subjects_bound_to_exact_terminal_outcomes() {
        let trusted_chain = runtime_encypher_chain_named(
            ORGANIZATION_VALIDATED_STRICT_POLICY,
            "Trusted Fixture Organization",
            "Trusted Fixture Actor",
        );
        let rejected_chain = runtime_encypher_chain_named(
            ORGANIZATION_VALIDATED_STRICT_POLICY,
            "Rejected Fixture Organization",
            "Rejected Fixture Actor",
        );
        let trusted_bytes = encypher_identity_assertion(&trusted_chain, None);
        let rejected_bytes = encypher_identity_assertion(&rejected_chain, None);
        let trust = encypher_root_trust(&trusted_chain.root_pem, CawgTrustSource::CallerSupplied);
        let manifest = ParsedManifest {
            label: "test".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.identity".into(), trusted_bytes.as_slice()),
                ("cawg.identity__1".into(), rejected_bytes.as_slice()),
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
        let timestamp_index = TimestampAssertionIndex::default();
        let mut results = ValidationResults::default();
        {
            let mut ctx = IdentityContext {
                manifest: &manifest,
                claim: &claim,
                validation_time: AFTER_INTERIM_CUTOFF,
                claim_timestamp: None,
                cawg_trust: Some(&trust),
                cawg_allowed_certs: None,
                ocsp_verification_time: AFTER_INTERIM_CUTOFF,
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

        let trusted = results
            .success
            .iter()
            .find(|status| status.code == CAWG_IDENTITY_TRUSTED && status.url == "cawg.identity")
            .and_then(|status| status.details.as_ref())
            .expect("trusted terminal details");
        assert_eq!(
            trusted["subject_organization"],
            "Trusted Fixture Organization"
        );
        assert_eq!(trusted["subject_common_name"], "Trusted Fixture Actor");
        assert_eq!(trusted["certificate_trusted"], true);

        assert!(results.success.iter().any(|status| {
            status.code == CAWG_X509_SIGNATURE_VALIDATED && status.url == "cawg.identity__1"
        }));
        let rejected = results
            .failure
            .iter()
            .find(|status| {
                status.code == CAWG_X509_CREDENTIAL_UNTRUSTED && status.url == "cawg.identity__1"
            })
            .and_then(|status| status.details.as_ref())
            .expect("rejected terminal details");
        assert!(rejected.get("subject_organization").is_none());
        assert!(rejected.get("subject_common_name").is_none());
        assert!(rejected.get("certificate_trusted").is_none());
        for status in results
            .success
            .iter()
            .chain(&results.informational)
            .chain(&results.failure)
            .filter(|status| status.url == "cawg.identity__1")
        {
            let details = status.details.as_ref();
            assert!(details
                .and_then(|value| value.get("subject_organization"))
                .is_none());
            assert!(details
                .and_then(|value| value.get("subject_common_name"))
                .is_none());
            assert!(details
                .and_then(|value| value.get("certificate_trusted"))
                .is_none());
        }
        assert!(!results.success.iter().any(|status| {
            status.url == "cawg.identity__1"
                && matches!(
                    status.code.as_str(),
                    CAWG_IDENTITY_TRUSTED | CAWG_IDENTITY_WELL_FORMED
                )
        }));
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

    /// CAWG-ID13-X509-VALIDATING-A-017, source-order first branch: the
    /// identity assertion's own `sigTst2` token. Its attested time is what the
    /// interim cutoff is measured against, so a credential validated in June
    /// 2027 is still accepted by the interim entry when the token proves a
    /// March 2027 signature.
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

    /// One entry of `VerifyOptions::cawg_trust_configurations`, in the JSON
    /// form the bindings send.
    fn trust_configuration(
        profile: &str,
        pem: &str,
        not_before: Option<&str>,
        not_after: Option<&str>,
    ) -> serde_json::Value {
        json!({
            "profile": profile,
            "certificates_pem": pem,
            "not_before": not_before,
            "not_after": not_after,
        })
    }

    /// Resolve caller options exactly as the public entry points do and run
    /// the identity lane against the CAWG trust they produce.
    fn configured_verdict(
        bytes: &[u8],
        configurations: Vec<serde_json::Value>,
        validation_time: OffsetDateTime,
        claim_timestamp: Option<OffsetDateTime>,
    ) -> ValidationResults {
        let options: crate::VerifyOptions = serde_json::from_value(json!({
            "no_default_trust": true,
            "cawg_trust_configurations": configurations,
        }))
        .expect("options JSON");
        let resolved = crate::ResolvedOptions::resolve(&options).expect("resolve options");
        identity_verdict_full(
            bytes,
            &binding_claim_refs(0x22),
            false,
            "c2pa.hash.data",
            resolved.cawg_trust(),
            resolved.cawg_allowed_certs(),
            true,
            None,
            &TimestampAssertionIndex::default(),
            validation_time,
            claim_timestamp,
            &[],
            Default::default(),
        )
    }

    /// CAWG-ID13-X509PROFILE-023/025/027 and the consumer side of 024: a
    /// caller that supplies the Mozilla or IPTC lists itself (no bundled
    /// trust) can declare them as interim S/MIME sources, and then the 31
    /// March 2027 condition applies to them: an untimestamped identity is
    /// trusted before the cutoff, refused after it, and rescued after it only
    /// by a trusted time stamp from before it. The same root configured as a
    /// base entry keeps the base model.
    #[test]
    fn a_caller_supplied_interim_source_is_held_to_the_cutoff() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion(&chain, None);
        let interim = || {
            vec![trust_configuration(
                "smime_interim",
                &chain.root_pem,
                None,
                None,
            )]
        };

        let in_window = configured_verdict(&bytes, interim(), BEFORE_INTERIM_CUTOFF, None);
        assert_eq!(failure_codes(&in_window), Vec::<&str>::new());
        assert_eq!(trusted_details(&in_window)["trust_source"], "smime_interim");

        let expired = configured_verdict(&bytes, interim(), AFTER_INTERIM_CUTOFF, None);
        assert!(!expired.has_success(CAWG_IDENTITY_TRUSTED));
        assert_eq!(untrusted_reason(&expired), "trusted_timestamp_required");

        let attested = configured_verdict(
            &bytes,
            interim(),
            AFTER_INTERIM_CUTOFF,
            Some(BEFORE_INTERIM_CUTOFF),
        );
        assert_eq!(failure_codes(&attested), Vec::<&str>::new());
        assert_eq!(trusted_details(&attested)["timestamp_trusted"], true);

        let base = configured_verdict(
            &bytes,
            vec![trust_configuration("base", &chain.root_pem, None, None)],
            AFTER_INTERIM_CUTOFF,
            None,
        );
        assert_eq!(failure_codes(&base), Vec::<&str>::new());
        assert_eq!(trusted_details(&base)["trust_source"], "caller_supplied");
    }

    /// CAWG-ID13-X509PROFILE-031: "The lists below MAY include both CA and
    /// end-entity certificates. The certificate under validation MUST either
    /// be directly included in one of these lists, or have a valid chain of
    /// trust to a certificate present in one of these lists." A configuration
    /// places each certificate by what it is, and a directly listed
    /// certificate keeps its source's interim conditions.
    #[test]
    fn a_configuration_places_each_certificate_by_what_it_is() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion(&chain, None);
        let only = |pem: &str| vec![trust_configuration("smime_interim", pem, None, None)];

        let anchored =
            configured_verdict(&bytes, only(&chain.root_pem), BEFORE_INTERIM_CUTOFF, None);
        assert_eq!(trusted_details(&anchored)["trust_source"], "smime_interim");

        let listed = configured_verdict(&bytes, only(&chain.leaf_pem), BEFORE_INTERIM_CUTOFF, None);
        assert_eq!(trusted_details(&listed)["trust_source"], "allowed_list");

        let mixed = format!("{}{}", chain.leaf_pem, chain.root_pem);
        let both = configured_verdict(&bytes, only(&mixed), BEFORE_INTERIM_CUTOFF, None);
        assert_eq!(failure_codes(&both), Vec::<&str>::new());

        let listed_expired =
            configured_verdict(&bytes, only(&chain.leaf_pem), AFTER_INTERIM_CUTOFF, None);
        assert_eq!(
            untrusted_reason(&listed_expired),
            "trusted_timestamp_required"
        );
    }

    /// CAWG-ID13-DELTA-009 (x509/validating): a configuration's `notBefore`
    /// and `notAfter` bound the signatures it validates, measured at the
    /// signature's trusted time stamp or, without one, at the current time.
    /// Each configuration carries its own window.
    #[test]
    fn each_configuration_window_bounds_what_it_validates() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion(&chain, None);
        let verdict = |pem: &str, not_before, not_after, at, stamped| {
            configured_verdict(
                &bytes,
                vec![trust_configuration("base", pem, not_before, not_after)],
                at,
                stamped,
            )
        };

        for pem in [&chain.root_pem, &chain.leaf_pem] {
            let ended = verdict(
                pem,
                None,
                Some("2027-02-01T00:00:00Z"),
                BEFORE_INTERIM_CUTOFF,
                None,
            );
            assert_eq!(untrusted_reason(&ended), "credential_untrusted");
            let not_started = verdict(
                pem,
                Some("2027-03-02T00:00:00Z"),
                None,
                BEFORE_INTERIM_CUTOFF,
                None,
            );
            assert_eq!(untrusted_reason(&not_started), "credential_untrusted");
            // Validated after the window closed, but time-stamped inside it.
            let stamped = verdict(
                pem,
                Some("2027-02-01T00:00:00Z"),
                Some("2027-03-15T00:00:00Z"),
                AFTER_INTERIM_CUTOFF,
                Some(BEFORE_INTERIM_CUTOFF),
            );
            assert_eq!(failure_codes(&stamped), Vec::<&str>::new());
        }

        // A second configuration without a window still validates on its own.
        let unbounded = configured_verdict(
            &bytes,
            vec![
                trust_configuration("base", &chain.root_pem, None, Some("2027-02-01T00:00:00Z")),
                trust_configuration("smime_interim", &chain.root_pem, None, None),
            ],
            BEFORE_INTERIM_CUTOFF,
            None,
        );
        assert_eq!(trusted_details(&unbounded)["trust_source"], "smime_interim");
    }

    /// CAWG-ID13-X509PROFILE-018: a certificate the validator configured
    /// itself keeps the base rules even when an interim source lists it too,
    /// whichever configuration comes first.
    #[test]
    fn a_root_listed_as_both_base_and_interim_keeps_the_base_rules() {
        let chain = runtime_encypher_chain(ORGANIZATION_VALIDATED_STRICT_POLICY);
        let bytes = encypher_identity_assertion(&chain, None);
        let results = configured_verdict(
            &bytes,
            vec![
                trust_configuration("smime_interim", &chain.root_pem, None, None),
                trust_configuration("base", &chain.root_pem, None, None),
            ],
            AFTER_INTERIM_CUTOFF,
            None,
        );
        assert_eq!(failure_codes(&results), Vec::<&str>::new());
        assert_eq!(trusted_details(&results)["trust_source"], "caller_supplied");
    }

    /// CAWG-ID13-X509PROFILE-031: placement by certificate content must not
    /// drop a version 1 root, which carries no BasicConstraints extension. A
    /// self-issued certificate without BasicConstraints is a trust anchor.
    #[test]
    fn a_self_issued_root_without_basic_constraints_anchors_a_chain() {
        let policy = || {
            CustomExtension::from_oid_content(
                &[2, 5, 29, 32],
                certificate_policies_value(ORGANIZATION_VALIDATED_STRICT_POLICY),
            )
        };
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        let mut root_name = DistinguishedName::new();
        root_name.push(DnType::CommonName, "Legacy Email Root");
        root_params.distinguished_name = root_name;
        root_params.not_before = datetime!(2025-01-01 0:00 UTC);
        root_params.not_after = datetime!(2030-01-01 0:00 UTC);
        root_params.is_ca = IsCa::NoCa;
        root_params.custom_extensions.push(policy());
        let root = root_params.self_signed(&root_key).expect("legacy root");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["actor.example".to_string()]).expect("leaf params");
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(DnType::CommonName, "Legacy Root Actor");
        leaf_params.distinguished_name = leaf_name;
        leaf_params.not_before = datetime!(2025-01-01 0:00 UTC);
        leaf_params.not_after = datetime!(2030-01-01 0:00 UTC);
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        leaf_params.custom_extensions.push(policy());
        let leaf = leaf_params
            .signed_by(&leaf_key, &root, &root_key)
            .expect("leaf under the legacy root");
        // rcgen emits v3 certificates. Re-encode the trust anchor as the v1
        // shape this compatibility rule is for. A trust anchor's self-
        // signature and extensions are not part of path processing; its name
        // and public key remain the ones that issued `leaf`.
        let mut legacy_root = Certificate::from_der(root.der()).expect("parse root");
        legacy_root.tbs_certificate.version = x509_cert::certificate::Version::V1;
        legacy_root.tbs_certificate.extensions = None;
        let legacy_root_pem = legacy_root
            .to_pem(der::pem::LineEnding::LF)
            .expect("encode v1 root");

        let options: crate::VerifyOptions = serde_json::from_value(json!({
            "no_default_trust": true,
            "cawg_trust_configurations": [trust_configuration("smime_interim", &legacy_root_pem, None, None)],
        }))
        .expect("options JSON");
        let resolved = crate::ResolvedOptions::resolve(&options).expect("resolve options");
        let at = datetime!(2026-06-01 0:00 UTC);
        let evidence = identity_certificate_trust(
            leaf.der(),
            &[],
            at,
            at,
            resolved.cawg_trust(),
            resolved.cawg_allowed_certs(),
            true,
            false,
        )
        .expect("the legacy root anchors the chain");
        assert_eq!(evidence.source, "smime_interim");
    }

    /// CAWG-ID13-X509PROFILE-018/025: each entry is offered its own rules, so
    /// the anchors an entry may use are chosen before the chain is searched.
    /// Here the issuing CA is cross-certified: one certificate chains to an
    /// interim root, another to a base root. Past the cutoff, with no time
    /// stamp, the interim path is refused, and it must not hide the base path
    /// the same credential also has.
    #[test]
    fn a_refused_interim_path_does_not_mask_a_base_path() {
        fn ca(name: &str) -> CertificateParams {
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, name);
            params.distinguished_name = dn;
            params.not_before = datetime!(2026-01-01 0:00 UTC);
            params.not_after = datetime!(2030-01-01 0:00 UTC);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.use_authority_key_identifier_extension = true;
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[2, 5, 29, 32],
                    certificate_policies_value(ORGANIZATION_VALIDATED_STRICT_POLICY),
                ));
            params
        }
        let interim_key = KeyPair::generate().expect("interim root key");
        let interim_root = ca("Interim Root")
            .self_signed(&interim_key)
            .expect("interim root");
        let base_key = KeyPair::generate().expect("base root key");
        let base_root = ca("Base Root").self_signed(&base_key).expect("base root");
        let issuing_key = KeyPair::generate().expect("issuing key");
        let via_interim = ca("Issuing CA")
            .signed_by(&issuing_key, &interim_root, &interim_key)
            .expect("issuing CA under the interim root");
        let via_base = ca("Issuing CA")
            .signed_by(&issuing_key, &base_root, &base_key)
            .expect("issuing CA under the base root");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["actor.example".to_string()]).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Cross-certified Actor");
        leaf_params.distinguished_name = dn;
        leaf_params.not_before = datetime!(2026-01-01 0:00 UTC);
        leaf_params.not_after = datetime!(2030-01-01 0:00 UTC);
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 32],
                certificate_policies_value(ORGANIZATION_VALIDATED_STRICT_POLICY),
            ));
        let leaf = leaf_params
            .signed_by(&leaf_key, &via_interim, &issuing_key)
            .expect("leaf");

        let mut trust = TrustList::from_certificates(
            AnchorPurpose::CawgIdentity,
            [interim_root.der().to_vec()],
        )
        .with_cawg_source(CawgTrustSource::SmimeInterim);
        trust.anchors.extend(
            TrustList::from_certificates(AnchorPurpose::CawgIdentity, [base_root.der().to_vec()])
                .with_cawg_source(CawgTrustSource::CallerSupplied)
                .anchors,
        );
        let intermediates = [via_interim.der().to_vec(), via_base.der().to_vec()];

        let evidence = identity_certificate_trust(
            leaf.der(),
            &intermediates,
            AFTER_INTERIM_CUTOFF,
            AFTER_INTERIM_CUTOFF,
            Some(&trust),
            None,
            true,
            false,
        )
        .expect("the base path accepts the credential");
        assert_eq!(evidence.source, "caller_supplied");
        assert_eq!(
            evidence.anchor_fingerprint,
            Some(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                base_root.der()
            )))
        );
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
    pub(crate) mod online_ocsp {
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
            ocsp_chain_with_options(ExtendedKeyUsagePurpose::EmailProtection, false)
        }

        fn ocsp_chain_with_leaf_eku(leaf_eku: ExtendedKeyUsagePurpose) -> OcspChain {
            ocsp_chain_with_options(leaf_eku, false)
        }

        fn ocsp_chain_with_issuing_aia(issuing_aia: bool) -> OcspChain {
            ocsp_chain_with_options(ExtendedKeyUsagePurpose::EmailProtection, issuing_aia)
        }

        fn ocsp_chain_with_options(
            leaf_eku: ExtendedKeyUsagePurpose,
            issuing_aia: bool,
        ) -> OcspChain {
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
            if issuing_aia {
                issuing_params
                    .custom_extensions
                    .push(aia_extension(RESPONDER_URL));
            }
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
            leaf_params.extended_key_usages = vec![leaf_eku];
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
            identity_assertion_for_payload(chain, identity_payload("cawg.publisher:primary", None))
        }

        fn identity_assertion_with_binding(chain: &OcspChain, binding: Value) -> Vec<u8> {
            identity_assertion_for_payload(
                chain,
                identity_payload_with_binding("cawg.publisher:primary", binding, None),
            )
        }

        fn identity_assertion_for_payload(chain: &OcspChain, payload: Value) -> Vec<u8> {
            identity_assertion_for_payload_with_root(chain, payload, false)
        }

        fn identity_assertion_for_payload_with_root(
            chain: &OcspChain,
            payload: Value,
            include_root: bool,
        ) -> Vec<u8> {
            use p256::ecdsa::signature::Signer as _;
            use p256::pkcs8::DecodePrivateKey as _;
            let canonical = encode(&payload, Profile::CanonicalForHashedSubstructures)
                .expect("encode signer_payload");
            let mut x5chain = vec![
                Value::Bytes(chain.leaf_der.clone()),
                Value::Bytes(chain.issuing_der.clone()),
            ];
            if include_root {
                x5chain.push(Value::Bytes(chain.root_der.clone()));
            }
            let protected = encode(
                &Value::Map(vec![
                    (Value::Integer(1), Value::Integer(-7)),
                    (Value::Integer(33), Value::Array(x5chain)),
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

        pub(crate) struct SdkOnlineIdentity {
            pub(crate) assertion: Vec<u8>,
            pub(crate) root_pem: String,
            pub(crate) leaf_sha256: String,
        }

        pub(crate) fn sdk_online_identity(hard_reference: Value) -> SdkOnlineIdentity {
            let chain = ocsp_chain();
            let leaf_sha256 = evidence_key(&chain.leaf_der);
            let assertion = identity_assertion_for_payload(
                &chain,
                identity_payload_with_binding("cawg.publisher:primary", hard_reference, None),
            );
            SdkOnlineIdentity {
                assertion,
                root_pem: chain.root_pem,
                leaf_sha256,
            }
        }

        fn identity_assertion_with_staples(
            chain: &OcspChain,
            tsa: &TestTsa,
            signed_at: OffsetDateTime,
            staples: Vec<Vec<u8>>,
        ) -> Vec<u8> {
            let base = identity_assertion(chain);
            identity_assertion_with_staples_from_base(&base, tsa, signed_at, staples)
        }

        fn identity_assertion_with_root_and_staples(
            chain: &OcspChain,
            tsa: &TestTsa,
            signed_at: OffsetDateTime,
            staples: Vec<Vec<u8>>,
        ) -> Vec<u8> {
            let base = identity_assertion_for_payload_with_root(
                chain,
                identity_payload("cawg.publisher:primary", None),
                true,
            );
            identity_assertion_with_staples_from_base(&base, tsa, signed_at, staples)
        }

        fn identity_assertion_with_staples_from_base(
            base: &[u8],
            tsa: &TestTsa,
            signed_at: OffsetDateTime,
            staples: Vec<Vec<u8>>,
        ) -> Vec<u8> {
            let input =
                timestamp_input(&fixture_identity_cose(base)).expect("identity timestamp input");
            let token = tsa.token(&input, signed_at);
            let mut headers = sig_tst_header("sigTst2", vec![timestamp_token_entry(token)]);
            headers.push((
                Value::Text("rVals".into()),
                Value::Map(vec![(
                    Value::Text("ocspVals".into()),
                    Value::Array(staples.into_iter().map(Value::Bytes).collect()),
                )]),
            ));
            with_unprotected_headers(base, headers)
        }

        fn alter_signed_role(assertion: &[u8]) -> Vec<u8> {
            let mut assertion =
                crate::c2pa_cbor::decode(assertion).expect("identity assertion decodes");
            let Value::Map(assertion_fields) = &mut assertion else {
                panic!("identity assertion is a map");
            };
            let payload_value = &mut assertion_fields
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some("signer_payload"))
                .expect("signer_payload")
                .1;
            let Value::Map(payload) = payload_value else {
                panic!("signer_payload map");
            };
            let role_value = &mut payload
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some("role"))
                .expect("role")
                .1;
            let Value::Array(role) = role_value else {
                panic!("role array");
            };
            role[0] = Value::Text("cawg.publisher:tampered".into());
            encode(&assertion, Profile::CanonicalForHashedSubstructures)
                .expect("encode altered identity assertion")
        }

        fn verdict_for_assertion(
            chain: &OcspChain,
            assertion: &[u8],
            tsa_trust: Option<&TrustList>,
            evidence: OnlineEvidence<'_>,
        ) -> ValidationResults {
            let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
            identity_verdict_full(
                assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&trust),
                None,
                true,
                tsa_trust,
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                evidence,
            )
        }

        /// Verify one identity assertion from `chain` against caller-supplied
        /// online evidence, at an instant inside every certificate validity
        /// window and inside every minted response's freshness interval.
        fn verdict(chain: &OcspChain, evidence: OnlineEvidence<'_>) -> ValidationResults {
            verdict_for_assertion(chain, &identity_assertion(chain), None, evidence)
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

        /// Model the verifier's store-wide certificate-status assertion input.
        fn verdict_with_status_assertion(
            chain: &OcspChain,
            responses: Vec<Vec<u8>>,
        ) -> ValidationResults {
            let status = encode(
                &Value::Map(vec![(
                    Value::Text("ocspVals".into()),
                    Value::Array(responses.into_iter().map(Value::Bytes).collect()),
                )]),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode certificate-status assertion");
            let assertions = [status.as_slice()];
            let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
            let identity = identity_assertion(chain);
            identity_verdict_full(
                &identity,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&trust),
                None,
                true,
                None,
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                Some(AFTER_INTERIM_CUTOFF),
                &assertions,
                OnlineEvidence::default(),
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
            answer_with_spec(
                issuer_der,
                issuer_key,
                subject_der,
                ResponseSpec { status, ..WINDOW },
            )
        }

        fn answer_with_spec(
            issuer_der: &[u8],
            issuer_key: &KeyPair,
            subject_der: &[u8],
            spec: ResponseSpec,
        ) -> Vec<u8> {
            response(
                issuer_der,
                subject_der,
                &Responder {
                    certificate_der: issuer_der,
                    key: issuer_key,
                    embed_certificate: false,
                },
                spec,
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

        pub(crate) struct StoreWideStatusFixture {
            pub(crate) identity: Vec<u8>,
            pub(crate) certificate_status: Vec<u8>,
            pub(crate) cawg_trust: TrustList,
            pub(crate) tsa_trust: TrustList,
        }

        pub(crate) fn store_wide_revoked_ca_fixture(binding: Value) -> StoreWideStatusFixture {
            let chain = ocsp_chain_with_issuing_aia(true);
            let identity = identity_assertion_with_binding(&chain, binding);
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let input =
                timestamp_input(&fixture_identity_cose(&identity)).expect("timestamp input");
            let token = tsa.token(&input, AFTER_INTERIM_CUTOFF);
            let identity = with_timestamp_tokens(&identity, "sigTst2", vec![token]);
            let certificate_status = encode(
                &Value::Map(vec![(
                    Value::Text("ocspVals".into()),
                    Value::Array(vec![
                        Value::Bytes(leaf_response(&chain, FixtureStatus::Good).1),
                        Value::Bytes(
                            issuing_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT)).1,
                        ),
                    ]),
                )]),
                Profile::LegacyPipelineBDefinite,
            )
            .expect("encode certificate-status assertion");

            StoreWideStatusFixture {
                identity,
                certificate_status,
                cawg_trust: encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied),
                tsa_trust: tsa.trust_list(),
            }
        }

        /// CAWG-ID13-X509-VALIDATING-A-055 / CAWG-ID13-X509VALB-002..003:
        /// end-to-end `rVals` evidence produces the CAWG leaf status.
        #[test]
        fn stapled_identity_responses_report_good_and_revoked() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let good = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::Good,
            );
            let good_assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![good]);
            let good_results = verdict_for_assertion(
                &chain,
                &good_assertion,
                Some(&tsa.trust_list()),
                OnlineEvidence::default(),
            );
            assert!(good_results.has_success(CAWG_X509_OCSP_NOT_REVOKED));
            assert_eq!(failure_codes(&good_results), Vec::<&str>::new());

            for (case, staple) in [
                ("malformed", b"not DER".to_vec()),
                (
                    "unauthorized",
                    answer(
                        &chain.issuing_der,
                        &chain.root_key,
                        &chain.leaf_der,
                        FixtureStatus::Good,
                    ),
                ),
            ] {
                let assertion = identity_assertion_with_staples(
                    &chain,
                    &tsa,
                    AFTER_INTERIM_CUTOFF,
                    vec![staple],
                );
                let results = verdict_for_assertion(
                    &chain,
                    &assertion,
                    Some(&tsa.trust_list()),
                    OnlineEvidence::default(),
                );
                assert!(
                    results.has_informational(CAWG_X509_OCSP_SKIPPED),
                    "{case}: {results:?}"
                );
                assert!(
                    !results.has_success(CAWG_X509_OCSP_NOT_REVOKED)
                        && !results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED),
                    "{case}: {results:?}"
                );
            }

            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let revoked_assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);
            let revoked_results = verdict_for_assertion(
                &chain,
                &revoked_assertion,
                Some(&tsa.trust_list()),
                OnlineEvidence::default(),
            );
            assert_eq!(
                failure_codes(&revoked_results),
                [CAWG_IDENTITY_CREDENTIAL_REVOKED]
            );
            assert!(
                revoked_results.has_success(CAWG_X509_SIGNATURE_VALIDATED),
                "{revoked_results:?}"
            );
            let revoked_status = revoked_results
                .failure
                .iter()
                .find(|status| status.code == CAWG_IDENTITY_CREDENTIAL_REVOKED)
                .expect("trusted revoked status");
            assert_eq!(
                revoked_status
                    .details
                    .as_ref()
                    .and_then(|details| details.get("chain_trusted"))
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );
            let details = revoked_status.details.as_ref().expect("revocation details");
            assert_eq!(details["trust_source"], "caller_supplied");
            assert!(details["anchor_fingerprint"].as_str().is_some());
            assert!(revoked_results.network_needs.is_empty());
        }

        /// CAWG Identity 1.3 x509/validating.adoc validates the signature
        /// before revocation. A revoked staple cannot assign status to a
        /// signer_payload that the credential did not sign.
        #[test]
        fn signature_mismatch_suppresses_stapled_leaf_revocation() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let signed =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);
            let altered = alter_signed_role(&signed);

            let results = verdict_for_assertion(
                &chain,
                &altered,
                Some(&tsa.trust_list()),
                OnlineEvidence::default(),
            );

            assert_eq!(failure_codes(&results), [CAWG_X509_SIGNATURE_MISMATCH]);
            assert!(results.has_success(CAWG_X509_CREDENTIAL_TRUSTED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            assert!(!results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
        }

        #[test]
        fn configured_untrusted_credential_precedes_signature_mismatch() {
            let chain = ocsp_chain();
            let wrong_anchor = ocsp_chain();
            let wrong_trust =
                encypher_root_trust(&wrong_anchor.root_pem, CawgTrustSource::CallerSupplied);
            let altered = alter_signed_role(&identity_assertion(&chain));

            let results = identity_verdict_full(
                &altered,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&wrong_trust),
                None,
                true,
                None,
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert_eq!(failure_codes(&results), [CAWG_X509_CREDENTIAL_UNTRUSTED]);
            assert!(!results.has_failure(CAWG_X509_SIGNATURE_MISMATCH));
            assert!(!results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
        }

        /// CAWG Identity 1.3 trust-model/scenarios.adoc applies revoked actor
        /// status only where a trust relationship exists. A chain outside
        /// every configured root remains untrusted, but its authenticated
        /// offline revocation evidence remains visible in report details.
        #[test]
        fn untrusted_chain_reports_stapled_leaf_revocation_without_assigning_actor_status() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let unrelated = ocsp_chain();
            let unrelated_trust =
                encypher_root_trust(&unrelated.root_pem, CawgTrustSource::CallerSupplied);
            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);

            let results = identity_verdict_full(
                &assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&unrelated_trust),
                None,
                true,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert!(results.has_failure(CAWG_X509_CREDENTIAL_UNTRUSTED));
            assert!(!results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            let untrusted = results
                .failure
                .iter()
                .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
                .expect("configured-untrusted status");
            let details = untrusted.details.as_ref().expect("untrusted details");
            assert_eq!(details["chain_trusted"], false);
            assert_eq!(details["revocation_status"], "leaf_revoked");
            assert!(results.network_needs.is_empty());
        }

        #[test]
        fn configured_untrusted_ca_evidence_preserves_the_trust_reason() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let unrelated = ocsp_chain();
            let unrelated_trust =
                encypher_root_trust(&unrelated.root_pem, CawgTrustSource::CallerSupplied);
            let ca_revoked = answer(
                &chain.root_der,
                &chain.root_key,
                &chain.issuing_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let verdict = |staples| {
                let assertion = identity_assertion_with_root_and_staples(
                    &chain,
                    &tsa,
                    AFTER_INTERIM_CUTOFF,
                    staples,
                );
                identity_verdict_full(
                    &assertion,
                    &binding_claim_refs(0x22),
                    false,
                    "c2pa.hash.data",
                    Some(&unrelated_trust),
                    None,
                    true,
                    Some(&tsa.trust_list()),
                    &TimestampAssertionIndex::default(),
                    AFTER_INTERIM_CUTOFF,
                    None,
                    &[],
                    OnlineEvidence::default(),
                )
            };
            let details = |results: &ValidationResults| {
                results
                    .failure
                    .iter()
                    .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
                    .and_then(|status| status.details.clone())
                    .expect("configured-untrusted details")
            };

            let baseline = verdict(Vec::new());
            let revoked = verdict(vec![ca_revoked]);
            let baseline_details = details(&baseline);
            let revoked_details = details(&revoked);
            assert_eq!(revoked_details["reason"], baseline_details["reason"]);
            assert_ne!(revoked_details["reason"], "ca_revoked");
            assert_eq!(revoked_details["chain_trusted"], false);
            assert_eq!(revoked_details["revocation_status"], "ca_revoked");
            assert!(!revoked.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
        }

        #[test]
        fn no_root_leaf_revocation_remains_well_formed_with_offline_evidence() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);
            let results = identity_verdict_full(
                &assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                None,
                None,
                true,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            let well_formed = results
                .success
                .iter()
                .find(|status| status.code == CAWG_IDENTITY_WELL_FORMED)
                .expect("well-formed status");
            let details = well_formed.details.as_ref().expect("well-formed details");
            assert_eq!(details["chain_trusted"], false);
            assert_eq!(details["revocation_status"], "leaf_revoked");
            assert!(results.network_needs.is_empty());
        }

        #[test]
        fn no_root_ca_revocation_rejects_the_credential() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let ca_revoked = answer(
                &chain.root_der,
                &chain.root_key,
                &chain.issuing_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion = identity_assertion_with_root_and_staples(
                &chain,
                &tsa,
                AFTER_INTERIM_CUTOFF,
                vec![ca_revoked],
            );
            let results = identity_verdict_full(
                &assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                None,
                None,
                true,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
            assert!(!results.has_success(CAWG_IDENTITY_WELL_FORMED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            let untrusted = results
                .failure
                .iter()
                .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
                .expect("CA revocation rejects the credential");
            let details = untrusted.details.as_ref().expect("untrusted details");
            assert_eq!(details["reason"], "ca_revoked");
            assert_eq!(details["chain_trusted"], false);
            assert_eq!(details["revocation_status"], "ca_revoked");
            assert!(results.network_needs.is_empty());
        }

        #[test]
        fn anchorless_document_signing_revocation_names_its_trust_source() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain_with_leaf_eku(ExtendedKeyUsagePurpose::Other(
                OID_KP_DOCUMENT_SIGNING
                    .split('.')
                    .map(|part| part.parse::<u64>().expect("OID component"))
                    .collect(),
            ));
            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);
            let results = identity_verdict_full(
                &assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                None,
                None,
                false,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
            let revoked = results
                .failure
                .iter()
                .find(|status| status.code == CAWG_IDENTITY_CREDENTIAL_REVOKED)
                .expect("document-signing leaf is revoked");
            let details = revoked.details.as_ref().expect("revocation details");
            assert_eq!(details["chain_trusted"], false);
            assert_eq!(details["trust_source"], "document_signing");
            assert!(details["anchor_fingerprint"].is_null());
        }

        /// Chain validity precedes revocation even when direct allow-list or
        /// anchorless document-signing acceptance bypasses path validation.
        #[test]
        fn validity_precedes_revocation_for_direct_and_anchorless_acceptance() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let signed_at = datetime!(2028-02-01 0:00 UTC);
            let revoked_spec = ResponseSpec {
                status: FixtureStatus::RevokedAt(REVOKED_AT),
                produced_at: b"20280201000000Z",
                this_update: b"20280101000000Z",
                next_update: Some(b"20290101000000Z"),
            };

            let allowed_chain = ocsp_chain();
            let allowed = TrustList::from_certificates(
                AnchorPurpose::CawgIdentity,
                [allowed_chain.leaf_der.clone()],
            )
            .with_cawg_source(CawgTrustSource::CallerSupplied);
            let allowed_revoked = answer_with_spec(
                &allowed_chain.issuing_der,
                &allowed_chain.issuing_key,
                &allowed_chain.leaf_der,
                revoked_spec,
            );
            let allowed_assertion = identity_assertion_with_staples(
                &allowed_chain,
                &tsa,
                signed_at,
                vec![allowed_revoked],
            );
            let allowed_results = identity_verdict_full(
                &allowed_assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                None,
                Some(&allowed),
                true,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                datetime!(2029-01-01 0:00 UTC),
                None,
                &[],
                OnlineEvidence::default(),
            );
            assert_eq!(
                failure_codes(&allowed_results),
                [CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY]
            );
            assert!(!allowed_results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));

            let document_chain = ocsp_chain_with_leaf_eku(ExtendedKeyUsagePurpose::Other(
                OID_KP_DOCUMENT_SIGNING
                    .split('.')
                    .map(|part| part.parse::<u64>().expect("OID component"))
                    .collect(),
            ));
            let document_revoked = answer_with_spec(
                &document_chain.issuing_der,
                &document_chain.issuing_key,
                &document_chain.leaf_der,
                revoked_spec,
            );
            let document_assertion = identity_assertion_with_staples(
                &document_chain,
                &tsa,
                signed_at,
                vec![document_revoked],
            );
            let document_results = identity_verdict_full(
                &document_assertion,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                None,
                None,
                false,
                Some(&tsa.trust_list()),
                &TimestampAssertionIndex::default(),
                datetime!(2029-01-01 0:00 UTC),
                None,
                &[],
                OnlineEvidence::default(),
            );
            assert_eq!(
                failure_codes(&document_results),
                [CAWG_X509_SIGNATURE_OUTSIDE_VALIDITY]
            );
            assert!(!document_results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
        }

        /// Embedded CA revocation keeps the established trust-path behavior:
        /// the assertion signature is still checked, then the credential is
        /// rejected as untrusted with a machine-readable CA reason.
        #[test]
        fn stapled_ca_revocation_preserves_signature_and_trust_reporting() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let ca_revoked = answer(
                &chain.root_der,
                &chain.root_key,
                &chain.issuing_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion = identity_assertion_with_staples(
                &chain,
                &tsa,
                AFTER_INTERIM_CUTOFF,
                vec![ca_revoked],
            );
            let results = verdict_for_assertion(
                &chain,
                &assertion,
                Some(&tsa.trust_list()),
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_CREDENTIAL_TRUSTED));
            assert!(results.has_success(CAWG_X509_SIGNATURE_VALIDATED));
            let failure = results
                .failure
                .iter()
                .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
                .expect("revoked CA rejects the identity credential");
            let details = failure.details.as_ref().expect("CA revocation details");
            assert_eq!(details["reason"], "ca_revoked");
            assert_eq!(details["chain_trusted"], true);
            assert_eq!(details["revocation_status"], "ca_revoked");
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
        }

        /// CAWG-ID13-X509-VALIDATING-A-057: an unusable first response does
        /// not prevent a later qualifying response from settling the leaf.
        #[test]
        fn stapled_identity_responses_try_invalid_before_valid() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let good = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::Good,
            );
            let assertion = identity_assertion_with_staples(
                &chain,
                &tsa,
                AFTER_INTERIM_CUTOFF,
                vec![b"not DER".to_vec(), good],
            );
            let results = verdict_for_assertion(
                &chain,
                &assertion,
                Some(&tsa.trust_list()),
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_OCSP_NOT_REVOKED));
            assert_eq!(failure_codes(&results), Vec::<&str>::new());
        }

        /// CAWG-ID13-X509-VALIDATING-A-061: embedded OCSP cannot establish
        /// historical non-revocation without a valid signed time stamp.
        #[test]
        fn stapled_good_without_a_time_stamp_does_not_establish_not_revoked() {
            let chain = ocsp_chain();
            let good = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::Good,
            );
            let assertion = with_unprotected_headers(
                &identity_assertion(&chain),
                vec![(
                    Value::Text("rVals".into()),
                    Value::Map(vec![(
                        Value::Text("ocspVals".into()),
                        Value::Array(vec![Value::Bytes(good)]),
                    )]),
                )],
            );
            let results =
                verdict_for_assertion(&chain, &assertion, None, OnlineEvidence::default());

            assert!(!results.has_success(CAWG_X509_OCSP_NOT_REVOKED));
            assert!(results.has_informational(CAWG_X509_OCSP_SKIPPED));
        }

        /// CAWG-ID13-X509VALB-003: a qualifying stapled revoked leaf is
        /// terminal for absent, unreachable, unusable, good, revoked, unknown,
        /// and outside-window online outcomes.
        #[test]
        fn stapled_revocation_overrides_every_online_leaf_outcome() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let revoked = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::RevokedAt(REVOKED_AT),
            );
            let assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, vec![revoked]);
            let leaf_key = evidence_key(&chain.leaf_der);
            let unreachable = vec![leaf_key.clone()];
            let invalid = HashMap::from([(leaf_key.clone(), Vec::new())]);
            let good = HashMap::from([leaf_response(&chain, FixtureStatus::Good)]);
            let online_revoked =
                HashMap::from([leaf_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT))]);
            let unknown = HashMap::from([leaf_response(&chain, FixtureStatus::Unknown)]);
            let outside = HashMap::from([(
                leaf_key,
                response(
                    &chain.issuing_der,
                    &chain.leaf_der,
                    &Responder {
                        certificate_der: &chain.issuing_der,
                        key: &chain.issuing_key,
                        embed_certificate: false,
                    },
                    ResponseSpec {
                        status: FixtureStatus::Good,
                        produced_at: b"20260101000000Z",
                        this_update: b"20260101000000Z",
                        next_update: Some(b"20260201000000Z"),
                    },
                ),
            )]);

            let cases = [
                ("absent", OnlineEvidence::default()),
                (
                    "unreachable",
                    OnlineEvidence {
                        ocsp_unreachable: Some(&unreachable),
                        ..OnlineEvidence::default()
                    },
                ),
                (
                    "unusable",
                    OnlineEvidence {
                        ocsp_responses: Some(&invalid),
                        ..OnlineEvidence::default()
                    },
                ),
                (
                    "good",
                    OnlineEvidence {
                        ocsp_responses: Some(&good),
                        ..OnlineEvidence::default()
                    },
                ),
                (
                    "revoked",
                    OnlineEvidence {
                        ocsp_responses: Some(&online_revoked),
                        ..OnlineEvidence::default()
                    },
                ),
                (
                    "unknown",
                    OnlineEvidence {
                        ocsp_responses: Some(&unknown),
                        ..OnlineEvidence::default()
                    },
                ),
                (
                    "outside-window",
                    OnlineEvidence {
                        ocsp_responses: Some(&outside),
                        ..OnlineEvidence::default()
                    },
                ),
            ];
            for (case, evidence) in cases {
                let results =
                    verdict_for_assertion(&chain, &assertion, Some(&tsa.trust_list()), evidence);
                assert_eq!(
                    failure_codes(&results),
                    [CAWG_IDENTITY_CREDENTIAL_REVOKED],
                    "{case}: {:?}",
                    results.failure
                );
                assert!(
                    !results.has_success(CAWG_X509_OCSP_NOT_REVOKED)
                        && !results.has_informational(CAWG_X509_OCSP_INACCESSIBLE)
                        && !results.has_informational(CAWG_X509_OCSP_UNKNOWN)
                        && !results.has_informational(CAWG_X509_OCSP_UNUSABLE_RESPONSE)
                        && !results.has_informational(CAWG_X509_OCSP_OUTSIDE_WINDOW),
                    "{case}: {results:?}"
                );
            }
        }

        /// CAWG-ID13-X509VALB-006,011,032: optional online evidence cannot
        /// erase a qualifying good staple, and each non-settling online
        /// outcome has the right code and retry need.
        #[test]
        fn non_settling_online_outcomes_preserve_stapled_good_and_need_policy() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let leaf_key = evidence_key(&chain.leaf_der);
            let unusable = HashMap::from([(leaf_key.clone(), Vec::new())]);
            let unknown = HashMap::from([leaf_response(&chain, FixtureStatus::Unknown)]);
            let unreachable = vec![leaf_key.clone()];
            let response_for = |spec| {
                HashMap::from([(
                    leaf_key.clone(),
                    response(
                        &chain.issuing_der,
                        &chain.leaf_der,
                        &Responder {
                            certificate_der: &chain.issuing_der,
                            key: &chain.issuing_key,
                            embed_certificate: false,
                        },
                        spec,
                    ),
                )])
            };
            let outside_retryable = response_for(ResponseSpec {
                status: FixtureStatus::Good,
                produced_at: b"20270101000000Z",
                this_update: b"20270101000000Z",
                next_update: Some(b"20270201000000Z"),
            });
            let outside_archived = response_for(ResponseSpec {
                status: FixtureStatus::Good,
                produced_at: b"20270601000000Z",
                this_update: b"20270601000000Z",
                next_update: Some(b"20270701000000Z"),
            });
            let cases = [
                (
                    "unusable",
                    OnlineEvidence {
                        ocsp_responses: Some(&unusable),
                        ..OnlineEvidence::default()
                    },
                    CAWG_X509_OCSP_UNUSABLE_RESPONSE,
                    1,
                ),
                (
                    "outside-retryable",
                    OnlineEvidence {
                        ocsp_responses: Some(&outside_retryable),
                        ..OnlineEvidence::default()
                    },
                    CAWG_X509_OCSP_OUTSIDE_WINDOW,
                    1,
                ),
                (
                    "outside-archived",
                    OnlineEvidence {
                        ocsp_responses: Some(&outside_archived),
                        ..OnlineEvidence::default()
                    },
                    CAWG_X509_OCSP_OUTSIDE_WINDOW,
                    0,
                ),
                (
                    "unknown",
                    OnlineEvidence {
                        ocsp_responses: Some(&unknown),
                        ..OnlineEvidence::default()
                    },
                    CAWG_X509_OCSP_UNKNOWN,
                    0,
                ),
                (
                    "unreachable",
                    OnlineEvidence {
                        ocsp_unreachable: Some(&unreachable),
                        ..OnlineEvidence::default()
                    },
                    CAWG_X509_OCSP_INACCESSIBLE,
                    0,
                ),
            ];
            let embedded_good = answer(
                &chain.issuing_der,
                &chain.issuing_key,
                &chain.leaf_der,
                FixtureStatus::Good,
            );
            for (has_good_staple, staples) in [(false, Vec::new()), (true, vec![embedded_good])] {
                let assertion =
                    identity_assertion_with_staples(&chain, &tsa, BEFORE_INTERIM_CUTOFF, staples);
                for (case, evidence, expected_code, expected_needs) in cases {
                    let results = verdict_for_assertion(
                        &chain,
                        &assertion,
                        Some(&tsa.trust_list()),
                        evidence,
                    );
                    assert!(
                        results.has_informational(expected_code),
                        "{case}, staple={has_good_staple}: {:?}",
                        results.informational
                    );
                    assert_eq!(
                        results.network_needs.len(),
                        expected_needs,
                        "{case}, staple={has_good_staple}: {:?}",
                        results.network_needs
                    );
                    assert_eq!(
                        results.has_success(CAWG_X509_OCSP_NOT_REVOKED),
                        has_good_staple,
                        "{case}: {:?}",
                        results.success
                    );
                }
            }
        }

        /// CAWG-ID13-X509-VALIDATING-A-051 and
        /// CAWG-ID13-X509-VALIDATING-A-056: the store-wide status-assertion
        /// aggregate includes assertions from subsequent manifests. A CA
        /// response is applied only to its matching AIA-enabled certificate,
        /// and CA revocation rejects trust without misreporting the leaf.
        #[test]
        fn a_certificate_status_assertion_applies_to_its_matching_ca() {
            let chain = ocsp_chain_with_issuing_aia(true);
            let results = verdict_with_status_assertion(
                &chain,
                vec![
                    leaf_response(&chain, FixtureStatus::Good).1,
                    issuing_response(&chain, FixtureStatus::RevokedAt(REVOKED_AT)).1,
                ],
            );

            assert_eq!(
                failure_codes(&results),
                [CAWG_X509_CREDENTIAL_UNTRUSTED],
                "{results:?}"
            );
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            assert!(!results.has_success(CAWG_IDENTITY_TRUSTED));
        }

        /// CAWG-ID13-X509VALB-030: a good OCSP response stapled in the
        /// identity COSE `rVals` establishes that the actor certificate was
        /// not revoked at its trusted time of signing.
        #[test]
        fn a_stapled_identity_ocsp_response_can_clear_the_identity_leaf() {
            let chain = ocsp_chain();
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let identity = identity_assertion(&chain);
            let input =
                timestamp_input(&fixture_identity_cose(&identity)).expect("timestamp input");
            let token = tsa.token(&input, AFTER_INTERIM_CUTOFF);
            let timestamped = with_timestamp_tokens(&identity, "sigTst2", vec![token]);
            let stapled = with_unprotected_header(
                &timestamped,
                "rVals",
                Value::Map(vec![(
                    Value::Text("ocspVals".into()),
                    Value::Array(vec![Value::Bytes(
                        leaf_response(&chain, FixtureStatus::Good).1,
                    )]),
                )]),
            );
            let trust = encypher_root_trust(&chain.root_pem, CawgTrustSource::CallerSupplied);
            let tsa_trust = tsa.trust_list();
            let results = identity_verdict_full(
                &stapled,
                &binding_claim_refs(0x22),
                false,
                "c2pa.hash.data",
                Some(&trust),
                None,
                true,
                Some(&tsa_trust),
                &TimestampAssertionIndex::default(),
                AFTER_INTERIM_CUTOFF,
                None,
                &[],
                OnlineEvidence::default(),
            );

            assert!(results.has_success(CAWG_X509_TIME_STAMP_TRUSTED));
            assert!(results.has_success(CAWG_X509_OCSP_NOT_REVOKED));
            assert_eq!(failure_codes(&results), Vec::<&str>::new());
            assert!(results.has_success(CAWG_IDENTITY_TRUSTED));
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
            assert!(results.has_success(CAWG_X509_CREDENTIAL_TRUSTED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
            let failure = results
                .failure
                .iter()
                .find(|status| status.code == CAWG_X509_CREDENTIAL_UNTRUSTED)
                .expect("online CA revocation rejects the identity credential");
            let details = failure.details.as_ref().expect("CA revocation details");
            assert_eq!(details["reason"], "ca_revoked");
            assert_eq!(details["chain_trusted"], true);
            assert_eq!(details["revocation_status"], "ca_revoked");
        }

        /// CA-chain handling predates the CAWG leaf's open freshness window.
        /// At a trusted signing time equal to `thisUpdate`, the established
        /// inclusive 24-hour policy can establish that a later CA revocation
        /// did not apply at signing. The CAWG leaf policy would reject this
        /// boundary and incorrectly treat the CA as revoked.
        #[test]
        fn a_ca_response_keeps_the_established_claim_window_policy() {
            let tsa = TestTsa::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2030-01-01 0:00 UTC),
            );
            let chain = ocsp_chain();
            let assertion =
                identity_assertion_with_staples(&chain, &tsa, AFTER_INTERIM_CUTOFF, Vec::new());
            let ca_response = response(
                &chain.root_der,
                &chain.issuing_der,
                &Responder {
                    certificate_der: &chain.root_der,
                    key: &chain.root_key,
                    embed_certificate: false,
                },
                ResponseSpec {
                    status: FixtureStatus::RevokedAt(b"20270701000000Z"),
                    produced_at: b"20270601120000Z",
                    this_update: b"20270601000000Z",
                    next_update: None,
                },
            );
            let responses = HashMap::from([(evidence_key(&chain.issuing_der), ca_response)]);
            let results = verdict_for_assertion(
                &chain,
                &assertion,
                Some(&tsa.trust_list()),
                OnlineEvidence {
                    ocsp_responses: Some(&responses),
                    ..OnlineEvidence::default()
                },
            );

            assert!(results.has_success(CAWG_IDENTITY_TRUSTED), "{results:?}");
            assert!(!results.has_failure(CAWG_X509_CREDENTIAL_UNTRUSTED));
            assert!(!results.has_failure(CAWG_IDENTITY_CREDENTIAL_REVOKED));
        }

        /// With no attested historical instant, equality at `thisUpdate` is
        /// outside CAWG's open window but remains refreshable because current
        /// time will advance.
        #[test]
        fn an_untimestamped_leaf_boundary_retains_the_ocsp_need() {
            let chain = ocsp_chain();
            let response = response(
                &chain.issuing_der,
                &chain.leaf_der,
                &Responder {
                    certificate_der: &chain.issuing_der,
                    key: &chain.issuing_key,
                    embed_certificate: false,
                },
                ResponseSpec {
                    status: FixtureStatus::Good,
                    produced_at: b"20270601000000Z",
                    this_update: b"20270601000000Z",
                    next_update: Some(b"20270701000000Z"),
                },
            );
            let results = verdict_with_responses(
                &chain,
                HashMap::from([(evidence_key(&chain.leaf_der), response)]),
            );

            assert!(results.has_informational(CAWG_X509_OCSP_OUTSIDE_WINDOW));
            assert!(!results.has_informational(CAWG_X509_OCSP_INACCESSIBLE));
            assert_eq!(results.network_needs.len(), 1, "{results:?}");
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
