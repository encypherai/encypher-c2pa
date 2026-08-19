//! CAWG Identity 1.2 assertion validation.
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
    extract_tsa_tokens, extract_x5chain, timestamp_input, verify_claim, CryptoError,
};
use crate::c2pa_trust::{
    certificate_eku_oids_der, certificate_policy_oids_der, certificate_valid_at,
    leaf_profile_acceptable_der, validate_chain, TrustList,
};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::OffsetDateTime;

use super::{
    evaluate_embedded_ocsp, is_supported_hard_binding_label, ClaimAssertionReference,
    ClaimAssertionRefs, EmbeddedOcspStatus as IdentityRevocationStatus, ValidationResults,
    CLAIM_SIGNATURE_MISMATCH,
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
pub const CAWG_IDENTITY_EXPECTED_PARTIAL_CLAIM_MISMATCH: &str =
    "cawg.identity.expected_partial_claim.mismatch";
pub const CAWG_IDENTITY_EXPECTED_CLAIM_GENERATOR_MISMATCH: &str =
    "cawg.identity.expected_claim_generator.mismatch";
pub const CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER: &str = "cawg.identity.unexpected_countersigner";
pub const CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISMATCH: &str =
    "cawg.identity.expected_countersigner.mismatch";
pub const CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING: &str =
    "cawg.identity.expected_countersigner.missing";
pub const CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_DUPLICATE: &str =
    "cawg.identity.expected_countersigner.duplicate";
pub const CAWG_ICA_DID_UNAVAILABLE: &str = "cawg.ica.did_unavailable";
pub const CAWG_IDENTITY_CREDENTIAL_REVOKED: &str = "cawg.identity.credential_revoked";
pub const CAWG_X509_ALGORITHM_UNSUPPORTED: &str = "cawg.x509.algorithm.unsupported";
pub const CAWG_X509_CREDENTIAL_INVALID: &str = "cawg.x509.credential.invalid";
pub const CAWG_X509_CREDENTIAL_EXPIRED: &str = "cawg.x509.credential.expired";
pub const CAWG_X509_OCSP_NOT_REVOKED: &str = "cawg.x509.ocsp.not_revoked";
pub const CAWG_X509_OCSP_SKIPPED: &str = "cawg.x509.ocsp.skipped";
/// Vendor-namespaced informational status: the assertion validated, but only
/// via a CAWG 1.1-era legacy shape (field-order `signer_payload` encoding,
/// 1.1 ICA JSON-LD context, or byte-array `c2paAsset` hashes). Never emitted
/// for canonical CAWG 1.2 inputs; strict encoding refuses these shapes.
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
    materialized_records: usize,
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
    pub did_documents: Option<&'a HashMap<String, serde_json::Value>>,
    /// Refuse CAWG 1.1-era legacy shapes; attempt only CAWG 1.2 canonical ones.
    pub strict_encoding: bool,
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

    verify_countersigners(ctx.manifest, claim_refs, ctx.results);
    let topology_invalid: HashSet<String> = ctx
        .results
        .failure
        .iter()
        .filter(|status| {
            matches!(
                status.code.as_str(),
                CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISMATCH
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_DUPLICATE
            )
        })
        .map(|status| status.url.clone())
        .collect();
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
        let url = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
            ctx.manifest.label
        );
        verify_identity_assertion(
            ctx,
            assertion,
            claim_refs,
            primary_binding,
            certificate_status_assertions,
            &url,
            !topology_invalid.contains(&url),
        );
    }
}

fn verify_identity_assertion(
    ctx: &mut IdentityContext<'_>,
    assertion: &Value,
    claim_refs: &ClaimAssertionRefs<'_>,
    primary_binding: Option<&ClaimAssertionReference<'_>>,
    certificate_status_assertions: &[&[u8]],
    url: &str,
    topology_valid: bool,
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
    let claim_binds_identity = claim_refs.references.iter().any(|reference| {
        reference
            .value
            .get("url")
            .and_then(Value::as_text)
            .is_some_and(|reference_url| reference_targets_identity(reference_url, url))
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

    // An EMPTY `referenced_assertions` array is structurally valid CBOR: the
    // upstream validator (c2pa-rs @ d7f13829, identity_assertion/signer_payload.rs
    // `check_against_manifest`) decodes it and reports the semantic
    // `cawg.identity.hard_binding_missing`, not `cawg.identity.cbor.invalid`.
    let referenced = match signer_payload.get("referenced_assertions") {
        Some(Value::Array(values)) => values,
        _ => {
            invalid_cbor(
                ctx.results,
                url,
                "referenced_assertions is missing or not an array",
            );
            return;
        }
    };
    let Some(sig_type) = signer_payload.get("sig_type").and_then(Value::as_text) else {
        invalid_cbor(ctx.results, url, "sig_type is missing");
        return;
    };
    let roles_valid = signer_payload.get("role").is_none_or(|value| match value {
        Value::Array(roles) => {
            !roles.is_empty() && roles.iter().all(|role| role.as_text().is_some())
        }
        _ => false,
    });
    if !roles_valid {
        invalid_cbor(
            ctx.results,
            url,
            "role must be a non-empty array of strings",
        );
        return;
    }

    let mut unique = HashSet::with_capacity(referenced.len());
    let mut duplicate = false;
    let mut mismatch = false;
    for reference in referenced {
        let encoded =
            encode(reference, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
        duplicate |= !unique.insert(encoded);
        mismatch |= !claim_refs
            .references
            .iter()
            .any(|claim_ref| same_hashed_uri(reference, claim_ref.value));
    }
    if duplicate {
        ctx.results.push_failure(
            CAWG_IDENTITY_ASSERTION_DUPLICATE,
            url.into(),
            "referenced_assertions contains a duplicate".into(),
        );
    }
    if mismatch {
        ctx.results.push_failure(
            CAWG_IDENTITY_ASSERTION_MISMATCH,
            url.into(),
            "a referenced assertion is not present in the claim".into(),
        );
    }

    let claim_hard_binding = primary_binding.map(|binding| binding.value);
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
                .and_then(|url| super::assertion_label_for_manifest(url, &ctx.manifest.label))
                .is_some_and(|label| is_supported_hard_binding_label(label, false))
        })
        .filter(|reference| {
            let encoded =
                encode(reference, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
            unique_hard_bindings.insert(encoded)
        })
        .collect();
    let hard_binding_valid = signer_hard_bindings.len() == 1
        && claim_hard_binding.is_some()
        && same_hashed_uri(signer_hard_bindings[0], claim_hard_binding.unwrap());
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
    if duplicate || mismatch || !hard_binding_valid {
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
            ctx.tsa_trust,
            ctx.did_documents,
            ctx.strict_encoding,
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

    // The COSE payload is the CBOR encoding of `signer_payload`. Interop note:
    // c2pa-rs (@ d7f13829, x509/x509_signature_verifier.rs) re-serializes the
    // decoded struct with definite lengths in stored field order and verifies
    // over those bytes (the CAWG 1.1-era shape); our own signer signs the
    // canonical RFC 8949 §4.2 encoding instead. By default accept either
    // encoding of the SAME decoded signer_payload — both bind identical
    // semantics — and surface a field-order-only verification via the
    // informational `com.encypher.cawg.legacyProfile`. Strict encoding
    // attempts ONLY the canonical bytes, so a 1.1-only signature fails with
    // the ordinary mismatch code.
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
        _ if !ctx.strict_encoding && stored_order != canonical => {
            verify_claim(signature, &stored_order, leaf)
                .map(|()| payload_encoding = "legacy-field-order")
                .map_err(|_| error)
        }
        _ => Err(error),
    });
    if let Err(error) = verified {
        let (code, explanation) = match error {
            CryptoError::UnsupportedAlg(_) => (
                CAWG_X509_ALGORITHM_UNSUPPORTED,
                "CAWG identity COSE signature uses an unsupported algorithm",
            ),
            _ => (
                CLAIM_SIGNATURE_MISMATCH,
                "CAWG identity COSE signature does not match signer_payload",
            ),
        };
        ctx.results
            .push_failure(code, url.into(), explanation.into());
        return;
    }
    if payload_encoding == "legacy-field-order" {
        ctx.results.push_informational(
            CAWG_LEGACY_PROFILE,
            url.into(),
            "identity signature verifies over the CAWG 1.1 field-order encoding, not the CAWG 1.2 canonical encoding"
                .into(),
        );
    }

    let identity_time = identity_timestamp(signature, ctx.tsa_trust, ctx.validation_time);
    let timestamp_trusted = identity_time.is_some() || ctx.claim_timestamp.is_some();
    let at = identity_time
        .or(ctx.claim_timestamp)
        .unwrap_or(ctx.validation_time);
    let expected_ok = verify_expected_claim_generator(signer_payload, leaf)
        && verify_expected_partial_claim(signer_payload, ctx.claim, url);
    if !expected_ok {
        if !verify_expected_claim_generator(signer_payload, leaf) {
            ctx.results.push_failure(
                CAWG_IDENTITY_EXPECTED_CLAIM_GENERATOR_MISMATCH,
                url.into(),
                "expected_claim_generator does not hash the identity signing certificate".into(),
            );
        }
        if !verify_expected_partial_claim(signer_payload, ctx.claim, url) {
            ctx.results.push_failure(
                CAWG_IDENTITY_EXPECTED_PARTIAL_CLAIM_MISMATCH,
                url.into(),
                "expected_partial_claim does not hash the claim with the identity reference zeroed"
                    .into(),
            );
        }
        return;
    }

    if !leaf_profile_acceptable_der(leaf) {
        ctx.results.push_failure(
            CAWG_X509_CREDENTIAL_INVALID,
            url.into(),
            "identity signing certificate does not satisfy the C2PA leaf credential profile".into(),
        );
        return;
    }

    if !certificate_valid_at(leaf, at) {
        ctx.results.push_failure(
            CAWG_X509_CREDENTIAL_EXPIRED,
            url.into(),
            "identity signing certificate is outside its validity window".into(),
        );
        return;
    }
    #[cfg(test)]
    record_identity_work(|counts| counts.ocsp_evaluations += 1);

    let revocation_status = evaluate_embedded_ocsp(
        signature,
        certificate_status_assertions,
        &chain,
        timestamp_trusted.then_some(at),
        ctx.ocsp_verification_time,
        ctx.cawg_trust,
    );
    match revocation_status {
        IdentityRevocationStatus::LeafRevoked
        | IdentityRevocationStatus::CaRevoked
        | IdentityRevocationStatus::LeafAndCaRevoked => {
            ctx.results.push_failure(
                CAWG_IDENTITY_CREDENTIAL_REVOKED,
                url.into(),
                "verified OCSP evidence reports an identity credential chain certificate revoked"
                    .into(),
            );
            return;
        }
        IdentityRevocationStatus::NotRevoked => ctx.results.push_success(
            CAWG_X509_OCSP_NOT_REVOKED,
            url.into(),
            "verified OCSP evidence reports the identity leaf not revoked".into(),
        ),
        IdentityRevocationStatus::Skipped => ctx.results.push_informational(
            CAWG_X509_OCSP_SKIPPED,
            url.into(),
            "CAWG identity OCSP evidence was unusable or did not cover the leaf".into(),
        ),
        IdentityRevocationStatus::NotChecked => {}
    }
    if !topology_valid {
        return;
    }

    let trust = identity_certificate_trust(
        leaf,
        &chain[1..],
        at,
        ctx.cawg_trust,
        ctx.cawg_allowed_certs,
        ctx.document_signing_require_anchor,
        timestamp_trusted,
    );
    if let Some(trust) = trust {
        ctx.results.push_success_with_details(
            CAWG_IDENTITY_TRUSTED,
            url.into(),
            "CAWG identity signature and X.509 trust policy validated".into(),
            json!({
                "trust_source": trust.source,
                "accepted_eku": trust.accepted_eku,
                "certificate_policy": trust.certificate_policy,
                "trusted_at": at.to_string(),
                "timestamp_trusted": timestamp_trusted,
                "revocation_status": revocation_status.as_str(),
                "payload_encoding": payload_encoding,
            }),
        );
    } else {
        let (accepted_eku, certificate_policy, trust_failure) = identity_trust_rejection(
            leaf,
            at,
            ctx.document_signing_require_anchor,
            timestamp_trusted,
        );
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

struct IdentityRecord {
    url: String,
    signer_payload: Value,
    partial_payload: Value,
    partial_key: Vec<u8>,
    credential: Option<Vec<u8>>,
}

fn verify_countersigners(
    manifest: &ParsedManifest<'_>,
    claim_refs: &ClaimAssertionRefs<'_>,
    results: &mut ValidationResults,
) {
    let identities: Vec<IdentityRecord> = claim_refs
        .references
        .iter()
        .filter_map(|reference| {
            let label = reference.label?;
            if !is_identity_assertion_label(label) {
                return None;
            }
            #[cfg(test)]
            record_identity_work(|counts| counts.materialized_records += 1);
            let assertion = claim_refs.indexed(label)?.decoded.as_ref()?;
            let signer_payload = assertion.get("signer_payload")?.clone();
            let partial_payload = without_expected_countersigners(&signer_payload);
            let partial_key =
                encode(&partial_payload, Profile::CanonicalForHashedSubstructures).ok()?;
            let credential = assertion
                .get("signature")
                .and_then(Value::as_bytes)
                .and_then(|signature| extract_x5chain(signature).ok())
                .and_then(|chain| chain.into_iter().next());
            Some(IdentityRecord {
                url: format!(
                    "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                    manifest.label
                ),
                signer_payload,
                partial_payload,
                partial_key,
                credential,
            })
        })
        .collect();

    for (identity_index, identity) in identities.iter().enumerate() {
        let Some(expected_value) = identity.signer_payload.get("expected_countersigners") else {
            continue;
        };
        let Value::Array(expected) = expected_value else {
            results.push_failure(
                CAWG_IDENTITY_CBOR_INVALID,
                identity.url.clone(),
                "expected_countersigners must be an array".into(),
            );
            continue;
        };
        if expected.is_empty() || expected.len() > MAX_IDENTITY_ASSERTIONS {
            results.push_failure(
                CAWG_IDENTITY_CBOR_INVALID,
                identity.url.clone(),
                format!(
                    "expected_countersigners must contain 1..={MAX_IDENTITY_ASSERTIONS} entries"
                ),
            );
            continue;
        }

        let mut expected_by_partial: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut seen_descriptions = HashSet::with_capacity(expected.len());
        let mut matched = vec![false; expected.len()];
        for (index, description) in expected.iter().enumerate() {
            let encoded =
                encode(description, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
            if !seen_descriptions.insert(encoded) {
                results.push_failure(
                    CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_DUPLICATE,
                    identity.url.clone(),
                    "expected_countersigners contains a duplicate entry".into(),
                );
            }
            let Some(partial) = description.get("partial_signer_payload") else {
                results.push_failure(
                    CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING,
                    identity.url.clone(),
                    "expected_countersigners entry has no partial_signer_payload".into(),
                );
                matched[index] = true;
                continue;
            };
            let key = encode(partial, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
            expected_by_partial.entry(key).or_default().push(index);
        }

        for (other_index, other) in identities.iter().enumerate() {
            if other_index == identity_index {
                continue;
            }
            let expected_index = expected_by_partial
                .get(&other.partial_key)
                .and_then(|indices| {
                    indices.iter().copied().find(|index| {
                        !matched[*index]
                            && expected[*index].get("partial_signer_payload")
                                == Some(&other.partial_payload)
                    })
                });
            let Some(expected_index) = expected_index else {
                results.push_failure(
                    CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER,
                    identity.url.clone(),
                    "another identity assertion was not described by expected_countersigners"
                        .into(),
                );
                continue;
            };
            matched[expected_index] = true;
            let description = &expected[expected_index];
            if let Some(expected_credential) = description.get("expected_credentials") {
                let matches = other.credential.as_deref().is_some_and(|credential| {
                    let encoded = encode(
                        &Value::Bytes(credential.to_vec()),
                        Profile::CanonicalForHashedSubstructures,
                    )
                    .unwrap_or_default();
                    hash_matches(expected_credential, &encoded)
                });
                if !matches {
                    results.push_failure(
                        CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISMATCH,
                        identity.url.clone(),
                        "expected countersigner payload matched but its credential did not".into(),
                    );
                }
            }
        }

        for (index, was_matched) in matched.into_iter().enumerate() {
            if !was_matched {
                results.push_failure(
                    CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING,
                    identity.url.clone(),
                    format!("described countersigner entry {index} is absent"),
                );
            }
        }
    }
}

fn without_expected_countersigners(signer_payload: &Value) -> Value {
    let mut partial = signer_payload.clone();
    if let Value::Map(entries) = &mut partial {
        entries.retain(|(key, _)| key.as_text() != Some("expected_countersigners"));
    }
    partial
}

fn reference_targets_identity(reference_url: &str, identity_url: &str) -> bool {
    if reference_url == identity_url {
        return true;
    }
    let identity_label = identity_url.rsplit('/').next().unwrap_or("cawg.identity");
    reference_url == format!("self#jumbf=c2pa.assertions/{identity_label}")
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

fn same_hashed_uri(left: &Value, right: &Value) -> bool {
    left.get("url").and_then(Value::as_text) == right.get("url").and_then(Value::as_text)
        && left.get("hash").and_then(Value::as_bytes) == right.get("hash").and_then(Value::as_bytes)
        && left.get("alg").and_then(Value::as_text) == right.get("alg").and_then(Value::as_text)
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

fn identity_timestamp(
    signature: &[u8],
    tsa_trust: Option<&TrustList>,
    verification_time: OffsetDateTime,
) -> Option<OffsetDateTime> {
    let tokens = extract_tsa_tokens(signature);
    let [Some(token)] = tokens.as_slice() else {
        return None;
    };
    let trust = tsa_trust?;
    let payload = timestamp_input(signature).ok()?;
    let result =
        crate::c2pa_trust::verify_timestamp_token(token, &payload, trust, verification_time);
    result.verified.then_some(result.time).flatten()
}

struct IdentityTrustEvidence {
    source: &'static str,
    accepted_eku: Option<&'static str>,
    certificate_policy: Option<String>,
}

fn identity_certificate_trust(
    leaf: &[u8],
    intermediates: &[Vec<u8>],
    at: OffsetDateTime,
    trust: Option<&TrustList>,
    allowed: Option<&TrustList>,
    document_signing_require_anchor: bool,
    identity_timestamp_trusted: bool,
) -> Option<IdentityTrustEvidence> {
    let ekus = certificate_eku_oids_der(leaf).unwrap_or_default();
    let document_signing = ekus.iter().any(|oid| oid == OID_KP_DOCUMENT_SIGNING);
    let email_protection = ekus.iter().any(|oid| oid == OID_KP_EMAIL_PROTECTION);
    let policy = approved_smime_policy(leaf);
    let allowed_match = allowed.is_some_and(|list| list.anchors.iter().any(|cert| cert == leaf));
    let chain_trusted = || {
        trust.is_some_and(|anchors| validate_chain(leaf, intermediates, anchors, Some(at)).trusted)
    };

    if document_signing {
        if allowed_match {
            return Some(IdentityTrustEvidence {
                source: "allowed_list",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
            });
        }
        if !document_signing_require_anchor || chain_trusted() {
            return Some(IdentityTrustEvidence {
                source: "document_signing",
                accepted_eku: Some(OID_KP_DOCUMENT_SIGNING),
                certificate_policy: None,
            });
        }
        return None;
    }

    if at.unix_timestamp() >= S_MIME_INTERIM_CUTOFF_UNIX
        || !identity_timestamp_trusted
        || !email_protection
        || policy.is_none()
    {
        return None;
    }
    if allowed_match {
        return Some(IdentityTrustEvidence {
            source: "allowed_list",
            accepted_eku: Some(OID_KP_EMAIL_PROTECTION),
            certificate_policy: policy,
        });
    }
    if !chain_trusted() {
        return None;
    }
    Some(IdentityTrustEvidence {
        source: "smime",
        accepted_eku: Some(OID_KP_EMAIL_PROTECTION),
        certificate_policy: policy,
    })
}

fn identity_trust_rejection(
    leaf: &[u8],
    at: OffsetDateTime,
    document_signing_require_anchor: bool,
    identity_timestamp_trusted: bool,
) -> (Option<&'static str>, Option<String>, &'static str) {
    let ekus = certificate_eku_oids_der(leaf).unwrap_or_default();
    if ekus.iter().any(|oid| oid == OID_KP_DOCUMENT_SIGNING) {
        return (
            Some(OID_KP_DOCUMENT_SIGNING),
            None,
            if document_signing_require_anchor {
                "document_signing_anchor_required"
            } else {
                "credential_untrusted"
            },
        );
    }
    if ekus.iter().any(|oid| oid == OID_KP_EMAIL_PROTECTION) {
        let policy = approved_smime_policy(leaf);
        let failure = if at.unix_timestamp() >= S_MIME_INTERIM_CUTOFF_UNIX {
            "smime_interim_expired"
        } else if !identity_timestamp_trusted {
            "trusted_timestamp_required"
        } else if policy.is_none() {
            "smime_policy_not_accepted"
        } else {
            "credential_untrusted"
        };
        return (Some(OID_KP_EMAIL_PROTECTION), policy, failure);
    }
    (None, None, "eku_not_accepted")
}

fn approved_smime_policy(cert: &[u8]) -> Option<String> {
    certificate_policy_oids_der(cert)
        .unwrap_or_default()
        .into_iter()
        .find(|oid| CAWG_SMIME_POLICY_OIDS.contains(&oid.as_str()))
}

fn verify_expected_claim_generator(signer_payload: &Value, leaf: &[u8]) -> bool {
    let Some(expected) = signer_payload.get("expected_claim_generator") else {
        return true;
    };
    let encoded = encode(
        &Value::Bytes(leaf.to_vec()),
        Profile::CanonicalForHashedSubstructures,
    )
    .unwrap_or_default();
    hash_matches(expected, &encoded)
}

fn verify_expected_partial_claim(
    signer_payload: &Value,
    claim: &Value,
    identity_url: &str,
) -> bool {
    let Some(expected) = signer_payload.get("expected_partial_claim") else {
        return true;
    };
    let mut partial = claim.clone();
    let mut replaced = false;
    if let Value::Map(map) = &mut partial {
        for field in ["assertions", "created_assertions", "gathered_assertions"] {
            let Some(Value::Array(refs)) = map
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some(field))
                .map(|(_, value)| value)
            else {
                continue;
            };
            for reference in refs {
                let matches = reference
                    .get("url")
                    .and_then(Value::as_text)
                    .is_some_and(|url| reference_targets_identity(url, identity_url));
                if !matches {
                    continue;
                }
                if let Value::Map(reference_map) = reference {
                    if let Some(Value::Bytes(hash)) = reference_map
                        .iter_mut()
                        .find(|(key, _)| key.as_text() == Some("hash"))
                        .map(|(_, value)| value)
                    {
                        hash.fill(0);
                        replaced = true;
                    }
                }
            }
        }
    }
    if !replaced {
        return false;
    }
    let Ok(encoded) = encode(&partial, Profile::CanonicalForHashedSubstructures) else {
        return false;
    };
    hash_matches(expected, &encoded)
}

fn hash_matches(expected: &Value, data: &[u8]) -> bool {
    let Some(algorithm) = expected.get("alg").and_then(Value::as_text) else {
        return false;
    };
    let Some(expected_hash) = expected.get("hash").and_then(Value::as_bytes) else {
        return false;
    };
    match algorithm {
        "sha256" => &Sha256::digest(data)[..] == expected_hash,
        "sha384" => &Sha384::digest(data)[..] == expected_hash,
        "sha512" => &Sha512::digest(data)[..] == expected_hash,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use const_oid::ObjectIdentifier;
    use der::Encode;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
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
        assert!(!same_hashed_uri(&full, &substituted));
        assert!(same_hashed_uri(&full, &full));
    }

    #[test]
    fn document_signing_requires_the_imported_leaf_profile() {
        let valid = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, false);
        let ca_leaf = actor_certificate(OID_KP_DOCUMENT_SIGNING, None, true);
        assert!(leaf_profile_acceptable_der(&valid));
        assert!(!leaf_profile_acceptable_der(&ca_leaf));
        assert!(identity_certificate_trust(
            &valid,
            &[],
            datetime!(2026-01-01 0:00 UTC),
            None,
            None,
            false,
            false,
        )
        .is_some());
    }

    #[test]
    fn smime_accepts_only_the_six_exact_policy_oids_before_cutoff() {
        let before_cutoff =
            OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX - 1).unwrap();
        for policy in CAWG_SMIME_POLICY_OIDS {
            let leaf = actor_certificate(OID_KP_EMAIL_PROTECTION, Some(policy), false);
            let allowed = TrustList {
                anchors: vec![leaf.clone()],
            };
            let evidence = identity_certificate_trust(
                &leaf,
                &[],
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
            let allowed = TrustList {
                anchors: vec![leaf.clone()],
            };
            assert!(identity_certificate_trust(
                &leaf,
                &[],
                before_cutoff,
                None,
                Some(&allowed),
                false,
                true,
            )
            .is_none());
        }
    }

    #[test]
    fn smime_cutoff_and_trusted_timestamp_boundaries_are_exact() {
        let leaf = actor_certificate(
            OID_KP_EMAIL_PROTECTION,
            Some(CAWG_SMIME_POLICY_OIDS[0]),
            false,
        );
        let allowed = TrustList {
            anchors: vec![leaf.clone()],
        };
        let accepted = OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX - 1).unwrap();
        let rejected = OffsetDateTime::from_unix_timestamp(S_MIME_INTERIM_CUTOFF_UNIX).unwrap();
        assert!(identity_certificate_trust(
            &leaf,
            &[],
            accepted,
            None,
            Some(&allowed),
            false,
            true,
        )
        .is_some());
        assert!(identity_certificate_trust(
            &leaf,
            &[],
            accepted,
            None,
            Some(&allowed),
            false,
            false,
        )
        .is_none());
        assert!(identity_certificate_trust(
            &leaf,
            &[],
            rejected,
            None,
            Some(&allowed),
            false,
            true,
        )
        .is_none());
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

    fn claim_with_references(references: Vec<Value>) -> Value {
        Value::Map(vec![(
            Value::Text("created_assertions".into()),
            Value::Array(references),
        )])
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
                did_documents: None,
                strict_encoding: false,
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
    fn multi_identity_countersigner_matching_is_one_to_one_and_fail_closed() {
        let secondary = identity_payload("cawg.publisher:secondary", None);
        let primary = identity_payload(
            "cawg.publisher:primary",
            Some(vec![countersigner_description(secondary.clone())]),
        );
        let primary_bytes = identity_bytes(primary);
        let secondary_bytes = identity_bytes(secondary.clone());
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
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let mut valid = ValidationResults::default();
        verify_countersigners(&manifest, &claim_refs, &mut valid);
        assert!(valid.failure.is_empty());

        let unexpected_bytes = identity_bytes(identity_payload("cawg.publisher:unexpected", None));
        let with_unexpected = ParsedManifest {
            assertions: vec![
                ("cawg.identity".into(), primary_bytes.as_slice()),
                ("cawg.identity__1".into(), secondary_bytes.as_slice()),
                ("cawg.identity__2".into(), unexpected_bytes.as_slice()),
            ],
            ..manifest
        };
        let unexpected_claim = claim_with_references(vec![
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity", 1),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__1", 2),
            hashed_uri("self#jumbf=c2pa.assertions/cawg.identity__2", 3),
        ]);
        let unexpected_refs = ClaimAssertionRefs::build(
            &with_unexpected,
            &unexpected_claim,
            super::super::ClaimGeneration::V2,
        );
        let mut invalid = ValidationResults::default();
        verify_countersigners(&with_unexpected, &unexpected_refs, &mut invalid);
        assert!(invalid
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER));
    }
    #[test]
    fn countersigner_topology_does_not_rescue_a_stale_primary_binding() {
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
                did_documents: None,
                strict_encoding: false,
                results: &mut results,
            };
            verify_identity_assertions(&mut ctx, &claim_refs, Some(primary_reference), &[]);
        }

        assert!(!results.failure.iter().any(|status| {
            matches!(
                status.code.as_str(),
                CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISMATCH
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING
                    | CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_DUPLICATE
            )
        }));
        let missing: Vec<_> = results
            .failure
            .iter()
            .filter(|status| status.code == CAWG_IDENTITY_HARD_BINDING_MISSING)
            .collect();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].url.ends_with("/cawg.identity"));
    }

    #[test]
    fn identity_cap_stops_before_materialization_cryptography_and_ocsp() {
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
                did_documents: None,
                strict_encoding: false,
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

    #[test]
    fn duplicate_expected_countersigners_are_terminal_topology_failures() {
        let secondary = identity_payload("cawg.publisher:secondary", None);
        let description = countersigner_description(secondary.clone());
        let primary = identity_payload(
            "cawg.publisher:primary",
            Some(vec![description.clone(), description]),
        );
        let primary_bytes = identity_bytes(primary);
        let secondary_bytes = identity_bytes(secondary);
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
        ]);
        let claim_refs =
            ClaimAssertionRefs::build(&manifest, &claim, super::super::ClaimGeneration::V2);
        let mut results = ValidationResults::default();
        verify_countersigners(&manifest, &claim_refs, &mut results);
        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_DUPLICATE));
        assert!(results
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_EXPECTED_COUNTERSIGNER_MISSING));
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
    /// non-canonical field order) under the given strict-encoding mode.
    fn identity_verdict_bytes(
        bytes: &[u8],
        claim_refs: &[Value],
        strict_encoding: bool,
    ) -> ValidationResults {
        identity_verdict_bytes_for_binding(bytes, claim_refs, strict_encoding, "c2pa.hash.data")
    }

    fn identity_verdict_bytes_for_binding(
        bytes: &[u8],
        claim_refs: &[Value],
        strict_encoding: bool,
        primary_label: &str,
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
            validation_time: datetime!(2025-05-01 0:00 UTC),
            claim_timestamp: None,
            cawg_trust: None,
            cawg_allowed_certs: None,
            ocsp_verification_time: datetime!(2025-05-01 0:00 UTC),
            document_signing_require_anchor: false,
            tsa_trust: None,
            did_documents: None,
            strict_encoding,
            results: &mut results,
        };
        verify_identity_assertion(
            &mut ctx,
            &assertion,
            &indexed_refs,
            Some(primary_binding),
            &[],
            "self#jumbf=/c2pa/test/c2pa.assertions/cawg.identity",
            true,
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
    fn empty_referenced_assertions_is_hard_binding_missing_not_cbor_invalid() {
        // Upstream precedence (c2pa-rs @ d7f13829, signer_payload.rs): an empty
        // referenced_assertions array decodes fine and fails the semantic
        // hard-binding presence check.
        let assertion = identity_assertion_map(Vec::new());
        let results = identity_verdict(&assertion, &binding_claim_refs(0x22));
        assert_eq!(
            failure_codes(&results),
            [CAWG_IDENTITY_HARD_BINDING_MISSING]
        );
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
    fn legacy_field_order_signature_verifies_by_default_with_informational() {
        let bytes = signed_identity_assertion_bytes(Profile::LegacyPipelineBDefinite);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), false);
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
    fn legacy_field_order_signature_fails_under_strict_encoding() {
        let bytes = signed_identity_assertion_bytes(Profile::LegacyPipelineBDefinite);
        let results = identity_verdict_bytes(&bytes, &binding_claim_refs(0x22), true);
        // Strict mode only attempts the canonical encoding, so the 1.1-only
        // signature fails with the EXISTING mismatch code (no new codes).
        assert_eq!(failure_codes(&results), [CLAIM_SIGNATURE_MISMATCH]);
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
}
