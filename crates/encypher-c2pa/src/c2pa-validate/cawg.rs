//! CAWG Identity 1.2 assertion validation.
//!
//! The validator is deliberately offline. It fully validates the X.509/COSE
//! profile (`cawg.x509.cose`) and the identity-claims-aggregation profile
//! (`cawg.identity_claims_aggregation`, see [`super::cawg_ica`]). ICA `did:web`
//! issuers resolve only against a caller-pinned DID-document store; anything
//! needing live resolution fails closed rather than being presented as trusted.

use std::collections::{HashMap, HashSet};

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use crate::c2pa_core::jumbf::ParsedManifest;
use crate::c2pa_crypto::{
    extract_ocsp_staples, extract_protected_x5chain, extract_tsa_tokens, extract_x5chain,
    timestamp_input, verify_claim, CryptoError,
};
use crate::c2pa_trust::{
    certificate_eku_oids_der, certificate_policy_oids_der, certificate_valid_at,
    leaf_profile_acceptable_der, resolve_issuer, validate_chain, OcspStatus, TrustList,
};
use serde_json::json;
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::OffsetDateTime;

use super::{ref_fields, ClaimGeneration, ValidationResults, CLAIM_SIGNATURE_MISMATCH};

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
    pub manifests: &'a [ParsedManifest<'a>],
    pub manifest_hashes: &'a HashMap<String, Vec<u8>>,
    pub claim: &'a Value,
    pub generation: ClaimGeneration,
    pub validation_time: OffsetDateTime,
    pub claim_timestamp: Option<OffsetDateTime>,
    pub cawg_trust: Option<&'a TrustList>,
    pub cawg_allowed_certs: Option<&'a TrustList>,
    pub document_signing_require_anchor: bool,
    pub tsa_trust: Option<&'a TrustList>,
    pub did_documents: Option<&'a HashMap<String, serde_json::Value>>,
    /// Refuse CAWG 1.1-era legacy shapes; attempt only CAWG 1.2 canonical ones.
    pub strict_encoding: bool,
    pub results: &'a mut ValidationResults,
}

/// Validate every CAWG identity assertion in the active manifest.
pub(super) fn verify_identity_assertions(ctx: &mut IdentityContext<'_>) {
    let claim_refs = collect_traced_claim_refs(ctx);
    verify_countersigners(ctx.manifest, ctx.results);
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
    for (label, bytes) in &ctx.manifest.assertions {
        if label == "cawg.identity" || label.starts_with("cawg.identity__") {
            let url = format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{label}",
                ctx.manifest.label
            );
            verify_identity_assertion(
                ctx,
                bytes,
                &claim_refs,
                &url,
                !topology_invalid.contains(&url),
            );
        }
    }
}

fn verify_identity_assertion(
    ctx: &mut IdentityContext<'_>,
    bytes: &[u8],
    claim_refs: &[Value],
    url: &str,
    topology_valid: bool,
) {
    let claim_binds_identity = claim_refs.iter().any(|reference| {
        reference
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
    let Ok(assertion) = decode(bytes) else {
        ctx.results.push_failure(
            CAWG_IDENTITY_CBOR_INVALID,
            url.into(),
            "identity assertion is not valid CBOR".into(),
        );
        return;
    };
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
            .iter()
            .any(|claim_ref| same_hashed_uri(reference, claim_ref));
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

    let claim_hard_binding = claim_refs
        .iter()
        .find(|reference| is_hard_binding(reference, &ctx.manifest.label));
    // Deduplicate before the hard-binding comparison: a duplicated reference is
    // reported once as `cawg.identity.assertion.duplicate` (terminal for this
    // assertion) and must not also trip the hard-binding count. Upstream
    // (c2pa-rs @ d7f13829, signer_payload.rs) judges hard-binding presence by
    // label only; per-reference hash equality is the mismatch check above.
    let mut unique_hard_bindings = HashSet::new();
    let signer_hard_bindings: Vec<&Value> = referenced
        .iter()
        .filter(|reference| is_hard_binding(reference, &ctx.manifest.label))
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
            "referenced_assertions does not contain exactly the claim hard binding".into(),
        );
    }
    if duplicate || mismatch || !hard_binding_valid {
        return;
    }

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
    let chain = extract_protected_x5chain(signature).unwrap_or_default();
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

    let identity_time = identity_timestamp(signature, ctx.tsa_trust);
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
    let revocation_status =
        identity_revocation_status(signature, ctx.manifests, &chain, at, ctx.cawg_trust);
    match revocation_status {
        IdentityRevocationStatus::Revoked => {
            ctx.results.push_failure(
                CAWG_IDENTITY_CREDENTIAL_REVOKED,
                url.into(),
                "verified OCSP evidence reports a CAWG identity certificate revoked".into(),
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

fn verify_countersigners(manifest: &ParsedManifest<'_>, results: &mut ValidationResults) {
    let identities: Vec<IdentityRecord> = manifest
        .assertions
        .iter()
        .filter(|(label, _)| label == "cawg.identity" || label.starts_with("cawg.identity__"))
        .filter_map(|(label, bytes)| {
            let assertion = decode(bytes).ok()?;
            let signer_payload = assertion.get("signer_payload")?.clone();
            let partial_payload = without_expected_countersigners(&signer_payload);
            let partial_key =
                encode(&partial_payload, Profile::CanonicalForHashedSubstructures).ok()?;
            let credential = assertion
                .get("signature")
                .and_then(Value::as_bytes)
                .and_then(|signature| extract_protected_x5chain(signature).ok())
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
    if identities.len() > MAX_IDENTITY_ASSERTIONS {
        results.push_failure(
            CAWG_IDENTITY_CBOR_INVALID,
            format!("self#jumbf=/c2pa/{}", manifest.label),
            format!(
                "manifest has {} CAWG identities; maximum is {MAX_IDENTITY_ASSERTIONS}",
                identities.len()
            ),
        );
        return;
    }

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

fn collect_claim_refs(claim: &Value, generation: ClaimGeneration) -> Vec<Value> {
    let mut refs = Vec::new();
    for field in ref_fields(generation) {
        if let Some(Value::Array(values)) = claim.get(field) {
            refs.extend(values.iter().cloned());
        }
    }
    refs
}

fn collect_traced_claim_refs(ctx: &IdentityContext<'_>) -> Vec<Value> {
    let mut collected = Vec::new();
    let mut queued = vec![ctx.manifest.label.clone()];
    let mut visited = HashSet::new();

    while let Some(manifest_label) = queued.pop() {
        if !visited.insert(manifest_label.clone()) {
            continue;
        }
        let Some(manifest) = ctx
            .manifests
            .iter()
            .find(|candidate| candidate.label == manifest_label)
        else {
            continue;
        };
        let (claim, generation) = if manifest.label == ctx.manifest.label {
            (ctx.claim.clone(), ctx.generation)
        } else {
            let Some(claim_cbor) = manifest.claim_cbor else {
                continue;
            };
            let Ok(claim) = decode(claim_cbor) else {
                continue;
            };
            let generation = if manifest.claim_box_label.as_deref() == Some("c2pa.claim.v2") {
                ClaimGeneration::V2
            } else {
                ClaimGeneration::V1
            };
            (claim, generation)
        };
        let claim_refs = collect_claim_refs(&claim, generation);

        for reference in &claim_refs {
            let Some(url) = reference.get("url").and_then(Value::as_text) else {
                continue;
            };
            let Some(assertion_label) = super::assertion_label_for_manifest(url, &manifest.label)
            else {
                continue;
            };
            if !assertion_label.starts_with("c2pa.ingredient") {
                continue;
            }
            let Some(assertion_jumbf) = manifest
                .assertion_jumbf
                .iter()
                .find(|(label, _)| label == assertion_label)
                .map(|(_, bytes)| *bytes)
            else {
                continue;
            };
            if !hash_matches(reference, assertion_jumbf) {
                continue;
            }
            let Some(ingredient) = manifest
                .assertions
                .iter()
                .find(|(label, _)| label == assertion_label)
                .and_then(|(_, bytes)| decode(bytes).ok())
            else {
                continue;
            };
            let Some(active_manifest) = ingredient.get("activeManifest") else {
                continue;
            };
            let Some(child_label) = active_manifest
                .get("url")
                .and_then(Value::as_text)
                .and_then(super::extract_manifest_label)
            else {
                continue;
            };
            let expected_hash = active_manifest.get("hash").and_then(Value::as_bytes);
            let algorithm = active_manifest
                .get("alg")
                .and_then(Value::as_text)
                .unwrap_or("sha256");
            if algorithm != "sha256"
                || ctx.manifest_hashes.get(&child_label).map(Vec::as_slice) != expected_hash
            {
                continue;
            }
            let Some(child) = ctx
                .manifests
                .iter()
                .find(|candidate| candidate.label == child_label)
            else {
                continue;
            };
            let (Some(child_claim), Some(child_signature)) =
                (child.claim_cbor, child.signature_cose)
            else {
                continue;
            };
            let Ok(chain) = extract_x5chain(child_signature) else {
                continue;
            };
            if chain
                .first()
                .is_none_or(|leaf| verify_claim(child_signature, child_claim, leaf).is_err())
            {
                continue;
            }
            queued.push(child_label);
        }
        collected.extend(claim_refs);
    }
    collected
}

fn reference_targets_identity(reference_url: &str, identity_url: &str) -> bool {
    if reference_url == identity_url {
        return true;
    }
    let identity_label = identity_url.rsplit('/').next().unwrap_or("cawg.identity");
    reference_url == format!("self#jumbf=c2pa.assertions/{identity_label}")
}

fn same_hashed_uri(left: &Value, right: &Value) -> bool {
    left.get("url").and_then(Value::as_text) == right.get("url").and_then(Value::as_text)
        && left.get("hash").and_then(Value::as_bytes) == right.get("hash").and_then(Value::as_bytes)
        && left.get("alg").and_then(Value::as_text).unwrap_or("sha256")
            == right
                .get("alg")
                .and_then(Value::as_text)
                .unwrap_or("sha256")
}

fn is_hard_binding(reference: &Value, manifest_label: &str) -> bool {
    let label = reference
        .get("url")
        .and_then(Value::as_text)
        .and_then(|url| super::assertion_label_for_manifest(url, manifest_label))
        .unwrap_or("");
    label == "c2pa.hash.data"
        || label == "c2pa.hash.bmff"
        || label.starts_with("c2pa.hash.bmff.")
        || label == "c2pa.hash.boxes"
        || label == "c2pa.hash.collection.data"
        || label == "c2pa.hash.multi-asset"
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

fn identity_timestamp(signature: &[u8], tsa_trust: Option<&TrustList>) -> Option<OffsetDateTime> {
    let tokens = extract_tsa_tokens(signature);
    let [Some(token)] = tokens.as_slice() else {
        return None;
    };
    let trust = tsa_trust?;
    let payload = timestamp_input(signature).ok()?;
    let result = crate::c2pa_trust::verify_timestamp_token(token, &payload, trust);
    result.verified.then_some(result.time).flatten()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentityRevocationStatus {
    NotChecked,
    NotRevoked,
    Revoked,
    Skipped,
}

impl IdentityRevocationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::NotRevoked => "not_revoked",
            Self::Revoked => "revoked",
            Self::Skipped => "skipped",
        }
    }
}

fn collect_ocsp_values(value: &Value, output: &mut Vec<Vec<u8>>, depth: usize) {
    if depth > 4 {
        return;
    }
    match value {
        Value::Map(entries) => {
            for (key, value) in entries {
                if key.as_text() == Some("ocspVals") {
                    if let Value::Array(values) = value {
                        output.extend(
                            values
                                .iter()
                                .filter_map(Value::as_bytes)
                                .map(<[u8]>::to_vec),
                        );
                    }
                } else {
                    collect_ocsp_values(value, output, depth + 1);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_ocsp_values(value, output, depth + 1);
            }
        }
        _ => {}
    }
}

fn identity_revocation_status(
    signature: &[u8],
    manifests: &[ParsedManifest<'_>],
    chain: &[Vec<u8>],
    at: OffsetDateTime,
    trust: Option<&TrustList>,
) -> IdentityRevocationStatus {
    let mut staples = extract_ocsp_staples(signature);
    for manifest in manifests {
        for (label, bytes) in &manifest.assertions {
            if label == "c2pa.certificate-status" {
                if let Ok(assertion) = decode(bytes) {
                    collect_ocsp_values(&assertion, &mut staples, 0);
                }
            }
        }
    }
    if staples.is_empty() {
        return IdentityRevocationStatus::NotChecked;
    }
    let mut issuer_candidates: Vec<Vec<u8>> = chain.iter().skip(1).cloned().collect();
    if let Some(trust) = trust {
        issuer_candidates.extend(trust.anchors.iter().cloned());
    }
    let mut leaf_good = false;
    for (index, subject) in chain.iter().enumerate() {
        let Some(issuer) = resolve_issuer(subject, &issuer_candidates) else {
            continue;
        };
        for staple in &staples {
            let Some(evaluation) =
                crate::c2pa_trust::evaluate_ocsp_verified(staple, &issuer, Some(subject), at)
            else {
                continue;
            };
            if !evaluation.is_fresh_at(at) {
                continue;
            }
            if evaluation.status == OcspStatus::Revoked {
                return IdentityRevocationStatus::Revoked;
            }
            if index == 0 && evaluation.status == OcspStatus::Good {
                leaf_good = true;
            }
        }
    }
    if leaf_good {
        IdentityRevocationStatus::NotRevoked
    } else {
        IdentityRevocationStatus::Skipped
    }
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
        let mut fields = vec![
            (
                Value::Text("referenced_assertions".into()),
                Value::Array(vec![hashed_uri(
                    "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data",
                    0x22,
                )]),
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
        let mut valid = ValidationResults::default();
        verify_countersigners(&manifest, &mut valid);
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
        let mut invalid = ValidationResults::default();
        verify_countersigners(&with_unexpected, &mut invalid);
        assert!(invalid
            .failure
            .iter()
            .any(|status| status.code == CAWG_IDENTITY_UNEXPECTED_COUNTERSIGNER));
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
        let mut results = ValidationResults::default();
        verify_countersigners(&manifest, &mut results);
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
        let bytes =
            encode(assertion, Profile::CanonicalForHashedSubstructures).expect("encode assertion");
        identity_verdict_bytes(&bytes, claim_refs, false)
    }

    /// Run `verify_identity_assertion` on raw assertion bytes (preserving any
    /// non-canonical field order) under the given strict-encoding mode.
    fn identity_verdict_bytes(
        bytes: &[u8],
        claim_refs: &[Value],
        strict_encoding: bool,
    ) -> ValidationResults {
        let manifest = ParsedManifest {
            label: "test".into(),
            assertions: vec![("cawg.identity".into(), bytes)],
            assertion_jumbf: Vec::new(),
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let manifests: [ParsedManifest<'_>; 0] = [];
        let manifest_hashes = HashMap::new();
        let claim = Value::Map(Vec::new());
        let mut results = ValidationResults::default();
        let mut ctx = IdentityContext {
            manifest: &manifest,
            manifests: &manifests,
            manifest_hashes: &manifest_hashes,
            claim: &claim,
            generation: ClaimGeneration::V2,
            validation_time: datetime!(2025-05-01 0:00 UTC),
            claim_timestamp: None,
            cawg_trust: None,
            cawg_allowed_certs: None,
            document_signing_require_anchor: false,
            tsa_trust: None,
            did_documents: None,
            strict_encoding,
            results: &mut results,
        };
        verify_identity_assertion(
            &mut ctx,
            bytes,
            claim_refs,
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
            hashed_uri("self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data", 0x33),
        ]);
        let mut claim_refs = binding_claim_refs(0x22);
        claim_refs.push(hashed_uri(
            "self#jumbf=/c2pa/test/c2pa.assertions/c2pa.hash.data",
            0x33,
        ));
        let results = identity_verdict(&assertion, &claim_refs);
        assert_eq!(
            failure_codes(&results),
            [CAWG_IDENTITY_HARD_BINDING_INCORRECT]
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
