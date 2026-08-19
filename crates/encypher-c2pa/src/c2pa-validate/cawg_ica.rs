//! Offline CAWG Identity 1.2 §8.1 identity-claims-aggregation validation.
//!
//! Validates the `cawg.identity_claims_aggregation` profile: a W3C Verifiable
//! Credential 2.0 (`IdentityClaimsAggregationCredential`) secured by COSE and
//! issued under a DID. Everything runs offline:
//!
//! - `did:jwk` issuers are decoded locally from the base64url JWK in the DID.
//! - `did:web` issuers resolve only against a caller-supplied pinned
//!   DID-document store; absent entries fail closed with
//!   `cawg.ica.did_unavailable`.
//! - Any other DID method is rejected with `cawg.ica.did_unsupported_method`.
//!
//! The validation order and failure taxonomy mirror the CAWG Identity 1.2
//! specification (and the reference c2pa-rs verifier's observable behavior):
//! COSE structure, algorithm, and credential-payload problems are fatal for the
//! assertion; later checks (content type, issuer resolution, signature,
//! timestamp, validity window, `c2paAsset` cross-check) accumulate failures and
//! only a fully clean run earns `cawg.ica.credential_valid`.

use std::collections::HashMap;

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use crate::c2pa_crypto::{extract_tsa_tokens, timestamp_input};
use crate::c2pa_trust::TrustList;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value as Json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::cawg::{CAWG_ICA_DID_UNAVAILABLE, CAWG_LEGACY_PROFILE};
use super::ValidationResults;

pub const CAWG_ICA_INVALID_COSE_SIGN1: &str = "cawg.ica.invalid_cose_sign1";
pub const CAWG_ICA_INVALID_ALG: &str = "cawg.ica.invalid_alg";
pub const CAWG_ICA_INVALID_CONTENT_TYPE: &str = "cawg.ica.invalid_content_type";
pub const CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL: &str = "cawg.ica.invalid_verifiable_credential";
pub const CAWG_ICA_INVALID_ISSUER: &str = "cawg.ica.invalid_issuer";
pub const CAWG_ICA_DID_UNSUPPORTED_METHOD: &str = "cawg.ica.did_unsupported_method";
pub const CAWG_ICA_INVALID_DID_DOCUMENT: &str = "cawg.ica.invalid_did_document";
pub const CAWG_ICA_SIGNATURE_MISMATCH: &str = "cawg.ica.signature_mismatch";
pub const CAWG_ICA_SIGNER_PAYLOAD_MISMATCH: &str = "cawg.ica.signer_payload.mismatch";
pub const CAWG_ICA_TIME_STAMP_VALIDATED: &str = "cawg.ica.time_stamp.validated";
pub const CAWG_ICA_TIME_STAMP_INVALID: &str = "cawg.ica.time_stamp.invalid";
pub const CAWG_ICA_VALID_FROM_MISSING: &str = "cawg.ica.valid_from.missing";
pub const CAWG_ICA_VALID_FROM_INVALID: &str = "cawg.ica.valid_from.invalid";
pub const CAWG_ICA_VALID_UNTIL_INVALID: &str = "cawg.ica.valid_until.invalid";
pub const CAWG_ICA_CREDENTIAL_VALID: &str = "cawg.ica.credential_valid";

/// COSE algorithm identifier for EdDSA. The ICA profile secures the VC with
/// COSE per *Securing Verifiable Credentials using JOSE and COSE*; EdDSA over
/// Ed25519 is the interoperable algorithm for DID-carried OKP keys.
const COSE_ALG_EDDSA: i128 = -8;
/// Protected-header content type the VC payload must declare.
const VC_CONTENT_TYPE: &str = "application/vc";
/// CAWG 1.1-era ICA JSON-LD context (the shape the reference ecosystem still
/// emits). Accepted by default and surfaced via `com.encypher.cawg.legacyProfile`.
const CAWG_ICA_CONTEXT_1_1: &str = "https://cawg.io/identity/1.1/ica/context/";
/// CAWG 1.2 ICA JSON-LD context — the only context accepted in strict mode.
const CAWG_ICA_CONTEXT_1_2: &str = "https://cawg.io/identity/1.2/ica/context/";

/// Validate one ICA identity assertion, appending status codes to `results`.
///
/// `signer_payload` is the decoded CBOR `signer_payload` map from the identity
/// assertion; `signature` its raw COSE_Sign1 bytes. `did_documents` is the
/// optional pinned offline `did:web` store keyed by primary DID (no fragment).
/// `strict_encoding` refuses CAWG 1.1-era legacy shapes (1.1 JSON-LD context,
/// byte-array `c2paAsset` hashes); by default they are accepted and surfaced
/// via the informational `com.encypher.cawg.legacyProfile` status.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_ica_assertion(
    signer_payload: &Value,
    signature: &[u8],
    url: &str,
    validation_time: OffsetDateTime,
    tsa_trust: Option<&TrustList>,
    did_documents: Option<&HashMap<String, Json>>,
    strict_encoding: bool,
    results: &mut ValidationResults,
) {
    let Some(cose) = CoseSign1::parse(signature) else {
        results.push_failure(
            CAWG_ICA_INVALID_COSE_SIGN1,
            url.into(),
            "ICA signature is not a valid COSE_Sign1_Tagged structure".into(),
        );
        return;
    };

    match protected_int(&cose.protected, 1) {
        Some(COSE_ALG_EDDSA) => {}
        Some(_) | None => {
            results.push_failure(
                CAWG_ICA_INVALID_ALG,
                url.into(),
                "COSE protected header is missing a supported signature algorithm".into(),
            );
            return;
        }
    }

    // Every failure past this point is recoverable: keep validating so a
    // report carries the complete failure set, and withhold the
    // `credential_valid` success unless the run stays clean.
    let mut ok = true;

    let content_type_valid = matches!(
        map_int(&cose.protected, 3),
        Some(Value::Text(text)) if text == VC_CONTENT_TYPE
    );
    if !content_type_valid {
        results.push_failure(
            CAWG_ICA_INVALID_CONTENT_TYPE,
            url.into(),
            "COSE protected content type is missing or is not application/vc".into(),
        );
        ok = false;
    }

    let Some(payload) = cose.payload.as_deref() else {
        results.push_failure(
            CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL,
            url.into(),
            "COSE payload does not carry the verifiable credential".into(),
        );
        return;
    };
    let credential = match parse_ica_credential(payload, strict_encoding) {
        Ok(credential) => credential,
        Err(reason) => {
            results.push_failure(
                CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL,
                url.into(),
                format!("payload is not a valid identity claims aggregation credential: {reason}"),
            );
            return;
        }
    };
    if credential.context_version == "1.1" {
        results.push_informational(
            CAWG_LEGACY_PROFILE,
            url.into(),
            "ICA credential declares the CAWG 1.1 JSON-LD context (https://cawg.io/identity/1.1/ica/context/), not the CAWG 1.2 context"
                .into(),
        );
    }

    match resolve_issuer_key(&credential.issuer, did_documents) {
        Ok(key) => {
            if !verify_eddsa_signature(&cose, payload, &key) {
                results.push_failure(
                    CAWG_ICA_SIGNATURE_MISMATCH,
                    url.into(),
                    "COSE signature does not verify against the issuer DID key".into(),
                );
                ok = false;
            }
        }
        Err(failure) => {
            results.push_failure(failure.code, url.into(), failure.explanation);
            ok = false;
        }
    }

    let timestamp = match ica_timestamp(signature, tsa_trust, validation_time) {
        IcaTimestamp::Absent => None,
        IcaTimestamp::Valid(at) => {
            results.push_success(
                CAWG_ICA_TIME_STAMP_VALIDATED,
                url.into(),
                "RFC 3161 timestamp verified over the ICA COSE signature".into(),
            );
            Some(at)
        }
        IcaTimestamp::Invalid => {
            results.push_failure(
                CAWG_ICA_TIME_STAMP_INVALID,
                url.into(),
                "sigTst2 timestamp token failed verification".into(),
            );
            ok = false;
            None
        }
    };

    match credential.valid_from {
        None => {
            results.push_failure(
                CAWG_ICA_VALID_FROM_MISSING,
                url.into(),
                "credential does not declare validFrom".into(),
            );
            ok = false;
        }
        Some(valid_from) => {
            if validation_time < valid_from {
                results.push_failure(
                    CAWG_ICA_VALID_FROM_INVALID,
                    url.into(),
                    "validFrom is after the validation time".into(),
                );
                ok = false;
            } else if timestamp.is_some_and(|at| at < valid_from) {
                results.push_failure(
                    CAWG_ICA_VALID_FROM_INVALID,
                    url.into(),
                    "validFrom is after the verified signature timestamp".into(),
                );
                ok = false;
            }
        }
    }
    if let Some(valid_until) = credential.valid_until {
        if validation_time > valid_until {
            results.push_failure(
                CAWG_ICA_VALID_UNTIL_INVALID,
                url.into(),
                "validUntil is before the validation time".into(),
            );
            ok = false;
        } else if timestamp.is_some_and(|at| at > valid_until) {
            results.push_failure(
                CAWG_ICA_VALID_UNTIL_INVALID,
                url.into(),
                "validUntil is before the verified signature timestamp".into(),
            );
            ok = false;
        }
    }

    let (payload_matches, legacy_hash_encoding) =
        signer_payload_matches(signer_payload, &credential.c2pa_asset, strict_encoding);
    if legacy_hash_encoding {
        results.push_informational(
            CAWG_LEGACY_PROFILE,
            url.into(),
            "c2paAsset referenced_assertions carry the legacy JSON byte-array hash encoding, not a base64 string"
                .into(),
        );
    }
    if !payload_matches {
        results.push_failure(
            CAWG_ICA_SIGNER_PAYLOAD_MISMATCH,
            url.into(),
            "credentialSubject.c2paAsset does not match the signed signer_payload".into(),
        );
        ok = false;
    }

    if ok {
        let trusted_at = timestamp.and_then(|at| at.format(&Rfc3339).ok());
        let trust_source = if credential.issuer.starts_with("did:jwk:") {
            "did_jwk"
        } else {
            "caller_pinned_did_document"
        };
        results.push_success_with_details(
            CAWG_ICA_CREDENTIAL_VALID,
            url.into(),
            "identity claims aggregation credential validated".into(),
            serde_json::json!({
                "ica_context": credential.context_version,
                "issuer": credential.issuer,
                "verified_identities": credential.verified_identities,
                "trust_source": trust_source,
                "timestamp_trusted": timestamp.is_some(),
                "trusted_at": trusted_at,
            }),
        );
    }
}

/// Decoded `COSE_Sign1_Tagged` pieces needed for ICA validation.
struct CoseSign1 {
    protected_bytes: Vec<u8>,
    protected: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parse tag-18 COSE_Sign1 bytes. Any structural deviation returns `None`.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let value = decode(bytes).ok()?;
        let Value::Tag(18, inner) = value else {
            return None;
        };
        let Value::Array(items) = *inner else {
            return None;
        };
        let mut items = items.into_iter();
        let (Some(protected_item), Some(Value::Map(_)), Some(payload_item), Some(signature_item)) =
            (items.next(), items.next(), items.next(), items.next())
        else {
            return None;
        };
        if items.next().is_some() {
            return None;
        }
        let Value::Bytes(protected_bytes) = protected_item else {
            return None;
        };
        let Value::Bytes(signature) = signature_item else {
            return None;
        };
        let payload = match payload_item {
            Value::Bytes(bytes) => Some(bytes),
            Value::Null => None,
            _ => return None,
        };
        let protected = if protected_bytes.is_empty() {
            Vec::new()
        } else {
            match decode(&protected_bytes).ok()? {
                Value::Map(entries) => entries,
                _ => return None,
            }
        };
        Some(Self {
            protected_bytes,
            protected,
            payload,
            signature,
        })
    }
}

/// Look up an integer-keyed protected-header entry.
fn map_int(entries: &[(Value, Value)], key: i128) -> Option<&Value> {
    entries.iter().find_map(|(k, v)| match k {
        Value::Integer(int) if *int == key => Some(v),
        _ => None,
    })
}

/// Integer value of an integer-keyed protected-header entry.
fn protected_int(entries: &[(Value, Value)], key: i128) -> Option<i128> {
    match map_int(entries, key) {
        Some(Value::Integer(int)) => Some(*int),
        _ => None,
    }
}

/// The subset of the identity claims aggregation VC the validator consumes.
struct IcaCredential {
    issuer: String,
    valid_from: Option<OffsetDateTime>,
    valid_until: Option<OffsetDateTime>,
    c2pa_asset: Json,
    verified_identities: Vec<Json>,
    /// CAWG ICA JSON-LD context generation: `"1.2"`, `"1.1"`, or `"unknown"`.
    context_version: &'static str,
}

/// Parse and shape-check the VC 2.0 JSON payload.
///
/// Mirrors the required fields of the W3C VC 2.0 data model plus the
/// `IdentityClaimsAggregationCredential` subject grammar (`verifiedIdentities`
/// and `c2paAsset`). Returns a stable reason string on rejection.
fn parse_ica_credential(
    payload: &[u8],
    strict_encoding: bool,
) -> Result<IcaCredential, &'static str> {
    let root: Json = serde_json::from_slice(payload).map_err(|_| "payload is not JSON")?;
    let object = root.as_object().ok_or("credential is not a JSON object")?;

    let contexts = object
        .get("@context")
        .and_then(Json::as_array)
        .ok_or("@context is missing or not an array")?;
    if contexts.is_empty() || !contexts.iter().all(|entry| entry.is_string()) {
        return Err("@context must be a non-empty array of strings");
    }
    let has_context = |url: &str| contexts.iter().any(|entry| entry.as_str() == Some(url));
    let context_version = if has_context(CAWG_ICA_CONTEXT_1_2) {
        "1.2"
    } else if has_context(CAWG_ICA_CONTEXT_1_1) {
        "1.1"
    } else {
        "unknown"
    };
    if context_version == "unknown" {
        return Err("credential lacks a CAWG ICA JSON-LD context");
    }
    if strict_encoding && context_version != "1.2" {
        return Err("strict encoding requires the CAWG 1.2 ICA JSON-LD context");
    }
    let types = object
        .get("type")
        .and_then(Json::as_array)
        .ok_or("type is missing or not an array")?;
    if types.is_empty() || !types.iter().all(|entry| entry.is_string()) {
        return Err("type must be a non-empty array of strings");
    }
    let has_type = |expected: &str| types.iter().any(|entry| entry.as_str() == Some(expected));
    if !has_type("VerifiableCredential") || !has_type("IdentityClaimsAggregationCredential") {
        return Err(
            "type must include VerifiableCredential and IdentityClaimsAggregationCredential",
        );
    }

    let issuer = object
        .get("issuer")
        .and_then(Json::as_str)
        .ok_or("issuer is missing or not a string")?;
    if !has_uri_scheme(issuer) {
        return Err("issuer is not a URI");
    }

    let subject = match object.get("credentialSubject") {
        Some(Json::Object(map)) => map,
        Some(Json::Array(items)) => items
            .first()
            .and_then(Json::as_object)
            .ok_or("credentialSubject array is empty or not objects")?,
        _ => return Err("credentialSubject is missing"),
    };
    let identities = subject
        .get("verifiedIdentities")
        .and_then(Json::as_array)
        .ok_or("verifiedIdentities is missing or not an array")?;
    if identities.is_empty() {
        return Err("verifiedIdentities is empty");
    }
    for identity in identities {
        let identity = identity
            .as_object()
            .ok_or("verifiedIdentities entry is not an object")?;
        if identity
            .get("type")
            .and_then(Json::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("verifiedIdentities entry lacks a type");
        }
        let verified_at = identity
            .get("verifiedAt")
            .and_then(Json::as_str)
            .ok_or("verifiedIdentities entry lacks verifiedAt")?;
        OffsetDateTime::parse(verified_at, &Rfc3339).map_err(|_| "verifiedAt is not RFC 3339")?;
        let provider = identity
            .get("provider")
            .and_then(Json::as_object)
            .ok_or("verifiedIdentities entry lacks a provider object")?;
        if provider.get("id").and_then(Json::as_str).is_none()
            || provider
                .get("name")
                .and_then(Json::as_str)
                .is_none_or(str::is_empty)
        {
            return Err("provider requires id and non-empty name");
        }
    }

    let c2pa_asset = subject
        .get("c2paAsset")
        .cloned()
        .ok_or("credentialSubject lacks c2paAsset")?;
    let asset = c2pa_asset.as_object().ok_or("c2paAsset is not an object")?;
    let referenced = asset
        .get("referenced_assertions")
        .and_then(Json::as_array)
        .ok_or("c2paAsset lacks referenced_assertions")?;
    for reference in referenced {
        let reference = reference
            .as_object()
            .ok_or("referenced_assertions entry is not an object")?;
        if reference.get("url").and_then(Json::as_str).is_none() {
            return Err("referenced_assertions entry lacks a url");
        }
        match reference.get("hash") {
            Some(Json::String(_)) | Some(Json::Array(_)) => {}
            _ => return Err("referenced_assertions entry lacks a hash"),
        }
    }
    if asset.get("sig_type").and_then(Json::as_str).is_none() {
        return Err("c2paAsset lacks sig_type");
    }

    let parse_instant = |key: &str| -> Result<Option<OffsetDateTime>, &'static str> {
        match object.get(key) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::String(text)) => OffsetDateTime::parse(text, &Rfc3339)
                .map(Some)
                .map_err(|_| "validity instant is not RFC 3339"),
            Some(_) => Err("validity instant is not a string"),
        }
    };

    Ok(IcaCredential {
        issuer: issuer.to_owned(),
        valid_from: parse_instant("validFrom")?,
        valid_until: parse_instant("validUntil")?,
        c2pa_asset,
        verified_identities: identities.clone(),
        context_version,
    })
}

/// Minimal URI scheme check (RFC 3986 `scheme ":"`).
fn has_uri_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// A failed issuer-key resolution, mapped to its CAWG status code.
#[derive(Debug)]
struct IssuerFailure {
    code: &'static str,
    explanation: String,
}

impl IssuerFailure {
    fn new(code: &'static str, explanation: impl Into<String>) -> Self {
        Self {
            code,
            explanation: explanation.into(),
        }
    }
}

/// Resolve the issuer DID to an Ed25519 verifying key, entirely offline.
fn resolve_issuer_key(
    issuer: &str,
    did_documents: Option<&HashMap<String, Json>>,
) -> Result<VerifyingKey, IssuerFailure> {
    let Some((method, method_specific_id)) = parse_did(issuer) else {
        return Err(IssuerFailure::new(
            CAWG_ICA_INVALID_ISSUER,
            format!("issuer is not a DID: {issuer}"),
        ));
    };
    let primary = issuer.split('#').next().unwrap_or(issuer);
    match method {
        "jwk" => {
            let jwk_id = method_specific_id.split('#').next().unwrap_or("");
            let jwk_bytes = base64_decode_url(jwk_id).ok_or_else(|| {
                IssuerFailure::new(
                    CAWG_ICA_INVALID_DID_DOCUMENT,
                    "did:jwk identifier is not base64url",
                )
            })?;
            let jwk: Json = serde_json::from_slice(&jwk_bytes).map_err(|_| {
                IssuerFailure::new(
                    CAWG_ICA_INVALID_DID_DOCUMENT,
                    "did:jwk identifier is not a JSON JWK",
                )
            })?;
            jwk_to_key(&jwk)
        }
        "web" => {
            let document = did_documents
                .and_then(|store| store.get(primary))
                .ok_or_else(|| {
                    IssuerFailure::new(
                        CAWG_ICA_DID_UNAVAILABLE,
                        "did:web issuer is not present in the pinned offline DID-document store",
                    )
                })?;
            let method_entry = document
                .get("assertionMethod")
                .and_then(Json::as_array)
                .and_then(|methods| methods.first())
                .ok_or_else(|| {
                    IssuerFailure::new(
                        CAWG_ICA_INVALID_DID_DOCUMENT,
                        "DID document does not contain an assertionMethod entry",
                    )
                })?;
            let jwk = method_entry
                .as_object()
                .and_then(|entry| entry.get("publicKeyJwk"))
                .ok_or_else(|| {
                    IssuerFailure::new(
                        CAWG_ICA_INVALID_DID_DOCUMENT,
                        "assertionMethod does not embed a publicKeyJwk",
                    )
                })?;
            jwk_to_key(jwk)
        }
        other => Err(IssuerFailure::new(
            CAWG_ICA_DID_UNSUPPORTED_METHOD,
            format!("unsupported DID method: {other}"),
        )),
    }
}

/// Parse `did:<method>:<method-specific-id>` and return the method and id.
///
/// Matches the reference validator's permissive prefix grammar: the method is
/// lowercase alphanumeric and the id must start with at least one legal DID
/// character.
fn parse_did(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("did:")?;
    let colon = rest.find(':')?;
    let (method, id) = (&rest[..colon], &rest[colon + 1..]);
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let first = *id.as_bytes().first()?;
    if !(first.is_ascii_alphanumeric()
        || matches!(first, b'/' | b'.' | b'%' | b'#' | b'?' | b'_' | b'-'))
    {
        return None;
    }
    Some((method, id))
}

/// Convert a JSON JWK to an Ed25519 verifying key.
///
/// The ICA profile carries OKP/Ed25519 keys; anything else is a DID-document
/// level rejection rather than an algorithm failure.
fn jwk_to_key(jwk: &Json) -> Result<VerifyingKey, IssuerFailure> {
    let invalid = |reason: &str| IssuerFailure::new(CAWG_ICA_INVALID_DID_DOCUMENT, reason);
    let object = jwk
        .as_object()
        .ok_or_else(|| invalid("JWK is not an object"))?;
    if object.get("kty").and_then(Json::as_str) != Some("OKP") {
        return Err(invalid("JWK kty is not OKP"));
    }
    if object.get("crv").and_then(Json::as_str) != Some("Ed25519") {
        return Err(invalid("JWK curve is not Ed25519"));
    }
    let x = object
        .get("x")
        .and_then(Json::as_str)
        .and_then(base64_decode_url)
        .ok_or_else(|| invalid("JWK x is not base64url"))?;
    let x: [u8; 32] = x
        .try_into()
        .map_err(|_| invalid("JWK x is not a 32-byte Ed25519 key"))?;
    VerifyingKey::from_bytes(&x).map_err(|_| invalid("JWK x is not a valid Ed25519 point"))
}

/// Verify the COSE_Sign1 EdDSA signature over `Sig_structure` with the
/// attached VC payload (RFC 9052 §4.4, empty external AAD).
fn verify_eddsa_signature(cose: &CoseSign1, payload: &[u8], key: &VerifyingKey) -> bool {
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(cose.protected_bytes.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let Ok(to_be_signed) = encode(&sig_structure, Profile::LegacyPipelineBDefinite) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&cose.signature) else {
        return false;
    };
    key.verify(&to_be_signed, &signature).is_ok()
}

/// Outcome of `sigTst2` timestamp evaluation.
enum IcaTimestamp {
    /// No timestamp header present: nothing to report.
    Absent,
    /// Token cryptographically verified; carries the generation time.
    Valid(OffsetDateTime),
    /// A token was present but failed verification.
    Invalid,
}

/// Evaluate the optional `sigTst2` timestamp on the ICA COSE signature.
///
/// With a caller-supplied TSA trust list the token must chain to it. Without
/// one, the token is verified cryptographically (imprint, CMS signature, TSA
/// EKU, validity at generation time) against the certificates it embeds — the
/// CAWG profile treats the timestamp as evidence about the credential's
/// validity window, not as a C2PA trust decision, matching the reference
/// validator's passthrough trust policy.
fn ica_timestamp(
    signature: &[u8],
    tsa_trust: Option<&TrustList>,
    verification_time: OffsetDateTime,
) -> IcaTimestamp {
    let tokens = extract_tsa_tokens(signature);
    if tokens.is_empty() {
        return IcaTimestamp::Absent;
    }
    let [Some(token)] = tokens.as_slice() else {
        return IcaTimestamp::Invalid;
    };
    let Ok(payload) = timestamp_input(signature) else {
        return IcaTimestamp::Invalid;
    };
    let passthrough;
    let trust = match tsa_trust {
        Some(trust) => trust,
        None => {
            passthrough = TrustList {
                anchors: embedded_timestamp_certificates(token),
            };
            &passthrough
        }
    };
    let result =
        crate::c2pa_trust::verify_timestamp_token(token, &payload, trust, verification_time);
    match (result.verified, result.time) {
        (true, Some(at)) => IcaTimestamp::Valid(at),
        _ => IcaTimestamp::Invalid,
    }
}

/// Extract the DER certificates embedded in an RFC 3161 token so they can act
/// as passthrough anchors when no TSA trust list is configured.
fn embedded_timestamp_certificates(token: &[u8]) -> Vec<Vec<u8>> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    let Ok(content_info) = ContentInfo::from_der(token) else {
        return Vec::new();
    };
    let Ok(signed_data) = content_info.content.decode_as::<SignedData>() else {
        return Vec::new();
    };
    signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(cert) => cert.to_der().ok(),
            _ => None,
        })
        .collect()
}

/// Compare the CBOR `signer_payload` against the VC's `credentialSubject.c2paAsset`.
///
/// `c2paAsset` is the JSON serialization of `signer_payload` with every CBOR
/// byte string re-encoded as standard base64 (CAWG Identity 1.2 §8.1.1.2). The
/// reference ecosystem also emits the base64 text as a JSON byte array, and
/// omits `alg` on either side; both are tolerated exactly as the reference
/// validator does — unless `strict_encoding` disables the byte-array form.
///
/// Returns `(matches, legacy_hash_encoding)`: the second flag is set when a
/// legacy byte-array hash was decoded during the comparison.
fn signer_payload_matches(
    signer_payload: &Value,
    c2pa_asset: &Json,
    strict_encoding: bool,
) -> (bool, bool) {
    let mut legacy_hash = false;
    let Some(asset) = c2pa_asset.as_object() else {
        return (false, legacy_hash);
    };
    if signer_payload.get("sig_type").and_then(Value::as_text)
        != asset.get("sig_type").and_then(Json::as_str)
    {
        return (false, legacy_hash);
    }

    let cbor_roles: Vec<&str> = match signer_payload.get("role") {
        Some(Value::Array(roles)) => roles.iter().filter_map(Value::as_text).collect(),
        _ => Vec::new(),
    };
    let vc_roles: Vec<&str> = match asset.get("role") {
        Some(Json::Array(roles)) => roles.iter().filter_map(Json::as_str).collect(),
        _ => Vec::new(),
    };
    if cbor_roles != vc_roles {
        return (false, legacy_hash);
    }

    let cbor_refs = match signer_payload.get("referenced_assertions") {
        Some(Value::Array(refs)) => refs,
        _ => return (false, legacy_hash),
    };
    let vc_refs = match asset.get("referenced_assertions") {
        Some(Json::Array(refs)) => refs,
        _ => return (false, legacy_hash),
    };
    if cbor_refs.len() != vc_refs.len() {
        return (false, legacy_hash);
    }
    let matches = cbor_refs.iter().zip(vc_refs).all(|(cbor_ref, vc_ref)| {
        hashed_uri_matches(cbor_ref, vc_ref, strict_encoding, &mut legacy_hash)
    });
    (matches, legacy_hash)
}

/// Compare one referenced-assertion entry between the CBOR and VC encodings.
fn hashed_uri_matches(
    cbor_ref: &Value,
    vc_ref: &Json,
    strict_encoding: bool,
    legacy_hash: &mut bool,
) -> bool {
    let Some(vc_ref) = vc_ref.as_object() else {
        return false;
    };
    if cbor_ref.get("url").and_then(Value::as_text) != vc_ref.get("url").and_then(Json::as_str) {
        return false;
    }
    // `alg` is optional and some signers omit it on the CBOR side only; when
    // the signed payload omits it, the VC value is not comparable evidence.
    if let Some(alg) = cbor_ref.get("alg").and_then(Value::as_text) {
        if vc_ref.get("alg").and_then(Json::as_str) != Some(alg) {
            return false;
        }
    }
    let Some(cbor_hash) = cbor_ref.get("hash").and_then(Value::as_bytes) else {
        return false;
    };
    let Some(decoded) = vc_hash_bytes(vc_ref.get("hash"), strict_encoding, legacy_hash) else {
        return false;
    };
    decoded == cbor_hash
}

/// Decode a VC `hash` entry to the raw digest bytes.
///
/// The value is the standard base64 of the CBOR digest, carried either as a
/// JSON string or (legacy encoders) as a JSON array of the string's bytes. The
/// byte-array form is refused under `strict_encoding`; when accepted, it sets
/// `legacy_hash`.
fn vc_hash_bytes(
    value: Option<&Json>,
    strict_encoding: bool,
    legacy_hash: &mut bool,
) -> Option<Vec<u8>> {
    let text: String = match value? {
        Json::String(text) => text.clone(),
        Json::Array(items) => {
            if strict_encoding {
                return None;
            }
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect();
            let text = String::from_utf8(bytes?).ok()?;
            *legacy_hash = true;
            text
        }
        _ => return None,
    };
    base64_decode_std(&text)
}

/// Decode standard-alphabet base64 (RFC 4648 §4), padding required or absent.
fn base64_decode_std(input: &str) -> Option<Vec<u8>> {
    base64_decode(input, false)
}

/// Decode base64url (RFC 4648 §5); padding tolerated either way.
fn base64_decode_url(input: &str) -> Option<Vec<u8>> {
    base64_decode(input, true)
}

fn base64_decode(input: &str, url_alphabet: bool) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in trimmed.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' if !url_alphabet => 62,
            b'/' if !url_alphabet => 63,
            b'-' if url_alphabet => 62,
            b'_' if url_alphabet => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    if bits >= 6 || (accumulator & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;
    use time::macros::datetime;

    const URL: &str = "self#jumbf=/c2pa/m/c2pa.assertions/cawg.identity";
    const HASH: [u8; 32] = [0xA7; 32];

    fn base64_encode(input: &[u8], url_alphabet: bool) -> String {
        let alphabet: &[u8; 64] = if url_alphabet {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let mut word = [0u8; 3];
            word[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from(word[0]) << 16 | u32::from(word[1]) << 8 | u32::from(word[2]);
            let symbols = [
                (bits >> 18) & 63,
                (bits >> 12) & 63,
                (bits >> 6) & 63,
                bits & 63,
            ];
            let emit = chunk.len() + 1;
            for symbol in &symbols[..emit] {
                out.push(alphabet[*symbol as usize] as char);
            }
        }
        out
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn did_jwk(key: &SigningKey) -> String {
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64_encode(key.verifying_key().as_bytes(), true),
        });
        format!(
            "did:jwk:{}",
            base64_encode(jwk.to_string().as_bytes(), true)
        )
    }

    fn signer_payload() -> Value {
        Value::Map(vec![
            (
                "referenced_assertions".into(),
                Value::Array(vec![Value::Map(vec![
                    (
                        "url".into(),
                        Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                    ),
                    ("hash".into(), Value::Bytes(HASH.to_vec())),
                ])]),
            ),
            (
                "sig_type".into(),
                Value::Text("cawg.identity_claims_aggregation".into()),
            ),
        ])
    }

    fn vc_json(issuer: &str, valid_from: Option<&str>, valid_until: Option<&str>) -> Json {
        let mut vc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://cawg.io/identity/1.1/ica/context/",
            ],
            "type": ["VerifiableCredential", "IdentityClaimsAggregationCredential"],
            "issuer": issuer,
            "credentialSubject": {
                "verifiedIdentities": [{
                    "type": "cawg.social_media",
                    "username": "user",
                    "verifiedAt": "2024-05-27T08:40:39Z",
                    "provider": {"id": "https://idp.example", "name": "Example IdP"},
                }],
                "c2paAsset": {
                    "referenced_assertions": [{
                        "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                        "hash": base64_encode(&HASH, false),
                    }],
                    "sig_type": "cawg.identity_claims_aggregation",
                },
            },
        });
        if let Some(valid_from) = valid_from {
            vc["validFrom"] = json!(valid_from);
        }
        if let Some(valid_until) = valid_until {
            vc["validUntil"] = json!(valid_until);
        }
        vc
    }

    fn ica_cose(key: &SigningKey, vc: &Json) -> Vec<u8> {
        let protected = Value::Map(vec![
            (Value::Integer(1), Value::Integer(COSE_ALG_EDDSA)),
            (Value::Integer(3), Value::Text(VC_CONTENT_TYPE.into())),
        ]);
        let protected_bytes =
            encode(&protected, Profile::LegacyPipelineBDefinite).expect("protected");
        let payload = serde_json::to_vec(vc).expect("payload");
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected_bytes.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]);
        let to_be_signed = encode(&sig_structure, Profile::LegacyPipelineBDefinite).expect("tbs");
        let signature = key.sign(&to_be_signed).to_bytes().to_vec();
        let cose = Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected_bytes),
                Value::Map(Vec::new()),
                Value::Bytes(payload),
                Value::Bytes(signature),
            ])),
        );
        encode(&cose, Profile::LegacyPipelineBDefinite).expect("cose")
    }

    fn run(cose: &[u8]) -> ValidationResults {
        run_mode(cose, false)
    }

    fn run_mode(cose: &[u8], strict_encoding: bool) -> ValidationResults {
        let mut results = ValidationResults::default();
        verify_ica_assertion(
            &signer_payload(),
            cose,
            URL,
            datetime!(2025-06-01 0:00 UTC),
            None,
            None,
            strict_encoding,
            &mut results,
        );
        results
    }

    fn codes(items: &[crate::c2pa_validate::StatusCode]) -> Vec<&str> {
        items.iter().map(|status| status.code.as_str()).collect()
    }

    #[test]
    fn full_valid_ica_flow_yields_credential_valid() {
        let key = signing_key();
        let vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        let results = run(&ica_cose(&key, &vc));
        assert!(
            results.failure.is_empty(),
            "failures: {:?}",
            results.failure
        );
        assert_eq!(codes(&results.success), vec![CAWG_ICA_CREDENTIAL_VALID]);
        let details = results.success[0]
            .details
            .as_ref()
            .expect("valid ICA reports identity details");
        assert_eq!(details["trust_source"], "did_jwk");
        assert_eq!(details["timestamp_trusted"], false);
        assert_eq!(details["trusted_at"], Json::Null);
        assert_eq!(
            details["verified_identities"],
            vc["credentialSubject"]["verifiedIdentities"]
        );
    }

    #[test]
    fn did_jwk_decodes_to_the_signing_public_key() {
        let key = signing_key();
        let resolved = resolve_issuer_key(&did_jwk(&key), None).expect("did:jwk resolves");
        assert_eq!(resolved.as_bytes(), key.verifying_key().as_bytes());
    }

    #[test]
    fn issuer_classification_matches_the_failure_taxonomy() {
        let store: HashMap<String, Json> = [
            (
                "did:web:pinned.example".to_string(),
                json!({"assertionMethod": [{"publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64_encode(signing_key().verifying_key().as_bytes(), true),
                }}]}),
            ),
            ("did:web:no-method.example".to_string(), json!({"id": "x"})),
        ]
        .into();
        let case = |issuer: &str, store: Option<&HashMap<String, Json>>| {
            resolve_issuer_key(issuer, store).map_err(|failure| failure.code)
        };
        assert_eq!(
            case("not-did:jwk:abc", None).unwrap_err(),
            CAWG_ICA_INVALID_ISSUER
        );
        assert_eq!(
            case("did:key:z6MkhaXgBZD", None).unwrap_err(),
            CAWG_ICA_DID_UNSUPPORTED_METHOD
        );
        // A DID-shaped id whose method-specific part is not a base64url JWK
        // is a DID-document problem, not an issuer-syntax problem.
        assert_eq!(
            case("did:jwk:AAAA", None).unwrap_err(),
            CAWG_ICA_INVALID_DID_DOCUMENT
        );
        // An id whose first character is outside the DID charset fails the
        // issuer syntax check itself.
        assert_eq!(
            case("did:jwk:!!!", None).unwrap_err(),
            CAWG_ICA_INVALID_ISSUER
        );
        assert_eq!(
            case("did:web:absent.example", Some(&store)).unwrap_err(),
            CAWG_ICA_DID_UNAVAILABLE
        );
        assert_eq!(
            case("did:web:no-method.example", Some(&store)).unwrap_err(),
            CAWG_ICA_INVALID_DID_DOCUMENT
        );
        assert!(case("did:web:pinned.example", Some(&store)).is_ok());
        assert_eq!(
            case("did:web:absent.example", None).unwrap_err(),
            CAWG_ICA_DID_UNAVAILABLE
        );
    }

    #[test]
    fn tampered_c2pa_asset_hash_is_a_signer_payload_mismatch() {
        let key = signing_key();
        let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        vc["credentialSubject"]["c2paAsset"]["referenced_assertions"][0]["hash"] =
            json!(base64_encode(&[0x55; 32], false));
        let results = run(&ica_cose(&key, &vc));
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_SIGNER_PAYLOAD_MISMATCH]
        );
        assert!(results.success.is_empty());
    }

    #[test]
    fn legacy_byte_array_hash_encoding_still_matches() {
        let key = signing_key();
        let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        let bytes: Vec<Json> = base64_encode(&HASH, false)
            .bytes()
            .map(|byte| json!(byte))
            .collect();
        vc["credentialSubject"]["c2paAsset"]["referenced_assertions"][0]["hash"] = json!(bytes);
        let results = run(&ica_cose(&key, &vc));
        assert!(
            results.failure.is_empty(),
            "failures: {:?}",
            results.failure
        );
        assert_eq!(codes(&results.success), vec![CAWG_ICA_CREDENTIAL_VALID]);
        // The byte-array hash shape is a CAWG 1.1-era legacy aspect: surfaced.
        assert!(results
            .informational
            .iter()
            .any(|status| status.code == CAWG_LEGACY_PROFILE
                && status.explanation.contains("byte-array")));
    }

    #[test]
    fn legacy_byte_array_hash_encoding_is_a_mismatch_under_strict_mode() {
        let key = signing_key();
        let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        let bytes: Vec<Json> = base64_encode(&HASH, false)
            .bytes()
            .map(|byte| json!(byte))
            .collect();
        vc["credentialSubject"]["c2paAsset"]["referenced_assertions"][0]["hash"] = json!(bytes);
        vc["@context"] = json!(["https://www.w3.org/ns/credentials/v2", CAWG_ICA_CONTEXT_1_2,]);
        let results = run_mode(&ica_cose(&key, &vc), true);
        // Strict mode refuses the byte-array decode, so the comparison fails
        // with the EXISTING mismatch code — no new failure codes.
        assert!(codes(&results.failure).contains(&CAWG_ICA_SIGNER_PAYLOAD_MISMATCH));
        assert!(!results
            .informational
            .iter()
            .any(|status| status.code == CAWG_LEGACY_PROFILE));
    }

    #[test]
    fn unknown_context_is_invalid_verifiable_credential() {
        let key = signing_key();
        let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        vc["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]);
        let results = run(&ica_cose(&key, &vc));
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL]
        );
        assert!(results.success.is_empty());
    }

    #[test]
    fn vc_type_must_name_the_ica_credential_profile() {
        let key = signing_key();
        for types in [
            json!(["VerifiableCredential"]),
            json!(["IdentityClaimsAggregationCredential"]),
        ] {
            let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
            vc["type"] = types;
            let results = run(&ica_cose(&key, &vc));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL]
            );
            assert!(results.success.is_empty());
        }
    }

    #[test]
    fn legacy_context_is_informational_by_default_and_refused_in_strict_mode() {
        let key = signing_key();
        let vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        let cose = ica_cose(&key, &vc);

        let default_run = run(&cose);
        assert!(default_run.failure.is_empty());
        let valid = default_run
            .success
            .iter()
            .find(|status| status.code == CAWG_ICA_CREDENTIAL_VALID)
            .expect("credential_valid");
        assert_eq!(
            valid
                .details
                .as_ref()
                .and_then(|details| details.get("ica_context"))
                .and_then(Json::as_str),
            Some("1.1")
        );
        assert!(default_run
            .informational
            .iter()
            .any(|status| status.code == CAWG_LEGACY_PROFILE
                && status.explanation.contains("1.1 JSON-LD context")));

        // Strict mode only attempts the CAWG 1.2 shape: the 1.1 context fails
        // the credential shape check with the EXISTING invalid code.
        let strict_run = run_mode(&cose, true);
        assert!(codes(&strict_run.failure).contains(&CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL));
        assert!(strict_run.success.is_empty());
    }

    #[test]
    fn v12_context_passes_strict_mode_without_the_legacy_signal() {
        let key = signing_key();
        let mut vc = vc_json(&did_jwk(&key), Some("2025-01-01T00:00:00Z"), None);
        vc["@context"] = json!(["https://www.w3.org/ns/credentials/v2", CAWG_ICA_CONTEXT_1_2,]);
        let cose = ica_cose(&key, &vc);
        for strict in [false, true] {
            let results = run_mode(&cose, strict);
            assert!(
                results.failure.is_empty(),
                "strict={strict} failures: {:?}",
                results.failure
            );
            assert!(!results
                .informational
                .iter()
                .any(|status| status.code == CAWG_LEGACY_PROFILE));
            let valid = results
                .success
                .iter()
                .find(|status| status.code == CAWG_ICA_CREDENTIAL_VALID)
                .expect("credential_valid");
            assert_eq!(
                valid
                    .details
                    .as_ref()
                    .and_then(|details| details.get("ica_context"))
                    .and_then(Json::as_str),
                Some("1.2")
            );
        }
    }

    #[test]
    fn validity_window_is_enforced_at_the_validation_time() {
        let key = signing_key();
        let did = did_jwk(&key);

        let future = run(&ica_cose(
            &key,
            &vc_json(&did, Some("2200-01-01T00:00:00Z"), None),
        ));
        assert_eq!(codes(&future.failure), vec![CAWG_ICA_VALID_FROM_INVALID]);

        let missing = run(&ica_cose(&key, &vc_json(&did, None, None)));
        assert_eq!(codes(&missing.failure), vec![CAWG_ICA_VALID_FROM_MISSING]);

        let expired = run(&ica_cose(
            &key,
            &vc_json(
                &did,
                Some("2025-01-01T00:00:00Z"),
                Some("2025-02-01T00:00:00Z"),
            ),
        ));
        assert_eq!(codes(&expired.failure), vec![CAWG_ICA_VALID_UNTIL_INVALID]);

        let open = run(&ica_cose(
            &key,
            &vc_json(
                &did,
                Some("2025-01-01T00:00:00Z"),
                Some("2200-01-01T00:00:00Z"),
            ),
        ));
        assert!(open.failure.is_empty());
        assert_eq!(codes(&open.success), vec![CAWG_ICA_CREDENTIAL_VALID]);
    }

    #[test]
    fn wrong_signing_key_is_a_signature_mismatch() {
        let signer = signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let vc = vc_json(&did_jwk(&other), Some("2025-01-01T00:00:00Z"), None);
        let results = run(&ica_cose(&signer, &vc));
        assert_eq!(codes(&results.failure), vec![CAWG_ICA_SIGNATURE_MISMATCH]);
        assert!(results.success.is_empty());
    }

    #[test]
    fn base64_decoders_reject_wrong_alphabets_and_roundtrip() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            base64_decode_std(&base64_encode(&data, false)).as_deref(),
            Some(data.as_slice())
        );
        assert_eq!(
            base64_decode_url(&base64_encode(&data, true)).as_deref(),
            Some(data.as_slice())
        );
        assert!(base64_decode_std("a-b_").is_none());
        assert!(base64_decode_url("a+b/").is_none());
        // Padded base64url is tolerated (did:jwk identifiers vary).
        assert_eq!(base64_decode_url("aGk=").as_deref(), Some(b"hi".as_slice()));
    }
}
