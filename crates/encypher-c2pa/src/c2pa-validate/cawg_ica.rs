// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Offline CAWG Identity 1.3 identity-claims-aggregation validation.

use std::collections::{HashMap, HashSet};

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use crate::c2pa_crypto::{
    extract_claim_tsa_tokens, extract_tsa_tokens, timestamp_input, ClaimTimestampVersion, CoseAlg,
};
use crate::c2pa_trust::TrustList;
use serde_json::{json, Value as Json};
use sha2::Digest as _;
use signature::{hazmat::PrehashVerifier as _, Verifier as _};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::cawg::is_cawg_label;
use super::vc_data_model::{
    self, CredentialDefect, VcVersion, XsdDateTime, XsdInstant, CAWG_ICA_CONTEXT,
    STATUS_CONTEXT_V1, VC_CONTEXT_V1, VC_CONTEXT_V2,
};
use super::ValidationResults;

pub const CAWG_ICA_INVALID_COSE_SIGN1: &str = "cawg.ica.invalid_cose_sign1";
pub const CAWG_ICA_INVALID_ALG: &str = "cawg.ica.invalid_alg";
pub const CAWG_ICA_INVALID_CONTENT_TYPE: &str = "cawg.ica.invalid_content_type";
pub const CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL: &str = "cawg.ica.invalid_verifiable_credential";
pub const CAWG_ICA_INVALID_ISSUER: &str = "cawg.ica.invalid_issuer";
pub const CAWG_ICA_DID_UNSUPPORTED_METHOD: &str = "cawg.ica.did_unsupported_method";
pub const CAWG_ICA_INVALID_DID_DOCUMENT: &str = "cawg.ica.invalid_did_document";
pub const CAWG_ICA_UNTRUSTED_ISSUER: &str = "cawg.ica.untrusted_issuer";
pub const CAWG_ICA_SIGNATURE_MISMATCH: &str = "cawg.ica.signature_mismatch";
pub const CAWG_ICA_SIGNER_PAYLOAD_MISMATCH: &str = "cawg.ica.signer_payload.mismatch";
pub const CAWG_ICA_TIME_STAMP_VALIDATED: &str = "cawg.ica.time_stamp.validated";
pub const CAWG_ICA_TIME_STAMP_INVALID: &str = "cawg.ica.time_stamp.invalid";
pub const CAWG_ICA_VALID_FROM_MISSING: &str = "cawg.ica.valid_from.missing";
pub const CAWG_ICA_VALID_FROM_INVALID: &str = "cawg.ica.valid_from.invalid";
pub const CAWG_ICA_VALID_UNTIL_INVALID: &str = "cawg.ica.valid_until.invalid";
pub const CAWG_ICA_REVOCATION_UNSUPPORTED: &str = "cawg.ica.revocation.unsupported";
pub const CAWG_ICA_REVOCATION_UNAVAILABLE: &str = "cawg.ica.revocation.unavailable";
pub const CAWG_ICA_CREDENTIAL_NOT_REVOKED: &str = "cawg.ica.credential.not_revoked";
pub const CAWG_ICA_CREDENTIAL_REVOKED: &str = "cawg.ica.credential.revoked";
pub const CAWG_ICA_VERIFIED_IDENTITIES_MISSING: &str = "cawg.ica.verified_identities.missing";
pub const CAWG_ICA_VERIFIED_IDENTITIES_INVALID: &str = "cawg.ica.verified_identities.invalid";
pub const CAWG_ICA_CREDENTIAL_VALID: &str = "cawg.ica.credential_valid";

const VC_CONTENT_TYPE: &str = "application/vc";
const MAX_DID_TRUST_DEPTH: usize = 16;

/// Validate one ICA identity assertion. Every resolver and trust input is
/// caller-supplied; this function never performs network I/O.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_ica_assertion(
    signer_payload: &Value,
    signature: &[u8],
    url: &str,
    validation_time: OffsetDateTime,
    manifest_time: Option<OffsetDateTime>,
    tsa_trust: Option<&TrustList>,
    did_documents: Option<&HashMap<String, Json>>,
    trusted_issuers: Option<&[String]>,
    trust_anchors: Option<&[String]>,
    status_lists: Option<&HashMap<String, String>>,
    results: &mut ValidationResults,
) {
    let Some(cose) = CoseSign1::parse(signature) else {
        results.push_failure(
            CAWG_ICA_INVALID_COSE_SIGN1,
            url.into(),
            "ICA signature is not a valid tagged COSE_Sign1 structure".into(),
        );
        return;
    };

    let algorithm = protected_int(&cose.protected, 1).and_then(CoseAlg::from_cose_id);
    let mut ok = true;
    if algorithm.is_none() {
        results.push_failure(
            CAWG_ICA_INVALID_ALG,
            url.into(),
            "COSE protected header is missing one of the seven C2PA signature algorithms".into(),
        );
        ok = false;
    }
    if !matches!(
        map_int(&cose.protected, 3),
        Some(Value::Text(content_type)) if content_type == VC_CONTENT_TYPE
    ) {
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
    let credential = match parse_ica_credential(payload) {
        Ok(credential) => credential,
        Err(CredentialDefect::Malformed(reason)) => {
            results.push_failure(
                CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL,
                url.into(),
                format!("payload is not a valid identity claims aggregation credential: {reason}"),
            );
            return;
        }
        // A context outside the pinned set: its semantics are unknown, so
        // the credential cannot be parsed with them (TECH-A-004 profile).
        Err(CredentialDefect::UnsupportedContext(contexts)) => {
            results.push_failure_with_details(
                CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL,
                url.into(),
                "the credential uses a JSON-LD context outside the verifier's pinned VC, CAWG ICA, and Bitstring Status List contexts"
                    .into(),
                json!({"reason": "unsupported_context", "contexts": contexts}),
            );
            return;
        }
    };

    let resolved = match resolve_issuer_key(&credential.issuer, did_documents) {
        Ok(resolved) => Some(resolved),
        Err(failure) => {
            // The DID document the blocked resolution needs is a fetchable
            // resource, so record what would be contacted alongside the code.
            if failure.code == super::cawg::CAWG_IDENTITY_NETWORK_TRAFFIC_BLOCKED {
                if let Some(url) = super::network_needs::did_web_url(&credential.issuer) {
                    super::network_needs::push_unique(
                        &mut results.network_needs,
                        super::NetworkNeed::DidDocument {
                            did: super::cawg_ica::primary_did(&credential.issuer).to_string(),
                            url,
                        },
                    );
                }
            }
            results.push_failure(failure.code, url.into(), failure.explanation);
            ok = false;
            None
        }
    };

    let trust_source = issuer_trust_source(
        &credential.issuer,
        resolved.as_ref().map(|resolved| &resolved.document),
        did_documents,
        trusted_issuers,
        trust_anchors,
    );
    if trust_source.is_none() {
        results.push_failure(
            CAWG_ICA_UNTRUSTED_ISSUER,
            url.into(),
            "ICA issuer is not present in, or traceable to, the caller's trust configuration"
                .into(),
        );
        ok = false;
    }

    if let (Some(algorithm), Some(resolved)) = (algorithm, resolved.as_ref()) {
        if !resolved
            .key
            .verify(algorithm, &cose.signature_input(payload), &cose.signature)
        {
            results.push_failure(
                CAWG_ICA_SIGNATURE_MISMATCH,
                url.into(),
                "COSE signature does not verify against the issuer DID key".into(),
            );
            ok = false;
        }
    }

    let identity_time = match ica_timestamp(&cose, signature, tsa_trust, validation_time) {
        IcaTimestamp::Absent => None,
        IcaTimestamp::Valid(at) => {
            results.push_success(
                CAWG_ICA_TIME_STAMP_VALIDATED,
                url.into(),
                "RFC 3161 sigTst2 timestamp verified over the ICA COSE signature".into(),
            );
            Some(at)
        }
        IcaTimestamp::Invalid => {
            results.push_failure(
                CAWG_ICA_TIME_STAMP_INVALID,
                url.into(),
                "identity COSE timestamp is malformed, untrusted, or uses the forbidden v1 sigTst header"
                    .into(),
            );
            ok = false;
            None
        }
    };

    let times: Vec<XsdInstant> = [Some(validation_time), manifest_time, identity_time]
        .into_iter()
        .flatten()
        .map(XsdInstant::from_time)
        .collect();
    match &credential.valid_from {
        ValidityField::Missing => {
            results.push_failure(
                CAWG_ICA_VALID_FROM_MISSING,
                url.into(),
                format!(
                    "{} credential lacks its required effective date",
                    credential.vc_version.label()
                ),
            );
            ok = false;
        }
        ValidityField::Malformed(reason) => {
            results.push_failure(
                CAWG_ICA_VALID_FROM_INVALID,
                url.into(),
                format!("credential effective date {reason}"),
            );
            ok = false;
        }
        ValidityField::Parsed(valid_from) => {
            if times.iter().any(|at| valid_from > at) {
                results.push_failure(
                    CAWG_ICA_VALID_FROM_INVALID,
                    url.into(),
                    "credential effective date is later than an applicable validation time".into(),
                );
                ok = false;
            }
        }
    }
    match &credential.valid_until {
        ValidityField::Missing => {}
        ValidityField::Malformed(reason) => {
            results.push_failure(
                CAWG_ICA_VALID_UNTIL_INVALID,
                url.into(),
                format!("credential expiration date {reason}"),
            );
            ok = false;
        }
        ValidityField::Parsed(valid_until) => {
            // V-22: VC 2.0 section 4.9 orders validFrom no later than
            // validUntil. VC 1.1 has no such rule.
            let explanation = if credential.vc_version == VcVersion::V2_0
                && matches!(
                    &credential.valid_from,
                    ValidityField::Parsed(valid_from) if valid_until < valid_from
                ) {
                Some("credential expiration date is earlier than its effective date")
            } else {
                times.iter().any(|at| valid_until < at).then_some(
                    "credential expiration date is earlier than an applicable validation time",
                )
            };
            if let Some(explanation) = explanation {
                results.push_failure(CAWG_ICA_VALID_UNTIL_INVALID, url.into(), explanation.into());
                ok = false;
            }
        }
    }

    match check_revocation(
        credential.credential_status.as_ref(),
        credential.bitstring_status_supported,
        status_lists,
    ) {
        Revocation::NotPresent => {}
        Revocation::Unsupported => {
            results.push_failure(
                CAWG_ICA_REVOCATION_UNSUPPORTED,
                url.into(),
                "credentialStatus does not contain a supported revocation entry".into(),
            );
            ok = false;
        }
        Revocation::Unavailable => {
            results.push_failure(
                CAWG_ICA_REVOCATION_UNAVAILABLE,
                url.into(),
                "the supported status list is absent from the caller's offline store".into(),
            );
            ok = false;
        }
        Revocation::NotRevoked => results.push_success(
            CAWG_ICA_CREDENTIAL_NOT_REVOKED,
            url.into(),
            "offline status-list evidence reports the credential not revoked".into(),
        ),
        Revocation::Revoked => {
            results.push_failure(
                CAWG_ICA_CREDENTIAL_REVOKED,
                url.into(),
                "offline status-list evidence reports the credential revoked".into(),
            );
            return;
        }
    }

    // 1.3 orders "Verify binding to C2PA asset" before "Verify verified
    // identities", and the validator SHALL follow its steps in that order.
    if super::report::cbor_to_json(signer_payload) != credential.c2pa_asset {
        results.push_failure(
            CAWG_ICA_SIGNER_PAYLOAD_MISMATCH,
            url.into(),
            "credentialSubject.c2paAsset is not the exact JSON serialization of signer_payload"
                .into(),
        );
        ok = false;
    }

    match &credential.verified_identities {
        VerifiedIdentities::Missing => {
            results.push_failure(
                CAWG_ICA_VERIFIED_IDENTITIES_MISSING,
                url.into(),
                "verifiedIdentities is missing, empty, or not an array".into(),
            );
            ok = false;
        }
        // The status mechanism cannot say which entry failed, so 1.3
        // recommends an out-of-band signal: each rejected entry's index and
        // the property that broke a condition.
        VerifiedIdentities::Invalid(defects) => {
            results.push_failure_with_details(
                CAWG_ICA_VERIFIED_IDENTITIES_INVALID,
                url.into(),
                "one or more verifiedIdentities entries violate the CAWG ICA data model".into(),
                json!({
                    "invalid_entries": defects
                        .iter()
                        .map(|(index, field)| json!({"index": index, "field": field}))
                        .collect::<Vec<_>>(),
                }),
            );
            ok = false;
        }
        VerifiedIdentities::Valid(_) => {}
    }

    if ok {
        let verified_identities = match &credential.verified_identities {
            VerifiedIdentities::Valid(values) => values.clone(),
            _ => Vec::new(),
        };
        let issuer_document = resolved.map(|resolved| resolved.document);
        results.push_success_with_details(
            CAWG_ICA_CREDENTIAL_VALID,
            url.into(),
            "identity claims aggregation credential validated".into(),
            json!({
                "credential": credential.raw,
                "issuer": credential.issuer,
                "issuer_metadata": {
                    "did": credential.issuer,
                    "did_method": parse_did(&credential.issuer).map(|(method, _)| method),
                    "did_document": issuer_document,
                    "trust_source": trust_source,
                },
                "verified_identities": verified_identities,
                "trust_source": trust_source,
                "timestamp_trusted": identity_time.is_some(),
                "trusted_at": identity_time.and_then(|at| at.format(&Rfc3339).ok()),
            }),
        );
    }
}

struct CoseSign1 {
    protected_bytes: Vec<u8>,
    protected: Vec<(Value, Value)>,
    unprotected: Vec<(Value, Value)>,
    payload: Option<Vec<u8>>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let Value::Tag(18, inner) = decode(bytes).ok()? else {
            return None;
        };
        let Value::Array(items) = *inner else {
            return None;
        };
        let [Value::Bytes(protected_bytes), Value::Map(unprotected), payload, Value::Bytes(signature)] =
            items.as_slice()
        else {
            return None;
        };
        let protected = if protected_bytes.is_empty() {
            Vec::new()
        } else {
            match decode(protected_bytes).ok()? {
                Value::Map(entries) => entries,
                _ => return None,
            }
        };
        let payload = match payload {
            Value::Bytes(bytes) => Some(bytes.clone()),
            Value::Null => None,
            _ => return None,
        };
        Some(Self {
            protected_bytes: protected_bytes.clone(),
            protected,
            unprotected: unprotected.clone(),
            payload,
            signature: signature.clone(),
        })
    }

    fn signature_input(&self, payload: &[u8]) -> Vec<u8> {
        encode(
            &Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(self.protected_bytes.clone()),
                Value::Bytes(Vec::new()),
                Value::Bytes(payload.to_vec()),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap_or_default()
    }

    fn has_unprotected(&self, name: &str) -> bool {
        self.unprotected
            .iter()
            .any(|(key, _)| key.as_text() == Some(name))
    }
}

fn map_int(entries: &[(Value, Value)], key: i128) -> Option<&Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| match candidate {
            Value::Integer(candidate) if *candidate == key => Some(value),
            _ => None,
        })
}

fn protected_int(entries: &[(Value, Value)], key: i128) -> Option<i128> {
    match map_int(entries, key) {
        Some(Value::Integer(value)) => Some(*value),
        _ => None,
    }
}

enum ValidityField {
    Missing,
    /// Completes "credential ... date ...".
    Malformed(&'static str),
    Parsed(XsdInstant),
}

enum VerifiedIdentities {
    Missing,
    /// Each rejected entry's index and the property that broke a condition.
    Invalid(Vec<(usize, &'static str)>),
    Valid(Vec<Json>),
}

struct IcaCredential {
    raw: Json,
    vc_version: VcVersion,
    issuer: String,
    valid_from: ValidityField,
    valid_until: ValidityField,
    credential_status: Option<Json>,
    bitstring_status_supported: bool,
    c2pa_asset: Json,
    verified_identities: VerifiedIdentities,
}

/// Parse and check the ICA credential against the CAWG Identity 1.3 prose.
///
/// `credentialSchema` is deliberately not evaluated. 1.3 only RECOMMENDS it,
/// and the published v1.3 schemas cannot serve as a gate: they reference
/// `#/definitions/...` while declaring `$defs`, they require `uri` for
/// `cawg.social_media` where the prose only recommends it, and production
/// credentials cite a schema URL that is neither listed one. These checks
/// implement the prose rules instead.
fn parse_ica_credential(payload: &[u8]) -> Result<IcaCredential, CredentialDefect> {
    let raw: Json = serde_json::from_slice(payload).map_err(|_| "payload is not JSON")?;
    let object = raw.as_object().ok_or("credential is not a JSON object")?;
    let contexts = object
        .get("@context")
        .and_then(Json::as_array)
        .ok_or("@context is missing or not an array")?;
    // VC 2.0 section 4.3 and VC 1.1 section 4.1: the first item is the data
    // model's own context URL, which also selects the model version.
    let version = match contexts.first().and_then(Json::as_str) {
        Some(VC_CONTEXT_V2) => VcVersion::V2_0,
        Some(VC_CONTEXT_V1) => VcVersion::V1_1,
        _ => return Err("first @context item is not a W3C Verifiable Credentials context".into()),
    };
    if !contexts
        .iter()
        .any(|entry| entry.as_str() == Some(CAWG_ICA_CONTEXT))
    {
        return Err("credential lacks the required CAWG Identity 1.1 ICA context".into());
    }
    vc_data_model::check_context_list(contexts, version)?;
    vc_data_model::check_body(object, contexts, version)?;

    let types = object
        .get("type")
        .and_then(Json::as_array)
        .ok_or("type is missing or not an array")?;
    if !types.iter().all(|entry| {
        entry
            .as_str()
            .is_some_and(|name| vc_data_model::is_type_name(name, version))
    }) {
        return Err("type entries must be terms or absolute URLs".into());
    }
    if ![
        "VerifiableCredential",
        "IdentityClaimsAggregationCredential",
    ]
    .into_iter()
    .all(|expected| types.iter().any(|entry| entry.as_str() == Some(expected)))
    {
        return Err("type lacks a required ICA credential type".into());
    }
    vc_data_model::check_properties(object, version)?;

    // VC 2.0 section 4.7 and VC 1.1 section 4.5: the issuer is a URL (2.0)
    // or URI (1.1). One that is not cannot be a DID, which CAWG reports as
    // an invalid issuer.
    let issuer = match object.get("issuer") {
        Some(Json::String(issuer)) => issuer.as_str(),
        Some(Json::Object(issuer)) => issuer.get("id").and_then(Json::as_str).unwrap_or_default(),
        _ => "",
    };
    let issuer = if vc_data_model::is_identifier(issuer, version) {
        issuer
    } else {
        ""
    }
    .to_string();

    let subject = match object.get("credentialSubject") {
        Some(Json::Object(subject)) => subject,
        Some(Json::Array(subjects)) if subjects.len() == 1 => subjects[0]
            .as_object()
            .ok_or("credentialSubject entry is not an object")?,
        _ => return Err("credentialSubject is missing or ambiguous".into()),
    };
    let c2pa_asset = subject.get("c2paAsset").cloned().unwrap_or(Json::Null);
    let verified_identities = match subject.get("verifiedIdentities") {
        Some(Json::Array(values)) if !values.is_empty() => {
            let defects: Vec<(usize, &'static str)> = values
                .iter()
                .enumerate()
                .filter_map(|(index, value)| {
                    verified_identity_defect(value).map(|field| (index, field))
                })
                .collect();
            if defects.is_empty() {
                VerifiedIdentities::Valid(values.clone())
            } else {
                VerifiedIdentities::Invalid(defects)
            }
        }
        _ => VerifiedIdentities::Missing,
    };

    // VC 2.0 section 4.9: validity dates are XML Schema `dateTimeStamp`s.
    // VC 1.1 sections 4.6 and 4.8: they are `dateTime`s, whose zone is
    // optional. XSD orders a zoneless value against every offset within
    // 14:00 of it, so against a validation time it is read at the bound
    // that can only reject more: the effective date at its latest instant,
    // the expiration at its earliest.
    const FOURTEEN_HOURS: i128 = 14 * 3600;
    const ZONELESS_V2: &str = "lacks a time zone: VC 2.0 section 5.8 reads it as UTC, but section 4.9 requires a dateTimeStamp";
    let parse_validity = |name: &str, zoneless_shift: i128| match object.get(name) {
        None => ValidityField::Missing,
        Some(Json::String(value)) => match vc_data_model::parse_xsd_date_time(value) {
            Ok(XsdDateTime::Zoned(at)) => ValidityField::Parsed(at),
            Ok(XsdDateTime::Local(local)) if version == VcVersion::V1_1 => {
                ValidityField::Parsed(local.shifted(zoneless_shift))
            }
            // VC 2.0 section 5.8 reads a zoneless value as UTC, but 4.9
            // requires a dateTimeStamp, so the value is still an error.
            Ok(XsdDateTime::Local(_)) => ValidityField::Malformed(ZONELESS_V2),
            Err(reason) => ValidityField::Malformed(reason),
        },
        Some(Json::Null) => ValidityField::Malformed("is null"),
        Some(_) => ValidityField::Malformed("is not a string"),
    };
    let (from_field, until_field) = match version {
        VcVersion::V1_1 => ("issuanceDate", "expirationDate"),
        VcVersion::V2_0 => ("validFrom", "validUntil"),
    };
    let valid_from = parse_validity(from_field, FOURTEEN_HOURS);
    let valid_until = parse_validity(until_field, -FOURTEEN_HOURS);
    let credential_status = object.get("credentialStatus").cloned();
    let bitstring_status_supported = version == VcVersion::V2_0
        || contexts
            .iter()
            .any(|context| context.as_str() == Some(STATUS_CONTEXT_V1));
    Ok(IcaCredential {
        raw,
        vc_version: version,
        issuer,
        valid_from,
        valid_until,
        bitstring_status_supported,
        credential_status,
        c2pa_asset,
        verified_identities,
    })
}

/// Name the property of a `verifiedIdentities` entry that breaks a condition
/// of CAWG Identity 1.3 "Verified identities" (`entry` when the entry is not
/// an object), or `None` when the entry meets every condition.
fn verified_identity_defect(value: &Json) -> Option<&'static str> {
    let Some(identity) = value.as_object() else {
        return Some("entry");
    };
    let Some(identity_type) = identity
        .get("type")
        .and_then(Json::as_str)
        .filter(|v| is_cawg_label(v))
    else {
        return Some("type");
    };
    if identity
        .get("verifiedAt")
        .and_then(Json::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .is_none()
    {
        return Some("verifiedAt");
    }
    let Some(provider) = identity.get("provider").and_then(Json::as_object) else {
        return Some("provider");
    };
    if !natural_language_string(provider.get("name")) {
        return Some("provider.name");
    }
    if provider
        .get("id")
        .is_some_and(|id| id.as_str().is_none_or(|id| !is_uri(id)))
    {
        return Some("provider.id");
    }
    for field in ["name", "username", "address"] {
        if identity
            .get(field)
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        {
            return Some(field);
        }
    }
    if identity
        .get("method")
        .is_some_and(|value| value.as_str().is_none_or(|method| !is_cawg_label(method)))
    {
        return Some("method");
    }
    if identity
        .get("uri")
        .is_some_and(|value| value.as_str().is_none_or(|uri| !is_uri(uri)))
    {
        return Some("uri");
    }
    let required = match identity_type {
        "cawg.document_verification" => "name",
        "cawg.web_site" => "uri",
        "cawg.social_media" => "username",
        "cawg.crypto_wallet" => "address",
        _ => return None,
    };
    let Some(value) = identity.get(required).and_then(Json::as_str) else {
        return Some(required);
    };
    // A wallet address "MUST be the unique alphanumeric string" for the
    // service. The social-media username carries the same words, but
    // production aggregators put display names such as "Eric Scouten" there,
    // so it keeps only the non-empty-string rule as an interop decision.
    (identity_type == "cawg.crypto_wallet" && !value.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some("address")
}

fn natural_language_string(value: Option<&Json>) -> bool {
    match value {
        Some(Json::String(value)) => !value.is_empty(),
        Some(Json::Object(values)) => {
            !values.is_empty()
                && values
                    .values()
                    .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        }
        _ => false,
    }
}

/// RFC 3986 section 3 `URI`: `scheme ":" hier-part [ "?" query ] [ "#"
/// fragment ]`, ASCII only.
pub(super) fn is_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut scheme = scheme.bytes();
    if !scheme
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        || !scheme.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (hier_part, query) = rest.split_once('?').unwrap_or((rest, ""));
    let pchar = |byte: u8| matches!(byte, b':' | b'@');
    let query_char = |byte: u8| matches!(byte, b':' | b'@' | b'/' | b'?');
    if !uri_component(query, query_char) || !uri_component(fragment, query_char) {
        return false;
    }
    let path_char = |byte: u8| pchar(byte) || byte == b'/';
    match hier_part.strip_prefix("//") {
        Some(after) => {
            let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
            is_uri_authority(authority) && uri_component(path, path_char)
        }
        None => uri_component(hier_part, path_char),
    }
}

/// RFC 3986 `authority`: `[ userinfo "@" ] host [ ":" port ]`.
fn is_uri_authority(authority: &str) -> bool {
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    if userinfo.is_some_and(|userinfo| !uri_component(userinfo, |byte| byte == b':')) {
        return false;
    }
    let (host_ok, port) = match host_port.strip_prefix('[') {
        Some(literal) => {
            let Some((address, port)) = literal.split_once(']') else {
                return false;
            };
            (is_ip_literal(address), port)
        }
        None => {
            let (host, port) = host_port.split_at(host_port.find(':').unwrap_or(host_port.len()));
            (uri_component(host, |_| false), port)
        }
    };
    host_ok
        && (port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit())))
}

/// RFC 3986 `IP-literal` contents: an IPv6 address or `IPvFuture`.
fn is_ip_literal(address: &str) -> bool {
    match address.strip_prefix(['v', 'V']) {
        Some(future) => future.split_once('.').is_some_and(|(version, rest)| {
            !version.is_empty()
                && version.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !rest.is_empty()
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:".contains(&byte))
        }),
        None => address.parse::<std::net::Ipv6Addr>().is_ok(),
    }
}

/// Every byte of `text` is unreserved, a sub-delimiter, a valid
/// percent-encoding, or accepted by `extra`.
fn uri_component(text: &str, extra: impl Fn(u8) -> bool) -> bool {
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        let valid = if byte == b'%' {
            bytes.next().is_some_and(|hex| hex.is_ascii_hexdigit())
                && bytes.next().is_some_and(|hex| hex.is_ascii_hexdigit())
        } else {
            byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte) || extra(byte)
        };
        if !valid {
            return false;
        }
    }
    true
}

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

struct ResolvedIssuer {
    key: IcaKey,
    document: Json,
}

enum IcaKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl IcaKey {
    fn verify(&self, algorithm: CoseAlg, data: &[u8], signature: &[u8]) -> bool {
        match (self, algorithm) {
            (Self::Ed25519(key), CoseAlg::EdDsa) => ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
            (Self::P256(key), CoseAlg::Es256) => verify_p256(key, algorithm, data, signature),
            (Self::P384(key), CoseAlg::Es384) => verify_p384(key, algorithm, data, signature),
            (Self::P521(key), CoseAlg::Es512) => verify_p521(key, algorithm, data, signature),
            (Self::Rsa(key), CoseAlg::Ps256) => {
                rsa::pss::VerifyingKey::<sha2::Sha256>::new(key.clone())
                    .verify(
                        data,
                        &match rsa::pss::Signature::try_from(signature) {
                            Ok(signature) => signature,
                            Err(_) => return false,
                        },
                    )
                    .is_ok()
            }
            (Self::Rsa(key), CoseAlg::Ps384) => {
                rsa::pss::VerifyingKey::<sha2::Sha384>::new(key.clone())
                    .verify(
                        data,
                        &match rsa::pss::Signature::try_from(signature) {
                            Ok(signature) => signature,
                            Err(_) => return false,
                        },
                    )
                    .is_ok()
            }
            (Self::Rsa(key), CoseAlg::Ps512) => {
                rsa::pss::VerifyingKey::<sha2::Sha512>::new(key.clone())
                    .verify(
                        data,
                        &match rsa::pss::Signature::try_from(signature) {
                            Ok(signature) => signature,
                            Err(_) => return false,
                        },
                    )
                    .is_ok()
            }
            _ => false,
        }
    }
}

macro_rules! verify_ecdsa {
    ($key:expr, $algorithm:expr, $data:expr, $signature:expr, $signature_type:path) => {{
        let digest = match $algorithm {
            CoseAlg::Es256 => sha2::Sha256::digest($data).to_vec(),
            CoseAlg::Es384 => sha2::Sha384::digest($data).to_vec(),
            CoseAlg::Es512 => sha2::Sha512::digest($data).to_vec(),
            _ => return false,
        };
        <$signature_type>::from_slice($signature)
            .or_else(|_| <$signature_type>::from_der($signature))
            .is_ok_and(|signature| $key.verify_prehash(&digest, &signature).is_ok())
    }};
}

fn verify_p256(
    key: &p256::ecdsa::VerifyingKey,
    algorithm: CoseAlg,
    data: &[u8],
    signature: &[u8],
) -> bool {
    verify_ecdsa!(key, algorithm, data, signature, p256::ecdsa::Signature)
}

fn verify_p384(
    key: &p384::ecdsa::VerifyingKey,
    algorithm: CoseAlg,
    data: &[u8],
    signature: &[u8],
) -> bool {
    verify_ecdsa!(key, algorithm, data, signature, p384::ecdsa::Signature)
}

fn verify_p521(
    key: &p521::ecdsa::VerifyingKey,
    algorithm: CoseAlg,
    data: &[u8],
    signature: &[u8],
) -> bool {
    verify_ecdsa!(key, algorithm, data, signature, p521::ecdsa::Signature)
}

fn resolve_issuer_key(
    issuer: &str,
    did_documents: Option<&HashMap<String, Json>>,
) -> Result<ResolvedIssuer, IssuerFailure> {
    let Some((method, method_specific_id)) = parse_did(issuer) else {
        return Err(IssuerFailure::new(
            CAWG_ICA_INVALID_ISSUER,
            format!("issuer is not a DID: {issuer}"),
        ));
    };
    let primary = primary_did(issuer);
    let document = match method {
        "jwk" => {
            let encoded = method_specific_id.split('#').next().unwrap_or_default();
            let bytes = base64_decode(encoded, true).ok_or_else(|| {
                IssuerFailure::new(
                    CAWG_ICA_INVALID_DID_DOCUMENT,
                    "did:jwk identifier is not base64url",
                )
            })?;
            let jwk: Json = serde_json::from_slice(&bytes).map_err(|_| {
                IssuerFailure::new(
                    CAWG_ICA_INVALID_DID_DOCUMENT,
                    "did:jwk identifier is not a JSON JWK",
                )
            })?;
            json!({
                "id": primary,
                "verificationMethod": [{
                    "id": format!("{primary}#0"),
                    "type": "JsonWebKey2020",
                    "controller": primary,
                    "publicKeyJwk": jwk,
                }],
                "assertionMethod": [format!("{primary}#0")],
            })
        }
        // CAWG 1.3 keeps `cawg.ica.did_unavailable` for a resolution that was
        // attempted and failed, and registers
        // `cawg.identity.network_traffic_blocked` for validation that cannot
        // complete because the validator is configured to prohibit the
        // required traffic. With no pinned store the SDK attempts no
        // resolution at all: the document could only come from the network it
        // never contacts. With a store, the store is the resolver, and a DID
        // it does not carry is a failed resolution.
        "web" => match did_documents {
            None => {
                return Err(IssuerFailure::new(
                    super::cawg::CAWG_IDENTITY_NETWORK_TRAFFIC_BLOCKED,
                    "did:web issuer resolution needs network access this verifier does not perform, and no offline DID-document store is configured",
                ))
            }
            Some(documents) => documents.get(primary).cloned().ok_or_else(|| {
                IssuerFailure::new(
                    super::cawg::CAWG_ICA_DID_UNAVAILABLE,
                    "did:web issuer is absent from the pinned offline DID-document store",
                )
            })?,
        },
        other => {
            return Err(IssuerFailure::new(
                CAWG_ICA_DID_UNSUPPORTED_METHOD,
                format!("unsupported DID method: {other}"),
            ))
        }
    };
    let key = key_from_did_document(primary, &document)?;
    Ok(ResolvedIssuer { key, document })
}

fn key_from_did_document(primary: &str, document: &Json) -> Result<IcaKey, IssuerFailure> {
    let invalid = |reason: &str| IssuerFailure::new(CAWG_ICA_INVALID_DID_DOCUMENT, reason);
    if document.get("id").and_then(Json::as_str) != Some(primary) {
        return Err(invalid("DID document id does not match the issuer DID"));
    }
    let assertion_methods = document
        .get("assertionMethod")
        .and_then(Json::as_array)
        .ok_or_else(|| invalid("DID document has no assertionMethod array"))?;
    let verification_methods = document
        .get("verificationMethod")
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for assertion_method in assertion_methods {
        let method = match assertion_method {
            Json::String(id) => verification_methods
                .iter()
                .find(|method| method.get("id").and_then(Json::as_str) == Some(id.as_str())),
            Json::Object(_) => Some(assertion_method),
            _ => None,
        };
        let Some(method) = method.and_then(Json::as_object) else {
            continue;
        };
        let Some(id) = method.get("id").and_then(Json::as_str) else {
            continue;
        };
        if !id.starts_with(&format!("{primary}#"))
            || method.get("controller").and_then(Json::as_str) != Some(primary)
            || method.get("type").and_then(Json::as_str) != Some("JsonWebKey2020")
        {
            continue;
        }
        if let Some(jwk) = method.get("publicKeyJwk") {
            return jwk_to_key(jwk);
        }
    }
    Err(invalid(
        "assertionMethod does not resolve to a matching JsonWebKey2020 verificationMethod",
    ))
}

fn jwk_to_key(jwk: &Json) -> Result<IcaKey, IssuerFailure> {
    let invalid = |reason: &str| IssuerFailure::new(CAWG_ICA_INVALID_DID_DOCUMENT, reason);
    let object = jwk
        .as_object()
        .ok_or_else(|| invalid("JWK is not an object"))?;
    match object.get("kty").and_then(Json::as_str) {
        Some("OKP") if object.get("crv").and_then(Json::as_str) == Some("Ed25519") => {
            let bytes = jwk_component(object, "x")?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| invalid("Ed25519 x is not 32 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map(IcaKey::Ed25519)
                .map_err(|_| invalid("Ed25519 x is not a valid point"))
        }
        Some("EC") => {
            let x = jwk_component(object, "x")?;
            let y = jwk_component(object, "y")?;
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(4);
            point.extend(x);
            point.extend(y);
            match object.get("crv").and_then(Json::as_str) {
                Some("P-256") => p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(IcaKey::P256)
                    .map_err(|_| invalid("P-256 JWK point is invalid")),
                Some("P-384") => p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(IcaKey::P384)
                    .map_err(|_| invalid("P-384 JWK point is invalid")),
                Some("P-521") => p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map(IcaKey::P521)
                    .map_err(|_| invalid("P-521 JWK point is invalid")),
                _ => Err(invalid("EC JWK curve is unsupported")),
            }
        }
        Some("RSA") => {
            let n = rsa::BigUint::from_bytes_be(&jwk_component(object, "n")?);
            let e = rsa::BigUint::from_bytes_be(&jwk_component(object, "e")?);
            rsa::RsaPublicKey::new(n, e)
                .map(IcaKey::Rsa)
                .map_err(|_| invalid("RSA JWK modulus or exponent is invalid"))
        }
        _ => Err(invalid("JWK key type is unsupported")),
    }
}

fn jwk_component(
    object: &serde_json::Map<String, Json>,
    name: &str,
) -> Result<Vec<u8>, IssuerFailure> {
    object
        .get(name)
        .and_then(Json::as_str)
        .and_then(|value| base64_decode(value, true))
        .ok_or_else(|| {
            IssuerFailure::new(
                CAWG_ICA_INVALID_DID_DOCUMENT,
                format!("JWK {name} is missing or not base64url"),
            )
        })
}

/// Split a DID or DID URL into its method and the text after `did:method:`.
///
/// The DID itself, up to the first `/`, `?`, or `#`, must follow DID Core
/// 1.0 section 3.1: `method-specific-id = *( *idchar ":" ) 1*idchar`, with
/// `idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded`.
fn parse_did(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("did:")?;
    let (method, id) = rest.split_once(':')?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !is_method_specific_id(id.split(['/', '?', '#']).next().unwrap_or_default())
    {
        return None;
    }
    Some((method, id))
}

fn is_method_specific_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.last().is_none_or(|&last| last == b':') {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = bytes.get(index + 1..index + 3);
                if !hex.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)) {
                    return false;
                }
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':') => {
                index += 1;
            }
            _ => return false,
        }
    }
    true
}

fn primary_did(did: &str) -> &str {
    did.split(['#', '?']).next().unwrap_or(did)
}

fn issuer_trust_source(
    issuer: &str,
    issuer_document: Option<&Json>,
    did_documents: Option<&HashMap<String, Json>>,
    trusted_issuers: Option<&[String]>,
    trust_anchors: Option<&[String]>,
) -> Option<&'static str> {
    let issuer = primary_did(issuer);
    if trusted_issuers
        .is_some_and(|issuers| issuers.iter().any(|trusted| primary_did(trusted) == issuer))
    {
        return Some("direct_issuer");
    }
    let anchors = trust_anchors?;
    if anchors.iter().any(|anchor| primary_did(anchor) == issuer) {
        return Some("trust_anchor");
    }

    let mut pending: Vec<String> = controllers(issuer_document?).map(str::to_owned).collect();
    let mut visited = HashSet::new();
    for _ in 0..MAX_DID_TRUST_DEPTH {
        let Some(controller) = pending.pop() else {
            break;
        };
        let controller = primary_did(&controller).to_string();
        if !visited.insert(controller.clone()) {
            continue;
        }
        if anchors
            .iter()
            .any(|anchor| primary_did(anchor) == controller)
        {
            return Some("controller_anchor");
        }
        if let Some(document) = did_documents.and_then(|documents| documents.get(&controller)) {
            pending.extend(controllers(document).map(str::to_owned));
        }
    }
    None
}

fn controllers(document: &Json) -> impl Iterator<Item = &str> {
    let values: Vec<&str> = match document.get("controller") {
        Some(Json::String(controller)) => vec![controller],
        Some(Json::Array(controllers)) => controllers.iter().filter_map(Json::as_str).collect(),
        _ => Vec::new(),
    };
    values.into_iter()
}

enum IcaTimestamp {
    Absent,
    Valid(OffsetDateTime),
    Invalid,
}

/// Resolve the ICA credential's time stamp.
///
/// 1.3 ICA validating inspects the `sigTst2` unprotected header alone, and
/// says of the legacy header: "C2PA 'version 1' time stamps are not supported
/// when used in identity assertions. A validator SHOULD ignore any value
/// found in a `sigTst` unprotected header." Ignoring it means the credential
/// carries no time stamp, so `cawg.ica.time_stamp.invalid` is reserved for a
/// `sigTst2` this validator could not verify.
fn ica_timestamp(
    cose: &CoseSign1,
    signature: &[u8],
    tsa_trust: Option<&TrustList>,
    verification_time: OffsetDateTime,
) -> IcaTimestamp {
    if !cose.has_unprotected("sigTst2") {
        return IcaTimestamp::Absent;
    }
    let tokens = extract_tsa_tokens(signature);
    let [Some(token)] = tokens.as_slice() else {
        return IcaTimestamp::Invalid;
    };
    let (Ok(payload), Some(trust)) = (timestamp_input(signature), tsa_trust) else {
        return IcaTimestamp::Invalid;
    };

    let result =
        crate::c2pa_trust::verify_timestamp_token(token, &payload, trust, verification_time);
    match (result.verified, result.time) {
        (true, Some(at)) => IcaTimestamp::Valid(at),
        _ => IcaTimestamp::Invalid,
    }
}

enum Revocation {
    NotPresent,
    Unsupported,
    Unavailable,
    NotRevoked,
    Revoked,
}

fn check_revocation(
    credential_status: Option<&Json>,
    bitstring_status_supported: bool,
    status_lists: Option<&HashMap<String, String>>,
) -> Revocation {
    let Some(credential_status) = credential_status else {
        return Revocation::NotPresent;
    };
    let entries: Vec<&Json> = match credential_status {
        Json::Array(entries) => entries.iter().collect(),
        Json::Object(_) => vec![credential_status],
        _ => return Revocation::Unsupported,
    };
    let mut found_supported = false;
    let mut unavailable = false;
    let mut unsupported = false;
    for entry in entries {
        if entry.get("statusPurpose").and_then(Json::as_str) != Some("revocation")
            || !json_type_contains(entry.get("type"), "BitstringStatusListEntry")
            || !bitstring_status_supported
        {
            continue;
        }
        found_supported = true;
        match check_bitstring_status_entry(entry, status_lists) {
            Revocation::Revoked => return Revocation::Revoked,
            Revocation::NotRevoked => {}
            Revocation::Unavailable => unavailable = true,
            Revocation::Unsupported => unsupported = true,
            Revocation::NotPresent => {
                unreachable!("a concrete status entry cannot be absent")
            }
        }
    }
    if !found_supported {
        Revocation::Unsupported
    } else if unavailable {
        Revocation::Unavailable
    } else if unsupported {
        Revocation::Unsupported
    } else {
        Revocation::NotRevoked
    }
}

fn check_bitstring_status_entry(
    entry: &Json,
    status_lists: Option<&HashMap<String, String>>,
) -> Revocation {
    let status_size = match entry.get("statusSize") {
        None => 1,
        Some(value) => match value.as_u64() {
            Some(0) | None => return Revocation::Unavailable,
            Some(size) => size,
        },
    };
    if status_size != 1 {
        return Revocation::Unsupported;
    }
    let Some(list_url) = entry.get("statusListCredential").and_then(Json::as_str) else {
        return Revocation::Unavailable;
    };
    let Some(index) = entry.get("statusListIndex").and_then(|value| {
        value
            .as_str()
            .and_then(|value| value.parse::<usize>().ok())
            .or_else(|| value.as_u64().and_then(|value| usize::try_from(value).ok()))
    }) else {
        return Revocation::Unavailable;
    };
    let Some(encoded) = status_lists.and_then(|lists| lists.get(list_url)) else {
        return Revocation::Unavailable;
    };
    let Some(bits) = base64_decode(encoded, false) else {
        return Revocation::Unavailable;
    };
    let Some(byte) = bits.get(index / 8) else {
        return Revocation::Unavailable;
    };
    if byte & (0x80_u8 >> (index % 8)) == 0 {
        Revocation::NotRevoked
    } else {
        Revocation::Revoked
    }
}

pub(super) fn json_type_contains(value: Option<&Json>, expected: &str) -> bool {
    match value {
        Some(Json::String(value)) => value == expected,
        Some(Json::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

pub(super) fn base64_decode(input: &str, url_alphabet: bool) -> Option<Vec<u8>> {
    let trimmed = input
        .strip_suffix("==")
        .or_else(|| input.strip_suffix('='))
        .unwrap_or(input);
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
    use crate::c2pa_trust::timestamp_fixture::TestTsa;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
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
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let mut word = [0_u8; 3];
            word[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from(word[0]) << 16 | u32::from(word[1]) << 8 | u32::from(word[2]);
            for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
                output.push(alphabet[((bits >> shift) & 63) as usize] as char);
            }
        }
        output
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

    fn vc_json(issuer: Json, vc_v1: bool) -> Json {
        let effective_field = if vc_v1 { "issuanceDate" } else { "validFrom" };
        let mut credential = json!({
            "@context": [
                if vc_v1 { VC_CONTEXT_V1 } else { VC_CONTEXT_V2 },
                CAWG_ICA_CONTEXT,
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
                "c2paAsset": super::super::report::cbor_to_json(&signer_payload()),
            },
        });
        credential[effective_field] = json!("2025-01-01T00:00:00Z");
        credential
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

    fn cose(algorithm: CoseAlg, payload: &[u8], sign: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
        cose_with_protected(
            Value::Map(vec![
                (Value::Integer(1), Value::Integer(algorithm.cose_id())),
                (Value::Integer(3), Value::Text(VC_CONTENT_TYPE.into())),
            ]),
            payload,
            sign,
        )
    }

    fn cose_with_protected(
        protected: Value,
        payload: &[u8],
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        let protected_bytes = encode(&protected, Profile::LegacyPipelineBDefinite).unwrap();
        let input = encode(
            &Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(protected_bytes.clone()),
                Value::Bytes(Vec::new()),
                Value::Bytes(payload.to_vec()),
            ]),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap();
        encode(
            &Value::Tag(
                18,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected_bytes),
                    Value::Map(Vec::new()),
                    Value::Bytes(payload.to_vec()),
                    Value::Bytes(sign(&input)),
                ])),
            ),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap()
    }

    fn eddsa_cose(key: &SigningKey, credential: &Json) -> Vec<u8> {
        let payload = serde_json::to_vec(credential).unwrap();
        cose(CoseAlg::EdDsa, &payload, |input| {
            key.sign(input).to_bytes().to_vec()
        })
    }

    fn run(
        cose: &[u8],
        trusted: &[String],
        status_lists: Option<&HashMap<String, String>>,
    ) -> ValidationResults {
        run_full(
            &signer_payload(),
            cose,
            trusted,
            datetime!(2025-06-01 0:00 UTC),
            Some(datetime!(2025-05-01 0:00 UTC)),
            None,
            status_lists,
        )
    }

    fn codes(items: &[super::super::StatusCode]) -> Vec<&str> {
        items.iter().map(|status| status.code.as_str()).collect()
    }

    #[test]
    fn self_issued_did_jwk_is_untrusted_without_configuration() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = vc_json(json!(did_jwk(&key)), false);
        let results = run(&eddsa_cose(&key, &credential), &[], None);
        assert!(codes(&results.failure).contains(&CAWG_ICA_UNTRUSTED_ISSUER));
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    #[test]
    fn direct_issuer_configuration_enables_credential_valid_with_full_details() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let credential = vc_json(json!(&did), false);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert!(results.failure.is_empty(), "{:?}", results.failure);
        let status = results
            .success
            .iter()
            .find(|status| status.code == CAWG_ICA_CREDENTIAL_VALID)
            .unwrap();
        let details = status.details.as_ref().unwrap();
        assert_eq!(details["credential"], credential);
        assert_eq!(details["issuer_metadata"]["trust_source"], "direct_issuer");
        assert!(details.get("subject_organization").is_none());
        assert!(details.get("subject_common_name").is_none());
        assert!(details.get("certificate_trusted").is_none());
        assert!(details.get("credential_sha256").is_none());
    }

    /// Splice a legacy v1 `sigTst` unprotected header into a finished COSE.
    /// The signature covers the protected bucket and the payload, so it still
    /// verifies.
    fn with_legacy_sig_tst(cose: &[u8]) -> Vec<u8> {
        let Ok(Value::Tag(18, boxed)) = crate::c2pa_cbor::decode(cose) else {
            panic!("fixture is a tagged COSE_Sign1");
        };
        let Value::Array(mut parts) = *boxed else {
            panic!("COSE_Sign1 is an array");
        };
        parts[1] = Value::Map(vec![(
            Value::Text("sigTst".into()),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("val".into()),
                    Value::Bytes(vec![0x30, 0x03, 0x02, 0x01, 0x00]),
                )])]),
            )]),
        )]);
        encode(
            &Value::Tag(18, Box::new(Value::Array(parts))),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap()
    }

    /// CAWG Identity 1.3, ICA validating: "C2PA 'version 1' time stamps are
    /// not supported when used in identity assertions. A validator SHOULD
    /// ignore any value found in a `sigTst` unprotected header." Ignoring it
    /// means the credential has no time stamp, not an invalid one, so
    /// `cawg.ica.time_stamp.invalid` belongs to a failing `sigTst2` alone.
    #[test]
    fn a_legacy_sig_tst_header_is_ignored_rather_than_reported_invalid() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let credential = vc_json(json!(&did), false);
        let results = run(
            &with_legacy_sig_tst(&eddsa_cose(&key, &credential)),
            std::slice::from_ref(&did),
            None,
        );
        assert!(results.failure.is_empty(), "{:?}", results.failure);
        assert!(!codes(&results.success).contains(&CAWG_ICA_TIME_STAMP_VALIDATED));
        assert!(codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    #[test]
    fn bitstring_status_context_preserves_revoked_credentials_in_both_vc_versions() {
        for vc_v1 in [true, false] {
            let key = SigningKey::from_bytes(&[7; 32]);
            let did = did_jwk(&key);
            let mut credential = vc_json(json!(&did), vc_v1);
            credential["@context"] = if vc_v1 {
                json!([VC_CONTEXT_V1, STATUS_CONTEXT_V1, CAWG_ICA_CONTEXT])
            } else {
                json!([VC_CONTEXT_V2, CAWG_ICA_CONTEXT, STATUS_CONTEXT_V1])
            };
            credential["credentialStatus"] = json!({
                "id": "https://status.example/list#3",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "3",
                "statusListCredential": "https://status.example/list",
            });
            let lists = HashMap::from([(
                "https://status.example/list".into(),
                base64_encode(&[0b0001_0000], false),
            )]);
            let results = run(
                &eddsa_cose(&key, &credential),
                std::slice::from_ref(&did),
                Some(&lists),
            );
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_CREDENTIAL_REVOKED],
                "VC {}",
                if vc_v1 { "1.1" } else { "2.0" }
            );
            assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
        }
    }

    #[test]
    fn bitstring_status_context_preserves_not_revoked_credentials_in_both_vc_versions() {
        for vc_v1 in [true, false] {
            let key = SigningKey::from_bytes(&[7; 32]);
            let did = did_jwk(&key);
            let mut credential = vc_json(json!(&did), vc_v1);
            credential["@context"] = if vc_v1 {
                json!([VC_CONTEXT_V1, STATUS_CONTEXT_V1, CAWG_ICA_CONTEXT])
            } else {
                json!([VC_CONTEXT_V2, CAWG_ICA_CONTEXT, STATUS_CONTEXT_V1])
            };
            credential["credentialStatus"] = json!({
                "id": "https://status.example/list#3",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "3",
                "statusListCredential": "https://status.example/list",
            });
            let lists = HashMap::from([(
                "https://status.example/list".into(),
                base64_encode(&[0], false),
            )]);
            let results = run(
                &eddsa_cose(&key, &credential),
                std::slice::from_ref(&did),
                Some(&lists),
            );
            assert!(
                results.failure.is_empty(),
                "VC {}: {:?}",
                if vc_v1 { "1.1" } else { "2.0" },
                results.failure
            );
            assert!(codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_NOT_REVOKED));
            assert!(codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
        }
    }

    #[test]
    fn vc_11_bitstring_term_without_its_context_is_unsupported() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), true);
        credential["credentialStatus"] = json!({
            "id": "https://status.example/list#3",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "3",
            "statusListCredential": "https://status.example/list",
        });
        let lists = HashMap::from([(
            "https://status.example/list".into(),
            base64_encode(&[0b0001_0000], false),
        )]);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            Some(&lists),
        );
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_REVOCATION_UNSUPPORTED]
        );
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_NOT_REVOKED));
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    #[test]
    fn bitstring_status_uses_most_significant_bit_order() {
        let entry = |index: usize| {
            json!({
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusSize": 1,
                "statusListIndex": index.to_string(),
                "statusListCredential": "https://status.example/list",
            })
        };
        let list_url = "https://status.example/list".to_string();

        // W3C Bitstring Status List index 3 is the fifth bit from the right.
        // Its LSB-order twin, index 4, must remain clear.
        let lists = HashMap::from([(
            list_url.clone(),
            base64_encode(&[0b0001_0000, 0b0000_0001], false),
        )]);
        assert!(matches!(
            check_bitstring_status_entry(&entry(3), Some(&lists)),
            Revocation::Revoked
        ));
        assert!(matches!(
            check_bitstring_status_entry(&entry(4), Some(&lists)),
            Revocation::NotRevoked
        ));
        assert!(matches!(
            check_bitstring_status_entry(&entry(15), Some(&lists)),
            Revocation::Revoked
        ));

        // The mirrored byte reverses those results and catches either
        // accidental interpretation as least-significant-bit first.
        let mirrored =
            HashMap::from([(list_url, base64_encode(&[0b0000_1000, 0b0000_0000], false))]);
        assert!(matches!(
            check_bitstring_status_entry(&entry(3), Some(&mirrored)),
            Revocation::NotRevoked
        ));
        assert!(matches!(
            check_bitstring_status_entry(&entry(4), Some(&mirrored)),
            Revocation::Revoked
        ));
    }

    #[test]
    fn unsupported_or_malformed_status_size_fails_closed() {
        let entry = |status_size: Json| {
            json!({
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusSize": status_size,
                "statusListIndex": "3",
                "statusListCredential": "https://status.example/list",
            })
        };
        // With two-bit entries, index 3 occupies the final two bits. Both are
        // set, but a validator that only implements one-bit entries must not
        // reinterpret the clear W3C bit at index 3 as NotRevoked.
        let lists = HashMap::from([(
            "https://status.example/list".into(),
            base64_encode(&[0b0000_0011], false),
        )]);
        let size_two = entry(json!(2));
        assert!(matches!(
            check_bitstring_status_entry(&size_two, Some(&lists)),
            Revocation::Unsupported
        ));
        assert!(matches!(
            check_revocation(Some(&size_two), true, Some(&lists)),
            Revocation::Unsupported
        ));

        for malformed in [entry(json!(0)), entry(json!("1")), entry(json!(1.5))] {
            assert!(matches!(
                check_bitstring_status_entry(&malformed, Some(&lists)),
                Revocation::Unavailable
            ));
        }
    }

    #[test]
    fn any_revoked_entry_wins_across_multiple_supported_status_entries() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialStatus"] = json!([
            {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "0",
                "statusListCredential": "https://status.example/list"
            },
            {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "3",
                "statusListCredential": "https://status.example/list"
            }
        ]);
        let lists = HashMap::from([(
            "https://status.example/list".into(),
            base64_encode(&[0b0001_0000], false),
        )]);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            Some(&lists),
        );
        assert!(codes(&results.failure).contains(&CAWG_ICA_CREDENTIAL_REVOKED));
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_NOT_REVOKED));
    }

    #[test]
    fn supported_status_without_offline_list_is_unavailable() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialStatus"] = json!({
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "0",
            "statusListCredential": "https://status.example/list",
        });
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert!(codes(&results.failure).contains(&CAWG_ICA_REVOCATION_UNAVAILABLE));
    }

    #[test]
    fn unsupported_status_method_is_reported() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialStatus"] = json!({
            "type": "VendorStatus",
            "statusPurpose": "revocation",
        });
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert!(codes(&results.failure).contains(&CAWG_ICA_REVOCATION_UNSUPPORTED));
    }

    #[test]
    fn es256_ica_credential_validates() {
        use p256::ecdsa::signature::Signer as _;
        let key = p256::ecdsa::SigningKey::from_bytes((&[9_u8; 32]).into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64_encode(point.x().unwrap(), true),
            "y": base64_encode(point.y().unwrap(), true),
        });
        let did = format!(
            "did:jwk:{}",
            base64_encode(jwk.to_string().as_bytes(), true)
        );
        let credential = vc_json(json!(&did), false);
        let payload = serde_json::to_vec(&credential).unwrap();
        let signature = cose(CoseAlg::Es256, &payload, |input| {
            let signature: p256::ecdsa::Signature = key.sign(input);
            signature.to_bytes().to_vec()
        });
        let results = run(&signature, std::slice::from_ref(&did), None);
        assert!(results.failure.is_empty(), "{:?}", results.failure);
        assert!(codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    #[test]
    fn vc_11_issuance_date_and_object_issuer_validate() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let credential = vc_json(json!({"id": did}), true);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert!(results.failure.is_empty(), "{:?}", results.failure);
        assert!(codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    #[test]
    fn non_spec_ica_context_is_rejected() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["@context"] =
            json!([VC_CONTEXT_V2, "https://cawg.io/identity/1.2/ica/context/"]);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL]
        );
    }

    #[test]
    fn malformed_object_issuer_uses_the_registered_invalid_issuer_code() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = vc_json(json!({"name": "missing DID"}), false);
        let results = run(&eddsa_cose(&key, &credential), &[], None);
        assert!(codes(&results.failure).contains(&CAWG_ICA_INVALID_ISSUER));
        assert!(!codes(&results.failure).contains(&CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL));
    }

    #[test]
    fn complete_signer_payload_json_must_match_exactly() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialSubject"]["c2paAsset"]["unexpected"] = json!(true);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert!(codes(&results.failure).contains(&CAWG_ICA_SIGNER_PAYLOAD_MISMATCH));
    }

    #[test]
    fn missing_and_invalid_verified_identities_have_specific_codes() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut missing = vc_json(json!(&did), false);
        missing["credentialSubject"]
            .as_object_mut()
            .unwrap()
            .remove("verifiedIdentities");
        let missing_results = run(
            &eddsa_cose(&key, &missing),
            std::slice::from_ref(&did),
            None,
        );
        assert!(codes(&missing_results.failure).contains(&CAWG_ICA_VERIFIED_IDENTITIES_MISSING));

        let mut invalid = vc_json(json!(&did), false);
        invalid["credentialSubject"]["verifiedIdentities"][0]["verifiedAt"] = json!("not-a-date");
        let invalid_results = run(
            &eddsa_cose(&key, &invalid),
            std::slice::from_ref(&did),
            None,
        );
        assert!(codes(&invalid_results.failure).contains(&CAWG_ICA_VERIFIED_IDENTITIES_INVALID));
    }

    #[test]
    fn did_assertion_method_reference_checks_document_id_method_id_and_controller() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = "did:web:issuer.example";
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64_encode(key.verifying_key().as_bytes(), true),
        });
        let document = json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }],
            "assertionMethod": [format!("{did}#key-1")],
        });
        assert!(key_from_did_document(did, &document).is_ok());
        for field in ["id", "controller"] {
            let mut invalid = document.clone();
            if field == "id" {
                invalid["id"] = json!("did:web:other.example");
            } else {
                invalid["verificationMethod"][0]["controller"] = json!("did:web:other.example");
            }
            assert!(key_from_did_document(did, &invalid).is_err());
        }
    }

    #[test]
    fn controller_chain_can_reach_configured_trust_anchor() {
        let issuer = "did:web:issuer.example";
        let anchor = "did:web:anchor.example".to_string();
        let document = json!({"id": issuer, "controller": anchor});
        assert_eq!(
            issuer_trust_source(issuer, Some(&document), None, None, Some(&[anchor])),
            Some("controller_anchor")
        );
    }

    /// Run one ICA assertion with an explicit pinned DID-document store.
    fn run_with_did_documents(
        cose: &[u8],
        did_documents: Option<&HashMap<String, Json>>,
    ) -> ValidationResults {
        let mut results = ValidationResults::default();
        verify_ica_assertion(
            &signer_payload(),
            cose,
            URL,
            datetime!(2025-06-01 0:00 UTC),
            Some(datetime!(2025-05-01 0:00 UTC)),
            None,
            did_documents,
            None,
            None,
            None,
            &mut results,
        );
        results
    }

    /// No pinned store means the DID document could only come from the network
    /// this verifier never contacts: CAWG 1.3 registers that as
    /// `cawg.identity.network_traffic_blocked`. A configured store that lacks
    /// the DID is an attempted resolution that failed, which stays
    /// `cawg.ica.did_unavailable`.
    #[test]
    fn offline_did_web_resolution_separates_blocked_traffic_from_failed_resolution() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let credential = vc_json(json!("did:web:issuer.example"), false);
        let cose = eddsa_cose(&key, &credential);

        let blocked = run_with_did_documents(&cose, None);
        assert!(
            codes(&blocked.failure).contains(&"cawg.identity.network_traffic_blocked"),
            "{:?}",
            codes(&blocked.failure)
        );
        assert!(!codes(&blocked.failure).contains(&"cawg.ica.did_unavailable"));
        // The blocked resolution names the document it would have fetched.
        assert_eq!(
            blocked
                .network_needs
                .iter()
                .map(super::super::NetworkNeed::to_json)
                .collect::<Vec<_>>(),
            vec![json!({
                "kind": "did_document",
                "did": "did:web:issuer.example",
                "url": "https://issuer.example/.well-known/did.json",
            })]
        );

        let store: HashMap<String, Json> = HashMap::new();
        let unresolved = run_with_did_documents(&cose, Some(&store));
        assert!(
            codes(&unresolved.failure).contains(&"cawg.ica.did_unavailable"),
            "{:?}",
            codes(&unresolved.failure)
        );
        assert!(!codes(&unresolved.failure).contains(&"cawg.identity.network_traffic_blocked"));
        // A configured store is a resolution the caller already attempted, so
        // there is no fetch left to offer.
        assert!(
            unresolved.network_needs.is_empty(),
            "{:?}",
            unresolved.network_needs
        );
    }

    // Ported from the retained commercial kernel (TEAM_465): behaviors it
    // defended that no public test covered.

    /// An issuer whose method-specific id breaks DID syntax is not a DID; a
    /// well-formed `did:jwk` whose id is not a JWK, and a pinned `did:web`
    /// document with no usable method, are DID-document failures.
    #[test]
    fn issuer_classification_separates_did_syntax_from_did_documents() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let store: HashMap<String, Json> = [
            (
                "did:web:pinned.example".to_string(),
                json!({
                    "id": "did:web:pinned.example",
                    "verificationMethod": [{
                        "id": "did:web:pinned.example#key-0",
                        "type": "JsonWebKey2020",
                        "controller": "did:web:pinned.example",
                        "publicKeyJwk": {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": base64_encode(key.verifying_key().as_bytes(), true),
                        },
                    }],
                    "assertionMethod": ["did:web:pinned.example#key-0"],
                }),
            ),
            (
                "did:web:no-method.example".to_string(),
                json!({"id": "did:web:no-method.example"}),
            ),
        ]
        .into();
        let case = |issuer: &str, store: Option<&HashMap<String, Json>>| {
            resolve_issuer_key(issuer, store)
                .err()
                .map(|failure| failure.code)
        };
        for not_a_did in [
            "did:jwk:!!!",
            "did:web:a b",
            "did:web:example:",
            "did:web:%zz",
        ] {
            assert_eq!(
                case(not_a_did, None),
                Some(CAWG_ICA_INVALID_ISSUER),
                "{not_a_did}"
            );
        }
        assert_eq!(
            case("did:jwk:AAAA", None),
            Some(CAWG_ICA_INVALID_DID_DOCUMENT)
        );
        assert_eq!(
            case("did:web:no-method.example", Some(&store)),
            Some(CAWG_ICA_INVALID_DID_DOCUMENT)
        );
        assert_eq!(case("did:web:pinned.example", Some(&store)), None);
        assert_eq!(case("did:web:pinned.example#key-0", Some(&store)), None);
        assert_eq!(case(&did_jwk(&key), None), None);
    }

    /// A `c2paAsset` hash written as a JSON array of byte values is not the
    /// base64 string the data model requires, so it never matches.
    #[test]
    fn a_byte_array_c2pa_asset_hash_is_a_signer_payload_mismatch() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialSubject"]["c2paAsset"]["referenced_assertions"][0]["hash"] =
            json!(HASH.to_vec());
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_SIGNER_PAYLOAD_MISMATCH]
        );
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
    }

    /// A valid credential under the required contexts carries no
    /// informational status: the contexts are not a compatibility signal.
    #[test]
    fn a_valid_credential_reports_no_informational_status() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        for vc_v1 in [true, false] {
            let results = run(
                &eddsa_cose(&key, &vc_json(json!(&did), vc_v1)),
                std::slice::from_ref(&did),
                None,
            );
            assert_credential_valid(&results, if vc_v1 { "VC 1.1" } else { "VC 2.0" });
            assert!(
                results.informational.is_empty(),
                "{:?}",
                results.informational
            );
        }
    }

    /// The URL-safe decoder round-trips every byte, refuses the standard
    /// alphabet, and tolerates padding.
    #[test]
    fn base64url_decoding_refuses_the_standard_alphabet() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            base64_decode(&base64_encode(&data, true), true).as_deref(),
            Some(data.as_slice())
        );
        assert_eq!(base64_decode("a+b/", true), None);
        assert_eq!(
            base64_decode("aGk=", true).as_deref(),
            Some(b"hi".as_slice())
        );
    }

    // CAWG Identity 1.3 ICA conformance. Each test names the requirement ids
    // of the TEAM_457 coverage matrix it defends.

    /// Validate `cose` with every caller input explicit.
    fn run_full(
        signer_payload: &Value,
        cose: &[u8],
        trusted: &[String],
        validation_time: OffsetDateTime,
        manifest_time: Option<OffsetDateTime>,
        tsa_trust: Option<&TrustList>,
        status_lists: Option<&HashMap<String, String>>,
    ) -> ValidationResults {
        let mut results = ValidationResults::default();
        verify_ica_assertion(
            signer_payload,
            cose,
            URL,
            validation_time,
            manifest_time,
            tsa_trust,
            None,
            Some(trusted),
            None,
            status_lists,
            &mut results,
        );
        results
    }

    /// Sign a VC 2.0 credential from the trusted `did:jwk` issuer after `edit`
    /// alters it, and validate it with the default inputs.
    fn validate_edited(edit: impl FnOnce(&mut Json)) -> ValidationResults {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        edit(&mut credential);
        run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        )
    }

    fn validate_identities(identities: Json) -> ValidationResults {
        validate_edited(|credential| {
            credential["credentialSubject"]["verifiedIdentities"] = identities;
        })
    }

    /// A verified identity with the always-required fields plus `fields`.
    fn identity(fields: Json) -> Json {
        let mut identity = json!({
            "verifiedAt": "2024-05-27T08:40:39Z",
            "provider": {"id": "https://idp.example", "name": "Example IdP"},
        });
        for (name, value) in fields.as_object().unwrap() {
            identity[name] = value.clone();
        }
        identity
    }

    fn edited(base: &Json, edit: impl FnOnce(&mut serde_json::Map<String, Json>)) -> Json {
        let mut value = base.clone();
        edit(value.as_object_mut().unwrap());
        value
    }

    fn assert_credential_valid(results: &ValidationResults, case: &str) {
        assert!(results.failure.is_empty(), "{case}: {:?}", results.failure);
        assert!(
            codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID),
            "{case}"
        );
    }

    /// CAWG-ID13-ICA-TECH-A-006: `type` MUST be present and MUST contain both
    /// `VerifiableCredential` and `IdentityClaimsAggregationCredential`.
    /// TECH-A-004 (VC data model): every `type` member is a string.
    #[test]
    fn credential_type_must_contain_both_ica_types() {
        let cases: [(&str, Option<Json>); 4] = [
            ("type missing", None),
            (
                "only VerifiableCredential",
                Some(json!(["VerifiableCredential"])),
            ),
            (
                "only IdentityClaimsAggregationCredential",
                Some(json!(["IdentityClaimsAggregationCredential"])),
            ),
            (
                "non-string member",
                Some(json!([
                    "VerifiableCredential",
                    "IdentityClaimsAggregationCredential",
                    7
                ])),
            ),
        ];
        for (case, types) in cases {
            let results = validate_edited(|credential| match types {
                Some(types) => credential["type"] = types,
                None => {
                    credential.as_object_mut().unwrap().remove("type");
                }
            });
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
                "{case}"
            );
        }
    }

    /// CAWG-ID13-ICA-TECH-A-004 and TECH-A-005: the VC data model requires
    /// its own context URL as the first `@context` item (VC 2.0 section
    /// 4.3, VC 1.1 section 4.1), and that URL selects the model version.
    #[test]
    fn the_vc_context_must_be_the_first_context_item() {
        for (vc_v1, context) in [
            (false, json!([CAWG_ICA_CONTEXT, VC_CONTEXT_V2])),
            (true, json!([CAWG_ICA_CONTEXT, VC_CONTEXT_V1])),
            (
                true,
                json!([STATUS_CONTEXT_V1, VC_CONTEXT_V1, CAWG_ICA_CONTEXT]),
            ),
        ] {
            let key = SigningKey::from_bytes(&[7; 32]);
            let did = did_jwk(&key);
            let mut credential = vc_json(json!(&did), vc_v1);
            credential["@context"] = context.clone();
            let results = run(
                &eddsa_cose(&key, &credential),
                std::slice::from_ref(&did),
                None,
            );
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
                "{context}"
            );
        }
    }

    // CAWG-ID13-ICA-TECH-A-004: the ICA MUST meet the W3C VC data model. The
    // V-nn ids are rows of PRDs/CURRENT/cawg13-vc-data-model.md. Every case
    // signs a credential from the trusted issuer that breaks only the named
    // rule, so the named outcome is the only failure.

    type Edit = Box<dyn FnOnce(&mut Json)>;

    /// Sign and validate a VC 1.1 credential after `edit`.
    fn validate_edited_v1(edit: impl FnOnce(&mut Json)) -> ValidationResults {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), true);
        edit(&mut credential);
        run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        )
    }

    /// Set `key` on the object at JSON pointer `at` ("" is the credential).
    fn put(at: &'static str, key: &'static str, value: Json) -> Edit {
        Box::new(move |credential| {
            credential.pointer_mut(at).expect(at)[key] = value;
        })
    }

    /// Apply several edits in order.
    fn all(edits: Vec<Edit>) -> Edit {
        Box::new(move |credential| edits.into_iter().for_each(|edit| edit(credential)))
    }

    const SUBJECT: &str = "/credentialSubject";
    const IDENTITY: &str = "/credentialSubject/verifiedIdentities/0";
    const IDENTITY_URI: &str = "https://social.example/alice";

    fn assert_invalid_vc(case: &str, expected_explanation: &str, results: &ValidationResults) {
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
            "{case}"
        );
        assert_eq!(
            results.failure[0].details, None,
            "{case}: not a profile limit"
        );
        assert!(
            results.failure[0]
                .explanation
                .contains(expected_explanation),
            "{case}: expected explanation containing {expected_explanation:?}, got {:?}",
            results.failure[0].explanation
        );
    }

    fn assert_each_invalid_vc(cases: Vec<(&str, &str, Edit)>) {
        for (case, expected_explanation, edit) in cases {
            assert_invalid_vc(case, expected_explanation, &validate_edited(edit));
        }
    }

    fn assert_each_valid(cases: Vec<(&str, Edit)>) {
        for (case, edit) in cases {
            assert_credential_valid(&validate_edited(edit), case);
        }
    }

    /// The SRI form of the VC 2.0 base context's SHA-256 digest (VC 2.0 B.1).
    fn v2_context_sri() -> String {
        let digest =
            hex::decode("59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734")
                .unwrap();
        format!("sha256-{}", base64_encode(&digest, false))
    }

    /// Every optional VC 2.0 property in conforming form validates, together
    /// with the `@json` literals, value objects, and list objects the body
    /// walk must leave alone.
    #[test]
    fn a_credential_using_every_optional_vc_property_validates() {
        let results = validate_edited(|credential| {
            credential["id"] = json!("urn:uuid:0c07c1ce-57cb-41af-bef2-1b932b986873");
            credential["type"] = json!([
                "VerifiableCredential",
                "IdentityClaimsAggregationCredential",
                "ExampleIcaExtension",
                "https://vocab.example/credentials#Other",
            ]);
            credential["name"] = json!("Identity claims");
            credential["description"] = json!([
                {"@value": "Verified identities", "@language": "en"},
                {"@value": "هويات", "@language": "ar", "@direction": "rtl"},
            ]);
            credential["credentialSubject"]["id"] = json!("did:web:subject.example:user:1");
            credential["credentialSubject"]["exampleClaim"] = json!({"@list": [
                {"@value": "a", "@language": "en"},
                {"@value": 2, "type": "https://t.example/Int"},
                {"@value": null},
            ]});
            credential["credentialSubject"]["exampleJson"] =
                json!({"@value": {"@nest": {"issuer": "x"}}, "type": "@json"});
            credential["validFrom"] = json!("2025-01-01T09:00:00.5+09:00");
            credential["validUntil"] = json!("2025-12-31T24:00:00Z");
            credential["credentialSchema"] = json!([{
                "id": "https://cawg.io/identity/1.1/ica/schema/",
                "type": "JsonSchema",
                "jsonSchema": {"@context": "literal", "@nest": {"issuer": "x"}},
            }]);
            credential["_sd"] = json!([{"@context": "literal"}]);
            credential["evidence"] = json!({"type": ["Evidence"], "id": "https://ev.example/1"});
            credential["termsOfUse"] = json!([{"type": "TrustFrameworkPolicy"}]);
            credential["refreshService"] = json!({"type": "ExampleRefresh"});
            credential["relatedResource"] = json!([
                {"id": VC_CONTEXT_V2, "digestSRI": v2_context_sri(), "mediaType": "application/ld+json"},
                {"id": "https://cawg.io/identity/1.1/ica/schema/", "digestSRI": [
                    "sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW",
                ]},
                {"id": "https://r.example/b", "digestMultibase": [
                    "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n",
                    format!("f1220{}", "ab".repeat(32)),
                ]},
            ]);
            credential["confidenceMethod"] = json!({"type": "ExampleConfidence"});
            credential["renderMethod"] = json!([{"type": "ExampleRender"}]);
            credential["proof"] = json!({"type": "DataIntegrityProof", "proofValue": "z58"});
        });
        assert_credential_valid(&results, "every optional property");
    }

    /// V-03, V-07: an unpinned URL, an inline context object, and an
    /// embedded `@context` are outside the supported profile. They fail
    /// closed with `details.reason` naming the profile limit.
    #[test]
    fn unsupported_contexts_fail_closed_with_a_reason() {
        let contexts = |extra: Json| {
            put(
                "",
                "@context",
                json!([VC_CONTEXT_V2, CAWG_ICA_CONTEXT, extra]),
            )
        };
        let status_list = "https://w3id.org/vc/status-list/2021/v1";
        let cases: Vec<(&str, Edit, Json)> = vec![
            (
                "unpinned URL",
                contexts(json!(status_list)),
                json!([status_list]),
            ),
            (
                "inline object",
                contexts(json!({"ex": "https://ex.example/"})),
                json!(["<inline>"]),
            ),
            (
                "embedded in the subject",
                put(SUBJECT, "@context", json!("https://x.example/")),
                json!(["<embedded>"]),
            ),
            (
                "embedded in a verified identity",
                put(IDENTITY, "@context", json!({})),
                json!(["<embedded>"]),
            ),
            (
                "embedded in a value object",
                put("", "name", json!({"@value": "x", "@context": {}})),
                json!(["<embedded>"]),
            ),
        ];
        for (case, edit, contexts) in cases {
            let results = validate_edited(edit);
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
                "{case}"
            );
            assert_eq!(
                results.failure[0].details,
                Some(json!({"reason": "unsupported_context", "contexts": contexts})),
                "{case}"
            );
        }
        let results = validate_edited(put(
            "",
            "@context",
            json!([
                VC_CONTEXT_V2,
                CAWG_ICA_CONTEXT,
                "https://unknown.example/first",
                "https://unknown.example/second",
            ]),
        ));
        assert_eq!(
            results.failure[0].details,
            Some(json!({
                "reason": "unsupported_context",
                "contexts": ["https://unknown.example/first"],
            }))
        );
    }

    /// V-03, V-05, V-06: context items are URLs, never repeat, and name one
    /// data-model base context.
    #[test]
    fn malformed_context_items_are_invalid() {
        let contexts = |extra: Json| {
            put(
                "",
                "@context",
                json!([VC_CONTEXT_V2, CAWG_ICA_CONTEXT, extra]),
            )
        };
        assert_each_invalid_vc(vec![
            (
                "string that is not a URL",
                "@context item is not a URL",
                contexts(json!("not a url")),
            ),
            (
                "null",
                "@context item is neither a URL nor a context object",
                contexts(Json::Null),
            ),
            (
                "number",
                "@context item is neither a URL nor a context object",
                contexts(json!(7)),
            ),
            (
                "repeated item",
                "@context repeats an item",
                contexts(json!(CAWG_ICA_CONTEXT)),
            ),
            (
                "both base contexts",
                "@context lists more than one data-model base context",
                contexts(json!(VC_CONTEXT_V1)),
            ),
        ]);
    }

    /// The VC 2.0 context types `_sd`, `JsonSchema`'s `jsonSchema`, and
    /// `cnf`'s `jwk` as `@json`. Their values are opaque literals only in
    /// those scopes: `JsonSchema` must be the literal type term, and VC 1.1
    /// has no `@json` terms at all.
    #[test]
    fn json_literals_are_opaque_only_where_a_pinned_context_says_so() {
        let nest = json!({"@nest": {"issuer": "did:example:other"}});
        assert_each_valid(vec![
            (
                "jsonSchema on a JsonSchema node",
                put(
                    "",
                    "credentialSchema",
                    json!({
                        "id": "https://s.example/", "type": "JsonSchema", "jsonSchema": nest.clone(),
                    }),
                ),
            ),
            ("top-level _sd", put("", "_sd", json!([nest.clone()]))),
            (
                "jwk under cnf",
                put("", "cnf", json!({"jwk": nest.clone()})),
            ),
        ]);
        assert_each_invalid_vc(vec![
            (
                "jsonSchema on a node typed with the full IRI",
                "JSON-LD keyword key",
                put(
                    "",
                    "credentialSchema",
                    json!({
                        "id": "https://s.example/",
                        "type": "https://www.w3.org/2018/credentials#JsonSchema",
                        "jsonSchema": nest.clone(),
                    }),
                ),
            ),
            (
                "jwk outside cnf",
                "JSON-LD keyword key",
                put("", "jwk", nest.clone()),
            ),
        ]);
        assert_invalid_vc(
            "VC 1.1 _sd",
            "JSON-LD keyword key",
            &validate_edited_v1(put("", "_sd", nest)),
        );
    }

    /// V-36a: compaction under the pinned contexts writes no keyword keys
    /// except in value and list objects. `@nest` would attach a second
    /// issuer or identity set the verifier never reads.
    #[test]
    fn keyword_keys_are_rejected_outside_value_and_list_objects() {
        let claim = |value: Json| put(SUBJECT, "exampleClaim", value);
        assert_each_invalid_vc(vec![
            (
                "top-level @nest",
                "JSON-LD keyword key",
                put("", "@nest", json!({"issuer": "did:example:other"})),
            ),
            (
                "subject @nest",
                "JSON-LD keyword key",
                put(
                    SUBJECT,
                    "@nest",
                    json!({"verifiedIdentities": [{"type": "cawg.affiliation"}]}),
                ),
            ),
            (
                "nested @type beside type",
                "JSON-LD keyword key",
                put(IDENTITY, "@type", json!("cawg.affiliation")),
            ),
            (
                "top-level @id",
                "JSON-LD keyword key",
                put("", "@id", json!("urn:a:1")),
            ),
            (
                "top-level @type",
                "JSON-LD keyword key",
                put("", "@type", json!("VerifiableCredential")),
            ),
            (
                "@graph",
                "JSON-LD keyword key",
                put(SUBJECT, "@graph", json!([])),
            ),
            (
                "@reverse",
                "JSON-LD keyword key",
                put(SUBJECT, "@reverse", json!({})),
            ),
            (
                "@included",
                "JSON-LD keyword key",
                put("", "@included", json!([])),
            ),
            (
                "keyword-form non-keyword",
                "JSON-LD keyword key",
                put("", "@foo", json!(1)),
            ),
            (
                "typed value with a language (15.3)",
                "typed value object also carries",
                claim(json!({"@value": "x", "type": "https://t.example/T", "@language": "en"})),
            ),
            (
                "object @value without @json",
                "non-scalar @value",
                claim(json!({"@value": {"a": 1}})),
            ),
            (
                "non-string @language",
                "language-tagged value object is malformed",
                claim(json!({"@value": "x", "@language": 7})),
            ),
            (
                "language-tagged number (15.4)",
                "language-tagged value object is malformed",
                claim(json!({"@value": 7, "@language": "en"})),
            ),
            (
                "blank-node type (15.5)",
                "typed value object has an invalid type",
                claim(json!({"@value": "x", "type": "_:b9"})),
            ),
            (
                "value object with a node key",
                "value object carries a key besides",
                claim(json!({"@value": "x", "name": "y"})),
            ),
            (
                "list object with another key",
                "list object carries a key besides @list",
                claim(json!({"@list": [], "name": "y"})),
            ),
        ]);
    }

    /// V-36b: an absolute or compact IRI key naming a pinned term's property
    /// merges with that term under JSON-LD.
    #[test]
    fn iri_keys_for_pinned_terms_are_rejected() {
        let identities =
            json!([{"type": "cawg.affiliation", "verifiedAt": "2024-05-27T08:40:39Z"}]);
        assert_each_invalid_vc(vec![
            (
                "full IRI of issuer",
                "IRI key for a property",
                put(
                    "",
                    "https://www.w3.org/2018/credentials#issuer",
                    json!("did:example:other"),
                ),
            ),
            (
                "compact CAWG IRI",
                "IRI key for a property",
                put(SUBJECT, "cawg:verifiedIdentities", identities.clone()),
            ),
            (
                "full CAWG IRI",
                "IRI key for a property",
                put(
                    SUBJECT,
                    "https://cawg.io/identity/1.1/ica/#verifiedIdentities",
                    identities,
                ),
            ),
            (
                "schema.org name",
                "IRI key for a property",
                put(IDENTITY, "https://schema.org/name", json!("Bob")),
            ),
        ]);
        assert_invalid_vc(
            "VC 1.1 cred prefix",
            "IRI key for a property",
            &validate_edited_v1(put("", "cred:issuer", json!("did:example:other"))),
        );
        assert_invalid_vc(
            "VC 1.1 status-context IRI",
            "IRI key for a property",
            &validate_edited_v1(all(vec![
                put(
                    "",
                    "@context",
                    json!([VC_CONTEXT_V1, STATUS_CONTEXT_V1, CAWG_ICA_CONTEXT]),
                ),
                put(
                    SUBJECT,
                    "https://www.w3.org/ns/credentials/status#statusListIndex",
                    json!("3"),
                ),
            ])),
        );
        assert_each_valid(vec![(
            "extension IRI",
            put(
                SUBJECT,
                "https://vocab.example/credentials#exampleClaim",
                json!("x"),
            ),
        )]);
    }

    /// V-36c, V-36d: `id` and `uri` both name a node. A second description
    /// of the same node merges into it under JSON-LD, so only references and
    /// the subject's providers may repeat an identifier.
    #[test]
    fn each_identifier_is_described_once() {
        let identity_uri = || put(IDENTITY, "uri", json!(IDENTITY_URI));
        let evidence = |value: Json| put("", "evidence", value);
        assert_each_invalid_vc(vec![
            (
                "id and uri on one node",
                "node carries both `id` and `uri`",
                all(vec![identity_uri(), put(IDENTITY, "id", json!("urn:x:1"))]),
            ),
            (
                "top-level uri that is not a URL",
                "node identifier is not a URL",
                put("", "uri", json!("not a url")),
            ),
            (
                "subject uri described again by evidence",
                "described by more than one map",
                all(vec![
                    put(SUBJECT, "uri", json!("did:example:subject")),
                    evidence(json!({"id": "did:example:subject", "type": "Evidence",
                        "verifiedIdentities": [{"type": "cawg.affiliation"}]})),
                ]),
            ),
            (
                "compact and full spellings of one subject id",
                "described by more than one map",
                all(vec![
                    put(SUBJECT, "id", json!("cawg:subject")),
                    evidence(
                        json!({"id": "https://cawg.io/identity/1.1/ica/#subject", "type": "Evidence"}),
                    ),
                ]),
            ),
            (
                "identity uri described again by evidence",
                "described by more than one map",
                all(vec![
                    identity_uri(),
                    evidence(json!({"id": IDENTITY_URI, "type": "Evidence", "name": "Bob"})),
                ]),
            ),
            (
                "provider id reused by evidence",
                "described by more than one map",
                evidence(json!({"id": "https://idp.example", "type": "Evidence"})),
            ),
            (
                "provider under evidence reusing the subject's provider id",
                "described by more than one map",
                evidence(json!({"type": "Evidence", "verifiedIdentities": [{
                    "type": "cawg.social_media",
                    "provider": {"id": "https://idp.example", "name": "Evil"},
                }]})),
            ),
            (
                "full-IRI JsonSchema node re-describing an identity",
                "described by more than one map",
                all(vec![
                    identity_uri(),
                    put(
                        "",
                        "credentialSchema",
                        json!({
                            "id": "https://s.example/",
                            "type": "https://www.w3.org/2018/credentials#JsonSchema",
                            "jsonSchema": {"uri": IDENTITY_URI, "name": "Bob"},
                        }),
                    ),
                ]),
            ),
            (
                "relatedResource naming the subject",
                "relatedResource describes",
                all(vec![
                    put(SUBJECT, "id", json!("did:example:subject")),
                    put(
                        "",
                        "relatedResource",
                        json!({"id": "did:example:subject",
                        "digestMultibase": "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"}),
                    ),
                ]),
            ),
            (
                "evidence repeating the credential id",
                "described by more than one map",
                all(vec![
                    put("", "id", json!("urn:uuid:1")),
                    evidence(json!({"id": "urn:uuid:1", "type": "Evidence"})),
                ]),
            ),
        ]);
        assert_invalid_vc(
            "VC 1.1 cred: and full spellings of the credential id",
            "described by more than one map",
            &validate_edited_v1(all(vec![
                put("", "id", json!("cred:self")),
                put(
                    "",
                    "evidence",
                    json!({"id": "https://www.w3.org/2018/credentials#self",
                    "type": "Evidence"}),
                ),
            ])),
        );
        assert_each_valid(vec![
            (
                "identities sharing a provider with differing names",
                put(
                    SUBJECT,
                    "verifiedIdentities",
                    json!([
                        identity(json!({"type": "cawg.social_media", "username": "a",
                        "provider": {"id": "https://linkedin.com", "name": "linkedin"}})),
                        identity(json!({"type": "cawg.document_verification", "name": "A",
                        "provider": {"id": "https://linkedin.com", "name": "LINKEDIN"}})),
                    ]),
                ),
            ),
            (
                "pure reference to the subject",
                all(vec![
                    put(SUBJECT, "id", json!("did:example:subject")),
                    evidence(json!({"type": "Evidence", "about": {"id": "did:example:subject"}})),
                ]),
            ),
            (
                "integrity reference to the schema",
                all(vec![
                    put(
                        "",
                        "credentialSchema",
                        json!({"id": "https://s.example/", "type": "JsonSchema"}),
                    ),
                    put(
                        "",
                        "relatedResource",
                        json!({"id": "https://s.example/",
                        "digestMultibase": "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"}),
                    ),
                ]),
            ),
        ]);
    }

    /// V-11, V-13, V-20: identifiers use the version's datatype (VC 2.0 URL,
    /// VC 1.1 URI) and `type` members are terms or absolute URLs.
    #[test]
    fn identifiers_and_type_names_use_the_version_datatype() {
        let with_type = |extra: &str| {
            put(
                "",
                "type",
                json!([
                    "VerifiableCredential",
                    "IdentityClaimsAggregationCredential",
                    extra
                ]),
            )
        };
        assert_each_valid(vec![(
            "Unicode URL",
            put("", "id", json!("https://example.org/café")),
        )]);
        assert_each_invalid_vc(vec![
            (
                "URL without a host",
                "node identifier is not a URL",
                put("", "id", json!("http:")),
            ),
            (
                "id with two values",
                "node identifier is not a single URL",
                put("", "id", json!(["urn:a:1", "urn:a:2"])),
            ),
            (
                "subject id not a URL",
                "node identifier is not a URL",
                put(SUBJECT, "id", json!("user 1")),
            ),
            (
                "subject id not a string",
                "node identifier is not a single URL",
                put(SUBJECT, "id", json!(1)),
            ),
            ("empty type", "type entries must be terms", with_type("")),
            (
                "keyword type",
                "type entries must be terms",
                with_type("@json"),
            ),
            (
                "type that is not an absolute URL",
                "type entries must be terms",
                with_type("ex:Bad Type"),
            ),
        ]);
        assert_invalid_vc(
            "VC 1.1 non-ASCII id is not a URI",
            "node identifier is not a URL",
            &validate_edited_v1(put("", "id", json!("https://example.org/café"))),
        );
    }

    /// CAWG checks `identity.uri` and `provider.id` itself. Their other
    /// `@id` aliases remain subject to the data-model version's datatype.
    #[test]
    fn identity_and_provider_aliases_use_the_version_datatype() {
        let identity_id = |value: &'static str| put(IDENTITY, "id", json!(value));
        let provider_uri = |value: &'static str| {
            Box::new(move |credential: &mut Json| {
                let provider = credential
                    .pointer_mut("/credentialSubject/verifiedIdentities/0/provider")
                    .unwrap()
                    .as_object_mut()
                    .unwrap();
                provider.remove("id");
                provider.insert("uri".to_string(), json!(value));
            }) as Edit
        };

        assert_each_invalid_vc(vec![
            (
                "VC 2.0 identity.id is relative",
                "node identifier is not a URL",
                identity_id("relative"),
            ),
            (
                "VC 2.0 provider.uri is relative",
                "node identifier is not a URL",
                provider_uri("relative"),
            ),
        ]);
        for (case, edit) in [
            (
                "VC 1.1 identity.id is not an ASCII URI",
                identity_id("https://example.org/café"),
            ),
            (
                "VC 1.1 provider.uri is not an ASCII URI",
                provider_uri("https://example.org/café"),
            ),
        ] {
            assert_invalid_vc(
                case,
                "node identifier is not a URL",
                &validate_edited_v1(edit),
            );
        }
    }

    /// V-18: the issuer must be a URL. A DID-shaped string that is not one
    /// is not a DID, which CAWG reports as `cawg.ica.invalid_issuer`.
    #[test]
    fn an_issuer_that_is_not_a_url_is_an_invalid_issuer() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = format!("{} ", did_jwk(&key));
        let credential = vc_json(json!(&did), false);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            None,
        );
        // With no DID there is nothing the trust configuration can match.
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_INVALID_ISSUER, CAWG_ICA_UNTRUSTED_ISSUER]
        );
    }

    /// V-16, V-17: `name` and `description` are strings or language value
    /// objects, alone or in an array.
    #[test]
    fn name_and_description_must_be_strings_or_language_values() {
        assert_each_invalid_vc(vec![
            (
                "number",
                "name is not a string or language value",
                put("", "name", json!(7)),
            ),
            (
                "empty array",
                "name is not a string or language value",
                put("", "name", json!([])),
            ),
            (
                "array member not a string",
                "description is not a string or language value",
                put("", "description", json!([7])),
            ),
            (
                "missing @value",
                "JSON-LD keyword key",
                put("", "name", json!({"@language": "en"})),
            ),
            (
                "non-string @value",
                "name is not a string or language value",
                put("", "name", json!({"@value": 7})),
            ),
            (
                "extra key",
                "value object carries a key besides",
                put(
                    "",
                    "name",
                    json!({"@value": "x", "@language": "en", "lang": "en"}),
                ),
            ),
            (
                "bad @direction",
                "language-tagged value object is malformed",
                put(
                    "",
                    "description",
                    json!({"@value": "x", "@direction": "up"}),
                ),
            ),
        ]);
    }

    /// V-15, V-24, V-26 to V-32, V-35: status, schema, and extension objects
    /// have a type and the shape each property requires. Related-resource
    /// digests are well formed, and those naming a pinned context match it.
    #[test]
    fn typed_credential_properties_must_be_well_formed() {
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let related = |entry: Json| put("", "relatedResource", entry);
        let multibase =
            |digest: &str| related(json!({"id": "https://r.example/a", "digestMultibase": digest}));
        assert_each_invalid_vc(vec![
            (
                "status as a string",
                "credentialStatus is not one or more typed objects",
                put("", "credentialStatus", json!("https://s.example/1")),
            ),
            (
                "status set with a non-object",
                "credentialStatus is not one or more typed objects",
                put("", "credentialStatus", json!([7])),
            ),
            (
                "empty status set",
                "credentialStatus is not one or more typed objects",
                put("", "credentialStatus", json!([])),
            ),
            (
                "status without type",
                "credentialStatus is not one or more typed objects",
                put(
                    "",
                    "credentialStatus",
                    json!({"statusPurpose": "revocation"}),
                ),
            ),
            (
                "status id not a URL",
                "node identifier is not a URL",
                put(
                    "",
                    "credentialStatus",
                    json!({"type": "BitstringStatusListEntry", "id": "s 1"}),
                ),
            ),
            (
                "schema without id",
                "credentialSchema is not one or more typed objects",
                put("", "credentialSchema", json!({"type": "JsonSchema"})),
            ),
            (
                "schema without type",
                "credentialSchema is not one or more typed objects",
                put("", "credentialSchema", json!({"id": "https://s.example/"})),
            ),
            (
                "evidence without type",
                "evidence is not one or more typed objects",
                put("", "evidence", json!({"id": "https://e.example/1"})),
            ),
            (
                "terms of use without type",
                "termsOfUse is not one or more typed objects",
                put("", "termsOfUse", json!([{"id": "https://t.example/"}])),
            ),
            (
                "refresh service without type",
                "refreshService is not one or more typed objects",
                put("", "refreshService", json!({})),
            ),
            (
                "proof without type",
                "proof is not one or more typed objects",
                put("", "proof", json!({"proofValue": "z58"})),
            ),
            (
                "confidence method without type",
                "confidenceMethod is not one or more typed objects",
                put("", "confidenceMethod", json!({})),
            ),
            (
                "render method without type",
                "renderMethod is not one or more typed objects",
                put("", "renderMethod", json!([{"id": "urn:r:1"}])),
            ),
            (
                "related resource without digest",
                "relatedResource entry has no digest",
                related(json!({"id": "https://r.example/a"})),
            ),
            (
                "related resource without id",
                "relatedResource entry lacks an id",
                related(json!({"digestSRI": sri})),
            ),
            (
                "related resource ids repeat",
                "relatedResource ids repeat",
                related(json!([
                    {"id": "https://r.example/a", "digestSRI": sri},
                    {"id": "https://r.example/a", "digestSRI": sri},
                ])),
            ),
            (
                "digestSRI outside the SRI grammar",
                "digestSRI value is not an SRI hash-expression",
                related(json!({"id": "https://r.example/a", "digestSRI": [sri, "md5-abc"]})),
            ),
            (
                "mediaType not a string",
                "relatedResource mediaType is not a string",
                related(json!({"id": "https://r.example/a", "digestSRI": sri, "mediaType": 7})),
            ),
            (
                "unsupported multibase prefix",
                "not a multibase-encoded multihash",
                multibase("x1220ab"),
            ),
            (
                "base58 outside its alphabet",
                "not a multibase-encoded multihash",
                multibase("zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR10"),
            ),
            (
                "truncated multihash",
                "not a multibase-encoded multihash",
                multibase("f122001"),
            ),
            (
                "sha2-256 multihash of the wrong length",
                "not a multibase-encoded multihash",
                multibase(&format!("f1210{}", "ab".repeat(16))),
            ),
            (
                "empty digestMultibase",
                "not a multibase-encoded multihash",
                multibase(""),
            ),
            (
                "pinned context with the wrong digest",
                "digest does not match the pinned context",
                related(json!({"id": VC_CONTEXT_V2, "digestSRI": sri})),
            ),
        ]);
    }

    /// Digest parsing happens before issuer trust and signature verification,
    /// so encoded inputs are bounded before any decoder sees them.
    #[test]
    fn oversized_related_resource_digests_have_a_fixed_rejection_reason() {
        const REASON: &str =
            "payload is not a valid identity claims aggregation credential: a relatedResource digest exceeds 140 encoded characters";
        for (case, field, value) in [
            (
                "64 KiB multibase",
                "digestMultibase",
                format!("z{}", "1".repeat(64 * 1024)),
            ),
            (
                "64 KiB SRI body",
                "digestSRI",
                format!("sha512-{}", "A".repeat(64 * 1024)),
            ),
        ] {
            let results = validate_edited(put(
                "",
                "relatedResource",
                json!({"id": "https://r.example/oversized", field: value}),
            ));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
                "{case}"
            );
            assert_eq!(results.failure[0].explanation, REASON, "{case}");
        }
    }

    /// Pinned context digests use a one-time cache, and an entry cannot turn
    /// a small signed payload into unbounded repeated digest work.
    #[test]
    fn related_resource_digest_arrays_are_bounded_and_unique() {
        let sri = v2_context_sri();
        for (case, digests, reason) in [
            (
                "large repeated valid digest array",
                vec![sri.clone(); 4096],
                "a relatedResource entry repeats a digest",
            ),
            (
                "too many distinct valid digest expressions",
                (0..=16).map(|index| format!("{sri}?v={index}")).collect(),
                "a relatedResource entry has more than 16 digests",
            ),
        ] {
            let results = validate_edited(put(
                "",
                "relatedResource",
                json!({"id": VC_CONTEXT_V2, "digestSRI": digests}),
            ));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL],
                "{case}"
            );
            assert!(
                results.failure[0].explanation.contains(reason),
                "{case}: {:?}",
                results.failure[0]
            );
        }
    }

    /// V-25, V-27: VC 1.1 also requires an `id` URI on credential status and
    /// refresh service objects, which VC 2.0 makes optional.
    #[test]
    fn vc_11_status_and_refresh_objects_need_an_id() {
        for (field, value) in [
            ("credentialStatus", json!({"type": "ExampleStatus"})),
            (
                "refreshService",
                json!({"type": "ManualRefreshService2018"}),
            ),
        ] {
            assert_invalid_vc(
                field,
                "is not one or more typed objects with URL identifiers",
                &validate_edited_v1(put("", field, value)),
            );
        }
        assert_each_valid(vec![(
            "VC 2.0 refresh service without id",
            put(
                "",
                "refreshService",
                json!({"type": "ManualRefreshService2018"}),
            ),
        )]);
    }

    /// CAWG-ID13-ICA-TECH-A-013 (consumers SHOULD accept the five defined
    /// types), TECH-A-014 (other label values MAY be used), and the optional
    /// fields of TECH-A-015/018/021/024: each type validates with only the
    /// fields its own row requires, so `name`, `username`, `address`, and
    /// `uri` are each absent from some accepted entry.
    #[test]
    fn every_defined_identity_type_validates_with_only_its_required_fields() {
        let identities = [
            identity(json!({"type": "cawg.document_verification", "name": "First Last"})),
            identity(json!({"type": "cawg.web_site", "uri": "https://named-actor.example/"})),
            identity(json!({"type": "cawg.affiliation"})),
            identity(json!({"type": "cawg.social_media", "username": "user"})),
            identity(json!({
                "type": "cawg.crypto_wallet",
                "address": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            })),
            identity(json!({"type": "com.example.passport_check"})),
        ];
        for identity in identities {
            let results = validate_identities(json!([identity.clone()]));
            assert_credential_valid(&results, &identity["type"].to_string());
            let details = results
                .success
                .iter()
                .find(|status| status.code == CAWG_ICA_CREDENTIAL_VALID)
                .and_then(|status| status.details.as_ref())
                .unwrap();
            assert_eq!(details["verified_identities"], json!([identity]));
        }
    }

    /// CAWG-ID13-ICA-TECHNICAL-B-004: consumers SHOULD be prepared to accept
    /// the five defined `method` values.
    #[test]
    fn every_defined_verification_method_validates() {
        for method in [
            "cawg.dns_record",
            "cawg.uri_file_verification",
            "cawg.email",
            "cawg.uri_meta_tag_verification",
            "cawg.federated_login",
        ] {
            let results = validate_identities(json!([identity(json!({
                "type": "cawg.web_site",
                "uri": "https://named-actor.example/",
                "method": method,
            }))]));
            assert_credential_valid(&results, method);
        }
    }

    /// CAWG-ID13-ICA-TECHNICAL-B-015: `provider.name` is a natural language
    /// string, which may be a language map as well as a plain string.
    #[test]
    fn provider_name_may_be_a_language_map() {
        let results = validate_identities(json!([identity(json!({
            "type": "cawg.social_media",
            "username": "user",
            "provider": {
                "id": "https://idp.example",
                "name": {"en": "Example IdP", "fr": "IdP exemple"},
            },
        }))]));
        assert_credential_valid(&results, "language map");
    }

    /// CAWG-ID13-ICA-VALIDATING-B-010: every condition in "Verified
    /// identities" is checked for each entry, and any unmet condition is
    /// `cawg.ica.verified_identities.invalid`. Rows: TECH-A-012, 016, 017,
    /// 019, 020, 022, 023, 025, 026; TECHNICAL-B-003, 007, 009, 012, 015.
    #[test]
    fn each_verified_identity_condition_is_enforced() {
        let base = identity(json!({"type": "cawg.social_media", "username": "user"}));
        let set = |field: &'static str, value: Json| {
            edited(&base, |identity| {
                identity.insert(field.into(), value);
            })
        };
        let remove = |field: &'static str| {
            edited(&base, |identity| {
                identity.remove(field);
            })
        };
        let provider = |edit: fn(&mut serde_json::Map<String, Json>)| {
            edited(&base, |identity| {
                edit(identity["provider"].as_object_mut().unwrap());
            })
        };
        let cases = [
            ("TECH-A-012 type missing", remove("type")),
            ("TECH-A-012 type not a string", set("type", json!(7))),
            ("TECH-A-012 type empty", set("type", json!(""))),
            ("TECH-A-016 name empty", set("name", json!(""))),
            ("TECH-A-016 name not a string", set("name", json!(7))),
            (
                "TECH-A-017 document_verification without name",
                set("type", json!("cawg.document_verification")),
            ),
            ("TECH-A-019 username empty", set("username", json!(""))),
            (
                "TECH-A-019 username not a string",
                set("username", json!(7)),
            ),
            (
                "TECH-A-020 social_media without username",
                remove("username"),
            ),
            ("TECH-A-022 address empty", set("address", json!(""))),
            ("TECH-A-022 address not a string", set("address", json!(7))),
            (
                "TECH-A-023 crypto_wallet without address",
                set("type", json!("cawg.crypto_wallet")),
            ),
            (
                "TECH-A-025 uri without a scheme",
                set("uri", json!("named-actor-site.example")),
            ),
            ("TECH-A-025 uri not a string", set("uri", json!(7))),
            (
                "TECH-A-026 web_site without uri",
                set("type", json!("cawg.web_site")),
            ),
            ("TECHNICAL-B-003 method empty", set("method", json!(""))),
            (
                "TECHNICAL-B-003 method not a string",
                set("method", json!(7)),
            ),
            ("TECHNICAL-B-007 verifiedAt missing", remove("verifiedAt")),
            (
                "TECHNICAL-B-007 verifiedAt not RFC 3339",
                set("verifiedAt", json!("2024-05-27")),
            ),
            ("TECHNICAL-B-009 provider missing", remove("provider")),
            (
                "TECHNICAL-B-009 provider not an object",
                set("provider", json!("Example IdP")),
            ),
            (
                "TECHNICAL-B-012 provider.id not a string",
                provider(|provider| {
                    provider.insert("id".into(), json!(7));
                }),
            ),
            (
                "TECHNICAL-B-012 provider.id without a scheme",
                provider(|provider| {
                    provider.insert("id".into(), json!("idp.example"));
                }),
            ),
            (
                "TECHNICAL-B-015 provider.name missing",
                provider(|provider| {
                    provider.remove("name");
                }),
            ),
            (
                "TECHNICAL-B-015 provider.name empty",
                provider(|provider| {
                    provider.insert("name".into(), json!(""));
                }),
            ),
            (
                "TECHNICAL-B-015 provider.name language map with an empty value",
                provider(|provider| {
                    provider.insert("name".into(), json!({"en": ""}));
                }),
            ),
            (
                "VALIDATING-B-010 entry not an object",
                json!("cawg.social_media"),
            ),
        ];
        for (case, entry) in cases {
            let results = validate_identities(json!([entry]));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_VERIFIED_IDENTITIES_INVALID],
                "{case}"
            );
            assert!(
                !codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID),
                "{case}"
            );
        }
    }

    /// CAWG-ID13-ICA-VALIDATING-B-008: a missing, non-array, or empty
    /// `verifiedIdentities` is `cawg.ica.verified_identities.missing`.
    #[test]
    fn absent_non_array_or_empty_verified_identities_are_missing() {
        for (case, value) in [
            ("absent", None),
            ("object", Some(json!({}))),
            ("string", Some(json!("cawg.social_media"))),
            ("empty array", Some(json!([]))),
        ] {
            let results = validate_edited(|credential| {
                let subject = credential["credentialSubject"].as_object_mut().unwrap();
                match value {
                    Some(value) => subject.insert("verifiedIdentities".into(), value),
                    None => subject.remove("verifiedIdentities"),
                };
            });
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_VERIFIED_IDENTITIES_MISSING],
                "{case}"
            );
        }
    }

    /// CAWG-ID13-ICA-VALIDATING-B-012: the validator SHOULD identify which
    /// `verifiedIdentities` entries are not accepted.
    #[test]
    fn invalid_verified_identities_name_each_rejected_entry() {
        let accepted = identity(json!({"type": "cawg.social_media", "username": "user"}));
        let results = validate_identities(json!([
            edited(&accepted, |identity| {
                identity.remove("verifiedAt");
            }),
            accepted.clone(),
            identity(json!({"type": "cawg.web_site"})),
        ]));
        let status = results
            .failure
            .iter()
            .find(|status| status.code == CAWG_ICA_VERIFIED_IDENTITIES_INVALID)
            .unwrap();
        assert_eq!(
            status.details.as_ref().unwrap()["invalid_entries"],
            json!([
                {"index": 0, "field": "verifiedAt"},
                {"index": 2, "field": "uri"},
            ])
        );
    }

    /// Bytes whose base64 uses alphabet indices 62 and 63 in every position,
    /// so the standard (`+/`) and URL-safe (`-_`) encodings always differ.
    fn index_62_63_hash() -> Vec<u8> {
        [0xFB, 0xFF, 0xBF].into_iter().cycle().take(32).collect()
    }

    fn payload_with_hash(hash: &[u8]) -> Value {
        Value::Map(vec![
            (
                "referenced_assertions".into(),
                Value::Array(vec![Value::Map(vec![
                    (
                        "url".into(),
                        Value::Text("self#jumbf=c2pa.assertions/c2pa.hash.data".into()),
                    ),
                    ("hash".into(), Value::Bytes(hash.to_vec())),
                ])]),
            ),
            (
                "sig_type".into(),
                Value::Text("cawg.identity_claims_aggregation".into()),
            ),
        ])
    }

    /// Validate a credential whose `c2paAsset` is `asset`, written by hand
    /// rather than by the serializer under test, against a signer payload
    /// carrying `index_62_63_hash`.
    fn validate_c2pa_asset(asset: Json) -> ValidationResults {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialSubject"]["c2paAsset"] = asset;
        run_full(
            &payload_with_hash(&index_62_63_hash()),
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            datetime!(2025-06-01 0:00 UTC),
            Some(datetime!(2025-05-01 0:00 UTC)),
            None,
            None,
        )
    }

    const STANDARD_HASH: &str = "+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/+/8=";

    fn c2pa_asset(hash: &str, assertions_key: &str, sig_type_key: &str) -> Json {
        json!({
            assertions_key: [{
                "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
                "hash": hash,
            }],
            sig_type_key: "cawg.identity_claims_aggregation",
        })
    }

    /// CAWG-ID13-ICA-VALIDATING-B-004 and TECHNICAL-B-018: byte strings are
    /// standard RFC 4648 section 4 base64 and MUST NOT use the URL-safe
    /// alphabet.
    #[test]
    fn c2pa_asset_hashes_use_the_standard_base64_alphabet() {
        let standard = validate_c2pa_asset(c2pa_asset(
            STANDARD_HASH,
            "referenced_assertions",
            "sig_type",
        ));
        assert_credential_valid(&standard, "standard alphabet");

        let url_safe = STANDARD_HASH.replace('+', "-").replace('/', "_");
        let results =
            validate_c2pa_asset(c2pa_asset(&url_safe, "referenced_assertions", "sig_type"));
        assert_eq!(
            codes(&results.failure),
            vec![CAWG_ICA_SIGNER_PAYLOAD_MISMATCH]
        );
    }

    /// CAWG-ID13-ICA-TECHNICAL-B-019: the encoding MUST NOT include line
    /// feeds.
    #[test]
    fn c2pa_asset_hashes_with_line_breaks_are_a_mismatch() {
        for broken in [
            format!("{}\n{}", &STANDARD_HASH[..20], &STANDARD_HASH[20..]),
            format!("{STANDARD_HASH}\r\n"),
        ] {
            let results =
                validate_c2pa_asset(c2pa_asset(&broken, "referenced_assertions", "sig_type"));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_SIGNER_PAYLOAD_MISMATCH],
                "{broken:?}"
            );
        }
    }

    /// CAWG-ID13-ICA-TECHNICAL-B-020 and B-021: field names are used exactly
    /// as in `signer_payload`; a snake_case to camelCase translation MUST NOT
    /// be performed.
    #[test]
    fn c2pa_asset_field_names_are_not_translated_to_camel_case() {
        for (assertions_key, sig_type_key) in [
            ("referencedAssertions", "sig_type"),
            ("referenced_assertions", "sigType"),
        ] {
            let results =
                validate_c2pa_asset(c2pa_asset(STANDARD_HASH, assertions_key, sig_type_key));
            assert_eq!(
                codes(&results.failure),
                vec![CAWG_ICA_SIGNER_PAYLOAD_MISMATCH],
                "{assertions_key}/{sig_type_key}"
            );
        }
    }

    /// Validate a credential signed with `algorithm` by the issuer whose
    /// public JWK is `jwk`.
    fn assert_algorithm_validates(
        algorithm: CoseAlg,
        jwk: Json,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) {
        let did = format!(
            "did:jwk:{}",
            base64_encode(jwk.to_string().as_bytes(), true)
        );
        let credential = vc_json(json!(&did), false);
        let signature = cose(algorithm, &serde_json::to_vec(&credential).unwrap(), sign);
        let results = run(&signature, std::slice::from_ref(&did), None);
        assert_credential_valid(&results, &format!("{algorithm:?}"));
    }

    fn ec_jwk(crv: &str, x: &[u8], y: &[u8]) -> Json {
        json!({
            "kty": "EC",
            "crv": crv,
            "x": base64_encode(x, true),
            "y": base64_encode(y, true),
        })
    }

    /// CAWG-ID13-ICA-TECH-A-036: the COSE signature may use any C2PA 2.4
    /// signature algorithm. ES384 and ES512.
    #[test]
    fn ecdsa_p384_and_p521_credentials_validate() {
        use p384::ecdsa::signature::Signer as _;

        let p384_key = p384::ecdsa::SigningKey::from_bytes((&[9_u8; 48]).into()).unwrap();
        let point = p384_key.verifying_key().to_encoded_point(false);
        assert_algorithm_validates(
            CoseAlg::Es384,
            ec_jwk("P-384", point.x().unwrap(), point.y().unwrap()),
            |input| {
                let signature: p384::ecdsa::Signature = p384_key.sign(input);
                signature.to_bytes().to_vec()
            },
        );

        let mut scalar = [9_u8; 66];
        scalar[0] = 1;
        let p521_key = p521::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        let point = p521::ecdsa::VerifyingKey::from(&p521_key).to_encoded_point(false);
        assert_algorithm_validates(
            CoseAlg::Es512,
            ec_jwk("P-521", point.x().unwrap(), point.y().unwrap()),
            |input| {
                let signature: p521::ecdsa::Signature = p521_key.sign(input);
                signature.to_bytes().to_vec()
            },
        );
    }

    /// CAWG-ID13-ICA-TECH-A-036: PS256, PS384, and PS512.
    #[test]
    fn rsa_pss_credentials_validate() {
        use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
        use rsa::traits::PublicKeyParts as _;

        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let jwk = json!({
            "kty": "RSA",
            "n": base64_encode(&key.n().to_bytes_be(), true),
            "e": base64_encode(&key.e().to_bytes_be(), true),
        });
        assert_algorithm_validates(CoseAlg::Ps256, jwk.clone(), |input| {
            rsa::pss::SigningKey::<sha2::Sha256>::new(key.clone())
                .sign_with_rng(&mut rand_core::OsRng, input)
                .to_vec()
        });
        assert_algorithm_validates(CoseAlg::Ps384, jwk.clone(), |input| {
            rsa::pss::SigningKey::<sha2::Sha384>::new(key.clone())
                .sign_with_rng(&mut rand_core::OsRng, input)
                .to_vec()
        });
        assert_algorithm_validates(CoseAlg::Ps512, jwk, |input| {
            rsa::pss::SigningKey::<sha2::Sha512>::new(key.clone())
                .sign_with_rng(&mut rand_core::OsRng, input)
                .to_vec()
        });
    }

    /// Attach a `sigTst2` header whose token the fixture TSA minted over the
    /// C2PA v2 time-stamp input of `cose`, attesting `gen_time`. The input
    /// covers the protected header and signature, not the unprotected
    /// bucket, so the header can be added after signing.
    fn with_sig_tst2(cose: &[u8], tsa: &TestTsa, gen_time: OffsetDateTime) -> Vec<u8> {
        let token = tsa.token(&timestamp_input(cose).unwrap(), gen_time);
        let Ok(Value::Tag(18, boxed)) = crate::c2pa_cbor::decode(cose) else {
            panic!("fixture is a tagged COSE_Sign1");
        };
        let Value::Array(mut parts) = *boxed else {
            panic!("COSE_Sign1 is an array");
        };
        parts[1] = Value::Map(vec![(
            Value::Text("sigTst2".into()),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("val".into()),
                    Value::Bytes(token),
                )])]),
            )]),
        )]);
        encode(
            &Value::Tag(18, Box::new(Value::Array(parts))),
            Profile::LegacyPipelineBDefinite,
        )
        .unwrap()
    }

    fn fixture_tsa() -> TestTsa {
        TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        )
    }

    /// A signed credential with `validFrom` set, time-stamped by `tsa` at
    /// 2025-03-01.
    fn time_stamped_credential(tsa: &TestTsa, valid_from: &str) -> (Vec<u8>, String) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["validFrom"] = json!(valid_from);
        let cose = with_sig_tst2(
            &eddsa_cose(&key, &credential),
            tsa,
            datetime!(2025-03-01 0:00 UTC),
        );
        (cose, did)
    }

    /// CAWG-ID13-ICA-TECH-A-031/032, VALIDATING-A-036, VALIDATING-B-025: a
    /// C2PA v2 `sigTst2` time stamp from a configured TSA is validated and
    /// reported as `cawg.ica.time_stamp.validated`, and its time is the
    /// credential's trusted time.
    #[test]
    fn a_trusted_sig_tst2_is_reported_validated() {
        let tsa = fixture_tsa();
        let (cose, did) = time_stamped_credential(&tsa, "2025-01-01T00:00:00Z");
        let results = run_full(
            &signer_payload(),
            &cose,
            std::slice::from_ref(&did),
            datetime!(2025-06-01 0:00 UTC),
            Some(datetime!(2025-05-01 0:00 UTC)),
            Some(&tsa.trust_list()),
            None,
        );
        assert_credential_valid(&results, "trusted sigTst2");
        assert!(codes(&results.success).contains(&CAWG_ICA_TIME_STAMP_VALIDATED));
        let details = results
            .success
            .iter()
            .find(|status| status.code == CAWG_ICA_CREDENTIAL_VALID)
            .and_then(|status| status.details.as_ref())
            .unwrap();
        assert_eq!(details["timestamp_trusted"], json!(true));
        assert_eq!(details["trusted_at"], json!("2025-03-01T00:00:00Z"));
    }

    /// CAWG-ID13-ICA-VALIDATING-A-044: the effective date is compared with
    /// the COSE time stamp. The time stamp alone predates `validFrom` here,
    /// so it alone produces `cawg.ica.valid_from.invalid`; when the same
    /// token cannot be validated it MUST NOT be used, and the credential's
    /// dates are then judged without it.
    #[test]
    fn a_validated_time_stamp_before_valid_from_invalidates_the_credential() {
        let tsa = fixture_tsa();
        let (cose, did) = time_stamped_credential(&tsa, "2025-04-01T00:00:00Z");
        let validate = |tsa_trust: Option<&TrustList>| {
            run_full(
                &signer_payload(),
                &cose,
                std::slice::from_ref(&did),
                datetime!(2025-06-01 0:00 UTC),
                Some(datetime!(2025-05-01 0:00 UTC)),
                tsa_trust,
                None,
            )
        };

        let trusted = validate(Some(&tsa.trust_list()));
        assert!(codes(&trusted.success).contains(&CAWG_ICA_TIME_STAMP_VALIDATED));
        assert_eq!(codes(&trusted.failure), vec![CAWG_ICA_VALID_FROM_INVALID]);

        let untrusted = validate(None);
        assert_eq!(codes(&untrusted.failure), vec![CAWG_ICA_TIME_STAMP_INVALID]);
    }

    fn validate_dates(
        vc_v1: bool,
        dates: Json,
        validation_time: OffsetDateTime,
        manifest_time: Option<OffsetDateTime>,
    ) -> ValidationResults {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), vc_v1);
        let object = credential.as_object_mut().unwrap();
        object.remove("issuanceDate");
        object.remove("validFrom");
        for (name, value) in dates.as_object().unwrap() {
            object.insert(name.clone(), value.clone());
        }
        run_full(
            &signer_payload(),
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            validation_time,
            manifest_time,
            None,
            None,
        )
    }

    /// CAWG-ID13-ICA-VALIDATING-A-044 and A-049: the effective and expiration
    /// dates are compared with the C2PA Manifest time stamp. Each case is
    /// valid at the current time and fails only because of the manifest
    /// time.
    #[test]
    fn manifest_time_bounds_the_effective_and_expiration_dates() {
        let manifest = Some(datetime!(2025-05-01 0:00 UTC));
        let cases = [
            (
                json!({"validFrom": "2025-05-15T00:00:00Z"}),
                datetime!(2025-06-01 0:00 UTC),
                CAWG_ICA_VALID_FROM_INVALID,
            ),
            (
                json!({
                    "validFrom": "2025-01-01T00:00:00Z",
                    "validUntil": "2025-03-01T00:00:00Z",
                }),
                datetime!(2025-02-01 0:00 UTC),
                CAWG_ICA_VALID_UNTIL_INVALID,
            ),
        ];
        for (dates, now, expected) in cases {
            let without_manifest = validate_dates(false, dates.clone(), now, None);
            assert_credential_valid(&without_manifest, &dates.to_string());
            let with_manifest = validate_dates(false, dates.clone(), now, manifest);
            assert_eq!(codes(&with_manifest.failure), vec![expected], "{dates}");
        }
    }

    /// CAWG-ID13-ICA-VALIDATING-A-047 and A-049: a VC 1.1 credential keeps
    /// its dates in `issuanceDate` and `expirationDate`, and the expiration
    /// date is compared with the validation time.
    #[test]
    fn vc_11_issuance_and_expiration_dates_bound_the_credential() {
        let now = datetime!(2025-06-01 0:00 UTC);
        let manifest = Some(datetime!(2025-05-01 0:00 UTC));
        let in_range = validate_dates(
            true,
            json!({
                "issuanceDate": "2025-01-01T00:00:00Z",
                "expirationDate": "2026-01-01T00:00:00Z",
            }),
            now,
            manifest,
        );
        assert_credential_valid(&in_range, "expirationDate in range");

        let expired = validate_dates(
            true,
            json!({
                "issuanceDate": "2025-01-01T00:00:00Z",
                "expirationDate": "2025-05-15T00:00:00Z",
            }),
            now,
            manifest,
        );
        assert_eq!(codes(&expired.failure), vec![CAWG_ICA_VALID_UNTIL_INVALID]);

        let malformed = validate_dates(
            true,
            json!({
                "issuanceDate": "2025-01-01T00:00:00Z",
                "expirationDate": "2026-01-01",
            }),
            now,
            manifest,
        );
        assert_eq!(
            codes(&malformed.failure),
            vec![CAWG_ICA_VALID_UNTIL_INVALID]
        );

        // A VC 2.0 field does not stand in for the VC 1.1 effective date.
        let wrong_version_field = validate_dates(
            true,
            json!({"validFrom": "2025-01-01T00:00:00Z"}),
            now,
            manifest,
        );
        assert_eq!(
            codes(&wrong_version_field.failure),
            vec![CAWG_ICA_VALID_FROM_MISSING]
        );
    }

    fn dates_v2(dates: Json, now: OffsetDateTime) -> ValidationResults {
        validate_dates(false, dates, now, None)
    }

    /// V-21, V-24a, V-45: VC 2.0 validity dates are XML Schema
    /// `dateTimeStamp`s compared exactly: the day must exist, `24:00:00` is
    /// the next midnight, and years and fractions are unbounded.
    #[test]
    fn vc_20_validity_dates_are_exact_xsd_date_time_stamps() {
        let now = datetime!(2025-06-01 0:00 UTC);
        let from = |value: Json| dates_v2(json!({"validFrom": value}), now);
        let until = |value: &str| {
            dates_v2(
                json!({"validFrom": "2025-01-01T00:00:00Z", "validUntil": value}),
                now,
            )
        };
        for value in [
            json!("2025-01-01 00:00:00Z"),
            json!("2025-01-01t00:00:00Z"),
            json!("2025-01-01T00:00:00z"),
            json!("2025-01-01T00:00:00+15:00"),
            json!("2025-01-01T00:00:60Z"),
            json!("2025-01-01T24:00:01Z"),
            json!("2025-01-01T00:00:00.Z"),
            json!("2023-02-29T00:00:00Z"),
            json!("2100-02-29T00:00:00Z"),
            json!("-1000000000000000000000000000000-01-01T00:00:00Z"),
            Json::Null,
        ] {
            assert_eq!(
                codes(&from(value.clone()).failure),
                vec![CAWG_ICA_VALID_FROM_INVALID],
                "{value}"
            );
        }
        let zoneless = from(json!("2025-01-01T00:00:00"));
        assert_eq!(codes(&zoneless.failure), vec![CAWG_ICA_VALID_FROM_INVALID]);
        assert!(
            zoneless.failure[0].explanation.contains("UTC"),
            "{:?}",
            zoneless.failure
        );
        for value in [
            "2024-02-29T00:00:00Z",
            "0000-02-29T00:00:00Z",
            "-0001-01-01T00:00:00Z",
            "2025-01-01T09:00:00+14:00",
        ] {
            assert_credential_valid(&from(json!(value)), value);
        }
        for value in [
            "2025-05-31T24:00:00Z",
            "10000-01-01T00:00:00Z",
            "9999-12-31T24:00:00Z",
        ] {
            assert_credential_valid(&until(value), value);
        }
        assert_eq!(
            codes(&until("2025-05-31T23:59:59Z").failure),
            vec![CAWG_ICA_VALID_UNTIL_INVALID]
        );
        let half = datetime!(2025-06-01 0:00:00.5 UTC);
        assert_credential_valid(
            &dates_v2(
                json!({"validFrom": "2025-01-01T00:00:00Z", "validUntil": "2025-06-01T00:00:00.5Z"}),
                half,
            ),
            "sub-second equality",
        );
        assert_eq!(
            codes(
                &dates_v2(
                    json!({"validFrom": "2025-06-01T00:00:00.5000000001Z"}),
                    half
                )
                .failure
            ),
            vec![CAWG_ICA_VALID_FROM_INVALID]
        );
    }

    fn flags_order(results: &ValidationResults) -> bool {
        results.failure.iter().any(|status| {
            status
                .explanation
                .contains("earlier than its effective date")
        })
    }

    /// V-22: VC 2.0 orders `validFrom` no later than `validUntil`, compared
    /// exactly. VC 1.1 has no such rule.
    #[test]
    fn the_validity_period_order_is_exact_and_vc_20_only() {
        let now = datetime!(2025-06-01 0:00 UTC);
        let pair = |from: &str, until: &str| {
            dates_v2(json!({"validFrom": from, "validUntil": until}), now)
        };
        let (a, b) = (
            "2025-01-01T00:00:00.1234567891Z",
            "2025-01-01T00:00:00.1234567892Z",
        );
        let (early, late) = (
            "1000000000000000000-01-01T00:00:00Z",
            "2000000000000000000-01-01T00:00:00Z",
        );
        assert!(!flags_order(&pair(a, b)));
        assert!(!flags_order(&pair(
            "2025-01-01T00:00:00.123456789012Z",
            "2025-01-01T00:00:00.123456789012Z"
        )));
        assert!(!flags_order(&pair(early, late)));
        assert!(flags_order(&pair(b, a)));
        assert!(flags_order(&pair(late, early)));

        let inside_neither = datetime!(2025-01-15 0:00 UTC);
        let v2 = dates_v2(
            json!({"validFrom": "2025-03-01T00:00:00Z", "validUntil": "2025-02-01T00:00:00Z"}),
            inside_neither,
        );
        assert_eq!(
            codes(&v2.failure),
            vec![CAWG_ICA_VALID_FROM_INVALID, CAWG_ICA_VALID_UNTIL_INVALID]
        );
        let v1 = validate_dates(
            true,
            json!({"issuanceDate": "2025-03-01T00:00:00Z", "expirationDate": "2025-02-01T00:00:00Z"}),
            inside_neither,
            None,
        );
        assert_eq!(codes(&v1.failure), vec![CAWG_ICA_VALID_FROM_INVALID]);
    }

    /// V-23: a VC 1.1 date is an XSD `dateTime`, whose zone is optional. A
    /// zoneless date is compared at the end of its ±14:00 range that can only
    /// reject more: effective dates at the latest instant, expiration dates
    /// at the earliest.
    #[test]
    fn vc_11_zoneless_dates_are_compared_fail_closed() {
        let now = datetime!(2025-06-01 0:00 UTC);
        let validate = |dates: Json| validate_dates(true, dates, now, None);
        assert_credential_valid(
            &validate(json!({
                "issuanceDate": "2025-05-31T09:59:59",
                "expirationDate": "2025-06-01T14:00:01",
            })),
            "zoneless dates 1 s inside the bound",
        );
        assert_eq!(
            codes(&validate(json!({"issuanceDate": "2025-05-31T10:00:01"})).failure),
            vec![CAWG_ICA_VALID_FROM_INVALID]
        );
        assert_eq!(
            codes(
                &validate(json!({
                    "issuanceDate": "2025-01-01T00:00:00",
                    "expirationDate": "2025-06-01T13:59:59",
                }))
                .failure
            ),
            vec![CAWG_ICA_VALID_UNTIL_INVALID]
        );
    }

    /// CAWG-ID13-ICA-VALIDATING-A-004: the validator SHALL follow the steps in
    /// the order presented. Credentials that fail every continuing step
    /// report the failures in that order: COSE headers, issuer (DID, then
    /// trust), signature, time stamp, validity range, revocation, then
    /// binding to the C2PA asset before verified identities.
    #[test]
    fn continuing_failures_are_reported_in_specification_order() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other_key = SigningKey::from_bytes(&[8; 32]);
        let valid_protected = || {
            Value::Map(vec![
                (Value::Integer(1), Value::Integer(CoseAlg::EdDsa.cose_id())),
                (Value::Integer(3), Value::Text(VC_CONTENT_TYPE.into())),
            ])
        };
        let cases = [
            (
                "invalid headers",
                json!(did_jwk(&key)),
                Value::Map(vec![
                    (Value::Integer(1), Value::Integer(-65_535)),
                    (Value::Integer(3), Value::Text("application/json".into())),
                ]),
                vec![
                    CAWG_ICA_INVALID_ALG,
                    CAWG_ICA_INVALID_CONTENT_TYPE,
                    CAWG_ICA_UNTRUSTED_ISSUER,
                ],
            ),
            (
                "wrong issuer key",
                json!(did_jwk(&other_key)),
                valid_protected(),
                vec![CAWG_ICA_UNTRUSTED_ISSUER, CAWG_ICA_SIGNATURE_MISMATCH],
            ),
            (
                "unsupported DID method",
                json!("did:example:issuer"),
                valid_protected(),
                vec![CAWG_ICA_DID_UNSUPPORTED_METHOD, CAWG_ICA_UNTRUSTED_ISSUER],
            ),
            (
                "issuer without a DID",
                json!({"name": "no DID"}),
                valid_protected(),
                vec![CAWG_ICA_INVALID_ISSUER, CAWG_ICA_UNTRUSTED_ISSUER],
            ),
        ];
        let tsa = fixture_tsa();
        for (case, issuer, protected, head) in cases {
            let mut credential = vc_json(issuer, false);
            credential["validFrom"] = json!("2026-01-01T00:00:00Z");
            credential["validUntil"] = json!("2025-01-15T00:00:00Z");
            credential["credentialStatus"] = json!({"type": "VendorStatus"});
            credential["credentialSubject"]["c2paAsset"]["sig_type"] = json!("other");
            credential["credentialSubject"]["verifiedIdentities"][0]
                .as_object_mut()
                .unwrap()
                .remove("verifiedAt");
            let signature = cose_with_protected(
                protected,
                &serde_json::to_vec(&credential).unwrap(),
                |input| key.sign(input).to_bytes().to_vec(),
            );
            let signature = with_sig_tst2(&signature, &tsa, datetime!(2025-03-01 0:00 UTC));
            let results = run(&signature, &[], None);
            let mut expected = head;
            expected.extend([
                CAWG_ICA_TIME_STAMP_INVALID,
                CAWG_ICA_VALID_FROM_INVALID,
                CAWG_ICA_VALID_UNTIL_INVALID,
                CAWG_ICA_REVOCATION_UNSUPPORTED,
                CAWG_ICA_SIGNER_PAYLOAD_MISMATCH,
                CAWG_ICA_VERIFIED_IDENTITIES_INVALID,
            ]);
            assert_eq!(codes(&results.failure), expected, "{case}");
        }
    }

    /// Validate one social-media identity carrying `field: value`, and
    /// return the `details.invalid_entries` fields it was rejected for.
    fn rejected_fields(field: &str, value: &str) -> Vec<String> {
        let mut entry = identity(json!({"type": "cawg.social_media", "username": "user"}));
        entry[field] = json!(value);
        let results = validate_identities(json!([entry]));
        results
            .failure
            .iter()
            .filter(|status| status.code == CAWG_ICA_VERIFIED_IDENTITIES_INVALID)
            .flat_map(|status| {
                status.details.as_ref().unwrap()["invalid_entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| entry["field"].as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// CAWG-ID13-ICA-TECH-A-014 and TECHNICAL-B-006: values other than the
    /// defined `type` and `method` values MAY be used "subject to
    /// restrictions described in Labels". The labels ABNF requires two or
    /// more period-separated components, each `1(DIGIT / ALPHA) *(DIGIT /
    /// ALPHA / "-" / "_")`.
    #[test]
    fn identity_type_and_method_must_be_namespaced_labels() {
        for field in ["type", "method"] {
            for label in [
                "cawg.social_media",
                "cawg.idv",
                "com.example.passport_check",
                "net.fine-art-school.v2",
                "com.example.2fa",
            ] {
                assert!(rejected_fields(field, label).is_empty(), "{field} {label}");
            }
            for label in [
                "passport",
                "cawg.",
                ".cawg",
                "cawg..idv",
                "com.example.-x",
                "com.example._x",
                "com example.x",
                "com.exämple.x",
                "com.example.x!",
                // labels.adoc reserves `__` for multiple-assertion suffixes.
                "com.example.a__b",
                "com.example.foo__bar",
                "cawg.social_media__1",
            ] {
                assert_eq!(
                    rejected_fields(field, label),
                    vec![field],
                    "{field} {label}"
                );
            }
        }
    }

    /// CAWG-ID13-ICA-TECH-A-025 and TECHNICAL-B-012: `uri` and `provider.id`
    /// MUST be valid URIs, which is the RFC 3986 `URI` production, not
    /// merely a scheme followed by a colon.
    #[test]
    fn uri_and_provider_id_must_be_rfc_3986_uris() {
        let valid = [
            "https://www.linkedin.com/profile-thirdparty-redirect/AgEvmWjOfQ_D-2mp",
            "https://user:pw@host.example:8443/a/b;c?q=1&r=%2F#frag/ment?",
            "https://[2001:db8::1]:443/",
            "https://192.0.2.1/",
            "did:web:idp.example",
            "mailto:actor@named.example",
            "urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4",
        ];
        let invalid = [
            "https://named actor.example/",
            "https://named.example/a b",
            "https://named.example/%zz",
            "https://named.example/%4",
            "https://named.example/#a#b",
            "https://named.example:80a/",
            "https://[2001:db8::zz]/",
            "https://named.example/<script>",
            "https://exämple.example/",
            "1https://named.example/",
        ];
        for uri in valid {
            assert!(rejected_fields("uri", uri).is_empty(), "uri {uri}");
            let provider = validate_identities(json!([identity(json!({
                "type": "cawg.social_media",
                "username": "user",
                "provider": {"id": uri, "name": "Example IdP"},
            }))]));
            assert_credential_valid(&provider, uri);
        }
        for uri in invalid {
            assert_eq!(rejected_fields("uri", uri), vec!["uri"], "uri {uri}");
            let provider = validate_identities(json!([identity(json!({
                "type": "cawg.social_media",
                "username": "user",
                "provider": {"id": uri, "name": "Example IdP"},
            }))]));
            assert_eq!(
                codes(&provider.failure),
                vec![CAWG_ICA_VERIFIED_IDENTITIES_INVALID],
                "provider.id {uri}"
            );
        }
    }

    /// CAWG-ID13-ICA-TECH-A-023: a `cawg.crypto_wallet` `address` MUST be an
    /// alphanumeric string. CAWG-ID13-ICA-TECH-A-020 uses the same words for
    /// a `cawg.social_media` `username`, but production aggregators emit
    /// display names there (Adobe: `"Eric Scouten"`), so the username keeps
    /// only its non-empty-string rule as a deliberate interop decision.
    #[test]
    fn crypto_wallet_address_must_be_alphanumeric_but_username_need_not_be() {
        let wallet = |address: &str| {
            validate_identities(json!([identity(json!({
                "type": "cawg.crypto_wallet",
                "address": address,
            }))]))
        };
        for address in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ] {
            assert_credential_valid(&wallet(address), address);
        }
        for address in [
            "0x5aAeb6053F 3E94",
            "eip155:1:0xab16a96D",
            "wallet.eth",
            "ädress",
        ] {
            assert_eq!(
                codes(&wallet(address).failure),
                vec![CAWG_ICA_VERIFIED_IDENTITIES_INVALID],
                "{address}"
            );
        }
        assert!(rejected_fields("username", "Eric Scouten").is_empty());
    }
}
