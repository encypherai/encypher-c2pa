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
const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
const CAWG_ICA_CONTEXT: &str = "https://cawg.io/identity/1.1/ica/context/";
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
        Err(reason) => {
            results.push_failure(
                CAWG_ICA_INVALID_VERIFIABLE_CREDENTIAL,
                url.into(),
                format!("payload is not a valid identity claims aggregation credential: {reason}"),
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

    match credential.valid_from {
        ValidityField::Missing => {
            results.push_failure(
                CAWG_ICA_VALID_FROM_MISSING,
                url.into(),
                format!(
                    "{} credential lacks its required effective date",
                    credential.vc_version
                ),
            );
            ok = false;
        }
        ValidityField::Malformed => {
            results.push_failure(
                CAWG_ICA_VALID_FROM_INVALID,
                url.into(),
                "credential effective date is not an RFC 3339 string".into(),
            );
            ok = false;
        }
        ValidityField::Parsed(valid_from) => {
            if [Some(validation_time), manifest_time, identity_time]
                .into_iter()
                .flatten()
                .any(|at| valid_from > at)
            {
                results.push_failure(
                    CAWG_ICA_VALID_FROM_INVALID,
                    url.into(),
                    "credential effective date is later than an applicable validation time".into(),
                );
                ok = false;
            }
        }
    }
    match credential.valid_until {
        ValidityField::Missing => {}
        ValidityField::Malformed => {
            results.push_failure(
                CAWG_ICA_VALID_UNTIL_INVALID,
                url.into(),
                "credential expiration date is not an RFC 3339 string".into(),
            );
            ok = false;
        }
        ValidityField::Parsed(valid_until) => {
            if [Some(validation_time), manifest_time, identity_time]
                .into_iter()
                .flatten()
                .any(|at| valid_until < at)
            {
                results.push_failure(
                    CAWG_ICA_VALID_UNTIL_INVALID,
                    url.into(),
                    "credential expiration date is earlier than an applicable validation time"
                        .into(),
                );
                ok = false;
            }
        }
    }

    match check_revocation(credential.credential_status.as_ref(), status_lists) {
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

    match &credential.verified_identities {
        VerifiedIdentities::Missing => {
            results.push_failure(
                CAWG_ICA_VERIFIED_IDENTITIES_MISSING,
                url.into(),
                "verifiedIdentities is missing, empty, or not an array".into(),
            );
            ok = false;
        }
        VerifiedIdentities::Invalid(_) => {
            results.push_failure(
                CAWG_ICA_VERIFIED_IDENTITIES_INVALID,
                url.into(),
                "one or more verifiedIdentities entries violate the CAWG ICA data model".into(),
            );
            ok = false;
        }
        VerifiedIdentities::Valid(_) => {}
    }

    if super::report::cbor_to_json(signer_payload) != credential.c2pa_asset {
        results.push_failure(
            CAWG_ICA_SIGNER_PAYLOAD_MISMATCH,
            url.into(),
            "credentialSubject.c2paAsset is not the exact JSON serialization of signer_payload"
                .into(),
        );
        ok = false;
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

#[derive(Clone, Copy)]
enum ValidityField {
    Missing,
    Malformed,
    Parsed(OffsetDateTime),
}

enum VerifiedIdentities {
    Missing,
    Invalid(Vec<Json>),
    Valid(Vec<Json>),
}

struct IcaCredential {
    raw: Json,
    vc_version: &'static str,
    issuer: String,
    valid_from: ValidityField,
    valid_until: ValidityField,
    credential_status: Option<Json>,
    c2pa_asset: Json,
    verified_identities: VerifiedIdentities,
}

fn parse_ica_credential(payload: &[u8]) -> Result<IcaCredential, &'static str> {
    let raw: Json = serde_json::from_slice(payload).map_err(|_| "payload is not JSON")?;
    let object = raw.as_object().ok_or("credential is not a JSON object")?;
    let contexts = object
        .get("@context")
        .and_then(Json::as_array)
        .ok_or("@context is missing or not an array")?;
    let contains = |expected: &str| {
        contexts
            .iter()
            .any(|entry| entry.as_str() == Some(expected))
    };
    let vc_version = if contains(VC_CONTEXT_V2) {
        "2.0"
    } else if contains(VC_CONTEXT_V1) {
        "1.1"
    } else {
        return Err("credential lacks a W3C Verifiable Credentials context");
    };
    if !contains(CAWG_ICA_CONTEXT) {
        return Err("credential lacks the required CAWG Identity 1.1 ICA context");
    }
    if contexts.iter().any(|entry| !entry.is_string()) {
        return Err("@context entries must be strings");
    }

    let types = object
        .get("type")
        .and_then(Json::as_array)
        .ok_or("type is missing or not an array")?;
    if ![
        "VerifiableCredential",
        "IdentityClaimsAggregationCredential",
    ]
    .into_iter()
    .all(|expected| types.iter().any(|entry| entry.as_str() == Some(expected)))
    {
        return Err("type lacks a required ICA credential type");
    }

    let issuer = match object.get("issuer") {
        Some(Json::String(issuer)) => issuer.clone(),
        Some(Json::Object(issuer)) => issuer
            .get("id")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    };

    let subject = match object.get("credentialSubject") {
        Some(Json::Object(subject)) => subject,
        Some(Json::Array(subjects)) if subjects.len() == 1 => subjects[0]
            .as_object()
            .ok_or("credentialSubject entry is not an object")?,
        _ => return Err("credentialSubject is missing or ambiguous"),
    };
    let c2pa_asset = subject.get("c2paAsset").cloned().unwrap_or(Json::Null);
    let verified_identities = match subject.get("verifiedIdentities") {
        Some(Json::Array(values)) if !values.is_empty() => {
            if values.iter().all(valid_verified_identity) {
                VerifiedIdentities::Valid(values.clone())
            } else {
                VerifiedIdentities::Invalid(values.clone())
            }
        }
        _ => VerifiedIdentities::Missing,
    };

    let parse_validity = |name: &str| match object.get(name) {
        None | Some(Json::Null) => ValidityField::Missing,
        Some(Json::String(value)) => OffsetDateTime::parse(value, &Rfc3339)
            .map(ValidityField::Parsed)
            .unwrap_or(ValidityField::Malformed),
        Some(_) => ValidityField::Malformed,
    };
    let (valid_from, valid_until) = if vc_version == "1.1" {
        (
            parse_validity("issuanceDate"),
            parse_validity("expirationDate"),
        )
    } else {
        (parse_validity("validFrom"), parse_validity("validUntil"))
    };

    let credential_status = object.get("credentialStatus").cloned();
    Ok(IcaCredential {
        raw,
        vc_version,
        issuer,
        valid_from,
        valid_until,
        credential_status,
        c2pa_asset,
        verified_identities,
    })
}

fn valid_verified_identity(value: &Json) -> bool {
    let Some(identity) = value.as_object() else {
        return false;
    };
    let Some(identity_type) = identity
        .get("type")
        .and_then(Json::as_str)
        .filter(|v| !v.is_empty())
    else {
        return false;
    };
    if identity
        .get("verifiedAt")
        .and_then(Json::as_str)
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .is_none()
    {
        return false;
    }
    let Some(provider) = identity.get("provider").and_then(Json::as_object) else {
        return false;
    };
    if !natural_language_string(provider.get("name")) {
        return false;
    }
    if provider
        .get("id")
        .is_some_and(|id| id.as_str().is_none_or(|id| !has_uri_scheme(id)))
    {
        return false;
    }
    for field in ["name", "username", "address", "method"] {
        if identity
            .get(field)
            .is_some_and(|value| value.as_str().is_none_or(str::is_empty))
        {
            return false;
        }
    }
    if identity
        .get("uri")
        .is_some_and(|value| value.as_str().is_none_or(|uri| !has_uri_scheme(uri)))
    {
        return false;
    }
    match identity_type {
        "cawg.document_verification" => identity.get("name").and_then(Json::as_str).is_some(),
        "cawg.web_site" => identity.get("uri").and_then(Json::as_str).is_some(),
        "cawg.social_media" => identity.get("username").and_then(Json::as_str).is_some(),
        "cawg.crypto_wallet" => identity.get("address").and_then(Json::as_str).is_some(),
        _ => true,
    }
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

fn has_uri_scheme(text: &str) -> bool {
    let Some((scheme, _)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
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

fn parse_did(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("did:")?;
    let (method, id) = rest.split_once(':')?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || id.is_empty()
    {
        return None;
    }
    Some((method, id))
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
    for entry in entries {
        if entry.get("statusPurpose").and_then(Json::as_str) != Some("revocation")
            || !json_type_contains(entry.get("type"), "BitstringStatusListEntry")
        {
            continue;
        }
        found_supported = true;
        match check_bitstring_status_entry(entry, status_lists) {
            Revocation::Revoked => return Revocation::Revoked,
            Revocation::NotRevoked => {}
            Revocation::Unavailable => unavailable = true,
            _ => unreachable!("single supported status entry has a bounded result"),
        }
    }
    if !found_supported {
        Revocation::Unsupported
    } else if unavailable {
        Revocation::Unavailable
    } else {
        Revocation::NotRevoked
    }
}

fn check_bitstring_status_entry(
    entry: &Json,
    status_lists: Option<&HashMap<String, String>>,
) -> Revocation {
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
    if byte & (1 << (index % 8)) == 0 {
        Revocation::NotRevoked
    } else {
        Revocation::Revoked
    }
}

fn json_type_contains(value: Option<&Json>, expected: &str) -> bool {
    match value {
        Some(Json::String(value)) => value == expected,
        Some(Json::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn base64_decode(input: &str, url_alphabet: bool) -> Option<Vec<u8>> {
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
        let protected = Value::Map(vec![
            (Value::Integer(1), Value::Integer(algorithm.cose_id())),
            (Value::Integer(3), Value::Text(VC_CONTENT_TYPE.into())),
        ]);
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
        let mut results = ValidationResults::default();
        verify_ica_assertion(
            &signer_payload(),
            cose,
            URL,
            datetime!(2025-06-01 0:00 UTC),
            Some(datetime!(2025-05-01 0:00 UTC)),
            None,
            None,
            Some(trusted),
            None,
            status_lists,
            &mut results,
        );
        results
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
    fn revoked_bitstring_status_stops_credential_validation() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let did = did_jwk(&key);
        let mut credential = vc_json(json!(&did), false);
        credential["credentialStatus"] = json!({
            "id": "https://status.example/list#3",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "3",
            "statusListCredential": "https://status.example/list",
        });
        let lists = HashMap::from([(
            "https://status.example/list".into(),
            base64_encode(&[0b0000_1000], false),
        )]);
        let results = run(
            &eddsa_cose(&key, &credential),
            std::slice::from_ref(&did),
            Some(&lists),
        );
        assert!(codes(&results.failure).contains(&CAWG_ICA_CREDENTIAL_REVOKED));
        assert!(!codes(&results.success).contains(&CAWG_ICA_CREDENTIAL_VALID));
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
            base64_encode(&[0b0000_1000], false),
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
}
