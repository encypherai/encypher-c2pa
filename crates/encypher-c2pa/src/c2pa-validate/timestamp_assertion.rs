// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Timestamp evidence selection, status placement, and `iat` validation.
//!
//! Three C2PA 2.4 rules meet here:
//!
//! - **Evidence order** (VAL-TIME-0001..0005). A `sigTst`/`sigTst2` header wins.
//!   When no header exists, or its token does not validate, the `c2pa.time-stamp`
//!   assertions indexed by C2PA Manifest identifier are tried in turn.
//! - **Status placement** (VAL-CRYP-0021..0026). Every inspection failure maps
//!   to its own informational code: `timeStamp.mismatch` for a bad CMS signature
//!   or message imprint, `timeStamp.untrusted` for an unsupported algorithm or a
//!   chain that cannot be built, `timeStamp.outsideValidity` *alone* when
//!   `genTime` falls outside the TSA chain's validity, `timeStamp.credentialInvalid`
//!   alongside untrusted when the TSA credential itself is unacceptable, and
//!   `timeStamp.malformed` only for structural defects.
//! - **Claimed time of signing** (VAL-CRYP-0029..0031). The optional protected
//!   `iat` is validated against the signer chain and any trusted timestamp, and
//!   reported informationally.

use std::collections::BTreeMap;

use time::OffsetDateTime;

use super::{
    ValidationResults, TIME_STAMP_MALFORMED, TIME_STAMP_OUTSIDE_VALIDITY, TIME_STAMP_TRUSTED,
    TIME_STAMP_UNTRUSTED, TIME_STAMP_VALIDATED,
};
use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_crypto::{
    parse_timestamp_header, protected_iat, timestamp_assertion_input, TimestampHeaderEvidence,
    TimestampHeaderVersion,
};
use crate::c2pa_trust::{certificate_valid_at, verify_timestamp_token, TrustList};

/// A `c2pa.time-stamp` assertion is not a single non-empty map of manifest
/// identifiers to non-empty tokens (VAL-TIME-0006/0007).
pub const ASSERTION_TIMESTAMP_MALFORMED: &str = "assertion.timestamp.malformed";
/// The timestamp token's CMS signature or message imprint did not match.
pub const TIME_STAMP_MISMATCH: &str = "timeStamp.mismatch";
/// The timestamp authority's credential is not acceptable for timestamping.
pub const TIME_STAMP_CREDENTIAL_INVALID: &str = "timeStamp.credentialInvalid";
/// The claimed time of signing (`iat`) falls inside the signer's validity.
pub const TIME_OF_SIGNING_INSIDE_VALIDITY: &str = "timeOfSigning.insideValidity";
/// The claimed time of signing (`iat`) falls outside the signer's validity.
pub const TIME_OF_SIGNING_OUTSIDE_VALIDITY: &str = "timeOfSigning.outsideValidity";
/// Encypher extension: a legacy `sigTst` (v1) token established the signing
/// time. Its message imprint covers the protected header and the claim, but not
/// the signature value, so it proves the claim and the signer's certificate
/// existed at the attested time - not that the private key produced this
/// signature then. There is no registered C2PA code for that distinction.
pub const TIMESTAMP_V1_SIGNATURE_UNBOUND: &str = "com.encypher.timestamp.v1SignatureUnbound";

/// Assertion label carrying `time-stamp-map` entries.
pub const TIME_STAMP_ASSERTION_LABEL: &str = "c2pa.time-stamp";

/// Maximum `time-stamp-entry` pairs accepted from one assertion.
const MAX_TIMESTAMP_ENTRIES: usize = 4096;
/// Maximum tokens retained for one C2PA Manifest identifier.
const MAX_TOKENS_PER_MANIFEST: usize = 32;

/// Where a `c2pa.time-stamp` assertion was found while walking the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampAssertionScope {
    /// The assertion belongs to a standard or update manifest.
    Manifest,
    /// The assertion belongs to an ingredient manifest and is ignored
    /// (VAL-TIME-0008).
    Ingredient,
}

/// C2PA-Manifest-identifier-keyed timestamp tokens gathered outside ingredients.
#[derive(Debug, Clone, Default)]
pub struct TimestampAssertionIndex {
    tokens: BTreeMap<String, Vec<Vec<u8>>>,
}

impl TimestampAssertionIndex {
    /// Index one `c2pa.time-stamp` assertion payload.
    ///
    /// Returns `false` when the payload is not a single non-empty map of
    /// non-empty manifest identifiers to non-empty token byte strings, or when
    /// it exceeds a verifier resource bound. Ingredient-scoped assertions are
    /// discarded before decoding, so adversarial ingredient data can neither
    /// contribute tokens nor raise a status on the active manifest.
    fn insert(&mut self, scope: TimestampAssertionScope, assertion_cbor: &[u8]) -> bool {
        if scope == TimestampAssertionScope::Ingredient {
            return true;
        }
        let Ok(decoded) = decode(assertion_cbor) else {
            return false;
        };
        let Some(entries) = decoded.as_map().filter(|entries| !entries.is_empty()) else {
            return false;
        };
        if entries.len() > MAX_TIMESTAMP_ENTRIES {
            return false;
        }
        // Stage every entry before mutating: a defect in the last pair must not
        // leave half of a malformed assertion in the index.
        let mut pending: Vec<(&str, &[u8])> = Vec::with_capacity(entries.len());
        for (manifest_id, token) in entries {
            let Some(manifest_id) = manifest_id.as_text().filter(|id| !id.is_empty()) else {
                return false;
            };
            let Some(token) = token.as_bytes().filter(|token| !token.is_empty()) else {
                return false;
            };
            // Duplicate keys in one map are a malformed assertion, not a
            // second token for the same manifest.
            if pending.iter().any(|(seen, _)| *seen == manifest_id) {
                return false;
            }
            if self.tokens.get(manifest_id).map_or(0, Vec::len) >= MAX_TOKENS_PER_MANIFEST {
                return false;
            }
            pending.push((manifest_id, token));
        }
        for (manifest_id, token) in pending {
            self.tokens
                .entry(manifest_id.to_string())
                .or_default()
                .push(token.to_vec());
        }
        true
    }

    /// Tokens recorded for a C2PA Manifest identifier, in encounter order.
    pub fn candidates(&self, manifest_id: &str) -> &[Vec<u8>] {
        self.tokens
            .get(manifest_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Index one timestamp assertion, emitting `assertion.timestamp.malformed`
/// when its shape is not the one VAL-TIME-0006 requires.
pub fn index_timestamp_assertion(
    index: &mut TimestampAssertionIndex,
    scope: TimestampAssertionScope,
    assertion_cbor: &[u8],
    results: &mut ValidationResults,
    url: &str,
) -> bool {
    if index.insert(scope, assertion_cbor) {
        return true;
    }
    results.push_failure(
        ASSERTION_TIMESTAMP_MALFORMED,
        url.to_string(),
        "c2pa.time-stamp assertion is not a non-empty map of manifest identifiers to tokens, or exceeds verifier limits".into(),
    );
    false
}

/// Build the store-wide timestamp index for one verification.
///
/// A time-stamp manifest is an ordinary manifest whose `c2pa.time-stamp`
/// assertion names the manifest it time-stamps. VAL-TIME-0008 requires
/// ignoring any such manifest reached through an ingredient, so a manifest that
/// any other manifest declares as an ingredient contributes no tokens: the
/// time-stamp manifest itself sits above the graph and is never an ingredient,
/// while one nested under an ingredient always is.
pub fn index_store_timestamp_assertions(
    manifests: &[crate::c2pa_core::jumbf::ParsedManifest<'_>],
    ingredient_labels: &std::collections::HashSet<String>,
    results: &mut ValidationResults,
) -> TimestampAssertionIndex {
    let mut index = TimestampAssertionIndex::default();
    for manifest in manifests {
        let scope = if ingredient_labels.contains(manifest.label.as_str()) {
            TimestampAssertionScope::Ingredient
        } else {
            TimestampAssertionScope::Manifest
        };
        for (label, payload) in &manifest.assertions {
            if label != TIME_STAMP_ASSERTION_LABEL {
                continue;
            }
            index_timestamp_assertion(
                &mut index,
                scope,
                payload,
                results,
                &format!(
                    "self#jumbf=/c2pa/{}/c2pa.assertions/{TIME_STAMP_ASSERTION_LABEL}",
                    manifest.label
                ),
            );
        }
    }
    index
}

/// Which evidence established the accepted signing time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    /// A `sigTst` or `sigTst2` COSE header.
    CoseHeader(TimestampHeaderVersion),
    /// A `c2pa.time-stamp` assertion entry for this manifest.
    TimeStampAssertion,
}

/// An accepted, TSA-authenticated signing time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedTimestamp {
    /// The attested RFC 3161 `genTime`.
    pub generated_at: OffsetDateTime,
    /// The evidence the fallback rules selected.
    pub source: TimestampSource,
}

/// Validate every timestamp evidence source for one claim signature.
///
/// Returns the attested time only after the RFC 3161 message imprint, CMS
/// signature, timestamping EKU, TSA leaf profile, chain validity at `genTime`,
/// and chain to a supplied TSA trust anchor have all passed.
// One evidence pass over several independent inputs; grouping them behind a
// struct would only move the same fields one indirection away.
#[allow(clippy::too_many_arguments)]
pub fn validate_timestamp_evidence(
    cose_sign1: &[u8],
    claim_cbor: &[u8],
    manifest_id: &str,
    assertions: &TimestampAssertionIndex,
    tsa_trust: Option<&TrustList>,
    verification_time: OffsetDateTime,
    results: &mut ValidationResults,
    url: &str,
) -> Option<TrustedTimestamp> {
    let evidence = match parse_timestamp_header(cose_sign1, claim_cbor) {
        Ok(evidence) => evidence,
        Err(_) => {
            results.push_informational(
                TIME_STAMP_MALFORMED,
                url.to_string(),
                "claim signature structure does not expose a readable timestamp header".into(),
            );
            TimestampHeaderEvidence::Absent
        }
    };

    let mut deferred: Option<(TokenFailure, &'static str)> = None;
    match evidence {
        TimestampHeaderEvidence::Ignored(defect) => results.push_informational(
            TIME_STAMP_MALFORMED,
            url.to_string(),
            defect.explanation().into(),
        ),
        TimestampHeaderEvidence::Present(header) => {
            match validate_token(
                &header.token_der,
                &header.message_imprint_input,
                tsa_trust,
                verification_time,
            ) {
                TokenOutcome::Trusted(generated_at) => {
                    report_trusted(results, url);
                    if header.version == TimestampHeaderVersion::SigTst {
                        results.push_informational(
                            TIMESTAMP_V1_SIGNATURE_UNBOUND,
                            url.to_string(),
                            "signing time came from a deprecated sigTst (v1) token, whose message imprint covers the protected header and claim but not the signature value".into(),
                        );
                    }
                    return Some(TrustedTimestamp {
                        generated_at,
                        source: TimestampSource::CoseHeader(header.version),
                    });
                }
                TokenOutcome::Failed(failure, reason) => deferred = Some((failure, reason)),
            }
        }
        TimestampHeaderEvidence::Absent => {}
    }

    // VAL-TIME-0002..0005: fall back to the `c2pa.time-stamp` assertions
    // recorded for this manifest identifier, trying each until one validates.
    let candidates = assertions.candidates(manifest_id);
    if !candidates.is_empty() {
        if let Ok(assertion_input) = timestamp_assertion_input(cose_sign1) {
            let mut assertion_failure = None;
            for token in candidates {
                match validate_token(token, &assertion_input, tsa_trust, verification_time) {
                    TokenOutcome::Trusted(generated_at) => {
                        report_trusted(results, url);
                        return Some(TrustedTimestamp {
                            generated_at,
                            source: TimestampSource::TimeStampAssertion,
                        });
                    }
                    TokenOutcome::Failed(failure, reason) => {
                        assertion_failure.get_or_insert((failure, reason));
                    }
                }
            }
            deferred = assertion_failure.or(deferred);
        }
    }

    if let Some((failure, reason)) = deferred {
        report_failure(failure, reason, results, url);
    }
    None
}

/// Validate the optional protected `iat` "claimed time of signing"
/// (VAL-CRYP-0029..0031).
///
/// Absence produces no status. Presence yields exactly one informational code:
/// `timeOfSigning.insideValidity` when the attested time falls inside every
/// certificate in the signer chain and is not later than a trusted timestamp,
/// `timeOfSigning.outsideValidity` otherwise. Neither affects the verdict; the
/// value is a claim generator's unattested assertion about its own clock.
pub fn validate_optional_iat(
    cose_sign1: &[u8],
    signer_chain_der: &[Vec<u8>],
    trusted_timestamp: Option<&TrustedTimestamp>,
    results: &mut ValidationResults,
    url: &str,
) {
    let signed_at = match protected_iat(cose_sign1) {
        Ok(None) => return,
        Ok(Some(iat)) => numeric_date_to_time(iat),
        Err(_) => None,
    };
    let Some(signed_at) = signed_at else {
        results.push_informational(
            TIME_OF_SIGNING_OUTSIDE_VALIDITY,
            url.to_string(),
            "the protected iat header is not a usable NumericDate".into(),
        );
        return;
    };
    let chain_valid = !signer_chain_der.is_empty()
        && signer_chain_der
            .iter()
            .all(|certificate| certificate_valid_at(certificate, signed_at));
    let not_after_timestamp = trusted_timestamp
        .map(|timestamp| signed_at <= timestamp.generated_at)
        .unwrap_or(true);
    if chain_valid && not_after_timestamp {
        results.push_informational(
            TIME_OF_SIGNING_INSIDE_VALIDITY,
            url.to_string(),
            "the claimed time of signing falls inside the signer chain's validity".into(),
        );
    } else {
        results.push_informational(
            TIME_OF_SIGNING_OUTSIDE_VALIDITY,
            url.to_string(),
            "the claimed time of signing falls outside the signer chain's validity or is later than the attested timestamp".into(),
        );
    }
}

/// Convert a CBOR `NumericDate` (seconds since the epoch) to a UTC instant.
pub(super) fn numeric_date_to_time(seconds: f64) -> Option<OffsetDateTime> {
    let whole = seconds.trunc();
    if !(i64::MIN as f64..=i64::MAX as f64).contains(&whole) {
        return None;
    }
    let base = OffsetDateTime::from_unix_timestamp(whole as i64).ok()?;
    let nanos = ((seconds - whole) * 1_000_000_000.0).round() as i64;
    base.checked_add(time::Duration::nanoseconds(nanos))
}

pub(super) enum TokenOutcome {
    Trusted(OffsetDateTime),
    Failed(TokenFailure, &'static str),
}

/// The registered status placement for one failed timestamp token.
#[derive(Clone, Copy)]
pub(super) enum TokenFailure {
    /// Structural defect: `timeStamp.malformed` (VAL-CRYP-0019/0022).
    Malformed,
    /// Bad CMS signature or message imprint: `timeStamp.mismatch`
    /// (VAL-CRYP-0022/0023).
    Mismatch,
    /// Unsupported algorithm, or no chain to a TSA anchor: `timeStamp.untrusted`
    /// (VAL-CRYP-0021/0022/0024).
    Untrusted,
    /// Unacceptable TSA credential: `timeStamp.untrusted` plus the optional
    /// `timeStamp.credentialInvalid` (VAL-CRYP-0024/0025).
    CredentialInvalid,
    /// `genTime` outside the TSA chain validity: `timeStamp.outsideValidity`
    /// ALONE (VAL-CRYP-0026).
    OutsideValidity,
}

pub(super) fn validate_token(
    token_der: &[u8],
    message_imprint_input: &[u8],
    trust: Option<&TrustList>,
    verification_time: OffsetDateTime,
) -> TokenOutcome {
    // An empty trust list still runs every structural and cryptographic check;
    // only the final anchor lookup reports `no_tsa_anchors`. That ordering is
    // what lets a caller with no TSA configuration still see a malformed or
    // mismatched token for what it is.
    let empty = TrustList::default();
    let verified = verify_timestamp_token(
        token_der,
        message_imprint_input,
        trust.unwrap_or(&empty),
        verification_time,
    );
    if let (true, Some(generated_at)) = (verified.verified, verified.time) {
        return TokenOutcome::Trusted(generated_at);
    }
    let reason = verified.error.unwrap_or("timestamp_parse_error");
    TokenOutcome::Failed(classify(reason), reason)
}

/// Map a `c2pa-trust` inspection reason onto its registered status placement.
fn classify(error: &str) -> TokenFailure {
    match error {
        // VAL-CRYP-0022/0023: the CMS signature or a digest did not match.
        "timestamp_imprint_mismatch"
        | "timestamp_message_digest_mismatch"
        | "timestamp_signature_invalid" => TokenFailure::Mismatch,
        // VAL-CRYP-0021/0022: an algorithm outside the allowed list.
        "timestamp_imprint_hash_unsupported" | "timestamp_digest_hash_unsupported" => {
            TokenFailure::Untrusted
        }
        // VAL-CRYP-0024: no chain to an anchor in the TSA trust list.
        "no_tsa_anchors" | "timestamp_tsa_untrusted" => TokenFailure::Untrusted,
        // VAL-CRYP-0026: attested time outside the TSA chain's validity.
        "timestamp_tsa_outside_validity" => TokenFailure::OutsideValidity,
        // VAL-CRYP-0024/0025: the TSA credential itself is unacceptable.
        "timestamp_signer_cert_missing"
        | "timestamp_signer_cert_invalid"
        | "timestamp_eku_invalid"
        | "timestamp_tsa_leaf_profile_invalid" => TokenFailure::CredentialInvalid,
        // Everything else is a structural defect in the token.
        _ => TokenFailure::Malformed,
    }
}

fn report_trusted(results: &mut ValidationResults, url: &str) {
    results.push_success(
        TIME_STAMP_VALIDATED,
        url.to_string(),
        "RFC 3161 timestamp signature and message imprint validated".into(),
    );
    results.push_success(
        TIME_STAMP_TRUSTED,
        url.to_string(),
        "timestamp authority chains to a supplied TSA trust anchor".into(),
    );
}

fn report_failure(failure: TokenFailure, reason: &str, results: &mut ValidationResults, url: &str) {
    match failure {
        TokenFailure::Malformed => results.push_informational(
            TIME_STAMP_MALFORMED,
            url.to_string(),
            format!("the RFC 3161 timestamp token is structurally malformed ({reason})"),
        ),
        TokenFailure::Mismatch => results.push_informational(
            TIME_STAMP_MISMATCH,
            url.to_string(),
            format!("the timestamp token's CMS signature or message imprint did not match ({reason})"),
        ),
        TokenFailure::Untrusted => results.push_informational(
            TIME_STAMP_UNTRUSTED,
            url.to_string(),
            format!("the timestamp authority does not chain to a supplied TSA trust anchor, or used an algorithm outside the allowed list ({reason})"),
        ),
        TokenFailure::CredentialInvalid => {
            results.push_informational(
                TIME_STAMP_CREDENTIAL_INVALID,
                url.to_string(),
                format!("the timestamp authority's certificate is not acceptable for timestamping ({reason})"),
            );
            results.push_informational(
                TIME_STAMP_UNTRUSTED,
                url.to_string(),
                "a trust chain to a TSA anchor could not be built from an unacceptable credential"
                    .into(),
            );
        }
        // VAL-CRYP-0026 places this code alone: an expired TSA chain is a
        // distinct, more specific outcome than an untrusted one.
        TokenFailure::OutsideValidity => results.push_informational(
            TIME_STAMP_OUTSIDE_VALIDITY,
            url.to_string(),
            format!("the attested genTime falls outside the TSA chain's validity window ({reason})"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::{encode, Profile};
    use crate::c2pa_trust::timestamp_fixture::TestTsa;
    use time::macros::datetime;

    fn enc(value: &Value) -> Vec<u8> {
        encode(value, Profile::LegacyPipelineBDefinite).expect("encode")
    }

    fn index_payload(payload: &Value) -> (bool, ValidationResults, TimestampAssertionIndex) {
        let mut index = TimestampAssertionIndex::default();
        let mut results = ValidationResults::default();
        let accepted = index_timestamp_assertion(
            &mut index,
            TimestampAssertionScope::Manifest,
            &enc(payload),
            &mut results,
            "self#jumbf=/c2pa/m/c2pa.assertions/c2pa.time-stamp",
        );
        (accepted, results, index)
    }

    const CLAIM: &[u8] = b"claim-cbor-payload";
    const SIGNATURE: &[u8] = b"cose-signature-bytes";
    const MANIFEST_ID: &str = "urn:c2pa:manifest";
    const URL: &str = "self#jumbf=/c2pa/urn:c2pa:manifest/c2pa.signature";

    fn tst_header(label: &str, token: Vec<u8>) -> Value {
        Value::Map(vec![(
            Value::Text(label.into()),
            Value::Map(vec![(
                Value::Text("tstTokens".into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text("val".into()),
                    Value::Bytes(token),
                )])]),
            )]),
        )])
    }

    /// Build a COSE_Sign1 whose unprotected bucket carries `header`.
    fn cose(header: Option<Value>) -> Vec<u8> {
        let unprotected = match header {
            Some(Value::Map(entries)) => Value::Map(entries),
            _ => Value::Map(Vec::new()),
        };
        enc(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(enc(&Value::Map(vec![(
                    Value::Integer(1),
                    Value::Integer(-7),
                )]))),
                unprotected,
                Value::Null,
                Value::Bytes(SIGNATURE.to_vec()),
            ])),
        ))
    }

    /// The exact bytes `label`'s message imprint must cover for this COSE
    /// shape. Derived from a placeholder-token COSE, since the imprint input
    /// depends only on the protected bucket and the signature.
    fn imprint_input(label: &str) -> Vec<u8> {
        // `sigTst` carries a TimeStampResp, `sigTst2` the bare token; the
        // placeholder must satisfy whichever shape the label declares.
        let placeholder = match label {
            "sigTst" => TestTsa::response(0, &[0x30, 0x00]),
            _ => vec![0x30, 0x00],
        };
        let probe = cose(Some(tst_header(label, placeholder)));
        match parse_timestamp_header(&probe, CLAIM).expect("probe header") {
            TimestampHeaderEvidence::Present(header) => header.message_imprint_input,
            other => panic!("probe header did not parse: {other:?}"),
        }
    }

    fn run(
        cose_sign1: &[u8],
        index: &TimestampAssertionIndex,
        trust: Option<&TrustList>,
        now: OffsetDateTime,
    ) -> (Option<TrustedTimestamp>, ValidationResults) {
        let mut results = ValidationResults::default();
        let trusted = validate_timestamp_evidence(
            cose_sign1,
            CLAIM,
            MANIFEST_ID,
            index,
            trust,
            now,
            &mut results,
            URL,
        );
        (trusted, results)
    }

    fn codes(statuses: &[super::super::StatusCode]) -> Vec<&str> {
        statuses.iter().map(|s| s.code.as_str()).collect()
    }

    #[test]
    fn a_trusted_legacy_sig_tst_establishes_signing_time_with_its_caveat() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let gen_time = datetime!(2026-06-01 12:00 UTC);
        let response = TestTsa::response(0, &tsa.token(&imprint_input("sigTst"), gen_time));
        let cose = cose(Some(tst_header("sigTst", response)));

        let (trusted, results) = run(
            &cose,
            &TimestampAssertionIndex::default(),
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );

        // C2PA 2.4 deprecates the v1 payload for generators but requires a
        // validator to process one (Claims "Choosing the Payload"), and
        // VAL-CRYP-0028 uses the attested time of any trusted, validated
        // time-stamp.
        assert_eq!(
            trusted,
            Some(TrustedTimestamp {
                generated_at: gen_time,
                source: TimestampSource::CoseHeader(TimestampHeaderVersion::SigTst),
            })
        );
        assert_eq!(
            codes(&results.success),
            vec![TIME_STAMP_VALIDATED, TIME_STAMP_TRUSTED]
        );
        // A v1 imprint covers the protected header and the claim, not the
        // signature value, so the caveat must be reported.
        assert_eq!(
            codes(&results.informational),
            vec![TIMESTAMP_V1_SIGNATURE_UNBOUND]
        );
    }

    #[test]
    fn a_trusted_sig_tst2_establishes_signing_time_without_the_v1_caveat() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let gen_time = datetime!(2026-06-01 12:00 UTC);
        let cose = cose(Some(tst_header(
            "sigTst2",
            tsa.token(&imprint_input("sigTst2"), gen_time),
        )));

        let (trusted, results) = run(
            &cose,
            &TimestampAssertionIndex::default(),
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );

        assert_eq!(
            trusted.map(|timestamp| timestamp.generated_at),
            Some(gen_time)
        );
        assert!(results.informational.is_empty());
    }

    #[test]
    fn a_time_stamp_assertion_token_is_used_when_no_header_validates() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let gen_time = datetime!(2026-06-01 12:00 UTC);
        // The assertion token's imprint covers the raw COSE signature bytes.
        let token = tsa.token(SIGNATURE, gen_time);
        let mut index = TimestampAssertionIndex::default();
        assert!(index.insert(
            TimestampAssertionScope::Manifest,
            &enc(&Value::Map(vec![(
                Value::Text(MANIFEST_ID.into()),
                Value::Bytes(token),
            )])),
        ));

        // No header at all: the assertion is the only evidence.
        let (trusted, _) = run(
            &cose(None),
            &index,
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );
        assert_eq!(
            trusted,
            Some(TrustedTimestamp {
                generated_at: gen_time,
                source: TimestampSource::TimeStampAssertion,
            })
        );

        // A header whose token does not validate must not suppress the
        // fallback (VAL-TIME-0002).
        let broken = cose(Some(tst_header(
            "sigTst2",
            b"\x30\x03\x02\x01\x00".to_vec(),
        )));
        let (trusted, _) = run(
            &broken,
            &index,
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );
        assert_eq!(
            trusted.map(|timestamp| timestamp.source),
            Some(TimestampSource::TimeStampAssertion)
        );

        // An entry for another manifest never applies to this one.
        let mut other = TimestampAssertionIndex::default();
        assert!(other.insert(
            TimestampAssertionScope::Manifest,
            &enc(&Value::Map(vec![(
                Value::Text("urn:c2pa:other".into()),
                Value::Bytes(tsa.token(SIGNATURE, gen_time)),
            )])),
        ));
        let (trusted, _) = run(
            &cose(None),
            &other,
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );
        assert_eq!(trusted, None);
    }

    #[test]
    fn gen_time_outside_the_tsa_validity_reports_outside_validity_alone() {
        // The TSA credential expires before the attested time.
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2026-01-01 0:00 UTC),
        );
        let gen_time = datetime!(2026-06-01 12:00 UTC);
        let cose = cose(Some(tst_header(
            "sigTst2",
            tsa.token(&imprint_input("sigTst2"), gen_time),
        )));

        let (trusted, results) = run(
            &cose,
            &TimestampAssertionIndex::default(),
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );

        assert_eq!(trusted, None);
        // VAL-CRYP-0026 places exactly this code, and not `timeStamp.untrusted`
        // alongside it: the authority is trusted, it was simply used after its
        // certificate expired.
        assert_eq!(
            codes(&results.informational),
            vec![TIME_STAMP_OUTSIDE_VALIDITY]
        );
        assert!(tsa.not_after() < gen_time);
    }

    #[test]
    fn a_token_that_does_not_bind_the_c2pa_input_is_a_mismatch() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let cose = cose(Some(tst_header(
            "sigTst2",
            tsa.token(b"some other document", datetime!(2026-06-01 12:00 UTC)),
        )));

        let (trusted, results) = run(
            &cose,
            &TimestampAssertionIndex::default(),
            Some(&tsa.trust_list()),
            datetime!(2026-09-01 0:00 UTC),
        );

        assert_eq!(trusted, None);
        assert_eq!(codes(&results.informational), vec![TIME_STAMP_MISMATCH]);
    }

    #[test]
    fn a_structurally_sound_token_without_tsa_anchors_is_untrusted_not_malformed() {
        let tsa = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2030-01-01 0:00 UTC),
        );
        let cose = cose(Some(tst_header(
            "sigTst2",
            tsa.token(&imprint_input("sigTst2"), datetime!(2026-06-01 12:00 UTC)),
        )));

        let (trusted, results) = run(
            &cose,
            &TimestampAssertionIndex::default(),
            None,
            datetime!(2026-09-01 0:00 UTC),
        );

        assert_eq!(trusted, None);
        assert_eq!(codes(&results.informational), vec![TIME_STAMP_UNTRUSTED]);
    }

    /// Build a COSE_Sign1 whose protected bucket carries `iat` (label 6).
    fn cose_with_iat(iat: Option<Value>) -> Vec<u8> {
        let mut protected = vec![(Value::Integer(1), Value::Integer(-7))];
        if let Some(iat) = iat {
            protected.push((Value::Integer(6), iat));
        }
        enc(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(enc(&Value::Map(protected))),
                Value::Map(Vec::new()),
                Value::Null,
                Value::Bytes(SIGNATURE.to_vec()),
            ])),
        ))
    }

    #[test]
    fn the_claimed_time_of_signing_is_reported_against_the_signer_chain() {
        // A leaf valid for 2025 only; `TestTsa`'s leaf is a convenient
        // certificate with a known window.
        let signer = TestTsa::new(
            datetime!(2025-01-01 0:00 UTC),
            datetime!(2026-01-01 0:00 UTC),
        );
        let chain: Vec<Vec<u8>> = signer
            .trust_list()
            .certificates()
            .map(<[u8]>::to_vec)
            .collect();

        let report = |iat: Option<Value>, trusted: Option<TrustedTimestamp>| {
            let mut results = ValidationResults::default();
            validate_optional_iat(
                &cose_with_iat(iat),
                &chain,
                trusted.as_ref(),
                &mut results,
                URL,
            );
            codes(&results.informational)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };

        // No `iat`: validating it is optional (VAL-CRYP-0029), so silence.
        assert!(report(None, None).is_empty());

        let inside = datetime!(2025-06-01 0:00 UTC).unix_timestamp();
        assert_eq!(
            report(Some(Value::Integer(inside as i128)), None),
            vec![TIME_OF_SIGNING_INSIDE_VALIDITY]
        );

        let outside = datetime!(2027-06-01 0:00 UTC).unix_timestamp();
        assert_eq!(
            report(Some(Value::Integer(outside as i128)), None),
            vec![TIME_OF_SIGNING_OUTSIDE_VALIDITY]
        );

        // VAL-CRYP-0030: the claimed time may not be later than the time a
        // trusted time-stamp attests.
        let timestamp = TrustedTimestamp {
            generated_at: datetime!(2025-03-01 0:00 UTC),
            source: TimestampSource::TimeStampAssertion,
        };
        assert_eq!(
            report(Some(Value::Integer(inside as i128)), Some(timestamp)),
            vec![TIME_OF_SIGNING_OUTSIDE_VALIDITY]
        );

        // An unusable NumericDate is reported, never silently ignored.
        assert_eq!(
            report(Some(Value::Text("yesterday".into())), None),
            vec![TIME_OF_SIGNING_OUTSIDE_VALIDITY]
        );
    }

    #[test]
    fn well_formed_assertion_indexes_tokens_by_manifest_identifier() {
        let payload = Value::Map(vec![
            (
                Value::Text("urn:c2pa:one".into()),
                Value::Bytes(b"token-one".to_vec()),
            ),
            (
                Value::Text("urn:c2pa:two".into()),
                Value::Bytes(b"token-two".to_vec()),
            ),
        ]);
        let (accepted, results, index) = index_payload(&payload);
        assert!(accepted);
        assert!(results.failure.is_empty());
        assert_eq!(index.candidates("urn:c2pa:one"), [b"token-one".to_vec()]);
        assert_eq!(index.candidates("urn:c2pa:two"), [b"token-two".to_vec()]);
        assert!(index.candidates("urn:c2pa:absent").is_empty());
    }

    #[test]
    fn malformed_assertion_shapes_fail_the_claim_and_index_nothing() {
        for payload in [
            // Not a map.
            Value::Array(vec![Value::Bytes(b"token".to_vec())]),
            // Empty map: VAL-TIME-0006 requires at least one pair.
            Value::Map(Vec::new()),
            // Empty manifest identifier.
            Value::Map(vec![(
                Value::Text(String::new()),
                Value::Bytes(b"t".to_vec()),
            )]),
            // Non-text key.
            Value::Map(vec![(Value::Integer(1), Value::Bytes(b"t".to_vec()))]),
            // Non-bytes value.
            Value::Map(vec![(
                Value::Text("urn:c2pa:one".into()),
                Value::Text("t".into()),
            )]),
            // Empty token.
            Value::Map(vec![(
                Value::Text("urn:c2pa:one".into()),
                Value::Bytes(Vec::new()),
            )]),
        ] {
            let (accepted, results, index) = index_payload(&payload);
            assert!(!accepted, "{payload:?} must be rejected");
            assert_eq!(
                results
                    .failure
                    .iter()
                    .map(|status| status.code.as_str())
                    .collect::<Vec<_>>(),
                vec![ASSERTION_TIMESTAMP_MALFORMED]
            );
            assert!(index.candidates("urn:c2pa:one").is_empty());
        }
    }

    #[test]
    fn a_defect_late_in_the_assertion_indexes_none_of_its_entries() {
        let payload = Value::Map(vec![
            (
                Value::Text("urn:c2pa:one".into()),
                Value::Bytes(b"token-one".to_vec()),
            ),
            (Value::Text("urn:c2pa:two".into()), Value::Null),
        ]);
        let (accepted, _, index) = index_payload(&payload);
        assert!(!accepted);
        assert!(index.candidates("urn:c2pa:one").is_empty());
    }

    #[test]
    fn ingredient_scoped_assertions_are_ignored_entirely() {
        let mut index = TimestampAssertionIndex::default();
        let mut results = ValidationResults::default();
        // A payload that would be a hard failure in manifest scope.
        let accepted = index_timestamp_assertion(
            &mut index,
            TimestampAssertionScope::Ingredient,
            &enc(&Value::Array(Vec::new())),
            &mut results,
            "self#jumbf=/c2pa/child/c2pa.assertions/c2pa.time-stamp",
        );
        assert!(
            accepted,
            "an ingredient timestamp assertion never fails the claim"
        );
        assert!(results.failure.is_empty());
        assert!(index.candidates("urn:c2pa:one").is_empty());
    }

    #[test]
    fn inspection_reasons_map_to_their_registered_status_placement() {
        let report = |error: &str| {
            let mut results = ValidationResults::default();
            report_failure(classify(error), error, &mut results, "url");
            results
                .informational
                .iter()
                .map(|status| status.code.clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(report("timestamp_imprint_mismatch"), [TIME_STAMP_MISMATCH]);
        assert_eq!(report("timestamp_signature_invalid"), [TIME_STAMP_MISMATCH]);
        assert_eq!(
            report("timestamp_imprint_hash_unsupported"),
            [TIME_STAMP_UNTRUSTED]
        );
        assert_eq!(report("timestamp_tsa_untrusted"), [TIME_STAMP_UNTRUSTED]);
        assert_eq!(report("no_tsa_anchors"), [TIME_STAMP_UNTRUSTED]);
        assert_eq!(
            report("timestamp_eku_invalid"),
            [TIME_STAMP_CREDENTIAL_INVALID, TIME_STAMP_UNTRUSTED]
        );
        assert_eq!(report("timestamp_parse_error"), [TIME_STAMP_MALFORMED]);
        assert_eq!(
            report("timestamp_signer_info_count_invalid"),
            [TIME_STAMP_MALFORMED]
        );
        // VAL-CRYP-0026: outsideValidity stands alone. Emitting untrusted
        // alongside it would report the TSA as unknown when it is in fact
        // trusted but was used outside its certificate's window.
        assert_eq!(
            report("timestamp_tsa_outside_validity"),
            [TIME_STAMP_OUTSIDE_VALIDITY]
        );
    }
}
