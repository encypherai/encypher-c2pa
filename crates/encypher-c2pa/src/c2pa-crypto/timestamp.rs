// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA `sigTst` and `sigTst2` timestamp-header parsing.
//!
//! Both header generations are closed CDDL shapes: a single-entry map whose
//! only member is `tstTokens`, an array of single-entry `{ "val": bstr }` maps.
//! This module enforces that shape, the mutual exclusivity of the two header
//! labels, the single-token cardinality rule (VAL-CRYP-0017), and the RFC 3161
//! `PKIStatusInfo` success requirement for the legacy `sigTst` response
//! (VAL-CRYP-0019). It also derives the exact bytes whose digest must appear in
//! the token's message imprint, which differ between the two generations.
//!
//! Nothing here touches the network.

use crate::c2pa_cbor::{decode, encode, Profile, Value};

use crate::c2pa_crypto::error::CryptoError;

/// CBOR tag for a `COSE_Sign1_Tagged` structure (RFC 9052).
const COSE_SIGN1_TAG: u64 = 18;
/// COSE protected-header label for the claimed time of signing (RFC 8392).
const COSE_HDR_IAT: i128 = 6;
const HEADER_SIG_TST: &str = "sigTst";
const HEADER_SIG_TST2: &str = "sigTst2";
const TOKENS_KEY: &str = "tstTokens";
const TOKEN_VALUE_KEY: &str = "val";

/// CBOR profile used for all COSE substructures.
const PROFILE: Profile = Profile::LegacyPipelineBDefinite;

/// The C2PA timestamp header generation carried by a claim signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampHeaderVersion {
    /// Legacy `sigTst`: the header carries an RFC 3161 `TimeStampResp`, and the
    /// message imprint covers a CounterSignature over the claim payload.
    SigTst,
    /// Current `sigTst2`: the header carries the bare RFC 3161
    /// `TimeStampToken`, and the imprint covers the encoded COSE signature.
    SigTst2,
}

/// A structurally valid, cardinality-safe timestamp header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampHeader {
    /// Which header label supplied this token.
    pub version: TimestampHeaderVersion,
    /// DER-encoded CMS `TimeStampToken`, unwrapped from the legacy
    /// `TimeStampResp` when `version` is [`TimestampHeaderVersion::SigTst`].
    pub token_der: Vec<u8>,
    /// Exact bytes the RFC 3161 message imprint must digest.
    pub message_imprint_input: Vec<u8>,
}

/// Why a present timestamp header must be ignored.
///
/// Each defect is reported as the informational `timeStamp.malformed` status
/// and the header contributes no signing time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampHeaderDefect {
    /// Both `sigTst` and `sigTst2` were present. They are mutually exclusive.
    ConflictingHeaders,
    /// The header did not have the closed CDDL map shape.
    MalformedShape,
    /// `tstTokens` did not contain exactly one entry (VAL-CRYP-0017).
    InvalidTokenCardinality,
    /// The legacy `sigTst` value was not a `TimeStampResp` whose
    /// `PKIStatusInfo.status` is 0 (granted) or 1 (grantedWithMods).
    InvalidTimeStampResponse,
}

impl TimestampHeaderDefect {
    /// Stable explanation for the informational status.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::ConflictingHeaders => {
                "sigTst and sigTst2 are mutually exclusive; both were present"
            }
            Self::MalformedShape => {
                "timestamp header does not have the closed sigTst/sigTst2 shape"
            }
            Self::InvalidTokenCardinality => "tstTokens does not contain exactly one token",
            Self::InvalidTimeStampResponse => {
                "legacy sigTst response was not a granted RFC 3161 TimeStampResp"
            }
        }
    }
}

/// Timestamp evidence selected from the COSE unprotected header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampHeaderEvidence {
    /// Neither header label was present.
    Absent,
    /// One well-formed header and its derived message-imprint input.
    Present(TimestampHeader),
    /// Timestamp material was present but must be ignored.
    Ignored(TimestampHeaderDefect),
}

/// Parse the C2PA timestamp header and derive its message-imprint input.
///
/// `claim_cbor` is the exact serialized claim payload: the legacy `sigTst`
/// imprint covers a CounterSignature over that payload, while `sigTst2` covers
/// a CounterSignature over the serialized COSE signature byte string.
///
/// C2PA 2.4 allows a header in either bucket (VAL-CRYP-0016), so both are
/// searched; a label occurring in both buckets, or twice in one bucket, is a
/// malformed shape.
pub fn parse_timestamp_header(
    cose_sign1: &[u8],
    claim_cbor: &[u8],
) -> Result<TimestampHeaderEvidence, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let signature = array[3]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("signature is not a byte string".into()))?;

    let protected = decode(protected_bytes)?;
    let buckets: [&[(Value, Value)]; 2] = [
        protected.as_map().unwrap_or(&[]),
        array[1].as_map().unwrap_or(&[]),
    ];
    let sig_tst = lookup_across_buckets(&buckets, HEADER_SIG_TST);
    let sig_tst2 = lookup_across_buckets(&buckets, HEADER_SIG_TST2);
    let (version, header) = match (sig_tst, sig_tst2) {
        (HeaderLookup::Absent, HeaderLookup::Absent) => return Ok(TimestampHeaderEvidence::Absent),
        (HeaderLookup::Duplicate, _) | (_, HeaderLookup::Duplicate) => {
            return Ok(TimestampHeaderEvidence::Ignored(
                TimestampHeaderDefect::MalformedShape,
            ))
        }
        (HeaderLookup::One(_), HeaderLookup::One(_)) => {
            return Ok(TimestampHeaderEvidence::Ignored(
                TimestampHeaderDefect::ConflictingHeaders,
            ))
        }
        (HeaderLookup::One(value), HeaderLookup::Absent) => (TimestampHeaderVersion::SigTst, value),
        (HeaderLookup::Absent, HeaderLookup::One(value)) => {
            (TimestampHeaderVersion::SigTst2, value)
        }
    };

    let stored = match parse_single_token(header) {
        Ok(token) => token,
        Err(defect) => return Ok(TimestampHeaderEvidence::Ignored(defect)),
    };
    let token_der = match version {
        TimestampHeaderVersion::SigTst => match granted_timestamp_token(stored) {
            Some(token) => token.to_vec(),
            None => {
                return Ok(TimestampHeaderEvidence::Ignored(
                    TimestampHeaderDefect::InvalidTimeStampResponse,
                ))
            }
        },
        TimestampHeaderVersion::SigTst2 => stored.to_vec(),
    };
    let message_imprint_input = match version {
        TimestampHeaderVersion::SigTst => counter_signature_input(protected_bytes, claim_cbor)?,
        TimestampHeaderVersion::SigTst2 => {
            let serialized_signature = encode(&Value::Bytes(signature.to_vec()), PROFILE)?;
            counter_signature_input(protected_bytes, &serialized_signature)?
        }
    };

    Ok(TimestampHeaderEvidence::Present(TimestampHeader {
        version,
        token_der,
        message_imprint_input,
    }))
}

/// Return the raw COSE signature bytes.
///
/// A `c2pa.time-stamp` assertion token (C2PA 2.4 "Time-stamps in a separate
/// assertion") uses these bytes directly as its RFC 3161 message-imprint input.
pub fn timestamp_assertion_input(cose_sign1: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    array[3]
        .as_bytes()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| CryptoError::Malformed("signature is not a byte string".into()))
}

/// Read the optional protected COSE `iat` (label 6) `NumericDate`.
///
/// `Ok(None)` means the claim generator did not attest a time of signing.
/// Non-negative integers and finite non-negative floats are accepted; a
/// duplicated, negative, non-finite, or wrongly typed value is an error.
/// A value in the unprotected bucket is not integrity-protected and is ignored.
pub fn protected_iat(cose_sign1: &[u8]) -> Result<Option<f64>, CryptoError> {
    let decoded = decode(cose_sign1)?;
    let array = cose_array(&decoded)?;
    let protected_bytes = array[0]
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a byte string".into()))?;
    let protected = decode(protected_bytes)?;
    let entries = protected
        .as_map()
        .ok_or_else(|| CryptoError::Malformed("protected header is not a map".into()))?;
    let mut found = None;
    for (key, value) in entries {
        if !matches!(key, Value::Integer(COSE_HDR_IAT)) {
            continue;
        }
        if found.is_some() {
            return Err(CryptoError::Malformed("duplicate protected iat".into()));
        }
        found = Some(match value {
            Value::Integer(seconds) if *seconds >= 0 => *seconds as f64,
            Value::Float(seconds) if seconds.is_finite() && *seconds >= 0.0 => *seconds,
            _ => return Err(CryptoError::Malformed("invalid protected iat".into())),
        });
    }
    Ok(found)
}

enum HeaderLookup<'a> {
    Absent,
    One(&'a Value),
    Duplicate,
}

/// Find `name` across the protected and unprotected buckets, treating any
/// repetition — within one bucket or across both — as a duplicate.
fn lookup_across_buckets<'a>(buckets: &[&'a [(Value, Value)]; 2], name: &str) -> HeaderLookup<'a> {
    let mut found = None;
    for bucket in buckets {
        for (key, candidate) in bucket.iter() {
            if key.as_text() != Some(name) {
                continue;
            }
            if found.is_some() {
                return HeaderLookup::Duplicate;
            }
            found = Some(candidate);
        }
    }
    found.map_or(HeaderLookup::Absent, HeaderLookup::One)
}

/// Enforce the closed `{ "tstTokens": [ { "val": bstr } ] }` header shape.
fn parse_single_token(header: &Value) -> Result<&[u8], TimestampHeaderDefect> {
    let entries = header
        .as_map()
        .ok_or(TimestampHeaderDefect::MalformedShape)?;
    if entries.len() != 1 || entries[0].0.as_text() != Some(TOKENS_KEY) {
        return Err(TimestampHeaderDefect::MalformedShape);
    }
    let Value::Array(tokens) = &entries[0].1 else {
        return Err(TimestampHeaderDefect::MalformedShape);
    };
    if tokens.len() != 1 {
        return Err(TimestampHeaderDefect::InvalidTokenCardinality);
    }
    let token_map = tokens[0]
        .as_map()
        .ok_or(TimestampHeaderDefect::MalformedShape)?;
    if token_map.len() != 1 || token_map[0].0.as_text() != Some(TOKEN_VALUE_KEY) {
        return Err(TimestampHeaderDefect::MalformedShape);
    }
    match &token_map[0].1 {
        Value::Bytes(token) if !token.is_empty() => Ok(token),
        _ => Err(TimestampHeaderDefect::MalformedShape),
    }
}

/// Build the RFC 9052 §4.4 `CounterSignature` `ToBeSigned` value.
fn counter_signature_input(body_protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(
        &Value::Array(vec![
            Value::Text("CounterSignature".to_string()),
            Value::Bytes(body_protected.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.to_vec()),
        ]),
        PROFILE,
    )
    .map_err(Into::into)
}

/// Borrow the four-element array inside a `COSE_Sign1_Tagged` value.
fn cose_array(value: &Value) -> Result<&[Value], CryptoError> {
    match value {
        Value::Tag(COSE_SIGN1_TAG, inner) => match inner.as_ref() {
            Value::Array(items) if items.len() == 4 => Ok(items),
            _ => Err(CryptoError::Malformed(
                "tag 18 content is not a 4-element array".into(),
            )),
        },
        _ => Err(CryptoError::Malformed(
            "not a COSE_Sign1_Tagged (tag 18) structure".into(),
        )),
    }
}

/// Unwrap the `timeStampToken` of an RFC 3161 `TimeStampResp` whose
/// `PKIStatusInfo.status` is 0 (granted) or 1 (grantedWithMods).
///
/// A minimal DER walk keeps this independent of the CMS layer, which only ever
/// sees a token that already passed the status check (VAL-CRYP-0019).
fn granted_timestamp_token(response: &[u8]) -> Option<&[u8]> {
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TST OPTIONAL }
    let mut outer = DerReader::new(read_tlv(response, 0x30)?);
    // PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
    let status_info = outer.next_tlv(0x30)?;
    let status = DerReader::new(status_info).next_tlv(0x02)?;
    // Accept only the single-byte encodings of 0 and 1.
    if !matches!(status, [0] | [1]) {
        return None;
    }
    let token = outer.remaining();
    if token.is_empty() {
        return None;
    }
    read_tlv(token, 0x30)?;
    Some(token)
}

/// Read one DER TLV of the expected tag from the front of `input`, returning
/// the full TLV (header included) only when it spans all of `input`.
fn read_tlv(input: &[u8], tag: u8) -> Option<&[u8]> {
    let mut reader = DerReader::new(input);
    let content = reader.next_tlv(tag)?;
    reader.remaining().is_empty().then_some(content)
}

/// Bounded forward-only DER reader over definite-length TLVs.
struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Consume the next TLV, which must carry `tag`, and return its content.
    fn next_tlv(&mut self, tag: u8) -> Option<&'a [u8]> {
        let bytes = self.input.get(self.offset..)?;
        if *bytes.first()? != tag {
            return None;
        }
        let first_length = *bytes.get(1)?;
        let (length, header) = if first_length < 0x80 {
            (usize::from(first_length), 2)
        } else {
            // Long form: the low seven bits count the length bytes. Reject the
            // indefinite form (0x80) and any length wider than a usize.
            let count = usize::from(first_length & 0x7f);
            if count == 0 || count > core::mem::size_of::<usize>() {
                return None;
            }
            let mut length = 0usize;
            for byte in bytes.get(2..2 + count)? {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            (length, 2 + count)
        };
        let end = header.checked_add(length)?;
        let content = bytes.get(header..end)?;
        self.offset += end;
        Some(content)
    }

    fn remaining(&self) -> &'a [u8] {
        self.input.get(self.offset..).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cose(protected: Vec<(Value, Value)>, unprotected: Vec<(Value, Value)>) -> Vec<u8> {
        let protected = encode(&Value::Map(protected), PROFILE).expect("encode protected");
        encode(
            &Value::Tag(
                COSE_SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(protected),
                    Value::Map(unprotected),
                    Value::Null,
                    Value::Bytes(b"signature-bytes".to_vec()),
                ])),
            ),
            PROFILE,
        )
        .expect("encode cose")
    }

    fn header(token: Vec<u8>) -> Value {
        Value::Map(vec![(
            Value::Text(TOKENS_KEY.into()),
            Value::Array(vec![Value::Map(vec![(
                Value::Text(TOKEN_VALUE_KEY.into()),
                Value::Bytes(token),
            )])]),
        )])
    }

    /// Minimal `TimeStampResp` carrying `status` and a SEQUENCE token body.
    fn timestamp_response(status: u8, token_body: &[u8]) -> Vec<u8> {
        let status_info = vec![0x30, 0x03, 0x02, 0x01, status];
        let mut token = vec![0x30, token_body.len() as u8];
        token.extend_from_slice(token_body);
        let mut content = status_info;
        content.extend_from_slice(&token);
        let mut response = vec![0x30, content.len() as u8];
        response.extend(content);
        response
    }

    #[test]
    fn sig_tst_and_sig_tst2_derive_different_message_imprint_inputs() {
        let claim = b"claim-cbor".to_vec();
        let token = timestamp_response(0, b"\x04\x02ok");

        let v1 = parse_timestamp_header(
            &cose(
                Vec::new(),
                vec![(Value::Text(HEADER_SIG_TST.into()), header(token.clone()))],
            ),
            &claim,
        )
        .expect("parse v1");
        let v2 = parse_timestamp_header(
            &cose(
                Vec::new(),
                vec![(
                    Value::Text(HEADER_SIG_TST2.into()),
                    header(b"\x30\x04\x04\x02ok".to_vec()),
                )],
            ),
            &claim,
        )
        .expect("parse v2");

        let TimestampHeaderEvidence::Present(v1) = v1 else {
            panic!("sigTst must parse as present evidence");
        };
        let TimestampHeaderEvidence::Present(v2) = v2 else {
            panic!("sigTst2 must parse as present evidence");
        };
        assert_eq!(v1.version, TimestampHeaderVersion::SigTst);
        assert_eq!(v2.version, TimestampHeaderVersion::SigTst2);
        // v1 unwraps the RFC 3161 response; v2 stores the bare token.
        assert_eq!(v1.token_der, b"\x30\x04\x04\x02ok".to_vec());
        assert_eq!(v2.token_der, b"\x30\x04\x04\x02ok".to_vec());
        // The v1 imprint covers the claim; the v2 imprint covers the encoded
        // signature byte string. They must never coincide.
        assert_ne!(v1.message_imprint_input, v2.message_imprint_input);
        assert!(v1
            .message_imprint_input
            .windows(claim.len())
            .any(|window| window == claim));
        assert!(v2
            .message_imprint_input
            .windows(b"signature-bytes".len())
            .any(|window| window == b"signature-bytes"));
    }

    #[test]
    fn header_defects_are_reported_instead_of_yielding_a_token() {
        let claim = b"claim-cbor".to_vec();
        let good = header(b"\x30\x04\x04\x02ok".to_vec());

        let both = cose(
            Vec::new(),
            vec![
                (
                    Value::Text(HEADER_SIG_TST.into()),
                    header(timestamp_response(0, b"\x04\x02ok")),
                ),
                (Value::Text(HEADER_SIG_TST2.into()), good.clone()),
            ],
        );
        assert_eq!(
            parse_timestamp_header(&both, &claim).expect("parse"),
            TimestampHeaderEvidence::Ignored(TimestampHeaderDefect::ConflictingHeaders)
        );

        // The same label in both buckets is a duplicate credential, not a
        // usable header.
        let duplicated = cose(
            vec![(Value::Text(HEADER_SIG_TST2.into()), good.clone())],
            vec![(Value::Text(HEADER_SIG_TST2.into()), good.clone())],
        );
        assert_eq!(
            parse_timestamp_header(&duplicated, &claim).expect("parse"),
            TimestampHeaderEvidence::Ignored(TimestampHeaderDefect::MalformedShape)
        );

        let two_tokens = Value::Map(vec![(
            Value::Text(TOKENS_KEY.into()),
            Value::Array(vec![
                Value::Map(vec![(
                    Value::Text(TOKEN_VALUE_KEY.into()),
                    Value::Bytes(b"\x30\x00".to_vec()),
                )]),
                Value::Map(vec![(
                    Value::Text(TOKEN_VALUE_KEY.into()),
                    Value::Bytes(b"\x30\x00".to_vec()),
                )]),
            ]),
        )]);
        assert_eq!(
            parse_timestamp_header(
                &cose(
                    Vec::new(),
                    vec![(Value::Text(HEADER_SIG_TST2.into()), two_tokens)]
                ),
                &claim
            )
            .expect("parse"),
            TimestampHeaderEvidence::Ignored(TimestampHeaderDefect::InvalidTokenCardinality)
        );

        let extra_member = Value::Map(vec![
            (
                Value::Text(TOKENS_KEY.into()),
                Value::Array(vec![Value::Map(vec![(
                    Value::Text(TOKEN_VALUE_KEY.into()),
                    Value::Bytes(b"\x30\x00".to_vec()),
                )])]),
            ),
            (Value::Text("extra".into()), Value::Integer(1)),
        ]);
        assert_eq!(
            parse_timestamp_header(
                &cose(
                    Vec::new(),
                    vec![(Value::Text(HEADER_SIG_TST2.into()), extra_member)]
                ),
                &claim
            )
            .expect("parse"),
            TimestampHeaderEvidence::Ignored(TimestampHeaderDefect::MalformedShape)
        );
    }

    #[test]
    fn legacy_response_must_carry_a_granted_pki_status() {
        let claim = b"claim-cbor".to_vec();
        for status in [0u8, 1] {
            let response = timestamp_response(status, b"\x04\x02ok");
            let evidence = parse_timestamp_header(
                &cose(
                    Vec::new(),
                    vec![(Value::Text(HEADER_SIG_TST.into()), header(response))],
                ),
                &claim,
            )
            .expect("parse");
            assert!(
                matches!(evidence, TimestampHeaderEvidence::Present(_)),
                "PKIStatusInfo status {status} is granted"
            );
        }
        // 2 is rejection; every non-granted status ignores the time-stamp.
        for status in [2u8, 3, 4, 5] {
            let response = timestamp_response(status, b"\x04\x02ok");
            assert_eq!(
                parse_timestamp_header(
                    &cose(
                        Vec::new(),
                        vec![(Value::Text(HEADER_SIG_TST.into()), header(response))],
                    ),
                    &claim
                )
                .expect("parse"),
                TimestampHeaderEvidence::Ignored(TimestampHeaderDefect::InvalidTimeStampResponse)
            );
        }
    }

    #[test]
    fn protected_iat_accepts_numeric_dates_and_rejects_unusable_ones() {
        let iat = |value: Value| {
            protected_iat(&cose(
                vec![(Value::Integer(COSE_HDR_IAT), value)],
                Vec::new(),
            ))
        };
        assert_eq!(
            iat(Value::Integer(1_700_000_000)).expect("int"),
            Some(1_700_000_000.0)
        );
        assert_eq!(iat(Value::Float(1.5)).expect("float"), Some(1.5));
        assert!(iat(Value::Integer(-1)).is_err());
        assert!(iat(Value::Float(f64::NAN)).is_err());
        assert!(iat(Value::Text("now".into())).is_err());
        assert_eq!(
            protected_iat(&cose(Vec::new(), Vec::new())).expect("absent"),
            None
        );
        // An `iat` in the unprotected bucket is not integrity-protected and
        // must not be read as a claimed time of signing.
        assert_eq!(
            protected_iat(&cose(
                Vec::new(),
                vec![(Value::Integer(COSE_HDR_IAT), Value::Integer(1))]
            ))
            .expect("unprotected"),
            None
        );
    }
}
