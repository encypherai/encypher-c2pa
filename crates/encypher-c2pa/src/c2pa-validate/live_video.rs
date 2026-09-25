// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA live-video session-key, `emsg`, and manifest-continuity validation.
//!
//! Every status code filed here is a registered C2PA 2.4 `livevideo.*` failure
//! code. None of them appears in the non-invalidating caveat set, so a stream
//! that fails any check below is `Invalid` under both postures.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use crate::c2pa_crypto::{cose_key_id, protected_iat, verify_with_cose_key};
use crate::c2pa_formats::StreamMethod;

use super::ValidationResults;

/// Live-video assertion sequence or stream mismatch.
pub const LIVEVIDEO_ASSERTION_INVALID: &str = "livevideo.assertion.invalid";
/// Unknown or malformed continuity method.
pub const LIVEVIDEO_CONTINUITY_METHOD_INVALID: &str = "livevideo.continuityMethod.invalid";
/// Init segment improperly contains media data.
pub const LIVEVIDEO_INIT_INVALID: &str = "livevideo.init.invalid";
/// A segment manifest failed ordinary C2PA validation.
pub const LIVEVIDEO_MANIFEST_INVALID: &str = "livevideo.manifest.invalid";
/// A segment lacks valid signed segment information or breaks manifest chaining.
pub const LIVEVIDEO_SEGMENT_INVALID: &str = "livevideo.segment.invalid";
/// A delivered session key or its signer binding is invalid.
pub const LIVEVIDEO_SESSION_KEY_INVALID: &str = "livevideo.sessionkey.invalid";

const CONTINUITY_MANIFEST_ID: &str = "c2pa.manifestId";
const MAX_SESSION_KEYS: usize = 64;
const MAX_EMSG_BOXES: usize = 64;

/// Hard cap on the top-level boxes any live segment walk will visit. A real
/// fragmented segment has a handful (`styp`, `moof`, `mdat`, `emsg`, padding);
/// anything beyond this is a box storm, not a stream.
const MAX_TOP_LEVEL_BOXES: usize = 4096;

/// The `scheme_id_uri` a C2PA verifiable-segment-info `emsg` must declare.
pub const SEGMENT_INFO_SCHEME_ID_URI: &str = "urn:c2pa:verifiable-segment-info";

/// The `value` a C2PA verifiable-segment-info `emsg` must declare.
pub const SEGMENT_INFO_VALUE: &str = "c2pa";

/// Registry-derived applicability for a live-video validation operation.
///
/// Callers resolve declared tokens through [`StreamMethod::from_token`], so an
/// unknown declaration cannot accidentally enable a hand-maintained fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveVideoApplicability {
    method: StreamMethod,
}

impl LiveVideoApplicability {
    /// Construct applicability from a registry-defined stream method.
    pub fn new(method: StreamMethod) -> Self {
        debug_assert!(StreamMethod::ALL.contains(&method));
        Self { method }
    }

    /// Declared method.
    pub fn method(self) -> StreamMethod {
        self.method
    }
}

/// A session key whose structure, signer binding, delivery time, and key ID pass.
#[derive(Debug, Clone)]
pub struct ValidatedSessionKey {
    /// Serialized COSE_Key used for signature validation.
    pub cose_key: Vec<u8>,
    /// Required COSE key identifier.
    pub key_id: Vec<u8>,
    /// Lowest segment sequence number this key may authenticate.
    pub minimum_sequence_number: u64,
    /// Session-key creation time.
    pub created_at: OffsetDateTime,
    /// Inclusive expiration time.
    pub expires_at: OffsetDateTime,
}

/// Parse and validate a `c2pa.session-keys` assertion.
///
/// Every accepted key proves possession through `signerBinding`, whose payload
/// must equal the exact DER end-entity certificate that signed the delivering
/// manifest. Invalid entries do not become candidates for segment validation.
pub fn validate_session_keys(
    applicability: LiveVideoApplicability,
    assertion_cbor: &[u8],
    signer_chain_der: &[Vec<u8>],
    results: &mut ValidationResults,
    url: &str,
) -> Vec<ValidatedSessionKey> {
    if applicability.method != StreamMethod::VerifiableSegmentInfo {
        return Vec::new();
    }
    let Some(signer_leaf) = signer_chain_der.first() else {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "session-key delivery has no signer certificate",
        );
        return Vec::new();
    };
    let Ok(Value::Map(root)) = decode(assertion_cbor) else {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "session-keys assertion CBOR is malformed",
        );
        return Vec::new();
    };
    if root.len() != 1 || root[0].0.as_text() != Some("keys") {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "session-keys assertion has an invalid shape",
        );
        return Vec::new();
    }
    let Value::Array(keys) = &root[0].1 else {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "session-keys keys value is not an array",
        );
        return Vec::new();
    };
    if keys.is_empty() || keys.len() > MAX_SESSION_KEYS {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "session-key cardinality is invalid",
        );
        return Vec::new();
    }

    let mut validated = Vec::with_capacity(keys.len());
    let mut any_invalid = false;
    for entry in keys {
        match validate_session_key(entry, signer_leaf, signer_chain_der) {
            Ok(key)
                if !validated
                    .iter()
                    .any(|known: &ValidatedSessionKey| known.key_id == key.key_id) =>
            {
                validated.push(key)
            }
            _ => any_invalid = true,
        }
    }
    if any_invalid || validated.is_empty() {
        report(
            results,
            LIVEVIDEO_SESSION_KEY_INVALID,
            url,
            "one or more session keys or signer bindings are invalid",
        );
    }
    validated
}

fn validate_session_key(
    entry: &Value,
    signer_leaf: &[u8],
    signer_chain_der: &[Vec<u8>],
) -> Result<ValidatedSessionKey, ()> {
    let map = entry.as_map().ok_or(())?;
    if map.len() != 5 {
        return Err(());
    }
    let key_value = unique_field(map, "key")?;
    let minimum_sequence_number = nonnegative_u64(unique_field(map, "minSequenceNumber")?)?;
    let created_at = tagged_datetime(unique_field(map, "createdAt")?)?;
    let validity_period = positive_i64(unique_field(map, "validityPeriod")?)?;
    let signer_binding = unique_field(map, "signerBinding")?;

    if !signer_chain_der
        .iter()
        .all(|certificate| crate::c2pa_trust::certificate_valid_at(certificate, created_at))
    {
        return Err(());
    }
    let expires_at = created_at
        .checked_add(time::Duration::seconds(validity_period))
        .ok_or(())?;
    let cose_key = encode(key_value, Profile::CanonicalForHashedSubstructures).map_err(|_| ())?;
    let key_id = cose_key_id(&cose_key).map_err(|_| ())?;
    let binding =
        encode(signer_binding, Profile::CanonicalForHashedSubstructures).map_err(|_| ())?;
    let verified = verify_with_cose_key(&binding, &cose_key).map_err(|_| ())?;
    if verified.payload != signer_leaf {
        return Err(());
    }
    if verified.key_id.as_deref().is_some_and(|id| id != key_id) {
        return Err(());
    }
    Ok(ValidatedSessionKey {
        cose_key,
        key_id,
        minimum_sequence_number,
        created_at,
        expires_at,
    })
}

/// Parsed live-video assertion and current manifest identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveVideoManifestState {
    /// Monotonically increasing segment sequence.
    pub sequence_number: u64,
    /// Stable stream identifier.
    pub stream_id: String,
    /// Current manifest ID, used by the next segment's continuity assertion.
    pub manifest_id: String,
}

/// Validate live-video sequence, stream, and `previousManifestId` chaining.
pub fn validate_live_video_assertion(
    applicability: LiveVideoApplicability,
    assertion_cbor: &[u8],
    current_manifest_id: &str,
    previous: Option<&LiveVideoManifestState>,
    results: &mut ValidationResults,
    url: &str,
) -> Option<LiveVideoManifestState> {
    if applicability.method != StreamMethod::PerSegment {
        return None;
    }
    let Ok(Value::Map(map)) = decode(assertion_cbor) else {
        report(
            results,
            LIVEVIDEO_ASSERTION_INVALID,
            url,
            "live-video assertion is malformed",
        );
        return None;
    };
    let parsed = (|| {
        let sequence_number = nonnegative_u64(unique_field(&map, "sequenceNumber")?)?;
        let stream_id = nonempty_text(unique_field(&map, "streamId")?)?;
        let continuity = nonempty_text(unique_field(&map, "continuityMethod")?)?;
        Ok::<_, ()>((sequence_number, stream_id, continuity))
    })();
    let Ok((sequence_number, stream_id, continuity)) = parsed else {
        report(
            results,
            LIVEVIDEO_ASSERTION_INVALID,
            url,
            "live-video assertion sequence or stream is invalid",
        );
        return None;
    };
    // Every applicable defect is reported rather than only the first. A consumer
    // deciding what to do with a broken live stream needs each reason, and a
    // caller that renders these statuses as text cannot attribute a rejection it
    // was never told about.
    let mut rejected = false;
    if continuity != CONTINUITY_MANIFEST_ID {
        report(
            results,
            LIVEVIDEO_CONTINUITY_METHOD_INVALID,
            url,
            "continuity method is unknown",
        );
        rejected = true;
    }
    let previous_manifest_id =
        match unique_field(&map, "previousManifestId").and_then(nonempty_text) {
            Ok(value) => Some(value),
            Err(_) => {
                report(
                    results,
                    LIVEVIDEO_CONTINUITY_METHOD_INVALID,
                    url,
                    "manifest-ID continuity is missing previousManifestId",
                );
                rejected = true;
                None
            }
        };
    if let Some(previous) = previous {
        if sequence_number != previous.sequence_number.saturating_add(1)
            || stream_id != previous.stream_id
        {
            report(
                results,
                LIVEVIDEO_ASSERTION_INVALID,
                url,
                "live-video sequence or stream does not match the predecessor",
            );
            rejected = true;
        }
        if previous_manifest_id.is_some_and(|declared| declared != previous.manifest_id) {
            report(
                results,
                LIVEVIDEO_SEGMENT_INVALID,
                url,
                "previousManifestId does not name the preceding manifest",
            );
            rejected = true;
        }
    }
    if rejected {
        return None;
    }
    Some(LiveVideoManifestState {
        sequence_number,
        stream_id: stream_id.to_string(),
        manifest_id: current_manifest_id.to_string(),
    })
}

/// Validate that a live init segment has no top-level `mdat` box.
pub fn validate_init_segment(
    _applicability: LiveVideoApplicability,
    init_segment: &[u8],
    results: &mut ValidationResults,
    url: &str,
) -> bool {
    // Stops at the FIRST `mdat`, and never collects the box list: the same
    // hostile-input reasoning as [`walk_top_level_boxes`] applies to an init
    // segment, which an attacker also supplies.
    match walk_top_level_boxes(init_segment, |item| {
        (item.box_type == *b"mdat").then_some(())
    }) {
        Ok(None) => true,
        Ok(Some(())) => {
            report(
                results,
                LIVEVIDEO_INIT_INVALID,
                url,
                "live init segment contains mdat",
            );
            false
        }
        Err(defect) => {
            report(results, LIVEVIDEO_INIT_INVALID, url, defect.explanation());
            false
        }
    }
}

/// Map ordinary segment-manifest validation into the normative live-video status.
pub fn validate_segment_manifest(
    _applicability: LiveVideoApplicability,
    manifest_valid: bool,
    results: &mut ValidationResults,
    url: &str,
) -> bool {
    if manifest_valid {
        true
    } else {
        report(
            results,
            LIVEVIDEO_MANIFEST_INVALID,
            url,
            "segment manifest failed C2PA validation",
        );
        false
    }
}

/// Successfully authenticated `segment-info-map` data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSegmentInfo {
    /// Signed segment sequence number.
    pub sequence_number: u64,
    /// Signed manifest identifier.
    pub manifest_id: String,
    /// Session key that authenticated the `emsg` payload.
    pub key_id: Vec<u8>,
}

/// Validate C2PA verifiable-segment-info carried in top-level BMFF `emsg` boxes.
///
/// All C2PA candidates are tried, bounded by [`MAX_EMSG_BOXES`]. Success
/// requires a known active `kid`, a valid COSE signature, exact manifest
/// binding, a matching structural BMFF hash (normally excluding `/emsg`), and,
/// unless the player signalled an expected seek, the expected sequence number.
// Eight parameters, matching the wide validator convention across this crate:
// the segment bytes, the two bindings it must satisfy, the key set, the
// validation instant, and the two reporting sinks are each independently
// required, and grouping them would move the same arity behind a struct every
// caller has to build anyway.
#[allow(clippy::too_many_arguments)]
pub fn validate_emsg_segment(
    applicability: LiveVideoApplicability,
    segment: &[u8],
    expected_sequence_number: Option<u64>,
    expected_manifest_id: &str,
    session_keys: &[ValidatedSessionKey],
    validation_time: OffsetDateTime,
    results: &mut ValidationResults,
    url: &str,
) -> Option<VerifiedSegmentInfo> {
    if applicability.method != StreamMethod::VerifiableSegmentInfo {
        return None;
    }
    if session_keys.is_empty() {
        report(
            results,
            LIVEVIDEO_SEGMENT_INVALID,
            url,
            "segment has no valid session keys",
        );
        return None;
    }
    // Two bounds, both load-bearing on hostile input, and nothing accumulated:
    // the walk itself stops after [`MAX_TOP_LEVEL_BOXES`] boxes, so a storm of
    // tiny boxes cannot make a validator allocate or work in proportion to the
    // attacker's box count before any other limit applies; and at most
    // [`MAX_EMSG_BOXES`] C2PA candidates are ever verified, so signature checks
    // cannot be amplified either.
    let mut candidates = 0usize;
    let mut verified = None;
    let mut unexpected = None;
    let walk = walk_top_level_boxes(segment, |item| {
        if item.box_type != *b"emsg" {
            return None;
        }
        // Only messages that declare the C2PA scheme and value are parsed, so an
        // unrelated DASH event cannot even reach a signature check.
        let Ok(message) = segment_info_message(item.body) else {
            return None;
        };
        candidates += 1;
        if candidates > MAX_EMSG_BOXES {
            return Some(());
        }
        let candidate = authenticate_segment_info(
            message,
            segment,
            expected_manifest_id,
            session_keys,
            validation_time,
        )?;
        if expected_sequence_number.is_none_or(|expected| candidate.sequence_number == expected) {
            verified = Some(candidate);
            Some(())
        } else {
            unexpected.get_or_insert(candidate);
            None
        }
    });
    if let Err(defect) = walk {
        report(
            results,
            LIVEVIDEO_SEGMENT_INVALID,
            url,
            defect.explanation(),
        );
        return None;
    }
    if verified.is_some() {
        return verified;
    }
    if let Some(unexpected) = unexpected {
        report(
            results,
            LIVEVIDEO_SEGMENT_INVALID,
            url,
            &format!(
                "unexpected sequence discontinuity: signed sequenceNumber {} does not follow {}",
                unexpected.sequence_number,
                expected_sequence_number.expect("unexpected candidate requires an expected value")
            ),
        );
        return Some(unexpected);
    }
    report(
        results,
        LIVEVIDEO_SEGMENT_INVALID,
        url,
        "no emsg box carried valid signed segment information",
    );
    None
}

/// One `emsg` message checked against the active session keys.
///
/// Success requires a valid COSE signature under a delivered key, that key's
/// `kid`, a signing time inside the key's window, a sequence number at or above
/// the key's delivery floor, exact `manifestId`, and a structural BMFF hash that
/// reproduces over the delivered bytes.
fn authenticate_segment_info(
    message: &[u8],
    segment: &[u8],
    expected_manifest_id: &str,
    session_keys: &[ValidatedSessionKey],
    validation_time: OffsetDateTime,
) -> Option<VerifiedSegmentInfo> {
    for key in session_keys {
        let Ok(verified) = verify_with_cose_key(message, &key.cose_key) else {
            continue;
        };
        if verified.key_id.as_deref() != Some(key.key_id.as_slice()) {
            continue;
        }
        let signed_at = match protected_iat(message) {
            Ok(None) => validation_time,
            Ok(Some(iat)) => match numeric_date(iat) {
                Some(signed_at) => signed_at,
                None => continue,
            },
            Err(_) => continue,
        };
        if signed_at < key.created_at || signed_at > key.expires_at {
            continue;
        }
        let Ok(Value::Map(info)) = decode(&verified.payload) else {
            continue;
        };
        let Ok(sequence_number) = unique_field(&info, "sequenceNumber").and_then(nonnegative_u64)
        else {
            continue;
        };
        if sequence_number < key.minimum_sequence_number {
            continue;
        }
        let Ok(manifest_id) = unique_field(&info, "manifestId").and_then(nonempty_text) else {
            continue;
        };
        if manifest_id != expected_manifest_id {
            continue;
        }
        let Ok(hash_map) = unique_field(&info, "bmffHash") else {
            continue;
        };
        if !verify_bmff_hash(hash_map, segment) {
            continue;
        }
        return Some(VerifiedSegmentInfo {
            sequence_number,
            manifest_id: manifest_id.to_string(),
            key_id: key.key_id.clone(),
        });
    }
    None
}

fn allowed_live_bmff_exclusion(xpath: &str) -> bool {
    xpath == "/emsg" || crate::c2pa_formats::BMFF_HASH_EXCLUSION_PATHS.contains(&xpath)
}

fn verify_bmff_hash(value: &Value, segment: &[u8]) -> bool {
    let Some(map) = value.as_map() else {
        return false;
    };
    let Ok(alg) = unique_field(map, "alg").and_then(nonempty_text) else {
        return false;
    };
    let Ok(expected) = unique_field(map, "hash").and_then(nonempty_bytes) else {
        return false;
    };
    let mut xpaths = Vec::new();
    if let Ok(Value::Array(exclusions)) = unique_field(map, "exclusions") {
        if exclusions.len() > 128 {
            return false;
        }
        for exclusion in exclusions {
            let Some(xpath) = exclusion.get("xpath").and_then(Value::as_text) else {
                return false;
            };
            if !allowed_live_bmff_exclusion(xpath) {
                return false;
            }
            xpaths.push(xpath.to_string());
        }
    }
    crate::c2pa_formats::bmff_hash(segment, alg, &xpaths)
        .is_ok_and(|actual| actual.as_slice() == expected)
}

fn numeric_date(seconds: f64) -> Option<OffsetDateTime> {
    if !seconds.is_finite() || seconds < i64::MIN as f64 || seconds > i64::MAX as f64 {
        return None;
    }
    let whole = seconds.trunc() as i64;
    let base = OffsetDateTime::from_unix_timestamp(whole).ok()?;
    let nanos = ((seconds - whole as f64) * 1_000_000_000.0).round() as i64;
    base.checked_add(time::Duration::nanoseconds(nanos))
}

fn tagged_datetime(value: &Value) -> Result<OffsetDateTime, ()> {
    let Value::Tag(0, inner) = value else {
        return Err(());
    };
    let text = inner.as_text().ok_or(())?;
    OffsetDateTime::parse(text, &Rfc3339).map_err(|_| ())
}

fn unique_field<'a>(map: &'a [(Value, Value)], name: &str) -> Result<&'a Value, ()> {
    let mut found = None;
    for (key, value) in map {
        if key.as_text() == Some(name) {
            if found.is_some() {
                return Err(());
            }
            found = Some(value);
        }
    }
    found.ok_or(())
}

fn nonempty_text(value: &Value) -> Result<&str, ()> {
    value.as_text().filter(|text| !text.is_empty()).ok_or(())
}

fn nonempty_bytes(value: &Value) -> Result<&[u8], ()> {
    value.as_bytes().filter(|bytes| !bytes.is_empty()).ok_or(())
}

fn nonnegative_u64(value: &Value) -> Result<u64, ()> {
    match value {
        Value::Integer(number) if *number >= 0 => u64::try_from(*number).map_err(|_| ()),
        _ => Err(()),
    }
}

fn positive_i64(value: &Value) -> Result<i64, ()> {
    match value {
        Value::Integer(number) if *number > 0 => i64::try_from(*number).map_err(|_| ()),
        _ => Err(()),
    }
}

#[derive(Debug)]
struct BmffBox<'a> {
    box_type: [u8; 4],
    body: &'a [u8],
}

/// Why a top-level box walk gave up.
///
/// The two are kept apart because they are different accusations, and a report
/// that merged them would leave a consumer -- and a test -- unable to tell which
/// guard fired. "Malformed" says the bytes are not a parseable box sequence;
/// "TooManyBoxes" says they parse fine and there are simply more of them than any
/// stream segment legitimately carries, which is the box-storm case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkDefect {
    /// A box header is truncated, or a declared size runs past the end.
    Malformed,
    /// More than [`MAX_TOP_LEVEL_BOXES`] top-level boxes.
    TooManyBoxes,
}

impl WalkDefect {
    /// The explanation filed with the status, one wording per defect.
    fn explanation(self) -> &'static str {
        match self {
            Self::Malformed => "top-level BMFF boxes are malformed",
            Self::TooManyBoxes => {
                "more top-level BMFF boxes than a live segment may carry; \
                 the box walk stopped at the box-storm limit"
            }
        }
    }
}

/// Walk the top-level boxes of `data` in file order WITHOUT accumulating them,
/// stopping early when `visit` returns `Some`.
///
/// Streaming is a hostile-input requirement, not a style choice. A collected
/// walk lets an attacker turn a segment of minimum-size (8-byte) boxes into a
/// vector of one entry per box -- work and memory proportional to their box
/// count, spent BEFORE any per-candidate limit such as [`MAX_EMSG_BOXES`] can
/// apply, because that limit counts candidates the collection has already paid
/// for. Here each box is examined as it is reached and nothing is retained, and
/// [`MAX_TOP_LEVEL_BOXES`] caps the walk itself: a real fragmented segment has a
/// handful of top-level boxes, so a file past that cap is refused as
/// [`WalkDefect::TooManyBoxes`] rather than walked to the end. The cap is a fixed
/// count, so the refusal is deterministic: it does not depend on timing, load, or
/// how much of the file a later check would have rejected anyway.
fn walk_top_level_boxes<T>(
    mut data: &[u8],
    mut visit: impl FnMut(&BmffBox<'_>) -> Option<T>,
) -> Result<Option<T>, WalkDefect> {
    let mut walked = 0usize;
    while !data.is_empty() {
        if data.len() < 8 {
            return Err(WalkDefect::Malformed);
        }
        walked += 1;
        if walked > MAX_TOP_LEVEL_BOXES {
            return Err(WalkDefect::TooManyBoxes);
        }
        let size32 = u32::from_be_bytes(data[0..4].try_into().map_err(|_| WalkDefect::Malformed)?);
        let box_type: [u8; 4] = data[4..8].try_into().map_err(|_| WalkDefect::Malformed)?;
        let (size, header) = match size32 {
            0 => (data.len(), 8),
            1 => {
                if data.len() < 16 {
                    return Err(WalkDefect::Malformed);
                }
                let size =
                    u64::from_be_bytes(data[8..16].try_into().map_err(|_| WalkDefect::Malformed)?);
                (
                    usize::try_from(size).map_err(|_| WalkDefect::Malformed)?,
                    16,
                )
            }
            size => (size as usize, 8),
        };
        if size < header || size > data.len() {
            return Err(WalkDefect::Malformed);
        }
        if let Some(found) = visit(&BmffBox {
            box_type,
            body: &data[header..size],
        }) {
            return Ok(Some(found));
        }
        data = &data[size..];
    }
    Ok(None)
}

/// The message payload of an `emsg` box that declares C2PA verifiable segment
/// information, or `Err` for any other event message.
///
/// The scheme and value are matched EXACTLY before the payload is looked at. A
/// live stream legitimately carries unrelated `emsg` events (ad insertion,
/// timed metadata), and a validator that treated any event body as candidate
/// segment information would burn a signature check on each one -- and, worse,
/// would accept segment information published under a scheme that promises
/// something else entirely.
fn segment_info_message(body: &[u8]) -> Result<&[u8], ()> {
    if body.len() < 4 {
        return Err(());
    }
    let version = body[0];
    let mut cursor = 4usize;
    // ISO/IEC 23009-1 orders the fields differently per version: version 0 puts
    // the two strings first, version 1 puts the timing fields first.
    let (scheme, value) = match version {
        0 => {
            let scheme = take_c_string(body, &mut cursor)?;
            let value = take_c_string(body, &mut cursor)?;
            cursor = cursor.checked_add(16).ok_or(())?;
            (scheme, value)
        }
        1 => {
            cursor = cursor.checked_add(20).ok_or(())?;
            let scheme = take_c_string(body, &mut cursor)?;
            let value = take_c_string(body, &mut cursor)?;
            (scheme, value)
        }
        _ => return Err(()),
    };
    if scheme != SEGMENT_INFO_SCHEME_ID_URI.as_bytes() || value != SEGMENT_INFO_VALUE.as_bytes() {
        return Err(());
    }
    if cursor >= body.len() {
        return Err(());
    }
    Ok(&body[cursor..])
}

fn take_c_string<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], ()> {
    let rest = data.get(*cursor..).ok_or(())?;
    let length = rest.iter().position(|byte| *byte == 0).ok_or(())?;
    *cursor = cursor.checked_add(length + 1).ok_or(())?;
    Ok(&rest[..length])
}

fn report(results: &mut ValidationResults, code: &str, url: &str, explanation: &str) {
    results.push_failure(code, url.into(), explanation.into());
}
