// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA live-video session-key, `emsg`, and manifest-continuity validation.
//!
//! Every status code filed here is a registered C2PA 2.4 `livevideo.*` failure
//! code. None of them appears in the non-invalidating caveat set, so a stream
//! that fails any check below is `Invalid` under both postures.

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::c2pa_cbor::{decode, encode, Profile, Value};
use crate::c2pa_crypto::{
    cose_key_id, protected_iat, verify_with_cose_key_with, ClaimAlgorithmList,
};
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

/// The `value` a C2PA verifiable-segment-info `emsg` must declare (C2PA 2.4
/// section 19.4.2).
pub const SEGMENT_INFO_VALUE: &str = "fseg";

/// The C2PA scheme URI with its terminating NUL, as an 18.6.2 exclusion `data`
/// value. Section 19.4.1 asks the `/emsg` exclusion to carry a `data` entry
/// whose value is the scheme URI; with the NUL, a longer scheme that merely
/// starts with the C2PA URI is not selected.
///
/// Section 19.4.1 also says that entry's `offset` is 0. Section 18.6.2 measures
/// `data` offsets from the start of the box including its header, where bytes
/// 0..8 are the box size and type, so offset 0 can never select an `emsg` and
/// the literal text cannot be satisfied. This validator does not reinterpret
/// offsets per box type: it applies every qualifier with the generic 18.6.2
/// matcher (a version-0 `emsg` with a 32-bit size has its scheme at offset 12,
/// one with a 64-bit size at 20) and then judges what the `/emsg` exclusions
/// actually remove.
const SEGMENT_INFO_EXCLUSION_VALUE: &[u8] = b"urn:c2pa:verifiable-segment-info\0";

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
///
/// Session keys follow the explicit claim-signature algorithm list selected by
/// the caller's C2PA revision.
pub fn validate_session_keys_with(
    applicability: LiveVideoApplicability,
    assertion_cbor: &[u8],
    signer_chain_der: &[Vec<u8>],
    algorithms: ClaimAlgorithmList,
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
        match validate_session_key(entry, signer_leaf, signer_chain_der, algorithms) {
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
    algorithms: ClaimAlgorithmList,
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
    let verified = verify_with_cose_key_with(&binding, &cose_key, algorithms).map_err(|_| ())?;
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

/// Validate every media segment of a session-key stream in presented order.
///
/// Each segment's session-key window is judged at its trusted
/// presentation-assessment time: `presentation_times[i]` when the caller
/// supplies per-segment times (exactly one per segment, index for index; any
/// other count is refused before a segment is evaluated), else `common_time`.
/// A historical stream whose keys rotated through disjoint windows therefore
/// verifies when the caller supplies the chronology it trusts.
///
/// The first presented segment must carry the lowest `minSequenceNumber` of
/// the authenticated session keys, clamped to at least 1: an init segment
/// re-issued during 24/7 rotation with keys starting at 8 begins its segments
/// at 8, and a key floor of 0 still starts at 1. Sequence continuity then runs
/// across key changes: the next expected `sequenceNumber` follows the last
/// authenticated segment whichever key signed it, and only an index in
/// `expected_seek_positions` (sorted, unique, in bounds) suspends it.
///
/// C2PA event `id`s must be unique within the session (C2PA 2.4 section
/// 19.4.2); one [`SessionEventIds`] ledger spans every supplied segment.
// Independently required inputs; see [`validate_emsg_segment_with`].
#[allow(clippy::too_many_arguments)]
pub fn validate_emsg_segments(
    applicability: LiveVideoApplicability,
    segments: &[&[u8]],
    init_timing: Result<&InitTrackTiming, &'static str>,
    expected_seek_positions: &[usize],
    expected_manifest_id: &str,
    session_keys: &[ValidatedSessionKey],
    common_time: OffsetDateTime,
    presentation_times: Option<&[OffsetDateTime]>,
    algorithms: ClaimAlgorithmList,
    results: &mut ValidationResults,
) {
    if presentation_times.is_some_and(|times| times.len() != segments.len()) {
        report(
            results,
            LIVEVIDEO_SEGMENT_INVALID,
            "self#segment",
            "presentation-assessment times do not name exactly one time per segment",
        );
        return;
    }
    let first_sequence_number = session_keys
        .iter()
        .map(|key| key.minimum_sequence_number)
        .min()
        .unwrap_or(1)
        .max(1);
    let mut next_sequence_number = Some(first_sequence_number);
    let mut event_ids = SessionEventIds::default();
    for (index, segment) in segments.iter().copied().enumerate() {
        let assessment_time = presentation_times.map_or(common_time, |times| times[index]);
        let expected_seek = expected_seek_positions.binary_search(&index).is_ok();
        let expected_sequence_number = if expected_seek {
            None
        } else {
            next_sequence_number
        };
        let url = format!("self#segment={}", index + 1);
        if !expected_seek && expected_sequence_number.is_none() {
            results.push_failure(
                LIVEVIDEO_SEGMENT_INVALID,
                url.clone(),
                "unexpected sequence discontinuity: predecessor sequenceNumber cannot be incremented"
                    .into(),
            );
        }
        if let Some(info) = validate_emsg_segment_with(
            applicability,
            segment,
            index,
            &mut event_ids,
            init_timing,
            expected_sequence_number,
            expected_manifest_id,
            session_keys,
            assessment_time,
            algorithms,
            results,
            &url,
        ) {
            next_sequence_number = info.sequence_number.checked_add(1);
        }
    }
}

/// The C2PA event `id`s one session has presented: each `id` maps to the whole
/// segment that first carried it (borrowed from the supplied segments, never
/// copied), that segment's index, and the index of the last segment that
/// carried it.
///
/// Section 19.4.2 makes the `id` unique within the session, and it sits in the
/// excluded `emsg`, outside both the signature and the hash, so nothing else
/// stops a splicer from relabelling one event with another's `id`, or from
/// appending an earlier segment's whole event to a later segment. A repeat is
/// accepted only when the WHOLE later segment is byte-identical to the segment
/// that first carried the `id`: a player that seeks back legitimately presents
/// the same segment again, and whether such a replay is acceptable is then
/// decided by the ordinary sequence and expected-seek rules, not by this
/// ledger. The same `id` twice in one segment, or a repeated `id` in a segment
/// that is not an exact replay, is refused.
#[derive(Debug, Default)]
pub struct SessionEventIds<'a> {
    seen: std::collections::BTreeMap<u32, SeenEvent<'a>>,
}

#[derive(Debug, Clone, Copy)]
struct SeenEvent<'a> {
    origin: &'a [u8],
    origin_index: usize,
    last_index: usize,
}

impl<'a> SessionEventIds<'a> {
    /// Admit one C2PA candidate's `id` carried by `segment` at `segment_index`.
    ///
    /// `replay_of` caches, for the segment being walked, the earlier segment it
    /// was already proven identical to, so a segment is compared byte for byte
    /// at most once however many of its events repeat. An exact replay maps
    /// every `id` to one origin: an identical segment's `id`s are registered
    /// against its first occurrence.
    fn admit(
        &mut self,
        id: u32,
        segment: &'a [u8],
        segment_index: usize,
        replay_of: &mut Option<usize>,
    ) -> Result<(), &'static str> {
        use std::collections::btree_map::Entry;
        const NOT_UNIQUE: &str = "C2PA emsg id is not unique in the session";
        match self.seen.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(SeenEvent {
                    origin: segment,
                    origin_index: segment_index,
                    last_index: segment_index,
                });
                Ok(())
            }
            Entry::Occupied(mut slot) => {
                let seen = slot.get_mut();
                if seen.last_index == segment_index {
                    return Err("C2PA emsg id repeats within the segment");
                }
                match *replay_of {
                    Some(origin) if origin == seen.origin_index => {}
                    Some(_) => return Err(NOT_UNIQUE),
                    None if seen.origin == segment => *replay_of = Some(seen.origin_index),
                    None => return Err(NOT_UNIQUE),
                }
                seen.last_index = segment_index;
                Ok(())
            }
        }
    }
}

/// Validate C2PA verifiable-segment-info carried in top-level BMFF `emsg` boxes.
///
/// Every C2PA candidate is examined, bounded by [`MAX_EMSG_BOXES`]; a segment
/// with more candidates than that is refused. A candidate is
/// a version-0 `emsg` declaring the C2PA scheme and the value `fseg` (C2PA 2.4
/// section 19.4.2). Success requires `presentation_time_delta` 0, a `timescale`
/// and `event_duration` that cover the segment's whole presentation span as the
/// init segment times it, a known `kid` whose window contains
/// `assessment_time`, a valid COSE signature, exact manifest binding, a
/// matching structural BMFF hash whose `/emsg` exclusions remove that C2PA
/// event and nothing but C2PA events (section 19.4.1), and, unless the player
/// signalled an expected seek, the expected sequence number.
///
/// Every candidate's `id` is admitted to `event_ids` before it is timed or
/// authenticated (see [`SessionEventIds`]); a refused `id` fails the segment
/// even when another candidate verified. Candidates after the one that
/// verified are still scanned for their `id`s, but no further signature is
/// checked.
///
/// `assessment_time` is the trusted instant at which the segment is judged to
/// have been presented. A signed `iat` never replaces it: a holder of an
/// expired session key can write any `iat` it likes.
///
/// `algorithms` is the claim-signature algorithm list selected by the caller's
/// C2PA revision.
// The segment bytes and its position, the session event ledger, the init
// timing, the two bindings it must satisfy, the key set, the assessment
// instant, and the two reporting sinks are each independently required, and
// grouping them would move the same arity behind a struct every caller has to
// build anyway.
#[allow(clippy::too_many_arguments)]
pub fn validate_emsg_segment_with<'a>(
    applicability: LiveVideoApplicability,
    segment: &'a [u8],
    segment_index: usize,
    event_ids: &mut SessionEventIds<'a>,
    init_timing: Result<&InitTrackTiming, &'static str>,
    expected_sequence_number: Option<u64>,
    expected_manifest_id: &str,
    session_keys: &[ValidatedSessionKey],
    assessment_time: OffsetDateTime,
    algorithms: ClaimAlgorithmList,
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
    let span = match init_timing.and_then(|timing| segment_presentation_span(segment, timing)) {
        Ok(span) => span,
        Err(defect) => {
            report(results, LIVEVIDEO_SEGMENT_INVALID, url, defect);
            return None;
        }
    };
    // Two bounds, both load-bearing on hostile input, and nothing accumulated
    // beyond the bounded `id` ledger: the walk itself stops after
    // [`MAX_TOP_LEVEL_BOXES`] boxes, so a storm of tiny boxes cannot make a
    // validator allocate or work in proportion to the attacker's box count
    // before any other limit applies; and at most [`MAX_EMSG_BOXES`] C2PA
    // candidates are ever examined, so signature checks and ledger entries
    // cannot be amplified either.
    let mut candidates = 0usize;
    let mut verified = None;
    let mut unexpected = None;
    let mut event_defect = None;
    let mut id_defect = None;
    let mut replay_of = None;
    let walk = walk_top_level_boxes(segment, |item| {
        if item.box_type != *b"emsg" {
            return None;
        }
        // Only messages that declare the C2PA scheme and value are parsed, so an
        // unrelated DASH event cannot even reach a signature check, and its
        // `id` lives in another scheme's namespace.
        let Ok(event) = segment_info_event(item.body) else {
            return None;
        };
        candidates += 1;
        if candidates > MAX_EMSG_BOXES {
            id_defect = Some("segment carries more C2PA emsg candidates than the verifier bound");
            return Some(());
        }
        if let Err(defect) = event_ids.admit(event.id, segment, segment_index, &mut replay_of) {
            id_defect = Some(defect);
            return Some(());
        }
        if verified.is_some() {
            return None;
        }
        if let Err(defect) = check_event_timing(&event, &span) {
            event_defect.get_or_insert(defect);
            return None;
        }
        let candidate = authenticate_segment_info(
            event.message,
            segment,
            (item.start, item.end),
            expected_manifest_id,
            session_keys,
            assessment_time,
            algorithms,
        )?;
        if expected_sequence_number.is_none_or(|expected| candidate.sequence_number == expected) {
            verified = Some(candidate);
        } else {
            unexpected.get_or_insert(candidate);
        }
        None
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
    if let Some(defect) = id_defect {
        report(results, LIVEVIDEO_SEGMENT_INVALID, url, defect);
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
        event_defect.unwrap_or("no emsg box carried valid signed segment information"),
    );
    None
}

/// Section 19.4.2 timing for one C2PA event: `presentation_time_delta` 0, and a
/// nonzero, known `timescale` and `event_duration` that cover the whole
/// segment. A version-0 event starts at the segment's presentation origin (its
/// earliest sample presentation time), so it covers the segment when
/// `event_duration / timescale` is at least the span from that origin to the
/// latest sample end of any track. The comparison is exact (cross-multiplied
/// with checked arithmetic), never rounded. `event_duration` 0xFFFFFFFF is the
/// ISO/IEC 23009-1 "unknown duration" value and covers nothing.
fn check_event_timing(
    event: &SegmentInfoEvent<'_>,
    span: &SegmentSpan,
) -> Result<(), &'static str> {
    if event.presentation_time_delta != 0 {
        return Err("C2PA emsg presentation_time_delta is not 0");
    }
    if event.timescale == 0 || event.event_duration == 0 || event.event_duration == u32::MAX {
        return Err("C2PA emsg timescale and event_duration do not cover the segment");
    }
    if span.covered_by(event.timescale, event.event_duration)? {
        Ok(())
    } else {
        Err("C2PA emsg event_duration is shorter than the segment's presentation span")
    }
}

/// One `emsg` message checked against the active session keys.
///
/// Success requires a key whose window contains `assessment_time`, a valid COSE
/// signature under that key, its `kid`, a protected `iat` (when present) that
/// also lies inside the key's window, a sequence number at or above the key's
/// delivery floor, exact `manifestId`, and a structural BMFF hash that
/// reproduces over the delivered bytes while excluding the carrying `emsg`
/// (`event_span`, absolute `[start, end)` in `segment`).
///
/// The two time checks are independent. `assessment_time` comes from the
/// caller, who vouches for when the segment was presented; `iat` comes from the
/// signer, so it can only add a constraint. Using `iat` in place of the
/// assessment time would let anyone holding an expired session key sign new
/// segments and backdate them into the window.
fn authenticate_segment_info(
    message: &[u8],
    segment: &[u8],
    event_span: (usize, usize),
    expected_manifest_id: &str,
    session_keys: &[ValidatedSessionKey],
    assessment_time: OffsetDateTime,
    algorithms: ClaimAlgorithmList,
) -> Option<VerifiedSegmentInfo> {
    let in_window = |key: &ValidatedSessionKey, at: OffsetDateTime| {
        (key.created_at..=key.expires_at).contains(&at)
    };
    for key in session_keys {
        if !in_window(key, assessment_time) {
            continue;
        }
        let Ok(verified) = verify_with_cose_key_with(message, &key.cose_key, algorithms) else {
            continue;
        };
        if verified.key_id.as_deref() != Some(key.key_id.as_slice()) {
            continue;
        }
        let iat_in_window = match protected_iat(message) {
            Ok(None) => true,
            Ok(Some(iat)) => numeric_date(iat).is_some_and(|signed_at| in_window(key, signed_at)),
            Err(_) => false,
        };
        if !iat_in_window {
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
        if !verify_bmff_hash(hash_map, segment, event_span) {
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

/// Section 19.4.1 `bmffHash` check over the delivered segment bytes.
///
/// Every exclusion is applied with its full 18.6.2 qualifiers (box-relative
/// `data` offsets, `length`, `version`, `flags`, `subset`), exactly as any
/// BMFF hash is. The `/emsg` exclusions are then judged by what they remove,
/// not by how they are spelled: at least one must exist and each must carry a
/// `data` qualifier on the C2PA scheme URI, together they must remove the whole
/// carrying C2PA `emsg`, and every byte they remove must belong to a
/// version-0 `emsg` whose `scheme_id_uri` is exactly the C2PA URI, so
/// ad-insertion and timed-metadata events stay authenticated. The `merkle`
/// field must be absent.
fn verify_bmff_hash(value: &Value, segment: &[u8], event_span: (usize, usize)) -> bool {
    let Some(map) = value.as_map() else {
        return false;
    };
    if map.iter().any(|(key, _)| key.as_text() == Some("merkle")) {
        return false;
    }
    let Ok(alg) = unique_field(map, "alg").and_then(nonempty_text) else {
        return false;
    };
    let Ok(expected) = unique_field(map, "hash").and_then(nonempty_bytes) else {
        return false;
    };
    let Ok(exclusions) = super::bmff_exclusion_maps(value) else {
        return false;
    };
    if !exclusions
        .iter()
        .all(|exclusion| allowed_live_bmff_exclusion(&exclusion.xpath))
    {
        return false;
    }
    let emsg_exclusions: Vec<_> = exclusions
        .iter()
        .filter(|exclusion| exclusion.xpath == "/emsg")
        .cloned()
        .collect();
    let names_c2pa_scheme = |exclusion: &crate::c2pa_formats::BmffExclusionMap| {
        exclusion.data.iter().any(|item| {
            item.value == SEGMENT_INFO_EXCLUSION_VALUE
                || item.value == SEGMENT_INFO_SCHEME_ID_URI.as_bytes()
        })
    };
    if emsg_exclusions.is_empty() || !emsg_exclusions.iter().all(names_c2pa_scheme) {
        return false;
    }
    let Ok(emsg_ranges) = crate::c2pa_formats::bmff_excluded_ranges(segment, &emsg_exclusions)
    else {
        return false;
    };
    let covers_event = emsg_ranges
        .iter()
        .any(|&(start, end)| start <= event_span.0 && event_span.1 <= end);
    if !covers_event || !emsg_exclusions_are_narrow(segment, &emsg_ranges) {
        return false;
    }
    crate::c2pa_formats::bmff_hash_with_exclusions(segment, alg, &exclusions)
        .is_ok_and(|actual| actual.as_slice() == expected)
}

/// True when every top-level box touched by `ranges` (sorted, merged, nonempty)
/// is a version-0 `emsg` whose `scheme_id_uri` is exactly the C2PA URI, in
/// either box-size form.
///
/// Range normalization merges touching ranges, so adjacent C2PA events removed
/// together arrive as ONE range spanning several boxes; it is consumed box by
/// box rather than required to fit a single box. Top-level boxes tile the
/// segment without gaps, so every byte a range covers belongs to some box, and
/// any touched box that is not a C2PA event (an unrelated `emsg`, `moof`,
/// `free`, ...) refuses the whole set.
fn emsg_exclusions_are_narrow(segment: &[u8], ranges: &[(usize, usize)]) -> bool {
    let mut next = 0usize;
    let walk = walk_top_level_boxes(segment, |item| {
        // Ranges ending at or before this box were judged by earlier boxes.
        while next < ranges.len() && ranges[next].1 <= item.start {
            next += 1;
        }
        let touched = next < ranges.len() && ranges[next].0 < item.end;
        let c2pa_event = item.box_type == *b"emsg"
            && version_0_scheme(item.body) == Some(SEGMENT_INFO_SCHEME_ID_URI.as_bytes());
        (touched && !c2pa_event).then_some(())
    });
    matches!(walk, Ok(None))
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
    /// Box start, header included, relative to the walked slice.
    start: usize,
    /// Box end (exclusive), relative to the walked slice.
    end: usize,
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
fn walk_top_level_boxes<'a, T>(
    mut data: &'a [u8],
    mut visit: impl FnMut(&BmffBox<'a>) -> Option<T>,
) -> Result<Option<T>, WalkDefect> {
    let mut walked = 0usize;
    let mut offset = 0usize;
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
            start: offset,
            end: offset + size,
            body: &data[header..size],
        }) {
            return Ok(Some(found));
        }
        data = &data[size..];
        offset += size;
    }
    Ok(None)
}

/// The fields of a C2PA verifiable-segment-info event message (a version-0
/// `emsg`, C2PA 2.4 section 19.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentInfoEvent<'a> {
    timescale: u32,
    presentation_time_delta: u32,
    event_duration: u32,
    /// Event `id`, unique within the session (section 19.4.2).
    id: u32,
    /// `message_data`: the encoded verifiable-segment-info.
    message: &'a [u8],
}

/// The C2PA event carried by an `emsg` body, or `Err` for any other event.
///
/// A C2PA event is a version-0 `emsg` whose scheme is the C2PA URI and whose
/// value is `fseg`, both matched EXACTLY before the payload is looked at. A
/// live stream legitimately carries unrelated `emsg` events (ad insertion,
/// timed metadata), and a validator that treated any event body as candidate
/// segment information would burn a signature check on each one -- and, worse,
/// would accept segment information published under a scheme that promises
/// something else entirely. A version-1 `emsg` is not a C2PA event: section
/// 19.4.2 fixes the version at 0.
fn segment_info_event(body: &[u8]) -> Result<SegmentInfoEvent<'_>, ()> {
    if body.len() < 4 || body[0] != 0 {
        return Err(());
    }
    let mut cursor = 4usize;
    let scheme = take_c_string(body, &mut cursor)?;
    let value = take_c_string(body, &mut cursor)?;
    if scheme != SEGMENT_INFO_SCHEME_ID_URI.as_bytes() || value != SEGMENT_INFO_VALUE.as_bytes() {
        return Err(());
    }
    let timescale = read_u32(body, cursor).ok_or(())?;
    let presentation_time_delta = read_u32(body, cursor + 4).ok_or(())?;
    let event_duration = read_u32(body, cursor + 8).ok_or(())?;
    let id = read_u32(body, cursor + 12).ok_or(())?;
    let message = body
        .get(cursor + 16..)
        .filter(|rest| !rest.is_empty())
        .ok_or(())?;
    Ok(SegmentInfoEvent {
        timescale,
        presentation_time_delta,
        event_duration,
        id,
        message,
    })
}

/// The `scheme_id_uri` of a version-0 `emsg` body, or `None` for any other
/// version. Section 19.4.2 fixes C2PA events at version 0, so a version-1
/// `emsg` that names the C2PA scheme is not a C2PA event and may not be
/// excluded from the hash as one.
fn version_0_scheme(body: &[u8]) -> Option<&[u8]> {
    if *body.first()? != 0 {
        return None;
    }
    let mut cursor = 4usize;
    take_c_string(body, &mut cursor).ok()
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

fn read_u64(data: &[u8], at: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(8)?)?;
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

/// Media timing the init segment declares for each track: the `mdhd`
/// timescale of each `trak` (keyed by its `tkhd` `track_ID`), the presentation
/// shift of its edit list, and any `mvex` `trex` default sample duration.
/// Section 19.4.2 requires the C2PA event to cover the whole segment, and only
/// the init segment says how a fragment's sample times map to presentation
/// time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitTrackTiming {
    tracks: Vec<InitTrack>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitTrack {
    track_id: u32,
    timescale: u32,
    default_sample_duration: Option<u32>,
    timeline: EditTimeline,
}

/// Most edit-list entries a track may declare. Real packagers write one to
/// three; the bound keeps the per-sample edit intersection linear.
const MAX_EDIT_ENTRIES: usize = 64;

/// How a track's composition times reach the movie (presentation) timeline.
///
/// Every value is an exact tick count of one presentation clock running at
/// `clock` ticks per second. Without an edit list the clock is the media
/// timescale and presentation time is composition time. With one, the clock is
/// `lcm(media timescale, movie timescale)`, so media ticks (times
/// `media_factor`) and movie ticks (an edit's position) are both whole numbers
/// of clock ticks and nothing is rounded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EditTimeline {
    clock: u64,
    media_factor: u64,
    /// `None` without an edit list (the identity map).
    edits: Option<Vec<MediaEdit>>,
}

/// One unit-rate edit: media clock ticks `[media_start, media_end)` are
/// presented from movie clock tick `movie_start` on. `media_end` is `None` for
/// the open-ended final edit fragmented files declare with duration 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MediaEdit {
    media_start: i128,
    media_end: Option<i128>,
    movie_start: i128,
}

impl EditTimeline {
    fn identity(timescale: u32) -> Self {
        Self {
            clock: u64::from(timescale),
            media_factor: 1,
            edits: None,
        }
    }

    /// Present the composition interval `[start, end)` (media ticks), handing
    /// each presented piece to `include` in clock ticks. Parts of the interval
    /// outside every edit are not presented and produce nothing.
    fn present(
        &self,
        start: i128,
        end: i128,
        mut include: impl FnMut(i128, i128),
    ) -> Result<(), &'static str> {
        let factor = i128::from(self.media_factor);
        let start = start.checked_mul(factor).ok_or(SEGMENT_TIMING_OVERFLOW)?;
        let end = end.checked_mul(factor).ok_or(SEGMENT_TIMING_OVERFLOW)?;
        let Some(edits) = &self.edits else {
            include(start, end);
            return Ok(());
        };
        for edit in edits {
            let low = start.max(edit.media_start);
            let high = edit.media_end.map_or(end, |media_end| end.min(media_end));
            if low >= high {
                continue;
            }
            let map = |media: i128| {
                media
                    .checked_sub(edit.media_start)
                    .and_then(|into_edit| edit.movie_start.checked_add(into_edit))
                    .ok_or(SEGMENT_TIMING_OVERFLOW)
            };
            include(map(low)?, map(high)?);
        }
        Ok(())
    }
}

impl InitTrackTiming {
    fn track(&self, track_id: u32) -> Option<&InitTrack> {
        self.tracks.iter().find(|track| track.track_id == track_id)
    }
}

/// FullBox field at the version-dependent offset shared by `mvhd`, `tkhd` and
/// `mdhd`: version 1 widens creation and modification times to 64 bits, so
/// `timescale` (mvhd, mdhd) and `track_ID` (tkhd) sit at 20, not 12.
fn header_field(body: &[u8]) -> Option<u32> {
    match body.first() {
        Some(0) => read_u32(body, 12),
        Some(1) => read_u32(body, 20),
        _ => None,
    }
}

/// Read [`InitTrackTiming`] from the init segment's single `moov`.
pub fn parse_init_track_timing(init_segment: &[u8]) -> Result<InitTrackTiming, &'static str> {
    const MALFORMED: &str = "init segment track timing is malformed";
    let mut moov = None;
    walk_top_level_boxes(init_segment, |item| {
        if item.box_type == *b"moov" {
            if moov.is_some() {
                return Some(());
            }
            moov = Some(item.body);
        }
        None
    })
    .map_err(|_| MALFORMED)?
    .map_or(Ok(()), |()| Err("init segment has more than one moov"))?;
    let moov = moov.ok_or("init segment has no moov")?;

    // Tracks are read after the walk: an empty edit is measured in the movie
    // timescale, and `mvhd` may follow the `trak` boxes.
    let mut movie_timescale = None;
    let mut traks = Vec::new();
    let mut defaults = Vec::new();
    let mut defect = None;
    walk_top_level_boxes(moov, |item| {
        let parsed = match &item.box_type {
            b"mvhd" => {
                movie_timescale = header_field(item.body);
                Ok(())
            }
            b"trak" => {
                traks.push(item.body);
                Ok(())
            }
            b"mvex" => walk_top_level_boxes(item.body, |child| {
                if child.box_type != *b"trex" {
                    return None;
                }
                match (read_u32(child.body, 4), read_u32(child.body, 12)) {
                    (Some(track_id), Some(duration)) => {
                        defaults.push((track_id, duration));
                        None
                    }
                    _ => Some(()),
                }
            })
            .map_err(|_| MALFORMED)
            .and_then(|stopped| stopped.map_or(Ok(()), |()| Err(MALFORMED))),
            _ => Ok(()),
        };
        match parsed {
            Ok(()) => None,
            Err(reason) => {
                defect = Some(reason);
                Some(())
            }
        }
    })
    .map_err(|_| MALFORMED)?;
    if let Some(reason) = defect {
        return Err(reason);
    }
    let mut timing = InitTrackTiming::default();
    for trak in traks {
        let track = trak_timing(trak, movie_timescale)?;
        if timing.track(track.track_id).is_some() {
            return Err("init segment declares a track_ID twice");
        }
        timing.tracks.push(track);
    }
    for (track_id, duration) in defaults {
        let Some(track) = timing
            .tracks
            .iter_mut()
            .find(|track| track.track_id == track_id)
        else {
            return Err("init segment trex names an undeclared track");
        };
        if track.default_sample_duration.replace(duration).is_some() {
            return Err("init segment declares two trex boxes for one track");
        }
    }
    Ok(timing)
}

/// `track_ID` from `trak/tkhd`, timescale from `trak/mdia/mdhd`, and the
/// presentation shift from `trak/edts/elst`.
fn trak_timing(trak: &[u8], movie_timescale: Option<u32>) -> Result<InitTrack, &'static str> {
    const MALFORMED: &str = "init segment track timing is malformed";
    let mut track_id = None;
    let mut timescale = None;
    let mut edts = None;
    let mut duplicate_edts = false;
    walk_top_level_boxes(trak, |item| {
        match &item.box_type {
            b"tkhd" => track_id = header_field(item.body),
            b"mdia" => {
                let _ = walk_top_level_boxes(item.body, |child| {
                    (child.box_type == *b"mdhd").then(|| timescale = header_field(child.body))
                });
            }
            b"edts" => duplicate_edts |= edts.replace(item.body).is_some(),
            _ => {}
        }
        None::<()>
    })
    .map_err(|_| MALFORMED)?;
    if duplicate_edts {
        return Err(UNSUPPORTED_EDIT_LIST);
    }
    let track_id = track_id.ok_or("init segment track has no readable tkhd track_ID")?;
    let timescale = timescale
        .filter(|timescale| *timescale != 0)
        .ok_or("init segment track has no nonzero mdhd timescale")?;
    let timeline = match edts {
        Some(edts) => edit_timeline(edts, timescale, movie_timescale)?,
        None => EditTimeline::identity(timescale),
    };
    Ok(InitTrack {
        track_id,
        timescale,
        default_sample_duration: None,
        timeline,
    })
}

const UNSUPPORTED_EDIT_LIST: &str = "init segment edit list cannot be applied to segment timing";

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

/// The presentation timeline one `edts` box gives its track.
///
/// Supported: no `elst` or an `elst` with no entries (the identity map), or up
/// to [`MAX_EDIT_ENTRIES`] unit-rate entries walked in order along the movie
/// timeline. An empty edit (`media_time` -1) advances the movie position by
/// its `segment_duration` (movie timescale) and presents nothing; its rate is
/// not consulted. A media edit (`media_time` >= 0, `media_rate` exactly 1.0)
/// presents media `[media_time, media_time + segment_duration)` (the duration
/// converted from movie to media time) from the current movie position, then
/// advances it. A media edit with duration 0 is the open-ended final edit
/// fragmented files write (FFmpeg: a 200-tick empty edit, then `media_time`
/// 2048 with duration 0) and is accepted only as the last entry. Dwells, other
/// rates, `media_time` below -1, a list with no media edit, a second `elst`, an
/// unknown `elst` version, and a missing or zero `mvhd` timescale are refused,
/// never guessed. All positions are exact ticks of `lcm(media, movie)`
/// timescale; arithmetic that overflows is refused, not rounded.
fn edit_timeline(
    edts: &[u8],
    media_timescale: u32,
    movie_timescale: Option<u32>,
) -> Result<EditTimeline, &'static str> {
    const MALFORMED: &str = "init segment track timing is malformed";
    let mut elst = None;
    let mut duplicate = false;
    walk_top_level_boxes(edts, |child| {
        if child.box_type == *b"elst" {
            duplicate |= elst.replace(child.body).is_some();
        }
        None::<()>
    })
    .map_err(|_| MALFORMED)?;
    if duplicate {
        return Err(UNSUPPORTED_EDIT_LIST);
    }
    let Some(elst) = elst else {
        return Ok(EditTimeline::identity(media_timescale));
    };
    let entry_len = match elst.first() {
        Some(0) => 12usize,
        Some(1) => 20,
        Some(_) => return Err(UNSUPPORTED_EDIT_LIST),
        None => return Err(MALFORMED),
    };
    let count = usize::try_from(read_u32(elst, 4).ok_or(MALFORMED)?).map_err(|_| MALFORMED)?;
    if count == 0 {
        return Ok(EditTimeline::identity(media_timescale));
    }
    if count > MAX_EDIT_ENTRIES {
        return Err(UNSUPPORTED_EDIT_LIST);
    }
    let table = count
        .checked_mul(entry_len)
        .and_then(|length| elst.get(8..8usize.checked_add(length)?))
        .ok_or(MALFORMED)?;
    let movie_timescale = movie_timescale
        .filter(|timescale| *timescale != 0)
        .ok_or("init segment edit list needs a nonzero mvhd timescale")?;
    let media = u64::from(media_timescale);
    let movie = u64::from(movie_timescale);
    let clock = (media / gcd(media, movie))
        .checked_mul(movie)
        .ok_or(UNSUPPORTED_EDIT_LIST)?;
    let media_factor = i128::from(clock / media);
    let movie_factor = i128::from(clock / movie);

    let mut movie_position = 0i128; // movie timescale ticks
    let mut edits = Vec::with_capacity(count);
    for (index, entry) in table.chunks_exact(entry_len).enumerate() {
        let (segment_duration, media_time, rate) = if entry_len == 12 {
            let time = read_u32(entry, 4).ok_or(MALFORMED)?;
            (
                u64::from(read_u32(entry, 0).ok_or(MALFORMED)?),
                i64::from(i32::from_be_bytes(time.to_be_bytes())),
                &entry[8..12],
            )
        } else {
            let time = read_u64(entry, 8).ok_or(MALFORMED)?;
            (
                read_u64(entry, 0).ok_or(MALFORMED)?,
                i64::from_be_bytes(time.to_be_bytes()),
                &entry[16..20],
            )
        };
        let duration = i128::from(segment_duration);
        match media_time {
            -1 => {}
            time if time >= 0 && rate == [0, 1, 0, 0] => {
                let media_start = i128::from(time)
                    .checked_mul(media_factor)
                    .ok_or(UNSUPPORTED_EDIT_LIST)?;
                let media_end = if segment_duration > 0 {
                    // dur movie ticks = dur * movie_factor clock ticks.
                    Some(
                        duration
                            .checked_mul(movie_factor)
                            .and_then(|length| media_start.checked_add(length))
                            .ok_or(UNSUPPORTED_EDIT_LIST)?,
                    )
                } else if index + 1 == count {
                    None
                } else {
                    return Err(UNSUPPORTED_EDIT_LIST);
                };
                edits.push(MediaEdit {
                    media_start,
                    media_end,
                    movie_start: movie_position
                        .checked_mul(movie_factor)
                        .ok_or(UNSUPPORTED_EDIT_LIST)?,
                });
            }
            _ => return Err(UNSUPPORTED_EDIT_LIST),
        }
        movie_position = movie_position
            .checked_add(duration)
            .ok_or(UNSUPPORTED_EDIT_LIST)?;
    }
    if edits.is_empty() {
        return Err(UNSUPPORTED_EDIT_LIST);
    }
    Ok(EditTimeline {
        clock,
        media_factor: clock / media,
        edits: Some(edits),
    })
}

const SEGMENT_TIMING_MALFORMED: &str = "media segment fragment timing is malformed";
const SEGMENT_TIMING_OVERFLOW: &str = "media segment timing exceeds verifier arithmetic bounds";

/// An exact presentation instant: `ticks / timescale` seconds in one track's
/// media timescale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MediaInstant {
    ticks: i128,
    timescale: u64,
}

impl MediaInstant {
    /// Exact ordering against an instant in another timescale, by
    /// cross-multiplication.
    fn compare(self, other: Self) -> Result<std::cmp::Ordering, &'static str> {
        let left = self
            .ticks
            .checked_mul(i128::from(other.timescale))
            .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        let right = other
            .ticks
            .checked_mul(i128::from(self.timescale))
            .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        Ok(left.cmp(&right))
    }
}

/// A media segment's presentation span: from its origin, the earliest sample
/// presentation start of any track, to its end, the latest sample presentation
/// end of any track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SegmentSpan {
    origin: MediaInstant,
    end: MediaInstant,
}

impl SegmentSpan {
    /// Whether an event of `event_duration / timescale` seconds starting at the
    /// origin reaches the end. With origin `o / To` and end `e / Te` that is
    /// `event_duration * Te * To >= (e * To - o * Te) * timescale`, evaluated
    /// exactly; an overflow is reported, never rounded away.
    fn covered_by(&self, timescale: u32, event_duration: u32) -> Result<bool, &'static str> {
        let end_scale = i128::from(self.end.timescale);
        let origin_scale = i128::from(self.origin.timescale);
        let span = self
            .end
            .ticks
            .checked_mul(origin_scale)
            .zip(self.origin.ticks.checked_mul(end_scale))
            .and_then(|(end, origin)| end.checked_sub(origin))
            .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        let needed = span
            .checked_mul(i128::from(timescale))
            .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        let offered = i128::from(event_duration)
            .checked_mul(end_scale)
            .and_then(|scaled| scaled.checked_mul(origin_scale))
            .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        Ok(offered >= needed)
    }
}

/// One track's running decode time and presentation extent within a segment.
struct TrackPresentation {
    track_id: u32,
    timescale: u64,
    /// Whether this track's first `traf` carried a `tfdt`; every later `traf`
    /// of the track must agree.
    anchored: bool,
    /// Decode time of the track's next sample, in media timescale units.
    decode_time: i128,
    /// Earliest sample presentation start and latest end, once a sample is seen.
    extent: Option<(i128, i128)>,
}

impl TrackPresentation {
    fn include(&mut self, start: i128, end: i128) {
        self.extent = Some(
            self.extent
                .map_or((start, end), |(low, high)| (low.min(start), high.max(end))),
        );
    }
}

/// The presentation span of a media segment across every track and fragment.
///
/// Decode time starts at each `traf`'s `tfdt` (`baseMediaDecodeTime`) and
/// advances by each sample's duration through that `traf`'s `trun` boxes in
/// order. A sample's composition interval runs from its decode time plus its
/// `trun` composition offset (unsigned in version 0, signed in version 1)
/// for its duration, and the track's edit list maps it onto the movie
/// timeline ([`EditTimeline::present`]); media outside every edit is not
/// presented. Gaps between fragments, tracks that start at different times,
/// edit delays, and reordered composition therefore widen the span exactly as
/// they do on screen; a sum of durations would hide them.
///
/// Without `tfdt`, a fragment's decode time is implied only by fragments
/// outside this segment. That is safe only for a single-track segment none of
/// whose fragments carries one, on a track without an edit list: under the
/// identity map the span does not depend on where the track starts, and its
/// fragments run back to back. An edit list places media by absolute media
/// time, so a `tfdt`-less fragment under one is refused, as is a track that
/// mixes fragments with and without `tfdt` or a `tfdt`-less fragment beside
/// another track. A segment with no timed sample has no span.
fn segment_presentation_span(
    segment: &[u8],
    timing: &InitTrackTiming,
) -> Result<SegmentSpan, &'static str> {
    let mut tracks: Vec<TrackPresentation> = Vec::new();
    let mut defect = None;
    walk_top_level_boxes(segment, |item| {
        if item.box_type != *b"moof" {
            return None;
        }
        let walked = walk_top_level_boxes(item.body, |child| {
            if child.box_type != *b"traf" {
                return None;
            }
            traf_presentation(child.body, timing, &mut tracks).err()
        });
        match walked {
            Ok(None) => None,
            Ok(Some(reason)) => {
                defect = Some(reason);
                Some(())
            }
            Err(_) => {
                defect = Some(SEGMENT_TIMING_MALFORMED);
                Some(())
            }
        }
    })
    .map_err(|_| SEGMENT_TIMING_MALFORMED)?;
    if let Some(reason) = defect {
        return Err(reason);
    }
    if tracks.len() > 1 && tracks.iter().any(|track| !track.anchored) {
        return Err(
            "media segment has a fragment without tfdt beside another track, \
             so its tracks cannot be aligned",
        );
    }
    let mut origin: Option<MediaInstant> = None;
    let mut end: Option<MediaInstant> = None;
    for track in &tracks {
        let Some((start, stop)) = track.extent else {
            continue;
        };
        let start = MediaInstant {
            ticks: start,
            timescale: track.timescale,
        };
        let stop = MediaInstant {
            ticks: stop,
            timescale: track.timescale,
        };
        if origin.map_or(Ok(true), |known| {
            start.compare(known).map(|order| order.is_lt())
        })? {
            origin = Some(start);
        }
        if end.map_or(Ok(true), |known| {
            stop.compare(known).map(|order| order.is_gt())
        })? {
            end = Some(stop);
        }
    }
    match (origin, end) {
        (Some(origin), Some(end)) => Ok(SegmentSpan { origin, end }),
        _ => Err("media segment carries no timed samples"),
    }
}

/// Place one `traf`'s samples on its track's presentation timeline.
///
/// A sample's duration is its `trun` entry when present (flag 0x000100), else
/// the `tfhd` default (flag 0x000008), else the init segment's `trex` default;
/// a sample with none of these cannot be timed.
fn traf_presentation(
    traf: &[u8],
    timing: &InitTrackTiming,
    tracks: &mut Vec<TrackPresentation>,
) -> Result<(), &'static str> {
    const MALFORMED: &str = SEGMENT_TIMING_MALFORMED;
    let mut tfhd = None;
    let mut tfdt = None;
    let mut duplicate = false;
    let mut truns = Vec::new();
    walk_top_level_boxes(traf, |item| {
        match &item.box_type {
            b"tfhd" => duplicate |= tfhd.replace(item.body).is_some(),
            b"tfdt" => duplicate |= tfdt.replace(item.body).is_some(),
            b"trun" => truns.push(item.body),
            _ => {}
        }
        None::<()>
    })
    .map_err(|_| MALFORMED)?;
    if duplicate {
        return Err(MALFORMED);
    }
    let tfhd = tfhd.ok_or(MALFORMED)?;
    let flags = read_u32(tfhd, 0).ok_or(MALFORMED)? & 0x00FF_FFFF;
    let track_id = read_u32(tfhd, 4).ok_or(MALFORMED)?;
    let track = timing
        .track(track_id)
        .ok_or("media segment fragment names a track the init segment does not declare")?;
    let mut cursor = 8usize;
    if flags & 0x01 != 0 {
        cursor += 8; // base_data_offset
    }
    if flags & 0x02 != 0 {
        cursor += 4; // sample_description_index
    }
    let default_duration = if flags & 0x08 != 0 {
        Some(read_u32(tfhd, cursor).ok_or(MALFORMED)?)
    } else {
        track.default_sample_duration
    };
    let base_decode_time = match tfdt {
        None => None,
        Some(body) => Some(match body.first() {
            Some(0) => u64::from(read_u32(body, 4).ok_or(MALFORMED)?),
            Some(1) => read_u64(body, 4).ok_or(MALFORMED)?,
            _ => return Err(MALFORMED),
        }),
    };
    let index = match tracks.iter().position(|known| known.track_id == track_id) {
        Some(index) => {
            if tracks[index].anchored != base_decode_time.is_some() {
                return Err("media segment track mixes fragments with and without tfdt");
            }
            index
        }
        None => {
            // Without tfdt the track's decode origin is only known up to a
            // constant, which the span ignores under the identity map. An edit
            // list clips and places media by ABSOLUTE media time, so an assumed
            // origin could move samples out of an edit and undercount the
            // segment; that timing is not established, so it is refused.
            if base_decode_time.is_none() && track.timeline.edits.is_some() {
                return Err("media segment fragment has no tfdt under an edit list, \
                     so its presentation timing cannot be established");
            }
            tracks.push(TrackPresentation {
                track_id,
                timescale: track.timeline.clock,
                anchored: base_decode_time.is_some(),
                decode_time: 0,
                extent: None,
            });
            tracks.len() - 1
        }
    };
    let state = &mut tracks[index];
    if let Some(base) = base_decode_time {
        state.decode_time = i128::from(base);
    }
    let timeline = &track.timeline;
    let no_duration = "media segment sample has no duration in trun, tfhd or trex";

    for trun in truns {
        let version = *trun.first().ok_or(MALFORMED)?;
        if version > 1 {
            return Err(MALFORMED);
        }
        let flags = read_u32(trun, 0).ok_or(MALFORMED)? & 0x00FF_FFFF;
        let sample_count = read_u32(trun, 4).ok_or(MALFORMED)?;
        let mut cursor = 8usize;
        if flags & 0x01 != 0 {
            cursor += 4; // data_offset
        }
        if flags & 0x04 != 0 {
            cursor += 4; // first_sample_flags
        }
        let present = |bits: &[u32]| bits.iter().filter(|bit| flags & **bit != 0).count() * 4;
        let stride = present(&[0x100, 0x200, 0x400, 0x800]);
        // Per-sample fields are duration, size, flags, composition offset.
        let composition_at = present(&[0x100, 0x200, 0x400]);
        let samples = usize::try_from(sample_count).map_err(|_| MALFORMED)?;
        let table_end = samples
            .checked_mul(stride)
            .and_then(|table| table.checked_add(cursor))
            .ok_or(MALFORMED)?;
        if table_end > trun.len() {
            return Err(MALFORMED);
        }
        if samples == 0 {
            continue;
        }
        if stride == 0 {
            // Every sample takes the default duration and no composition
            // offset, so the run is one contiguous interval. Computed in closed
            // form: an empty sample table does not bound `sample_count`.
            let length = i128::from(sample_count)
                .checked_mul(i128::from(default_duration.ok_or(no_duration)?))
                .ok_or(SEGMENT_TIMING_OVERFLOW)?;
            let start = state.decode_time;
            let end = start.checked_add(length).ok_or(SEGMENT_TIMING_OVERFLOW)?;
            timeline.present(start, end, |low, high| state.include(low, high))?;
            state.decode_time = state
                .decode_time
                .checked_add(length)
                .ok_or(SEGMENT_TIMING_OVERFLOW)?;
            continue;
        }
        // The sample table is present, so `trun.len()` bounds this loop.
        for sample in 0..samples {
            let entry = cursor + sample * stride;
            let duration = if flags & 0x100 != 0 {
                read_u32(trun, entry).ok_or(MALFORMED)?
            } else {
                default_duration.ok_or(no_duration)?
            };
            let composition_offset = if flags & 0x800 == 0 {
                0
            } else {
                let raw = read_u32(trun, entry + composition_at).ok_or(MALFORMED)?;
                if version == 0 {
                    i128::from(raw)
                } else {
                    i128::from(i32::from_be_bytes(raw.to_be_bytes()))
                }
            };
            let start = state
                .decode_time
                .checked_add(composition_offset)
                .ok_or(SEGMENT_TIMING_OVERFLOW)?;
            let end = start
                .checked_add(i128::from(duration))
                .ok_or(SEGMENT_TIMING_OVERFLOW)?;
            timeline.present(start, end, |low, high| state.include(low, high))?;
            state.decode_time = state
                .decode_time
                .checked_add(i128::from(duration))
                .ok_or(SEGMENT_TIMING_OVERFLOW)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use time::macros::datetime;

    const MANIFEST_ID: &str = "urn:c2pa:3f1c2d5e-8a7b-4c6d-9e0f-1a2b3c4d5e6f";
    const SCHEME_NUL: &[u8] = b"urn:c2pa:verifiable-segment-info\0";

    fn iso(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(8 + body.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    }

    /// A box written with the 64-bit `largesize` header form.
    fn iso_large(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = 1u32.to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(&u64::try_from(16 + body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn full(version: u8, flags: u32, fields: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![version];
        out.extend_from_slice(&flags.to_be_bytes()[1..]);
        for field in fields {
            out.extend_from_slice(field);
        }
        out
    }

    fn be(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    fn text(value: &str) -> Value {
        Value::Text(value.into())
    }

    /// One video track (ID 1) at a 90 kHz timescale whose `trex` default sample
    /// duration is 3000 ticks.
    fn init_segment() -> Vec<u8> {
        let tkhd = iso(b"tkhd", &full(0, 3, &[&[0; 8], &be(1), &[0; 4]]));
        let mdhd = iso(b"mdhd", &full(0, 0, &[&[0; 8], &be(90_000), &be(0)]));
        let trak = iso(b"trak", &[tkhd, iso(b"mdia", &mdhd)].concat());
        let trex = iso(
            b"trex",
            &full(0, 0, &[&be(1), &be(1), &be(3000), &be(0), &be(0)]),
        );
        let moov = iso(b"moov", &[trak, iso(b"mvex", &trex)].concat());
        [iso(b"ftyp", b"isom\0\0\0\0isomiso6"), moov].concat()
    }

    /// Two samples of track 1, each timed by the `trex` default: 6000 ticks of
    /// a 90 kHz clock, 1/15 s.
    fn fragment(track_id: u32) -> Vec<u8> {
        let tfhd = iso(b"tfhd", &full(0, 0x02_0000, &[&be(track_id)]));
        let trun = iso(b"trun", &full(0, 0, &[&be(2)]));
        let traf = iso(b"traf", &[tfhd, trun].concat());
        let moof = iso(
            b"moof",
            &[iso(b"mfhd", &full(0, 0, &[&be(1)])), traf].concat(),
        );
        [moof, iso(b"mdat", b"two samples of media")].concat()
    }

    /// A session signer: private scalar seed, `kid`, and the start of its
    /// one-hour window.
    #[derive(Clone, Copy)]
    struct TestKey {
        seed: u8,
        algorithm: i128,
        kid: &'static [u8],
        created_at: OffsetDateTime,
    }

    /// Key A, valid 12:00 to 13:00 on the test day.
    const KEY_A: TestKey = TestKey {
        seed: 7,
        algorithm: -7,
        kid: b"session-key-1",
        created_at: datetime!(2026-10-26 12:00 UTC),
    };

    /// Key B, valid 14:00 to 15:00: disjoint from key A's window.
    const KEY_B: TestKey = TestKey {
        seed: 9,
        algorithm: -7,
        kid: b"session-key-2",
        created_at: datetime!(2026-10-26 14:00 UTC),
    };

    /// The trusted presentation-assessment time of the single-segment cases,
    /// inside key A's window.
    const ASSESSED: OffsetDateTime = datetime!(2026-10-26 12:30 UTC);

    impl TestKey {
        fn signing_key(self) -> SigningKey {
            SigningKey::from_bytes((&[self.seed; 32]).into()).unwrap()
        }

        fn expires_at(self) -> OffsetDateTime {
            self.created_at + time::Duration::hours(1)
        }

        /// An honest signing time, one minute into the window.
        fn honest_iat(self) -> OffsetDateTime {
            self.created_at + time::Duration::minutes(1)
        }

        fn session_key(self) -> ValidatedSessionKey {
            let point = self.signing_key().verifying_key().to_sec1_point(false);
            let cose_key = encode(
                &Value::Map(vec![
                    (Value::Integer(1), Value::Integer(2)),
                    (Value::Integer(2), Value::Bytes(self.kid.to_vec())),
                    (Value::Integer(3), Value::Integer(self.algorithm)),
                    (Value::Integer(-1), Value::Integer(1)),
                    (
                        Value::Integer(-2),
                        Value::Bytes(point.x().unwrap().to_vec()),
                    ),
                    (
                        Value::Integer(-3),
                        Value::Bytes(point.y().unwrap().to_vec()),
                    ),
                ]),
                Profile::CanonicalForHashedSubstructures,
            )
            .unwrap();
            ValidatedSessionKey {
                cose_key,
                key_id: self.kid.to_vec(),
                minimum_sequence_number: 1,
                created_at: self.created_at,
                expires_at: self.expires_at(),
            }
        }

        /// COSE_Sign1 over `payload`, with a protected `iat` when one is given.
        fn sign(self, payload: &[u8], iat: Option<OffsetDateTime>) -> Vec<u8> {
            let mut header = vec![(Value::Integer(1), Value::Integer(self.algorithm))];
            if let Some(iat) = iat {
                header.push((
                    Value::Integer(6),
                    Value::Integer(i128::from(iat.unix_timestamp())),
                ));
            }
            let protected = encode(&Value::Map(header), Profile::LegacyPipelineBDefinite).unwrap();
            let to_be_signed = encode(
                &Value::Array(vec![
                    text("Signature1"),
                    Value::Bytes(protected.clone()),
                    Value::Bytes(Vec::new()),
                    Value::Bytes(payload.to_vec()),
                ]),
                Profile::LegacyPipelineBDefinite,
            )
            .unwrap();
            let signature: Signature = self.signing_key().sign(&to_be_signed);
            encode(
                &Value::Tag(
                    18,
                    Box::new(Value::Array(vec![
                        Value::Bytes(protected),
                        Value::Map(vec![(Value::Integer(4), Value::Bytes(self.kid.to_vec()))]),
                        Value::Bytes(payload.to_vec()),
                        Value::Bytes(signature.to_bytes().to_vec()),
                    ])),
                ),
                Profile::LegacyPipelineBDefinite,
            )
            .unwrap()
        }
    }

    fn emsg_exclusion(offset: i128, value: &[u8]) -> Value {
        Value::Map(vec![
            (text("xpath"), text("/emsg")),
            (
                text("data"),
                Value::Array(vec![Value::Map(vec![
                    (text("offset"), Value::Integer(offset)),
                    (text("value"), Value::Bytes(value.to_vec())),
                ])]),
            ),
        ])
    }

    /// [`emsg_exclusion`] with an 18.6.2 FullBox `version` qualifier.
    fn versioned_emsg_exclusion(offset: i128, value: &[u8], version: i128) -> Value {
        let Value::Map(mut fields) = emsg_exclusion(offset, value) else {
            unreachable!("emsg_exclusion builds a map");
        };
        fields.push((text("version"), Value::Integer(version)));
        Value::Map(fields)
    }

    /// One segment's C2PA event and the boxes around it. Every field defaults
    /// to the section 19.4.1/19.4.2 shape, signed by key A with an honest `iat`.
    struct Case {
        value: &'static [u8],
        timescale: u32,
        presentation_time_delta: u32,
        event_duration: u32,
        large_box: bool,
        exclusions: Vec<Value>,
        merkle: bool,
        other_event: Option<Vec<u8>>,
        media: Vec<u8>,
        sequence_number: i128,
        key: TestKey,
        iat: Option<OffsetDateTime>,
        /// The unsigned `emsg` `id`; `None` uses the sequence number, so the
        /// segments of one test stream carry distinct ids.
        event_id: Option<u32>,
    }

    impl Default for Case {
        fn default() -> Self {
            Self {
                value: b"fseg",
                timescale: 1000,
                presentation_time_delta: 0,
                // 67 ms covers 1/15 s; 66 ms does not.
                event_duration: 67,
                large_box: false,
                exclusions: vec![emsg_exclusion(12, SCHEME_NUL)],
                merkle: false,
                other_event: None,
                media: fragment(1),
                sequence_number: 1,
                key: KEY_A,
                iat: Some(KEY_A.honest_iat()),
                event_id: None,
            }
        }
    }

    impl Case {
        fn assemble(&self, hash: Vec<u8>) -> Vec<u8> {
            let mut bmff_hash = vec![
                (text("alg"), text("sha256")),
                (text("hash"), Value::Bytes(hash)),
                (text("exclusions"), Value::Array(self.exclusions.clone())),
            ];
            if self.merkle {
                bmff_hash.push((text("merkle"), Value::Array(Vec::new())));
            }
            let payload = encode(
                &Value::Map(vec![
                    (text("sequenceNumber"), Value::Integer(self.sequence_number)),
                    (text("manifestId"), text(MANIFEST_ID)),
                    (text("bmffHash"), Value::Map(bmff_hash)),
                ]),
                Profile::CanonicalForHashedSubstructures,
            )
            .unwrap();
            let mut value = self.value.to_vec();
            value.push(0);
            let body = full(
                0,
                0,
                &[
                    SCHEME_NUL,
                    &value,
                    &be(self.timescale),
                    &be(self.presentation_time_delta),
                    &be(self.event_duration),
                    &be(self
                        .event_id
                        .unwrap_or_else(|| u32::try_from(self.sequence_number).unwrap())),
                    &self.key.sign(&payload, self.iat),
                ],
            );
            let emsg = if self.large_box {
                iso_large(b"emsg", &body)
            } else {
                iso(b"emsg", &body)
            };
            [
                iso(b"styp", b"msdh\0\0\0\0msdhmsix"),
                emsg,
                self.other_event.clone().unwrap_or_default(),
                self.media.clone(),
            ]
            .concat()
        }

        /// The segment, with a `bmffHash` computed over its final bytes.
        /// Signatures and digests have fixed lengths, so the draft and the
        /// final segment share every box offset.
        fn segment(&self) -> Vec<u8> {
            let draft = self.assemble(vec![0; 32]);
            let maps = super::super::bmff_exclusion_maps(&Value::Map(vec![(
                text("exclusions"),
                Value::Array(self.exclusions.clone()),
            )]))
            .unwrap();
            let hash =
                crate::c2pa_formats::bmff_hash_with_exclusions(&draft, "sha256", &maps).unwrap();
            self.assemble(hash)
        }
    }

    fn other_event(scheme: &[u8]) -> Vec<u8> {
        iso(
            b"emsg",
            &full(
                0,
                0,
                &[
                    scheme,
                    b"\0",
                    b"1\0",
                    &be(1000),
                    &be(0),
                    &be(67),
                    &be(9),
                    b"splice",
                ],
            ),
        )
    }

    fn validate_with(
        init: &[u8],
        segment: &[u8],
        keys: &[ValidatedSessionKey],
        assessment_time: OffsetDateTime,
    ) -> (Option<VerifiedSegmentInfo>, ValidationResults) {
        let timing = parse_init_track_timing(init);
        let mut results = ValidationResults::default();
        let verified = validate_emsg_segment_with(
            LiveVideoApplicability::new(StreamMethod::VerifiableSegmentInfo),
            segment,
            0,
            &mut SessionEventIds::default(),
            timing.as_ref().map_err(|defect| *defect),
            Some(1),
            MANIFEST_ID,
            keys,
            assessment_time,
            ClaimAlgorithmList::V2_4,
            &mut results,
            "self#segment=1",
        );
        (verified, results)
    }

    fn validate_at(
        segment: &[u8],
        assessment_time: OffsetDateTime,
    ) -> (Option<VerifiedSegmentInfo>, ValidationResults) {
        validate_with(
            &init_segment(),
            segment,
            &[KEY_A.session_key()],
            assessment_time,
        )
    }

    fn validate(segment: &[u8]) -> (Option<VerifiedSegmentInfo>, ValidationResults) {
        validate_at(segment, ASSESSED)
    }

    fn assert_rejected(case: Case, why: &str) {
        let (verified, results) = validate(&case.segment());
        assert!(verified.is_none(), "{why}");
        assert!(
            results
                .failure
                .iter()
                .any(|status| status.code == LIVEVIDEO_SEGMENT_INVALID),
            "{why}: {results:?}"
        );
    }

    #[test]
    fn a_section_19_4_event_authenticates_its_segment() {
        let (verified, results) = validate(&Case::default().segment());
        let verified = verified.unwrap_or_else(|| panic!("{results:?}"));
        assert_eq!(verified.sequence_number, 1);
        assert_eq!(verified.manifest_id, MANIFEST_ID);
        assert!(results.failure.is_empty(), "{results:?}");
    }

    #[test]
    fn the_event_value_must_be_fseg() {
        assert_rejected(
            Case {
                value: b"c2pa",
                ..Case::default()
            },
            "the pre-19.4.2 value c2pa is not a C2PA event",
        );
    }

    #[test]
    fn presentation_time_delta_must_be_zero() {
        assert_rejected(
            Case {
                presentation_time_delta: 1,
                ..Case::default()
            },
            "presentation_time_delta 1",
        );
    }

    #[test]
    fn the_event_must_cover_the_whole_segment() {
        for (timescale, event_duration) in [(1000, 66), (1000, 0), (0, 67), (1000, u32::MAX)] {
            assert_rejected(
                Case {
                    timescale,
                    event_duration,
                    ..Case::default()
                },
                &format!("{event_duration}/{timescale} s against 1/15 s of media"),
            );
        }
        let (exact, results) = validate(
            &Case {
                timescale: 90_000,
                event_duration: 6000,
                ..Case::default()
            }
            .segment(),
        );
        assert!(
            exact.is_some(),
            "an exact cover in the media timescale: {results:?}"
        );
    }

    #[test]
    fn a_fragment_of_an_undeclared_track_cannot_be_timed() {
        assert_rejected(
            Case {
                media: fragment(2),
                ..Case::default()
            },
            "track 2 is not in the init segment",
        );
    }

    #[test]
    fn the_bmff_hash_must_carry_no_merkle_tree() {
        assert_rejected(
            Case {
                merkle: true,
                ..Case::default()
            },
            "merkle field present",
        );
    }

    #[test]
    fn an_unqualified_emsg_exclusion_is_refused() {
        assert_rejected(
            Case {
                exclusions: vec![Value::Map(vec![(text("xpath"), text("/emsg"))])],
                ..Case::default()
            },
            "bare /emsg exclusion",
        );
    }

    #[test]
    fn an_exclusion_that_also_removes_another_event_is_refused() {
        // Without the NUL, the qualifier also selects a scheme that merely starts
        // with the C2PA URI, so that unsigned event would escape the hash.
        let lookalike = other_event(b"urn:c2pa:verifiable-segment-info-x");
        assert_rejected(
            Case {
                exclusions: vec![emsg_exclusion(12, SCHEME_NUL.split_last().unwrap().1)],
                other_event: Some(lookalike.clone()),
                ..Case::default()
            },
            "exclusion removes a non-C2PA emsg",
        );
        let (verified, results) = validate(
            &Case {
                other_event: Some(lookalike),
                ..Case::default()
            }
            .segment(),
        );
        assert!(
            verified.is_some(),
            "with the NUL the lookalike is hashed: {results:?}"
        );
    }

    #[test]
    fn the_exclusion_must_remove_the_carrying_event() {
        // Matches nothing: offset 0 is the box size field under 18.6.2.
        assert_rejected(
            Case {
                exclusions: vec![emsg_exclusion(0, SCHEME_NUL)],
                ..Case::default()
            },
            "the literal 19.4.1 offset 0 selects no emsg",
        );
    }

    #[test]
    fn other_events_stay_authenticated() {
        let case = Case {
            other_event: Some(other_event(b"urn:scte:scte35:2013:bin")),
            ..Case::default()
        };
        let segment = case.segment();
        let (verified, results) = validate(&segment);
        assert!(verified.is_some(), "{results:?}");

        let splice = segment
            .windows(6)
            .position(|bytes| bytes == b"splice")
            .unwrap();
        let mut edited = segment;
        edited[splice] ^= 0x01;
        let (verified, _) = validate(&edited);
        assert!(
            verified.is_none(),
            "an edited ad-insertion event must fail the hash"
        );
    }

    #[test]
    fn edited_media_fails_the_hash() {
        let mut segment = Case::default().segment();
        let last = segment.len() - 1;
        segment[last] ^= 0x01;
        let (verified, _) = validate(&segment);
        assert!(verified.is_none());
    }

    #[test]
    fn a_64_bit_size_event_is_matched_by_the_generic_offset() {
        // With a 16-byte header the scheme sits at box offset 20, not 12.
        let (verified, results) = validate(
            &Case {
                large_box: true,
                exclusions: vec![emsg_exclusion(20, SCHEME_NUL)],
                ..Case::default()
            }
            .segment(),
        );
        assert!(verified.is_some(), "{results:?}");
        assert_rejected(
            Case {
                large_box: true,
                ..Case::default()
            },
            "offset 12 of a 64-bit-size box is inside its largesize field",
        );
    }

    #[test]
    fn a_version_1_event_is_not_a_c2pa_event() {
        let body = full(
            1,
            0,
            &[
                &be(1000),
                &[0; 8],
                &be(67),
                &be(1),
                SCHEME_NUL,
                b"fseg\0",
                b"m",
            ],
        );
        assert!(segment_info_event(&body).is_err());
        assert_eq!(version_0_scheme(&body), None);
    }

    #[test]
    fn init_timing_reads_version_1_headers_and_rejects_orphan_trex() {
        let tkhd = iso(b"tkhd", &full(1, 3, &[&[0; 16], &be(7), &[0; 4]]));
        let mdhd = iso(b"mdhd", &full(1, 0, &[&[0; 16], &be(48_000), &[0; 8]]));
        let trak = iso(b"trak", &[tkhd, iso(b"mdia", &mdhd)].concat());
        let timing = parse_init_track_timing(&iso(b"moov", &trak)).unwrap();
        assert_eq!(timing.track(7).map(|track| track.timescale), Some(48_000));

        let orphan = iso(
            b"trex",
            &full(0, 0, &[&be(8), &be(1), &be(1), &be(0), &be(0)]),
        );
        let moov = iso(b"moov", &[trak, iso(b"mvex", &orphan)].concat());
        assert!(parse_init_track_timing(&moov).is_err());
    }

    fn rejected_with(results: &ValidationResults, url: &str) -> bool {
        results
            .failure
            .iter()
            .any(|status| status.code == LIVEVIDEO_SEGMENT_INVALID && status.url == url)
    }

    #[test]
    fn the_trusted_assessment_time_must_fall_inside_the_key_window() {
        let segment = Case::default().segment();
        let second = time::Duration::seconds(1);
        for at in [KEY_A.created_at, ASSESSED, KEY_A.expires_at()] {
            let (verified, results) = validate_at(&segment, at);
            assert!(verified.is_some(), "inclusive window at {at}: {results:?}");
        }
        for at in [KEY_A.created_at - second, KEY_A.expires_at() + second] {
            let (verified, results) = validate_at(&segment, at);
            assert!(verified.is_none(), "outside the window at {at}");
            assert!(rejected_with(&results, "self#segment=1"), "{results:?}");
        }
    }

    #[test]
    fn a_backdated_iat_cannot_revive_an_expired_key() {
        let after_expiry = datetime!(2026-10-26 16:00 UTC);
        // The key A holder signs after expiry and writes an in-window iat.
        let backdated = Case {
            iat: Some(KEY_A.created_at + time::Duration::minutes(5)),
            ..Case::default()
        }
        .segment();
        let (verified, results) = validate_at(&backdated, after_expiry);
        assert!(verified.is_none(), "backdating alone must not verify");
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");

        // Without an iat the trusted time alone decides.
        let unstamped = Case {
            iat: None,
            ..Case::default()
        }
        .segment();
        assert!(validate_at(&unstamped, ASSESSED).0.is_some());
        assert!(validate_at(&unstamped, after_expiry).0.is_none());
    }

    #[test]
    fn a_signed_iat_outside_the_window_is_refused_at_any_assessment_time() {
        assert_rejected(
            Case {
                iat: Some(KEY_A.expires_at() + time::Duration::minutes(1)),
                ..Case::default()
            },
            "iat after the key expired",
        );
        assert_rejected(
            Case {
                iat: Some(KEY_A.created_at - time::Duration::minutes(1)),
                ..Case::default()
            },
            "iat before the key was created",
        );
    }

    /// After both keys expired: a common time no segment can be judged at.
    const AFTER_BOTH: OffsetDateTime = datetime!(2026-10-26 16:00 UTC);

    /// Validate `segments` as one session-key stream delivering keys A and B.
    fn validate_stream(
        segments: &[Vec<u8>],
        common_time: OffsetDateTime,
        presentation_times: Option<&[OffsetDateTime]>,
    ) -> ValidationResults {
        validate_stream_with_keys(
            segments,
            &[KEY_A.session_key(), KEY_B.session_key()],
            common_time,
            presentation_times,
        )
    }

    fn validate_stream_with_keys(
        segments: &[Vec<u8>],
        keys: &[ValidatedSessionKey],
        common_time: OffsetDateTime,
        presentation_times: Option<&[OffsetDateTime]>,
    ) -> ValidationResults {
        let timing = parse_init_track_timing(&init_segment()).unwrap();
        let refs: Vec<&[u8]> = segments.iter().map(Vec::as_slice).collect();
        let mut results = ValidationResults::default();
        validate_emsg_segments(
            LiveVideoApplicability::new(StreamMethod::VerifiableSegmentInfo),
            &refs,
            Ok(&timing),
            &[],
            MANIFEST_ID,
            keys,
            common_time,
            presentation_times,
            ClaimAlgorithmList::V2_4,
            &mut results,
        );
        results
    }

    #[test]
    fn collection_threads_the_explicit_algorithm_policy_to_every_segment() {
        let esp_key = TestKey {
            algorithm: -9,
            ..KEY_A
        };
        let segments: Vec<Vec<u8>> = (1..=2)
            .map(|sequence_number| {
                Case {
                    key: esp_key,
                    sequence_number,
                    ..Case::default()
                }
                .segment()
            })
            .collect();
        let refs: Vec<&[u8]> = segments.iter().map(Vec::as_slice).collect();
        let timing = parse_init_track_timing(&init_segment()).unwrap();
        for (algorithms, accepted) in [
            (ClaimAlgorithmList::V2_4, false),
            (ClaimAlgorithmList::V2_5, true),
        ] {
            let mut results = ValidationResults::default();
            validate_emsg_segments(
                LiveVideoApplicability::new(StreamMethod::VerifiableSegmentInfo),
                &refs,
                Ok(&timing),
                &[],
                MANIFEST_ID,
                &[esp_key.session_key()],
                AFTER_BOTH,
                Some(&[ASSESSED, ASSESSED]),
                algorithms,
                &mut results,
            );
            assert_eq!(results.failure.is_empty(), accepted, "{results:?}");
        }
    }

    /// Key-A segments validated as one stream with expected seeks at `seeks`.
    fn validate_seeking(segments: &[Vec<u8>], seeks: &[usize]) -> ValidationResults {
        let timing = parse_init_track_timing(&init_segment()).unwrap();
        let refs: Vec<&[u8]> = segments.iter().map(Vec::as_slice).collect();
        let mut results = ValidationResults::default();
        validate_emsg_segments(
            LiveVideoApplicability::new(StreamMethod::VerifiableSegmentInfo),
            &refs,
            Ok(&timing),
            seeks,
            MANIFEST_ID,
            &[KEY_A.session_key()],
            ASSESSED,
            None,
            ClaimAlgorithmList::V2_4,
            &mut results,
        );
        results
    }

    fn explains(results: &ValidationResults, url: &str, text: &str) -> bool {
        results
            .failure
            .iter()
            .any(|status| status.url == url && status.explanation.contains(text))
    }

    /// A C2PA-scheme `fseg` event with `id`, whose unsigned message never
    /// authenticates: a candidate for the id ledger, never for success.
    fn c2pa_candidate(id: u32) -> Vec<u8> {
        iso(
            b"emsg",
            &full(
                0,
                0,
                &[
                    SCHEME_NUL,
                    b"fseg\0",
                    &be(1000),
                    &be(0),
                    &be(67),
                    &be(id),
                    b"not a signature",
                ],
            ),
        )
    }

    #[test]
    fn an_event_id_relabelled_onto_another_segment_is_refused() {
        // Segment 2 is correctly signed and hashed; only its unsigned id is
        // changed to segment 1's.
        let relabelled = [
            key_a_segment(1),
            Case {
                sequence_number: 2,
                event_id: Some(1),
                ..Case::default()
            }
            .segment(),
        ];
        let results = validate_seeking(&relabelled, &[]);
        assert!(!rejected_with(&results, "self#segment=1"), "{results:?}");
        assert!(
            explains(&results, "self#segment=2", "not unique in the session"),
            "{results:?}"
        );
        // A signalled seek does not excuse a different event under a reused id.
        let results = validate_seeking(&relabelled, &[1]);
        assert!(
            explains(&results, "self#segment=2", "not unique in the session"),
            "{results:?}"
        );
        // Distinct ids verify.
        let distinct = [key_a_segment(1), key_a_segment(2)];
        assert!(validate_seeking(&distinct, &[]).failure.is_empty());
    }

    #[test]
    fn a_repeated_event_id_within_one_segment_is_refused() {
        // A second C2PA candidate right after the carrying event, reusing its id.
        assert_rejected(
            Case {
                other_event: Some(c2pa_candidate(1)),
                ..Case::default()
            },
            "adjacent C2PA candidate repeats the carrying event's id",
        );
        let (_, results) = validate(
            &Case {
                other_event: Some(c2pa_candidate(1)),
                ..Case::default()
            }
            .segment(),
        );
        assert!(
            explains(&results, "self#segment=1", "repeats within the segment"),
            "{results:?}"
        );
        // Two identical trailing copies of one event are a repeat too.
        assert_rejected(
            Case {
                other_event: Some([c2pa_candidate(5), c2pa_candidate(5)].concat()),
                ..Case::default()
            },
            "identical copies in one segment",
        );
        // A trailing candidate with a fresh id is scanned, not authenticated,
        // and does not disturb the verified event.
        let (verified, results) = validate(
            &Case {
                other_event: Some(c2pa_candidate(7)),
                ..Case::default()
            }
            .segment(),
        );
        assert!(verified.is_some(), "{results:?}");
    }

    #[test]
    fn ids_of_unrelated_schemes_do_not_collide_with_c2pa_events() {
        // other_event carries id 9 under the SCTE-35 scheme.
        let (verified, results) = validate(
            &Case {
                event_id: Some(9),
                other_event: Some(other_event(b"urn:scte:scte35:2013:bin")),
                ..Case::default()
            }
            .segment(),
        );
        assert!(verified.is_some(), "{results:?}");
    }

    #[test]
    fn an_identical_segment_replayed_after_a_signalled_seek_is_the_same_event() {
        let one = key_a_segment(1);
        let two = key_a_segment(2);
        // Seeking back to segment 1 presents its identical event again.
        let seek_back = [one.clone(), two.clone(), one.clone()];
        let results = validate_seeking(&seek_back, &[2]);
        assert!(results.failure.is_empty(), "{results:?}");
        // Without the seek signal the same replay breaks the sequence.
        let results = validate_seeking(&seek_back, &[]);
        assert!(!rejected_with(&results, "self#segment=2"), "{results:?}");
        assert!(rejected_with(&results, "self#segment=3"), "{results:?}");
        // A contiguous duplicate is refused unless a seek is signalled there.
        let replayed = [one.clone(), one];
        assert!(rejected_with(
            &validate_seeking(&replayed, &[]),
            "self#segment=2"
        ));
        assert!(validate_seeking(&replayed, &[1]).failure.is_empty());
    }

    #[test]
    fn a_replay_after_a_seek_continues_contiguously() {
        // 1, 2, then a signalled seek back to 1, then 2 follows normally.
        let one = key_a_segment(1);
        let two = key_a_segment(2);
        let stream = [one.clone(), two.clone(), one, two];
        let results = validate_seeking(&stream, &[2]);
        assert!(results.failure.is_empty(), "{results:?}");
    }

    /// The C2PA `emsg` box that carries `segment`'s event: the box right after
    /// the leading `styp`, as [`Case`] lays it out.
    fn carrier_of(segment: &[u8]) -> Vec<u8> {
        let styp_len =
            usize::try_from(u32::from_be_bytes(segment[0..4].try_into().unwrap())).unwrap();
        let emsg_len = usize::try_from(u32::from_be_bytes(
            segment[styp_len..styp_len + 4].try_into().unwrap(),
        ))
        .unwrap();
        assert_eq!(&segment[styp_len + 4..styp_len + 8], b"emsg");
        segment[styp_len..styp_len + emsg_len].to_vec()
    }

    #[test]
    fn an_earlier_carrier_appended_to_a_later_segment_is_refused() {
        // Segment 2 is correctly signed and hashed with its own event, and also
        // carries segment 1's whole carrying emsg after it. That copy matches
        // the ledger byte for byte, but segment 2 is not a replay of segment 1.
        let one = key_a_segment(1);
        let two = Case {
            sequence_number: 2,
            other_event: Some(carrier_of(&one)),
            ..Case::default()
        }
        .segment();
        let results = validate_seeking(&[one.clone(), two.clone()], &[]);
        assert!(!rejected_with(&results, "self#segment=1"), "{results:?}");
        assert!(
            explains(&results, "self#segment=2", "not unique in the session"),
            "{results:?}"
        );
        // A signalled seek does not change that.
        let results = validate_seeking(&[one, two], &[1]);
        assert!(
            explains(&results, "self#segment=2", "not unique in the session"),
            "{results:?}"
        );
    }

    #[test]
    fn a_segment_with_several_events_replays_only_as_a_whole() {
        // Each segment carries its own event plus a second C2PA candidate.
        let with_extra = |sequence_number: i128, extra_id: u32| {
            Case {
                sequence_number,
                other_event: Some(c2pa_candidate(extra_id)),
                ..Case::default()
            }
            .segment()
        };
        let one = with_extra(1, 101);
        let two = with_extra(2, 102);
        let seek_back = [one.clone(), two.clone(), one.clone()];
        let results = validate_seeking(&seek_back, &[2]);
        assert!(results.failure.is_empty(), "{results:?}");
        let results = validate_seeking(&seek_back, &[]);
        assert!(rejected_with(&results, "self#segment=3"), "{results:?}");

        // Keeping segment 1's extra event but presenting a different segment
        // around it is not a replay.
        let mixed = with_extra(2, 101);
        let results = validate_seeking(&[one, mixed], &[1]);
        assert!(
            explains(&results, "self#segment=2", "not unique in the session"),
            "{results:?}"
        );
    }

    /// Key A delivered with `minSequenceNumber` `floor`.
    fn key_a_from(floor: u64) -> ValidatedSessionKey {
        ValidatedSessionKey {
            minimum_sequence_number: floor,
            ..KEY_A.session_key()
        }
    }

    /// A key-A segment carrying `sequence_number`.
    fn key_a_segment(sequence_number: i128) -> Vec<u8> {
        Case {
            sequence_number,
            ..Case::default()
        }
        .segment()
    }

    #[test]
    fn a_rotated_init_starts_its_segments_at_the_delivered_key_floor() {
        // A 24/7 publisher re-issues its init segment with a key whose floor is
        // 8, so the first segment presented after it is sequence 8.
        let keys = [key_a_from(8)];
        let in_order = [key_a_segment(8), key_a_segment(9)];
        let results = validate_stream_with_keys(&in_order, &keys, ASSESSED, None);
        assert!(results.failure.is_empty(), "{results:?}");

        let dropped_first = [key_a_segment(9)];
        let results = validate_stream_with_keys(&dropped_first, &keys, ASSESSED, None);
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");

        let reordered = [key_a_segment(9), key_a_segment(8)];
        let results = validate_stream_with_keys(&reordered, &keys, ASSESSED, None);
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");
        assert!(rejected_with(&results, "self#segment=2"), "{results:?}");

        // Below its floor the key authenticates nothing, whatever the start.
        let below_floor = [key_a_segment(7), key_a_segment(8)];
        let results = validate_stream_with_keys(&below_floor, &keys, ASSESSED, None);
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");
    }

    #[test]
    fn the_first_expected_sequence_is_the_lowest_key_floor_and_at_least_one() {
        // The ordinary floor of 1 starts at 1, as before.
        let ordinary = [key_a_segment(1), key_a_segment(2)];
        let results = validate_stream_with_keys(&ordinary, &[key_a_from(1)], ASSESSED, None);
        assert!(results.failure.is_empty(), "{results:?}");
        // A floor of 0 still starts at 1.
        let results = validate_stream_with_keys(&ordinary, &[key_a_from(0)], ASSESSED, None);
        assert!(results.failure.is_empty(), "{results:?}");
        // With several keys the lowest floor decides the start.
        let keys = [
            key_a_from(8),
            ValidatedSessionKey {
                minimum_sequence_number: 12,
                ..KEY_B.session_key()
            },
        ];
        let results = validate_stream_with_keys(&[key_a_segment(8)], &keys, ASSESSED, None);
        assert!(results.failure.is_empty(), "{results:?}");
    }

    /// Sequence 1 under key A, then sequences 2 and 3 under key B after a
    /// rotation into a disjoint window.
    fn rotated_stream() -> Vec<Vec<u8>> {
        vec![
            Case::default().segment(),
            Case {
                sequence_number: 2,
                key: KEY_B,
                iat: Some(KEY_B.honest_iat()),
                ..Case::default()
            }
            .segment(),
            Case {
                sequence_number: 3,
                key: KEY_B,
                iat: Some(KEY_B.honest_iat() + time::Duration::minutes(1)),
                ..Case::default()
            }
            .segment(),
        ]
    }

    #[test]
    fn a_historical_stream_verifies_across_disjoint_key_windows_with_trusted_times() {
        let stream = rotated_stream();
        let in_b = datetime!(2026-10-26 14:30 UTC);
        let presented = [ASSESSED, in_b, datetime!(2026-10-26 14:45 UTC)];
        // The common time is past both windows, so success proves each segment
        // was judged at its own supplied time.
        let results = validate_stream(&stream, AFTER_BOTH, Some(&presented));
        assert!(
            results.failure.is_empty(),
            "each segment judged at its own trusted time, sequence continuous across the key change: {results:?}"
        );

        // One common time inside key B's window: segment 1 is judged after key A
        // expired, and its honest in-window iat does not rescue it. Segment 2
        // then breaks the expected sequence; segment 3 follows segment 2.
        let results = validate_stream(&stream, in_b, None);
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");
        assert!(rejected_with(&results, "self#segment=2"), "{results:?}");
        assert!(!rejected_with(&results, "self#segment=3"), "{results:?}");

        // Times swapped between the two keys fail both mismatched segments.
        let results = validate_stream(&stream, AFTER_BOTH, Some(&[in_b, ASSESSED, in_b]));
        assert!(rejected_with(&results, "self#segment=1"), "{results:?}");
        assert!(rejected_with(&results, "self#segment=2"), "{results:?}");
    }

    #[test]
    fn assessment_times_must_name_one_time_per_segment() {
        let results = validate_stream(&rotated_stream(), ASSESSED, Some(&[ASSESSED, ASSESSED]));
        assert_eq!(results.failure.len(), 1, "{results:?}");
        assert!(rejected_with(&results, "self#segment"), "{results:?}");
    }

    /// A `trak` for `track_id` at `timescale`, with an optional `elst` body.
    fn trak(track_id: u32, timescale: u32, elst: Option<Vec<u8>>) -> Vec<u8> {
        let mut children = iso(b"tkhd", &full(0, 3, &[&[0; 8], &be(track_id), &[0; 4]]));
        if let Some(elst) = elst {
            children.extend_from_slice(&iso(b"edts", &iso(b"elst", &elst)));
        }
        let mdhd = iso(b"mdhd", &full(0, 0, &[&[0; 8], &be(timescale), &be(0)]));
        children.extend_from_slice(&iso(b"mdia", &mdhd));
        iso(b"trak", &children)
    }

    /// An init segment with a 1 kHz movie timescale declaring `traks` and no
    /// `trex` defaults.
    fn init_with(traks: &[Vec<u8>]) -> Vec<u8> {
        init_with_movie(Some(1000), traks)
    }

    /// An init segment whose `mvhd` declares `movie_timescale` (no `mvhd` at
    /// all for `None`).
    fn init_with_movie(movie_timescale: Option<u32>, traks: &[Vec<u8>]) -> Vec<u8> {
        let mvhd = movie_timescale
            .map(|timescale| iso(b"mvhd", &full(0, 0, &[&[0; 8], &be(timescale), &be(0)])))
            .unwrap_or_default();
        [
            iso(b"ftyp", b"isom\0\0\0\0isomiso6"),
            iso(b"moov", &[mvhd, traks.concat()].concat()),
        ]
        .concat()
    }

    /// A version-0 `elst` body; each entry is `(segment_duration, media_time,
    /// media_rate_integer)` with a zero rate fraction.
    fn elst(entries: &[(u32, i32, i16)]) -> Vec<u8> {
        let mut fields = be(u32::try_from(entries.len()).unwrap()).to_vec();
        for (segment_duration, media_time, rate) in entries {
            fields.extend_from_slice(&be(*segment_duration));
            fields.extend_from_slice(&media_time.to_be_bytes());
            fields.extend_from_slice(&rate.to_be_bytes());
            fields.extend_from_slice(&0i16.to_be_bytes());
        }
        full(0, 0, &[&fields])
    }

    /// One `traf` of `track_id` with an optional version-1 `tfdt` and one
    /// `trun` of the given version whose samples each carry a duration and a
    /// composition offset.
    fn traf(track_id: u32, tfdt: Option<u64>, trun_version: u8, samples: &[(u32, i32)]) -> Vec<u8> {
        let mut children = iso(b"tfhd", &full(0, 0x02_0000, &[&be(track_id)]));
        if let Some(base) = tfdt {
            children.extend_from_slice(&iso(b"tfdt", &full(1, 0, &[&base.to_be_bytes()])));
        }
        let mut table = be(u32::try_from(samples.len()).unwrap()).to_vec();
        for (duration, offset) in samples {
            table.extend_from_slice(&be(*duration));
            table.extend_from_slice(&offset.to_be_bytes());
        }
        children.extend_from_slice(&iso(b"trun", &full(trun_version, 0x0900, &[&table])));
        iso(b"traf", &children)
    }

    /// One `moof` around `trafs`, then its `mdat`.
    fn moof_of(trafs: &[Vec<u8>]) -> Vec<u8> {
        let moof = iso(
            b"moof",
            &[iso(b"mfhd", &full(0, 0, &[&be(1)])), trafs.concat()].concat(),
        );
        [moof, iso(b"mdat", b"media")].concat()
    }

    /// Whether a correctly signed event of `event_duration / timescale` seconds
    /// authenticates `media` under `init`, with the statuses filed.
    fn timed(
        init: &[u8],
        media: &[u8],
        timescale: u32,
        event_duration: u32,
    ) -> (bool, ValidationResults) {
        let segment = Case {
            media: media.to_vec(),
            timescale,
            event_duration,
            ..Case::default()
        }
        .segment();
        let (verified, results) = validate_with(init, &segment, &[KEY_A.session_key()], ASSESSED);
        (verified.is_some(), results)
    }

    fn covers(init: &[u8], media: &[u8], timescale: u32, event_duration: u32) -> bool {
        timed(init, media, timescale, event_duration).0
    }

    /// Why `media` cannot be timed at all: an event lasting about 49 days still
    /// fails, so the refusal comes from the timing, never from the duration.
    fn timing_defect(init: &[u8], media: &[u8]) -> String {
        let (verified, results) = timed(init, media, 1000, u32::MAX - 1);
        assert!(!verified, "{results:?}");
        results
            .failure
            .iter()
            .map(|status| status.explanation.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[test]
    fn a_tfdt_gap_widens_the_span_beyond_the_summed_durations() {
        let init = init_with(&[trak(1, 1000, None)]);
        // Samples at [0, 1) s and [10, 11) s: 2 s of media spanning 11 s.
        let media = [
            moof_of(&[traf(1, Some(0), 0, &[(1000, 0)])]),
            moof_of(&[traf(1, Some(10_000), 0, &[(1000, 0)])]),
        ]
        .concat();
        assert!(covers(&init, &media, 1000, 11_000));
        assert!(!covers(&init, &media, 1000, 10_999));
        assert!(
            !covers(&init, &media, 1000, 2000),
            "the duration sum does not cover the gap"
        );
    }

    #[test]
    fn tracks_that_start_at_different_times_are_spanned_together() {
        // Video at 90 kHz presents [0.5, 1.5) s; audio at 48 kHz presents [0, 1) s.
        let init = init_with(&[trak(1, 90_000, None), trak(2, 48_000, None)]);
        let media = moof_of(&[
            traf(1, Some(45_000), 0, &[(90_000, 0)]),
            traf(2, Some(0), 0, &[(48_000, 0)]),
        ]);
        assert!(covers(&init, &media, 1000, 1500));
        assert!(
            covers(&init, &media, 90_000, 135_000),
            "exact in a track timescale"
        );
        assert!(!covers(&init, &media, 90_000, 134_999));
        assert!(
            !covers(&init, &media, 1000, 1000),
            "each track alone lasts 1 s"
        );
    }

    #[test]
    fn composition_offsets_move_presentation_in_both_trun_versions() {
        let init = init_with(&[trak(1, 1000, None)]);
        // Version 0, unsigned: decode 0, 100, 200 present at 100, 400, 200, so
        // the span is [100, 500), 400 ticks from an origin that is not 0.
        let unsigned = moof_of(&[traf(1, Some(0), 0, &[(100, 100), (100, 300), (100, 0)])]);
        assert!(covers(&init, &unsigned, 1000, 400));
        assert!(!covers(&init, &unsigned, 1000, 399));
        assert!(
            !covers(&init, &unsigned, 1000, 300),
            "the duration sum misses the reordered tail"
        );
        // Version 1, signed: decode 1000, 1100 present at 900, 1200, so the
        // span is [900, 1300).
        let signed = moof_of(&[traf(1, Some(1000), 1, &[(100, -100), (100, 100)])]);
        assert!(covers(&init, &signed, 1000, 400));
        assert!(!covers(&init, &signed, 1000, 399));
        // The same bits in version 0 are an offset of 2^32 - 100 ticks.
        let reread = moof_of(&[traf(1, Some(1000), 0, &[(100, -100), (100, 100)])]);
        assert!(!covers(&init, &reread, 1000, 400));
    }

    #[test]
    fn a_single_open_ended_edit_shifts_its_track() {
        // Track 1's edit presents composition time 500 first, aligning it with
        // track 2 at [0, 1) s. Ignoring the edit would demand 1.5 s.
        let init = init_with(&[
            trak(1, 1000, Some(elst(&[(0, 500, 1)]))),
            trak(2, 1000, None),
        ]);
        let media = moof_of(&[
            traf(1, Some(500), 0, &[(1000, 0)]),
            traf(2, Some(0), 0, &[(1000, 0)]),
        ]);
        assert!(covers(&init, &media, 1000, 1000));
        assert!(!covers(&init, &media, 1000, 999));
    }

    #[test]
    fn the_ffmpeg_empty_edit_then_open_media_edit_delays_its_track() {
        // The exact `elst` FFmpeg wrote for a fragmented HLS video track at
        // 10240 Hz under a 1000 Hz movie: a 200-tick empty edit, then
        // media_time 2048 at unit rate with duration 0 (open-ended).
        let ffmpeg = elst(&[(200, -1, 1), (0, 2048, 1)]);
        assert_eq!(
            ffmpeg,
            hex::decode("0000000000000002000000c8ffffffff00010000000000000000080000010000")
                .unwrap()
        );
        // Video composition 2048 is presented at 0.2 s, so [0.2, 1.2) s; audio
        // presents [0, 1) s. Dropping the empty edit would claim 1 s.
        let init = init_with(&[trak(1, 10_240, Some(ffmpeg)), trak(2, 1000, None)]);
        let media = moof_of(&[
            traf(1, Some(2048), 0, &[(10_240, 0)]),
            traf(2, Some(0), 0, &[(1000, 0)]),
        ]);
        assert!(covers(&init, &media, 1000, 1200));
        assert!(!covers(&init, &media, 1000, 1199));
        assert!(!covers(&init, &media, 1000, 1000));
    }

    #[test]
    fn an_empty_edit_that_is_not_whole_media_ticks_stays_exact() {
        // 1 movie tick at 1000 Hz is 44.1 ticks of a 44100 Hz track: the
        // presentation clock is lcm(44100, 1000), so nothing is rounded.
        let init = init_with(&[
            trak(1, 44_100, Some(elst(&[(1, -1, 1), (0, 0, 1)]))),
            trak(2, 1000, None),
        ]);
        let media = moof_of(&[
            traf(1, Some(0), 0, &[(44_100, 0)]),
            traf(2, Some(0), 0, &[(1000, 0)]),
        ]);
        assert!(covers(&init, &media, 1000, 1001));
        assert!(!covers(&init, &media, 1000, 1000));
    }

    #[test]
    fn finite_edits_clip_and_place_media_on_the_movie_timeline() {
        let media = moof_of(&[traf(1, Some(0), 0, &[(1000, 0), (1000, 0), (1000, 0)])]);
        // Media [0, 0.5) s at movie 0, then media [2, 2.5) s at movie 0.5: of
        // 3 s of samples only 1 s is presented.
        let clipped = init_with(&[trak(1, 1000, Some(elst(&[(500, 0, 1), (500, 2000, 1)])))]);
        assert!(covers(&clipped, &media, 1000, 1000));
        assert!(!covers(&clipped, &media, 1000, 999));
        // Media [0, 1) s at movie 0, a 1 s empty edit, then media [1, 2) s at
        // movie 2: the presented span is 3 s.
        let delayed = init_with(&[trak(
            1,
            1000,
            Some(elst(&[(1000, 0, 1), (1000, -1, 1), (1000, 1000, 1)])),
        )]);
        assert!(covers(&delayed, &media, 1000, 3000));
        assert!(!covers(&delayed, &media, 1000, 2999));
        // An edit that presents none of the segment's media leaves no span.
        let elsewhere = init_with(&[trak(1, 1000, Some(elst(&[(500, 5000, 1)])))]);
        assert!(timing_defect(&elsewhere, &media).contains("no timed samples"));
    }

    #[test]
    fn edit_lists_that_cannot_be_mapped_are_refused() {
        let media = moof_of(&[traf(1, Some(0), 0, &[(1000, 0)])]);
        let too_many = vec![(10_u32, -1_i32, 1_i16); MAX_EDIT_ENTRIES + 1];
        for (entries, why) in [
            (vec![(1000_u32, -1_i32, 1_i16)], "only an empty edit"),
            (
                vec![(0, 0, 1), (1000, 0, 1)],
                "zero-duration media edit before the end",
            ),
            (vec![(1000, -2, 1)], "media_time below -1"),
            (vec![(0, 0, 2)], "double rate"),
            (vec![(1000, 0, 0)], "dwell"),
            (too_many, "more entries than the verifier bound"),
        ] {
            let init = init_with(&[trak(1, 1000, Some(elst(&entries)))]);
            assert_eq!(
                parse_init_track_timing(&init),
                Err(UNSUPPORTED_EDIT_LIST),
                "{why}"
            );
            assert!(
                timing_defect(&init, &media).contains(UNSUPPORTED_EDIT_LIST),
                "{why}"
            );
        }
        let no_movie = init_with_movie(None, &[trak(1, 1000, Some(elst(&[(0, 0, 1)])))]);
        assert!(timing_defect(&no_movie, &media).contains("mvhd timescale"));
        let no_entries = init_with_movie(None, &[trak(1, 1000, Some(elst(&[])))]);
        assert!(covers(&no_entries, &media, 1000, 1000));
    }

    #[test]
    fn fragments_without_tfdt_are_timed_only_when_they_cannot_be_misplaced() {
        let one = init_with(&[trak(1, 1000, None)]);
        // A single track without tfdt runs back to back from an unknown start.
        let floating = [
            moof_of(&[traf(1, None, 0, &[(1000, 0)])]),
            moof_of(&[traf(1, None, 0, &[(1000, 0)])]),
        ]
        .concat();
        assert!(covers(&one, &floating, 1000, 2000));
        assert!(!covers(&one, &floating, 1000, 1999));

        let mixed = [
            moof_of(&[traf(1, Some(0), 0, &[(1000, 0)])]),
            moof_of(&[traf(1, None, 0, &[(1000, 0)])]),
        ]
        .concat();
        assert!(timing_defect(&one, &mixed).contains("mixes fragments with and without tfdt"));

        let two = init_with(&[trak(1, 1000, None), trak(2, 1000, None)]);
        let unaligned = moof_of(&[
            traf(1, Some(0), 0, &[(1000, 0)]),
            traf(2, None, 0, &[(1000, 0)]),
        ]);
        assert!(timing_defect(&two, &unaligned).contains("cannot be aligned"));
    }

    #[test]
    fn a_fragment_without_tfdt_cannot_be_placed_under_an_edit_list() {
        // The edit presents media from composition time 500. Segment 1 starts
        // at tfdt 0, so its one 1000-tick sample presents only [500, 1000):
        // 0.5 s. Segment 2 continues at media 1000 but omits tfdt; assuming
        // origin 0 would clip it to the same 0.5 s although it really presents
        // a full second, so a 500 ms event must not validate it.
        let init = init_with(&[trak(1, 1000, Some(elst(&[(0, 500, 1)])))]);
        let first = moof_of(&[traf(1, Some(0), 0, &[(1000, 0)])]);
        assert!(covers(&init, &first, 1000, 500));
        assert!(!covers(&init, &first, 1000, 499));

        let second = moof_of(&[traf(1, None, 0, &[(1000, 0)])]);
        assert!(!covers(&init, &second, 1000, 500));
        assert!(timing_defect(&init, &second).contains("no tfdt under an edit list"));

        // With tfdt the second segment is placed exactly: [1000, 2000) media is
        // movie [0.5, 1.5) s, a full second.
        let anchored = moof_of(&[traf(1, Some(1000), 0, &[(1000, 0)])]);
        assert!(covers(&init, &anchored, 1000, 1000));
        assert!(!covers(&init, &anchored, 1000, 999));

        // Without an edit list an implicit origin stays accepted.
        let plain = init_with(&[trak(1, 1000, None)]);
        assert!(covers(&plain, &second, 1000, 1000));
    }

    #[test]
    fn a_segment_without_samples_has_no_span_to_cover() {
        let init = init_with(&[trak(1, 1000, None)]);
        let empty = moof_of(&[traf(1, Some(0), 0, &[])]);
        assert!(timing_defect(&init, &empty).contains("no timed samples"));
    }

    #[test]
    fn a_shortened_event_duration_fails_although_the_emsg_is_excluded() {
        // The C2PA emsg is outside the hash, so its fields can be edited without
        // breaking the signature or the digest; only the timing check catches it.
        let mut segment = Case::default().segment();
        assert!(validate(&segment).0.is_some());
        let scheme = segment
            .windows(SCHEME_NUL.len())
            .position(|bytes| bytes == SCHEME_NUL)
            .unwrap();
        let duration_at = scheme + SCHEME_NUL.len() + b"fseg\0".len() + 8;
        assert_eq!(segment[duration_at..duration_at + 4], be(67));
        segment[duration_at..duration_at + 4].copy_from_slice(&be(66));
        let (verified, results) = validate(&segment);
        assert!(verified.is_none());
        assert!(
            results
                .failure
                .iter()
                .any(|status| status.explanation.contains("presentation span")),
            "{results:?}"
        );
    }

    /// A version-1 `emsg`: timing fields first, then scheme and value, so the
    /// scheme sits at box offset 32.
    fn version_1_event(scheme: &[u8]) -> Vec<u8> {
        iso(
            b"emsg",
            &full(
                1,
                0,
                &[
                    &be(1000),
                    &0u64.to_be_bytes(),
                    &be(67),
                    &be(9),
                    scheme,
                    b"\0",
                    b"1\0",
                    b"timed",
                ],
            ),
        )
    }

    #[test]
    fn adjacent_c2pa_events_removed_as_one_range_verify() {
        // A second C2PA-scheme event directly after the carrying one: the same
        // qualifier selects both, and normalization merges them into one range
        // spanning two boxes.
        let case = Case {
            other_event: Some(other_event(b"urn:c2pa:verifiable-segment-info")),
            ..Case::default()
        };
        let segment = case.segment();
        let maps = super::super::bmff_exclusion_maps(&Value::Map(vec![(
            text("exclusions"),
            Value::Array(case.exclusions.clone()),
        )]))
        .unwrap();
        let ranges = crate::c2pa_formats::bmff_excluded_ranges(&segment, &maps).unwrap();
        assert_eq!(ranges.len(), 1, "one merged range: {ranges:?}");
        let (verified, results) = validate(&segment);
        assert!(verified.is_some(), "{results:?}");
    }

    #[test]
    fn a_merged_exclusion_may_not_reach_a_non_c2pa_event() {
        // The second exclusion's version qualifier selects the adjacent
        // version-1 event that names the C2PA scheme. A version-1 emsg is not a
        // C2PA event, so the merged range reaching into it is refused.
        let v1 = version_1_event(b"urn:c2pa:verifiable-segment-info");
        assert_rejected(
            Case {
                exclusions: vec![
                    emsg_exclusion(12, SCHEME_NUL),
                    versioned_emsg_exclusion(32, SCHEME_NUL, 1),
                ],
                other_event: Some(v1.clone()),
                ..Case::default()
            },
            "merged range reaches a version-1 emsg",
        );
        // Left inside the hash, the same event is harmless.
        let (verified, results) = validate(
            &Case {
                other_event: Some(v1),
                ..Case::default()
            }
            .segment(),
        );
        assert!(verified.is_some(), "{results:?}");
    }

    #[test]
    fn a_version_qualifier_selects_the_carrying_event() {
        // emsg is a FullBox: version 0 selects the C2PA event, version 1 does
        // not, and then nothing removes the carrying event.
        let (verified, results) = validate(
            &Case {
                exclusions: vec![versioned_emsg_exclusion(12, SCHEME_NUL, 0)],
                ..Case::default()
            }
            .segment(),
        );
        assert!(verified.is_some(), "{results:?}");
        assert_rejected(
            Case {
                exclusions: vec![versioned_emsg_exclusion(12, SCHEME_NUL, 1)],
                ..Case::default()
            },
            "a version 1 qualifier cannot select a version 0 event",
        );
    }

    #[test]
    fn an_event_between_excluded_c2pa_events_stays_authenticated() {
        let splice = other_event(b"urn:scte:scte35:2013:bin");
        let c2pa = other_event(b"urn:c2pa:verifiable-segment-info");
        let segment = Case {
            other_event: Some([splice, c2pa].concat()),
            ..Case::default()
        }
        .segment();
        let (verified, results) = validate(&segment);
        assert!(verified.is_some(), "{results:?}");
        // The first "splice" bytes belong to the SCTE event.
        let at = segment
            .windows(6)
            .position(|bytes| bytes == b"splice")
            .unwrap();
        let mut edited = segment;
        edited[at] ^= 0x01;
        assert!(
            validate(&edited).0.is_none(),
            "the SCTE event between two excluded C2PA events stays hashed"
        );
    }
}
