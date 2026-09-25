// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Explicit fMP4/CMAF fragmented-stream verification.
//!
//! Two protection methods, told apart by the caller's declaration, and within
//! the first by reading the manifest rather than by trusting a declaration:
//!
//! - [`StreamMethod::VerifiableSegmentInfo`] covers the two standard bindings a
//!   live init segment can carry:
//!   - a session-key delivery (`c2pa.session-keys`, C2PA 2.4) whose segments are
//!     authenticated by signed `emsg` verifiable segment information
//!     ([`verify_live_session`]);
//!   - otherwise the Merkle binding of [`super::verify_fragmented`] (spec A.5.4
//!     leaf recompute + stored-row climb);
//!
//!   Both lanes gate the declared encapsulation's brands first.
//! - [`StreamMethod::PerSegment`] verifies each segment as a standalone asset and
//!   then RECOMPUTES the chain: every segment after the first must carry a
//!   `parentOf` `c2pa.ingredient.v3` assertion whose claim-signed
//!   `activeManifest` hash equals the SHA-256 of its predecessor's active
//!   manifest, and its declared continuity must satisfy
//!   [`super::live_video::validate_live_video_assertion`].
//!
//! The chain check is what makes per-segment mode more than a pile of
//! independently signed files: the segment-identity assertion's
//! `previousManifestId` is only a label, so a splicer could mint a self-consistent
//! replacement segment. The ingredient hashed-URI cannot be forged without the
//! predecessor's exact manifest bytes.
//!
//! This module also owns the fail-closed gate that
//! [`super::verify_with_fragments`] applies to every caller-supplied fragment
//! list ([`require_fragments_bound`]): a fragment that no binding in the active
//! manifest can cover must never leave a report saying integrity is valid.

use time::OffsetDateTime;

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::jumbf::{
    manifest_superboxes_from_store, parse_manifest_store, superbox_content, ParsedManifest,
};
use crate::c2pa_formats::{
    bmff_check_stream_brand, AssetFormat, StreamEncapsulation, StreamFileRole, StreamMethod,
};

use super::live_video::{
    validate_emsg_segment, validate_init_segment, validate_live_video_assertion,
    validate_segment_manifest, validate_session_keys, LiveVideoApplicability,
    LiveVideoManifestState, LIVEVIDEO_CONTINUITY_METHOD_INVALID, LIVEVIDEO_SEGMENT_INVALID,
    LIVEVIDEO_SESSION_KEY_INVALID,
};
use super::{
    hash_bytes, CawgTrustInputs, ClaimGeneration, Json, ValidateError, ValidationResults,
    ValidationState, VerifyInput, VerifyOutput, ASSERTION_BMFF_HASH_MATCH,
    ASSERTION_BMFF_HASH_MISMATCH,
};

/// Informational: a Merkle binding declares fragment trees that this run did not
/// evaluate, because no fragment files were supplied.
///
/// Entity-namespaced because C2PA 2.4 registers no "not evaluated" code for a
/// hard binding. Reporting the omission under `assertion.bmffHash.match` - which
/// is what this verifier used to do - tells a consumer a binding succeeded when
/// nothing was checked, which is exactly the claim a verifier must never make
/// (PRD 5.9).
pub const BMFF_FRAGMENTS_NOT_EVALUATED: &str = "com.encypher.bmffHash.fragmentsNotEvaluated";

/// Label of the claim-bound live-video segment-identity assertion. Vendor-
/// prefixed because the `c2pa.` namespace is a closed allowlist under
/// Conformance Program 0.2.
const LIVE_VIDEO_SEGMENT_LABEL: &str = "com.encypher.livevideo.segment";

/// Label of the spec-defined session-key delivery assertion. Its presence as a
/// CLAIM-BOUND assertion of the init manifest is what selects the live-session
/// lane.
const SESSION_KEYS_LABEL: &str = "c2pa.session-keys";

/// Base label of the ingredient assertion carrying the chain link. Additional
/// ingredients use the standard `__N` instance suffix.
const INGREDIENT_ASSERTION_LABEL: &str = "c2pa.ingredient.v3";

/// Hash algorithm the chain link is recomputed under.
const CHAIN_HASH_ALG: &str = "sha256";

/// One segment's independent verification plus the identity it declares.
pub struct SegmentVerification {
    /// Zero-based position in the presented stream. The init segment is 0.
    pub sequence_number: usize,
    /// Active manifest label read from this segment, or an empty string when the
    /// segment carries no manifest.
    pub manifest_label: String,
    /// `previousManifestId` this segment declares, if any.
    pub previous_manifest_label: Option<String>,
    /// This segment's standalone verification: what a consumer that received
    /// only this segment would see.
    pub output: VerifyOutput,
}

/// Result of [`verify_per_segment`].
pub struct PerSegmentVerifyOutput {
    /// Per-segment standalone results, in presented order.
    pub segments: Vec<SegmentVerification>,
    /// True only when every segment verified on its own AND every link between
    /// consecutive segments recomputed. A caller may present the segments it
    /// received; a broken link is reported, never assumed benign.
    pub chain_valid: bool,
    /// Human-readable reasons `chain_valid` is false, in stream order.
    pub chain_failures: Vec<String>,
}

/// Result of [`verify_stream`], discriminated by the verified method.
///
/// [`VerifyOutput`] is far larger than the per-segment summary (a full reader
/// report plus optional crJSON), so it is boxed rather than making every value
/// of this enum pay for the bigger variant.
pub enum StreamVerifyOutput {
    /// The init segment's manifest verified against the supplied segments, by
    /// session key or by Merkle tree.
    VerifiableSegmentInfo(Box<VerifyOutput>),
    /// Every segment verified standalone, plus the recomputed chain.
    PerSegment(PerSegmentVerifyOutput),
}

impl StreamVerifyOutput {
    /// The method this result describes.
    pub const fn method(&self) -> StreamMethod {
        match self {
            Self::VerifiableSegmentInfo(_) => StreamMethod::VerifiableSegmentInfo,
            Self::PerSegment(_) => StreamMethod::PerSegment,
        }
    }
}

/// Verify a fragmented stream under an explicitly declared encapsulation and
/// method.
///
/// `input.data` is IGNORED — the bytes come from `init_segment` and `segments` —
/// while `input.mime`, `input.profile`, and every trust setting are honored. For
/// [`StreamMethod::VerifiableSegmentInfo`] the init segment is the manifest
/// carrier and `segments` are its fragments; for [`StreamMethod::PerSegment`] the
/// init segment is chain position 0 and `segments` follow it in order.
///
/// Which binding a [`StreamMethod::VerifiableSegmentInfo`] stream used is read
/// off the init manifest, never taken from the caller: a claim-bound
/// `c2pa.session-keys` assertion means the C2PA 2.4 session-key lane
/// ([`verify_live_session`]), and its absence means the Merkle binding. A
/// verifier that needed an out-of-band declaration to pick the right integrity
/// check would be trusting the party it is checking.
pub fn verify_stream<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<StreamVerifyOutput, ValidateError> {
    verify_stream_with_expected_seeks(
        input,
        init_segment,
        segments,
        &[],
        encapsulation,
        method,
        cawg_inputs,
    )
}

fn verify_stream_with_expected_seeks<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    expected_seek_positions: &[usize],
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<StreamVerifyOutput, ValidateError> {
    validate_expected_seek_positions(expected_seek_positions, segments.len())?;
    match method {
        StreamMethod::VerifiableSegmentInfo => {
            match session_key_delivery(init_segment, input.mime)? {
                Some(delivery) => {
                    check_stream_brands(init_segment, segments, encapsulation)?;
                    verify_delivered_live_session(
                        input,
                        init_segment,
                        segments,
                        expected_seek_positions,
                        &delivery,
                        cawg_inputs,
                    )
                }
                None => verify_fragmented_with_encapsulation_and_expected_seeks(
                    &input_for(input, init_segment),
                    segments,
                    expected_seek_positions,
                    encapsulation,
                    cawg_inputs,
                ),
            }
            .map(|out| StreamVerifyOutput::VerifiableSegmentInfo(Box::new(out)))
        }
        StreamMethod::PerSegment => verify_per_segment_with_expected_seeks(
            input,
            init_segment,
            segments,
            expected_seek_positions,
            encapsulation,
            cawg_inputs,
        )
        .map(StreamVerifyOutput::PerSegment),
    }
}

/// Panic-contained [`verify_stream`] with flat CAWG trust arguments.
///
/// The facade cannot name the crate-private `CawgTrustInputs`, so the CAWG
/// settings arrive as the same flat list the other `_safe` entry points take,
/// and panic containment matches them too: a verifier must never abort the host
/// process, and this result crosses FFI edges.
#[allow(clippy::too_many_arguments)]
pub fn verify_stream_safe<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    cawg_trust: Option<&crate::c2pa_trust::TrustList>,
    cawg_allowed_certs: Option<&crate::c2pa_trust::TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<StreamVerifyOutput, ValidateError> {
    verify_stream_safe_with_expected_seeks(
        input,
        init_segment,
        segments,
        &[],
        encapsulation,
        method,
        cawg_trust,
        cawg_allowed_certs,
        document_signing_require_anchor,
        cawg_did_documents,
        cawg_ica_trusted_issuers,
        cawg_ica_trust_anchors,
        cawg_ica_status_lists,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_stream_safe_with_expected_seeks<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    expected_seek_positions: &[usize],
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    cawg_trust: Option<&crate::c2pa_trust::TrustList>,
    cawg_allowed_certs: Option<&crate::c2pa_trust::TrustList>,
    document_signing_require_anchor: bool,
    cawg_did_documents: Option<&std::collections::HashMap<String, Json>>,
    cawg_ica_trusted_issuers: Option<&[String]>,
    cawg_ica_trust_anchors: Option<&[String]>,
    cawg_ica_status_lists: Option<&std::collections::HashMap<String, String>>,
) -> Result<StreamVerifyOutput, ValidateError> {
    let cawg_inputs = CawgTrustInputs {
        trust: cawg_trust,
        allowed_certs: cawg_allowed_certs,
        document_signing_require_anchor,
        did_documents: cawg_did_documents,
        ica_trusted_issuers: cawg_ica_trusted_issuers,
        ica_trust_anchors: cawg_ica_trust_anchors,
        ica_status_lists: cawg_ica_status_lists,
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify_stream_with_expected_seeks(
            input,
            init_segment,
            segments,
            expected_seek_positions,
            encapsulation,
            method,
            cawg_inputs,
        )
    })) {
        Ok(result) => result,
        Err(_) => Err(ValidateError::Panic),
    }
}

/// Verify a C2PA 2.4 live session: an init segment whose manifest delivers a
/// session key, plus media segments authenticated by that key.
///
/// Returns the init manifest's own verification with every `livevideo.*` status
/// filed into it, so one report answers "is this stream what it claims to be?".
/// Any live-video failure is an unknown-to-the-caveat-list failure code, which
/// makes [`VerifyOutput::validation_state`] [`ValidationState::Invalid`] under
/// both postures.
///
/// What must hold, in order:
/// 1. the init manifest validates as an ordinary asset (mapped to
///    `livevideo.manifest.invalid` when it does not);
/// 2. the init segment carries no `mdat`, because media outside a segment carries
///    no segment information and could never be authenticated;
/// 3. every delivered session key proves possession through a `signerBinding`
///    over the exact certificate that signed the delivering manifest;
/// 4. every media segment carries an `emsg` whose signature, active `kid`,
///    sequence number, `manifestId`, and structural hash all check out.
pub fn verify_live_session(
    input: &VerifyInput<'_>,
    init_segment: &[u8],
    segments: &[&[u8]],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    check_stream_brands(init_segment, segments, encapsulation)?;
    let delivery = session_key_delivery(init_segment, input.mime)?.ok_or_else(|| {
        ValidateError::Stream(
            "init segment delivers no claim-bound session key, so it is not a live session".into(),
        )
    })?;
    verify_delivered_live_session(input, init_segment, segments, &[], &delivery, cawg_inputs)
}

/// [`verify_live_session`] with the delivery already read, so the dispatching
/// caller in [`verify_stream`] parses the init manifest exactly once.
fn verify_delivered_live_session(
    input: &VerifyInput<'_>,
    init_segment: &[u8],
    segments: &[&[u8]],
    expected_seek_positions: &[usize],
    delivery: &SessionKeyDelivery,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    let applicability = LiveVideoApplicability::new(StreamMethod::VerifiableSegmentInfo);
    let mut out = super::verify_with_fragments(&input_for(input, init_segment), &[], cawg_inputs)?;
    let manifest_id = &delivery.manifest_label;

    validate_segment_manifest(
        applicability,
        out.validation_state != ValidationState::Invalid,
        &mut out.results,
        &format!("self#jumbf=/c2pa/{manifest_id}"),
    );
    validate_init_segment(
        applicability,
        init_segment,
        &mut out.results,
        "self#init-segment",
    );

    let keys_url = format!("self#jumbf=/c2pa/{manifest_id}/c2pa.assertions/{SESSION_KEYS_LABEL}");
    let keys = match &delivery.session_keys {
        Ok(assertion_cbor) => validate_session_keys(
            applicability,
            assertion_cbor,
            &delivery.signer_chain_der,
            &mut out.results,
            &keys_url,
        ),
        Err(defect) => {
            out.results
                .push_failure(LIVEVIDEO_SESSION_KEY_INVALID, keys_url, (*defect).into());
            Vec::new()
        }
    };

    let validation_time = input
        .validation_time
        .unwrap_or_else(OffsetDateTime::now_utc);
    let mut next_sequence_number = Some(1u64);
    for (index, segment) in segments.iter().enumerate() {
        let expected_seek = expected_seek_positions.binary_search(&index).is_ok();
        let expected_sequence_number = if expected_seek {
            None
        } else {
            next_sequence_number
        };
        let url = format!("self#segment={}", index + 1);
        if !expected_seek && expected_sequence_number.is_none() {
            out.results.push_failure(
                LIVEVIDEO_SEGMENT_INVALID,
                url.clone(),
                "unexpected sequence discontinuity: predecessor sequenceNumber cannot be incremented"
                    .into(),
            );
        }
        if let Some(info) = validate_emsg_segment(
            applicability,
            segment,
            expected_sequence_number,
            manifest_id,
            &keys,
            validation_time,
            &mut out.results,
            &url,
        ) {
            next_sequence_number = info.sequence_number.checked_add(1);
        }
    }
    restate_results(&mut out, input.profile);
    Ok(out)
}

/// The init manifest's session-key delivery.
struct SessionKeyDelivery {
    /// Active manifest URN: the `manifestId` every segment message must name.
    manifest_label: String,
    /// The sole claim-bound delivery assertion's CBOR, or why the delivery
    /// cannot be honored at all.
    session_keys: Result<Vec<u8>, &'static str>,
    /// The delivering manifest's signer chain, leaf first: what each key's
    /// `signerBinding` must bind itself to.
    signer_chain_der: Vec<Vec<u8>>,
}

/// Read the init manifest's session-key delivery, or `None` when this stream is
/// not a live session and the Merkle lane owns it.
///
/// Selection is CLAIM-BOUND. Two consequences are deliberate. A single
/// unreferenced `c2pa.session-keys` box does NOT select this lane: no honest
/// signer emits one, so it is an injection into some other stream, and honoring
/// it would let an attacker replace a Merkle integrity check with a lane the
/// stream was never signed for. More than one box means at least one is forged,
/// and no reading of the store can say which -- so the delivery is reported
/// unusable rather than resolved by position.
fn session_key_delivery(
    init_segment: &[u8],
    mime: &str,
) -> Result<Option<SessionKeyDelivery>, ValidateError> {
    let format = AssetFormat::from_mime(mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(mime.to_string()))?;
    let Some(store) = crate::c2pa_formats::extract_manifest(format, init_segment)? else {
        return Ok(None);
    };
    let parsed = parse_manifest_store(&store)?;
    let Some(active) = parsed.manifests.last() else {
        return Ok(None);
    };
    let found: Vec<_> = active
        .assertions
        .iter()
        .filter(|(label, _)| label == SESSION_KEYS_LABEL)
        .collect();
    let session_keys = match found.as_slice() {
        [] => return Ok(None),
        [(label, cbor)] => {
            if !claim_references_assertion(active, label) {
                return Ok(None);
            }
            Ok((*cbor).to_vec())
        }
        _ => Err(
            "init manifest carries more than one session-key delivery assertion, \
             so none of its keys can be trusted",
        ),
    };
    Ok(Some(SessionKeyDelivery {
        manifest_label: active.label.clone(),
        session_keys,
        signer_chain_der: active
            .signature_cose
            .and_then(|cose| crate::c2pa_crypto::extract_x5chain(cose).ok())
            .unwrap_or_default(),
    }))
}

/// [`super::verify_fragmented`] with a declared encapsulation.
///
/// `input.data` is the init segment. Adds only the fail-closed brand gate, so a
/// stream presented as CMAF whose bytes are plain fMP4 is rejected instead of
/// silently verifying.
pub fn verify_fragmented_with_encapsulation(
    input: &VerifyInput,
    fragments: &[&[u8]],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    verify_fragmented_with_encapsulation_and_expected_seeks(
        input,
        fragments,
        &[],
        encapsulation,
        cawg_inputs,
    )
}

fn verify_fragmented_with_encapsulation_and_expected_seeks(
    input: &VerifyInput,
    fragments: &[&[u8]],
    expected_seek_positions: &[usize],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifyOutput, ValidateError> {
    check_stream_brands(input.data, fragments, encapsulation)?;
    super::verify_with_fragments_and_expected_seeks(
        input,
        fragments,
        expected_seek_positions,
        cawg_inputs,
    )
}

/// A progressive BMFF portion that has passed its Merkle leaf check.
///
/// The bytes are private and can be obtained only by consuming this token via
/// [`release`](Self::release). Callers that route renderable bytes through this
/// API therefore cannot accidentally treat a pending or failed verification as
/// releasable content.
pub struct VerifiedBmffPortion<'a> {
    bytes: &'a [u8],
    /// The full result that authorized this release.
    pub verification: VerifyOutput,
}

impl<'a> VerifiedBmffPortion<'a> {
    /// Consume the verified token and release its exact, unmodified bytes.
    pub fn release(self) -> &'a [u8] {
        self.bytes
    }
}

/// Verify one progressively received BMFF portion before making it renderable.
///
/// `input.data` is the signed init segment. A token is returned only when both
/// the init hash and this portion's Merkle leaf produced success results and
/// the complete verification state is non-invalid. This stateless gate treats
/// the portion boundary as player-selected; use the stream verifier to enforce
/// continuity across several portions. Missing auxiliary Merkle data, a wrong
/// leaf location, mutated bytes, a broken claim binding, or any other integrity
/// failure returns an error and releases no bytes.
pub fn verify_bmff_portion_before_release<'a>(
    input: &VerifyInput<'_>,
    portion: &'a [u8],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<VerifiedBmffPortion<'a>, ValidateError> {
    let verification =
        verify_fragmented_with_encapsulation(input, &[portion], encapsulation, cawg_inputs)?;
    let bmff_successes = verification
        .results
        .success
        .iter()
        .filter(|status| status.code == ASSERTION_BMFF_HASH_MATCH)
        .count();
    if verification.validation_state == ValidationState::Invalid || bmff_successes < 2 {
        return Err(ValidateError::Stream(
            "BMFF portion was not Merkle-verified; release refused".into(),
        ));
    }
    Ok(VerifiedBmffPortion {
        bytes: portion,
        verification,
    })
}

/// Verify each segment of a per-segment stream independently, then recompute the
/// prior-manifest chain.
///
/// Each segment is verified exactly as a standalone asset, so
/// `segments[i].output.validation_state` answers "would a consumer that received
/// only this segment accept it?". The chain result answers the separate question
/// "is this the stream that was signed, in this order?".
///
/// Chain rejections (all reported, never fatal):
/// - a segment carrying no manifest, or whose standalone state is
///   [`ValidationState::Invalid`];
/// - a missing or malformed [`LIVE_VIDEO_SEGMENT_LABEL`] assertion;
/// - a declared `sequenceNumber`, `streamId`, `encapsulation`, or `method` that
///   disagrees with the presented stream;
/// - continuity: for every segment with a predecessor, whatever
///   [`super::live_video::validate_live_video_assertion`] rejects. That function
///   is the single decision point: it files the normative `livevideo.*` status
///   into the segment's own report and the chain message here is derived from
///   the code it filed. A `previousManifestId` on position 0, which has no
///   predecessor, is rejected here instead;
/// - a missing `parentOf` ingredient, or an ingredient `activeManifest` hash that
///   does not equal the SHA-256 of the predecessor's active manifest.
pub fn verify_per_segment<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<PerSegmentVerifyOutput, ValidateError> {
    verify_per_segment_with_expected_seeks(
        input,
        init_segment,
        segments,
        &[],
        encapsulation,
        cawg_inputs,
    )
}

fn verify_per_segment_with_expected_seeks<'a>(
    input: &VerifyInput<'a>,
    init_segment: &'a [u8],
    segments: &[&'a [u8]],
    expected_seek_positions: &[usize],
    encapsulation: StreamEncapsulation,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<PerSegmentVerifyOutput, ValidateError> {
    check_stream_brands(init_segment, segments, encapsulation)?;

    let applicability = LiveVideoApplicability::new(StreamMethod::PerSegment);
    let mut verifications = Vec::with_capacity(segments.len() + 1);
    let mut failures = Vec::new();
    // The predecessor's identity: (active manifest label, active manifest hash).
    let mut previous: Option<(String, Vec<u8>)> = None;
    // The predecessor's DECLARED continuity state, which is what the live-video
    // validator compares the next segment against.
    let mut previous_live: Option<LiveVideoManifestState> = None;
    let mut next_sequence_number = Some(0i128);
    let mut stream_id: Option<String> = None;

    for (position, segment) in std::iter::once(init_segment)
        .chain(segments.iter().copied())
        .enumerate()
    {
        let expected_seek = position > 0
            && expected_seek_positions
                .binary_search(&(position - 1))
                .is_ok();
        let mut verified =
            super::verify_with_fragments(&input_for(input, segment), &[], cawg_inputs)?;
        let facts = segment_facts(segment, input.mime)?;

        let (manifest_label, active_manifest_hash) = match &facts {
            Some(facts) => (
                facts.manifest_label.clone(),
                Some(facts.active_manifest_hash.clone()),
            ),
            None => {
                failures.push(format!("segment {position}: carries no C2PA manifest"));
                (String::new(), None)
            }
        };
        if verified.validation_state == ValidationState::Invalid {
            failures.push(format!(
                "segment {position}: standalone validation state is Invalid"
            ));
        }

        let declared = match facts.as_ref().map(|facts| &facts.declared) {
            Some(Ok(declared)) => Some(declared),
            Some(Err(defect)) => {
                failures.push(format!("segment {position}: {defect}"));
                None
            }
            None => None,
        };
        if let Some(declared) = declared {
            check_declaration(
                position,
                declared,
                if expected_seek {
                    None
                } else {
                    next_sequence_number
                },
                expected_seek,
                encapsulation,
                &mut stream_id,
                &mut failures,
            );
            next_sequence_number = declared
                .sequence_number
                .filter(|sequence| *sequence >= 0)
                .and_then(|sequence| sequence.checked_add(1));
        } else {
            next_sequence_number = None;
        }

        let previous_manifest_label =
            declared.and_then(|declared| declared.previous_manifest_id.clone());
        // At a signalled seek boundary the current assertion is still parsed and
        // structurally validated, but it is not compared with the last rendered
        // portion. The next portion must follow this one normally.
        let continuity_previous = if expected_seek {
            None
        } else {
            previous_live.as_ref()
        };
        if previous_live.is_some() || expected_seek {
            if let Some(facts) = facts.as_ref() {
                let already_filed = verified.results.failure.len();
                let accepted = validate_live_video_assertion(
                    applicability,
                    &facts.declaration_cbor,
                    &facts.manifest_label,
                    continuity_previous,
                    &mut verified.results,
                    &format!(
                        "self#jumbf=/c2pa/{}/c2pa.assertions/{LIVE_VIDEO_SEGMENT_LABEL}",
                        facts.manifest_label
                    ),
                )
                .is_some();
                if !accepted {
                    let expected_label = previous_live
                        .as_ref()
                        .map(|state| state.manifest_id.as_str())
                        .unwrap_or("");
                    for status in &verified.results.failure[already_filed..] {
                        failures.push(live_chain_failure(
                            position,
                            &status.code,
                            expected_label,
                            previous_manifest_label.as_deref(),
                        ));
                    }
                    restate_results(&mut verified, input.profile);
                }
            }
        } else if !expected_seek {
            if let (None, Some(claimed)) = (&previous, &previous_manifest_label) {
                failures.push(format!(
                    "segment {position}: declares previousManifestId {claimed:?} but has no predecessor"
                ));
            }
        }

        // The authenticated link remains required after a seek, but it is
        // compared only when the preceding signed portion was presented.
        let parent_link = facts.as_ref().map(|facts| &facts.parent_link);
        match (&previous, parent_link) {
            (_, Some(Err(defect))) => failures.push(format!("segment {position}: {defect}")),
            (Some((expected_label, _)), Some(Ok(None))) => failures.push(format!(
                "segment {position}: no parentOf {INGREDIENT_ASSERTION_LABEL} assertion \
                 linking to manifest {expected_label:?}"
            )),
            (Some((_, expected_hash)), Some(Ok(Some(linked))))
                if !expected_seek && linked != expected_hash =>
            {
                failures.push(format!(
                    "segment {position}: ingredient activeManifest hash does not match the \
                     preceding segment's manifest"
                ));
            }
            (None, Some(Ok(Some(_)))) => failures.push(format!(
                "segment {position}: carries a parentOf {INGREDIENT_ASSERTION_LABEL} assertion \
                 but has no predecessor"
            )),
            _ => {}
        }

        // Derived from what this segment DECLARES, not from whether its own
        // continuity passed: one broken link must not silence the check on every
        // later segment.
        previous_live = facts
            .as_ref()
            .zip(declared)
            .and_then(|(facts, declared)| declared_live_state(declared, &facts.manifest_label));
        verifications.push(SegmentVerification {
            sequence_number: position,
            manifest_label: manifest_label.clone(),
            previous_manifest_label,
            output: verified,
        });
        previous = active_manifest_hash.map(|hash| (manifest_label, hash));
    }

    Ok(PerSegmentVerifyOutput {
        chain_valid: failures.is_empty(),
        chain_failures: failures,
        segments: verifications,
    })
}

/// Fail closed when caller-supplied fragments were never bound by any binding in
/// the active manifest.
///
/// The Merkle lane ([`super::verify_bmff_fragments`]) is the ONLY consumer of the
/// `fragments` argument. Before this gate, a caller who handed
/// [`super::verify_fragmented`] the segments of a session-key stream, of a
/// per-segment stream, or of any asset whose binding is not a fragment Merkle
/// tree got those bytes silently ignored and a report saying `integrity: valid`
/// and `hard_binding: match` — a success verdict covering bytes nothing had
/// checked. That is exploitable: a tampered media segment presented alongside an
/// authentic init segment verified.
///
/// The condition is a property of the MANIFEST, not of the outcome: a fragment
/// list is bound only if the active manifest declares a `c2pa.hash.bmff.v2`/`v3`
/// binding carrying at least one Merkle entry with an `initHash`. When it does
/// not, `livevideo.segment.invalid` is filed (the registered C2PA 2.4 code for a
/// segment that carries no valid signed segment information) and every
/// validity-derived field of the report is recomputed from it.
pub(crate) fn require_fragments_bound(
    out: &mut VerifyOutput,
    manifest: &ParsedManifest<'_>,
    fragments: &[&[u8]],
    profile: crate::c2pa_core::EngineProfile,
) {
    if fragments.is_empty() || declares_fragment_merkle(manifest) {
        return;
    }
    out.results.push_failure(
        LIVEVIDEO_SEGMENT_INVALID,
        format!("self#jumbf=/c2pa/{}", manifest.label),
        format!(
            "{} caller-supplied fragment(s) were not bound: the active manifest declares no \
             fragment merkle tree. Verify this stream with the stream verifier, which selects \
             the session-key or per-segment binding from the manifest",
            fragments.len()
        ),
    );
    restate_results(out, profile);
}

/// Enforce the signed Merkle-leaf playback order, allowing a discontinuity only
/// at a position the player explicitly marked as an expected seek.
pub(crate) fn validate_fragment_sequence(
    out: &mut VerifyOutput,
    manifest: &ParsedManifest<'_>,
    fragments: &[&[u8]],
    expected_seek_positions: &[usize],
    profile: crate::c2pa_core::EngineProfile,
) {
    if fragments.is_empty() {
        return;
    }
    let Some(binding_label) = fragment_merkle_label(manifest) else {
        return;
    };

    let mut failed = false;
    let mut last_locations =
        std::collections::HashMap::<(i128, i128), usize>::with_capacity(fragments.len());
    for (position, fragment) in fragments.iter().enumerate() {
        let expected_seek = expected_seek_positions.binary_search(&position).is_ok();
        if expected_seek {
            last_locations.clear();
        }
        let Ok(mut boxes) = crate::c2pa_formats::bmff_merkle_boxes(fragment) else {
            continue;
        };
        if boxes.len() != 1 {
            continue;
        }
        let Some(Ok(merkle_box)) = boxes.pop() else {
            continue;
        };
        let key = (merkle_box.unique_id, merkle_box.local_id);
        let Some(previous) = last_locations.insert(key, merkle_box.location) else {
            continue;
        };
        if previous
            .checked_add(1)
            .is_some_and(|expected| merkle_box.location == expected)
        {
            continue;
        }
        failed = true;
        let explanation = format!(
            "fragment {position}: unexpected discontinuity at playback location {} after \
             {previous} for uniqueId={} localId={}",
            merkle_box.location, merkle_box.unique_id, merkle_box.local_id
        );
        // C2PA 2.4 assigns bmffHash.mismatch to every BMFF-validation failure
        // in this section other than the conditions explicitly called malformed.
        out.results.push_failure(
            ASSERTION_BMFF_HASH_MISMATCH,
            format!(
                "self#jumbf=/c2pa/{}/c2pa.assertions/{binding_label}",
                manifest.label
            ),
            explanation,
        );
    }
    if failed {
        restate_results(out, profile);
    }
}

/// The hard binding that can cover fragment files: a supported BMFF hash
/// assertion carrying at least one Merkle entry with an `initHash`.
fn fragment_merkle_label<'a>(manifest: &'a ParsedManifest<'_>) -> Option<&'a str> {
    manifest.assertions.iter().find_map(|(label, cbor)| {
        if !super::is_supported_bmff_hash_label(label) {
            return None;
        }
        let assertion = decode(cbor).ok()?;
        match assertion.get("merkle") {
            Some(Value::Array(entries))
                if entries.iter().any(|entry| entry.get("initHash").is_some()) =>
            {
                Some(label.as_str())
            }
            _ => None,
        }
    })
}

fn declares_fragment_merkle(manifest: &ParsedManifest<'_>) -> bool {
    fragment_merkle_label(manifest).is_some()
}

/// Re-derive everything a report says about validity from `out.results`.
///
/// A subsystem that reaches its conclusion AFTER the reader report was built
/// (live-video segment authentication cannot run until the manifest that
/// delivers the session keys has been read) must not leave the report
/// disagreeing with the status set. `validation_state`, `validation_status`,
/// `validation_results`, and `provenance_verdict` are all pure functions of the
/// results, so they are recomputed here together rather than patched one at a
/// time.
pub(crate) fn restate_results(out: &mut VerifyOutput, profile: crate::c2pa_core::EngineProfile) {
    out.validation_state = super::compute_state(&out.results, profile);
    let Some(object) = out.report_json.as_object_mut() else {
        return;
    };
    object.insert(
        "validation_status".to_string(),
        super::status_array(&out.results.failure),
    );
    super::restate_validation_results(object, &out.results);
    object.insert(
        "validation_state".to_string(),
        Json::String(out.validation_state.as_str().to_string()),
    );
    // Preserved rather than recomputed: whether provenance is present is a fact
    // about the asset, not about the status set.
    let present = object
        .get("provenance_verdict")
        .and_then(|verdict| verdict.get("present"))
        .and_then(Json::as_bool)
        .unwrap_or(true);
    object.insert(
        "provenance_verdict".to_string(),
        super::provenance_verdict_json(&out.results, present, profile),
    );
}

/// Whether the claim of `manifest` references the assertion box labelled
/// `alabel`.
///
/// The engine enforces claim -> store but NOT store -> claim: an EXTRA assertion
/// box the claim never references does not fail the binding walk, because that
/// walk only follows the claim's own references. So a check that trusts a box it
/// merely FOUND in the store can be fed an injected one, with the claim CBOR and
/// COSE signature left byte-identical. Both claim generations are consulted,
/// matched on the label after the `c2pa.assertions/` path segment, so an older
/// writer's manifest cannot evade the check by carrying v1 references.
fn claim_references_assertion(manifest: &ParsedManifest<'_>, alabel: &str) -> bool {
    let Some(claim) = manifest.claim_cbor.and_then(|bytes| decode(bytes).ok()) else {
        return false;
    };
    [ClaimGeneration::V1, ClaimGeneration::V2]
        .into_iter()
        .flat_map(super::ref_fields)
        .filter_map(|field| match claim.get(field) {
            Some(Value::Array(items)) => Some(items.clone()),
            _ => None,
        })
        .flatten()
        .filter_map(|item| item.get("url").and_then(Value::as_text).map(str::to_string))
        .any(|url| url.rsplit("c2pa.assertions/").next() == Some(alabel))
}

/// The continuity state a successor is compared against: what this segment
/// declares, plus the manifest identity it must be named by.
fn declared_live_state(
    declared: &DeclaredSegment,
    manifest_label: &str,
) -> Option<LiveVideoManifestState> {
    Some(LiveVideoManifestState {
        sequence_number: u64::try_from(declared.sequence_number?).ok()?,
        stream_id: declared.stream_id.clone()?,
        manifest_id: manifest_label.to_owned(),
    })
}

/// The chain-report line for one filed live-video status.
///
/// The status code decides the wording, so the human report and the normative
/// result always describe the same defect.
fn live_chain_failure(
    position: usize,
    code: &str,
    expected_label: &str,
    claimed: Option<&str>,
) -> String {
    match code {
        LIVEVIDEO_SEGMENT_INVALID => format!(
            "segment {position}: previousManifestId {claimed:?} does not name the \
             preceding manifest {expected_label:?}"
        ),
        LIVEVIDEO_CONTINUITY_METHOD_INVALID => format!(
            "segment {position}: declares no usable manifest-ID continuity; expected \
             previousManifestId {expected_label:?}"
        ),
        _ => format!(
            "segment {position}: declared live-video sequence or stream does not follow \
             the preceding segment"
        ),
    }
}

/// Cross-check one segment's declared identity against the presented stream.
fn check_declaration(
    position: usize,
    declared: &DeclaredSegment,
    expected_sequence_number: Option<i128>,
    expected_seek: bool,
    encapsulation: StreamEncapsulation,
    stream_id: &mut Option<String>,
    failures: &mut Vec<String>,
) {
    match (
        declared.sequence_number,
        expected_sequence_number,
        expected_seek,
    ) {
        (Some(sequence), _, true) if sequence >= 0 => {}
        (Some(sequence), Some(expected), false) if sequence == expected => {}
        (Some(sequence), Some(expected), false) => failures.push(format!(
            "segment {position}: unexpected sequence discontinuity, declares sequenceNumber \
             {sequence}, expected {expected}"
        )),
        (Some(sequence), None, false) => failures.push(format!(
            "segment {position}: sequenceNumber {sequence} cannot follow an exhausted sequence"
        )),
        (Some(sequence), _, _) => failures.push(format!(
            "segment {position}: declares invalid sequenceNumber {sequence}"
        )),
        (None, _, _) => failures.push(format!(
            "segment {position}: {LIVE_VIDEO_SEGMENT_LABEL} has no sequenceNumber"
        )),
    }
    match (&declared.stream_id, &stream_id) {
        (Some(declared_id), None) => *stream_id = Some(declared_id.clone()),
        (Some(declared_id), Some(expected)) if declared_id != expected => failures.push(format!(
            "segment {position}: declares streamId {declared_id:?}, expected {expected:?}"
        )),
        (Some(_), Some(_)) => {}
        (None, _) => failures.push(format!(
            "segment {position}: {LIVE_VIDEO_SEGMENT_LABEL} has no streamId"
        )),
    }
    if declared.encapsulation.as_deref() != Some(encapsulation.token()) {
        failures.push(format!(
            "segment {position}: declares encapsulation {:?}, verified as {}",
            declared.encapsulation, encapsulation
        ));
    }
    if declared.method.as_deref() != Some(StreamMethod::PerSegment.token()) {
        failures.push(format!(
            "segment {position}: declares method {:?}, verified as {}",
            declared.method,
            StreamMethod::PerSegment
        ));
    }
}

/// The [`LIVE_VIDEO_SEGMENT_LABEL`] fields a segment declares. Every field is
/// optional at this layer so a malformed assertion is reported precisely rather
/// than collapsing the whole read.
struct DeclaredSegment {
    sequence_number: Option<i128>,
    stream_id: Option<String>,
    encapsulation: Option<String>,
    method: Option<String>,
    previous_manifest_id: Option<String>,
}

/// The chain facts read from one signed segment.
struct SegmentFacts {
    manifest_label: String,
    /// SHA-256 over the active manifest's JUMBF superbox content: exactly what
    /// the next segment's ingredient assertion records.
    active_manifest_hash: Vec<u8>,
    /// The segment's ordering record, or why it cannot be honored.
    declared: Result<DeclaredSegment, &'static str>,
    /// The same record's raw CBOR, empty when the record cannot be honored. The
    /// live-video status SSOT re-reads it rather than trusting fields decoded
    /// here, so one parser owns what the normative statuses are decided from.
    declaration_cbor: Vec<u8>,
    /// `activeManifest.hash` from this segment's sole claim-bound `parentOf`
    /// ingredient: `Ok(None)` when it has none, `Err` when the store's link
    /// cannot be trusted.
    parent_link: Result<Option<Vec<u8>>, &'static str>,
}

/// Read one segment's chain facts, or `None` when it carries no manifest.
///
/// Both reads below are guarded against unreferenced-box injection, in this
/// order: COUNT first, so a duplicate is refused before any value is read and
/// the guard cannot be bypassed by whichever box a `find` happens to return;
/// then CLAIM REFERENCE, so a box the claim does not cover is refused rather
/// than honored.
///
/// Neither guard is redundant. For a segment THIS engine signed both labels are
/// always emitted and always claim-referenced, so the hashed-URI walk already
/// catches prepend-of-a-duplicate-label and replace-in-place. That reasoning is
/// about our own output; an attacker chooses the input. A verifiable-segment-info
/// init segment is signed by the same signer, is valid on its own, and carries
/// NEITHER assertion — so for that input the labels are absent from the claim, no
/// hashed-URI is left behind to fail, and the claim-reference guard is the ONLY
/// barrier against laundering it into a chain under the original signer's
/// certificate.
fn segment_facts(segment: &[u8], mime: &str) -> Result<Option<SegmentFacts>, ValidateError> {
    let format = AssetFormat::from_mime(mime)
        .ok_or_else(|| ValidateError::UnsupportedMime(mime.to_string()))?;
    let Some(store) = crate::c2pa_formats::extract_manifest(format, segment)? else {
        return Ok(None);
    };
    let parsed = parse_manifest_store(&store)?;
    let Some(active) = parsed.manifests.last() else {
        return Ok(None);
    };
    let active_manifest_hash = manifest_superboxes_from_store(&store)?
        .last()
        .and_then(|superbox| superbox_content(superbox).ok())
        .and_then(|content| hash_bytes(CHAIN_HASH_ALG, content))
        .ok_or_else(|| {
            ValidateError::Stream("segment manifest store has no hashable active manifest".into())
        })?;

    let (declared, declaration_cbor) = match read_declaration(active) {
        Ok((declared, cbor)) => (Ok(declared), cbor),
        Err(defect) => (Err(defect), Vec::new()),
    };
    Ok(Some(SegmentFacts {
        manifest_label: active.label.clone(),
        active_manifest_hash,
        declared,
        declaration_cbor,
        parent_link: read_parent_link(active),
    }))
}

/// The sole claim-bound ordering record of `active`.
///
/// Multiplicity is enforced BY CONSTRUCTION via an exactly-one slice pattern
/// rather than by a count guard placed ahead of the value read. A guard is only
/// correct while it stays ahead; a pattern that cannot match two elements makes
/// the property a compile-time fact, so a later edit cannot reorder it into dead
/// code.
fn read_declaration(
    active: &ParsedManifest<'_>,
) -> Result<(DeclaredSegment, Vec<u8>), &'static str> {
    let found: Vec<_> = active
        .assertions
        .iter()
        .filter(|(label, _)| label == LIVE_VIDEO_SEGMENT_LABEL)
        .collect();
    let [(label, cbor)] = found.as_slice() else {
        return Err(if found.is_empty() {
            "missing segment-identity assertion"
        } else {
            "carries more than one segment-identity assertion, so its declared \
             ordering cannot be trusted"
        });
    };
    if !claim_references_assertion(active, label) {
        return Err("segment-identity assertion is not referenced by the claim");
    }
    let value = decode(cbor).map_err(|_| "segment-identity assertion is not decodable CBOR")?;
    Ok((
        DeclaredSegment {
            sequence_number: match value.get("sequenceNumber") {
                Some(Value::Integer(sequence)) => Some(*sequence),
                _ => None,
            },
            stream_id: text_field(&value, "streamId"),
            encapsulation: text_field(&value, "encapsulation"),
            method: text_field(&value, "method"),
            previous_manifest_id: text_field(&value, "previousManifestId"),
        },
        (*cbor).to_vec(),
    ))
}

/// The `activeManifest.hash` of `active`'s sole claim-bound `parentOf`
/// ingredient. Sibling ingredients with other relationships are ignored: a
/// manifest may legitimately carry several, but it has at most one parent.
///
/// As in [`read_declaration`], exactly-one is a slice pattern rather than a count
/// guard, so multiplicity cannot be reordered into dead code by a later edit.
fn read_parent_link(active: &ParsedManifest<'_>) -> Result<Option<Vec<u8>>, &'static str> {
    let parents: Vec<_> = active
        .assertions
        .iter()
        .filter(|(label, _)| is_ingredient_label(label))
        .filter_map(|(label, cbor)| decode(cbor).ok().map(|value| (label, value)))
        .filter(|(_, value)| value.get("relationship").and_then(Value::as_text) == Some("parentOf"))
        .collect();
    let [(label, value)] = parents.as_slice() else {
        if parents.is_empty() {
            return Ok(None);
        }
        return Err(
            "carries more than one parentOf ingredient assertion, so its chain link \
             cannot be trusted",
        );
    };
    if !claim_references_assertion(active, label) {
        return Err("parentOf ingredient assertion is not referenced by the claim");
    }
    value
        .get("activeManifest")
        .and_then(|manifest| manifest.get("hash"))
        .and_then(Value::as_bytes)
        .map(<[u8]>::to_vec)
        .map(Some)
        .ok_or("parentOf ingredient assertion carries no activeManifest hash")
}

/// A text field of a CBOR map, cloned.
fn text_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_text).map(str::to_owned)
}

/// The base ingredient label or one of its standard `__N` instances.
fn is_ingredient_label(label: &str) -> bool {
    label == INGREDIENT_ASSERTION_LABEL
        || label
            .strip_prefix(INGREDIENT_ASSERTION_LABEL)
            .and_then(|suffix| suffix.strip_prefix("__"))
            .and_then(|instance| instance.parse::<usize>().ok())
            .is_some_and(|instance| instance > 0)
}

/// Validate the caller's expected-seek signals before any signed bytes are
/// evaluated. Positions index the supplied portions and must be unique and
/// increasing so one signal can suppress exactly one boundary.
pub(crate) fn validate_expected_seek_positions(
    expected_seek_positions: &[usize],
    segment_count: usize,
) -> Result<(), ValidateError> {
    let mut previous = None;
    for &position in expected_seek_positions {
        if position >= segment_count {
            return Err(ValidateError::Stream(format!(
                "expected seek position {position} is outside {segment_count} presented segment(s)"
            )));
        }
        if previous.is_some_and(|prior| prior >= position) {
            return Err(ValidateError::Stream(
                "expected seek positions must be unique and strictly increasing".into(),
            ));
        }
        previous = Some(position);
    }
    Ok(())
}

/// Brand-gate an explicitly declared stream, naming the offending file.
fn check_stream_brands(
    init_segment: &[u8],
    segments: &[&[u8]],
    encapsulation: StreamEncapsulation,
) -> Result<(), ValidateError> {
    bmff_check_stream_brand(init_segment, StreamFileRole::Init, encapsulation)
        .map_err(|e| ValidateError::Stream(format!("{encapsulation} init segment: {e}")))?;
    for (index, segment) in segments.iter().enumerate() {
        bmff_check_stream_brand(segment, StreamFileRole::Segment, encapsulation)
            .map_err(|e| ValidateError::Stream(format!("{encapsulation} segment {index}: {e}")))?;
    }
    Ok(())
}

/// `input` retargeted at `data`, keeping every trust, evidence, and profile
/// setting.
fn input_for<'a>(input: &VerifyInput<'a>, data: &'a [u8]) -> VerifyInput<'a> {
    VerifyInput { data, ..*input }
}
