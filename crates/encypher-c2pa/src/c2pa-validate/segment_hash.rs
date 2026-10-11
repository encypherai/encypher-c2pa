// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA 2.5 `c2pa.hash.segment` validation (Validate the Asset's Content,
//! "Validating a segment hash"): the hard binding of an append-only text
//! checkpoint.
//!
//! The active checkpoint's segment hash is checked for structure, its
//! sentinel position, its segment digest and its coverage of the file, then
//! the chain of predecessor checkpoints is walked: each predecessor sentinel
//! line must hash to the recorded `predecessorSentinel.hash`, and the store
//! that line references must carry a segment hash that is itself well formed,
//! correctly placed and matching, back to the first checkpoint.
//!
//! An external predecessor store is read only from caller-supplied evidence or
//! the network-free resource provider; the kernel never fetches. Provider
//! bodies are borrowed through the verification pass's URI cache. When a store
//! is absent, `manifest.inaccessible` is recorded without rejecting the active
//! checkpoint, and every earlier segment is reported unverified, exactly as
//! the clause directs.
//!
//! Open upstream question (specs-core issue 2589): the clause authenticates a
//! predecessor through two paths - the sentinel digest chain here and the
//! `parentOf` ingredient the checkpoint manifest declares - without requiring
//! that both name the same manifest. This module implements the digest chain
//! as written and does not invent the missing identity rule.

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::jumbf::{expand_store, parse_manifest_store};
use crate::c2pa_formats::{
    checkpoint_sentinel_at, AppendOnlyFlavor, CheckpointReference, CheckpointSentinel,
};
use serde_json::json;

use super::{
    base_assertion_label, hash_bytes, is_allowed_hash_algorithm, network_needs,
    resolved_hash_algorithm, NetworkNeed, ValidationResults, ALGORITHM_UNSUPPORTED,
    MANIFEST_INACCESSIBLE,
};

/// Success: a segment hash matched its segment.
pub const ASSERTION_SEGMENT_HASH_MATCH: &str = "assertion.segmentHash.match";
/// Failure: a segment's digest, or its sentinel position, did not match.
pub const ASSERTION_SEGMENT_HASH_MISMATCH: &str = "assertion.segmentHash.mismatch";
/// Failure: a segment hash assertion is structurally invalid.
pub const ASSERTION_SEGMENT_HASH_MALFORMED: &str = "assertion.segmentHash.malformed";
/// Failure: the checkpoints leave bytes of the file uncovered.
pub const ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE: &str = "assertion.segmentHash.partialCoverage";
/// Failure: a predecessor sentinel line does not hash to the recorded digest.
pub const ASSERTION_SEGMENT_HASH_PREDECESSOR_MISMATCH: &str =
    "assertion.segmentHash.predecessorMismatch";
/// Failure: an append-only text file has no usable active sentinel line.
pub const MANIFEST_APPEND_ONLY_TEXT_NO_SENTINEL: &str = "manifest.appendOnlyText.noSentinel";

/// Checkpoints the chain walk follows before it stops and reports the rest of
/// the history unverified. Each step decodes one store, so the bound caps
/// verifier work on a file with an adversarially long chain.
const MAX_CHECKPOINT_CHAIN: usize = 4096;
/// Aggregate store bytes the chain walk decodes.
const MAX_CHAIN_STORE_BYTES: usize = 256 * 1024 * 1024;

/// The fields of one `segment-hash-map`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SegmentHash {
    alg: String,
    hash: Vec<u8>,
    start: usize,
    end: usize,
    sentinel_length: Option<usize>,
    predecessor: Option<Predecessor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Predecessor {
    start: usize,
    length: usize,
    hash: Vec<u8>,
}

/// Why a segment hash map could not be read.
enum ParseError {
    Malformed(&'static str),
    Algorithm(String),
}

fn uint(value: Option<&Value>) -> Option<usize> {
    match value {
        Some(Value::Integer(n)) if *n >= 0 => usize::try_from(*n).ok(),
        _ => None,
    }
}

/// Read a `segment-hash-map`. `enclosing` supplies the claim's `alg` when the
/// assertion names none.
fn parse(assertion: &Value, enclosing: &Value) -> Result<SegmentHash, ParseError> {
    match assertion.get("version") {
        Some(Value::Integer(1)) => {}
        _ => return Err(ParseError::Malformed("version is absent or not 1")),
    }
    let hash = assertion
        .get("hash")
        .and_then(Value::as_bytes)
        .ok_or(ParseError::Malformed("hash is absent"))?
        .to_vec();
    let start = uint(assertion.get("segmentStart")).ok_or(ParseError::Malformed(
        "segmentStart is absent or not an unsigned integer",
    ))?;
    let end = uint(assertion.get("segmentEnd")).ok_or(ParseError::Malformed(
        "segmentEnd is absent or not an unsigned integer",
    ))?;
    if end < start {
        return Err(ParseError::Malformed(
            "segmentEnd is less than segmentStart",
        ));
    }
    let sentinel_length = match assertion.get("sentinelLength") {
        None => None,
        value => Some(uint(value).ok_or(ParseError::Malformed(
            "sentinelLength is not an unsigned integer",
        ))?),
    };
    let predecessor = match assertion.get("predecessorSentinel") {
        None => None,
        Some(map) => {
            let (Some(start), Some(length), Some(hash)) = (
                uint(map.get("start")),
                uint(map.get("length")),
                map.get("hash").and_then(Value::as_bytes),
            ) else {
                return Err(ParseError::Malformed(
                    "predecessorSentinel lacks start, length or hash",
                ));
            };
            Some(Predecessor {
                start,
                length,
                hash: hash.to_vec(),
            })
        }
    };
    let alg = resolved_hash_algorithm(assertion, enclosing)
        .ok_or_else(|| ParseError::Algorithm("segment hash names no hash algorithm".into()))?;
    if !is_allowed_hash_algorithm(alg) {
        return Err(ParseError::Algorithm(format!(
            "segment hash uses unsupported hash algorithm '{alg}'"
        )));
    }
    Ok(SegmentHash {
        alg: alg.to_string(),
        hash,
        start,
        end,
        sentinel_length,
        predecessor,
    })
}

/// The sentinel line beginning at `start`, in whichever line grammar the file
/// uses. A file supplied without a format hint (an external store's asset) is
/// tried as plain text first, then as JSON Lines.
fn sentinel_at(
    data: &[u8],
    start: usize,
    flavor: Option<AppendOnlyFlavor>,
) -> Option<CheckpointSentinel> {
    match flavor {
        Some(flavor) => checkpoint_sentinel_at(data, start, flavor),
        None => checkpoint_sentinel_at(data, start, AppendOnlyFlavor::PlainText)
            .or_else(|| checkpoint_sentinel_at(data, start, AppendOnlyFlavor::JsonLines)),
    }
}

/// One checkpoint's General checks: sentinel position and form, and the
/// segment digest. Returns the sentinel on success.
fn check_segment(
    segment: &SegmentHash,
    data: &[u8],
    flavor: Option<AppendOnlyFlavor>,
    expected_sentinel_start: Option<usize>,
    url: &str,
    results: &mut ValidationResults,
) -> Option<CheckpointSentinel> {
    let Some(sentinel) = sentinel_at(data, segment.end, flavor)
        .filter(|sentinel| expected_sentinel_start.is_none_or(|start| start == sentinel.start))
    else {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_MISMATCH,
            url.to_string(),
            "the sentinel line carrying this manifest does not begin at segmentEnd".into(),
        );
        return None;
    };
    let external = matches!(sentinel.reference, CheckpointReference::External(_));
    if external != segment.sentinel_length.is_some() {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_MALFORMED,
            url.to_string(),
            if external {
                "sentinelLength is absent although the sentinel references an external store"
            } else {
                "sentinelLength is present although the sentinel carries the store inline"
            }
            .into(),
        );
        return None;
    }
    let digest = hash_bytes(&segment.alg, &data[segment.start..segment.end]);
    if digest.as_deref() != Some(segment.hash.as_slice()) {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_MISMATCH,
            url.to_string(),
            format!(
                "segment [{}, {}) does not hash to the recorded value",
                segment.start, segment.end
            ),
        );
        return None;
    }
    Some(sentinel)
}

/// The first-checkpoint and contiguity coverage rules.
fn check_start(segment: &SegmentHash, url: &str, results: &mut ValidationResults) -> bool {
    let expected = segment
        .predecessor
        .as_ref()
        .map_or(Some(0), |p| p.start.checked_add(p.length));
    if expected == Some(segment.start) {
        return true;
    }
    results.push_failure(
        ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE,
        url.to_string(),
        match &segment.predecessor {
            None => "the first checkpoint's segment does not start at byte 0".to_string(),
            Some(_) => "the segment does not start immediately after the preceding sentinel line"
                .to_string(),
        },
    );
    false
}

/// What a predecessor's store yielded for the chain walk.
struct PredecessorCheckpoint {
    manifest_label: String,
    assertion_label: String,
    manifest_bytes: usize,
    segment: Result<SegmentHash, ParseError>,
}

/// Decode a predecessor store and read its active manifest's segment hash.
fn predecessor_checkpoint(store: &[u8]) -> Result<PredecessorCheckpoint, &'static str> {
    let expanded = expand_store(store).map_err(|_| "predecessor store is not a manifest store")?;
    let parsed = parse_manifest_store(expanded.bytes())
        .map_err(|_| "predecessor store is not a manifest store")?;
    let manifest = parsed
        .manifests
        .last()
        .ok_or("predecessor store contains no manifest")?;
    let claim = manifest
        .claim_cbor
        .and_then(|bytes| decode(bytes).ok())
        .ok_or("predecessor checkpoint claim cannot be decoded")?;
    let mut segments = manifest
        .assertions
        .iter()
        .filter(|(label, _)| base_assertion_label(label) == "c2pa.hash.segment");
    let (Some((assertion_label, payload)), None) = (segments.next(), segments.next()) else {
        return Err("predecessor checkpoint does not carry exactly one c2pa.hash.segment");
    };
    let segment = match decode(*payload) {
        Ok(assertion) => parse(&assertion, &claim),
        Err(_) => Err(ParseError::Malformed("segment hash CBOR is invalid")),
    };
    Ok(PredecessorCheckpoint {
        manifest_label: manifest.label.clone(),
        assertion_label: assertion_label.clone(),
        manifest_bytes: manifest.manifest_jumbf.len(),
        segment,
    })
}

/// Locate the predecessor store named by one claim-declared segment binding.
/// This parses only the schema and sentinel needed for discovery; it performs
/// no digest, signature, or trust validation.
pub(super) fn locate_predecessor_reference(
    claim_refs: &super::ClaimAssertionRefs<'_>,
    claim: &Value,
    data: &[u8],
    flavor: AppendOnlyFlavor,
) -> Result<Option<CheckpointReference>, ()> {
    let mut declared = claim_refs.references.iter().filter_map(|reference| {
        let label = reference.label?;
        (base_assertion_label(label) == "c2pa.hash.segment").then_some(label)
    });
    let label = declared.next().ok_or(())?;
    if declared.next().is_some() {
        return Err(());
    }
    let assertion = claim_refs
        .indexed(label)
        .and_then(|assertion| assertion.decoded.as_ref())
        .ok_or(())?;
    let segment = parse(assertion, claim).map_err(|_| ())?;
    let Some(predecessor) = segment.predecessor else {
        return Ok(None);
    };
    let sentinel = sentinel_at(data, predecessor.start, Some(flavor))
        .filter(|sentinel| sentinel.length == predecessor.length)
        .ok_or(())?;
    Ok(Some(sentinel.reference))
}

/// The schema defect of a segment hash assertion, checked without the file:
/// the General structure rules and the hash algorithm. Position, digest,
/// coverage and chain rules need the file's bytes.
pub(super) fn schema_defect(assertion: &Value, claim: &Value) -> Option<(&'static str, String)> {
    match parse(assertion, claim) {
        Ok(_) => None,
        Err(ParseError::Malformed(why)) => Some((ASSERTION_SEGMENT_HASH_MALFORMED, why.into())),
        Err(ParseError::Algorithm(why)) => Some((ALGORITHM_UNSUPPORTED, why)),
    }
}

fn push_parse_error(error: ParseError, url: &str, results: &mut ValidationResults) {
    match error {
        ParseError::Malformed(why) => results.push_failure(
            ASSERTION_SEGMENT_HASH_MALFORMED,
            url.to_string(),
            why.into(),
        ),
        ParseError::Algorithm(why) => {
            results.push_failure(ALGORITHM_UNSUPPORTED, url.to_string(), why)
        }
    }
}

/// Validate the active checkpoint's `c2pa.hash.segment` binding and its chain.
///
/// `active_sentinel` is the sentinel the locator selected when the store came
/// from the file itself; a store supplied separately has none, and its
/// sentinel is then found at `segmentEnd` alone. `binding_compromised` keeps
/// a match from being reported after the assertion's own hashed-URI binding
/// failed.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    assertion: Option<&Value>,
    claim: &Value,
    data: &[u8],
    flavor: Option<AppendOnlyFlavor>,
    active_sentinel: Option<usize>,
    binding_compromised: bool,
    url: &str,
    resources: &mut super::refs::ResourceCache<'_>,
    budget: &mut super::ingredient_graph::Budget,
    results: &mut ValidationResults,
) {
    let Some(assertion) = assertion else {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_MALFORMED,
            url.to_string(),
            "segment hash CBOR is invalid".into(),
        );
        return;
    };
    let segment = match parse(assertion, claim) {
        Ok(segment) => segment,
        Err(error) => return push_parse_error(error, url, results),
    };
    if segment.end > data.len() {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_MISMATCH,
            url.to_string(),
            "segmentEnd lies beyond the end of the file".into(),
        );
        return;
    }
    let Some(sentinel) = check_segment(&segment, data, flavor, active_sentinel, url, results)
    else {
        return;
    };
    // Coverage of the asset, active checkpoint: its sentinel ends at EOF.
    let boundary = segment
        .end
        .checked_add(segment.sentinel_length.unwrap_or(sentinel.length));
    if boundary != Some(data.len()) {
        results.push_failure(
            ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE,
            url.to_string(),
            "the active checkpoint's sentinel line does not end at the end of the file".into(),
        );
        return;
    }
    if !check_start(&segment, url, results) {
        return;
    }
    if !binding_compromised {
        results.push_success(
            ASSERTION_SEGMENT_HASH_MATCH,
            url.to_string(),
            format!("segment [{}, {}) hash valid", segment.start, segment.end),
        );
    }
    verify_chain(segment, data, flavor, url, resources, budget, results);
}

/// Walk the predecessor chain from the active checkpoint to the first.
fn verify_chain(
    active: SegmentHash,
    data: &[u8],
    flavor: Option<AppendOnlyFlavor>,
    active_url: &str,
    resources: &mut super::refs::ResourceCache<'_>,
    budget: &mut super::ingredient_graph::Budget,
    results: &mut ValidationResults,
) {
    let mut current = active;
    let mut current_url = active_url.to_string();
    let mut decoded_bytes = 0usize;
    for depth in 1..=MAX_CHECKPOINT_CHAIN {
        let Some(predecessor) = current.predecessor.clone() else {
            return;
        };
        let line_end = predecessor.start.checked_add(predecessor.length);
        let digest = line_end
            .filter(|end| *end <= data.len())
            .and_then(|end| hash_bytes(&current.alg, &data[predecessor.start..end]));
        if digest.as_deref() != Some(predecessor.hash.as_slice()) {
            results.push_failure(
                ASSERTION_SEGMENT_HASH_PREDECESSOR_MISMATCH,
                current_url,
                "the preceding sentinel line does not hash to predecessorSentinel.hash".into(),
            );
            return;
        }
        let Some(line) = sentinel_at(data, predecessor.start, flavor)
            .filter(|line| line.length == predecessor.length)
        else {
            results.push_failure(
                ASSERTION_SEGMENT_HASH_PREDECESSOR_MISMATCH,
                current_url,
                "predecessorSentinel does not locate a complete checkpoint sentinel line".into(),
            );
            return;
        };
        if !budget.resource_edge(depth) {
            results.push_informational(
                MANIFEST_INACCESSIBLE,
                current_url,
                "earlier checkpoint stores exceed the graph limits; earlier history is unverified"
                    .into(),
            );
            return;
        }
        let store: &[u8] = match &line.reference {
            CheckpointReference::Inline(store) => store,
            CheckpointReference::External(uri) => match resources.resolve(uri) {
                super::refs::ResolvedResource::Retrieved { bytes, .. } => bytes,
                super::refs::ResolvedResource::Unavailable => {
                    results.push_informational_with_details(
                            MANIFEST_INACCESSIBLE,
                            uri.clone(),
                            "an earlier checkpoint's external manifest store could not be retrieved; that segment and every earlier one are unverified".into(),
                            json!({
                                "checkpoint_sentinel_start": predecessor.start,
                                "history": "unverified",
                            }),
                        );
                    return;
                }
                super::refs::ResolvedResource::NotAttempted => {
                    results.push_informational_with_details(
                            MANIFEST_INACCESSIBLE,
                            uri.clone(),
                            "an earlier checkpoint's manifest store is external and was not supplied; that segment and every earlier one are unverified".into(),
                            json!({
                                "checkpoint_sentinel_start": predecessor.start,
                                "history": "unverified",
                            }),
                        );
                    network_needs::push_unique(
                        &mut results.network_needs,
                        NetworkNeed::ExternalData {
                            uri: uri.clone(),
                            assertion_label: "c2pa.hash.segment".to_string(),
                        },
                    );
                    return;
                }
            },
        };
        decoded_bytes = decoded_bytes.saturating_add(store.len());
        if decoded_bytes > MAX_CHAIN_STORE_BYTES || store.len() > crate::MAX_MANIFEST_STORE_BYTES {
            results.push_informational(
                MANIFEST_INACCESSIBLE,
                current_url,
                "earlier checkpoint stores exceed the verifier bound; earlier history is unverified"
                    .into(),
            );
            return;
        }
        let checkpoint = match predecessor_checkpoint(store) {
            Ok(checkpoint) => checkpoint,
            Err(why) => {
                results.push_failure(ASSERTION_SEGMENT_HASH_MALFORMED, current_url, why.into());
                return;
            }
        };
        if !budget.resource_bytes(checkpoint.manifest_bytes) {
            results.push_informational(
                MANIFEST_INACCESSIBLE,
                current_url,
                "earlier checkpoint stores exceed the graph limits; earlier history is unverified"
                    .into(),
            );
            return;
        }
        let url = format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/{}",
            checkpoint.manifest_label, checkpoint.assertion_label
        );
        let segment = match checkpoint.segment {
            Ok(segment) => segment,
            Err(error) => return push_parse_error(error, &url, results),
        };
        if segment.end > data.len() {
            results.push_failure(
                ASSERTION_SEGMENT_HASH_MISMATCH,
                url,
                "segmentEnd lies beyond the end of the file".into(),
            );
            return;
        }
        if check_segment(
            &segment,
            data,
            flavor,
            Some(predecessor.start),
            &url,
            results,
        )
        .is_none()
            || !check_start(&segment, &url, results)
        {
            return;
        }
        // A non-active checkpoint's sentinel must be exactly the line the
        // next checkpoint located, so its declared length (when it has one)
        // must agree with it.
        if segment
            .sentinel_length
            .is_some_and(|length| length != predecessor.length)
        {
            results.push_failure(
                ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE,
                url,
                "sentinelLength disagrees with the sentinel line the next checkpoint located"
                    .into(),
            );
            return;
        }
        results.push_success(
            ASSERTION_SEGMENT_HASH_MATCH,
            url.clone(),
            format!(
                "earlier checkpoint segment [{}, {}) hash valid",
                segment.start, segment.end
            ),
        );
        current = segment;
        current_url = url;
    }
    if current.predecessor.is_some() {
        results.push_informational(
            MANIFEST_INACCESSIBLE,
            current_url,
            "the checkpoint chain exceeds the verifier bound; earlier history is unverified".into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::ingredient_graph::GraphLimits;
    use super::super::OnlineEvidence;
    use super::*;
    use crate::c2pa_core::jumbf::{assertion_box, build_manifest, build_manifest_store};
    use sha2::{Digest, Sha256};

    fn int(n: usize) -> Value {
        Value::Integer(n as i128)
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_string())
    }

    fn segment_map(
        data: &[u8],
        start: usize,
        end: usize,
        sentinel_length: Option<usize>,
        predecessor: Option<(usize, usize)>,
    ) -> Value {
        let mut map = vec![
            (text("version"), int(1)),
            (text("alg"), text("sha256")),
            (
                text("hash"),
                Value::Bytes(Sha256::digest(&data[start..end]).to_vec()),
            ),
            (text("segmentStart"), int(start)),
            (text("segmentEnd"), int(end)),
        ];
        if let Some(length) = sentinel_length {
            map.push((text("sentinelLength"), int(length)));
        }
        if let Some((p_start, p_len)) = predecessor {
            map.push((
                text("predecessorSentinel"),
                Value::Map(vec![
                    (text("start"), int(p_start)),
                    (text("length"), int(p_len)),
                    (
                        text("hash"),
                        Value::Bytes(Sha256::digest(&data[p_start..p_start + p_len]).to_vec()),
                    ),
                ]),
            ));
        }
        Value::Map(map)
    }

    fn line(reference: &str) -> String {
        format!("-----BEGIN C2PA CHECKPOINT----- {reference} -----END C2PA CHECKPOINT-----\n")
    }

    fn run(assertion: &Value, data: &[u8], evidence: OnlineEvidence<'_>) -> ValidationResults {
        run_with_resources(assertion, data, evidence, None, GraphLimits::default())
    }

    fn run_with_resources(
        assertion: &Value,
        data: &[u8],
        evidence: OnlineEvidence<'_>,
        provider: Option<&dyn super::super::refs::ExternalResources>,
        limits: GraphLimits,
    ) -> ValidationResults {
        let mut results = ValidationResults::default();
        let mut resources = super::super::refs::ResourceCache::with_evidence(provider, evidence);
        let mut budget = super::super::ingredient_graph::Budget::new(limits);
        verify(
            Some(assertion),
            &Value::Map(Vec::new()),
            data,
            Some(AppendOnlyFlavor::PlainText),
            None,
            false,
            "self#jumbf=/c2pa/urn:active/c2pa.assertions/c2pa.hash.segment",
            &mut resources,
            &mut budget,
            &mut results,
        );
        budget.report("urn:active", &mut results);
        results
    }

    /// The spec's first test vector: external sentinel, LF line endings.
    fn first_checkpoint() -> (Vec<u8>, Value) {
        let mut data = b"alpha\nbravo\n".to_vec();
        data.extend_from_slice(
            line("https://northwindtraders.com/provenance/chk1.c2pa").as_bytes(),
        );
        let assertion = segment_map(&data, 0, 12, Some(112), None);
        (data, assertion)
    }

    #[test]
    fn first_checkpoint_matches_and_covers_the_file() {
        let (data, assertion) = first_checkpoint();
        let results = run(&assertion, &data, OnlineEvidence::default());
        assert!(
            results.has_success(ASSERTION_SEGMENT_HASH_MATCH),
            "{results:?}"
        );
        assert!(results.failure.is_empty(), "{results:?}");
    }

    #[test]
    fn tampering_with_the_segment_is_a_mismatch() {
        let (mut data, assertion) = first_checkpoint();
        data[0] = b'A';
        let results = run(&assertion, &data, OnlineEvidence::default());
        assert!(results.has_failure(ASSERTION_SEGMENT_HASH_MISMATCH));
        assert!(!results.has_success(ASSERTION_SEGMENT_HASH_MATCH));
    }

    #[test]
    fn appended_uncovered_content_is_partial_coverage() {
        let (mut data, assertion) = first_checkpoint();
        data.extend_from_slice(b"charlie\n");
        let results = run(&assertion, &data, OnlineEvidence::default());
        assert!(results.has_failure(ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE));
    }

    #[test]
    fn a_first_checkpoint_must_start_at_zero() {
        let (data, _) = first_checkpoint();
        let assertion = segment_map(&data, 6, 12, Some(112), None);
        let results = run(&assertion, &data, OnlineEvidence::default());
        assert!(results.has_failure(ASSERTION_SEGMENT_HASH_PARTIAL_COVERAGE));
    }

    #[test]
    fn structure_and_sentinel_form_are_checked() {
        let (data, _) = first_checkpoint();
        // sentinelLength absent with an external reference.
        let missing_length = segment_map(&data, 0, 12, None, None);
        assert!(run(&missing_length, &data, OnlineEvidence::default())
            .has_failure(ASSERTION_SEGMENT_HASH_MALFORMED));
        // version 2.
        let Value::Map(mut entries) = segment_map(&data, 0, 12, Some(112), None) else {
            unreachable!()
        };
        entries[0].1 = int(2);
        assert!(run(&Value::Map(entries), &data, OnlineEvidence::default())
            .has_failure(ASSERTION_SEGMENT_HASH_MALFORMED));
        // segmentEnd before segmentStart.
        let reversed = Value::Map(vec![
            (text("version"), int(1)),
            (text("alg"), text("sha256")),
            (text("hash"), Value::Bytes(vec![0; 32])),
            (text("segmentStart"), int(5)),
            (text("segmentEnd"), int(4)),
        ]);
        assert!(run(&reversed, &data, OnlineEvidence::default())
            .has_failure(ASSERTION_SEGMENT_HASH_MALFORMED));
        // segmentEnd not at the sentinel.
        let off = segment_map(&data, 0, 11, Some(112), None);
        assert!(run(&off, &data, OnlineEvidence::default())
            .has_failure(ASSERTION_SEGMENT_HASH_MISMATCH));
        // Unsupported algorithm.
        let Value::Map(mut entries) = segment_map(&data, 0, 12, Some(112), None) else {
            unreachable!()
        };
        entries[1].1 = text("md5");
        assert!(run(&Value::Map(entries), &data, OnlineEvidence::default())
            .has_failure(ALGORITHM_UNSUPPORTED));
    }

    /// A two-checkpoint file whose first checkpoint store is inline.
    fn two_checkpoints() -> (Vec<u8>, Value) {
        let mut data = b"alpha\nbravo\n".to_vec();
        let first_assertion = segment_map(&data, 0, 12, None, None);
        let assertion = assertion_box(
            "c2pa.hash.segment",
            &crate::c2pa_cbor::encode(
                &first_assertion,
                crate::c2pa_cbor::Profile::CanonicalForHashedSubstructures,
            )
            .unwrap(),
            None,
        );
        let manifest = build_manifest("urn:c2pa:first", &[assertion], &[0xa0], &[0xd2, 0x84]);
        let store = build_manifest_store(&[manifest]);
        let first_line = line(&format!(
            "data:application/c2pa;base64,{}",
            crate::c2pa_formats::util::base64_encode(&store)
        ));
        data.extend_from_slice(first_line.as_bytes());
        let second_start = data.len();
        data.extend_from_slice(b"charlie\ndelta\n");
        let second_end = data.len();
        let external = line("https://e.example/chk2.c2pa");
        data.extend_from_slice(external.as_bytes());
        let active = segment_map(
            &data,
            second_start,
            second_end,
            Some(external.len()),
            Some((12, first_line.len())),
        );
        (data, active)
    }

    #[test]
    fn the_chain_is_walked_through_an_inline_predecessor() {
        let (data, active) = two_checkpoints();
        let results = run(&active, &data, OnlineEvidence::default());
        assert!(results.failure.is_empty(), "{results:?}");
        let matches = results
            .success
            .iter()
            .filter(|status| status.code == ASSERTION_SEGMENT_HASH_MATCH)
            .count();
        assert_eq!(matches, 2, "active and predecessor both verified");
    }

    fn two_external_checkpoints() -> (Vec<u8>, Value, Vec<u8>) {
        let mut data = b"alpha\n".to_vec();
        let first_line = line("https://e.example/chk1.c2pa");
        data.extend_from_slice(first_line.as_bytes());
        let first_assertion = segment_map(&data, 0, 6, Some(first_line.len()), None);
        let assertion = assertion_box(
            "c2pa.hash.segment",
            &crate::c2pa_cbor::encode(
                &first_assertion,
                crate::c2pa_cbor::Profile::CanonicalForHashedSubstructures,
            )
            .unwrap(),
            None,
        );
        let manifest = build_manifest("urn:c2pa:first", &[assertion], &[0xa0], &[0xd2, 0x84]);
        let store = build_manifest_store(&[manifest]);
        let second_start = data.len();
        data.extend_from_slice(b"bravo\n");
        let second_end = data.len();
        let second_line = line("https://e.example/chk2.c2pa");
        data.extend_from_slice(second_line.as_bytes());
        let active = segment_map(
            &data,
            second_start,
            second_end,
            Some(second_line.len()),
            Some((6, first_line.len())),
        );
        (data, active, store)
    }

    #[test]
    fn injected_resource_verifies_external_predecessor_with_graph_limits() {
        struct Provider<'a> {
            store: &'a [u8],
            calls: std::cell::Cell<usize>,
        }

        impl super::super::refs::ExternalResources for Provider<'_> {
            fn resolve(&self, url: &str) -> super::super::refs::ExternalResource<'_> {
                assert_eq!(url, "https://e.example/chk1.c2pa");
                self.calls.set(self.calls.get() + 1);
                super::super::refs::ExternalResource::Retrieved {
                    bytes: self.store,
                    media_type: Some("application/c2pa"),
                }
            }
        }

        let (data, active, store) = two_external_checkpoints();
        let provider = Provider {
            store: &store,
            calls: std::cell::Cell::new(0),
        };
        let results = run_with_resources(
            &active,
            &data,
            OnlineEvidence::default(),
            Some(&provider),
            GraphLimits::default(),
        );
        assert!(results.failure.is_empty(), "{results:?}");
        assert_eq!(
            results
                .success
                .iter()
                .filter(|status| status.code == ASSERTION_SEGMENT_HASH_MATCH)
                .count(),
            2
        );
        assert_eq!(provider.calls.get(), 1);

        let limited = run_with_resources(
            &active,
            &data,
            OnlineEvidence::default(),
            Some(&provider),
            GraphLimits::lowered(32, 0, usize::MAX, usize::MAX),
        );
        assert!(limited.has_informational(super::super::ingredient_graph::GRAPH_LIMIT_EXCEEDED));
        assert_eq!(
            provider.calls.get(),
            1,
            "node limit is enforced before provider resolution"
        );
    }

    #[test]
    fn rewriting_history_breaks_the_predecessor_digest() {
        let (mut data, active) = two_checkpoints();
        // Flip one Base64 character of the first sentinel's inline store.
        let at = 12 + "-----BEGIN C2PA CHECKPOINT----- data:application/c2pa;base64,".len() + 4;
        data[at] = if data[at] == b'A' { b'B' } else { b'A' };
        let results = run(&active, &data, OnlineEvidence::default());
        assert!(results.has_failure(ASSERTION_SEGMENT_HASH_PREDECESSOR_MISMATCH));
    }

    #[test]
    fn rewriting_an_earlier_segment_fails_the_predecessor_check() {
        let (mut data, active) = two_checkpoints();
        data[0] = b'A';
        let results = run(&active, &data, OnlineEvidence::default());
        assert!(results.has_failure(ASSERTION_SEGMENT_HASH_MISMATCH));
        // The active segment itself still matched.
        assert!(results.has_success(ASSERTION_SEGMENT_HASH_MATCH));
    }

    #[test]
    fn an_unavailable_external_predecessor_is_inaccessible_not_rejected() {
        let mut data = b"alpha\n".to_vec();
        let first = line("https://e.example/chk1.c2pa");
        data.extend_from_slice(first.as_bytes());
        let second_start = data.len();
        data.extend_from_slice(b"bravo\n");
        let second_end = data.len();
        let second = line("https://e.example/chk2.c2pa");
        data.extend_from_slice(second.as_bytes());
        let active = segment_map(
            &data,
            second_start,
            second_end,
            Some(second.len()),
            Some((6, first.len())),
        );
        let results = run(&active, &data, OnlineEvidence::default());
        assert!(results.failure.is_empty(), "{results:?}");
        assert!(results.has_success(ASSERTION_SEGMENT_HASH_MATCH));
        assert!(results.has_informational(MANIFEST_INACCESSIBLE));
        assert!(results.network_needs.iter().any(|need| matches!(
            need,
            NetworkNeed::ExternalData { uri, .. } if uri == "https://e.example/chk1.c2pa"
        )));
    }
}
