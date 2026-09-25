// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Live-video and fragmented-stream verification contracts (PRD 1.1, 5.9).
//!
//! The corpus is `tests/fixtures/live-video`; see its README for provenance.
//! Every case is offline and deterministic: the fixtures are signed bytes and
//! nothing here reaches the network.

use std::path::PathBuf;

use encypher_c2pa::{
    StreamEncapsulation, StreamMethod, TelemetryOptions, VerificationReport, VerifyOptions,
};

/// The registered C2PA 2.4 code for a segment that carries no valid signed
/// segment information.
const LIVEVIDEO_SEGMENT_INVALID: &str = "livevideo.segment.invalid";
const ASSERTION_BMFF_HASH_MATCH: &str = "assertion.bmffHash.match";
const ASSERTION_BMFF_HASH_MISMATCH: &str = "assertion.bmffHash.mismatch";

/// Every spec-2.4 encapsulation x method combination in the corpus.
const COMBINATIONS: [(&str, StreamEncapsulation, StreamMethod); 4] = [
    (
        "fmp4-verifiable-segment-info",
        StreamEncapsulation::Fmp4,
        StreamMethod::VerifiableSegmentInfo,
    ),
    (
        "cmaf-verifiable-segment-info",
        StreamEncapsulation::Cmaf,
        StreamMethod::VerifiableSegmentInfo,
    ),
    (
        "fmp4-per-segment",
        StreamEncapsulation::Fmp4,
        StreamMethod::PerSegment,
    ),
    (
        "cmaf-per-segment",
        StreamEncapsulation::Cmaf,
        StreamMethod::PerSegment,
    ),
];

struct Stream {
    init: Vec<u8>,
    segments: Vec<Vec<u8>>,
}

impl Stream {
    fn load(name: &str) -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/live-video")
            .join(name);
        let read = |file: String| {
            std::fs::read(base.join(&file)).unwrap_or_else(|e| panic!("{name}/{file}: {e}"))
        };
        Stream {
            init: read("init.mp4".to_string()),
            segments: (0..3).map(|i| read(format!("seg-{i}.m4s"))).collect(),
        }
    }

    /// Flip the last byte of `seg-1.m4s`: a single-bit media edit, the cheapest
    /// realistic splice.
    fn tamper_second_segment(mut self) -> Self {
        let segment = &mut self.segments[1];
        let last = segment.len() - 1;
        segment[last] ^= 0x01;
        self
    }

    fn refs(&self) -> Vec<&[u8]> {
        self.segments.iter().map(Vec::as_slice).collect()
    }
}

/// Telemetry is pinned off so no case can emit a request.
fn options() -> VerifyOptions {
    VerifyOptions {
        telemetry: TelemetryOptions {
            enabled: Some(false),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn options_with_seeks(expected_seek_positions: Vec<usize>) -> VerifyOptions {
    VerifyOptions {
        expected_seek_positions,
        ..options()
    }
}

fn failure_codes(report: &VerificationReport) -> Vec<&str> {
    report
        .validation_results
        .failure
        .iter()
        .map(|status| status.code.as_str())
        .collect()
}

fn informational_codes(report: &VerificationReport) -> Vec<&str> {
    report
        .validation_results
        .informational
        .iter()
        .map(|status| status.code.as_str())
        .collect()
}

fn success_codes(report: &VerificationReport) -> Vec<&str> {
    report
        .validation_results
        .success
        .iter()
        .map(|status| status.code.as_str())
        .collect()
}

#[test]
fn clean_streams_verify_in_every_2_4_combination() {
    for (name, encapsulation, method) in COMBINATIONS {
        let stream = Stream::load(name);
        let report = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &stream.refs(),
            "video/mp4",
            encapsulation,
            method,
            &options(),
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));

        assert_eq!(report.integrity, "valid", "{name}: {report:?}");
        assert_eq!(report.encapsulation, encapsulation, "{name}");
        assert_eq!(report.method, method, "{name}");
        match method {
            StreamMethod::VerifiableSegmentInfo => {
                let stream_report = report.stream.as_ref().expect("stream report");
                assert_eq!(stream_report.hard_binding, "match", "{name}");
                assert!(
                    !failure_codes(stream_report).contains(&LIVEVIDEO_SEGMENT_INVALID),
                    "{name}: {:?}",
                    failure_codes(stream_report)
                );
            }
            StreamMethod::PerSegment => {
                assert_eq!(report.chain_valid, Some(true), "{name}");
                assert!(report.chain_failures.is_empty(), "{name}");
                // The init segment plus its three media segments.
                assert_eq!(report.segments.len(), 4, "{name}");
                for segment in &report.segments {
                    assert_eq!(segment.report.integrity, "valid", "{name}");
                }
            }
        }
    }
}

#[test]
fn a_tampered_media_segment_fails_every_2_4_combination() {
    for (name, encapsulation, method) in COMBINATIONS {
        let stream = Stream::load(name).tamper_second_segment();
        let report = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &stream.refs(),
            "video/mp4",
            encapsulation,
            method,
            &options(),
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));

        assert_eq!(report.integrity, "invalid", "{name}");
        match method {
            StreamMethod::VerifiableSegmentInfo => {
                // A session-key stream authenticates each segment through its
                // signed `emsg`, so a mutated segment is exactly
                // `livevideo.segment.invalid`.
                let stream_report = report.stream.as_ref().expect("stream report");
                assert!(
                    failure_codes(stream_report).contains(&LIVEVIDEO_SEGMENT_INVALID),
                    "{name}: {:?}",
                    failure_codes(stream_report)
                );
                assert_eq!(stream_report.validation_state, "Invalid", "{name}");
            }
            StreamMethod::PerSegment => {
                // Each segment carries its own manifest, so the mutated one
                // fails its own hard binding and the chain is reported broken.
                let mutated = &report.segments[2];
                assert_eq!(mutated.report.integrity, "invalid", "{name}");
                assert!(
                    failure_codes(&mutated.report).contains(&ASSERTION_BMFF_HASH_MISMATCH),
                    "{name}: {:?}",
                    failure_codes(&mutated.report)
                );
                assert_eq!(report.chain_valid, Some(false), "{name}");
                assert!(!report.chain_failures.is_empty(), "{name}");
            }
        }
    }
}

#[test]
fn fragments_no_binding_can_cover_never_verify() {
    // PRD 1.1.1. `verify_fragmented` binds fragments through a BMFF Merkle tree
    // and nothing else. Handing it a session-key stream or a per-segment stream
    // used to have the segments silently ignored, leaving a report that said
    // `integrity: valid` and `hard_binding: match` over bytes nothing checked.
    for (name, _, _) in COMBINATIONS {
        let stream = Stream::load(name).tamper_second_segment();
        let report = encypher_c2pa::verify_fragmented_with_options(
            &stream.init,
            &stream.refs(),
            "video/mp4",
            &options(),
        )
        .unwrap_or_else(|error| panic!("{name}: {error}"));

        assert_eq!(report.integrity, "invalid", "{name}");
        assert_ne!(report.hard_binding, "match", "{name}");
        assert!(
            failure_codes(&report).contains(&LIVEVIDEO_SEGMENT_INVALID),
            "{name}: {:?}",
            failure_codes(&report)
        );
    }
}

#[test]
fn a_merkle_stream_still_verifies_and_still_catches_tampering() {
    // The Merkle lane must keep working: the fail-closed gate above is about
    // manifests that bind no fragments, not about the binding that does.
    let clean = Stream::load("fmp4-merkle-2.2");
    let report = encypher_c2pa::verify_fragmented_with_options(
        &clean.init,
        &clean.refs(),
        "video/mp4",
        &options(),
    )
    .expect("merkle stream verifies");
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.hard_binding, "match");
    assert!(!failure_codes(&report).contains(&LIVEVIDEO_SEGMENT_INVALID));

    let tampered = Stream::load("fmp4-merkle-2.2").tamper_second_segment();
    let report = encypher_c2pa::verify_fragmented_with_options(
        &tampered.init,
        &tampered.refs(),
        "video/mp4",
        &options(),
    )
    .expect("tampered merkle stream reports");
    assert_eq!(report.integrity, "invalid");
    assert!(
        failure_codes(&report).contains(&ASSERTION_BMFF_HASH_MISMATCH),
        "{:?}",
        failure_codes(&report)
    );
}

#[test]
fn an_expected_seek_allows_a_verified_sequence_discontinuity() {
    for (name, encapsulation, method) in [
        (
            "fmp4-verifiable-segment-info",
            StreamEncapsulation::Fmp4,
            StreamMethod::VerifiableSegmentInfo,
        ),
        (
            "fmp4-per-segment",
            StreamEncapsulation::Fmp4,
            StreamMethod::PerSegment,
        ),
        (
            "fmp4-merkle-2.2",
            StreamEncapsulation::Fmp4,
            StreamMethod::VerifiableSegmentInfo,
        ),
    ] {
        let stream = Stream::load(name);
        let discontinuous = vec![stream.segments[0].as_slice(), stream.segments[2].as_slice()];

        let unexpected = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &discontinuous,
            "video/mp4",
            encapsulation,
            method,
            &options(),
        )
        .unwrap_or_else(|error| panic!("{name} unexpected discontinuity: {error}"));
        assert_eq!(
            unexpected.integrity, "invalid",
            "{name}: an unsignalled gap must be visible"
        );

        let expected = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &discontinuous,
            "video/mp4",
            encapsulation,
            method,
            &options_with_seeks(vec![1]),
        )
        .unwrap_or_else(|error| panic!("{name} expected seek: {error}"));
        assert_eq!(
            expected.integrity, "valid",
            "{name}: an explicitly signalled seek must not invalidate authenticated portions"
        );

        let mut tampered_after_seek = stream.segments[2].clone();
        let last = tampered_after_seek.len() - 1;
        tampered_after_seek[last] ^= 0x01;
        let tampered_discontinuous = vec![
            stream.segments[0].as_slice(),
            tampered_after_seek.as_slice(),
        ];
        let tampered = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &tampered_discontinuous,
            "video/mp4",
            encapsulation,
            method,
            &options_with_seeks(vec![1]),
        )
        .unwrap_or_else(|error| panic!("{name} tampered after expected seek: {error}"));
        assert_eq!(
            tampered.integrity, "invalid",
            "{name}: a seek signal must never bypass portion authentication"
        );

        let backwards = vec![stream.segments[2].as_slice(), stream.segments[0].as_slice()];
        let unexpected_backwards = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &backwards,
            "video/mp4",
            encapsulation,
            method,
            &options(),
        )
        .unwrap_or_else(|error| panic!("{name} unexpected backwards discontinuity: {error}"));
        assert_eq!(
            unexpected_backwards.integrity, "invalid",
            "{name}: an unsignalled backwards seek must be visible"
        );
        let expected_backwards = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &backwards,
            "video/mp4",
            encapsulation,
            method,
            &options_with_seeks(vec![0, 1]),
        )
        .unwrap_or_else(|error| panic!("{name} expected backwards seek: {error}"));
        assert_eq!(
            expected_backwards.integrity, "valid",
            "{name}: expected seek signals must cover backwards playback too"
        );
    }
}

#[test]
fn expected_seek_positions_must_name_unique_presented_segments() {
    let stream = Stream::load("fmp4-verifiable-segment-info");
    for invalid in [&[2][..], &[1, 1][..], &[1, 0][..]] {
        let error = encypher_c2pa::verify_stream_with_options(
            &stream.init,
            &stream.refs()[..2],
            "video/mp4",
            StreamEncapsulation::Fmp4,
            StreamMethod::VerifiableSegmentInfo,
            &options_with_seeks(invalid.to_vec()),
        )
        .expect_err("invalid expected-seek positions must fail closed");
        assert!(
            error.to_string().contains("expected seek position"),
            "{invalid:?}: {error}"
        );
    }
}

#[test]
fn fragmented_merkle_subsets_enforce_sequence_unless_a_seek_is_expected() {
    let stream = Stream::load("fmp4-merkle-2.2");
    let leading = vec![stream.segments[0].as_slice(), stream.segments[1].as_slice()];
    let report = encypher_c2pa::verify_fragmented_with_options(
        &stream.init,
        &leading,
        "video/mp4",
        &options(),
    )
    .expect("a leading contiguous run with unavailable trailing fragments verifies");
    assert_eq!(report.integrity, "valid");
    assert!(!failure_codes(&report).contains(&ASSERTION_BMFF_HASH_MISMATCH));

    let gap = vec![stream.segments[0].as_slice(), stream.segments[2].as_slice()];
    let report =
        encypher_c2pa::verify_fragmented_with_options(&stream.init, &gap, "video/mp4", &options())
            .expect("an unexpected gap is reported");
    assert_eq!(report.integrity, "invalid");
    assert!(failure_codes(&report).contains(&ASSERTION_BMFF_HASH_MISMATCH));

    let report = encypher_c2pa::verify_fragmented_with_options(
        &stream.init,
        &gap,
        "video/mp4",
        &options_with_seeks(vec![1]),
    )
    .expect("an expected gap verifies");
    assert_eq!(report.integrity, "valid");
    assert!(!failure_codes(&report).contains(&ASSERTION_BMFF_HASH_MISMATCH));

    let reordered = vec![stream.segments[1].as_slice(), stream.segments[0].as_slice()];
    let report = encypher_c2pa::verify_fragmented_with_options(
        &stream.init,
        &reordered,
        "video/mp4",
        &options(),
    )
    .expect("reordered fragments are reported");
    assert_eq!(report.integrity, "invalid");
    assert!(failure_codes(&report).contains(&ASSERTION_BMFF_HASH_MISMATCH));
}

#[test]
fn an_unevaluated_merkle_fragment_tree_is_never_reported_as_matched() {
    // PRD 5.9. With no fragments supplied there is nothing to say about the
    // fragment trees, and the report must not say it with the success code.
    let stream = Stream::load("fmp4-merkle-2.2");
    let report = encypher_c2pa::verify_with_options(&stream.init, "video/mp4", &options())
        .expect("init segment verifies alone");

    assert!(
        informational_codes(&report).contains(&"com.encypher.bmffHash.fragmentsNotEvaluated"),
        "{:?}",
        informational_codes(&report)
    );
    assert!(
        !informational_codes(&report).contains(&ASSERTION_BMFF_HASH_MATCH),
        "an unevaluated fragment tree must never carry the success code: {:?}",
        informational_codes(&report)
    );
    // The init segment's own hash WAS evaluated, so that success stays.
    assert!(success_codes(&report).contains(&ASSERTION_BMFF_HASH_MATCH));
}

#[test]
fn a_stream_presented_under_the_wrong_encapsulation_is_refused() {
    // The brand gate is a Conformance Program 0.2 requirement: an fMP4 stream
    // declared as CMAF must not verify under a declaration its bytes do not
    // support.
    let stream = Stream::load("fmp4-verifiable-segment-info");
    let error = encypher_c2pa::verify_stream_with_options(
        &stream.init,
        &stream.refs(),
        "video/mp4",
        StreamEncapsulation::Cmaf,
        StreamMethod::VerifiableSegmentInfo,
        &options(),
    )
    .expect_err("fMP4 bytes must not verify as CMAF");
    assert!(
        error.to_string().contains("CMAF"),
        "{error}: expected the brand gate to name the declared encapsulation"
    );
}

#[test]
fn stream_tokens_round_trip_the_conformance_program_spelling() {
    assert_eq!(StreamEncapsulation::Fmp4.token(), "fMP4");
    assert_eq!(StreamEncapsulation::Cmaf.token(), "CMAF");
    assert_eq!(
        StreamMethod::VerifiableSegmentInfo.token(),
        "verifiable-segment-info"
    );
    assert_eq!(StreamMethod::PerSegment.token(), "per-segment");

    for value in [StreamEncapsulation::Fmp4, StreamEncapsulation::Cmaf] {
        assert_eq!(StreamEncapsulation::from_token(value.token()), Some(value));
        assert_eq!(
            StreamEncapsulation::from_token(&value.token().to_ascii_lowercase()),
            Some(value)
        );
    }
    for value in [
        StreamMethod::VerifiableSegmentInfo,
        StreamMethod::PerSegment,
    ] {
        assert_eq!(StreamMethod::from_token(value.token()), Some(value));
        assert_eq!(
            StreamMethod::from_token(&value.token().to_ascii_uppercase()),
            Some(value)
        );
    }
    assert_eq!(StreamEncapsulation::from_token("mpeg-ts"), None);
    assert_eq!(StreamMethod::from_token("whole-stream"), None);
}
