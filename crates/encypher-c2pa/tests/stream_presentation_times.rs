// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! `VerifyOptions::stream_presentation_times`: trusted per-segment assessment
//! instants for C2PA 2.4 session-key streams.
//!
//! Every instant is derived from the fixture set's own `segments.json`
//! `validation_time`: the trusted clock reading recorded after the set was
//! signed and verified, so it follows the session key's creation and falls
//! inside its 24-hour validity window. Two days either side of it is outside
//! that window and inside every fixture certificate's validity. Nothing here
//! reads the wall clock, and a regenerated fixture set carries its own anchor.

use std::path::PathBuf;

use encypher_c2pa::{
    Error, StreamEncapsulation, StreamMethod, StreamVerificationReport, TelemetryOptions,
    VerifyOptions,
};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const LIVEVIDEO_SEGMENT_INVALID: &str = "livevideo.segment.invalid";
const SESSION_KEY_STREAM: &str = "fmp4-verifiable-segment-info";

const SESSION_KEY_STREAMS: [(&str, StreamEncapsulation); 2] = [
    (SESSION_KEY_STREAM, StreamEncapsulation::Fmp4),
    ("cmaf-verifiable-segment-info", StreamEncapsulation::Cmaf),
];

fn fixture_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/live-video")
        .join(name)
}

/// RFC 3339 instants relative to one fixture set's recorded validation time.
struct Clock(OffsetDateTime);

impl Clock {
    fn of(name: &str) -> Self {
        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(fixture_dir(name).join("segments.json")).expect("segments.json"),
        )
        .expect("segments.json is JSON");
        let recorded = index["validation_time"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}/segments.json records no validation_time"));
        Self(OffsetDateTime::parse(recorded, &Rfc3339).expect("RFC 3339 validation_time"))
    }

    fn at(&self, offset: Duration) -> String {
        (self.0 + offset).format(&Rfc3339).expect("RFC 3339")
    }

    /// Inside the session window, `seconds` after the recorded time.
    fn in_window(&self, seconds: i64) -> String {
        self.at(Duration::seconds(seconds))
    }

    fn after_expiry(&self) -> String {
        self.at(Duration::days(2))
    }

    fn before_creation(&self) -> String {
        self.at(Duration::days(-2))
    }
}

struct Stream {
    init: Vec<u8>,
    segments: Vec<Vec<u8>>,
}

impl Stream {
    fn load(name: &str) -> Self {
        let base = fixture_dir(name);
        let read = |file: String| {
            std::fs::read(base.join(&file)).unwrap_or_else(|e| panic!("{name}/{file}: {e}"))
        };
        Stream {
            init: read("init.mp4".to_string()),
            segments: (0..3).map(|i| read(format!("seg-{i}.m4s"))).collect(),
        }
    }

    fn refs(&self) -> Vec<&[u8]> {
        self.segments.iter().map(Vec::as_slice).collect()
    }

    fn verify(
        &self,
        encapsulation: StreamEncapsulation,
        method: StreamMethod,
        options: &VerifyOptions,
    ) -> Result<StreamVerificationReport, Error> {
        encypher_c2pa::verify_stream_with_options(
            &self.init,
            &self.refs(),
            "video/mp4",
            encapsulation,
            method,
            options,
        )
    }
}

/// Telemetry pinned off; validation and presentation instants as given.
fn options(validation_time: &str, presentation_times: Option<&[String]>) -> VerifyOptions {
    VerifyOptions {
        validation_time: Some(validation_time.to_string()),
        stream_presentation_times: presentation_times.map(<[String]>::to_vec),
        telemetry: TelemetryOptions {
            enabled: Some(false),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// URLs of the `livevideo.segment.invalid` failures in a session-key report.
fn invalid_segment_urls(report: &StreamVerificationReport) -> Vec<&str> {
    report
        .stream
        .as_ref()
        .expect("session-key stream report")
        .validation_results
        .failure
        .iter()
        .filter(|status| status.code == LIVEVIDEO_SEGMENT_INVALID)
        .map(|status| status.url.as_str())
        .collect()
}

#[test]
fn omitted_presentation_times_assess_every_segment_at_validation_time() {
    for (name, encapsulation) in SESSION_KEY_STREAMS {
        let clock = Clock::of(name);
        let stream = Stream::load(name);
        let current = stream
            .verify(
                encapsulation,
                StreamMethod::VerifiableSegmentInfo,
                &options(&clock.in_window(0), None),
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(current.integrity, "valid", "{name}: {current:?}");

        let expired = stream
            .verify(
                encapsulation,
                StreamMethod::VerifiableSegmentInfo,
                &options(&clock.after_expiry(), None),
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(expired.integrity, "invalid", "{name}: {expired:?}");
        assert!(
            !invalid_segment_urls(&expired).is_empty(),
            "{name}: segments assessed after key expiry must fail: {expired:?}"
        );
    }
}

#[test]
fn trusted_presentation_times_verify_an_archive_after_key_expiry() {
    for (name, encapsulation) in SESSION_KEY_STREAMS {
        let clock = Clock::of(name);
        // Distinct, increasing instants inside the key window, assessed after
        // it closed. Continuity is still checked across all three, so a valid
        // verdict also proves the per-segment times did not break it.
        let times = [clock.in_window(0), clock.in_window(1), clock.in_window(2)];
        let after_expiry = clock.after_expiry();
        let report = Stream::load(name)
            .verify(
                encapsulation,
                StreamMethod::VerifiableSegmentInfo,
                &options(&after_expiry, Some(&times)),
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(report.integrity, "valid", "{name}: {report:?}");
        assert!(invalid_segment_urls(&report).is_empty(), "{name}");
        // Certificate trust is still judged at the common validation time:
        // per-segment instants never move that clock.
        let stream_report = report.stream.as_ref().expect("stream report");
        assert_eq!(stream_report.trust.validation_time, after_expiry, "{name}");
    }
}

#[test]
fn each_presentation_time_judges_only_its_own_segment() {
    let clock = Clock::of(SESSION_KEY_STREAM);
    let stream = Stream::load(SESSION_KEY_STREAM);
    let inside = clock.in_window(0);
    for outside in [clock.after_expiry(), clock.before_creation()] {
        for position in 0..3 {
            let mut times = [inside.clone(), inside.clone(), inside.clone()];
            times[position] = outside.clone();
            let report = stream
                .verify(
                    StreamEncapsulation::Fmp4,
                    StreamMethod::VerifiableSegmentInfo,
                    &options(&inside, Some(&times)),
                )
                .expect("verifies");
            assert_eq!(report.integrity, "invalid", "{times:?}: {report:?}");
            let expected = format!("self#segment={}", position + 1);
            let urls = invalid_segment_urls(&report);
            assert!(
                urls.contains(&expected.as_str()),
                "{times:?}: the out-of-window segment must fail: {urls:?}"
            );
            for earlier in 1..=position {
                let earlier = format!("self#segment={earlier}");
                assert!(
                    !urls.contains(&earlier.as_str()),
                    "{times:?}: an in-window predecessor must not fail: {urls:?}"
                );
            }
        }
    }
}

#[test]
fn a_count_that_differs_from_the_segments_is_refused() {
    let t = Clock::of(SESSION_KEY_STREAM).in_window(0);
    let stream = Stream::load(SESSION_KEY_STREAM);
    for count in [0, 2, 4] {
        let times = vec![t.clone(); count];
        let error = stream
            .verify(
                StreamEncapsulation::Fmp4,
                StreamMethod::VerifiableSegmentInfo,
                &options(&t, Some(times.as_slice())),
            )
            .expect_err("a miscounted list must fail closed");
        assert!(
            matches!(error, Error::InvalidValidationTime(_)),
            "{count}: {error:?}"
        );
        assert_eq!(error.code(), "invalid_validation_time");
        let message = error.to_string();
        assert!(
            message.contains("stream_presentation_times")
                && message.contains(&format!("{count} entries for 3")),
            "{count}: {message}"
        );
    }
}

#[test]
fn a_malformed_presentation_time_is_refused_by_index() {
    let t = Clock::of(SESSION_KEY_STREAM).in_window(0);
    let malformed = options(&t, Some(&[t.clone(), "yesterday".into(), t.clone()]));
    let error = malformed
        .validate()
        .expect_err("validate must refuse a malformed instant before any asset is read");
    assert!(
        error.to_string().contains("stream_presentation_times[1]"),
        "{error}"
    );
    let retained_error = malformed
        .validate_with_external_data()
        .expect_err("external-data preflight must refuse the same malformed instant");
    assert_eq!(retained_error.code(), error.code());
    assert!(
        retained_error
            .to_string()
            .contains("stream_presentation_times[1]"),
        "{retained_error}"
    );

    let error = Stream::load(SESSION_KEY_STREAM)
        .verify(
            StreamEncapsulation::Fmp4,
            StreamMethod::VerifiableSegmentInfo,
            &malformed,
        )
        .expect_err("a malformed instant must fail closed");
    assert!(
        matches!(error, Error::InvalidValidationTime(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("stream_presentation_times[1]"),
        "{error}"
    );
}

#[test]
fn lanes_without_session_keys_refuse_presentation_times() {
    // The refusal precedes any window check, so any well-formed instant
    // serves; the legacy Merkle set records no generation time of its own.
    let t = Clock::of(SESSION_KEY_STREAM).in_window(0);
    let times = [t.clone(), t.clone(), t.clone()];
    for (name, encapsulation, method) in [
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
        (
            "fmp4-merkle-2.2",
            StreamEncapsulation::Fmp4,
            StreamMethod::VerifiableSegmentInfo,
        ),
    ] {
        let error = Stream::load(name)
            .verify(encapsulation, method, &options(&t, Some(&times)))
            .expect_err("presentation times must be refused, never ignored");
        assert!(
            error.to_string().contains("presentation times"),
            "{name}: {error}"
        );
    }

    let merkle = Stream::load("fmp4-merkle-2.2");
    let error = encypher_c2pa::verify_fragmented_with_options(
        &merkle.init,
        &merkle.refs(),
        "video/mp4",
        &options(&t, Some(&times)),
    )
    .expect_err("fragmented verification must refuse presentation times");
    assert!(
        matches!(error, Error::InvalidValidationTime(_)),
        "{error:?}"
    );
}

#[test]
fn graph_fragment_verification_refuses_present_times_but_keeps_absent_times_valid() {
    let t = Clock::of(SESSION_KEY_STREAM).in_window(0);
    let merkle = Stream::load("fmp4-merkle-2.2");
    let verify = |presentation_times: Option<&[String]>| {
        encypher_c2pa::verify_fragmented_with_graph_inputs(
            &merkle.init,
            &merkle.refs(),
            "video/mp4",
            &options(&t, presentation_times),
            encypher_c2pa::GraphInputs::default(),
        )
    };
    let absent = verify(None).expect("absent times retain Merkle verification");
    assert_eq!(absent.integrity, "valid", "{absent:?}");
    assert_eq!(absent.hard_binding, "match", "{absent:?}");

    for times in [
        Vec::new(),
        vec![t.clone(); merkle.segments.len()],
        vec![t.clone()],
        vec!["not-a-time".into()],
    ] {
        let error = verify(Some(&times))
            .expect_err("graph fragmented verification must refuse supplied presentation times");
        assert!(
            matches!(error, Error::InvalidValidationTime(_)),
            "{times:?}: {error:?}"
        );
        assert_eq!(error.code(), "invalid_validation_time");
        assert!(
            error.to_string().contains("stream_presentation_times"),
            "{times:?}: {error}"
        );
    }
}
