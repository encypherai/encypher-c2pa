// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! `verify --fragment --encapsulation --segment-mode` end to end.
//!
//! The exit code is the contract a CI pipeline gates on, so each case asserts
//! it alongside the reported verdict.

use std::path::{Path, PathBuf};
use std::process::Command;

fn stream_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../encypher-c2pa/tests/fixtures/live-video")
        .join(name)
}

const SESSION_KEY_STREAM: &str = "fmp4-verifiable-segment-info";

/// The trusted instant recorded when the fixture set was generated and
/// verified (`segments.json` `validation_time`). It follows the session key's
/// creation and falls inside its 24-hour window, so runs are pinned to it
/// instead of the wall clock and survive fixture regeneration.
fn fixture_validation_time(name: &str) -> String {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(stream_dir(name).join("segments.json")).expect("segments.json"),
    )
    .expect("segments.json is JSON");
    index["validation_time"]
        .as_str()
        .unwrap_or_else(|| panic!("{name}/segments.json records no validation_time"))
        .to_string()
}

/// `instant` (RFC 3339) moved by whole days, keeping its time of day and
/// offset. Two days clears the 24-hour session window in either direction.
fn shift_days(instant: &str, days: i64) -> String {
    let instant =
        time::OffsetDateTime::parse(instant, &time::format_description::well_known::Rfc3339)
            .expect("fixture RFC 3339 time");
    (instant + time::Duration::days(days))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("shifted fixture time")
}

/// Run `verify` over one fixture stream at its recorded validation time,
/// optionally corrupting `seg-1.m4s` first. Returns (exit code, stdout).
fn verify_stream(name: &str, encapsulation: &str, method: &str, tamper: bool) -> (i32, String) {
    let time = fixture_validation_time(name);
    let (code, stdout, _) = run_stream(name, encapsulation, method, tamper, &["--time", &time]);
    (code, stdout)
}

/// [`verify_stream`] with extra CLI arguments. Returns (exit code, stdout,
/// stderr).
fn run_stream(
    name: &str,
    encapsulation: &str,
    method: &str,
    tamper: bool,
    extra: &[&str],
) -> (i32, String, String) {
    // Tests run in parallel threads of one process, so the pid alone cannot
    // keep two runs of the same fixture from sharing a work directory.
    static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let source = stream_dir(name);
    let work = std::env::temp_dir().join(format!(
        "encypher-stream-{name}-{method}-{}-{}-{run}",
        tamper,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).expect("work dir");
    let mut segments = Vec::new();
    for file in ["init.mp4", "seg-0.m4s", "seg-1.m4s", "seg-2.m4s"] {
        let mut bytes = std::fs::read(source.join(file)).expect("fixture");
        if tamper && file == "seg-1.m4s" {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        std::fs::write(work.join(file), &bytes).expect("stage fixture");
        if file != "init.mp4" {
            segments.push(work.join(file));
        }
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"));
    command
        .arg("verify")
        .arg(work.join("init.mp4"))
        .arg("--mime")
        .arg("video/mp4")
        .arg("--no-telemetry")
        .arg("--encapsulation")
        .arg(encapsulation)
        .arg("--segment-mode")
        .arg(method);
    for segment in &segments {
        command.arg("--fragment").arg(segment);
    }
    command.args(extra);
    let output = command.output().expect("run CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    let _ = std::fs::remove_dir_all(&work);
    (output.status.code().unwrap_or(-1), stdout, stderr)
}

/// Session-key run assessed at `time`, with one `--stream-presentation-time`
/// per entry of `presentation_times`.
fn run_session_key_stream(time: &str, presentation_times: &[&str]) -> (i32, String, String) {
    let mut args = vec!["--time", time];
    for &presentation_time in presentation_times {
        args.extend(["--stream-presentation-time", presentation_time]);
    }
    run_stream(
        SESSION_KEY_STREAM,
        "fmp4",
        "verifiable-segment-info",
        false,
        &args,
    )
}

#[test]
fn a_clean_stream_verifies_and_exits_success() {
    for (name, encapsulation, method) in [
        (
            "fmp4-verifiable-segment-info",
            "fmp4",
            "verifiable-segment-info",
        ),
        ("cmaf-per-segment", "cmaf", "per-segment"),
    ] {
        let (code, stdout) = verify_stream(name, encapsulation, method, false);
        assert_eq!(code, 0, "{name}:\n{stdout}");
        assert!(stdout.contains("integrity: valid"), "{name}:\n{stdout}");
    }
}

#[test]
fn a_tampered_segment_exits_two_and_names_the_live_video_code() {
    let (code, stdout) = verify_stream(
        "fmp4-verifiable-segment-info",
        "fmp4",
        "verifiable-segment-info",
        true,
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.contains("integrity: invalid"), "{stdout}");
    assert!(stdout.contains("livevideo.segment.invalid"), "{stdout}");
}

#[test]
fn a_tampered_per_segment_stream_exits_two_and_breaks_the_chain() {
    let (code, stdout) = verify_stream("cmaf-per-segment", "cmaf", "per-segment", true);
    assert_eq!(code, 2, "{stdout}");
    assert!(stdout.contains("integrity: invalid"), "{stdout}");
    assert!(stdout.contains("chain: broken"), "{stdout}");
}

#[test]
fn an_unknown_encapsulation_is_rejected_before_any_bytes_are_read() {
    let source = stream_dir("fmp4-verifiable-segment-info");
    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(source.join("init.mp4"))
        .arg("--mime")
        .arg("video/mp4")
        .arg("--no-telemetry")
        .arg("--encapsulation")
        .arg("mpeg-ts")
        .arg("--fragment")
        .arg(source.join("seg-0.m4s"))
        .output()
        .expect("run CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("unknown --encapsulation"), "{stderr}");
}

#[test]
fn an_archive_check_after_key_expiry_needs_trusted_presentation_times() {
    let in_window = fixture_validation_time(SESSION_KEY_STREAM);
    let after_expiry = shift_days(&in_window, 2);
    let (code, stdout, stderr) = run_session_key_stream(&after_expiry, &[]);
    assert_eq!(code, 2, "{stdout}{stderr}");
    assert!(stdout.contains("livevideo.segment.invalid"), "{stdout}");

    let (code, stdout, stderr) =
        run_session_key_stream(&after_expiry, &[&in_window, &in_window, &in_window]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert!(stdout.contains("integrity: valid"), "{stdout}");
}

#[test]
fn each_presentation_time_judges_only_its_own_segment() {
    let in_window = fixture_validation_time(SESSION_KEY_STREAM);
    for outside in [shift_days(&in_window, 2), shift_days(&in_window, -2)] {
        let (code, stdout, stderr) =
            run_session_key_stream(&in_window, &[&in_window, &in_window, &outside]);
        assert_eq!(code, 2, "{outside}: {stdout}{stderr}");
        assert!(stdout.contains("livevideo.segment.invalid"), "{stdout}");
    }
}

#[test]
fn miscounted_or_malformed_presentation_times_are_refused() {
    let t = fixture_validation_time(SESSION_KEY_STREAM);
    let t = t.as_str();
    for times in [&[t, t][..], &[t, t, t, t][..], &[t, "yesterday", t][..]] {
        let (code, stdout, stderr) = run_session_key_stream(t, times);
        assert_eq!(code, 1, "{times:?}: {stdout}{stderr}");
        assert!(
            stderr.contains("invalid_validation_time")
                && stderr.contains("stream_presentation_times"),
            "{times:?}: {stderr}"
        );
    }
}
