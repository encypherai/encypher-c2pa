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

/// Run `verify` over one fixture stream, optionally corrupting `seg-1.m4s`
/// first. Returns (exit code, stdout).
fn verify_stream(name: &str, encapsulation: &str, method: &str, tamper: bool) -> (i32, String) {
    let source = stream_dir(name);
    let work = std::env::temp_dir().join(format!(
        "encypher-stream-{name}-{method}-{}-{}",
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
    let output = command.output().expect("run CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let _ = std::fs::remove_dir_all(&work);
    (output.status.code().unwrap_or(-1), stdout)
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
