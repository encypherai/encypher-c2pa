// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! `--spec` selects the C2PA validation policy.
//!
//! The default and `--spec 2.4` must stay byte-identical, `--spec 2.5` must
//! reach the kernel and the report, and an unknown or unsupported selection
//! must fail with `unsupported_spec_version` before the asset is opened.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const VALIDATION_TIME: &str = "2026-01-01T00:00:00Z";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn verify(asset: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(asset)
        .args(["--json", "--offline", "--time", VALIDATION_TIME])
        .args(extra)
        .output()
        .expect("run CLI")
}

fn report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON report on stdout")
}

#[test]
fn default_and_explicit_2_4_are_byte_identical() {
    let asset = fixture("signed_test.jpg");
    let default = verify(&asset, &[]);
    let explicit = verify(&asset, &["--spec", "2.4"]);
    assert_eq!(default.status.code(), explicit.status.code());
    assert_eq!(
        default.stdout, explicit.stdout,
        "--spec 2.4 must not change a single report byte"
    );
    let value = report(&default);
    assert_eq!(value["profile"], "c2pa-2.4");
    assert_eq!(value["manifest_report"]["engine_profile"]["spec_version"], "2.4");
}

#[test]
fn spec_2_5_reaches_the_report() {
    let output = verify(&fixture("signed_test.jpg"), &["--spec", "2.5"]);
    let value = report(&output);
    assert_eq!(value["profile"], "c2pa-2.5");
    assert_eq!(value["manifest_report"]["engine_profile"]["spec_version"], "2.5");
    assert_eq!(
        value["manifest_report"]["engine_profile"]["compliance_level"],
        "core-spec"
    );
}

#[test]
fn unknown_or_unsupported_selection_fails_before_asset_io() {
    let missing = fixture("does-not-exist.jpg");
    for extra in [
        &["--spec", "2.6"][..],
        &["--spec", "2.4.0"][..],
        &["--spec", "2.5", "--strict-conformance"][..],
    ] {
        let output = verify(&missing, extra);
        assert!(!output.status.success(), "{extra:?} must fail");
        let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
        assert!(
            stderr.starts_with("unsupported_spec_version:"),
            "{extra:?} must fail on the selector before reading the missing asset, got: {stderr}"
        );
    }
}
