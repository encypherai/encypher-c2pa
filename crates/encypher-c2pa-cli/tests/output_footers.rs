//! Sales-funnel edge instrumentation lives on the CLI's human output only.
//!
//! These tests pin two contracts: `explain` of a known code prints the
//! docs-link footer, and `--json` verify output never carries the docs URL so
//! machine consumers stay byte-stable.

use std::path::{Path, PathBuf};
use std::process::Command;

fn signed_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed_test.mp4")
}

#[test]
fn explain_known_code_emits_details_url() {
    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("explain")
        .arg("signingCredential.untrusted")
        .output()
        .expect("run CLI");
    assert!(output.status.success(), "explain should exit success");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let last = stdout.lines().last().expect("at least one line");
    assert_eq!(
        last,
        "details: https://encypher.com/c2pa/codes/signingCredential.untrusted"
    );
}

#[test]
fn json_verify_output_has_no_docs_url() {
    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(signed_fixture())
        .arg("--json")
        .output()
        .expect("run CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(
        !stdout.contains("encypher.com/c2pa/codes"),
        "JSON verify output must stay free of the docs URL, got:\n{stdout}"
    );
}
