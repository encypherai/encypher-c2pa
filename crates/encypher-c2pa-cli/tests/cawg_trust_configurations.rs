// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cawg/generated/identity-1.2")
}

fn scratch(test: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "encypher-cawg-trust-config-{test}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("scratch directory");
    directory
}

fn write_configuration(path: &Path, profile: &str, certificate_pem: &str) {
    std::fs::write(
        path,
        serde_json::to_vec(&json!([{
            "profile": profile,
            "certificates_pem": certificate_pem,
        }]))
        .expect("configuration JSON"),
    )
    .expect("configuration file");
}

fn run(asset: &Path, first: &Path, second: &Path, stream: bool) -> Output {
    let corpus = corpus_dir();
    let mut command = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"));
    command
        .arg("verify")
        .arg(asset)
        .arg("--mime")
        .arg(if stream { "video/mp4" } else { "image/jpeg" })
        .arg("--no-default-trust")
        .arg("--allowed")
        .arg(corpus.join("trust/claim-allowed.pem"))
        .arg("--cawg-trust-configurations")
        .arg(first)
        .arg("--cawg-trust-configurations")
        .arg(second)
        .arg("--time")
        .arg("2026-08-06T00:00:00Z")
        .arg("--offline")
        .arg("--no-telemetry")
        .arg("--json");
    if stream {
        command
            .arg("--fragment")
            .arg(asset.with_file_name("missing.m4s"))
            .arg("--encapsulation")
            .arg("fmp4");
    }
    command.output().expect("run CLI")
}

#[test]
fn the_second_configuration_file_contributes_its_entry() {
    let corpus = corpus_dir();
    let work = scratch("second-entry");
    let first = work.join("first.json");
    let second = work.join("second.json");
    write_configuration(
        &first,
        "base",
        &std::fs::read_to_string(corpus.join("certs/ps256.cert.pem")).expect("first cert"),
    );
    write_configuration(
        &second,
        "base",
        &std::fs::read_to_string(corpus.join("certs/es256.cert.pem")).expect("second cert"),
    );

    let output = run(
        &corpus.join("assets/x509-es256-jpeg.jpg"),
        &first,
        &second,
        false,
    );
    assert!(
        matches!(output.status.code(), Some(0) | Some(2)),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    let success = report["manifest_report"]["validation_results"]["activeManifest"]["success"]
        .as_array()
        .expect("success statuses");
    let trusted = success
        .iter()
        .find(|status| status["code"] == "cawg.identity.trusted")
        .expect("second file's identity certificate must be trusted");
    assert_eq!(trusted["details"]["trust_source"], "allowed_list");
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn malformed_second_file_names_its_concatenated_index_before_asset_io() {
    let corpus = corpus_dir();
    let work = scratch("malformed-second");
    let first = work.join("first.json");
    let second = work.join("second.json");
    write_configuration(
        &first,
        "base",
        &std::fs::read_to_string(corpus.join("certs/ps256.cert.pem")).expect("first cert"),
    );
    write_configuration(&second, "smime_interim", "");

    for stream in [false, true] {
        let missing = work.join(if stream { "missing.mp4" } else { "missing.jpg" });
        let output = run(&missing, &first, &second, stream);
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
        assert!(stderr.contains("invalid_trust_material"), "{stderr}");
        assert!(
            stderr.contains("cawg_trust_configurations[1].certificates_pem"),
            "{stderr}"
        );
        assert!(!stderr.contains("No such file"), "{stderr}");
    }
    let _ = std::fs::remove_dir_all(work);
}
