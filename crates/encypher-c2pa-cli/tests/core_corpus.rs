//! Offline core-C2PA contract over pinned third-party media.
//!
//! The assets come from a fixed `contentauth/c2pa-rs` commit, but verification
//! is performed only by this repository's `encypher-c2pa` binary. Expected
//! outcomes come from C2PA 2.4 status-code semantics, not from another
//! implementation's runtime output.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/core")
}

fn index() -> Value {
    let path = corpus_dir().join("corpus.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn vectors(index: &Value) -> &Vec<Value> {
    index["vectors"].as_array().expect("vectors array")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn code_set(value: &Value, field: &str) -> BTreeSet<String> {
    value[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} array"))
        .iter()
        .map(|code| code.as_str().expect("status code").to_owned())
        .collect()
}

fn bucket_codes(report: &Value, bucket: &str) -> BTreeSet<String> {
    report["validation_results"]["activeManifest"][bucket]
        .as_array()
        .expect("validation result bucket")
        .iter()
        .map(|item| item["code"].as_str().expect("status code").to_owned())
        .collect()
}

fn verify(vector: &Value) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(corpus_dir().join(vector["path"].as_str().expect("path")))
        .arg("--mime")
        .arg(vector["mime_type"].as_str().expect("mime_type"))
        .arg("--time")
        .arg(
            vector["fixed_validation_time"]
                .as_str()
                .expect("fixed_validation_time"),
        )
        .arg("--json")
        .output()
        .expect("run Encypher CLI");
    let code = output.status.code().expect("CLI exit code");
    assert!(
        matches!(code, 0 | 2),
        "{}: CLI exited {code}: {}",
        vector["id"],
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("CLI JSON envelope");
    (code, envelope["manifest_report"].clone())
}

#[test]
fn corpus_is_pinned_licensed_and_offline() {
    let index = index();
    assert_eq!(index["network_policy"], "offline");
    assert_eq!(index["spec_version"], "2.4");

    for source in index["sources"].as_array().expect("sources array") {
        assert_eq!(
            source["commit"].as_str().expect("source commit").len(),
            40,
            "source commit must be immutable"
        );
        for license in source["license_files"]
            .as_array()
            .expect("license_files array")
        {
            let path = corpus_dir().join(license.as_str().expect("license path"));
            assert!(path.is_file(), "missing source license {}", path.display());
        }
    }

    for vector in vectors(&index) {
        let path = corpus_dir().join(vector["path"].as_str().expect("path"));
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            bytes.len() as u64,
            vector["size"].as_u64().expect("size"),
            "{}: size drift",
            vector["id"]
        );
        assert_eq!(
            sha256_hex(&bytes),
            vector["sha256"].as_str().expect("sha256"),
            "{}: content drift",
            vector["id"]
        );
        assert_eq!(
            vector["source"]["commit"], index["sources"][0]["commit"],
            "{}: source commit drift",
            vector["id"]
        );
    }
}

#[test]
fn third_party_core_vectors_match_c2pa_2_4_expectations() {
    let index = index();
    for vector in vectors(&index) {
        let expected = &vector["normative_expected"];
        let (exit_code, report) = verify(vector);
        assert_eq!(
            exit_code,
            expected["exit_code"].as_i64().expect("exit_code") as i32,
            "{}: exit code",
            vector["id"]
        );
        assert_eq!(
            report["validation_state"], expected["validation_state"],
            "{}: validation state",
            vector["id"]
        );
        assert_eq!(
            report["manifests"].as_object().expect("manifests").len(),
            expected["manifest_count"].as_u64().expect("manifest_count") as usize,
            "{}: manifest count",
            vector["id"]
        );

        let success = bucket_codes(&report, "success");
        let failures = bucket_codes(&report, "failure");
        let required_success = code_set(expected, "required_success_codes");
        assert!(
            required_success.is_subset(&success),
            "{}: missing required success: expected {required_success:?}, observed {success:?}",
            vector["id"]
        );
        for forbidden in code_set(expected, "forbidden_success_codes") {
            assert!(
                !success.contains(&forbidden),
                "{}: forbidden success {forbidden}",
                vector["id"]
            );
        }
        assert_eq!(
            failures,
            code_set(expected, "failure_codes"),
            "{}: failure codes",
            vector["id"]
        );
    }
}
