//! Offline interoperability gate for the pinned and generated CAWG corpus.
//!
//! Rust port of the engine's `test_cawg_interop_corpus.py` gate, driving this
//! repository's CLI binary and asserting the same status-code sets. Everything
//! runs offline from the frozen vectors under `tests/vectors/cawg/`. The
//! contributed vectors (redistribution pending) and the dual-engine Python
//! audit (needs the commercial engine) intentionally do not port.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cawg")
}

fn load(path: &Path) -> Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn external_index() -> Value {
    load(&corpus_dir().join("corpus.json"))
}

fn generated_index() -> Value {
    load(&corpus_dir().join("generated/identity-1.2/index.json"))
}

fn vectors(index: &Value) -> &Vec<Value> {
    index["vectors"].as_array().expect("vectors array")
}

fn vector_by_id<'a>(index: &'a Value, id: &str) -> &'a Value {
    vectors(index)
        .iter()
        .find(|vector| vector["id"] == id)
        .unwrap_or_else(|| panic!("vector {id} missing from index"))
}

/// How the vector's CAWG trust bundle is passed to the CLI.
#[derive(Clone, Copy, PartialEq)]
enum CawgTrustMode {
    /// `--cawg-allowed` (end-entity allow list; the default lane).
    Allowed,
    /// `--cawg-trust` (chain-to-anchor lane).
    Trust,
    /// No CAWG trust material at all.
    None,
}

/// Run the CLI on one corpus vector and return the READER report (the raw
/// engine report the commercial CLI prints; this CLI nests it under
/// `manifest_report` in its envelope).
fn verify(vector: &Value, mode: CawgTrustMode) -> Value {
    verify_at(
        vector,
        mode,
        vector["fixed_validation_time"].as_str().expect("time"),
    )
}

fn verify_at(vector: &Value, mode: CawgTrustMode, validation_time: &str) -> Value {
    let corpus = corpus_dir();
    let mut command = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"));
    command
        .arg("verify")
        .arg(corpus.join(vector["path"].as_str().expect("path")))
        .arg("--mime")
        .arg(vector["mime_type"].as_str().expect("mime_type"))
        .arg("--time")
        .arg(validation_time)
        // Corpus expectations are defined against the fixture's own trust
        // inputs, not the SDK's independently refreshed packaged snapshot.
        .arg("--no-default-trust")
        .arg("--json");
    let trust = &vector["trust"];
    if let Some(path) = trust["claim_allowed_list"].as_str() {
        command.arg("--allowed").arg(corpus.join(path));
    }
    if let Some(path) = trust["cawg_allowed_list"].as_str() {
        match mode {
            CawgTrustMode::Allowed => command.arg("--cawg-allowed").arg(corpus.join(path)),
            CawgTrustMode::Trust => command.arg("--cawg-trust").arg(corpus.join(path)),
            CawgTrustMode::None => &mut command,
        };
    }
    if let Some(path) = trust["tsa_trust_list"].as_str() {
        command.arg("--tsa-trust").arg(corpus.join(path));
    }
    if let Some(documents) = trust["did_documents"].as_array() {
        for document in documents {
            command
                .arg("--cawg-did-documents")
                .arg(corpus.join(document.as_str().expect("did document path")));
        }
    }
    let output = command.output().expect("run CLI");
    // Exit code 2 means "verified, integrity not valid" — a legitimate verdict
    // for negative vectors. Anything else non-zero is a CLI failure.
    let code = output.status.code();
    assert!(
        matches!(code, Some(0) | Some(2)),
        "{}: CLI exited {:?}: {}",
        vector["id"],
        code,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "{}: CLI emitted no JSON: {}",
        vector["id"],
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("CLI JSON envelope");
    envelope["manifest_report"].clone()
}

fn active_results(report: &Value) -> &Value {
    &report["validation_results"]["activeManifest"]
}

fn bucket_codes(report: &Value, bucket: &str) -> BTreeSet<String> {
    active_results(report)[bucket]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn codes(report: &Value) -> BTreeSet<String> {
    let mut all = bucket_codes(report, "success");
    all.extend(bucket_codes(report, "failure"));
    all.extend(bucket_codes(report, "informational"));
    all
}

/// The CAWG interop contract: every `cawg.*` code plus the one C2PA code a
/// broken identity COSE surfaces through.
fn cawg_contract_codes(report: &Value) -> BTreeSet<String> {
    codes(report)
        .into_iter()
        .filter(|code| code.starts_with("cawg.") || code == "claimSignature.mismatch")
        .collect()
}

fn required_codes(vector: &Value, section: &str) -> BTreeSet<String> {
    vector[section]["required_codes"]
        .as_array()
        .expect("required_codes")
        .iter()
        .map(|code| code.as_str().expect("code").to_owned())
        .collect()
}

fn success_item<'a>(report: &'a Value, code: &str) -> &'a Value {
    active_results(report)["success"]
        .as_array()
        .expect("success array")
        .iter()
        .find(|item| item["code"] == code)
        .unwrap_or_else(|| panic!("success item {code} missing"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

/// Every file the corpus indices pin must be present with the pinned SHA-256
/// and size, and both indices must declare the offline network policy. This is
/// the Rust equivalent of `manage_corpus.py check` so the gate has no Python
/// dependency.
#[test]
fn corpus_integrity_is_offline() {
    let corpus = corpus_dir();
    for index in [external_index(), generated_index()] {
        assert_eq!(index["network_policy"], "offline");
        for vector in vectors(&index) {
            let path = corpus.join(vector["path"].as_str().expect("path"));
            let bytes =
                std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
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
        }
    }
}

/// Pinned external vectors (c2pa-rs / c2pa-cpp fixtures) produce exactly the
/// recorded CAWG contract codes.
#[test]
fn external_corpus_observation_is_stable() {
    for vector in vectors(&external_index()) {
        let report = verify(vector, CawgTrustMode::Allowed);
        assert_eq!(
            cawg_contract_codes(&report),
            required_codes(vector, "current_sdk_observation"),
            "{}",
            vector["id"]
        );
    }
}

/// Every pinned external vector must satisfy its spec-derived CAWG expectation.
/// `current_sdk_observation` separately records implementation drift, but a
/// normative disagreement fails CI rather than being logged and skipped.
#[test]
fn external_normative_expectations() {
    let mut mismatches = Vec::new();
    for vector in vectors(&external_index()) {
        let observed = cawg_contract_codes(&verify(vector, CawgTrustMode::Allowed));
        let expected = required_codes(vector, "normative_expected");
        if observed != expected {
            mismatches.push(format!(
                "{}: observed={observed:?}, normative={expected:?}",
                vector["id"]
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "external CAWG normative mismatches:\n{}",
        mismatches.join("\n")
    );
}

/// Document-signing identities are trusted only when their chain reaches
/// caller-supplied CAWG trust material.
#[test]
fn generated_document_signing_trust_root_is_enforced() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-jpeg");

    let unanchored = verify(vector, CawgTrustMode::None);
    let well_formed = success_item(&unanchored, "cawg.identity.well-formed");
    assert_eq!(
        well_formed["details"]["trust_failure"],
        "document_signing_anchor_required"
    );
    assert!(!codes(&unanchored).contains("cawg.identity.trusted"));

    let anchored = verify(vector, CawgTrustMode::Trust);
    let trusted = success_item(&anchored, "cawg.identity.trusted");
    assert_eq!(trusted["details"]["trust_source"], "document_signing");
}

/// The generated corpus never touches the network: OCSP is reported skipped
/// and the trusted-identity evidence records `revocation_status: not_checked`.
#[test]
fn generated_network_policy_is_explicitly_offline() {
    let index = generated_index();
    assert_eq!(index["network_policy"], "offline");
    let vector = vector_by_id(&index, "x509-es256-jpeg");
    let report = verify(vector, CawgTrustMode::Allowed);
    assert!(codes(&report).contains("signingCredential.ocsp.skipped"));
    let trusted = success_item(&report, "cawg.identity.trusted");
    assert_eq!(trusted["details"]["timestamp_trusted"], false);
    assert_eq!(trusted["details"]["revocation_status"], "not_checked");
}

/// Per-vector gate over the generated corpus: frozen bytes, then the full
/// normative verdict (required/forbidden code sets, validation state) and the
/// identity assertion's referenced-assertion layout.
#[test]
fn generated_vector_hash_and_native_verdict() {
    let corpus = corpus_dir();
    for vector in vectors(&generated_index()) {
        let id = &vector["id"];
        let asset = corpus.join(vector["path"].as_str().expect("path"));
        let bytes = std::fs::read(&asset).expect("read asset");
        assert_eq!(bytes.len() as u64, vector["size"].as_u64().expect("size"));
        assert_eq!(
            sha256_hex(&bytes),
            vector["sha256"].as_str().expect("sha256")
        );

        let report = verify(vector, CawgTrustMode::Allowed);
        let success = bucket_codes(&report, "success");
        let failures = bucket_codes(&report, "failure");
        let expected = &vector["normative_expected"];
        assert!(
            required_codes(vector, "normative_expected").is_subset(&success),
            "{id}: required success codes missing: have {success:?}"
        );
        for forbidden in expected["forbidden_success_codes"]
            .as_array()
            .expect("array")
        {
            assert!(
                !success.contains(forbidden.as_str().expect("code")),
                "{id}: forbidden success code present"
            );
        }
        let required_failures: BTreeSet<String> = expected["required_failure_codes"]
            .as_array()
            .expect("array")
            .iter()
            .map(|code| code.as_str().expect("code").to_owned())
            .collect();
        assert_eq!(failures, required_failures, "{id}");
        assert_eq!(
            report["validation_state"], expected["validation_state"],
            "{id}"
        );
        for prefix in expected["forbidden_failure_prefixes"]
            .as_array()
            .expect("array")
        {
            let prefix = prefix.as_str().expect("prefix");
            assert!(
                !failures.iter().any(|code| code.starts_with(prefix)),
                "{id}: failure with forbidden prefix {prefix}"
            );
        }

        let manifest = &report["manifests"][report["active_manifest"].as_str().expect("label")];
        let identity = assertion_data(manifest, "cawg.identity");
        let references = identity["signer_payload"]["referenced_assertions"]
            .as_array()
            .expect("referenced_assertions");
        let urls: Vec<&str> = references
            .iter()
            .map(|reference| reference["url"].as_str().expect("url"))
            .collect();
        let expected_urls: Vec<&str> = vector["identity_references"]
            .as_array()
            .expect("identity_references")
            .iter()
            .map(|url| url.as_str().expect("url"))
            .collect();
        assert_eq!(urls, expected_urls, "{id}");
        assert_eq!(
            urls[0],
            format!(
                "self#jumbf=c2pa.assertions/{}",
                vector["hard_binding"].as_str().expect("hard_binding")
            ),
            "{id}"
        );
        for reference in references {
            assert!(
                base64_decodes(reference["hash"].as_str().expect("hash")),
                "{id}: reference hash is not valid base64"
            );
        }
    }
}

/// IPTC best-practice shape: cawg.metadata and cawg.training-mining sit under
/// the publisher's identity signature alongside the hard binding.
#[test]
fn generated_bestpractice_vector_covers_editorial_metadata() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-bestpractice-jpeg");
    assert_eq!(
        vector["identity_references"],
        serde_json::json!([
            "self#jumbf=c2pa.assertions/c2pa.hash.data",
            "self#jumbf=c2pa.assertions/cawg.metadata",
            "self#jumbf=c2pa.assertions/cawg.training-mining",
        ])
    );
    let report = verify(vector, CawgTrustMode::Allowed);
    assert_eq!(report["validation_state"], "Trusted");
    assert!(codes(&report).contains("cawg.identity.trusted"));

    let manifest = &report["manifests"][report["active_manifest"].as_str().expect("label")];
    let labels: Vec<&str> = manifest["assertions"]
        .as_array()
        .expect("assertions")
        .iter()
        .map(|item| item["label"].as_str().expect("label"))
        .collect();
    assert!(labels.contains(&"cawg.metadata"));
    assert!(labels.contains(&"cawg.training-mining"));
    let tdm = assertion_data(manifest, "cawg.training-mining");
    assert_eq!(
        tdm["entries"]["cawg.ai_generative_training"]["use"],
        "notAllowed"
    );

    let identity = assertion_data(manifest, "cawg.identity");
    let urls: Vec<&Value> = identity["signer_payload"]["referenced_assertions"]
        .as_array()
        .expect("references")
        .iter()
        .map(|reference| &reference["url"])
        .collect();
    let expected: Vec<&Value> = vector["identity_references"]
        .as_array()
        .expect("identity_references")
        .iter()
        .collect();
    assert_eq!(urls, expected);
}

/// The corpus certificates are valid 2026-08-01..2036-08-01. Outside that
/// window the claim credential is outside validity and the CAWG identity lane
/// is not evaluated at all: no `cawg.*` code of any polarity is emitted.
#[test]
fn generated_time_shift_outside_validity_is_never_trusted() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-jpeg");
    for shifted_time in ["2040-01-01T00:00:00Z", "2020-01-01T00:00:00Z"] {
        let report = verify_at(vector, CawgTrustMode::Allowed, shifted_time);
        let failures = bucket_codes(&report, "failure");
        let expected: BTreeSet<String> = [
            "claimSignature.outsideValidity",
            "signingCredential.untrusted",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert_eq!(failures, expected, "{shifted_time}");
        let all = codes(&report);
        assert!(!all.contains("cawg.identity.trusted"), "{shifted_time}");
        assert!(cawg_contract_codes(&report).is_empty(), "{shifted_time}");
        assert!(
            !all.contains("claimSignature.insideValidity"),
            "{shifted_time}"
        );
        assert_eq!(report["validation_state"], "Valid", "{shifted_time}");
    }
}

/// The interim S/MIME lane: emailProtection EKU + approved policy OID, only
/// reachable with a trusted RFC 3161 timestamp.
#[test]
fn generated_smime_lane_is_trusted_via_email_protection_eku() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-smime-jpeg");
    let report = verify(vector, CawgTrustMode::Allowed);
    assert_eq!(report["validation_state"], "Trusted");
    let trusted = success_item(&report, "cawg.identity.trusted");
    let details = &trusted["details"];
    assert_eq!(details["accepted_eku"], "1.3.6.1.5.5.7.3.4");
    assert_eq!(details["trust_source"], "allowed_list");
    assert_eq!(details["certificate_policy"], "2.23.140.1.5.2.2");
    assert_eq!(details["timestamp_trusted"], true);
    let all = codes(&report);
    assert!(all.contains("timeStamp.validated"));
    assert!(all.contains("timeStamp.trusted"));
}

/// A 512-byte pad1 must round-trip in the report and never perturb the verdict.
#[test]
fn generated_pad1_vector_reports_nonzero_padding() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-pad1-jpeg");
    assert_eq!(vector["cawg_pad1"], 512);
    let report = verify(vector, CawgTrustMode::Allowed);
    let manifest = &report["manifests"][report["active_manifest"].as_str().expect("label")];
    let identity = assertion_data(manifest, "cawg.identity");
    let pad1 = identity["pad1"].as_str().expect("pad1");
    assert_eq!(base64_len(pad1), Some(512));
    assert_eq!(report["validation_state"], "Trusted");
    assert!(codes(&report).contains("cawg.identity.trusted"));

    let plain = verify(
        vector_by_id(&index, "x509-es256-jpeg"),
        CawgTrustMode::Allowed,
    );
    let plain_manifest = &plain["manifests"][plain["active_manifest"].as_str().expect("label")];
    assert_eq!(assertion_data(plain_manifest, "cawg.identity")["pad1"], "");
}

/// Composition: the parent embeds a CAWG-signed PNG ingredient whose stored
/// validation records its own trusted identity.
#[test]
fn generated_composed_vector_embeds_cawg_signed_ingredient() {
    let index = generated_index();
    let vector = vector_by_id(&index, "x509-es256-composed-jpeg");
    assert_eq!(vector["composition"], true);
    let report = verify(vector, CawgTrustMode::Allowed);
    assert_eq!(report["validation_state"], "Trusted");
    assert!(codes(&report).contains("cawg.identity.trusted"));

    let manifest = &report["manifests"][report["active_manifest"].as_str().expect("label")];
    let ingredient = assertion_data(manifest, "c2pa.ingredient.v3");
    assert_eq!(ingredient["relationship"], "componentOf");
    assert_eq!(ingredient["dc:format"], "image/png");
    let ingredient_label = "urn:c2pa:00000000-0000-4000-8000-000000001203:encypher";
    assert_eq!(
        ingredient["activeManifest"]["url"],
        format!("self#jumbf=/c2pa/{ingredient_label}")
    );
    assert!(report["manifests"][ingredient_label].is_object());
    let stored_success = ingredient["validationResults"]["activeManifest"]["success"]
        .as_array()
        .expect("stored success");
    assert!(stored_success
        .iter()
        .any(|item| item["code"] == "cawg.identity.trusted"));
}

/// The realworld index ships without its (redistribution-pending) binaries:
/// the manager + pinned digests let users fetch them on demand, and the trust
/// PEMs it references are present.
#[test]
fn realworld_index_ships_fetchable_metadata() {
    let corpus = corpus_dir();
    let index = load(&corpus.join("realworld/index.json"));
    assert_eq!(index["network_policy"], "offline");
    assert!(corpus.join("realworld/manage_realworld.py").is_file());
    for (_, entry) in index["trust"].as_object().expect("trust map") {
        let path = corpus
            .join("realworld")
            .join(entry["path"].as_str().expect("path"));
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(
            sha256_hex(&bytes),
            entry["sha256"].as_str().expect("sha256")
        );
    }
    for vector in vectors(&index) {
        let entry = vector["path"].as_str().expect("path");
        assert!(entry.starts_with("assets/"), "unexpected layout: {entry}");
        assert!(vector["sha256"].as_str().is_some());
        assert!(vector["source_url"].as_str().is_some());
    }
}

fn assertion_data<'a>(manifest: &'a Value, label: &str) -> &'a Value {
    manifest["assertions"]
        .as_array()
        .expect("assertions")
        .iter()
        .find(|item| item["label"] == label)
        .map(|item| &item["data"])
        .unwrap_or_else(|| panic!("assertion {label} missing"))
}

/// Strict base64 check without pulling in a base64 crate: alphabet + padding.
fn base64_decodes(text: &str) -> bool {
    base64_len(text).is_some()
}

/// Decoded length of strict standard-alphabet base64, or `None` when invalid.
fn base64_len(text: &str) -> Option<usize> {
    if text.len() % 4 != 0 {
        return None;
    }
    let padding = text.bytes().rev().take_while(|&byte| byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &text.as_bytes()[..text.len() - padding];
    if !body
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return None;
    }
    if text.is_empty() {
        return Some(0);
    }
    Some(text.len() / 4 * 3 - padding)
}
