// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! The crJSON the verifier emits under `strict_conformance` is checked against
//! the C2PA 2.4 crJSON schema, so a conformance-program rubric reading it sees
//! the same document shape it gets from the reference implementation.

use std::fs;
use std::path::PathBuf;

use boon::{Compiler, SchemaIndex, Schemas};
use encypher_c2pa::{verify_with_options, VerifyOptions};
use serde_json::Value;

/// Pinned C2PA test assets from the `contentauth/c2pa-rs` corpus.
const ASSETS: &[(&str, &str)] = &[
    ("C.jpg", "image/jpeg"),
    ("CACA.jpg", "image/jpeg"),
    ("E-sig-CA.jpg", "image/jpeg"),
    ("XCA.jpg", "image/jpeg"),
    ("no_alg.jpg", "image/jpeg"),
    ("video1.mp4", "video/mp4"),
];

fn asset(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/core/external/contentauth-c2pa-rs/bc3ca83d/assets")
        .join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

fn strict_options() -> VerifyOptions {
    VerifyOptions {
        strict_conformance: true,
        ..VerifyOptions::default()
    }
}

fn content_credentials(name: &str, mime: &str) -> Value {
    let report = verify_with_options(&asset(name), mime, &strict_options())
        .unwrap_or_else(|error| panic!("{name} verifies: {error}"));
    report
        .content_credentials
        .unwrap_or_else(|| panic!("{name} emits crJSON under strict conformance"))
}

fn crjson_schema() -> (Schemas, SchemaIndex) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crjson/crJSON.schema.json");
    let document: Value = serde_json::from_slice(&fs::read(&path).expect("schema is readable"))
        .expect("schema is valid JSON");
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler
        .add_resource("crJSON.schema.json", document)
        .expect("schema registers");
    let index = compiler
        .compile("crJSON.schema.json", &mut schemas)
        .expect("schema compiles");
    (schemas, index)
}

#[test]
fn strict_conformance_crjson_validates_against_the_c2pa_2_4_schema() {
    let (schemas, index) = crjson_schema();
    for (name, mime) in ASSETS {
        let document = content_credentials(name, mime);
        if let Err(error) = schemas.validate(&document, index) {
            panic!("{name} crJSON violates the C2PA 2.4 schema:\n{error:#}");
        }
    }
}

#[test]
fn every_manifest_carries_the_required_conformance_fields() {
    for (name, mime) in ASSETS {
        let document = content_credentials(name, mime);
        let manifests = document["manifests"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} crJSON has a manifests array"));
        assert!(!manifests.is_empty(), "{name} has at least one manifest");
        for manifest in manifests {
            assert!(
                manifest.get("claim").is_some() ^ manifest.get("claim.v2").is_some(),
                "{name}: exactly one of claim or claim.v2 is present"
            );
            assert!(
                manifest.get("signature").is_some(),
                "{name}: every manifest carries a signature object"
            );
            let results = &manifest["validationResults"];
            assert!(
                results["validationTime"]
                    .as_str()
                    .is_some_and(|time| time.contains('T') && !time.is_empty()),
                "{name}: validationResults carries an RFC 3339 validationTime"
            );
            assert_eq!(
                results["specVersion"], "2.4.0",
                "{name}: validationResults names the spec revision"
            );
        }
    }
}

#[test]
fn the_active_manifest_leads_the_manifests_array() {
    // CACA.jpg nests an ingredient manifest, so store order and crJSON order
    // genuinely differ.
    let document = content_credentials("CACA.jpg", "image/jpeg");
    let report = verify_with_options(&asset("CACA.jpg"), "image/jpeg", &strict_options())
        .expect("CACA.jpg verifies");
    let active = report.manifest_report["active_manifest"]
        .as_str()
        .expect("the report names an active manifest")
        .to_string();
    let manifests = document["manifests"].as_array().expect("manifests array");

    assert!(manifests.len() > 1, "CACA.jpg carries nested manifests");
    assert_eq!(manifests[0]["label"], active.as_str());
    assert!(
        !manifests[0]["validationResults"]["success"]
            .as_array()
            .expect("success codes")
            .is_empty(),
        "the active manifest reports the verifier's status codes"
    );
}

#[test]
fn the_signing_certificate_reaches_the_signature_object() {
    let document = content_credentials("C.jpg", "image/jpeg");
    let signature = &document["manifests"][0]["signature"];

    assert!(
        signature["algorithm"]
            .as_str()
            .is_some_and(|alg| alg.starts_with("ES") || alg.starts_with("PS") || alg == "Ed25519"),
        "algorithm is a C2PA signature algorithm name, got {:?}",
        signature["algorithm"]
    );
    let certificate = &signature["certificateInfo"];
    assert!(certificate["serialNumber"].as_str().is_some());
    assert!(certificate["subject"].is_object());
    assert!(certificate["issuer"].is_object());
    assert!(certificate["validity"]["notBefore"].as_str().is_some());
    assert!(certificate["validity"]["notAfter"].as_str().is_some());
}

#[test]
fn the_default_posture_emits_no_crjson() {
    for (name, mime) in ASSETS {
        let report = verify_with_options(&asset(name), mime, &VerifyOptions::default())
            .unwrap_or_else(|error| panic!("{name} verifies: {error}"));
        assert!(
            report.content_credentials.is_none(),
            "{name}: crJSON is a strict-conformance side output"
        );
    }
}
