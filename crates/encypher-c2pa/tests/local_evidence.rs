// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Local evidence: one verification that also hands back the exact embedded
//! store it verified, so a remote service can re-verify that store without
//! receiving the asset.

use std::fs;
use std::path::PathBuf;

use encypher_c2pa::{
    local_evidence_with_options, verify_with_manifest_store, verify_with_options, TelemetryOptions,
    VerifyOptions,
};
use sha2::{Digest, Sha256};

fn read(relative: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// Offline, deterministic options: telemetry off and a fixed instant, so two
/// verifications of the same bytes produce identical reports.
fn options() -> VerifyOptions {
    VerifyOptions {
        validation_time: Some("2026-09-01T00:00:00Z".into()),
        telemetry: TelemetryOptions {
            enabled: Some(false),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("marker present in fixture")
}

struct Case {
    name: &'static str,
    asset: Vec<u8>,
    mime: &'static str,
    algorithm: &'static str,
    /// Offset of one content byte the hard binding covers and the container
    /// parser does not need, so flipping it changes the hash and nothing else.
    tamper_at: usize,
}

fn cases() -> Vec<Case> {
    let data_jpeg = read("../../tests/fixtures/signed_test.jpg");
    let boxes_jpeg =
        read("src/c2pa-validate/tests/fixtures/c2pa-rs-compressed/compressed_boxhash.jpg");
    let boxes_png =
        read("src/c2pa-validate/tests/fixtures/c2pa-rs-compressed/compressed_boxhash.png");
    let epub = read("src/c2pa-validate/tests/fixtures/compressed-epub/application_epub_zip.epub");
    let mp4 = read("../../tests/fixtures/signed_test.mp4");
    vec![
        Case {
            name: "data-hash JPEG",
            tamper_at: data_jpeg.len() - 32,
            asset: data_jpeg,
            mime: "image/jpeg",
            algorithm: "c2pa.hash.data",
        },
        Case {
            name: "box-hash JPEG",
            tamper_at: boxes_jpeg.len() - 32,
            asset: boxes_jpeg,
            mime: "image/jpeg",
            algorithm: "c2pa.hash.boxes",
        },
        Case {
            name: "box-hash PNG",
            // Inside the IDAT payload.
            tamper_at: find(&boxes_png, b"IDAT") + 8,
            asset: boxes_png,
            mime: "image/png",
            algorithm: "c2pa.hash.boxes",
        },
        Case {
            name: "collection-hash EPUB",
            // The stored `mimetype` entry's content, after its local header.
            tamper_at: find(&epub, b"mimetype") + b"mimetype".len() + 2,
            asset: epub,
            mime: "application/epub+zip",
            algorithm: "c2pa.hash.collection.data",
        },
        Case {
            name: "BMFF MP4",
            tamper_at: find(&mp4, b"mdat") + 16,
            asset: mp4,
            mime: "video/mp4",
            algorithm: "c2pa.hash.bmff.v3",
        },
    ]
}

#[test]
fn a_signed_asset_yields_the_verified_store_and_a_matching_binding() {
    for case in cases() {
        let evidence = local_evidence_with_options(&case.asset, case.mime, &options())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));

        assert_eq!(evidence.report.integrity, "valid", "{}", case.name);
        assert_eq!(
            evidence.hard_binding.algorithm.as_deref(),
            Some(case.algorithm),
            "{}",
            case.name
        );
        assert_eq!(evidence.hard_binding.status, "match", "{}", case.name);
        assert_eq!(
            evidence.asset_sha256,
            hex::encode(Sha256::digest(&case.asset)),
            "{}",
            case.name
        );

        let store = evidence
            .manifest_store
            .as_deref()
            .unwrap_or_else(|| panic!("{}: embedded store returned", case.name));
        let store_sha256 = hex::encode(Sha256::digest(store));
        assert_eq!(
            evidence.manifest_store_sha256.as_deref(),
            Some(store_sha256.as_str()),
            "{}",
            case.name
        );
        // The report binds itself to the same bytes, so a service can tell
        // which store the local verdict was computed over.
        assert_eq!(
            evidence.report.manifest_report["manifest_store_sha256"],
            store_sha256.as_str(),
            "{}",
            case.name
        );

        // The returned bytes are a complete store: verified detached against
        // the same asset, they reach the same verdict.
        let detached = verify_with_manifest_store(&case.asset, store, case.mime, &options())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(detached.integrity, "valid", "{}", case.name);
        assert_eq!(detached.hard_binding, "match", "{}", case.name);
    }
}

#[test]
fn the_report_is_exactly_what_verify_returns() {
    for case in cases() {
        let evidence = local_evidence_with_options(&case.asset, case.mime, &options())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        let report = verify_with_options(&case.asset, case.mime, &options())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(
            evidence.report.to_json().unwrap(),
            report.to_json().unwrap(),
            "{}",
            case.name
        );
    }
}

#[test]
fn an_altered_asset_reports_a_mismatch_on_the_same_binding() {
    for case in cases() {
        let mut tampered = case.asset.clone();
        tampered[case.tamper_at] ^= 0x01;
        let evidence = local_evidence_with_options(&tampered, case.mime, &options())
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));

        assert_ne!(evidence.report.integrity, "valid", "{}", case.name);
        assert_eq!(evidence.hard_binding.status, "mismatch", "{}", case.name);
        assert_eq!(
            evidence.hard_binding.algorithm.as_deref(),
            Some(case.algorithm),
            "{}",
            case.name
        );
        // The store itself is untouched, so it is still returned for the
        // service to re-verify and log.
        assert!(evidence.manifest_store.is_some(), "{}", case.name);
        assert_ne!(
            evidence.asset_sha256,
            hex::encode(Sha256::digest(&case.asset)),
            "{}",
            case.name
        );
    }
}

#[test]
fn an_unsigned_asset_has_no_store_and_an_unknown_binding() {
    // SOI, a minimal scan, EOI: a complete JPEG with no C2PA segment.
    let jpeg = [
        0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x00, 0xFF, 0xD9,
    ];
    let evidence =
        local_evidence_with_options(&jpeg, "image/jpeg", &options()).expect("verification runs");

    assert!(!evidence.report.present);
    assert_eq!(evidence.manifest_store, None);
    assert_eq!(evidence.manifest_store_sha256, None);
    assert_eq!(evidence.hard_binding.algorithm, None);
    assert_eq!(evidence.hard_binding.status, "unknown");
    assert_eq!(evidence.asset_sha256, hex::encode(Sha256::digest(jpeg)));
}

#[test]
fn an_unsupported_mime_type_is_an_error() {
    let error = local_evidence_with_options(b"plain", "application/x-unknown", &options())
        .expect_err("no reader for this type");
    assert_eq!(error.code(), "unsupported_mime");
}
