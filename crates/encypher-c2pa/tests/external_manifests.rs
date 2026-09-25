// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! External manifests: a store the caller supplies separately, and the remote
//! declaration an asset carries when its store lives somewhere else.

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use encypher_c2pa::{
    detached_manifest_evidence, verify, verify_with_manifest_store, TelemetryOptions, VerifyOptions,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    fs::read(path).expect("fixture must be readable")
}

/// Trust and telemetry are irrelevant to these assertions; verification must
/// stay entirely local, so the telemetry request is switched off explicitly.
fn offline_options() -> VerifyOptions {
    VerifyOptions {
        telemetry: TelemetryOptions {
            enabled: Some(false),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A JPEG with no embedded manifest whose XMP names a remote store.
fn jpeg_declaring_remote_manifest(uri: &str) -> Vec<u8> {
    let packet = format!(
        concat!(
            r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>"#,
            r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF"#,
            r#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#,
            r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/""#,
            r#" dcterms:provenance="{}"/></rdf:RDF></x:xmpmeta>"#,
            r#"<?xpacket end="w"?>"#,
        ),
        uri
    );
    let mut payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    payload.extend_from_slice(packet.as_bytes());

    let mut jpeg = vec![0xFF, 0xD8];
    jpeg.extend_from_slice(&[0xFF, 0xE1]);
    jpeg.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
    jpeg.extend_from_slice(&payload);
    // A minimal scan so the asset is a complete JPEG, not a header fragment.
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    jpeg.extend_from_slice(&[0x00, 0xFF, 0xD9]);
    jpeg
}

#[test]
fn a_manifest_store_supplied_separately_verifies_against_its_asset() {
    let asset = fixture("signed_test.jpg");
    let store = detached_manifest_evidence(&asset, "image/jpeg")
        .expect("evidence extraction succeeds")
        .expect("the fixture carries an embedded manifest")
        .manifest_store;

    let report = verify_with_manifest_store(&asset, &store, "image/jpeg", &offline_options())
        .expect("verification succeeds");

    assert!(report.present);
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.signature, "valid");
    assert_eq!(report.hard_binding, "match");
}

#[test]
fn a_manifest_store_does_not_verify_against_an_altered_asset() {
    let asset = fixture("signed_test.jpg");
    let store = detached_manifest_evidence(&asset, "image/jpeg")
        .expect("evidence extraction succeeds")
        .expect("the fixture carries an embedded manifest")
        .manifest_store;
    let mut tampered = asset.clone();
    // A pixel byte, well past the header and outside the manifest carrier.
    let target = tampered.len() - 32;
    tampered[target] ^= 0x01;

    let report = verify_with_manifest_store(&tampered, &store, "image/jpeg", &offline_options())
        .expect("verification returns a report");

    assert_ne!(report.integrity, "valid");
    assert_ne!(report.hard_binding, "match");
}

#[test]
fn a_manifest_store_that_cannot_be_read_is_refused_rather_than_parsed() {
    let asset = fixture("signed_test.jpg");
    let error = verify_with_manifest_store(&asset, &[], "image/jpeg", &offline_options())
        .expect_err("an empty store is not a manifest");
    assert_eq!(error.code(), "verification_error");

    // `mime_type` describes the asset. The host-less store type is not an asset.
    let store = fixture("signed_test.c2pa");
    let error = verify_with_manifest_store(&asset, &store, "application/c2pa", &offline_options())
        .expect_err("the content side cannot be a manifest store");
    assert_eq!(error.code(), "unsupported_mime");
}

#[test]
fn a_declared_remote_manifest_is_reported_inaccessible_with_its_uri() {
    let uri = "https://manifests.example.test/asset-1.c2pa";
    let asset = jpeg_declaring_remote_manifest(uri);

    let report =
        verify(&asset, "image/jpeg").expect("a remote declaration is a report, not an error");

    // The asset is under provenance - it names where its manifest lives - but
    // the store is not here to be checked, so integrity is not valid. This is
    // the same shape the font remote-manifest path already reports.
    assert!(report.present);
    assert_ne!(report.integrity, "valid");
    let status = report
        .validation_results
        .failure
        .iter()
        .find(|status| status.code == "manifest.inaccessible")
        .unwrap_or_else(|| panic!("{:?}", report.validation_results));
    assert_eq!(status.url, uri);
    assert_eq!(
        status
            .details
            .as_ref()
            .and_then(|details| details.get("remote_manifest_uri"))
            .and_then(|value| value.as_str()),
        Some(uri)
    );
    assert_eq!(
        status
            .details
            .as_ref()
            .and_then(|details| details.get("declared_in"))
            .and_then(|value| value.as_str()),
        Some("xmp.dcterms:provenance")
    );
}

/// An embedded store wins: the remote declaration is only consulted when there
/// is nothing to read in the asset (C2PA 2.4 Validation, By Reference).
#[test]
fn an_embedded_store_takes_precedence_over_a_remote_declaration() {
    let report = verify(&fixture("signed_test.jpg"), "image/jpeg").expect("verification succeeds");

    assert!(report.present);
    assert!(!report
        .validation_results
        .failure
        .iter()
        .any(|status| status.code == "manifest.inaccessible"));
}

/// The declared URI is reported, never fetched. A listener stands in for the
/// manifest repository and must never be connected to.
#[test]
fn reading_a_remote_declaration_opens_no_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
    let uri = format!(
        "http://{}/asset-1.c2pa",
        listener.local_addr().expect("listener address")
    );
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let connected = listener.accept().is_ok();
        let _ = sender.send(connected);
    });

    let asset = jpeg_declaring_remote_manifest(&uri);
    let report = verify_with_options_offline(&asset);

    assert!(report
        .validation_results
        .failure
        .iter()
        .any(|status| status.code == "manifest.inaccessible" && status.url == uri));
    assert!(
        receiver.recv_timeout(Duration::from_secs(2)).is_err(),
        "the verifier connected to the declared manifest repository"
    );
}

fn verify_with_options_offline(asset: &[u8]) -> encypher_c2pa::VerificationReport {
    encypher_c2pa::verify_with_options(asset, "image/jpeg", &offline_options())
        .expect("verification returns a report")
}
