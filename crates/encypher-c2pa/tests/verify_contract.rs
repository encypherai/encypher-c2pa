// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use encypher_c2pa::{
    verify, verify_with_options, TelemetryOptions, VerifyOptions, C2PA_PROFILE,
    REPORT_SCHEMA_VERSION,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    fs::read(path).expect("fixture must be readable")
}

#[test]
fn signed_jpeg_uses_bundled_trust_without_implying_integrity() {
    let report = verify(&fixture("signed_test.jpg"), "image/jpeg").expect("verification succeeds");

    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.profile, C2PA_PROFILE);
    assert!(report.present);
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.signature, "valid");
    assert_eq!(report.hard_binding, "match");
    assert_eq!(report.trust.status, "not_valid_for_supplied_material");
    assert_eq!(report.trust.basis, "bundled_static_material");
    assert_eq!(report.trust.revocation.status, "not_checked");
}

#[test]
fn bundled_trust_can_be_disabled_for_caller_controlled_verification() {
    let options = VerifyOptions {
        no_default_trust: true,
        ..Default::default()
    };
    let report = verify_with_options(&fixture("signed_test.jpg"), "image/jpeg", &options)
        .expect("verification succeeds");

    assert_eq!(report.integrity, "valid");
    assert_eq!(report.trust.status, "not_evaluated");
    assert_eq!(report.trust.basis, "none");
}

#[test]
fn signed_mp4_uses_the_same_public_report_contract() {
    let report = verify(&fixture("signed_test.mp4"), "video/mp4").expect("verification succeeds");

    assert!(report.present);
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.hard_binding, "match");
}

/// Real Encypher-signed BigTIFFs, one per byte order and one per conformant
/// placement: the little-endian file carries the C2PA entry inside its single
/// main IFD (C2PA 2.4 A.3.6) and the big-endian one is multi-page with a
/// dedicated last IFD (2.2 A.3.5). Both failed outright before BigTIFF was
/// read, with `not a valid Tiff asset: bad TIFF magic`.
#[test]
fn signed_bigtiff_verifies_in_both_byte_orders_and_placements() {
    for name in [
        "signed_bigtiff_le_single_page.tif",
        "signed_bigtiff_be_multi_page.tif",
    ] {
        let report = verify(&fixture(name), "image/tiff").expect("verification succeeds");

        assert!(report.present, "{name}");
        assert_eq!(report.integrity, "valid", "{name}");
        assert_eq!(report.signature, "valid", "{name}");
        assert_eq!(report.hard_binding, "match", "{name}");
    }
}

/// Offset and length of the manifest store inside a little-endian BigTIFF,
/// read from IFD tag 52545, so a tamper test can prove the byte it changes is
/// outside the carrier rather than assume it.
fn bigtiff_le_carrier(asset: &[u8]) -> (usize, usize) {
    assert_eq!(&asset[..4], b"II+\x00", "little-endian BigTIFF");
    let u16_at = |at: usize| u16::from_le_bytes(asset[at..at + 2].try_into().unwrap());
    let u64_at = |at: usize| {
        usize::try_from(u64::from_le_bytes(asset[at..at + 8].try_into().unwrap())).unwrap()
    };
    let mut ifd = u64_at(8);
    while ifd != 0 {
        let count = u64_at(ifd);
        for index in 0..count {
            let entry = ifd + 8 + index * 20;
            if u16_at(entry) == 0xCD41 {
                return (u64_at(entry + 12), u64_at(entry + 4));
            }
        }
        ifd = u64_at(ifd + 8 + count * 20);
    }
    panic!("the fixture carries a C2PA entry");
}

/// A byte changed in the image data of a signed BigTIFF, outside the resolved
/// manifest carrier, must not still read as valid.
#[test]
fn a_tampered_bigtiff_page_is_not_reported_as_valid_integrity() {
    let mut asset = fixture("signed_bigtiff_le_single_page.tif");
    let (carrier_start, carrier_length) = bigtiff_le_carrier(&asset);
    // Half way into the image data the page entries point at, well before the
    // store appended at the end of the file.
    let page_byte = carrier_start / 2;
    assert!(
        page_byte < carrier_start || page_byte >= carrier_start + carrier_length,
        "the flipped byte must lie outside the manifest carrier"
    );
    asset[page_byte] ^= 0x01;

    let report = verify(&asset, "image/tiff").expect("verification succeeds");
    assert_ne!(report.integrity, "valid");
    assert_eq!(report.hard_binding, "mismatch");
}

#[test]
fn tampering_is_not_reported_as_valid_integrity() {
    let mut asset = fixture("signed_test.jpg");
    asset[200] ^= 0x01;

    if let Ok(report) = verify(&asset, "image/jpeg") {
        assert_ne!(report.integrity, "valid");
    }
}

#[test]
fn opt_in_failure_telemetry_posts_only_the_bounded_event() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/event", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            request.extend_from_slice(&chunk[..count]);
            let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(str::trim)
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap();
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        sender.send(request).unwrap();
    });

    let mut asset = fixture("signed_test.jpg");
    asset[200] ^= 0x01;
    let options = VerifyOptions {
        telemetry: TelemetryOptions {
            enabled: Some(true),
            endpoint: Some(endpoint),
            sdk_name: Some("rust".to_string()),
        },
        ..Default::default()
    };
    let _ = verify_with_options(&asset, "image/jpeg", &options);

    let request = receiver.recv_timeout(Duration::from_secs(4)).unwrap();
    let body_start = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let event: serde_json::Value = serde_json::from_slice(&request[body_start..]).unwrap();
    assert_eq!(event["sdk_name"], "rust");
    assert_eq!(event["mime_type"], "image/jpeg");
    assert!(matches!(
        event["failure_kind"].as_str(),
        Some("invalid_provenance" | "verification_error")
    ));
    assert!(event.get("asset").is_none());
    assert!(event.get("manifest").is_none());
    assert!(event.get("path").is_none());
}
