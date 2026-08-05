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
fn signed_jpeg_reports_integrity_without_implying_trust() {
    let report = verify(&fixture("signed_test.jpg"), "image/jpeg").expect("verification succeeds");

    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(report.profile, C2PA_PROFILE);
    assert!(report.present);
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.signature, "valid");
    assert_eq!(report.hard_binding, "match");
    assert_eq!(report.trust.status, "not_evaluated");
    assert_eq!(report.trust.basis, "none");
    assert_eq!(report.trust.revocation.status, "not_checked");
}

#[test]
fn signed_mp4_uses_the_same_public_report_contract() {
    let report = verify(&fixture("signed_test.mp4"), "video/mp4").expect("verification succeeds");

    assert!(report.present);
    assert_eq!(report.integrity, "valid");
    assert_eq!(report.hard_binding, "match");
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
