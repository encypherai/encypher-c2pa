//! Contract guards for the opt-in `--encypher-api` provenance lookup.
//!
//! These pin the privacy and stability contract: default verification makes no
//! network call, the flag attaches Encypher's record verbatim without touching
//! any local report field or the exit code, and every failure mode degrades to
//! an error object plus a stderr warning rather than a changed verdict or a
//! panic. The mock server is a bare std `TcpListener` returning canned JSON,
//! mirroring the SDK's telemetry transport test.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn signed_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed_test.mp4")
}

fn run_verify(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(signed_fixture())
        .args(args)
        .output()
        .expect("run CLI")
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
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
            .unwrap_or(0);
        if request.len() >= header_end + 4 + content_length {
            break;
        }
    }
    request
}

/// Bind a one-shot lookup server returning `status_line` + `body`. Returns the
/// endpoint URL and a receiver carrying the raw request bytes it observed.
fn spawn_lookup_server(
    status_line: &'static str,
    body: &'static str,
) -> (String, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        let response = format!(
            "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        let _ = sender.send(request);
    });
    (endpoint, receiver)
}

fn request_body(request: &[u8]) -> Value {
    let body_start = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("request has a body")
        + 4;
    serde_json::from_slice(&request[body_start..]).expect("request body is JSON")
}

#[test]
fn no_flag_makes_no_lookup_and_omits_key() {
    let output = run_verify(&["--json"]);
    assert!(output.status.success(), "signed fixture verifies");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        value.get("encypher_api").is_none(),
        "default verify must not carry the encypher_api key:\n{stdout}"
    );
}

#[test]
fn flag_attaches_verbatim_response_and_sends_only_the_digest() {
    let body = r#"{"success":true,"found":true,"document_id":"doc_test123","verification_url":"https://verify.example/doc_test123","organization_name":"Test Org","media_type":"video","signed_at":"2026-08-07T00:00:00Z"}"#;
    let (endpoint, requests) = spawn_lookup_server("HTTP/1.1 200 OK", body);

    let output = run_verify(&[
        "--json",
        "--encypher-api",
        "--encypher-api-endpoint",
        &endpoint,
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let expected: Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        value.get("encypher_api"),
        Some(&expected),
        "encypher_api must be the verbatim parsed response:\n{stdout}"
    );

    let sent = request_body(&requests.recv_timeout(Duration::from_secs(4)).unwrap());
    let digest = sent["content_sha256"].as_str().expect("digest present");
    let expected_digest = hex::encode(Sha256::digest(std::fs::read(signed_fixture()).unwrap()));
    assert_eq!(
        digest, expected_digest,
        "digest must be SHA-256 of exact bytes"
    );
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "digest must be 64 lowercase hex chars: {digest}"
    );
    assert_eq!(
        sent.as_object().unwrap().len(),
        1,
        "only the content_sha256 digest leaves the machine: {sent}"
    );
}

#[test]
fn flag_preserves_local_report_bytes_and_exit_code_in_json() {
    let (endpoint, _requests) =
        spawn_lookup_server("HTTP/1.1 200 OK", r#"{"success":true,"found":false}"#);
    // Pin the validation instant so the only permitted difference is the key.
    let time = "2026-08-07T00:00:00Z";
    let flagged = run_verify(&[
        "--json",
        "--time",
        time,
        "--encypher-api",
        "--encypher-api-endpoint",
        &endpoint,
    ]);
    let plain = run_verify(&["--json", "--time", time]);

    assert_eq!(
        flagged.status.code(),
        plain.status.code(),
        "exit code unchanged"
    );

    let mut flagged_value: Value =
        serde_json::from_str(&String::from_utf8(flagged.stdout).unwrap()).unwrap();
    assert!(flagged_value
        .as_object_mut()
        .unwrap()
        .remove("encypher_api")
        .is_some());
    let flagged_local = serde_json::to_string_pretty(&flagged_value).unwrap();
    let plain_local = String::from_utf8(plain.stdout).unwrap();
    assert_eq!(
        flagged_local,
        plain_local.trim_end(),
        "local report bytes must be identical apart from the added key"
    );
}

#[test]
fn human_mode_appends_trailing_block_without_disturbing_local_lines() {
    let body = r#"{"success":true,"found":true,"verification_url":"https://verify.example/doc_test123","organization_name":"Test Org","media_type":"video"}"#;
    let (endpoint, _requests) = spawn_lookup_server("HTTP/1.1 200 OK", body);
    let flagged = run_verify(&["--encypher-api", "--encypher-api-endpoint", &endpoint]);
    let plain = run_verify(&[]);

    assert_eq!(flagged.status.code(), plain.status.code());
    let flagged_out = String::from_utf8(flagged.stdout).unwrap();
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    assert!(
        flagged_out.starts_with(&plain_out),
        "local human lines must be an unchanged prefix:\nflagged:\n{flagged_out}\nplain:\n{plain_out}"
    );
    let trailing = &flagged_out[plain_out.len()..];
    assert_eq!(
        trailing,
        "encypher api: found\n  verification url: https://verify.example/doc_test123\n  organization: Test Org\n  media type: video\n"
    );
}

#[test]
fn unreachable_endpoint_yields_error_object_and_stable_exit() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
    drop(listener); // the port now refuses connections, so the lookup fails fast

    let flagged = run_verify(&[
        "--json",
        "--encypher-api",
        "--encypher-api-endpoint",
        &endpoint,
    ]);
    let plain = run_verify(&["--json"]);
    assert_eq!(
        flagged.status.code(),
        plain.status.code(),
        "unreachable lookup must not change the exit code"
    );

    let value: Value = serde_json::from_str(&String::from_utf8(flagged.stdout).unwrap()).unwrap();
    let api = value.get("encypher_api").expect("encypher_api present");
    assert_eq!(
        api.get("error").and_then(Value::as_str),
        Some("unreachable")
    );
    let stderr = String::from_utf8(flagged.stderr).unwrap();
    assert!(
        stderr.contains("encypher api unreachable"),
        "a stderr warning is expected: {stderr}"
    );
}

#[test]
fn non_2xx_yields_error_object_without_changing_exit() {
    let (endpoint, _requests) =
        spawn_lookup_server("HTTP/1.1 500 Internal Server Error", r#"{"error":"boom"}"#);
    let flagged = run_verify(&[
        "--json",
        "--encypher-api",
        "--encypher-api-endpoint",
        &endpoint,
    ]);
    let plain = run_verify(&["--json"]);
    assert_eq!(flagged.status.code(), plain.status.code());

    let value: Value = serde_json::from_str(&String::from_utf8(flagged.stdout).unwrap()).unwrap();
    let api = value.get("encypher_api").unwrap();
    assert_eq!(
        api.get("error").and_then(Value::as_str),
        Some("http_status")
    );
    assert_eq!(api.get("status").and_then(Value::as_u64), Some(500));
}
