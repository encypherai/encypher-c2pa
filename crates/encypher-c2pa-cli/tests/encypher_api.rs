//! Contract guards for opt-in `--encypher-api` server verification.
//!
//! These pin the privacy and stability contract: default verification makes no
//! network call, the flag sends the exact file digest plus detached C2PA
//! evidence but never the media payload, and failures never alter the local
//! report or exit code. The mock server is a bare std `TcpListener`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

const PATH_LIMIT: u64 = 128 * 1024 * 1024;
fn signed_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed_test.mp4")
}

fn run_verify_path(asset: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(asset)
        .args(args)
        .output()
        .expect("run CLI")
}

fn run_verify(args: &[&str]) -> Output {
    run_verify_path(&signed_fixture(), args)
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

/// Bind a one-shot verification server returning `status_line` + `body`.
/// Returns the endpoint URL and the raw request observed by the server.
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
fn flag_attaches_verbatim_response_without_uploading_media() {
    let body = r#"{"protocol":"encypher-local-verification/1","asset":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":22022,"mime":"video/mp4"},"server_manifest_validation":{"status":"valid","signature_valid":true,"trust":"trusted"},"local_claims":{"manifest_store_match":true,"binding_match":true,"signature_match":true,"trust_match":true},"encypher_registry":{"artifact_match":true,"binding_match":true,"document_id":"doc_test123","verification_url":"https://verify.example/doc_test123","media_type":"video","basis":"client_computed_sha256_and_server_validated_binding"}}"#;
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
    assert_eq!(value.get("encypher_api"), Some(&expected));

    let sent = request_body(&requests.recv_timeout(Duration::from_secs(4)).unwrap());
    let expected_bytes = std::fs::read(signed_fixture()).unwrap();
    assert_eq!(sent["protocol"], "encypher-local-verification/1");
    assert_eq!(
        sent["asset"]["sha256"],
        hex::encode(Sha256::digest(&expected_bytes))
    );
    assert_eq!(sent["asset"]["size_bytes"], expected_bytes.len());
    assert_eq!(sent["asset"]["mime"], "video/mp4");
    assert_eq!(
        sent["local_validation"]["binding"]["algorithm"],
        "c2pa.hash.bmff.v3"
    );
    assert_eq!(sent["local_validation"]["binding"]["status"], "match");
    let manifest = BASE64
        .decode(sent["c2pa"]["manifest_store_b64"].as_str().unwrap())
        .unwrap();
    let carrier = BASE64
        .decode(sent["c2pa"]["carrier_b64"].as_str().unwrap())
        .unwrap();
    assert!(!manifest.is_empty());
    assert!(carrier.len() < expected_bytes.len());
    assert_eq!(
        sent["c2pa"]["manifest_store_sha256"],
        hex::encode(Sha256::digest(&manifest))
    );
    assert!(sent.get("file").is_none());
    assert!(sent.get("media").is_none());
    assert!(sent.get("signed_file_b64").is_none());
    assert!(sent.get("asset_b64").is_none());
}

#[test]
fn api_flag_rejects_oversized_asset_before_lookup() {
    let path = std::env::temp_dir().join(format!(
        "encypher-c2pa-cli-oversized-{}.mp4",
        std::process::id()
    ));
    let file = std::fs::File::create(&path).expect("create sparse asset");
    file.set_len(PATH_LIMIT + 1).expect("size sparse asset");
    drop(file);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
    let output = run_verify_path(
        &path,
        &["--encypher-api", "--encypher-api-endpoint", &endpoint],
    );
    std::fs::remove_file(&path).expect("remove sparse asset");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("128 MiB path limit"),
        "expected bounded-reader rejection: {stderr}"
    );
    let lookup = listener.accept();
    assert!(
        matches!(&lookup, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "lookup must not occur before source rejection: {lookup:?}"
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
    let body = r#"{"protocol":"encypher-local-verification/1","asset":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":22022,"mime":"video/mp4"},"server_manifest_validation":{"status":"valid","signature_valid":true,"trust":"trusted"},"local_claims":{"manifest_store_match":true,"binding_match":true,"signature_match":true,"trust_match":true},"encypher_registry":{"artifact_match":true,"binding_match":true,"document_id":"doc_test123","verification_url":"https://verify.example/doc_test123","media_type":"video","basis":"client_computed_sha256_and_server_validated_binding"}}"#;
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
        "encypher api: manifest valid\n  artifact match: yes\n  binding match: yes\n  verification url: https://verify.example/doc_test123\n"
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
