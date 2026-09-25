// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! End-to-end online checks through the command line.
//!
//! The asset declares where its manifest store lives. Offline, that is
//! reported and nothing is contacted. With `--online` the store is fetched
//! from an in-process server on `127.0.0.1` and the asset verifies against it.
//! No test here reaches beyond the loopback interface.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::Value;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name),
    )
    .expect("fixture must be readable")
}

/// `signed_test.jpg` with its embedded manifest segment replaced, byte for
/// byte, by an XMP segment that names where the store lives.
///
/// Same length, same position, so the bytes the signed data hash covers are
/// untouched: the file has no manifest inside it any more, but the store in
/// `signed_test.c2pa` still binds to it.
fn jpeg_declaring_remote_manifest(uri: &str) -> Vec<u8> {
    let original = fixture("signed_test.jpg");
    assert_eq!(
        &original[20..22],
        &[0xFF, 0xEB],
        "the fixture must carry its manifest in an APP11 segment at offset 20"
    );
    let declared = usize::from(u16::from_be_bytes([original[22], original[23]]));
    let segment_end = 22 + declared;

    const XMP_HEADER: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
    let head = format!(
        concat!(
            r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>"#,
            r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF"#,
            r#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#,
            r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/""#,
            r#" dcterms:provenance="{}"/></rdf:RDF></x:xmpmeta>"#,
        ),
        uri
    );
    let tail = r#"<?xpacket end="w"?>"#;
    let payload_len = declared - 2;
    let padding = payload_len - XMP_HEADER.len() - head.len() - tail.len();

    let mut segment = vec![0xFF, 0xE1];
    segment.extend_from_slice(&u16::try_from(declared).unwrap().to_be_bytes());
    segment.extend_from_slice(XMP_HEADER);
    segment.extend_from_slice(head.as_bytes());
    segment.extend(std::iter::repeat_n(b' ', padding));
    segment.extend_from_slice(tail.as_bytes());
    assert_eq!(segment.len(), segment_end - 20);

    let mut asset = original[..20].to_vec();
    asset.extend_from_slice(&segment);
    asset.extend_from_slice(&original[segment_end..]);
    asset
}

/// Serves one path over plain http on the loopback interface.
struct ManifestServer {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl ManifestServer {
    fn start(path: &'static str, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
        let address = listener.local_addr().expect("listener address");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(&stream);
                let mut start = String::new();
                if reader.read_line(&mut start).is_err() {
                    continue;
                }
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) if line.trim_end().is_empty() => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let response = if start.contains(path) {
                    let mut head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/c2pa\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes();
                    head.extend_from_slice(&body);
                    head
                } else {
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_vec()
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        Self { address, hits }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}

fn state_dir(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-state")
        .join(format!("cli-online-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("test state directory");
    path
}

fn run_verify(asset: &Path, config_dir: &Path, extra: &[&str]) -> (Option<i32>, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .arg("verify")
        .arg(asset)
        .arg("--json")
        .arg("--no-telemetry")
        .args(extra)
        .env("ENCYPHER_C2PA_CONFIG_DIR", config_dir)
        .env_remove("ENCYPHER_C2PA_ONLINE")
        .output()
        .expect("run the CLI");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let report = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!(
            "CLI did not print a report ({error})\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), report)
}

#[test]
fn a_declared_manifest_store_is_reported_offline_and_fetched_when_allowed() {
    let store = fixture("signed_test.c2pa");
    let server = ManifestServer::start("/store.c2pa", store);
    let uri = server.url("/store.c2pa");
    let asset_bytes = jpeg_declaring_remote_manifest(&uri);
    let config = state_dir("declared-store");
    let asset = config.join("declared.jpg");
    std::fs::write(&asset, &asset_bytes).expect("write the test asset");

    // Offline: the declaration is reported, the store is not fetched, and the
    // report says exactly what allowing a fetch would settle.
    let (code, offline) = run_verify(&asset, &config, &[]);
    assert_eq!(code, Some(2), "an unresolved manifest is not a pass");
    assert!(
        offline["validation_results"]["failure"]
            .as_array()
            .expect("failures")
            .iter()
            .any(|status| status["code"] == "manifest.inaccessible"),
        "{offline:#}"
    );
    assert_eq!(offline["network"]["enabled"], Value::Bool(false));
    assert_eq!(
        offline["network"]["needed"],
        serde_json::json!([{"kind": "remote_manifest", "uri": uri}])
    );
    assert_eq!(
        offline["network"]["requests"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        server.hits.load(Ordering::SeqCst),
        0,
        "an offline run must not contact the manifest repository"
    );

    // Online: the store is fetched from the loopback server and the asset
    // verifies against it, hard binding and all.
    let (code, online) = run_verify(
        &asset,
        &config,
        &["--online", "--online-allow-private-networks"],
    );
    assert_eq!(code, Some(0), "{online:#}");
    assert_eq!(online["integrity"], "valid", "{online:#}");
    assert_eq!(online["hard_binding"], "match", "{online:#}");
    assert_eq!(online["network"]["enabled"], Value::Bool(true));
    let request = &online["network"]["requests"][0];
    assert_eq!(request["purpose"], "remote_manifest");
    assert_eq!(request["url"], uri.as_str());
    assert_eq!(request["outcome"], "fetched", "{online:#}");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);

    let _ = std::fs::remove_dir_all(config);
}

/// `--offline` overrides a saved `on`, and the saved choice governs a run that
/// passes no flag at all.
#[test]
fn the_saved_choice_governs_and_a_flag_overrides_it() {
    let store = fixture("signed_test.c2pa");
    let server = ManifestServer::start("/store.c2pa", store);
    let uri = server.url("/store.c2pa");
    let config = state_dir("saved-choice");
    let asset = config.join("declared.jpg");
    std::fs::write(&asset, jpeg_declaring_remote_manifest(&uri)).expect("write the test asset");
    std::fs::write(config.join("online.json"), br#"{"online":"on"}"#).expect("save the choice");

    let (_, forced_offline) = run_verify(&asset, &config, &["--offline"]);
    assert_eq!(forced_offline["network"]["enabled"], Value::Bool(false));
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);

    let (code, saved) = run_verify(&asset, &config, &["--online-allow-private-networks"]);
    assert_eq!(code, Some(0), "{saved:#}");
    assert_eq!(saved["network"]["enabled"], Value::Bool(true));
    assert_eq!(saved["integrity"], "valid", "{saved:#}");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);

    let _ = std::fs::remove_dir_all(config);
}

/// Without the intranet flag a loopback manifest repository is refused by the
/// address policy, and the run reports why rather than silently going offline.
#[test]
fn a_loopback_repository_is_refused_unless_the_operator_opted_in() {
    let store = fixture("signed_test.c2pa");
    let server = ManifestServer::start("/store.c2pa", store);
    let uri = server.url("/store.c2pa");
    let config = state_dir("loopback-refused");
    let asset = config.join("declared.jpg");
    std::fs::write(&asset, jpeg_declaring_remote_manifest(&uri)).expect("write the test asset");

    let (code, report) = run_verify(&asset, &config, &["--online"]);

    assert_eq!(code, Some(2), "{report:#}");
    assert_eq!(report["network"]["enabled"], Value::Bool(true));
    let request = &report["network"]["requests"][0];
    assert_eq!(request["outcome"], "blocked", "{report:#}");
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);

    let _ = std::fs::remove_dir_all(config);
}

#[test]
fn the_online_subcommand_round_trips_the_saved_choice() {
    let config = state_dir("subcommand");
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
            .args(args)
            .env("ENCYPHER_C2PA_CONFIG_DIR", &config)
            .env_remove("ENCYPHER_C2PA_ONLINE")
            .output()
            .expect("run the CLI");
        assert!(output.status.success(), "{args:?}");
        String::from_utf8(output.stdout).expect("utf8 stdout")
    };

    assert!(run(&["online", "status"]).contains("No choice"));
    run(&["online", "on"]);
    assert!(run(&["online", "status"]).contains("allowed"));
    run(&["online", "ask"]);
    assert!(run(&["online", "status"]).contains("each time"));
    run(&["online", "off"]);
    assert!(run(&["online", "status"]).contains("refused"));

    let _ = std::fs::remove_dir_all(config);
}
