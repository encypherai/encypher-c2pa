// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! The update check through the command line, against an index served on
//! `127.0.0.1`. No test here reaches beyond the loopback interface.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Serves `body` for every request and counts them.
struct IndexServer {
    url: String,
    hits: Arc<AtomicUsize>,
}

impl IndexServer {
    fn start(body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/en/cy/encypher-c2pa-cli",
            listener.local_addr().unwrap()
        );
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|read| read > 2) {
                    line.clear();
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { url, hits }
    }
}

fn index_line(version: &str) -> String {
    format!(
        r#"{{"name":"encypher-c2pa-cli","vers":"{version}","deps":[],"cksum":"00","features":{{}},"yanked":false}}"#
    )
}

fn config_dir(test: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("encypher-update-{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn cli(config: &Path, index_url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .args(args)
        .env("ENCYPHER_C2PA_CONFIG_DIR", config)
        .env("ENCYPHER_C2PA_UPDATE_INDEX_URL", index_url)
        .env_remove("ENCYPHER_C2PA_UPDATE_CHECK")
        .env("CARGO_HOME", config.join("cargo-home"))
        .output()
        .unwrap()
}

#[test]
fn a_run_with_nobody_at_the_terminal_never_checks_for_updates() {
    let server = IndexServer::start(index_line("99.0.0"));
    let config = config_dir("noninteractive");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/signed_test.jpg");

    let output = cli(
        &config,
        &server.url,
        &["verify", fixture.to_str().unwrap(), "--no-telemetry"],
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(server.hits.load(Ordering::SeqCst), 0);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("is available"));
    assert!(
        !config.join("update.json").exists(),
        "no check, so nothing recorded"
    );
}

#[test]
fn update_offers_the_newest_release_with_the_cargo_command() {
    let current = env!("CARGO_PKG_VERSION");
    let config = config_dir("offer");

    let latest = IndexServer::start(index_line(current));
    let output = cli(&config, &latest.url, &["update"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("is the latest release"));

    let newer = IndexServer::start(format!("{}\n{}", index_line(current), index_line("99.0.0")));
    let output = cli(&config, &newer.url, &["update"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("encypher-c2pa 99.0.0 is available"),
        "{stdout}"
    );
    // The test binary is not in cargo's install directory, so nothing is
    // installed and the command is printed instead.
    assert!(
        stderr.contains("cargo install encypher-c2pa-cli --version 99.0.0 --locked"),
        "{stderr}"
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn update_check_off_is_saved_in_the_settings_file() {
    let config = config_dir("setting");
    let unused = "http://127.0.0.1:9/unused";

    let output = cli(&config, unused, &["update-check", "off"]);
    assert_eq!(output.status.code(), Some(0));
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.join("update.json")).unwrap()).unwrap();
    assert_eq!(saved["check"], false);

    let output = Command::new(env!("CARGO_BIN_EXE_encypher-c2pa"))
        .args(["update-check", "status"])
        .env("ENCYPHER_C2PA_CONFIG_DIR", &config)
        .env("ENCYPHER_C2PA_UPDATE_CHECK", "on")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("on (ENCYPHER_C2PA_UPDATE_CHECK overrides"),
        "the environment outranks the file"
    );
}
