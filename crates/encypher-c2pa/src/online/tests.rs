// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Online-check tests.
//!
//! Nothing here reaches the public internet. The address policy is tested as a
//! pure function, the fetcher against an in-process server bound to
//! `127.0.0.1`, and the orchestration against an injected fetcher.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;

use super::*;
use crate::online_consent::{set_interactive_online_consent, OnlinePreference};
use crate::VerifyOptions;

/// Tests that read or write process-wide state - the environment, the
/// interactive-consent flag, the configuration directory - run one at a time.
static PROCESS_STATE: Mutex<()> = Mutex::new(());

fn process_state() -> MutexGuard<'static, ()> {
    PROCESS_STATE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

// ---------------------------------------------------------------------------
// Address policy
// ---------------------------------------------------------------------------

#[cfg(feature = "online")]
mod addresses {
    use super::super::native::blocked_reason;
    use std::net::IpAddr;

    fn reason(address: &str) -> Option<&'static str> {
        blocked_reason(address.parse::<IpAddr>().expect("test address"))
    }

    #[test]
    fn every_range_a_file_could_point_at_internally_is_refused() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.13.7.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "100::1",
        ] {
            assert!(
                reason(address).is_some(),
                "{address} must not be contactable"
            );
        }
    }

    /// An IPv6 address that carries an IPv4 one reaches that IPv4 host, so the
    /// four ways of writing 169.254.169.254 in IPv6 are all the metadata
    /// service.
    #[test]
    fn an_ipv4_address_wrapped_in_ipv6_is_judged_as_that_ipv4_address() {
        for address in [
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "64:ff9b::169.254.169.254",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                reason(address).is_some(),
                "{address} must not be contactable"
            );
        }
    }

    #[test]
    fn ordinary_public_addresses_are_contactable() {
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "198.20.0.1",
            "2606:4700::1111",
            "2001:db9::1",
        ] {
            assert_eq!(reason(address), None, "{address} must be contactable");
        }
    }
}

// ---------------------------------------------------------------------------
// An in-process HTTP server
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    target: String,
    content_type: Option<String>,
    user_agent: Option<String>,
    body: Vec<u8>,
}

/// A one-thread HTTP/1.1 server on `127.0.0.1`, driven by a closure that sees
/// the request count and the parsed request.
struct TestServer {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl TestServer {
    fn start<F>(respond: F) -> Self
    where
        F: Fn(usize, &Request) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
        let address = listener.local_addr().expect("listener address");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                let index = counter.fetch_add(1, Ordering::SeqCst);
                let response = respond(index, &request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        Self { address, hits }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut start = String::new();
    reader.read_line(&mut start).ok()?;
    let mut parts = start.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut content_length = 0_usize;
    let mut content_type = None;
    let mut user_agent = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match name.to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "content-type" => content_type = Some(value),
            "user-agent" => user_agent = Some(value),
            _ => {}
        }
    }
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(Request {
        method,
        target,
        content_type,
        user_agent,
        body,
    })
}

fn ok_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------
// The native fetcher
// ---------------------------------------------------------------------------

#[cfg(feature = "online")]
mod fetcher {
    use super::*;
    use crate::online::native::{join_redirect, NativeFetcher};

    fn manifest_request(url: &str) -> FetchRequest<'_> {
        FetchRequest {
            url,
            method: FetchMethod::Get,
            body: None,
            content_type: None,
            accept: Some("application/c2pa"),
            limit: 1024,
            allow_http: false,
        }
    }

    fn ocsp_request<'a>(url: &'a str, body: &'a [u8]) -> FetchRequest<'a> {
        FetchRequest {
            url,
            method: FetchMethod::Post,
            body: Some(body),
            content_type: Some("application/ocsp-request"),
            accept: Some("application/ocsp-response"),
            limit: 1024,
            allow_http: false,
        }
    }

    /// The default posture: a URL that resolves to a loopback address is
    /// refused by policy, and no connection is attempted.
    #[test]
    fn a_loopback_address_is_refused_before_anything_is_sent() {
        let server = TestServer::start(|_, _| ok_response("application/c2pa", b"store"));
        let url = format!("https://{}/store.c2pa", server.address);
        let error = NativeFetcher::new(false)
            .fetch(&manifest_request(&url))
            .expect_err("a loopback address must be refused");
        assert!(error.blocked, "{}", error.detail);
        assert!(error.detail.contains("loopback"), "{}", error.detail);
        assert_eq!(server.hits(), 0);
    }

    /// Plaintext is refused for everything except OCSP. The scheme is judged
    /// before a socket is opened, so the server never sees the request.
    #[test]
    fn plaintext_is_refused_for_anything_but_ocsp() {
        let server = TestServer::start(|_, _| ok_response("application/c2pa", b"store"));
        let url = server.url("/store.c2pa");
        let error = NativeFetcher::new(false)
            .fetch(&manifest_request(&url))
            .expect_err("http must be refused for a manifest store");
        assert!(error.blocked, "{}", error.detail);
        assert!(
            error.detail.contains("https is required"),
            "{}",
            error.detail
        );
        assert_eq!(server.hits(), 0);
    }

    /// An OCSP responder is reached over plain http by design, posts the DER
    /// request, and identifies this SDK by name and version.
    #[test]
    fn an_ocsp_request_is_posted_as_der_over_plain_http() {
        let (recorder, seen) = std::sync::mpsc::channel();
        let server = TestServer::start(move |_, request| {
            let _ = recorder.send((
                request.method.clone(),
                request.content_type.clone(),
                request.user_agent.clone(),
                request.body.clone(),
            ));
            ok_response("application/ocsp-response", b"\x30\x03signed")
        });
        let url = server.url("/ocsp");
        let response = NativeFetcher::new(true)
            .fetch(&ocsp_request(&url, b"der-request"))
            .expect("the responder answers");

        assert_eq!(response.bytes, b"\x30\x03signed");
        let (method, content_type, user_agent, body) = seen
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the server recorded the request");
        assert_eq!(method, "POST");
        assert_eq!(content_type.as_deref(), Some("application/ocsp-request"));
        assert_eq!(
            user_agent.as_deref(),
            Some(concat!("encypher-c2pa/", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(&body[..], b"der-request");
    }

    #[test]
    fn a_body_over_the_limit_is_refused_rather_than_read() {
        let server =
            TestServer::start(|_, _| ok_response("application/ocsp-response", &vec![0x41; 4096]));
        let url = server.url("/ocsp");
        let error = NativeFetcher::new(true)
            .fetch(&FetchRequest {
                limit: 512,
                ..ocsp_request(&url, b"der")
            })
            .expect_err("an oversized body must be refused");
        assert!(error.blocked, "{}", error.detail);
        assert!(error.detail.contains("512 byte limit"), "{}", error.detail);
    }

    /// Each hop is judged afresh, so a server cannot redirect its way to a
    /// scheme this SDK refused at the start.
    #[test]
    fn a_redirect_to_a_refused_scheme_is_blocked_at_that_hop() {
        let server = TestServer::start(|_, _| redirect_response("ftp://files.invalid/store.c2pa"));
        let url = server.url("/ocsp");
        let error = NativeFetcher::new(true)
            .fetch(&ocsp_request(&url, b"der"))
            .expect_err("the redirect target must be refused");
        assert!(error.blocked, "{}", error.detail);
        assert!(error.detail.contains("ftp"), "{}", error.detail);
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn a_redirect_chain_stops_at_the_hop_limit() {
        let server = TestServer::start(|index, _| redirect_response(&format!("/hop-{index}")));
        let url = server.url("/ocsp");
        let error = NativeFetcher::new(true)
            .fetch(&ocsp_request(&url, b"der"))
            .expect_err("an endless redirect chain must stop");
        assert!(error.blocked, "{}", error.detail);
        assert!(error.detail.contains("redirects"), "{}", error.detail);
        // The first request plus the three hops it is allowed to follow.
        assert_eq!(server.hits(), 4);
        assert_eq!(error.requests_used, 4);
    }

    #[test]
    fn a_redirect_within_the_limit_is_followed_to_the_body() {
        let server = TestServer::start(|index, request| {
            if index == 0 {
                redirect_response("/final")
            } else {
                ok_response("application/ocsp-response", request.target.as_bytes())
            }
        });
        let url = server.url("/ocsp");
        let response = NativeFetcher::new(true)
            .fetch(&ocsp_request(&url, b"der"))
            .expect("the redirect is followed");
        assert_eq!(response.bytes, b"/final");
        assert_eq!(response.requests_used, 2);
    }

    #[test]
    fn a_server_error_is_a_failure_rather_than_a_refusal() {
        let server = TestServer::start(|_, _| {
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_vec()
        });
        let url = server.url("/ocsp");
        let error = NativeFetcher::new(true)
            .fetch(&ocsp_request(&url, b"der"))
            .expect_err("503 is not an answer");
        assert!(!error.blocked, "{}", error.detail);
        assert!(error.detail.contains("503"), "{}", error.detail);
    }

    #[test]
    fn redirect_targets_resolve_against_the_url_that_produced_them() {
        let base = "https://store.test/a/b/store.c2pa?v=1";
        assert_eq!(
            join_redirect(base, "https://other.test/x").as_deref(),
            Some("https://other.test/x")
        );
        assert_eq!(
            join_redirect(base, "/root.c2pa").as_deref(),
            Some("https://store.test/root.c2pa")
        );
        assert_eq!(
            join_redirect(base, "next.c2pa").as_deref(),
            Some("https://store.test/a/b/next.c2pa")
        );
        assert_eq!(
            join_redirect(base, "//elsewhere.test/x").as_deref(),
            Some("https://elsewhere.test/x")
        );
        assert_eq!(join_redirect(base, "  "), None);
    }
}

// ---------------------------------------------------------------------------
// Consent resolution
// ---------------------------------------------------------------------------

fn temporary_config_dir(name: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-state")
        .join(format!("online-gather-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("test configuration directory");
    path
}

fn save_choice(directory: &std::path::Path, token: &str) {
    std::fs::write(
        directory.join("online.json"),
        format!("{{\"online\":\"{token}\"}}"),
    )
    .expect("write the saved choice");
}

fn needs() -> Vec<NetworkNeed> {
    vec![NetworkNeed::RemoteManifest {
        uri: "https://store.test/a.c2pa".to_string(),
    }]
}

/// A library call resolves the explicit option, then the operator's
/// environment override, and stops. The saved file belongs to the terminal.
#[test]
fn a_library_call_never_reads_the_saved_choice() {
    let _guard = process_state();
    let directory = temporary_config_dir("library-ignores-file");
    save_choice(&directory, "on");
    std::env::set_var("ENCYPHER_C2PA_CONFIG_DIR", &directory);
    std::env::remove_var("ENCYPHER_C2PA_ONLINE");
    set_interactive_online_consent(false);

    assert!(!resolve_online(&VerifyOptions::default(), &needs()));

    // The same saved choice does govern a surface that opted in.
    set_interactive_online_consent(true);
    assert!(resolve_online(&VerifyOptions::default(), &needs()));

    set_interactive_online_consent(false);
    std::env::remove_var("ENCYPHER_C2PA_CONFIG_DIR");
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn the_environment_override_beats_the_saved_choice() {
    let _guard = process_state();
    let directory = temporary_config_dir("env-precedence");
    save_choice(&directory, "on");
    std::env::set_var("ENCYPHER_C2PA_CONFIG_DIR", &directory);
    set_interactive_online_consent(true);

    std::env::set_var("ENCYPHER_C2PA_ONLINE", "off");
    assert!(!resolve_online(&VerifyOptions::default(), &needs()));
    assert_eq!(
        crate::online_consent::online_preference().unwrap(),
        Some(OnlinePreference::Off)
    );

    save_choice(&directory, "off");
    std::env::set_var("ENCYPHER_C2PA_ONLINE", "on");
    assert!(resolve_online(&VerifyOptions::default(), &needs()));

    // An unreadable override fails closed rather than falling back to a file
    // the operator has just tried to override.
    std::env::set_var("ENCYPHER_C2PA_ONLINE", "maybe");
    save_choice(&directory, "on");
    assert!(!resolve_online(&VerifyOptions::default(), &needs()));

    set_interactive_online_consent(false);
    std::env::remove_var("ENCYPHER_C2PA_ONLINE");
    std::env::remove_var("ENCYPHER_C2PA_CONFIG_DIR");
    let _ = std::fs::remove_dir_all(directory);
}

/// The explicit option is the caller's decision and outranks the operator's.
#[test]
fn an_explicit_option_beats_the_environment() {
    let _guard = process_state();
    std::env::set_var("ENCYPHER_C2PA_ONLINE", "on");
    assert!(!resolve_online(
        &VerifyOptions {
            online: Some(false),
            ..VerifyOptions::default()
        },
        &needs()
    ));
    std::env::set_var("ENCYPHER_C2PA_ONLINE", "off");
    assert!(resolve_online(
        &VerifyOptions {
            online: Some(true),
            ..VerifyOptions::default()
        },
        &needs()
    ));
    std::env::remove_var("ENCYPHER_C2PA_ONLINE");
}

/// `ask` with nobody to ask stays offline. The test process has no terminal on
/// stdin, which is exactly the cron job and CI case.
#[test]
fn a_run_with_nobody_to_ask_stays_offline() {
    let _guard = process_state();
    let directory = temporary_config_dir("ask-noninteractive");
    save_choice(&directory, "ask");
    std::env::set_var("ENCYPHER_C2PA_CONFIG_DIR", &directory);
    std::env::remove_var("ENCYPHER_C2PA_ONLINE");
    set_interactive_online_consent(true);

    assert!(!resolve_online(&VerifyOptions::default(), &needs()));

    // And so does a machine that has never been asked.
    std::fs::remove_file(directory.join("online.json")).expect("remove the saved choice");
    assert!(!resolve_online(&VerifyOptions::default(), &needs()));

    set_interactive_online_consent(false);
    std::env::remove_var("ENCYPHER_C2PA_CONFIG_DIR");
    let _ = std::fs::remove_dir_all(directory);
}

// ---------------------------------------------------------------------------
// Orchestration with an injected fetcher
// ---------------------------------------------------------------------------

struct ScriptedFetcher {
    answers: HashMap<String, Result<Vec<u8>, String>>,
    calls: AtomicUsize,
}

impl ScriptedFetcher {
    fn new(answers: &[(&str, Result<&[u8], &str>)]) -> Self {
        Self {
            answers: answers
                .iter()
                .map(|(url, answer)| {
                    (
                        (*url).to_string(),
                        match answer {
                            Ok(bytes) => Ok(bytes.to_vec()),
                            Err(detail) => Err((*detail).to_string()),
                        },
                    )
                })
                .collect(),
            calls: AtomicUsize::new(0),
        }
    }
}

impl Fetcher for ScriptedFetcher {
    fn fetch(&self, request: &FetchRequest<'_>) -> FetchResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.get(request.url) {
            Some(Ok(bytes)) => Ok(FetchOk {
                bytes: bytes.clone(),
                requests_used: 1,
            }),
            Some(Err(detail)) => Err(FetchErr {
                blocked: false,
                detail: detail.clone(),
                requests_used: 1,
            }),
            None => Err(FetchErr {
                blocked: true,
                detail: format!("{} was not scripted", request.url),
                requests_used: 1,
            }),
        }
    }
}

#[test]
fn each_kind_of_need_is_filed_as_the_evidence_it_is() {
    let needs = vec![
        NetworkNeed::RemoteManifest {
            uri: "https://store.test/a.c2pa".to_string(),
        },
        NetworkNeed::Ocsp {
            purpose: OcspPurpose::ClaimSigner,
            responder_url: "http://ocsp.test/".to_string(),
            request_der: b"der".to_vec(),
            certificate_sha256_hex: "aa11".to_string(),
        },
        NetworkNeed::Ocsp {
            purpose: OcspPurpose::CawgIdentity {
                assertion_label: "cawg.identity".to_string(),
            },
            responder_url: "http://ocsp.test/identity".to_string(),
            request_der: b"der2".to_vec(),
            certificate_sha256_hex: "bb22".to_string(),
        },
        NetworkNeed::DidDocument {
            did: "did:web:issuer.test".to_string(),
            url: "https://issuer.test/.well-known/did.json".to_string(),
        },
        NetworkNeed::ExternalData {
            uri: "https://cdn.test/data.bin".to_string(),
            assertion_label: "c2pa.cloud-data".to_string(),
        },
    ];
    let fetcher = ScriptedFetcher::new(&[
        ("https://store.test/a.c2pa", Ok(b"manifest-store")),
        ("http://ocsp.test/", Ok(b"\x30\x03ok")),
        ("http://ocsp.test/identity", Err("connection refused")),
        (
            "https://issuer.test/.well-known/did.json",
            Ok(br#"{"id":"did:web:issuer.test"}"#),
        ),
        ("https://cdn.test/data.bin", Ok(b"abc")),
    ]);

    let (requests, evidence) = fetch_all(&fetcher, &needs);

    assert_eq!(
        evidence.manifest_store.as_deref(),
        Some(&b"manifest-store"[..])
    );
    assert_eq!(
        evidence.ocsp_responses.get("aa11").map(String::as_str),
        Some("MANvaw==")
    );
    assert_eq!(evidence.ocsp_unreachable, vec!["bb22".to_string()]);
    assert_eq!(
        evidence.did_documents.get("did:web:issuer.test"),
        Some(&json!({"id": "did:web:issuer.test"}))
    );
    assert_eq!(
        evidence
            .external_data
            .get("https://cdn.test/data.bin")
            .map(String::as_str),
        Some("YWJj")
    );

    let outcomes: Vec<(&str, &str)> = requests
        .iter()
        .map(|request| (request.purpose.as_str(), request.outcome.as_str()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("remote_manifest", "fetched"),
            ("ocsp.claim_signer", "fetched"),
            ("ocsp.cawg_identity", "failed"),
            ("did_document", "fetched"),
            ("external_data", "fetched"),
        ]
    );
}

/// One verification gets a fixed number of requests. A manifest that names
/// hundreds of external resources cannot turn this SDK into a crawler.
#[test]
fn the_request_budget_bounds_one_verification() {
    let urls: Vec<String> = (0..20)
        .map(|index| format!("https://cdn.test/{index}.bin"))
        .collect();
    let script: Vec<(&str, Result<&[u8], &str>)> = urls
        .iter()
        .map(|url| (url.as_str(), Ok(&b"x"[..])))
        .collect();
    let fetcher = ScriptedFetcher::new(&script);
    let needs: Vec<NetworkNeed> = urls
        .iter()
        .map(|uri| NetworkNeed::ExternalData {
            uri: uri.clone(),
            assertion_label: "c2pa.cloud-data".to_string(),
        })
        .collect();

    let (requests, _) = fetch_all(&fetcher, &needs);

    assert_eq!(fetcher.calls.load(Ordering::SeqCst), MAX_REQUESTS);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.outcome == "fetched")
            .count(),
        MAX_REQUESTS
    );
    let skipped: Vec<&NetworkRequest> = requests
        .iter()
        .filter(|request| request.outcome == "skipped")
        .collect();
    assert_eq!(skipped.len(), 20 - MAX_REQUESTS);
    assert!(skipped[0].detail.contains("budget"), "{skipped:?}");
}

/// Offline is not silence: the report still says what a fetch would settle.
#[test]
fn an_offline_run_still_lists_what_it_could_have_checked() {
    let _guard = process_state();
    std::env::remove_var("ENCYPHER_C2PA_ONLINE");
    set_interactive_online_consent(false);

    let (network, evidence) = gather(&VerifyOptions::default(), &needs());

    assert!(!network.enabled);
    assert!(network.requests.is_empty());
    assert!(evidence.is_empty());
    assert_eq!(
        network.needed,
        vec![json!({"kind": "remote_manifest", "uri": "https://store.test/a.c2pa"})]
    );
}

#[test]
fn pass_two_receives_the_evidence_and_never_fetches_again() {
    let mut evidence = OnlineEvidence::default();
    evidence.did_documents.insert(
        "did:web:issuer.test".to_string(),
        json!({"id": "did:web:issuer.test"}),
    );
    let options = VerifyOptions {
        online: Some(true),
        ..VerifyOptions::default()
    };

    let next = apply_evidence(&options, &evidence);

    assert_eq!(next.online, Some(false));
    assert_eq!(
        next.cawg_did_documents
            .as_ref()
            .and_then(|documents| documents.get("did:web:issuer.test")),
        Some(&json!({"id": "did:web:issuer.test"}))
    );
}

/// A caller's own pinned DID documents are kept; a fetched one is added.
#[test]
fn fetched_did_documents_extend_the_caller_supplied_store() {
    let mut pinned = HashMap::new();
    pinned.insert("did:web:pinned.test".to_string(), json!({"id": "pinned"}));
    let options = VerifyOptions {
        cawg_did_documents: Some(pinned),
        ..VerifyOptions::default()
    };
    let mut evidence = OnlineEvidence::default();
    evidence
        .did_documents
        .insert("did:web:fetched.test".to_string(), json!({"id": "fetched"}));

    let next = apply_evidence(&options, &evidence);
    let documents = next.cawg_did_documents.expect("a merged store");

    assert_eq!(documents.len(), 2);
    assert!(documents.contains_key("did:web:pinned.test"));
    assert!(documents.contains_key("did:web:fetched.test"));
}

// ---------------------------------------------------------------------------
// Report shape
// ---------------------------------------------------------------------------

#[test]
fn the_network_block_serializes_as_the_documented_shape() {
    let report = NetworkReport {
        enabled: true,
        needed: vec![json!({"kind": "remote_manifest", "uri": "https://store.test/a.c2pa"})],
        requests: vec![NetworkRequest {
            purpose: "remote_manifest".to_string(),
            url: "https://store.test/a.c2pa".to_string(),
            outcome: "fetched".to_string(),
            detail: "1024 bytes".to_string(),
        }],
    };
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        json!({
            "enabled": true,
            "needed": [{"kind": "remote_manifest", "uri": "https://store.test/a.c2pa"}],
            "requests": [{
                "purpose": "remote_manifest",
                "url": "https://store.test/a.c2pa",
                "outcome": "fetched",
                "detail": "1024 bytes",
            }],
        })
    );
}

/// An older report has no `network` block, and must still deserialize.
#[test]
fn a_report_without_a_network_block_still_reads() {
    let report: NetworkReport = serde_json::from_str("{}").unwrap();
    assert!(!report.enabled);
    assert!(report.needed.is_empty());
}

#[test]
fn every_need_describes_itself_for_the_prompt_and_the_report() {
    let need = NetworkNeed::Ocsp {
        purpose: OcspPurpose::CawgIdentity {
            assertion_label: "cawg.identity".to_string(),
        },
        responder_url: "http://ocsp.identity.test:8080/check".to_string(),
        request_der: Vec::new(),
        certificate_sha256_hex: "ff00".to_string(),
    };
    assert_eq!(need.purpose_token(), "ocsp.cawg_identity");
    assert_eq!(
        need.to_json(),
        json!({
            "kind": "ocsp",
            "purpose": "cawg_identity",
            "assertion_label": "cawg.identity",
            "responder_url": "http://ocsp.identity.test:8080/check",
            "certificate_sha256": "ff00",
        })
    );
    assert!(
        need.consent_line().ends_with("from ocsp.identity.test"),
        "{}",
        need.consent_line()
    );
}

#[test]
fn a_host_is_read_out_of_a_url_without_its_port_or_credentials() {
    assert_eq!(host_of("https://store.test/a.c2pa"), "store.test");
    assert_eq!(host_of("https://store.test:8443/a"), "store.test");
    assert_eq!(host_of("https://user:pass@store.test/a"), "store.test");
    assert_eq!(host_of("https://[2001:db8::1]:8443/a"), "[2001:db8::1]");
    assert_eq!(host_of("not a url"), "not a url");
}

#[test]
fn base64_matches_rfc_4648_including_padding() {
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}
