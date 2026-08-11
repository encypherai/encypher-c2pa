//! Opt-in Encypher server verification for the `verify` subcommand.
//!
//! This is an explicit, per-invocation network call gated behind
//! `--encypher-api`. It sends the exact file SHA-256 and, when the container
//! supports it, the raw embedded C2PA manifest store plus its small carrier.
//! The asset bytes remain local. The response never influences the local
//! verdict or process exit code. Failures become a small error object and a
//! one-line stderr warning; this module never panics.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use encypher_c2pa::{DetachedManifestEvidence, VerificationReport};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Default authenticated endpoint for independent server-side validation.
/// Overridable through the hidden `--encypher-api-endpoint` flag for
/// self-hosting and tests.
pub const DEFAULT_ENDPOINT: &str = "https://api.encypher.com/api/v1/verify/local";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!(
    "encypher-c2pa-cli/",
    env!("CARGO_PKG_VERSION"),
    " (+https://encypher.com/c2pa)"
);

/// Lowercase hex SHA-256 of the exact asset bytes.
pub fn content_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn local_binding(report: &VerificationReport) -> Option<Value> {
    let active = report.manifest_report.get("active_manifest")?.as_str()?;
    let assertions = report
        .manifest_report
        .get("manifests")?
        .get(active)?
        .get("assertions")?
        .as_array()?;
    let assertion = assertions.iter().find(|assertion| {
        assertion
            .get("label")
            .and_then(Value::as_str)
            .is_some_and(|label| {
                label.starts_with("c2pa.hash.data") || label.starts_with("c2pa.hash.bmff")
            })
    })?;
    let algorithm = assertion.get("label")?.as_str()?;
    let encoded = assertion.get("data")?.get("hash")?.as_str()?;
    let digest = BASE64.decode(encoded).ok()?;
    Some(json!({
        "algorithm": algorithm,
        "digest": hex::encode(digest),
        "status": report.hard_binding,
    }))
}

fn request_body(
    bytes: &[u8],
    mime: &str,
    report: &VerificationReport,
    evidence: Option<&DetachedManifestEvidence>,
) -> Value {
    let c2pa = evidence.map(|evidence| {
        json!({
            "manifest_store_b64": BASE64.encode(&evidence.manifest_store),
            "manifest_store_sha256": evidence.manifest_store_sha256,
            "carrier_b64": BASE64.encode(&evidence.carrier),
        })
    });
    json!({
        "protocol": "encypher-local-verification/1",
        "asset": {
            "sha256": content_sha256(bytes),
            "size_bytes": bytes.len(),
            "mime": mime,
        },
        "local_validation": {
            "integrity": report.integrity,
            "signature": report.signature,
            "hard_binding": report.hard_binding,
            "trust": report.trust.status,
            "binding": local_binding(report),
        },
        "c2pa": c2pa,
    })
}

/// Ask Encypher to validate the detached manifest and match its binding and
/// exact file digest against registry records. Never propagates a remote error.
pub fn verify(
    endpoint: &str,
    api_key: Option<&str>,
    bytes: &[u8],
    mime: &str,
    report: &VerificationReport,
    evidence: Option<&DetachedManifestEvidence>,
) -> Value {
    let api_key = api_key.filter(|value| !value.trim().is_empty());
    let loopback = endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:");
    if api_key.is_none() && !loopback {
        eprintln!("warning: encypher api requires ENCYPHER_API_KEY");
        return json!({ "error": "missing_api_key" });
    }
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let request = agent.post(endpoint).set("User-Agent", USER_AGENT);
    let request = match api_key {
        Some(value) => request.set("Authorization", &format!("Bearer {value}")),
        None => request,
    };
    let response = request.send_json(request_body(bytes, mime, report, evidence));
    match response {
        Ok(resp) => match resp.into_json::<Value>() {
            Ok(value) => value,
            Err(error) => {
                eprintln!("warning: encypher api returned an unreadable response ({error})");
                json!({ "error": "invalid_response" })
            }
        },
        Err(ureq::Error::Status(code, _)) => {
            eprintln!("warning: encypher api returned HTTP status {code}");
            json!({ "error": "http_status", "status": code })
        }
        Err(ureq::Error::Transport(error)) => {
            eprintln!("warning: encypher api unreachable ({error})");
            json!({ "error": "unreachable" })
        }
    }
}

/// Print the server result as a trailing human-readable block without changing
/// any local report line above it.
pub fn render_human(result: &Value) {
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        println!("encypher api: verification failed ({error})");
        return;
    }
    let manifest = result.get("server_manifest_validation");
    println!(
        "encypher api: manifest {}",
        manifest
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("not_evaluated")
    );
    let registry = result.get("encypher_registry");
    println!(
        "  artifact match: {}",
        registry
            .and_then(|value| value.get("artifact_match"))
            .and_then(Value::as_bool)
            .map_or("unknown", |matched| if matched { "yes" } else { "no" })
    );
    println!(
        "  binding match: {}",
        registry
            .and_then(|value| value.get("binding_match"))
            .and_then(Value::as_bool)
            .map_or("unknown", |matched| if matched { "yes" } else { "no" })
    );
    if let Some(url) = registry
        .and_then(|value| value.get("verification_url"))
        .and_then(Value::as_str)
    {
        println!("  verification url: {url}");
    }
}
