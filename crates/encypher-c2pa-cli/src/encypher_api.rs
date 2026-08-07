//! Opt-in Encypher provenance lookup for the `verify` subcommand.
//!
//! This is an explicit, per-invocation network call gated behind
//! `--encypher-api`. It sends only a SHA-256 digest of the exact asset bytes,
//! renders Encypher's record as a separate section, and never influences the
//! local verdict or the process exit code. Any failure degrades to a small
//! error object plus a one-line stderr warning; it never panics.

use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Default Encypher provenance lookup endpoint. Overridable via the hidden
/// `--encypher-api-endpoint` flag for self-hosting and tests, mirroring the
/// failure-telemetry endpoint override.
pub const DEFAULT_ENDPOINT: &str = "https://api.encypher.com/api/v1/lookup";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = concat!(
    "encypher-c2pa-cli/",
    env!("CARGO_PKG_VERSION"),
    " (+https://encypher.com/c2pa)"
);

/// Lowercase hex SHA-256 of the exact asset bytes.
pub fn content_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Query the Encypher provenance lookup for a content hash. Returns the
/// verbatim parsed JSON on a 2xx response, or a small error object on any
/// transport, status, or decode failure (also writing one stderr warning).
/// Never panics, never propagates; the caller renders the value and the local
/// verdict and exit code stay unchanged.
pub fn lookup(endpoint: &str, content_sha256: &str) -> Value {
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let response = agent
        .post(endpoint)
        .set("User-Agent", USER_AGENT)
        .send_json(json!({ "content_sha256": content_sha256 }));
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

/// Print the lookup result as a trailing human-readable block. Mirrors the
/// `encypher_api` JSON key without changing any local report line above it.
pub fn render_human(result: &Value) {
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        println!("encypher api: lookup failed ({error})");
        return;
    }
    let found = result
        .get("found")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !found {
        println!("encypher api: not found");
        return;
    }
    println!("encypher api: found");
    if let Some(url) = result.get("verification_url").and_then(Value::as_str) {
        println!("  verification url: {url}");
    }
    if let Some(org) = result.get("organization_name").and_then(Value::as_str) {
        println!("  organization: {org}");
    }
    if let Some(media) = result.get("media_type").and_then(Value::as_str) {
        println!("  media type: {media}");
    }
}
