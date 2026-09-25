// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Opt-in online checks.
//!
//! The verification kernel stays pure and offline. When a file references
//! something only a server can settle - a manifest store held elsewhere, the
//! revocation status of a signing certificate, the DID document of an identity
//! issuer, content stored outside the asset - the kernel records the need and
//! reports it. Nothing is fetched unless the caller said yes.
//!
//! A verification that fetches runs twice. Pass 1 is the ordinary offline
//! verification and produces the list of needs. The fetcher retrieves what was
//! allowed. Pass 2 is another ordinary offline verification, with the fetched
//! material handed in as caller-supplied evidence. The same bytes and the same
//! evidence therefore always produce the same verdict, and the network can
//! only ever add evidence, never change how it is judged.
//!
//! The fetcher is deliberately narrow. It speaks https only, except to OCSP
//! responders, whose answers are signed and verified before they count. Every
//! hostname is resolved through a filter that rejects loopback, private,
//! link-local, carrier-NAT, unique-local, multicast and documentation
//! addresses, and the connection uses the address that was vetted, so a name
//! that changes its answer between the check and the connection cannot reach
//! an internal service. Asset bytes never leave the machine: an OCSP request
//! carries a certificate serial number and issuer hashes, nothing else.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::online_consent::{
    environment_online, interactive_online_consent_allowed, prompt_for_online_consent,
    saved_online_preference, OnlinePreference,
};
use crate::VerifyOptions;

/// Largest manifest store this SDK will accept from a server, matching the
/// limit the offline entry points already apply to a caller-supplied store.
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
/// An OCSP response is a signed status for one certificate. Anything larger is
/// not one.
const MAX_OCSP_BYTES: usize = 64 * 1024;
/// A DID document is a small JSON object.
const MAX_DID_DOCUMENT_BYTES: usize = 256 * 1024;
/// Externally stored assertion content, bounded like a manifest store.
const MAX_EXTERNAL_DATA_BYTES: usize = 64 * 1024 * 1024;
/// Total HTTP requests one verification may make, redirects included.
const MAX_REQUESTS: usize = 16;

pub(crate) use crate::c2pa_validate::{NetworkNeed, OcspPurpose};

/// What a verification did, or could have done, on the network.
///
/// `needed` lists what a fetch could settle and is filled in whether or not
/// online checks were allowed, so an offline caller can see exactly what
/// turning them on would do. Its entries are the kernel's own description of
/// each need. `requests` records every attempt, including the ones that were
/// refused.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetworkReport {
    /// Whether this verification was allowed to fetch.
    pub enabled: bool,
    /// Every network resource this asset references.
    pub needed: Vec<Value>,
    /// Every request that was attempted.
    pub requests: Vec<NetworkRequest>,
}

impl NetworkReport {
    /// Record that a body arrived but could not be used for what it was
    /// fetched for. The request happened, so it is not removed; its outcome
    /// stops being a success.
    pub(crate) fn mark_unusable(&mut self, purpose: &str, detail: String) {
        if let Some(request) = self
            .requests
            .iter_mut()
            .find(|request| request.purpose == purpose && request.outcome == "fetched")
        {
            request.outcome = "failed".to_string();
            request.detail = detail;
        }
    }
}

/// One attempted fetch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkRequest {
    /// `remote_manifest`, `ocsp.claim_signer`, `ocsp.cawg_identity`,
    /// `did_document`, or `external_data`.
    pub purpose: String,
    /// The URL that was requested.
    pub url: String,
    /// `fetched`, `failed`, `blocked`, or `skipped`.
    ///
    /// `blocked` means this SDK refused: a forbidden address, a plaintext URL,
    /// an oversized body, too many redirects. `failed` means the server or the
    /// network did not deliver. `skipped` means the request was never made.
    pub outcome: String,
    /// Why, in one line.
    pub detail: String,
}

/// Material fetched for pass 2, in the shape the offline entry points already
/// accept from a caller who fetched it themselves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OnlineEvidence {
    /// A manifest store retrieved from the URI the asset declares.
    pub(crate) manifest_store: Option<Vec<u8>>,
    /// Certificate SHA-256 (lowercase hex) -> base64 DER OCSPResponse.
    pub(crate) ocsp_responses: HashMap<String, String>,
    /// Certificate SHA-256 (lowercase hex) whose responder gave no usable answer.
    pub(crate) ocsp_unreachable: Vec<String>,
    /// Need URI -> base64 content bytes.
    pub(crate) external_data: HashMap<String, String>,
    /// Primary DID -> DID document.
    pub(crate) did_documents: HashMap<String, Value>,
}

impl OnlineEvidence {
    pub(crate) fn is_empty(&self) -> bool {
        self.manifest_store.is_none()
            && self.ocsp_responses.is_empty()
            && self.ocsp_unreachable.is_empty()
            && self.external_data.is_empty()
            && self.did_documents.is_empty()
    }
}

impl NetworkNeed {
    /// The token used in [`NetworkRequest::purpose`].
    pub(crate) fn purpose_token(&self) -> &'static str {
        match self {
            Self::RemoteManifest { .. } => "remote_manifest",
            Self::Ocsp {
                purpose: OcspPurpose::ClaimSigner,
                ..
            } => "ocsp.claim_signer",
            Self::Ocsp { .. } => "ocsp.cawg_identity",
            Self::DidDocument { .. } => "did_document",
            Self::ExternalData { .. } => "external_data",
        }
    }

    /// The URL that would be contacted.
    pub(crate) fn url(&self) -> &str {
        match self {
            Self::RemoteManifest { uri } => uri,
            Self::Ocsp { responder_url, .. } => responder_url,
            Self::DidDocument { url, .. } => url,
            Self::ExternalData { uri, .. } => uri,
        }
    }

    /// One prompt line: what this is for, and who would learn about the file.
    fn consent_line(&self) -> String {
        let what = match self {
            Self::RemoteManifest { .. } => "the manifest store this file points to".to_string(),
            Self::Ocsp {
                purpose: OcspPurpose::ClaimSigner,
                ..
            } => "whether the signing certificate has been revoked".to_string(),
            Self::Ocsp {
                purpose: OcspPurpose::CawgIdentity { assertion_label },
                ..
            } => format!("whether the identity certificate in {assertion_label} has been revoked"),
            Self::DidDocument { did, .. } => format!("the issuer document for {did}"),
            Self::ExternalData {
                assertion_label, ..
            } => format!("content stored outside the file, for {assertion_label}"),
        };
        format!("{what}, from {}", host_of(self.url()))
    }
}

/// The needs recorded by one kernel verification.
pub(crate) fn network_needs(output: &crate::c2pa_validate::VerifyOutput) -> Vec<NetworkNeed> {
    output.network_needs.clone()
}

/// Decide whether this verification may fetch, fetch what it may, and report.
///
/// The decision order is explicit option, then the `ENCYPHER_C2PA_ONLINE`
/// operator override, then - on a terminal surface only - the saved choice and
/// a prompt. A library call stops after the environment variable: it may be
/// verifying an untrusted file on a server, where a choice somebody made at a
/// laptop must not switch fetching on.
pub(crate) fn gather(
    options: &VerifyOptions,
    needs: &[NetworkNeed],
) -> (NetworkReport, OnlineEvidence) {
    let needed: Vec<Value> = needs.iter().map(NetworkNeed::to_json).collect();
    let enabled = resolve_online(options, needs);
    if !enabled || needs.is_empty() {
        return (
            NetworkReport {
                enabled,
                needed,
                requests: Vec::new(),
            },
            OnlineEvidence::default(),
        );
    }
    let fetcher = new_fetcher(options.online_allow_private_networks);
    let (requests, evidence) = fetch_all(fetcher.as_ref(), needs);
    (
        NetworkReport {
            enabled: true,
            needed,
            requests,
        },
        evidence,
    )
}

fn resolve_online(options: &VerifyOptions, needs: &[NetworkNeed]) -> bool {
    if let Some(explicit) = options.online {
        return explicit;
    }
    match environment_online() {
        Ok(Some(enabled)) => return enabled,
        Ok(None) => {}
        // An operator typed something this SDK does not understand. Fetching is
        // the side with consequences, so an unreadable override stays off.
        Err(_) => return false,
    }
    if !interactive_online_consent_allowed() || needs.is_empty() {
        return false;
    }
    match saved_online_preference() {
        Ok(Some(OnlinePreference::On)) => true,
        Ok(Some(OnlinePreference::Off)) => false,
        Ok(Some(OnlinePreference::Ask)) | Ok(None) => {
            let lines: Vec<String> = needs.iter().map(NetworkNeed::consent_line).collect();
            prompt_for_online_consent(&lines)
                .ok()
                .flatten()
                .unwrap_or(false)
        }
        Err(_) => false,
    }
}

/// Build the options for pass 2 from what was fetched.
pub(crate) fn apply_evidence(options: &VerifyOptions, evidence: &OnlineEvidence) -> VerifyOptions {
    let mut next = options.clone();
    // Pass 2 verifies with what pass 1 obtained. It never fetches again, so a
    // server that answers differently on a second request cannot extend the
    // work one verification does.
    next.online = Some(false);
    if !evidence.did_documents.is_empty() {
        let mut documents = next.cawg_did_documents.unwrap_or_default();
        documents.extend(
            evidence
                .did_documents
                .iter()
                .map(|(did, document)| (did.clone(), document.clone())),
        );
        next.cawg_did_documents = Some(documents);
    }
    if !evidence.ocsp_responses.is_empty() {
        let mut responses = next.ocsp_responses.unwrap_or_default();
        responses.extend(evidence.ocsp_responses.clone());
        next.ocsp_responses = Some(responses);
    }
    if !evidence.ocsp_unreachable.is_empty() {
        let mut unreachable = next.ocsp_unreachable.unwrap_or_default();
        unreachable.extend(evidence.ocsp_unreachable.iter().cloned());
        next.ocsp_unreachable = Some(unreachable);
    }
    if !evidence.external_data.is_empty() {
        let mut data = next.external_data.unwrap_or_default();
        data.extend(evidence.external_data.clone());
        next.external_data = Some(data);
    }
    next
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchMethod {
    Get,
    Post,
}

/// One outbound request, fully described by policy rather than by the caller.
#[cfg_attr(
    not(feature = "online"),
    allow(dead_code, reason = "only the native fetcher reads a request")
)]
pub(crate) struct FetchRequest<'a> {
    pub(crate) url: &'a str,
    pub(crate) method: FetchMethod,
    pub(crate) body: Option<&'a [u8]>,
    pub(crate) content_type: Option<&'a str>,
    pub(crate) accept: Option<&'a str>,
    /// Maximum body this request may accept.
    pub(crate) limit: usize,
    /// True only for OCSP, whose responses are signed and verified.
    pub(crate) allow_http: bool,
}

#[derive(Debug)]
pub(crate) struct FetchOk {
    pub(crate) bytes: Vec<u8>,
    pub(crate) requests_used: usize,
}

#[derive(Debug)]
pub(crate) struct FetchErr {
    /// True when this SDK refused, false when the network or server did.
    pub(crate) blocked: bool,
    pub(crate) detail: String,
    pub(crate) requests_used: usize,
}

pub(crate) type FetchResult = Result<FetchOk, FetchErr>;

pub(crate) trait Fetcher {
    fn fetch(&self, request: &FetchRequest<'_>) -> FetchResult;
}

fn blocked(detail: impl Into<String>, requests_used: usize) -> FetchErr {
    FetchErr {
        blocked: true,
        detail: detail.into(),
        requests_used,
    }
}

/// Run every need through `fetcher`, within the request budget.
pub(crate) fn fetch_all(
    fetcher: &dyn Fetcher,
    needs: &[NetworkNeed],
) -> (Vec<NetworkRequest>, OnlineEvidence) {
    let mut requests = Vec::with_capacity(needs.len());
    let mut evidence = OnlineEvidence::default();
    let mut budget = MAX_REQUESTS;

    for need in needs {
        let purpose = need.purpose_token().to_string();
        let url = need.url().to_string();
        if budget == 0 {
            requests.push(NetworkRequest {
                purpose,
                url,
                outcome: "skipped".to_string(),
                detail: format!("the {MAX_REQUESTS} request budget for one verification is spent"),
            });
            if let NetworkNeed::Ocsp {
                certificate_sha256_hex,
                ..
            } = need
            {
                push_unreachable(&mut evidence, certificate_sha256_hex);
            }
            continue;
        }

        let request = match need {
            NetworkNeed::RemoteManifest { uri } => FetchRequest {
                url: uri,
                method: FetchMethod::Get,
                body: None,
                content_type: None,
                accept: Some("application/c2pa"),
                limit: MAX_MANIFEST_BYTES,
                allow_http: false,
            },
            NetworkNeed::Ocsp {
                responder_url,
                request_der,
                ..
            } => FetchRequest {
                url: responder_url,
                method: FetchMethod::Post,
                body: Some(request_der),
                content_type: Some("application/ocsp-request"),
                accept: Some("application/ocsp-response"),
                limit: MAX_OCSP_BYTES,
                // RFC 6960 responders are reached over plain HTTP by design:
                // the response is signed, and this SDK verifies that signature
                // before the answer counts for anything.
                allow_http: true,
            },
            NetworkNeed::DidDocument { url, .. } => FetchRequest {
                url,
                method: FetchMethod::Get,
                body: None,
                content_type: None,
                accept: Some("application/did+json, application/json"),
                limit: MAX_DID_DOCUMENT_BYTES,
                allow_http: false,
            },
            NetworkNeed::ExternalData { uri, .. } => FetchRequest {
                url: uri,
                method: FetchMethod::Get,
                body: None,
                content_type: None,
                accept: None,
                limit: MAX_EXTERNAL_DATA_BYTES,
                allow_http: false,
            },
        };

        let (outcome, detail) = match fetcher.fetch(&request) {
            Ok(FetchOk {
                bytes,
                requests_used,
            }) => {
                budget = budget.saturating_sub(requests_used.max(1));
                accept_evidence(&mut evidence, need, bytes)
            }
            Err(FetchErr {
                blocked,
                detail,
                requests_used,
            }) => {
                budget = budget.saturating_sub(requests_used.max(1));
                if let NetworkNeed::Ocsp {
                    certificate_sha256_hex,
                    ..
                } = need
                {
                    push_unreachable(&mut evidence, certificate_sha256_hex);
                }
                (
                    if blocked { "blocked" } else { "failed" }.to_string(),
                    detail,
                )
            }
        };
        requests.push(NetworkRequest {
            purpose,
            url,
            outcome,
            detail,
        });
    }

    (requests, evidence)
}

fn push_unreachable(evidence: &mut OnlineEvidence, certificate_sha256_hex: &str) {
    if !evidence
        .ocsp_unreachable
        .iter()
        .any(|existing| existing == certificate_sha256_hex)
    {
        evidence
            .ocsp_unreachable
            .push(certificate_sha256_hex.to_string());
    }
}

/// File one fetched body under the evidence it is, and say what happened.
fn accept_evidence(
    evidence: &mut OnlineEvidence,
    need: &NetworkNeed,
    bytes: Vec<u8>,
) -> (String, String) {
    let length = bytes.len();
    match need {
        NetworkNeed::RemoteManifest { .. } => {
            evidence.manifest_store = Some(bytes);
            ("fetched".to_string(), format!("{length} bytes"))
        }
        NetworkNeed::Ocsp {
            certificate_sha256_hex,
            ..
        } => {
            evidence
                .ocsp_responses
                .insert(certificate_sha256_hex.clone(), base64_encode(&bytes));
            ("fetched".to_string(), format!("{length} bytes"))
        }
        NetworkNeed::DidDocument { did, .. } => match serde_json::from_slice::<Value>(&bytes) {
            Ok(document) => {
                evidence.did_documents.insert(did.clone(), document);
                ("fetched".to_string(), format!("{length} bytes"))
            }
            Err(error) => (
                "failed".to_string(),
                format!("the DID document is not JSON: {error}"),
            ),
        },
        NetworkNeed::ExternalData { uri, .. } => {
            evidence
                .external_data
                .insert(uri.clone(), base64_encode(&bytes));
            ("fetched".to_string(), format!("{length} bytes"))
        }
    }
}

// ---------------------------------------------------------------------------
// URL handling
// ---------------------------------------------------------------------------

/// Split a URL into scheme, authority, and the rest. `None` when it is not an
/// absolute URL this SDK can reason about.
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, remainder) = url.split_once("://")?;
    if scheme.is_empty() || remainder.is_empty() {
        return None;
    }
    let end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let (authority, rest) = remainder.split_at(end);
    if authority.is_empty() {
        return None;
    }
    Some((scheme, authority, rest))
}

/// The hostname a URL would contact, for the consent prompt.
fn host_of(url: &str) -> String {
    let Some((_, authority, _)) = split_url(url) else {
        return url.to_string();
    };
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(end) = authority.find(']') {
        return authority[..=end].to_string();
    }
    authority
        .split_once(':')
        .map_or(authority, |(host, _)| host)
        .to_string()
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/// Standard base64 (RFC 4648) with padding, the encoding the caller-supplied
/// evidence options already use.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------
// The native fetcher
// ---------------------------------------------------------------------------

#[cfg(feature = "online")]
fn new_fetcher(allow_private_networks: bool) -> Box<dyn Fetcher> {
    Box::new(native::NativeFetcher::new(allow_private_networks))
}

#[cfg(not(feature = "online"))]
fn new_fetcher(_allow_private_networks: bool) -> Box<dyn Fetcher> {
    Box::new(DisabledFetcher)
}

/// The fetcher of a build compiled without the `online` feature. It refuses
/// every request rather than pretending none was needed.
#[cfg(not(feature = "online"))]
struct DisabledFetcher;

#[cfg(not(feature = "online"))]
impl Fetcher for DisabledFetcher {
    fn fetch(&self, _request: &FetchRequest<'_>) -> FetchResult {
        Err(blocked(
            "this build was compiled without the online feature",
            0,
        ))
    }
}

#[cfg(feature = "online")]
pub(crate) mod native {
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
    use std::time::Duration;
    use std::{io, net};

    use super::{
        blocked, split_url, FetchErr, FetchMethod, FetchOk, FetchRequest, FetchResult, Fetcher,
    };

    /// Redirect hops allowed per request. Every hop is re-checked.
    const MAX_REDIRECTS: usize = 3;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    const USER_AGENT: &str = concat!("encypher-c2pa/", env!("CARGO_PKG_VERSION"));
    /// Marker planted in the resolver's error so the fetcher can tell a refusal
    /// by policy from a name that simply does not resolve.
    const BLOCKED_ADDRESS_MARKER: &str = "address is not permitted";

    fn failed(detail: impl Into<String>, requests_used: usize) -> FetchErr {
        FetchErr {
            blocked: false,
            detail: detail.into(),
            requests_used,
        }
    }

    /// Why an address may not be contacted, or `None` when it may.
    ///
    /// This is the whole address policy in one readable function, so it can be
    /// tested one range at a time.
    pub(crate) fn blocked_reason(address: IpAddr) -> Option<&'static str> {
        match address {
            IpAddr::V4(address) => blocked_reason_v4(address),
            IpAddr::V6(address) => blocked_reason_v6(address),
        }
    }

    fn blocked_reason_v4(address: Ipv4Addr) -> Option<&'static str> {
        let [a, b, c, _] = address.octets();
        Some(match (a, b, c) {
            (0, _, _) => "unspecified network",
            (10, _, _) => "private network",
            (100, 64..=127, _) => "carrier-grade NAT",
            (127, _, _) => "loopback",
            (169, 254, _) => "link-local, including the cloud metadata service",
            (172, 16..=31, _) => "private network",
            (192, 0, 0) => "IETF protocol assignment",
            (192, 0, 2) => "documentation",
            (192, 168, _) => "private network",
            (198, 18..=19, _) => "benchmarking",
            (198, 51, 100) => "documentation",
            (203, 0, 113) => "documentation",
            (224..=239, _, _) => "multicast",
            (240..=255, _, _) => "reserved or broadcast",
            _ => return None,
        })
    }

    fn blocked_reason_v6(address: Ipv6Addr) -> Option<&'static str> {
        // An address that carries an IPv4 one - mapped, compatible, 6to4,
        // NAT64 - reaches the IPv4 host it names, so it is judged as that host.
        if let Some(embedded) = embedded_ipv4(address) {
            if let Some(reason) = blocked_reason_v4(embedded) {
                return Some(reason);
            }
        }
        let segments = address.segments();
        if address.is_unspecified() {
            return Some("unspecified address");
        }
        if address.is_loopback() {
            return Some("loopback");
        }
        if address.is_multicast() {
            return Some("multicast");
        }
        Some(match segments[0] {
            first if first & 0xfe00 == 0xfc00 => "unique local",
            first if first & 0xffc0 == 0xfe80 => "link-local",
            0x2001 if segments[1] == 0x0db8 => "documentation",
            0x0100 if segments[1] == 0 && segments[2] == 0 && segments[3] == 0 => "discard-only",
            _ => return None,
        })
    }

    fn embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
        let segments = address.segments();
        let octets = address.octets();
        let tail = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        // ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible, deprecated).
        if segments[0..5] == [0, 0, 0, 0, 0] && (segments[5] == 0xffff || segments[5] == 0) {
            return Some(tail);
        }
        // 2002:a.b.c.d::/16, the 6to4 prefix.
        if segments[0] == 0x2002 {
            return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
        }
        // 64:ff9b::/96 and 64:ff9b:1::/48, the NAT64 prefixes.
        if segments[0] == 0x0064 && segments[1] == 0xff9b {
            return Some(tail);
        }
        None
    }

    /// Resolve a `Location` header against the URL that produced it.
    pub(crate) fn join_redirect(base: &str, location: &str) -> Option<String> {
        let location = location.trim();
        if location.is_empty() {
            return None;
        }
        if location.contains("://") {
            return Some(location.to_string());
        }
        let (scheme, authority, rest) = split_url(base)?;
        if let Some(network_path) = location.strip_prefix("//") {
            return Some(format!("{scheme}://{network_path}"));
        }
        if location.starts_with('/') {
            return Some(format!("{scheme}://{authority}{location}"));
        }
        let path = rest.split(['?', '#']).next().unwrap_or("");
        let directory = path.rfind('/').map_or("/", |index| &path[..=index]);
        Some(format!("{scheme}://{authority}{directory}{location}"))
    }

    /// Resolves names and drops every address this SDK must not contact.
    ///
    /// The filter sits in the resolver rather than in front of it, so the
    /// connection uses an address that was vetted. Checking a hostname and then
    /// letting the stack resolve it again leaves a window in which the answer
    /// can change to an internal one.
    pub(crate) struct FilteringResolver {
        pub(crate) allow_private_networks: bool,
    }

    impl ureq::Resolver for FilteringResolver {
        fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
            let resolved: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
            if self.allow_private_networks {
                return Ok(resolved);
            }
            let mut refused: Option<(net::IpAddr, &'static str)> = None;
            let permitted: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|address| match blocked_reason(address.ip()) {
                    Some(reason) => {
                        refused.get_or_insert((address.ip(), reason));
                        false
                    }
                    None => true,
                })
                .collect();
            if permitted.is_empty() {
                let detail = match refused {
                    Some((address, reason)) => format!(
                        "{netloc} resolves to {address}, a {reason} {BLOCKED_ADDRESS_MARKER}"
                    ),
                    None => format!("{netloc} resolves to no address"),
                };
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, detail));
            }
            Ok(permitted)
        }
    }

    pub(crate) struct NativeFetcher {
        agent: ureq::Agent,
        /// Intranet mode: the address filter is off, and plaintext http is
        /// allowed for every purpose rather than for OCSP alone. An operator
        /// who sets it has declared this deployment's own network trusted; a
        /// manifest repository on an internal host is routinely plain http.
        intranet: bool,
    }

    impl NativeFetcher {
        pub(crate) fn new(allow_private_networks: bool) -> Self {
            Self {
                agent: ureq::AgentBuilder::new()
                    .timeout_connect(CONNECT_TIMEOUT)
                    .timeout(REQUEST_TIMEOUT)
                    // Redirects are followed here, one hop at a time, so that
                    // every hop's scheme and address are checked afresh.
                    .redirects(0)
                    .user_agent(USER_AGENT)
                    .resolver(FilteringResolver {
                        allow_private_networks,
                    })
                    .build(),
                intranet: allow_private_networks,
            }
        }
    }

    impl Fetcher for NativeFetcher {
        fn fetch(&self, request: &FetchRequest<'_>) -> FetchResult {
            let mut url = request.url.to_string();
            let mut used = 0;

            for hop in 0..=MAX_REDIRECTS {
                match split_url(&url) {
                    None => return Err(blocked(format!("{url} is not an absolute URL"), used)),
                    Some((scheme, _, _)) if scheme.eq_ignore_ascii_case("https") => {}
                    Some((scheme, _, _))
                        if (request.allow_http || self.intranet)
                            && scheme.eq_ignore_ascii_case("http") => {}
                    Some((scheme, _, _)) => {
                        return Err(blocked(
                            format!("{scheme} is not allowed for this request; https is required"),
                            used,
                        ))
                    }
                }

                used += 1;
                let mut call = match request.method {
                    FetchMethod::Get => self.agent.get(&url),
                    FetchMethod::Post => self.agent.post(&url),
                };
                if let Some(content_type) = request.content_type {
                    call = call.set("content-type", content_type);
                }
                if let Some(accept) = request.accept {
                    call = call.set("accept", accept);
                }
                let response = match request.body {
                    Some(body) => call.send_bytes(body),
                    None => call.call(),
                };
                let response = match response {
                    Ok(response) => response,
                    Err(ureq::Error::Status(status, _)) => {
                        return Err(failed(format!("the server answered HTTP {status}"), used))
                    }
                    Err(ureq::Error::Transport(transport)) => {
                        let detail = transport.to_string();
                        return Err(if detail.contains(BLOCKED_ADDRESS_MARKER) {
                            blocked(detail, used)
                        } else {
                            failed(detail, used)
                        });
                    }
                };

                if (300..400).contains(&response.status()) {
                    if hop == MAX_REDIRECTS {
                        return Err(blocked(
                            format!("more than {MAX_REDIRECTS} redirects"),
                            used,
                        ));
                    }
                    let Some(location) = response.header("location") else {
                        return Err(failed("a redirect carried no location", used));
                    };
                    let Some(next) = join_redirect(&url, location) else {
                        return Err(failed(format!("unusable redirect to {location}"), used));
                    };
                    url = next;
                    continue;
                }

                return read_body(response, request.limit, used);
            }
            Err(blocked(
                format!("more than {MAX_REDIRECTS} redirects"),
                used,
            ))
        }
    }

    fn read_body(response: ureq::Response, limit: usize, used: usize) -> FetchResult {
        let mut bytes = Vec::new();
        let capped = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        if let Err(error) = response.into_reader().take(capped).read_to_end(&mut bytes) {
            return Err(failed(error.to_string(), used));
        }
        if bytes.len() > limit {
            return Err(blocked(
                format!("the response is larger than the {limit} byte limit"),
                used,
            ));
        }
        Ok(FetchOk {
            bytes,
            requests_used: used,
        })
    }
}

// Test-only: `online/tests.rs` carries `#![cfg(test)]` itself.
mod tests;
