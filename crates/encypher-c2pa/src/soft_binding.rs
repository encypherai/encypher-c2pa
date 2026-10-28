// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Read-only client for the C2PA Soft Binding Resolution API.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use url::Url;

use crate::online::{new_fetcher, FetchMethod, FetchRequest, Fetcher};
use crate::{verify_with_manifest_store, Error, VerificationReport, VerifyOptions};

const MAX_SERVICE_JSON_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_RESULTS: u16 = 10;
const MAX_RESULTS: u16 = 100;

/// Explicit consent carried by query variants that disclose asset material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftBindingDisclosureConsent {
    /// Upload the asset supplied for local verification to the resolution service.
    UploadAsset,
    /// Disclose the supplied asset reference to the resolution service.
    DiscloseReference,
}

/// One explicitly selected Soft Binding Resolution API query route.
///
/// Routes never fall back to one another. In particular, the resolver never
/// uploads `asset` unless `Content` is selected with `UploadAsset` consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case", deny_unknown_fields)]
pub enum SoftBindingQuery {
    /// `GET /matches/byBinding`, preferred for values that fit in a URL.
    BindingGet { alg: String, value: String },
    /// `POST /matches/byBinding`, for large values.
    BindingPost { alg: String, value: String },
    /// `POST /matches/byContent`, uploading the asset bytes.
    Content {
        #[serde(default)]
        alg: Option<String>,
        #[serde(default)]
        hint_alg: Option<String>,
        #[serde(default)]
        hint_value: Option<String>,
        consent: SoftBindingDisclosureConsent,
    },
    /// Optional `POST /matches/byReference`, disclosing an HTTPS asset URL.
    Reference {
        #[serde(default)]
        alg: Option<String>,
        #[serde(default)]
        hint_alg: Option<String>,
        #[serde(default)]
        hint_value: Option<String>,
        reference_url: String,
        asset_length: u64,
        #[serde(default)]
        asset_type: Option<String>,
        #[serde(default)]
        region: Option<Json>,
        consent: SoftBindingDisclosureConsent,
    },
}

impl SoftBindingQuery {
    fn algorithm(&self) -> Option<&str> {
        match self {
            Self::BindingGet { alg, .. } | Self::BindingPost { alg, .. } => Some(alg),
            Self::Content { alg, .. } | Self::Reference { alg, .. } => alg.as_deref(),
        }
    }

    fn hint_algorithm(&self) -> Option<&str> {
        match self {
            Self::Content { hint_alg, .. } | Self::Reference { hint_alg, .. } => {
                hint_alg.as_deref()
            }
            Self::BindingGet { .. } | Self::BindingPost { .. } => None,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        let nonempty = |value: &str, name: &str| {
            if value.trim().is_empty() {
                Err(Error::Verification(format!(
                    "soft-binding query requires non-empty {name}"
                )))
            } else {
                Ok(())
            }
        };
        match self {
            Self::BindingGet { alg, value } | Self::BindingPost { alg, value } => {
                nonempty(alg, "alg")?;
                nonempty(value, "value")?;
            }
            Self::Content {
                alg,
                hint_alg,
                hint_value,
                consent,
            } => {
                if *consent != SoftBindingDisclosureConsent::UploadAsset {
                    return Err(Error::Verification(
                        "byContent requires upload_asset consent".into(),
                    ));
                }
                validate_optional_query_fields(alg, hint_alg, hint_value)?;
            }
            Self::Reference {
                alg,
                hint_alg,
                hint_value,
                reference_url,
                asset_length,
                consent,
                ..
            } => {
                if *consent != SoftBindingDisclosureConsent::DiscloseReference {
                    return Err(Error::Verification(
                        "byReference requires disclose_reference consent".into(),
                    ));
                }
                validate_optional_query_fields(alg, hint_alg, hint_value)?;
                if *asset_length == 0 {
                    return Err(Error::Verification(
                        "byReference asset_length must be positive".into(),
                    ));
                }
                let reference = Url::parse(reference_url).map_err(|_| {
                    Error::Verification("byReference reference_url is not an absolute URL".into())
                })?;
                if reference.scheme() != "https" || reference.host_str().is_none() {
                    return Err(Error::Verification(
                        "byReference reference_url must be HTTPS".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_optional_query_fields(
    alg: &Option<String>,
    hint_alg: &Option<String>,
    hint_value: &Option<String>,
) -> Result<(), Error> {
    if alg.as_ref().is_some_and(|value| value.trim().is_empty()) {
        return Err(Error::Verification("soft-binding alg is empty".into()));
    }
    match (hint_alg, hint_value) {
        (None, None) => Ok(()),
        (Some(alg), Some(value)) if !alg.trim().is_empty() && !value.trim().is_empty() => Ok(()),
        _ => Err(Error::Verification(
            "soft-binding hint_alg and hint_value must be supplied together and non-empty".into(),
        )),
    }
}

/// Network and optional read-only evidence policy for soft-binding recovery.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SoftBindingResolverOptions {
    /// Exact allowed origins (`scheme://host[:port]`).
    pub allowed_origins: Vec<String>,
    /// Permit private/link-local destinations and plaintext HTTP for an
    /// explicitly trusted intranet deployment.
    pub allow_private_networks: bool,
    /// Maximum matches requested, from 1 through 100. Zero uses 10.
    pub max_results: u16,
    /// Fetch the service status document when discovery advertises one.
    pub fetch_status: bool,
    /// Fetch each recovered manifest's repository-reported receipt result.
    pub fetch_receipts: bool,
}

/// Service discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingDiscovery {
    pub api_endpoint: String,
    pub c2pa_specification_version: String,
    #[serde(default)]
    pub capabilities_endpoint: Option<String>,
    #[serde(default)]
    pub status_endpoint: Option<String>,
}

/// Service capability document. Unknown capability names remain visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingCapabilities {
    pub c2pa_specification_version: String,
    pub supported_capabilities: Vec<String>,
}

/// One registered algorithm returned by a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftBindingAlgorithm {
    pub alg: String,
}

/// Algorithms a service accepts for query operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SoftBindingAlgorithms {
    #[serde(default)]
    pub watermarks: Vec<SoftBindingAlgorithm>,
    #[serde(default)]
    pub fingerprints: Vec<SoftBindingAlgorithm>,
}

/// One query match from a local or federated repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingMatch {
    pub manifest_id: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub similarity_score: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct QueryResult {
    #[serde(default)]
    matches: Vec<SoftBindingMatch>,
}

/// Repository-reported receipt evidence. `server_reported_verified` is not a
/// local cryptographic receipt verdict.
#[derive(Debug, Clone, Serialize)]
pub struct SoftBindingReceiptEvidence {
    pub receipt: Json,
    pub server_reported_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_error: Option<String>,
}

/// A fetched manifest store and its ordinary local C2PA verification report.
#[derive(Debug, Serialize)]
pub struct RecoveredSoftBindingManifest {
    pub matched: SoftBindingMatch,
    #[serde(skip_serializing)]
    pub manifest_store: Vec<u8>,
    pub report: VerificationReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SoftBindingReceiptEvidence>,
}

/// Complete evidence from one read-only resolution flow.
#[derive(Debug, Serialize)]
pub struct SoftBindingResolution {
    pub discovery: SoftBindingDiscovery,
    pub capabilities: SoftBindingCapabilities,
    pub algorithms: SoftBindingAlgorithms,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Json>,
    pub recovered: Vec<RecoveredSoftBindingManifest>,
}

/// HTTP method emitted by the transport-independent resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftBindingHttpMethod {
    Get,
    Post,
}

/// One bounded read-only request emitted by [`SoftBindingResolverSession`].
pub struct SoftBindingFetchRequest<'a> {
    pub method: SoftBindingHttpMethod,
    pub url: &'a str,
    pub content_type: Option<&'a str>,
    pub accept: &'static str,
    pub body: Option<&'a [u8]>,
    pub max_response_bytes: usize,
}

enum RequestBody<'a> {
    None,
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl RequestBody<'_> {
    fn as_slice(&self) -> Option<&[u8]> {
        match self {
            Self::None => None,
            Self::Borrowed(bytes) => Some(bytes),
            Self::Owned(bytes) => Some(bytes),
        }
    }
}

enum PendingKind {
    Discovery,
    Capabilities,
    Status,
    Algorithms,
    Query,
    Manifest(SoftBindingMatch, Url),
    Receipt(usize),
}

struct PendingRequest<'a> {
    method: SoftBindingHttpMethod,
    url: Url,
    content_type: Option<&'a str>,
    accept: &'static str,
    body: RequestBody<'a>,
    max_response_bytes: usize,
    kind: PendingKind,
}

/// Transport-independent Soft Binding Resolution API state machine.
///
/// A transport MUST issue the exact method, URL, headers, and body returned by
/// `next_request`, refuse redirects, omit ambient credentials, enforce its own
/// egress policy, and pass the response's final URL to `accept_response`.
pub struct SoftBindingResolverSession<'a> {
    asset: &'a [u8],
    mime_type: &'a str,
    query: &'a SoftBindingQuery,
    verify_options: &'a VerifyOptions,
    options: &'a SoftBindingResolverOptions,
    root: Url,
    allowed: Vec<String>,
    max_results: u16,
    api: Option<Url>,
    discovery: Option<SoftBindingDiscovery>,
    capabilities: Option<SoftBindingCapabilities>,
    algorithms: Option<SoftBindingAlgorithms>,
    status: Option<Json>,
    matches: std::vec::IntoIter<SoftBindingMatch>,
    recovered: Vec<RecoveredSoftBindingManifest>,
    pending: Option<PendingRequest<'a>>,
}

impl<'a> SoftBindingResolverSession<'a> {
    pub fn new(
        asset: &'a [u8],
        mime_type: &'a str,
        service_root: &str,
        query: &'a SoftBindingQuery,
        verify_options: &'a VerifyOptions,
        options: &'a SoftBindingResolverOptions,
    ) -> Result<Self, Error> {
        verify_options.validate()?;
        if !crate::online::online_enabled(verify_options) {
            return Err(Error::Verification(
                "soft-binding resolution requires online=true or ENCYPHER_C2PA_ONLINE=on".into(),
            ));
        }
        if mime_type.trim().is_empty() {
            return Err(Error::Verification(
                "soft-binding MIME type is empty".into(),
            ));
        }
        query.validate()?;
        let allowed = allowed_origins(&options.allowed_origins)?;
        if allowed.is_empty() {
            return Err(Error::Verification(
                "soft-binding resolution requires at least one allowed origin".into(),
            ));
        }
        let root = Url::parse(service_root).map_err(|error| {
            Error::Verification(format!("invalid soft-binding service root: {error}"))
        })?;
        require_allowed(&root, &allowed)?;
        let max_results = match options.max_results {
            0 => DEFAULT_MAX_RESULTS,
            value @ 1..=MAX_RESULTS => value,
            value => {
                return Err(Error::Verification(format!(
                    "soft-binding max_results {value} exceeds {MAX_RESULTS}"
                )))
            }
        };
        let mut well_known = root.clone();
        well_known.set_path("/.well-known/c2pa-soft-binding-resolution");
        well_known.set_query(None);
        well_known.set_fragment(None);
        Ok(Self {
            asset,
            mime_type,
            query,
            verify_options,
            options,
            root,
            allowed,
            max_results,
            api: None,
            discovery: None,
            capabilities: None,
            algorithms: None,
            status: None,
            matches: Vec::new().into_iter(),
            recovered: Vec::new(),
            pending: Some(PendingRequest {
                method: SoftBindingHttpMethod::Get,
                url: well_known,
                content_type: None,
                accept: "application/json",
                body: RequestBody::None,
                max_response_bytes: MAX_SERVICE_JSON_BYTES,
                kind: PendingKind::Discovery,
            }),
        })
    }

    pub fn next_request(&self) -> Option<SoftBindingFetchRequest<'_>> {
        self.pending
            .as_ref()
            .map(|request| SoftBindingFetchRequest {
                method: request.method,
                url: request.url.as_str(),
                content_type: request.content_type,
                accept: request.accept,
                body: request.body.as_slice(),
                max_response_bytes: request.max_response_bytes,
            })
    }

    pub fn accept_response(&mut self, final_url: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let pending = self.pending.take().ok_or_else(|| {
            Error::Verification("soft-binding session has no pending request".into())
        })?;
        let final_url = Url::parse(final_url).map_err(|_| {
            Error::Verification("soft-binding transport returned an invalid final URL".into())
        })?;
        if final_url != pending.url {
            return Err(Error::Verification(
                "soft-binding redirect was refused".into(),
            ));
        }
        if bytes.len() > pending.max_response_bytes {
            return Err(Error::Verification(format!(
                "soft-binding response exceeds {} bytes",
                pending.max_response_bytes
            )));
        }
        match pending.kind {
            PendingKind::Discovery => self.accept_discovery(&bytes),
            PendingKind::Capabilities => self.accept_capabilities(&bytes),
            PendingKind::Status => self.accept_status(&bytes),
            PendingKind::Algorithms => self.accept_algorithms(&bytes),
            PendingKind::Query => self.accept_matches(&bytes),
            PendingKind::Manifest(matched, repository) => {
                self.accept_manifest(matched, repository, bytes)
            }
            PendingKind::Receipt(index) => self.accept_receipt(index, &bytes),
        }
    }

    pub fn finish(self) -> Result<SoftBindingResolution, Error> {
        if self.pending.is_some() {
            return Err(Error::Verification(
                "soft-binding session still has a pending request".into(),
            ));
        }
        Ok(SoftBindingResolution {
            discovery: self.discovery.ok_or_else(|| {
                Error::Verification("soft-binding discovery did not complete".into())
            })?,
            capabilities: self.capabilities.ok_or_else(|| {
                Error::Verification("soft-binding capabilities did not complete".into())
            })?,
            algorithms: self.algorithms.ok_or_else(|| {
                Error::Verification("soft-binding algorithm discovery did not complete".into())
            })?,
            status: self.status,
            recovered: self.recovered,
        })
    }

    fn accept_discovery(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let discovery: SoftBindingDiscovery = parse_json(bytes, "soft-binding discovery")?;
        let api = directory_endpoint(resolve_endpoint(
            &self.root,
            &discovery.api_endpoint,
            &self.allowed,
        )?);
        let capabilities_url = match discovery.capabilities_endpoint.as_deref() {
            Some(endpoint) => resolve_endpoint(&self.root, endpoint, &self.allowed)?,
            None => api.join("services/capabilities").map_err(url_error)?,
        };
        require_allowed(&capabilities_url, &self.allowed)?;
        self.api = Some(api);
        self.discovery = Some(discovery);
        self.pending = Some(json_get(capabilities_url, PendingKind::Capabilities));
        Ok(())
    }

    fn accept_capabilities(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let capabilities: SoftBindingCapabilities = parse_json(bytes, "soft-binding capabilities")?;
        match self.query {
            SoftBindingQuery::Content { .. }
                if !capabilities
                    .supported_capabilities
                    .iter()
                    .any(|value| value == "queryByContent") =>
            {
                return Err(Error::Verification(
                    "soft-binding service does not advertise queryByContent".into(),
                ));
            }
            SoftBindingQuery::Reference { .. }
                if !capabilities
                    .supported_capabilities
                    .iter()
                    .any(|value| value == "queryByReference") =>
            {
                return Err(Error::Verification(
                    "soft-binding service does not advertise queryByReference".into(),
                ));
            }
            _ => {}
        }
        self.capabilities = Some(capabilities);
        if self.options.fetch_status {
            let endpoint = self
                .discovery
                .as_ref()
                .and_then(|value| value.status_endpoint.as_deref())
                .ok_or_else(|| {
                    Error::Verification(
                        "soft-binding status was requested but no endpoint was advertised".into(),
                    )
                })?;
            let url = resolve_endpoint(&self.root, endpoint, &self.allowed)?;
            self.pending = Some(json_get(url, PendingKind::Status));
        } else {
            self.schedule_algorithms()?;
        }
        Ok(())
    }

    fn accept_status(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let status: Json = parse_json(bytes, "soft-binding status")?;
        if status.get("status").and_then(Json::as_str).is_none()
            || status.get("timestamp").and_then(Json::as_str).is_none()
        {
            return Err(Error::Verification(
                "soft-binding status response is malformed".into(),
            ));
        }
        self.status = Some(status);
        self.schedule_algorithms()
    }

    fn schedule_algorithms(&mut self) -> Result<(), Error> {
        let url = self
            .api
            .as_ref()
            .ok_or_else(|| Error::Verification("soft-binding API endpoint is absent".into()))?
            .join("services/supportedAlgorithms")
            .map_err(url_error)?;
        require_allowed(&url, &self.allowed)?;
        self.pending = Some(json_get(url, PendingKind::Algorithms));
        Ok(())
    }

    fn accept_algorithms(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let algorithms: SoftBindingAlgorithms =
            parse_json(bytes, "soft-binding supported algorithms")?;
        for selected in [self.query.algorithm(), self.query.hint_algorithm()]
            .into_iter()
            .flatten()
        {
            if !algorithms
                .watermarks
                .iter()
                .chain(&algorithms.fingerprints)
                .any(|entry| entry.alg == selected)
            {
                return Err(Error::Verification(format!(
                    "soft-binding service does not advertise algorithm {selected:?}"
                )));
            }
        }
        self.algorithms = Some(algorithms);
        self.pending = Some(self.query_request()?);
        Ok(())
    }

    fn query_request(&self) -> Result<PendingRequest<'a>, Error> {
        let api = self
            .api
            .as_ref()
            .ok_or_else(|| Error::Verification("soft-binding API endpoint is absent".into()))?;
        let mut url;
        let (method, content_type, body) = match self.query {
            SoftBindingQuery::BindingGet { alg, value } => {
                url = api.join("matches/byBinding").map_err(url_error)?;
                url.query_pairs_mut()
                    .append_pair("value", value)
                    .append_pair("alg", alg)
                    .append_pair("maxResults", &self.max_results.to_string());
                (SoftBindingHttpMethod::Get, None, RequestBody::None)
            }
            SoftBindingQuery::BindingPost { alg, value } => {
                url = api.join("matches/byBinding").map_err(url_error)?;
                url.query_pairs_mut()
                    .append_pair("maxResults", &self.max_results.to_string());
                let body = serde_json::to_vec(&json!({"alg": alg, "value": value}))
                    .map_err(Error::Serialize)?;
                (
                    SoftBindingHttpMethod::Post,
                    Some("application/json"),
                    RequestBody::Owned(body),
                )
            }
            SoftBindingQuery::Content {
                alg,
                hint_alg,
                hint_value,
                ..
            } => {
                url = api.join("matches/byContent").map_err(url_error)?;
                append_optional_query(&mut url, "alg", alg.as_deref());
                append_optional_query(&mut url, "hintAlg", hint_alg.as_deref());
                append_optional_query(&mut url, "hintValue", hint_value.as_deref());
                url.query_pairs_mut()
                    .append_pair("maxResults", &self.max_results.to_string());
                (
                    SoftBindingHttpMethod::Post,
                    Some(self.mime_type),
                    RequestBody::Borrowed(self.asset),
                )
            }
            SoftBindingQuery::Reference {
                alg,
                hint_alg,
                hint_value,
                reference_url,
                asset_length,
                asset_type,
                region,
                ..
            } => {
                url = api.join("matches/byReference").map_err(url_error)?;
                append_optional_query(&mut url, "alg", alg.as_deref());
                append_optional_query(&mut url, "hintAlg", hint_alg.as_deref());
                append_optional_query(&mut url, "hintValue", hint_value.as_deref());
                url.query_pairs_mut()
                    .append_pair("maxResults", &self.max_results.to_string());
                let mut value = json!({
                    "referenceUrl": reference_url,
                    "assetLength": asset_length,
                });
                if let Some(asset_type) = asset_type {
                    value["assetType"] = Json::String(asset_type.clone());
                }
                if let Some(region) = region {
                    value["region"] = region.clone();
                }
                let body = serde_json::to_vec(&value).map_err(Error::Serialize)?;
                (
                    SoftBindingHttpMethod::Post,
                    Some("application/json"),
                    RequestBody::Owned(body),
                )
            }
        };
        require_allowed(&url, &self.allowed)?;
        Ok(PendingRequest {
            method,
            url,
            content_type,
            accept: "application/json",
            body,
            max_response_bytes: MAX_SERVICE_JSON_BYTES,
            kind: PendingKind::Query,
        })
    }

    fn accept_matches(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let result: QueryResult = parse_json(bytes, "soft-binding query")?;
        if result.matches.len() > usize::from(self.max_results) {
            return Err(Error::Verification(format!(
                "soft-binding service returned {} matches after a limit of {}",
                result.matches.len(),
                self.max_results
            )));
        }
        for matched in &result.matches {
            if matched.manifest_id.is_empty() {
                return Err(Error::Verification(
                    "soft-binding service returned an empty manifestId".into(),
                ));
            }
            if matched.similarity_score.is_some_and(|score| score > 100) {
                return Err(Error::Verification(
                    "soft-binding service returned similarityScore above 100".into(),
                ));
            }
        }
        self.matches = result.matches.into_iter();
        self.schedule_next_manifest()
    }

    fn schedule_next_manifest(&mut self) -> Result<(), Error> {
        let Some(matched) = self.matches.next() else {
            self.pending = None;
            return Ok(());
        };
        let api = self
            .api
            .as_ref()
            .ok_or_else(|| Error::Verification("soft-binding API endpoint is absent".into()))?;
        let repository = directory_endpoint(match matched.endpoint.as_deref() {
            Some(endpoint) => resolve_endpoint(api, endpoint, &self.allowed)?,
            None => api.clone(),
        });
        let mut url = manifest_endpoint(&repository, &matched.manifest_id)?;
        url.query_pairs_mut()
            .append_pair("returnActiveManifest", "false");
        require_allowed(&url, &self.allowed)?;
        self.pending = Some(PendingRequest {
            method: SoftBindingHttpMethod::Get,
            url,
            content_type: None,
            accept: "application/c2pa",
            body: RequestBody::None,
            max_response_bytes: MAX_MANIFEST_BYTES,
            kind: PendingKind::Manifest(matched, repository),
        });
        Ok(())
    }

    fn accept_manifest(
        &mut self,
        matched: SoftBindingMatch,
        repository: Url,
        manifest_store: Vec<u8>,
    ) -> Result<(), Error> {
        let report = verify_with_manifest_store(
            self.asset,
            &manifest_store,
            self.mime_type,
            self.verify_options,
        )?;
        self.recovered.push(RecoveredSoftBindingManifest {
            matched,
            manifest_store,
            report,
            receipt: None,
        });
        if self.options.fetch_receipts {
            let index = self.recovered.len() - 1;
            let manifest_id = &self.recovered[index].matched.manifest_id;
            let url = receipt_endpoint(&repository, manifest_id)?;
            require_allowed(&url, &self.allowed)?;
            self.pending = Some(json_get(url, PendingKind::Receipt(index)));
            Ok(())
        } else {
            self.schedule_next_manifest()
        }
    }

    fn accept_receipt(&mut self, index: usize, bytes: &[u8]) -> Result<(), Error> {
        let receipt: Json = parse_json(bytes, "soft-binding receipt")?;
        self.recovered[index].receipt = Some(receipt_evidence(receipt)?);
        self.schedule_next_manifest()
    }
}

fn json_get<'a>(url: Url, kind: PendingKind) -> PendingRequest<'a> {
    PendingRequest {
        method: SoftBindingHttpMethod::Get,
        url,
        content_type: None,
        accept: "application/json",
        body: RequestBody::None,
        max_response_bytes: MAX_SERVICE_JSON_BYTES,
        kind,
    }
}

enum ReceiptPendingKind {
    Discovery,
    Verification,
}

struct ReceiptPending {
    method: SoftBindingHttpMethod,
    url: Url,
    body: Option<Vec<u8>>,
    kind: ReceiptPendingKind,
}

/// Transport-independent session for the repository's explicit receipt POST.
///
/// The returned result is the repository's report. This session does not
/// locally prove or cryptographically verify the receipt.
pub struct SoftBindingReceiptVerificationSession {
    manifest_id: String,
    receipt: Json,
    root: Url,
    allowed: Vec<String>,
    pending: Option<ReceiptPending>,
    result: Option<SoftBindingReceiptEvidence>,
}

impl SoftBindingReceiptVerificationSession {
    pub fn new(
        service_root: &str,
        manifest_id: &str,
        receipt: Json,
        verify_options: &VerifyOptions,
        resolver_options: &SoftBindingResolverOptions,
    ) -> Result<Self, Error> {
        verify_options.validate()?;
        if !crate::online::online_enabled(verify_options) {
            return Err(Error::Verification(
                "soft-binding receipt submission requires online=true or ENCYPHER_C2PA_ONLINE=on"
                    .into(),
            ));
        }
        if manifest_id.trim().is_empty() {
            return Err(Error::Verification(
                "soft-binding receipt manifest id is empty".into(),
            ));
        }
        if !receipt.is_object() {
            return Err(Error::Verification(
                "soft-binding receipt must be a JSON object".into(),
            ));
        }
        let allowed = allowed_origins(&resolver_options.allowed_origins)?;
        if allowed.is_empty() {
            return Err(Error::Verification(
                "soft-binding receipt submission requires at least one allowed origin".into(),
            ));
        }
        let root = Url::parse(service_root).map_err(|error| {
            Error::Verification(format!("invalid soft-binding service root: {error}"))
        })?;
        require_allowed(&root, &allowed)?;
        let mut well_known = root.clone();
        well_known.set_path("/.well-known/c2pa-soft-binding-resolution");
        well_known.set_query(None);
        well_known.set_fragment(None);
        Ok(Self {
            manifest_id: manifest_id.to_owned(),
            receipt,
            root,
            allowed,
            pending: Some(ReceiptPending {
                method: SoftBindingHttpMethod::Get,
                url: well_known,
                body: None,
                kind: ReceiptPendingKind::Discovery,
            }),
            result: None,
        })
    }

    pub fn next_request(&self) -> Option<SoftBindingFetchRequest<'_>> {
        self.pending
            .as_ref()
            .map(|request| SoftBindingFetchRequest {
                method: request.method,
                url: request.url.as_str(),
                content_type: request.body.as_ref().map(|_| "application/json"),
                accept: "application/json",
                body: request.body.as_deref(),
                max_response_bytes: MAX_SERVICE_JSON_BYTES,
            })
    }

    pub fn accept_response(&mut self, final_url: &str, bytes: Vec<u8>) -> Result<(), Error> {
        let pending = self.pending.take().ok_or_else(|| {
            Error::Verification("soft-binding receipt session has no pending request".into())
        })?;
        let final_url = Url::parse(final_url).map_err(|_| {
            Error::Verification("soft-binding transport returned an invalid final URL".into())
        })?;
        if final_url != pending.url {
            return Err(Error::Verification(
                "soft-binding redirect was refused".into(),
            ));
        }
        if bytes.len() > MAX_SERVICE_JSON_BYTES {
            return Err(Error::Verification(format!(
                "soft-binding response exceeds {MAX_SERVICE_JSON_BYTES} bytes"
            )));
        }
        match pending.kind {
            ReceiptPendingKind::Discovery => {
                let discovery: SoftBindingDiscovery = parse_json(&bytes, "soft-binding discovery")?;
                let repository = directory_endpoint(resolve_endpoint(
                    &self.root,
                    &discovery.api_endpoint,
                    &self.allowed,
                )?);
                let url = receipt_endpoint(&repository, &self.manifest_id)?;
                require_allowed(&url, &self.allowed)?;
                let body = serde_json::to_vec(&self.receipt).map_err(Error::Serialize)?;
                self.pending = Some(ReceiptPending {
                    method: SoftBindingHttpMethod::Post,
                    url,
                    body: Some(body),
                    kind: ReceiptPendingKind::Verification,
                });
            }
            ReceiptPendingKind::Verification => {
                let receipt: Json = parse_json(&bytes, "soft-binding receipt verification")?;
                self.result = Some(receipt_evidence(receipt)?);
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<SoftBindingReceiptEvidence, Error> {
        if self.pending.is_some() {
            return Err(Error::Verification(
                "soft-binding receipt session still has a pending request".into(),
            ));
        }
        self.result.ok_or_else(|| {
            Error::Verification("soft-binding receipt verification did not complete".into())
        })
    }
}

/// Ask a repository to verify a caller-supplied receipt. The result remains
/// server-reported evidence and is not a local cryptographic receipt verdict.
pub fn request_soft_binding_receipt_verification(
    service_root: &str,
    manifest_id: &str,
    receipt: Json,
    verify_options: &VerifyOptions,
    resolver_options: &SoftBindingResolverOptions,
) -> Result<SoftBindingReceiptEvidence, Error> {
    let fetcher = new_fetcher(resolver_options.allow_private_networks);
    let mut session = SoftBindingReceiptVerificationSession::new(
        service_root,
        manifest_id,
        receipt,
        verify_options,
        resolver_options,
    )?;
    while let Some(request) = session.next_request() {
        let requested_url = request.url.to_string();
        let bytes = fetch_transport(
            fetcher.as_ref(),
            &request,
            resolver_options.allow_private_networks,
        )?;
        session.accept_response(&requested_url, bytes)?;
    }
    session.finish()
}

/// Discover, query, fetch and locally verify matching manifest stores through
/// the native no-redirect transport.
pub fn resolve_soft_binding(
    asset: &[u8],
    mime_type: &str,
    service_root: &str,
    query: &SoftBindingQuery,
    verify_options: &VerifyOptions,
    resolver_options: &SoftBindingResolverOptions,
) -> Result<SoftBindingResolution, Error> {
    let fetcher = new_fetcher(resolver_options.allow_private_networks);
    let mut session = SoftBindingResolverSession::new(
        asset,
        mime_type,
        service_root,
        query,
        verify_options,
        resolver_options,
    )?;
    while let Some(request) = session.next_request() {
        let requested_url = request.url.to_string();
        let bytes = fetch_transport(
            fetcher.as_ref(),
            &request,
            resolver_options.allow_private_networks,
        )?;
        session.accept_response(&requested_url, bytes)?;
    }
    session.finish()
}

fn receipt_evidence(mut response: Json) -> Result<SoftBindingReceiptEvidence, Error> {
    let verified = response
        .get("verified")
        .and_then(Json::as_bool)
        .ok_or_else(|| Error::Verification("soft-binding receipt result is malformed".into()))?;
    let server_error = response
        .get("error")
        .and_then(Json::as_str)
        .map(str::to_string);
    let receipt = response
        .as_object_mut()
        .map(|object| {
            object.remove("verified");
            object.remove("error");
            Json::Object(std::mem::take(object))
        })
        .ok_or_else(|| Error::Verification("soft-binding receipt result is malformed".into()))?;
    Ok(SoftBindingReceiptEvidence {
        receipt,
        server_reported_verified: verified,
        server_error,
    })
}

fn fetch_transport(
    fetcher: &dyn Fetcher,
    request: &SoftBindingFetchRequest<'_>,
    allow_http: bool,
) -> Result<Vec<u8>, Error> {
    let method = match request.method {
        SoftBindingHttpMethod::Get => FetchMethod::Get,
        SoftBindingHttpMethod::Post => FetchMethod::Post,
    };
    fetcher
        .fetch(&FetchRequest {
            url: request.url,
            method,
            body: request.body,
            content_type: request.content_type,
            accept: Some(request.accept),
            limit: request.max_response_bytes,
            allow_http,
            // This legacy transport refuses redirects independently of the
            // exact-2.5 graph session's cumulative request budget.
            remaining_requests: usize::MAX,
        })
        .map(|response| response.bytes)
        .map_err(|error| {
            let detail = if error.blocked {
                "request blocked by network policy"
            } else {
                "network request failed"
            };
            Error::Verification(format!("soft-binding request failed: {detail}"))
        })
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], purpose: &str) -> Result<T, Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Error::Verification(format!("{purpose} returned invalid JSON: {error}")))
}

fn append_optional_query(url: &mut Url, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        url.query_pairs_mut().append_pair(name, value);
    }
}

fn allowed_origins(values: &[String]) -> Result<Vec<String>, Error> {
    let mut origins = Vec::with_capacity(values.len());
    for value in values {
        let url = Url::parse(value).map_err(|error| {
            Error::Verification(format!("invalid allowed origin {value:?}: {error}"))
        })?;
        if url.cannot_be_a_base()
            || url.host_str().is_none()
            || !matches!(url.scheme(), "https" | "http")
        {
            return Err(Error::Verification(format!(
                "allowed origin {value:?} is not an HTTP network origin"
            )));
        }
        let origin = url.origin().ascii_serialization();
        let canonical = format!("{origin}/");
        if origin == "null" || (url.as_str() != origin && url.as_str() != canonical) {
            return Err(Error::Verification(format!(
                "allowed origin {value:?} must contain only scheme, host and optional port"
            )));
        }
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    Ok(origins)
}

fn require_allowed(url: &Url, allowed: &[String]) -> Result<(), Error> {
    let origin = url.origin().ascii_serialization();
    if url.username().is_empty()
        && url.password().is_none()
        && allowed.iter().any(|entry| entry == &origin)
    {
        Ok(())
    } else {
        Err(Error::Verification(format!(
            "soft-binding endpoint origin {origin:?} is not allowlisted"
        )))
    }
}

fn resolve_endpoint(base: &Url, endpoint: &str, allowed: &[String]) -> Result<Url, Error> {
    let resolved = base.join(endpoint).map_err(url_error)?;
    require_allowed(&resolved, allowed)?;
    Ok(resolved)
}

fn directory_endpoint(mut endpoint: Url) -> Url {
    if !endpoint.path().ends_with('/') {
        let mut path = endpoint.path().to_owned();
        path.push('/');
        endpoint.set_path(&path);
    }
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

fn manifest_endpoint(repository: &Url, manifest_id: &str) -> Result<Url, Error> {
    let mut endpoint = repository.clone();
    endpoint
        .path_segments_mut()
        .map_err(|_| {
            Error::Verification("soft-binding endpoint cannot carry path segments".into())
        })?
        .pop_if_empty()
        .push("manifests")
        .push(manifest_id);
    Ok(endpoint)
}

fn receipt_endpoint(repository: &Url, manifest_id: &str) -> Result<Url, Error> {
    let mut endpoint = manifest_endpoint(repository, manifest_id)?;
    endpoint
        .path_segments_mut()
        .map_err(|_| {
            Error::Verification("soft-binding endpoint cannot carry path segments".into())
        })?
        .push("receipts");
    Ok(endpoint)
}

fn url_error(error: url::ParseError) -> Error {
    Error::Verification(format!("invalid soft-binding endpoint: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_origins_require_exact_origin_syntax() {
        assert_eq!(
            allowed_origins(&["https://resolver.example".into()]).unwrap(),
            ["https://resolver.example"]
        );
        assert!(allowed_origins(&["https://resolver.example/api".into()]).is_err());
        assert!(allowed_origins(&["https://resolver.example////".into()]).is_err());
        assert!(allowed_origins(&["ftp://resolver.example".into()]).is_err());
        assert!(allowed_origins(&["file:///tmp/repository".into()]).is_err());
    }

    #[test]
    fn directory_endpoints_preserve_the_advertised_base_path() {
        let base = directory_endpoint(Url::parse("https://resolver.example/v1").unwrap());
        assert_eq!(
            base.join("matches/byBinding").unwrap().as_str(),
            "https://resolver.example/v1/matches/byBinding"
        );
    }

    #[test]
    fn every_resolved_endpoint_must_be_allowlisted() {
        let base = Url::parse("https://resolver.example/v1/").unwrap();
        let allowed = vec!["https://resolver.example".into()];
        assert!(resolve_endpoint(&base, "https://federated.example/v1", &allowed).is_err());
        let credentialed = Url::parse("https://user:secret@resolver.example/v1").unwrap();
        assert!(require_allowed(&credentialed, &allowed).is_err());
        assert!(resolve_endpoint(&base, "matches/byBinding", &allowed).is_ok());
    }

    #[test]
    fn disclosure_routes_require_matching_explicit_consent() {
        let query = SoftBindingQuery::Content {
            alg: None,
            hint_alg: None,
            hint_value: None,
            consent: SoftBindingDisclosureConsent::DiscloseReference,
        };
        assert!(query.validate().is_err());
    }

    fn online_options() -> VerifyOptions {
        VerifyOptions {
            online: Some(true),
            ..VerifyOptions::default()
        }
    }

    fn resolver_options() -> SoftBindingResolverOptions {
        SoftBindingResolverOptions {
            allowed_origins: vec!["https://192.0.2.1".into()],
            ..SoftBindingResolverOptions::default()
        }
    }

    fn accept_current(
        session: &mut SoftBindingResolverSession<'_>,
        json: &str,
    ) -> Result<(), Error> {
        let url = session.next_request().unwrap().url.to_owned();
        session.accept_response(&url, json.as_bytes().to_vec())
    }

    #[test]
    fn binding_get_session_uses_exact_selected_route_and_default_limit() {
        let query = SoftBindingQuery::BindingGet {
            alg: "c2pa.soft-binding.example".into(),
            value: "registered value".into(),
        };
        let verify = online_options();
        let resolver = resolver_options();
        let mut session = SoftBindingResolverSession::new(
            b"asset",
            "image/jpeg",
            "https://192.0.2.1",
            &query,
            &verify,
            &resolver,
        )
        .unwrap();
        accept_current(
            &mut session,
            r#"{"apiEndpoint":"/v1","c2paSpecificationVersion":"2.5"}"#,
        )
        .unwrap();
        accept_current(
            &mut session,
            r#"{"c2paSpecificationVersion":"2.5","supportedCapabilities":[]}"#,
        )
        .unwrap();
        accept_current(
            &mut session,
            r#"{"watermarks":[{"alg":"c2pa.soft-binding.example"}],"fingerprints":[]}"#,
        )
        .unwrap();
        let request = session.next_request().unwrap();
        assert_eq!(request.method, SoftBindingHttpMethod::Get);
        assert!(request.url.contains("/v1/matches/byBinding?"));
        assert!(request.url.contains("maxResults=10"));
        assert!(request.url.contains("registered+value"));
        let url = request.url.to_owned();
        session
            .accept_response(&url, br#"{"matches":[]}"#.to_vec())
            .unwrap();
        assert!(session.finish().unwrap().recovered.is_empty());
    }

    #[test]
    fn content_session_requires_capability_and_emits_asset_body() {
        let query = SoftBindingQuery::Content {
            alg: None,
            hint_alg: None,
            hint_value: None,
            consent: SoftBindingDisclosureConsent::UploadAsset,
        };
        let verify = online_options();
        let resolver = resolver_options();
        let mut session = SoftBindingResolverSession::new(
            b"exact asset",
            "image/jpeg",
            "https://192.0.2.1",
            &query,
            &verify,
            &resolver,
        )
        .unwrap();
        accept_current(
            &mut session,
            r#"{"apiEndpoint":"/v1/","c2paSpecificationVersion":"2.5"}"#,
        )
        .unwrap();
        accept_current(
            &mut session,
            r#"{"c2paSpecificationVersion":"2.5","supportedCapabilities":["queryByContent"]}"#,
        )
        .unwrap();
        accept_current(&mut session, r#"{"watermarks":[],"fingerprints":[]}"#).unwrap();
        let request = session.next_request().unwrap();
        assert_eq!(request.method, SoftBindingHttpMethod::Post);
        assert_eq!(request.content_type, Some("image/jpeg"));
        assert_eq!(request.body, Some(&b"exact asset"[..]));
        assert!(request.url.contains("/v1/matches/byContent?"));
    }

    #[test]
    fn receipt_result_stays_server_reported_and_manifest_ids_cannot_escape_repository() {
        let verify = online_options();
        let resolver = resolver_options();
        let manifest_id = "../other?escape#fragment";
        let receipt = json!({
            "@context": "https://c2pa.org/ns/",
            "@type": "org.c2pa.manifest-receipt",
            "repository": {"uri": "https://192.0.2.1", "manifestId": manifest_id},
            "anchor": {"uri": "https://192.0.2.1/a", "proof": {}}
        });
        let mut session = SoftBindingReceiptVerificationSession::new(
            "https://192.0.2.1",
            manifest_id,
            receipt,
            &verify,
            &resolver,
        )
        .unwrap();
        let discovery_url = session.next_request().unwrap().url.to_owned();
        session
            .accept_response(
                &discovery_url,
                br#"{"apiEndpoint":"/v1/","c2paSpecificationVersion":"2.5"}"#.to_vec(),
            )
            .unwrap();
        let request = session.next_request().unwrap();
        let endpoint = Url::parse(request.url).unwrap();
        assert_eq!(endpoint.origin().ascii_serialization(), "https://192.0.2.1");
        let segments = endpoint.path_segments().unwrap().collect::<Vec<_>>();
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0], "v1");
        assert_eq!(segments[1], "manifests");
        assert!(!segments[2].is_empty());
        assert_eq!(segments[3], "receipts");
        assert!(!segments.iter().any(|segment| segment.is_empty()));
        assert!(endpoint.query().is_none());
        assert!(endpoint.fragment().is_none());
        let url = request.url.to_owned();
        session
            .accept_response(
                &url,
                br#"{"@context":"x","@type":"org.c2pa.manifest-receipt","repository":{},"anchor":{},"verified":false,"error":"no match"}"#.to_vec(),
            )
            .unwrap();
        let evidence = session.finish().unwrap();
        assert!(!evidence.server_reported_verified);
        assert_eq!(evidence.server_error.as_deref(), Some("no match"));
    }
}
