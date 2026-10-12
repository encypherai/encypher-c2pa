// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Native orchestration for the C2PA 2.5 external-resource graph.
//!
//! Discovery and final verification remain network-free kernel operations. This
//! adapter owns every caller-supplied or fetched body, applies consent before a
//! fetch, and lends the completed resource map to the one final kernel pass.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::online::{self, FetchSession, NetworkNeed, NetworkReport};
use crate::{
    ExternalDidDocumentRequest, ExternalResource, ExternalResourceKind, ExternalResourceRequest,
    ExternalResourceStopReason, ExternalResources, ValidatedExternalData, VerifyOptions,
};

const MAX_DID_DOCUMENT_BYTES: usize = 256 * 1024;

#[derive(Debug)]
enum ResourceOutcome {
    Retrieved {
        bytes: Vec<u8>,
        media_type: Option<String>,
        caller_supplied: bool,
    },
    Unavailable {
        caller_supplied: bool,
    },
}

/// Stable, owned resource outcomes shared by discovery and final verification.
#[derive(Debug, Default)]
pub(crate) struct NativeResources {
    outcomes: HashMap<String, ResourceOutcome>,
}

impl NativeResources {
    fn from_caller(mut evidence: ValidatedExternalData) -> Self {
        let mut outcomes = HashMap::with_capacity(
            evidence
                .data
                .len()
                .saturating_add(evidence.unreachable.len()),
        );
        for (uri, bytes) in evidence.data {
            let media_type = evidence.media_types.remove(&uri);
            outcomes.insert(
                uri,
                ResourceOutcome::Retrieved {
                    bytes,
                    media_type,
                    caller_supplied: true,
                },
            );
        }
        // A body is authoritative over a contradictory unreachable marker.
        for uri in evidence.unreachable {
            outcomes.entry(uri).or_insert(ResourceOutcome::Unavailable {
                caller_supplied: true,
            });
        }
        Self { outcomes }
    }

    fn is_caller_evidence(&self, uri: &str) -> bool {
        match self.outcomes.get(uri) {
            Some(ResourceOutcome::Retrieved {
                caller_supplied, ..
            })
            | Some(ResourceOutcome::Unavailable { caller_supplied }) => *caller_supplied,
            None => false,
        }
    }

    fn has_outcome(&self, uri: &str) -> bool {
        self.outcomes.contains_key(uri)
    }

    pub(crate) fn bytes(&self, uri: &str) -> Option<&[u8]> {
        match self.outcomes.get(uri) {
            Some(ResourceOutcome::Retrieved { bytes, .. }) => Some(bytes),
            Some(ResourceOutcome::Unavailable { .. }) | None => None,
        }
    }

    fn fetched(&mut self, uri: String, bytes: Vec<u8>, media_type: Option<String>) {
        self.outcomes.insert(
            uri,
            ResourceOutcome::Retrieved {
                bytes,
                media_type,
                caller_supplied: false,
            },
        );
    }

    fn unavailable(&mut self, uri: String) {
        self.outcomes
            .entry(uri)
            .or_insert(ResourceOutcome::Unavailable {
                caller_supplied: false,
            });
    }
}

impl ExternalResources for NativeResources {
    fn resolve(&self, url: &str) -> ExternalResource<'_> {
        match self.outcomes.get(url) {
            Some(ResourceOutcome::Retrieved {
                bytes, media_type, ..
            }) => ExternalResource::Retrieved {
                bytes,
                media_type: media_type.as_deref(),
            },
            Some(ResourceOutcome::Unavailable { .. }) => ExternalResource::Unavailable,
            None => ExternalResource::NotAttempted,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct OcspUpdate {
    pub(crate) responses: HashMap<String, Vec<u8>>,
    pub(crate) unreachable: Vec<String>,
}

impl OcspUpdate {
    pub(crate) fn has_evidence(&self) -> bool {
        !self.responses.is_empty() || !self.unreachable.is_empty()
    }
}

/// One consent, transport-budget, and payload-ownership scope per verification.
pub(crate) struct NativeOnline {
    resources: NativeResources,
    session: FetchSession,
    network: NetworkReport,
    handled_gets: HashSet<String>,
    handled_ocsp: HashSet<(String, Vec<u8>)>,
}

impl NativeOnline {
    pub(crate) fn new(evidence: ValidatedExternalData, options: &VerifyOptions) -> Self {
        Self {
            resources: NativeResources::from_caller(evidence),
            session: FetchSession::new(options.online_allow_private_networks),
            network: NetworkReport {
                enabled: online::resolve_online(options, &[]),
                needed: Vec::new(),
                requests: Vec::new(),
            },
            handled_gets: HashSet::new(),
            handled_ocsp: HashSet::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_fetcher(
        evidence: ValidatedExternalData,
        options: &VerifyOptions,
        fetcher: Box<dyn online::Fetcher>,
    ) -> Self {
        let mut state = Self::new(evidence, options);
        state.session = FetchSession::with_fetcher(fetcher);
        state
    }

    pub(crate) fn resources(&self) -> &NativeResources {
        &self.resources
    }

    fn push_needed(&mut self, need: Value) {
        if !self.network.needed.contains(&need) {
            self.network.needed.push(need);
        }
    }

    /// Resolve one D2 frontier item, reusing caller or earlier fetched bytes.
    pub(crate) fn ensure_graph_resource(
        &mut self,
        options: &VerifyOptions,
        request: &ExternalResourceRequest,
        terminal_root: bool,
    ) {
        if !self.resources.is_caller_evidence(&request.uri) {
            self.push_needed(if terminal_root {
                json!({ "kind": "remote_manifest", "uri": request.uri })
            } else if request.kind == ExternalResourceKind::SegmentManifestStore {
                json!({
                    "kind": "external_data",
                    "uri": request.uri,
                    "assertion_label": "c2pa.hash.segment",
                })
            } else {
                // D2 intentionally exposes the URI and kind, not the assertion
                // label. Final verification supplies exact labels for a body
                // that remains unresolved.
                json!({ "kind": "external_data", "uri": request.uri })
            });
        }
        if self.resources.has_outcome(&request.uri)
            || !self.handled_gets.insert(request.uri.clone())
        {
            return;
        }

        let need = if terminal_root {
            NetworkNeed::RemoteManifest {
                uri: request.uri.clone(),
            }
        } else {
            NetworkNeed::ExternalData {
                uri: request.uri.clone(),
                assertion_label: if request.kind == ExternalResourceKind::SegmentManifestStore {
                    "c2pa.hash.segment".to_string()
                } else {
                    "c2pa.external-resource".to_string()
                },
            }
        };
        if !online::resolve_online(options, std::slice::from_ref(&need)) {
            return;
        }
        self.network.enabled = true;
        let (attempt, result) = self.session.fetch(&need);
        self.network.requests.push(attempt);
        match result {
            Ok(fetched) => {
                self.resources
                    .fetched(request.uri.clone(), fetched.bytes, fetched.media_type)
            }
            Err(error) if !error.blocked || error.received_response => {
                self.resources.unavailable(request.uri.clone());
            }
            Err(_) => {}
        }
    }

    /// Resolve every unpinned DID found by D2, sharing the GET body cache.
    pub(crate) fn resolve_did_documents(
        &mut self,
        options: &VerifyOptions,
        requests: &[ExternalDidDocumentRequest],
        pinned: Option<&HashMap<String, Value>>,
    ) -> HashMap<String, Value> {
        let mut documents = HashMap::new();
        for request in requests {
            if pinned.is_some_and(|pinned| pinned.contains_key(&request.did)) {
                continue;
            }
            let caller_supplied = self.resources.is_caller_evidence(&request.url);
            if !caller_supplied {
                self.push_needed(json!({
                    "kind": "did_document",
                    "did": request.did,
                    "url": request.url,
                }));
            }

            let mut fresh_request = None;
            if !self.resources.has_outcome(&request.url)
                && self.handled_gets.insert(request.url.clone())
            {
                let need = NetworkNeed::DidDocument {
                    did: request.did.clone(),
                    url: request.url.clone(),
                };
                if online::resolve_online(options, std::slice::from_ref(&need)) {
                    self.network.enabled = true;
                    let (attempt, result) = self.session.fetch(&need);
                    let request_index = self.network.requests.len();
                    self.network.requests.push(attempt);
                    fresh_request = Some(request_index);
                    match result {
                        Ok(fetched) => self.resources.fetched(
                            request.url.clone(),
                            fetched.bytes,
                            fetched.media_type,
                        ),
                        Err(error) if !error.blocked || error.received_response => {
                            self.resources.unavailable(request.url.clone());
                        }
                        Err(_) => {}
                    }
                }
            }

            let Some(bytes) = self.resources.bytes(&request.url) else {
                continue;
            };
            if bytes.len() > MAX_DID_DOCUMENT_BYTES {
                if let Some(attempt) =
                    fresh_request.and_then(|index| self.network.requests.get_mut(index))
                {
                    attempt.outcome = "failed".to_string();
                    attempt.detail = format!(
                        "the DID document is larger than the {MAX_DID_DOCUMENT_BYTES} byte limit"
                    );
                }
                continue;
            }
            match serde_json::from_slice(bytes) {
                Ok(document) => {
                    documents.insert(request.did.clone(), document);
                }
                Err(error) => {
                    if let Some(attempt) =
                        fresh_request.and_then(|index| self.network.requests.get_mut(index))
                    {
                        attempt.outcome = "failed".to_string();
                        attempt.detail = format!("the DID document is not JSON: {error}");
                    }
                }
            }
        }
        documents
    }

    /// Record parse-only rejection on the request that delivered the body.
    pub(crate) fn mark_discovery_stop(&mut self, reason: Option<&ExternalResourceStopReason>) {
        let Some(ExternalResourceStopReason::ManifestMalformed { uri: Some(uri) }) = reason else {
            return;
        };
        if let Some(request) = self
            .network
            .requests
            .iter_mut()
            .find(|request| request.url == *uri && request.outcome == "fetched")
        {
            request.outcome = "failed".to_string();
            request.detail = "the fetched manifest store is malformed".to_string();
        }
    }

    /// Fetch only OCSP requests emitted by the validation-dependent final pass.
    pub(crate) fn fetch_ocsp(
        &mut self,
        options: &VerifyOptions,
        needs: &[NetworkNeed],
    ) -> OcspUpdate {
        let mut update = OcspUpdate::default();
        for need in needs {
            let NetworkNeed::Ocsp {
                certificate_sha256_hex,
                request_der,
                ..
            } = need
            else {
                continue;
            };
            self.push_needed(need.to_json());
            if !self
                .handled_ocsp
                .insert((certificate_sha256_hex.clone(), request_der.clone()))
            {
                continue;
            }
            if !online::resolve_online(options, std::slice::from_ref(need)) {
                continue;
            }
            self.network.enabled = true;
            let (attempt, result) = self.session.fetch(need);
            self.network.requests.push(attempt);
            match result {
                Ok(fetched) => {
                    update
                        .responses
                        .entry(certificate_sha256_hex.clone())
                        .or_insert(fetched.bytes);
                }
                Err(error) if error.received_response => {
                    // The empty response is the kernel's existing sentinel for
                    // a body that arrived but was unusable under transport bounds.
                    update
                        .responses
                        .entry(certificate_sha256_hex.clone())
                        .or_default();
                }
                Err(error) if !error.blocked => {
                    if !update
                        .unreachable
                        .iter()
                        .any(|certificate| certificate == certificate_sha256_hex)
                    {
                        update.unreachable.push(certificate_sha256_hex.clone());
                    }
                }
                Err(_) => {}
            }
        }
        update
    }

    /// Merge final kernel needs with D2 needs and return the complete report.
    pub(crate) fn finish(mut self, needs: &[NetworkNeed]) -> NetworkReport {
        for need in needs {
            self.push_needed(need.to_json());
        }
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    struct ScriptedFetcher {
        calls: Rc<RefCell<Vec<String>>>,
        results: RefCell<VecDeque<online::FetchResult>>,
    }

    impl online::Fetcher for ScriptedFetcher {
        fn fetch(&self, request: &online::FetchRequest<'_>) -> online::FetchResult {
            self.calls.borrow_mut().push(request.url.to_string());
            self.results
                .borrow_mut()
                .pop_front()
                .expect("one scripted result per transport call")
        }
    }

    fn options() -> VerifyOptions {
        VerifyOptions {
            spec_version: Some("2.5".to_string()),
            online: Some(true),
            ..VerifyOptions::default()
        }
    }

    fn fetched(bytes: &[u8]) -> online::FetchResult {
        Ok(online::FetchOk {
            bytes: bytes.to_vec(),
            media_type: Some("application/c2pa".to_string()),
            requests_used: 1,
        })
    }

    fn graph_request(uri: &str, kind: ExternalResourceKind) -> ExternalResourceRequest {
        ExternalResourceRequest {
            uri: uri.to_string(),
            kind,
        }
    }

    #[test]
    fn caller_body_wins_over_unreachable_without_copying() {
        let uri = "https://evidence.example/root.c2pa".to_string();
        let resources = NativeResources::from_caller(ValidatedExternalData {
            data: HashMap::from([(uri.clone(), vec![1, 2, 3])]),
            media_types: HashMap::from([(uri.clone(), "application/c2pa".to_string())]),
            unreachable: vec![uri.clone()],
        });
        match resources.resolve(&uri) {
            ExternalResource::Retrieved { bytes, media_type } => {
                assert_eq!(bytes, [1, 2, 3]);
                assert_eq!(media_type, Some("application/c2pa"));
            }
            ExternalResource::NotAttempted | ExternalResource::Unavailable => {
                panic!("caller bytes must remain authoritative")
            }
        }
    }

    #[test]
    fn caller_unreachable_remains_distinct_from_missing() {
        let unavailable = "https://evidence.example/unavailable".to_string();
        let resources = NativeResources::from_caller(ValidatedExternalData {
            unreachable: vec![unavailable.clone()],
            ..ValidatedExternalData::default()
        });
        assert!(matches!(
            resources.resolve(&unavailable),
            ExternalResource::Unavailable
        ));
        assert!(matches!(
            resources.resolve("https://evidence.example/missing"),
            ExternalResource::NotAttempted
        ));
    }

    #[test]
    fn caller_root_body_causes_zero_transport_calls() {
        let uri = "https://evidence.example/root.c2pa".to_string();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData {
                data: HashMap::from([(uri.clone(), vec![1, 2, 3])]),
                ..ValidatedExternalData::default()
            },
            &options(),
            Box::new(ScriptedFetcher {
                calls: Rc::clone(&calls),
                results: RefCell::new(VecDeque::new()),
            }),
        );
        state.ensure_graph_resource(
            &options(),
            &graph_request(&uri, ExternalResourceKind::SegmentManifestStore),
            true,
        );

        assert!(calls.borrow().is_empty());
        assert_eq!(state.resources().bytes(&uri), Some(&[1, 2, 3][..]));
        assert!(state.finish(&[]).needed.is_empty());
    }

    #[test]
    fn offline_missing_root_is_needed_but_never_attempted() {
        let uri = "https://evidence.example/missing.c2pa";
        let calls = Rc::new(RefCell::new(Vec::new()));
        let offline = VerifyOptions {
            spec_version: Some("2.5".to_string()),
            online: Some(false),
            ..VerifyOptions::default()
        };
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData::default(),
            &offline,
            Box::new(ScriptedFetcher {
                calls: Rc::clone(&calls),
                results: RefCell::new(VecDeque::new()),
            }),
        );
        state.ensure_graph_resource(
            &offline,
            &graph_request(uri, ExternalResourceKind::SegmentManifestStore),
            true,
        );

        assert!(calls.borrow().is_empty());
        assert!(matches!(
            state.resources().resolve(uri),
            ExternalResource::NotAttempted
        ));
        let network = state.finish(&[]);
        assert!(!network.enabled);
        assert_eq!(
            network.needed,
            vec![serde_json::json!({ "kind": "remote_manifest", "uri": uri })]
        );
    }

    #[test]
    fn graph_gets_are_deduplicated_by_uri_and_reuse_one_owned_body() {
        let uri = "https://evidence.example/predecessor.c2pa";
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData::default(),
            &options(),
            Box::new(ScriptedFetcher {
                calls: Rc::clone(&calls),
                results: RefCell::new(VecDeque::from([fetched(&[4, 5, 6])])),
            }),
        );
        state.ensure_graph_resource(
            &options(),
            &graph_request(uri, ExternalResourceKind::Opaque),
            false,
        );
        state.ensure_graph_resource(
            &options(),
            &graph_request(uri, ExternalResourceKind::SegmentManifestStore),
            false,
        );

        assert_eq!(calls.borrow().as_slice(), [uri]);
        assert_eq!(state.resources().bytes(uri), Some(&[4, 5, 6][..]));
    }

    #[test]
    fn cached_did_body_enforces_the_exact_size_boundary_without_refetch() {
        fn document(length: usize) -> Vec<u8> {
            let mut bytes = b"{\"x\":\"".to_vec();
            bytes.resize(length - 2, b'a');
            bytes.extend_from_slice(b"\"}");
            assert_eq!(bytes.len(), length);
            bytes
        }

        let accepted_url = "https://identity.example/accepted.json".to_string();
        let oversized_url = "https://identity.example/oversized.json".to_string();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData {
                data: HashMap::from([
                    (accepted_url.clone(), document(MAX_DID_DOCUMENT_BYTES)),
                    (oversized_url.clone(), document(MAX_DID_DOCUMENT_BYTES + 1)),
                ]),
                ..ValidatedExternalData::default()
            },
            &options(),
            Box::new(ScriptedFetcher {
                calls: Rc::clone(&calls),
                results: RefCell::new(VecDeque::new()),
            }),
        );
        let documents = state.resolve_did_documents(
            &options(),
            &[
                ExternalDidDocumentRequest {
                    did: "did:web:identity.example:accepted".to_string(),
                    url: accepted_url,
                },
                ExternalDidDocumentRequest {
                    did: "did:web:identity.example:oversized".to_string(),
                    url: oversized_url,
                },
            ],
            None,
        );

        assert!(calls.borrow().is_empty());
        assert!(documents.contains_key("did:web:identity.example:accepted"));
        assert!(!documents.contains_key("did:web:identity.example:oversized"));
    }

    #[test]
    fn attempted_failure_is_unavailable_but_policy_block_is_not_attempted() {
        let failed_uri = "https://evidence.example/failed";
        let blocked_uri = "https://evidence.example/blocked";
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData::default(),
            &options(),
            Box::new(ScriptedFetcher {
                calls,
                results: RefCell::new(VecDeque::from([
                    Err(online::FetchErr {
                        blocked: false,
                        received_response: false,
                        detail: "connection failed".to_string(),
                        requests_used: 1,
                        received_bytes: 0,
                    }),
                    Err(online::FetchErr {
                        blocked: true,
                        received_response: false,
                        detail: "destination rejected".to_string(),
                        requests_used: 0,
                        received_bytes: 0,
                    }),
                ])),
            }),
        );
        state.ensure_graph_resource(
            &options(),
            &graph_request(failed_uri, ExternalResourceKind::Opaque),
            false,
        );
        state.ensure_graph_resource(
            &options(),
            &graph_request(blocked_uri, ExternalResourceKind::Opaque),
            false,
        );

        assert!(matches!(
            state.resources().resolve(failed_uri),
            ExternalResource::Unavailable
        ));
        assert!(matches!(
            state.resources().resolve(blocked_uri),
            ExternalResource::NotAttempted
        ));
    }

    #[test]
    fn ocsp_deduplicates_certificate_request_identity_not_responder_uri() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData::default(),
            &options(),
            Box::new(ScriptedFetcher {
                calls: Rc::clone(&calls),
                results: RefCell::new(VecDeque::from([fetched(&[1]), fetched(&[2])])),
            }),
        );
        let responder = "http://ocsp.example.test";
        let first = NetworkNeed::Ocsp {
            purpose: online::OcspPurpose::ClaimSigner,
            responder_url: responder.to_string(),
            request_der: vec![1],
            certificate_sha256_hex: "aa".to_string(),
        };
        let duplicate = first.clone();
        let second = NetworkNeed::Ocsp {
            purpose: online::OcspPurpose::ClaimSigner,
            responder_url: responder.to_string(),
            request_der: vec![2],
            certificate_sha256_hex: "bb".to_string(),
        };
        let update = state.fetch_ocsp(&options(), &[first, duplicate, second]);

        assert_eq!(calls.borrow().as_slice(), [responder, responder]);
        assert_eq!(
            update.responses.get("aa").map(Vec::as_slice),
            Some(&[1][..])
        );
        assert_eq!(
            update.responses.get("bb").map(Vec::as_slice),
            Some(&[2][..])
        );
    }

    #[test]
    fn failed_ocsp_is_unreachable_but_policy_block_remains_not_attempted() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut state = NativeOnline::with_fetcher(
            ValidatedExternalData::default(),
            &options(),
            Box::new(ScriptedFetcher {
                calls,
                results: RefCell::new(VecDeque::from([
                    Err(online::FetchErr {
                        blocked: false,
                        received_response: false,
                        detail: "connection failed".to_string(),
                        requests_used: 1,
                        received_bytes: 0,
                    }),
                    Err(online::FetchErr {
                        blocked: true,
                        received_response: false,
                        detail: "destination rejected".to_string(),
                        requests_used: 0,
                        received_bytes: 0,
                    }),
                ])),
            }),
        );
        let responder = "http://ocsp.example.test";
        let failed = NetworkNeed::Ocsp {
            purpose: online::OcspPurpose::ClaimSigner,
            responder_url: responder.to_string(),
            request_der: vec![1],
            certificate_sha256_hex: "aa".to_string(),
        };
        let blocked = NetworkNeed::Ocsp {
            purpose: online::OcspPurpose::ClaimSigner,
            responder_url: responder.to_string(),
            request_der: vec![2],
            certificate_sha256_hex: "bb".to_string(),
        };
        let update = state.fetch_ocsp(&options(), &[failed, blocked]);

        assert!(update.has_evidence());
        assert!(update.responses.is_empty());
        assert_eq!(update.unreachable, vec!["aa".to_string()]);
    }
}
