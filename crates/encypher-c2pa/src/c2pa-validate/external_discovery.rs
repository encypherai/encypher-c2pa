// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Parse-only discovery of caller-resolved external verification resources.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::jumbf::{expand_store, parse_manifest_store};
use crate::c2pa_formats::{AppendOnlyFlavor, AssetFormat, CheckpointReference};
use crate::{Error, VerifyOptions};

use super::ingredient_graph::GraphLimits;
use super::refs::{ExternalResource, ExternalResources};
use super::versions;
use super::{base_assertion_label, ClaimAssertionRefs, EngineProfile, SpecVersion};

/// How final verification uses one discovered external resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalResourceKind {
    /// Terminal content whose signed digest is checked without further traversal.
    Opaque,
    /// A C2PA manifest store that may introduce append-history predecessors.
    SegmentManifestStore,
}

/// One external URI the caller may resolve before final verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalResourceRequest {
    /// Absolute external URI declared by signed manifest content.
    pub uri: String,
    /// Whether the body is terminal or may introduce another predecessor.
    pub kind: ExternalResourceKind,
}

/// One DID document a network adapter may resolve before final verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDidDocumentRequest {
    /// Primary DID, without a fragment or query.
    pub did: String,
    /// HTTPS URL defined by the `did:web` method.
    pub url: String,
}

/// The graph ceiling that stopped parse-only discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphLimitKind {
    /// Maximum traversal depth.
    Depth,
    /// Maximum distinct manifest nodes.
    Nodes,
    /// Maximum examined references.
    References,
    /// Maximum cumulative visited JUMBF bytes.
    Bytes,
}

/// Why discovery could not reach a complete resource frontier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalResourceStopReason {
    /// A caller-lowered or engine graph ceiling was reached.
    GraphLimitExceeded {
        /// Ceiling that stopped discovery.
        limit: GraphLimitKind,
    },
    /// A required external manifest-store body was not available.
    PredecessorUnavailable {
        /// URI whose provider outcome was unavailable or not attempted.
        uri: String,
    },
    /// A manifest store could not be parsed far enough to continue discovery.
    ManifestMalformed {
        /// External predecessor URI, or `None` for the initial or an inline store.
        uri: Option<String>,
    },
}

#[derive(Default)]
struct UriState {
    root: bool,
    root_parsed: bool,
    segment: bool,
    segment_parsed: bool,
    segment_depth: usize,
}

struct DiscoveryBudget {
    limits: GraphLimits,
    nodes: usize,
    references: usize,
    bytes: usize,
}

impl DiscoveryBudget {
    fn new(limits: GraphLimits) -> Self {
        Self {
            limits: GraphLimits::lowered(
                limits.max_depth,
                limits.max_nodes,
                limits.max_references,
                limits.max_bytes,
            ),
            nodes: 0,
            references: 0,
            bytes: 0,
        }
    }

    fn depth(&self, depth: usize) -> Result<(), GraphLimitKind> {
        if depth > self.limits.max_depth {
            Err(GraphLimitKind::Depth)
        } else {
            Ok(())
        }
    }

    fn node(&mut self) -> Result<(), GraphLimitKind> {
        if self.nodes >= self.limits.max_nodes {
            return Err(GraphLimitKind::Nodes);
        }
        self.nodes += 1;
        Ok(())
    }

    fn reference(&mut self) -> Result<(), GraphLimitKind> {
        if self.references >= self.limits.max_references {
            return Err(GraphLimitKind::References);
        }
        self.references += 1;
        Ok(())
    }

    fn references(&mut self, count: usize) -> Result<(), GraphLimitKind> {
        let total = self.references.saturating_add(count);
        if total > self.limits.max_references {
            self.references = self.limits.max_references;
            return Err(GraphLimitKind::References);
        }
        self.references = total;
        Ok(())
    }

    fn references_left(&self) -> usize {
        self.limits.max_references.saturating_sub(self.references)
    }

    fn bytes(&mut self, count: usize) -> Result<(), GraphLimitKind> {
        let total = self.bytes.saturating_add(count);
        if total > self.limits.max_bytes {
            return Err(GraphLimitKind::Bytes);
        }
        self.bytes = total;
        Ok(())
    }
}

struct DiscoverySession {
    profile: EngineProfile,
    flavor: Option<AppendOnlyFlavor>,
    budget: DiscoveryBudget,
    uris: HashMap<String, UriState>,
    did_document_ids: HashSet<String>,
    did_documents: Vec<ExternalDidDocumentRequest>,
    stop_reason: Option<ExternalResourceStopReason>,
}

impl DiscoverySession {
    fn stop(&mut self, reason: ExternalResourceStopReason) {
        if self.stop_reason.is_none() {
            self.stop_reason = Some(reason);
        }
    }

    fn graph_stop(&mut self, limit: GraphLimitKind) {
        self.stop(ExternalResourceStopReason::GraphLimitExceeded { limit });
    }

    fn stopped(&self) -> bool {
        self.stop_reason.is_some()
    }
}

/// A parse-only, bounded external-resource discovery session.
///
/// `resources` is the current ordered frontier. The caller resolves that
/// frontier into an [`ExternalResources`] provider, then calls
/// [`ExternalResourcePlan::continue_with`]. The method replaces it with the
/// next frontier. The plan owns `asset`, so native bindings can retain their
/// own zero-copy byte container without self-referential borrows.
pub struct ExternalResourcePlan<A: AsRef<[u8]>> {
    /// True once an embedded, supplied, or retrieved initial store was located,
    /// before parsing it. A malformed embedded store therefore cannot trigger
    /// a remote-manifest fallback. `false` authorizes a different root fallback
    /// only when [`Self::stop_reason`] is `None` and [`Self::resources`] is empty.
    pub manifest_store_present: bool,
    /// Current first-seen resource frontier.
    pub resources: Vec<ExternalResourceRequest>,
    /// True when discovery terminated before proving the frontier complete.
    pub truncated: bool,
    /// Typed terminal reason when `truncated` is true.
    pub stop_reason: Option<ExternalResourceStopReason>,
    asset: A,
    session: DiscoverySession,
}

impl<A: AsRef<[u8]>> ExternalResourcePlan<A> {
    /// Borrow the original asset for the one final verification pass.
    pub fn asset(&self) -> &[u8] {
        self.asset.as_ref()
    }

    /// DID documents found by parse-only inspection of active ICA identities.
    ///
    /// The list accumulates as retrieved initial stores are parsed. Callers
    /// must prefer a document already pinned in [`VerifyOptions`] and fetch
    /// only entries that remain unresolved.
    pub fn did_documents(&self) -> &[ExternalDidDocumentRequest] {
        &self.session.did_documents
    }

    /// Consume the current frontier from caller-held outcomes and discover the
    /// next manifest-store or append-history frontier. No network I/O or
    /// verification occurs.
    pub fn continue_with(&mut self, resources: &dyn ExternalResources) -> Result<(), Error> {
        if self.stop_reason.is_some() {
            self.resources.clear();
            return Ok(());
        }
        let current = std::mem::take(&mut self.resources);
        let asset = self.asset.as_ref();
        for request in current {
            if request.kind != ExternalResourceKind::SegmentManifestStore {
                continue;
            }
            let is_root = self
                .session
                .uris
                .get(&request.uri)
                .is_some_and(|state| state.root);
            let continued = if is_root {
                resolve_root_uri(
                    asset,
                    &mut self.session,
                    &mut self.resources,
                    resources,
                    &request.uri,
                    &mut self.manifest_store_present,
                )
            } else {
                resolve_segment_uri(
                    asset,
                    &mut self.session,
                    &mut self.resources,
                    resources,
                    &request.uri,
                )
            };
            if !continued {
                break;
            }
        }
        if let Some(reason) = self.session.stop_reason.take() {
            self.stop(reason);
        }
        Ok(())
    }

    fn stop(&mut self, reason: ExternalResourceStopReason) {
        self.resources.clear();
        self.truncated = true;
        self.stop_reason = Some(reason);
    }
}

fn new_plan<A: AsRef<[u8]>>(
    asset: A,
    profile: EngineProfile,
    flavor: Option<AppendOnlyFlavor>,
    limits: GraphLimits,
) -> ExternalResourcePlan<A> {
    ExternalResourcePlan {
        manifest_store_present: false,
        resources: Vec::new(),
        truncated: false,
        stop_reason: None,
        asset,
        session: DiscoverySession {
            profile,
            flavor,
            budget: DiscoveryBudget::new(limits),
            uris: HashMap::new(),
            did_document_ids: HashSet::new(),
            did_documents: Vec::new(),
            stop_reason: None,
        },
    }
}

/// Discover external resources from the same embedded store selected by final
/// verification under the caller-selected policy. Only `spec_version` and
/// `strict_conformance` are consulted; trust, evidence, clocks, and cryptography
/// belong to final verification.
pub fn locate_external_resources<A: AsRef<[u8]>>(
    asset: A,
    mime_type: &str,
    options: &VerifyOptions,
    limits: GraphLimits,
) -> Result<ExternalResourcePlan<A>, Error> {
    let profile =
        crate::resolve_profile(options.spec_version.as_deref(), options.strict_conformance)?;
    let mime = if profile.version == SpecVersion::V2_5 {
        let mime = crate::c2pa_core::spec::canonicalize_mime(mime_type);
        if !crate::c2pa_formats::detached_mime_permitted(&mime, profile.version) {
            return Err(Error::UnsupportedMime(mime));
        }
        mime
    } else {
        crate::resolve_mime(mime_type, profile)?
    };
    let format = match AssetFormat::from_canonical_mime(&mime) {
        Some(format)
            if crate::c2pa_core::spec::reader_permits(&mime, profile.version)
                && crate::require_embedded_mime(&mime, profile).is_ok() =>
        {
            format
        }
        _ if profile.version == SpecVersion::V2_5 => AssetFormat::Opaque,
        _ => return Err(Error::UnsupportedMime(mime)),
    };
    let format = super::spec25::select_format(format, &mime, asset.as_ref(), profile);
    let flavor = match format {
        AssetFormat::AppendOnlyText { flavor } => Some(flavor),
        _ => None,
    };
    let store =
        crate::c2pa_formats::extract_manifest_for_spec(format, asset.as_ref(), profile.version);
    let mut plan = new_plan(asset, profile, flavor, limits);
    match store {
        Ok(Some(store)) => {
            plan.manifest_store_present = true;
            scan_initial_store(
                plan.asset.as_ref(),
                &store,
                &mut plan.session,
                &mut plan.resources,
                None,
                None,
            );
        }
        Ok(None) => {
            if format != AssetFormat::Opaque {
                match crate::c2pa_formats::locate_remote_manifest(format, plan.asset.as_ref()) {
                    Ok(crate::c2pa_formats::RemoteManifestLocation::Remote(remote)) => {
                        add_root_manifest(&mut plan.session, &mut plan.resources, remote.uri);
                    }
                    Ok(crate::c2pa_formats::RemoteManifestLocation::Malformed) => {
                        plan.session
                            .stop(ExternalResourceStopReason::ManifestMalformed { uri: None });
                    }
                    Ok(crate::c2pa_formats::RemoteManifestLocation::Absent) | Err(_) => {}
                }
            }
        }
        Err(_) => plan
            .session
            .stop(ExternalResourceStopReason::ManifestMalformed { uri: None }),
    }
    if let Some(reason) = plan.session.stop_reason.take() {
        plan.stop(reason);
    }
    Ok(plan)
}

/// Discover external resources from a caller-supplied initial store. The
/// supplied store is authoritative even if `asset` also embeds one, matching
/// [`crate::verify_with_manifest_store_and_graph_inputs`]. It is parsed during
/// this call and is not retained by the returned plan. Only the caller's policy
/// and carrier selection are consulted.
pub fn locate_external_resources_with_manifest_store<A: AsRef<[u8]>>(
    asset: A,
    manifest_store: &[u8],
    mime_type: &str,
    options: &VerifyOptions,
    limits: GraphLimits,
) -> Result<ExternalResourcePlan<A>, Error> {
    let profile =
        crate::resolve_profile(options.spec_version.as_deref(), options.strict_conformance)?;
    let mime = crate::resolve_detached_mime(mime_type, profile)?;
    locate_external_resources_with_canonical_manifest_store(
        asset,
        manifest_store,
        &mime,
        profile,
        limits,
    )
}

/// Detached discovery after the facade has normalized and admitted the MIME.
pub(crate) fn locate_external_resources_with_canonical_manifest_store<A: AsRef<[u8]>>(
    asset: A,
    manifest_store: &[u8],
    mime: &str,
    profile: EngineProfile,
    limits: GraphLimits,
) -> Result<ExternalResourcePlan<A>, Error> {
    let format = AssetFormat::from_detached_content_for_profile(mime, asset.as_ref(), profile)
        .map_err(|error| Error::Verification(error.to_string()))?
        .ok_or_else(|| Error::UnsupportedMime(mime.to_string()))?;
    let format = super::spec25::select_format(format, mime, asset.as_ref(), profile);
    let flavor = match format {
        AssetFormat::AppendOnlyText { flavor } => Some(flavor),
        _ => None,
    };
    let mut plan = new_plan(asset, profile, flavor, limits);
    if manifest_store.is_empty() {
        plan.session
            .stop(ExternalResourceStopReason::ManifestMalformed { uri: None });
    } else {
        plan.manifest_store_present = true;
        if manifest_store.len() > crate::MAX_MANIFEST_STORE_BYTES {
            plan.session
                .stop(ExternalResourceStopReason::ManifestMalformed { uri: None });
        } else {
            scan_initial_store(
                plan.asset.as_ref(),
                manifest_store,
                &mut plan.session,
                &mut plan.resources,
                None,
                None,
            );
        }
    }
    if let Some(reason) = plan.session.stop_reason.take() {
        plan.stop(reason);
    }
    Ok(plan)
}

fn scan_initial_store(
    asset: &[u8],
    bytes: &[u8],
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    provider: Option<&dyn ExternalResources>,
    uri: Option<&str>,
) {
    let malformed = || ExternalResourceStopReason::ManifestMalformed {
        uri: uri.map(str::to_string),
    };
    let expanded = match expand_store(bytes) {
        Ok(expanded) => expanded,
        Err(_) => {
            session.stop(malformed());
            return;
        }
    };
    let store = match parse_manifest_store(expanded.bytes()) {
        Ok(store) => store,
        Err(_) => {
            session.stop(malformed());
            return;
        }
    };
    let Some(active_index) = store.manifests.len().checked_sub(1) else {
        session.stop(malformed());
        return;
    };
    let index: HashMap<&str, usize> = store
        .manifests
        .iter()
        .enumerate()
        .map(|(index, manifest)| (manifest.label.as_str(), index))
        .collect();
    let claims: Vec<Option<Value>> = store
        .manifests
        .iter()
        .map(|manifest| manifest.claim_cbor.and_then(|claim| decode(claim).ok()))
        .collect();
    let active_manifest = &store.manifests[active_index];
    let Some(active_claim) = claims[active_index].as_ref() else {
        session.stop(malformed());
        return;
    };
    let active_generation = versions::claim_generation(active_manifest, active_claim);
    let active_refs = ClaimAssertionRefs::build(active_manifest, active_claim, active_generation);
    for (did, url) in super::cawg::locate_identity_did_documents(&active_refs) {
        // The did:web mapper emits HTTPS. Keep the check at this public
        // discovery boundary so malformed future methods never become browser
        // fetch instructions.
        if url.starts_with("https://") && session.did_document_ids.insert(did.clone()) {
            // The plan owns these strings because the parsed store may be a
            // retrieved body borrowed only for this continuation call.
            session
                .did_documents
                .push(ExternalDidDocumentRequest { did, url });
        }
    }

    // Final verification spends this shared budget in the same order: active
    // cloud/external data, linked resources, generic references, ingredient
    // traversal, then append-history predecessors.
    locate_external_data(&active_refs, session, frontier);
    if session.stopped() {
        return;
    }
    if session.profile.version == SpecVersion::V2_5 {
        let (urls, walked) =
            super::spec25::locate_linked_resources(&active_refs, session.budget.references_left());
        if let Err(limit) = session.budget.references(walked.examined) {
            session.graph_stop(limit);
            return;
        }
        if walked.truncated {
            session.graph_stop(GraphLimitKind::References);
            return;
        }
        for url in urls {
            add_opaque(session, frontier, url);
        }
    }
    let (urls, walked) = super::refs::locate_external_references(
        &active_refs,
        active_generation,
        session.profile,
        session.budget.references_left(),
    );
    if let Err(limit) = session.budget.references(walked.examined) {
        session.graph_stop(limit);
        return;
    }
    if walked.truncated {
        session.graph_stop(GraphLimitKind::References);
        return;
    }
    for url in urls {
        add_opaque(session, frontier, url);
    }

    let active_predecessor =
        if session.profile.version == SpecVersion::V2_5 && session.flavor.is_some() {
            let flavor = session.flavor.expect("append-only flavor checked");
            let operative =
                super::caller_binding::operative_reference(&active_refs, false, session.profile)
                    .filter(|reference| {
                        reference
                            .label
                            .is_some_and(super::spec25::is_segment_hash_label)
                    });
            Some(if operative.is_some() {
                super::segment_hash::locate_predecessor_reference(
                    &active_refs,
                    active_claim,
                    asset,
                    flavor,
                )
            } else {
                Err(())
            })
        } else {
            None
        };

    let mut reached = HashSet::from([active_index]);
    let mut queue = VecDeque::from([(active_index, 0usize)]);
    while let Some((manifest_index, depth)) = queue.pop_front() {
        if session.stopped() {
            return;
        }
        let manifest = &store.manifests[manifest_index];
        if let Err(limit) = session.budget.node() {
            session.graph_stop(limit);
            return;
        }
        if let Err(limit) = session.budget.bytes(manifest.manifest_jumbf.len()) {
            session.graph_stop(limit);
            return;
        }
        let Some(claim) = claims[manifest_index].as_ref() else {
            session.stop(malformed());
            return;
        };
        let is_active = manifest_index == active_index;
        let generation = if is_active {
            active_generation
        } else {
            versions::claim_generation(manifest, claim)
        };
        let reached_refs;
        let claim_refs = if is_active {
            &active_refs
        } else {
            reached_refs = ClaimAssertionRefs::build(manifest, claim, generation);
            &reached_refs
        };
        if !is_active && super::ingredient_graph::is_time_stamp_manifest(claim_refs) {
            continue;
        }

        if !is_active {
            let (urls, walked) = super::refs::locate_external_references(
                claim_refs,
                generation,
                session.profile,
                session.budget.references_left(),
            );
            if let Err(limit) = session.budget.references(walked.examined) {
                session.graph_stop(limit);
                return;
            }
            if walked.truncated {
                session.graph_stop(GraphLimitKind::References);
                return;
            }
            for url in urls {
                add_opaque(session, frontier, url);
            }
        }

        enqueue_ingredients(claim_refs, depth, &index, &mut reached, &mut queue, session);
    }
    if session.stopped() {
        return;
    }
    match active_predecessor {
        Some(Ok(Some(reference))) => {
            process_predecessor_reference(asset, session, frontier, provider, reference, 1);
        }
        Some(Ok(None)) | None => {}
        Some(Err(())) => {
            session.stop(malformed());
        }
    }
}

fn enqueue_ingredients(
    claim_refs: &ClaimAssertionRefs<'_>,
    depth: usize,
    index: &HashMap<&str, usize>,
    reached: &mut HashSet<usize>,
    queue: &mut VecDeque<(usize, usize)>,
    session: &mut DiscoverySession,
) {
    for reference in &claim_refs.references {
        let Some(label) = reference
            .label
            .filter(|label| label.starts_with("c2pa.ingredient"))
        else {
            continue;
        };
        let Some(ingredient) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        let target = ingredient
            .get("activeManifest")
            .or_else(|| ingredient.get("c2pa_manifest"))
            .and_then(|link| link.get("url"))
            .and_then(Value::as_text)
            .and_then(super::extract_manifest_label);
        let Some(target) = target else {
            continue;
        };
        if let Err(limit) = session.budget.reference() {
            session.graph_stop(limit);
            return;
        }
        let Some(target) = index.get(target).copied() else {
            continue;
        };
        if !reached.insert(target) {
            continue;
        }
        if let Err(limit) = session.budget.depth(depth.saturating_add(1)) {
            session.graph_stop(limit);
            return;
        }
        queue.push_back((target, depth + 1));
    }
}

fn locate_external_data(
    claim_refs: &ClaimAssertionRefs<'_>,
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
) {
    for reference in &claim_refs.references {
        let Some(label) = reference.label else {
            continue;
        };
        let kind = base_assertion_label(label);
        if kind != "c2pa.cloud-data" && kind != "c2pa.external-reference" {
            continue;
        }
        if let Err(limit) = session.budget.reference() {
            session.graph_stop(limit);
            return;
        }
        let Some(assertion) = claim_refs
            .indexed(label)
            .and_then(|assertion| assertion.decoded.as_ref())
        else {
            continue;
        };
        if kind == "c2pa.cloud-data"
            && (assertion.get("label").and_then(Value::as_text).is_none()
                || assertion.get("size").is_none()
                || assertion
                    .get("location")
                    .and_then(|location| location.get("alg"))
                    .and_then(Value::as_text)
                    .is_none()
                || assertion
                    .get("location")
                    .and_then(|location| location.get("hash"))
                    .and_then(Value::as_bytes)
                    .is_none())
        {
            continue;
        }
        if kind == "c2pa.external-reference" {
            let Some(location) = assertion.get("location") else {
                continue;
            };
            if location.get("alg").is_some() != location.get("hash").is_some() {
                continue;
            }
        }
        let uri = assertion
            .get("location")
            .and_then(|location| location.get("url"))
            .and_then(Value::as_text);
        if let Some(uri) =
            uri.filter(|uri| uri.starts_with("https://") || uri.starts_with("http://"))
        {
            add_opaque(session, frontier, uri.to_string());
        }
    }
}

fn add_opaque(
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    uri: String,
) {
    if session.uris.contains_key(&uri) {
        return;
    }
    session.uris.insert(uri.clone(), UriState::default());
    frontier.push(ExternalResourceRequest {
        uri,
        kind: ExternalResourceKind::Opaque,
    });
}

fn add_root_manifest(
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    uri: String,
) {
    let state = session.uris.entry(uri.clone()).or_default();
    if state.root {
        return;
    }
    state.root = true;
    frontier.push(ExternalResourceRequest {
        uri,
        kind: ExternalResourceKind::SegmentManifestStore,
    });
}

fn process_predecessor_reference(
    asset: &[u8],
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    provider: Option<&dyn ExternalResources>,
    reference: CheckpointReference,
    depth: usize,
) {
    if let Err(limit) = session.budget.reference() {
        session.graph_stop(limit);
        return;
    }
    if let Err(limit) = session.budget.depth(depth) {
        session.graph_stop(limit);
        return;
    }
    match reference {
        CheckpointReference::Inline(store) => {
            if let Err(limit) = session.budget.node() {
                session.graph_stop(limit);
                return;
            }
            scan_predecessor_store(asset, session, frontier, provider, &store, None, depth);
        }
        CheckpointReference::External(uri) => {
            let prior = session.uris.contains_key(&uri);
            if session.uris.get(&uri).is_some_and(|state| state.segment) {
                return;
            }
            if let Err(limit) = session.budget.node() {
                session.graph_stop(limit);
                return;
            }
            let state = session.uris.entry(uri.clone()).or_default();
            state.segment = true;
            state.segment_depth = depth;
            if let Some(request) = frontier.iter_mut().find(|request| request.uri == uri) {
                request.kind = ExternalResourceKind::SegmentManifestStore;
                return;
            }
            if prior {
                let Some(provider) = provider else {
                    session.stop(ExternalResourceStopReason::PredecessorUnavailable { uri });
                    return;
                };
                resolve_segment_uri(asset, session, frontier, provider, &uri);
            } else {
                frontier.push(ExternalResourceRequest {
                    uri,
                    kind: ExternalResourceKind::SegmentManifestStore,
                });
            }
        }
    }
}

fn resolve_root_uri(
    asset: &[u8],
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    provider: &dyn ExternalResources,
    uri: &str,
    manifest_store_present: &mut bool,
) -> bool {
    let Some(state) = session.uris.get_mut(uri) else {
        session.stop(ExternalResourceStopReason::PredecessorUnavailable {
            uri: uri.to_string(),
        });
        return false;
    };
    if state.root_parsed {
        return true;
    }
    state.root_parsed = true;
    match provider.resolve(uri) {
        ExternalResource::Retrieved { bytes, .. } => {
            *manifest_store_present = true;
            // This body has already been held and parsed as the initial store.
            // If its predecessor points back to the same URI, global URI
            // deduplication must not query or parse the body a second time.
            let state = session
                .uris
                .get_mut(uri)
                .expect("root resource state remains present");
            state.segment = true;
            state.segment_parsed = true;
            scan_initial_store(asset, bytes, session, frontier, Some(provider), Some(uri));
            !session.stopped()
        }
        ExternalResource::NotAttempted | ExternalResource::Unavailable => {
            session.stop(ExternalResourceStopReason::PredecessorUnavailable {
                uri: uri.to_string(),
            });
            false
        }
    }
}

fn resolve_segment_uri(
    asset: &[u8],
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    provider: &dyn ExternalResources,
    uri: &str,
) -> bool {
    let depth = {
        let Some(state) = session.uris.get_mut(uri) else {
            session.stop(ExternalResourceStopReason::PredecessorUnavailable {
                uri: uri.to_string(),
            });
            return false;
        };
        if state.segment_parsed {
            return true;
        }
        state.segment_parsed = true;
        state.segment_depth
    };
    match provider.resolve(uri) {
        ExternalResource::Retrieved { bytes, .. } => {
            scan_predecessor_store(
                asset,
                session,
                frontier,
                Some(provider),
                bytes,
                Some(uri),
                depth,
            );
            !session.stopped()
        }
        ExternalResource::NotAttempted | ExternalResource::Unavailable => {
            session.stop(ExternalResourceStopReason::PredecessorUnavailable {
                uri: uri.to_string(),
            });
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_predecessor_store(
    asset: &[u8],
    session: &mut DiscoverySession,
    frontier: &mut Vec<ExternalResourceRequest>,
    provider: Option<&dyn ExternalResources>,
    bytes: &[u8],
    uri: Option<&str>,
    depth: usize,
) {
    let malformed = || ExternalResourceStopReason::ManifestMalformed {
        uri: uri.map(str::to_string),
    };
    if bytes.len() > crate::MAX_MANIFEST_STORE_BYTES {
        session.stop(malformed());
        return;
    }
    let expanded = match expand_store(bytes) {
        Ok(expanded) => expanded,
        Err(_) => {
            session.stop(malformed());
            return;
        }
    };
    let store = match parse_manifest_store(expanded.bytes()) {
        Ok(store) => store,
        Err(_) => {
            session.stop(malformed());
            return;
        }
    };
    let Some(manifest) = store.manifests.last() else {
        session.stop(malformed());
        return;
    };
    if let Err(limit) = session.budget.bytes(manifest.manifest_jumbf.len()) {
        session.graph_stop(limit);
        return;
    }
    let Some(claim) = manifest.claim_cbor.and_then(|claim| decode(claim).ok()) else {
        session.stop(malformed());
        return;
    };
    let generation = versions::claim_generation(manifest, &claim);
    let claim_refs = ClaimAssertionRefs::build(manifest, &claim, generation);
    let Some(flavor) = session.flavor else {
        session.stop(malformed());
        return;
    };
    let operative = super::caller_binding::operative_reference(&claim_refs, false, session.profile)
        .filter(|reference| {
            reference
                .label
                .is_some_and(super::spec25::is_segment_hash_label)
        });
    if operative.is_none() {
        session.stop(malformed());
        return;
    }
    match super::segment_hash::locate_predecessor_reference(&claim_refs, &claim, asset, flavor) {
        Ok(Some(reference)) => process_predecessor_reference(
            asset,
            session,
            frontier,
            provider,
            reference,
            depth.saturating_add(1),
        ),
        Ok(None) => {}
        Err(()) => session.stop(malformed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::Profile;
    use crate::c2pa_core::jumbf::{assertion_box, build_manifest, build_manifest_store};
    use sha2::{Digest, Sha256};

    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }

    fn int(value: usize) -> Value {
        Value::Integer(value as i128)
    }

    fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (text(key), value))
                .collect(),
        )
    }

    fn encode(value: &Value) -> Vec<u8> {
        crate::c2pa_cbor::encode(value, Profile::CanonicalForHashedSubstructures)
            .expect("fixture CBOR")
    }

    fn reference(label: &str) -> Value {
        map(vec![
            ("url", text(&format!("self#jumbf=c2pa.assertions/{label}"))),
            ("alg", text("sha256")),
            ("hash", Value::Bytes(vec![0; 32])),
        ])
    }

    fn claim(labels: &[&str]) -> Vec<u8> {
        encode(&map(vec![
            ("alg", text("sha256")),
            (
                "created_assertions",
                Value::Array(labels.iter().map(|label| reference(label)).collect()),
            ),
        ]))
    }

    fn segment(
        asset: &[u8],
        start: usize,
        end: usize,
        sentinel_length: usize,
        predecessor: Option<(usize, usize)>,
    ) -> Value {
        let mut entries = vec![
            ("version", int(1)),
            ("alg", text("sha256")),
            (
                "hash",
                Value::Bytes(Sha256::digest(&asset[start..end]).to_vec()),
            ),
            ("segmentStart", int(start)),
            ("segmentEnd", int(end)),
            ("sentinelLength", int(sentinel_length)),
        ];
        if let Some((predecessor_start, predecessor_length)) = predecessor {
            entries.push((
                "predecessorSentinel",
                map(vec![
                    ("start", int(predecessor_start)),
                    ("length", int(predecessor_length)),
                    (
                        "hash",
                        Value::Bytes(
                            Sha256::digest(
                                &asset[predecessor_start..predecessor_start + predecessor_length],
                            )
                            .to_vec(),
                        ),
                    ),
                ]),
            ));
        }
        map(entries)
    }

    fn sentinel(uri: &str) -> String {
        format!("-----BEGIN C2PA CHECKPOINT----- {uri} -----END C2PA CHECKPOINT-----\n")
    }

    fn store(label: &str, assertions: Vec<(&str, Value)>) -> Vec<u8> {
        let labels: Vec<&str> = assertions.iter().map(|(label, _)| *label).collect();
        let boxes: Vec<Vec<u8>> = assertions
            .into_iter()
            .map(|(label, value)| assertion_box(label, &encode(&value), None))
            .collect();
        let manifest = build_manifest(label, &boxes, &claim(&labels), &[0xd2, 0x84]);
        build_manifest_store(&[manifest])
    }

    #[test]
    fn unknown_policy_fails_before_locator_parsing() {
        let options = VerifyOptions {
            spec_version: Some("next".into()),
            ..VerifyOptions::default()
        };
        let error = match locate_external_resources(
            b"not a jpeg".to_vec(),
            "image/jpeg",
            &options,
            GraphLimits::default(),
        ) {
            Ok(_) => panic!("unknown policy accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::UnsupportedSpecVersion(_)));
    }

    #[test]
    fn external_only_mime_is_admitted_for_25_discovery_but_not_older_policy() {
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let plan = locate_external_resources(
            b"external-only".to_vec(),
            "application/vnd.example.future",
            &options,
            GraphLimits::default(),
        )
        .expect("2.5 external-only discovery");
        assert!(!plan.manifest_store_present);
        assert!(plan.resources.is_empty());
        assert_eq!(plan.stop_reason, None);

        let old = locate_external_resources(
            b"external-only".to_vec(),
            "application/vnd.example.future",
            &VerifyOptions::default(),
            GraphLimits::default(),
        );
        assert!(matches!(old, Err(Error::UnsupportedMime(_))));

        let malformed = locate_external_resources(
            b"external-only".to_vec(),
            "not a mime",
            &options,
            GraphLimits::default(),
        );
        assert!(matches!(malformed, Err(Error::UnsupportedMime(_))));
    }

    #[test]
    fn extraction_error_is_a_typed_no_fallback_stop_without_presence() {
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let plan = locate_external_resources(
            b"not a jpeg".to_vec(),
            "image/jpeg",
            &options,
            GraphLimits::default(),
        )
        .expect("typed extraction stop");
        assert!(!plan.manifest_store_present);
        assert!(plan.truncated);
        assert_eq!(
            plan.stop_reason,
            Some(ExternalResourceStopReason::ManifestMalformed { uri: None })
        );
        assert!(plan.resources.is_empty());
    }

    #[test]
    fn malformed_initial_store_is_present_and_blocks_fallback() {
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let plan = locate_external_resources_with_manifest_store(
            Vec::from(&b"asset"[..]),
            b"not a manifest store",
            "text/plain",
            &options,
            GraphLimits::default(),
        )
        .expect("parse-only plan");
        assert!(plan.manifest_store_present);
        assert!(plan.truncated);
        assert_eq!(
            plan.stop_reason,
            Some(ExternalResourceStopReason::ManifestMalformed { uri: None })
        );
        assert!(plan.resources.is_empty());
        assert_eq!(plan.asset(), b"asset");
    }

    #[test]
    fn graph_node_limit_is_typed_for_the_initial_manifest() {
        let initial = store("urn:c2pa:active", Vec::new());
        let plan = locate_external_resources_with_manifest_store(
            &b"asset"[..],
            &initial,
            "text/plain",
            &VerifyOptions::default(),
            GraphLimits::lowered(32, 0, usize::MAX, usize::MAX),
        )
        .expect("parse-only plan");
        assert!(plan.manifest_store_present);
        assert_eq!(
            plan.stop_reason,
            Some(ExternalResourceStopReason::GraphLimitExceeded {
                limit: GraphLimitKind::Nodes,
            })
        );
        assert!(plan.resources.is_empty());
    }

    #[test]
    fn opaque_uri_promotes_from_an_earlier_frontier_without_refetching() {
        const EARLY_URI: &str = "https://e.example/early.c2pa";
        const MIDDLE_URI: &str = "https://e.example/middle.c2pa";
        const ACTIVE_URI: &str = "https://e.example/active.c2pa";

        let mut asset = b"alpha\n".to_vec();
        let early_line = sentinel(EARLY_URI);
        asset.extend_from_slice(early_line.as_bytes());
        let middle_start = asset.len();
        asset.extend_from_slice(b"bravo\n");
        let middle_end = asset.len();
        let middle_line = sentinel(MIDDLE_URI);
        asset.extend_from_slice(middle_line.as_bytes());
        let active_start = asset.len();
        asset.extend_from_slice(b"charlie\n");
        let active_end = asset.len();
        let active_line = sentinel(ACTIVE_URI);
        asset.extend_from_slice(active_line.as_bytes());

        let active_segment = segment(
            &asset,
            active_start,
            active_end,
            active_line.len(),
            Some((middle_end, middle_line.len())),
        );
        let cloud = map(vec![
            ("label", text("c2pa.metadata")),
            ("size", int(1)),
            (
                "location",
                map(vec![
                    ("url", text(EARLY_URI)),
                    ("alg", text("sha256")),
                    ("hash", Value::Bytes(vec![0; 32])),
                ]),
            ),
        ]);
        let active_store = store(
            "urn:c2pa:active",
            vec![
                ("c2pa.cloud-data", cloud),
                ("c2pa.hash.segment", active_segment),
            ],
        );
        let middle_segment = segment(
            &asset,
            middle_start,
            middle_end,
            middle_line.len(),
            Some((6, early_line.len())),
        );
        let middle_store = store(
            "urn:c2pa:middle",
            vec![("c2pa.hash.segment", middle_segment)],
        );
        let early_segment = segment(&asset, 0, 6, early_line.len(), None);
        let early_store = store("urn:c2pa:early", vec![("c2pa.hash.segment", early_segment)]);
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let mut plan = locate_external_resources_with_manifest_store(
            asset,
            &active_store,
            "text/plain",
            &options,
            GraphLimits::default(),
        )
        .expect("initial discovery");
        assert_eq!(
            plan.resources,
            vec![
                ExternalResourceRequest {
                    uri: EARLY_URI.into(),
                    kind: ExternalResourceKind::Opaque,
                },
                ExternalResourceRequest {
                    uri: MIDDLE_URI.into(),
                    kind: ExternalResourceKind::SegmentManifestStore,
                },
            ]
        );

        struct Provider<'a> {
            early: &'a [u8],
            middle: &'a [u8],
            calls: std::cell::RefCell<Vec<String>>,
        }
        impl ExternalResources for Provider<'_> {
            fn resolve(&self, uri: &str) -> ExternalResource<'_> {
                self.calls.borrow_mut().push(uri.to_string());
                let bytes = match uri {
                    EARLY_URI => self.early,
                    MIDDLE_URI => self.middle,
                    _ => panic!("unexpected URI {uri}"),
                };
                ExternalResource::Retrieved {
                    bytes,
                    media_type: Some("application/c2pa"),
                }
            }
        }
        let provider = Provider {
            early: &early_store,
            middle: &middle_store,
            calls: std::cell::RefCell::new(Vec::new()),
        };
        plan.continue_with(&provider).expect("continue discovery");
        assert!(plan.resources.is_empty());
        assert!(!plan.truncated);
        assert_eq!(plan.stop_reason, None);
        assert_eq!(
            provider.calls.into_inner(),
            vec![MIDDLE_URI.to_string(), EARLY_URI.to_string()]
        );
    }

    #[test]
    fn append_only_root_uri_uses_the_format_locator_and_continues_as_an_initial_store() {
        const ROOT_URI: &str = "https://e.example/active.c2pa";
        let root_line = sentinel(ROOT_URI);
        let prefix = b"root\n";
        let mut asset = prefix.to_vec();
        asset.extend_from_slice(root_line.as_bytes());
        let root_store = store(
            "urn:c2pa:root",
            vec![(
                "c2pa.hash.segment",
                segment(&asset, 0, prefix.len(), root_line.len(), None),
            )],
        );
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let mut plan =
            locate_external_resources(asset, "text/plain", &options, GraphLimits::default())
                .expect("root discovery");
        assert!(!plan.manifest_store_present);
        assert_eq!(
            plan.resources,
            vec![ExternalResourceRequest {
                uri: ROOT_URI.into(),
                kind: ExternalResourceKind::SegmentManifestStore,
            }]
        );

        struct RootProvider<'a> {
            store: &'a [u8],
            calls: std::cell::Cell<usize>,
        }
        impl ExternalResources for RootProvider<'_> {
            fn resolve(&self, uri: &str) -> ExternalResource<'_> {
                assert_eq!(uri, ROOT_URI);
                self.calls.set(self.calls.get() + 1);
                ExternalResource::Retrieved {
                    bytes: self.store,
                    media_type: Some("application/c2pa"),
                }
            }
        }
        let provider = RootProvider {
            store: &root_store,
            calls: std::cell::Cell::new(0),
        };
        plan.continue_with(&provider).expect("root continuation");
        assert!(plan.manifest_store_present);
        assert!(plan.resources.is_empty());
        assert!(!plan.truncated);
        assert_eq!(plan.stop_reason, None);
        assert_eq!(provider.calls.get(), 1);
    }

    #[test]
    fn malformed_terminal_checkpoint_never_falls_back_to_an_older_external_root() {
        let asset = format!(
            "body\n{}{}",
            sentinel("https://e.example/older.c2pa"),
            sentinel("data:application/c2pa;base64,***")
        );
        let options = VerifyOptions {
            spec_version: Some("2.5".into()),
            ..VerifyOptions::default()
        };
        let plan = locate_external_resources(
            asset.into_bytes(),
            "text/plain",
            &options,
            GraphLimits::default(),
        )
        .expect("terminal selection");
        assert!(!plan.manifest_store_present);
        assert!(plan.truncated);
        assert!(plan.resources.is_empty());
        assert_eq!(
            plan.stop_reason,
            Some(ExternalResourceStopReason::ManifestMalformed { uri: None })
        );
    }

    #[test]
    fn unavailable_predecessor_is_typed_without_flattening_provider_outcome() {
        struct Denied;
        impl ExternalResources for Denied {
            fn resolve(&self, _: &str) -> ExternalResource<'_> {
                ExternalResource::NotAttempted
            }
        }

        let mut plan = new_plan(
            Vec::<u8>::new(),
            EngineProfile::GENEROUS,
            Some(AppendOnlyFlavor::PlainText),
            GraphLimits::default(),
        );
        let uri = "https://e.example/predecessor.c2pa".to_string();
        plan.session.uris.insert(
            uri.clone(),
            UriState {
                segment: true,
                segment_depth: 1,
                ..UriState::default()
            },
        );
        plan.resources.push(ExternalResourceRequest {
            uri: uri.clone(),
            kind: ExternalResourceKind::SegmentManifestStore,
        });
        plan.continue_with(&Denied).expect("typed stop");
        assert!(plan.resources.is_empty());
        assert_eq!(
            plan.stop_reason,
            Some(ExternalResourceStopReason::PredecessorUnavailable { uri })
        );
    }
}
