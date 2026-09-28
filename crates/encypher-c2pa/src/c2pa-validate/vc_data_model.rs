// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! W3C Verifiable Credentials Data Model checks for CAWG identity claims
//! aggregation credentials (CAWG-ID13-ICA-TECH-A-004).
//!
//! The verifier performs VC 2.0 section 6.3 "type-specific credential
//! processing": it understands exactly four JSON-LD contexts, pinned by the
//! SHA-256 of their served bytes and embedded here, never retrieves a context,
//! and performs no JSON-LD expansion. What that profile cannot establish fails
//! closed. The V-nn ids refer to the requirement rows of
//! `PRDs/CURRENT/cawg13-vc-data-model.md`.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use serde_json::{Map, Value as Json};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use time::OffsetDateTime;

use super::cawg_ica::{base64_decode, is_uri, json_type_contains};

pub(super) const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";
pub(super) const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub(super) const CAWG_ICA_CONTEXT: &str = "https://cawg.io/identity/1.1/ica/context/";
pub(super) const STATUS_CONTEXT_V1: &str = "https://www.w3.org/ns/credentials/status/v1";

/// The pinned context documents, byte for byte as served.
const PINNED_CONTEXTS: [(&str, &[u8]); 4] = [
    (
        VC_CONTEXT_V1,
        include_bytes!("contexts/credentials-v1.jsonld"),
    ),
    (
        VC_CONTEXT_V2,
        include_bytes!("contexts/credentials-v2.jsonld"),
    ),
    (
        CAWG_ICA_CONTEXT,
        include_bytes!("contexts/cawg-ica-1.1.jsonld"),
    ),
    (
        STATUS_CONTEXT_V1,
        include_bytes!("contexts/credentials-status-v1.jsonld"),
    ),
];

/// Precomputed digests of one pinned context document.
struct PinnedDigests {
    sha256: [u8; 32],
    sha384: [u8; 48],
    sha512: [u8; 64],
}

/// Hash each vendored context once. Credential-supplied digest arrays compare
/// against this cache instead of repeatedly hashing documents before trust and
/// signature checks.
static PINNED_DIGESTS: LazyLock<[PinnedDigests; PINNED_CONTEXTS.len()]> = LazyLock::new(|| {
    PINNED_CONTEXTS.map(|(_, bytes)| PinnedDigests {
        sha256: Sha256::digest(bytes).into(),
        sha384: Sha384::digest(bytes).into(),
        sha512: Sha512::digest(bytes).into(),
    })
});

/// The VC data-model version selected by `@context[0]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VcVersion {
    V1_1,
    V2_0,
}

impl VcVersion {
    pub(super) fn label(self) -> &'static str {
        match self {
            VcVersion::V1_1 => "1.1",
            VcVersion::V2_0 => "2.0",
        }
    }
}

/// Why a credential is not accepted as a verifiable credential.
pub(super) enum CredentialDefect {
    /// The credential breaks a data-model rule, or a shape rule of the
    /// supported profile; the text names it.
    Malformed(Cow<'static, str>),
    /// A context the verifier does not understand: an unpinned URL,
    /// `<inline>` for an object item, or `<embedded>` for a node `@context`.
    UnsupportedContext(Vec<String>),
}

impl From<&'static str> for CredentialDefect {
    fn from(explanation: &'static str) -> Self {
        CredentialDefect::Malformed(Cow::Borrowed(explanation))
    }
}

type Checked = Result<(), CredentialDefect>;

/// VC 2.0 identifiers are WHATWG URLs; VC 1.1 identifiers are RFC 3986 URIs.
pub(super) fn is_identifier(text: &str, version: VcVersion) -> bool {
    match version {
        VcVersion::V2_0 => is_url(text),
        VcVersion::V1_1 => is_uri(text),
    }
}

/// A valid absolute URL string: the URL Standard parser succeeds and reports
/// no validation error.
fn is_url(text: &str) -> bool {
    let violated = Cell::new(false);
    let note = |_| violated.set(true);
    url::Url::options()
        .syntax_violation_callback(Some(&note))
        .parse(text)
        .is_ok()
        && !violated.get()
}

/// V-13: "terms and absolute URL strings". A value with a colon must be an
/// identifier (absolute or compact IRI); one without is a term, which the
/// CAWG context's `@vocab` maps.
pub(super) fn is_type_name(value: &str, version: VcVersion) -> bool {
    !value.is_empty()
        && !value.starts_with('@')
        && (!value.contains(':') || is_identifier(value, version))
}

/// V-03, V-05, V-06, V-07: items after the base context are pinned URLs,
/// unique, with one base context. Object items are outside the profile.
pub(super) fn check_context_list(contexts: &[Json], version: VcVersion) -> Checked {
    let mut seen = HashSet::new();
    if let Some(base) = contexts.first().and_then(Json::as_str) {
        seen.insert(base);
    }
    for item in contexts.iter().skip(1) {
        match item {
            Json::String(url) => {
                if !is_identifier(url, version) {
                    return Err("@context item is not a URL".into());
                }
                if !seen.insert(url.as_str()) {
                    return Err("@context repeats an item".into());
                }
                if url == VC_CONTEXT_V1 || url == VC_CONTEXT_V2 {
                    return Err("@context lists more than one data-model base context".into());
                }
                if url != CAWG_ICA_CONTEXT && url != STATUS_CONTEXT_V1 {
                    // Stop at the first unknown context. This bounds both
                    // pre-authentication work and report growth.
                    return Err(CredentialDefect::UnsupportedContext(vec![url.clone()]));
                }
            }
            Json::Object(_) => {
                return Err(CredentialDefect::UnsupportedContext(vec![
                    "<inline>".to_string()
                ]));
            }
            _ => return Err("@context item is neither a URL nor a context object".into()),
        }
    }
    Ok(())
}

/// Term IRIs and prefixes of an active pinned context set, taken from every
/// scope of its vendored documents.
struct PinnedTerms {
    /// The IRI each term definition maps to.
    iris: HashSet<String>,
    /// Terms usable as a compact-IRI prefix, per JSON-LD 1.1 section 4.4.
    prefixes: HashMap<String, String>,
}

/// Pinned term sets for each base context, with and without the optional
/// Bitstring Status List context.
static PINNED_TERMS: LazyLock<[PinnedTerms; 4]> = LazyLock::new(|| {
    [
        PinnedTerms::from_documents(&[PINNED_CONTEXTS[0].1, PINNED_CONTEXTS[2].1]),
        PinnedTerms::from_documents(&[
            PINNED_CONTEXTS[0].1,
            PINNED_CONTEXTS[2].1,
            PINNED_CONTEXTS[3].1,
        ]),
        PinnedTerms::from_documents(&[PINNED_CONTEXTS[1].1, PINNED_CONTEXTS[2].1]),
        PinnedTerms::from_documents(&[
            PINNED_CONTEXTS[1].1,
            PINNED_CONTEXTS[2].1,
            PINNED_CONTEXTS[3].1,
        ]),
    ]
});

impl PinnedTerms {
    fn for_contexts(version: VcVersion, contexts: &[Json]) -> &'static PinnedTerms {
        let has_status = contexts
            .iter()
            .any(|context| context.as_str() == Some(STATUS_CONTEXT_V1));
        match (version, has_status) {
            (VcVersion::V1_1, false) => &PINNED_TERMS[0],
            (VcVersion::V1_1, true) => &PINNED_TERMS[1],
            (VcVersion::V2_0, false) => &PINNED_TERMS[2],
            (VcVersion::V2_0, true) => &PINNED_TERMS[3],
        }
    }

    fn from_documents(documents: &[&[u8]]) -> PinnedTerms {
        let contexts: Vec<Json> = documents
            .iter()
            .map(|bytes| {
                let document: Json = serde_json::from_slice(bytes).expect("pinned context is JSON");
                document["@context"].clone()
            })
            .collect();
        let mut definitions = Vec::new();
        for context in &contexts {
            collect_definitions(context, &mut definitions);
        }
        let mut terms = PinnedTerms {
            iris: HashSet::new(),
            prefixes: HashMap::new(),
        };
        // Prefix mappings first: term IRIs are then expanded against them.
        for (term, definition) in &definitions {
            match definition {
                Json::String(iri)
                    if !term.contains([':', '/'])
                        && iri.ends_with([':', '/', '?', '#', '[', ']', '@']) =>
                {
                    terms.prefixes.insert(term.to_string(), iri.clone());
                }
                Json::Object(expanded) if expanded.get("@prefix") == Some(&Json::Bool(true)) => {
                    if let Some(iri) = expanded.get("@id").and_then(Json::as_str) {
                        terms.prefixes.insert(term.to_string(), iri.to_string());
                    }
                }
                _ => {}
            }
        }
        for (_, definition) in &definitions {
            let iri = match definition {
                Json::String(iri) => Some(iri.as_str()),
                Json::Object(expanded) => expanded.get("@id").and_then(Json::as_str),
                _ => None,
            };
            if let Some(iri) = iri.filter(|iri| !iri.starts_with('@') && iri.contains(':')) {
                let expanded = terms.expand(iri).into_owned();
                terms.iris.insert(expanded);
            }
        }
        terms
    }

    /// Expand a compact IRI whose prefix is a pinned prefix; anything else
    /// is returned unchanged (an absolute IRI, or an unknown prefix).
    fn expand<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match text.split_once(':') {
            Some((prefix, suffix)) if !suffix.starts_with("//") => {
                match self.prefixes.get(prefix) {
                    Some(iri) => Cow::Owned(format!("{iri}{suffix}")),
                    None => Cow::Borrowed(text),
                }
            }
            _ => Cow::Borrowed(text),
        }
    }
}

/// Every `(term, definition)` of a context definition and of the scoped
/// contexts nested in its term definitions.
fn collect_definitions<'a>(context: &'a Json, into: &mut Vec<(&'a str, &'a Json)>) {
    let Some(context) = context.as_object() else {
        return;
    };
    for (term, definition) in context {
        if term.starts_with('@') {
            continue;
        }
        into.push((term, definition));
        if let Some(scoped) = definition.get("@context") {
            collect_definitions(scoped, into);
        }
    }
}

/// The `@json` terms of the pinned VC 2.0 context, by scope. VC 1.1 and the
/// CAWG context define none. A unit test checks this table against the
/// vendored bytes.
const V2_JSON_TOP_LEVEL: &str = "_sd";
const V2_JSON_TYPE_SCOPED: (&str, &str) = ("JsonSchema", "jsonSchema");
const V2_JSON_PROPERTY_SCOPED: (&str, &str) = ("cnf", "jwk");

/// Where a map sits, as far as the uniqueness rule (V-36d) and the
/// identifier datatype rule (V-36c) care.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Credential,
    Subject,
    /// An entry of `credentialSubject.verifiedIdentities`.
    Identity,
    /// The `provider` of such an entry.
    Provider,
    Issuer,
    /// An entry of the credential's `relatedResource`.
    Related,
    Other,
}

impl Role {
    /// Maps the verifier validates in place; a second description of their
    /// identifier would add values it never read.
    fn is_validated(self) -> bool {
        matches!(
            self,
            Role::Credential | Role::Subject | Role::Identity | Role::Provider | Role::Issuer
        )
    }

    fn child(self, key: &str) -> Role {
        match (self, key) {
            (Role::Credential, "credentialSubject") => Role::Subject,
            (Role::Credential, "issuer") => Role::Issuer,
            (Role::Credential, "relatedResource") => Role::Related,
            (Role::Subject, "verifiedIdentities") => Role::Identity,
            (Role::Identity, "provider") => Role::Provider,
            _ => Role::Other,
        }
    }
}

/// V-36 body walk: keyword keys, IRI keys, embedded contexts, node
/// identifiers, and one description per identifier.
struct BodyWalk {
    version: VcVersion,
    terms: &'static PinnedTerms,
    /// Normalized identifier to the role of the map that described it.
    described: HashMap<String, Role>,
    /// Identifiers named by `relatedResource` integrity references.
    integrity: Vec<String>,
}

pub(super) fn check_body(
    credential: &Map<String, Json>,
    contexts: &[Json],
    version: VcVersion,
) -> Checked {
    let mut walk = BodyWalk {
        version,
        terms: PinnedTerms::for_contexts(version, contexts),
        described: HashMap::new(),
        integrity: Vec::new(),
    };
    walk.node(credential, Role::Credential, false)?;
    for identifier in &walk.integrity {
        if walk
            .described
            .get(identifier)
            .is_some_and(|role| role.is_validated())
        {
            return Err(CredentialDefect::Malformed(Cow::Owned(format!(
                "relatedResource describes `{identifier}`, which the credential already describes"
            ))));
        }
    }
    Ok(())
}

impl BodyWalk {
    fn value(&mut self, value: &Json, role: Role, in_cnf: bool) -> Checked {
        match value {
            Json::Array(items) => items
                .iter()
                .try_for_each(|item| self.value(item, role, in_cnf)),
            Json::Object(map) => self.map(map, role, in_cnf),
            _ => Ok(()),
        }
    }

    fn map(&mut self, map: &Map<String, Json>, role: Role, in_cnf: bool) -> Checked {
        // Expansion processes `@context` in every map it meets.
        if map.contains_key("@context") {
            return Err(CredentialDefect::UnsupportedContext(vec![
                "<embedded>".to_string()
            ]));
        }
        if map.contains_key("@value") {
            return value_object_defect(map, self.version)
                .map_or(Ok(()), |defect| Err(defect.into()));
        }
        if let Some(items) = map.get("@list") {
            if map.len() != 1 {
                return Err("a list object carries a key besides @list".into());
            }
            return self.value(items, Role::Other, in_cnf);
        }
        self.node(map, role, in_cnf)
    }

    fn node(&mut self, node: &Map<String, Json>, role: Role, in_cnf: bool) -> Checked {
        for key in node.keys() {
            if role == Role::Credential && key == "@context" {
                continue;
            }
            // V-36a: compaction under the pinned contexts writes no keyword
            // key on a node; `@nest` would merge its members into this node.
            if key.starts_with('@') {
                return Err(CredentialDefect::Malformed(Cow::Owned(format!(
                    "`{key}` is a JSON-LD keyword key outside a value or list object"
                ))));
            }
            // V-36b: an IRI key for a pinned term's property merges with it.
            if key.contains(':') && self.terms.iris.contains(self.terms.expand(key).as_ref()) {
                return Err(CredentialDefect::Malformed(Cow::Owned(format!(
                    "`{key}` is an IRI key for a property the pinned contexts name by a term"
                ))));
            }
        }
        self.identify(node, role)?;
        let json_scoped = self.version == VcVersion::V2_0
            && json_type_contains(node.get("type"), V2_JSON_TYPE_SCOPED.0);
        for (key, value) in node {
            if role == Role::Credential && key == "@context" {
                continue;
            }
            if self.version == VcVersion::V2_0
                && (key == V2_JSON_TOP_LEVEL
                    || (json_scoped && key == V2_JSON_TYPE_SCOPED.1)
                    || (in_cnf && key == V2_JSON_PROPERTY_SCOPED.1))
            {
                continue;
            }
            let in_cnf =
                in_cnf || (self.version == VcVersion::V2_0 && key == V2_JSON_PROPERTY_SCOPED.0);
            self.value(value, role.child(key), in_cnf)?;
        }
        Ok(())
    }

    /// V-36c and V-36d for one node.
    fn identify(&mut self, node: &Map<String, Json>, role: Role) -> Checked {
        let (identifier_key, identifier) = match (node.get("id"), node.get("uri")) {
            (Some(_), Some(_)) => return Err("a node carries both `id` and `uri`".into()),
            (Some(identifier), None) => ("id", identifier),
            (None, Some(identifier)) => ("uri", identifier),
            (None, None) => return Ok(()),
        };
        // Preserve CAWG's dedicated codes only for fields its own checks
        // consume. The issuer is checked below parse; Identity `uri` and
        // Provider `id` are checked by `verified_identity_defect`.
        let checked_by_cawg = role == Role::Issuer
            || (role == Role::Identity && identifier_key == "uri")
            || (role == Role::Provider && identifier_key == "id");
        let Some(identifier) = identifier.as_str() else {
            if checked_by_cawg {
                return Ok(());
            }
            return Err("a node identifier is not a single URL".into());
        };
        if !checked_by_cawg && !is_identifier(identifier, self.version) {
            return Err("a node identifier is not a URL".into());
        }
        if node.len() == 1 {
            return Ok(()); // A reference, not a description.
        }
        let identifier = self.terms.expand(identifier).into_owned();
        if role == Role::Related
            && node.iter().all(|(key, value)| match key.as_str() {
                "id" | "digestSRI" | "digestMultibase" => true,
                "mediaType" => value.is_string(),
                _ => false,
            })
        {
            self.integrity.push(identifier);
            return Ok(());
        }
        match self.described.get(&identifier) {
            None => {
                self.described.insert(identifier, role);
                Ok(())
            }
            // Providers are validated where they stand, so the subject's
            // identities may share one (a production Adobe credential names
            // the same provider "linkedin" and "LINKEDIN").
            Some(Role::Provider) if role == Role::Provider => Ok(()),
            Some(_) => Err(CredentialDefect::Malformed(Cow::Owned(format!(
                "`{identifier}` is described by more than one map"
            )))),
        }
    }
}

/// V-36a: a value object that JSON-LD 1.1 API Expansion step 15 accepts,
/// written with the pinned `type` alias.
fn value_object_defect(value: &Map<String, Json>, version: VcVersion) -> Option<&'static str> {
    if !value
        .keys()
        .all(|key| matches!(key.as_str(), "@value" | "@language" | "@direction" | "type"))
    {
        return Some(
            "a value object carries a key besides @value, @language, @direction, and type",
        );
    }
    let literal = &value["@value"];
    match value.get("type") {
        Some(_) if value.contains_key("@language") || value.contains_key("@direction") => {
            Some("a typed value object also carries @language or @direction")
        }
        Some(Json::String(json)) if json == "@json" => None,
        Some(Json::String(datatype)) => {
            (!is_type_name(datatype, version) || datatype.starts_with("_:") || !is_scalar(literal))
                .then_some("a typed value object has an invalid type or a non-scalar @value")
        }
        Some(_) => Some("a value object type is not a string"),
        None if value.contains_key("@language") || value.contains_key("@direction") => {
            (!language_tagged_value(value)).then_some("a language-tagged value object is malformed")
        }
        None => (!is_scalar(literal)).then_some("a value object has a non-scalar @value"),
    }
}

fn is_scalar(value: &Json) -> bool {
    !matches!(value, Json::Array(_) | Json::Object(_))
}

/// V-17 and Expansion step 15.4: a string `@value`, a string `@language`,
/// and a base-direction `@direction`.
fn language_tagged_value(value: &Map<String, Json>) -> bool {
    value.get("@value").is_some_and(Json::is_string)
        && value.get("@language").is_none_or(Json::is_string)
        && value
            .get("@direction")
            .is_none_or(|direction| matches!(direction.as_str(), Some("ltr" | "rtl")))
}

/// Check the credential-level properties rows V-15 to V-17, V-24 to V-32,
/// and V-35 describe.
pub(super) fn check_properties(credential: &Map<String, Json>, version: VcVersion) -> Checked {
    let v2 = version == VcVersion::V2_0;
    if v2 {
        for property in ["name", "description"] {
            if credential
                .get(property)
                .is_some_and(|value| !natural_language_value(value))
            {
                return Err(CredentialDefect::Malformed(Cow::Owned(format!(
                    "{property} is not a string or language value"
                ))));
            }
        }
        if let Some(resources) = credential.get("relatedResource") {
            related_resources(resources, version)?;
        }
    }
    let v1 = !v2;
    // (property, defined in this version, `id` required)
    for (property, defined, id_required) in [
        ("credentialStatus", true, v1),
        ("credentialSchema", true, true),
        ("refreshService", true, v1),
        ("termsOfUse", true, false),
        ("evidence", true, false),
        ("proof", true, false),
        ("confidenceMethod", v2, false),
        ("renderMethod", v2, false),
    ] {
        if defined
            && credential
                .get(property)
                .is_some_and(|value| !typed_objects(value, id_required, version))
        {
            return Err(CredentialDefect::Malformed(Cow::Owned(format!(
                "{property} is not one or more typed objects with URL identifiers"
            ))));
        }
    }
    Ok(())
}

/// A single object or a non-empty array of objects.
fn one_or_more_objects(value: &Json) -> Option<&[Json]> {
    match value {
        Json::Object(_) => Some(std::slice::from_ref(value)),
        Json::Array(items) if !items.is_empty() && items.iter().all(Json::is_object) => Some(items),
        _ => None,
    }
}

/// V-15: one or more objects, each with a `type` and an identifier (which
/// may be absent unless `id_required`).
fn typed_objects(value: &Json, id_required: bool, version: VcVersion) -> bool {
    one_or_more_objects(value).is_some_and(|items| {
        items.iter().all(|item| {
            let types_ok = match item.get("type") {
                Some(Json::String(name)) => is_type_name(name, version),
                Some(Json::Array(names)) => {
                    !names.is_empty()
                        && names.iter().all(|name| {
                            name.as_str()
                                .is_some_and(|name| is_type_name(name, version))
                        })
                }
                _ => false,
            };
            let id_ok = match item.get("id") {
                Some(id) => id.as_str().is_some_and(|id| is_identifier(id, version)),
                None => !id_required,
            };
            types_ok && id_ok
        })
    })
}

/// V-16, V-17: a string, a language value object, or a non-empty array of
/// them (VC 2.0 sections 4.6 and 11.1).
fn natural_language_value(value: &Json) -> bool {
    let single = |value: &Json| match value {
        Json::String(_) => true,
        Json::Object(language_value) => {
            language_value
                .keys()
                .all(|key| matches!(key.as_str(), "@value" | "@language" | "@direction"))
                && language_tagged_value(language_value)
        }
        _ => false,
    };
    match value {
        Json::Array(values) => !values.is_empty() && values.iter().all(single),
        value => single(value),
    }
}

/// V-30, V-31: `relatedResource` entries have a unique identifier and at
/// least one well-formed digest. An entry naming a pinned context must match
/// the pinned bytes, since the verifier makes use of that resource.
fn related_resources(value: &Json, version: VcVersion) -> Checked {
    let items = one_or_more_objects(value).ok_or("relatedResource is not one or more objects")?;
    let mut ids = HashSet::with_capacity(items.len());
    for item in items {
        let Some(id) = item.get("id").and_then(Json::as_str) else {
            return Err("a relatedResource entry lacks an id".into());
        };
        if !is_identifier(id, version) {
            return Err("a relatedResource id is not a URL".into());
        }
        if !ids.insert(id) {
            return Err("relatedResource ids repeat".into());
        }
        if item
            .get("mediaType")
            .is_some_and(|media| !media.is_string())
        {
            return Err("a relatedResource mediaType is not a string".into());
        }
        let pinned = PINNED_CONTEXTS
            .iter()
            .position(|(url, _)| *url == id)
            .map(|index| &PINNED_DIGESTS[index]);
        let mut has_digest = false;
        let mut digest_count = 0;
        let mut seen_digests = HashSet::new();
        for expression in strings(item.get("digestSRI"))? {
            let expression = expression?;
            check_digest_cardinality(expression, &mut digest_count, &mut seen_digests)?;
            has_digest = true;
            let (algorithm, digest) = sri_hash(expression).map_err(digest_defect)?;
            if let Some(pinned) = pinned {
                if digest != algorithm.cached(pinned) {
                    return Err("a relatedResource digest does not match the pinned context".into());
                }
            }
        }
        for encoded in strings(item.get("digestMultibase"))? {
            let encoded = encoded?;
            check_digest_cardinality(encoded, &mut digest_count, &mut seen_digests)?;
            has_digest = true;
            const NOT_MULTIHASH: &str =
                "a digestMultibase value is not a multibase-encoded multihash";
            let decoded = multibase_decode(encoded).map_err(|error| match error {
                DigestDecodeError::TooLong => digest_defect(error),
                DigestDecodeError::Invalid => NOT_MULTIHASH.into(),
            })?;
            let (code, digest) = multihash(&decoded).ok_or(NOT_MULTIHASH)?;
            if let Some(pinned) = pinned {
                let algorithm = match code {
                    0x12 => DigestAlgorithm::Sha256,
                    0x20 => DigestAlgorithm::Sha384,
                    0x13 => DigestAlgorithm::Sha512,
                    _ => {
                        return Err(
                            "a relatedResource digest for a pinned context uses an algorithm the verifier cannot compute"
                                .into(),
                        )
                    }
                };
                if digest != algorithm.cached(pinned) {
                    return Err("a relatedResource digest does not match the pinned context".into());
                }
            }
        }
        if !has_digest {
            return Err("a relatedResource entry has no digest".into());
        }
    }
    Ok(())
}

const MAX_DIGESTS_PER_RESOURCE: usize = 16;

fn check_digest_cardinality<'a>(
    digest: &'a str,
    count: &mut usize,
    seen: &mut HashSet<&'a str>,
) -> Checked {
    *count += 1;
    if *count > MAX_DIGESTS_PER_RESOURCE {
        return Err(CredentialDefect::Malformed(Cow::Owned(format!(
            "a relatedResource entry has more than {MAX_DIGESTS_PER_RESOURCE} digests"
        ))));
    }
    if !seen.insert(digest) {
        return Err("a relatedResource entry repeats a digest".into());
    }
    Ok(())
}

/// A borrowed iterator over a digest string or non-empty array of strings.
enum Strings<'a> {
    Empty,
    One(Option<&'a str>),
    Many(std::slice::Iter<'a, Json>),
}

impl<'a> Iterator for Strings<'a> {
    type Item = Result<&'a str, CredentialDefect>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Strings::Empty => None,
            Strings::One(value) => value.take().map(Ok),
            Strings::Many(values) => values.next().map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| "a relatedResource digest is not a string".into())
            }),
        }
    }
}

/// "One or more" strings; absent is none.
fn strings(value: Option<&Json>) -> Result<Strings<'_>, CredentialDefect> {
    match value {
        None => Ok(Strings::Empty),
        Some(Json::String(text)) => Ok(Strings::One(Some(text))),
        Some(Json::Array(texts)) if !texts.is_empty() => Ok(Strings::Many(texts.iter())),
        Some(_) => Err("a relatedResource digest is not one or more strings".into()),
    }
}

#[derive(Clone, Copy)]
enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn cached(self, digests: &PinnedDigests) -> &[u8] {
        match self {
            DigestAlgorithm::Sha256 => &digests.sha256,
            DigestAlgorithm::Sha384 => &digests.sha384,
            DigestAlgorithm::Sha512 => &digests.sha512,
        }
    }
}

const MAX_ENCODED_DIGEST_LEN: usize = 140;
const MAX_DECODED_MULTIHASH_LEN: usize = 68;

#[derive(Clone, Copy)]
enum DigestDecodeError {
    TooLong,
    Invalid,
}

fn digest_defect(error: DigestDecodeError) -> CredentialDefect {
    match error {
        DigestDecodeError::TooLong => CredentialDefect::Malformed(Cow::Owned(format!(
            "a relatedResource digest exceeds {MAX_ENCODED_DIGEST_LEN} encoded characters"
        ))),
        DigestDecodeError::Invalid => "a digestSRI value is not an SRI hash-expression".into(),
    }
}

/// Subresource Integrity `hash-expression`: `hash-algo "-" base64-value`
/// with an optional `"?" option-expression`. Returns the algorithm and the
/// decoded digest.
fn sri_hash(text: &str) -> Result<(DigestAlgorithm, Vec<u8>), DigestDecodeError> {
    let (expression, options) = text.split_once('?').unwrap_or((text, ""));
    let (algorithm, digest) = expression
        .split_once('-')
        .ok_or(DigestDecodeError::Invalid)?;
    if digest.len() > MAX_ENCODED_DIGEST_LEN {
        return Err(DigestDecodeError::TooLong);
    }
    let algorithm = match algorithm {
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        "sha512" => DigestAlgorithm::Sha512,
        _ => return Err(DigestDecodeError::Invalid),
    };
    let body = digest.trim_end_matches('=');
    if body.is_empty()
        || digest.len() - body.len() > 2
        || !options.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(DigestDecodeError::Invalid);
    }
    let url_alphabet = body.contains(['-', '_']);
    let decoded = base64_decode(body, url_alphabet).ok_or(DigestDecodeError::Invalid)?;
    Ok((algorithm, decoded))
}

/// Decode a multibase string. Supported bases: base58btc (`z`), base64url
/// (`u` unpadded, `U` padded), base64 (`m`, `M`), base16 (`f`, `F`), and
/// base32 (`b`, `B`).
fn multibase_decode(text: &str) -> Result<Vec<u8>, DigestDecodeError> {
    if text.len() > MAX_ENCODED_DIGEST_LEN {
        return Err(DigestDecodeError::TooLong);
    }
    let mut chars = text.chars();
    let prefix = chars.next().ok_or(DigestDecodeError::Invalid)?;
    let body = chars.as_str();
    let decoded = match prefix {
        'z' => base58btc_decode(body),
        'u' | 'm' if body.contains('=') => None,
        'U' | 'M' if body.len() % 4 != 0 => None,
        'u' | 'U' => base64_decode(body, true),
        'm' | 'M' => base64_decode(body, false),
        'f' => base16_decode(body, false),
        'F' => base16_decode(body, true),
        'b' => base32_decode(body, false),
        'B' => base32_decode(body, true),
        _ => None,
    };
    decoded.ok_or(DigestDecodeError::Invalid)
}

fn base58btc_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = text.bytes().take_while(|&byte| byte == b'1').count();
    if zeros > MAX_DECODED_MULTIHASH_LEN {
        return None;
    }
    let mut number: Vec<u8> = Vec::new(); // little-endian base 256
    for byte in text.bytes().skip(zeros) {
        let mut carry = ALPHABET.iter().position(|&symbol| symbol == byte)? as u32;
        for digit in &mut number {
            carry += u32::from(*digit) * 58;
            *digit = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if zeros + number.len() >= MAX_DECODED_MULTIHASH_LEN {
                return None;
            }
            number.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut bytes = vec![0; zeros];
    bytes.extend(number.iter().rev());
    Some(bytes)
}

fn base16_decode(text: &str, upper: bool) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' if !upper => Some(byte - b'a' + 10),
        b'A'..=b'F' if upper => Some(byte - b'A' + 10),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

/// RFC 4648 base32 without padding.
fn base32_decode(text: &str, upper: bool) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len() * 5 / 8);
    let (mut accumulator, mut bits) = (0_u32, 0_u32);
    for byte in text.bytes() {
        let value = match byte {
            b'a'..=b'z' if !upper => byte - b'a',
            b'A'..=b'Z' if upper => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    (bits < 5 && accumulator == 0).then_some(output)
}

/// Parse a multihash: an unsigned-varint code, an unsigned-varint length
/// equal to the remaining bytes, and the registered length for SHA-2.
fn multihash(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (code, rest) = unsigned_varint(bytes)?;
    let (length, digest) = unsigned_varint(rest)?;
    let registered = match code {
        0x12 => Some(32),
        0x20 => Some(48),
        0x13 => Some(64),
        _ => None,
    };
    (u64::try_from(digest.len()).ok() == Some(length) && registered.is_none_or(|n| n == length))
        .then_some((code, digest))
}

/// A minimally encoded unsigned varint of at most nine bytes.
fn unsigned_varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0_u64;
    for (index, &byte) in bytes.iter().enumerate().take(9) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return None;
            }
            return Some((value, &bytes[index + 1..]));
        }
    }
    None
}

/// An exact XML Schema `dateTime` value normalized to UTC: whole seconds
/// since the Unix epoch and the fraction's decimal digits with trailing
/// zeros trimmed. The derived order is exact: seconds first, then the
/// trimmed fractions compare correctly as strings.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct XsdInstant {
    seconds: i128,
    fraction: String,
}

impl XsdInstant {
    pub(super) fn from_time(at: OffsetDateTime) -> Self {
        let fraction = format!("{:09}", at.nanosecond());
        XsdInstant {
            seconds: i128::from(at.unix_timestamp()),
            fraction: fraction.trim_end_matches('0').to_string(),
        }
    }

    pub(super) fn shifted(self, seconds: i128) -> Self {
        XsdInstant {
            seconds: self.seconds + seconds,
            ..self
        }
    }
}

/// A parsed XSD `dateTime`: zoned (a `dateTimeStamp`) or zoneless.
pub(super) enum XsdDateTime {
    Zoned(XsdInstant),
    /// Read as if it were UTC.
    Local(XsdInstant),
}

/// Parse the XSD 1.1 `dateTime` lexical form:
/// `-?YYYY+-MM-DDThh:mm:ss[.s+][Z|(+|-)hh:mm]`. The day must exist in its
/// month (proleptic Gregorian, year 0000 a leap year), the zone lies within
/// 14:00, and `24:00:00` is the next day's midnight. Years of up to 30
/// digits are supported, which keeps the seconds inside `i128`. The error
/// completes the sentence "credential ... date ...".
pub(super) fn parse_xsd_date_time(text: &str) -> Result<XsdDateTime, &'static str> {
    const FORM: &str = "is not in the XML Schema dateTime lexical form";
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let year_digits = unsigned.bytes().take_while(u8::is_ascii_digit).count();
    if year_digits < 4 || (year_digits > 4 && unsigned.starts_with('0')) {
        return Err(FORM);
    }
    if year_digits > 30 {
        return Err("has a year beyond the verifier's supported 30 digits");
    }
    let year: i128 = unsigned[..year_digits].parse().map_err(|_| FORM)?;
    let year = if negative { -year } else { year };
    let rest = &unsigned.as_bytes()[year_digits..];
    let two = |at: usize| -> Option<u32> {
        let digits = rest.get(at..at + 2)?;
        digits
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| u32::from(digits[0] - b'0') * 10 + u32::from(digits[1] - b'0'))
    };
    if [(0, b'-'), (3, b'-'), (6, b'T'), (9, b':'), (12, b':')]
        .iter()
        .any(|&(at, separator)| rest.get(at) != Some(&separator))
    {
        return Err(FORM);
    }
    let fields = (|| Some((two(1)?, two(4)?, two(7)?, two(10)?, two(13)?)))();
    let (month, day, hour, minute, second) = fields.ok_or(FORM)?;
    let mut tail = &rest[15..];
    let mut fraction = "";
    if let Some(after_point) = tail.strip_prefix(b".") {
        let length = after_point
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if length == 0 {
            return Err(FORM);
        }
        // The digits are ASCII, so the slice is valid UTF-8.
        fraction = std::str::from_utf8(&after_point[..length])
            .map_err(|_| FORM)?
            .trim_end_matches('0');
        tail = &after_point[length..];
    }
    let end_of_day = hour == 24 && minute == 0 && second == 0 && fraction.is_empty();
    if !(1..=12).contains(&month) || minute > 59 || second > 59 || (hour > 23 && !end_of_day) {
        return Err(FORM);
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err("has a day that does not exist in its month");
    }
    let local =
        days_from_civil(year, month, day) * 86_400 + i128::from(hour * 3600 + minute * 60 + second);
    let instant = |offset: i128| XsdInstant {
        seconds: local - offset,
        fraction: fraction.to_string(),
    };
    match tail {
        [] => Ok(XsdDateTime::Local(instant(0))),
        [b'Z'] => Ok(XsdDateTime::Zoned(instant(0))),
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let digit = |byte: u8| byte.is_ascii_digit().then(|| i128::from(byte - b'0'));
            let (hours, minutes) = (|| {
                Some((
                    digit(*h1)? * 10 + digit(*h2)?,
                    digit(*m1)? * 10 + digit(*m2)?,
                ))
            })()
            .ok_or(FORM)?;
            if minutes > 59 || hours > 14 || (hours == 14 && minutes > 0) {
                return Err(FORM);
            }
            let offset = (hours * 60 + minutes) * 60;
            Ok(XsdDateTime::Zoned(instant(if *sign == b'-' {
                -offset
            } else {
                offset
            })))
        }
        _ => Err(FORM),
    }
}

fn days_in_month(year: i128, month: u32) -> u32 {
    match month {
        2 if year.rem_euclid(4) == 0
            && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0) =>
        {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a proleptic-Gregorian date (H. Hinnant's
/// `days_from_civil`), for any year.
fn days_from_civil(year: i128, month: u32, day: u32) -> i128 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i128::from(month);
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + i128::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one-time digest cache is derived from the exact vendored bytes for
    /// every supported SRI algorithm.
    #[test]
    fn pinned_digest_cache_matches_the_vendored_contexts() {
        let expected_sha256 = [
            "ab4ddd9a531758807a79a5b450510d61ae8d147eab966cc9a200c07095b0cdcc",
            "59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734",
            "750c94af1c3d7e587dc19f3a06ef1e9bfe8412a1e94ef15037ae83f3baeb82e9",
            "fda5add353231e6a6884a46b12e6c75464281900cb348284d9c360f62381d9f7",
        ];
        for (index, ((url, bytes), digest)) in
            PINNED_CONTEXTS.iter().zip(expected_sha256).enumerate()
        {
            let cached = &PINNED_DIGESTS[index];
            assert_eq!(hex::encode(cached.sha256), digest, "{url}");
            assert_eq!(cached.sha384.as_slice(), &Sha384::digest(bytes)[..]);
            assert_eq!(cached.sha512.as_slice(), &Sha512::digest(bytes)[..]);
        }
    }

    /// The base58 decoder independently enforces the largest supported
    /// multihash size, even when its encoded input remains below the text cap.
    #[test]
    fn base58_decoder_stops_above_the_supported_multihash_size() {
        assert!(base58btc_decode(&"z".repeat(94)).is_none());
        assert!(multibase_decode(&format!("z{}", "z".repeat(94))).is_err());
    }

    /// The static `@json` table is exactly what the vendored documents
    /// define: three VC 2.0 terms, none in VC 1.1 or CAWG.
    #[test]
    fn json_literal_table_matches_the_vendored_contexts() {
        fn json_terms(context: &Json, scope: &str, into: &mut Vec<(String, String)>) {
            for (term, definition) in context.as_object().unwrap() {
                if definition.get("@type").and_then(Json::as_str) == Some("@json") {
                    into.push((scope.to_string(), term.clone()));
                }
                if let Some(scoped) = definition.get("@context").filter(|c| c.is_object()) {
                    json_terms(scoped, term, into);
                }
            }
        }
        let terms = |bytes: &[u8]| {
            let document: Json = serde_json::from_slice(bytes).unwrap();
            let mut found = Vec::new();
            json_terms(&document["@context"], "", &mut found);
            found
        };
        assert!(terms(PINNED_CONTEXTS[0].1).is_empty());
        assert!(terms(PINNED_CONTEXTS[2].1).is_empty());
        assert!(terms(PINNED_CONTEXTS[3].1).is_empty());
        let scoped = |(scope, term): (&str, &str)| (scope.to_string(), term.to_string());
        assert_eq!(
            terms(PINNED_CONTEXTS[1].1),
            vec![
                scoped(V2_JSON_TYPE_SCOPED),
                (String::new(), V2_JSON_TOP_LEVEL.to_string()),
                scoped(V2_JSON_PROPERTY_SCOPED),
            ]
        );
    }

    /// The only `@id` aliases in every supported pinned context set are `id`
    /// and CAWG's `uri`, which the identifier rules treat as node identifiers.
    #[test]
    fn id_and_uri_are_the_only_identifier_aliases() {
        for documents in [[0, 2, 3], [1, 2, 3]] {
            let mut aliases = HashSet::new();
            for index in documents {
                let document: Json = serde_json::from_slice(PINNED_CONTEXTS[index].1).unwrap();
                let mut definitions = Vec::new();
                collect_definitions(&document["@context"], &mut definitions);
                aliases.extend(
                    definitions
                        .into_iter()
                        .filter(|(_, definition)| definition.as_str() == Some("@id"))
                        .map(|(term, _)| term.to_string()),
                );
            }
            assert_eq!(
                aliases,
                HashSet::from(["id".to_string(), "uri".to_string()])
            );
        }
    }
}
