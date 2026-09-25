// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Certificate trust validation for C2PA claim-signing certificates.
//!
//! The defining feature over the upstream `c2pa-rs` validator is that
//! [`validate_chain`] honors an explicit `validation_time`: certificate
//! `notBefore`/`notAfter` windows are checked against the supplied instant
//! rather than the system clock. This makes it possible to validate a
//! signature *as of* the moment it was produced (e.g. anchored by a trusted
//! timestamp token) even after the signing certificate has expired.
//!
//! # Components
//! - [`TrustList`] — a set of [`TrustAnchor`] configurations (DER certificate,
//!   trust window, and [`AnchorPurpose`]).
//! - [`EkuPolicy`] — Extended Key Usage enforcement for leaf certificates.
//! - [`validate_chain`] — build and validate a path from a leaf certificate to
//!   a trust anchor configured for the requested purpose.
//! - [`RevocationDenylist`] — internal serial/fingerprint revocation set.

pub(crate) mod ocsp;
mod profile;
pub(crate) use ocsp::online::{
    build_request as build_ocsp_request, evaluate as evaluate_ocsp_online,
    responder_url as ocsp_responder_url, OnlineVerdict as OnlineOcspVerdict,
};
pub(crate) use ocsp::{
    evaluate_verified as evaluate_ocsp_verified, OcspStatus, MAX_OCSP_RESPONSE_BYTES,
};
mod timestamp;
/// Test-only RFC 3161 fixture minting. Compiled out of the published library.
#[cfg(test)]
pub(crate) mod timestamp_fixture;
use std::collections::{HashMap, HashSet};
pub(crate) use timestamp::{
    describe_timestamp_token, inspect_timestamp_token, token_from_timestamp_response,
    verify_timestamp_token, TimestampResult, TokenDescription,
};

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::signature::Verifier as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use time::OffsetDateTime;
use x509_cert::ext::pkix::{BasicConstraints, CertificatePolicies, ExtendedKeyUsage};
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// C2PA claim-signing EKU (`c2pa-kp-claimSigning`).
pub const OID_C2PA_CLAIM_SIGNING: &str = "1.3.6.1.4.1.62558.2.1";
/// `id-kp-emailProtection`.
pub const OID_EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
/// Adobe `documentSigning` EKU.
pub const OID_ADOBE_DOCUMENT_SIGNING: &str = "1.2.840.113583.1.1.5";
/// IETF `id-kp-documentSigning` EKU.
pub const OID_IETF_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";
/// `id-kp-timeStamping` - required EKU for a TSA certificate, and a purpose a
/// C2PA claim signer is never authorized for (see
/// [`leaf_is_acceptable_claim_signer`]).
pub const OID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// `id-kp-OCSPSigning` - delegated OCSP responder EKU, and a purpose a C2PA
/// claim signer is never authorized for.
pub const OID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
/// Microsoft C2PA manifest-signing EKU.
pub const OID_MICROSOFT_C2PA: &str = "1.3.6.1.4.1.311.76.59.1.9";

const OID_EXT_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `anyExtendedKeyUsage` — forbidden for a C2PA claim-signing leaf.
const OID_ANY_EKU: &str = "2.5.29.37.0";

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

const OID_CURVE_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_CURVE_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_CURVE_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Maximum certificates walked while building a chain, guarding against loops.
const MAX_CHAIN_DEPTH: usize = 20;
/// Maximum issuer candidates expanded across the whole path search, bounding
/// the work an adversarial bag of cross-signed intermediates can force.
const MAX_PATH_NODES: usize = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while constructing trust material.
#[derive(Debug, Error)]
pub enum TrustError {
    /// The PEM input contained no parseable certificates.
    #[error("no certificates found in PEM input")]
    NoCertificates,
    /// A certificate could not be decoded.
    #[error("failed to decode certificate: {0}")]
    Decode(String),
}

// ---------------------------------------------------------------------------
// Hash selection
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum SigHash {
    Sha256,
    Sha384,
    Sha512,
}

fn digest_bytes(hash: SigHash, msg: &[u8]) -> Vec<u8> {
    match hash {
        SigHash::Sha256 => Sha256::digest(msg).to_vec(),
        SigHash::Sha384 => Sha384::digest(msg).to_vec(),
        SigHash::Sha512 => Sha512::digest(msg).to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------

/// The signing purpose a trust-anchor configuration authorizes.
///
/// The Trust Model keeps one list of trust-anchor configurations per accepted
/// EKU, requires the time-stamping list to be "separate from the lists for
/// C2PA signers", and requires a validator to "use only the trust anchors it
/// associates with EKUs present in the certificate". Purposes are therefore
/// not interchangeable: a claim signer never chains to a time-stamping anchor,
/// and a CAWG named-actor credential never chains to a claim-signing anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorPurpose {
    /// C2PA claim signing.
    ClaimSigning,
    /// RFC 3161 time-stamping (`id-kp-timeStamping`).
    TimeStamping,
    /// CAWG named-actor (identity) credentials.
    CawgIdentity,
}

/// Which entry of the CAWG trust configuration an anchor belongs to.
///
/// CAWG Identity 1.3 has a validator keep a *CAWG trust configuration*: a list
/// of accepted EKUs, each with its own accepted certificate policies and trust
/// anchors. Its "interim trust model additions" are not a property of the EKU
/// but of two named sources - the Mozilla root store with the email trust bit
/// and the IPTC Verified News Publishers lists - and they carry extra
/// conditions, a trusted time stamp and the 31 March 2027 cutoff, that no
/// other configured anchor is subject to. An anchor therefore has to say which
/// entry configured it.
///
/// Only [`AnchorPurpose::CawgIdentity`] anchors are read through this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CawgTrustSource {
    /// One of the two sources the interim S/MIME additions name. The interim
    /// conditions bind, and this is the default for any anchor that does not
    /// declare otherwise, so an unlabeled source is held to the stricter rule.
    SmimeInterim,
    /// The bundled Encypher Verified Organizations identity root.
    EncypherVerifiedOrganizations,
    /// An anchor or end-entity certificate the caller configured.
    CallerSupplied,
}

impl CawgTrustSource {
    /// The `trust_source` detail reported for a credential this entry accepted.
    pub fn label(self) -> &'static str {
        match self {
            Self::SmimeInterim => "smime_interim",
            Self::EncypherVerifiedOrganizations => "encypher_verified_organizations",
            Self::CallerSupplied => "caller_supplied",
        }
    }

    /// True when the interim S/MIME conditions apply to this entry.
    pub fn interim(self) -> bool {
        matches!(self, Self::SmimeInterim)
    }
}

/// One trust-anchor configuration: the anchor certificate plus the window in
/// which the configuration is trusted and the purpose it authorizes.
///
/// VAL-CRYP-0010/0011: a configuration carrying a `not_before` must not
/// validate claim signatures whose signing time precedes it, and one carrying a
/// `not_after` must not validate signatures after it. These bounds belong to
/// the configuration and are independent of the anchor certificate's own
/// `notBefore`/`notAfter`.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// DER-encoded anchor certificate.
    pub certificate: Vec<u8>,
    /// The purpose this configuration authorizes.
    pub purpose: AnchorPurpose,
    /// Configured start of trust. `None` leaves the start unbounded.
    pub not_before: Option<OffsetDateTime>,
    /// Configured end of trust. `None` leaves the end unbounded.
    pub not_after: Option<OffsetDateTime>,
    /// The CAWG trust configuration entry that supplied this anchor. Read only
    /// for [`AnchorPurpose::CawgIdentity`].
    pub cawg_source: CawgTrustSource,
}

impl TrustAnchor {
    /// An unbounded configuration authorizing `purpose`.
    pub fn new(certificate: Vec<u8>, purpose: AnchorPurpose) -> Self {
        Self {
            certificate,
            purpose,
            not_before: None,
            not_after: None,
            cawg_source: CawgTrustSource::SmimeInterim,
        }
    }

    /// Lowercase hex SHA-256 of the anchor certificate's DER.
    pub fn fingerprint(&self) -> String {
        fingerprint_hex(&self.certificate)
    }

    /// True when this configuration is in force at `at`.
    pub fn active_at(&self, at: OffsetDateTime) -> bool {
        self.not_before.is_none_or(|start| at >= start)
            && self.not_after.is_none_or(|end| at <= end)
    }
}

// ---------------------------------------------------------------------------
// TrustList
// ---------------------------------------------------------------------------

/// A set of trust-anchor configurations.
#[derive(Debug, Clone, Default)]
pub struct TrustList {
    /// The configured anchors.
    pub anchors: Vec<TrustAnchor>,
}

impl TrustList {
    /// Build a claim-signing trust list from a PEM bundle.
    pub fn from_pem(pem: &str) -> Result<Self, TrustError> {
        Self::from_pem_for(AnchorPurpose::ClaimSigning, pem)
    }

    /// Build a trust list for `purpose` from a PEM bundle containing one or
    /// more certificates.
    ///
    /// Each `CERTIFICATE` block is parsed and re-encoded to canonical DER.
    /// Returns [`TrustError::NoCertificates`] when the bundle yields no
    /// certificates and [`TrustError::Decode`] when a block cannot be decoded.
    pub fn from_pem_for(purpose: AnchorPurpose, pem: &str) -> Result<Self, TrustError> {
        // Guard before x509-cert: `Certificate::load_pem_chain` PANICS
        // (subtract with overflow) on input containing no PEM block at all —
        // observed in the wild with the IPTC VNPL anchor list, which is served
        // as a legitimate zero-byte file while no anchors are registered. A
        // verifier must fail closed on such input, never crash.
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(TrustError::NoCertificates);
        }
        let certs = Certificate::load_pem_chain(pem.as_bytes())
            .map_err(|e| TrustError::Decode(e.to_string()))?;
        if certs.is_empty() {
            return Err(TrustError::NoCertificates);
        }
        let mut anchors = Vec::with_capacity(certs.len());
        for cert in &certs {
            let der = cert
                .to_der()
                .map_err(|e| TrustError::Decode(e.to_string()))?;
            anchors.push(TrustAnchor::new(der, purpose));
        }
        Ok(Self { anchors })
    }

    /// An unbounded trust list for `purpose` over already-decoded DER.
    pub fn from_certificates(
        purpose: AnchorPurpose,
        certificates: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        Self {
            anchors: certificates
                .into_iter()
                .map(|der| TrustAnchor::new(der, purpose))
                .collect(),
        }
    }

    /// Apply configured trust bounds to every anchor in this list.
    pub fn with_bounds(
        mut self,
        not_before: Option<OffsetDateTime>,
        not_after: Option<OffsetDateTime>,
    ) -> Self {
        for anchor in &mut self.anchors {
            anchor.not_before = not_before;
            anchor.not_after = not_after;
        }
        self
    }

    /// Declare which CAWG trust configuration entry supplied every anchor in
    /// this list.
    pub fn with_cawg_source(mut self, source: CawgTrustSource) -> Self {
        for anchor in &mut self.anchors {
            anchor.cawg_source = source;
        }
        self
    }

    /// The configured certificate equal to `der`, whatever its purpose or
    /// window. Used by the private-credential ("allowed") store, which trusts
    /// an end-entity certificate directly rather than as an anchor, and which
    /// still needs the entry that configured it.
    pub fn find_certificate(&self, der: &[u8]) -> Option<&TrustAnchor> {
        self.anchors.iter().find(|anchor| anchor.certificate == der)
    }

    /// True when `der` is one of the configured certificates.
    pub fn contains_certificate(&self, der: &[u8]) -> bool {
        self.find_certificate(der).is_some()
    }

    /// Every configured certificate, in configuration order.
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        self.anchors
            .iter()
            .map(|anchor| anchor.certificate.as_slice())
    }

    /// Return the Common Name (`CN`) of each anchor certificate.
    ///
    /// Anchors without a `CN` attribute are skipped, mirroring the enterprise
    /// `get_trust_anchor_subjects` behavior.
    pub fn anchor_subjects(&self) -> Vec<String> {
        self.certificates()
            .filter_map(|der| {
                let cert = Certificate::from_der(der).ok()?;
                common_name(&cert)
            })
            .collect()
    }

    /// The anchors that authorize `purpose` and are in force at `at`, each
    /// with its index in this list so a completed path can name the anchor it
    /// terminated at.
    fn active_anchors(
        &self,
        purpose: AnchorPurpose,
        at: OffsetDateTime,
    ) -> Vec<(usize, &TrustAnchor)> {
        self.anchors
            .iter()
            .enumerate()
            .filter(|(_, anchor)| anchor.purpose == purpose && anchor.active_at(at))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// EkuPolicy
// ---------------------------------------------------------------------------

/// Extended Key Usage policy: a leaf certificate is acceptable when it carries
/// at least one of the allowed EKU OIDs.
#[derive(Debug, Clone)]
pub struct EkuPolicy {
    /// Dotted-decimal OIDs accepted as a valid claim-signing EKU.
    pub allowed_oids: Vec<String>,
}

impl Default for EkuPolicy {
    /// Default policy: the full C2PA claim-signing EKU set the reference
    /// validator (c2pa-rs `check_certificate_profile`) accepts - the C2PA
    /// claim-signing OID, both document-signing OIDs, `emailProtection`
    /// (still the most widely deployed claim-signer EKU, e.g. the IPTC
    /// newsroom guide's GlobalSign certificates), and the Microsoft C2PA OID.
    /// `timeStamping` and `OCSPSigning` are never in this set: they authorize
    /// a different purpose, and the profile forbids a certificate from being
    /// valid for more than one (see [`leaf_acceptable_der`]).
    fn default() -> Self {
        Self {
            allowed_oids: vec![
                OID_C2PA_CLAIM_SIGNING.to_string(),
                OID_ADOBE_DOCUMENT_SIGNING.to_string(),
                OID_IETF_DOCUMENT_SIGNING.to_string(),
                OID_EMAIL_PROTECTION.to_string(),
                OID_MICROSOFT_C2PA.to_string(),
            ],
        }
    }
}

impl EkuPolicy {
    /// Return `true` when `cert_der` declares an Extended Key Usage extension
    /// containing at least one of the policy's allowed OIDs.
    ///
    /// A certificate lacking an EKU extension is rejected (returns `false`),
    /// unless the policy itself lists no allowed OIDs (in which case any
    /// certificate is accepted, matching the upstream semantics).
    pub fn cert_has_required_eku(&self, cert_der: &[u8]) -> bool {
        if self.allowed_oids.is_empty() {
            return true;
        }
        let Ok(cert) = Certificate::from_der(cert_der) else {
            return false;
        };
        let Some(ekus) = certificate_eku_oids(&cert) else {
            return false;
        };
        ekus.iter()
            .any(|oid| self.allowed_oids.iter().any(|allowed| allowed == oid))
    }
}

/// Collect the EKU OIDs (dotted strings) declared by a certificate, if any.
fn certificate_eku_oids(cert: &Certificate) -> Option<Vec<String>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts.iter().find(|e| e.extn_id == OID_EXT_EKU)?;
    let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(eku.0.iter().map(|oid| oid.to_string()).collect())
}

/// Return the extended-key-usage OIDs declared by a DER certificate.
pub fn certificate_eku_oids_der(cert_der: &[u8]) -> Option<Vec<String>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    certificate_eku_oids(&cert)
}

/// Return the certificate-policy OIDs declared by a DER certificate.
pub fn certificate_policy_oids_der(cert_der: &[u8]) -> Option<Vec<String>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let oid = ObjectIdentifier::new_unwrap("2.5.29.32");
    let ext = exts.iter().find(|extension| extension.extn_id == oid)?;
    let policies = CertificatePolicies::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(
        policies
            .0
            .iter()
            .map(|policy| policy.policy_identifier.to_string())
            .collect(),
    )
}

/// True when the DER certificate's validity window contains `at`.
pub fn certificate_valid_at(cert_der: &[u8], at: OffsetDateTime) -> bool {
    Certificate::from_der(cert_der)
        .map(|cert| valid_at(&cert, at))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

/// Result of a certificate chain validation.
#[derive(Debug, Clone)]
pub struct ChainResult {
    /// `true` when the leaf chains to one of the supplied trust anchors and
    /// every link verified (signatures + validity window at `validated_at`).
    pub trusted: bool,
    /// `true` when every certificate in the walked chain was inside its
    /// validity window at `validated_at`. When `false`, the signature is
    /// "outside validity" (distinct from merely untrusted): the leaf itself may
    /// be valid but an issuer in the chain was expired/not-yet-valid.
    pub chain_validity_ok: bool,
    /// `true` when the leaf certificate is an acceptable C2PA claim signer:
    /// it carries a permitted claim-signing EKU (and not `anyExtendedKeyUsage`),
    /// is not a CA certificate, and does not assert the `keyCertSign` key usage.
    /// When `false`, the credential is structurally invalid for claim signing.
    pub leaf_acceptable: bool,
    /// Human-readable explanation when `trusted` is `false`.
    pub reason: Option<String>,
    /// The instant the chain was evaluated against — the supplied
    /// `validation_time` when provided, otherwise the current UTC time.
    pub validated_at: OffsetDateTime,
    /// Index, in the trust list that was searched, of the anchor the trusted
    /// path terminated at. `None` unless `trusted`.
    ///
    /// A trust list can hold anchors configured under different rules - the
    /// CAWG trust configuration is exactly that - so the caller has to be able
    /// to tell which one accepted the credential.
    pub anchor: Option<usize>,
}

impl ChainResult {
    fn untrusted(reason: impl Into<String>, at: OffsetDateTime) -> Self {
        Self {
            trusted: false,
            chain_validity_ok: true,
            leaf_acceptable: true,
            reason: Some(reason.into()),
            validated_at: at,
            anchor: None,
        }
    }

    /// The anchor the trusted path terminated at, resolved against the trust
    /// list that produced this result.
    pub fn terminating_anchor<'a>(&self, trust: &'a TrustList) -> Option<&'a TrustAnchor> {
        trust.anchors.get(self.anchor?)
    }
}

/// How a candidate certification path ended.
///
/// Ordered worst to best so the path builder can keep the most favorable
/// outcome it found across every candidate path it explored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PathOutcome {
    /// No candidate path reached an anchor in force for the purpose.
    NoPath,
    /// A path reached an anchor but failed the profile or a path constraint.
    Rejected(&'static str),
    /// A path reached an anchor, but a certificate on it was outside its
    /// validity window at the validation instant.
    OutsideValidity,
    /// A path reached an anchor and satisfied every check.
    Trusted,
}

/// Validate `leaf_der` against the anchors in `trust` that authorize `purpose`,
/// optionally using `intermediates_der` to bridge the chain.
///
/// When `validation_time` is `Some`, all `notBefore`/`notAfter` checks use that
/// instant instead of the system clock — this is the key capability that lets a
/// signature remain verifiable after its certificate expires, provided the
/// validation time falls within the certificate's original validity window.
/// The same instant selects which trust-anchor configurations are in force
/// (VAL-CRYP-0010/0011).
///
/// Path building searches the caller-supplied intermediates and the in-force
/// anchors as an unordered bag, backtracking when a candidate issuer leads
/// nowhere, and the completed path is checked against the C2PA certificate
/// profile and the RFC 5280 section 6 constraints ([`profile::path_violation`]).
/// The end-entity certificate's own profile compliance is reported separately
/// in `leaf_acceptable`, because a TSA or CAWG leaf is validated against a
/// different purpose's EKU set by its own caller.
pub fn validate_chain(
    leaf_der: &[u8],
    intermediates_der: &[Vec<u8>],
    trust: &TrustList,
    purpose: AnchorPurpose,
    validation_time: Option<OffsetDateTime>,
) -> ChainResult {
    let at = validation_time.unwrap_or_else(OffsetDateTime::now_utc);

    let leaf = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => return ChainResult::untrusted(format!("invalid leaf certificate: {e}"), at),
    };

    // Leaf acceptability for claim signing: the C2PA certificate profile plus
    // a permitted claim-signing EKU. Independent of trust-anchor chaining — an
    // otherwise-trusted chain with an unacceptable leaf is still not a valid
    // claim signer.
    let leaf_acceptable = leaf_is_acceptable_claim_signer(&leaf);

    // Only anchors configured for this purpose, and in force at `at`, may
    // terminate a path. The same certificate configured twice keeps its first
    // entry, so a duplicate cannot silently relabel an anchor.
    let mut anchor_indices: HashMap<String, usize> = HashMap::new();
    let mut candidates: Vec<Certificate> = Vec::new();
    for der in intermediates_der {
        if let Ok(c) = Certificate::from_der(der) {
            candidates.push(c);
        }
    }
    for (index, anchor) in trust.active_anchors(purpose, at) {
        if let Ok(c) = Certificate::from_der(&anchor.certificate) {
            anchor_indices
                .entry(fingerprint_hex(&anchor.certificate))
                .or_insert(index);
            candidates.push(c);
        }
    }

    let mut path = vec![leaf];
    let mut seen: HashSet<String> = HashSet::from([fingerprint_hex(leaf_der)]);
    let mut budget = MAX_PATH_NODES;
    let mut anchor = None;
    let outcome = extend_path(
        &mut path,
        &candidates,
        &anchor_indices,
        at,
        &mut seen,
        &mut budget,
        &mut anchor,
    );

    let (trusted, chain_validity_ok, reason) = match outcome {
        PathOutcome::Trusted => (true, true, None),
        PathOutcome::OutsideValidity => (
            false,
            false,
            Some("a certificate in the chain was outside its validity window".to_string()),
        ),
        PathOutcome::Rejected(reason) => (false, true, Some(reason.to_string())),
        PathOutcome::NoPath => (
            false,
            valid_at(path.first().expect("path holds the leaf"), at),
            Some("certificate does not chain to a trusted anchor".to_string()),
        ),
    };
    ChainResult {
        trusted,
        chain_validity_ok,
        leaf_acceptable,
        reason,
        validated_at: at,
        anchor: trusted.then_some(anchor).flatten(),
    }
}

/// Depth-first path building from `path.last()` towards an in-force anchor.
///
/// Subject names are not unique and trust stores routinely hold cross-signed
/// CAs with identical names, so a single greedy step up the chain can dead-end
/// on a certificate that never reaches an anchor. Every issuer that actually
/// signed the current certificate is therefore tried, and the best outcome
/// across the explored paths is returned. `seen` breaks loops; `budget` bounds
/// the search against an adversarial bag of intermediates.
///
/// `anchor` receives the index of the anchor a trusted path terminated at. The
/// search stops at the first trusted path, so the value cannot be overwritten
/// by a later, worse one.
fn extend_path(
    path: &mut Vec<Certificate>,
    candidates: &[Certificate],
    anchor_indices: &HashMap<String, usize>,
    at: OffsetDateTime,
    seen: &mut HashSet<String>,
    budget: &mut usize,
    anchor: &mut Option<usize>,
) -> PathOutcome {
    let current = path.last().expect("path is never empty").clone();
    let Ok(current_der) = current.to_der() else {
        return PathOutcome::NoPath;
    };
    if let Some(&index) = anchor_indices.get(&fingerprint_hex(&current_der)) {
        let outcome = evaluate_path(path, at);
        if outcome == PathOutcome::Trusted {
            *anchor = Some(index);
        }
        return outcome;
    }
    if path.len() >= MAX_CHAIN_DEPTH
        || current.tbs_certificate.subject == current.tbs_certificate.issuer
    {
        // A self-signed certificate that is not an anchor terminates the path
        // without reaching one.
        return PathOutcome::NoPath;
    }

    let mut best = PathOutcome::NoPath;
    for candidate in candidates {
        if *budget == 0 {
            break;
        }
        if candidate.tbs_certificate.subject != current.tbs_certificate.issuer
            || !verify_signature(&current, candidate)
        {
            continue;
        }
        let Ok(der) = candidate.to_der() else {
            continue;
        };
        let fingerprint = fingerprint_hex(&der);
        if !seen.insert(fingerprint.clone()) {
            continue;
        }
        *budget -= 1;
        path.push(candidate.clone());
        let outcome = extend_path(path, candidates, anchor_indices, at, seen, budget, anchor);
        path.pop();
        seen.remove(&fingerprint);
        best = best.max(outcome);
        if best == PathOutcome::Trusted {
            break;
        }
    }
    best
}

/// Check a complete path, end entity first and anchor last.
fn evaluate_path(path: &[Certificate], at: OffsetDateTime) -> PathOutcome {
    if let Some(reason) = profile::path_violation(path) {
        return PathOutcome::Rejected(reason);
    }
    if path.iter().any(|cert| !valid_at(cert, at)) {
        return PathOutcome::OutsideValidity;
    }
    PathOutcome::Trusted
}

/// Find the certificate that issued `leaf_der`, searching `candidates` (e.g. the
/// x5chain intermediates followed by the trust anchors).
///
/// A candidate is accepted as the issuer when its subject DN equals `leaf`'s
/// issuer DN **and** it actually signed `leaf`. Returns a borrowed issuer DER
/// slice so callers do not clone a chain merely to evaluate revocation.
///
/// This resolves the authority an OCSP responder must be authorized by: per
/// RFC 6960 §4.2.2.2 the responder is either the issuer of the certificate in
/// question or a responder certificate issued by that same issuer. The issuer
/// is frequently a trust anchor that is *not* carried in the COSE x5chain, so it
/// must be located across both the chain and the trust list.
pub fn resolve_issuer<'a>(
    leaf_der: &[u8],
    candidates: impl IntoIterator<Item = &'a [u8]>,
) -> Option<&'a [u8]> {
    let leaf = Certificate::from_der(leaf_der).ok()?;
    let leaf_issuer_dn = leaf.tbs_certificate.issuer.to_der().ok()?;
    for cand_der in candidates {
        let Ok(cand) = Certificate::from_der(cand_der) else {
            continue;
        };
        let Ok(cand_subject_dn) = cand.tbs_certificate.subject.to_der() else {
            continue;
        };
        if cand_subject_dn == leaf_issuer_dn && verify_signature(&leaf, &cand) {
            return Some(cand_der);
        }
    }
    None
}
// ---------------------------------------------------------------------------
// RevocationDenylist
// ---------------------------------------------------------------------------

/// Internal revocation denylist matching leaf certificates by serial number or
/// SHA-256 fingerprint (both lowercase hex, no separators).
#[derive(Debug, Clone, Default)]
pub struct RevocationDenylist {
    /// Revoked certificate serial numbers (lowercase hex, minimal form).
    pub serials: HashSet<String>,
    /// Revoked certificate SHA-256 fingerprints (lowercase hex).
    pub fingerprints: HashSet<String>,
}

impl RevocationDenylist {
    /// Build a denylist, normalizing every token to trimmed lowercase.
    pub fn new(
        serials: impl IntoIterator<Item = String>,
        fingerprints: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            serials: normalize_tokens(serials),
            fingerprints: normalize_tokens(fingerprints),
        }
    }

    /// Return `true` when `cert_der` is revoked by serial or fingerprint.
    ///
    /// The fingerprint check works even when the certificate cannot be parsed,
    /// since it is computed directly over the supplied DER. The serial check
    /// requires a parseable certificate.
    pub fn is_revoked(&self, cert_der: &[u8]) -> bool {
        if !self.fingerprints.is_empty() && self.fingerprints.contains(&fingerprint_hex(cert_der)) {
            return true;
        }
        if !self.serials.is_empty() {
            if let Ok(cert) = Certificate::from_der(cert_der) {
                let serial = serial_hex(cert.tbs_certificate.serial_number.as_bytes());
                if self.serials.contains(&serial) {
                    return true;
                }
            }
        }
        false
    }
}

fn normalize_tokens(values: impl IntoIterator<Item = String>) -> HashSet<String> {
    values
        .into_iter()
        .filter_map(|v| {
            let t = v.trim().to_ascii_lowercase();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 fingerprint of a DER certificate.
fn fingerprint_hex(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Render a DER serial-number integer as minimal lowercase hex.
///
/// Matches Python's `format(cert.serial_number, "x")`: leading zero bytes
/// (including the sign-guard `0x00`) are dropped, and a zero serial renders as
/// `"0"`.
fn serial_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Extract the Common Name attribute value from a certificate's subject.
fn common_name(cert: &Certificate) -> Option<String> {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid == OID_AT_COMMON_NAME {
                // CN string types (PrintableString/UTF8String/IA5String) all carry
                // UTF-8-compatible content in their value bytes.
                let raw = atav.value.value();
                return Some(String::from_utf8_lossy(raw).into_owned());
            }
        }
    }
    None
}

/// True when the certificate's validity window contains `t`.
fn valid_at(cert: &Certificate, t: OffsetDateTime) -> bool {
    let nb = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let na = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    let now = t.unix_timestamp();
    nb <= now && now <= na
}

/// True when the certificate carries BasicConstraints with `cA = TRUE`.
fn is_ca_certificate(cert: &Certificate) -> bool {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_EXT_BASIC_CONSTRAINTS) else {
        return false;
    };
    BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map(|bc| bc.ca)
        .unwrap_or(false)
}

/// The BasicConstraints `pathLenConstraint` of a CA certificate, if present.
/// `None` means unconstrained (or not a CA / no extension).
fn path_len_constraint(cert: &Certificate) -> Option<usize> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id == OID_EXT_BASIC_CONSTRAINTS)?;
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).ok()?;
    bc.path_len_constraint.map(|n| n as usize)
}

/// True when the certificate asserts the `keyCertSign` key usage bit.
fn has_key_cert_sign(cert: &Certificate) -> bool {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_EXT_KEY_USAGE) else {
        return false;
    };
    use x509_cert::ext::pkix::KeyUsage;
    KeyUsage::from_der(ext.extn_value.as_bytes())
        .map(|ku| ku.key_cert_sign())
        .unwrap_or(false)
}

/// True when the certificate carries a keyUsage extension that asserts the
/// `digitalSignature` bit. A claim-signing leaf MUST declare keyUsage with
/// digitalSignature: a leaf with no keyUsage extension is rejected.
fn allows_digital_signature(cert: &Certificate) -> bool {
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    let Some(ext) = exts.iter().find(|e| e.extn_id == OID_EXT_KEY_USAGE) else {
        return false;
    };
    use x509_cert::ext::pkix::KeyUsage;
    KeyUsage::from_der(ext.extn_value.as_bytes())
        .map(|ku| ku.digital_signature())
        .unwrap_or(false)
}

/// True when a DER certificate satisfies the C2PA end-entity certificate
/// profile, independent of the application-specific permitted EKU set.
///
/// CAWG imports the C2PA credential profile but defines its own accepted EKUs
/// (IETF document signing and interim S/MIME email protection), so it uses
/// this predicate before applying its own EKU policy.
pub fn leaf_profile_acceptable_der(leaf_der: &[u8]) -> bool {
    Certificate::from_der(leaf_der)
        .is_ok_and(|leaf| profile::profile_violation(&leaf, profile::CertRole::EndEntity).is_none())
}

/// True when `leaf` is an acceptable C2PA claim-signing certificate.
///
/// Per the C2PA trust model the leaf MUST:
/// - satisfy the end-entity certificate profile ([`profile::profile_violation`]):
///   v3, no unique IDs, an Authority Key Identifier, a Key Usage extension
///   asserting `digitalSignature` and not `keyCertSign`, no `cA` basic
///   constraint, a non-empty EKU without `anyExtendedKeyUsage`, an allowed
///   signature algorithm and public key, and no unrecognized critical extension;
/// - NOT be valid for `timeStamping` or `OCSPSigning`, which are separate
///   purposes a claim signer is never authorized for;
/// - carry at least one permitted claim-signing EKU ([`EkuPolicy::default`]).
fn leaf_is_acceptable_claim_signer(leaf: &Certificate) -> bool {
    if profile::profile_violation(leaf, profile::CertRole::EndEntity).is_some() {
        return false;
    }
    let Some(ekus) = certificate_eku_oids(leaf) else {
        return false;
    };
    // Purpose isolation (Trust Model, Certificate Trust Chain): a certificate
    // is authorized for at most one of C2PA signing, time-stamp signing, and
    // OCSP response signing, and "a validator shall ensure a signing
    // certificate is authorized for the purpose for which it is being used".
    // A certificate valid for timeStamping or OCSPSigning is therefore never a
    // valid claim signer - whether or not that is its only EKU.
    if ekus
        .iter()
        .any(|oid| oid == OID_KP_TIME_STAMPING || oid == OID_KP_OCSP_SIGNING)
    {
        return false;
    }
    let policy = EkuPolicy::default();
    ekus.iter()
        .any(|oid| policy.allowed_oids.iter().any(|allowed| allowed == oid))
}

/// [`leaf_is_acceptable_claim_signer`] over a DER-encoded certificate, for
/// callers that trust the certificate directly (allowed list) and therefore
/// never run a chain evaluation. Unparseable certificates are unacceptable.
pub fn leaf_acceptable_der(leaf_der: &[u8]) -> bool {
    Certificate::from_der(leaf_der)
        .map(|c| leaf_is_acceptable_claim_signer(&c))
        .unwrap_or(false)
}

/// Verify that `subject` was signed by `issuer`'s public key.
///
/// Supports ECDSA over NIST P-256/P-384/P-521, RSA PKCS#1 v1.5, and Ed25519.
/// Unsupported algorithms return `false` rather than erroring.
fn verify_signature(subject: &Certificate, issuer: &Certificate) -> bool {
    let Ok(tbs) = subject.tbs_certificate.to_der() else {
        return false;
    };
    let Some(sig) = subject.signature.as_bytes() else {
        return false;
    };
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let Some(pubkey) = spki.subject_public_key.as_bytes() else {
        return false;
    };
    let sig_alg = subject.signature_algorithm.oid;
    let key_alg = spki.algorithm.oid;

    if key_alg == OID_EC_PUBLIC_KEY {
        let hash = match sig_alg {
            OID_ECDSA_SHA256 => SigHash::Sha256,
            OID_ECDSA_SHA384 => SigHash::Sha384,
            OID_ECDSA_SHA512 => SigHash::Sha512,
            _ => return false,
        };
        let curve = match spki.algorithm.parameters.as_ref() {
            Some(p) => match p.decode_as::<ObjectIdentifier>() {
                Ok(oid) => oid,
                Err(_) => return false,
            },
            None => return false,
        };
        verify_ecdsa(curve, hash, pubkey, sig, &tbs)
    } else if key_alg == OID_RSA_ENCRYPTION {
        let hash = match sig_alg {
            OID_RSA_SHA256 => SigHash::Sha256,
            OID_RSA_SHA384 => SigHash::Sha384,
            OID_RSA_SHA512 => SigHash::Sha512,
            _ => return false,
        };
        verify_rsa(hash, pubkey, sig, &tbs)
    } else if key_alg == OID_ED25519 {
        verify_ed25519(pubkey, sig, &tbs)
    } else {
        false
    }
}

fn verify_ecdsa(
    curve: ObjectIdentifier,
    hash: SigHash,
    pubkey: &[u8],
    sig_der: &[u8],
    tbs: &[u8],
) -> bool {
    let prehash = digest_bytes(hash, tbs);
    if curve == OID_CURVE_P256 {
        let (Ok(vk), Ok(sig)) = (
            p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p256::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else if curve == OID_CURVE_P384 {
        let (Ok(vk), Ok(sig)) = (
            p384::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p384::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else if curve == OID_CURVE_P521 {
        let (Ok(vk), Ok(sig)) = (
            p521::ecdsa::VerifyingKey::from_sec1_bytes(pubkey),
            p521::ecdsa::Signature::from_der(sig_der),
        ) else {
            return false;
        };
        vk.verify_prehash(&prehash, &sig).is_ok()
    } else {
        false
    }
}

fn verify_rsa(hash: SigHash, pubkey_der: &[u8], sig: &[u8], tbs: &[u8]) -> bool {
    let Ok(pubkey) = rsa::RsaPublicKey::from_pkcs1_der(pubkey_der) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig) else {
        return false;
    };
    match hash {
        SigHash::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pubkey)
            .verify(tbs, &signature)
            .is_ok(),
        SigHash::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(pubkey)
            .verify(tbs, &signature)
            .is_ok(),
        SigHash::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(pubkey)
            .verify(tbs, &signature)
            .is_ok(),
    }
}

fn verify_ed25519(pubkey: &[u8], sig: &[u8], tbs: &[u8]) -> bool {
    let Ok(key_bytes): Result<[u8; 32], _> = pubkey.try_into() else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_strict(tbs, &signature).is_ok()
}

#[cfg(test)]
mod tests;
