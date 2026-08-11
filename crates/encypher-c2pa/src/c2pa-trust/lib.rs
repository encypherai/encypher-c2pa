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
//! - [`TrustList`] — a set of trusted anchor certificates (DER).
//! - [`EkuPolicy`] — Extended Key Usage enforcement for leaf certificates.
//! - [`validate_chain`] — walk a leaf certificate up to a trusted anchor.
//! - [`RevocationDenylist`] — internal serial/fingerprint revocation set.

pub(crate) mod ocsp;
pub(crate) use ocsp::{
    evaluate_verified as evaluate_ocsp_verified, OcspStatus, MAX_OCSP_RESPONSE_BYTES,
};
mod timestamp;
use std::collections::HashSet;
pub(crate) use timestamp::{
    inspect_timestamp_token, token_from_timestamp_response, verify_timestamp_token, TimestampResult,
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
/// `id-kp-timeStamping` — required EKU for a TSA certificate. Acceptable for a
/// claim signer only as the certificate's SOLE EKU (upstream combination rule).
pub const OID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// `id-kp-OCSPSigning` — delegated OCSP responder EKU. Acceptable for a claim
/// signer only as the certificate's SOLE EKU (upstream combination rule).
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
// TrustList
// ---------------------------------------------------------------------------

/// A set of trusted anchor certificates, stored as DER.
#[derive(Debug, Clone, Default)]
pub struct TrustList {
    /// DER-encoded anchor certificates.
    pub anchors: Vec<Vec<u8>>,
}

impl TrustList {
    /// Build a trust list from a PEM bundle containing one or more certificates.
    ///
    /// Each `CERTIFICATE` block is parsed and re-encoded to canonical DER.
    /// Returns [`TrustError::NoCertificates`] when the bundle yields no
    /// certificates and [`TrustError::Decode`] when a block cannot be decoded.
    pub fn from_pem(pem: &str) -> Result<Self, TrustError> {
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
            anchors.push(der);
        }
        Ok(Self { anchors })
    }

    /// Return the Common Name (`CN`) of each anchor certificate.
    ///
    /// Anchors without a `CN` attribute are skipped, mirroring the enterprise
    /// `get_trust_anchor_subjects` behavior.
    pub fn anchor_subjects(&self) -> Vec<String> {
        self.anchors
            .iter()
            .filter_map(|der| {
                let cert = Certificate::from_der(der).ok()?;
                common_name(&cert)
            })
            .collect()
    }

    /// Set of SHA-256 fingerprints (lowercase hex) of all anchors.
    fn anchor_fingerprints(&self) -> HashSet<String> {
        self.anchors
            .iter()
            .map(|der| fingerprint_hex(der))
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
    /// validator (c2pa-rs `check_certificate_profile`) accepts — the C2PA
    /// claim-signing OID, both document-signing OIDs, `emailProtection`
    /// (still the most widely deployed claim-signer EKU, e.g. the IPTC
    /// newsroom guide's GlobalSign certificates), and the Microsoft C2PA OID.
    /// `timeStamping`/`OCSPSigning` are handled separately: they are
    /// acceptable only as a certificate's sole EKU
    /// (see [`leaf_acceptable_der`]).
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
}

impl ChainResult {
    fn untrusted(reason: impl Into<String>, at: OffsetDateTime) -> Self {
        Self {
            trusted: false,
            chain_validity_ok: true,
            leaf_acceptable: true,
            reason: Some(reason.into()),
            validated_at: at,
        }
    }
}

/// Validate `leaf_der` against `trust`, optionally using `intermediates_der`
/// to bridge the chain.
///
/// When `validation_time` is `Some`, all `notBefore`/`notAfter` checks use that
/// instant instead of the system clock — this is the key capability that lets a
/// signature remain verifiable after its certificate expires, provided the
/// validation time falls within the certificate's original validity window.
///
/// The chain is considered `trusted` only when some certificate walked from the
/// leaf (inclusive) matches a trust anchor by SHA-256 fingerprint, and every
/// issuer link verified its signature, carried CA basic constraints, and was
/// itself valid at `validation_time`.
// `intermediates_below` is a deliberate walk counter (chain-depth accounting
// documented against MAX_CHAIN_DEPTH); an enumerate() would obscure it.
#[allow(clippy::explicit_counter_loop)]
pub fn validate_chain(
    leaf_der: &[u8],
    intermediates_der: &[Vec<u8>],
    trust: &TrustList,
    validation_time: Option<OffsetDateTime>,
) -> ChainResult {
    let at = validation_time.unwrap_or_else(OffsetDateTime::now_utc);

    let leaf = match Certificate::from_der(leaf_der) {
        Ok(c) => c,
        Err(e) => return ChainResult::untrusted(format!("invalid leaf certificate: {e}"), at),
    };

    // Leaf acceptability for claim signing: it must carry a permitted
    // claim-signing EKU (and not anyExtendedKeyUsage), must not be a CA, and
    // must not assert keyCertSign. These are independent of trust-anchor
    // chaining — an otherwise-trusted chain with an unacceptable leaf is still
    // not a valid claim signer.
    let leaf_acceptable = leaf_is_acceptable_claim_signer(&leaf);

    // Track whether every certificate in the walked chain is valid at `at`.
    // The leaf being expired/not-yet-valid is the most common case.
    let mut chain_validity_ok = valid_at(&leaf, at);

    // Candidate issuers: caller-supplied intermediates followed by anchors.
    let mut candidates: Vec<Certificate> = Vec::new();
    for der in intermediates_der {
        if let Ok(c) = Certificate::from_der(der) {
            candidates.push(c);
        }
    }
    for der in &trust.anchors {
        if let Ok(c) = Certificate::from_der(der) {
            candidates.push(c);
        }
    }

    let anchor_fps = trust.anchor_fingerprints();

    let mut chain_fps: HashSet<String> = HashSet::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut current = leaf;
    let mut current_der: Vec<u8> = leaf_der.to_vec();
    // Number of non-self-signed CA certs between the leaf and the current cert,
    // used to enforce each issuer's BasicConstraints pathLenConstraint.
    let mut intermediates_below: usize = 0;

    // Construct an untrusted result capturing the current validity/acceptability
    // flags. Defined as a closure over only the immutable `leaf_acceptable`/`at`;
    // `chain_validity_ok` is passed explicitly so it can still be reassigned.
    let untrusted_with = |reason: &str, validity_ok: bool| ChainResult {
        trusted: false,
        chain_validity_ok: validity_ok,
        leaf_acceptable,
        reason: Some(reason.to_string()),
        validated_at: at,
    };

    for _ in 0..MAX_CHAIN_DEPTH {
        let fp = fingerprint_hex(&current_der);
        chain_fps.insert(fp.clone());
        if seen.contains(&fp) {
            break;
        }
        seen.insert(fp);

        // Self-signed: verify its own signature and stop walking.
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            if !verify_signature(&current, &current) {
                return untrusted_with("chain root signature invalid", chain_validity_ok);
            }
            break;
        }

        // Find an issuer whose subject matches the current issuer name.
        let issuer = candidates
            .iter()
            .find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
            .cloned();
        let Some(issuer) = issuer else {
            break; // Cannot walk further; trust decision falls to fingerprint set.
        };

        if !is_ca_certificate(&issuer) {
            return untrusted_with("issuer certificate is not a CA", chain_validity_ok);
        }
        // pathLenConstraint: the number of intermediate CAs allowed below this
        // issuer. `intermediates_below` counts CAs already walked beneath it.
        if let Some(max) = path_len_constraint(&issuer) {
            if intermediates_below > max {
                return untrusted_with("issuer pathLenConstraint violated", chain_validity_ok);
            }
        }
        if !verify_signature(&current, &issuer) {
            return untrusted_with(
                "certificate signature verification failed",
                chain_validity_ok,
            );
        }
        if !valid_at(&issuer, at) {
            chain_validity_ok = false;
        }

        intermediates_below += 1;
        current_der = match issuer.to_der() {
            Ok(d) => d,
            Err(e) => {
                return untrusted_with(&format!("failed to encode issuer: {e}"), chain_validity_ok)
            }
        };
        current = issuer;
    }

    let chains_to_anchor = chain_fps.intersection(&anchor_fps).next().is_some();
    // A trusted verdict requires chaining to an anchor with the whole chain
    // valid at `at`. Leaf claim-signer acceptability (EKU/keyUsage/CA) is
    // reported separately in `leaf_acceptable` and applied by the caller only on
    // the claim-signing path — it must NOT gate TSA/timestamp chains, whose
    // leaves carry a timestamping EKU rather than a claim-signing one.
    let trusted = chains_to_anchor && chain_validity_ok;
    ChainResult {
        trusted,
        chain_validity_ok,
        leaf_acceptable,
        reason: if trusted {
            None
        } else if !chains_to_anchor {
            Some("certificate does not chain to a trusted anchor".into())
        } else {
            Some("a certificate in the chain was outside its validity window".into())
        },
        validated_at: at,
    }
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

/// True when a DER certificate satisfies the C2PA leaf structural profile,
/// independent of the application-specific permitted EKU set.
///
/// CAWG imports the C2PA credential profile but defines its own accepted EKUs
/// (IETF document signing and interim S/MIME email protection), so it uses
/// this predicate before applying its own EKU policy.
pub fn leaf_profile_acceptable_der(leaf_der: &[u8]) -> bool {
    let Ok(leaf) = Certificate::from_der(leaf_der) else {
        return false;
    };
    if is_ca_certificate(&leaf) || has_key_cert_sign(&leaf) || !allows_digital_signature(&leaf) {
        return false;
    }
    certificate_eku_oids(&leaf).is_some_and(|ekus| !ekus.iter().any(|oid| oid == OID_ANY_EKU))
}

/// True when `leaf` is an acceptable C2PA claim-signing certificate.
///
/// Per the C2PA trust model the leaf MUST:
/// - carry at least one permitted claim-signing EKU ([`EkuPolicy::default`]),
/// - NOT carry `anyExtendedKeyUsage`,
/// - NOT be a CA certificate, and NOT assert `keyCertSign`,
/// - assert `digitalSignature` (or omit keyUsage entirely).
fn leaf_is_acceptable_claim_signer(leaf: &Certificate) -> bool {
    // Reject CA / keyCertSign leaves outright.
    if is_ca_certificate(leaf) || has_key_cert_sign(leaf) {
        return false;
    }
    if !allows_digital_signature(leaf) {
        return false;
    }
    // EKU: must declare one, must not include anyExtendedKeyUsage, and must
    // satisfy the reference profile's combination rules: `timeStamping` and
    // `OCSPSigning` are each acceptable only as the certificate's SOLE EKU;
    // otherwise the certificate must carry a permitted claim-signing OID.
    let Some(ekus) = certificate_eku_oids(leaf) else {
        return false;
    };
    if ekus.iter().any(|oid| oid == OID_ANY_EKU) {
        return false;
    }
    let special = ekus
        .iter()
        .any(|oid| oid == OID_KP_TIME_STAMPING || oid == OID_KP_OCSP_SIGNING);
    if special {
        return ekus.len() == 1;
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
