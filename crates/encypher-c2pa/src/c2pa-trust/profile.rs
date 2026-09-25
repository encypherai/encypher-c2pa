// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! C2PA certificate profile and RFC 5280 path constraints.
//!
//! The Trust Model clause "Certificate Profiles" states requirements that every
//! certificate offered as a signing credential must satisfy, and requires the
//! chain itself to be built and validated by the RFC 5280 section 6 procedure
//! for the purpose in question. This module holds both halves:
//!
//! - [`profile_violation`] checks one certificate against the profile.
//! - [`path_violation`] checks a complete candidate path against the RFC 5280
//!   constraints the profile leans on: basic constraints and `pathLenConstraint`,
//!   `keyCertSign` on CAs, name constraints, and policy constraints.
//!
//! Both return `Some(reason)` on rejection so the caller can report *why* a
//! credential was refused instead of collapsing every defect into "untrusted".
//!
//! The trust anchor's own certificate is deliberately **not** subject to
//! [`profile_violation`]: RFC 5280 section 6.1 treats an anchor as a name, a
//! key and an algorithm rather than as a certificate on the path. Its name and
//! policy constraints are still honored, which is what section 6.2 permits.

use std::collections::HashSet;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    CertificatePolicies, NameConstraints, PolicyConstraints, SubjectAltName,
};
use x509_cert::Certificate;

use super::{
    allows_digital_signature, certificate_eku_oids, has_key_cert_sign, is_ca_certificate,
    path_len_constraint, OID_ANY_EKU, OID_EXT_BASIC_CONSTRAINTS, OID_EXT_EKU, OID_EXT_KEY_USAGE,
    OID_KP_OCSP_SIGNING, OID_KP_TIME_STAMPING,
};

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

const OID_EXT_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EXT_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_EXT_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
const OID_EXT_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
const OID_EXT_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");
const OID_EXT_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_EXT_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");
const OID_EXT_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");

/// `anyPolicy`, the wildcard certificate policy.
const OID_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32.0");

const OID_AT_EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
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

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// Minimum RSA modulus length the profile accepts, in bits.
const MIN_RSA_MODULUS_BITS: u32 = 2048;

/// Extensions this validator understands well enough to honor when a
/// certificate marks them critical. RFC 5280 section 6.1.4(f) requires a path
/// to be rejected when it carries a critical extension the validator does not
/// process, so anything outside this set is a rejection.
const RECOGNIZED_CRITICAL_EXTENSIONS: &[ObjectIdentifier] = &[
    OID_EXT_SUBJECT_KEY_IDENTIFIER,
    OID_EXT_KEY_USAGE,
    OID_EXT_SUBJECT_ALT_NAME,
    OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_NAME_CONSTRAINTS,
    OID_EXT_CERTIFICATE_POLICIES,
    OID_EXT_AUTHORITY_KEY_IDENTIFIER,
    OID_EXT_POLICY_CONSTRAINTS,
    OID_EXT_INHIBIT_ANY_POLICY,
    OID_EXT_EKU,
];

/// Where a certificate sits on the path being validated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CertRole {
    /// The certificate whose key produced the signature under validation.
    EndEntity,
    /// A CA certificate between the end entity and the trust anchor.
    Intermediate,
}

// ---------------------------------------------------------------------------
// Single-certificate profile
// ---------------------------------------------------------------------------

/// Check one certificate against the C2PA certificate profile.
///
/// Returns `Some(reason)` when the certificate is unacceptable. The EKU
/// *purpose* rules that differ per application (which claim-signing OIDs are
/// accepted) stay with the caller; what lives here is what the profile demands
/// of every certificate regardless of purpose.
pub(crate) fn profile_violation(cert: &Certificate, role: CertRole) -> Option<&'static str> {
    // "All certificates shall fulfill the following requirements": signature
    // algorithm allow list and public-key constraints.
    if let Some(reason) = signature_algorithm_violation(cert) {
        return Some(reason);
    }
    if let Some(reason) = public_key_violation(cert) {
        return Some(reason);
    }

    // RFC 5280 4.1.1.2: the outer signatureAlgorithm must match the inner
    // TBSCertificate signature field, or the certificate is malformed.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Some("certificate signature algorithm does not match its TBSCertificate");
    }

    if cert.tbs_certificate.version != Version::V3 {
        return Some("certificate is not X.509 v3");
    }
    if cert.tbs_certificate.issuer_unique_id.is_some()
        || cert.tbs_certificate.subject_unique_id.is_some()
    {
        return Some("certificate carries an issuerUniqueID or subjectUniqueID");
    }

    let self_signed = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
    if !self_signed && !has_extension(cert, OID_EXT_AUTHORITY_KEY_IDENTIFIER) {
        return Some("certificate is not self-signed and has no Authority Key Identifier");
    }

    if let Some(reason) = critical_extension_violation(cert) {
        return Some(reason);
    }

    let is_ca = is_ca_certificate(cert);
    if is_ca && !has_extension(cert, OID_EXT_SUBJECT_KEY_IDENTIFIER) {
        return Some("CA certificate has no Subject Key Identifier");
    }

    // "The Key Usage extension shall be present", and keyCertSign is reserved
    // for certificates whose Basic Constraints assert cA.
    if !has_extension(cert, OID_EXT_KEY_USAGE) {
        return Some("certificate has no Key Usage extension");
    }
    if has_key_cert_sign(cert) && !is_ca {
        return Some("certificate asserts keyCertSign without the cA basic constraint");
    }

    match role {
        CertRole::Intermediate => {
            if !is_ca {
                return Some("issuer certificate does not assert the cA basic constraint");
            }
            // RFC 5280 6.1.4(n): a CA on the path must assert keyCertSign.
            if !has_key_cert_sign(cert) {
                return Some("CA certificate does not assert keyCertSign");
            }
        }
        CertRole::EndEntity => {
            if is_ca {
                return Some("signing certificate asserts the cA basic constraint");
            }
            if !allows_digital_signature(cert) {
                return Some("signing certificate does not assert digitalSignature");
            }
            if let Some(reason) = end_entity_eku_violation(cert) {
                return Some(reason);
            }
        }
    }
    None
}

/// The EKU rules the profile places on an end-entity certificate: present and
/// non-empty, no `anyExtendedKeyUsage`, and at most one of the time-stamping
/// and OCSP-signing purposes, exclusive of every other purpose.
fn end_entity_eku_violation(cert: &Certificate) -> Option<&'static str> {
    let Some(ekus) = certificate_eku_oids(cert) else {
        return Some("end-entity certificate has no Extended Key Usage extension");
    };
    if ekus.is_empty() {
        return Some("end-entity certificate has an empty Extended Key Usage extension");
    }
    if ekus.iter().any(|oid| oid == OID_ANY_EKU) {
        return Some("end-entity certificate carries anyExtendedKeyUsage");
    }
    let time_stamping = ekus.iter().any(|oid| oid == OID_KP_TIME_STAMPING);
    let ocsp_signing = ekus.iter().any(|oid| oid == OID_KP_OCSP_SIGNING);
    if (time_stamping || ocsp_signing) && ekus.len() != 1 {
        // "If a certificate is valid for either id-kp-timeStamping or
        // id-kp-OCSPSigning, it shall be valid for exactly one of those two
        // purposes, and not valid for any other purpose."
        return Some("certificate mixes time-stamping or OCSP signing with another purpose");
    }
    None
}

fn has_extension(cert: &Certificate, oid: ObjectIdentifier) -> bool {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .is_some_and(|exts| exts.iter().any(|ext| ext.extn_id == oid))
}

fn extension_value(cert: &Certificate, oid: ObjectIdentifier) -> Option<&[u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|ext| ext.extn_id == oid)
        .map(|ext| ext.extn_value.as_bytes())
}

fn critical_extension_violation(cert: &Certificate) -> Option<&'static str> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let unknown = exts
        .iter()
        .any(|ext| ext.critical && !RECOGNIZED_CRITICAL_EXTENSIONS.contains(&ext.extn_id));
    unknown.then_some("certificate carries an unrecognized critical extension")
}

/// The `signatureAlgorithm` allow list, including the RSASSA-PSS parameter
/// constraints the profile spells out.
fn signature_algorithm_violation(cert: &Certificate) -> Option<&'static str> {
    let alg = &cert.signature_algorithm;
    match alg.oid {
        OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512 | OID_RSA_SHA256
        | OID_RSA_SHA384 | OID_RSA_SHA512 | OID_ED25519 => None,
        OID_RSASSA_PSS => {
            let Some(parameters) = alg.parameters.as_ref() else {
                return Some("RSASSA-PSS certificate signature has no parameters");
            };
            let Ok(der) = parameters.to_der() else {
                return Some("RSASSA-PSS certificate signature parameters are malformed");
            };
            let Ok(params) = rsa::pkcs1::RsaPssParams::try_from(der.as_slice()) else {
                return Some("RSASSA-PSS certificate signature parameters are malformed");
            };
            if !matches!(params.hash.oid, OID_SHA256 | OID_SHA384 | OID_SHA512) {
                return Some("RSASSA-PSS hashAlgorithm is not SHA-256, SHA-384 or SHA-512");
            }
            if params.mask_gen.oid != OID_MGF1 {
                return Some("RSASSA-PSS maskGenAlgorithm is not MGF1");
            }
            let Some(mask_hash) = params.mask_gen.parameters.as_ref() else {
                return Some("RSASSA-PSS maskGenAlgorithm has no hash parameter");
            };
            if mask_hash.oid != params.hash.oid {
                return Some("RSASSA-PSS MGF1 hash does not match hashAlgorithm");
            }
            None
        }
        _ => Some("certificate signature algorithm is outside the C2PA allow list"),
    }
}

/// The `subjectPublicKeyInfo` constraints: named curves for EC keys, and a
/// 2048-bit floor for RSA keys.
fn public_key_violation(cert: &Certificate) -> Option<&'static str> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        return match curve {
            Some(OID_CURVE_P256 | OID_CURVE_P384 | OID_CURVE_P521) => None,
            _ => Some("EC public key does not use prime256v1, secp384r1 or secp521r1"),
        };
    }
    if spki.algorithm.oid == OID_RSA_ENCRYPTION || spki.algorithm.oid == OID_RSASSA_PSS {
        let Some(raw) = spki.subject_public_key.as_bytes() else {
            return Some("RSA public key bit string has unused bits");
        };
        let Ok(key) = rsa::pkcs1::RsaPublicKey::try_from(raw) else {
            return Some("RSA public key is malformed");
        };
        // `as_bytes` drops the DER sign-guard byte, so the bit length is taken
        // from the first significant octet of the modulus.
        let modulus = key.modulus.as_bytes();
        let bits = modulus
            .iter()
            .position(|byte| *byte != 0)
            .map(|first| (modulus.len() - first) as u32 * 8 - modulus[first].leading_zeros())
            .unwrap_or(0);
        if bits < MIN_RSA_MODULUS_BITS {
            return Some("RSA modulus is shorter than 2048 bits");
        }
        return None;
    }
    if spki.algorithm.oid == OID_ED25519 {
        return None;
    }
    Some("certificate public key algorithm is outside the C2PA allow list")
}

// ---------------------------------------------------------------------------
// Path constraints
// ---------------------------------------------------------------------------

/// Check a complete candidate path, ordered end entity first and trust anchor
/// last, against the RFC 5280 section 6 constraints.
///
/// `path[0]` is the certificate under validation; `path[path.len() - 1]` is the
/// anchor. A single-element path (the anchor is itself the credential) has no
/// constraints to apply.
pub(crate) fn path_violation(path: &[Certificate]) -> Option<&'static str> {
    for (index, cert) in path.iter().enumerate() {
        // The anchor is a trusted name and key, not a path certificate.
        if index + 1 == path.len() {
            break;
        }
        let role = if index == 0 {
            CertRole::EndEntity
        } else {
            CertRole::Intermediate
        };
        if let Some(reason) = profile_violation(cert, role) {
            return Some(reason);
        }
    }

    // pathLenConstraint: an issuer at `index` has `index - 1` intermediate CAs
    // below it, none of which it is allowed to exceed.
    for (index, issuer) in path.iter().enumerate().skip(1) {
        if let Some(max) = path_len_constraint(issuer) {
            if index - 1 > max {
                return Some("issuer pathLenConstraint violated");
            }
        }
    }

    if let Some(reason) = name_constraints_violation(path) {
        return Some(reason);
    }
    policy_violation(path)
}

/// Apply each CA's name constraints to every certificate beneath it.
fn name_constraints_violation(path: &[Certificate]) -> Option<&'static str> {
    for (index, ca) in path.iter().enumerate().skip(1) {
        let Some(raw) = extension_value(ca, OID_EXT_NAME_CONSTRAINTS) else {
            continue;
        };
        let Ok(constraints) = NameConstraints::from_der(raw) else {
            return Some("name constraints extension is malformed");
        };
        for subtrees in [
            constraints.permitted_subtrees.as_ref(),
            constraints.excluded_subtrees.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for subtree in subtrees {
                if subtree.minimum != 0 || subtree.maximum.is_some() {
                    return Some("name constraints use the unsupported minimum/maximum fields");
                }
                if !supported_constraint_base(&subtree.base) {
                    return Some("name constraints use an unsupported name form");
                }
            }
        }
        for subordinate in &path[..index] {
            if let Some(reason) = subordinate_names_violation(subordinate, &constraints) {
                return Some(reason);
            }
        }
    }
    None
}

fn supported_constraint_base(base: &GeneralName) -> bool {
    matches!(
        base,
        GeneralName::Rfc822Name(_)
            | GeneralName::DnsName(_)
            | GeneralName::DirectoryName(_)
            | GeneralName::UniformResourceIdentifier(_)
            | GeneralName::IpAddress(_)
    )
}

/// Every name a certificate presents: its subject DN, the e-mail address
/// attributes inside that DN, and its subject alternative names.
fn subordinate_names(cert: &Certificate) -> Vec<GeneralName> {
    let mut names = vec![GeneralName::DirectoryName(
        cert.tbs_certificate.subject.clone(),
    )];
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid == OID_AT_EMAIL_ADDRESS {
                if let Ok(value) = atav.value.decode_as::<der::asn1::Ia5String>() {
                    names.push(GeneralName::Rfc822Name(value));
                }
            }
        }
    }
    if let Some(raw) = extension_value(cert, OID_EXT_SUBJECT_ALT_NAME) {
        if let Ok(san) = SubjectAltName::from_der(raw) {
            names.extend(san.0);
        }
    }
    names
}

fn subordinate_names_violation(
    cert: &Certificate,
    constraints: &NameConstraints,
) -> Option<&'static str> {
    let names = subordinate_names(cert);
    if let Some(excluded) = constraints.excluded_subtrees.as_ref() {
        for subtree in excluded {
            if names.iter().any(|name| name_within(name, &subtree.base)) {
                return Some("certificate name falls inside an excluded name subtree");
            }
        }
    }
    let permitted = constraints.permitted_subtrees.as_ref()?;
    for name in &names {
        // A name form that the CA did not constrain stays unrestricted; a name
        // form it did constrain must match one of its subtrees.
        let constrained: Vec<&GeneralSubtree> = permitted
            .iter()
            .filter(|subtree| same_name_form(name, &subtree.base))
            .collect();
        if constrained.is_empty() {
            continue;
        }
        if !constrained
            .iter()
            .any(|subtree| name_within(name, &subtree.base))
        {
            return Some("certificate name falls outside every permitted name subtree");
        }
    }
    None
}

fn same_name_form(name: &GeneralName, base: &GeneralName) -> bool {
    std::mem::discriminant(name) == std::mem::discriminant(base)
}

/// RFC 5280 4.2.1.10 subtree membership for the name forms this validator
/// processes.
fn name_within(name: &GeneralName, base: &GeneralName) -> bool {
    match (name, base) {
        (GeneralName::DnsName(name), GeneralName::DnsName(base)) => {
            host_within(name.as_str(), base.as_str())
        }
        (GeneralName::Rfc822Name(name), GeneralName::Rfc822Name(base)) => {
            rfc822_within(name.as_str(), base.as_str())
        }
        (
            GeneralName::UniformResourceIdentifier(name),
            GeneralName::UniformResourceIdentifier(base),
        ) => uri_host(name.as_str()).is_some_and(|host| host_within(host, base.as_str())),
        (GeneralName::IpAddress(name), GeneralName::IpAddress(base)) => {
            ip_within(name.as_bytes(), base.as_bytes())
        }
        (GeneralName::DirectoryName(name), GeneralName::DirectoryName(base)) => {
            // A DN is within a subtree when the base is a prefix of its RDN
            // sequence, compared on encoded RDNs.
            if base.0.len() > name.0.len() {
                return false;
            }
            base.0.iter().zip(name.0.iter()).all(|(base, name)| {
                match (base.to_der(), name.to_der()) {
                    (Ok(base), Ok(name)) => base == name,
                    _ => false,
                }
            })
        }
        _ => false,
    }
}

fn host_within(host: &str, base: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let base = base.to_ascii_lowercase();
    if base.is_empty() {
        return true;
    }
    if host == base {
        return true;
    }
    let base = base.strip_prefix('.').unwrap_or(&base);
    host.len() > base.len()
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
}

fn rfc822_within(name: &str, base: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let base = base.to_ascii_lowercase();
    if base.contains('@') {
        return name == base;
    }
    let Some(host) = name.split_once('@').map(|(_, host)| host.to_string()) else {
        return false;
    };
    if base.starts_with('.') {
        return host_within(&host, &base);
    }
    host == base
}

fn uri_host(uri: &str) -> Option<&str> {
    let rest = uri.split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Some(authority.split(':').next().unwrap_or(authority))
}

fn ip_within(name: &[u8], base: &[u8]) -> bool {
    // A constraint base is an address followed by a mask of equal length.
    if base.len() != name.len() * 2 {
        return false;
    }
    let (network, mask) = base.split_at(name.len());
    name.iter()
        .zip(network.iter())
        .zip(mask.iter())
        .all(|((addr, net), mask)| addr & mask == net & mask)
}

/// RFC 5280 section 6.1.4 policy processing, in the conservative form this
/// verifier can honor: policy mapping is not implemented, so a path that
/// requires it is rejected rather than accepted unchecked.
fn policy_violation(path: &[Certificate]) -> Option<&'static str> {
    let mut explicit_policy_required = false;
    for (index, ca) in path.iter().enumerate().skip(1) {
        if has_extension(ca, OID_EXT_POLICY_MAPPINGS) {
            return Some("certificate policy mapping is not supported");
        }
        let Some(raw) = extension_value(ca, OID_EXT_POLICY_CONSTRAINTS) else {
            continue;
        };
        let Ok(constraints) = PolicyConstraints::from_der(raw) else {
            return Some("policy constraints extension is malformed");
        };
        if let Some(skip) = constraints.require_explicit_policy {
            // `skip` counts the certificates that may still appear before an
            // explicit policy is required for the whole path.
            if (index as u64) > u64::from(skip) {
                explicit_policy_required = true;
            }
        }
    }
    if !explicit_policy_required {
        return None;
    }

    // With no caller-supplied initial policy set, an explicit policy is
    // satisfied when every certificate below the anchor asserts at least one
    // policy and the assertions intersect.
    let mut common: Option<HashSet<ObjectIdentifier>> = None;
    for cert in &path[..path.len().saturating_sub(1)] {
        let Some(raw) = extension_value(cert, OID_EXT_CERTIFICATE_POLICIES) else {
            return Some("an explicit certificate policy is required but not asserted");
        };
        let Ok(policies) = CertificatePolicies::from_der(raw) else {
            return Some("certificate policies extension is malformed");
        };
        let asserted: HashSet<ObjectIdentifier> = policies
            .0
            .iter()
            .map(|policy| policy.policy_identifier)
            .filter(|oid| *oid != OID_ANY_POLICY)
            .collect();
        if asserted.is_empty() {
            return Some("an explicit certificate policy is required but not asserted");
        }
        common = Some(match common {
            None => asserted,
            Some(previous) => previous.intersection(&asserted).copied().collect(),
        });
    }
    match common {
        Some(common) if common.is_empty() => {
            Some("no certificate policy is common to the whole path")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
