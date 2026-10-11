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
//! RFC 5280 treats the trust anchor as a name, key, and algorithm rather than
//! as a certificate on the path. Exact 2.5 still admits its certificate under
//! the C2PA profile, but its encoded validity period and path constraints are
//! not RFC 5280 trust-anchor inputs.

use std::collections::{HashMap, HashSet};

use const_oid::ObjectIdentifier;
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::certificate::Version;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    CertificatePolicies, InhibitAnyPolicy, NameConstraints, PolicyConstraints, PolicyMappings,
    SubjectAltName,
};
use x509_cert::Certificate;

use super::{
    allows_digital_signature, certificate_eku_oids, has_key_cert_sign, is_ca_certificate,
    path_len_constraint, AnchorPurpose, CertificateProfile, OID_ANY_EKU, OID_EXT_BASIC_CONSTRAINTS,
    OID_EXT_EKU, OID_EXT_KEY_USAGE, OID_KP_OCSP_SIGNING, OID_KP_TIME_STAMPING,
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
const OID_QT_CPS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.1");
const OID_QT_USER_NOTICE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.2.2");

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

const OID_ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const OID_ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const OID_ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

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

/// Which revision's profile applies, and whether the end entity is a signing
/// credential the algorithm requirements bind.
///
/// The 2.4 profile applies the signature-algorithm and public-key allow lists
/// to every path certificate. The 2.5 profile adds RSASSA-PSS with the full
/// RFC 4055 salt range and ML-DSA-44/65/87, and scopes those requirements to
/// claim-signing certificates: "The requirements do not apply to TSA, OCSP or
/// CA certificates in certificate chains" (Trust Model, Certificate Profiles,
/// General Requirements). CAWG credentials import the C2PA claim-signing
/// profile, so they are bound as well.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ProfileRules {
    profile: CertificateProfile,
    signing_credential: bool,
}

impl ProfileRules {
    /// The established 2.4 rules.
    pub(crate) const V2_4: Self = Self {
        profile: CertificateProfile::V2_4,
        signing_credential: true,
    };

    /// Rules for an end entity validated for `purpose` under `profile`.
    pub(crate) fn for_purpose(profile: CertificateProfile, purpose: AnchorPurpose) -> Self {
        Self {
            profile,
            signing_credential: purpose != AnchorPurpose::TimeStamping,
        }
    }

    /// Rules for a TSA or OCSP responder end entity under `profile`.
    pub(crate) fn exempt_end_entity(profile: CertificateProfile) -> Self {
        Self {
            profile,
            signing_credential: false,
        }
    }

    fn algorithm_violation(self, cert: &Certificate, role: CertRole) -> Option<&'static str> {
        match self.profile {
            CertificateProfile::V2_2 | CertificateProfile::V2_4 => {
                signature_algorithm_violation(cert).or_else(|| public_key_violation(cert))
            }
            CertificateProfile::V2_5 if role == CertRole::EndEntity && self.signing_credential => {
                signature_algorithm_violation_v2_5(cert).or_else(|| public_key_violation_v2_5(cert))
            }
            CertificateProfile::V2_5 => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Single-certificate profile
// ---------------------------------------------------------------------------

/// [`profile_violation_with`] under [`ProfileRules::V2_4`].
pub(crate) fn profile_violation(cert: &Certificate, role: CertRole) -> Option<&'static str> {
    profile_violation_with(cert, role, ProfileRules::V2_4)
}

/// Check one certificate against the C2PA certificate profile.
///
/// Returns `Some(reason)` when the certificate is unacceptable. The EKU
/// *purpose* rules that differ per application (which claim-signing OIDs are
/// accepted) stay with the caller; what lives here is what the profile demands
/// of every certificate regardless of purpose, plus the algorithm
/// requirements `rules` selects.
pub(crate) fn profile_violation_with(
    cert: &Certificate,
    role: CertRole,
    rules: ProfileRules,
) -> Option<&'static str> {
    // Signature algorithm allow list and public-key constraints.
    if let Some(reason) = rules.algorithm_violation(cert, role) {
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

    let has_aki = has_extension(cert, OID_EXT_AUTHORITY_KEY_IDENTIFIER);
    if !has_aki {
        let names_match = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
        let self_signed = names_match
            && (rules.profile != CertificateProfile::V2_5
                || super::verify_signature_with(cert, cert, CertificateProfile::V2_5));
        if !self_signed {
            return Some(if rules.profile == CertificateProfile::V2_5 {
                "certificate has no Authority Key Identifier and its self-signed status cannot be verified"
            } else {
                "certificate is not self-signed and has no Authority Key Identifier"
            });
        }
    }

    if rules.profile == CertificateProfile::V2_5 {
        if let Some(extensions) = cert.tbs_certificate.extensions.as_ref() {
            let mut seen = HashSet::with_capacity(extensions.len());
            if extensions
                .iter()
                .any(|extension| !seen.insert(extension.extn_id))
            {
                return Some("certificate repeats an extension OID");
            }
        }
    }

    if let Some(reason) = critical_extension_violation(cert, rules) {
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

fn critical_extension_violation(cert: &Certificate, rules: ProfileRules) -> Option<&'static str> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    let unknown = exts.iter().any(|ext| {
        ext.critical
            && !RECOGNIZED_CRITICAL_EXTENSIONS.contains(&ext.extn_id)
            && !(rules.profile == CertificateProfile::V2_5
                && ext.extn_id == OID_EXT_POLICY_MAPPINGS)
    });
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

/// The 2.5 `signatureAlgorithm` allow list for a claim-signing certificate:
/// the 2.4 algorithms plus ML-DSA-44/65/87 with absent parameters, and
/// RSASSA-PSS whose parameters carry a present SHA-256/384/512 hash and MGF1
/// over the same hash. The salt length may be any RFC 4055 value.
fn signature_algorithm_violation_v2_5(cert: &Certificate) -> Option<&'static str> {
    let alg = &cert.signature_algorithm;
    match alg.oid {
        OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512 | OID_RSA_SHA256
        | OID_RSA_SHA384 | OID_RSA_SHA512 | OID_ED25519 => None,
        OID_ML_DSA_44 | OID_ML_DSA_65 | OID_ML_DSA_87 => alg
            .parameters
            .is_some()
            .then_some("ML-DSA certificate signature algorithm carries parameters"),
        OID_RSASSA_PSS => {
            let Some(parameters) = alg.parameters.as_ref() else {
                return Some("RSASSA-PSS certificate signature has no parameters");
            };
            pss_parameters_violation(parameters)
        }
        _ => Some("certificate signature algorithm is outside the C2PA allow list"),
    }
}

/// RFC 4055 `RSASSA-PSS-params` read with a full-range salt length.
fn pss_parameters_violation(parameters: &der::Any) -> Option<&'static str> {
    use der::{Reader as _, TagMode, TagNumber};

    let parsed = parameters.sequence(|reader| {
        let hash: Option<spki::AlgorithmIdentifierRef<'_>> =
            reader.context_specific(TagNumber::N0, TagMode::Explicit)?;
        let mask: Option<spki::AlgorithmIdentifier<spki::AlgorithmIdentifierRef<'_>>> =
            reader.context_specific(TagNumber::N1, TagMode::Explicit)?;
        let _salt: Option<u32> = reader.context_specific(TagNumber::N2, TagMode::Explicit)?;
        let _trailer: Option<u32> = reader.context_specific(TagNumber::N3, TagMode::Explicit)?;
        Ok((
            hash.map(|hash| hash.oid),
            mask.map(|mask| (mask.oid, mask.parameters.map(|inner| inner.oid))),
        ))
    });
    let Ok((hash, mask)) = parsed else {
        return Some("RSASSA-PSS certificate signature parameters are malformed");
    };
    let Some(hash) = hash else {
        return Some("RSASSA-PSS hashAlgorithm is absent");
    };
    if !matches!(hash, OID_SHA256 | OID_SHA384 | OID_SHA512) {
        return Some("RSASSA-PSS hashAlgorithm is not SHA-256, SHA-384 or SHA-512");
    }
    match mask {
        None => Some("RSASSA-PSS maskGenAlgorithm is absent"),
        Some((mgf, _)) if mgf != OID_MGF1 => Some("RSASSA-PSS maskGenAlgorithm is not MGF1"),
        Some((_, None)) => Some("RSASSA-PSS maskGenAlgorithm has no hash parameter"),
        Some((_, Some(mask_hash))) if mask_hash != hash => {
            Some("RSASSA-PSS MGF1 hash does not match hashAlgorithm")
        }
        Some(_) => None,
    }
}

/// The 2.5 `subjectPublicKeyInfo` constraints for a claim-signing
/// certificate: the 2.4 rules plus an ML-DSA key with absent parameters and
/// the RFC 9881 encoding of its parameter set.
fn public_key_violation_v2_5(cert: &Certificate) -> Option<&'static str> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if matches!(
        spki.algorithm.oid,
        OID_ML_DSA_44 | OID_ML_DSA_65 | OID_ML_DSA_87
    ) {
        let Ok(der) = spki.to_der() else {
            return Some("ML-DSA public key is malformed");
        };
        return crate::c2pa_crypto::ml_dsa_spki_alg(&der)
            .is_err()
            .then_some("ML-DSA public key is not an RFC 9881 encoding of its parameter set");
    }
    public_key_violation(cert)
}

// ---------------------------------------------------------------------------
// Path constraints
// ---------------------------------------------------------------------------

/// Check a complete candidate path, ordered end entity first and trust anchor
/// last, against the certificate profile `rules` select and the RFC 5280
/// section 6 constraints.
///
/// `path[0]` is the certificate under validation; `path[path.len() - 1]` is the
/// anchor. Exact 2.5 admits the anchor under the C2PA certificate profile but
/// excludes its encoded RFC 5280 path constraints.
pub(crate) fn path_violation(path: &[Certificate], rules: ProfileRules) -> Option<&'static str> {
    let exact_v2_5 = rules.profile == CertificateProfile::V2_5;
    for (index, cert) in path.iter().enumerate() {
        let anchor = index + 1 == path.len();
        if anchor && !exact_v2_5 {
            break;
        }
        // Exact 2.5 retains C2PA certificate-profile admission for the
        // configured anchor. Its RFC 5280 role is still trust-anchor input,
        // so path constraints below exclude its encoded extensions.
        let role = if anchor && is_ca_certificate(cert) {
            CertRole::Intermediate
        } else if index == 0 {
            CertRole::EndEntity
        } else {
            CertRole::Intermediate
        };
        if let Some(reason) = profile_violation_with(cert, role, rules) {
            return Some(reason);
        }
    }

    // The anchor's encoded pathLenConstraint is not a trust-anchor input.
    let issuer_end = if exact_v2_5 {
        path.len().saturating_sub(1)
    } else {
        path.len()
    };
    for (index, issuer) in path[..issuer_end].iter().enumerate().skip(1) {
        if let Some(max) = path_len_constraint(issuer) {
            let ca_certificates_below = if exact_v2_5 {
                path[1..index]
                    .iter()
                    .filter(|cert| cert.tbs_certificate.subject != cert.tbs_certificate.issuer)
                    .count()
            } else {
                index - 1
            };
            if ca_certificates_below > max {
                return Some("issuer pathLenConstraint violated");
            }
        }
    }

    let constrained_path = if exact_v2_5 {
        &path[..path.len().saturating_sub(1)]
    } else {
        path
    };
    if let Some(reason) = name_constraints_violation(constrained_path, exact_v2_5) {
        return Some(reason);
    }
    policy_violation(path, rules)
}

/// Apply each CA's name constraints to every certificate beneath it.
fn name_constraints_violation(path: &[Certificate], exact_v2_5: bool) -> Option<&'static str> {
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
        for (subordinate_index, subordinate) in path[..index].iter().enumerate() {
            if exact_v2_5
                && subordinate_index > 0
                && subordinate.tbs_certificate.subject == subordinate.tbs_certificate.issuer
            {
                continue;
            }
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

/// Apply certificate-policy processing while retaining the established 2.2
/// and 2.4 refusal behavior. Exact 2.5 paths use the RFC 5280 section 6 policy
/// tree and counters, including mappings and `anyPolicy`.
fn policy_violation(path: &[Certificate], rules: ProfileRules) -> Option<&'static str> {
    match rules.profile {
        CertificateProfile::V2_5 => rfc5280_policy_violation(path),
        CertificateProfile::V2_2 | CertificateProfile::V2_4 => legacy_policy_violation(path),
    }
}

/// The pre-2.5 policy behavior is intentionally frozen for compatibility.
fn legacy_policy_violation(path: &[Certificate]) -> Option<&'static str> {
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
            if (index as u64) > u64::from(skip) {
                explicit_policy_required = true;
            }
        }
    }
    if !explicit_policy_required {
        return None;
    }

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

/// Expected policies for one RFC 9618 policy-graph node.
///
/// `None` is the common singleton case: the expected policy is the node's own
/// valid-policy OID. A set is allocated only when policy mappings replace it.
type ExpectedPolicies = Option<HashSet<ObjectIdentifier>>;

/// The current policy-graph level, keyed by valid-policy OID.
///
/// RFC 9618 section 5.2 requires at most one node for each OID at a depth.
type PolicyLevel = HashMap<ObjectIdentifier, ExpectedPolicies>;

#[derive(Default)]
struct ParsedPolicyExtensions {
    policies: Option<CertificatePolicies>,
    mappings: Option<HashMap<ObjectIdentifier, HashSet<ObjectIdentifier>>>,
    constraints: Option<PolicyConstraints>,
    inhibit_any_policy: Option<u32>,
}

/// RFC 5280 section 6 as updated by RFC 9618. The C2PA API supplies the
/// unconstrained user policy set and no initial inhibit flags, so all three
/// counters start at n+1.
fn rfc5280_policy_violation(path: &[Certificate]) -> Option<&'static str> {
    let certificate_count = path.len().saturating_sub(1);
    if certificate_count == 0 {
        return path
            .first()
            .and_then(|target_anchor| parse_policy_extensions(target_anchor).err());
    }

    let mut root = HashMap::new();
    root.insert(OID_ANY_POLICY, None);
    let mut valid_policy_level = Some(root);
    let mut explicit_policy = certificate_count + 1;
    let mut policy_mapping = certificate_count + 1;
    let mut inhibit_any_policy = certificate_count + 1;

    // RFC order is trust anchor toward target. The anchor itself is an input,
    // not one of the n certificates processed by section 6.1.
    for (offset, cert) in path[..certificate_count].iter().rev().enumerate() {
        let position = offset + 1;
        let self_issued = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
        let parsed = match parse_policy_extensions(cert) {
            Ok(parsed) => parsed,
            Err(reason) => return Some(reason),
        };
        valid_policy_level = process_certificate_policies(
            parsed.policies.as_ref(),
            valid_policy_level,
            inhibit_any_policy,
            self_issued,
            position,
            certificate_count,
        );

        if explicit_policy == 0 && valid_policy_level.is_none() {
            return Some("an explicit certificate policy is required but not asserted");
        }

        if position < certificate_count {
            if let (Some(nodes), Some(mappings)) = (valid_policy_level.as_mut(), parsed.mappings) {
                apply_policy_mappings(nodes, mappings, policy_mapping);
                if nodes.is_empty() {
                    valid_policy_level = None;
                }
            }

            if !self_issued {
                explicit_policy = explicit_policy.saturating_sub(1);
                policy_mapping = policy_mapping.saturating_sub(1);
                inhibit_any_policy = inhibit_any_policy.saturating_sub(1);
            }
            if let Some(constraints) = parsed.constraints {
                if let Some(skip) = constraints.require_explicit_policy {
                    explicit_policy = explicit_policy.min(skip as usize);
                }
                if let Some(skip) = constraints.inhibit_policy_mapping {
                    policy_mapping = policy_mapping.min(skip as usize);
                }
            }
            if let Some(skip) = parsed.inhibit_any_policy {
                inhibit_any_policy = inhibit_any_policy.min(skip as usize);
            }
        } else {
            explicit_policy = explicit_policy.saturating_sub(1);
            if parsed
                .constraints
                .is_some_and(|constraints| constraints.require_explicit_policy == Some(0))
            {
                explicit_policy = 0;
            }
        }
    }

    (explicit_policy == 0 && valid_policy_level.is_none())
        .then_some("an explicit certificate policy is required but not asserted")
}

fn parse_policy_extensions(cert: &Certificate) -> Result<ParsedPolicyExtensions, &'static str> {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(ParsedPolicyExtensions::default());
    };

    let mut parsed = ParsedPolicyExtensions::default();
    for extension in extensions {
        match extension.extn_id {
            OID_EXT_CERTIFICATE_POLICIES => {
                let policies = CertificatePolicies::from_der(extension.extn_value.as_bytes())
                    .map_err(|_| "certificate policies extension is malformed")?;
                validate_certificate_policies(&policies, extension.critical)?;
                parsed.policies = Some(policies);
            }
            OID_EXT_POLICY_MAPPINGS => {
                let mappings = PolicyMappings::from_der(extension.extn_value.as_bytes())
                    .map_err(|_| "policy mappings extension is malformed")?;
                if mappings.0.is_empty() {
                    return Err("policy mappings extension is malformed");
                }
                let mut groups: HashMap<ObjectIdentifier, HashSet<ObjectIdentifier>> =
                    HashMap::new();
                for mapping in mappings.0 {
                    if mapping.issuer_domain_policy == OID_ANY_POLICY
                        || mapping.subject_domain_policy == OID_ANY_POLICY
                    {
                        return Err("policy mapping to or from anyPolicy is forbidden");
                    }
                    groups
                        .entry(mapping.issuer_domain_policy)
                        .or_default()
                        .insert(mapping.subject_domain_policy);
                }
                parsed.mappings = Some(groups);
            }
            OID_EXT_POLICY_CONSTRAINTS => {
                let constraints = PolicyConstraints::from_der(extension.extn_value.as_bytes())
                    .map_err(|_| "policy constraints extension is malformed")?;
                if constraints.require_explicit_policy.is_none()
                    && constraints.inhibit_policy_mapping.is_none()
                {
                    return Err("policy constraints extension is empty");
                }
                parsed.constraints = Some(constraints);
            }
            OID_EXT_INHIBIT_ANY_POLICY => {
                let skip = InhibitAnyPolicy::from_der(extension.extn_value.as_bytes())
                    .map_err(|_| "inhibit anyPolicy extension is malformed")?;
                parsed.inhibit_any_policy = Some(skip.0);
            }
            _ => {}
        }
    }
    Ok(parsed)
}

fn validate_certificate_policies(
    policies: &CertificatePolicies,
    critical: bool,
) -> Result<(), &'static str> {
    if policies.0.is_empty() {
        return Err("certificate policies extension is malformed");
    }
    let mut seen = HashSet::with_capacity(policies.0.len());
    for policy in &policies.0 {
        if !seen.insert(policy.policy_identifier) {
            return Err("certificate policies extension repeats a policy OID");
        }
        validate_policy_qualifiers(policy, critical)?;
    }
    Ok(())
}

fn validate_policy_qualifiers(
    policy: &PolicyInformation,
    critical: bool,
) -> Result<(), &'static str> {
    let Some(qualifiers) = policy.policy_qualifiers.as_ref() else {
        return Ok(());
    };
    if qualifiers.is_empty() {
        return Err("certificate policy qualifiers are empty");
    }
    for qualifier in qualifiers {
        let Some(value) = qualifier.qualifier.as_ref() else {
            return Err("certificate policy qualifier has no value");
        };
        match qualifier.policy_qualifier_id {
            OID_QT_CPS => {
                value
                    .decode_as::<der::asn1::Ia5String>()
                    .map_err(|_| "certificate policy CPS qualifier is malformed")?;
            }
            OID_QT_USER_NOTICE => validate_user_notice(value)?,
            _ if critical || policy.policy_identifier == OID_ANY_POLICY => {
                return Err("critical certificate policy has an unknown qualifier");
            }
            _ => {}
        }
    }
    Ok(())
}

/// Decode RFC 5280 `UserNotice` directly. x509-cert 0.2.5 models
/// `NoticeReference` with the wrong field types and omits two `DisplayText`
/// alternatives, so its `UserNotice` type cannot validate the wire format.
fn validate_user_notice(value: &der::Any) -> Result<(), &'static str> {
    use der::Reader as _;

    value
        .sequence(|reader| {
            if reader.is_finished() {
                return Ok(());
            }
            if reader.peek_tag()? == Tag::Sequence {
                let notice_reference: der::asn1::AnyRef<'_> = reader.decode()?;
                validate_notice_reference(notice_reference)?;
            }
            if !reader.is_finished() {
                let explicit_text: der::asn1::AnyRef<'_> = reader.decode()?;
                validate_display_text(explicit_text, false)?;
            }
            Ok(())
        })
        .map_err(|_| "certificate policy userNotice qualifier is malformed")
}

fn validate_notice_reference(value: der::asn1::AnyRef<'_>) -> der::Result<()> {
    use der::Reader as _;

    value.sequence(|reader| {
        let organization: der::asn1::AnyRef<'_> = reader.decode()?;
        validate_display_text(organization, true)?;
        let notice_numbers: der::asn1::AnyRef<'_> = reader.decode()?;
        notice_numbers.sequence(|numbers| {
            while !numbers.is_finished() {
                numbers.decode::<der::asn1::IntRef<'_>>()?;
            }
            Ok(())
        })
    })
}

fn validate_display_text(
    value: der::asn1::AnyRef<'_>,
    enforce_200_character_limit: bool,
) -> der::Result<()> {
    let bytes = value.value();
    let character_count = match value.tag() {
        Tag::Ia5String if bytes.iter().all(u8::is_ascii) => Some(bytes.len()),
        Tag::VisibleString if bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) => {
            Some(bytes.len())
        }
        Tag::Utf8String => std::str::from_utf8(bytes)
            .ok()
            .map(|text| text.chars().count()),
        Tag::BmpString
            if bytes.len() % 2 == 0
                && bytes.chunks_exact(2).all(|unit| {
                    !matches!(u16::from_be_bytes([unit[0], unit[1]]), 0xd800..=0xdfff)
                }) =>
        {
            Some(bytes.len() / 2)
        }
        _ => None,
    };
    if character_count
        .is_some_and(|count| count > 0 && (!enforce_200_character_limit || count <= 200))
    {
        Ok(())
    } else {
        Err(value.tag().unexpected_error(None))
    }
}

fn process_certificate_policies(
    policies: Option<&CertificatePolicies>,
    previous: Option<PolicyLevel>,
    inhibit_any_policy: usize,
    self_issued: bool,
    position: usize,
    certificate_count: usize,
) -> Option<PolicyLevel> {
    let policies = policies?;
    let previous = previous?;
    let mut expected_policies = HashSet::with_capacity(previous.len());
    for (valid, expected) in &previous {
        match expected {
            Some(expected) => expected_policies.extend(expected),
            None => {
                expected_policies.insert(*valid);
            }
        }
    }
    let mut current = HashMap::with_capacity(policies.0.len());

    for policy in policies
        .0
        .iter()
        .filter(|policy| policy.policy_identifier != OID_ANY_POLICY)
    {
        let oid = policy.policy_identifier;
        if expected_policies.contains(&oid) || previous.contains_key(&OID_ANY_POLICY) {
            current.entry(oid).or_insert(None);
        }
    }

    let has_any_policy = policies
        .0
        .iter()
        .any(|policy| policy.policy_identifier == OID_ANY_POLICY);
    if has_any_policy && (inhibit_any_policy > 0 || (position < certificate_count && self_issued)) {
        for oid in expected_policies {
            current.entry(oid).or_insert(None);
        }
    }

    (!current.is_empty()).then_some(current)
}

fn apply_policy_mappings(
    nodes: &mut PolicyLevel,
    mappings: HashMap<ObjectIdentifier, HashSet<ObjectIdentifier>>,
    policy_mapping: usize,
) {
    for (issuer, subjects) in mappings {
        if policy_mapping == 0 {
            nodes.remove(&issuer);
        } else if let Some(expected) = nodes.get_mut(&issuer) {
            *expected = Some(subjects);
        } else if nodes.contains_key(&OID_ANY_POLICY) {
            nodes.insert(issuer, Some(subjects));
        }
    }
}

#[cfg(test)]
mod tests;
