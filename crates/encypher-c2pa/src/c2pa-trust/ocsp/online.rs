// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! The request side of OCSP, and the online-response policy.
//!
//! The verification kernel never opens a socket. It builds the RFC 6960
//! `OCSPRequest` a caller (or the SDK's own fetcher) would send, names the
//! responder from the certificate's Authority Information Access extension,
//! and later evaluates whatever DER `OCSPResponse` the caller hands back.
//!
//! The verification lane chooses the online response window. C2PA claim
//! validation keeps the verifier's established inclusive-`thisUpdate` and
//! absent-`nextUpdate` fallback. CAWG Identity 1.3 applies the literal open
//! `(thisUpdate,nextUpdate)` interval and requires `nextUpdate`. Both use a
//! trusted attested time when one exists and the verification time otherwise,
//! and both let a `revoked` response issued after the attested signing time
//! establish "not revoked at signing".

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use time::OffsetDateTime;
use x509_cert::Certificate;

use super::{
    cert_id_matches, sha1_digest, tlv, trim_unsigned, Der, OcspRevocationReason, OcspStatus,
    MAX_OCSP_SINGLE_RESPONSES, OID_SHA1,
};

/// `id-pe-authorityInfoAccess` (RFC 5280 §4.2.2.1).
const OID_EXT_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
/// `id-ad-ocsp` (RFC 5280 §4.2.2.1), the AIA access method naming a responder.
const OID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

/// Longest responder URL accepted from a certificate.
///
/// The URL is echoed into the report and handed to a fetcher, so an absurd
/// value in an attacker-supplied certificate is dropped rather than carried.
const MAX_RESPONDER_URL_BYTES: usize = 2_048;

/// Which specification lane supplies the online OCSP time-window rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnlinePolicy {
    C2paClaim,
    CawgIdentity,
}

/// What an accepted online OCSP response establishes about one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnlineVerdict {
    /// The certificate was not revoked at the time of signing.
    NotRevoked,
    /// The certificate is revoked.
    Revoked,
    /// The responder does not know this certificate.
    Unknown,
    /// A response about this certificate was accepted, but it did not cover
    /// the effective validation instant. A fresh response can help only when
    /// the instant is later than the response window.
    OutsideWindow { refresh_may_cover: bool },
    /// Received bytes were unparseable, unauthorized, or about another
    /// certificate.
    Unusable,
}

/// The OCSP responder URL in `cert_der`'s Authority Information Access
/// extension, if it declares one.
///
/// C2PA 2.4 Validation, "Validate the credential revocation information":
/// "If a certificate does not support revocation status, or the certificate
/// issuer did not provide a method to query its revocation status, the
/// validator shall treat the credential as not revoked." A certificate with no
/// AIA OCSP entry therefore produces no network need at all.
pub(crate) fn responder_url(cert_der: &[u8]) -> Option<String> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    let aia = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_EXT_AUTHORITY_INFO_ACCESS)?;

    let mut descriptions = Der::new(aia.extn_value.as_bytes());
    let list = descriptions.sequence()?;
    let mut list = Der::new(list);
    while !list.is_empty() {
        let description = list.sequence()?;
        let mut description = Der::new(description);
        let method = description.object_identifier()?;
        // `accessLocation` is a GeneralName; only `uniformResourceIdentifier`
        // ([6] IMPLICIT IA5String) names something fetchable.
        let (tag, body) = description.tlv()?;
        if method != OID_AD_OCSP || tag != 0x86 || body.len() > MAX_RESPONDER_URL_BYTES {
            continue;
        }
        let url = std::str::from_utf8(body).ok()?;
        if !url.is_ascii() || url.is_empty() {
            continue;
        }
        return Some(url.to_string());
    }
    None
}

/// Build the DER `OCSPRequest` that asks `issuer_der`'s responder about
/// `subject_der`.
///
/// The `CertID` uses SHA-1 over the issuer name and key, as RFC 6960 §4.1.1
/// and §B.1 specify and as deployed responders require. This is protocol
/// plumbing for certificate identification, not a C2PA content hash, so the
/// C2PA hashing-algorithm rules do not reach it.
///
/// The request is unsigned and carries no nonce: a nonce would force every
/// responder to bypass its cached, pre-signed responses, which large CAs
/// answer with an error, and the response is bound to the certificate by its
/// own `CertID` in any case.
pub(crate) fn build_request(issuer_der: &[u8], subject_der: &[u8]) -> Option<Vec<u8>> {
    let issuer = Certificate::from_der(issuer_der).ok()?;
    let subject = Certificate::from_der(subject_der).ok()?;
    let cert_id = cert_id(&issuer, &subject)?;
    let request_list = tlv(0x30, &tlv(0x30, &cert_id));
    let tbs_request = tlv(0x30, &request_list);
    Some(tlv(0x30, &tbs_request))
}

/// `CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }`.
fn cert_id(issuer: &Certificate, subject: &Certificate) -> Option<Vec<u8>> {
    let issuer_name = issuer.tbs_certificate.subject.to_der().ok()?;
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()?;
    // AlgorithmIdentifier with an explicit NULL parameter: responders that
    // reject the absent-parameters form are common enough that the NULL is the
    // interoperable choice.
    let mut algorithm = OID_SHA1.to_der().ok()?;
    algorithm.extend(tlv(0x05, &[]));

    let mut body = tlv(0x30, &algorithm);
    body.extend(tlv(0x04, &sha1_digest(&issuer_name)));
    body.extend(tlv(0x04, &sha1_digest(issuer_key)));
    body.extend(serial_number(subject));
    Some(tlv(0x30, &body))
}

/// The subject's `serialNumber` re-encoded as a DER INTEGER.
fn serial_number(subject: &Certificate) -> Vec<u8> {
    let raw = subject.tbs_certificate.serial_number.as_bytes();
    let trimmed = trim_unsigned(raw);
    // A DER INTEGER is signed: a leading octet of 0x80 or more needs a zero
    // sign guard, which `x509-cert` has already stripped from `as_bytes`.
    if trimmed.first().is_some_and(|first| *first >= 0x80) {
        let mut guarded = Vec::with_capacity(trimmed.len() + 1);
        guarded.push(0x00);
        guarded.extend_from_slice(trimmed);
        return tlv(0x02, &guarded);
    }
    tlv(0x02, trimmed)
}

/// Evaluate an online OCSP response for `subject_der` under `policy`.
///
/// `attested` is the time from a *valid* time-stamp, or `None` when the
/// signature has none. `verification_time` is the current real-world time (or
/// the caller's fixed validation instant).
pub(crate) fn evaluate(
    der: &[u8],
    issuer_der: &[u8],
    subject_der: &[u8],
    attested: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    policy: OnlinePolicy,
) -> OnlineVerdict {
    let Some(accepted) = super::accept(der, issuer_der, subject_der, verification_time) else {
        return OnlineVerdict::Unusable;
    };
    let Some(verdicts) = single_response_verdicts(
        accepted.responses,
        &accepted.issuer,
        &accepted.subject,
        accepted.produced_at,
        attested,
        verification_time,
        policy,
    ) else {
        return OnlineVerdict::Unusable;
    };
    reduce_verdicts(verdicts)
}

fn reduce_verdicts(verdicts: impl IntoIterator<Item = OnlineVerdict>) -> OnlineVerdict {
    fn rank(verdict: OnlineVerdict) -> u8 {
        match verdict {
            OnlineVerdict::Unusable => 0,
            OnlineVerdict::OutsideWindow { .. } => 1,
            OnlineVerdict::Unknown => 2,
            OnlineVerdict::NotRevoked => 3,
            OnlineVerdict::Revoked => 4,
        }
    }

    let mut best = OnlineVerdict::Unusable;
    let mut refresh_may_cover = false;
    for verdict in verdicts {
        if let OnlineVerdict::OutsideWindow {
            refresh_may_cover: refresh,
        } = verdict
        {
            refresh_may_cover |= refresh;
        }
        if rank(verdict) > rank(best) {
            best = verdict;
        }
    }
    match best {
        OnlineVerdict::OutsideWindow { .. } => OnlineVerdict::OutsideWindow { refresh_may_cover },
        verdict => verdict,
    }
}

/// One verdict per `SingleResponse` whose `CertID` names this certificate.
///
/// `None` means the `responses` field itself is malformed or over budget,
/// which makes the whole response unusable.
fn single_response_verdicts(
    responses: &[u8],
    issuer: &Certificate,
    subject: &Certificate,
    produced_at: OffsetDateTime,
    attested: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    policy: OnlinePolicy,
) -> Option<Vec<OnlineVerdict>> {
    let mut preflight = Der::new(responses);
    let mut response_count = 0usize;
    while !preflight.is_empty() {
        if response_count >= MAX_OCSP_SINGLE_RESPONSES {
            return None;
        }
        preflight.sequence()?;
        response_count += 1;
    }

    let mut verdicts = Vec::new();
    let mut response_list = Der::new(responses);
    while !response_list.is_empty() {
        let single = response_list.sequence()?;
        let mut single = Der::new(single);
        let cert_id = single.sequence()?;
        if !cert_id_matches(cert_id, issuer, subject) {
            continue;
        }
        let status = single.cert_status()?;
        let this_update = single.generalized_time().ok()?;
        let next_update = if single.peek_tag() == Some(0xa0) {
            single
                .tagged(0)
                .and_then(|body| Der::new(body).generalized_time().ok())
        } else {
            None
        };
        verdicts.push(verdict_for(
            status,
            this_update,
            next_update,
            produced_at,
            attested,
            verification_time,
            policy,
        ));
    }
    Some(verdicts)
}

/// Apply the online policy to one accepted `SingleResponse`.
fn verdict_for(
    status: OcspStatus,
    this_update: OffsetDateTime,
    next_update: Option<OffsetDateTime>,
    produced_at: OffsetDateTime,
    attested: Option<OffsetDateTime>,
    verification_time: OffsetDateTime,
    policy: OnlinePolicy,
) -> OnlineVerdict {
    // An `unknown` answer carries no certificate status to be stale about.
    if status == OcspStatus::Unknown {
        return OnlineVerdict::Unknown;
    }

    let effective = attested.unwrap_or(verification_time);
    let (in_window, refresh_may_cover) = match policy {
        OnlinePolicy::C2paClaim => (
            effective >= this_update
                && match next_update {
                    Some(next_update) => effective < next_update,
                    None => produced_at
                        .checked_add(time::Duration::hours(24))
                        .is_some_and(|limit| effective < limit),
                },
            true,
        ),
        OnlinePolicy::CawgIdentity => (
            effective > this_update
                && next_update.is_some_and(|next_update| effective < next_update),
            attested.is_none() || effective > this_update,
        ),
    };

    match status {
        OcspStatus::Good
        | OcspStatus::Revoked {
            reason: Some(OcspRevocationReason::RemoveFromCrl),
            ..
        } => {
            if in_window {
                OnlineVerdict::NotRevoked
            } else {
                match policy {
                    OnlinePolicy::C2paClaim => OnlineVerdict::Unusable,
                    OnlinePolicy::CawgIdentity => {
                        OnlineVerdict::OutsideWindow { refresh_may_cover }
                    }
                }
            }
        }
        OcspStatus::Revoked {
            revocation_time, ..
        } => match attested {
            Some(attested) if in_window && revocation_time > attested => OnlineVerdict::NotRevoked,
            _ => OnlineVerdict::Revoked,
        },
        OcspStatus::Unknown => OnlineVerdict::Unknown,
    }
}

/// The `CertID` contents of a DER `OCSPRequest` carrying exactly one request.
///
/// Test support for asserting that a built request names the certificate a
/// responder would be asked about.
#[cfg(test)]
pub(crate) fn request_cert_id(request: &[u8]) -> Option<Vec<u8>> {
    /// Unwrap one SEQUENCE, requiring it to be the only element present.
    fn only_sequence(bytes: &[u8]) -> Option<&[u8]> {
        let mut cursor = Der::new(bytes);
        let contents = cursor.sequence()?;
        cursor.is_empty().then_some(contents)
    }

    // OCSPRequest -> TBSRequest -> requestList -> Request -> CertID.
    let tbs_request = only_sequence(request)?;
    let request_list = only_sequence(tbs_request)?;
    let single = only_sequence(request_list)?;
    let cert_id = only_sequence(single)?;
    Some(only_sequence(cert_id)?.to_vec())
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use time::macros::datetime;

    use super::super::fixture::{response, FixtureStatus, Responder, ResponseSpec};
    use super::*;

    const NOW: OffsetDateTime = datetime!(2026-06-01 0:00 UTC);
    const SIGNED_AT: OffsetDateTime = datetime!(2026-01-01 0:00 UTC);

    fn ca(common_name: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::new(vec!["ca.example".to_string()]).expect("CA params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2040-01-01 0:00 UTC);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = params.self_signed(&key).expect("self-signed CA");
        (certificate, key)
    }

    /// An `AuthorityInfoAccessSyntax` naming one `id-ad-ocsp` responder URL.
    fn aia_extension(url: &str) -> CustomExtension {
        let mut description = OID_AD_OCSP.to_der().expect("id-ad-ocsp");
        description.extend(tlv(0x86, url.as_bytes()));
        let syntax = tlv(0x30, &tlv(0x30, &description));
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], syntax)
    }

    fn leaf(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
        responder_url: Option<&str>,
    ) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params =
            CertificateParams::new(vec!["signer.example".to_string()]).expect("leaf params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Online OCSP Subject");
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if let Some(url) = responder_url {
            params.custom_extensions.push(aia_extension(url));
        }
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("issued leaf");
        (certificate, key)
    }

    /// An end-entity certificate issued by `issuer` that does NOT carry the
    /// `id-kp-OCSPSigning` EKU, so RFC 6960 4.2.2.2 never authorizes it.
    fn unauthorized_responder(
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
    ) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("responder key");
        let mut params = CertificateParams::new(vec!["responder.example".to_string()])
            .expect("responder params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Unauthorized Responder");
        params.distinguished_name = name;
        params.not_before = datetime!(2025-01-01 0:00 UTC);
        params.not_after = datetime!(2030-01-01 0:00 UTC);
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        let certificate = params
            .signed_by(&key, issuer, issuer_key)
            .expect("issued responder");
        (certificate, key)
    }

    struct Pair {
        issuer_der: Vec<u8>,
        issuer_key: KeyPair,
        subject_der: Vec<u8>,
    }

    fn pair(responder_url: Option<&str>) -> Pair {
        let (issuer, issuer_key) = ca("Online OCSP Issuer");
        let (subject, _) = leaf(&issuer, &issuer_key, responder_url);
        Pair {
            issuer_der: issuer.der().as_ref().to_vec(),
            issuer_key,
            subject_der: subject.der().as_ref().to_vec(),
        }
    }

    impl Pair {
        fn issuer_signed(&self, spec: ResponseSpec) -> Vec<u8> {
            response(
                &self.issuer_der,
                &self.subject_der,
                &Responder {
                    certificate_der: &self.issuer_der,
                    key: &self.issuer_key,
                    embed_certificate: false,
                },
                spec,
            )
        }

        fn evaluate(&self, der: &[u8], attested: Option<OffsetDateTime>) -> OnlineVerdict {
            self.evaluate_with(der, attested, OnlinePolicy::C2paClaim)
        }

        fn evaluate_with(
            &self,
            der: &[u8],
            attested: Option<OffsetDateTime>,
            policy: OnlinePolicy,
        ) -> OnlineVerdict {
            evaluate(
                der,
                &self.issuer_der,
                &self.subject_der,
                attested,
                NOW,
                policy,
            )
        }
    }

    #[test]
    fn the_responder_url_comes_from_the_aia_extension() {
        let with_aia = pair(Some("http://ocsp.example/responder"));
        assert_eq!(
            responder_url(&with_aia.subject_der).as_deref(),
            Some("http://ocsp.example/responder")
        );
        // A certificate whose issuer published no query method produces no
        // need: C2PA 2.4 says to treat that credential as not revoked.
        let without_aia = pair(None);
        assert_eq!(responder_url(&without_aia.subject_der), None);
        assert_eq!(responder_url(&without_aia.issuer_der), None);
    }

    #[test]
    fn the_built_request_identifies_the_subject_under_its_issuer() {
        let mine = pair(Some("http://ocsp.example/responder"));
        let request = build_request(&mine.issuer_der, &mine.subject_der).expect("request");
        let cert_id = request_cert_id(&request).expect("cert id");

        let issuer = Certificate::from_der(&mine.issuer_der).expect("issuer");
        let subject = Certificate::from_der(&mine.subject_der).expect("subject");
        assert!(cert_id_matches(&cert_id, &issuer, &subject));

        // The same request must not identify an unrelated certificate.
        let other = pair(None);
        let other_subject = Certificate::from_der(&other.subject_der).expect("other subject");
        assert!(!cert_id_matches(&cert_id, &issuer, &other_subject));
    }

    #[test]
    fn a_fresh_good_response_establishes_not_revoked() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let good = pair.issuer_signed(ResponseSpec::fresh(FixtureStatus::Good));
        assert_eq!(
            pair.evaluate(&good, Some(SIGNED_AT)),
            OnlineVerdict::NotRevoked
        );
        // With no time-stamp the current time carries the window instead.
        assert_eq!(pair.evaluate(&good, None), OnlineVerdict::NotRevoked);
    }

    #[test]
    fn a_response_whose_window_has_closed_is_no_answer_at_all() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let stale = pair.issuer_signed(ResponseSpec {
            status: FixtureStatus::Good,
            produced_at: b"20250101000000Z",
            this_update: b"20250101000000Z",
            next_update: Some(b"20250102000000Z"),
        });
        // A `good` status the responder no longer stands behind must not be
        // read as a revocation, and must not be read as a clean bill either.
        assert_eq!(
            pair.evaluate(&stale, Some(SIGNED_AT)),
            OnlineVerdict::Unusable
        );
        assert_eq!(pair.evaluate(&stale, None), OnlineVerdict::Unusable);
    }

    #[test]
    fn an_omitted_next_update_bounds_the_window_at_twenty_four_hours() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let open_ended = pair.issuer_signed(ResponseSpec {
            status: FixtureStatus::Good,
            produced_at: b"20251231120000Z",
            this_update: b"20251231120000Z",
            next_update: None,
        });
        // `2026-01-01 00:00` is inside `producedAt + 24h`; `NOW` is not.
        assert_eq!(
            pair.evaluate(&open_ended, Some(SIGNED_AT)),
            OnlineVerdict::NotRevoked
        );
        assert_eq!(pair.evaluate(&open_ended, None), OnlineVerdict::Unusable);
    }

    /// CAWG-ID13-X509VALB-011: CAWG uses the literal open interval and does
    /// not borrow the C2PA claim lane's absent-nextUpdate fallback.
    #[test]
    fn cawg_window_is_open_and_requires_next_update() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let bounded = pair.issuer_signed(ResponseSpec {
            status: FixtureStatus::Good,
            produced_at: b"20260101000000Z",
            this_update: b"20260101000000Z",
            next_update: Some(b"20260201000000Z"),
        });
        assert_eq!(
            pair.evaluate_with(
                &bounded,
                Some(datetime!(2026-01-01 0:00 UTC)),
                OnlinePolicy::CawgIdentity,
            ),
            OnlineVerdict::OutsideWindow {
                refresh_may_cover: false,
            }
        );
        assert_eq!(
            pair.evaluate_with(
                &bounded,
                Some(datetime!(2026-02-01 0:00 UTC)),
                OnlinePolicy::CawgIdentity,
            ),
            OnlineVerdict::OutsideWindow {
                refresh_may_cover: true,
            }
        );

        let unbounded = pair.issuer_signed(ResponseSpec {
            status: FixtureStatus::Good,
            produced_at: b"20251231120000Z",
            this_update: b"20251231120000Z",
            next_update: None,
        });
        assert_eq!(
            pair.evaluate_with(&unbounded, Some(SIGNED_AT), OnlinePolicy::CawgIdentity,),
            OnlineVerdict::OutsideWindow {
                refresh_may_cover: true,
            }
        );
        assert_eq!(
            pair.evaluate_with(
                &unbounded,
                Some(datetime!(2025-12-31 12:00 UTC)),
                OnlinePolicy::CawgIdentity,
            ),
            OnlineVerdict::OutsideWindow {
                refresh_may_cover: false,
            }
        );
    }

    /// CAWG-ID13-X509VALB-006: only an actual revoked status dominates the
    /// matching entries in one BasicOCSPResponse.
    #[test]
    fn multi_response_reduction_does_not_treat_window_miss_as_revocation() {
        assert_eq!(
            reduce_verdicts([
                OnlineVerdict::OutsideWindow {
                    refresh_may_cover: true,
                },
                OnlineVerdict::NotRevoked,
            ]),
            OnlineVerdict::NotRevoked
        );
        assert_eq!(
            reduce_verdicts([OnlineVerdict::NotRevoked, OnlineVerdict::Revoked]),
            OnlineVerdict::Revoked
        );
    }

    #[test]
    fn an_unknown_status_is_reported_as_unknown() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let unknown = pair.issuer_signed(ResponseSpec::fresh(FixtureStatus::Unknown));
        assert_eq!(
            pair.evaluate(&unknown, Some(SIGNED_AT)),
            OnlineVerdict::Unknown
        );
    }

    #[test]
    fn revocation_before_the_attested_signing_time_revokes() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let revoked = pair.issuer_signed(ResponseSpec::fresh(FixtureStatus::RevokedAt(
            b"20250601000000Z",
        )));
        assert_eq!(
            pair.evaluate(&revoked, Some(SIGNED_AT)),
            OnlineVerdict::Revoked
        );
        assert_eq!(pair.evaluate(&revoked, None), OnlineVerdict::Revoked);
    }

    #[test]
    fn revocation_after_the_attested_signing_time_leaves_the_signature_good() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let revoked = pair.issuer_signed(ResponseSpec::fresh(FixtureStatus::RevokedAt(
            b"20260301000000Z",
        )));
        assert_eq!(
            pair.evaluate(&revoked, Some(SIGNED_AT)),
            OnlineVerdict::NotRevoked
        );
        // Without an attested time there is nothing for the revocation to be
        // "after", so the certificate stays revoked.
        assert_eq!(pair.evaluate(&revoked, None), OnlineVerdict::Revoked);
    }

    #[test]
    fn remove_from_crl_is_affirmative_non_revocation() {
        let pair = pair(Some("http://ocsp.example/responder"));
        let removed = pair.issuer_signed(ResponseSpec::fresh(FixtureStatus::RemovedFromCrlAt(
            b"20250601000000Z",
        )));
        assert_eq!(
            pair.evaluate(&removed, Some(SIGNED_AT)),
            OnlineVerdict::NotRevoked
        );
    }

    #[test]
    fn a_response_from_an_unauthorized_responder_is_no_answer() {
        let (issuer, issuer_key) = ca("Online OCSP Issuer");
        let (subject, _) = leaf(&issuer, &issuer_key, Some("http://ocsp.example/responder"));
        let (responder, responder_key) = unauthorized_responder(&issuer, &issuer_key);
        let issuer_der = issuer.der().as_ref().to_vec();
        let subject_der = subject.der().as_ref().to_vec();
        let responder_der = responder.der().as_ref().to_vec();

        let good = response(
            &issuer_der,
            &subject_der,
            &Responder {
                certificate_der: &responder_der,
                key: &responder_key,
                embed_certificate: true,
            },
            ResponseSpec::fresh(FixtureStatus::Good),
        );
        assert_eq!(
            evaluate(
                &good,
                &issuer_der,
                &subject_der,
                Some(SIGNED_AT),
                NOW,
                OnlinePolicy::C2paClaim,
            ),
            OnlineVerdict::Unusable
        );
    }

    #[test]
    fn a_response_about_another_certificate_is_no_answer() {
        let mine = pair(Some("http://ocsp.example/responder"));
        let theirs = pair(Some("http://ocsp.example/responder"));
        let good = theirs.issuer_signed(ResponseSpec::fresh(FixtureStatus::Good));
        assert_eq!(
            evaluate(
                &good,
                &mine.issuer_der,
                &mine.subject_der,
                Some(SIGNED_AT),
                NOW,
                OnlinePolicy::C2paClaim,
            ),
            OnlineVerdict::Unusable
        );
    }

    #[test]
    fn garbage_is_no_answer() {
        let pair = pair(None);
        assert_eq!(
            pair.evaluate(b"not der", Some(SIGNED_AT)),
            OnlineVerdict::Unusable
        );
        assert_eq!(pair.evaluate(&[], None), OnlineVerdict::Unusable);
    }
}
