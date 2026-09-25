// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Test-only RFC 6960 response minting. Compiled out of the published library.
//!
//! [`issuer_signed_response`] produces a complete `OCSPResponse` signed
//! directly by the certificate's issuer, which RFC 6960 4.2.2.2 accepts
//! without a delegated responder certificate. Enough to drive
//! [`super::evaluate_verified`] end to end from the validation crate, which
//! cannot reach `ocsp`'s own test helpers.
//!
//! [`response`] takes the same fixture apart along the axes the online
//! procedure cares about: who signed it, what status it carries, and how fresh
//! its `thisUpdate`/`nextUpdate` window is.

use der::{Decode, Encode};
use rcgen::KeyPair;
use x509_cert::Certificate;

use super::{sha1_digest, tlv, OID_ECDSA_SHA256, OID_PKIX_OCSP_BASIC, OID_SHA1};

/// The certificate status a minted response asserts.
#[derive(Clone, Copy)]
pub(crate) enum FixtureStatus {
    Good,
    /// Revoked at the given `GeneralizedTime`, with reason `keyCompromise`.
    RevokedAt(&'static [u8]),
    /// Revoked at the given `GeneralizedTime`, with reason `removeFromCRL`.
    RemovedFromCrlAt(&'static [u8]),
    /// The responder does not know this certificate.
    Unknown,
}

/// Every axis of a minted response the revocation policies react to.
#[derive(Clone, Copy)]
pub(crate) struct ResponseSpec {
    pub(crate) status: FixtureStatus,
    /// `producedAt`, as a `GeneralizedTime` body.
    pub(crate) produced_at: &'static [u8],
    /// `thisUpdate`, as a `GeneralizedTime` body.
    pub(crate) this_update: &'static [u8],
    /// `nextUpdate`, as a `GeneralizedTime` body. `None` omits the field.
    pub(crate) next_update: Option<&'static [u8]>,
}

impl ResponseSpec {
    /// A window wide enough to contain every fixture signing and verification
    /// instant used by the validation tests.
    pub(crate) fn fresh(status: FixtureStatus) -> Self {
        Self {
            status,
            produced_at: b"20250101000000Z",
            this_update: b"20250101000000Z",
            next_update: Some(b"20300101000000Z"),
        }
    }
}

/// Who signs a minted response, and which certificate travels in `certs`.
pub(crate) struct Responder<'a> {
    /// DER of the certificate whose subject appears as the `ResponderID` and
    /// whose key signs `tbsResponseData`.
    pub(crate) certificate_der: &'a [u8],
    pub(crate) key: &'a KeyPair,
    /// True when `certificate_der` must be carried in the response's `certs`
    /// field, which is the case for anything other than the issuer itself.
    pub(crate) embed_certificate: bool,
}

/// `CertID` over the SHA-1 issuer name and key hashes plus the subject serial.
fn cert_id(issuer: &Certificate, subject: &Certificate) -> Vec<u8> {
    let issuer_name = issuer
        .tbs_certificate
        .subject
        .to_der()
        .expect("issuer name");
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .expect("issuer key");
    let mut body = tlv(0x30, &OID_SHA1.to_der().expect("hash algorithm"));
    body.extend(tlv(0x04, &sha1_digest(&issuer_name)));
    body.extend(tlv(0x04, &sha1_digest(issuer_key)));
    body.extend(tlv(0x02, subject.tbs_certificate.serial_number.as_bytes()));
    tlv(0x30, &body)
}

/// Mint a complete `OCSPResponse` for `subject`, signed by `issuer`.
///
/// `producedAt`, `thisUpdate` and `nextUpdate` are fixed to a window that
/// contains the fixture signing and verification instants used by the
/// validation tests.
pub(crate) fn issuer_signed_response(
    issuer_der: &[u8],
    subject_der: &[u8],
    issuer_key: &KeyPair,
    status: FixtureStatus,
) -> Vec<u8> {
    response(
        issuer_der,
        subject_der,
        &Responder {
            certificate_der: issuer_der,
            key: issuer_key,
            embed_certificate: false,
        },
        ResponseSpec::fresh(status),
    )
}

/// Mint a complete `OCSPResponse` for `subject_der` under `issuer_der`,
/// signed by `responder` and shaped by `spec`.
pub(crate) fn response(
    issuer_der: &[u8],
    subject_der: &[u8],
    responder: &Responder<'_>,
    spec: ResponseSpec,
) -> Vec<u8> {
    let issuer = Certificate::from_der(issuer_der).expect("issuer certificate");
    let subject = Certificate::from_der(subject_der).expect("subject certificate");
    let responder_certificate =
        Certificate::from_der(responder.certificate_der).expect("responder certificate");

    let status = match spec.status {
        FixtureStatus::Good => tlv(0x80, &[]),
        FixtureStatus::RevokedAt(time) => revoked(time, 1),
        FixtureStatus::RemovedFromCrlAt(time) => revoked(time, 8),
        FixtureStatus::Unknown => tlv(0x82, &[]),
    };
    let mut single = cert_id(&issuer, &subject);
    single.extend(status);
    single.extend(tlv(0x18, spec.this_update));
    if let Some(next_update) = spec.next_update {
        single.extend(tlv(0xa0, &tlv(0x18, next_update)));
    }
    let responses = tlv(0x30, &tlv(0x30, &single));

    // byName responder id, matching the signing certificate's own subject.
    let mut response_data = tlv(
        0xa1,
        &responder_certificate
            .tbs_certificate
            .subject
            .to_der()
            .expect("responder name"),
    );
    response_data.extend(tlv(0x18, spec.produced_at));
    response_data.extend(responses);
    let tbs = tlv(0x30, &response_data);

    let signature = {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;
        let key =
            SigningKey::from_pkcs8_der(&responder.key.serialize_der()).expect("load responder key");
        let signature: Signature = key.sign(&tbs);
        signature.to_der().as_bytes().to_vec()
    };

    let mut basic = tbs;
    basic.extend(tlv(
        0x30,
        &OID_ECDSA_SHA256.to_der().expect("signature OID"),
    ));
    let mut signature_bits = vec![0x00];
    signature_bits.extend_from_slice(&signature);
    basic.extend(tlv(0x03, &signature_bits));
    if responder.embed_certificate {
        basic.extend(tlv(
            0xa0,
            &tlv(
                0x30,
                &responder_certificate.to_der().expect("responder der"),
            ),
        ));
    }
    let basic = tlv(0x30, &basic);

    let mut response_bytes = OID_PKIX_OCSP_BASIC.to_der().expect("basic OCSP OID");
    response_bytes.extend(tlv(0x04, &basic));
    let mut response = tlv(0x0a, &[0x00]);
    response.extend(tlv(0xa0, &tlv(0x30, &response_bytes)));
    tlv(0x30, &response)
}

/// `revoked [1] IMPLICIT RevokedInfo` with an explicit `revocationReason`.
fn revoked(time: &[u8], reason: u8) -> Vec<u8> {
    let mut body = tlv(0x18, time);
    body.extend(tlv(0xa0, &tlv(0x0a, &[reason])));
    tlv(0xa1, &body)
}
