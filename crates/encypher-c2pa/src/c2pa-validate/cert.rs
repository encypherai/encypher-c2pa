// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Certificate and COSE header inspection used to populate the validation
//! report's `signature_info` block and to evaluate the signing certificate's
//! validity window.
//!
//! These helpers never panic on malformed input: every accessor returns an
//! `Option` so the verifier can continue producing a result even when a field
//! is missing or undecodable.

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_crypto::CoseAlg;
use const_oid::ObjectIdentifier;
use der::{Decode, Tag, Tagged};
use time::OffsetDateTime;
use x509_cert::{name::Name, Certificate};

/// `id-at-commonName`.
pub(crate) const OID_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `id-at-organizationName`.
pub(crate) const OID_AT_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const MAX_REPORT_NAME_BYTES: usize = 256;

/// Information extracted from the signing certificate and COSE algorithm, used
/// to render the `signature_info` object in the reader report.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    /// Signing algorithm name (`Es256`, `Es384`, `Es512`, `Ps256`, `Ed25519`).
    pub alg: Option<String>,
    /// Leaf certificate Common Name (`CN`).
    pub common_name: Option<String>,
    /// Leaf certificate issuer Organization (`O`).
    pub issuer: Option<String>,
    /// Leaf certificate serial number rendered as a decimal string.
    pub cert_serial_number: Option<String>,
}

/// Extract the COSE signature algorithm from a `COSE_Sign1_Tagged` structure.
///
/// Reads the protected header byte string (`{1: alg}`), decodes it, and maps the
/// integer algorithm identifier to a [`CoseAlg`]. Returns `None` for any
/// structural problem or unsupported algorithm.
pub fn cose_alg(cose_sign1: &[u8]) -> Option<CoseAlg> {
    let value = decode(cose_sign1).ok()?;
    let array = match &value {
        Value::Tag(18, inner) => inner.as_ref(),
        other => other,
    };
    let items = match array {
        Value::Array(items) => items,
        _ => return None,
    };
    let protected = items.first()?.as_bytes()?;
    let header = decode(protected).ok()?;
    let map = header.as_map()?;
    for (k, v) in map {
        if let (Value::Integer(1), Value::Integer(id)) = (k, v) {
            return CoseAlg::from_cose_id(*id);
        }
    }
    None
}

/// The reader-report algorithm name for a [`CoseAlg`], matching the
/// capitalization emitted by the reference pipeline (`Es256`, `Ed25519`, ...).
pub fn alg_name(alg: CoseAlg) -> &'static str {
    match alg {
        CoseAlg::Es256 => "Es256",
        CoseAlg::Es384 => "Es384",
        CoseAlg::Es512 => "Es512",
        CoseAlg::Ps256 => "Ps256",
        CoseAlg::Ps384 => "Ps384",
        CoseAlg::Ps512 => "Ps512",
        CoseAlg::EdDsa => "Ed25519",
    }
}

/// Build the [`SignatureInfo`] for a leaf certificate (DER) and COSE structure.
pub fn signature_info(leaf_der: &[u8], cose_sign1: &[u8]) -> SignatureInfo {
    let mut info = SignatureInfo {
        alg: cose_alg(cose_sign1).map(|a| alg_name(a).to_string()),
        ..SignatureInfo::default()
    };
    if let Ok(cert) = Certificate::from_der(leaf_der) {
        info.common_name = name_attribute(&cert.tbs_certificate.subject, OID_AT_COMMON_NAME);
        info.issuer = name_attribute(&cert.tbs_certificate.issuer, OID_AT_ORGANIZATION);
        info.cert_serial_number = Some(serial_decimal(
            cert.tbs_certificate.serial_number.as_bytes(),
        ));
    }
    info
}

/// Return the first attribute with `oid` in decoded DER RDN/AVA order.
///
/// Report names accept modern RFC 5280 DirectoryString encodings plus IA5String
/// compatibility input. The first matching attribute is terminal: an unusable
/// value is omitted rather than replaced by a later attacker-selected value.
pub(crate) fn name_attribute(name: &Name, oid: ObjectIdentifier) -> Option<String> {
    for rdn in &name.0 {
        for attribute in rdn.0.iter() {
            if attribute.oid != oid {
                continue;
            }
            if !matches!(
                attribute.value.tag(),
                Tag::PrintableString | Tag::Utf8String | Tag::Ia5String
            ) {
                return None;
            }
            let raw = std::str::from_utf8(attribute.value.value()).ok()?;
            let mut sanitized = String::with_capacity(raw.len().min(MAX_REPORT_NAME_BYTES));
            for character in raw
                .chars()
                .filter(|character| !is_display_control(*character))
            {
                if sanitized.len() + character.len_utf8() > MAX_REPORT_NAME_BYTES {
                    return None;
                }
                sanitized.push(character);
            }
            return (!sanitized.is_empty()).then_some(sanitized);
        }
    }
    None
}

fn is_display_control(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{061c}'
            | '\u{200b}'
            | '\u{200e}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// True when the certificate's `notBefore`/`notAfter` window contains `t`.
pub fn valid_at(leaf_der: &[u8], t: OffsetDateTime) -> bool {
    let Ok(cert) = Certificate::from_der(leaf_der) else {
        return false;
    };
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

/// Render a big-endian DER integer (the certificate serial number) as a decimal
/// string, matching Python's `str(cert.serial_number)`.
///
/// The DER sign-guard leading `0x00` byte is harmless here because the value is
/// treated as an unsigned magnitude; a zero serial renders as `"0"`.
fn serial_decimal(be_bytes: &[u8]) -> String {
    // Repeated long division of the base-256 magnitude by 10.
    let mut digits = be_bytes.to_vec();
    // Strip leading zero bytes so an all-zero input still yields "0".
    let start = digits.iter().position(|&b| b != 0).unwrap_or(digits.len());
    digits.drain(..start);
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while !digits.is_empty() {
        let mut remainder: u16 = 0;
        let mut quotient = Vec::with_capacity(digits.len());
        for &byte in digits.iter() {
            let acc = (remainder << 8) | byte as u16;
            quotient.push((acc / 10) as u8);
            remainder = acc % 10;
        }
        // Drop leading zeros of the quotient.
        let q_start = quotient
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(quotient.len());
        digits = quotient[q_start..].to_vec();
        out.push(b'0' + remainder as u8);
    }
    out.reverse();
    String::from_utf8(out).expect("ascii digits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{asn1::SetOfVec, Encode, Tag};
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use x509_cert::{
        attr::AttributeTypeAndValue,
        name::{Name, RdnSequence, RelativeDistinguishedName},
    };

    fn name_attribute_value(
        oid: ObjectIdentifier,
        tag: Tag,
        bytes: impl Into<Box<[u8]>>,
    ) -> AttributeTypeAndValue {
        AttributeTypeAndValue {
            oid,
            value: der::Any::new(tag, bytes).expect("test attribute"),
        }
    }

    fn name(attributes: Vec<AttributeTypeAndValue>) -> Name {
        RdnSequence(
            attributes
                .into_iter()
                .map(|attribute| {
                    RelativeDistinguishedName(
                        SetOfVec::try_from(vec![attribute]).expect("one attribute RDN"),
                    )
                })
                .collect(),
        )
    }

    fn test_certificate() -> Certificate {
        let key = KeyPair::generate().expect("test key");
        let mut params = CertificateParams::new(vec!["subject.example".into()]).expect("params");
        let mut subject = DistinguishedName::new();
        subject.push(DnType::OrganizationName, "Original Issuer");
        subject.push(DnType::CommonName, "Original Subject");
        params.distinguished_name = subject;
        let der = params.self_signed(&key).expect("certificate");
        Certificate::from_der(der.der()).expect("parse certificate")
    }

    fn removed_display_code_points() -> Vec<char> {
        let mut code_points: Vec<char> = (0..=0x1f)
            .chain(0x7f..=0x9f)
            .filter_map(char::from_u32)
            .collect();
        code_points.extend(
            [
                0x061c, 0x200b, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d,
                0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff,
            ]
            .into_iter()
            .filter_map(char::from_u32),
        );
        code_points
    }

    #[test]
    fn name_attribute_strips_each_display_control_and_preserves_scripts() {
        for control in removed_display_code_points() {
            let value = format!("出{control}版");
            let subject = name(vec![name_attribute_value(
                OID_AT_ORGANIZATION,
                Tag::Utf8String,
                value.into_bytes(),
            )]);
            assert_eq!(
                name_attribute(&subject, OID_AT_ORGANIZATION).as_deref(),
                Some("出版"),
                "U+{:04X}",
                control as u32
            );
        }

        let preserved = "出版社\u{200c}\u{200d}";
        let subject = name(vec![name_attribute_value(
            OID_AT_ORGANIZATION,
            Tag::Utf8String,
            preserved.as_bytes().to_vec(),
        )]);
        assert_eq!(
            name_attribute(&subject, OID_AT_ORGANIZATION).as_deref(),
            Some(preserved)
        );
    }

    #[test]
    fn name_attribute_enforces_utf8_byte_boundary_without_truncation() {
        for (value, expected) in [
            ("a".repeat(256), Some("a".repeat(256))),
            ("a".repeat(257), None),
            (
                format!("{}é", "a".repeat(254)),
                Some(format!("{}é", "a".repeat(254))),
            ),
            (format!("{}é", "a".repeat(255)), None),
        ] {
            let subject = name(vec![name_attribute_value(
                OID_AT_ORGANIZATION,
                Tag::Utf8String,
                value.into_bytes(),
            )]);
            assert_eq!(name_attribute(&subject, OID_AT_ORGANIZATION), expected);
        }
    }

    #[test]
    fn unusable_first_attribute_never_falls_through() {
        for first in [vec![0x00], vec![b'x'; 257]] {
            let subject = name(vec![
                name_attribute_value(OID_AT_ORGANIZATION, Tag::Utf8String, first),
                name_attribute_value(
                    OID_AT_ORGANIZATION,
                    Tag::Utf8String,
                    b"Later Organization".to_vec(),
                ),
            ]);
            assert_eq!(name_attribute(&subject, OID_AT_ORGANIZATION), None);
        }
    }

    #[test]
    fn name_attribute_accepts_only_report_string_encodings() {
        for tag in [Tag::BmpString, Tag::TeletexString] {
            let subject = name(vec![name_attribute_value(
                OID_AT_ORGANIZATION,
                tag,
                b"hidden".to_vec(),
            )]);
            assert_eq!(name_attribute(&subject, OID_AT_ORGANIZATION), None);
        }
        let invalid_utf8 = name(vec![name_attribute_value(
            OID_AT_ORGANIZATION,
            Tag::Utf8String,
            vec![0xff],
        )]);
        assert_eq!(name_attribute(&invalid_utf8, OID_AT_ORGANIZATION), None);
        for tag in [Tag::PrintableString, Tag::Ia5String] {
            let subject = name(vec![name_attribute_value(
                OID_AT_ORGANIZATION,
                tag,
                b"Compatible".to_vec(),
            )]);
            assert_eq!(
                name_attribute(&subject, OID_AT_ORGANIZATION).as_deref(),
                Some("Compatible")
            );
        }
    }

    #[test]
    fn signature_info_uses_sanitized_bounded_name_attributes() {
        let mut certificate = test_certificate();
        certificate.tbs_certificate.issuer = name(vec![name_attribute_value(
            OID_AT_ORGANIZATION,
            Tag::Utf8String,
            "Safe\u{202e} Issuer".as_bytes().to_vec(),
        )]);
        let der = certificate.to_der().expect("re-encode certificate");
        assert_eq!(
            signature_info(&der, &[]).issuer.as_deref(),
            Some("Safe Issuer")
        );

        certificate.tbs_certificate.issuer = name(vec![name_attribute_value(
            OID_AT_ORGANIZATION,
            Tag::BmpString,
            vec![0x00, b'B'],
        )]);
        let der = certificate.to_der().expect("re-encode certificate");
        assert_eq!(signature_info(&der, &[]).issuer, None);
    }

    #[test]
    fn serial_decimal_handles_zero_and_sign_guard() {
        assert_eq!(serial_decimal(&[]), "0");
        assert_eq!(serial_decimal(&[0x00]), "0");
        assert_eq!(serial_decimal(&[0x00, 0x01]), "1");
        assert_eq!(serial_decimal(&[0x01, 0x00]), "256");
        // 0xFFFF = 65535
        assert_eq!(serial_decimal(&[0xFF, 0xFF]), "65535");
    }
}
