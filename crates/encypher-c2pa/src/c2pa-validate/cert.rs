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
use der::Decode;
use time::OffsetDateTime;
use x509_cert::Certificate;

/// `id-at-commonName`.
const OID_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// `id-at-organizationName`.
const OID_AT_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

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
        info.common_name = attribute(&cert, OID_AT_COMMON_NAME, true);
        info.issuer = attribute(&cert, OID_AT_ORGANIZATION, false);
        info.cert_serial_number = Some(serial_decimal(
            cert.tbs_certificate.serial_number.as_bytes(),
        ));
    }
    info
}

/// Look up a distinguished-name attribute by OID on the subject (`subject =
/// true`) or issuer (`subject = false`) name.
fn attribute(cert: &Certificate, oid: ObjectIdentifier, subject: bool) -> Option<String> {
    let name = if subject {
        &cert.tbs_certificate.subject
    } else {
        &cert.tbs_certificate.issuer
    };
    for rdn in name.0.iter() {
        for atav in rdn.0.iter() {
            if atav.oid == oid {
                let raw = atav.value.value();
                return Some(String::from_utf8_lossy(raw).into_owned());
            }
        }
    }
    None
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
