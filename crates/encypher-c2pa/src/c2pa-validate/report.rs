//! JSON report construction matching the reader report SSOT shape.
//!
//! The report mirrors the c2pa-python `Reader` output: an `active_manifest`
//! label, a `manifests` map keyed by label, plus the flat `validation_status`,
//! `validation_results`, and `validation_state` fields. CBOR assertion payloads
//! are converted to JSON with byte strings encoded as standard base64 (matching
//! the reference `_sanitize_for_json`).

use crate::c2pa_cbor::Value;
use serde_json::{Map, Value as Json};

/// Convert a decoded CBOR [`Value`] into a JSON value.
///
/// Byte strings become base64 text; integer/text map keys are stringified.
/// Tagged values are unwrapped to their content. Non-finite floats degrade to
/// `null` (JSON cannot represent them).
pub fn cbor_to_json(value: &Value) -> Json {
    match value {
        Value::Integer(n) => {
            if let Ok(i) = i64::try_from(*n) {
                Json::from(i)
            } else {
                Json::String(n.to_string())
            }
        }
        Value::Bytes(b) => Json::String(base64_encode(b)),
        Value::Text(s) => Json::String(s.clone()),
        Value::Array(items) => Json::Array(items.iter().map(cbor_to_json).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                map.insert(key_to_string(k), cbor_to_json(v));
            }
            Json::Object(map)
        }
        Value::Tag(_, inner) => cbor_to_json(inner),
        Value::Bool(b) => Json::Bool(*b),
        Value::Null => Json::Null,
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
    }
}

/// Render a CBOR map key as a JSON object key.
fn key_to_string(key: &Value) -> String {
    match key {
        Value::Text(s) => s.clone(),
        Value::Integer(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}

/// Standard base64 (RFC 4648) encoder with padding.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn bytes_become_base64_in_json() {
        let v = Value::Map(vec![(
            Value::Text("h".into()),
            Value::Bytes(vec![0xDE, 0xAD]),
        )]);
        let json = cbor_to_json(&v);
        assert_eq!(json["h"], Json::String("3q0=".to_string()));
    }
}
