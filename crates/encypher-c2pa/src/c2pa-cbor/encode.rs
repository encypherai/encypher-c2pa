//! CBOR encoder supporting definite and indefinite length per profile.
//!
//! Hand-rolled per RFC 8949 because `ciborium` does not expose control over
//! indefinite-length headers, which Pipeline A (c2pa-rs 0.78.4) emits and which
//! must be reproduced byte-for-byte.

use crate::c2pa_cbor::{canonical_sort, value::Value, Profile};
use thiserror::Error;

/// Error returned when a [`Value`] cannot be encoded.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A float was not representable (NaN/inf handling differs by profile).
    #[error("non-finite float not supported in canonical profile")]
    NonFiniteFloat,
}

const MT_UINT: u8 = 0 << 5;
const MT_NINT: u8 = 1 << 5;
const MT_BYTES: u8 = 2 << 5;
const MT_TEXT: u8 = 3 << 5;
const MT_ARRAY: u8 = 4 << 5;
const MT_MAP: u8 = 5 << 5;
const MT_TAG: u8 = 6 << 5;
const MT_SIMPLE: u8 = 7 << 5;

/// Write the CBOR encoding of `value` into `out`.
pub fn encode_into(out: &mut Vec<u8>, value: &Value, profile: Profile) -> Result<(), EncodeError> {
    match value {
        Value::Integer(n) => {
            encode_int(out, *n);
            Ok(())
        }
        Value::Bytes(b) => {
            // Byte strings: c2pa-rs ciborium emits indefinite-length chunked
            // bstr (0x5f .. 0xff) for streamed values, but claims/assertions use
            // definite bstr. We use definite here; indefinite bstr is only
            // emitted for explicitly streamed payloads, which claims are not.
            write_head(out, MT_BYTES, b.len() as u64);
            out.extend_from_slice(b);
            Ok(())
        }
        Value::Text(s) => {
            write_head(out, MT_TEXT, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
            Ok(())
        }
        Value::Array(items) => {
            if profile.indefinite() {
                out.push(MT_ARRAY | 31); // 0x9f indefinite
                for item in items {
                    encode_into(out, item, profile)?;
                }
                out.push(0xff);
            } else {
                write_head(out, MT_ARRAY, items.len() as u64);
                for item in items {
                    encode_into(out, item, profile)?;
                }
            }
            Ok(())
        }
        Value::Map(entries) => {
            let mut entries = entries.clone();
            if profile.sort_keys() {
                canonical_sort(&mut entries);
            }
            if profile.indefinite() {
                out.push(MT_MAP | 31); // 0xbf indefinite
                for (k, v) in &entries {
                    encode_into(out, k, profile)?;
                    encode_into(out, v, profile)?;
                }
                out.push(0xff);
            } else {
                write_head(out, MT_MAP, entries.len() as u64);
                for (k, v) in &entries {
                    encode_into(out, k, profile)?;
                    encode_into(out, v, profile)?;
                }
            }
            Ok(())
        }
        Value::Tag(tag, inner) => {
            write_head(out, MT_TAG, *tag);
            encode_into(out, inner, profile)
        }
        Value::Bool(b) => {
            out.push(MT_SIMPLE | if *b { 21 } else { 20 });
            Ok(())
        }
        Value::Null => {
            out.push(MT_SIMPLE | 22);
            Ok(())
        }
        Value::Float(f) => {
            if profile.sort_keys() && !f.is_finite() {
                return Err(EncodeError::NonFiniteFloat);
            }
            out.push(MT_SIMPLE | 27); // f64
            out.extend_from_slice(&f.to_bits().to_be_bytes());
            Ok(())
        }
    }
}

fn encode_int(out: &mut Vec<u8>, n: i128) {
    if n >= 0 {
        write_head(out, MT_UINT, n as u64);
    } else {
        // negative: encoded as -1 - n
        let m = (-1 - n) as u64;
        write_head(out, MT_NINT, m);
    }
}

/// Write a CBOR head (major type + argument), shortest-form per RFC 8949.
fn write_head(out: &mut Vec<u8>, mt: u8, arg: u64) {
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}
