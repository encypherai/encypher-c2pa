//! CBOR decoder handling both definite and indefinite length items.
//!
//! Used for verification: parsing claims/assertions/signatures regardless of
//! which legacy emitter produced them (indefinite from c2pa-rs, definite from
//! Pipeline B). Hardened against adversarial input (depth/length/node bounds).

use crate::c2pa_cbor::value::Value;
use thiserror::Error;

/// Error returned when CBOR bytes cannot be decoded.
#[derive(Debug, Error, PartialEq)]
pub enum DecodeError {
    /// Input ended before a complete item was parsed.
    #[error("unexpected end of input at offset {0}")]
    Eof(usize),
    /// A reserved/unsupported additional-information value was encountered.
    #[error("unsupported additional info {1} for major type {0}")]
    Unsupported(u8, u8),
    /// Nesting exceeded the configured maximum depth (DoS guard).
    #[error("maximum nesting depth exceeded")]
    DepthExceeded,
    /// A CBOR item graph exceeded the decoder-wide allocation budget.
    #[error("maximum decoded value node count exceeded ({0})")]
    NodeLimitExceeded(usize),
    /// A declared length exceeded the remaining input (DoS guard).
    #[error("declared length {0} exceeds remaining input")]
    LengthOverflow(u64),
    /// Trailing bytes remained after a complete top-level item.
    #[error("trailing bytes after top-level item at offset {0}")]
    Trailing(usize),
}

const MAX_DEPTH: usize = 64;
const MAX_VALUE_NODES: usize = 1 << 20;

/// Input accepted by [`decode`].
///
/// Ordinary callers pass a byte slice. Verification code that retains several
/// decoded values can pass `(bytes, &mut remaining_nodes)` so every decode
/// spends from one caller-owned allocation budget.
pub(crate) trait DecodeInput {
    fn decode(self) -> Result<Value, DecodeError>;
}

impl<T> DecodeInput for &T
where
    T: AsRef<[u8]> + ?Sized,
{
    fn decode(self) -> Result<Value, DecodeError> {
        let mut remaining_nodes = MAX_VALUE_NODES;
        decode_bounded(self.as_ref(), &mut remaining_nodes)
    }
}

impl DecodeInput for (&[u8], &mut usize) {
    fn decode(self) -> Result<Value, DecodeError> {
        decode_bounded(self.0, self.1)
    }
}

/// Decode a single top-level CBOR item, rejecting trailing bytes.
pub(crate) fn decode(input: impl DecodeInput) -> Result<Value, DecodeError> {
    DecodeInput::decode(input)
}

fn decode_bounded(data: &[u8], remaining_nodes: &mut usize) -> Result<Value, DecodeError> {
    let node_limit = *remaining_nodes;
    let mut p = Parser {
        data,
        pos: 0,
        remaining_nodes: node_limit,
        node_limit,
    };
    let parsed = p.item(0);
    *remaining_nodes = p.remaining_nodes;
    let v = parsed?;
    if p.pos != data.len() {
        return Err(DecodeError::Trailing(p.pos));
    }
    Ok(v)
}

/// Decode a single top-level CBOR item from the start of `data`, returning the
/// value and the number of bytes consumed. Trailing bytes are permitted (the
/// caller decides what they mean, for example the zero padding C2PA's auxiliary
/// BMFF `merkle` boxes carry after their CBOR payload).
pub fn decode_prefix(data: &[u8]) -> Result<(Value, usize), DecodeError> {
    let mut p = Parser {
        data,
        pos: 0,
        remaining_nodes: MAX_VALUE_NODES,
        node_limit: MAX_VALUE_NODES,
    };
    let v = p.item(0)?;
    Ok((v, p.pos))
}

fn length_to_usize_with_max(len: u64, max: usize) -> Result<usize, DecodeError> {
    let converted = usize::try_from(len).map_err(|_| DecodeError::LengthOverflow(len))?;
    if converted > max {
        return Err(DecodeError::LengthOverflow(len));
    }
    Ok(converted)
}

fn length_to_usize(len: u64) -> Result<usize, DecodeError> {
    length_to_usize_with_max(len, usize::MAX)
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    remaining_nodes: usize,
    node_limit: usize,
}

impl<'a> Parser<'a> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.data.get(self.pos).ok_or(DecodeError::Eof(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DecodeError::LengthOverflow(n as u64))?;
        if end > self.data.len() {
            return Err(DecodeError::LengthOverflow(n as u64));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read the argument for a head byte; returns None for indefinite (ai=31).
    fn argument(&mut self, ai: u8) -> Result<Option<u64>, DecodeError> {
        match ai {
            0..=23 => Ok(Some(ai as u64)),
            24 => Ok(Some(self.byte()? as u64)),
            25 => {
                let b = self.take(2)?;
                Ok(Some(u16::from_be_bytes([b[0], b[1]]) as u64))
            }
            26 => {
                let b = self.take(4)?;
                Ok(Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64))
            }
            27 => {
                let b = self.take(8)?;
                Ok(Some(u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ])))
            }
            31 => Ok(None), // indefinite
            other => Err(DecodeError::Unsupported(0xff, other)),
        }
    }

    fn claim_node(&mut self, depth: usize) -> Result<(), DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::DepthExceeded);
        }
        if self.remaining_nodes == 0 {
            return Err(DecodeError::NodeLimitExceeded(self.node_limit));
        }
        self.remaining_nodes -= 1;
        Ok(())
    }

    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        self.claim_node(depth)?;
        let head = self.byte()?;
        let mt = head >> 5;
        let ai = head & 0x1f;

        match mt {
            0 | 1 => {
                let n = self.argument(ai)?.ok_or(DecodeError::Unsupported(mt, 31))? as i128;
                if mt == 0 {
                    Ok(Value::Integer(n))
                } else {
                    Ok(Value::Integer(-1 - n))
                }
            }
            2 | 3 => {
                let bytes = self.string(ai, depth, mt)?;
                if mt == 2 {
                    Ok(Value::Bytes(bytes))
                } else {
                    Ok(Value::Text(
                        String::from_utf8(bytes).map_err(|_| DecodeError::Unsupported(3, ai))?,
                    ))
                }
            }
            4 => self.array(ai, depth),
            5 => self.map(ai, depth),
            6 => {
                let tag = self.argument(ai)?.ok_or(DecodeError::Unsupported(6, 31))?;
                let inner = self.item(depth + 1)?;
                Ok(Value::Tag(tag, Box::new(inner)))
            }
            7 => self.simple(ai),
            _ => unreachable!("major type is 3 bits"),
        }
    }

    fn string(&mut self, ai: u8, depth: usize, required_major: u8) -> Result<Vec<u8>, DecodeError> {
        match self.argument(ai)? {
            Some(len) => {
                let bytes = self.take(length_to_usize(len)?)?;
                if required_major == 3 {
                    std::str::from_utf8(bytes).map_err(|_| DecodeError::Unsupported(3, ai))?;
                }
                Ok(bytes.to_vec())
            }
            None => {
                let mut buf = Vec::new();
                loop {
                    if *self.data.get(self.pos).ok_or(DecodeError::Eof(self.pos))? == 0xff {
                        self.pos += 1;
                        break;
                    }

                    self.claim_node(depth + 1)?;
                    let head = self.byte()?;
                    let chunk_major = head >> 5;
                    let chunk_ai = head & 0x1f;
                    if chunk_major != required_major || chunk_ai == 31 {
                        return Err(DecodeError::Unsupported(required_major, 31));
                    }
                    let len = self
                        .argument(chunk_ai)?
                        .ok_or(DecodeError::Unsupported(required_major, 31))?;
                    let chunk = self.take(length_to_usize(len)?)?;
                    if required_major == 3 {
                        std::str::from_utf8(chunk).map_err(|_| DecodeError::Unsupported(3, 31))?;
                    }
                    buf.extend_from_slice(chunk);
                }
                Ok(buf)
            }
        }
    }

    fn array(&mut self, ai: u8, depth: usize) -> Result<Value, DecodeError> {
        let mut items = Vec::new();
        match self.argument(ai)? {
            Some(len) => {
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
            }
            None => loop {
                if *self.data.get(self.pos).ok_or(DecodeError::Eof(self.pos))? == 0xff {
                    self.pos += 1;
                    break;
                }
                items.push(self.item(depth + 1)?);
            },
        }
        Ok(Value::Array(items))
    }

    fn map(&mut self, ai: u8, depth: usize) -> Result<Value, DecodeError> {
        let mut entries = Vec::new();
        match self.argument(ai)? {
            Some(len) => {
                for _ in 0..len {
                    let k = self.item(depth + 1)?;
                    let v = self.item(depth + 1)?;
                    entries.push((k, v));
                }
            }
            None => loop {
                if *self.data.get(self.pos).ok_or(DecodeError::Eof(self.pos))? == 0xff {
                    self.pos += 1;
                    break;
                }
                let k = self.item(depth + 1)?;
                let v = self.item(depth + 1)?;
                entries.push((k, v));
            },
        }
        Ok(Value::Map(entries))
    }

    fn simple(&mut self, ai: u8) -> Result<Value, DecodeError> {
        match ai {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Ok(Value::Null), // undefined -> null
            25 => {
                let b = self.take(2)?;
                Ok(Value::Float(half_to_f64(u16::from_be_bytes([b[0], b[1]]))))
            }
            26 => {
                let b = self.take(4)?;
                Ok(Value::Float(
                    f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64
                ))
            }
            27 => {
                let b = self.take(8)?;
                Ok(Value::Float(f64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ])))
            }
            other => Err(DecodeError::Unsupported(7, other)),
        }
    }
}

/// Convert IEEE 754 half-precision (binary16) to f64.
fn half_to_f64(half: u16) -> f64 {
    let sign = (half >> 15) & 1;
    let exp = (half >> 10) & 0x1f;
    let mant = half & 0x3ff;
    let val = if exp == 0 {
        (mant as f64) * 2f64.powi(-24)
    } else if exp == 31 {
        if mant == 0 {
            f64::INFINITY
        } else {
            f64::NAN
        }
    } else {
        (1.0 + (mant as f64) / 1024.0) * 2f64.powi(exp as i32 - 15)
    };
    if sign == 1 {
        -val
    } else {
        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_trailing_bytes() {
        // two integers back to back -> trailing
        assert_eq!(decode(&[0x01, 0x02]), Err(DecodeError::Trailing(1)));
    }

    #[test]
    fn declared_length_conversion_respects_target_width() {
        let wasm32_max = usize::try_from(u32::MAX).unwrap();
        assert_eq!(
            length_to_usize_with_max(u64::from(u32::MAX), wasm32_max),
            Ok(wasm32_max)
        );
        assert_eq!(
            length_to_usize_with_max(1u64 << 32, wasm32_max),
            Err(DecodeError::LengthOverflow(1u64 << 32))
        );
    }

    #[test]
    fn oversized_definite_byte_and_text_lengths_fail_closed() {
        for major_type in [0x5b, 0x7b] {
            let mut encoded = vec![major_type];
            encoded.extend_from_slice(&(1u64 << 32).to_be_bytes());
            assert_eq!(
                decode(&encoded),
                Err(DecodeError::LengthOverflow(1u64 << 32))
            );
        }
    }

    #[test]
    fn rejects_indefinite_integer_and_tag_arguments() {
        assert_eq!(decode(&[0x1f]), Err(DecodeError::Unsupported(0, 31)));
        assert_eq!(decode(&[0x3f]), Err(DecodeError::Unsupported(1, 31)));
        assert_eq!(decode(&[0xdf, 0x00]), Err(DecodeError::Unsupported(6, 31)));
    }

    #[test]
    fn rejects_mixed_and_nested_indefinite_string_chunks() {
        let invalid = [
            &[0x5f, 0x61, b'a', 0xff][..],
            &[0x7f, 0x41, b'a', 0xff],
            &[0x5f, 0x5f, 0x41, b'a', 0xff, 0xff],
            &[0x7f, 0x7f, 0x61, b'a', 0xff, 0xff],
        ];

        for encoded in invalid {
            assert!(decode(encoded).is_err(), "{encoded:02x?} decoded");
        }
    }

    #[test]
    fn concatenates_definite_same_major_indefinite_string_chunks() {
        assert_eq!(
            decode(&[0x5f, 0x42, 0x00, 0x01, 0x41, 0xff, 0xff]),
            Ok(Value::Bytes(vec![0x00, 0x01, 0xff]))
        );
        assert_eq!(
            decode(&[0x7f, 0x62, b'a', b'b', 0x61, b'c', 0xff]),
            Ok(Value::Text("abc".to_owned()))
        );
        assert_eq!(
            decode(&[0x9f, 0x5f, 0x41, 0x01, 0xff, 0x02, 0xff]),
            Ok(Value::Array(vec![
                Value::Bytes(vec![0x01]),
                Value::Integer(2),
            ]))
        );
    }

    #[test]
    fn decodes_indefinite_map() {
        // 0xbf "a"(0x61 0x61) 1(0x01) 0xff
        let v = decode(&[0xbf, 0x61, 0x61, 0x01, 0xff]).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Integer(1)));
    }

    #[test]
    fn depth_guard() {
        // deeply nested indefinite arrays
        let mut data = vec![0x9f; MAX_DEPTH + 5];
        data.extend(std::iter::repeat_n(0xff, MAX_DEPTH + 5));
        assert_eq!(decode(&data), Err(DecodeError::DepthExceeded));
    }

    #[test]
    fn collection_node_guard_rejects_small_token_amplification() {
        let declared = u32::try_from(MAX_VALUE_NODES).unwrap();
        let mut data = Vec::with_capacity(5 + MAX_VALUE_NODES);
        data.push(0x9a);
        data.extend_from_slice(&declared.to_be_bytes());
        data.extend(std::iter::repeat_n(0xf6, MAX_VALUE_NODES));

        assert_eq!(
            decode(&data),
            Err(DecodeError::NodeLimitExceeded(MAX_VALUE_NODES))
        );
    }
    #[test]
    fn caller_owned_node_budget_is_shared_across_decodes() {
        let value = [0x82, 0xf6, 0xf6]; // array plus two nulls = three nodes
        let mut remaining = 5;
        assert!(decode((value.as_slice(), &mut remaining)).is_ok());
        assert_eq!(remaining, 2);
        assert_eq!(
            decode((value.as_slice(), &mut remaining)),
            Err(DecodeError::NodeLimitExceeded(2))
        );
        assert_eq!(remaining, 0);
    }
}
