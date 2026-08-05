//! CBOR decoder handling both definite and indefinite length items.
//!
//! Used for verification: parsing claims/assertions/signatures regardless of
//! which legacy emitter produced them (indefinite from c2pa-rs, definite from
//! Pipeline B). Hardened against adversarial input (depth/length bounds).

use crate::value::Value;
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
    /// A declared length exceeded the remaining input (DoS guard).
    #[error("declared length {0} exceeds remaining input")]
    LengthOverflow(u64),
    /// Trailing bytes remained after a complete top-level item.
    #[error("trailing bytes after top-level item at offset {0}")]
    Trailing(usize),
}

const MAX_DEPTH: usize = 64;

/// Decode a single top-level CBOR item, rejecting trailing bytes.
pub fn decode(data: &[u8]) -> Result<Value, DecodeError> {
    let mut p = Parser { data, pos: 0 };
    let v = p.item(0)?;
    if p.pos != data.len() {
        return Err(DecodeError::Trailing(p.pos));
    }
    Ok(v)
}

/// Decode a single top-level CBOR item from the start of `data`, returning the
/// value and the number of bytes consumed. Trailing bytes are permitted (the
/// caller decides what they mean — e.g. the zero padding C2PA's auxiliary
/// BMFF `merkle` boxes carry after their CBOR payload).
pub fn decode_prefix(data: &[u8]) -> Result<(Value, usize), DecodeError> {
    let mut p = Parser { data, pos: 0 };
    let v = p.item(0)?;
    Ok((v, p.pos))
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
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

    fn item(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::DepthExceeded);
        }
        let head = self.byte()?;
        let mt = head >> 5;
        let ai = head & 0x1f;

        match mt {
            0 => Ok(Value::Integer(self.argument(ai)?.unwrap_or(0) as i128)),
            1 => {
                let n = self.argument(ai)?.unwrap_or(0) as i128;
                Ok(Value::Integer(-1 - n))
            }
            2 => self.byte_string(ai, depth),
            3 => {
                let v = self.byte_string(ai, depth)?;
                match v {
                    Value::Bytes(b) => Ok(Value::Text(
                        String::from_utf8(b).map_err(|_| DecodeError::Unsupported(3, ai))?,
                    )),
                    other => Ok(other),
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

    fn byte_string(&mut self, ai: u8, depth: usize) -> Result<Value, DecodeError> {
        match self.argument(ai)? {
            Some(len) => {
                let bytes = self.take(len as usize)?.to_vec();
                Ok(Value::Bytes(bytes))
            }
            None => {
                // indefinite-length byte string: concatenate chunks until 0xff
                let mut buf = Vec::new();
                loop {
                    if *self.data.get(self.pos).ok_or(DecodeError::Eof(self.pos))? == 0xff {
                        self.pos += 1;
                        break;
                    }
                    if depth > MAX_DEPTH {
                        return Err(DecodeError::DepthExceeded);
                    }
                    match self.item(depth + 1)? {
                        Value::Bytes(b) => buf.extend_from_slice(&b),
                        Value::Text(s) => buf.extend_from_slice(s.as_bytes()),
                        _ => return Err(DecodeError::Unsupported(2, 31)),
                    }
                }
                Ok(Value::Bytes(buf))
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
}
