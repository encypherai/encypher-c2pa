//! Shared byte-reading helpers and an ISOBMFF box walker.

use crate::{AssetFormat, FormatError};

/// Read a big-endian `u16` at `off`, or `None` if out of bounds.
#[inline]
pub(crate) fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// Read a big-endian 24-bit value at `off`, or `None` if out of bounds.
#[inline]
pub(crate) fn be_u24(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 3)
        .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
}

/// Read a big-endian `u32` at `off`, or `None` if out of bounds.
#[inline]
pub(crate) fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a big-endian `u64` at `off`, or `None` if out of bounds.
#[inline]
pub(crate) fn be_u64(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a little-endian `u32` at `off`, or `None` if out of bounds.
#[inline]
pub(crate) fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One top-level ISOBMFF box: its type and byte span within the buffer.
pub(crate) struct IsoBox {
    /// 4-byte box type code.
    pub box_type: [u8; 4],
    /// Offset of the box header (start of the size field).
    pub start: usize,
    /// Offset of the box's payload (after the size/type/largesize fields).
    pub payload_start: usize,
    /// One-past-the-end offset of the entire box.
    pub end: usize,
}

/// Walk top-level ISOBMFF boxes, invoking `f` for each.
///
/// Handles 32-bit sizes, the 64-bit `largesize` escape (size field == 1) and
/// the to-end-of-file escape (size field == 0). Only box *headers* are read;
/// payloads are referenced by offset, so no payload bytes are copied. Returns a
/// [`FormatError::Truncated`] if a header runs past the end of `data`.
pub(crate) fn walk_iso_boxes(
    data: &[u8],
    format: AssetFormat,
    mut f: impl FnMut(&IsoBox),
) -> Result<(), FormatError> {
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let size32 = be_u32(data, pos).ok_or(FormatError::Truncated(format))? as u64;
        let mut box_type = [0u8; 4];
        box_type.copy_from_slice(&data[pos + 4..pos + 8]);

        let (payload_start, end) = if size32 == 1 {
            let large = be_u64(data, pos + 8).ok_or(FormatError::Truncated(format))?;
            let end = pos
                .checked_add(large as usize)
                .filter(|&e| (large as usize) >= 16 && e <= data.len())
                .ok_or(FormatError::Truncated(format))?;
            (pos + 16, end)
        } else if size32 == 0 {
            // Extends to end of file.
            (pos + 8, data.len())
        } else {
            let end = pos
                .checked_add(size32 as usize)
                .filter(|&e| (size32 as usize) >= 8 && e <= data.len())
                .ok_or(FormatError::Truncated(format))?;
            (pos + 8, end)
        };

        f(&IsoBox {
            box_type,
            start: pos,
            payload_start,
            end,
        });

        if end <= pos {
            // Defensive: a zero-progress box would loop forever.
            break;
        }
        pos = end;
    }
    Ok(())
}

/// Build a 32/64-bit ISOBMFF box header for `box_type` wrapping a payload of
/// `payload_len` bytes (plus an optional fixed prefix already counted in
/// `payload_len`). Returns the header bytes; the caller appends the payload.
pub(crate) fn iso_box_header(box_type: &[u8; 4], payload_len: usize) -> Vec<u8> {
    let total = 8 + payload_len;
    if (total as u64) < (1u64 << 32) {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(&(total as u32).to_be_bytes());
        h.extend_from_slice(box_type);
        h
    } else {
        let mut h = Vec::with_capacity(16);
        h.extend_from_slice(&1u32.to_be_bytes());
        h.extend_from_slice(box_type);
        h.extend_from_slice(&((total + 8) as u64).to_be_bytes());
        h
    }
}

/// Streaming CRC-32 (ISO 3309 / zlib polynomial `0xEDB88320`), table-free.
pub(crate) struct Crc32 {
    value: u32,
}

impl Crc32 {
    /// Create a fresh CRC-32 accumulator.
    pub(crate) fn new() -> Self {
        Crc32 { value: 0xFFFF_FFFF }
    }

    /// Fold `bytes` into the running CRC.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.value ^= b as u32;
            for _ in 0..8 {
                let mask = (self.value & 1).wrapping_neg();
                self.value = (self.value >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    /// Finalize and return the CRC value.
    pub(crate) fn finalize(self) -> u32 {
        self.value ^ 0xFFFF_FFFF
    }
}

/// CRC-32 of a single byte slice.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(bytes);
    c.finalize()
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648) encode with padding.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 0x3F] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 0x3F] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 (RFC 4648) decode. Returns `None` on invalid input.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            return None;
        }
        let pads = chunk.iter().filter(|&&c| c == b'=').count();
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pads < 2 {
            out.push((n >> 8) as u8);
        }
        if pads < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}
