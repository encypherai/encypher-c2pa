// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! SafeTensors (C2PA 2.5 "Embedding manifests into SafeTensors"): an 8-byte
//! little-endian header length, a UTF-8 JSON header, then tensor bytes. The
//! Base64 store is the value of the `c2pa:manifest` key inside the header's
//! `__metadata__` object, and the data-hash exclusion is that value's bytes
//! between the JSON quotes.
//!
//! The header is scanned in place, not deserialized into a map, for two
//! reasons: a map would silently merge duplicate keys, and the clause treats
//! a second `c2pa:manifest` key as no manifest located; and the exclusion
//! must be the exact stored bytes. The scanner validates the whole header as
//! JSON within fixed nesting and size bounds. SafeTensors has no registered
//! media type; see the non-normative aliases in [`crate::c2pa_core::spec`].

use crate::c2pa_formats::util::base64_decode;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::SafeTensors;
const MANIFEST_KEY: &str = "c2pa:manifest";
const METADATA_KEY: &str = "__metadata__";
/// Largest header the reader accepts. The reference implementation caps the
/// header at 100 MB; a store is at most 64 MiB, so its Base64 fits.
const MAX_HEADER_BYTES: usize = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

struct ManifestValue {
    span: std::ops::Range<usize>,
    text: String,
}

struct Scanner<'a> {
    text: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn skip_ws(&mut self) {
        while matches!(self.text.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), FormatError> {
        self.skip_ws();
        if self.text.get(self.pos) == Some(&byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(invalid("malformed JSON header"))
        }
    }

    /// A string: its decoded value and the raw span between the quotes.
    fn string(&mut self) -> Result<(String, (usize, usize)), FormatError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut decoded = String::new();
        loop {
            let byte = *self.text.get(self.pos).ok_or(FormatError::Truncated(FMT))?;
            match byte {
                b'"' => {
                    let span = (start, self.pos);
                    self.pos += 1;
                    return Ok((decoded, span));
                }
                b'\\' => {
                    let escape = *self
                        .text
                        .get(self.pos + 1)
                        .ok_or(FormatError::Truncated(FMT))?;
                    self.pos += 2;
                    let character = match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let unit = self.hex4()?;
                            if (0xd800..0xdc00).contains(&unit) {
                                if self.text.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(invalid("unpaired surrogate in JSON string"));
                                }
                                self.pos += 2;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(invalid("unpaired surrogate in JSON string"));
                                }
                                char::from_u32(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00))
                                    .ok_or(invalid("invalid JSON escape"))?
                            } else {
                                char::from_u32(unit).ok_or(invalid("invalid JSON escape"))?
                            }
                        }
                        _ => return Err(invalid("invalid JSON escape")),
                    };
                    decoded.push(character);
                }
                0x00..=0x1f => return Err(invalid("control character in JSON string")),
                _ => {
                    // The header was validated as UTF-8 up front; decode the
                    // one character starting here without rescanning the rest.
                    let width = match byte {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let encoded = self
                        .text
                        .get(self.pos..self.pos + width)
                        .ok_or(FormatError::Truncated(FMT))?;
                    let character = std::str::from_utf8(encoded)
                        .ok()
                        .and_then(|s| s.chars().next())
                        .ok_or(invalid("JSON header is not UTF-8"))?;
                    decoded.push(character);
                    self.pos += width;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, FormatError> {
        let digits = self
            .text
            .get(self.pos..self.pos + 4)
            .ok_or(FormatError::Truncated(FMT))?;
        let digits = std::str::from_utf8(digits).map_err(|_| invalid("invalid JSON escape"))?;
        let value = u32::from_str_radix(digits, 16).map_err(|_| invalid("invalid JSON escape"))?;
        self.pos += 4;
        Ok(value)
    }

    /// Skip any JSON value, validating it.
    fn value(&mut self, depth: usize) -> Result<(), FormatError> {
        if depth > MAX_DEPTH {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "JSON nesting exceeds the verifier bound",
            });
        }
        self.skip_ws();
        match self.text.get(self.pos) {
            Some(b'{') => self.object(depth, |_, _, _| Ok(false)).map(|_| ()),
            Some(b'[') => {
                self.pos += 1;
                self.skip_ws();
                if self.text.get(self.pos) == Some(&b']') {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.value(depth + 1)?;
                    self.skip_ws();
                    match self.text.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(());
                        }
                        _ => return Err(invalid("malformed JSON array")),
                    }
                }
            }
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(invalid("malformed JSON value")),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), FormatError> {
        if self.text.get(self.pos..self.pos + word.len()) == Some(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(invalid("malformed JSON literal"))
        }
    }

    fn number(&mut self) -> Result<(), FormatError> {
        let start = self.pos;
        while matches!(
            self.text.get(self.pos),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos += 1;
        }
        let token = std::str::from_utf8(&self.text[start..self.pos])
            .map_err(|_| invalid("malformed JSON number"))?;
        serde_json::from_str::<serde_json::Number>(token)
            .map(|_| ())
            .map_err(|_| invalid("malformed JSON number"))
    }

    /// Walk an object. `member` sees each key and decides whether it consumed
    /// the value itself (`Ok(true)`); otherwise the value is skipped.
    fn object(
        &mut self,
        depth: usize,
        mut member: impl FnMut(&mut Self, &str, usize) -> Result<bool, FormatError>,
    ) -> Result<(), FormatError> {
        self.expect(b'{')?;
        self.skip_ws();
        if self.text.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            let (key, _) = self.string()?;
            self.expect(b':')?;
            if !member(self, &key, depth + 1)? {
                self.value(depth + 1)?;
            }
            self.skip_ws();
            match self.text.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(invalid("malformed JSON object")),
            }
        }
    }
}

/// Every `c2pa:manifest` value in every top-level `__metadata__` object.
fn manifest_values(data: &[u8]) -> Result<Vec<ManifestValue>, FormatError> {
    let header_len = data
        .get(..8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
        .ok_or(FormatError::Truncated(FMT))?;
    let header_len = usize::try_from(header_len)
        .ok()
        .filter(|len| *len <= MAX_HEADER_BYTES)
        .ok_or(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "header length exceeds the verifier bound",
        })?;
    let header_end = 8usize
        .checked_add(header_len)
        .filter(|end| *end <= data.len())
        .ok_or(invalid("header length exceeds the file"))?;
    let header = &data[8..header_end];
    std::str::from_utf8(header).map_err(|_| invalid("JSON header is not UTF-8"))?;
    if header.first() != Some(&b'{') {
        return Err(invalid("JSON header does not start with '{'"));
    }
    let mut scanner = Scanner {
        text: header,
        pos: 0,
    };
    let mut values = Vec::new();
    let mut metadata_objects = 0usize;
    scanner.object(0, |scanner, key, depth| {
        if key != METADATA_KEY {
            return Ok(false);
        }
        metadata_objects += 1;
        scanner.skip_ws();
        if scanner.text.get(scanner.pos) != Some(&b'{') {
            return Err(invalid("__metadata__ is not an object"));
        }
        scanner.object(depth, |scanner, key, _| {
            if key != MANIFEST_KEY {
                return Ok(false);
            }
            scanner.skip_ws();
            let (text, (start, stop)) = scanner.string()?;
            values.push(ManifestValue {
                span: 8 + start..8 + stop,
                text,
            });
            Ok(true)
        })?;
        Ok(true)
    })?;
    // Trailing bytes must be whitespace (the format pads with spaces).
    scanner.skip_ws();
    if scanner.pos != header.len() {
        return Err(invalid("bytes follow the JSON header object"));
    }
    if metadata_objects > 1 {
        // Two `__metadata__` keys: no single object holds the manifest.
        return Ok(Vec::new());
    }
    Ok(values)
}

fn locate(data: &[u8]) -> Result<Option<ManifestValue>, FormatError> {
    let mut values = manifest_values(data)?;
    Ok(if values.len() == 1 {
        values.pop()
    } else {
        None
    })
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let Some(ManifestValue { text, .. }) = locate(data)? else {
        return Ok(None);
    };
    let bytes = base64_decode(&text).ok_or(invalid("invalid base64 in c2pa:manifest value"))?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate(data)?
        .map(|value| DataHashExclusion {
            start: value.span.start,
            length: value.span.len(),
        })
        .into_iter()
        .collect())
}

#[cfg(test)]
pub(crate) fn sample_asset(header_json: &str) -> Vec<u8> {
    let mut out = (header_json.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(header_json.as_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::util::base64_encode;

    fn header(metadata: &str) -> String {
        format!(
            "{{\"w\":{{\"dtype\":\"F32\",\"shape\":[2,2],\"data_offsets\":[0,16]}},\"__metadata__\":{{{metadata}}}}}"
        )
    }

    #[test]
    fn extracts_and_excludes_the_value_between_quotes() {
        let store = b"safetensors jumbf".to_vec();
        let encoded = base64_encode(&store);
        let asset = sample_asset(&header(&format!(
            "\"format\":\"pt\",\"c2pa:manifest\":\"{encoded}\""
        )));
        assert_eq!(extract(&asset).unwrap(), Some(store));
        let spans = exclusions(&asset).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &asset[spans[0].start..spans[0].start + spans[0].length],
            encoded.as_bytes()
        );
    }

    #[test]
    fn escaped_solidus_decodes_before_base64() {
        // A serializer may write '/' as "\/"; the decoded value is the Base64.
        let store = vec![0xffu8, 0xff, 0xff];
        let encoded = base64_encode(&store);
        assert!(encoded.contains('/'));
        let escaped = encoded.replace('/', "\\/");
        let asset = sample_asset(&header(&format!("\"c2pa:manifest\":\"{escaped}\"")));
        assert_eq!(extract(&asset).unwrap(), Some(store));
    }

    #[test]
    fn duplicate_keys_locate_no_manifest() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&header(&format!(
            "\"c2pa:manifest\":\"{encoded}\",\"c2pa:manifest\":\"{encoded}\""
        )));
        assert_eq!(extract(&asset).unwrap(), None);
        assert!(exclusions(&asset).unwrap().is_empty());
    }

    #[test]
    fn the_key_outside_metadata_is_not_a_carrier() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&format!("{{\"c2pa:manifest\":\"{encoded}\"}}"));
        assert_eq!(extract(&asset).unwrap(), None);
    }

    #[test]
    fn rejects_bad_header_lengths_and_json() {
        let mut too_long = sample_asset(&header(""));
        too_long[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(extract(&too_long).is_err());
        let mut past_end = sample_asset(&header(""));
        let declared = (past_end.len() as u64) * 2;
        past_end[..8].copy_from_slice(&declared.to_le_bytes());
        assert!(extract(&past_end).is_err());
        assert!(extract(&sample_asset("{\"a\":}")).is_err());
        assert!(extract(&sample_asset("{\"a\":1} x")).is_err());
        assert!(extract(&sample_asset(&header("\"c2pa:manifest\":7"))).is_err());
    }
}
