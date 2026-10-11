// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Apache Parquet (`application/vnd.apache.parquet`, C2PA 2.5 "Embedding
//! manifests into Parquet"): the Base64 store is the `value` of the one
//! `KeyValue` in the footer's `FileMetaData.key_value_metadata` (field 5)
//! whose `key` is `c2pa:manifest`. The data-hash exclusion is the value's
//! string bytes, not its compact-Thrift length prefix.
//!
//! The footer is read in place with a bounded compact-protocol walker; it is
//! never re-serialized. An encrypted-footer file (`PARE` magic) cannot carry
//! an embedded store by the clause's own note, so it reports no manifest;
//! external-manifest verification still applies to it.

use crate::c2pa_formats::util::{base64_decode, le_u32};
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Parquet;
const KEY_VALUE_METADATA_FIELD: i16 = 5;
const MANIFEST_KEY: &[u8] = b"c2pa:manifest";
const MAX_DEPTH: usize = 64;
/// Upper bound on list, set and map element counts the walker accepts; each
/// element costs at least one byte, so the footer length bounds them anyway.
const MAX_CONTAINER_ELEMENTS: usize = 64 * 1024 * 1024;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, FormatError> {
        if self.pos >= self.end {
            return Err(FormatError::Truncated(FMT));
        }
        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn varint(&mut self) -> Result<u64, FormatError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("varint exceeds ten bytes"))
    }

    fn zigzag_i16(&mut self) -> Result<i16, FormatError> {
        let raw = self.varint()?;
        let value = ((raw >> 1) as i64) ^ -((raw & 1) as i64);
        i16::try_from(value).map_err(|_| invalid("field id out of range"))
    }

    fn skip(&mut self, count: usize) -> Result<(), FormatError> {
        self.pos = self
            .pos
            .checked_add(count)
            .filter(|p| *p <= self.end)
            .ok_or(FormatError::Truncated(FMT))?;
        Ok(())
    }

    /// A binary/string: its byte span.
    fn binary(&mut self) -> Result<(usize, usize), FormatError> {
        let len = usize::try_from(self.varint()?).map_err(|_| FormatError::Truncated(FMT))?;
        let start = self.pos;
        self.skip(len)?;
        Ok((start, self.pos))
    }

    fn element_count(&mut self, header: u8) -> Result<usize, FormatError> {
        let short = usize::from(header >> 4);
        let count = if short == 15 {
            usize::try_from(self.varint()?).map_err(|_| invalid("container too large"))?
        } else {
            short
        };
        if count > MAX_CONTAINER_ELEMENTS {
            return Err(invalid("container too large"));
        }
        Ok(count)
    }

    /// Skip one value of compact type `kind`. In a list, booleans occupy one
    /// byte; as struct fields their value lives in the field header.
    fn skip_value(
        &mut self,
        kind: u8,
        depth: usize,
        in_container: bool,
    ) -> Result<(), FormatError> {
        if depth > MAX_DEPTH {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "Thrift nesting exceeds the verifier bound",
            });
        }
        match kind {
            1 | 2 => {
                if in_container {
                    self.byte()?;
                }
                Ok(())
            }
            3 => self.byte().map(|_| ()),
            4..=6 => self.varint().map(|_| ()),
            7 => self.skip(8),
            8 => self.binary().map(|_| ()),
            9 | 10 => {
                let header = self.byte()?;
                let count = self.element_count(header)?;
                for _ in 0..count {
                    self.skip_value(header & 0x0f, depth + 1, true)?;
                }
                Ok(())
            }
            11 => {
                let count =
                    usize::try_from(self.varint()?).map_err(|_| invalid("container too large"))?;
                if count == 0 {
                    return Ok(());
                }
                if count > MAX_CONTAINER_ELEMENTS {
                    return Err(invalid("container too large"));
                }
                let types = self.byte()?;
                for _ in 0..count {
                    self.skip_value(types >> 4, depth + 1, true)?;
                    self.skip_value(types & 0x0f, depth + 1, true)?;
                }
                Ok(())
            }
            12 => self.walk_struct(depth + 1, |_, _, _, _| Ok(false)),
            _ => Err(invalid("unknown compact-protocol type")),
        }
    }

    /// Walk a struct's fields. `field` sees each id and type and reports
    /// whether it consumed the value.
    fn walk_struct(
        &mut self,
        depth: usize,
        mut field: impl FnMut(&mut Self, i16, u8, usize) -> Result<bool, FormatError>,
    ) -> Result<(), FormatError> {
        let mut last_id: i16 = 0;
        loop {
            let header = self.byte()?;
            if header == 0 {
                return Ok(());
            }
            let kind = header & 0x0f;
            let delta = header >> 4;
            let id = if delta == 0 {
                self.zigzag_i16()?
            } else {
                last_id
                    .checked_add(i16::from(delta))
                    .ok_or(invalid("field id out of range"))?
            };
            last_id = id;
            if !field(self, id, kind, depth)? {
                self.skip_value(kind, depth, false)?;
            }
        }
    }
}

/// Every `c2pa:manifest` value span in the footer's `key_value_metadata`.
fn manifest_values(data: &[u8]) -> Result<Vec<(usize, usize)>, FormatError> {
    if data.len() < 12 || &data[..4] != b"PAR1" {
        return Err(invalid("missing leading PAR1 magic"));
    }
    let tail = &data[data.len() - 4..];
    if tail == b"PARE" {
        // Encrypted footer: no embedded C2PA carrier exists.
        return Ok(Vec::new());
    }
    if tail != b"PAR1" {
        return Err(invalid("missing trailing PAR1 magic"));
    }
    let footer_len = le_u32(data, data.len() - 8).ok_or(FormatError::Truncated(FMT))? as usize;
    let footer_end = data.len() - 8;
    let footer_start = footer_end
        .checked_sub(footer_len)
        .filter(|start| *start >= 4)
        .ok_or(invalid("footer length exceeds the file"))?;
    let mut reader = Reader {
        data,
        pos: footer_start,
        end: footer_end,
    };
    let mut values = Vec::new();
    reader.walk_struct(0, |reader, id, kind, depth| {
        if id != KEY_VALUE_METADATA_FIELD {
            return Ok(false);
        }
        if kind != 9 {
            return Err(invalid("key_value_metadata is not a list"));
        }
        let header = reader.byte()?;
        if header & 0x0f != 12 {
            return Err(invalid("key_value_metadata elements are not structs"));
        }
        let count = reader.element_count(header)?;
        for _ in 0..count {
            let mut key = None;
            let mut value = None;
            reader.walk_struct(depth + 1, |reader, id, kind, _| match (id, kind) {
                (1, 8) => {
                    key = Some(reader.binary()?);
                    Ok(true)
                }
                (2, 8) => {
                    value = Some(reader.binary()?);
                    Ok(true)
                }
                (1 | 2, _) => Err(invalid("KeyValue key or value is not a string")),
                _ => Ok(false),
            })?;
            let key = key.ok_or(invalid("KeyValue without a key"))?;
            if &data[key.0..key.1] == MANIFEST_KEY {
                values.push(value.ok_or(invalid("c2pa:manifest KeyValue without a value"))?);
            }
        }
        Ok(true)
    })?;
    if reader.pos != footer_end {
        return Err(invalid("bytes follow the FileMetaData struct"));
    }
    Ok(values)
}

fn locate(data: &[u8]) -> Result<Option<(usize, usize)>, FormatError> {
    Ok(match manifest_values(data)?.as_slice() {
        [only] => Some(*only),
        _ => None,
    })
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let Some((start, stop)) = locate(data)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&data[start..stop])
        .map_err(|_| invalid("c2pa:manifest value is not UTF-8"))?;
    let bytes = base64_decode(text).ok_or(invalid("invalid base64 in c2pa:manifest value"))?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate(data)?
        .map(|(start, stop)| DataHashExclusion {
            start,
            length: stop - start,
        })
        .into_iter()
        .collect())
}

/// A minimal Parquet file: `PAR1`, a column-chunk stand-in, a compact-Thrift
/// `FileMetaData` with `version`, `num_rows`, the given key/value metadata,
/// and `created_by`, then the footer length and `PAR1`.
#[cfg(test)]
pub(crate) fn sample_asset(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn binary(bytes: &[u8], out: &mut Vec<u8>) {
        varint(bytes.len() as u64, out);
        out.extend_from_slice(bytes);
    }
    let mut footer = Vec::new();
    // field 1 version: i32 (type 5), zigzag(2) = 4.
    footer.push(0x15);
    varint(4, &mut footer);
    // field 3 num_rows: i64 (type 6), delta 2.
    footer.push(0x26);
    varint(20, &mut footer);
    // field 5 key_value_metadata: list (type 9), delta 2.
    footer.push(0x29);
    if entries.len() < 15 {
        footer.push(((entries.len() as u8) << 4) | 12);
    } else {
        footer.push(0xf0 | 12);
        varint(entries.len() as u64, &mut footer);
    }
    for (key, value) in entries {
        footer.push(0x18);
        binary(key, &mut footer);
        footer.push(0x18);
        binary(value, &mut footer);
        footer.push(0x00);
    }
    // field 6 created_by: binary (type 8), delta 1.
    footer.push(0x18);
    binary(b"encypher-test", &mut footer);
    footer.push(0x00);
    let mut out = b"PAR1".to_vec();
    out.extend_from_slice(b"column-chunk-bytes");
    out.extend_from_slice(&footer);
    out.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    out.extend_from_slice(b"PAR1");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::util::base64_encode;

    #[test]
    fn extracts_and_excludes_only_the_value_string_bytes() {
        let store = b"parquet jumbf".to_vec();
        let encoded = base64_encode(&store);
        let asset = sample_asset(&[(b"pandas", b"{}"), (MANIFEST_KEY, encoded.as_bytes())]);
        assert_eq!(extract(&asset).unwrap(), Some(store));
        let spans = exclusions(&asset).unwrap();
        assert_eq!(spans.len(), 1);
        let span = spans[0];
        assert_eq!(
            &asset[span.start..span.start + span.length],
            encoded.as_bytes()
        );
        // The length prefix stays hashed.
        assert_eq!(asset[span.start - 1] as usize, encoded.len());
    }

    #[test]
    fn duplicate_entries_locate_no_manifest() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&[
            (MANIFEST_KEY, encoded.as_bytes()),
            (MANIFEST_KEY, encoded.as_bytes()),
        ]);
        assert_eq!(extract(&asset).unwrap(), None);
    }

    #[test]
    fn encrypted_footer_has_no_embedded_manifest() {
        let mut asset = sample_asset(&[]);
        let len = asset.len();
        asset[len - 4..].copy_from_slice(b"PARE");
        assert_eq!(extract(&asset).unwrap(), None);
    }

    #[test]
    fn rejects_malformed_footers() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&[(MANIFEST_KEY, encoded.as_bytes())]);
        let mut wrong_len = asset.clone();
        let at = wrong_len.len() - 8;
        wrong_len[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract(&wrong_len).is_err());
        let mut no_magic = asset.clone();
        no_magic[0] = b'X';
        assert!(extract(&no_magic).is_err());
        assert!(extract(&sample_asset(&[(MANIFEST_KEY, b"***")])).is_err());
    }
}
