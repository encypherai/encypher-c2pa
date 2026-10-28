// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! ONNX (C2PA 2.5 "Embedding manifests into ONNX"): the Base64 store is the
//! `value` of the one `StringStringEntryProto` in `ModelProto.metadata_props`
//! (field 14) whose `key` is `c2pa:manifest`. The data-hash exclusion is the
//! value's bytes inside the serialized message, nothing else.
//!
//! The reader walks the protobuf wire format of the file as stored and never
//! re-serializes it, so the offsets it reports are the bytes the signer
//! hashed. ONNX has no registered media type; the reader is reached through
//! the documented non-normative aliases in [`crate::c2pa_core::spec`].

use crate::c2pa_formats::util::base64_decode;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Onnx;
const METADATA_PROPS_FIELD: u64 = 14;
const KEY_FIELD: u64 = 1;
const VALUE_FIELD: u64 = 2;
const MANIFEST_KEY: &[u8] = b"c2pa:manifest";

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

fn read_varint(data: &[u8], pos: &mut usize, end: usize) -> Result<u64, FormatError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        if *pos >= end {
            return Err(FormatError::Truncated(FMT));
        }
        let byte = data[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("varint exceeds ten bytes"))
}

/// One protobuf field: number, and for length-delimited fields the payload
/// span. Other wire types are skipped.
struct Field {
    number: u64,
    payload: Option<(usize, usize)>,
}

fn next_field(data: &[u8], pos: &mut usize, end: usize) -> Result<Field, FormatError> {
    let tag = read_varint(data, pos, end)?;
    let number = tag >> 3;
    if number == 0 {
        return Err(invalid("field number zero"));
    }
    let payload = match tag & 7 {
        0 => {
            read_varint(data, pos, end)?;
            None
        }
        1 => {
            *pos = pos
                .checked_add(8)
                .filter(|p| *p <= end)
                .ok_or(FormatError::Truncated(FMT))?;
            None
        }
        2 => {
            let len = usize::try_from(read_varint(data, pos, end)?)
                .map_err(|_| FormatError::Truncated(FMT))?;
            let start = *pos;
            let stop = start
                .checked_add(len)
                .filter(|p| *p <= end)
                .ok_or(FormatError::Truncated(FMT))?;
            *pos = stop;
            Some((start, stop))
        }
        5 => {
            *pos = pos
                .checked_add(4)
                .filter(|p| *p <= end)
                .ok_or(FormatError::Truncated(FMT))?;
            None
        }
        _ => {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "protobuf group or unknown wire type",
            })
        }
    };
    Ok(Field { number, payload })
}

/// Every `c2pa:manifest` entry's value span. Protobuf merges a repeated
/// scalar by keeping the last occurrence, so the last `key` and last `value`
/// of an entry are the ones a protobuf reader sees.
fn manifest_values(data: &[u8]) -> Result<Vec<(usize, usize)>, FormatError> {
    let mut values = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let field = next_field(data, &mut pos, data.len())?;
        let (Some((start, stop)), METADATA_PROPS_FIELD) = (field.payload, field.number) else {
            if field.number == METADATA_PROPS_FIELD {
                return Err(invalid("metadata_props is not length-delimited"));
            }
            continue;
        };
        let mut key: Option<(usize, usize)> = None;
        let mut value: Option<(usize, usize)> = None;
        let mut inner = start;
        while inner < stop {
            let entry_field = next_field(data, &mut inner, stop)?;
            match (entry_field.number, entry_field.payload) {
                (KEY_FIELD, Some(span)) => key = Some(span),
                (VALUE_FIELD, Some(span)) => value = Some(span),
                (KEY_FIELD | VALUE_FIELD, None) => {
                    return Err(invalid("metadata_props key or value is not a string"))
                }
                _ => {}
            }
        }
        if key.is_some_and(|(s, e)| &data[s..e] == MANIFEST_KEY) {
            // An entry without a value carries the empty string.
            values.push(value.unwrap_or((stop, stop)));
        }
    }
    Ok(values)
}

/// The single value span; several `c2pa:manifest` entries locate no
/// manifest.
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

#[cfg(test)]
pub(crate) fn sample_asset(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn ld(field: u64, payload: &[u8], out: &mut Vec<u8>) {
        varint((field << 3) | 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }
    let mut out = Vec::new();
    // ir_version (field 1, varint) and producer_name (field 2, string).
    varint(1 << 3, &mut out);
    varint(9, &mut out);
    ld(2, b"encypher-test", &mut out);
    for (key, value) in entries {
        let mut entry = Vec::new();
        ld(KEY_FIELD, key, &mut entry);
        ld(VALUE_FIELD, value, &mut entry);
        ld(METADATA_PROPS_FIELD, &entry, &mut out);
    }
    // graph (field 7) after the metadata, so the walker must continue past it.
    ld(7, b"\x0a\x04node", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::util::base64_encode;

    #[test]
    fn extracts_and_excludes_only_the_value_bytes() {
        let store = b"onnx jumbf".to_vec();
        let encoded = base64_encode(&store);
        let asset = sample_asset(&[(b"author", b"x"), (MANIFEST_KEY, encoded.as_bytes())]);
        assert_eq!(extract(&asset).unwrap(), Some(store));
        let spans = exclusions(&asset).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &asset[spans[0].start..spans[0].start + spans[0].length],
            encoded.as_bytes()
        );
    }

    #[test]
    fn duplicate_entries_locate_no_manifest() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&[
            (MANIFEST_KEY, encoded.as_bytes()),
            (MANIFEST_KEY, encoded.as_bytes()),
        ]);
        assert_eq!(extract(&asset).unwrap(), None);
        assert!(exclusions(&asset).unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_protobuf() {
        let encoded = base64_encode(b"x");
        let asset = sample_asset(&[(MANIFEST_KEY, encoded.as_bytes())]);
        assert!(extract(&asset[..asset.len() - 3]).is_err());
        // Group wire type.
        assert!(extract(&[0x0b]).is_err());
        let bad = sample_asset(&[(MANIFEST_KEY, b"***")]);
        assert!(extract(&bad).is_err());
    }

    #[test]
    fn a_model_without_the_key_has_no_manifest() {
        assert_eq!(extract(&sample_asset(&[(b"k", b"v")])).unwrap(), None);
    }
}
