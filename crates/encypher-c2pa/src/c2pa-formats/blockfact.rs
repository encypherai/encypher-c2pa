// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! BlockFact `.facti`/`.facta`/`.factv` (`image/vnd.blockfact.facti`,
//! `audio/vnd.blockfact.facta`, `video/vnd.blockfact.factv`; C2PA 2.5
//! "Embedding manifests into .facti/.facta/.factv"): a 4-byte magic, a
//! big-endian metadata length, JSON metadata whose `media_length` locates the
//! end of the media payload, then a big-endian extension-block count and
//! typed blocks (`type`, big-endian `length`, `data`). The store is the data
//! of the one `C2PA` block, and that data alone is the data-hash exclusion.
//!
//! Magic values come from the BlockFact format specification v2.0 that the
//! C2PA clause cites: `FA 49 41 00` (facti), `FA 41 41 00` (facta) and
//! `FA 56 41 00` (factv). Unknown block types are skipped as the clause
//! requires, and a second `C2PA` block locates no manifest.

use crate::c2pa_formats::util::{be_u16, be_u32};
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::BlockFact;
const MAGICS: [[u8; 4]; 3] = [
    [0xfa, 0x49, 0x41, 0x00],
    [0xfa, 0x41, 0x41, 0x00],
    [0xfa, 0x56, 0x41, 0x00],
];
const C2PA_BLOCK: &[u8; 4] = b"C2PA";
/// Largest JSON metadata the reader decodes.
const MAX_METADATA_BYTES: usize = 1024 * 1024;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// The `C2PA` block data spans. Empty when the file is a version 1 file (no
/// extension blocks).
fn c2pa_blocks(data: &[u8]) -> Result<Vec<(usize, usize)>, FormatError> {
    let magic = data.get(..4).ok_or(FormatError::Truncated(FMT))?;
    if !MAGICS.iter().any(|candidate| candidate == magic) {
        return Err(invalid("unknown BlockFact magic"));
    }
    let metadata_len = be_u32(data, 4).ok_or(FormatError::Truncated(FMT))? as usize;
    if metadata_len > MAX_METADATA_BYTES {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "metadata exceeds the verifier bound",
        });
    }
    let metadata_end = 8usize
        .checked_add(metadata_len)
        .filter(|end| *end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let metadata: serde_json::Value = serde_json::from_slice(&data[8..metadata_end])
        .map_err(|_| invalid("metadata is not JSON"))?;
    let object = metadata
        .as_object()
        .ok_or(invalid("metadata is not a JSON object"))?;
    let version = object
        .get("format_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(invalid("metadata has no integer format_version"))?;
    let lengths: Vec<u64> = ["media_length", "image_length"]
        .iter()
        .filter_map(|key| object.get(*key))
        .map(|value| {
            value
                .as_u64()
                .ok_or(invalid("media length is not an integer"))
        })
        .collect::<Result<_, _>>()?;
    let media_len = match lengths.as_slice() {
        [] => return Err(invalid("metadata has no media_length")),
        [only] => *only,
        [first, second] if first == second => *first,
        _ => return Err(invalid("media_length and image_length disagree")),
    };
    let media_end = usize::try_from(media_len)
        .ok()
        .and_then(|len| metadata_end.checked_add(len))
        .filter(|end| *end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    if version < 2 {
        // Version 1 files end with the media payload; there are no blocks.
        return if media_end == data.len() {
            Ok(Vec::new())
        } else {
            Err(invalid(
                "bytes follow the media payload of a version 1 file",
            ))
        };
    }
    if version > 2 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "format_version is newer than 2",
        });
    }
    let count = be_u16(data, media_end).ok_or(FormatError::Truncated(FMT))?;
    let mut pos = media_end + 2;
    let mut found = Vec::new();
    for _ in 0..count {
        let kind = data.get(pos..pos + 4).ok_or(FormatError::Truncated(FMT))?;
        let len = be_u32(data, pos + 4).ok_or(FormatError::Truncated(FMT))? as usize;
        let start = pos + 8;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        if kind == C2PA_BLOCK {
            found.push((start, end));
        }
        pos = end;
    }
    if pos != data.len() {
        return Err(invalid("bytes follow the last extension block"));
    }
    Ok(found)
}

fn locate(data: &[u8]) -> Result<Option<(usize, usize)>, FormatError> {
    Ok(match c2pa_blocks(data)?.as_slice() {
        [only] => Some(*only),
        _ => None,
    })
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(locate(data)?
        .filter(|(start, end)| end > start)
        .map(|(start, end)| data[start..end].to_vec()))
}

pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate(data)?
        .map(|(start, end)| DataHashExclusion {
            start,
            length: end - start,
        })
        .into_iter()
        .collect())
}

#[cfg(test)]
pub(crate) fn sample_asset(magic: usize, blocks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let media = b"\xff\xd8media-payload\xff\xd9";
    let metadata = format!("{{\"format_version\":2,\"media_length\":{}}}", media.len());
    let mut out = MAGICS[magic].to_vec();
    out.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    out.extend_from_slice(metadata.as_bytes());
    out.extend_from_slice(media);
    out.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    for (kind, body) in blocks {
        out.extend_from_slice(*kind);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_extracts_and_excludes_the_c2pa_block_data() {
        for magic in 0..MAGICS.len() {
            let asset = sample_asset(magic, &[(b"ZKPF", b"proof"), (C2PA_BLOCK, b"store")]);
            assert_eq!(extract(&asset).unwrap().as_deref(), Some(&b"store"[..]));
            let spans = exclusions(&asset).unwrap();
            assert_eq!(spans.len(), 1);
            assert_eq!(
                &asset[spans[0].start..spans[0].start + spans[0].length],
                b"store"
            );
            // The block type and length stay hashed.
            assert_eq!(&asset[spans[0].start - 8..spans[0].start - 4], C2PA_BLOCK);
        }
    }

    #[test]
    fn two_c2pa_blocks_locate_no_manifest() {
        let asset = sample_asset(0, &[(C2PA_BLOCK, b"a"), (C2PA_BLOCK, b"b")]);
        assert_eq!(extract(&asset).unwrap(), None);
        assert!(exclusions(&asset).unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_framing() {
        let asset = sample_asset(1, &[(C2PA_BLOCK, b"store")]);
        assert!(extract(&asset[..asset.len() - 1]).is_err());
        let mut trailing = asset.clone();
        trailing.push(0);
        assert!(extract(&trailing).is_err());
        let mut bad_magic = asset.clone();
        bad_magic[1] = 0x00;
        assert!(extract(&bad_magic).is_err());
    }

    #[test]
    fn disagreeing_lengths_are_rejected() {
        let metadata = b"{\"format_version\":2,\"media_length\":1,\"image_length\":2}";
        let mut asset = MAGICS[0].to_vec();
        asset.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        asset.extend_from_slice(metadata);
        asset.extend_from_slice(b"mm\x00\x00");
        assert!(extract(&asset).is_err());
    }
}
