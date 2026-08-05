//! FLAC: JUMBF in an ID3v2 `GEOB` frame prepended to the native FLAC stream.
//!
//! C2PA 2.4 routes FLAC through the common ID3 embedding defined by A.3.4.
//! Legacy native `c2pa` APPLICATION blocks remain readable so existing assets
//! do not regress, but all new writes use ID3v2.3 `GEOB` with MIME type
//! `application/c2pa`.

use crate::util::be_u24;
use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Flac;
const MAGIC: &[u8; 4] = b"fLaC";
const APP_ID: &[u8; 4] = b"c2pa";
const BLOCK_APPLICATION: u8 = 2;
const FLAG_LAST: u8 = 0x80;

fn check_magic(data: &[u8]) -> Result<(), FormatError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing fLaC magic",
        });
    }
    Ok(())
}

/// A parsed metadata block.
struct Block {
    block_type: u8,
    /// Offset of the 4-byte block header.
    header_start: usize,
    /// Offset of the block data.
    data_start: usize,
    /// Length of the block data.
    data_len: usize,
    /// One-past-the-end offset of the block.
    end: usize,
}

/// Walk metadata blocks, invoking `f` for each. Returns the offset of the first
/// audio frame (one past the last metadata block).
fn walk_blocks(data: &[u8], mut f: impl FnMut(&Block)) -> Result<usize, FormatError> {
    check_magic(data)?;
    let mut pos = 4;
    loop {
        if pos + 4 > data.len() {
            return Err(FormatError::Truncated(FMT));
        }
        let header = data[pos];
        let is_last = header & FLAG_LAST != 0;
        let block_type = header & 0x7F;
        let data_len = be_u24(data, pos + 1).ok_or(FormatError::Truncated(FMT))? as usize;
        let data_start = pos + 4;
        let end = data_start
            .checked_add(data_len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        f(&Block {
            block_type,
            header_start: pos,
            data_start,
            data_len,
            end,
        });
        pos = end;
        if is_last {
            break;
        }
    }
    Ok(pos)
}

fn synchsafe_decode(bytes: &[u8]) -> usize {
    (((bytes[0] as usize) & 0x7f) << 21)
        | (((bytes[1] as usize) & 0x7f) << 14)
        | (((bytes[2] as usize) & 0x7f) << 7)
        | ((bytes[3] as usize) & 0x7f)
}

/// Return the offset of the native `fLaC` stream, validating an optional ID3
/// prefix and its v2.4 footer.
fn flac_start(data: &[u8]) -> Result<usize, FormatError> {
    if data.len() >= 3 && &data[..3] == b"ID3" {
        if data.len() < 10 {
            return Err(FormatError::Truncated(FMT));
        }
        let footer_len = usize::from(data[3] == 4 && data[5] & 0x10 != 0) * 10;
        let start = 10usize
            .checked_add(synchsafe_decode(&data[6..10]))
            .and_then(|offset| offset.checked_add(footer_len))
            .filter(|&offset| offset <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        check_magic(&data[start..])?;
        Ok(start)
    } else {
        check_magic(data)?;
        Ok(0)
    }
}

fn extract_native(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let mut found = None;
    walk_blocks(data, |block| {
        if found.is_none()
            && block.block_type == BLOCK_APPLICATION
            && block.data_len >= 4
            && &data[block.data_start..block.data_start + 4] == APP_ID
        {
            found = Some(data[block.data_start + 4..block.end].to_vec());
        }
    })?;
    Ok(found)
}

/// Extract the manifest store from a FLAC asset.
///
/// The normative ID3v2 `GEOB` layout takes precedence. Native FLAC
/// `APPLICATION` blocks are accepted only as a legacy read path.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let start = flac_start(data)?;
    if start != 0 {
        if let Some(store) = crate::id3::extract(data)? {
            return Ok(Some(store));
        }
    }
    extract_native(&data[start..])
}

/// Remove an ID3-hosted C2PA manifest and every legacy native `c2pa`
/// APPLICATION block. A C2PA-bearing ID3 tag is removed as a whole, matching
/// the certified ID3 writer's clean-tag replacement behavior.
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    let start = flac_start(asset)?;
    let id3_has_manifest = start != 0 && crate::id3::extract(asset)?.is_some();
    let native = &asset[start..];

    struct Rec {
        header_start: usize,
        end: usize,
        is_c2pa: bool,
    }
    let mut recs = Vec::new();
    walk_blocks(native, |block| {
        recs.push(Rec {
            header_start: block.header_start,
            end: block.end,
            is_c2pa: block.block_type == BLOCK_APPLICATION
                && block.data_len >= 4
                && &native[block.data_start..block.data_start + 4] == APP_ID,
        });
    })?;
    let native_has_manifest = recs.iter().any(|record| record.is_c2pa);
    if !id3_has_manifest && !native_has_manifest {
        return Ok(asset.to_vec());
    }

    let audio_start = recs.last().map(|record| record.end).unwrap_or(4);
    let mut clean_native = Vec::with_capacity(native.len());
    clean_native.extend_from_slice(MAGIC);
    let mut kept_headers = Vec::new();
    for record in &recs {
        if !record.is_c2pa {
            kept_headers.push(clean_native.len());
            clean_native.extend_from_slice(&native[record.header_start..record.end]);
        }
    }
    clean_native.extend_from_slice(&native[audio_start..]);
    for &position in &kept_headers {
        clean_native[position] &= !FLAG_LAST;
    }
    if let Some(&position) = kept_headers.last() {
        clean_native[position] |= FLAG_LAST;
    }

    if id3_has_manifest {
        return Ok(clean_native);
    }
    let mut out = Vec::with_capacity(start + clean_native.len());
    out.extend_from_slice(&asset[..start]);
    out.extend_from_slice(&clean_native);
    Ok(out)
}

/// Embed according to C2PA 2.4 A.3.4: prepend a clean ID3v2.3 tag containing
/// one `GEOB` frame with MIME type `application/c2pa`.
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    crate::id3::embed(&clean, manifest_store)
}

/// Return the active manifest span. ID3 `GEOB` takes precedence; the native
/// APPLICATION span is returned only for a legacy asset without a C2PA GEOB.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let start = flac_start(data)?;
    if start != 0 {
        let id3 = crate::id3::exclusions(data)?;
        if !id3.is_empty() {
            return Ok(id3);
        }
    }
    let mut native = Vec::new();
    walk_blocks(&data[start..], |block| {
        if block.block_type == BLOCK_APPLICATION
            && block.data_len >= 4
            && &data[start + block.data_start..start + block.data_start + 4] == APP_ID
        {
            native.push(DataHashExclusion {
                start: start + block.header_start,
                length: block.end - block.header_start,
            });
        }
    })?;
    Ok(native)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    /// Minimal FLAC: magic + a STREAMINFO block (last) + a fake audio frame.
    fn tiny_flac() -> Vec<u8> {
        let mut v = Vec::from(*MAGIC);
        // STREAMINFO (type 0), 34 bytes, marked last.
        v.push(FLAG_LAST); // type 0, last
        v.extend_from_slice(&[0, 0, 34]); // length 34
        v.extend_from_slice(&[0u8; 34]);
        // Pretend audio frame sync.
        v.extend_from_slice(&[0xFF, 0xF8, 0x00, 0x00]);
        v
    }

    #[test]
    fn roundtrip_uses_id3_geob() {
        let store = dummy_manifest_store();
        let source = tiny_flac();
        let embedded = embed(&source, &store).unwrap();
        assert_eq!(&embedded[..3], b"ID3");
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
        let start = flac_start(&embedded).unwrap();
        assert_eq!(&embedded[start..], source);
        assert_eq!(exclusions(&embedded).unwrap().len(), 1);
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_flac()).unwrap(), None);
    }

    #[test]
    fn rejects_non_flac() {
        assert!(matches!(
            extract(b"RIFF...."),
            Err(FormatError::InvalidStructure { .. })
        ));
    }

    #[test]
    fn id3_prefixed_flac_extracts_via_geob() {
        let store = dummy_manifest_store();
        let id3_wrapped = crate::id3::embed(&tiny_flac(), &store).unwrap();
        assert_eq!(
            extract(&id3_wrapped).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let source = tiny_flac();
        let first = embed(&source, b"FIRST-manifest-store").unwrap();
        let second = embed(&first, b"SECOND-manifest-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECOND-manifest-store"[..])
        );
        assert_eq!(&second[flac_start(&second).unwrap()..], source);
    }

    #[test]
    fn legacy_application_block_is_read_and_migrated() {
        let source = tiny_flac();
        let audio_start = walk_blocks(&source, |_| {}).unwrap();
        let manifest = b"legacy-native-manifest";
        let mut legacy = source[..audio_start].to_vec();
        legacy[4] &= !FLAG_LAST;
        legacy.push(FLAG_LAST | BLOCK_APPLICATION);
        let block_len = (APP_ID.len() + manifest.len()) as u32;
        legacy.extend_from_slice(&block_len.to_be_bytes()[1..]);
        legacy.extend_from_slice(APP_ID);
        legacy.extend_from_slice(manifest);
        legacy.extend_from_slice(&source[audio_start..]);

        assert_eq!(extract(&legacy).unwrap().as_deref(), Some(&manifest[..]));
        let migrated = embed(&legacy, b"new-geob-manifest").unwrap();
        assert_eq!(&migrated[..3], b"ID3");
        assert_eq!(
            extract(&migrated).unwrap().as_deref(),
            Some(&b"new-geob-manifest"[..])
        );
        let native = &migrated[flac_start(&migrated).unwrap()..];
        assert_eq!(extract_native(native).unwrap(), None);
    }
}
