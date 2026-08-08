//! GIF: JUMBF in an Application Extension block.
//!
//! After the header, logical screen descriptor, and optional global color
//! table, GIF carries a stream of blocks. C2PA stores the manifest store in an
//! Application Extension (`0x21 0xFF 0x0B`) whose 11-byte application identifier
//! is `C2PA_GIF` + a 3-byte auth code; the manifest is split across the
//! extension's data sub-blocks (each at most 255 bytes), terminated by a zero
//! block.
//!
//! Note: the application identifier is an implementation convention; interop
//! with other C2PA GIF tooling should be confirmed against the chosen id.

use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Gif;
const EXTENSION_INTRODUCER: u8 = 0x21;
const APP_EXTENSION_LABEL: u8 = 0xFF;
const IMAGE_SEPARATOR: u8 = 0x2C;
const TRAILER: u8 = 0x3B;
const APP_BLOCK_SIZE: u8 = 0x0B;
/// 11-byte application identifier + auth code.
const APP_ID: &[u8; 11] = b"C2PA_GIF\x01\x00\x00";

fn check_header(data: &[u8]) -> Result<(), FormatError> {
    if data.len() < 13 || (&data[..6] != b"GIF87a" && &data[..6] != b"GIF89a") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing GIF signature",
        });
    }
    Ok(())
}

/// Offset of the first block, after the header, logical screen descriptor, and
/// global color table (if present).
fn first_block_offset(data: &[u8]) -> Result<usize, FormatError> {
    check_header(data)?;
    let packed = data[10];
    let mut off = 13;
    if packed & 0x80 != 0 {
        let gct_size = 3 * (1usize << ((packed & 0x07) + 1));
        off += gct_size;
    }
    if off > data.len() {
        return Err(FormatError::Truncated(FMT));
    }
    Ok(off)
}

/// Skip a chain of data sub-blocks starting at `pos`; returns the offset just
/// past the terminating zero block.
fn skip_subblocks(data: &[u8], mut pos: usize) -> Result<usize, FormatError> {
    loop {
        let len = *data.get(pos).ok_or(FormatError::Truncated(FMT))? as usize;
        pos += 1;
        if len == 0 {
            return Ok(pos);
        }
        pos = pos
            .checked_add(len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
    }
}

/// Collect the concatenated data sub-blocks starting at `pos`; returns the bytes
/// and the offset just past the terminator.
fn read_subblocks(data: &[u8], mut pos: usize) -> Result<(Vec<u8>, usize), FormatError> {
    let mut out = Vec::new();
    loop {
        let len = *data.get(pos).ok_or(FormatError::Truncated(FMT))? as usize;
        pos += 1;
        if len == 0 {
            return Ok((out, pos));
        }
        let end = pos
            .checked_add(len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        out.extend_from_slice(&data[pos..end]);
        pos = end;
    }
}

/// Locate every C2PA Application Extension block, returning `(block_start,
/// block_end, payload)` for each. Normally zero or one; [`strip`] and
/// [`exclusions`] defensively handle more.
fn find_c2pa_extensions(data: &[u8]) -> Result<Vec<(usize, usize, Vec<u8>)>, FormatError> {
    let mut pos = first_block_offset(data)?;
    let mut found = Vec::new();
    while pos < data.len() {
        match data[pos] {
            TRAILER => break,
            IMAGE_SEPARATOR => {
                let packed = *data.get(pos + 9).ok_or(FormatError::Truncated(FMT))?;
                pos += 10;
                if packed & 0x80 != 0 {
                    pos += 3 * (1usize << ((packed & 0x07) + 1));
                }
                pos = pos
                    .checked_add(1)
                    .filter(|&e| e <= data.len())
                    .ok_or(FormatError::Truncated(FMT))?;
                pos = skip_subblocks(data, pos)?;
            }
            EXTENSION_INTRODUCER => {
                let block_start = pos;
                let label = *data.get(pos + 1).ok_or(FormatError::Truncated(FMT))?;
                let sub_start = pos + 2;
                if label == APP_EXTENSION_LABEL {
                    let id_len = *data.get(sub_start).ok_or(FormatError::Truncated(FMT))? as usize;
                    let id_start = sub_start + 1;
                    let id_end = id_start
                        .checked_add(id_len)
                        .filter(|&e| e <= data.len())
                        .ok_or(FormatError::Truncated(FMT))?;
                    if id_len == APP_BLOCK_SIZE as usize && &data[id_start..id_end] == APP_ID {
                        let (payload, block_end) = read_subblocks(data, id_end)?;
                        found.push((block_start, block_end, payload));
                        pos = block_end;
                    } else {
                        pos = skip_subblocks(data, id_end)?;
                    }
                } else {
                    pos = skip_subblocks(data, sub_start)?;
                }
            }
            _ => {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "unexpected GIF block",
                })
            }
        }
    }
    Ok(found)
}

/// Extract the manifest store from the C2PA Application Extension.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(find_c2pa_extensions(data)?
        .into_iter()
        .next()
        .map(|(_, _, payload)| payload))
}

/// Remove every existing C2PA Application Extension block, leaving all other
/// blocks and their order untouched. A no-op when the asset has no manifest.
#[cfg(feature = "test-support")]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    let spans = find_c2pa_extensions(asset)?;
    if spans.is_empty() {
        return Ok(asset.to_vec());
    }
    let mut out = Vec::with_capacity(asset.len());
    let mut cursor = 0usize;
    for (start, end, _) in spans {
        out.extend_from_slice(&asset[cursor..start]);
        cursor = end;
    }
    out.extend_from_slice(&asset[cursor..]);
    Ok(out)
}

#[cfg(feature = "test-support")]
pub(crate) fn build_application_extension(manifest_store: &[u8]) -> Vec<u8> {
    let mut extension = Vec::with_capacity(manifest_store.len() + 32);
    extension.push(EXTENSION_INTRODUCER);
    extension.push(APP_EXTENSION_LABEL);
    extension.push(APP_BLOCK_SIZE);
    extension.extend_from_slice(APP_ID);
    for chunk in manifest_store.chunks(255) {
        extension.push(chunk.len() as u8);
        extension.extend_from_slice(chunk);
    }
    extension.push(0);
    extension
}

/// Insert a C2PA Application Extension after the global color table.
///
/// Any existing C2PA extension(s) are stripped first: prior insertion always
/// landed the new extension first in the block stream, so a first-match
/// reader happened to pick up the fresh manifest, but the stale extension was
/// never actually removed (permanent orphan bytes, and one insertion-point
/// change away from silently flipping to a stale-wins bug).
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let at = first_block_offset(&clean)?;
    let ext = build_application_extension(manifest_store);

    let mut out = Vec::with_capacity(clean.len() + ext.len());
    out.extend_from_slice(&clean[..at]);
    out.extend_from_slice(&ext);
    out.extend_from_slice(&clean[at..]);
    Ok(out)
}

/// The C2PA Application Extension byte span(s) as `c2pa.hash.data`
/// exclusions. Empty if absent.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(find_c2pa_extensions(data)?
        .into_iter()
        .map(|(start, end, _)| DataHashExclusion {
            start,
            length: end - start,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    /// Minimal GIF89a: header + LSD (no GCT) + image + trailer.
    fn tiny_gif() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"GIF89a");
        // LSD: 1x1, packed=0 (no GCT), bg=0, aspect=0.
        v.extend_from_slice(&[1, 0, 1, 0, 0x00, 0x00, 0x00]);
        // Image descriptor: separator, left/top/w/h, packed=0.
        v.push(IMAGE_SEPARATOR);
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
        // LZW min code size + one data sub-block + terminator.
        v.push(0x02);
        v.push(0x02);
        v.extend_from_slice(&[0x44, 0x01]);
        v.push(0x00);
        v.push(TRAILER);
        v
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_gif(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first_store = dummy_manifest_store();
        let second_assertion = c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:0002",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = c2pa_core::jumbf::build_manifest_store(&[second_manifest]);
        assert_ne!(first_store, second_store, "fixture stores must differ");

        let first = embed(&tiny_gif(), &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice())
        );
        assert_eq!(
            find_c2pa_extensions(&second).unwrap().len(),
            1,
            "re-embed must leave exactly one C2PA extension"
        );
    }

    #[test]
    fn roundtrip_multi_subblock() {
        // Force splitting across multiple 255-byte sub-blocks.
        let assertion = c2pa_core::jumbf::assertion_box("c2pa.big", &vec![0x5Au8; 1000], None);
        let manifest =
            c2pa_core::jumbf::build_manifest("urn:c2pa:big", &[assertion], &[0xa0], &[0xd2, 0x84]);
        let store = c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let embedded = embed(&tiny_gif(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_gif()).unwrap(), None);
    }

    #[test]
    fn rejects_non_gif() {
        assert!(matches!(
            extract(b"not a gif file"),
            Err(FormatError::InvalidStructure { .. })
        ));
    }

    #[test]
    fn exclusions_cover_app_extension() {
        let store = dummy_manifest_store();
        let asset = tiny_gif();
        let embedded = embed(&asset, &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        // Span begins at the 0x21 introducer.
        assert_eq!(embedded[start], EXTENSION_INTRODUCER);
        // Deleting the span restores the original asset byte-for-byte.
        let mut rebuilt = embedded[..start].to_vec();
        rebuilt.extend_from_slice(&embedded[start + length..]);
        assert_eq!(rebuilt, asset);
    }

    #[test]
    fn exclusions_cover_multi_subblock_extension() {
        let assertion = c2pa_core::jumbf::assertion_box("c2pa.big", &vec![0x5Au8; 1000], None);
        let manifest =
            c2pa_core::jumbf::build_manifest("urn:c2pa:big", &[assertion], &[0xa0], &[0xd2, 0x84]);
        let store = c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let asset = tiny_gif();
        let embedded = embed(&asset, &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        let mut rebuilt = embedded[..start].to_vec();
        rebuilt.extend_from_slice(&embedded[start + length..]);
        assert_eq!(rebuilt, asset);
    }

    #[test]
    fn exclusions_empty_without_manifest() {
        assert!(exclusions(&tiny_gif()).unwrap().is_empty());
    }
}
