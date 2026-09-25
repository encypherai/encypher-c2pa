// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

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

use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

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

fn first_image_descriptor(data: &[u8]) -> Result<Option<usize>, FormatError> {
    let mut position = first_block_offset(data)?;
    while position < data.len() {
        match data[position] {
            IMAGE_SEPARATOR => return Ok(Some(position)),
            TRAILER => return Ok(None),
            EXTENSION_INTRODUCER => {
                let label = *data.get(position + 1).ok_or(FormatError::Truncated(FMT))?;
                let subblocks = position + 2;
                if label == APP_EXTENSION_LABEL {
                    let identifier_length =
                        *data.get(subblocks).ok_or(FormatError::Truncated(FMT))? as usize;
                    position = skip_subblocks(
                        data,
                        subblocks
                            .checked_add(1 + identifier_length)
                            .filter(|end| *end <= data.len())
                            .ok_or(FormatError::Truncated(FMT))?,
                    )?;
                } else {
                    position = skip_subblocks(data, subblocks)?;
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
    Ok(None)
}

pub(crate) fn placement_error(data: &[u8]) -> Result<Option<&'static str>, FormatError> {
    let Some(first_image) = first_image_descriptor(data)? else {
        return Ok(None);
    };
    Ok(find_c2pa_extensions(data)?
        .iter()
        .any(|(start, _, _)| *start > first_image)
        .then_some("GIF C2PA Application Extension follows the first image descriptor"))
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
#[cfg(test)]
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

#[cfg(test)]
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
#[cfg(test)]
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

/// A minimal GIF89a (header, LSD without a global color table, one frame,
/// trailer) for tests in other modules of this crate.
#[cfg(test)]
pub(crate) fn sample_asset() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"GIF89a");
    // LSD: 1x1, packed=0 (no GCT), bg=0, aspect=0.
    v.extend_from_slice(&[1, 0, 1, 0, 0x00, 0x00, 0x00]);
    // Image descriptor: separator, left/top/w/h, packed=0.
    v.push(IMAGE_SEPARATOR);
    v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
    // LZW min code size + one data sub-block + terminator.
    v.extend_from_slice(&[0x02, 0x02, 0x44, 0x01, 0x00]);
    v.push(TRAILER);
    v
}

/// Segment a GIF into the named boxes of C2PA 2.4 BoxesHash "GIF-specific
/// Handling": the 6-byte header is `GIF89a`, the Logical Screen Descriptor is
/// `LSD` and absorbs the Global Color Table, an Image Descriptor is `2C` and
/// absorbs the Local Color Table, its Table Based Image Data is `TBID`, an
/// extension block is `<introducer><label>` in upper-case hex (e.g. `21FE`),
/// and the trailer is `3B`. The Application Extension carrying the manifest
/// store is named `C2PA`.
///
/// Every byte is covered: bytes after the trailer become a `c2pa.after` box
/// (BoxesHash "Special handling of multi-part assets"), which an assertion
/// that does not list it rejects as an unknown box rather than leaving the
/// trailing bytes unhashed.
pub(crate) fn box_spans(data: &[u8]) -> Result<Vec<crate::c2pa_formats::BoxSpan>, FormatError> {
    use crate::c2pa_formats::BoxSpan;

    let first_block = first_block_offset(data)?;
    let mut spans = vec![
        BoxSpan::contiguous("GIF89a", 0, 6),
        BoxSpan::contiguous("LSD", 6, first_block),
    ];
    let mut pos = first_block;
    let mut trailer_seen = false;
    while pos < data.len() {
        match data[pos] {
            TRAILER => {
                spans.push(BoxSpan::contiguous("3B", pos, pos + 1));
                pos += 1;
                trailer_seen = true;
                break;
            }
            IMAGE_SEPARATOR => {
                let packed = *data.get(pos + 9).ok_or(FormatError::Truncated(FMT))?;
                let mut descriptor_end = pos + 10;
                if packed & 0x80 != 0 {
                    descriptor_end += 3 * (1usize << ((packed & 0x07) + 1));
                }
                // The LZW minimum code size byte opens the image data.
                let data_start = descriptor_end
                    .checked_add(1)
                    .filter(|&end| end <= data.len())
                    .ok_or(FormatError::Truncated(FMT))?;
                let end = skip_subblocks(data, data_start)?;
                spans.push(BoxSpan::contiguous("2C", pos, descriptor_end));
                spans.push(BoxSpan::contiguous("TBID", descriptor_end, end));
                pos = end;
            }
            EXTENSION_INTRODUCER => {
                let label = *data.get(pos + 1).ok_or(FormatError::Truncated(FMT))?;
                let sub_start = pos + 2;
                let (name, end) = if label == APP_EXTENSION_LABEL {
                    let id_len = *data.get(sub_start).ok_or(FormatError::Truncated(FMT))? as usize;
                    let id_start = sub_start + 1;
                    let id_end = id_start
                        .checked_add(id_len)
                        .filter(|&end| end <= data.len())
                        .ok_or(FormatError::Truncated(FMT))?;
                    let is_c2pa =
                        id_len == APP_BLOCK_SIZE as usize && &data[id_start..id_end] == APP_ID;
                    let name = if is_c2pa {
                        "C2PA".to_string()
                    } else {
                        "21FF".to_string()
                    };
                    (name, skip_subblocks(data, id_end)?)
                } else {
                    (format!("21{label:02X}"), skip_subblocks(data, sub_start)?)
                };
                spans.push(BoxSpan::contiguous(name, pos, end));
                pos = end;
            }
            _ => {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "unexpected GIF block",
                })
            }
        }
    }
    if !trailer_seen {
        return Err(FormatError::Truncated(FMT));
    }
    if pos < data.len() {
        spans.push(BoxSpan::contiguous("c2pa.after", pos, data.len()));
    }
    Ok(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::tests::dummy_manifest_store;

    /// Minimal GIF89a: header + LSD (no GCT) + image + trailer.
    fn tiny_gif() -> Vec<u8> {
        sample_asset()
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_gif(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
        assert_eq!(placement_error(&embedded).unwrap(), None);
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first_store = dummy_manifest_store();
        let second_assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:0002",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = crate::c2pa_core::jumbf::build_manifest_store(&[second_manifest]);
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
        let assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.big", &vec![0x5Au8; 1000], None);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:big",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
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
        let assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.big", &vec![0x5Au8; 1000], None);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:big",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
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
    fn strict_placement_rejects_extension_after_first_image() {
        let mut asset = tiny_gif();
        let extension = build_application_extension(&dummy_manifest_store());
        let trailer = asset.pop().unwrap();
        asset.extend_from_slice(&extension);
        asset.push(trailer);
        assert!(placement_error(&asset).unwrap().is_some());
    }

    #[test]
    fn exclusions_empty_without_manifest() {
        assert!(exclusions(&tiny_gif()).unwrap().is_empty());
    }

    /// A GIF with a Global Color Table, a comment extension, and one frame.
    fn gif_with_extras() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"GIF89a");
        // LSD: 1x1, packed=0x80 (GCT of 2 entries), bg=0, aspect=0.
        v.extend_from_slice(&[1, 0, 1, 0, 0x80, 0x00, 0x00]);
        // Global Color Table: 2 entries of 3 bytes.
        v.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // Comment extension with one sub-block.
        v.extend_from_slice(&[EXTENSION_INTRODUCER, 0xFE, 0x03]);
        v.extend_from_slice(b"hi!");
        v.push(0x00);
        // Image descriptor with no local color table.
        v.push(IMAGE_SEPARATOR);
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
        // LZW min code size + one data sub-block + terminator.
        v.extend_from_slice(&[0x02, 0x02, 0x44, 0x01, 0x00]);
        v.push(TRAILER);
        v
    }

    #[test]
    fn box_spans_name_every_gif_block_per_spec() {
        let asset = gif_with_extras();
        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let spans = box_spans(&embedded).unwrap();
        assert_eq!(
            crate::c2pa_formats::tests::span_names(&spans),
            ["GIF89a", "LSD", "C2PA", "21FE", "2C", "TBID", "3B"],
        );
        crate::c2pa_formats::tests::assert_box_coverage(&spans, embedded.len());
        // The LSD box absorbs the Global Color Table: 7 + 6 bytes.
        assert_eq!(spans[1].byte_len(), 13);
        // The C2PA box is exactly the manifest carrier the data hash excludes.
        let carrier = exclusions(&embedded).unwrap();
        assert_eq!(carrier.len(), 1);
        assert_eq!(spans[2].start(), carrier[0].start);
        assert_eq!(spans[2].byte_len(), carrier[0].length);
    }

    #[test]
    fn box_spans_absorb_the_local_color_table_into_the_image_descriptor() {
        let mut asset = Vec::new();
        asset.extend_from_slice(b"GIF89a");
        asset.extend_from_slice(&[1, 0, 1, 0, 0x00, 0x00, 0x00]);
        asset.push(IMAGE_SEPARATOR);
        // packed=0x80: a local color table of 2 entries follows the descriptor.
        asset.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0x80]);
        asset.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        asset.extend_from_slice(&[0x02, 0x02, 0x44, 0x01, 0x00]);
        asset.push(TRAILER);

        let spans = box_spans(&asset).unwrap();
        assert_eq!(
            crate::c2pa_formats::tests::span_names(&spans),
            ["GIF89a", "LSD", "2C", "TBID", "3B"],
        );
        assert_eq!(spans[2].byte_len(), 10 + 6);
        crate::c2pa_formats::tests::assert_box_coverage(&spans, asset.len());
    }

    #[test]
    fn bytes_after_the_trailer_become_an_explicit_after_box() {
        let mut asset = tiny_gif();
        asset.extend_from_slice(b"trailing");
        let spans = box_spans(&asset).unwrap();
        assert_eq!(spans.last().unwrap().name, "c2pa.after");
        crate::c2pa_formats::tests::assert_box_coverage(&spans, asset.len());
    }

    #[test]
    fn a_gif_without_a_trailer_is_not_segmentable() {
        let asset = tiny_gif();
        let truncated = &asset[..asset.len() - 1];
        assert!(matches!(
            box_spans(truncated),
            Err(FormatError::Truncated(FMT))
        ));
    }
}
