//! PNG: JUMBF carried in a `caBX` chunk.
//!
//! A PNG file is the 8-byte signature followed by a sequence of chunks, each
//! `length(4 BE) | type(4) | data | crc(4)`. C2PA stores the manifest store as
//! the `data` of a single `caBX` chunk, inserted before `IEND`. The CRC covers
//! the type and data fields (ISO 3309 / zlib CRC-32).

use crate::util::be_u32;
#[cfg(feature = "test-support")]
use crate::util::Crc32;
use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Png;
const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const TYPE_CABX: &[u8; 4] = b"caBX";
const TYPE_IEND: &[u8; 4] = b"IEND";

fn check_signature(data: &[u8]) -> Result<(), FormatError> {
    if data.len() < 8 || data[..8] != SIGNATURE {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing PNG signature",
        });
    }
    Ok(())
}

/// A parsed PNG chunk and its byte span.
struct Chunk {
    type_code: [u8; 4],
    /// Offset of the chunk's `length` field.
    start: usize,
    /// Offset of the chunk data.
    data_start: usize,
    /// Length of the chunk data.
    data_len: usize,
    /// One-past-the-end offset (after the CRC).
    end: usize,
}

/// Walk PNG chunks, invoking `f` for each. Stops after `IEND`.
fn walk_chunks(data: &[u8], mut f: impl FnMut(&Chunk)) -> Result<(), FormatError> {
    check_signature(data)?;
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let len = be_u32(data, pos).ok_or(FormatError::Truncated(FMT))? as usize;
        let mut type_code = [0u8; 4];
        type_code.copy_from_slice(&data[pos + 4..pos + 8]);
        let data_start = pos + 8;
        let end = data_start
            .checked_add(len)
            .and_then(|e| e.checked_add(4))
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        f(&Chunk {
            type_code,
            start: pos,
            data_start,
            data_len: len,
            end,
        });
        pos = end;
        if &type_code == TYPE_IEND {
            break;
        }
    }
    Ok(())
}

/// Segment the whole PNG into named spans for `c2pa.hash.boxes` (spec 18.4
/// PNG convention): the 8-byte signature is `PNGh`, every chunk is named by
/// its type code, and the `caBX` chunk carrying the C2PA Manifest Store is
/// named `C2PA` (consecutive `caBX` chunks merge into one span). Trailing
/// bytes after `IEND` extend the final span so coverage stays total.
pub(crate) fn box_spans(data: &[u8]) -> Result<Vec<crate::BoxSpan>, FormatError> {
    check_signature(data)?;
    let mut spans: Vec<crate::BoxSpan> = vec![crate::BoxSpan {
        name: "PNGh".into(),
        start: 0,
        end: 8,
    }];
    walk_chunks(data, |c| {
        let name = if &c.type_code == TYPE_CABX {
            "C2PA".to_string()
        } else {
            String::from_utf8_lossy(&c.type_code).into_owned()
        };
        if name == "C2PA" {
            if let Some(last) = spans.last_mut() {
                if last.name == "C2PA" && last.end == c.start {
                    last.end = c.end;
                    return;
                }
            }
        }
        spans.push(crate::BoxSpan {
            name,
            start: c.start,
            end: c.end,
        });
    })?;
    if let Some(last) = spans.last_mut() {
        if last.end < data.len() && last.name == "IEND" {
            last.end = data.len();
        }
    }
    Ok(spans)
}

/// Extract the `caBX` chunk data.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let mut found = None;
    walk_chunks(data, |c| {
        if &c.type_code == TYPE_CABX && found.is_none() {
            found = Some(data[c.data_start..c.data_start + c.data_len].to_vec());
        }
    })?;
    Ok(found)
}

/// Remove every existing `caBX` chunk, leaving all other chunks and their
/// order untouched. A no-op when the asset has no manifest.
#[cfg(feature = "test-support")]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    check_signature(asset)?;
    let mut out = Vec::with_capacity(asset.len());
    out.extend_from_slice(&asset[..8]);
    let mut cursor = 8;
    walk_chunks(asset, |c| {
        if &c.type_code == TYPE_CABX {
            out.extend_from_slice(&asset[cursor..c.start]);
            cursor = c.end;
        }
    })?;
    out.extend_from_slice(&asset[cursor..]);
    Ok(out)
}

/// Insert a `caBX` chunk carrying `manifest_store` immediately before `IEND`.
///
/// Any `caBX` chunk(s) already present are stripped first, so re-signing an
/// already-signed PNG always leaves exactly one manifest in the container
/// (the fresh one) rather than a stale chunk that silently outranks it on
/// read-back.
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let mut iend_start = None;
    walk_chunks(&clean, |c| {
        if &c.type_code == TYPE_IEND && iend_start.is_none() {
            iend_start = Some(c.start);
        }
    })?;
    let at = iend_start.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "missing IEND chunk",
    })?;

    let chunk = build_chunk(TYPE_CABX, manifest_store);
    let mut out = Vec::with_capacity(clean.len() + chunk.len());
    out.extend_from_slice(&clean[..at]);
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&clean[at..]);
    Ok(out)
}

/// The `caBX` chunk byte span as a single exclusion.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let mut ex = Vec::new();
    walk_chunks(data, |c| {
        if &c.type_code == TYPE_CABX {
            ex.push(DataHashExclusion {
                start: c.start,
                length: c.end - c.start,
            });
        }
    })?;
    Ok(ex)
}

/// Build a PNG chunk: `length | type | data | crc`.
#[cfg(feature = "test-support")]
pub(crate) fn build_cabx_chunk(data: &[u8]) -> Vec<u8> {
    build_chunk(TYPE_CABX, data)
}

#[cfg(feature = "test-support")]
fn build_chunk(type_code: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(type_code);
    out.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(type_code);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    /// Minimal PNG: signature + IHDR + IDAT + IEND, with valid CRCs.
    fn tiny_png() -> Vec<u8> {
        let mut v = Vec::from(SIGNATURE);
        // IHDR: 1x1, 8-bit grayscale.
        let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0];
        v.extend_from_slice(&build_chunk(b"IHDR", &ihdr));
        v.extend_from_slice(&build_chunk(
            b"IDAT",
            &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01],
        ));
        v.extend_from_slice(&build_chunk(b"IEND", &[]));
        v
    }

    fn metadata_png() -> Vec<u8> {
        let mut png = Vec::from(SIGNATURE);
        let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0];
        png.extend_from_slice(&build_chunk(b"IHDR", &ihdr));
        png.extend_from_slice(&build_chunk(b"iCCP", b"Encypher ICC profile"));
        png.extend_from_slice(&build_chunk(b"cICP", &[1, 13, 6, 1]));
        png.extend_from_slice(&build_chunk(b"eXIf", &[0x45; 78]));
        png.extend_from_slice(&build_chunk(
            b"iTXt",
            b"XML:com.adobe.xmp\0\0\0\0\0<x:xmpmeta>rights</x:xmpmeta>",
        ));
        png.extend_from_slice(&build_chunk(b"iDOT", &[0, 0, 0, 4]));
        for payload in [
            &[0x78, 0x9C][..],
            &[0x63, 0x00][..],
            &[0x00, 0x00][..],
            &[0x02, 0x00, 0x01][..],
        ] {
            png.extend_from_slice(&build_chunk(b"IDAT", payload));
        }
        png.extend_from_slice(&build_chunk(b"IEND", &[]));
        png
    }

    fn raw_chunks(data: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
        let mut chunks = Vec::new();
        walk_chunks(data, |chunk| {
            chunks.push((chunk.type_code, data[chunk.start..chunk.end].to_vec()));
        })
        .unwrap();
        chunks
    }

    #[test]
    fn embed_preserves_every_non_cabx_chunk_byte_for_byte() {
        let source = metadata_png();
        let embedded = embed(&source, &dummy_manifest_store()).unwrap();
        let retained: Vec<_> = raw_chunks(&embedded)
            .into_iter()
            .filter(|(kind, _)| kind != TYPE_CABX)
            .collect();

        assert_eq!(retained, raw_chunks(&source));
        assert_eq!(
            retained.iter().filter(|(kind, _)| kind == b"IDAT").count(),
            4,
            "IDAT segmentation must not change"
        );
        for kind in [b"iCCP", b"cICP", b"eXIf", b"iTXt", b"iDOT"] {
            assert!(retained.iter().any(|(found, _)| found == kind));
        }
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of the IEND chunk type "IEND" is 0xAE426082.
        let mut c = Crc32::new();
        c.update(b"IEND");
        assert_eq!(c.finalize(), 0xAE42_6082);
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_png(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn cabx_inserted_before_iend() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_png(), &store).unwrap();
        let mut order = Vec::new();
        walk_chunks(&embedded, |c| order.push(c.type_code)).unwrap();
        let cabx = order.iter().position(|t| t == TYPE_CABX).unwrap();
        let iend = order.iter().position(|t| t == TYPE_IEND).unwrap();
        assert!(cabx < iend);
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first = embed(&tiny_png(), b"FIRST-manifest-store").unwrap();
        let second = embed(&first, b"SECOND-manifest-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECOND-manifest-store"[..])
        );
        let mut cabx_count = 0;
        walk_chunks(&second, |c| {
            if &c.type_code == TYPE_CABX {
                cabx_count += 1;
            }
        })
        .unwrap();
        assert_eq!(cabx_count, 1, "re-embed must leave exactly one caBX chunk");
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_png()).unwrap(), None);
    }

    #[test]
    fn rejects_non_png() {
        assert!(matches!(
            extract(b"\x00\x01\x02\x03\x04\x05\x06\x07"),
            Err(FormatError::InvalidStructure { .. })
        ));
    }
}
