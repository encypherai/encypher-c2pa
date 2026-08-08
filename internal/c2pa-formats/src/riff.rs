//! RIFF (WAV/AVI/WebP): JUMBF in a `C2PA` chunk.
//!
//! A RIFF file is `RIFF | size(4 LE) | form-type(4)` followed by chunks, each
//! `id(4) | size(4 LE) | data | pad`, padded to an even length. C2PA stores the
//! manifest store as the data of a `C2PA` chunk appended after the existing
//! chunks; the top-level `RIFF` size field is updated accordingly.

use crate::util::le_u32;
use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Riff;
const RIFF: &[u8; 4] = b"RIFF";
const CHUNK_C2PA: &[u8; 4] = b"C2PA";

fn check_riff(data: &[u8]) -> Result<(), FormatError> {
    if data.len() < 12 || &data[..4] != RIFF {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing RIFF header",
        });
    }
    Ok(())
}

/// A parsed RIFF chunk.
struct Chunk {
    id: [u8; 4],
    /// Offset of the chunk header (id field).
    start: usize,
    data_start: usize,
    data_len: usize,
    /// One-past-the-end offset including any pad byte.
    end: usize,
}

/// Walk top-level RIFF chunks (after the 12-byte header).
fn walk_chunks(data: &[u8], mut f: impl FnMut(&Chunk)) -> Result<(), FormatError> {
    check_riff(data)?;
    let mut pos = 12;
    while pos + 8 <= data.len() {
        let mut id = [0u8; 4];
        id.copy_from_slice(&data[pos..pos + 4]);
        let len = le_u32(data, pos + 4).ok_or(FormatError::Truncated(FMT))? as usize;
        let data_start = pos + 8;
        let data_end = data_start
            .checked_add(len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        // RIFF chunks are word-aligned: a pad byte follows odd-length data.
        let end = if len % 2 == 1 && data_end < data.len() {
            data_end + 1
        } else {
            data_end
        };
        f(&Chunk {
            id,
            start: pos,
            data_start,
            data_len: len,
            end,
        });
        pos = end;
    }
    Ok(())
}

/// Extract the `C2PA` chunk data.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let mut found = None;
    walk_chunks(data, |c| {
        if &c.id == CHUNK_C2PA && found.is_none() {
            found = Some(data[c.data_start..c.data_start + c.data_len].to_vec());
        }
    })?;
    Ok(found)
}

/// Remove every existing `C2PA` chunk, leaving all other chunks and their
/// order untouched, and recompute the `RIFF` size field. A no-op when the
/// asset has no manifest.
#[cfg(feature = "test-support")]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    check_riff(asset)?;
    let mut out = Vec::with_capacity(asset.len());
    out.extend_from_slice(&asset[..12]);
    let mut cursor = 12;
    walk_chunks(asset, |c| {
        if &c.id == CHUNK_C2PA {
            out.extend_from_slice(&asset[cursor..c.start]);
            cursor = c.end;
        }
    })?;
    out.extend_from_slice(&asset[cursor..]);
    let riff_size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());
    Ok(out)
}

/// Build the exact RIFF `C2PA` carrier bytes for a manifest store.
#[cfg(feature = "test-support")]
pub(crate) fn build_c2pa_chunk(manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    if manifest_store.len() > u32::MAX as usize {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: u32::MAX as usize,
            got: manifest_store.len(),
        });
    }
    let mut out = Vec::with_capacity(manifest_store.len() + 9);
    out.extend_from_slice(CHUNK_C2PA);
    out.extend_from_slice(&(manifest_store.len() as u32).to_le_bytes());
    out.extend_from_slice(manifest_store);
    if manifest_store.len() % 2 == 1 {
        out.push(0);
    }
    Ok(out)
}

/// Append a `C2PA` chunk and update the `RIFF` size field.
///
/// Any `C2PA` chunk(s) already present are stripped first, so re-signing an
/// already-signed RIFF asset always leaves exactly one manifest in the
/// container (the fresh one) rather than a stale chunk that silently
/// outranks it on read-back.
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let carrier = build_c2pa_chunk(manifest_store)?;
    let clean = strip(asset)?;

    let mut out = Vec::with_capacity(clean.len() + carrier.len() + 1);
    out.extend_from_slice(&clean);
    // The file must be word-aligned before a new chunk begins.
    if out.len() % 2 == 1 {
        out.push(0);
    }
    out.extend_from_slice(&carrier);

    // RIFF size = total file size minus the 8-byte `RIFF | size` prefix.
    let riff_size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());
    Ok(out)
}

/// The `C2PA` chunk byte span as a single exclusion.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let mut ex = Vec::new();
    walk_chunks(data, |c| {
        if &c.id == CHUNK_C2PA {
            ex.push(DataHashExclusion {
                start: c.start,
                length: c.end - c.start,
            });
        }
    })?;
    Ok(ex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    /// Minimal WAV: RIFF/WAVE with a tiny fmt chunk.
    fn tiny_wav() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVE");
        body.extend_from_slice(b"fmt ");
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&[1, 0, 1, 0, 0x44, 0xAC, 0, 0, 0x88, 0x58, 1, 0, 2, 0, 16, 0]);
        let mut v = Vec::from(*RIFF);
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_wav(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn riff_size_updated() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_wav(), &store).unwrap();
        let declared = le_u32(&embedded, 4).unwrap() as usize;
        assert_eq!(declared, embedded.len() - 8);
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_wav()).unwrap(), None);
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first = embed(&tiny_wav(), b"FIRST-manifest-store").unwrap();
        let second = embed(&first, b"SECOND-manifest-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECOND-manifest-store"[..])
        );
        let mut c2pa_count = 0;
        walk_chunks(&second, |c| {
            if &c.id == CHUNK_C2PA {
                c2pa_count += 1;
            }
        })
        .unwrap();
        assert_eq!(c2pa_count, 1, "re-embed must leave exactly one C2PA chunk");
        let declared = le_u32(&second, 4).unwrap() as usize;
        assert_eq!(declared, second.len() - 8);
    }

    #[test]
    fn rejects_non_riff() {
        assert!(matches!(
            extract(b"NOTRIFFNOTRIFF"),
            Err(FormatError::InvalidStructure { .. })
        ));
    }
}
