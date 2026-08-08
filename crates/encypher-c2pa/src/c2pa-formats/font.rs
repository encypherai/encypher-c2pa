//! SFNT fonts (OTF/TTF): JUMBF in a `C2PA` table.
//!
//! An SFNT file begins with a header (`sfnt` version, table count, binary-search
//! hints) followed by a table directory of 16-byte records
//! (`tag(4) | checksum(4) | offset(4) | length(4)`). C2PA stores the manifest
//! store as the contents of a table tagged `C2PA`.
//!
//! Both extraction and embedding are supported. Embedding rebuilds the font:
//! it appends a `C2PA` table (4-byte aligned), recomputes the binary-search
//! header fields and every table offset, the new table's checksum, and the
//! `head.checkSumAdjustment`.

use crate::c2pa_formats::util::be_u32;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Font;
const TAG_C2PA: &[u8; 4] = b"C2PA";

/// Recognized SFNT version tags.
fn is_sfnt_version(v: &[u8]) -> bool {
    matches!(v, [0x00, 0x01, 0x00, 0x00] | b"OTTO" | b"true" | b"typ1")
}

/// Extract the manifest store from the `C2PA` SFNT table.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    if data.len() < 12 || !is_sfnt_version(&data[0..4]) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "not an SFNT font",
        });
    }
    let num_tables = u16::from_be_bytes([data[4], data[5]]) as usize;
    let dir_start: usize = 12;
    let dir_end = dir_start
        .checked_add(num_tables * 16)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    for i in 0..num_tables {
        let rec = dir_start + i * 16;
        if &data[rec..rec + 4] != TAG_C2PA {
            continue;
        }
        let offset = be_u32(data, rec + 8).ok_or(FormatError::Truncated(FMT))? as usize;
        let length = be_u32(data, rec + 12).ok_or(FormatError::Truncated(FMT))? as usize;
        let end = offset
            .checked_add(length)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        return Ok(Some(data[offset..end].to_vec()));
    }
    let _ = dir_end;
    Ok(None)
}

/// Compute an SFNT table checksum: the wrapping sum of the table's big-endian
/// `u32` words, treating the table as zero-padded to a multiple of 4 bytes.
#[cfg(test)]
fn table_checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() {
        let mut word = [0u8; 4];
        let n = core::cmp::min(4, data.len() - i);
        word[..n].copy_from_slice(&data[i..i + n]);
        sum = sum.wrapping_add(u32::from_be_bytes(word));
        i += 4;
    }
    sum
}

/// Compute `(searchRange, entrySelector, rangeShift)` for `n` tables.
///
/// `searchRange = 16 * 2^floor(log2(n))`, `entrySelector = floor(log2(n))`,
/// `rangeShift = n*16 - searchRange`.
#[cfg(test)]
fn search_params(n: usize) -> (u16, u16, u16) {
    let mut es = 0u16;
    let mut pow = 1usize;
    while pow * 2 <= n {
        pow *= 2;
        es += 1;
    }
    let search_range = (pow * 16) as u16;
    let range_shift = (n * 16) as u16 - search_range;
    (search_range, es, range_shift)
}

/// Embed `manifest_store` into an SFNT font as a `C2PA` table.
///
/// The font is rebuilt from scratch: existing tables (minus any prior `C2PA`
/// table) are kept, a new `C2PA` table holding the manifest is appended, all
/// tables are laid out 4-byte aligned after a directory whose record count grew
/// by one, and every table offset is rewritten. The directory is sorted by
/// ascending tag, the binary-search header fields and each table's checksum are
/// recomputed, and — if a `head` table is present — its `checkSumAdjustment` is
/// recomputed so the whole-font checksum equals `0xB1B0AFBA`.
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    if asset.len() < 12 || !is_sfnt_version(&asset[0..4]) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "not an SFNT font",
        });
    }
    let mut sfnt_version = [0u8; 4];
    sfnt_version.copy_from_slice(&asset[0..4]);
    let num_tables = u16::from_be_bytes([asset[4], asset[5]]) as usize;
    let dir_start: usize = 12;
    dir_start
        .checked_add(num_tables * 16)
        .filter(|&e| e <= asset.len())
        .ok_or(FormatError::Truncated(FMT))?;

    // Collect existing tables (tag, data), excluding any prior C2PA table.
    let mut tables: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    for i in 0..num_tables {
        let rec = dir_start + i * 16;
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&asset[rec..rec + 4]);
        if &tag == TAG_C2PA {
            continue;
        }
        let offset = be_u32(asset, rec + 8).ok_or(FormatError::Truncated(FMT))? as usize;
        let length = be_u32(asset, rec + 12).ok_or(FormatError::Truncated(FMT))? as usize;
        let end = offset
            .checked_add(length)
            .filter(|&e| e <= asset.len())
            .ok_or(FormatError::Truncated(FMT))?;
        tables.push((tag, asset[offset..end].to_vec()));
    }
    tables.push((*TAG_C2PA, manifest_store.to_vec()));
    // The table directory must be sorted by ascending tag.
    tables.sort_by_key(|a| a.0);

    let new_num = tables.len();
    let dir_size = 12 + new_num * 16;

    // Assign 4-byte-aligned offsets for each table's data.
    let mut offsets = Vec::with_capacity(new_num);
    let mut cursor = dir_size;
    for (_, d) in &tables {
        offsets.push(cursor);
        cursor += (d.len() + 3) & !3;
    }
    let mut out = vec![0u8; cursor];

    // Header.
    out[0..4].copy_from_slice(&sfnt_version);
    out[4..6].copy_from_slice(&(new_num as u16).to_be_bytes());
    let (sr, es, rs) = search_params(new_num);
    out[6..8].copy_from_slice(&sr.to_be_bytes());
    out[8..10].copy_from_slice(&es.to_be_bytes());
    out[10..12].copy_from_slice(&rs.to_be_bytes());

    // Write table data (padding bytes are already zero).
    let mut head_off = None;
    for (i, (tag, d)) in tables.iter().enumerate() {
        let off = offsets[i];
        out[off..off + d.len()].copy_from_slice(d);
        if tag == b"head" {
            head_off = Some(off);
        }
    }
    // Zero head.checkSumAdjustment (offset+8) before computing checksums.
    if let Some(off) = head_off {
        if cursor >= off + 12 {
            out[off + 8..off + 12].copy_from_slice(&[0, 0, 0, 0]);
        }
    }

    // Write directory records with recomputed checksums and offsets.
    for (i, (tag, d)) in tables.iter().enumerate() {
        let rec = 12 + i * 16;
        let off = offsets[i];
        let padded = (d.len() + 3) & !3;
        let checksum = table_checksum(&out[off..off + padded]);
        out[rec..rec + 4].copy_from_slice(tag);
        out[rec + 4..rec + 8].copy_from_slice(&checksum.to_be_bytes());
        out[rec + 8..rec + 12].copy_from_slice(&(off as u32).to_be_bytes());
        out[rec + 12..rec + 16].copy_from_slice(&(d.len() as u32).to_be_bytes());
    }

    // checkSumAdjustment = 0xB1B0AFBA - checksum(entire font with the field 0).
    if let Some(off) = head_off {
        if cursor >= off + 12 {
            let whole = table_checksum(&out);
            let adj = 0xB1B0AFBAu32.wrapping_sub(whole);
            out[off + 8..off + 12].copy_from_slice(&adj.to_be_bytes());
        }
    }
    Ok(out)
}

/// `c2pa.hash.data` exclusions for an SFNT font.
///
/// Excludes (1) the `C2PA` manifest table payload, (2) the `C2PA` table's
/// directory-record checksum, and (3) `head.checkSumAdjustment`. All three are
/// recomputed when the placeholder manifest is replaced with the real one during
/// two-pass signing (the per-table checksum over the new payload, and the
/// whole-font checkSumAdjustment), so none can be part of the stable data
/// binding. Everything else (glyph data, all other tables, the directory
/// structure) is attested.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    if data.len() < 12 || !is_sfnt_version(&data[0..4]) {
        return Ok(Vec::new());
    }
    let num_tables = u16::from_be_bytes([data[4], data[5]]) as usize;
    let dir_start: usize = 12;
    dir_start
        .checked_add(num_tables * 16)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let mut out: Vec<DataHashExclusion> = Vec::new();
    for i in 0..num_tables {
        let rec = dir_start + i * 16;
        let tag = &data[rec..rec + 4];
        if tag == TAG_C2PA {
            let offset = be_u32(data, rec + 8).ok_or(FormatError::Truncated(FMT))? as usize;
            let length = be_u32(data, rec + 12).ok_or(FormatError::Truncated(FMT))? as usize;
            if offset
                .checked_add(length)
                .filter(|&e| e <= data.len())
                .is_none()
            {
                return Err(FormatError::Truncated(FMT));
            }
            out.push(DataHashExclusion {
                start: rec + 4,
                length: 4,
            }); // C2PA dir checksum
            out.push(DataHashExclusion {
                start: offset,
                length,
            }); // manifest payload
        } else if tag == b"head" {
            let offset = be_u32(data, rec + 8).ok_or(FormatError::Truncated(FMT))? as usize;
            if offset
                .checked_add(12)
                .filter(|&e| e <= data.len())
                .is_some()
            {
                out.push(DataHashExclusion {
                    start: offset + 8,
                    length: 4,
                }); // checkSumAdjustment
            }
        }
    }
    out.sort_by_key(|e| e.start);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TrueType font with one `C2PA` table holding `manifest`.
    fn font_with_manifest(manifest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // sfnt version
        v.extend_from_slice(&1u16.to_be_bytes()); // numTables
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // searchRange/entrySelector/rangeShift
        let table_off = 12 + 16; // after directory
        v.extend_from_slice(TAG_C2PA);
        v.extend_from_slice(&0u32.to_be_bytes()); // checksum (ignored on read)
        v.extend_from_slice(&(table_off as u32).to_be_bytes());
        v.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        v.extend_from_slice(manifest);
        v
    }

    fn bare_font() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        v
    }

    #[test]
    fn exclusions_cover_c2pa_table() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let embedded = embed(&bare_font(), &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        // C2PA directory-record checksum (4 bytes) + the manifest payload.
        assert_eq!(ex.len(), 2);
        let payload = ex.iter().max_by_key(|e| e.length).unwrap();
        assert_eq!(
            &embedded[payload.start..payload.start + payload.length],
            store.as_slice()
        );
        assert!(exclusions(&bare_font()).unwrap().is_empty());
    }

    #[test]
    fn data_hash_stable_across_manifest_swap() {
        // Two-pass signing replaces a placeholder manifest with the real one of
        // the SAME length. Every byte OUTSIDE the exclusions must be identical so
        // the c2pa.hash.data binding is stable (this is the dataHash.mismatch fix).
        let placeholder = vec![0u8; 64];
        let real = vec![0xABu8; 64];
        let fa = embed(&font_with_head(), &placeholder).unwrap();
        let fb = embed(&font_with_head(), &real).unwrap();
        assert_eq!(fa.len(), fb.len());
        let ex = exclusions(&fa).unwrap();
        let excluded = |i: usize| ex.iter().any(|e| i >= e.start && i < e.start + e.length);
        for i in 0..fa.len() {
            if !excluded(i) {
                assert_eq!(
                    fa[i], fb[i],
                    "non-excluded byte {i} changed across the manifest swap"
                );
            }
        }
        // The exclusions are exactly: head.checkSumAdjustment, C2PA dir checksum,
        // and the manifest payload.
        assert_eq!(ex.len(), 3);
    }

    /// Build a font with a single 54-byte `head` table. Input checksums/offsets
    /// need not be correct; embed recomputes them.
    fn font_with_head() -> Vec<u8> {
        let head_len = 54usize;
        let head_off = 12 + 16;
        let total = head_off + ((head_len + 3) & !3);
        let mut v = vec![0u8; total];
        v[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        v[4..6].copy_from_slice(&1u16.to_be_bytes()); // numTables
        v[6..8].copy_from_slice(&16u16.to_be_bytes()); // searchRange (n=1)
                                                       // entrySelector / rangeShift already zero
        v[12..16].copy_from_slice(b"head");
        v[20..24].copy_from_slice(&(head_off as u32).to_be_bytes()); // offset
        v[24..28].copy_from_slice(&(head_len as u32).to_be_bytes()); // length
                                                                     // head magicNumber (0x5F0F3CF5) at head offset+12 — informational only.
        v[head_off + 12..head_off + 16].copy_from_slice(&0x5F0F3CF5u32.to_be_bytes());
        v
    }

    #[test]
    fn extract_tagged_manifest() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let asset = font_with_manifest(&store);
        assert_eq!(extract(&asset).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&bare_font()).unwrap(), None);
    }

    #[test]
    fn embed_round_trips() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let out = embed(&font_with_head(), &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_recomputes_checksum_adjustment() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let out = embed(&font_with_head(), &store).unwrap();
        // After writing head.checkSumAdjustment, the whole-font checksum is the
        // OpenType magic constant.
        assert_eq!(table_checksum(&out), 0xB1B0AFBA);
    }

    #[test]
    fn embed_into_bare_round_trips() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let out = embed(&bare_font(), &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first = embed(&font_with_head(), b"FIRST-manifest-store").unwrap();
        let second = embed(&first, b"SECOND-manifest-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECOND-manifest-store"[..])
        );
        let num = u16::from_be_bytes([second[4], second[5]]) as usize;
        let c2pa = (0..num)
            .filter(|&i| &second[12 + i * 16..16 + i * 16] == TAG_C2PA)
            .count();
        assert_eq!(c2pa, 1);
    }

    #[test]
    fn rejects_non_font() {
        assert!(extract(b"%PDF-1.7\x00\x00\x00\x00").is_err());
    }
}
