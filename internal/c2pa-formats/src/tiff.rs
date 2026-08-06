//! TIFF / DNG: JUMBF in IFD tag `0xCD41` (52545).
//!
//! TIFF is a header (`II`/`MM` byte order, magic `42`, offset to the first IFD)
//! followed by Image File Directories. C2PA stores the manifest store in an IFD
//! entry with tag `0xCD41`, type `UNDEFINED` (7); the entry value is the JUMBF
//! bytes (inline if `count <= 4`, otherwise an offset to them).
//!
//! Both extraction and embedding are supported. Embedding uses an
//! append-new-IFD strategy (see [`embed`]) that keeps every original byte in
//! place, so existing out-of-line value offsets stay valid without rewriting.

use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Tiff;
const TAG_C2PA: u16 = 0xCD41;

/// TIFF byte order.
#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes([b[0], b[1]]),
            Endian::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endian::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
}

fn parse_header(data: &[u8]) -> Result<(Endian, usize), FormatError> {
    if data.len() < 8 {
        return Err(FormatError::Truncated(FMT));
    }
    let endian = match &data[0..2] {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad byte-order mark",
            })
        }
    };
    if endian.u16(&data[2..4]) != 42 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad TIFF magic",
        });
    }
    let ifd_off = endian.u32(&data[4..8]) as usize;
    Ok((endian, ifd_off))
}

/// Extract the manifest store from IFD tag `0xCD41`. Follows the IFD chain.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let (endian, mut ifd_off) = parse_header(data)?;
    // Guard against cyclic IFD chains.
    let mut visited = 0;
    while ifd_off != 0 && visited < 64 {
        visited += 1;
        if ifd_off + 2 > data.len() {
            return Err(FormatError::Truncated(FMT));
        }
        let count = endian.u16(&data[ifd_off..ifd_off + 2]) as usize;
        let entries_start = ifd_off + 2;
        let entries_end = entries_start
            .checked_add(count * 12)
            .filter(|&e| e + 4 <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        for i in 0..count {
            let e = entries_start + i * 12;
            let tag = endian.u16(&data[e..e + 2]);
            if tag != TAG_C2PA {
                continue;
            }
            let value_count = endian.u32(&data[e + 4..e + 8]) as usize;
            // For type UNDEFINED/BYTE the element size is 1.
            if value_count <= 4 {
                return Ok(Some(data[e + 8..e + 8 + value_count].to_vec()));
            }
            let off = endian.u32(&data[e + 8..e + 12]) as usize;
            let end = off
                .checked_add(value_count)
                .filter(|&x| x <= data.len())
                .ok_or(FormatError::Truncated(FMT))?;
            return Ok(Some(data[off..end].to_vec()));
        }
        ifd_off = endian.u32(&data[entries_end..entries_end + 4]) as usize;
    }
    Ok(None)
}

/// The appended manifest-store payload byte span as a single exclusion.
///
/// Mirrors [`extract`]: walks the IFD chain to the `0xCD41` entry and excludes
/// exactly the manifest *value* bytes it points at — the out-of-line payload
/// `embed` appends (`count > 4`), or the inline value field for a tiny
/// `count <= 4` manifest. The IFD entry's tag/type/count/offset and the
/// appended IFD itself are deliberately NOT excluded: their bytes depend only
/// on the manifest's *length* and *position* (both fixed across the two-pass
/// signing flow, where the placeholder has the final size), never on its
/// content, so the `c2pa.hash.data` digest legitimately covers them. Honors
/// both byte orders. Returns an empty vec if no manifest is present.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let (endian, mut ifd_off) = parse_header(data)?;
    let mut visited = 0;
    while ifd_off != 0 && visited < 64 {
        visited += 1;
        if ifd_off + 2 > data.len() {
            return Err(FormatError::Truncated(FMT));
        }
        let count = endian.u16(&data[ifd_off..ifd_off + 2]) as usize;
        let entries_start = ifd_off + 2;
        let entries_end = entries_start
            .checked_add(count * 12)
            .filter(|&e| e + 4 <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        for i in 0..count {
            let e = entries_start + i * 12;
            if endian.u16(&data[e..e + 2]) != TAG_C2PA {
                continue;
            }
            let value_count = endian.u32(&data[e + 4..e + 8]) as usize;
            if value_count <= 4 {
                // Inline value: the manifest sits in the entry's value field.
                return Ok(vec![DataHashExclusion {
                    start: e + 8,
                    length: value_count,
                }]);
            }
            let off = endian.u32(&data[e + 8..e + 12]) as usize;
            off.checked_add(value_count)
                .filter(|&x| x <= data.len())
                .ok_or(FormatError::Truncated(FMT))?;
            return Ok(vec![DataHashExclusion {
                start: off,
                length: value_count,
            }]);
        }
        ifd_off = endian.u32(&data[entries_end..entries_end + 4]) as usize;
    }
    Ok(Vec::new())
}

/// Embed `manifest_store` into a TIFF/DNG using an append-new-IFD strategy.
///
/// The original asset is copied verbatim, the manifest bytes are appended
/// (word-aligned), and a fresh IFD is appended at the end of the file. That IFD
/// contains the first IFD's entries (minus any prior `0xCD41` entry) plus a new
/// `0xCD41` / `UNDEFINED` entry pointing at the appended manifest, with the
/// first IFD's `next-IFD` pointer preserved so the rest of the chain is
/// unchanged. The header's first-IFD offset is repointed at the new IFD. Because
/// every original byte keeps its position, all existing out-of-line value
/// offsets (strip data, etc.) stay valid without rewriting. Entries are
/// re-sorted by ascending tag to remain spec-conformant. Honors both byte
/// orders.
///
/// Constraints: only the *first* IFD's entries are folded into the new IFD; any
/// subsequent IFDs are reached through the preserved next-IFD pointer (their
/// bytes are untouched). A pre-existing manifest in the first IFD is replaced;
/// one elsewhere in the chain is left in place.
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let (endian, ifd_off) = parse_header(asset)?;
    let mut entries: Vec<[u8; 12]> = Vec::new();
    let mut next_ifd: u32 = 0;
    if ifd_off != 0 {
        if ifd_off + 2 > asset.len() {
            return Err(FormatError::Truncated(FMT));
        }
        let count = endian.u16(&asset[ifd_off..ifd_off + 2]) as usize;
        let entries_start = ifd_off + 2;
        let entries_end = entries_start
            .checked_add(count * 12)
            .filter(|&e| e + 4 <= asset.len())
            .ok_or(FormatError::Truncated(FMT))?;
        for i in 0..count {
            let e = entries_start + i * 12;
            if endian.u16(&asset[e..e + 2]) == TAG_C2PA {
                continue;
            }
            let mut rec = [0u8; 12];
            rec.copy_from_slice(&asset[e..e + 12]);
            entries.push(rec);
        }
        next_ifd = endian.u32(&asset[entries_end..entries_end + 4]);
    }

    let mut out = asset.to_vec();
    if !out.len().is_multiple_of(2) {
        out.push(0);
    }
    let manifest_off = out.len();
    out.extend_from_slice(manifest_store);
    if !out.len().is_multiple_of(2) {
        out.push(0);
    }
    let new_ifd_off = out.len();

    // Build the new C2PA entry: tag, type=UNDEFINED(7), count, value/offset.
    let mut rec = Vec::with_capacity(12);
    write_u16(&mut rec, endian, TAG_C2PA);
    write_u16(&mut rec, endian, 7);
    write_u32(&mut rec, endian, manifest_store.len() as u32);
    if manifest_store.len() <= 4 {
        // Inline value: raw bytes, left-justified, zero-padded to 4 bytes.
        let mut val = [0u8; 4];
        val[..manifest_store.len()].copy_from_slice(manifest_store);
        rec.extend_from_slice(&val);
    } else {
        write_u32(&mut rec, endian, manifest_off as u32);
    }
    let mut c2pa = [0u8; 12];
    c2pa.copy_from_slice(&rec);
    entries.push(c2pa);

    // TIFF requires IFD entries sorted by ascending tag.
    entries.sort_by_key(|r| endian.u16(&r[0..2]));

    write_u16(&mut out, endian, entries.len() as u16);
    for r in &entries {
        out.extend_from_slice(r);
    }
    write_u32(&mut out, endian, next_ifd);

    // Repoint the header's first-IFD offset at the appended IFD.
    match endian {
        Endian::Little => out[4..8].copy_from_slice(&(new_ifd_off as u32).to_le_bytes()),
        Endian::Big => out[4..8].copy_from_slice(&(new_ifd_off as u32).to_be_bytes()),
    }
    Ok(out)
}

fn write_u16(out: &mut Vec<u8>, endian: Endian, x: u16) {
    match endian {
        Endian::Little => out.extend_from_slice(&x.to_le_bytes()),
        Endian::Big => out.extend_from_slice(&x.to_be_bytes()),
    }
}

fn write_u32(out: &mut Vec<u8>, endian: Endian, x: u32) {
    match endian {
        Endian::Little => out.extend_from_slice(&x.to_le_bytes()),
        Endian::Big => out.extend_from_slice(&x.to_be_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a little-endian TIFF with a single IFD containing the C2PA tag
    /// whose value points to `manifest` appended after the IFD.
    fn tiff_with_manifest(manifest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&42u16.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes()); // IFD at offset 8
                                                  // IFD: 1 entry.
        v.extend_from_slice(&1u16.to_le_bytes());
        // Entry: tag, type=7 (UNDEFINED), count, offset.
        let manifest_off = 8 + 2 + 12 + 4; // header+count+entry+nextifd
        v.extend_from_slice(&TAG_C2PA.to_le_bytes());
        v.extend_from_slice(&7u16.to_le_bytes());
        v.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
        v.extend_from_slice(&(manifest_off as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
        v.extend_from_slice(manifest);
        v
    }

    fn bare_tiff() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"II");
        v.extend_from_slice(&42u16.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // 0 entries
        v.extend_from_slice(&0u32.to_le_bytes()); // next IFD = 0
        v
    }

    #[test]
    fn extract_tagged_manifest() {
        let store = crate::tests::dummy_manifest_store();
        let asset = tiff_with_manifest(&store);
        assert_eq!(extract(&asset).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&bare_tiff()).unwrap(), None);
    }

    /// Build a TIFF (endianness selectable) with one out-of-line
    /// `ImageDescription` (`0x010E`) entry, plus the description bytes, so embed
    /// can be shown to preserve pre-existing out-of-line values.
    fn tiff_with_desc(le: bool) -> (Vec<u8>, Vec<u8>) {
        let desc = b"hello-tiff-description".to_vec();
        let w16 = |v: &mut Vec<u8>, x: u16| {
            if le {
                v.extend_from_slice(&x.to_le_bytes());
            } else {
                v.extend_from_slice(&x.to_be_bytes());
            }
        };
        let w32 = |v: &mut Vec<u8>, x: u32| {
            if le {
                v.extend_from_slice(&x.to_le_bytes());
            } else {
                v.extend_from_slice(&x.to_be_bytes());
            }
        };
        let mut v = Vec::new();
        v.extend_from_slice(if le { b"II" } else { b"MM" });
        w16(&mut v, 42);
        w32(&mut v, 8); // IFD at offset 8
        let desc_off = 8 + 2 + 12 + 4; // header + count + entry + next-IFD
        w16(&mut v, 1); // 1 entry
        w16(&mut v, 0x010E); // ImageDescription
        w16(&mut v, 2); // ASCII
        w32(&mut v, desc.len() as u32);
        w32(&mut v, desc_off as u32);
        w32(&mut v, 0); // next IFD = 0
        v.extend_from_slice(&desc);
        (v, desc)
    }

    #[test]
    fn embed_round_trips_le() {
        let store = crate::tests::dummy_manifest_store();
        let (asset, _) = tiff_with_desc(true);
        let out = embed(&asset, &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_round_trips_be() {
        let store = crate::tests::dummy_manifest_store();
        let (asset, _) = tiff_with_desc(false);
        let out = embed(&asset, &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_into_bare_round_trips() {
        let store = crate::tests::dummy_manifest_store();
        let out = embed(&bare_tiff(), &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_preserves_existing_entries() {
        let store = crate::tests::dummy_manifest_store();
        let (asset, desc) = tiff_with_desc(true);
        let out = embed(&asset, &store).unwrap();
        let (endian, ifd_off) = parse_header(&out).unwrap();
        let count = endian.u16(&out[ifd_off..ifd_off + 2]) as usize;
        let mut found = None;
        for i in 0..count {
            let e = ifd_off + 2 + i * 12;
            if endian.u16(&out[e..e + 2]) == 0x010E {
                let n = endian.u32(&out[e + 4..e + 8]) as usize;
                let off = endian.u32(&out[e + 8..e + 12]) as usize;
                found = Some(out[off..off + n].to_vec());
            }
        }
        assert_eq!(found.as_deref(), Some(desc.as_slice()));
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let (asset, _) = tiff_with_desc(true);
        let first = embed(&asset, b"FIRSTMANIFEST-store").unwrap();
        let second = embed(&first, b"SECONDMANIFEST-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECONDMANIFEST-store"[..])
        );
        let (endian, ifd_off) = parse_header(&second).unwrap();
        let count = endian.u16(&second[ifd_off..ifd_off + 2]) as usize;
        let c2pa = (0..count)
            .filter(|&i| {
                endian.u16(&second[ifd_off + 2 + i * 12..ifd_off + 4 + i * 12]) == TAG_C2PA
            })
            .count();
        assert_eq!(c2pa, 1);
    }

    #[test]
    fn rejects_non_tiff() {
        assert!(extract(b"\x00\x01\x02\x03\x04\x05\x06\x07").is_err());
    }
}
