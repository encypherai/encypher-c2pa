//! ZIP (EPUB/DOCX/ODT/OXPS): JUMBF in entry `META-INF/content_credential.c2pa`.
//!
//! The manifest store is a *stored* (uncompressed) ZIP entry whose name is
//! `META-INF/content_credential.c2pa`. Extraction locates that entry through the
//! central directory; embedding appends a new stored entry and rebuilds the
//! central directory and end-of-central-directory record.
//!
//! Only standard (non-ZIP64) archives are supported; ZIP64 archives return
//! [`FormatError::UnsupportedVariant`].

#[cfg(feature = "test-support")]
use crate::util::crc32;
use crate::util::le_u32;
use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Zip;
const ENTRY_NAME: &[u8] = b"META-INF/content_credential.c2pa";
const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const METHOD_STORED: u16 = 0;

fn le16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Parsed end-of-central-directory record.
struct Eocd {
    total_entries: u16,
    /// Parsed for completeness; only the write path consumes it.
    #[cfg_attr(not(feature = "test-support"), allow(dead_code))]
    cd_size: u32,
    cd_offset: u32,
    /// Offset of the EOCD record itself.
    eocd_offset: usize,
}

/// Locate and parse the EOCD record by scanning backwards from the end.
fn find_eocd(data: &[u8]) -> Result<Eocd, FormatError> {
    if data.len() < 22 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "too small for ZIP EOCD",
        });
    }
    let max_back = data.len().saturating_sub(22 + 0xFFFF);
    let mut pos = data.len() - 22;
    loop {
        if le_u32(data, pos) == Some(SIG_EOCD) {
            let total_entries = le16(data, pos + 10).ok_or(FormatError::Truncated(FMT))?;
            let cd_size = le_u32(data, pos + 12).ok_or(FormatError::Truncated(FMT))?;
            let cd_offset = le_u32(data, pos + 16).ok_or(FormatError::Truncated(FMT))?;
            if cd_offset == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF || total_entries == 0xFFFF {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "ZIP64 archive",
                });
            }
            return Ok(Eocd {
                total_entries,
                cd_size,
                cd_offset,
                eocd_offset: pos,
            });
        }
        if pos == 0 || pos <= max_back {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "no EOCD record",
            });
        }
        pos -= 1;
    }
}

/// A central-directory entry's salient fields.
struct CdEntry {
    method: u16,
    comp_size: u32,
    local_offset: u32,
}

/// Find a central-directory entry by name. Returns `None` if absent.
fn find_cd_entry(data: &[u8], eocd: &Eocd, name: &[u8]) -> Result<Option<CdEntry>, FormatError> {
    let mut pos = eocd.cd_offset as usize;
    for _ in 0..eocd.total_entries {
        if le_u32(data, pos) != Some(SIG_CENTRAL) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad central directory signature",
            });
        }
        let method = le16(data, pos + 10).ok_or(FormatError::Truncated(FMT))?;
        let comp_size = le_u32(data, pos + 20).ok_or(FormatError::Truncated(FMT))?;
        let name_len = le16(data, pos + 28).ok_or(FormatError::Truncated(FMT))? as usize;
        let extra_len = le16(data, pos + 30).ok_or(FormatError::Truncated(FMT))? as usize;
        let comment_len = le16(data, pos + 32).ok_or(FormatError::Truncated(FMT))? as usize;
        let local_offset = le_u32(data, pos + 42).ok_or(FormatError::Truncated(FMT))?;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        if &data[name_start..name_end] == name {
            return Ok(Some(CdEntry {
                method,
                comp_size,
                local_offset,
            }));
        }
        pos = name_end + extra_len + comment_len;
    }
    Ok(None)
}

/// Walk every central-directory entry, yielding `(name, method, comp_size,
/// local_offset)`.
fn walk_cd(
    data: &[u8],
    eocd: &Eocd,
    mut f: impl FnMut(&[u8], u16, u32, u32),
) -> Result<(), FormatError> {
    let mut pos = eocd.cd_offset as usize;
    for _ in 0..eocd.total_entries {
        if le_u32(data, pos) != Some(SIG_CENTRAL) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad central directory signature",
            });
        }
        let method = le16(data, pos + 10).ok_or(FormatError::Truncated(FMT))?;
        let comp_size = le_u32(data, pos + 20).ok_or(FormatError::Truncated(FMT))?;
        let name_len = le16(data, pos + 28).ok_or(FormatError::Truncated(FMT))? as usize;
        let extra_len = le16(data, pos + 30).ok_or(FormatError::Truncated(FMT))? as usize;
        let comment_len = le16(data, pos + 32).ok_or(FormatError::Truncated(FMT))? as usize;
        let local_offset = le_u32(data, pos + 42).ok_or(FormatError::Truncated(FMT))?;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        f(&data[name_start..name_end], method, comp_size, local_offset);
        pos = name_end + extra_len + comment_len;
    }
    Ok(())
}

/// Every entry name in the archive, in central-directory order.
pub fn zip_entry_names(data: &[u8]) -> Result<Vec<String>, FormatError> {
    let eocd = find_eocd(data)?;
    let mut names = Vec::with_capacity(eocd.total_entries as usize);
    walk_cd(data, &eocd, |name, _, _, _| {
        names.push(String::from_utf8_lossy(name).into_owned());
    })?;
    Ok(names)
}

/// The decompressed content of the named entry (`None` when absent).
///
/// Supports `stored` (method 0) and `deflate` (method 8) entries — the only
/// methods in real-world OPC/EPUB archives. Other methods return
/// [`FormatError::UnsupportedVariant`].
pub fn zip_entry_data(data: &[u8], name: &str) -> Result<Option<Vec<u8>>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, name.as_bytes())? else {
        return Ok(None);
    };
    let lh = entry.local_offset as usize;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = lh + 30 + name_len + extra_len;
    let data_end = data_start
        .checked_add(entry.comp_size as usize)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let raw = &data[data_start..data_end];
    match entry.method {
        METHOD_STORED => Ok(Some(raw.to_vec())),
        8 => miniz_oxide::inflate::decompress_to_vec(raw)
            .map(Some)
            .map_err(|_| FormatError::InvalidStructure {
                format: FMT,
                detail: "deflate stream corrupt",
            }),
        _ => Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "unsupported ZIP compression method",
        }),
    }
}

/// Byte slices hashed in order for `zip_central_directory_hash` (A.6.2.2).
///
/// This covers every central-directory header and the complete EOCD record,
/// while skipping only the four-byte CRC-32 field in the manifest entry's
/// central header. Returning borrowed slices avoids copying large directories.
pub fn zip_central_directory_hash_parts(data: &[u8]) -> Result<Vec<&[u8]>, FormatError> {
    let eocd = find_eocd(data)?;
    let mut parts = Vec::with_capacity(3);
    let mut pos = eocd.cd_offset as usize;
    let mut part_start = pos;
    for _ in 0..eocd.total_entries {
        if le_u32(data, pos) != Some(SIG_CENTRAL) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad central directory signature",
            });
        }
        let name_len = le16(data, pos + 28).ok_or(FormatError::Truncated(FMT))? as usize;
        let extra_len = le16(data, pos + 30).ok_or(FormatError::Truncated(FMT))? as usize;
        let comment_len = le16(data, pos + 32).ok_or(FormatError::Truncated(FMT))? as usize;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&end| end <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        let entry_end = name_end
            .checked_add(extra_len)
            .and_then(|end| end.checked_add(comment_len))
            .filter(|&end| end <= eocd.eocd_offset)
            .ok_or(FormatError::Truncated(FMT))?;
        if &data[name_start..name_end] == ENTRY_NAME {
            parts.push(&data[part_start..pos + 16]);
            part_start = pos + 20;
        }
        pos = entry_end;
    }
    if pos != eocd.eocd_offset {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "central directory size does not reach EOCD",
        });
    }
    parts.push(&data[part_start..]);
    Ok(parts)
}

/// The named entry's full LOCAL span: from its local file header through the
/// start of the next local entry (or the central directory) — header, name,
/// extra field, compressed data, and any data descriptor. This is the byte
/// range the in-the-wild `c2pa.hash.collection.data` per-URI hashes cover
/// (empirically: the c2pa-org public-testfiles ZIP vector). `None` if absent.
pub fn zip_entry_local_span(
    data: &[u8],
    name: &str,
) -> Result<Option<(usize, usize)>, FormatError> {
    let eocd = find_eocd(data)?;
    let mut offsets: Vec<u32> = Vec::with_capacity(eocd.total_entries as usize);
    let mut target: Option<u32> = None;
    walk_cd(data, &eocd, |n, _, _, local_offset| {
        offsets.push(local_offset);
        if n == name.as_bytes() {
            target = Some(local_offset);
        }
    })?;
    let Some(start) = target else { return Ok(None) };
    let end = offsets
        .iter()
        .copied()
        .filter(|&o| o > start)
        .min()
        .map_or(eocd.cd_offset as usize, |o| o as usize);
    Ok(Some((start as usize, end)))
}

/// The exact A.6.2.1 hash span for a ZIP member: its complete local file
/// header, file name and extra field, followed by its compressed/encrypted
/// content. A trailing data descriptor is not part of the span.
pub fn zip_entry_hash_span(data: &[u8], name: &str) -> Result<Option<(usize, usize)>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, name.as_bytes())? else {
        return Ok(None);
    };
    let start = entry.local_offset as usize;
    if le_u32(data, start) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, start + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, start + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = start
        .checked_add(30 + name_len + extra_len)
        .filter(|&offset| offset <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let end = data_start
        .checked_add(entry.comp_size as usize)
        .filter(|&offset| offset <= eocd.cd_offset as usize)
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(Some((start, end)))
}

/// Extract the manifest store from the `META-INF/content_credential.c2pa` entry.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, ENTRY_NAME)? else {
        return Ok(None);
    };
    if entry.method != METHOD_STORED {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "C2PA ZIP entry must be stored, not compressed",
        });
    }
    // Read the local file header to find the data offset (extra field length can
    // differ from the central directory copy).
    let lh = entry.local_offset as usize;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = lh + 30 + name_len + extra_len;
    let data_end = data_start
        .checked_add(entry.comp_size as usize)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(Some(data[data_start..data_end].to_vec()))
}

/// The stored manifest entry's data region as a `c2pa.hash.data` exclusion.
/// Only the manifest payload bytes are excluded; the surrounding ZIP structures
/// (local header, central directory, EOCD) are covered by the data hash.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, ENTRY_NAME)? else {
        return Ok(Vec::new());
    };
    if entry.method != METHOD_STORED {
        return Ok(Vec::new());
    }
    let lh = entry.local_offset as usize;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = lh + 30 + name_len + extra_len;
    let data_end = data_start
        .checked_add(entry.comp_size as usize)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(vec![DataHashExclusion {
        start: data_start,
        length: data_end - data_start,
    }])
}

/// Remove the `META-INF/content_credential.c2pa` entry (if present),
/// rebuilding local entries, the central directory, and the EOCD record so
/// all offsets stay consistent. A no-op when the asset has no manifest entry.
#[cfg(feature = "test-support")]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    let eocd = find_eocd(asset)?;
    if find_cd_entry(asset, &eocd, ENTRY_NAME)?.is_none() {
        return Ok(asset.to_vec());
    }

    struct CdRec {
        name: Vec<u8>,
        record_start: usize,
        record_end: usize,
        local_offset: u32,
    }
    let mut recs: Vec<CdRec> = Vec::new();
    let mut pos = eocd.cd_offset as usize;
    for _ in 0..eocd.total_entries {
        if le_u32(asset, pos) != Some(SIG_CENTRAL) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad central directory signature",
            });
        }
        let name_len = le16(asset, pos + 28).ok_or(FormatError::Truncated(FMT))? as usize;
        let extra_len = le16(asset, pos + 30).ok_or(FormatError::Truncated(FMT))? as usize;
        let comment_len = le16(asset, pos + 32).ok_or(FormatError::Truncated(FMT))? as usize;
        let local_offset = le_u32(asset, pos + 42).ok_or(FormatError::Truncated(FMT))?;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&e| e <= asset.len())
            .ok_or(FormatError::Truncated(FMT))?;
        let record_end = name_end + extra_len + comment_len;
        recs.push(CdRec {
            name: asset[name_start..name_end].to_vec(),
            record_start: pos,
            record_end,
            local_offset,
        });
        pos = record_end;
    }

    // Walk local entries in physical order so each kept entry's span runs up
    // to the next entry's local offset (or the central directory).
    let mut by_offset: Vec<&CdRec> = recs.iter().collect();
    by_offset.sort_by_key(|r| r.local_offset);
    let cd_start = eocd.cd_offset as usize;

    let mut out = Vec::with_capacity(asset.len());
    let mut new_offsets: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    for (i, r) in by_offset.iter().enumerate() {
        let span_end = by_offset
            .get(i + 1)
            .map(|n| n.local_offset as usize)
            .unwrap_or(cd_start);
        if r.name.as_slice() == ENTRY_NAME {
            continue;
        }
        new_offsets.insert(r.local_offset, out.len() as u32);
        out.extend_from_slice(&asset[r.local_offset as usize..span_end]);
    }

    let new_cd_offset = out.len();
    let mut kept_count: u16 = 0;
    for r in &recs {
        if r.name.as_slice() == ENTRY_NAME {
            continue;
        }
        let mut record = asset[r.record_start..r.record_end].to_vec();
        let new_local = new_offsets[&r.local_offset];
        record[42..46].copy_from_slice(&new_local.to_le_bytes());
        out.extend_from_slice(&record);
        kept_count += 1;
    }
    let new_cd_size = (out.len() - new_cd_offset) as u32;

    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&kept_count.to_le_bytes());
    out.extend_from_slice(&kept_count.to_le_bytes());
    out.extend_from_slice(&new_cd_size.to_le_bytes());
    out.extend_from_slice(&(new_cd_offset as u32).to_le_bytes());
    let comment_off = eocd.eocd_offset + 22;
    let comment = &asset[comment_off..];
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

/// Append a stored `META-INF/content_credential.c2pa` entry.
///
/// Any such entry already present is stripped first, so re-signing an
/// already-signed ZIP-based document (EPUB/DOCX/ODT/OXPS) always leaves
/// exactly one manifest entry (the fresh one) rather than a stale entry that
/// silently outranks it on read-back.
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let eocd = find_eocd(&clean)?;
    if manifest_store.len() > u32::MAX as usize {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: u32::MAX as usize,
            got: manifest_store.len(),
        });
    }
    let asset = clean.as_slice();
    let size = manifest_store.len() as u32;
    // The manifest entry is excluded from per-file collection hashing, and
    // A.6.2.2 skips this central header's CRC field. We can therefore write the
    // real CRC after the manifest is complete without changing the collection
    // binding, while keeping the resulting package valid for ordinary ZIP
    // readers.
    let crc = crc32(manifest_store);
    let cd_start = eocd.cd_offset as usize;
    let cd_size = eocd.cd_size as usize;
    if cd_start + cd_size > asset.len() {
        return Err(FormatError::Truncated(FMT));
    }

    // New local file header goes where the central directory currently begins.
    let new_local_offset = eocd.cd_offset;

    let mut local = Vec::new();
    local.extend_from_slice(&SIG_LOCAL.to_le_bytes());
    local.extend_from_slice(&20u16.to_le_bytes()); // version needed
    local.extend_from_slice(&0u16.to_le_bytes()); // flags
    local.extend_from_slice(&METHOD_STORED.to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes()); // mod time
    local.extend_from_slice(&0u16.to_le_bytes()); // mod date
    local.extend_from_slice(&crc.to_le_bytes());
    local.extend_from_slice(&size.to_le_bytes()); // comp size
    local.extend_from_slice(&size.to_le_bytes()); // uncomp size
    local.extend_from_slice(&(ENTRY_NAME.len() as u16).to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes()); // extra len
    local.extend_from_slice(ENTRY_NAME);
    local.extend_from_slice(manifest_store);

    let mut central = Vec::new();
    central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
    central.extend_from_slice(&20u16.to_le_bytes()); // version made by
    central.extend_from_slice(&20u16.to_le_bytes()); // version needed
    central.extend_from_slice(&0u16.to_le_bytes()); // flags
    central.extend_from_slice(&METHOD_STORED.to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes()); // mod time
    central.extend_from_slice(&0u16.to_le_bytes()); // mod date
    central.extend_from_slice(&crc.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&(ENTRY_NAME.len() as u16).to_le_bytes());
    central.extend_from_slice(&0u16.to_le_bytes()); // extra len
    central.extend_from_slice(&0u16.to_le_bytes()); // comment len
    central.extend_from_slice(&0u16.to_le_bytes()); // disk start
    central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    central.extend_from_slice(&new_local_offset.to_le_bytes());
    central.extend_from_slice(ENTRY_NAME);

    let new_cd_offset = new_local_offset as usize + local.len();
    let new_cd_size = cd_size + central.len();
    let new_total = eocd.total_entries + 1;

    let mut out = Vec::with_capacity(asset.len() + local.len() + central.len() + 22);
    // Local entries up to where the old central directory started.
    out.extend_from_slice(&asset[..cd_start]);
    // New local entry.
    out.extend_from_slice(&local);
    // Old central directory, then the new central header.
    out.extend_from_slice(&asset[cd_start..cd_start + cd_size]);
    out.extend_from_slice(&central);
    // Fresh EOCD.
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&new_total.to_le_bytes()); // entries this disk
    out.extend_from_slice(&new_total.to_le_bytes()); // total entries
    out.extend_from_slice(&(new_cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(new_cd_offset as u32).to_le_bytes());
    // Comment length, then any existing archive comment.
    let comment_off = eocd.eocd_offset + 22;
    let comment = &asset[comment_off..];
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;
    use crate::util::crc32;

    /// Build a tiny ZIP with one stored entry named `mimetype`.
    fn tiny_zip() -> Vec<u8> {
        let name = b"mimetype";
        let content = b"application/epub+zip";
        let crc = crc32(content);
        let size = content.len() as u32;

        let mut local = Vec::new();
        local.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&METHOD_STORED.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(content);

        let cd_offset = local.len() as u32;
        let mut central = Vec::new();
        central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&METHOD_STORED.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes()); // local offset 0
        central.extend_from_slice(name);

        let cd_size = central.len() as u32;
        let mut v = local;
        v.extend_from_slice(&central);
        v.extend_from_slice(&SIG_EOCD.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&cd_size.to_le_bytes());
        v.extend_from_slice(&cd_offset.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first = embed(&tiny_zip(), b"FIRST-manifest-store").unwrap();
        let second = embed(&first, b"SECOND-manifest-store").unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(&b"SECOND-manifest-store"[..])
        );
        let names = zip_entry_names(&second).unwrap();
        let c2pa_count = names.iter().filter(|n| n.as_bytes() == ENTRY_NAME).count();
        assert_eq!(c2pa_count, 1, "re-embed must leave exactly one C2PA entry");
        // The unrelated pre-existing entry must survive both re-signs.
        assert!(names.iter().any(|n| n == "mimetype"));
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_zip(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn preexisting_entry_still_present() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_zip(), &store).unwrap();
        let eocd = find_eocd(&embedded).unwrap();
        assert_eq!(eocd.total_entries, 2);
        assert!(find_cd_entry(&embedded, &eocd, b"mimetype")
            .unwrap()
            .is_some());
    }

    #[test]
    fn manifest_crc_is_valid_and_omitted_from_cd_hash() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_zip(), &store).unwrap();
        let eocd = find_eocd(&embedded).unwrap();
        let entry = find_cd_entry(&embedded, &eocd, ENTRY_NAME)
            .unwrap()
            .expect("manifest entry");
        let expected_crc = crc32(&store);
        assert_eq!(
            le_u32(&embedded, entry.local_offset as usize + 14),
            Some(expected_crc)
        );

        let central_name = embedded[eocd.cd_offset as usize..eocd.eocd_offset]
            .windows(ENTRY_NAME.len())
            .position(|candidate| candidate == ENTRY_NAME)
            .map(|offset| eocd.cd_offset as usize + offset)
            .expect("manifest central-directory name");
        let central_header = central_name - 46;
        assert_eq!(le_u32(&embedded, central_header + 16), Some(expected_crc));

        let joined = |data: &[u8]| {
            zip_central_directory_hash_parts(data)
                .unwrap()
                .into_iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
        };
        let expected_input = joined(&embedded);
        let mut changed_crc = embedded.clone();
        changed_crc[central_header + 16..central_header + 20]
            .copy_from_slice(&expected_crc.wrapping_add(1).to_le_bytes());
        assert_eq!(joined(&changed_crc), expected_input);

        let mut changed_size = embedded.clone();
        changed_size[central_header + 20] ^= 1;
        assert_ne!(joined(&changed_size), expected_input);
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_zip()).unwrap(), None);
    }

    #[test]
    fn rejects_non_zip() {
        assert!(extract(b"not a zip file at all really").is_err());
    }
}
