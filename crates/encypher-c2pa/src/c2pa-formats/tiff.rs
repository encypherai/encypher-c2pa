// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! TIFF / BigTIFF / DNG: JUMBF in IFD tag `0xCD41` (52545).
//!
//! A TIFF is a header (`II`/`MM` byte order, magic `42`, offset to the first
//! IFD) followed by a chain of Image File Directories. BigTIFF (magic `43`)
//! keeps that shape at wider fields: 8-byte entry counts, 20-byte entries and
//! 8-byte offsets. Every width the container fixes is taken from [`Tiff`], so
//! one reader serves both generations.
//!
//! C2PA stores the manifest store in an IFD entry with tag `0xCD41` and tag
//! type `UNDEFINED` (7); the entry value is the JUMBF bytes, held inline when
//! they fit the value field (4 bytes classic, 8 bytes BigTIFF) and otherwise
//! addressed by offset.
//!
//! Both conformant placements are read. C2PA 2.2 A.3.5 puts the manifest store
//! in "the last IFD, the IFD immediately preceding the end of the file", as its
//! only entry; 2.4 A.3.6 keeps that for a multi-page asset and also allows a
//! single-page TIFF to carry the entry inside its one main IFD.
//! [`placement_error`] is what holds a conformance-mode caller to that.
//!
//! Reading is hostile-input work: the chain, the entry tables and every value
//! span come from the asset. Offsets are resolved with checked arithmetic, a
//! chain may not revisit or overlap an IFD it has already read, and both its
//! length and the directory bytes it may read are bounded.

use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};
use std::collections::BTreeMap;

const FMT: AssetFormat = AssetFormat::Tiff;
const TAG_C2PA: u16 = 0xCD41;
/// C2PA 2.4 A.3.6: the C2PA IFD entry is stored "with a tag type of 7".
const TYPE_UNDEFINED: u16 = 7;
/// Bound on how many IFDs one walk will read. Real assets use a handful (one
/// per page); the cap only exists so a doctored chain cannot make the walk
/// unbounded once the visited-span map has ruled out cycles.
const MAX_IFD_CHAIN: usize = 1024;
/// Cumulative bound on the IFD entry-table bytes one walk will read (64 MiB).
///
/// [`MAX_IFD_CHAIN`] bounds how many IFDs a walk reads, not how large each one
/// is: a classic IFD may declare 65535 entries (768 KiB of table) and a BigTIFF
/// one far more. The budget is charged from the DECLARED table size before the
/// table is read, so an oversized directory is refused up front. Real assets
/// spend kilobytes here.
const MAX_IFD_TABLE_BYTES: u64 = 64 * 1024 * 1024;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// Which TIFF container generation an asset uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// Classic TIFF (magic 42): 2-byte entry counts, 12-byte entries, 4-byte
    /// offsets, values up to 4 bytes stored inline.
    Classic,
    /// BigTIFF (magic 43): 8-byte entry counts, 20-byte entries, 8-byte
    /// offsets, values up to 8 bytes stored inline.
    Big,
}

/// Byte order and field widths for one parsed TIFF header.
#[derive(Clone, Copy, Debug)]
struct Tiff {
    little: bool,
    variant: Variant,
    first_ifd: u64,
}

impl Tiff {
    /// Fixed-size header length. No IFD may start inside it.
    fn header_len(self) -> u64 {
        match self.variant {
            Variant::Classic => 8,
            Variant::Big => 16,
        }
    }

    /// Width of an IFD's entry-count field.
    fn count_len(self) -> usize {
        match self.variant {
            Variant::Classic => 2,
            Variant::Big => 8,
        }
    }

    /// Width of one IFD entry.
    fn entry_len(self) -> usize {
        match self.variant {
            Variant::Classic => 12,
            Variant::Big => 20,
        }
    }

    /// Width of a next-IFD pointer, of an entry's value-count field, and of an
    /// entry's value/offset field. All three are the variant's offset width.
    fn offset_len(self) -> usize {
        match self.variant {
            Variant::Classic => 4,
            Variant::Big => 8,
        }
    }

    fn u16_at(self, bytes: &[u8], at: usize) -> Option<u16> {
        let window: [u8; 2] = bytes.get(at..)?.get(..2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(window)
        } else {
            u16::from_be_bytes(window)
        })
    }

    /// Read an offset-width field (4 bytes classic, 8 bytes BigTIFF).
    fn offset_at(self, bytes: &[u8], at: usize) -> Option<u64> {
        let window = bytes.get(at..)?.get(..self.offset_len())?;
        Some(match self.variant {
            Variant::Classic => {
                let narrow: [u8; 4] = window.try_into().ok()?;
                u64::from(if self.little {
                    u32::from_le_bytes(narrow)
                } else {
                    u32::from_be_bytes(narrow)
                })
            }
            Variant::Big => {
                let wide: [u8; 8] = window.try_into().ok()?;
                if self.little {
                    u64::from_le_bytes(wide)
                } else {
                    u64::from_be_bytes(wide)
                }
            }
        })
    }

    /// Read an IFD's entry-count field.
    fn count_at(self, bytes: &[u8], at: usize) -> Option<u64> {
        match self.variant {
            Variant::Classic => self.u16_at(bytes, at).map(u64::from),
            Variant::Big => self.offset_at(bytes, at),
        }
    }
}

/// Parse the fixed header of a classic TIFF or a BigTIFF.
///
/// A BigTIFF declares its offset width and a reserved zero field; any other
/// pair is a container this reader must not guess at.
fn read_header(data: &[u8]) -> Result<Tiff, FormatError> {
    let prefix = data.get(..8).ok_or(FormatError::Truncated(FMT))?;
    let little = match &prefix[0..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Err(invalid("bad byte-order mark")),
    };
    let classic = Tiff {
        little,
        variant: Variant::Classic,
        first_ifd: 0,
    };
    match classic
        .u16_at(prefix, 2)
        .ok_or(FormatError::Truncated(FMT))?
    {
        42 => Ok(Tiff {
            first_ifd: classic
                .offset_at(prefix, 4)
                .ok_or(FormatError::Truncated(FMT))?,
            ..classic
        }),
        43 => {
            let header = data.get(..16).ok_or(FormatError::Truncated(FMT))?;
            if classic.u16_at(header, 4) != Some(8) {
                return Err(invalid("unsupported BigTIFF offset width"));
            }
            if classic.u16_at(header, 6) != Some(0) {
                return Err(invalid("BigTIFF reserved header field is not zero"));
            }
            let big = Tiff {
                variant: Variant::Big,
                ..classic
            };
            Ok(Tiff {
                first_ifd: big
                    .offset_at(header, 8)
                    .ok_or(FormatError::Truncated(FMT))?,
                ..big
            })
        }
        _ => Err(invalid("bad TIFF magic")),
    }
}

/// One IFD of the main chain: its entry table and its next-IFD pointer.
struct Ifd<'a> {
    /// Number of entries the IFD declares.
    count: usize,
    /// Offset of the first entry.
    entries_start: u64,
    /// The entry table: `count * entry_len` bytes of the asset.
    entries: &'a [u8],
    /// Value of the next-IFD pointer.
    next: u64,
}

impl Ifd<'_> {
    fn entry(&self, t: Tiff, index: usize) -> &[u8] {
        &self.entries[index * t.entry_len()..(index + 1) * t.entry_len()]
    }

    fn tag(&self, t: Tiff, index: usize) -> u16 {
        t.u16_at(self.entry(t, index), 0)
            .expect("walk sized the entry table")
    }
}

/// Walk the main IFD chain once.
///
/// `strict` selects the failure mode each caller needs. The C2PA carrier paths
/// treat a structural problem as a hard error, because a carrier this reader
/// cannot resolve must never be silently ignored. The tolerant mode used for
/// the optional XMP packet stops the walk and keeps what it already reached, so
/// reading an optional tag can never turn an asset into a failure.
///
/// Cycles are caught by a map of visited IFD spans, not by a counter, so a
/// two-IFD loop is refused as a cycle rather than mistaken for a long chain.
/// The same map refuses a chain whose IFDs overlap: two directories of one
/// chain never share bytes, and allowing it would let a doctored asset aim a
/// thousand IFDs at one table region. [`MAX_IFD_CHAIN`] separately bounds
/// acyclic chains and [`MAX_IFD_TABLE_BYTES`] bounds what they may read. An IFD
/// offset pointing inside the fixed header is refused: it cannot be a
/// directory, and following it would let the header be re-read as entry data.
fn walk<'a>(data: &'a [u8], t: Tiff, strict: bool) -> Result<Vec<Ifd<'a>>, FormatError> {
    let mut chain: Vec<Ifd<'a>> = Vec::new();
    let mut state = Walk {
        spans: BTreeMap::new(),
        budget: MAX_IFD_TABLE_BYTES,
    };
    let mut offset = t.first_ifd;
    while offset != 0 {
        match read_ifd(data, t, offset, &mut state) {
            Ok(ifd) => {
                offset = ifd.next;
                chain.push(ifd);
            }
            Err(error) if strict => return Err(error),
            Err(_) => break,
        }
    }
    Ok(chain)
}

fn read_ifd<'a>(
    data: &'a [u8],
    t: Tiff,
    offset: u64,
    state: &mut Walk,
) -> Result<Ifd<'a>, FormatError> {
    if offset < t.header_len() {
        return Err(invalid("TIFF IFD offset points into the header"));
    }
    if state.spans.contains_key(&offset) {
        return Err(invalid("cyclic TIFF IFD chain"));
    }
    if state.spans.len() >= MAX_IFD_CHAIN {
        return Err(invalid("TIFF IFD chain exceeds the supported length"));
    }
    // Every offset below is derived from container fields the asset controls,
    // and `usize` is 32 bits on wasm32, so each step is checked: a wrapped
    // offset would point the walk at bytes it was never given.
    let count_start = usize::try_from(offset).map_err(|_| FormatError::Truncated(FMT))?;
    let count_field = data
        .get(count_start..)
        .and_then(|tail| tail.get(..t.count_len()))
        .ok_or(FormatError::Truncated(FMT))?;
    let count = t
        .count_at(count_field, 0)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(FormatError::Truncated(FMT))?;
    let entries_start = offset
        .checked_add(t.count_len() as u64)
        .ok_or(FormatError::Truncated(FMT))?;
    let entry_bytes = count
        .checked_mul(t.entry_len())
        .ok_or(FormatError::Truncated(FMT))?;
    let table_len = entry_bytes
        .checked_add(t.offset_len())
        .ok_or(FormatError::Truncated(FMT))?;
    let end = entries_start
        .checked_add(table_len as u64)
        .ok_or(FormatError::Truncated(FMT))?;
    let Some(budget) = state.budget.checked_sub(table_len as u64) else {
        return Err(invalid(
            "TIFF IFD chain exceeds the supported directory size",
        ));
    };
    state.budget = budget;
    if state.overlaps(offset, end) {
        return Err(invalid("overlapping TIFF IFD tables"));
    }
    let table_start = usize::try_from(entries_start).map_err(|_| FormatError::Truncated(FMT))?;
    let table = data
        .get(table_start..)
        .and_then(|tail| tail.get(..table_len))
        .ok_or(FormatError::Truncated(FMT))?;
    let next = t
        .offset_at(table, entry_bytes)
        .ok_or(FormatError::Truncated(FMT))?;
    state.spans.insert(offset, end);
    Ok(Ifd {
        count,
        entries_start,
        entries: &table[..entry_bytes],
        next,
    })
}

/// What one chain traversal remembers: the byte span of every IFD it has read,
/// and the entry-table bytes it may still read.
struct Walk {
    spans: BTreeMap<u64, u64>,
    budget: u64,
}

impl Walk {
    /// Does `[start, end)` intersect an IFD this walk already read?
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.spans
            .range(..start)
            .next_back()
            .is_some_and(|(_, prior_end)| *prior_end > start)
            || self
                .spans
                .range(start..)
                .next()
                .is_some_and(|(next_start, _)| *next_start < end)
    }
}

/// Resolve one entry's value span inside the asset.
///
/// The tags this reader resolves (`0xCD41` and XMP) are byte-typed, so the
/// entry's value count is its byte length. A value that fits the entry's value
/// field is stored there; anything longer is addressed by offset.
fn value_span(data: &[u8], t: Tiff, ifd: &Ifd<'_>, index: usize) -> Option<(usize, usize)> {
    let entry = ifd.entry(t, index);
    let length = t.offset_at(entry, 4)?;
    let start = if length <= t.offset_len() as u64 {
        ifd.entries_start
            .checked_add((index as u64).checked_mul(t.entry_len() as u64)?)?
            .checked_add(4 + t.offset_len() as u64)?
    } else {
        t.offset_at(entry, 4 + t.offset_len())?
    };
    if start.checked_add(length)? > data.len() as u64 {
        return None;
    }
    Some((usize::try_from(start).ok()?, usize::try_from(length).ok()?))
}

/// Byte span of the first reachable C2PA manifest store.
///
/// A `0xCD41` entry whose tag type is not `UNDEFINED` is a refusal rather than
/// a carrier: C2PA 2.4 A.3.6 fixes the type, and reading a differently typed
/// entry as bytes would mean this reader and a conformant one disagree about
/// where the manifest store is.
fn manifest_span(data: &[u8]) -> Result<Option<(usize, usize)>, FormatError> {
    let t = read_header(data)?;
    for ifd in walk(data, t, true)? {
        for index in 0..ifd.count {
            if ifd.tag(t, index) != TAG_C2PA {
                continue;
            }
            if t.u16_at(ifd.entry(t, index), 2) != Some(TYPE_UNDEFINED) {
                return Err(invalid(
                    "C2PA TIFF entry has a tag type other than UNDEFINED",
                ));
            }
            return value_span(data, t, &ifd, index)
                .map(Some)
                .ok_or(FormatError::Truncated(FMT));
        }
    }
    Ok(None)
}

/// Extract the manifest store from IFD tag `0xCD41`. Follows the IFD chain.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(manifest_span(data)?.map(|(start, length)| data[start..start + length].to_vec()))
}

/// The XMP packet stored in IFD tag 700, if the asset carries one.
///
/// Discovery is best-effort and total: a malformed IFD chain yields no packet
/// rather than an error, so reading the optional remote-manifest declaration
/// can never change how a well-formed asset validates.
pub(crate) fn xmp_packet(data: &[u8]) -> Option<&[u8]> {
    let t = read_header(data).ok()?;
    for ifd in walk(data, t, false).ok()? {
        for index in 0..ifd.count {
            if ifd.tag(t, index) != crate::c2pa_formats::xmp::TIFF_XMP_TAG {
                continue;
            }
            let (start, length) = value_span(data, t, &ifd, index)?;
            return data.get(start..start + length);
        }
    }
    None
}

/// Is the manifest store where C2PA requires it?
///
/// 2.2 A.3.5 requires the store to be the only entry of the last IFD, "the IFD
/// immediately preceding the end of the file", at any page count. 2.4 A.3.6
/// keeps that for a multi-IFD asset but also allows a TIFF with one main IFD to
/// carry the entry within that IFD. Either way the entry belongs to the last
/// IFD of the main chain, and an asset resolving to more than one C2PA entry is
/// ambiguous.
///
/// The tag-type check the carrier paths apply is deliberately not repeated
/// here: a second entry written with the wrong type is still a second entry,
/// and skipping it would hide it from the multiplicity rule.
pub(crate) fn placement_error(data: &[u8]) -> Result<Option<&'static str>, FormatError> {
    let t = read_header(data)?;
    let chain = walk(data, t, true)?;
    // One element per C2PA entry, holding the index of the IFD carrying it.
    let mut carriers: Vec<usize> = Vec::new();
    for (position, ifd) in chain.iter().enumerate() {
        for index in 0..ifd.count {
            if ifd.tag(t, index) == TAG_C2PA {
                carriers.push(position);
            }
        }
    }
    if carriers.len() > 1 {
        return Ok(Some(
            "TIFF main-IFD chain contains more than one C2PA entry",
        ));
    }
    let Some(&carrier) = carriers.first() else {
        return Ok(None);
    };
    if carrier + 1 != chain.len() {
        return Ok(Some("TIFF C2PA entry is not in the last main IFD"));
    }
    if chain.len() > 1 && chain[carrier].count != 1 {
        return Ok(Some(
            "TIFF C2PA entry is not the only entry in its main IFD",
        ));
    }
    Ok(None)
}

/// The appended manifest-store payload byte span as a single exclusion.
///
/// Mirrors [`extract`]: walks the IFD chain to the `0xCD41` entry and excludes
/// exactly the manifest *value* bytes it points at, whether those are an
/// out-of-line payload or the inline value field of a tiny manifest. The IFD
/// entry's tag/type/count/offset and the carrier IFD itself are deliberately
/// NOT excluded: their bytes depend only on the manifest's *length* and
/// *position* (both fixed across the two-pass signing flow, where the
/// placeholder has the final size), never on its content, so the
/// `c2pa.hash.data` digest legitimately covers them. Honors both byte orders
/// and both container generations. Returns an empty vec if no manifest is
/// present.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(
        manifest_span(data)?.map_or_else(Vec::new, |(start, length)| {
            vec![DataHashExclusion { start, length }]
        }),
    )
}

/// Embed `manifest_store` into a classic TIFF/DNG using an append-new-IFD
/// strategy.
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
/// one elsewhere in the chain is left in place. BigTIFF is read but never
/// written: this build is verification-only and the writer exists for the
/// round-trip tests alone.
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let t = read_header(asset)?;
    if t.variant != Variant::Classic {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "BigTIFF is read-only in this build",
        });
    }
    let chain = walk(asset, t, true)?;
    let mut entries: Vec<[u8; 12]> = Vec::new();
    let mut next_ifd: u32 = 0;
    if let Some(first) = chain.first() {
        for index in 0..first.count {
            let entry = first.entry(t, index);
            if t.u16_at(entry, 0) == Some(TAG_C2PA) {
                continue;
            }
            let mut row = [0u8; 12];
            row.copy_from_slice(entry);
            entries.push(row);
        }
        next_ifd = u32::try_from(first.next).expect("classic next-IFD pointer is 32 bits");
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
    write_u16(&mut rec, t.little, TAG_C2PA);
    write_u16(&mut rec, t.little, TYPE_UNDEFINED);
    write_u32(&mut rec, t.little, manifest_store.len() as u32);
    if manifest_store.len() <= 4 {
        // Inline value: raw bytes, left-justified, zero-padded to 4 bytes.
        let mut val = [0u8; 4];
        val[..manifest_store.len()].copy_from_slice(manifest_store);
        rec.extend_from_slice(&val);
    } else {
        write_u32(&mut rec, t.little, manifest_off as u32);
    }
    let mut c2pa = [0u8; 12];
    c2pa.copy_from_slice(&rec);
    entries.push(c2pa);

    // TIFF requires IFD entries sorted by ascending tag.
    entries.sort_by_key(|row| t.u16_at(row, 0).expect("entry row is 12 bytes"));

    write_u16(&mut out, t.little, entries.len() as u16);
    for row in &entries {
        out.extend_from_slice(row);
    }
    write_u32(&mut out, t.little, next_ifd);

    // Repoint the header's first-IFD offset at the appended IFD.
    let pointer = new_ifd_off as u32;
    out[4..8].copy_from_slice(&if t.little {
        pointer.to_le_bytes()
    } else {
        pointer.to_be_bytes()
    });
    Ok(out)
}

#[cfg(test)]
fn write_u16(out: &mut Vec<u8>, little: bool, x: u16) {
    out.extend_from_slice(&if little {
        x.to_le_bytes()
    } else {
        x.to_be_bytes()
    });
}

#[cfg(test)]
fn write_u32(out: &mut Vec<u8>, little: bool, x: u32) {
    out.extend_from_slice(&if little {
        x.to_le_bytes()
    } else {
        x.to_be_bytes()
    });
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

    /// A BigTIFF entry row: tag, type, 8-byte count, 8-byte value field.
    ///
    /// `value` is the raw value field, already the container's 8 bytes, so a
    /// caller can write an offset or an inline payload with one helper.
    fn big_entry(little: bool, tag: u16, tag_type: u16, count: u64, value: [u8; 8]) -> Vec<u8> {
        let mut row = Vec::with_capacity(20);
        write_u16(&mut row, little, tag);
        write_u16(&mut row, little, tag_type);
        row.extend_from_slice(&if little {
            count.to_le_bytes()
        } else {
            count.to_be_bytes()
        });
        row.extend_from_slice(&value);
        row
    }

    fn big_offset(little: bool, value: u64) -> [u8; 8] {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }

    /// A BigTIFF IFD: entry count, the rows verbatim, then the next-IFD
    /// pointer.
    fn big_ifd(little: bool, rows: &[Vec<u8>], next: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&big_offset(little, rows.len() as u64));
        for row in rows {
            out.extend_from_slice(row);
        }
        out.extend_from_slice(&big_offset(little, next));
        out
    }

    fn big_header(little: bool, first_ifd: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(if little { b"II" } else { b"MM" });
        write_u16(&mut out, little, 43);
        write_u16(&mut out, little, 8); // offset bytesize
        write_u16(&mut out, little, 0); // reserved
        out.extend_from_slice(&big_offset(little, first_ifd));
        out
    }

    /// C2PA 2.4 A.3.6 single-page BigTIFF: one main IFD carrying an image tag
    /// and the C2PA entry, with the manifest store appended after it.
    ///
    /// Returns the asset and the manifest's byte span.
    fn bigtiff_single_page(little: bool, manifest: &[u8]) -> (Vec<u8>, usize, usize) {
        let description = b"hello-bigtiff-description";
        // header + count + two entries + next-IFD pointer.
        let ifd_len = 8 + 2 * 20 + 8;
        let description_off = 16 + ifd_len;
        let manifest_off = description_off + description.len();
        let rows = vec![
            big_entry(
                little,
                0x010E, // ImageDescription
                2,      // ASCII
                description.len() as u64,
                big_offset(little, description_off as u64),
            ),
            big_entry(
                little,
                TAG_C2PA,
                TYPE_UNDEFINED,
                manifest.len() as u64,
                big_offset(little, manifest_off as u64),
            ),
        ];
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &rows, 0));
        assert_eq!(asset.len(), description_off);
        asset.extend_from_slice(description);
        asset.extend_from_slice(manifest);
        (asset, manifest_off, manifest.len())
    }

    /// C2PA 2.2 A.3.5 / 2.4 A.3.6 multi-page BigTIFF: two page IFDs followed by
    /// a dedicated last IFD whose only entry is the C2PA entry.
    fn bigtiff_multi_page(little: bool, manifest: &[u8]) -> (Vec<u8>, usize, usize) {
        let page_len = 8 + 20 + 8; // count + one entry + next-IFD pointer
        let first_page = 16u64;
        let second_page = first_page + page_len as u64;
        let manifest_off = second_page as usize + page_len;
        let carrier_off = manifest_off + manifest.len();
        let page_row = |little: bool| {
            big_entry(
                little,
                0x0100, // ImageWidth
                3,      // SHORT
                1,
                big_offset(little, 1),
            )
        };
        let mut asset = big_header(little, first_page);
        asset.extend_from_slice(&big_ifd(little, &[page_row(little)], second_page));
        asset.extend_from_slice(&big_ifd(little, &[page_row(little)], carrier_off as u64));
        assert_eq!(asset.len(), manifest_off);
        asset.extend_from_slice(manifest);
        let carrier_row = big_entry(
            little,
            TAG_C2PA,
            TYPE_UNDEFINED,
            manifest.len() as u64,
            big_offset(little, manifest_off as u64),
        );
        asset.extend_from_slice(&big_ifd(little, &[carrier_row], 0));
        (asset, manifest_off, manifest.len())
    }

    #[test]
    fn extract_tagged_manifest() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let asset = tiff_with_manifest(&store);
        assert_eq!(extract(&asset).unwrap().as_deref(), Some(store.as_slice()));
        assert_eq!(placement_error(&asset).unwrap(), None);
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
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (asset, _) = tiff_with_desc(true);
        let out = embed(&asset, &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_round_trips_be() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (asset, _) = tiff_with_desc(false);
        let out = embed(&asset, &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_into_bare_round_trips() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let out = embed(&bare_tiff(), &store).unwrap();
        assert_eq!(extract(&out).unwrap().as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn embed_preserves_existing_entries() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (asset, desc) = tiff_with_desc(true);
        let out = embed(&asset, &store).unwrap();
        let t = read_header(&out).unwrap();
        let chain = walk(&out, t, true).unwrap();
        let ifd = chain.first().expect("one IFD");
        let mut found = None;
        for index in 0..ifd.count {
            if ifd.tag(t, index) == 0x010E {
                let (start, length) = value_span(&out, t, ifd, index).expect("description span");
                found = Some(out[start..start + length].to_vec());
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
        let t = read_header(&second).unwrap();
        let chain = walk(&second, t, true).unwrap();
        let ifd = chain.first().expect("one IFD");
        let c2pa = (0..ifd.count)
            .filter(|&index| ifd.tag(t, index) == TAG_C2PA)
            .count();
        assert_eq!(c2pa, 1);
    }

    #[test]
    fn strict_placement_requires_manifest_in_last_main_ifd() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let mut asset = tiff_with_manifest(&store);
        let second_ifd = asset.len() as u32;
        asset[22..26].copy_from_slice(&second_ifd.to_le_bytes());
        asset.extend_from_slice(&0u16.to_le_bytes());
        asset.extend_from_slice(&0u32.to_le_bytes());
        assert!(placement_error(&asset).unwrap().is_some());
    }

    #[test]
    fn rejects_non_tiff() {
        assert!(extract(b"\x00\x01\x02\x03\x04\x05\x06\x07").is_err());
    }

    /// C2PA 2.4 A.3.6 allows a single-page asset to carry the entry inside its
    /// one main IFD. Both byte orders read the same store.
    #[test]
    fn reads_a_single_page_bigtiff_in_either_byte_order() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        for little in [true, false] {
            let (asset, start, length) = bigtiff_single_page(little, &store);
            assert_eq!(
                extract(&asset).unwrap().as_deref(),
                Some(store.as_slice()),
                "little={little}"
            );
            assert_eq!(placement_error(&asset).unwrap(), None, "little={little}");
            assert_eq!(
                exclusions(&asset).unwrap(),
                vec![DataHashExclusion { start, length }],
                "little={little}"
            );
        }
    }

    /// 2.2 A.3.5 and multi-page 2.4 A.3.6: a dedicated last IFD holding only
    /// the C2PA entry.
    #[test]
    fn reads_a_multi_page_bigtiff_in_either_byte_order() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        for little in [true, false] {
            let (asset, start, length) = bigtiff_multi_page(little, &store);
            assert_eq!(
                extract(&asset).unwrap().as_deref(),
                Some(store.as_slice()),
                "little={little}"
            );
            assert_eq!(placement_error(&asset).unwrap(), None, "little={little}");
            assert_eq!(
                exclusions(&asset).unwrap(),
                vec![DataHashExclusion { start, length }],
                "little={little}"
            );
        }
    }

    /// A BigTIFF manifest short enough to sit in the 8-byte value field is read
    /// from the entry itself, and excluded there.
    #[test]
    fn reads_an_inline_bigtiff_value() {
        let manifest = b"12345678";
        let little = true;
        let mut value = [0u8; 8];
        value.copy_from_slice(manifest);
        let row = big_entry(
            little,
            TAG_C2PA,
            TYPE_UNDEFINED,
            manifest.len() as u64,
            value,
        );
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &[row], 0));
        assert_eq!(extract(&asset).unwrap().as_deref(), Some(&manifest[..]));
        // count field (8) + tag/type (4) inside the entry, entries start at 24.
        assert_eq!(
            exclusions(&asset).unwrap(),
            vec![DataHashExclusion {
                start: 24 + 12,
                length: 8
            }]
        );
    }

    /// C2PA 2.4 A.3.6 fixes the tag type at `UNDEFINED`. A differently typed
    /// `0xCD41` entry is refused rather than read as a manifest store.
    #[test]
    fn refuses_a_bigtiff_c2pa_entry_with_the_wrong_tag_type() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (mut asset, _, _) = bigtiff_single_page(true, &store);
        // Second entry of the single main IFD: header 16 + count 8 + one row.
        let type_field = 16 + 8 + 20 + 2;
        asset[type_field..type_field + 2].copy_from_slice(&1u16.to_le_bytes()); // BYTE
        assert!(extract(&asset).is_err());
        assert!(exclusions(&asset).is_err());
    }

    /// The C2PA entry in a page IFD rather than the last one is the layout 2.2
    /// A.3.5 forbids.
    #[test]
    fn refuses_a_bigtiff_carrier_outside_the_last_ifd() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let little = true;
        let carrier_row = big_entry(
            little,
            TAG_C2PA,
            TYPE_UNDEFINED,
            store.len() as u64,
            big_offset(little, (16 + 2 * (8 + 20 + 8)) as u64),
        );
        let page_row = big_entry(little, 0x0100, 3, 1, big_offset(little, 1));
        let second_page = 16 + (8 + 20 + 8) as u64;
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &[carrier_row], second_page));
        asset.extend_from_slice(&big_ifd(little, &[page_row], 0));
        asset.extend_from_slice(&store);
        assert_eq!(
            placement_error(&asset).unwrap(),
            Some("TIFF C2PA entry is not in the last main IFD")
        );
    }

    /// A multi-page asset must use a dedicated carrier IFD, so a last IFD that
    /// also holds image tags is refused.
    #[test]
    fn refuses_a_shared_last_ifd_in_a_multi_page_bigtiff() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let little = true;
        let page_len = 8 + 20 + 8;
        let last_len = 8 + 2 * 20 + 8;
        let manifest_off = 16 + page_len + last_len;
        let page_row = big_entry(little, 0x0100, 3, 1, big_offset(little, 1));
        let last_rows = vec![
            big_entry(little, 0x0100, 3, 1, big_offset(little, 1)),
            big_entry(
                little,
                TAG_C2PA,
                TYPE_UNDEFINED,
                store.len() as u64,
                big_offset(little, manifest_off as u64),
            ),
        ];
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &[page_row], (16 + page_len) as u64));
        asset.extend_from_slice(&big_ifd(little, &last_rows, 0));
        asset.extend_from_slice(&store);
        assert_eq!(
            placement_error(&asset).unwrap(),
            Some("TIFF C2PA entry is not the only entry in its main IFD")
        );
    }

    #[test]
    fn refuses_a_bigtiff_header_this_reader_cannot_address() {
        let little = true;
        let mut wrong_width = big_header(little, 16);
        wrong_width[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(
            read_header(&wrong_width).unwrap_err(),
            invalid("unsupported BigTIFF offset width")
        );

        let mut reserved = big_header(little, 16);
        reserved[6..8].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            read_header(&reserved).unwrap_err(),
            invalid("BigTIFF reserved header field is not zero")
        );

        let truncated = &big_header(little, 16)[..12];
        assert_eq!(
            read_header(truncated).unwrap_err(),
            FormatError::Truncated(FMT)
        );
    }

    /// A BigTIFF header is 16 bytes, so an IFD at offset 8 overlaps it. Reading
    /// the header back as entry data is what the bound prevents.
    #[test]
    fn refuses_a_bigtiff_ifd_inside_the_header() {
        let mut asset = big_header(true, 8);
        asset.extend_from_slice(&big_ifd(true, &[], 0));
        assert_eq!(
            extract(&asset).unwrap_err(),
            invalid("TIFF IFD offset points into the header")
        );
    }

    #[test]
    fn refuses_a_cyclic_bigtiff_chain() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let little = true;
        let page_row = big_entry(little, 0x0100, 3, 1, big_offset(little, 1));
        let second = 16 + (8 + 20 + 8) as u64;
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &[page_row.clone()], second));
        // The second IFD points back at the first.
        asset.extend_from_slice(&big_ifd(little, &[page_row], 16));
        asset.extend_from_slice(&store);
        assert_eq!(
            extract(&asset).unwrap_err(),
            invalid("cyclic TIFF IFD chain")
        );
    }

    /// Two IFDs of one chain never share bytes. An overlapping pair is the
    /// shape that lets one table region be walked many times.
    #[test]
    fn refuses_overlapping_bigtiff_ifds() {
        let little = true;
        let page_row = big_entry(little, 0x0100, 3, 1, big_offset(little, 1));
        // One IFD spanning 16..52: count 16..24, its entry row 24..44, its
        // next-IFD pointer 44..52. Pointing that pointer at itself makes the
        // second IFD start inside the first one's own bytes.
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_ifd(little, &[page_row], 44));
        assert_eq!(asset.len(), 52);
        assert_eq!(
            extract(&asset).unwrap_err(),
            invalid("overlapping TIFF IFD tables")
        );
    }

    /// A BigTIFF entry count is 64 bits wide, so a doctored one can ask for
    /// more table than any file holds. It must be refused, never allocated.
    #[test]
    fn refuses_an_oversized_bigtiff_entry_count() {
        let little = true;
        let mut asset = big_header(little, 16);
        asset.extend_from_slice(&big_offset(little, u64::MAX));
        asset.extend_from_slice(&[0u8; 64]);
        assert!(extract(&asset).is_err());

        let mut budget = big_header(little, 16);
        // Under the arithmetic ceiling but far over the table budget.
        budget.extend_from_slice(&big_offset(little, 1 << 40));
        budget.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            extract(&budget).unwrap_err(),
            invalid("TIFF IFD chain exceeds the supported directory size")
        );
    }

    #[test]
    fn refuses_a_truncated_bigtiff_ifd_and_value() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (asset, _, _) = bigtiff_single_page(true, &store);

        let short_table = &asset[..30];
        assert_eq!(
            extract(short_table).unwrap_err(),
            FormatError::Truncated(FMT)
        );

        let short_value = &asset[..asset.len() - 1];
        assert_eq!(
            extract(short_value).unwrap_err(),
            FormatError::Truncated(FMT)
        );
    }

    /// BigTIFF is read, never written: this build verifies only.
    #[test]
    fn refuses_to_write_a_bigtiff() {
        let store = crate::c2pa_formats::tests::dummy_manifest_store();
        let (asset, _, _) = bigtiff_single_page(true, &store);
        assert_eq!(
            embed(&asset, &store).unwrap_err(),
            FormatError::UnsupportedVariant {
                format: FMT,
                detail: "BigTIFF is read-only in this build",
            }
        );
    }
}
