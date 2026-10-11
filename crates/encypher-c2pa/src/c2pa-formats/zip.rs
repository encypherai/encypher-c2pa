// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! ZIP/ZIP64 verifier for C2PA collection bindings.
//!
//! The manifest store is the stored, unencrypted entry
//! `META-INF/content_credential.c2pa`. Reader geometry supports ZIP32 and
//! single-disk ZIP64, including ZIP64 extended-information fields and 64-bit
//! data descriptors. The public crate has no production writer.

use std::collections::HashMap;

use crate::c2pa_formats::util::le_u32;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Zip;
const ENTRY_NAME: &[u8] = b"META-INF/content_credential.c2pa";
const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;
const SIG_DESCRIPTOR: u32 = 0x0807_4b50;
const METHOD_STORED: u16 = 0;
const MAX_ZIP_ENTRIES: usize = 1 << 20;

#[cfg(test)]
thread_local! {
    static CENTRAL_ENTRIES_PARSED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn le16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le64(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

struct Eocd {
    total_entries: usize,
    cd_size: usize,
    cd_offset: usize,
    /// First byte after the central directory (ZIP64 EOCD or classic EOCD).
    directory_end: usize,
    eocd_offset: usize,
}

fn usize64(value: u64, detail: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::UnsupportedVariant {
        format: FMT,
        detail,
    })
}

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
            let disk = le16(data, pos + 4).ok_or(FormatError::Truncated(FMT))?;
            let cd_disk = le16(data, pos + 6).ok_or(FormatError::Truncated(FMT))?;
            let entries_disk = le16(data, pos + 8).ok_or(FormatError::Truncated(FMT))?;
            let entries = le16(data, pos + 10).ok_or(FormatError::Truncated(FMT))?;
            let cd_size = le_u32(data, pos + 12).ok_or(FormatError::Truncated(FMT))?;
            let cd_offset = le_u32(data, pos + 16).ok_or(FormatError::Truncated(FMT))?;
            let comment_len = le16(data, pos + 20).ok_or(FormatError::Truncated(FMT))? as usize;
            if pos.checked_add(22 + comment_len) != Some(data.len()) {
                if pos == 0 || pos <= max_back {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "no EOCD record",
                    });
                }
                pos -= 1;
                continue;
            }
            let has_zip64_locator = pos
                .checked_sub(20)
                .is_some_and(|at| le_u32(data, at) == Some(SIG_ZIP64_LOCATOR));
            let zip64 = has_zip64_locator
                || entries == u16::MAX
                || entries_disk == u16::MAX
                || cd_size == u32::MAX
                || cd_offset == u32::MAX;
            if !zip64 {
                if disk != 0 || cd_disk != 0 || entries_disk != entries {
                    return Err(FormatError::UnsupportedVariant {
                        format: FMT,
                        detail: "multi-disk ZIP archive",
                    });
                }
                return Ok(Eocd {
                    total_entries: entries as usize,
                    cd_size: cd_size as usize,
                    cd_offset: cd_offset as usize,
                    directory_end: pos,
                    eocd_offset: pos,
                });
            }
            let locator = pos.checked_sub(20).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "ZIP64 EOCD locator is missing",
            })?;
            if le_u32(data, locator) != Some(SIG_ZIP64_LOCATOR)
                || le_u32(data, locator + 4) != Some(0)
                || le_u32(data, locator + 16) != Some(1)
            {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "multi-disk or malformed ZIP64 archive",
                });
            }
            let zip64_offset = usize64(
                le64(data, locator + 8).ok_or(FormatError::Truncated(FMT))?,
                "ZIP64 EOCD offset exceeds address space",
            )?;
            if le_u32(data, zip64_offset) != Some(SIG_ZIP64_EOCD) {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "ZIP64 EOCD record is missing",
                });
            }
            let record_size = usize64(
                le64(data, zip64_offset + 4).ok_or(FormatError::Truncated(FMT))?,
                "ZIP64 EOCD record is too large",
            )?;
            if record_size < 44
                || zip64_offset.checked_add(12 + record_size) != Some(locator)
                || le_u32(data, zip64_offset + 16) != Some(0)
                || le_u32(data, zip64_offset + 20) != Some(0)
            {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "malformed ZIP64 EOCD record",
                });
            }
            let entries_disk64 =
                le64(data, zip64_offset + 24).ok_or(FormatError::Truncated(FMT))?;
            let entries64 = le64(data, zip64_offset + 32).ok_or(FormatError::Truncated(FMT))?;
            if entries_disk64 != entries64 {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "multi-disk ZIP64 archive",
                });
            }
            let total_entries = usize64(entries64, "ZIP64 entry count exceeds address space")?;
            if total_entries > MAX_ZIP_ENTRIES {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "ZIP archive has too many entries",
                });
            }
            let cd_size = usize64(
                le64(data, zip64_offset + 40).ok_or(FormatError::Truncated(FMT))?,
                "ZIP64 central directory is too large",
            )?;
            let cd_offset = usize64(
                le64(data, zip64_offset + 48).ok_or(FormatError::Truncated(FMT))?,
                "ZIP64 central directory offset exceeds address space",
            )?;
            return Ok(Eocd {
                total_entries,
                cd_size,
                cd_offset,
                directory_end: zip64_offset,
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

fn central_directory_bounds(data: &[u8], eocd: &Eocd) -> Result<(usize, usize), FormatError> {
    let start = eocd.cd_offset;
    let end = start
        .checked_add(eocd.cd_size)
        .filter(|&end| end == eocd.directory_end && end <= data.len())
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "central directory bounds do not match EOCD",
        })?;
    Ok((start, end))
}

#[derive(Clone, Copy)]
pub struct ZipMember<'a> {
    raw_name: &'a [u8],
    method: u16,
    flags: u16,
    crc: u32,
    comp_size: u64,
    uncomp_size: u64,
    zip64_sizes: bool,
    data_span: (usize, usize),
    hash_span: (usize, usize),
    local_span: (usize, usize),
    central_span: (usize, usize),
}

impl<'a> ZipMember<'a> {
    pub fn raw_name(&self) -> &'a [u8] {
        self.raw_name
    }

    pub fn hash_span(&self) -> (usize, usize) {
        self.hash_span
    }

    pub fn local_span(&self) -> (usize, usize) {
        self.local_span
    }
}

/// A bounded, one-pass index of a standard ZIP central directory.
pub struct ZipIndex<'a> {
    members: Vec<ZipMember<'a>>,
    by_name: HashMap<&'a [u8], usize>,
    central_hash_parts: Vec<&'a [u8]>,
}

impl<'a> ZipIndex<'a> {
    pub fn members(&self) -> &[ZipMember<'a>] {
        &self.members
    }

    pub fn get(&self, raw_name: &[u8]) -> Option<&ZipMember<'a>> {
        self.by_name
            .get(raw_name)
            .map(|&index| &self.members[index])
    }

    pub fn central_directory_hash_parts(&self) -> &[&'a [u8]] {
        &self.central_hash_parts
    }
}

fn local_data_span(
    data: &[u8],
    eocd: &Eocd,
    method_size_offset: (u16, u16, u64, u64),
    expected_name: &[u8],
) -> Result<(usize, usize), FormatError> {
    let (method, flags, comp_size, local_offset) = method_size_offset;
    let lh = usize64(
        local_offset,
        "ZIP64 local-header offset exceeds address space",
    )?;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    if le16(data, lh + 6) != Some(flags) || le16(data, lh + 8) != Some(method) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "ZIP local and central flags or compression method disagree",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let name_start = lh
        .checked_add(30)
        .filter(|&offset| offset <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let name_end = name_start
        .checked_add(name_len)
        .filter(|&offset| offset <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    if data.get(name_start..name_end) != Some(expected_name) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "central directory name disagrees with local header",
        });
    }
    let data_start = name_end
        .checked_add(extra_len)
        .filter(|&offset| offset <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let comp_size = usize64(comp_size, "ZIP64 member is too large")?;
    let data_end = data_start
        .checked_add(comp_size)
        .filter(|&offset| offset <= eocd.cd_offset)
        .ok_or(FormatError::Truncated(FMT))?;
    Ok((data_start, data_end))
}

fn zip64_central_values(
    extra: &[u8],
    uncomp32: u32,
    comp32: u32,
    offset32: u32,
    disk32: u16,
) -> Result<(u64, u64, u64, bool), FormatError> {
    let needs =
        uncomp32 == u32::MAX || comp32 == u32::MAX || offset32 == u32::MAX || disk32 == u16::MAX;
    if !needs {
        if disk32 != 0 {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "multi-disk ZIP archive",
            });
        }
        return Ok((
            u64::from(uncomp32),
            u64::from(comp32),
            u64::from(offset32),
            false,
        ));
    }
    let mut cursor = 0usize;
    let mut zip64 = None;
    while cursor < extra.len() {
        let id = le16(extra, cursor).ok_or(FormatError::Truncated(FMT))?;
        let size = le16(extra, cursor + 2).ok_or(FormatError::Truncated(FMT))? as usize;
        let start = cursor + 4;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= extra.len())
            .ok_or(FormatError::Truncated(FMT))?;
        if id == 0x0001 {
            if zip64.is_some() {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "duplicate ZIP64 extended information field",
                });
            }
            zip64 = Some(&extra[start..end]);
        }
        cursor = end;
    }
    let field = zip64.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "ZIP64 extended information field is missing",
    })?;
    let mut at = 0usize;
    let mut next_u64 = || {
        let value = le64(field, at).ok_or(FormatError::Truncated(FMT))?;
        at += 8;
        Ok::<u64, FormatError>(value)
    };
    let uncomp = if uncomp32 == u32::MAX {
        next_u64()?
    } else {
        u64::from(uncomp32)
    };
    let comp = if comp32 == u32::MAX {
        next_u64()?
    } else {
        u64::from(comp32)
    };
    let offset = if offset32 == u32::MAX {
        next_u64()?
    } else {
        u64::from(offset32)
    };
    if disk32 == u16::MAX {
        let disk = le_u32(field, at).ok_or(FormatError::Truncated(FMT))?;
        if disk != 0 {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "multi-disk ZIP64 archive",
            });
        }
    }
    Ok((
        uncomp,
        comp,
        offset,
        uncomp32 == u32::MAX || comp32 == u32::MAX,
    ))
}

fn local_offset_order(members: &[ZipMember<'_>]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..members.len()).collect();
    let mut scratch = vec![0usize; members.len()];
    for shift in (0..usize::BITS).step_by(8) {
        let mut counts = [0usize; 256];
        for &index in &order {
            counts[(members[index].hash_span.0 >> shift) & 0xff] += 1;
        }
        let mut next = 0;
        for count in &mut counts {
            let current = *count;
            *count = next;
            next += current;
        }
        for &index in &order {
            let bucket = (members[index].hash_span.0 >> shift) & 0xff;
            scratch[counts[bucket]] = index;
            counts[bucket] += 1;
        }
        std::mem::swap(&mut order, &mut scratch);
    }
    order
}

fn data_descriptor_end(
    data: &[u8],
    member: &ZipMember<'_>,
    limit: usize,
) -> Result<usize, FormatError> {
    if member.flags & 8 == 0 {
        return Ok(member.data_span.1);
    }
    let start = member.data_span.1;
    let matches = |at: usize| -> bool {
        if member.zip64_sizes {
            at.checked_add(20).is_some_and(|end| end <= limit)
                && le_u32(data, at) == Some(member.crc)
                && le64(data, at + 4) == Some(member.comp_size)
                && le64(data, at + 12) == Some(member.uncomp_size)
        } else {
            at.checked_add(12).is_some_and(|end| end <= limit)
                && le_u32(data, at) == Some(member.crc)
                && le_u32(data, at + 4) == u32::try_from(member.comp_size).ok()
                && le_u32(data, at + 8) == u32::try_from(member.uncomp_size).ok()
        }
    };
    let signed = start
        .checked_add(4)
        .filter(|at| le_u32(data, start) == Some(SIG_DESCRIPTOR) && matches(*at));
    let payload = signed.or_else(|| matches(start).then_some(start)).ok_or(
        FormatError::InvalidStructure {
            format: FMT,
            detail: "ZIP data descriptor is missing or disagrees with central directory",
        },
    )?;
    payload
        .checked_add(if member.zip64_sizes { 20 } else { 12 })
        .ok_or(FormatError::Truncated(FMT))
}

fn build_zip_index<'a>(data: &'a [u8], eocd: &Eocd) -> Result<ZipIndex<'a>, FormatError> {
    let (mut pos, cd_end) = central_directory_bounds(data, eocd)?;
    let mut members = Vec::with_capacity(eocd.total_entries);
    let mut by_name = HashMap::with_capacity(eocd.total_entries);
    let mut central_hash_parts = Vec::with_capacity(3);
    let mut part_start = pos;

    for _ in 0..eocd.total_entries {
        #[cfg(test)]
        CENTRAL_ENTRIES_PARSED.with(|count| count.set(count.get() + 1));
        if pos >= cd_end || le_u32(data, pos) != Some(SIG_CENTRAL) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "bad central directory signature",
            });
        }
        let flags = le16(data, pos + 8).ok_or(FormatError::Truncated(FMT))?;
        let method = le16(data, pos + 10).ok_or(FormatError::Truncated(FMT))?;
        let crc = le_u32(data, pos + 16).ok_or(FormatError::Truncated(FMT))?;
        let comp32 = le_u32(data, pos + 20).ok_or(FormatError::Truncated(FMT))?;
        let uncomp32 = le_u32(data, pos + 24).ok_or(FormatError::Truncated(FMT))?;
        let name_len = le16(data, pos + 28).ok_or(FormatError::Truncated(FMT))? as usize;
        let extra_len = le16(data, pos + 30).ok_or(FormatError::Truncated(FMT))? as usize;
        let comment_len = le16(data, pos + 32).ok_or(FormatError::Truncated(FMT))? as usize;
        let disk = le16(data, pos + 34).ok_or(FormatError::Truncated(FMT))?;
        let offset32 = le_u32(data, pos + 42).ok_or(FormatError::Truncated(FMT))?;
        let name_start = pos + 46;
        let name_end = name_start
            .checked_add(name_len)
            .filter(|&end| end <= cd_end)
            .ok_or(FormatError::Truncated(FMT))?;
        let extra_end = name_end
            .checked_add(extra_len)
            .filter(|&end| end <= cd_end)
            .ok_or(FormatError::Truncated(FMT))?;
        let entry_end = extra_end
            .checked_add(comment_len)
            .filter(|&end| end <= cd_end)
            .ok_or(FormatError::Truncated(FMT))?;
        let raw_name = &data[name_start..name_end];
        if by_name.contains_key(raw_name) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "duplicate ZIP entry name",
            });
        }
        let (uncomp_size, comp_size, local_offset, zip64_sizes) =
            zip64_central_values(&data[name_end..extra_end], uncomp32, comp32, offset32, disk)?;
        let data_span = local_data_span(
            data,
            eocd,
            (method, flags, comp_size, local_offset),
            raw_name,
        )?;
        let local_offset = usize64(
            local_offset,
            "ZIP64 local-header offset exceeds address space",
        )?;
        let hash_span = (local_offset, data_span.1);
        if raw_name == ENTRY_NAME {
            central_hash_parts.push(&data[part_start..pos + 16]);
            part_start = pos + 20;
        }
        let index = members.len();
        members.push(ZipMember {
            raw_name,
            method,
            flags,
            crc,
            comp_size,
            uncomp_size,
            zip64_sizes,
            data_span,
            hash_span,
            local_span: hash_span,
            central_span: (pos, entry_end),
        });
        by_name.insert(raw_name, index);
        pos = entry_end;
    }
    if pos != cd_end {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "central directory size does not match entries",
        });
    }
    central_hash_parts.push(&data[part_start..]);

    let order = local_offset_order(&members);
    for (position, &index) in order.iter().enumerate() {
        let limit = order
            .get(position + 1)
            .map_or(eocd.cd_offset, |&next| members[next].hash_span.0);
        let hash_end = data_descriptor_end(data, &members[index], limit)?;
        if hash_end > limit {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "overlapping ZIP local entries",
            });
        }
        members[index].hash_span.1 = hash_end;
        members[index].local_span.1 = limit;
    }

    Ok(ZipIndex {
        members,
        by_name,
        central_hash_parts,
    })
}

pub fn zip_index(data: &[u8]) -> Result<ZipIndex<'_>, FormatError> {
    let eocd = find_eocd(data)?;
    build_zip_index(data, &eocd)
}

#[derive(Clone, Copy)]
struct CdEntry {
    method: u16,
    flags: u16,
    comp_size: u64,
    local_offset: u64,
}

fn find_cd_entry(data: &[u8], eocd: &Eocd, name: &[u8]) -> Result<Option<CdEntry>, FormatError> {
    Ok(build_zip_index(data, eocd)?
        .get(name)
        .map(|member| CdEntry {
            method: member.method,
            flags: member.flags,
            comp_size: member.comp_size,
            local_offset: member.hash_span.0 as u64,
        }))
}

pub fn zip_entry_names(data: &[u8]) -> Result<Vec<String>, FormatError> {
    Ok(zip_index(data)?
        .members()
        .iter()
        .map(|member| String::from_utf8_lossy(member.raw_name()).into_owned())
        .collect())
}

pub fn zip_entry_data(data: &[u8], name: &str) -> Result<Option<Vec<u8>>, FormatError> {
    let index = zip_index(data)?;
    let Some(entry) = index.get(name.as_bytes()) else {
        return Ok(None);
    };
    let raw = &data[entry.data_span.0..entry.data_span.1];
    match entry.method {
        METHOD_STORED => Ok(Some(raw.to_vec())),
        8 => {
            miniz_oxide::inflate::decompress_to_vec_with_limit(raw, crate::MAX_MANIFEST_STORE_BYTES)
                .map(Some)
                .map_err(|error| {
                    if error.status == miniz_oxide::inflate::TINFLStatus::HasMoreOutput {
                        FormatError::ManifestTooLarge {
                            format: FMT,
                            max: crate::MAX_MANIFEST_STORE_BYTES,
                            got: crate::MAX_MANIFEST_STORE_BYTES + 1,
                        }
                    } else {
                        FormatError::InvalidStructure {
                            format: FMT,
                            detail: "deflate stream corrupt",
                        }
                    }
                })
        }
        _ => Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "unsupported ZIP compression method",
        }),
    }
}

pub fn zip_central_directory_hash_parts(data: &[u8]) -> Result<Vec<&[u8]>, FormatError> {
    Ok(zip_index(data)?.central_hash_parts)
}

pub fn zip_entry_local_span(
    data: &[u8],
    name: &str,
) -> Result<Option<(usize, usize)>, FormatError> {
    Ok(zip_index(data)?
        .get(name.as_bytes())
        .map(ZipMember::local_span))
}

pub fn zip_entry_hash_span(data: &[u8], name: &str) -> Result<Option<(usize, usize)>, FormatError> {
    Ok(zip_index(data)?
        .get(name.as_bytes())
        .map(ZipMember::hash_span))
}

/// Extract the manifest store from the `META-INF/content_credential.c2pa` entry.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, ENTRY_NAME)? else {
        return Ok(None);
    };
    if entry.method != METHOD_STORED || entry.flags != 0 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "C2PA ZIP entry must be stored, unencrypted, and have flags zero",
        });
    }
    let comp_size = usize64(entry.comp_size, "ZIP64 manifest entry is too large")?;
    super::ensure_manifest_store_size(FMT, comp_size)?;
    let lh = usize64(
        entry.local_offset,
        "ZIP64 local-header offset exceeds address space",
    )?;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = lh
        .checked_add(30 + name_len + extra_len)
        .ok_or(FormatError::Truncated(FMT))?;
    let data_end = data_start
        .checked_add(comp_size)
        .filter(|&end| end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(Some(
        super::logical_manifest_store(&data[data_start..data_end]).to_vec(),
    ))
}

/// The stored manifest entry's data region as a `c2pa.hash.data` exclusion.
/// Only the manifest payload bytes are excluded; the surrounding ZIP structures
/// (local header, central directory, EOCD) are covered by the data hash.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let eocd = find_eocd(data)?;
    let Some(entry) = find_cd_entry(data, &eocd, ENTRY_NAME)? else {
        return Ok(Vec::new());
    };
    if entry.method != METHOD_STORED || entry.flags != 0 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "C2PA ZIP entry must be stored, unencrypted, and have flags zero",
        });
    }
    let lh = usize64(
        entry.local_offset,
        "ZIP64 local-header offset exceeds address space",
    )?;
    if le_u32(data, lh) != Some(SIG_LOCAL) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "bad local file header signature",
        });
    }
    let name_len = le16(data, lh + 26).ok_or(FormatError::Truncated(FMT))? as usize;
    let extra_len = le16(data, lh + 28).ok_or(FormatError::Truncated(FMT))? as usize;
    let data_start = lh
        .checked_add(30 + name_len + extra_len)
        .ok_or(FormatError::Truncated(FMT))?;
    let comp_size = usize64(entry.comp_size, "ZIP64 manifest entry is too large")?;
    let data_end = data_start
        .checked_add(comp_size)
        .filter(|&end| end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(vec![DataHashExclusion {
        start: data_start,
        length: data_end - data_start,
    }])
}

/// Remove the `META-INF/content_credential.c2pa` entry (if present),
/// rebuilding local entries, the central directory, and the EOCD record so
/// all offsets stay consistent. A no-op when the asset has no manifest entry.
#[cfg(test)]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    let eocd = find_eocd(asset)?;
    let index = build_zip_index(asset, &eocd)?;
    if index.get(ENTRY_NAME).is_none() {
        return Ok(asset.to_vec());
    }

    let order = local_offset_order(index.members());
    let first_local = order
        .first()
        .map_or(eocd.cd_offset, |&member| index.members[member].local_span.0);
    let mut out = Vec::with_capacity(asset.len());
    out.extend_from_slice(&asset[..first_local]);
    let mut new_offsets = HashMap::with_capacity(index.members.len());
    for member_index in order {
        let member = &index.members[member_index];
        if member.raw_name == ENTRY_NAME {
            continue;
        }
        new_offsets.insert(member.local_span.0, out.len() as u32);
        out.extend_from_slice(&asset[member.local_span.0..member.local_span.1]);
    }

    let new_cd_offset = out.len();
    let mut kept_count = 0u16;
    for member in index.members() {
        if member.raw_name == ENTRY_NAME {
            continue;
        }
        let mut record = asset[member.central_span.0..member.central_span.1].to_vec();
        let new_local = new_offsets[&member.local_span.0];
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
    let comment = &asset[eocd.eocd_offset + 22..];
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
#[cfg(test)]
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
    let crc = crate::c2pa_formats::util::crc32(manifest_store);
    let cd_start = eocd.cd_offset;
    let cd_size = eocd.cd_size;
    if cd_start + cd_size > asset.len() {
        return Err(FormatError::Truncated(FMT));
    }

    // The test-only writer intentionally remains ZIP32.
    let new_local_offset =
        u32::try_from(eocd.cd_offset).map_err(|_| FormatError::UnsupportedVariant {
            format: FMT,
            detail: "test-only ZIP writer does not emit ZIP64",
        })?;

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
    let new_total =
        u16::try_from(eocd.total_entries + 1).map_err(|_| FormatError::UnsupportedVariant {
            format: FMT,
            detail: "test-only ZIP writer does not emit ZIP64",
        })?;

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
    use crate::c2pa_formats::tests::dummy_manifest_store;
    use crate::c2pa_formats::util::crc32;

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
    fn extraction_trims_zero_filled_placeholder_tail() {
        let store = dummy_manifest_store();
        let mut padded = store.clone();
        padded.resize(store.len() + 1024, 0);
        let embedded = embed(&tiny_zip(), &padded).unwrap();
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

    fn stored_zip_with_names(names: &[String]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut central = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let content = [(index & 0xff) as u8];
            let crc = crc32(&content);
            let size = content.len() as u32;
            let local_offset = body.len() as u32;

            body.extend_from_slice(&SIG_LOCAL.to_le_bytes());
            body.extend_from_slice(&20u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&METHOD_STORED.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&crc.to_le_bytes());
            body.extend_from_slice(&size.to_le_bytes());
            body.extend_from_slice(&size.to_le_bytes());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&content);

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
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = body.len() as u32;
        let cd_size = central.len() as u32;
        let count = names.len() as u16;
        body.extend_from_slice(&central);
        body.extend_from_slice(&SIG_EOCD.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    #[test]
    fn central_directory_index_walk_and_lookups_are_linear() {
        const ENTRY_COUNT: usize = 4096;
        let mut names = (0..ENTRY_COUNT)
            .map(|index| format!("word/media/image{index:05}.bin"))
            .collect::<Vec<_>>();
        names.push("[Content_Types].xml".into());
        let archive = stored_zip_with_names(&names);

        CENTRAL_ENTRIES_PARSED.with(|count| count.set(0));
        let index = zip_index(&archive).expect("large ZIP index");
        assert_eq!(index.members().len(), names.len());
        assert_eq!(
            CENTRAL_ENTRIES_PARSED.with(std::cell::Cell::get),
            names.len(),
            "index construction must walk each central entry exactly once"
        );
        for name in &names {
            let member = index.get(name.as_bytes()).expect("indexed member");
            let (start, end) = member.hash_span();
            assert!(start < end);
        }
        assert_eq!(
            CENTRAL_ENTRIES_PARSED.with(std::cell::Cell::get),
            names.len(),
            "O(1) lookups must not reparse the central directory"
        );
        assert_eq!(
            index
                .get(b"[Content_Types].xml")
                .expect("DOCX bracket member")
                .raw_name(),
            b"[Content_Types].xml"
        );
    }

    #[test]
    fn index_rejects_duplicate_names_and_zip64_sentinel() {
        let duplicate = stored_zip_with_names(&["same.xml".into(), "same.xml".into()]);
        assert!(zip_index(&duplicate).is_err());

        let mut zip64 = tiny_zip();
        let eocd = find_eocd(&zip64).unwrap().eocd_offset;
        zip64[eocd + 10..eocd + 12].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            zip_index(&zip64),
            Err(FormatError::UnsupportedVariant { .. })
        ));
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_zip()).unwrap(), None);
    }

    #[test]
    fn rejects_non_zip() {
        assert!(extract(b"not a zip file at all really").is_err());
    }

    fn zip64_with_manifest_and_descriptor() -> (Vec<u8>, Vec<u8>) {
        let store = dummy_manifest_store();
        let data_name = b"payload.bin";
        let payload = b"descriptor-covered";
        let mut zip = Vec::new();
        let manifest_offset = zip.len() as u64;
        let manifest_crc = crc32(&store);
        zip.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&METHOD_STORED.to_le_bytes());
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&manifest_crc.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&(ENTRY_NAME.len() as u16).to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(ENTRY_NAME);
        zip.extend_from_slice(&0x0001u16.to_le_bytes());
        zip.extend_from_slice(&16u16.to_le_bytes());
        zip.extend_from_slice(&(store.len() as u64).to_le_bytes());
        zip.extend_from_slice(&(store.len() as u64).to_le_bytes());
        zip.extend_from_slice(&store);

        let payload_offset = zip.len() as u64;
        let payload_crc = crc32(payload);
        zip.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&8u16.to_le_bytes());
        zip.extend_from_slice(&METHOD_STORED.to_le_bytes());
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&(data_name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(data_name);
        zip.extend_from_slice(&0x0001u16.to_le_bytes());
        zip.extend_from_slice(&16u16.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        zip.extend_from_slice(payload);
        zip.extend_from_slice(&SIG_DESCRIPTOR.to_le_bytes());
        zip.extend_from_slice(&payload_crc.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u64).to_le_bytes());

        let cd_offset = zip.len() as u64;
        for (name, crc, size, offset, flags) in [
            (
                ENTRY_NAME,
                manifest_crc,
                store.len() as u64,
                manifest_offset,
                0u16,
            ),
            (
                data_name.as_slice(),
                payload_crc,
                payload.len() as u64,
                payload_offset,
                8u16,
            ),
        ] {
            zip.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
            zip.extend_from_slice(&45u16.to_le_bytes());
            zip.extend_from_slice(&45u16.to_le_bytes());
            zip.extend_from_slice(&flags.to_le_bytes());
            zip.extend_from_slice(&METHOD_STORED.to_le_bytes());
            zip.extend_from_slice(&[0; 4]);
            zip.extend_from_slice(&crc.to_le_bytes());
            zip.extend_from_slice(&u32::MAX.to_le_bytes());
            zip.extend_from_slice(&u32::MAX.to_le_bytes());
            zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
            zip.extend_from_slice(&28u16.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&0u16.to_le_bytes());
            zip.extend_from_slice(&0u32.to_le_bytes());
            zip.extend_from_slice(&u32::MAX.to_le_bytes());
            zip.extend_from_slice(name);
            zip.extend_from_slice(&0x0001u16.to_le_bytes());
            zip.extend_from_slice(&24u16.to_le_bytes());
            zip.extend_from_slice(&size.to_le_bytes());
            zip.extend_from_slice(&size.to_le_bytes());
            zip.extend_from_slice(&offset.to_le_bytes());
        }
        let cd_size = zip.len() as u64 - cd_offset;
        let zip64_offset = zip.len() as u64;
        zip.extend_from_slice(&SIG_ZIP64_EOCD.to_le_bytes());
        zip.extend_from_slice(&44u64.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&45u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&2u64.to_le_bytes());
        zip.extend_from_slice(&2u64.to_le_bytes());
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&cd_offset.to_le_bytes());
        zip.extend_from_slice(&SIG_ZIP64_LOCATOR.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&zip64_offset.to_le_bytes());
        zip.extend_from_slice(&1u32.to_le_bytes());
        zip.extend_from_slice(&SIG_EOCD.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&u16::MAX.to_le_bytes());
        zip.extend_from_slice(&u16::MAX.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&u32::MAX.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        (zip, store)
    }

    #[test]
    fn zip64_reader_hashes_descriptor_and_end_records() {
        let (archive, store) = zip64_with_manifest_and_descriptor();
        assert_eq!(extract(&archive).unwrap(), Some(store));
        let index = zip_index(&archive).unwrap();
        assert_eq!(index.members().len(), 2);
        let payload = index.get(b"payload.bin").unwrap();
        assert_eq!(
            payload.hash_span().1 - payload.data_span.1,
            24,
            "signed ZIP64 descriptor is part of the member hash"
        );
        let parts = index.central_directory_hash_parts();
        assert_eq!(parts.len(), 2, "manifest CRC is the only central gap");
        assert!(
            parts
                .last()
                .unwrap()
                .windows(4)
                .any(|bytes| bytes == SIG_ZIP64_EOCD.to_le_bytes()),
            "ZIP64 EOCD and locator are covered by the central-directory digest"
        );

        let mut tampered = archive;
        let eocd = find_eocd(&tampered).unwrap();
        let locator = eocd.eocd_offset - 20;
        let zip64 = le64(&tampered, locator + 8).unwrap() as usize;
        tampered[zip64 + 48..zip64 + 56].copy_from_slice(&0u64.to_le_bytes());
        assert!(zip_index(&tampered).is_err());
    }
}
