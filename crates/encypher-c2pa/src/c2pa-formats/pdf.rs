// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! PDF C2PA manifest discovery.
//!
//! Document-level extraction follows the catalog `/AF` association. Retained
//! stores are enumerated through classic or stream cross-reference history.
//! Embedded-file streams may use an indirect `/Length`, `/FlateDecode`, and
//! the `/Crypt` filter with `/Name /Identity` required for encrypted PDFs.
//! Object-level `/AF` associations are inventoried separately so an embedded
//! image or font can never be mistaken for the document-level credential.
//!
//! The production crate is verification-only. Its test-only writer emits a
//! conservative uncompressed incremental update for regression fixtures.

use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use crate::c2pa_core::jumbf::UUID_MANIFEST_STORE;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Pdf;
const MAX_PDF_REVISIONS: usize = 64;
const MAX_AF_ENTRIES: usize = 4_096;
const DUPLICATE_STORES: &str = "PDF update section contains more than one C2PA Manifest Store";

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocatedStore {
    raw_span: (usize, usize),
    store_span: Option<(usize, usize)>,
    decoded_store: Option<Vec<u8>>,
}

impl LocatedStore {
    fn bytes<'a>(&'a self, asset: &'a [u8]) -> Option<&'a [u8]> {
        if let Some(decoded) = &self.decoded_store {
            return Some(decoded);
        }
        let (start, length) = self.store_span?;
        asset.get(start..start.checked_add(length)?)
    }
}

/// One C2PA Manifest Store introduced by a PDF incremental update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PdfManifestStoreSection {
    pub section_index: usize,
    pub section_end: usize,
    store_span: Option<(usize, usize)>,
    decoded_store: Option<Vec<u8>>,
    pub defect: Option<&'static str>,
}

impl PdfManifestStoreSection {
    pub fn store<'a>(&'a self, asset: &'a [u8]) -> Option<&'a [u8]> {
        if let Some(decoded) = &self.decoded_store {
            return Some(decoded);
        }
        let (start, length) = self.store_span?;
        asset.get(start..start.checked_add(length)?)
    }
}

/// Enumerate retained PDF manifest stores in update order.
///
/// Revision boundaries come from the bounded classic `xref` `/Prev` chain,
/// never from scanning arbitrary stream contents for `%%EOF`.
pub(crate) fn manifest_store_sections(
    data: &[u8],
) -> Result<Vec<PdfManifestStoreSection>, FormatError> {
    if find_root(data)?.is_none() {
        return Ok(Vec::new());
    }
    let ends = revision_ends(data)?;
    let mut sections = Vec::new();
    let mut seen = Vec::new();
    let mut previous_end = 0usize;
    for (section_index, &section_end) in ends.iter().enumerate() {
        let rendition = &data[..section_end];
        let section = previous_end..section_end;
        previous_end = section_end;
        match locate_store_in_section(rendition, section) {
            Ok(Some(store)) if !seen.contains(&store.raw_span) => {
                seen.push(store.raw_span);
                sections.push(PdfManifestStoreSection {
                    section_index,
                    section_end,
                    store_span: store.store_span,
                    decoded_store: store.decoded_store,
                    defect: None,
                });
            }
            Ok(_) => {}
            Err(error) => sections.push(PdfManifestStoreSection {
                section_index,
                section_end,
                store_span: None,
                decoded_store: None,
                defect: Some(defect_detail(&error)),
            }),
        }
    }
    Ok(sections)
}

/// Extract the C2PA manifest store declared by the document catalog's `/AF`
/// entry, if any.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(locate_store(data)?.and_then(|store| store.bytes(data).map(<[u8]>::to_vec)))
}

/// The embedded manifest-store `jumb` superbox span as a `c2pa.hash.data`
/// exclusion. A decoded Flate stream has no byte-for-byte position in the PDF,
/// so no unsafe decoded offset is ever reported.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let Some(store) = locate_store(data)? else {
        return Ok(Vec::new());
    };
    let Some((start, length)) = store.store_span else {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "compressed C2PA manifest stream has no byte range to exclude",
        });
    };
    Ok(vec![DataHashExclusion { start, length }])
}

/// Resolve the document-level manifest while leaving object-level associations
/// to [`object_manifest_stores`].
fn locate_store(data: &[u8]) -> Result<Option<LocatedStore>, FormatError> {
    if find_root(data)?.is_none() {
        return Ok(None);
    }
    locate_store_in_section(data, 0..data.len())
}

fn locate_store_in_section(
    data: &[u8],
    section: Range<usize>,
) -> Result<Option<LocatedStore>, FormatError> {
    let Some((root_num, root_gen)) = find_root(data)? else {
        return Ok(None);
    };
    let Some(cat_pos) = find_obj_last(data, root_num, root_gen) else {
        return Ok(None);
    };
    let Some((cat_open, cat_close)) = dict_span(data, cat_pos) else {
        return Ok(None);
    };
    let cat = &data[cat_open..cat_close];
    let Some(af_pos) = find_name_last(cat, b"/AF") else {
        return Ok(None);
    };
    let refs = parse_ref_array(cat, af_pos + 3);
    if refs.len() > MAX_AF_ENTRIES {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF catalog /AF has too many entries",
        });
    }

    let mut stream_refs = Vec::new();
    for &(n, g) in &refs {
        let Some(pos) = find_obj_last(data, n, g) else {
            continue;
        };
        let Some((open, close)) = dict_span(data, pos) else {
            continue;
        };
        let spec = &data[open..close];
        if !has_name_value(spec, b"/AFRelationship", b"/C2PA_Manifest") {
            continue;
        }
        let Some(ef_pos) = find_name(spec, b"/EF") else {
            continue;
        };
        let Some((ef_open, ef_close)) = dict_span(spec, ef_pos) else {
            continue;
        };
        let ef = &spec[ef_open..ef_close];
        let Some(f_pos) = find_name(ef, b"/F") else {
            continue;
        };
        if let Some((num, gen, _)) = read_ref(ef, f_pos + 2) {
            if !stream_refs.contains(&(num, gen)) {
                stream_refs.push((num, gen));
            }
        }
    }

    let mut stores = Vec::with_capacity(stream_refs.len());
    for (num, generation) in stream_refs {
        let object = find_obj_last(data, num, generation).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA filespec references a missing stream object",
        })?;
        match manifest_stream(data, num, generation) {
            Ok(store) => stores.push(store),
            Err(error) if section.contains(&object) => return Err(error),
            Err(_) => continue,
        }
    }
    let introduced: Vec<_> = stores
        .iter()
        .filter(|store| section.contains(&store.raw_span.0))
        .collect();
    if introduced.len() > 1 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: DUPLICATE_STORES,
        });
    }
    Ok(introduced
        .first()
        .map(|store| (*store).clone())
        .or_else(|| stores.last().cloned()))
}

fn defect_detail(error: &FormatError) -> &'static str {
    match error {
        FormatError::InvalidStructure { detail, .. }
        | FormatError::UnsupportedVariant { detail, .. } => detail,
        _ => "PDF update section declares an unreadable C2PA Manifest Store",
    }
}

/// Resolve and decode a C2PA embedded-file stream. `/Crypt` is accepted only
/// with the standard `/Identity` crypt filter; it is therefore byte-preserving.
/// Flate decoding is bounded by the public manifest-store size ceiling.
fn manifest_stream(data: &[u8], snum: u64, sgen: u64) -> Result<LocatedStore, FormatError> {
    let obj_pos = find_obj_last(data, snum, sgen).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA filespec references a missing stream object",
    })?;
    let (o, c) = dict_span(data, obj_pos).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no dictionary",
    })?;
    let d = &data[o..c];
    if !has_name_value(d, b"/Subtype", b"/application#2Fc2pa") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA embedded-file stream has no application/c2pa subtype",
        });
    }
    let l_pos = find_name(d, b"/Length").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no /Length",
    })?;
    let stream_len = if let Some((num, generation, _)) = read_ref(d, l_pos + 7) {
        let length_object =
            find_obj_last(data, num, generation).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "indirect C2PA stream /Length object is missing",
            })?;
        let marker =
            find_from(data, b"obj", length_object).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "indirect C2PA stream /Length object is malformed",
            })?;
        read_uint(data, marker + 3).map(|(value, _)| value).ok_or(
            FormatError::InvalidStructure {
                format: FMT,
                detail: "indirect C2PA stream /Length is not a number",
            },
        )?
    } else {
        read_uint(d, l_pos + 7)
            .map(|(value, _)| value)
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "C2PA stream /Length is not a number",
            })?
    };
    let stream_len = usize::try_from(stream_len).map_err(|_| FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream length is out of range",
    })?;
    let kw = find_from(data, b"stream", c).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no stream data",
    })?;
    let object_end = find_from(data, b"endobj", c).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no endobj",
    })?;
    if kw >= object_end {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA stream object has no stream data",
        });
    }
    let mut stream_start = kw + 6;
    match data.get(stream_start..stream_start.saturating_add(2)) {
        Some(b"\r\n") => stream_start += 2,
        _ if data.get(stream_start) == Some(&b'\n') => stream_start += 1,
        _ if data.get(stream_start) == Some(&b'\r') => stream_start += 1,
        _ => {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF stream keyword is not followed by an end-of-line marker",
            })
        }
    }
    let stream_end = stream_start
        .checked_add(stream_len)
        .filter(|end| *end <= object_end)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA stream length is out of range",
        })?;
    let filters = pdf_filter_names(d)?;
    let crypt = filters.iter().any(|filter| matches!(*filter, b"/Crypt"));
    if crypt && !has_name_value(d, b"/Name", b"/Identity") {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "encrypted C2PA stream does not use the Identity crypt filter",
        });
    }
    let mut decoded = data[stream_start..stream_end].to_vec();
    let mut compressed = false;
    for filter in filters {
        match filter {
            b"/Crypt" => {}
            b"/FlateDecode" | b"/Fl" => {
                compressed = true;
                decoded = inflate_pdf_stream(&decoded)?;
            }
            _ => {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "unsupported C2PA manifest stream filter",
                })
            }
        }
    }
    let length = manifest_store_length(&decoded)?;
    decoded.truncate(length);
    Ok(LocatedStore {
        raw_span: (stream_start, stream_len),
        store_span: (!compressed).then_some((stream_start, length)),
        decoded_store: compressed.then_some(decoded),
    })
}

fn manifest_store_length(bytes: &[u8]) -> Result<usize, FormatError> {
    let lbox = bytes
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA stream too short for a JUMBF box",
        })?;
    let is_store = bytes.get(4..8) == Some(b"jumb")
        && bytes.get(12..16) == Some(b"jumd")
        && bytes.get(16..32) == Some(&UUID_MANIFEST_STORE[..]);
    if !is_store || lbox < 8 || lbox > bytes.len() {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "declared C2PA stream does not hold a manifest store",
        });
    }
    Ok(lbox)
}

fn pdf_filter_names(dict: &[u8]) -> Result<Vec<&[u8]>, FormatError> {
    let Some(at) = find_name(dict, b"/Filter") else {
        return Ok(Vec::new());
    };
    let mut cursor = at + b"/Filter".len();
    while dict.get(cursor).is_some_and(|byte| is_ws(*byte)) {
        cursor += 1;
    }
    let array = dict.get(cursor) == Some(&b'[');
    if array {
        cursor += 1;
    }
    let mut names = Vec::new();
    loop {
        while dict.get(cursor).is_some_and(|byte| is_ws(*byte)) {
            cursor += 1;
        }
        if array && dict.get(cursor) == Some(&b']') {
            break;
        }
        if dict.get(cursor) != Some(&b'/') {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF stream /Filter is not a name or name array",
            });
        }
        let start = cursor;
        cursor += 1;
        while dict
            .get(cursor)
            .is_some_and(|byte| !is_ws(*byte) && !is_delim(*byte))
        {
            cursor += 1;
        }
        names.push(&dict[start..cursor]);
        if !array {
            break;
        }
    }
    Ok(names)
}

fn inflate_pdf_stream(raw: &[u8]) -> Result<Vec<u8>, FormatError> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::{decompress_to_vec_with_limit, decompress_to_vec_zlib_with_limit};

    let limit = crate::MAX_MANIFEST_STORE_BYTES;
    match decompress_to_vec_zlib_with_limit(raw, limit) {
        Ok(out) => Ok(out),
        Err(error) if error.status == TINFLStatus::HasMoreOutput => {
            Err(FormatError::ManifestTooLarge {
                format: FMT,
                max: limit,
                got: limit + 1,
            })
        }
        Err(_) => decompress_to_vec_with_limit(raw, limit).map_err(|error| {
            if error.status == TINFLStatus::HasMoreOutput {
                FormatError::ManifestTooLarge {
                    format: FMT,
                    max: limit,
                    got: limit + 1,
                }
            } else {
                FormatError::InvalidStructure {
                    format: FMT,
                    detail: "C2PA manifest stream is not valid Flate data",
                }
            }
        }),
    }
}

#[derive(Clone, Copy)]
enum AuthSlot {
    Free,
    Offset { offset: usize, generation: u64 },
    InStream { stream: u64, index: usize },
}

struct AuthSection {
    entries: Vec<(u64, AuthSlot)>,
    previous: Option<usize>,
    supplemental: Option<usize>,
    root: Option<(u64, u64)>,
}

struct AuthOwned {
    text: Vec<u8>,
    dictionary: Option<(usize, usize)>,
    stream: Option<(usize, usize)>,
}

impl AuthOwned {
    fn dict(&self) -> Option<&[u8]> {
        self.dictionary.map(|(start, end)| &self.text[start..end])
    }
}

struct AuthObjectStream {
    data: Vec<u8>,
    first: usize,
    offsets: Vec<(u64, usize)>,
}

/// Read-only PDF resolver used by the C2PA 2.5 catalog and object paths.
///
/// Cross-reference slots are authoritative. It resolves classic tables,
/// xref streams, hybrid `/XRefStm` sections and compressed object streams;
/// bytes that merely resemble objects are never discovered.
struct AuthDocument<'a> {
    data: &'a [u8],
    slots: HashMap<u64, AuthSlot>,
    object_streams: HashMap<u64, AuthObjectStream>,
    root: Option<(u64, u64)>,
}

impl<'a> AuthDocument<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, FormatError> {
        let startxref = rfind(data, b"startxref").ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF is missing startxref",
        })?;
        let latest = read_uint(data, startxref + b"startxref".len())
            .and_then(|(offset, _)| usize::try_from(offset).ok())
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF startxref offset is invalid",
            })?;
        let mut document = Self {
            data,
            slots: HashMap::new(),
            object_streams: HashMap::new(),
            root: None,
        };
        let mut next = Some(latest);
        let mut visited = HashSet::new();
        while let Some(offset) = next {
            if !visited.insert(offset) {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF cross-reference chain contains a cycle",
                });
            }
            if visited.len() > MAX_PDF_REVISIONS {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "PDF has too many cross-reference revisions",
                });
            }
            let section = auth_section(data, offset)?;
            if document.root.is_none() {
                document.root = section.root;
            }
            if let Some(supplemental) = section.supplemental {
                if !visited.insert(supplemental) {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF hybrid cross-reference chain contains a cycle",
                    });
                }
                let stream = auth_xref_stream(data, supplemental)?;
                if document.root.is_none() {
                    document.root = stream.root;
                }
                for (number, slot) in stream.entries {
                    document.slots.entry(number).or_insert(slot);
                }
            }
            for (number, slot) in section.entries {
                document.slots.entry(number).or_insert(slot);
            }
            if document.slots.len() > (1 << 21) {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "PDF cross-reference table is too large",
                });
            }
            next = section.previous;
        }
        Ok(document)
    }

    fn references(&self) -> Vec<(u64, u64)> {
        let mut references: Vec<_> = self
            .slots
            .iter()
            .filter_map(|(&number, slot)| match slot {
                AuthSlot::Free => None,
                AuthSlot::Offset { generation, .. } => Some((number, *generation)),
                AuthSlot::InStream { .. } => Some((number, 0)),
            })
            .collect();
        references.sort_unstable();
        references
    }

    fn fetch(
        &mut self,
        number: u64,
        generation: u64,
        depth: usize,
    ) -> Result<AuthOwned, FormatError> {
        if depth >= 16 {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF object resolution is too deep",
            });
        }
        let slot = self
            .slots
            .get(&number)
            .copied()
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF reference names a missing object",
            })?;
        match slot {
            AuthSlot::Free => Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF reference names a deleted object",
            }),
            AuthSlot::Offset {
                offset,
                generation: expected_generation,
            } => {
                if generation != expected_generation {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF reference generation does not match cross-reference entry",
                    });
                }
                self.fetch_offset(number, generation, offset, depth)
            }
            AuthSlot::InStream { stream, index } => {
                if generation != 0 {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "compressed PDF object has a nonzero generation",
                    });
                }
                self.fetch_compressed(number, stream, index, depth)
            }
        }
    }

    fn fetch_offset(
        &mut self,
        expected_number: u64,
        expected_generation: u64,
        offset: usize,
        depth: usize,
    ) -> Result<AuthOwned, FormatError> {
        let (number, after_number) =
            read_uint(self.data, offset).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference offset has no object",
            })?;
        let (generation, mut cursor) =
            read_uint(self.data, after_number).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF object has no generation",
            })?;
        cursor = skip_pdf_ws(self.data, cursor);
        if number != expected_number
            || generation != expected_generation
            || self.data.get(cursor..cursor + 3) != Some(b"obj")
        {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF object header disagrees with cross-reference entry",
            });
        }
        let value = skip_pdf_ws(self.data, cursor + 3);
        let Some((open, close)) = direct_dict_span(self.data, value) else {
            let marker =
                find_from(self.data, b"endobj", value).ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF indirect object has no endobj",
                })?;
            let mut end = marker;
            while end > value && is_ws(self.data[end - 1]) {
                end -= 1;
            }
            if end == value {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF indirect object has no value",
                });
            }
            return Ok(AuthOwned {
                text: self.data[value..end].to_vec(),
                dictionary: None,
                stream: None,
            });
        };
        let dictionary = self.data[open..close].to_vec();
        let mut after = skip_pdf_ws(self.data, close);
        let stream = if self.data.get(after..after + 6) == Some(b"stream")
            && self.data.get(after + 6).is_some_and(|byte| is_ws(*byte))
        {
            after += 6;
            match self.data.get(after..after.saturating_add(2)) {
                Some(b"\r\n") => after += 2,
                _ if self.data.get(after) == Some(&b'\n')
                    || self.data.get(after) == Some(&b'\r') =>
                {
                    after += 1
                }
                _ => {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF stream keyword is not followed by an end-of-line marker",
                    })
                }
            }
            let length_at =
                find_name(&dictionary, b"/Length").ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF stream has no /Length",
                })?;
            let length = if let Some((length_number, length_generation, _)) =
                read_ref(&dictionary, length_at + b"/Length".len())
            {
                let length = self.fetch(length_number, length_generation, depth + 1)?;
                read_uint(&length.text, 0).map(|(value, _)| value).ok_or(
                    FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF indirect stream /Length is not an integer",
                    },
                )?
            } else {
                read_uint(&dictionary, length_at + b"/Length".len())
                    .map(|(value, _)| value)
                    .ok_or(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF stream /Length is not an integer",
                    })?
            };
            let length = usize::try_from(length).map_err(|_| FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF stream length is out of range",
            })?;
            let end = after
                .checked_add(length)
                .filter(|&end| end <= self.data.len())
                .ok_or(FormatError::Truncated(FMT))?;
            let terminator = skip_pdf_ws(self.data, end);
            if self.data.get(terminator..terminator + 9) != Some(b"endstream") {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF stream length does not reach endstream",
                });
            }
            let object_end = skip_pdf_ws(self.data, terminator + 9);
            if self.data.get(object_end..object_end + 6) != Some(b"endobj") {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF stream object has no endobj",
                });
            }
            Some((after, length))
        } else {
            if self.data.get(after..after + 6) != Some(b"endobj") {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF indirect object has no endobj",
                });
            }
            None
        };
        let length = dictionary.len();
        Ok(AuthOwned {
            text: dictionary,
            dictionary: Some((0, length)),
            stream,
        })
    }

    fn fetch_compressed(
        &mut self,
        number: u64,
        stream_number: u64,
        index: usize,
        depth: usize,
    ) -> Result<AuthOwned, FormatError> {
        if !self.object_streams.contains_key(&stream_number) {
            let stream = self.fetch(stream_number, 0, depth + 1)?;
            let dict = stream.dict().ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF object stream has no dictionary",
            })?;
            if !has_name_value(dict, b"/Type", b"/ObjStm") {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF compressed object points outside an object stream",
                });
            }
            let count = dict_uint(dict, b"/N")?;
            let first = usize::try_from(dict_uint(dict, b"/First")?).map_err(|_| {
                FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF object-stream /First is out of range",
                }
            })?;
            if count > 65_536 {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "PDF object stream contains too many objects",
                });
            }
            let (start, length) = stream.stream.ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF object stream has no stream payload",
            })?;
            let data = decode_auth_stream(dict, &self.data[start..start + length])?;
            if first > data.len() {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF object-stream /First exceeds decoded data",
                });
            }
            let mut cursor = 0usize;
            let mut offsets = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let (object_number, after_number) =
                    read_uint(&data, cursor).ok_or(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF object-stream header is truncated",
                    })?;
                let (relative, after_relative) =
                    read_uint(&data, after_number).ok_or(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF object-stream header is truncated",
                    })?;
                let relative =
                    usize::try_from(relative).map_err(|_| FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF object-stream offset is out of range",
                    })?;
                offsets.push((object_number, relative));
                cursor = after_relative;
            }
            self.object_streams.insert(
                stream_number,
                AuthObjectStream {
                    data,
                    first,
                    offsets,
                },
            );
        }
        let stream = self
            .object_streams
            .get(&stream_number)
            .expect("inserted above");
        let &(found, relative) =
            stream
                .offsets
                .get(index)
                .ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF compressed-object index is out of range",
                })?;
        if found != number {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF object-stream index names a different object",
            });
        }
        let start = stream
            .first
            .checked_add(relative)
            .filter(|&start| start <= stream.data.len())
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF compressed-object offset is out of range",
            })?;
        let end = stream
            .offsets
            .get(index + 1)
            .map_or(stream.data.len(), |next| {
                stream.first.saturating_add(next.1)
            });
        if end < start || end > stream.data.len() {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF compressed-object bounds are invalid",
            });
        }
        let text = stream.data[start..end].to_vec();
        let dictionary = direct_dict_span(&text, 0);
        Ok(AuthOwned {
            text,
            dictionary,
            stream: None,
        })
    }
}

fn direct_dict_span(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let open = skip_pdf_ws(data, from);
    if data.get(open..open + 2) != Some(b"<<") {
        return None;
    }
    dict_span(data, open).filter(|(found, _)| *found == open)
}
fn skip_pdf_ws(data: &[u8], mut cursor: usize) -> usize {
    while data.get(cursor).is_some_and(|byte| is_ws(*byte)) {
        cursor += 1;
    }
    cursor
}

fn dict_uint(dict: &[u8], key: &[u8]) -> Result<u64, FormatError> {
    let at = find_name(dict, key).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF dictionary is missing a required integer",
    })?;
    read_uint(dict, at + key.len())
        .map(|(value, _)| value)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF dictionary value is not an integer",
        })
}

fn dict_uint_array(dict: &[u8], key: &[u8]) -> Result<Vec<u64>, FormatError> {
    let at = find_name(dict, key).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF dictionary is missing a required integer array",
    })?;
    let mut cursor = skip_pdf_ws(dict, at + key.len());
    if dict.get(cursor) != Some(&b'[') {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF dictionary value is not an integer array",
        });
    }
    cursor += 1;
    let mut values = Vec::new();
    loop {
        cursor = skip_pdf_ws(dict, cursor);
        if dict.get(cursor) == Some(&b']') {
            return Ok(values);
        }
        let (value, end) = read_uint(dict, cursor).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF integer array is malformed",
        })?;
        values.push(value);
        cursor = end;
    }
}

fn auth_section(data: &[u8], offset: usize) -> Result<AuthSection, FormatError> {
    if data.get(offset..offset.saturating_add(4)) != Some(b"xref") {
        return auth_xref_stream(data, offset);
    }
    let mut cursor = offset + 4;
    let mut entries = Vec::new();
    loop {
        cursor = skip_pdf_ws(data, cursor);
        if data.get(cursor..cursor.saturating_add(7)) == Some(b"trailer") {
            cursor += 7;
            break;
        }
        let (first, after_first) =
            read_uint(data, cursor).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF xref subsection header is malformed",
            })?;
        let (count, after_count) =
            read_uint(data, after_first).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF xref subsection count is malformed",
            })?;
        if count > (1 << 21) {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF xref subsection is too large",
            });
        }
        cursor = after_count;
        for index in 0..count {
            let (field, after_field) =
                read_uint(data, cursor).ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF xref entry is malformed",
                })?;
            let (generation, after_generation) =
                read_uint(data, after_field).ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF xref entry is malformed",
                })?;
            cursor = skip_pdf_ws(data, after_generation);
            let kind = *data.get(cursor).ok_or(FormatError::Truncated(FMT))?;
            cursor += 1;
            let number = first
                .checked_add(index)
                .ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF xref object number overflows",
                })?;
            let slot = match kind {
                b'f' => AuthSlot::Free,
                b'n' => AuthSlot::Offset {
                    offset: usize::try_from(field).map_err(|_| FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF xref object offset is out of range",
                    })?,
                    generation,
                },
                _ => {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF xref entry has an invalid type",
                    })
                }
            };
            entries.push((number, slot));
        }
    }
    let (open, close) = direct_dict_span(data, cursor).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF trailer has no dictionary",
    })?;
    let trailer = &data[open..close];
    Ok(AuthSection {
        entries,
        previous: dict_optional_offset(trailer, b"/Prev")?,
        supplemental: dict_optional_offset(trailer, b"/XRefStm")?,
        root: find_name(trailer, b"/Root")
            .and_then(|at| read_ref(trailer, at + b"/Root".len()))
            .map(|(number, generation, _)| (number, generation)),
    })
}

fn dict_optional_offset(dict: &[u8], key: &[u8]) -> Result<Option<usize>, FormatError> {
    let Some(at) = find_name(dict, key) else {
        return Ok(None);
    };
    let value = read_uint(dict, at + key.len())
        .and_then(|(value, _)| usize::try_from(value).ok())
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF cross-reference offset is invalid",
        })?;
    Ok(Some(value))
}

fn auth_xref_stream(data: &[u8], offset: usize) -> Result<AuthSection, FormatError> {
    let (_, after_number) = read_uint(data, offset).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream has no object header",
    })?;
    let (_, mut cursor) = read_uint(data, after_number).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream has no generation",
    })?;
    cursor = skip_pdf_ws(data, cursor);
    if data.get(cursor..cursor + 3) != Some(b"obj") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no object marker",
        });
    }
    let (open, close) =
        direct_dict_span(data, cursor + 3).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no dictionary",
        })?;
    let dict = &data[open..close];
    if !has_name_value(dict, b"/Type", b"/XRef") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF startxref target is not an xref section",
        });
    }
    let widths = dict_uint_array(dict, b"/W")?;
    if widths.len() != 3 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream /W must have three integers",
        });
    }
    let length = usize::try_from(dict_uint(dict, b"/Length")?).map_err(|_| {
        FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream length is out of range",
        }
    })?;
    let keyword = skip_pdf_ws(data, close);
    if data.get(keyword..keyword + 6) != Some(b"stream") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no stream payload",
        });
    }
    let mut start = keyword + 6;
    match data.get(start..start.saturating_add(2)) {
        Some(b"\r\n") => start += 2,
        _ if data.get(start) == Some(&b'\n') || data.get(start) == Some(&b'\r') => start += 1,
        _ => return Err(FormatError::Truncated(FMT)),
    }
    let end = start
        .checked_add(length)
        .filter(|&end| end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let endstream = skip_pdf_ws(data, end);
    if data.get(endstream..endstream + 9) != Some(b"endstream") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream length does not reach endstream",
        });
    }
    let endobj = skip_pdf_ws(data, endstream + 9);
    if data.get(endobj..endobj + 6) != Some(b"endobj") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no endobj",
        });
    }
    let decoded = decode_auth_stream(dict, &data[start..end])?;
    let indices = match find_name(dict, b"/Index") {
        Some(_) => dict_uint_array(dict, b"/Index")?,
        None => vec![0, dict_uint(dict, b"/Size")?],
    };
    if indices.len() % 2 != 0 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream /Index is malformed",
        });
    }
    let widths: Vec<usize> = widths
        .into_iter()
        .map(|width| usize::try_from(width).unwrap_or(usize::MAX))
        .collect();
    if widths.iter().any(|&width| width > 8) {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF xref-stream field width is unsupported",
        });
    }
    let row = widths.iter().sum::<usize>();
    if row == 0 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream row is empty",
        });
    }
    let mut payload = 0usize;
    let mut entries = Vec::new();
    for pair in indices.chunks_exact(2) {
        for number in pair[0]
            ..pair[0]
                .checked_add(pair[1])
                .ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF xref-stream range overflows",
                })?
        {
            let end = payload
                .checked_add(row)
                .filter(|&end| end <= decoded.len())
                .ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF xref-stream payload is truncated",
                })?;
            let mut at = payload;
            let mut fields = [0u64; 3];
            for (field, &width) in fields.iter_mut().zip(&widths) {
                for &byte in &decoded[at..at + width] {
                    *field = (*field << 8) | u64::from(byte);
                }
                at += width;
            }
            if widths[0] == 0 {
                fields[0] = 1;
            }
            let slot = match fields[0] {
                0 => AuthSlot::Free,
                1 => AuthSlot::Offset {
                    offset: usize::try_from(fields[1]).map_err(|_| {
                        FormatError::InvalidStructure {
                            format: FMT,
                            detail: "PDF xref-stream object offset is out of range",
                        }
                    })?,
                    generation: fields[2],
                },
                2 => AuthSlot::InStream {
                    stream: fields[1],
                    index: usize::try_from(fields[2]).map_err(|_| {
                        FormatError::InvalidStructure {
                            format: FMT,
                            detail: "PDF compressed-object index is out of range",
                        }
                    })?,
                },
                _ => {
                    payload = end;
                    continue;
                }
            };
            entries.push((number, slot));
            payload = end;
        }
    }
    if payload != decoded.len() {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref-stream payload has trailing entries",
        });
    }
    Ok(AuthSection {
        entries,
        previous: dict_optional_offset(dict, b"/Prev")?,
        supplemental: None,
        root: find_name(dict, b"/Root")
            .and_then(|at| read_ref(dict, at + b"/Root".len()))
            .map(|(number, generation, _)| (number, generation)),
    })
}

fn decode_auth_stream(dict: &[u8], raw: &[u8]) -> Result<Vec<u8>, FormatError> {
    let filters = pdf_filter_names(dict)?;
    let filter_count = filters.len();
    let mut decoded = raw.to_vec();
    for (filter_index, filter) in filters.into_iter().enumerate() {
        match filter {
            b"/FlateDecode" | b"/Fl" => {
                decoded = inflate_pdf_stream(&decoded)?;
                decoded = apply_auth_predictor(dict, decoded, filter_count)?;
            }
            b"/Crypt" if auth_crypt_identity(dict, filter_index, filter_count)? => {}
            _ => {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "unsupported PDF structural stream filter",
                })
            }
        }
    }
    Ok(decoded)
}

fn auth_crypt_identity(
    stream_dict: &[u8],
    filter_index: usize,
    filter_count: usize,
) -> Result<bool, FormatError> {
    let Some(at) = find_name(stream_dict, b"/DecodeParms") else {
        return Ok(false);
    };
    let mut cursor = skip_pdf_ws(stream_dict, at + b"/DecodeParms".len());
    if filter_count == 1 {
        let (open, close) =
            direct_dict_span(stream_dict, cursor).ok_or(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF /Crypt filter has no parameter dictionary",
            })?;
        return Ok(has_name_value(
            &stream_dict[open..close],
            b"/Name",
            b"/Identity",
        ));
    }
    if stream_dict.get(cursor) != Some(&b'[') {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF filter array has no matching /DecodeParms array",
        });
    }
    cursor += 1;
    for index in 0..filter_count {
        cursor = skip_pdf_ws(stream_dict, cursor);
        if stream_dict.get(cursor..cursor + 4) == Some(b"null") {
            if index == filter_index {
                return Ok(false);
            }
            cursor += 4;
            continue;
        }
        let (open, close) =
            direct_dict_span(stream_dict, cursor).ok_or(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF /DecodeParms array entry is not a dictionary",
            })?;
        if index == filter_index {
            return Ok(has_name_value(
                &stream_dict[open..close],
                b"/Name",
                b"/Identity",
            ));
        }
        cursor = close;
    }
    Ok(false)
}

fn apply_auth_predictor(
    stream_dict: &[u8],
    data: Vec<u8>,
    filter_count: usize,
) -> Result<Vec<u8>, FormatError> {
    let Some(at) = find_name(stream_dict, b"/DecodeParms") else {
        return Ok(data);
    };
    if filter_count != 1 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF structural stream has ambiguous /DecodeParms",
        });
    }
    let (open, close) = direct_dict_span(stream_dict, at + b"/DecodeParms".len()).ok_or(
        FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF structural stream /DecodeParms is not a dictionary",
        },
    )?;
    let parameters = &stream_dict[open..close];
    let predictor = find_name(parameters, b"/Predictor")
        .and_then(|at| read_uint(parameters, at + b"/Predictor".len()))
        .map_or(1, |(value, _)| value);
    if predictor <= 1 {
        return Ok(data);
    }
    if !(10..=15).contains(&predictor) {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "PDF structural stream predictor is unsupported",
        });
    }
    let parameter = |name: &[u8], default| {
        find_name(parameters, name)
            .and_then(|at| read_uint(parameters, at + name.len()))
            .map_or(default, |(value, _)| value)
    };
    let colors = parameter(b"/Colors", 1);
    let bits = parameter(b"/BitsPerComponent", 8);
    let columns = parameter(b"/Columns", 1);
    if colors == 0 || bits == 0 || columns == 0 || colors > 32 || bits > 16 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF predictor parameters are out of range",
        });
    }
    let pixel_bits = colors
        .checked_mul(bits)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF predictor pixel width overflows",
        })?;
    let row = columns
        .checked_mul(pixel_bits)
        .and_then(|value| value.checked_add(7))
        .and_then(|value| usize::try_from(value / 8).ok())
        .filter(|&value| value > 0)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF predictor row width is invalid",
        })?;
    let pixel = usize::try_from(pixel_bits.div_ceil(8)).unwrap_or(1).max(1);
    let mut output = Vec::with_capacity(data.len());
    let mut previous = vec![0u8; row];
    let mut cursor = 0usize;
    while cursor < data.len() {
        let kind = data[cursor];
        cursor += 1;
        let end = cursor
            .checked_add(row)
            .filter(|&end| end <= data.len())
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF predictor row is truncated",
            })?;
        let mut current = data[cursor..end].to_vec();
        cursor = end;
        match kind {
            0 => {}
            1 => {
                for index in pixel..row {
                    current[index] = current[index].wrapping_add(current[index - pixel]);
                }
            }
            2 => {
                for index in 0..row {
                    current[index] = current[index].wrapping_add(previous[index]);
                }
            }
            3 => {
                for index in 0..row {
                    let left = if index >= pixel {
                        current[index - pixel]
                    } else {
                        0
                    };
                    current[index] = current[index]
                        .wrapping_add(((u16::from(left) + u16::from(previous[index])) / 2) as u8);
                }
            }
            4 => {
                for index in 0..row {
                    let left = if index >= pixel {
                        current[index - pixel]
                    } else {
                        0
                    };
                    let above_left = if index >= pixel {
                        previous[index - pixel]
                    } else {
                        0
                    };
                    current[index] =
                        current[index].wrapping_add(paeth(left, previous[index], above_left));
                }
            }
            _ => {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF predictor row has an invalid filter",
                })
            }
        }
        output.extend_from_slice(&current);
        previous = current;
    }
    Ok(output)
}

fn paeth(left: u8, above: u8, above_left: u8) -> u8 {
    let left = i32::from(left);
    let above = i32::from(above);
    let above_left = i32::from(above_left);
    let estimate = left + above - above_left;
    let left_distance = (estimate - left).abs();
    let above_distance = (estimate - above).abs();
    let diagonal_distance = (estimate - above_left).abs();
    if left_distance <= above_distance && left_distance <= diagonal_distance {
        left as u8
    } else if above_distance <= diagonal_distance {
        above as u8
    } else {
        above_left as u8
    }
}
/// An object-level `/AF` association and the exact bytes of the owning PDF
/// information resource against which its manifest must be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PdfObjectManifestStore {
    pub owner_number: u64,
    pub owner_generation: u64,
    coverage_span: Option<(usize, usize)>,
    coverage_bytes: Vec<u8>,
    store_span: Option<(usize, usize)>,
    decoded_store: Option<Vec<u8>>,
    pub defect: Option<&'static str>,
}

impl PdfObjectManifestStore {
    pub fn coverage<'a>(&'a self, asset: &'a [u8]) -> Option<&'a [u8]> {
        match self.coverage_span {
            Some((start, length)) => asset.get(start..start + length),
            None => Some(&self.coverage_bytes),
        }
    }

    pub fn store<'a>(&'a self, asset: &'a [u8]) -> Option<&'a [u8]> {
        if let Some(decoded) = &self.decoded_store {
            return Some(decoded);
        }
        let (start, length) = self.store_span?;
        asset.get(start..start + length)
    }
}

/// Enumerate object-level C2PA associations without changing document-level
/// extraction. Cross-reference resolution is authoritative: superseded or
/// unreferenced object-shaped bytes are ignored, while compressed owners in
/// object streams are resolved.
pub(crate) fn object_manifest_stores(
    data: &[u8],
) -> Result<Vec<PdfObjectManifestStore>, FormatError> {
    let mut document = AuthDocument::parse(data)?;
    let root = document.root.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF trailer has no /Root",
    })?;
    let catalog = document.fetch(root.0, root.1, 0)?;
    if !catalog
        .dict()
        .is_some_and(|dict| has_name_value(dict, b"/Type", b"/Catalog"))
    {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF /Root does not resolve to the authoritative catalog",
        });
    }
    let references = document.references();
    let mut out = Vec::new();
    for (number, generation) in references {
        if root == (number, generation) {
            continue;
        }
        let owner = document.fetch(number, generation, 0)?;
        let Some(dict) = owner.dict() else {
            continue;
        };
        let Some(af_at) = find_name(dict, b"/AF") else {
            continue;
        };
        let (coverage_span, coverage_bytes) = match owner.stream {
            Some(span) => (Some(span), Vec::new()),
            None => (None, dict.to_vec()),
        };
        let refs = match auth_association_references(&mut document, dict, af_at) {
            Ok(refs) => refs,
            Err(error) => {
                out.push(PdfObjectManifestStore {
                    owner_number: number,
                    owner_generation: generation,
                    coverage_span,
                    coverage_bytes,
                    store_span: None,
                    decoded_store: None,
                    defect: Some(defect_detail(&error)),
                });
                continue;
            }
        };
        if refs.is_empty() {
            out.push(PdfObjectManifestStore {
                owner_number: number,
                owner_generation: generation,
                coverage_span,
                coverage_bytes,
                store_span: None,
                decoded_store: None,
                defect: Some("object-level PDF /AF is not a file specification"),
            });
            continue;
        }
        let mut stores = Vec::new();
        let mut malformed = None;
        for (spec_number, spec_generation) in refs {
            match auth_filespec_store(&mut document, spec_number, spec_generation) {
                Ok(Some(store)) => stores.push(store),
                Ok(None) => {}
                Err(error) => malformed = Some(defect_detail(&error)),
            }
        }
        if stores.len() != 1 {
            out.push(PdfObjectManifestStore {
                owner_number: number,
                owner_generation: generation,
                coverage_span,
                coverage_bytes,
                store_span: None,
                decoded_store: None,
                defect: Some(if stores.len() > 1 {
                    "object-level PDF /AF associates more than one C2PA Manifest Store"
                } else {
                    malformed.unwrap_or("object-level PDF /AF has no C2PA Manifest Store")
                }),
            });
            continue;
        }
        let store = stores.pop().expect("length checked");
        out.push(PdfObjectManifestStore {
            owner_number: number,
            owner_generation: generation,
            coverage_span,
            coverage_bytes,
            store_span: store.store_span,
            decoded_store: store.decoded_store,
            defect: malformed,
        });
    }
    Ok(out)
}

fn auth_association_references(
    document: &mut AuthDocument<'_>,
    owner_dict: &[u8],
    af_at: usize,
) -> Result<Vec<(u64, u64)>, FormatError> {
    let value = skip_pdf_ws(owner_dict, af_at + b"/AF".len());
    if owner_dict.get(value) == Some(&b'[') {
        return Ok(parse_ref_array(owner_dict, value));
    }
    let (number, generation, _) =
        read_ref(owner_dict, value).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "object-level PDF /AF is not an indirect reference or array",
        })?;
    let target = document.fetch(number, generation, 0)?;
    if target.dict().is_some() {
        Ok(vec![(number, generation)])
    } else {
        let references = parse_ref_array(&target.text, 0);
        if references.is_empty() {
            Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "object-level PDF /AF reference is not an array",
            })
        } else {
            Ok(references)
        }
    }
}

fn auth_filespec_store(
    document: &mut AuthDocument<'_>,
    number: u64,
    generation: u64,
) -> Result<Option<LocatedStore>, FormatError> {
    let spec = document.fetch(number, generation, 0)?;
    let dict = spec.dict().ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "object-level PDF /AF file specification is malformed",
    })?;
    if !has_name_value(dict, b"/AFRelationship", b"/C2PA_Manifest") {
        return Ok(None);
    }
    let ef_at = find_name(dict, b"/EF").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "object-level C2PA file specification has no /EF",
    })?;
    let value = skip_pdf_ws(dict, ef_at + b"/EF".len());
    let ef_owned;
    let ef = if let Some((ef_number, ef_generation, _)) = read_ref(dict, value) {
        ef_owned = document.fetch(ef_number, ef_generation, 0)?;
        ef_owned.dict().ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "object-level C2PA /EF reference is not a dictionary",
        })?
    } else {
        let (open, close) = direct_dict_span(dict, value).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "object-level C2PA /EF is not a dictionary",
        })?;
        &dict[open..close]
    };
    let file_at = find_name(ef, b"/F")
        .or_else(|| find_name(ef, b"/UF"))
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "object-level C2PA /EF names no embedded file",
        })?;
    let (stream_number, stream_generation, _) =
        read_ref(ef, file_at + 2).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "object-level C2PA /EF is not an indirect reference",
        })?;
    auth_manifest_stream(document, stream_number, stream_generation).map(Some)
}

fn auth_manifest_stream(
    document: &mut AuthDocument<'_>,
    number: u64,
    generation: u64,
) -> Result<LocatedStore, FormatError> {
    let stream = document.fetch(number, generation, 0)?;
    let dict = stream.dict().ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no dictionary",
    })?;
    if !has_name_value(dict, b"/Subtype", b"/application#2Fc2pa") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA embedded-file stream has no application/c2pa subtype",
        });
    }
    let (start, raw_length) = stream.stream.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA embedded file is not a stream",
    })?;
    let raw = document
        .data
        .get(start..start + raw_length)
        .ok_or(FormatError::Truncated(FMT))?;
    let filters = pdf_filter_names(dict)?;
    let transforms = filters.iter().any(|filter| *filter != b"/Crypt");
    let decoded = decode_auth_stream(dict, raw)?;
    let length = manifest_store_length(&decoded)?;
    if transforms {
        let mut decoded = decoded;
        decoded.truncate(length);
        Ok(LocatedStore {
            raw_span: (start, raw_length),
            store_span: None,
            decoded_store: Some(decoded),
        })
    } else {
        Ok(LocatedStore {
            raw_span: (start, raw_length),
            store_span: Some((start, length)),
            decoded_store: None,
        })
    }
}

fn auth_catalog_store(data: &[u8]) -> Result<Option<LocatedStore>, FormatError> {
    let mut document = AuthDocument::parse(data)?;
    let root = document.root.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF trailer has no /Root",
    })?;
    let catalog = document.fetch(root.0, root.1, 0)?;
    let dict = catalog.dict().ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF /Root is not a catalog dictionary",
    })?;
    if !has_name_value(dict, b"/Type", b"/Catalog") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF /Root is not the catalog",
        });
    }
    let Some(af_at) = find_name(dict, b"/AF") else {
        return Ok(None);
    };
    let references = auth_association_references(&mut document, dict, af_at)?;
    let mut stores = Vec::new();
    for (number, generation) in references {
        if let Some(store) = auth_filespec_store(&mut document, number, generation)? {
            stores.push(store);
        }
    }
    match stores.len() {
        0 => Ok(None),
        1 => Ok(stores.pop()),
        _ => Err(FormatError::InvalidStructure {
            format: FMT,
            detail: DUPLICATE_STORES,
        }),
    }
}

/// C2PA 2.5 catalog extraction through authoritative PDF object resolution.
pub(crate) fn extract_v2_5(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(auth_catalog_store(data)?.and_then(|store| store.bytes(data).map(<[u8]>::to_vec)))
}

/// C2PA 2.5 data-hash exclusion through authoritative PDF object resolution.
pub(crate) fn exclusions_v2_5(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let Some(store) = auth_catalog_store(data)? else {
        return Ok(Vec::new());
    };
    match store.store_span {
        Some((start, length)) => Ok(vec![DataHashExclusion { start, length }]),
        None => Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "compressed C2PA manifest stream has no byte range to exclude",
        }),
    }
}

/// C2PA 2.5 retained catalog stores, each resolved in its historical rendition
/// through that rendition's authoritative cross-reference map.
pub(crate) fn manifest_store_sections_v2_5(
    data: &[u8],
) -> Result<Vec<PdfManifestStoreSection>, FormatError> {
    let ends = revision_ends(data)?;
    let mut sections = Vec::new();
    let mut seen = Vec::new();
    for (section_index, section_end) in ends.into_iter().enumerate() {
        let rendition = &data[..section_end];
        match auth_catalog_store(rendition) {
            Ok(Some(store)) if !seen.contains(&store.raw_span) => {
                seen.push(store.raw_span);
                sections.push(PdfManifestStoreSection {
                    section_index,
                    section_end,
                    store_span: store.store_span,
                    decoded_store: store.decoded_store,
                    defect: None,
                });
            }
            Ok(_) => {}
            Err(error) => sections.push(PdfManifestStoreSection {
                section_index,
                section_end,
                store_span: None,
                decoded_store: None,
                defect: Some(defect_detail(&error)),
            }),
        }
    }
    Ok(sections)
}

/// Historical rendition ends, oldest first, from the classic `/Prev` chain.
fn revision_ends(data: &[u8]) -> Result<Vec<usize>, FormatError> {
    let startxref = rfind(data, b"startxref").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF is missing startxref",
    })?;
    let (offset, _) = read_uint(data, startxref + 9).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF startxref offset is not a number",
    })?;
    let mut next = Some(
        usize::try_from(offset)
            .ok()
            .filter(|offset| *offset < data.len())
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference offset is out of range",
            })?,
    );
    let mut visited = Vec::new();
    let mut ends = Vec::new();
    while let Some(offset) = next {
        if visited.contains(&offset) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference chain contains a cycle",
            });
        }
        visited.push(offset);
        if visited.len() > MAX_PDF_REVISIONS {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF has too many incremental update sections",
            });
        }
        let dict = xref_dictionary(data, offset)?;
        let section_end = xref_structure_end(data, offset)?;
        let previous = find_name(dict, b"/Prev")
            .map(|position| {
                read_uint(dict, position + 5)
                    .and_then(|(value, _)| usize::try_from(value).ok())
                    .ok_or(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF trailer /Prev is not a valid offset",
                    })
            })
            .transpose()?;
        if previous.is_some_and(|previous| previous >= offset) {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "forward PDF revision references are not supported",
            });
        }
        let keyword =
            find_from(data, b"startxref", section_end).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF revision has no startxref",
            })?;
        let (declared, mut cursor) =
            read_uint(data, keyword + 9).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF revision startxref is not a number",
            })?;
        if declared != offset as u64 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF revision startxref does not match its cross-reference section",
            });
        }
        while data.get(cursor).is_some_and(|byte| is_ws(*byte)) {
            cursor += 1;
        }
        if data.get(cursor..cursor.saturating_add(5)) != Some(b"%%EOF") {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF revision has no EOF marker",
            });
        }
        cursor += 5;
        while data.get(cursor).is_some_and(|byte| is_ws(*byte)) {
            cursor += 1;
        }
        ends.push(cursor);
        next = previous;
    }
    ends.reverse();
    if ends.last().copied() != Some(data.len()) {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF final trailer does not terminate the file",
        });
    }
    Ok(ends)
}

/// Byte immediately after a classic trailer dictionary or xref-stream
/// `endobj`. Searching for the revision's `startxref` begins here, never in
/// arbitrary compressed xref payload bytes.
fn xref_structure_end(data: &[u8], offset: usize) -> Result<usize, FormatError> {
    if data.get(offset..offset.saturating_add(4)) == Some(b"xref") {
        let trailer =
            find_from(data, b"trailer", offset + 4).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference table has no trailer",
            })?;
        return dict_span(data, trailer).map(|(_, close)| close).ok_or(
            FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF trailer has no dictionary",
            },
        );
    }
    let (_, close) = dict_span(data, offset).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream has no dictionary",
    })?;
    let stream = find_from(data, b"stream", close).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream has no stream body",
    })?;
    let endstream = find_from(data, b"endstream", stream + b"stream".len()).ok_or(
        FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no endstream marker",
        },
    )?;
    let endobj = find_from(data, b"endobj", endstream + b"endstream".len()).ok_or(
        FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no endobj marker",
        },
    )?;
    Ok(endobj + b"endobj".len())
}

/// Return the trailer dictionary at an exact `startxref` target.
///
/// ISO 32000-1 section 7.5.8 puts trailer entries such as `/Root` and `/Prev`
/// directly in an xref-stream dictionary. The stream entries themselves are
/// not needed for catalog discovery because this verifier resolves indirect
/// objects from the bounded file bytes, but the xref stream is still checked
/// for its mandatory structural fields and a complete declared stream body.
fn xref_dictionary(data: &[u8], offset: usize) -> Result<&[u8], FormatError> {
    if data.get(offset..offset.saturating_add(4)) == Some(b"xref") {
        let trailer =
            find_from(data, b"trailer", offset + 4).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference table has no trailer",
            })?;
        let (open, close) = dict_span(data, trailer).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF trailer has no dictionary",
        })?;
        return Ok(&data[open..close]);
    }

    let (_, after_number) = read_uint(data, offset).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream does not begin with an indirect object",
    })?;
    let (_, after_generation) =
        read_uint(data, after_number).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no generation number",
        })?;
    let mut cursor = after_generation;
    while data.get(cursor).is_some_and(|byte| is_ws(*byte)) {
        cursor += 1;
    }
    if data.get(cursor..cursor.saturating_add(3)) != Some(b"obj")
        || data
            .get(cursor + 3)
            .is_some_and(|byte| !is_ws(*byte) && !is_delim(*byte))
    {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no indirect-object marker",
        });
    }
    let (open, close) = dict_span(data, cursor + 3).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF xref stream has no dictionary",
    })?;
    let dict = &data[open..close];
    if !has_name_value(dict, b"/Type", b"/XRef") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF startxref target is neither a table nor an xref stream",
        });
    }
    for required in [b"/Size".as_slice(), b"/W".as_slice(), b"/Length".as_slice()] {
        if find_name(dict, required).is_none() {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF xref stream is missing a required dictionary field",
            });
        }
    }
    let length_at = find_name(dict, b"/Length").unwrap();
    let (stream_len, _) =
        read_uint(dict, length_at + b"/Length".len()).ok_or(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "indirect PDF xref-stream lengths are not supported",
        })?;
    let stream_len = usize::try_from(stream_len).map_err(|_| FormatError::Truncated(FMT))?;
    let stream_keyword =
        find_from(data, b"stream", close).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF xref stream has no stream body",
        })?;
    let mut stream_start = stream_keyword + b"stream".len();
    match data.get(stream_start..stream_start.saturating_add(2)) {
        Some(b"\r\n") => stream_start += 2,
        _ if data.get(stream_start) == Some(&b'\n') => stream_start += 1,
        _ if data.get(stream_start) == Some(&b'\r') => stream_start += 1,
        _ => {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF xref stream keyword is not followed by an end-of-line marker",
            })
        }
    }
    stream_start
        .checked_add(stream_len)
        .filter(|end| *end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    Ok(dict)
}

/// Resolve the newest inherited `/Root` through classic trailers or ISO 32000
/// cross-reference streams. The `/Prev` chain is cycle-checked and bounded.
fn find_root(data: &[u8]) -> Result<Option<(u64, u64)>, FormatError> {
    let Some(startxref) = rfind(data, b"startxref") else {
        return Ok(None);
    };
    let (offset, _) =
        read_uint(data, startxref + b"startxref".len()).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF startxref offset is not a number",
        })?;
    let mut next = Some(
        usize::try_from(offset)
            .ok()
            .filter(|offset| *offset < data.len())
            .ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference offset is out of range",
            })?,
    );
    let mut visited = Vec::new();
    while let Some(offset) = next {
        if visited.contains(&offset) {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference chain contains a cycle",
            });
        }
        visited.push(offset);
        if visited.len() > MAX_PDF_REVISIONS {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "PDF has too many incremental update sections",
            });
        }
        let dict = xref_dictionary(data, offset)?;
        if let Some(position) = find_name(dict, b"/Root") {
            return read_ref(dict, position + b"/Root".len())
                .map(|(number, generation, _)| Some((number, generation)))
                .ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "PDF trailer /Root is not an indirect reference",
                });
        }
        next = find_name(dict, b"/Prev")
            .map(|position| {
                read_uint(dict, position + b"/Prev".len())
                    .and_then(|(value, _)| usize::try_from(value).ok())
                    .filter(|previous| *previous < offset)
                    .ok_or(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "PDF trailer /Prev is not a valid backward offset",
                    })
            })
            .transpose()?;
    }
    Ok(None)
}

/// True for the PDF white-space bytes (PDF 32000-1 §7.2.2).
#[inline]
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
}

/// True for PDF delimiter bytes (PDF 32000-1 §7.2.2).
#[inline]
fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// True when the name token starting at `pos` (which begins with `/`) ends
/// exactly at `pos + len`: the following byte must not be a regular character,
/// or `/AF` would also match `/AFRelationship`.
#[inline]
fn name_boundary(data: &[u8], pos: usize, len: usize) -> bool {
    match data.get(pos + len) {
        None => true,
        Some(&b) => is_ws(b) || is_delim(b),
    }
}

/// First occurrence of the name token `name` (starting with `/`) in `data`.
fn find_name(data: &[u8], name: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while let Some(p) = find_from(data, name, from) {
        if name_boundary(data, p, name.len()) {
            return Some(p);
        }
        from = p + 1;
    }
    None
}

/// Last occurrence of the name token `name` in `data`.
fn find_name_last(data: &[u8], name: &[u8]) -> Option<usize> {
    let mut last = None;
    let mut from = 0usize;
    while let Some(p) = find_from(data, name, from) {
        if name_boundary(data, p, name.len()) {
            last = Some(p);
        }
        from = p + 1;
    }
    last
}

/// True when `dict` contains `key` whose value is the name token `value`.
fn has_name_value(dict: &[u8], key: &[u8], value: &[u8]) -> bool {
    let Some(k) = find_name(dict, key) else {
        return false;
    };
    let mut i = k + key.len();
    while i < dict.len() && is_ws(dict[i]) {
        i += 1;
    }
    dict.get(i..i + value.len()) == Some(value) && name_boundary(dict, i, value.len())
}

/// Parse an `/AF`-style value at `i`: either `[ n g R ... ]` or a bare
/// `n g R`. Returns the references in declaration order.
fn parse_ref_array(data: &[u8], mut i: usize) -> Vec<(u64, u64)> {
    let mut refs = Vec::new();
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    if data.get(i) == Some(&b'[') {
        i += 1;
        loop {
            while i < data.len() && is_ws(data[i]) {
                i += 1;
            }
            if i >= data.len() || data[i] == b']' {
                break;
            }
            match read_ref(data, i) {
                Some((n, g, end)) => {
                    refs.push((n, g));
                    i = end;
                }
                None => break,
            }
        }
    } else if let Some((n, g, _)) = read_ref(data, i) {
        refs.push((n, g));
    }
    refs
}

/// The last (newest) definition of the indirect object `num gen obj`, with the
/// match required to start on a token boundary so `2 0 obj` cannot match
/// inside `12 0 obj`.
fn find_obj_last(data: &[u8], num: u64, gen: u64) -> Option<usize> {
    let needle = format!("{num} {gen} obj");
    let needle = needle.as_bytes();
    let mut last = None;
    let mut from = 0usize;
    while let Some(p) = find_from(data, needle, from) {
        let boundary_before = p == 0 || is_ws(data[p - 1]) || is_delim(data[p - 1]);
        let boundary_after = name_boundary(data, p, needle.len());
        if boundary_before && boundary_after {
            last = Some(p);
        }
        from = p + 1;
    }
    last
}

/// Find the last occurrence of `needle` in `data`.
fn rfind(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return None;
    }
    (0..=data.len() - needle.len())
        .rev()
        .find(|&i| &data[i..i + needle.len()] == needle)
}

/// Find the first occurrence of `needle` in `data` at or after `from`.
fn find_from(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let slice = data.get(from..)?;
    slice
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Read an unsigned decimal integer at `i`, skipping leading PDF white-space.
/// Returns the value and the index just past the last digit.
fn read_uint(data: &[u8], mut i: usize) -> Option<(u64, usize)> {
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    let start = i;
    while i < data.len() && data[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let mut v: u64 = 0;
    for &b in &data[start..i] {
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some((v, i))
}

/// Read an indirect reference `<num> <gen> R` at `i`. Returns
/// `(num, gen, end)` where `end` is the index just past the `R`.
fn read_ref(data: &[u8], i: usize) -> Option<(u64, u64, usize)> {
    let (num, i) = read_uint(data, i)?;
    let (gen, mut i) = read_uint(data, i)?;
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    (data.get(i) == Some(&b'R')).then_some((num, gen, i + 1))
}

/// Span of the first dictionary (`<< … >>`, nesting-aware) at or after `from`.
/// Returns `(open, end)` where `data[open..end]` is the whole `<< … >>`.
fn dict_span(data: &[u8], from: usize) -> Option<(usize, usize)> {
    let open = find_from(data, b"<<", from)?;
    let mut depth = 0usize;
    let mut i = open;
    while i + 1 < data.len() {
        if &data[i..i + 2] == b"<<" {
            depth += 1;
            i += 2;
        } else if &data[i..i + 2] == b">>" {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some((open, i));
            }
        } else {
            i += 1;
        }
    }
    None
}

/// The document `/Root` reference, `/Size`, previous `startxref`, and the raw
/// `/ID` value from the most recent classic `trailer` dictionary.
#[cfg(test)]
struct TrailerInfo {
    root_num: u64,
    root_gen: u64,
    /// Number of objects = highest object number + 1 (next free number).
    size: u64,
    prev_startxref: u64,
    /// Raw `[<hex> <hex>]` bytes of the newest `/ID`, carried into the
    /// appended trailer (PDF 32000-1 §14.4 keeps `/ID` across updates).
    id_raw: Option<Vec<u8>>,
}

/// Parse the classic cross-reference trailer(s). Errors if the PDF has no
/// `trailer` keyword (cross-reference stream) or lacks `/Root`//`/Size`.
#[cfg(test)]
fn parse_trailer(asset: &[u8]) -> Result<TrailerInfo, FormatError> {
    if rfind(asset, b"trailer").is_none() {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "cross-reference stream (no classic trailer) is not supported for embedding",
        });
    }
    // Walk every trailer dict: keep the last `/Root` and `/ID` seen (newest
    // update) and the largest `/Size` (object count only grows across
    // incremental updates).
    let mut root: Option<(u64, u64)> = None;
    let mut size: Option<u64> = None;
    let mut id_raw: Option<Vec<u8>> = None;
    let mut search = 0usize;
    while let Some(p) = find_from(asset, b"trailer", search) {
        search = p + 7;
        let Some((open, close)) = dict_span(asset, p) else {
            continue;
        };
        let dict = &asset[open..close];
        if let Some(k) = find_name(dict, b"/Root") {
            if let Some((n, g, _)) = read_ref(dict, k + 5) {
                root = Some((n, g));
            }
        }
        if let Some(k) = find_name(dict, b"/Size") {
            if let Some((s, _)) = read_uint(dict, k + 5) {
                size = Some(size.map_or(s, |cur| cur.max(s)));
            }
        }
        if let Some(k) = find_name(dict, b"/ID") {
            // Value is an array of two strings: `[<hex> <hex>]`. Hex strings
            // cannot contain `]`, so the first `]` closes the array.
            let mut i = k + 3;
            while i < dict.len() && is_ws(dict[i]) {
                i += 1;
            }
            if dict.get(i) == Some(&b'[') {
                if let Some(close_br) = find_from(dict, b"]", i) {
                    id_raw = Some(dict[i..=close_br].to_vec());
                }
            }
        }
    }
    let (root_num, root_gen) = root.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF trailer is missing /Root",
    })?;
    let size = size.ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF trailer is missing /Size",
    })?;
    let sx = rfind(asset, b"startxref").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF is missing startxref",
    })?;
    let (prev_startxref, _) = read_uint(asset, sx + 9).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "PDF startxref offset is not a number",
    })?;
    Ok(TrailerInfo {
        root_num,
        root_gen,
        size,
        prev_startxref,
        id_raw,
    })
}

/// Remove every `/AF <value>` entry from a catalog dictionary body so the
/// re-emitted catalog carries exactly one `/AF` (the new one). Duplicate keys
/// in a PDF dictionary are undefined behavior most readers resolve as
/// "last wins" -- never rely on that.
#[cfg(test)]
fn strip_af_entries(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    while let Some(af) = find_name_last(&out, b"/AF") {
        let mut j = af + 3;
        while j < out.len() && is_ws(out[j]) {
            j += 1;
        }
        let end = if out.get(j) == Some(&b'[') {
            find_from(&out, b"]", j).map(|e| e + 1)
        } else {
            read_ref(&out, j).map(|(_, _, e)| e)
        };
        match end {
            Some(e) if e <= out.len() => {
                out.drain(af..e);
            }
            _ => break,
        }
    }
    out
}

/// Embed `manifest_store` into `asset` via a PDF incremental update.
///
/// The returned bytes begin with `asset` unchanged; appended after it are the
/// manifest `/EmbeddedFile` stream, a `/Filespec`, an updated catalog object
/// (original catalog with its `/AF` replaced), a classic `xref` section, and a
/// `trailer`/`startxref`/`%%EOF` chained to the prior cross-reference section.
/// The manifest store is stored uncompressed so [`extract`] round-trips it.
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    if !asset.starts_with(b"%PDF-") {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing %PDF- header",
        });
    }
    let TrailerInfo {
        root_num,
        root_gen,
        size,
        prev_startxref,
        id_raw,
    } = parse_trailer(asset)?;

    // Locate the current catalog object body so it can be re-emitted with an
    // added /AF entry. The newest definition is the last one in byte order.
    let cat_pos =
        find_obj_last(asset, root_num, root_gen).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "catalog object not found",
        })?;
    let (cat_open, cat_close) = dict_span(asset, cat_pos).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "catalog object has no dictionary",
    })?;
    let cat_body = strip_af_entries(&asset[cat_open + 2..cat_close - 2]);

    // New object numbers: the manifest stream and its file spec.
    let manifest_num = size;
    let filespec_num = size + 1;
    let new_size = size + 2;

    let mut out = Vec::with_capacity(asset.len() + manifest_store.len() + 512);
    out.extend_from_slice(asset);
    if out.last() != Some(&b'\n') {
        out.push(b'\n');
    }

    // (1) Manifest store as an uncompressed EmbeddedFile stream.
    let off_manifest = out.len();
    out.extend_from_slice(
        format!(
            "{} 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length {} >>\nstream\n",
            manifest_num,
            manifest_store.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(manifest_store);
    out.extend_from_slice(b"\nendstream\nendobj\n");

    // (2) File specification referencing the embedded manifest.
    let off_filespec = out.len();
    out.extend_from_slice(
        format!(
            "{filespec_num} 0 obj\n<< /Type /Filespec /F (c2pa.c2pa) /UF (c2pa.c2pa) \
             /AFRelationship /C2PA_Manifest /EF << /F {manifest_num} 0 R /UF {manifest_num} 0 R >> >>\nendobj\n"
        )
        .as_bytes(),
    );

    // (3) Updated catalog: original body (minus any prior /AF) plus an /AF
    // array pointing at the new spec.
    let off_catalog = out.len();
    out.extend_from_slice(format!("{root_num} {root_gen} obj\n<<").as_bytes());
    out.extend_from_slice(&cat_body);
    out.extend_from_slice(format!(" /AF [{filespec_num} 0 R] >>\nendobj\n").as_bytes());

    // (4) Classic xref section listing only the changed/new objects, grouped
    // into ascending consecutive subsections. Each entry carries its own
    // generation (the catalog keeps its original generation).
    let mut entries = [
        (root_num, root_gen, off_catalog),
        (manifest_num, 0, off_manifest),
        (filespec_num, 0, off_filespec),
    ];
    entries.sort_by_key(|e| e.0);
    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    let mut idx = 0;
    while idx < entries.len() {
        let mut j = idx;
        while j + 1 < entries.len() && entries[j + 1].0 == entries[j].0 + 1 {
            j += 1;
        }
        out.extend_from_slice(format!("{} {}\n", entries[idx].0, j - idx + 1).as_bytes());
        for &(_, gen, off) in &entries[idx..=j] {
            // 20-byte entry: 10-digit offset, 5-digit gen, 'n', 2-byte EOL.
            out.extend_from_slice(format!("{off:010} {gen:05} n \n").as_bytes());
        }
        idx = j + 1;
    }

    // (5) Trailer chained to the prior section (carrying the original /ID
    // forward per PDF 32000-1 §14.4), then startxref/%%EOF.
    let id_part = id_raw
        .map(|id| format!(" /ID {}", String::from_utf8_lossy(&id)))
        .unwrap_or_default();
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {new_size} /Root {root_num} {root_gen} R /Prev {prev_startxref}{id_part} >>\nstartxref\n{xref_off}\n%%EOF\n"
        )
        .as_bytes(),
    );

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::tests::dummy_manifest_store;

    #[test]
    fn no_manifest_returns_none() {
        let pdf = b"%PDF-1.7\nno c2pa here\n%%EOF";
        assert_eq!(extract(pdf).unwrap(), None);
    }

    #[test]
    fn ignores_bare_jumb_ascii() {
        // The word "jumb" appearing without any /AF declaration is not a store.
        let pdf = b"%PDF-1.7\nstream contains jumb but not a box\nendstream";
        assert_eq!(extract(pdf).unwrap(), None);
    }

    /// The regression that motivated /AF-based resolution: a PDF whose page
    /// content embeds an image that carries its OWN C2PA manifest (e.g. an
    /// AI-generated JPEG). The image's manifest bytes are present raw in the
    /// file, but the document itself declares no manifest -- extract must
    /// return None, not the image's store.
    #[test]
    fn embedded_image_manifest_is_not_the_documents() {
        let mut pdf = minimal_pdf();
        // Splice a real store (as an image's DCT stream would carry it) into
        // the body without any /AF declaration.
        let image_store = dummy_manifest_store();
        let insert_at = pdf.len() - 20; // before the trailer tail
        pdf.splice(insert_at..insert_at, image_store.iter().copied());
        assert_eq!(
            extract(&pdf).unwrap(),
            None,
            "an embedded image's manifest must not be reported as the PDF's"
        );
        assert!(exclusions(&pdf).unwrap().is_empty());
    }

    /// Build a minimal valid single-page PDF with a classic xref + trailer.
    fn minimal_pdf() -> Vec<u8> {
        minimal_pdf_with_trailer_extra("")
    }

    /// Like [`minimal_pdf`], with extra raw entries appended inside the
    /// trailer dictionary (e.g. `/ID [<aa> <bb>]`).
    fn minimal_pdf_with_trailer_extra(extra: &str) -> Vec<u8> {
        let mut pdf = Vec::new();
        let mut offsets = [0usize; 4];
        pdf.extend_from_slice(b"%PDF-1.7\n");
        offsets[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets[2] = pdf.len();
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        offsets[3] = pdf.len();
        pdf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
        );
        let xref_off = pdf.len();
        pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
        for &off in &offsets[1..4] {
            pdf.extend_from_slice(format!("{:010} {:05} n \n", off, 0).as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 4 /Root 1 0 R{extra} >>\nstartxref\n").as_bytes(),
        );
        pdf.extend_from_slice(format!("{xref_off}\n%%EOF\n").as_bytes());
        pdf
    }

    fn pdf_with_xref_stream(manifest_store: &[u8]) -> Vec<u8> {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /AF [2 0 R] >>\nendobj\n");
        pdf.extend_from_slice(
            b"2 0 obj\n<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 3 0 R >> >>\nendobj\n",
        );
        pdf.extend_from_slice(
            format!(
                "3 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length {} >>\nstream\n",
                manifest_store.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(manifest_store);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        let xref_offset = pdf.len();
        // The stream body is structurally bounded but its entries need not be
        // consulted to resolve trailer key /Root.
        let entries = [0u8; 35];
        pdf.extend_from_slice(
            format!(
                "4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [1 4 2] /Length {} >>\nstream\n",
                entries.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&entries);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(format!("startxref\n{xref_offset}\n%%EOF\n").as_bytes());
        pdf
    }

    #[test]
    fn extracts_manifest_when_newest_revision_uses_xref_stream() {
        let store = dummy_manifest_store();
        let pdf = pdf_with_xref_stream(&store);
        assert_eq!(extract(&pdf).unwrap().as_deref(), Some(store.as_slice()));
        let output = crate::c2pa_validate::verify(&crate::c2pa_validate::VerifyInput {
            data: &pdf,
            mime: "application/pdf",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: crate::c2pa_core::EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        })
        .unwrap();
        assert_ne!(
            output.validation_state,
            crate::c2pa_validate::ValidationState::None,
            "xref-stream PDFs must reach manifest validation, not no-provenance"
        );
    }

    #[test]
    fn embed_round_trips_via_incremental_update() {
        let pdf = minimal_pdf();
        let store = dummy_manifest_store();
        let out = embed(&pdf, &store).unwrap();

        // (a) Output begins with the original PDF unchanged.
        assert!(
            out.starts_with(&pdf),
            "incremental update must preserve original bytes"
        );

        // (b) extract recovers the exact manifest store via /AF resolution.
        let got = extract(&out).unwrap().expect("store present after embed");
        assert_eq!(got, store, "embedded store must round-trip through extract");
    }

    #[test]
    fn appended_xref_and_trailer_are_well_formed() {
        let pdf = minimal_pdf();
        let prev_xref = read_uint(&pdf, rfind(&pdf, b"startxref").unwrap() + 9)
            .unwrap()
            .0;
        let out = embed(&pdf, &dummy_manifest_store()).unwrap();

        // The file ends with a well-formed %%EOF.
        assert!(out.ends_with(b"%%EOF\n"));

        // The final startxref points at the appended `xref` keyword.
        let sx = rfind(&out, b"startxref").unwrap();
        let (new_xref, _) = read_uint(&out, sx + 9).unwrap();
        let new_xref = new_xref as usize;
        assert_eq!(&out[new_xref..new_xref + 4], b"xref");
        // The appended xref lives in the region after the original bytes.
        assert!(new_xref >= pdf.len());

        // The new trailer chains to the original cross-reference section via
        // /Prev pointing at the original startxref offset.
        let prev_kw = find_from(&out, b"/Prev", new_xref).expect("/Prev in new trailer");
        let (prev_val, _) = read_uint(&out, prev_kw + 5).unwrap();
        assert_eq!(prev_val, prev_xref);
        // /Size and /Root reflect the two appended objects.
        let info = parse_trailer(&out).unwrap();
        assert_eq!(info.root_num, 1);
        // Two new objects (stream + filespec) grew /Size from 4 to 6.
        assert_eq!(info.size, 6);

        // The updated catalog carries an /AF reference to the file spec.
        let cat = find_obj_last(&out, 1, 0).unwrap();
        let (open, close) = dict_span(&out, cat).unwrap();
        assert!(find_name(&out[open..close], b"/AF").is_some());
    }

    #[test]
    fn trailer_id_is_carried_into_the_update() {
        let pdf = minimal_pdf_with_trailer_extra(" /ID [<aabb> <ccdd>]");
        let out = embed(&pdf, &dummy_manifest_store()).unwrap();
        // The appended (newest) trailer repeats the original /ID.
        let last_trailer = rfind(&out, b"trailer").unwrap();
        let (open, close) = dict_span(&out, last_trailer).unwrap();
        let dict = &out[open..close];
        let id = find_name(dict, b"/ID").expect("/ID carried into appended trailer");
        assert!(find_from(dict, b"<aabb>", id).is_some());
    }

    #[test]
    fn rejects_cross_reference_stream_pdf() {
        // No `trailer` keyword => modern xref stream, unsupported for embedding.
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\nstartxref\n9\n%%EOF\n";
        let err = embed(pdf, &dummy_manifest_store()).unwrap_err();
        assert!(matches!(
            err,
            FormatError::UnsupportedVariant { format: FMT, .. }
        ));
        // The bytes claim that the catalog object itself is an xref stream.
        // Discovery fails closed instead of treating that malformed target as
        // a clean PDF with no provenance.
        assert!(extract(pdf).is_err());
    }

    #[test]
    fn re_embed_returns_latest_manifest_and_single_af() {
        use crate::c2pa_core::jumbf::{assertion_box, build_manifest, build_manifest_store};
        let pdf = minimal_pdf();
        let first_store = dummy_manifest_store();
        let second_assertion = assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = build_manifest(
            "urn:c2pa:test:0002",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = build_manifest_store(&[second_manifest]);
        assert_ne!(first_store, second_store, "fixture stores must differ");

        let first = embed(&pdf, &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();

        // A PDF incremental update preserves the original manifest stream
        // verbatim; extract must still resolve the MOST RECENT one, not the
        // stale first-signed manifest still physically present earlier in
        // the file.
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice()),
            "extract must return the most recently signed manifest, not history"
        );

        // The two-pass signer's hash exclusion must track the same (latest)
        // span, or c2pa.hash.data would be computed over the wrong region.
        let ex = exclusions(&second).unwrap();
        assert_eq!(ex.len(), 1);
        assert_eq!(
            &second[ex[0].start..ex[0].start + ex[0].length],
            second_store.as_slice()
        );

        // The re-emitted catalog must carry exactly one /AF key: the old one
        // is stripped, never left behind as a duplicate dictionary key.
        let cat = find_obj_last(&second, 1, 0).unwrap();
        let (open, close) = dict_span(&second, cat).unwrap();
        let dict = &second[open..close];
        let mut count = 0;
        let mut from = 0;
        while let Some(p) = find_from(dict, b"/AF", from) {
            if name_boundary(dict, p, 3) {
                count += 1;
            }
            from = p + 1;
        }
        assert_eq!(count, 1, "catalog must have exactly one /AF key");
    }

    #[test]
    fn rejects_two_stores_introduced_by_one_update_section() {
        let base = minimal_pdf();
        let store = dummy_manifest_store();
        let previous_xref = rfind(&base, b"startxref")
            .and_then(|position| read_uint(&base, position + 9))
            .map(|(offset, _)| offset)
            .unwrap();
        let mut pdf = base;
        let mut offsets = Vec::new();
        for (stream_number, filespec_number) in [(4u64, 5u64), (6, 7)] {
            let stream_offset = pdf.len();
            pdf.extend_from_slice(
                format!(
                    "{stream_number} 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length {} >>\nstream\n",
                    store.len()
                )
                .as_bytes(),
            );
            pdf.extend_from_slice(&store);
            pdf.extend_from_slice(b"\nendstream\nendobj\n");
            offsets.push((stream_number, stream_offset));
            let filespec_offset = pdf.len();
            pdf.extend_from_slice(
                format!(
                    "{filespec_number} 0 obj\n<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F {stream_number} 0 R >> >>\nendobj\n"
                )
                .as_bytes(),
            );
            offsets.push((filespec_number, filespec_offset));
        }
        let catalog_offset = pdf.len();
        pdf.extend_from_slice(
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AF [5 0 R 7 0 R] >>\nendobj\n",
        );
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n1 1\n");
        pdf.extend_from_slice(format!("{catalog_offset:010} 00000 n \n").as_bytes());
        pdf.extend_from_slice(b"4 4\n");
        offsets.sort_by_key(|(number, _)| *number);
        for (_, offset) in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size 8 /Root 1 0 R /Prev {previous_xref} >>\nstartxref\n{xref}\n%%EOF\n"
            )
            .as_bytes(),
        );

        let sections = manifest_store_sections(&pdf).unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].defect, Some(DUPLICATE_STORES));
        assert!(matches!(
            extract(&pdf),
            Err(FormatError::InvalidStructure {
                detail: DUPLICATE_STORES,
                ..
            })
        ));
    }

    #[test]
    fn history_keeps_valid_earlier_store_when_later_store_is_malformed() {
        let pdf = minimal_pdf();
        let first_store = dummy_manifest_store();
        let first = embed(&pdf, &first_store).unwrap();
        let malformed = embed(&first, b"not a manifest store").unwrap();

        let sections = manifest_store_sections(&malformed).unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].store(&malformed), Some(first_store.as_slice()));
        assert_eq!(sections[0].defect, None);
        assert!(sections[1].store(&malformed).is_none());
        assert!(sections[1].defect.is_some());
    }

    /// Legacy two-pass signers (the pypdf path) write the store into a larger
    /// zero-padded placeholder stream: the store must be sliced by its own
    /// LBox, not the stream /Length.
    #[test]
    fn zero_padded_placeholder_stream_is_sliced_by_lbox() {
        let pdf = minimal_pdf();
        let store = dummy_manifest_store();
        let out = embed(&pdf, &store).unwrap();
        // Rewrite the embedded stream with 64 bytes of zero padding after the
        // store, updating /Length accordingly (still uncompressed).
        let kw = find_from(&out, b"stream\n", 0).unwrap();
        let data_start = kw + 7;
        let padded_len = store.len() + 64;
        let mut padded = out[..kw].to_vec();
        // Fix the /Length in the dict we just copied.
        let l = find_name(&padded, b"/Length").unwrap();
        let (old_len, digits_end) = read_uint(&padded, l + 7).unwrap();
        assert_eq!(old_len as usize, store.len());
        let digits_start = digits_end - old_len.to_string().len();
        padded.splice(
            digits_start..digits_end,
            padded_len.to_string().into_bytes(),
        );
        padded.extend_from_slice(b"stream\n");
        padded.extend_from_slice(&store);
        padded.extend_from_slice(&[0u8; 64]);
        padded.extend_from_slice(&out[data_start + store.len()..]);
        // The appended bytes move the classic xref table by the padding length.
        // Keep the hand-built fixture structurally valid by rebasing startxref.
        let startxref = rfind(&padded, b"startxref").unwrap();
        let (old_xref, digits_end) = read_uint(&padded, startxref + 9).unwrap();
        let digits_start = digits_end - old_xref.to_string().len();
        padded.splice(
            digits_start..digits_end,
            (old_xref + 64).to_string().into_bytes(),
        );
        let got = extract(&padded).unwrap().expect("store found");
        assert_eq!(got, store, "store must be sliced by its own LBox");
    }

    fn pdf_with_custom_store(stream_dictionary: &str, payload: &[u8], encrypted: bool) -> Vec<u8> {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut offsets = [0usize; 6];
        offsets[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /AF [2 0 R] >>\nendobj\n");
        offsets[2] = pdf.len();
        pdf.extend_from_slice(
            b"2 0 obj\n<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 3 0 R >> >>\nendobj\n",
        );
        offsets[3] = pdf.len();
        pdf.extend_from_slice(
            format!(
                "3 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa {stream_dictionary} >>\nstream\n"
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(payload);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets[4] = pdf.len();
        pdf.extend_from_slice(format!("4 0 obj\n{}\nendobj\n", payload.len()).as_bytes());
        offsets[5] = pdf.len();
        pdf.extend_from_slice(b"5 0 obj\n<< /Filter /Standard /V 4 >>\nendobj\n");
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in &offsets[1..] {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        let encrypt = if encrypted { " /Encrypt 5 0 R" } else { "" };
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R{encrypt} >>\nstartxref\n{xref}\n%%EOF\n")
                .as_bytes(),
        );
        pdf
    }

    #[test]
    fn filtered_identity_and_indirect_length_streams_are_read() {
        let store = dummy_manifest_store();
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&store, 6);
        let flate = pdf_with_custom_store("/Length 4 0 R /Filter /FlateDecode", &compressed, false);
        assert_eq!(extract(&flate).unwrap(), Some(store.clone()));
        assert!(matches!(
            exclusions(&flate),
            Err(FormatError::UnsupportedVariant { .. })
        ));

        let identity = pdf_with_custom_store(
            "/Length 4 0 R /Filter /Crypt /DecodeParms << /Name /Identity >>",
            &store,
            true,
        );
        assert_eq!(extract(&identity).unwrap(), Some(store.clone()));
        let spans = exclusions(&identity).unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &identity[spans[0].start..spans[0].start + spans[0].length],
            store.as_slice()
        );

        let non_identity = pdf_with_custom_store(
            "/Length 4 0 R /Filter /Crypt /DecodeParms << /Name /StdCF >>",
            &store,
            true,
        );
        assert!(matches!(
            extract(&non_identity),
            Err(FormatError::UnsupportedVariant { .. })
        ));
    }

    #[test]
    fn xref_stream_revision_history_keeps_its_store() {
        let store = dummy_manifest_store();
        let pdf = pdf_with_xref_stream(&store);
        let history = manifest_store_sections(&pdf).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].section_end, pdf.len());
        assert_eq!(history[0].store(&pdf), Some(store.as_slice()));
    }

    #[test]
    fn object_level_af_has_independent_exact_coverage() {
        let store = dummy_manifest_store();
        let resource = b"object-level-image-bytes";
        let mut pdf = b"%PDF-2.0\n".to_vec();
        let mut offsets = [0usize; 7];
        offsets[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets[2] = pdf.len();
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        offsets[3] = pdf.len();
        pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /XObject << /Im0 4 0 R >> >> >>\nendobj\n");
        offsets[4] = pdf.len();
        pdf.extend_from_slice(
            format!(
                "4 0 obj\n<< /Type /XObject /Subtype /Image /AF [6 0 R] /Length {} >>\nstream\n",
                resource.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(resource);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets[5] = pdf.len();
        pdf.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length {} >>\nstream\n",
                store.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&store);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets[6] = pdf.len();
        pdf.extend_from_slice(
            b"6 0 obj\n<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 5 0 R >> >>\nendobj\n",
        );
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
        for offset in &offsets[1..] {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );

        assert_eq!(extract(&pdf).unwrap(), None);
        let objects = object_manifest_stores(&pdf).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].owner_number, 4);
        assert_eq!(objects[0].coverage(&pdf), Some(resource.as_slice()));
        assert_eq!(objects[0].store(&pdf), Some(store.as_slice()));
        assert_eq!(objects[0].defect, None);

        let mut decoy = pdf.clone();
        decoy.extend_from_slice(b"4 0 obj\n<< /Type /XObject /AF [999 0 R] >>\nendobj\n");
        let authoritative = object_manifest_stores(&decoy).unwrap();
        assert_eq!(authoritative.len(), 1);
        assert_eq!(
            authoritative[0].coverage(&decoy),
            Some(resource.as_slice()),
            "an unreferenced duplicate object cannot supersede the xref-selected owner"
        );

        let mut malformed = pdf.clone();
        let offset_field = malformed[xref..]
            .windows(10)
            .position(|window| window == format!("{:010}", offsets[4]).as_bytes())
            .map(|relative| xref + relative)
            .unwrap();
        malformed[offset_field..offset_field + 10]
            .copy_from_slice(format!("{:010}", offsets[4] + 1).as_bytes());
        assert!(object_manifest_stores(&malformed).is_err());
    }

    #[test]
    fn compressed_object_owner_is_resolved_from_xref_stream() {
        let store = dummy_manifest_store();
        let owner = b"<< /Type /XObject /Subtype /Image /AF [6 0 R] >>";
        let mut object_stream_data = b"4 0 ".to_vec();
        object_stream_data.extend_from_slice(owner);
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&object_stream_data, 6);

        let mut pdf = b"%PDF-2.0\n".to_vec();
        let mut offsets = [0usize; 8];
        offsets[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        offsets[2] = pdf.len();
        pdf.extend_from_slice(
            format!(
                "2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length {} >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets[5] = pdf.len();
        pdf.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Fc2pa /Length {} >>\nstream\n",
                store.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&store);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        offsets[6] = pdf.len();
        pdf.extend_from_slice(
            b"6 0 obj\n<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 5 0 R >> >>\nendobj\n",
        );
        offsets[7] = pdf.len();

        let mut xref_data = Vec::new();
        for (kind, field1, field2) in [
            (0u8, 0u32, u16::MAX),
            (1, offsets[1] as u32, 0),
            (1, offsets[2] as u32, 0),
            (0, 0, 0),
            (2, 2, 0),
            (1, offsets[5] as u32, 0),
            (1, offsets[6] as u32, 0),
            (1, offsets[7] as u32, 0),
        ] {
            xref_data.push(kind);
            xref_data.extend_from_slice(&field1.to_be_bytes());
            xref_data.extend_from_slice(&field2.to_be_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "7 0 obj\n<< /Type /XRef /Size 8 /Root 1 0 R /W [1 4 2] /Length {} >>\nstream\n",
                xref_data.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&xref_data);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(format!("startxref\n{}\n%%EOF\n", offsets[7]).as_bytes());

        let objects = object_manifest_stores(&pdf).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].owner_number, 4);
        assert_eq!(objects[0].coverage(&pdf), Some(owner.as_slice()));
        assert_eq!(objects[0].store(&pdf), Some(store.as_slice()));
    }
}
