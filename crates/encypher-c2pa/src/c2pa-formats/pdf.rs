// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! PDF: C2PA manifests are carried as an embedded file stream (Subtype
//! `application/c2pa`, `AFRelationship` `C2PA_Manifest`).
//!
//! Embedding uses a PDF *incremental update*: the original bytes are preserved
//! verbatim and the manifest store is appended as an uncompressed
//! `/EmbeddedFile` stream, referenced from a `/Filespec` (`AFRelationship`
//! `C2PA_Manifest`) that is attached to the document catalog via its `/AF`
//! array. A fresh classic `xref` section plus a `trailer` carrying `/Prev`
//! (chained to the prior cross-reference section), the updated `/Root`, and the
//! original `/ID` (when present) complete the update, followed by
//! `startxref`/`%%EOF`. The test-only writer rejects source PDFs that use
//! cross-reference streams; the verification reader supports both classic
//! xref tables and xref streams.
//!
//! Extraction resolves the manifest the way the PDF spec declares it: the
//! newest xref table trailer or xref-stream dictionary `/Root` -> newest
//! catalog definition -> `/AF` array -> `/Filespec` with
//! `AFRelationship /C2PA_Manifest` -> `/EF /F`
//! embedded-file stream. The store is then sliced by its own JUMBF `LBox`
//! (legacy signers zero-pad the stream past the store). A raw JUMBF byte-scan
//! is deliberately NOT used: a PDF whose *embedded images* carry their own
//! C2PA manifests (e.g. an AI-generated JPEG inside the page content) must not
//! have an image's manifest reported as the document's. An `/AF`-declared
//! manifest stream that is compressed (`/Filter`) or has an indirect `/Length`
//! is reported as [`FormatError::UnsupportedVariant`] rather than silently
//! skipped.

use std::ops::Range;

use crate::c2pa_core::jumbf::UUID_MANIFEST_STORE;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Pdf;
const MAX_PDF_REVISIONS: usize = 64;
const MAX_AF_ENTRIES: usize = 4_096;
const DUPLICATE_STORES: &str = "PDF update section contains more than one C2PA Manifest Store";

/// One C2PA Manifest Store introduced by a PDF incremental update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PdfManifestStoreSection {
    pub section_index: usize,
    pub section_end: usize,
    store_span: Option<(usize, usize)>,
    pub defect: Option<&'static str>,
}

impl PdfManifestStoreSection {
    pub fn store<'a>(&self, asset: &'a [u8]) -> Option<&'a [u8]> {
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
            Ok(Some(span)) if !seen.contains(&span) => {
                seen.push(span);
                sections.push(PdfManifestStoreSection {
                    section_index,
                    section_end,
                    store_span: Some(span),
                    defect: None,
                });
            }
            Ok(_) => {}
            Err(error) => sections.push(PdfManifestStoreSection {
                section_index,
                section_end,
                store_span: None,
                defect: Some(defect_detail(&error)),
            }),
        }
    }
    Ok(sections)
}

/// Extract the C2PA manifest store declared by the document catalog's `/AF`
/// entry, if any.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(locate_store_span(data)?.map(|(start, length)| data[start..start + length].to_vec()))
}

/// The embedded manifest-store `jumb` superbox span as a `c2pa.hash.data`
/// exclusion. The incremental-update xref/trailer appended after it are PDF
/// structural bytes the data hash covers; only the manifest store is excluded.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate_store_span(data)?
        .map(|(start, length)| vec![DataHashExclusion { start, length }])
        .unwrap_or_default())
}

/// Resolve the `(start, length)` span of the document's C2PA manifest store by
/// walking the spec-declared path: xref trailer `/Root` -> catalog `/AF` ->
/// `/Filespec` (`AFRelationship /C2PA_Manifest`) -> `/EF /F` stream.
///
/// Returns `Ok(None)` when the document declares no `/Root`, `/AF`, or C2PA
/// filespec. Embedded images with their own manifests are invisible to this
/// resolver by design. Malformed xref streams and declared manifests that
/// cannot be read fail closed.
fn locate_store_span(data: &[u8]) -> Result<Option<(usize, usize)>, FormatError> {
    if find_root(data)?.is_none() {
        return Ok(None);
    }
    // Active extraction preserves the existing tolerant reader behavior. The
    // incremental-history path separately uses xref-defined section ranges.
    locate_store_in_section(data, 0..data.len())
}

fn locate_store_in_section(
    data: &[u8],
    section: Range<usize>,
) -> Result<Option<(usize, usize)>, FormatError> {
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
        match manifest_stream_span(data, num, generation) {
            Ok(span) => stores.push(span),
            Err(error) if section.contains(&object) => return Err(error),
            Err(_) => continue,
        }
    }
    let introduced: Vec<_> = stores
        .iter()
        .copied()
        .filter(|(start, _)| section.contains(start))
        .collect();
    if introduced.len() > 1 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: DUPLICATE_STORES,
        });
    }
    Ok(introduced
        .first()
        .copied()
        .or_else(|| stores.last().copied()))
}

fn defect_detail(error: &FormatError) -> &'static str {
    match error {
        FormatError::InvalidStructure { detail, .. }
        | FormatError::UnsupportedVariant { detail, .. } => detail,
        _ => "PDF update section declares an unreadable C2PA Manifest Store",
    }
}

/// The `(start, length)` of the manifest store inside the embedded-file stream
/// object `snum sgen obj`. The store is sliced by its own JUMBF `LBox`: legacy
/// two-pass signers write the store into a larger zero-padded placeholder, so
/// the stream `/Length` is an upper bound, not the store size.
fn manifest_stream_span(data: &[u8], snum: u64, sgen: u64) -> Result<(usize, usize), FormatError> {
    let obj_pos = find_obj_last(data, snum, sgen).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA filespec references a missing stream object",
    })?;
    let (o, c) = dict_span(data, obj_pos).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no dictionary",
    })?;
    let d = &data[o..c];
    if find_name(d, b"/Filter").is_some() {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "compressed (filtered) C2PA manifest stream is not supported",
        });
    }
    let l_pos = find_name(d, b"/Length").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no /Length",
    })?;
    if read_ref(d, l_pos + 7).is_some() {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "indirect /Length on the C2PA manifest stream is not supported",
        });
    }
    let (stream_len, _) = read_uint(d, l_pos + 7).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream /Length is not a number",
    })?;
    // The `stream` keyword follows the dictionary; data begins after its EOL
    // (CRLF or LF per PDF 32000-1 7.3.8.1).
    let kw = find_from(data, b"stream", c).ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "C2PA stream object has no stream data",
    })?;
    let mut s = kw + 6;
    if data.get(s) == Some(&b'\r') {
        s += 1;
    }
    if data.get(s) == Some(&b'\n') {
        s += 1;
    }
    let stream_end = s
        .checked_add(stream_len as usize)
        .filter(|&e| e <= data.len())
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA stream length is out of range",
        })?;
    // Validate and bound the store by its own JUMBF framing.
    let lbox = data
        .get(s..s + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "C2PA stream too short for a JUMBF box",
        })?;
    let is_store = data.get(s + 4..s + 8) == Some(b"jumb")
        && data.get(s + 12..s + 16) == Some(b"jumd")
        && data.get(s + 16..s + 32) == Some(&UUID_MANIFEST_STORE[..]);
    if !is_store || lbox < 8 || s + lbox > stream_end {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "declared C2PA stream does not hold a manifest store",
        });
    }
    Ok((s, lbox))
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
        if data.get(offset..offset.saturating_add(4)) != Some(b"xref") {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "cross-reference streams are not supported",
            });
        }
        let trailer =
            find_from(data, b"trailer", offset + 4).ok_or(FormatError::InvalidStructure {
                format: FMT,
                detail: "PDF cross-reference table has no trailer",
            })?;
        let (open, close) = dict_span(data, trailer).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "PDF trailer has no dictionary",
        })?;
        let dict = &data[open..close];
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
            find_from(data, b"startxref", close).ok_or(FormatError::InvalidStructure {
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
                    "{stream_number} 0 obj\n<< /Type /EmbeddedFile /Length {} >>\nstream\n",
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
}
