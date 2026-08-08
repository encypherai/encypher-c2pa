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
//! `startxref`/`%%EOF`. Source PDFs that use cross-reference *streams* (i.e.
//! have no `trailer` keyword) are rejected with
//! [`FormatError::UnsupportedVariant`]; classic `xref` tables are supported.
//!
//! Extraction (the verifier path) resolves the manifest the way the PDF spec
//! declares it: newest classic trailer `/Root` -> newest catalog definition ->
//! `/AF` array -> `/Filespec` with `AFRelationship /C2PA_Manifest` -> `/EF /F`
//! embedded-file stream. The store is then sliced by its own JUMBF `LBox`
//! (legacy signers zero-pad the stream past the store). A raw JUMBF byte-scan
//! is deliberately NOT used: a PDF whose *embedded images* carry their own
//! C2PA manifests (e.g. an AI-generated JPEG inside the page content) must not
//! have an image's manifest reported as the document's. An `/AF`-declared
//! manifest stream that is compressed (`/Filter`) or has an indirect `/Length`
//! is reported as [`FormatError::UnsupportedVariant`] rather than silently
//! skipped.

use crate::c2pa_core::jumbf::UUID_MANIFEST_STORE;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Pdf;

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
/// walking the spec-declared path: trailer `/Root` -> catalog `/AF` ->
/// `/Filespec` (`AFRelationship /C2PA_Manifest`) -> `/EF /F` stream.
///
/// Returns `Ok(None)` when the document declares no manifest (no classic
/// trailer, no `/AF`, or no C2PA filespec) -- embedded images with their own
/// manifests are invisible to this resolver by design. Errors only when a
/// declared manifest exists but cannot be read (compressed stream, indirect
/// length, malformed store).
fn locate_store_span(data: &[u8]) -> Result<Option<(usize, usize)>, FormatError> {
    let Some((root_num, root_gen)) = find_root(data) else {
        return Ok(None);
    };
    let Some(cat_pos) = find_obj_last(data, root_num, root_gen) else {
        return Ok(None);
    };
    let Some((cat_open, cat_close)) = dict_span(data, cat_pos) else {
        return Ok(None);
    };
    let cat = &data[cat_open..cat_close];

    // Last /AF key wins: dictionaries written by older embeds may carry
    // duplicate /AF keys, and PDF readers conventionally keep the last.
    let Some(af_pos) = find_name_last(cat, b"/AF") else {
        return Ok(None);
    };
    let refs = parse_ref_array(cat, af_pos + 3);

    // The C2PA filespec: AFRelationship /C2PA_Manifest. When several match
    // (non-conformant, but possible across foreign incremental updates), the
    // last declared one wins, matching the "newest state" rule used
    // everywhere else in this resolver.
    let mut stream_ref: Option<(u64, u64)> = None;
    for &(n, g) in &refs {
        let Some(pos) = find_obj_last(data, n, g) else {
            continue;
        };
        let Some((o, c)) = dict_span(data, pos) else {
            continue;
        };
        let spec = &data[o..c];
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
            stream_ref = Some((num, gen));
        }
    }
    let Some((snum, sgen)) = stream_ref else {
        return Ok(None);
    };
    manifest_stream_span(data, snum, sgen).map(Some)
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

/// The newest `/Root` reference from the classic trailer chain, or `None`
/// when the PDF has no classic trailer (cross-reference stream PDFs).
fn find_root(data: &[u8]) -> Option<(u64, u64)> {
    let mut root: Option<(u64, u64)> = None;
    let mut search = 0usize;
    while let Some(p) = find_from(data, b"trailer", search) {
        search = p + 7;
        let Some((open, close)) = dict_span(data, p) else {
            continue;
        };
        let dict = &data[open..close];
        if let Some(k) = find_name(dict, b"/Root") {
            if let Some((n, g, _)) = read_ref(dict, k + 5) {
                root = Some((n, g));
            }
        }
    }
    root
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
#[cfg(test)]
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
        // Extraction on the same input is a clean None, not an error: a
        // verifier must not hard-fail on PDFs we cannot embed into.
        assert_eq!(extract(pdf).unwrap(), None);
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
        let got = extract(&padded).unwrap().expect("store found");
        assert_eq!(got, store, "store must be sliced by its own LBox");
    }
}
