// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Text-asset C2PA embedding through the published `c2pa-text` crate.
//!
//! Three independent C2PA 2.4 text pipelines, one per [`TextMethod`]:
//! - **A.8 unstructured** — invisible Unicode variation-selector wrapper
//!   (`c2pa_text::embed_manifest`/`extract_manifest`). The micro-format used for
//!   social posts and as the end-of-text binding for plain text.
//! - **A.9 structured** — an ASCII-armour `-----BEGIN C2PA MANIFEST-----` block
//!   (`c2pa_text::structured`) for source, config, Markdown, XML, JSON, etc.
//! - **A.7 HTML** — an inline `<script type="application/c2pa">` element
//!   (`c2pa_text::html`).
//!
//! The asset bytes are UTF-8 text. The manifest store (binary JUMBF) is carried
//! verbatim: the VS wrapper and the HTML inline script embed the raw bytes; the
//! structured block embeds a `data:application/c2pa;base64,…` reference.

use crate::c2pa_formats::{AssetFormat, FormatError};

/// Which C2PA text embedding method applies to an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextMethod {
    /// A.8 unstructured: variation-selector wrapper appended to the text.
    Unstructured,
    /// A.9 structured: ASCII-armour manifest block.
    Structured,
    /// A.7 HTML: inline `<script type="application/c2pa">`.
    Html,
}

impl TextMethod {
    fn fmt(self) -> AssetFormat {
        match self {
            TextMethod::Unstructured => AssetFormat::TextUnstructured,
            TextMethod::Structured => AssetFormat::TextStructured {
                comment_prefix: "",
                comment_suffix: "",
            },
            TextMethod::Html => AssetFormat::TextHtml,
        }
    }

    fn invalid_utf8(self) -> FormatError {
        FormatError::InvalidStructure {
            format: self.fmt(),
            detail: "text asset is not valid UTF-8",
        }
    }
}

/// Which revision's text-carrier locating rules apply.
///
/// C2PA 2.4 and 2.5 differ in how a text carrier is located, not in how its
/// hard binding is hashed:
///
/// - **Unstructured (A.8).** 2.4 names corrupted and duplicate wrappers with
///   `manifest.text.*` failure codes and selects among several wrappers by the
///   data-hash exclusion. 2.5 ignores any candidate that does not fully decode,
///   treats zero or several valid wrappers as no manifest located, and admits
///   any trailing padding: a wrapper is valid when its decoded selector run is
///   at least `manifestLength + 13` bytes, and the whole run (padding
///   included) is the wrapper's byte range. The 2.4 reader consumes only
///   `0x00`/`0xFF` padding up to the deterministic padded length.
/// - **Structured (A.9).** 2.4 reports `manifest.structuredText.*` failures.
///   2.5 treats a missing, unpaired, duplicated, empty, or unusable block as
///   no manifest located, trims only U+0020/U+0009/U+000A/U+000D, and requires
///   either a valid nonempty C2PA data URI or a syntactically valid remote URI.
/// - **HTML (A.7).** 2.4 counts matching elements anywhere in the document.
///   2.5 ignores elements outside `head`; more than one in `head` is no
///   manifest located.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum TextLocatorRules {
    /// C2PA 2.4 (and the default).
    #[default]
    V2_4,
    /// C2PA 2.5.
    V2_5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextDiagnostic {
    CorruptedWrapper,
    StructuredNoManifest,
    StructuredEmptyReference,
    StructuredMalformedReference,
    StructuredMultipleReferences,
    StructuredNoResolutionPath,
}

impl TextDiagnostic {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CorruptedWrapper => "manifest.text.corruptedWrapper",
            Self::StructuredNoManifest => "manifest.structuredText.noManifest",
            Self::StructuredEmptyReference => "manifest.structuredText.emptyReference",
            Self::StructuredMalformedReference => "manifest.structuredText.malformedReference",
            Self::StructuredMultipleReferences => "manifest.structuredText.multipleReferences",
            Self::StructuredNoResolutionPath => "manifest.structuredText.noResolutionPath",
        }
    }
}

fn uri_shape_valid(reference: &str) -> bool {
    let Some((scheme, rest)) = reference.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')))
        })
        && !rest.is_empty()
        && !reference.bytes().any(|byte| byte.is_ascii_whitespace())
}

#[derive(Debug, Clone, Copy)]
struct UnstructuredWrapper {
    start: usize,
    length: usize,
    manifest_start: usize,
    manifest_length: usize,
}

/// Every complete `C2PATextManifestWrapper` in `text`.
///
/// A candidate is a U+FEFF followed by a run of variation selectors whose
/// decoded header carries the magic, version 1, and a declared manifest length
/// the run can hold. Candidates that cannot be fully decoded are skipped
/// under both rule sets; only the measured span differs (see
/// [`TextLocatorRules`]).
fn unstructured_wrappers(text: &str, rules: TextLocatorRules) -> Vec<UnstructuredWrapper> {
    const HEADER_LEN: usize = 13;
    const MAGIC: &[u8; 8] = b"C2PATXT\0";
    const VERSION: u8 = 1;

    let mut wrappers = Vec::new();
    let mut search_from = 0usize;
    while let Some(relative) = text[search_from..].find('\u{feff}') {
        let start = search_from + relative;
        let selectors_start = start + '\u{feff}'.len_utf8();
        let mut run_end = selectors_start;
        let mut selector_count = 0usize;
        let mut header = [0u8; HEADER_LEN];
        for character in text[selectors_start..].chars() {
            let Some(byte) = crate::c2pa_formats::text_standard::vs_to_byte(character) else {
                break;
            };
            if selector_count < HEADER_LEN {
                header[selector_count] = byte;
            }
            selector_count += 1;
            run_end += character.len_utf8();
        }
        search_from = run_end.max(selectors_start);
        if selector_count < HEADER_LEN || &header[..8] != MAGIC || header[8] != VERSION {
            continue;
        }
        let manifest_length =
            u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;
        if manifest_length > crate::MAX_MANIFEST_STORE_BYTES
            || selector_count < HEADER_LEN + manifest_length
        {
            continue;
        }

        let mut position = selectors_start;
        let mut manifest_start = selectors_start;
        for (index, character) in text[selectors_start..].chars().enumerate() {
            if index == HEADER_LEN {
                manifest_start = position;
            }
            if index == HEADER_LEN + manifest_length {
                break;
            }
            position += character.len_utf8();
        }

        match rules {
            TextLocatorRules::V2_4 => {
                let padded_bound = start
                    .checked_add(c2pa_text::worst_case_wrapper_byte_length(manifest_length))
                    .unwrap_or(usize::MAX);
                for character in text[position..run_end].chars() {
                    match crate::c2pa_formats::text_standard::vs_to_byte(character) {
                        Some(0x00 | 0xff) if position + character.len_utf8() <= padded_bound => {
                            position += character.len_utf8();
                        }
                        _ => break,
                    }
                }
            }
            // 2.5 Validating a text data hash: "trailing bytes are padding and
            // shall be ignored", and "The byte range of a wrapper includes any
            // trailing padding bytes" - whatever their values.
            TextLocatorRules::V2_5 => position = run_end,
        }
        wrappers.push(UnstructuredWrapper {
            start,
            length: position - start,
            manifest_start,
            manifest_length,
        });
        if search_from <= start {
            search_from = selectors_start;
        }
    }
    wrappers
}

/// The one wrapper a reader may use: the first under 2.4, the only one under
/// 2.5 (zero or several valid wrappers locate no manifest).
fn selected_unstructured_wrapper(
    text: &str,
    rules: TextLocatorRules,
) -> Option<UnstructuredWrapper> {
    let wrappers = unstructured_wrappers(text, rules);
    match rules {
        TextLocatorRules::V2_4 => wrappers.into_iter().next(),
        TextLocatorRules::V2_5 => match wrappers.as_slice() {
            [only] => Some(*only),
            _ => None,
        },
    }
}

pub(crate) fn unstructured_wrapper_spans(
    data: &[u8],
    rules: TextLocatorRules,
) -> Result<Vec<DataHashExclusion>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| TextMethod::Unstructured.invalid_utf8())?;
    Ok(unstructured_wrappers(text, rules)
        .into_iter()
        .map(|wrapper| DataHashExclusion {
            start: wrapper.start,
            length: wrapper.length,
        })
        .collect())
}

/// The whitespace 2.5 trims from a structured-text manifest reference.
const STRUCTURED_REFERENCE_WHITESPACE: [char; 4] = [' ', '\t', '\n', '\r'];

struct StructuredTextCarrier<'a> {
    span: (usize, usize),
    reference: &'a str,
}

/// Locate the 2.5 structured-text block without decoding the store when the
/// caller needs only its exclusion span.
///
/// Locating the C2PA Manifest Store, Special Considerations for Structured
/// Text: exactly one `BEGIN`/`END` pair, END after BEGIN; otherwise no block.
fn structured_block_v2_5(text: &str) -> Option<StructuredTextCarrier<'_>> {
    let bytes = text.as_bytes();
    let begin_delimiter = c2pa_text::structured::BEGIN_DELIMITER;
    let end_delimiter = c2pa_text::structured::END_DELIMITER;
    if text.matches(begin_delimiter).count() != 1 || text.matches(end_delimiter).count() != 1 {
        return None;
    }
    let begin = text.find(begin_delimiter)? + begin_delimiter.len();
    let end = text.find(end_delimiter)?;
    if end < begin {
        return None;
    }
    // Bare CR is unsupported as a line terminator, but U+000D is one of the
    // four characters trimmed from the reference itself.
    if bytes[..begin]
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
        || bytes[end..]
            .iter()
            .enumerate()
            .any(|(offset, byte)| *byte == b'\r' && bytes.get(end + offset + 1) != Some(&b'\n'))
    {
        return None;
    }
    let reference = text[begin..end].trim_matches(STRUCTURED_REFERENCE_WHITESPACE.as_slice());
    let valid_reference = reference
        .strip_prefix(c2pa_text::structured::DATA_URI_PREFIX)
        .filter(|payload| !payload.is_empty())
        .and_then(crate::c2pa_formats::util::base64_decode)
        .is_some_and(|store| !store.is_empty())
        || (!reference.starts_with("data:") && uri_shape_valid(reference));
    if !valid_reference {
        return None;
    }
    let span = structured_block_span_v2_5(
        text,
        begin - begin_delimiter.len(),
        end + end_delimiter.len(),
    );
    Some(StructuredTextCarrier { span, reference })
}

/// The 2.5 structured-text data-hash exclusion (Structured Text, Hard
/// Binding, Manifest Blocks), read in binary mode. The block runs from the
/// first byte of the line holding `BEGIN` to the end of the line holding
/// `END` (one comment line, or the front-matter lines between them).
///
/// - At the beginning of the file: from byte 0 through the block's line
///   terminator (the whole file when the block is all there is).
/// - At the end of the file (no terminator after the block): from the line
///   terminator that precedes the block (`\n`, or `\r\n`) to end of file.
/// - Elsewhere (after a header line such as `WEBVTT` or an XML declaration,
///   or inside front matter): from the block's first byte through its line
///   terminator.
fn structured_block_span_v2_5(text: &str, begin_at: usize, end_after: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let line_start = bytes[..begin_at]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let terminated_end = bytes[end_after..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| end_after + offset + 1);
    match terminated_end {
        _ if line_start == 0 => (0, terminated_end.unwrap_or(bytes.len())),
        // The block's line is the file's last line (the END delimiter "appears
        // on the last line"), with or without a final terminator.
        None => preceding_newline_to_end(bytes, line_start),
        Some(end) if end == bytes.len() => preceding_newline_to_end(bytes, line_start),
        Some(end) => (line_start, end - line_start),
    }
}

/// From the line terminator before `line_start` (`\r\n` or `\n`) to the end
/// of the file.
fn preceding_newline_to_end(bytes: &[u8], line_start: usize) -> (usize, usize) {
    let newline = line_start - 1;
    let start = if newline > 0 && bytes[newline - 1] == b'\r' {
        newline - 1
    } else {
        newline
    };
    (start, bytes.len() - start)
}

/// The 2.5 HTML manifest carrier: the single C2PA element inside `head`.
struct HtmlHeadCarrier {
    /// Byte span of the inline `script` element, `None` for a `link`.
    script_span: Option<(usize, usize)>,
    /// The decoded inline store, `None` for a `link` or invalid Base64.
    manifest: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct HtmlStartTag {
    start: usize,
    end: usize,
    name: (usize, usize),
    attributes: (usize, usize),
    self_closing: bool,
}

#[inline]
fn html_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

#[inline]
fn html_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b':' | b'_')
}

fn ascii_eq(text: &str, span: (usize, usize), expected: &[u8]) -> bool {
    text.as_bytes()[span.0..span.1].eq_ignore_ascii_case(expected)
}

/// End of an HTML tag, respecting quoted attribute values. A `>` inside an
/// attribute value is data, not syntax.
fn html_tag_end(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    let mut quote = None;
    while let Some(&byte) = bytes.get(cursor) {
        match (quote, byte) {
            (Some(open), close) if open == close => quote = None,
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'>') => return Some(cursor + 1),
            _ => {}
        }
        cursor += 1;
    }
    None
}

/// Parse one start tag at `start`. Comments, declarations, processing
/// instructions and end tags are not start tags.
fn html_start_tag(text: &str, start: usize) -> Option<HtmlStartTag> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'<') || matches!(bytes.get(start + 1), Some(b'!' | b'?' | b'/')) {
        return None;
    }
    let name_start = start + 1;
    let mut name_end = name_start;
    while bytes
        .get(name_end)
        .is_some_and(|byte| html_name_byte(*byte))
    {
        name_end += 1;
    }
    if name_end == name_start {
        return None;
    }
    let end = html_tag_end(bytes, name_end)?;
    let mut slash = end - 1;
    while slash > name_end && html_space(bytes[slash - 1]) {
        slash -= 1;
    }
    let self_closing = slash > name_end && bytes[slash - 1] == b'/';
    let attributes_end = if self_closing { slash - 1 } else { end - 1 };
    Some(HtmlStartTag {
        start,
        end,
        name: (name_start, name_end),
        attributes: (name_end, attributes_end),
        self_closing,
    })
}

/// First declared value of `wanted` in a start tag. HTML attribute names are
/// ASCII case-insensitive; values may be single-quoted, double-quoted,
/// unquoted, empty or separated from `=` by arbitrary HTML whitespace.
fn html_attribute<'a>(text: &'a str, tag: HtmlStartTag, wanted: &[u8]) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut cursor = tag.attributes.0;
    while cursor < tag.attributes.1 {
        while cursor < tag.attributes.1 && (html_space(bytes[cursor]) || bytes[cursor] == b'/') {
            cursor += 1;
        }
        let name_start = cursor;
        while cursor < tag.attributes.1
            && !html_space(bytes[cursor])
            && !matches!(bytes[cursor], b'=' | b'/' | b'>')
        {
            cursor += 1;
        }
        let name_end = cursor;
        while cursor < tag.attributes.1 && html_space(bytes[cursor]) {
            cursor += 1;
        }
        let mut value = cursor..cursor;
        if cursor < tag.attributes.1 && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < tag.attributes.1 && html_space(bytes[cursor]) {
                cursor += 1;
            }
            if cursor < tag.attributes.1 && matches!(bytes[cursor], b'\'' | b'"') {
                let quote = bytes[cursor];
                cursor += 1;
                let value_start = cursor;
                while cursor < tag.attributes.1 && bytes[cursor] != quote {
                    cursor += 1;
                }
                value = value_start..cursor;
                if cursor < tag.attributes.1 {
                    cursor += 1;
                }
            } else {
                let value_start = cursor;
                while cursor < tag.attributes.1
                    && !html_space(bytes[cursor])
                    && bytes[cursor] != b'>'
                {
                    cursor += 1;
                }
                value = value_start..cursor;
            }
        }
        if name_end > name_start && bytes[name_start..name_end].eq_ignore_ascii_case(wanted) {
            return text.get(value);
        }
        if cursor == name_start {
            cursor += 1;
        }
    }
    None
}

/// Find the end tag for an HTML raw-text/RCDATA element. Other markup inside
/// the element is content and cannot create a manifest association.
fn html_raw_end(text: &str, name: &[u8], mut cursor: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    while cursor + 2 + name.len() <= bytes.len() {
        let relative = bytes[cursor..].iter().position(|byte| *byte == b'<')?;
        let start = cursor + relative;
        if bytes.get(start + 1) == Some(&b'/')
            && bytes
                .get(start + 2..start + 2 + name.len())
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
            && bytes
                .get(start + 2 + name.len())
                .is_some_and(|byte| html_space(*byte) || *byte == b'>')
        {
            return html_tag_end(bytes, start + 2 + name.len()).map(|end| (start, end));
        }
        cursor = start + 1;
    }
    None
}

/// Skip a template subtree. Its parsed contents live in a separate document
/// fragment and are not children of the document's `head`.
fn html_template_end(text: &str, mut cursor: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 1usize;
    while cursor < bytes.len() {
        let relative = bytes[cursor..].iter().position(|byte| *byte == b'<')?;
        let start = cursor + relative;
        if bytes.get(start..start + 4) == Some(b"<!--") {
            let close = bytes[start + 4..]
                .windows(3)
                .position(|window| window == b"-->")?;
            cursor = start + 4 + close + 3;
            continue;
        }
        if bytes.get(start + 1) == Some(&b'/') {
            let mut name_end = start + 2;
            while bytes
                .get(name_end)
                .is_some_and(|byte| html_name_byte(*byte))
            {
                name_end += 1;
            }
            let end = html_tag_end(bytes, name_end)?;
            if bytes[start + 2..name_end].eq_ignore_ascii_case(b"template") {
                depth -= 1;
                if depth == 0 {
                    return Some(end);
                }
            }
            cursor = end;
            continue;
        }
        let Some(tag) = html_start_tag(text, start) else {
            cursor = html_tag_end(bytes, start + 1).unwrap_or(bytes.len());
            continue;
        };
        if ascii_eq(text, tag.name, b"template") && !tag.self_closing {
            depth += 1;
            cursor = tag.end;
        } else if (ascii_eq(text, tag.name, b"script")
            || ascii_eq(text, tag.name, b"style")
            || ascii_eq(text, tag.name, b"title")
            || ascii_eq(text, tag.name, b"textarea")
            || ascii_eq(text, tag.name, b"xmp")
            || ascii_eq(text, tag.name, b"iframe")
            || ascii_eq(text, tag.name, b"noembed")
            || ascii_eq(text, tag.name, b"noframes"))
            && !tag.self_closing
        {
            let name = &bytes[tag.name.0..tag.name.1];
            cursor = html_raw_end(text, name, tag.end)?.1;
        } else {
            cursor = tag.end;
        }
    }
    None
}

fn html_head_content_tag(text: &str, tag: HtmlStartTag) -> bool {
    [
        b"base".as_slice(),
        b"basefont",
        b"bgsound",
        b"link",
        b"meta",
        b"noframes",
        b"noscript",
        b"script",
        b"style",
        b"template",
        b"title",
    ]
    .into_iter()
    .any(|name| ascii_eq(text, tag.name, name))
}

fn html_rel_is_c2pa(value: &str) -> bool {
    value
        .split(|character: char| character.is_ascii_whitespace())
        .any(|token| token.eq_ignore_ascii_case("c2pa-manifest"))
}

/// Locating the C2PA Manifest Store, Special Considerations for HTML (2.5).
/// This is a bounded lexical tokenizer rather than substring matching:
/// comments are skipped, tag ends honor quotes, attributes accept every HTML
/// quoting form, and markup-looking bytes in raw-text elements stay inert.
fn html_head_carrier_v2_5(text: &str) -> Option<HtmlHeadCarrier> {
    let bytes = text.as_bytes();
    let mut cursor = 0usize;
    let mut in_head = false;
    let mut saw_head = false;
    let mut matches: Vec<HtmlHeadCarrier> = Vec::new();

    while cursor < bytes.len() {
        let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == b'<') else {
            break;
        };
        let start = cursor + relative;
        let text_before_tag = &bytes[cursor..start];
        if text_before_tag.iter().any(|byte| !html_space(*byte)) {
            if in_head {
                in_head = false;
            }
            if !saw_head {
                saw_head = true;
            }
        }
        if bytes.get(start..start + 4) == Some(b"<!--") {
            let close = bytes[start + 4..]
                .windows(3)
                .position(|window| window == b"-->")?;
            cursor = start + 4 + close + 3;
            continue;
        }
        if bytes.get(start + 1) == Some(&b'/') {
            let mut name_end = start + 2;
            while bytes
                .get(name_end)
                .is_some_and(|byte| html_name_byte(*byte))
            {
                name_end += 1;
            }
            let end = html_tag_end(bytes, name_end)?;
            if bytes[start + 2..name_end].eq_ignore_ascii_case(b"head") {
                if !in_head {
                    return None;
                }
                break;
            }
            cursor = end;
            continue;
        }
        let Some(tag) = html_start_tag(text, start) else {
            cursor = html_tag_end(bytes, start + 1).unwrap_or(bytes.len());
            continue;
        };
        if ascii_eq(text, tag.name, b"head") {
            if saw_head || in_head {
                return None;
            }
            saw_head = true;
            in_head = true;
            cursor = tag.end;
            continue;
        }
        if !in_head {
            if ascii_eq(text, tag.name, b"body") {
                break;
            }
            if !saw_head && html_head_content_tag(text, tag) {
                // HTML permits both `head` tags to be omitted. The tree builder
                // inserts an implicit head around leading head-content tokens.
                saw_head = true;
                in_head = true;
            } else {
                // `html` precedes an explicit or implicit head. Any other
                // element starts the body and prevents a later head-content
                // token from opening a second, implicit head.
                if !saw_head && !ascii_eq(text, tag.name, b"html") {
                    saw_head = true;
                }
                cursor = tag.end;
                continue;
            }
        }
        if ascii_eq(text, tag.name, b"body") {
            break;
        }
        if ascii_eq(text, tag.name, b"template") {
            if tag.self_closing {
                cursor = tag.end;
            } else {
                cursor = html_template_end(text, tag.end)?;
            }
            continue;
        }
        if ascii_eq(text, tag.name, b"script") {
            if tag.self_closing {
                cursor = tag.end;
                continue;
            }
            let (close_start, close_end) = html_raw_end(text, b"script", tag.end)?;
            if html_attribute(text, tag, b"type")
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/c2pa"))
            {
                let content = &text[tag.end..close_start];
                matches.push(HtmlHeadCarrier {
                    script_span: Some((tag.start, close_end - tag.start)),
                    manifest: crate::c2pa_formats::util::base64_decode(
                        content.trim_matches(|character: char| character.is_ascii_whitespace()),
                    )
                    .filter(|store| !store.is_empty()),
                });
            }
            cursor = close_end;
            continue;
        }
        if ascii_eq(text, tag.name, b"style")
            || ascii_eq(text, tag.name, b"title")
            || ascii_eq(text, tag.name, b"textarea")
            || ascii_eq(text, tag.name, b"xmp")
            || ascii_eq(text, tag.name, b"iframe")
            || ascii_eq(text, tag.name, b"noembed")
            || ascii_eq(text, tag.name, b"noframes")
            || ascii_eq(text, tag.name, b"noscript")
        {
            let name = &bytes[tag.name.0..tag.name.1];
            cursor = html_raw_end(text, name, tag.end)?.1;
            continue;
        }
        if ascii_eq(text, tag.name, b"link")
            && html_attribute(text, tag, b"rel").is_some_and(html_rel_is_c2pa)
        {
            matches.push(HtmlHeadCarrier {
                script_span: None,
                manifest: None,
            });
        }
        cursor = tag.end;
    }
    if !saw_head || matches.len() != 1 {
        return None;
    }
    matches.pop()
}

/// The legacy (2.4) unstructured/structured carrier diagnostics. The 2.5
/// locator reports none: every defect it covers locates no manifest instead.
pub(crate) fn diagnostic(method: TextMethod, data: &[u8]) -> Option<TextDiagnostic> {
    let text = match std::str::from_utf8(data) {
        Ok(text) => text,
        Err(_) => return None,
    };
    match method {
        TextMethod::Unstructured => {
            let validation = c2pa_text::validate_text(text);
            match validation.primary_code() {
                c2pa_text::ValidationCode::Valid => None,
                c2pa_text::ValidationCode::CorruptedWrapper => {
                    Some(TextDiagnostic::CorruptedWrapper)
                }
                c2pa_text::ValidationCode::MultipleWrappers => None,
            }
        }
        TextMethod::Structured => match c2pa_text::structured::extract_structured(text) {
            Err(c2pa_text::structured::StructuredError::NoManifest) => {
                Some(TextDiagnostic::StructuredNoManifest)
            }
            Err(c2pa_text::structured::StructuredError::EmptyReference) => {
                Some(TextDiagnostic::StructuredEmptyReference)
            }
            Err(c2pa_text::structured::StructuredError::MultipleReferences) => {
                Some(TextDiagnostic::StructuredMultipleReferences)
            }
            Ok(extracted) if extracted.manifest.is_some() => None,
            Ok(extracted) if extracted.reference.starts_with("data:") => {
                Some(TextDiagnostic::StructuredMalformedReference)
            }
            Ok(extracted) if !uri_shape_valid(&extracted.reference) => {
                Some(TextDiagnostic::StructuredMalformedReference)
            }
            Ok(_) => Some(TextDiagnostic::StructuredNoResolutionPath),
        },
        TextMethod::Html => None,
    }
}

/// Extract the raw manifest-store bytes from a text asset using `method`.
pub(crate) fn extract(
    method: TextMethod,
    data: &[u8],
    rules: TextLocatorRules,
) -> Result<Option<Vec<u8>>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| method.invalid_utf8())?;
    match (method, rules) {
        (TextMethod::Unstructured, _) => {
            let Some(wrapper) = selected_unstructured_wrapper(text, rules) else {
                return Ok(None);
            };
            let manifest = text[wrapper.manifest_start..]
                .chars()
                .take(wrapper.manifest_length)
                .filter_map(crate::c2pa_formats::text_standard::vs_to_byte)
                .collect();
            Ok(Some(manifest))
        }
        (TextMethod::Structured, TextLocatorRules::V2_4) => {
            match c2pa_text::structured::extract_structured(text) {
                // Only the inline `data:` reference carries bytes; a URL reference
                // resolves elsewhere and yields no embedded manifest here.
                Ok(ext) => Ok(ext.manifest),
                Err(_) => Ok(None),
            }
        }
        (TextMethod::Structured, TextLocatorRules::V2_5) => {
            // Only a non-empty inline C2PA data URI locates a store.
            Ok(structured_block_v2_5(text)
                .and_then(|block| {
                    block
                        .reference
                        .strip_prefix(c2pa_text::structured::DATA_URI_PREFIX)
                })
                .filter(|payload| !payload.is_empty())
                .and_then(crate::c2pa_formats::util::base64_decode)
                .filter(|bytes| !bytes.is_empty()))
        }
        (TextMethod::Html, TextLocatorRules::V2_4) => match c2pa_text::html::extract_html(text) {
            Ok(Some(ext)) => Ok(ext.manifest),
            Ok(None) => Ok(None),
            Err(_) => Ok(None),
        },
        (TextMethod::Html, TextLocatorRules::V2_5) => {
            Ok(html_head_carrier_v2_5(text).and_then(|carrier| carrier.manifest))
        }
    }
}

/// Embed a manifest store into a text asset using `method`, returning the new
/// UTF-8 text bytes.
#[cfg(test)]
pub(crate) fn embed(
    method: TextMethod,
    asset: &[u8],
    manifest_store: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let text = std::str::from_utf8(asset).map_err(|_| method.invalid_utf8())?;
    let out = match method {
        TextMethod::Unstructured => {
            // Use a DETERMINISTIC fixed-length (padded) wrapper. Its UTF-8 byte
            // length depends only on the manifest BYTE COUNT, not its contents,
            // so across the two-pass data-hash signing loop (where the manifest
            // hash changes but its length is fixed) the wrapper length — and thus
            // the c2pa.hash.data exclusion offset — stays stable and the loop
            // converges. An unpadded wrapper would shift length as the hash
            // avalanches and may never converge.
            use unicode_normalization::UnicodeNormalization;
            let normalized: String = text.nfc().collect();
            let target = c2pa_text::worst_case_wrapper_byte_length(manifest_store.len());
            let wrapper =
                c2pa_text::encode_wrapper_padded(manifest_store, target).map_err(|_| {
                    FormatError::InvalidStructure {
                        format: AssetFormat::TextUnstructured,
                        detail: "padded wrapper encoding failed",
                    }
                })?;
            format!("{normalized}{wrapper}")
        }
        // Bare block (no comment markers). The comment-aware entry point used by
        // the format dispatch is `embed_structured`, which knows the host
        // language's comment syntax. `structured_text` is infallible.
        TextMethod::Structured => structured_text(text, manifest_store, "", ""),
        TextMethod::Html => {
            c2pa_text::html::embed_html_inline(text, manifest_store, "\n")
                .map_err(|_| FormatError::InvalidStructure {
                    format: AssetFormat::TextHtml,
                    detail: "html inline embed failed (document has no </head>)",
                })?
                .html
        }
    };
    Ok(out.into_bytes())
}

/// Build the A.9 structured-text bytes: a `data:application/c2pa;base64,…`
/// armour block wrapped in the given host comment delimiters and appended at
/// end-of-text ([`c2pa_text::structured::Placement::End`]). Empty delimiters
/// produce a bare block.
#[cfg(test)]
fn structured_text(
    text: &str,
    manifest_store: &[u8],
    comment_prefix: &str,
    comment_suffix: &str,
) -> String {
    let reference = c2pa_text::structured::encode_data_uri(manifest_store);
    c2pa_text::structured::embed_structured(
        text,
        &reference,
        comment_prefix,
        comment_suffix,
        c2pa_text::structured::Placement::End,
        "\n",
    )
    .text
}

/// Embed a manifest store into a structured text asset (A.9), wrapping the
/// armour block in the host language's `comment_prefix`/`comment_suffix` so the
/// signed asset stays syntactically valid (e.g. `<!--`/`-->` for XML, `/*`/`*/`
/// for CSS). Both delimiters empty embeds a bare block.
#[cfg(test)]
pub(crate) fn embed_structured(
    asset: &[u8],
    manifest_store: &[u8],
    comment_prefix: &str,
    comment_suffix: &str,
) -> Result<Vec<u8>, FormatError> {
    let text = std::str::from_utf8(asset).map_err(|_| TextMethod::Structured.invalid_utf8())?;
    Ok(structured_text(text, manifest_store, comment_prefix, comment_suffix).into_bytes())
}

use crate::c2pa_formats::DataHashExclusion;

/// Compute the `c2pa.hash.data` exclusion range for a text asset that already
/// carries an embedded manifest, per method. Returns an empty vec when no
/// manifest is present.
///
/// - A.8 unstructured: the variation-selector wrapper span
///   ([`c2pa_text::ExtractionResult`] `offset`/`length`).
/// - A.9 structured: the armour block span, located by its delimiters.
/// - A.7 HTML: the `<script type="application/c2pa">…</script>` element span.
pub(crate) fn exclusions(
    method: TextMethod,
    data: &[u8],
    rules: TextLocatorRules,
) -> Result<Vec<DataHashExclusion>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| method.invalid_utf8())?;
    let range = match (method, rules) {
        (TextMethod::Unstructured, _) => selected_unstructured_wrapper(text, rules)
            .map(|wrapper| (wrapper.start, wrapper.length)),
        (TextMethod::Structured, TextLocatorRules::V2_4) => structured_block_span(text),
        (TextMethod::Structured, TextLocatorRules::V2_5) => {
            structured_block_v2_5(text).map(|block| block.span)
        }
        (TextMethod::Html, TextLocatorRules::V2_4) => {
            locate_span(text, "<script type=\"application/c2pa\"", "</script>")
        }
        (TextMethod::Html, TextLocatorRules::V2_5) => {
            html_head_carrier_v2_5(text).and_then(|carrier| carrier.script_span)
        }
    };
    Ok(range
        .into_iter()
        .map(|(start, length)| DataHashExclusion { start, length })
        .collect())
}

/// Locate the byte span from the start of `begin` to the end of the first
/// `end` that follows it, inclusive. Returns `None` if either delimiter is
/// absent. Byte offsets (UTF-8), as required by the `c2pa.hash.data` binding.
fn locate_span(text: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let start = text.find(begin)?;
    let after_begin = start + begin.len();
    let end_rel = text[after_begin..].find(end)?;
    let end_abs = after_begin + end_rel + end.len();
    Some((start, end_abs - start))
}

/// Locate the A.9 structured manifest block's `c2pa.hash.data` exclusion
/// (C2PA 2.4 A.9.4). The armour delimiters are found first, then the span is
/// grown to the whole comment line(s) holding them, so host comment markers
/// (`<!-- … -->`, `/* … */`) are excluded with the armour. The line
/// terminators then follow A.9.4: a block appended at the end of the file is
/// excluded from the newline preceding it, and a block at the start of the file
/// is excluded through its trailing line terminator. Both match the range
/// `c2pa_text::structured::embed_structured` reports. Scanning for `\n` (0x0A)
/// is UTF-8-safe: it never occurs inside a multi-byte sequence.
fn structured_block_span(text: &str) -> Option<(usize, usize)> {
    let (start, len) = locate_span(
        text,
        c2pa_text::structured::BEGIN_DELIMITER,
        c2pa_text::structured::END_DELIMITER,
    )?;
    let bytes = text.as_bytes();
    let mut block_start = start;
    while block_start > 0 && bytes[block_start - 1] != b'\n' {
        block_start -= 1;
    }
    block_start = block_start.saturating_sub(1);
    let mut block_end = start + len;
    while block_end < bytes.len() && bytes[block_end] != b'\n' {
        block_end += 1;
    }
    if block_end < bytes.len() {
        block_end += 1;
    }
    Some((block_start, block_end - block_start))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small but structurally plausible "manifest store" stand-in. The text
    // pipelines treat it as opaque bytes, so byte-identity round-trip is the
    // contract under test.
    fn fake_store() -> Vec<u8> {
        (0u8..64)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    #[test]
    fn unstructured_diagnostics_reject_corrupt_but_defer_multiple_wrappers() {
        let mut corrupted = c2pa_text::encode_wrapper(&[1, 2, 3]);
        corrupted.pop();
        assert_eq!(
            diagnostic(TextMethod::Unstructured, corrupted.as_bytes()),
            Some(TextDiagnostic::CorruptedWrapper)
        );

        let wrapper = c2pa_text::encode_wrapper(&[1]);
        let multiple = format!("{wrapper}text{wrapper}");
        assert_eq!(
            diagnostic(TextMethod::Unstructured, multiple.as_bytes()),
            None,
            "the data-hash exclusions select the matching wrapper"
        );
    }

    #[test]
    fn structured_diagnostics_keep_failure_reasons_distinct() {
        use c2pa_text::structured::{BEGIN_DELIMITER as BEGIN, END_DELIMITER as END};

        assert_eq!(
            diagnostic(TextMethod::Structured, b"no manifest"),
            Some(TextDiagnostic::StructuredNoManifest)
        );
        assert_eq!(
            diagnostic(
                TextMethod::Structured,
                format!("{BEGIN}   {END}").as_bytes()
            ),
            Some(TextDiagnostic::StructuredEmptyReference)
        );
        assert_eq!(
            diagnostic(
                TextMethod::Structured,
                format!("{BEGIN} not a uri {END}").as_bytes()
            ),
            Some(TextDiagnostic::StructuredMalformedReference)
        );
        assert_eq!(
            diagnostic(
                TextMethod::Structured,
                format!("{BEGIN} https://example.invalid/manifest.c2pa {END}").as_bytes()
            ),
            Some(TextDiagnostic::StructuredNoResolutionPath)
        );
        assert_eq!(
            diagnostic(
                TextMethod::Structured,
                format!("{BEGIN} data:application/c2pa;base64,AA== {END}{BEGIN} data:application/c2pa;base64,AQ== {END}")
                    .as_bytes()
            ),
            Some(TextDiagnostic::StructuredMultipleReferences)
        );
    }

    /// Parse a hex string to bytes.
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Golden vectors copied verbatim from `c2pa-text/golden/vectors.json` (the
    // cross-language SSOT). These prove the engine's text embed is byte-identical
    // to the published c2pa-text crate — and guard against the dependency drifting.

    #[test]
    fn golden_unstructured_ascii_small() {
        // vectors.json unstructured_embed[ascii_small]. The engine's sign path
        // pads the wrapper for two-pass convergence, so we assert byte-parity
        // against the SSOT's UNPADDED `embed_manifest` directly (proving the
        // c2pa-text dependency is the right version/codec), then confirm the
        // engine's padded embed still extracts the same manifest.
        let manifest = unhex("deadbeef");
        let expected = unhex("68656c6c6f20776f726c64efbbbff3a084b3f3a084a2f3a08580f3a084b1f3a08584f3a08588f3a08584efb880efb881efb880efb880efb880efb884f3a0878ef3a0869df3a086aef3a0879f");
        let ssot = c2pa_text::embed_manifest("hello world", &manifest);
        assert_eq!(
            ssot.into_bytes(),
            expected,
            "SSOT VS wrapper must match golden"
        );
        // Engine padded embed: different bytes (padded) but same extracted manifest.
        let engine = embed(TextMethod::Unstructured, b"hello world", &manifest).unwrap();
        assert_eq!(
            extract(TextMethod::Unstructured, &engine, TextLocatorRules::V2_4).unwrap(),
            Some(manifest)
        );
    }

    #[test]
    fn golden_html_inline_small() {
        // vectors.json html_inline[inline_small]
        let manifest = unhex("deadbeef");
        let html = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Example</title>\n</head>\n<body>\n<p>Content here.</p>\n</body>\n</html>\n";
        let expected = unhex("3c21444f43545950452068746d6c3e0a3c68746d6c206c616e673d22656e223e0a3c686561643e0a3c6d65746120636861727365743d227574662d38223e0a3c7469746c653e4578616d706c653c2f7469746c653e0a3c73637269707420747970653d226170706c69636174696f6e2f63327061223e3371322b37773d3d3c2f7363726970743e0a3c2f686561643e0a3c626f64793e0a3c703e436f6e74656e7420686572652e3c2f703e0a3c2f626f64793e0a3c2f68746d6c3e0a");
        let out = embed(TextMethod::Html, html.as_bytes(), &manifest).unwrap();
        assert_eq!(
            out, expected,
            "HTML inline embed must match c2pa-text golden"
        );
    }

    #[test]
    fn unstructured_round_trips() {
        let store = fake_store();
        let embedded = embed(TextMethod::Unstructured, b"a social post", &store).unwrap();
        let out = extract(TextMethod::Unstructured, &embedded, TextLocatorRules::V2_4).unwrap();
        assert_eq!(out, Some(store));
        // Carrier text is preserved as a visible prefix.
        assert!(String::from_utf8(embedded)
            .unwrap()
            .starts_with("a social post"));
    }

    #[test]
    fn structured_round_trips() {
        let store = fake_store();
        let src = "# Title\n\nsome markdown body\n";
        let embedded = embed(TextMethod::Structured, src.as_bytes(), &store).unwrap();
        let text = String::from_utf8(embedded.clone()).unwrap();
        assert!(text.contains("BEGIN C2PA MANIFEST"));
        let out = extract(TextMethod::Structured, &embedded, TextLocatorRules::V2_4).unwrap();
        assert_eq!(out, Some(store));
    }

    #[test]
    fn html_round_trips() {
        let store = fake_store();
        let html = "<html><head><title>x</title></head><body>hi</body></html>";
        let embedded = embed(TextMethod::Html, html.as_bytes(), &store).unwrap();
        let text = String::from_utf8(embedded.clone()).unwrap();
        assert!(text.contains("application/c2pa"));
        let out = extract(TextMethod::Html, &embedded, TextLocatorRules::V2_4).unwrap();
        assert_eq!(out, Some(store));
    }

    #[test]
    fn no_manifest_is_none_not_error() {
        for rules in [TextLocatorRules::V2_4, TextLocatorRules::V2_5] {
            assert_eq!(
                extract(TextMethod::Unstructured, b"plain text", rules).unwrap(),
                None
            );
            assert_eq!(
                extract(TextMethod::Structured, b"plain text", rules).unwrap(),
                None
            );
            assert_eq!(
                extract(TextMethod::Html, b"<html></html>", rules).unwrap(),
                None
            );
        }
    }

    #[test]
    fn invalid_utf8_errors() {
        for rules in [TextLocatorRules::V2_4, TextLocatorRules::V2_5] {
            assert!(extract(TextMethod::Unstructured, &[0xff, 0xfe], rules).is_err());
        }
    }

    #[test]
    fn structured_comment_wrapped_round_trips() {
        let store = fake_store();
        let src = "body { color: red }\n";
        // CSS comment delimiters: /* … */ — keeps the signed source valid CSS.
        let embedded = embed_structured(src.as_bytes(), &store, "/*", "*/").unwrap();
        let text = String::from_utf8(embedded.clone()).unwrap();
        assert!(text.contains("/* -----BEGIN C2PA MANIFEST-----"));
        assert!(text.trim_end().ends_with("*/"));
        assert!(text.starts_with(src));
        // Manifest round-trips despite the comment wrapping.
        assert_eq!(
            extract(TextMethod::Structured, &embedded, TextLocatorRules::V2_4).unwrap(),
            Some(store)
        );
        // The data-hash exclusion spans the WHOLE comment block (markers
        // included) from its preceding newline (A.9.4).
        let ex = exclusions(TextMethod::Structured, &embedded, TextLocatorRules::V2_4).unwrap();
        assert_eq!(ex.len(), 1);
        let excluded = &embedded[ex[0].start..ex[0].start + ex[0].length];
        assert!(excluded.starts_with(b"\n/* -----BEGIN C2PA MANIFEST-----"));
        assert!(excluded.ends_with(b"*/"));
        assert_eq!(ex[0].start, src.len());
        assert_eq!(&embedded[..src.len()], src.as_bytes());
    }

    /// Append padding selectors for `bytes` after an encoded wrapper.
    fn with_padding(wrapper: &str, bytes: &[u8]) -> String {
        let mut padded = wrapper.to_string();
        for byte in bytes {
            padded.push(crate::c2pa_formats::text_standard::byte_to_vs(*byte));
        }
        padded
    }

    #[test]
    fn unstructured_padding_span_differs_by_revision() {
        let store = fake_store();
        let wrapper = c2pa_text::encode_wrapper(&store);
        // The 2.5 generator procedure pads with 0x00 then 0x10 bytes; the 2.4
        // reader consumes only 0x00/0xFF padding, so it stops at the first 0x10.
        let text = format!("post{}", with_padding(&wrapper, &[0x00, 0x00, 0x10, 0x10]));
        let v24 = unstructured_wrapper_spans(text.as_bytes(), TextLocatorRules::V2_4).unwrap();
        let v25 = unstructured_wrapper_spans(text.as_bytes(), TextLocatorRules::V2_5).unwrap();
        assert_eq!(v24.len(), 1);
        assert_eq!(v25.len(), 1);
        assert_eq!(v24[0].start, 4);
        assert_eq!(v25[0].start, 4);
        assert_eq!(
            v25[0].length,
            text.len() - 4,
            "2.5 wrapper range includes every trailing padding selector"
        );
        assert_eq!(
            v25[0].length - v24[0].length,
            2 * '\u{E0100}'.len_utf8(),
            "2.4 stops before the 0x10 padding"
        );
        // Both revisions decode the same store: padding never enters it.
        for rules in [TextLocatorRules::V2_4, TextLocatorRules::V2_5] {
            assert_eq!(
                extract(TextMethod::Unstructured, text.as_bytes(), rules).unwrap(),
                Some(store.clone())
            );
        }
        // Existing 0xFF padding stays admitted under 2.5.
        let legacy = format!("post{}", with_padding(&wrapper, &[0xff, 0xff, 0xff]));
        assert_eq!(
            extract(
                TextMethod::Unstructured,
                legacy.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            Some(store.clone())
        );
        let legacy_v25 =
            unstructured_wrapper_spans(legacy.as_bytes(), TextLocatorRules::V2_5).unwrap();
        let legacy_v24 =
            unstructured_wrapper_spans(legacy.as_bytes(), TextLocatorRules::V2_4).unwrap();
        assert_eq!(legacy_v25, legacy_v24);
    }

    #[test]
    fn unstructured_multiple_wrappers_locate_nothing_under_v2_5() {
        let first = c2pa_text::encode_wrapper(&[1, 2, 3]);
        let second = c2pa_text::encode_wrapper(&[4, 5, 6]);
        let text = format!("{first} text {second}");
        assert_eq!(
            extract(
                TextMethod::Unstructured,
                text.as_bytes(),
                TextLocatorRules::V2_4
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            extract(
                TextMethod::Unstructured,
                text.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );
        assert!(exclusions(
            TextMethod::Unstructured,
            text.as_bytes(),
            TextLocatorRules::V2_5
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn unstructured_malformed_candidate_is_ignored_under_v2_5() {
        let mut truncated = c2pa_text::encode_wrapper(&[9, 9, 9]);
        truncated.pop();
        let valid = c2pa_text::encode_wrapper(&[7, 7]);
        let text = format!("{truncated} body {valid}");
        assert_eq!(
            extract(
                TextMethod::Unstructured,
                text.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            Some(vec![7, 7])
        );
        assert_eq!(
            extract(
                TextMethod::Unstructured,
                truncated.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn structured_v2_5_trims_only_ascii_whitespace_and_requires_c2pa_data_uri() {
        use c2pa_text::structured::{BEGIN_DELIMITER as BEGIN, END_DELIMITER as END};

        let inline = format!("x\n# {BEGIN}\t data:application/c2pa;base64,AQID \r{END}\n");
        for rules in [TextLocatorRules::V2_4, TextLocatorRules::V2_5] {
            assert_eq!(
                extract(TextMethod::Structured, inline.as_bytes(), rules).unwrap(),
                Some(vec![1, 2, 3])
            );
        }
        // U+00A0 is Unicode whitespace (trimmed by 2.4's reader) but not one of
        // the four characters 2.5 trims, so the 2.5 reference is not a data URI.
        let nbsp = format!("x\n# {BEGIN}\u{a0}data:application/c2pa;base64,AQID {END}\n");
        assert_eq!(
            extract(
                TextMethod::Structured,
                nbsp.as_bytes(),
                TextLocatorRules::V2_4
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            extract(
                TextMethod::Structured,
                nbsp.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );
        let wrong_type = format!("# {BEGIN} data:text/plain;base64,AQID {END}\n");
        let bad_base64 = format!("# {BEGIN} data:application/c2pa;base64,*** {END}\n");
        let doubled = format!("{inline}{inline}");
        for text in [wrong_type, bad_base64, doubled] {
            assert_eq!(
                extract(
                    TextMethod::Structured,
                    text.as_bytes(),
                    TextLocatorRules::V2_5
                )
                .unwrap(),
                None
            );
            assert!(
                exclusions(
                    TextMethod::Structured,
                    text.as_bytes(),
                    TextLocatorRules::V2_5
                )
                .unwrap()
                .is_empty()
                    || text.matches(BEGIN).count() == 1
            );
        }
    }

    #[test]
    fn structured_v2_5_exclusion_geometry_follows_block_position() {
        use c2pa_text::structured::{BEGIN_DELIMITER as BEGIN, END_DELIMITER as END};

        let block = format!("# {BEGIN} data:application/c2pa;base64,AQID {END}");
        let span = |text: &str| {
            let spans = exclusions(
                TextMethod::Structured,
                text.as_bytes(),
                TextLocatorRules::V2_5,
            )
            .unwrap();
            assert_eq!(spans.len(), 1, "{text:?}");
            text[spans[0].start..spans[0].start + spans[0].length].to_string()
        };
        // Beginning: the block line and its terminator.
        assert_eq!(span(&format!("{block}\nbody\n")), format!("{block}\n"));
        // Whole file.
        assert_eq!(span(&block), block);
        // End, LF and CRLF: from the preceding terminator to end of file.
        assert_eq!(span(&format!("body\n{block}")), format!("\n{block}"));
        assert_eq!(
            span(&format!("body\r\n{block}\r\n")),
            format!("\r\n{block}\r\n")
        );
        // After a reserved header line (WebVTT): the block line and terminator.
        let vtt_block = format!("NOTE {BEGIN} https://e.example/m.c2pa {END}");
        let vtt = format!("WEBVTT\n\n{vtt_block}\n\n00:00:00.000 --> 00:00:05.000\nHi\n");
        assert_eq!(span(&vtt), format!("{vtt_block}\n"));
        // Front matter: only the BEGIN..END lines, not the `---` delimiters.
        let front = format!("---\n{BEGIN}\nhttps://e.example/m.c2pa\n{END}\ntitle: x\n---\nbody\n");
        assert_eq!(
            span(&front),
            format!("{BEGIN}\nhttps://e.example/m.c2pa\n{END}\n")
        );
    }

    #[test]
    fn html_v2_5_scopes_discovery_to_head() {
        let body_only = "<html><head><title>t</title></head><body>\
            <script type=\"application/c2pa\">AQID</script></body></html>";
        assert_eq!(
            extract(
                TextMethod::Html,
                body_only.as_bytes(),
                TextLocatorRules::V2_4
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            extract(
                TextMethod::Html,
                body_only.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );

        let head_and_body = "<html><HEAD>\n<script type=\"application/c2pa\"> AQID\n</script>\
            </head><body><script type=\"application/c2pa\">BAUG</script></body></html>";
        assert_eq!(
            extract(
                TextMethod::Html,
                head_and_body.as_bytes(),
                TextLocatorRules::V2_4
            )
            .unwrap(),
            None,
            "2.4 counts the body element and finds two"
        );
        assert_eq!(
            extract(
                TextMethod::Html,
                head_and_body.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        let span = exclusions(
            TextMethod::Html,
            head_and_body.as_bytes(),
            TextLocatorRules::V2_5,
        )
        .unwrap();
        assert_eq!(span.len(), 1);
        let excluded = &head_and_body[span[0].start..span[0].start + span[0].length];
        assert!(excluded.starts_with("<script") && excluded.ends_with("</script>"));
        assert!(excluded.contains("AQID"));

        let two_in_head = "<html><head><script type=\"application/c2pa\">AQID</script>\
            <link rel=\"c2pa-manifest\" href=\"https://x/m.c2pa\"></head></html>";
        assert_eq!(
            extract(
                TextMethod::Html,
                two_in_head.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );
        let header_not_head = "<header><script type=\"application/c2pa\">AQID</script></header>";
        assert_eq!(
            extract(
                TextMethod::Html,
                header_not_head.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn html_v2_5_tokenizer_handles_attributes_comments_and_raw_text() {
        let valid = "<html><HeAd data-note='>'>\
            <!-- <script type=\"application/c2pa\">AAAA</script> -->\
            <style>.x::after{content:'<link rel=c2pa-manifest>'}</style>\
            <SCRIPT disabled TYPE = 'APPLICATION/C2PA'> AQID </ScRiPt>\
            </head><body><script type=application/c2pa>BAUG</script></body></html>";
        assert_eq!(
            extract(TextMethod::Html, valid.as_bytes(), TextLocatorRules::V2_5).unwrap(),
            Some(vec![1, 2, 3])
        );
        let ranges =
            exclusions(TextMethod::Html, valid.as_bytes(), TextLocatorRules::V2_5).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            &valid[ranges[0].start..ranges[0].start + ranges[0].length],
            "<SCRIPT disabled TYPE = 'APPLICATION/C2PA'> AQID </ScRiPt>"
        );

        let external = "<html><head><link href=https://e.example/m.c2pa \
                        REL='alternate C2PA-MANIFEST' data-note='>'></head></html>";
        assert_eq!(
            extract(
                TextMethod::Html,
                external.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            None,
            "external resolution is optional and does not expose embedded bytes"
        );
        assert!(
            exclusions(
                TextMethod::Html,
                external.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap()
            .is_empty(),
            "an external link binds the complete HTML byte stream"
        );
    }

    #[test]
    fn html_v2_5_comments_and_raw_text_cannot_create_duplicates() {
        let html = "<html><head>\
            <script type='text/plain'>\
              <script type='application/c2pa'>AAAA</script>\
            </script>\
            <textarea><link rel='c2pa-manifest'></textarea>\
            <script type=application/c2pa>AQID</script>\
            </head></html>";
        assert_eq!(
            extract(TextMethod::Html, html.as_bytes(), TextLocatorRules::V2_5).unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn html_v2_5_handles_implicit_head_and_ignores_template_contents() {
        let implicit = "<!doctype html><title>T</title>\
            <script type=application/c2pa>AQID</script><body>content";
        assert_eq!(
            extract(
                TextMethod::Html,
                implicit.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );

        let template = "<html><head><template>\
            <script type=application/c2pa>AAAA</script>\
            <template><link rel=c2pa-manifest></template>\
            </template><script type=application/c2pa>AQID</script></head></html>";
        assert_eq!(
            extract(
                TextMethod::Html,
                template.as_bytes(),
                TextLocatorRules::V2_5
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn structured_v2_5_refuses_invalid_reference_geometry() {
        use c2pa_text::structured::{BEGIN_DELIMITER as BEGIN, END_DELIMITER as END};

        for text in [
            format!("# {BEGIN} data:application/c2pa;base64,*** {END}\n"),
            format!("# {BEGIN} data:text/plain;base64,AQID {END}\n"),
            format!("# {BEGIN} relative/path.c2pa {END}\n"),
            format!("# {BEGIN} data:application/c2pa;base64,AQID {END}\rbody"),
        ] {
            assert!(
                exclusions(
                    TextMethod::Structured,
                    text.as_bytes(),
                    TextLocatorRules::V2_5
                )
                .unwrap()
                .is_empty(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn structured_exclusion_is_the_a94_range_for_either_placement() {
        // A.9.4 includes the preceding newline at EOF, or the trailing
        // terminator at the start of the file.
        use c2pa_text::structured::{embed_structured, encode_data_uri, Placement};
        let reference = encode_data_uri(&fake_store());
        for (placement, host) in [
            (Placement::End, "# Title\n\nsome markdown body\n"),
            (Placement::End, "# Title without a final newline"),
            (Placement::Start, "body { color: red }\n"),
        ] {
            let signed = embed_structured(host, &reference, "<!--", "-->", placement, "\n");
            let ex = exclusions(
                TextMethod::Structured,
                signed.text.as_bytes(),
                TextLocatorRules::V2_4,
            )
            .unwrap();
            assert_eq!(
                ex.iter().map(|e| (e.start, e.length)).collect::<Vec<_>>(),
                vec![(signed.exclusion_start, signed.exclusion_length)],
                "{placement:?}: {host:?}"
            );
        }
    }
}
