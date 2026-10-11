// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Standalone TTML (`application/ttml+xml`, C2PA 2.5 "Embedding manifests into
//! TTML"): the Base64 store is the content of a `c2pa:manifest` element at
//! `/tt:tt/tt:head/tt:metadata/c2pa:manifest`, and the data-hash exclusion
//! runs from the `<` of its opening tag to the `>` of its closing tag.
//!
//! Elements are matched by namespace, never by prefix: a document that binds
//! the TTML namespace as the default namespace, or the C2PA namespace to
//! another prefix, carries the same element. The scanner tracks namespace
//! declarations per element and skips comments, processing instructions,
//! CDATA sections and the document type declaration, so a `c2pa:manifest`
//! inside any of those is never mistaken for the carrier.
//!
//! TTML carried as a track inside BMFF is not this carrier: the store then
//! lives in the outer BMFF container.

use crate::c2pa_formats::util::base64_decode;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Ttml;
const TTML_NS: &str = "http://www.w3.org/ns/ttml";
const C2PA_NS: &str = "http://c2pa.org/manifest";
/// Element nesting the reader follows before refusing the document.
const MAX_DEPTH: usize = 256;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// One open element: its resolved name and the namespace bindings it adds.
struct Open<'a> {
    qname: &'a str,
    namespace: Option<String>,
    local: &'a str,
    bindings: Vec<(&'a str, String)>,
    /// Byte offset of the `<` of the start tag.
    start: usize,
    /// Byte offset just past the start tag's `>`.
    content_start: usize,
}

/// A `c2pa:manifest` element at the carrier path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Carrier {
    element_start: usize,
    element_end: usize,
    content_start: usize,
    content_end: usize,
}

/// Replace the five predefined XML entities and numeric character references
/// in an attribute value. Anything else is malformed.
fn unescape(value: &str) -> Result<String, FormatError> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let semi = after
            .find(';')
            .ok_or(invalid("unterminated entity reference"))?;
        let entity = &after[..semi];
        let decoded = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "apos" => '\'',
            "quot" => '"',
            _ => {
                let code = if let Some(hex) = entity.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = entity.strip_prefix('#') {
                    dec.parse::<u32>().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .ok_or(invalid("unknown entity reference"))?
            }
        };
        out.push(decoded);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn is_name_char(character: char) -> bool {
    !character.is_whitespace() && !matches!(character, '/' | '>' | '=' | '<' | '"' | '\'')
}

/// Parse a start tag beginning at `start` (`<` already seen). Returns the
/// element name, its attributes, the offset past `>`, and whether it is an
/// empty-element tag.
#[allow(clippy::type_complexity)]
fn parse_start_tag(
    text: &str,
    start: usize,
) -> Result<(&str, Vec<(&str, String)>, usize, bool), FormatError> {
    let bytes = text.as_bytes();
    let mut pos = start + 1;
    let name_start = pos;
    while pos < bytes.len() && is_name_char(text[pos..].chars().next().unwrap_or(' ')) {
        pos += text[pos..].chars().next().map_or(1, char::len_utf8);
    }
    if pos == name_start {
        return Err(invalid("element without a name"));
    }
    let name = &text[name_start..pos];
    let mut attributes = Vec::new();
    loop {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        match bytes.get(pos) {
            None => return Err(FormatError::Truncated(FMT)),
            Some(b'>') => return Ok((name, attributes, pos + 1, false)),
            Some(b'/') => {
                return if bytes.get(pos + 1) == Some(&b'>') {
                    Ok((name, attributes, pos + 2, true))
                } else {
                    Err(invalid("stray '/' in a start tag"))
                };
            }
            _ => {}
        }
        let attr_start = pos;
        while pos < bytes.len() && is_name_char(text[pos..].chars().next().unwrap_or(' ')) {
            pos += text[pos..].chars().next().map_or(1, char::len_utf8);
        }
        if pos == attr_start {
            return Err(invalid("malformed attribute"));
        }
        let attr = &text[attr_start..pos];
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if bytes.get(pos) != Some(&b'=') {
            return Err(invalid("attribute without a value"));
        }
        pos += 1;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let quote = *bytes.get(pos).ok_or(FormatError::Truncated(FMT))?;
        if quote != b'"' && quote != b'\'' {
            return Err(invalid("unquoted attribute value"));
        }
        let value_start = pos + 1;
        let value_end = text[value_start..]
            .find(quote as char)
            .map(|offset| value_start + offset)
            .ok_or(FormatError::Truncated(FMT))?;
        attributes.push((attr, unescape(&text[value_start..value_end])?));
        pos = value_end + 1;
    }
}

/// Resolve `prefix` against the open-element stack (innermost first).
fn resolve<'s, 'n>(
    stack: &'s [Open<'n>],
    own: &'s [(&'n str, String)],
    prefix: &str,
) -> Option<&'s str> {
    let key = if prefix.is_empty() { "xmlns" } else { prefix };
    own.iter()
        .chain(stack.iter().rev().flat_map(|open| open.bindings.iter()))
        .find(|(name, _)| *name == key)
        .map(|(_, uri)| uri.as_str())
        .filter(|uri| !uri.is_empty())
}

/// Every `c2pa:manifest` element at the TTML carrier path.
fn carriers(text: &str) -> Result<Vec<Carrier>, FormatError> {
    let mut stack: Vec<Open<'_>> = Vec::new();
    let mut found = Vec::new();
    let mut saw_root = false;
    let mut cursor = 0usize;
    while let Some(relative) = text[cursor..].find('<') {
        let start = cursor + relative;
        let rest = &text[start..];
        if let Some(body) = rest.strip_prefix("<!--") {
            let end = body.find("-->").ok_or(FormatError::Truncated(FMT))?;
            cursor = start + 4 + end + 3;
            continue;
        }
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let end = body.find("]]>").ok_or(FormatError::Truncated(FMT))?;
            cursor = start + 9 + end + 3;
            continue;
        }
        if let Some(body) = rest.strip_prefix("<?") {
            let end = body.find("?>").ok_or(FormatError::Truncated(FMT))?;
            cursor = start + 2 + end + 2;
            continue;
        }
        if rest.starts_with("<!") {
            // DOCTYPE, possibly with an internal subset in brackets.
            let mut depth = 0usize;
            let mut end = None;
            for (offset, byte) in rest.bytes().enumerate().skip(2) {
                match byte {
                    b'[' => depth += 1,
                    b']' => depth = depth.saturating_sub(1),
                    b'>' if depth == 0 => {
                        end = Some(offset);
                        break;
                    }
                    _ => {}
                }
            }
            cursor = start + end.ok_or(FormatError::Truncated(FMT))? + 1;
            continue;
        }
        if let Some(body) = rest.strip_prefix("</") {
            let gt = body.find('>').ok_or(FormatError::Truncated(FMT))?;
            let name = body[..gt].trim_end();
            let open = stack.pop().ok_or(invalid("end tag without a start tag"))?;
            if open.qname != name {
                return Err(invalid("mismatched end tag"));
            }
            let element_end = start + 2 + gt + 1;
            if is_carrier(&open, &stack) {
                found.push(Carrier {
                    element_start: open.start,
                    element_end,
                    content_start: open.content_start,
                    content_end: start,
                });
            }
            cursor = element_end;
            continue;
        }
        let (qname, attributes, after, empty) = parse_start_tag(text, start)?;
        if stack.is_empty() {
            if saw_root {
                return Err(invalid("more than one root element"));
            }
            saw_root = true;
        }
        let bindings: Vec<(&str, String)> = attributes
            .into_iter()
            .filter_map(|(name, value)| {
                if name == "xmlns" {
                    Some(("xmlns", value))
                } else {
                    name.strip_prefix("xmlns:").map(|prefix| (prefix, value))
                }
            })
            .collect();
        let (prefix, local) = qname.split_once(':').unwrap_or(("", qname));
        let namespace = resolve(&stack, &bindings, prefix).map(str::to_string);
        if !prefix.is_empty() && namespace.is_none() {
            return Err(invalid("undeclared namespace prefix"));
        }
        let open = Open {
            qname,
            namespace,
            local,
            bindings,
            start,
            content_start: after,
        };
        if empty {
            if is_carrier(&open, &stack) {
                found.push(Carrier {
                    element_start: start,
                    element_end: after,
                    content_start: after,
                    content_end: after,
                });
            }
        } else {
            if stack.len() >= MAX_DEPTH {
                return Err(FormatError::UnsupportedVariant {
                    format: FMT,
                    detail: "element nesting exceeds the verifier bound",
                });
            }
            stack.push(open);
        }
        cursor = after;
    }
    if !stack.is_empty() {
        return Err(FormatError::Truncated(FMT));
    }
    Ok(found)
}

/// `open` is `c2pa:manifest` and its ancestors are exactly `tt`, `head`,
/// `metadata` in the TTML namespace.
fn is_carrier(open: &Open<'_>, ancestors: &[Open<'_>]) -> bool {
    let ttml = |element: &Open<'_>, local: &str| {
        element.local == local && element.namespace.as_deref() == Some(TTML_NS)
    };
    open.local == "manifest"
        && open.namespace.as_deref() == Some(C2PA_NS)
        && matches!(ancestors, [tt, head, metadata]
            if ttml(tt, "tt") && ttml(head, "head") && ttml(metadata, "metadata"))
}

/// The single carrier; a document with several locates no manifest.
fn locate(data: &[u8]) -> Result<Option<Carrier>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| invalid("TTML is not valid UTF-8"))?;
    Ok(match carriers(text)?.as_slice() {
        [only] => Some(*only),
        _ => None,
    })
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let Some(carrier) = locate(data)? else {
        return Ok(None);
    };
    // The content is ASCII Base64 by definition; surrounding XML whitespace is
    // insignificant.
    let content = std::str::from_utf8(&data[carrier.content_start..carrier.content_end])
        .map_err(|_| invalid("c2pa:manifest content is not UTF-8"))?
        .trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let bytes = base64_decode(content).ok_or(invalid("invalid base64 in c2pa:manifest"))?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

/// The single data-hash exclusion: the whole `c2pa:manifest` element.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate(data)?
        .map(|carrier| DataHashExclusion {
            start: carrier.element_start,
            length: carrier.element_end - carrier.element_start,
        })
        .into_iter()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::util::base64_encode;

    fn document(head_metadata: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <tt:tt xml:lang=\"en\" xmlns:tt=\"http://www.w3.org/ns/ttml\" xmlns:c2pa=\"http://c2pa.org/manifest\">\n\
             <tt:head><tt:metadata>{head_metadata}</tt:metadata></tt:head>\n\
             <tt:body><tt:div><tt:p begin=\"00:00:01.000\" end=\"00:00:04.000\">Hi</tt:p></tt:div></tt:body>\n\
             </tt:tt>\n"
        )
    }

    #[test]
    fn extracts_the_store_and_excludes_the_whole_element() {
        let store = b"jumbf store".to_vec();
        let element = format!(
            "<c2pa:manifest>\n  {}\n</c2pa:manifest>",
            base64_encode(&store)
        );
        let text = document(&element);
        assert_eq!(extract(text.as_bytes()).unwrap(), Some(store));
        let spans = exclusions(text.as_bytes()).unwrap();
        assert_eq!(spans.len(), 1);
        let excluded = &text[spans[0].start..spans[0].start + spans[0].length];
        assert_eq!(excluded, element);
    }

    #[test]
    fn matches_by_namespace_not_prefix() {
        let store = vec![1u8, 2, 3];
        let text = format!(
            "<tt xmlns=\"http://www.w3.org/ns/ttml\"><head><metadata>\
             <m:manifest xmlns:m=\"http://c2pa.org/manifest\">{}</m:manifest>\
             </metadata></head><body/></tt>",
            base64_encode(&store)
        );
        assert_eq!(extract(text.as_bytes()).unwrap(), Some(store));
    }

    #[test]
    fn ignores_elements_off_the_carrier_path_or_in_comments() {
        let b64 = base64_encode(b"x");
        // Inside tt:body, not tt:head/tt:metadata.
        let misplaced = format!(
            "<tt:tt xmlns:tt=\"http://www.w3.org/ns/ttml\" xmlns:c2pa=\"http://c2pa.org/manifest\">\
             <tt:head/><tt:body><c2pa:manifest>{b64}</c2pa:manifest></tt:body></tt:tt>"
        );
        assert_eq!(extract(misplaced.as_bytes()).unwrap(), None);
        // Wrong namespace bound to the c2pa prefix.
        let wrong_ns = document(&format!(
            "<x:manifest xmlns:x=\"urn:other\">{b64}</x:manifest>"
        ));
        assert_eq!(extract(wrong_ns.as_bytes()).unwrap(), None);
        // Commented out.
        let commented = document(&format!("<!-- <c2pa:manifest>{b64}</c2pa:manifest> -->"));
        assert_eq!(extract(commented.as_bytes()).unwrap(), None);
    }

    #[test]
    fn two_carriers_locate_no_manifest() {
        let b64 = base64_encode(b"x");
        let text = document(&format!(
            "<c2pa:manifest>{b64}</c2pa:manifest><c2pa:manifest>{b64}</c2pa:manifest>"
        ));
        assert_eq!(extract(text.as_bytes()).unwrap(), None);
        assert!(exclusions(text.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn malformed_documents_are_rejected() {
        assert!(extract(b"<tt:tt xmlns:tt=\"http://www.w3.org/ns/ttml\"><tt:head>").is_err());
        assert!(extract(b"<tt:tt><tt:head></tt:tt>").is_err());
        assert!(extract(b"<p:tt></p:tt>").is_err(), "undeclared prefix");
        let bad_base64 = document("<c2pa:manifest>***</c2pa:manifest>");
        assert!(extract(bad_base64.as_bytes()).is_err());
    }
}
