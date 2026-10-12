// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Append-only plain text and JSON Lines (C2PA 2.5 "Embedding manifests into
//! append-only text files" and "Special Considerations for Append-Only Text
//! Files"): a rolling chain of checkpoints, each a complete sentinel line
//! appended after the segment it covers.
//!
//! A plain-text sentinel is the line
//! `-----BEGIN C2PA CHECKPOINT----- <reference> -----END C2PA CHECKPOINT-----`;
//! a JSONL sentinel is a JSON object line with a `c2pa:checkpoint` string
//! member. The reference is an external URI or a
//! `data:application/c2pa;base64,` URI carrying the store inline.
//!
//! The active checkpoint is the last complete sentinel line, found by
//! scanning complete lines from the end. If that last candidate is malformed
//! no manifest is located (`manifest.appendOnlyText.noSentinel`). Byte
//! offsets are those of the file read in binary mode, and a sentinel's length
//! includes its LF or CRLF terminator.

use crate::c2pa_formats::util::base64_decode;
use crate::c2pa_formats::{DataHashExclusion, FormatError};

pub(crate) const BEGIN_CHECKPOINT: &str = "-----BEGIN C2PA CHECKPOINT-----";
pub(crate) const END_CHECKPOINT: &str = "-----END C2PA CHECKPOINT-----";
const JSONL_MEMBER: &str = "c2pa:checkpoint";
/// The quoted member name a JSONL sentinel candidate contains.
const JSONL_NEEDLE: &[u8] = b"\"c2pa:checkpoint\"";
const DATA_URI_PREFIX: &str = "data:application/c2pa;base64,";
/// The whitespace trimmed from a manifest reference.
const REFERENCE_WHITESPACE: [char; 4] = [' ', '\t', '\n', '\r'];

/// The line grammar a file's sentinels use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppendOnlyFlavor {
    /// Plain-text logs (`text/plain`): armour-delimited sentinel lines.
    PlainText,
    /// JSON Lines: `{"c2pa:checkpoint": "<reference>"}` lines.
    JsonLines,
}

/// Where a checkpoint's store lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SentinelReference {
    /// The decoded store carried inline in a `data:` URI.
    Inline(Vec<u8>),
    /// An external URI the store must be retrieved from.
    External(String),
}

/// One complete sentinel line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sentinel {
    /// Byte offset of the line's first byte.
    pub(crate) start: usize,
    /// Byte length including the line terminator.
    pub(crate) length: usize,
    pub(crate) reference: SentinelReference,
}

/// What the active-checkpoint scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Located {
    /// No candidate line at all.
    None,
    /// The last candidate line is malformed or its reference is unusable.
    Malformed,
    /// The active checkpoint.
    Active(Sentinel),
}

/// Complete lines of `data`, each as `(start, content_end, line_end)`, where
/// `content_end` excludes the LF/CRLF terminator and `line_end` includes it.
/// A final unterminated fragment is not a complete line.
fn complete_lines(data: &[u8]) -> impl DoubleEndedIterator<Item = (usize, usize, usize)> + '_ {
    let mut starts = Vec::new();
    let mut start = 0usize;
    for (index, byte) in data.iter().enumerate() {
        if *byte == b'\n' {
            let content_end = if index > start && data[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            starts.push((start, content_end, index + 1));
            start = index + 1;
        }
    }
    starts.into_iter()
}

/// Whether a line is a sentinel candidate for `flavor`: plain text begins
/// with the BEGIN delimiter; a JSONL line names the `c2pa:checkpoint` member.
fn is_candidate(line: &[u8], flavor: AppendOnlyFlavor) -> bool {
    match flavor {
        AppendOnlyFlavor::PlainText => line.starts_with(BEGIN_CHECKPOINT.as_bytes()),
        AppendOnlyFlavor::JsonLines => line
            .windows(JSONL_NEEDLE.len())
            .any(|window| window == JSONL_NEEDLE),
    }
}

/// The reference text of a candidate line, `None` when the line is malformed.
fn reference_text(line: &[u8], flavor: AppendOnlyFlavor) -> Option<String> {
    let text = std::str::from_utf8(line).ok()?;
    match flavor {
        AppendOnlyFlavor::PlainText => {
            let inner = text
                .strip_prefix(BEGIN_CHECKPOINT)?
                .strip_suffix(END_CHECKPOINT)?;
            Some(inner.to_string())
        }
        AppendOnlyFlavor::JsonLines => {
            let value: serde_json::Value = serde_json::from_str(text).ok()?;
            let object = value.as_object()?;
            object.get(JSONL_MEMBER)?.as_str().map(str::to_string)
        }
    }
}

/// Resolve a reference: an inline store, or an external URI. `None` for an
/// unusable reference (empty, a `data:` URI of another type or encoding, or
/// invalid Base64).
fn resolve(reference: &str) -> Option<SentinelReference> {
    let reference = reference.trim_matches(REFERENCE_WHITESPACE.as_slice());
    if reference.is_empty() {
        return None;
    }
    if let Some(payload) = reference.strip_prefix(DATA_URI_PREFIX) {
        let store = base64_decode(payload).filter(|store| !store.is_empty())?;
        if store.len() > crate::MAX_MANIFEST_STORE_BYTES {
            return None;
        }
        return Some(SentinelReference::Inline(store));
    }
    if reference
        .get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"))
    {
        return None;
    }
    let (scheme, rest) = reference.split_once(':')?;
    let scheme_ok = scheme
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    (scheme_ok && !rest.is_empty() && !reference.chars().any(char::is_whitespace))
        .then(|| SentinelReference::External(reference.to_string()))
}

/// Locate the active checkpoint.
pub(crate) fn locate_active(data: &[u8], flavor: AppendOnlyFlavor) -> Located {
    for (start, content_end, line_end) in complete_lines(data).rev() {
        let line = &data[start..content_end];
        if !is_candidate(line, flavor) {
            continue;
        }
        return match reference_text(line, flavor).as_deref().and_then(resolve) {
            Some(reference) => Located::Active(Sentinel {
                start,
                length: line_end - start,
                reference,
            }),
            None => Located::Malformed,
        };
    }
    Located::None
}

/// The sentinel line beginning exactly at `start`, if a well-formed one
/// does. Used to check that a checkpoint's `segmentEnd` lands on its own
/// sentinel and to read a predecessor's sentinel.
pub(crate) fn sentinel_at(data: &[u8], start: usize, flavor: AppendOnlyFlavor) -> Option<Sentinel> {
    if start > data.len() || (start > 0 && data[start - 1] != b'\n') {
        return None;
    }
    let newline = data[start..].iter().position(|byte| *byte == b'\n')?;
    let line_end = start + newline + 1;
    let mut content_end = start + newline;
    if content_end > start && data[content_end - 1] == b'\r' {
        content_end -= 1;
    }
    let line = &data[start..content_end];
    if !is_candidate(line, flavor) {
        return None;
    }
    let reference = resolve(&reference_text(line, flavor)?)?;
    Some(Sentinel {
        start,
        length: line_end - start,
        reference,
    })
}

/// Whether the file carries any complete checkpoint sentinel line. The two
/// text methods are told apart by their delimiters alone, so this decides
/// whether a `text/plain` asset is read as append-only text.
pub(crate) fn declares_checkpoints(data: &[u8], flavor: AppendOnlyFlavor) -> bool {
    complete_lines(data)
        .any(|(start, content_end, _)| is_candidate(&data[start..content_end], flavor))
}

/// The inline store of the active checkpoint. An external reference, a
/// malformed last candidate, or no candidate locates no embedded store; the
/// validator reports those outcomes itself from [`locate_active`].
pub(crate) fn extract(
    data: &[u8],
    flavor: AppendOnlyFlavor,
) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(match locate_active(data, flavor) {
        Located::Active(Sentinel {
            reference: SentinelReference::Inline(store),
            ..
        }) => Some(store),
        _ => None,
    })
}

/// The active sentinel line. A checkpoint binds its content with
/// `c2pa.hash.segment`, never with a data hash; the span is reported so a
/// data hash a non-conforming generator wrote is measured against the real
/// carrier rather than against nothing.
pub(crate) fn exclusions(
    data: &[u8],
    flavor: AppendOnlyFlavor,
) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(match locate_active(data, flavor) {
        Located::Active(sentinel) => vec![DataHashExclusion {
            start: sentinel.start,
            length: sentinel.length,
        }],
        _ => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LF_VECTOR: &[u8] = b"alpha\nbravo\n-----BEGIN C2PA CHECKPOINT----- https://northwindtraders.com/provenance/chk1.c2pa -----END C2PA CHECKPOINT-----\n";

    #[test]
    fn spec_test_vector_geometry() {
        // First checkpoint, LF: segment [0, 12), sentinel [12, 124).
        let Located::Active(sentinel) = locate_active(LF_VECTOR, AppendOnlyFlavor::PlainText)
        else {
            panic!("sentinel located")
        };
        assert_eq!((sentinel.start, sentinel.length), (12, 112));
        assert_eq!(
            sentinel.reference,
            SentinelReference::External(
                "https://northwindtraders.com/provenance/chk1.c2pa".to_string()
            )
        );
        assert_eq!(
            sentinel_at(LF_VECTOR, 12, AppendOnlyFlavor::PlainText),
            Some(sentinel)
        );
        // CRLF: the 113-byte sentinel occupies [14, 127).
        let crlf = String::from_utf8(LF_VECTOR.to_vec())
            .unwrap()
            .replace('\n', "\r\n");
        let Located::Active(sentinel) = locate_active(crlf.as_bytes(), AppendOnlyFlavor::PlainText)
        else {
            panic!("sentinel located")
        };
        assert_eq!((sentinel.start, sentinel.length), (14, 113));
    }

    #[test]
    fn inline_references_decode_and_bad_ones_are_malformed() {
        let ok = b"x\n-----BEGIN C2PA CHECKPOINT----- data:application/c2pa;base64,AQID -----END C2PA CHECKPOINT-----\n";
        assert_eq!(
            extract(ok, AppendOnlyFlavor::PlainText).unwrap(),
            Some(vec![1, 2, 3])
        );
        for bad in [
            &b"x\n-----BEGIN C2PA CHECKPOINT----- data:text/plain;base64,AQID -----END C2PA CHECKPOINT-----\n"[..],
            b"x\n-----BEGIN C2PA CHECKPOINT----- data:application/c2pa;base64,*** -----END C2PA CHECKPOINT-----\n",
            b"x\n-----BEGIN C2PA CHECKPOINT-----    -----END C2PA CHECKPOINT-----\n",
            b"x\n-----BEGIN C2PA CHECKPOINT----- https://a/b no end delimiter\n",
        ] {
            assert_eq!(locate_active(bad, AppendOnlyFlavor::PlainText), Located::Malformed);
        }
    }

    #[test]
    fn only_the_last_candidate_counts_and_unterminated_lines_are_ignored() {
        // A valid earlier sentinel does not rescue a malformed last candidate.
        let text = format!(
            "{}more\n-----BEGIN C2PA CHECKPOINT----- broken\n",
            String::from_utf8(LF_VECTOR.to_vec()).unwrap()
        );
        assert_eq!(
            locate_active(text.as_bytes(), AppendOnlyFlavor::PlainText),
            Located::Malformed
        );
        // An unterminated trailing sentinel is not complete; the earlier one is
        // active (its coverage check then fails in the validator).
        let mut unterminated = LF_VECTOR.to_vec();
        unterminated.extend_from_slice(
            b"-----BEGIN C2PA CHECKPOINT----- https://x/y -----END C2PA CHECKPOINT-----",
        );
        assert!(matches!(
            locate_active(&unterminated, AppendOnlyFlavor::PlainText),
            Located::Active(Sentinel { start: 12, .. })
        ));
        assert_eq!(
            locate_active(b"no sentinel\n", AppendOnlyFlavor::PlainText),
            Located::None
        );
    }

    #[test]
    fn jsonl_sentinels() {
        let text = b"{\"a\":1}\n{\"c2pa:checkpoint\":\"https://e.example/c.c2pa\"}\n";
        assert!(matches!(
            locate_active(text, AppendOnlyFlavor::JsonLines),
            Located::Active(Sentinel {
                start: 8,
                length: 47,
                ..
            })
        ));
        let not_string = b"{\"c2pa:checkpoint\":7}\n";
        assert_eq!(
            locate_active(not_string, AppendOnlyFlavor::JsonLines),
            Located::Malformed
        );
        // A plain-text sentinel is not a JSONL sentinel and vice versa.
        assert_eq!(
            locate_active(LF_VECTOR, AppendOnlyFlavor::JsonLines),
            Located::None
        );
        assert!(declares_checkpoints(LF_VECTOR, AppendOnlyFlavor::PlainText));
        assert!(!declares_checkpoints(
            b"plain\n",
            AppendOnlyFlavor::PlainText
        ));
    }

    #[test]
    fn sentinel_at_requires_a_line_start() {
        assert_eq!(
            sentinel_at(LF_VECTOR, 13, AppendOnlyFlavor::PlainText),
            None
        );
        assert_eq!(sentinel_at(LF_VECTOR, 0, AppendOnlyFlavor::PlainText), None);
        assert_eq!(
            sentinel_at(LF_VECTOR, 999, AppendOnlyFlavor::PlainText),
            None
        );
    }
}
