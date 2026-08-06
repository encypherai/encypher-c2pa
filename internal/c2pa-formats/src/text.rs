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

use crate::{AssetFormat, FormatError};

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

/// Extract the raw manifest-store bytes from a text asset using `method`.
pub(crate) fn extract(method: TextMethod, data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| method.invalid_utf8())?;
    match method {
        TextMethod::Unstructured => match c2pa_text::extract_manifest(text) {
            Ok(res) => Ok(res.manifest),
            // No wrapper present is "no manifest", not a malformed container.
            Err(_) => Ok(None),
        },
        TextMethod::Structured => match c2pa_text::structured::extract_structured(text) {
            // Only the inline `data:` reference carries bytes; a URL reference
            // resolves elsewhere and yields no embedded manifest here.
            Ok(ext) => Ok(ext.manifest),
            Err(_) => Ok(None),
        },
        TextMethod::Html => match c2pa_text::html::extract_html(text) {
            Ok(Some(ext)) => Ok(ext.manifest),
            Ok(None) => Ok(None),
            Err(_) => Ok(None),
        },
    }
}

/// Embed a manifest store into a text asset using `method`, returning the new
/// UTF-8 text bytes.
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
pub(crate) fn embed_structured(
    asset: &[u8],
    manifest_store: &[u8],
    comment_prefix: &str,
    comment_suffix: &str,
) -> Result<Vec<u8>, FormatError> {
    let text = std::str::from_utf8(asset).map_err(|_| TextMethod::Structured.invalid_utf8())?;
    Ok(structured_text(text, manifest_store, comment_prefix, comment_suffix).into_bytes())
}

use crate::DataHashExclusion;

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
) -> Result<Vec<DataHashExclusion>, FormatError> {
    let text = std::str::from_utf8(data).map_err(|_| method.invalid_utf8())?;
    let range = match method {
        TextMethod::Unstructured => match c2pa_text::extract_manifest(text) {
            Ok(res) => match (res.offset, res.length) {
                (Some(start), Some(length)) => Some((start, length)),
                _ => None,
            },
            Err(_) => None,
        },
        TextMethod::Structured => structured_block_span(text),
        TextMethod::Html => locate_span(text, "<script type=\"application/c2pa\"", "</script>"),
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

/// Locate the full A.9 structured manifest block span, widening the bare armour
/// delimiter span to include any host comment markers that wrap it (e.g.
/// `<!-- … -->`, `/* … */`). The armour delimiters are found first, then the
/// span is grown to the start of the line holding `BEGIN` and the end of the
/// line holding `END`, so the `c2pa.hash.data` exclusion covers the entire
/// comment-wrapped annotation rather than just the inner armour. For an
/// un-wrapped (bare) block the widened span equals the delimiter span. Scanning
/// for `\n` (0x0A) is UTF-8-safe: it never occurs inside a multi-byte sequence.
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
    let mut block_end = start + len;
    while block_end < bytes.len() && bytes[block_end] != b'\n' {
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
            extract(TextMethod::Unstructured, &engine).unwrap(),
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
        let out = extract(TextMethod::Unstructured, &embedded).unwrap();
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
        let out = extract(TextMethod::Structured, &embedded).unwrap();
        assert_eq!(out, Some(store));
    }

    #[test]
    fn html_round_trips() {
        let store = fake_store();
        let html = "<html><head><title>x</title></head><body>hi</body></html>";
        let embedded = embed(TextMethod::Html, html.as_bytes(), &store).unwrap();
        let text = String::from_utf8(embedded.clone()).unwrap();
        assert!(text.contains("application/c2pa"));
        let out = extract(TextMethod::Html, &embedded).unwrap();
        assert_eq!(out, Some(store));
    }

    #[test]
    fn no_manifest_is_none_not_error() {
        assert_eq!(
            extract(TextMethod::Unstructured, b"plain text").unwrap(),
            None
        );
        assert_eq!(
            extract(TextMethod::Structured, b"plain text").unwrap(),
            None
        );
        assert_eq!(extract(TextMethod::Html, b"<html></html>").unwrap(), None);
    }

    #[test]
    fn invalid_utf8_errors() {
        assert!(extract(TextMethod::Unstructured, &[0xff, 0xfe]).is_err());
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
            extract(TextMethod::Structured, &embedded).unwrap(),
            Some(store)
        );
        // The data-hash exclusion spans the WHOLE comment block (markers
        // included); the original source lies entirely outside it.
        let ex = exclusions(TextMethod::Structured, &embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let excluded = &embedded[ex[0].start..ex[0].start + ex[0].length];
        assert!(excluded.starts_with(b"/* -----BEGIN C2PA MANIFEST-----"));
        assert!(excluded.ends_with(b"*/"));
        assert!(ex[0].start >= src.len());
        assert_eq!(&embedded[..src.len()], src.as_bytes());
    }
}
