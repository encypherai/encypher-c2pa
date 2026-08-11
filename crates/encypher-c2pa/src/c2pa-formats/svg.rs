//! SVG: JUMBF base64-encoded in a `<c2pa:manifest>` metadata element.
//!
//! SVG has no binary container, so the manifest store is base64-encoded inside
//! a metadata element under the C2PA namespace:
//!
//! ```text
//! <metadata><c2pa:manifest xmlns:c2pa="http://c2pa.org/manifest">BASE64</c2pa:manifest></metadata>
//! ```
//!
//! The element is inserted as the first child of the root `<svg>` element. For
//! robustness when reading third-party SVGs, extraction also falls back to the
//! older `<?c2pa-manifest BASE64?>` processing-instruction convention.

use crate::c2pa_formats::util::base64_decode;
#[cfg(test)]
use crate::c2pa_formats::util::base64_encode;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Svg;
const ELEM_OPEN_TAG: &str = "<c2pa:manifest";
const ELEM_CLOSE: &str = "</c2pa:manifest>";
const PI_OPEN: &str = "<?c2pa-manifest ";
const PI_CLOSE: &str = "?>";
/// The wrapper element `embed` writes around `<c2pa:manifest>`.
const META_OPEN: &str = "<metadata>";
const META_CLOSE: &str = "</metadata>";

fn as_str(data: &[u8]) -> Result<&str, FormatError> {
    std::str::from_utf8(data).map_err(|_| FormatError::InvalidStructure {
        format: FMT,
        detail: "SVG is not valid UTF-8",
    })
}

/// Extract the manifest store from the `<c2pa:manifest>` element, falling back
/// to the `<?c2pa-manifest ?>` processing instruction.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let text = as_str(data)?;

    // Primary: <c2pa:manifest ...>BASE64</c2pa:manifest>
    if let Some(open) = text.find(ELEM_OPEN_TAG) {
        // Skip to the end of the open tag ('>').
        let after_open = &text[open + ELEM_OPEN_TAG.len()..];
        if let Some(gt) = after_open.find('>') {
            let body = &after_open[gt + 1..];
            if let Some(close) = body.find(ELEM_CLOSE) {
                let b64 = body[..close].trim();
                let bytes = base64_decode(b64).ok_or(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "invalid base64 in c2pa:manifest element",
                })?;
                return Ok(Some(bytes));
            }
        }
    }

    // Fallback: <?c2pa-manifest BASE64?>
    if let Some(open) = text.find(PI_OPEN) {
        let rest = &text[open + PI_OPEN.len()..];
        let close = rest.find(PI_CLOSE).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "unterminated c2pa PI",
        })?;
        let b64 = rest[..close].trim();
        let bytes = base64_decode(b64).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "invalid base64 in c2pa PI",
        })?;
        return Ok(Some(bytes));
    }

    Ok(None)
}

/// Remove the existing manifest element (or `<?c2pa-manifest ?>` PI
/// fallback), reusing the same span [`exclusions`] computes. A no-op when
/// the asset has no manifest.
#[cfg(test)]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    let ex = exclusions(asset)?;
    let Some(span) = ex.first() else {
        return Ok(asset.to_vec());
    };
    let mut out = Vec::with_capacity(asset.len());
    out.extend_from_slice(&asset[..span.start]);
    out.extend_from_slice(&asset[span.start + span.length..]);
    Ok(out)
}

/// Insert a `<metadata><c2pa:manifest>` element as the first child of `<svg>`.
///
/// Any existing manifest element is stripped first: prior insertion always
/// landed the new element first in document order, so a first-match reader
/// happened to pick up the fresh manifest, but the stale element was never
/// actually removed (permanent orphan markup, and one insertion-point change
/// away from silently flipping to a stale-wins bug).
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let text = as_str(&clean)?;
    // Find the end of the opening <svg ...> tag.
    let svg_open = text.find("<svg").ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "no <svg> root element",
    })?;
    let after_svg = &text[svg_open..];
    let gt = after_svg.find('>').ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "unterminated <svg> tag",
    })?;
    let insert_at = svg_open + gt + 1;

    let elem = format!(
        "<metadata><c2pa:manifest xmlns:c2pa=\"http://c2pa.org/manifest\">{}</c2pa:manifest></metadata>",
        base64_encode(manifest_store)
    );
    let mut out = Vec::with_capacity(clean.len() + elem.len());
    out.extend_from_slice(&clean[..insert_at]);
    out.extend_from_slice(elem.as_bytes());
    out.extend_from_slice(&clean[insert_at..]);
    Ok(out)
}

/// The byte span of the embedded manifest element as a single exclusion.
///
/// Covers the same `<c2pa:manifest>` element [`extract`] locates, extended to
/// include the `<metadata>...</metadata>` wrapper [`embed`] writes around it
/// (when present, immediately adjacent). Falls back to the `<?c2pa-manifest ?>`
/// processing instruction. Empty if no manifest is present.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let text = as_str(data)?;

    // Primary: the <c2pa:manifest> element (plus its <metadata> wrapper).
    if let Some(open) = text.find(ELEM_OPEN_TAG) {
        let after_open = &text[open + ELEM_OPEN_TAG.len()..];
        if let Some(gt) = after_open.find('>') {
            let body_start = open + ELEM_OPEN_TAG.len() + gt + 1;
            if let Some(rel_close) = text[body_start..].find(ELEM_CLOSE) {
                let mut start = open;
                let mut end = body_start + rel_close + ELEM_CLOSE.len();
                // Absorb the wrapper iff it is immediately adjacent (as `embed` writes it).
                if text[..start].ends_with(META_OPEN) {
                    start -= META_OPEN.len();
                }
                if text[end..].starts_with(META_CLOSE) {
                    end += META_CLOSE.len();
                }
                return Ok(vec![DataHashExclusion {
                    start,
                    length: end - start,
                }]);
            }
        }
    }

    // Fallback: the <?c2pa-manifest ?> processing instruction.
    if let Some(open) = text.find(PI_OPEN) {
        let rest = &text[open + PI_OPEN.len()..];
        let close = rest.find(PI_CLOSE).ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "unterminated c2pa PI",
        })?;
        let end = open + PI_OPEN.len() + close + PI_CLOSE.len();
        return Ok(vec![DataHashExclusion {
            start: open,
            length: end - open,
        }]);
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::tests::dummy_manifest_store;

    fn tiny_svg() -> Vec<u8> {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>"#
            .to_vec()
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_svg(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first_store = dummy_manifest_store();
        let second_assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:0002",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = crate::c2pa_core::jumbf::build_manifest_store(&[second_manifest]);
        assert_ne!(first_store, second_store, "fixture stores must differ");

        let first = embed(&tiny_svg(), &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice())
        );
        let text = std::str::from_utf8(&second).unwrap();
        let occurrences = text.matches(ELEM_OPEN_TAG).count();
        assert_eq!(
            occurrences, 1,
            "re-embed must leave exactly one c2pa:manifest element"
        );
    }

    #[test]
    fn manifest_element_is_svg_child() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_svg(), &store).unwrap();
        let text = std::str::from_utf8(&embedded).unwrap();
        assert!(text.find("<svg").unwrap() < text.find(ELEM_OPEN_TAG).unwrap());
        assert!(text.contains("</c2pa:manifest></metadata>"));
    }

    #[test]
    fn extracts_live_style_element() {
        // Mirrors the live pipeline's exact element shape.
        let store = dummy_manifest_store();
        let b64 = base64_encode(&store);
        let svg = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><metadata><c2pa:manifest xmlns:c2pa=\"http://c2pa.org/manifest\">{b64}</c2pa:manifest></metadata></svg>"
        );
        assert_eq!(
            extract(svg.as_bytes()).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn roundtrip_no_xml_decl() {
        let store = dummy_manifest_store();
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>".to_vec();
        let embedded = embed(&svg, &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_svg()).unwrap(), None);
    }

    #[test]
    fn base64_roundtrips_arbitrary_bytes() {
        for n in 0..32usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let enc = base64_encode(&data);
            assert_eq!(base64_decode(&enc).unwrap(), data, "len {n}");
        }
    }

    #[test]
    fn exclusions_cover_manifest_element() {
        let store = dummy_manifest_store();
        let asset = tiny_svg();
        let embedded = embed(&asset, &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        let span = &embedded[start..start + length];
        // The span is exactly the inserted <metadata>...</metadata> element.
        assert!(span.starts_with(b"<metadata><c2pa:manifest"));
        assert!(span.ends_with(b"</c2pa:manifest></metadata>"));
        // Deleting the span restores the original asset byte-for-byte.
        let mut rebuilt = embedded[..start].to_vec();
        rebuilt.extend_from_slice(&embedded[start + length..]);
        assert_eq!(rebuilt, asset);
    }

    #[test]
    fn exclusions_pi_fallback() {
        let store = dummy_manifest_store();
        let b64 = base64_encode(&store);
        let svg = format!("<svg><?c2pa-manifest {b64}?></svg>");
        let ex = exclusions(svg.as_bytes()).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        let span = &svg.as_bytes()[start..start + length];
        assert!(span.starts_with(b"<?c2pa-manifest "));
        assert!(span.ends_with(b"?>"));
    }

    #[test]
    fn exclusions_empty_without_manifest() {
        assert!(exclusions(&tiny_svg()).unwrap().is_empty());
    }
}
