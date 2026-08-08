//! JPEG XL: JUMBF as a top-level `jumb` box in the ISOBMFF container.
//!
//! JXL has two framings. The ISOBMFF *container* form begins with the 12-byte
//! signature box (`0000000C 4A584C20 0D0A870A`) and stores boxes just like other
//! ISOBMFF formats; C2PA places the manifest store directly as a top-level
//! `jumb` box (the manifest store *is* a `jumb` superbox). The bare codestream
//! form (starting `FF 0A`) has no box structure; embedding into it would require
//! wrapping the codestream into a container, which is not supported here.

use crate::util::walk_iso_boxes;
use crate::{AssetFormat, DataHashExclusion, FormatError};
use c2pa_core::jumbf::parse_manifest_store;

const FMT: AssetFormat = AssetFormat::Jxl;
const TYPE_JUMB: &[u8; 4] = b"jumb";
#[cfg(feature = "test-support")]
const TYPE_FTYP: &[u8; 4] = b"ftyp";
const CONTAINER_SIG: [u8; 12] = [
    0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
];

fn is_container(data: &[u8]) -> bool {
    data.len() >= 12 && data[..12] == CONTAINER_SIG
}

fn check_jxl(data: &[u8]) -> Result<(), FormatError> {
    if is_container(data) {
        Ok(())
    } else if data.len() >= 2 && data[0] == 0xFF && data[1] == 0x0A {
        Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "bare JXL codestream has no box structure",
        })
    } else {
        Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "not a JXL container",
        })
    }
}

/// Return true if a top-level `jumb` box is a complete C2PA manifest store.
fn is_manifest_store(box_bytes: &[u8]) -> bool {
    parse_manifest_store(box_bytes).is_ok_and(|store| !store.manifests.is_empty())
}

/// Extract the manifest store: the top-level `jumb` box whose superbox UUID is
/// the manifest-store UUID. The box bytes *are* the manifest store.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    check_jxl(data)?;
    let mut found = None;
    walk_iso_boxes(data, FMT, |b| {
        if found.is_none() && &b.box_type == TYPE_JUMB {
            let box_bytes = &data[b.start..b.end];
            if is_manifest_store(box_bytes) {
                found = Some(box_bytes.to_vec());
            }
        }
    })?;
    Ok(found)
}

/// Remove every existing manifest-store `jumb` box, leaving all other
/// top-level boxes and their order untouched. A no-op when the asset has no
/// manifest.
#[cfg(feature = "test-support")]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    check_jxl(asset)?;
    let mut out = Vec::with_capacity(asset.len());
    let mut cursor = 0usize;
    walk_iso_boxes(asset, FMT, |b| {
        if &b.box_type == TYPE_JUMB && is_manifest_store(&asset[b.start..b.end]) {
            out.extend_from_slice(&asset[cursor..b.start]);
            cursor = b.end;
        }
    })?;
    out.extend_from_slice(&asset[cursor..]);
    Ok(out)
}

/// Insert the manifest store as a top-level `jumb` box after `ftyp`.
///
/// Any manifest-store `jumb` box already present is stripped first: prior
/// insertion always landed the new box first in file order, so a first-match
/// reader happened to pick up the fresh manifest, but the stale box was
/// never actually removed (permanent orphan bytes, and one insertion-point
/// change away from silently flipping to a stale-wins bug).
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    // The manifest store must already be a `jumb` box.
    if manifest_store.len() < 8 || &manifest_store[4..8] != TYPE_JUMB {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "manifest store is not a jumb box",
        });
    }
    let clean = strip(asset)?;
    let mut insert_at = 12; // after the signature box
    walk_iso_boxes(&clean, FMT, |b| {
        if &b.box_type == TYPE_FTYP {
            insert_at = b.end;
        }
    })?;
    let mut out = Vec::with_capacity(clean.len() + manifest_store.len());
    out.extend_from_slice(&clean[..insert_at]);
    out.extend_from_slice(manifest_store);
    out.extend_from_slice(&clean[insert_at..]);
    Ok(out)
}

/// The C2PA manifest-store `jumb` box byte span as a single exclusion.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    check_jxl(data)?;
    let mut ex = Vec::new();
    walk_iso_boxes(data, FMT, |b| {
        if ex.is_empty() && &b.box_type == TYPE_JUMB && is_manifest_store(&data[b.start..b.end]) {
            ex.push(DataHashExclusion {
                start: b.start,
                length: b.end - b.start,
            });
        }
    })?;
    Ok(ex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;
    use crate::util::iso_box_header;

    fn iso_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = iso_box_header(box_type, payload.len());
        v.extend_from_slice(payload);
        v
    }

    /// Minimal JXL container: signature box + ftyp + a codestream box.
    fn tiny_jxl() -> Vec<u8> {
        let mut v = Vec::from(CONTAINER_SIG);
        v.extend_from_slice(&iso_box(b"ftyp", b"jxl \x00\x00\x00\x00jxl "));
        v.extend_from_slice(&iso_box(b"jxlc", &[0xFF, 0x0A, 0x00, 0x01]));
        v
    }

    #[test]
    fn exclusions_cover_jumb_box() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_jxl(), &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        // The excluded span is exactly the inserted manifest store.
        assert_eq!(&embedded[start..start + length], store.as_slice());
        // Bare asset -> no exclusion.
        assert!(exclusions(&tiny_jxl()).unwrap().is_empty());
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_jxl(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn re_embed_replaces_manifest() {
        let first_store = dummy_manifest_store();
        let second_assertion = c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:0002",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = c2pa_core::jumbf::build_manifest_store(&[second_manifest]);
        assert_ne!(first_store, second_store, "fixture stores must differ");

        let first = embed(&tiny_jxl(), &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice())
        );
        let mut store_boxes = 0;
        walk_iso_boxes(&second, FMT, |b| {
            if &b.box_type == TYPE_JUMB && is_manifest_store(&second[b.start..b.end]) {
                store_boxes += 1;
            }
        })
        .unwrap();
        assert_eq!(
            store_boxes, 1,
            "re-embed must leave exactly one manifest store box"
        );
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_jxl()).unwrap(), None);
    }

    #[test]
    fn rejects_raw_codestream() {
        assert!(matches!(
            extract(&[0xFF, 0x0A, 0x00, 0x00]),
            Err(FormatError::UnsupportedVariant { .. })
        ));
    }

    #[test]
    fn rejects_non_jxl() {
        assert!(matches!(
            extract(b"not jxl at all!!"),
            Err(FormatError::InvalidStructure { .. })
        ));
    }
}
