//! MP3: JUMBF in an ID3v2 `GEOB` (General Encapsulated Object) frame.
//!
//! C2PA stores the manifest store in a `GEOB` frame whose MIME type is
//! `application/c2pa`. The GEOB payload is
//! `encoding(1) | mime\0 | filename\0 | description\0 | binary-object`. If the
//! asset has no ID3v2 tag, a fresh ID3v2.3 tag containing only the GEOB frame is
//! prepended.

use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Id3;
const GEOB_MIME: &[u8] = b"application/c2pa";
#[cfg(feature = "test-support")]
const GEOB_FILENAME: &[u8] = b"c2pa";
#[cfg(feature = "test-support")]
const GEOB_DESC: &[u8] = b"c2pa manifest store";
#[cfg(feature = "test-support")]
const MAX_SYNCHSAFE: usize = (1 << 28) - 1;

/// Encode a 28-bit value as a 4-byte synchsafe integer.
#[cfg(feature = "test-support")]
fn synchsafe_encode(n: u32) -> [u8; 4] {
    [
        ((n >> 21) & 0x7F) as u8,
        ((n >> 14) & 0x7F) as u8,
        ((n >> 7) & 0x7F) as u8,
        (n & 0x7F) as u8,
    ]
}

/// Decode a 4-byte synchsafe integer.
fn synchsafe_decode(b: &[u8]) -> u32 {
    ((b[0] as u32 & 0x7F) << 21)
        | ((b[1] as u32 & 0x7F) << 14)
        | ((b[2] as u32 & 0x7F) << 7)
        | (b[3] as u32 & 0x7F)
}

fn has_id3(data: &[u8]) -> bool {
    data.len() >= 10 && &data[..3] == b"ID3"
}

/// Build a GEOB frame (header + payload) for the given ID3 major version.
#[cfg(feature = "test-support")]
fn build_geob_frame(manifest: &[u8], major: u8) -> Result<Vec<u8>, FormatError> {
    // payload: encoding(0) | mime\0 | filename\0 | description\0 | binary
    let mut payload = Vec::with_capacity(manifest.len() + GEOB_MIME.len() + GEOB_DESC.len() + 8);
    payload.push(0x00); // ISO-8859-1
    payload.extend_from_slice(GEOB_MIME);
    payload.push(0x00);
    payload.extend_from_slice(GEOB_FILENAME);
    payload.push(0x00);
    payload.extend_from_slice(GEOB_DESC);
    payload.push(0x00);
    payload.extend_from_slice(manifest);

    if major >= 4 && payload.len() > MAX_SYNCHSAFE {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: MAX_SYNCHSAFE,
            got: manifest.len(),
        });
    }
    if payload.len() > u32::MAX as usize {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: u32::MAX as usize,
            got: manifest.len(),
        });
    }

    let mut frame = Vec::with_capacity(10 + payload.len());
    frame.extend_from_slice(b"GEOB");
    if major >= 4 {
        frame.extend_from_slice(&synchsafe_encode(payload.len() as u32));
    } else {
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    }
    frame.extend_from_slice(&[0x00, 0x00]); // flags
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Read a byte string terminated by `0x00` (or `0x00 0x00` when `wide`).
/// Returns the content and the offset just past the terminator.
fn read_terminated(data: &[u8], start: usize, wide: bool) -> Option<(&[u8], usize)> {
    let mut i = start;
    if wide {
        while i + 1 < data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                return Some((&data[start..i], i + 2));
            }
            i += 2;
        }
        None
    } else {
        while i < data.len() {
            if data[i] == 0 {
                return Some((&data[start..i], i + 1));
            }
            i += 1;
        }
        None
    }
}

/// Extract the manifest store from a `GEOB` frame with MIME `application/c2pa`.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    if !has_id3(data) {
        // Bare MPEG audio with no ID3v2 tag carries no manifest.
        return Ok(None);
    }
    let major = data[3];
    let tag_size = synchsafe_decode(&data[6..10]) as usize;
    let tag_end = (10 + tag_size).min(data.len());

    let mut pos = 10;
    while pos + 10 <= tag_end {
        if data[pos] == 0 {
            break; // padding
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&data[pos..pos + 4]);
        let frame_size = if major >= 4 {
            synchsafe_decode(&data[pos + 4..pos + 8]) as usize
        } else {
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize
        };
        let body_start = pos + 10;
        let body_end = body_start
            .checked_add(frame_size)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        if &id == b"GEOB" {
            if let Some(manifest) = parse_geob(&data[body_start..body_end]) {
                return Ok(Some(manifest));
            }
        }
        pos = body_end;
    }
    Ok(None)
}

/// Parse a GEOB body; return the binary object iff the MIME is `application/c2pa`.
fn parse_geob(body: &[u8]) -> Option<Vec<u8>> {
    let encoding = *body.first()?;
    let wide = encoding == 1 || encoding == 2; // UTF-16 variants
                                               // MIME is always ISO-8859-1 (single null).
    let (mime, after_mime) = read_terminated(body, 1, false)?;
    if mime != GEOB_MIME {
        return None;
    }
    let (_filename, after_filename) = read_terminated(body, after_mime, wide)?;
    let (_desc, after_desc) = read_terminated(body, after_filename, wide)?;
    Some(body[after_desc..].to_vec())
}

/// Embed the manifest in a clean ID3v2.3 `GEOB` frame. Any existing ID3v2 tag is
/// stripped (matches the certified Pipeline-B embedder).
#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    // Byte-parity with the legacy Pipeline-B embedder: strip any existing ID3v2
    // tag and write a clean ID3v2.3 tag holding only the C2PA GEOB frame. The
    // C2PA GEOB definition references id3v2.3.0, and v2.4 synchsafe frame sizes
    // are unreadable by v2.3-only parsers (interop). Existing ID3 frames are
    // intentionally dropped, exactly as in the certified output.
    let audio: &[u8] = if has_id3(asset) {
        let tag_size = synchsafe_decode(&asset[6..10]) as usize;
        // ID3v2.4 may append a 10-byte footer (header byte 5 bit 0x10 set).
        let footer = if asset[3] == 4 && asset[5] & 0x10 != 0 {
            10usize
        } else {
            0
        };
        let tag_end = 10usize
            .checked_add(tag_size)
            .and_then(|e| e.checked_add(footer))
            .filter(|&e| e <= asset.len())
            .ok_or(FormatError::Truncated(FMT))?;
        &asset[tag_end..]
    } else {
        asset
    };
    let frame = build_geob_frame(manifest_store, 3)?;
    if frame.len() > MAX_SYNCHSAFE {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: MAX_SYNCHSAFE,
            got: manifest_store.len(),
        });
    }
    let mut out = Vec::with_capacity(audio.len() + frame.len() + 10);
    out.extend_from_slice(b"ID3");
    out.extend_from_slice(&[0x03, 0x00, 0x00]); // v2.3.0, no flags
    out.extend_from_slice(&synchsafe_encode(frame.len() as u32));
    out.extend_from_slice(&frame);
    out.extend_from_slice(audio);
    Ok(out)
}

/// The C2PA `GEOB` frame byte span (header + payload) as a single exclusion.
///
/// Walks the ID3v2 frame chain exactly as [`extract`] does and returns the span
/// of the `application/c2pa` GEOB frame — the region whose bytes change with the
/// manifest. Empty if there is no ID3v2 tag or no C2PA GEOB frame.
///
/// Note: this is the minimal span matching [`extract`]. When [`embed`] grows an
/// *existing* tag it also rewrites the 10-byte ID3 header's size field; that
/// field is deterministic from the (placeholder-fixed) frame length and so is
/// stable across the two signing passes — it is intentionally not excluded.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    if !has_id3(data) {
        return Ok(Vec::new());
    }
    let major = data[3];
    let tag_size = synchsafe_decode(&data[6..10]) as usize;
    let tag_end = (10 + tag_size).min(data.len());

    let mut pos = 10;
    while pos + 10 <= tag_end {
        if data[pos] == 0 {
            break; // padding
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&data[pos..pos + 4]);
        let frame_size = if major >= 4 {
            synchsafe_decode(&data[pos + 4..pos + 8]) as usize
        } else {
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize
        };
        let body_start = pos + 10;
        let body_end = body_start
            .checked_add(frame_size)
            .filter(|&e| e <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        if &id == b"GEOB" && parse_geob(&data[body_start..body_end]).is_some() {
            return Ok(vec![DataHashExclusion {
                start: pos,
                length: body_end - pos,
            }]);
        }
        pos = body_end;
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    /// Bare MPEG frame bytes (no ID3 tag).
    fn bare_mp3() -> Vec<u8> {
        vec![0xFF, 0xFB, 0x90, 0x00, 0x11, 0x22, 0x33, 0x44]
    }

    /// MP3 with an existing ID3v2.4 tag holding a TIT2 frame.
    fn mp3_with_tag() -> Vec<u8> {
        let title = b"\x00Song"; // encoding + text
        let mut frame = Vec::new();
        frame.extend_from_slice(b"TIT2");
        frame.extend_from_slice(&synchsafe_encode(title.len() as u32));
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(title);

        let mut v = Vec::new();
        v.extend_from_slice(b"ID3");
        v.extend_from_slice(&[0x04, 0x00, 0x00]);
        v.extend_from_slice(&synchsafe_encode(frame.len() as u32));
        v.extend_from_slice(&frame);
        v.extend_from_slice(&bare_mp3());
        v
    }

    #[test]
    fn synchsafe_roundtrip() {
        for n in [0u32, 1, 127, 128, 16383, 16384, 268_435_455] {
            assert_eq!(synchsafe_decode(&synchsafe_encode(n)), n);
        }
    }

    #[test]
    fn roundtrip_no_existing_tag() {
        let store = dummy_manifest_store();
        let embedded = embed(&bare_mp3(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
        // Audio must be preserved at the tail.
        assert!(embedded.ends_with(&bare_mp3()));
    }

    #[test]
    fn existing_tag_replaced_with_clean_v23() {
        let store = dummy_manifest_store();
        let embedded = embed(&mp3_with_tag(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
        // Existing tags are stripped and replaced with a clean ID3v2.3 GEOB-only
        // tag (matches the certified Pipeline-B embedder), so TIT2 is dropped.
        assert_eq!(&embedded[3..6], &[0x03, 0x00, 0x00], "fresh tag is ID3v2.3");
        assert!(
            !embedded.windows(4).any(|w| w == b"TIT2"),
            "existing frames stripped"
        );
        assert!(embedded.ends_with(&bare_mp3()));
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&bare_mp3()).unwrap(), None);
        assert_eq!(extract(&mp3_with_tag()).unwrap(), None);
    }

    #[test]
    fn exclusions_cover_geob_frame_fresh_tag() {
        let store = dummy_manifest_store();
        let embedded = embed(&bare_mp3(), &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        let DataHashExclusion { start, length } = ex[0];
        // A fresh tag is exactly the 10-byte header followed by the GEOB frame.
        // The GEOB frame sits just after the 10-byte ID3v2 header in a fresh tag.
        assert_eq!(start, 10, "GEOB frame starts after the 10-byte ID3 header");
        assert!(length > 0);
        // Everything after the excluded region is the original bare MP3 audio.
        assert!(
            embedded[start + length..].ends_with(&bare_mp3()) || embedded.ends_with(&bare_mp3())
        );
    }

    #[test]
    fn strips_v24_footer() {
        // A v2.4 tag with the footer-present flag (byte 5 bit 0x10) appends a
        // 10-byte footer after the frames; embed must strip header+frames+footer.
        let store = dummy_manifest_store();
        let mut tagged = Vec::new();
        tagged.extend_from_slice(b"ID3");
        tagged.extend_from_slice(&[0x04, 0x00, 0x10]); // v2.4, footer-present flag
        tagged.extend_from_slice(&synchsafe_encode(0)); // empty frames
        tagged.extend_from_slice(b"3DI"); // 10-byte footer
        tagged.extend_from_slice(&[0x04, 0x00, 0x10]);
        tagged.extend_from_slice(&synchsafe_encode(0));
        tagged.extend_from_slice(&bare_mp3());
        let embedded = embed(&tagged, &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
        assert_eq!(
            &embedded[3..6],
            &[0x03, 0x00, 0x00],
            "rewritten as clean v2.3"
        );
        assert!(
            embedded.ends_with(&bare_mp3()),
            "audio preserved, footer stripped"
        );
    }

    #[test]
    fn geob_fields_are_deterministic() {
        // Fixed GEOB payload fields:
        // encoding(0) | "application/c2pa"\0 | "c2pa"\0 | "c2pa manifest store"\0 | store.
        let store = dummy_manifest_store();
        let embedded = embed(&bare_mp3(), &store).unwrap();
        let mut expected = vec![0x00u8];
        expected.extend_from_slice(b"application/c2pa\x00");
        expected.extend_from_slice(b"c2pa\x00");
        expected.extend_from_slice(b"c2pa manifest store\x00");
        let payload_start = 10 + 10; // ID3 header + GEOB frame header
        assert_eq!(
            &embedded[payload_start..payload_start + expected.len()],
            expected.as_slice()
        );
    }
}
