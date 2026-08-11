//! JPEG: JUMBF carried in `APP11` (`0xFFEB`) marker segments.
//!
//! A C2PA manifest store may exceed a single 64 KiB JPEG marker, so it is
//! fragmented across one or more `APP11` segments following the JUMBF-in-JPEG
//! layout (ISO/IEC 19566-5 / C2PA "Embedding manifests into JPEG"). Each segment
//! payload is:
//!
//! ```text
//! CI(2)='JP' | En(2) box-instance | Z(4) packet-seq | LBox(4) | TBox(4) | [XLBox(8)] | DBox(fragment)
//! ```
//!
//! `LBox`/`TBox`/`XLBox` (the JUMBF box header) are repeated in every segment;
//! the box *content* is split across the `DBox` fragments in ascending `Z`
//! order. Reassembly prepends the header to the concatenated fragments.

use crate::c2pa_formats::util::be_u16;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Jpeg;
#[cfg(test)]
const MARKER_APP0: u8 = 0xE0;
const MARKER_APP11: u8 = 0xEB;
const MARKER_SOS: u8 = 0xDA;
const MARKER_EOI: u8 = 0xD9;
const CI_JP: [u8; 2] = [0x4A, 0x50];
/// Box instance number we write; readers group fragments by this value.
#[cfg(test)]
const BOX_INSTANCE: u16 = 1;
/// Maximum `Le` field value (including the 2 length bytes).
#[cfg(test)]
const MAX_SEGMENT_LEN: usize = 0xFFFF;
/// Aggregate cap for parseable APP11 packet metadata across the JPEG.
///
/// A maximum-sized manifest needs fewer than 1,100 full APP11 segments. This
/// higher limit preserves unusually fragmented carriers while bounding the
/// packet vectors to roughly one MiB even when every fragment has no DBox.
const MAX_APP11_PACKET_COUNT: usize = 16 * 1024;

fn check_soi(data: &[u8]) -> Result<(), FormatError> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "missing SOI marker",
        });
    }
    Ok(())
}

/// A single parsed marker segment carrying a length field.
struct Segment {
    marker: u8,
    /// Offset of the `0xFF` introducing the marker.
    start: usize,
    /// Offset of the segment payload (after the 2-byte length field).
    payload_start: usize,
    /// One-past-the-end offset of the whole segment.
    end: usize,
}

/// Walk JPEG marker segments from SOI up to (and excluding) SOS / EOI, invoking
/// `f` for each length-bearing segment.
fn walk_segments(data: &[u8], mut f: impl FnMut(&Segment)) -> Result<(), FormatError> {
    check_soi(data)?;
    let mut pos = 2;
    while pos + 1 < data.len() {
        if data[pos] != 0xFF {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "expected marker prefix 0xFF",
            });
        }
        // Skip fill bytes (0xFF padding).
        let mut mp = pos + 1;
        while mp < data.len() && data[mp] == 0xFF {
            mp += 1;
        }
        if mp >= data.len() {
            break;
        }
        let marker = data[mp];
        // Standalone markers without a length field.
        if marker == MARKER_EOI || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            if marker == MARKER_EOI {
                break;
            }
            pos = mp + 1;
            continue;
        }
        if marker == MARKER_SOS {
            // Entropy-coded data follows; no further APP segments of interest.
            break;
        }
        let len = be_u16(data, mp + 1).ok_or(FormatError::Truncated(FMT))? as usize;
        if len < 2 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "segment length < 2",
            });
        }
        let payload_start = mp + 3;
        let end = mp + 1 + len;
        if end > data.len() {
            return Err(FormatError::Truncated(FMT));
        }
        f(&Segment {
            marker,
            start: pos,
            payload_start,
            end,
        });
        pos = end;
    }
    Ok(())
}

/// Map a JPEG marker byte to its C2PA box-hash identifier (spec 18.4
/// conventions: `SOI`, `APP0`…`APP15`, `DQT`, `DHT`, `SOF0`…, `SOS`,
/// `RST0`…`RST7`, `COM`, `EOI`).
fn marker_name(marker: u8) -> String {
    match marker {
        0xC4 => "DHT".into(),
        0xC8 => "JPG".into(),
        0xCC => "DAC".into(),
        0xC0..=0xCF => format!("SOF{}", marker - 0xC0),
        0xD8 => "SOI".into(),
        0xD9 => "EOI".into(),
        0xDA => "SOS".into(),
        0xDB => "DQT".into(),
        0xDC => "DNL".into(),
        0xDD => "DRI".into(),
        0xDE => "DHP".into(),
        0xDF => "EXP".into(),
        0xE0..=0xEF => format!("APP{}", marker - 0xE0),
        0xF0..=0xFD => format!("JPG{}", marker - 0xF0),
        0xFE => "COM".into(),
        other => format!("FF{other:02X}"),
    }
}

/// Scan entropy-coded data starting at `from`, returning the offset of the
/// next real marker (`0xFF` followed by a byte that is neither `0x00`
/// byte-stuffing nor `0xFF` fill), or the end of `data`.
fn entropy_end(data: &[u8], from: usize) -> usize {
    let mut e = from;
    while e + 1 < data.len() {
        if data[e] == 0xFF && data[e + 1] != 0x00 && data[e + 1] != 0xFF {
            return e;
        }
        e += 1;
    }
    data.len()
}

/// Segment the whole JPEG into named spans for `c2pa.hash.boxes` (spec
/// 15.12.3 + 18.4): every byte of the asset is covered by exactly one span.
/// `SOS`/`RSTn` spans include their entropy-coded data; the contiguous run of
/// C2PA `APP11` segments (CI = `JP`, i.e. manifest-store fragments) is merged
/// into one span named `C2PA`; trailing bytes after `EOI` extend the `EOI`
/// span so coverage stays total.
pub(crate) fn box_spans(data: &[u8]) -> Result<Vec<crate::c2pa_formats::BoxSpan>, FormatError> {
    check_soi(data)?;
    let c2pa_spans = valid_app11_spans(data)?;
    let mut spans: Vec<crate::c2pa_formats::BoxSpan> = vec![crate::c2pa_formats::BoxSpan {
        name: "SOI".into(),
        start: 0,
        end: 2,
    }];
    let push =
        |spans: &mut Vec<crate::c2pa_formats::BoxSpan>, name: String, start: usize, end: usize| {
            // Merge the contiguous C2PA APP11 run into a single span.
            if name == "C2PA" {
                if let Some(last) = spans.last_mut() {
                    if last.name == "C2PA" && last.end == start {
                        last.end = end;
                        return;
                    }
                }
            }
            spans.push(crate::c2pa_formats::BoxSpan { name, start, end });
        };
    let mut pos = 2;
    while pos + 1 < data.len() {
        if data[pos] != 0xFF {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "expected marker prefix 0xFF",
            });
        }
        let mut mp = pos + 1;
        while mp < data.len() && data[mp] == 0xFF {
            mp += 1;
        }
        if mp >= data.len() {
            break;
        }
        let marker = data[mp];
        if marker == MARKER_EOI {
            // EOI plus any trailing bytes: coverage must be total.
            push(&mut spans, "EOI".into(), pos, data.len());
            return Ok(spans);
        }
        if (0xD0..=0xD7).contains(&marker) || marker == MARKER_SOS {
            // SOS (header + scan data) or RSTn (marker + following scan data).
            let hdr_end = if marker == MARKER_SOS {
                let len = be_u16(data, mp + 1).ok_or(FormatError::Truncated(FMT))? as usize;
                mp + 1 + len
            } else {
                mp + 1
            };
            if hdr_end > data.len() {
                return Err(FormatError::Truncated(FMT));
            }
            let end = entropy_end(data, hdr_end);
            let name = if marker == MARKER_SOS {
                "SOS".into()
            } else {
                format!("RST{}", marker - 0xD0)
            };
            push(&mut spans, name, pos, end);
            pos = end;
            continue;
        }
        let len = be_u16(data, mp + 1).ok_or(FormatError::Truncated(FMT))? as usize;
        if len < 2 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "segment length < 2",
            });
        }
        let end = mp + 1 + len;
        if end > data.len() {
            return Err(FormatError::Truncated(FMT));
        }
        let name = if marker == MARKER_APP11
            && c2pa_spans
                .iter()
                .any(|(start, family_end)| pos >= *start && end <= *family_end)
        {
            "C2PA".into()
        } else {
            marker_name(marker)
        };
        push(&mut spans, name, pos, end);
        pos = end;
    }
    Ok(spans)
}

/// Extract and reassemble the manifest store from `APP11` fragments.
/// An APP11 fragment: `(Z sequence number, box header, dbox payload)`.

#[derive(Clone)]
struct App11Packet<'a> {
    start: usize,
    end: usize,
    en: u16,
    z: u32,
    header: &'a [u8],
    dbox: &'a [u8],
}

fn parse_app11_packet<'a>(data: &'a [u8], seg: &Segment) -> Option<App11Packet<'a>> {
    if seg.marker != MARKER_APP11 {
        return None;
    }
    let payload = &data[seg.payload_start..seg.end];
    if payload.len() < 16 || payload[0..2] != CI_JP {
        return None;
    }
    let en = u16::from_be_bytes([payload[2], payload[3]]);
    let z = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let lbox = u32::from_be_bytes(payload[8..12].try_into().ok()?);
    let header_len = if lbox == 1 { 16 } else { 8 };
    if payload.len() < 8 + header_len || &payload[12..16] != b"jumb" {
        return None;
    }
    Some(App11Packet {
        start: seg.start,
        end: seg.end,
        en,
        z,
        header: &payload[8..8 + header_len],
        dbox: &payload[8 + header_len..],
    })
}

fn declared_box_len(header: &[u8]) -> Option<usize> {
    let lbox = u32::from_be_bytes(header.get(0..4)?.try_into().ok()?);
    match lbox {
        0 => None,
        1 => usize::try_from(u64::from_be_bytes(header.get(8..16)?.try_into().ok()?)).ok(),
        n => usize::try_from(n).ok(),
    }
}

fn app11_family_is_valid(family: &[App11Packet<'_>]) -> Result<bool, FormatError> {
    let Some(first) = family.first() else {
        return Ok(false);
    };
    let dbox_len = family
        .iter()
        .try_fold(0usize, |total, packet| total.checked_add(packet.dbox.len()));
    let Some(assembled_len) = dbox_len.and_then(|length| first.header.len().checked_add(length))
    else {
        return Err(FormatError::ManifestTooLarge {
            format: FMT,
            max: crate::MAX_MANIFEST_STORE_BYTES,
            got: usize::MAX,
        });
    };
    let sequence_is_valid = family.iter().enumerate().all(|(index, packet)| {
        packet.z == index as u32 + 1
            && packet.header == first.header
            && (index == 0 || family[index - 1].end == packet.start)
    });
    if !sequence_is_valid || declared_box_len(first.header) != Some(assembled_len) {
        return Ok(false);
    }
    super::ensure_manifest_store_size(FMT, assembled_len)?;
    Ok(
        crate::c2pa_core::jumbf::parse_manifest_store(&assemble_family(family))
            .is_ok_and(|store| !store.manifests.is_empty()),
    )
}

/// Return only complete, contiguous JUMBF APP11 families. A payload merely
/// beginning with `JP` is foreign metadata unless its packet sequence,
/// repeated box header, and declared store length all validate.
fn valid_app11_families<'a>(data: &'a [u8]) -> Result<Vec<Vec<App11Packet<'a>>>, FormatError> {
    let valid = |family: &[App11Packet<'_>]| app11_family_is_valid(family);
    let mut families = Vec::new();
    let mut current: Vec<App11Packet<'a>> = Vec::new();
    let mut packet_count = 0usize;
    let mut family_error = None;

    walk_segments(data, |seg| {
        if family_error.is_some() {
            return;
        }
        let Some(packet) = parse_app11_packet(data, seg) else {
            return;
        };
        packet_count += 1;
        if packet_count > MAX_APP11_PACKET_COUNT {
            family_error = Some(FormatError::InvalidStructure {
                format: FMT,
                detail: "APP11 packet metadata limit exceeded",
            });
            return;
        }

        let continues = current.last().is_some_and(|previous| {
            previous.en == packet.en
                && previous.z.checked_add(1) == Some(packet.z)
                && previous.header == packet.header
                && previous.end == packet.start
        });
        if !current.is_empty() && !continues {
            match valid(&current) {
                Ok(true) => families.push(std::mem::take(&mut current)),
                Ok(false) => current.clear(),
                Err(error) => {
                    family_error = Some(error);
                    return;
                }
            }
        }
        current.push(packet);
    })?;

    if let Some(error) = family_error {
        return Err(error);
    }
    if valid(&current)? {
        families.push(current);
    }
    Ok(families)
}

pub(crate) fn valid_app11_spans(data: &[u8]) -> Result<Vec<(usize, usize)>, FormatError> {
    Ok(valid_app11_families(data)?
        .into_iter()
        .map(|family| {
            let start = family[0].start;
            let end = family.last().expect("family is non-empty").end;
            (start, end)
        })
        .collect())
}

fn assemble_family(family: &[App11Packet<'_>]) -> Vec<u8> {
    let mut out = family[0].header.to_vec();
    for packet in family {
        out.extend_from_slice(packet.dbox);
    }
    out
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(valid_app11_families(data)?
        .last()
        .map(|family| assemble_family(family)))
}

/// Build the `APP11` segment bytes carrying `manifest_store`.
#[cfg(test)]
pub(crate) fn build_app11_segments(manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    if manifest_store.len() < 8 {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "manifest store too short",
        });
    }
    let header_len = if manifest_store[0..4] == [0, 0, 0, 1] {
        16
    } else {
        8
    };
    if manifest_store.len() < header_len {
        return Err(FormatError::Truncated(FMT));
    }
    let header = &manifest_store[..header_len];
    let content = &manifest_store[header_len..];

    // Le = Le(2) + CI(2) + En(2) + Z(4) + header + chunk.
    let max_chunk = MAX_SEGMENT_LEN - 2 - 2 - 2 - 4 - header_len;
    let mut out = Vec::new();
    let mut z: u32 = 1;
    let emit = |chunk: &[u8], out: &mut Vec<u8>, z: &mut u32| {
        let le = 2 + 2 + 2 + 4 + header_len + chunk.len();
        out.push(0xFF);
        out.push(MARKER_APP11);
        out.extend_from_slice(&(le as u16).to_be_bytes());
        out.extend_from_slice(&CI_JP);
        out.extend_from_slice(&BOX_INSTANCE.to_be_bytes());
        out.extend_from_slice(&z.to_be_bytes());
        out.extend_from_slice(header);
        out.extend_from_slice(chunk);
        *z += 1;
    };

    if content.is_empty() {
        emit(&[], &mut out, &mut z);
    } else {
        for chunk in content.chunks(max_chunk) {
            emit(chunk, &mut out, &mut z);
        }
    }
    Ok(out)
}

/// Find the byte offset at which to insert `APP11` segments: after SOI and any
/// leading `APP0` (JFIF) segment.
#[cfg(test)]
fn insertion_offset(data: &[u8]) -> Result<usize, FormatError> {
    check_soi(data)?;
    let mut insert_at = 2;
    walk_segments(data, |seg| {
        if seg.start == 2 && seg.marker == MARKER_APP0 {
            insert_at = seg.end;
        }
    })?;
    Ok(insert_at)
}
/// Remove every existing C2PA `APP11` (CI = `JP`) segment, leaving all other
/// marker segments and entropy-coded data untouched. A no-op when the asset
/// has no manifest.
///
/// Required before inserting new segments: [`embed`] always writes box
/// instance `1` starting fragment sequence `1` (byte-compatible with a
/// single-instance JUMBF-in-JPEG reader), so a second embed over an
/// unstripped asset would interleave two unrelated manifests' fragments under
/// the same `(instance, sequence)` keys -- corrupting the JUMBF beyond repair
/// rather than merely leaving a stale one.
#[cfg(test)]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    check_soi(asset)?;
    let spans = valid_app11_spans(asset)?;
    let mut out = Vec::with_capacity(asset.len());
    let mut cursor = 0;
    for (start, end) in spans {
        out.extend_from_slice(&asset[cursor..start]);
        cursor = end;
    }
    out.extend_from_slice(&asset[cursor..]);
    Ok(out)
}

/// Insert a manifest store as `APP11` segments after SOI/APP0.
///
/// Any existing C2PA `APP11` segments are stripped first (see [`strip`]).
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let at = insertion_offset(&clean)?;
    let segments = build_app11_segments(manifest_store)?;
    let mut out = Vec::with_capacity(clean.len() + segments.len());
    out.extend_from_slice(&clean[..at]);
    out.extend_from_slice(&segments);
    out.extend_from_slice(&clean[at..]);
    Ok(out)
}

/// Report the contiguous span occupied by C2PA (`CI = JP`) `APP11` segments.
///
/// Foreign APP11 metadata is hashed. C2PA packets must form one contiguous
/// carrier; accepting separated packets would require widening the exclusion
/// across unrelated bytes.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(valid_app11_spans(data)?
        .into_iter()
        .map(|(start, end)| DataHashExclusion {
            start,
            length: end - start,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::tests::dummy_manifest_store;

    /// Minimal JPEG: SOI + APP0(JFIF) + a fake SOS + entropy + EOI.
    fn tiny_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8]; // SOI
                                      // APP0 JFIF, length 16
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        v.extend_from_slice(b"JFIF\0");
        v.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
        // SOS, length 12
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C]);
        v.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00]);
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // entropy
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v
    }

    #[test]
    fn embedded_single_segment_extracts_exact_parseable_store() {
        let store = dummy_manifest_store();
        let asset = tiny_jpeg();
        let embedded = embed(&asset, &store).unwrap();
        let extracted = extract(&embedded).unwrap().unwrap();
        assert_eq!(extracted, store);
        assert_eq!(
            crate::c2pa_core::jumbf::parse_manifest_store(&extracted)
                .unwrap()
                .manifests
                .len(),
            1
        );
    }

    #[test]
    fn roundtrip_multi_segment() {
        // Force fragmentation across several APP11 segments.
        let assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.big", &vec![0x41u8; 200_000], None);
        let manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:big",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let store = crate::c2pa_core::jumbf::build_manifest_store(&[manifest]);
        let asset = tiny_jpeg();
        let embedded = embed(&asset, &store).unwrap();
        // Confirm multiple APP11 segments were produced.
        let mut app11_count = 0;
        walk_segments(&embedded, |s| {
            if s.marker == MARKER_APP11 {
                app11_count += 1;
            }
        })
        .unwrap();
        assert!(
            app11_count > 1,
            "expected multiple APP11 segments, got {app11_count}"
        );
        let got = extract(&embedded).unwrap();
        assert_eq!(got.as_deref(), Some(store.as_slice()));
    }

    #[test]
    fn oversized_app11_family_fails_before_assembly() {
        let chunk = vec![0u8; 1024 * 1024];
        let packet_count = crate::MAX_MANIFEST_STORE_BYTES / chunk.len() + 1;
        let assembled_len = 8 + packet_count * chunk.len();
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&(assembled_len as u32).to_be_bytes());
        header[4..].copy_from_slice(b"jumb");
        let family = (0..packet_count)
            .map(|index| App11Packet {
                start: index,
                end: index + 1,
                en: 1,
                z: index as u32 + 1,
                header: &header,
                dbox: &chunk,
            })
            .collect::<Vec<_>>();

        assert!(matches!(
            app11_family_is_valid(&family),
            Err(FormatError::ManifestTooLarge {
                format: FMT,
                max: crate::MAX_MANIFEST_STORE_BYTES,
                got,
            }) if got == assembled_len
        ));
    }

    fn append_empty_app11_packet(jpeg: &mut Vec<u8>, sequence: u32) {
        jpeg.extend_from_slice(&[0xff, MARKER_APP11, 0x00, 0x12]);
        jpeg.extend_from_slice(&CI_JP);
        jpeg.extend_from_slice(&1u16.to_be_bytes());
        jpeg.extend_from_slice(&sequence.to_be_bytes());
        jpeg.extend_from_slice(&8u32.to_be_bytes());
        jpeg.extend_from_slice(b"jumb");
    }

    fn empty_app11_packet_flood(packet_count: usize) -> Vec<u8> {
        let mut jpeg = Vec::with_capacity(4 + packet_count * 20);
        jpeg.extend_from_slice(&[0xff, 0xd8]);
        for sequence in 1..=packet_count {
            append_empty_app11_packet(&mut jpeg, sequence as u32);
        }
        jpeg.extend_from_slice(&[0xff, MARKER_EOI]);
        jpeg
    }

    #[test]
    fn app11_packet_metadata_limit_allows_exact_boundary() {
        let jpeg = empty_app11_packet_flood(MAX_APP11_PACKET_COUNT);
        assert_eq!(extract(&jpeg).unwrap(), None);
    }

    #[test]
    fn app11_packet_metadata_limit_rejects_zero_payload_flood() {
        let jpeg = empty_app11_packet_flood(MAX_APP11_PACKET_COUNT + 1);
        assert!(matches!(
            extract(&jpeg),
            Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "APP11 packet metadata limit exceeded",
            })
        ));
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_jpeg()).unwrap(), None);
    }

    #[test]
    fn rejects_non_jpeg() {
        assert!(matches!(
            extract(b"not a jpeg"),
            Err(FormatError::InvalidStructure { .. })
        ));
    }

    #[test]
    fn exclusions_cover_app11() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_jpeg(), &store).unwrap();
        let ex = exclusions(&embedded).unwrap();
        assert_eq!(ex.len(), 1);
        // The excluded bytes start with an APP11 marker.
        assert_eq!(&embedded[ex[0].start..ex[0].start + 2], &[0xFF, 0xEB]);
    }

    #[test]
    fn re_embed_replaces_manifest_without_corruption() {
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

        let first = embed(&tiny_jpeg(), &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();

        // Exactly one APP11 JUMBF sequence remains -- no leftover fragments
        // from the first embed to collide with the second's.
        let mut app11_count = 0;
        walk_segments(&second, |s| {
            if s.marker == MARKER_APP11 {
                app11_count += 1;
            }
        })
        .unwrap();
        assert_eq!(app11_count, 1, "stale APP11 fragments must be stripped");

        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice()),
            "re-embed must produce a cleanly parseable, current manifest"
        );
    }
    #[test]
    fn exclusions_do_not_widen_across_foreign_app11() {
        let store = dummy_manifest_store();
        let mut signed = embed(&tiny_jpeg(), &store).unwrap();
        let foreign = [0xff, 0xeb, 0x00, 0x06, b'X', b'M', b'P', 0];
        signed.splice(2..2, foreign);

        let ex = exclusions(&signed).unwrap();
        assert_eq!(ex.len(), 1);
        assert_eq!(&signed[ex[0].start + 4..ex[0].start + 6], b"JP");
        assert!(ex[0].start >= 2 + foreign.len());
    }

    #[test]
    fn foreign_jp_app11_is_not_a_manifest_carrier() {
        let mut asset = tiny_jpeg();
        let foreign = [
            0xff, 0xeb, 0x00, 0x12, b'J', b'P', 0, 1, 0, 0, 0, 1, 0, 0, 0, 8, b'j', b'u', b'm',
            b'b',
        ];
        asset.splice(2..2, foreign);

        assert_eq!(strip(&asset).unwrap(), asset);
        assert!(exclusions(&asset).unwrap().is_empty());
        assert_eq!(extract(&asset).unwrap(), None);

        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let [carrier] = exclusions(&embedded).unwrap().try_into().unwrap();
        assert_eq!(carrier.start, 2);
        let foreign_start = carrier.start + carrier.length;
        assert_eq!(
            &embedded[foreign_start..foreign_start + foreign.len()],
            &foreign
        );
    }
}
