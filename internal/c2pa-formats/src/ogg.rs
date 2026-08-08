//! Ogg Vorbis: C2PA JUMBF in a dedicated logical bitstream.
//!
//! The first packet in the C2PA stream is `\x00c2pa` followed immediately by
//! the manifest store. The stream is independent of the Vorbis audio stream and
//! may span any number of Ogg pages.

use std::collections::HashMap;

use crate::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Ogg;
const CAPTURE: &[u8; 4] = b"OggS";
const C2PA_PACKET_ID: &[u8; 5] = b"\x00c2pa";
const CRC_POLYNOMIAL: u32 = 0x04c1_1db7;
const BOS: u8 = 0x02;
const EOS: u8 = 0x04;
const CONTINUED: u8 = 0x01;

#[derive(Debug, Clone)]
struct Page {
    start: usize,
    end: usize,
    #[cfg(feature = "test-support")]
    header_type: u8,
    serial: u32,
}

#[derive(Default)]
struct StreamState {
    last_sequence: Option<u32>,
    packet_open: bool,
    eos: bool,
    packet_count: usize,
    first_packet: Vec<u8>,
    first_complete: bool,
}

struct ValidatedOgg {
    pages: Vec<Page>,
    manifest_serial: Option<u32>,
    manifest: Option<Vec<u8>>,
}

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// Parse and validate every page and logical stream in an Ogg asset.
///
/// This is the single authority used for full assets and detached carriers.
/// In addition to page framing and CRC, it enforces the stream state machine:
/// zero-based contiguous non-wrapping sequence numbers, legal flags, packet
/// continuation, a real final lacing terminator, and exactly one logical C2PA
/// packet across the asset.
fn validate_ogg(data: &[u8]) -> Result<ValidatedOgg, FormatError> {
    if data.is_empty() {
        return Err(invalid("empty Ogg stream"));
    }

    let mut pages = Vec::new();
    let mut streams: HashMap<u32, StreamState> = HashMap::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let fixed_end = pos.checked_add(27).ok_or(FormatError::Truncated(FMT))?;
        let fixed = data
            .get(pos..fixed_end)
            .ok_or(FormatError::Truncated(FMT))?;
        if &fixed[..4] != CAPTURE || fixed[4] != 0 {
            return Err(invalid("invalid Ogg page header"));
        }
        let header_type = fixed[5];
        if header_type & !(BOS | EOS | CONTINUED) != 0 {
            return Err(invalid("invalid Ogg page flags"));
        }
        let serial = u32::from_le_bytes(fixed[14..18].try_into().unwrap());
        let sequence = u32::from_le_bytes(fixed[18..22].try_into().unwrap());
        let segment_count = fixed[26] as usize;
        if segment_count == 0 {
            return Err(invalid("Ogg page has no lacing values"));
        }
        let lace_end = fixed_end
            .checked_add(segment_count)
            .filter(|&end| end <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        let laces = data[fixed_end..lace_end].to_vec();
        let body_len: usize = laces.iter().map(|&n| n as usize).sum();
        let end = lace_end
            .checked_add(body_len)
            .filter(|&end| end <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        let expected_crc = u32::from_le_bytes(fixed[22..26].try_into().unwrap());
        if ogg_crc_page(&data[pos..end]) != expected_crc {
            return Err(invalid("Ogg page checksum mismatch"));
        }

        let state = streams.entry(serial).or_default();
        match state.last_sequence {
            None => {
                if sequence != 0 || header_type & BOS == 0 || header_type & CONTINUED != 0 {
                    return Err(invalid("invalid first page for Ogg logical stream"));
                }
            }
            Some(previous) => {
                let expected = previous
                    .checked_add(1)
                    .ok_or(invalid("Ogg page sequence number wrapped"))?;
                if sequence != expected {
                    return Err(invalid("non-contiguous Ogg page sequence"));
                }
                if state.eos {
                    return Err(invalid("Ogg page follows end-of-stream"));
                }
                if header_type & BOS != 0 {
                    return Err(invalid("later Ogg page has beginning-of-stream flag"));
                }
                if (header_type & CONTINUED != 0) != state.packet_open {
                    return Err(invalid("Ogg packet continuation flag mismatch"));
                }
            }
        }

        let mut body = lace_end;
        for &lace in &laces {
            let next = body + lace as usize;
            if !state.first_complete {
                state.first_packet.extend_from_slice(&data[body..next]);
            }
            body = next;
            if lace < 255 {
                state.packet_count = state
                    .packet_count
                    .checked_add(1)
                    .ok_or(invalid("too many Ogg packets"))?;
                state.first_complete = true;
                state.packet_open = false;
            } else {
                state.packet_open = true;
            }
        }
        if header_type & EOS != 0 {
            if state.packet_open {
                return Err(invalid("Ogg stream ends without a packet terminator"));
            }
            state.eos = true;
        }
        state.last_sequence = Some(sequence);
        pages.push(Page {
            start: pos,
            end,
            #[cfg(feature = "test-support")]
            header_type,
            serial,
        });
        pos = end;
    }

    let mut manifest_serial = None;
    let mut manifest = None;
    for (serial, state) in streams {
        if !state.eos {
            return Err(invalid("Ogg logical stream has no end-of-stream page"));
        }
        if let Some(store) = state.first_packet.strip_prefix(C2PA_PACKET_ID) {
            if manifest.is_some() {
                return Err(invalid("multiple Ogg C2PA logical streams"));
            }
            if state.packet_count != 1 {
                return Err(invalid("material follows Ogg C2PA packet"));
            }
            manifest_serial = Some(serial);
            manifest = Some(store.to_vec());
        }
    }
    Ok(ValidatedOgg {
        pages,
        manifest_serial,
        manifest,
    })
}

pub(crate) fn extract_carrier(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(validate_ogg(data)?.manifest)
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    extract_carrier(data)
}

#[cfg(feature = "test-support")]
pub(crate) fn strip(data: &[u8]) -> Result<Vec<u8>, FormatError> {
    let validated = validate_ogg(data)?;
    let Some(manifest_serial) = validated.manifest_serial else {
        return Ok(data.to_vec());
    };

    let kept_len: usize = validated
        .pages
        .iter()
        .filter(|page| page.serial != manifest_serial)
        .map(|page| page.end - page.start)
        .sum();
    let mut out = Vec::with_capacity(kept_len);
    for page in validated.pages {
        if page.serial != manifest_serial {
            out.extend_from_slice(&data[page.start..page.end]);
        }
    }
    Ok(out)
}

#[cfg(feature = "test-support")]
fn ogg_crc(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ CRC_POLYNOMIAL
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn ogg_crc_page(page: &[u8]) -> u32 {
    let mut crc = 0u32;
    for (index, &actual) in page.iter().enumerate() {
        let byte = if (22..26).contains(&index) { 0 } else { actual };
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ CRC_POLYNOMIAL
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(feature = "test-support")]
fn build_page(
    header_type: u8,
    granule_position: u64,
    serial: u32,
    sequence: u32,
    laces: &[u8],
    body: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(laces.iter().map(|&n| n as usize).sum::<usize>(), body.len());
    let mut page = Vec::with_capacity(27 + laces.len() + body.len());
    page.extend_from_slice(CAPTURE);
    page.push(0);
    page.push(header_type);
    page.extend_from_slice(&granule_position.to_le_bytes());
    page.extend_from_slice(&serial.to_le_bytes());
    page.extend_from_slice(&sequence.to_le_bytes());
    page.extend_from_slice(&0u32.to_le_bytes());
    page.push(laces.len() as u8);
    page.extend_from_slice(laces);
    page.extend_from_slice(body);
    let checksum = ogg_crc(&page);
    page[22..26].copy_from_slice(&checksum.to_le_bytes());
    page
}

#[cfg(feature = "test-support")]
fn packet_laces(packet_len: usize) -> Vec<u8> {
    let full = packet_len / 255;
    let remainder = packet_len % 255;
    let mut laces = Vec::with_capacity(full + 1);
    laces.resize(full, 255);
    laces.push(remainder as u8);
    laces
}

#[cfg(feature = "test-support")]
pub(crate) fn build_manifest_pages(
    manifest_store: &[u8],
    serial: u32,
) -> Result<Vec<u8>, FormatError> {
    let packet_len = C2PA_PACKET_ID
        .len()
        .checked_add(manifest_store.len())
        .ok_or(FormatError::ManifestTooLarge {
            format: FMT,
            max: usize::MAX - C2PA_PACKET_ID.len(),
            got: manifest_store.len(),
        })?;
    let mut packet = Vec::with_capacity(packet_len);
    packet.extend_from_slice(C2PA_PACKET_ID);
    packet.extend_from_slice(manifest_store);
    let laces = packet_laces(packet.len());
    let page_count = laces.len().div_ceil(255);
    let mut pages = Vec::with_capacity(packet.len() + 27 * page_count + laces.len());
    let mut body_offset = 0usize;
    for (page_index, page_laces) in laces.chunks(255).enumerate() {
        let body_len: usize = page_laces.iter().map(|&n| n as usize).sum();
        let last = page_index + 1 == page_count;
        let mut header_type = if page_index == 0 { BOS } else { CONTINUED };
        if last {
            header_type |= EOS;
        }
        let granule = if last { 0 } else { u64::MAX };
        let body_end = body_offset + body_len;
        pages.extend_from_slice(&build_page(
            header_type,
            granule,
            serial,
            page_index as u32,
            page_laces,
            &packet[body_offset..body_end],
        ));
        body_offset = body_end;
    }
    Ok(pages)
}

#[cfg(feature = "test-support")]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let pages = validate_ogg(&clean)?.pages;
    let used: std::collections::HashSet<u32> = pages.iter().map(|page| page.serial).collect();
    let mut serial = u32::from_le_bytes(*b"c2pa");
    while used.contains(&serial) {
        serial = serial.wrapping_add(1);
    }

    let insert_at = pages
        .iter()
        .find(|page| page.header_type & BOS == 0)
        .map(|page| page.start)
        .unwrap_or(clean.len());
    let manifest_pages = build_manifest_pages(manifest_store, serial)?;

    let mut out = Vec::with_capacity(clean.len() + manifest_pages.len());
    out.extend_from_slice(&clean[..insert_at]);
    out.extend_from_slice(&manifest_pages);
    out.extend_from_slice(&clean[insert_at..]);
    Ok(out)
}

pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let validated = validate_ogg(data)?;
    let Some(manifest_serial) = validated.manifest_serial else {
        return Ok(Vec::new());
    };
    Ok(validated
        .pages
        .into_iter()
        .filter(|page| page.serial == manifest_serial)
        .map(|page| DataHashExclusion {
            start: page.start,
            length: page.end - page.start,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::dummy_manifest_store;

    fn bare_ogg() -> Vec<u8> {
        let packet = b"\x01vorbisfixture";
        build_page(BOS | EOS, 0, 7, 0, &[packet.len() as u8], packet)
    }

    fn update_page_crc(data: &mut [u8], start: usize) {
        let lace_end = start + 27 + data[start + 26] as usize;
        let body_len: usize = data[start + 27..lace_end]
            .iter()
            .map(|&lace| lace as usize)
            .sum();
        let end = lace_end + body_len;
        let checksum = ogg_crc_page(&data[start..end]);
        data[start + 22..start + 26].copy_from_slice(&checksum.to_le_bytes());
    }

    fn assert_full_rejected(data: &[u8]) {
        assert!(extract(data).is_err());
        assert!(exclusions(data).is_err());
    }

    fn manifest_pages(data: &[u8]) -> Vec<Page> {
        let validated = validate_ogg(data).unwrap();
        let serial = validated.manifest_serial.unwrap();
        validated
            .pages
            .into_iter()
            .filter(|page| page.serial == serial)
            .collect()
    }

    #[test]
    fn manifest_round_trip_and_strip() {
        let asset = bare_ogg();
        let store = dummy_manifest_store();
        let embedded = embed(&asset, &store).unwrap();
        assert_eq!(extract(&embedded).unwrap(), Some(store));
        assert_eq!(strip(&embedded).unwrap(), asset);
        assert_eq!(exclusions(&embedded).unwrap().len(), 1);
    }

    #[test]
    fn manifest_bos_precedes_first_audio_data_page() {
        let serial = 7;
        let identification = b"\x01vorbisfixture";
        let comments = b"\x03vorbiscomments";
        let audio = b"audio-packet";
        let mut asset = build_page(
            BOS,
            0,
            serial,
            0,
            &[identification.len() as u8],
            identification,
        );
        asset.extend_from_slice(&build_page(
            0,
            0,
            serial,
            1,
            &[comments.len() as u8],
            comments,
        ));
        asset.extend_from_slice(&build_page(EOS, 1, serial, 2, &[audio.len() as u8], audio));

        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let pages = validate_ogg(&embedded).unwrap().pages;
        assert_eq!(pages[0].serial, serial);
        assert_ne!(pages[1].serial, serial);
        assert_ne!(pages[1].header_type & BOS, 0);
        assert_eq!(pages[2].serial, serial);
        assert_eq!(pages[2].header_type & BOS, 0);
        assert_eq!(strip(&embedded).unwrap(), asset);
    }

    #[test]
    fn packet_spans_multiple_pages() {
        let asset = bare_ogg();
        let store = vec![0x5a; 130_000];
        let embedded = embed(&asset, &store).unwrap();
        assert_eq!(extract(&embedded).unwrap(), Some(store));
        assert!(exclusions(&embedded).unwrap().len() >= 2);
    }

    #[test]
    fn replacement_keeps_one_manifest_stream() {
        let asset = bare_ogg();
        let first = embed(&asset, b"first").unwrap();
        let second = embed(&first, b"second").unwrap();
        assert_eq!(extract(&second).unwrap(), Some(b"second".to_vec()));
        assert_eq!(strip(&second).unwrap(), asset);
    }

    #[test]
    fn truncated_page_is_rejected() {
        let mut asset = bare_ogg();
        asset.pop();
        assert!(extract(&asset).is_err());
    }
    #[test]
    fn full_asset_rejects_flipped_manifest_crc() {
        let mut asset = embed(&bare_ogg(), &dummy_manifest_store()).unwrap();
        let page = manifest_pages(&asset).remove(0);
        asset[page.end - 1] ^= 1;
        assert_full_rejected(&asset);
    }

    #[test]
    fn full_asset_rejects_reserved_flags() {
        let mut asset = embed(&bare_ogg(), &dummy_manifest_store()).unwrap();
        let page = manifest_pages(&asset).remove(0);
        asset[page.start + 5] |= 0x08;
        update_page_crc(&mut asset, page.start);
        assert_full_rejected(&asset);
    }

    #[test]
    fn full_asset_rejects_later_bos_and_sequence_gap() {
        let asset = embed(&bare_ogg(), &vec![0x5a; 130_000]).unwrap();
        let pages = manifest_pages(&asset);
        assert!(pages.len() > 1);

        let mut later_bos = asset.clone();
        later_bos[pages[1].start + 5] |= BOS;
        update_page_crc(&mut later_bos, pages[1].start);
        assert_full_rejected(&later_bos);

        let mut sequence_gap = asset;
        sequence_gap[pages[1].start + 18..pages[1].start + 22].copy_from_slice(&2u32.to_le_bytes());
        update_page_crc(&mut sequence_gap, pages[1].start);
        assert_full_rejected(&sequence_gap);
    }

    #[test]
    fn full_asset_rejects_empty_page() {
        let empty = build_page(BOS | EOS, 0, 99, 0, &[], &[]);
        assert_full_rejected(&empty);
    }

    #[test]
    fn full_asset_rejects_missing_eos_and_packet_terminator() {
        let mut missing_eos = embed(&bare_ogg(), &dummy_manifest_store()).unwrap();
        let page = manifest_pages(&missing_eos).remove(0);
        missing_eos[page.start + 5] &= !EOS;
        update_page_crc(&mut missing_eos, page.start);
        assert_full_rejected(&missing_eos);

        let mut unterminated_body = C2PA_PACKET_ID.to_vec();
        unterminated_body.resize(255, 0x5a);
        let unterminated = build_page(BOS | EOS, 0, 99, 0, &[255], &unterminated_body);
        assert_full_rejected(&unterminated);
    }

    #[test]
    fn full_asset_rejects_packet_or_page_after_manifest() {
        let store = b"x";
        let mut packet = C2PA_PACKET_ID.to_vec();
        packet.extend_from_slice(store);
        let first_len = u8::try_from(packet.len()).unwrap();
        packet.push(b'x');
        let mut trailing_packet = build_page(BOS | EOS, 0, 99, 0, &[first_len, 1], &packet);
        trailing_packet.extend_from_slice(&bare_ogg());
        assert_full_rejected(&trailing_packet);

        let mut trailing_page = build_manifest_pages(store, 99).unwrap();
        trailing_page.extend_from_slice(&build_page(EOS, 0, 99, 1, &[1], b"x"));
        trailing_page.extend_from_slice(&bare_ogg());
        assert_full_rejected(&trailing_page);
    }

    #[test]
    fn full_asset_rejects_duplicate_c2pa_streams() {
        let store = dummy_manifest_store();
        let mut asset = build_manifest_pages(&store, 98).unwrap();
        asset.extend_from_slice(&build_manifest_pages(&store, 99).unwrap());
        asset.extend_from_slice(&bare_ogg());
        assert_full_rejected(&asset);
    }
}
