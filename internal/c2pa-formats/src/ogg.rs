//! Ogg Vorbis: C2PA JUMBF in a dedicated logical bitstream.
//!
//! The first packet in the C2PA stream is `\x00c2pa` followed immediately by
//! the manifest store. The stream is independent of the Vorbis audio stream and
//! may span any number of Ogg pages.

use std::collections::HashSet;

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
    header_type: u8,
    serial: u32,
    laces: Vec<u8>,
    body_start: usize,
}

fn parse_pages(data: &[u8]) -> Result<Vec<Page>, FormatError> {
    if data.is_empty() {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "empty Ogg stream",
        });
    }

    let mut pages = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let fixed_end = pos.checked_add(27).ok_or(FormatError::Truncated(FMT))?;
        let fixed = data
            .get(pos..fixed_end)
            .ok_or(FormatError::Truncated(FMT))?;
        if &fixed[..4] != CAPTURE || fixed[4] != 0 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "invalid Ogg page header",
            });
        }
        let segment_count = fixed[26] as usize;
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
        pages.push(Page {
            start: pos,
            end,
            header_type: fixed[5],
            serial: u32::from_le_bytes([fixed[14], fixed[15], fixed[16], fixed[17]]),
            laces,
            body_start: lace_end,
        });
        pos = end;
    }
    Ok(pages)
}

fn first_packet(data: &[u8], pages: &[Page], first: usize) -> Result<Vec<u8>, FormatError> {
    let serial = pages[first].serial;
    let mut packet = Vec::new();
    let mut first_stream_page = true;

    for page in pages
        .iter()
        .skip(first)
        .filter(|page| page.serial == serial)
    {
        if first_stream_page {
            if page.header_type & BOS == 0 || page.header_type & CONTINUED != 0 {
                return Err(FormatError::InvalidStructure {
                    format: FMT,
                    detail: "invalid first page for Ogg logical stream",
                });
            }
            first_stream_page = false;
        } else if page.header_type & CONTINUED == 0 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "continued Ogg packet missing continuation flag",
            });
        }

        let mut body = page.body_start;
        for &lace in &page.laces {
            let next = body + lace as usize;
            packet.extend_from_slice(&data[body..next]);
            body = next;
            if lace < 255 {
                return Ok(packet);
            }
        }
    }

    Err(FormatError::Truncated(FMT))
}

fn manifest_serials(data: &[u8], pages: &[Page]) -> Result<HashSet<u32>, FormatError> {
    let mut seen = HashSet::new();
    let mut manifests = HashSet::new();
    for (index, page) in pages.iter().enumerate() {
        if !seen.insert(page.serial) {
            continue;
        }
        if page.header_type & BOS == 0 {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "Ogg logical stream has no beginning-of-stream page",
            });
        }
        let packet = first_packet(data, pages, index)?;
        if packet.starts_with(C2PA_PACKET_ID) {
            manifests.insert(page.serial);
        }
    }
    Ok(manifests)
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    let pages = parse_pages(data)?;
    let mut seen = HashSet::new();
    for (index, page) in pages.iter().enumerate() {
        if !seen.insert(page.serial) {
            continue;
        }
        let packet = first_packet(data, &pages, index)?;
        if let Some(manifest) = packet.strip_prefix(C2PA_PACKET_ID) {
            return Ok(Some(manifest.to_vec()));
        }
    }
    Ok(None)
}

pub(crate) fn strip(data: &[u8]) -> Result<Vec<u8>, FormatError> {
    let pages = parse_pages(data)?;
    let manifests = manifest_serials(data, &pages)?;
    if manifests.is_empty() {
        return Ok(data.to_vec());
    }

    let kept_len: usize = pages
        .iter()
        .filter(|page| !manifests.contains(&page.serial))
        .map(|page| page.end - page.start)
        .sum();
    let mut out = Vec::with_capacity(kept_len);
    for page in pages {
        if !manifests.contains(&page.serial) {
            out.extend_from_slice(&data[page.start..page.end]);
        }
    }
    Ok(out)
}

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

fn packet_laces(packet_len: usize) -> Vec<u8> {
    let full = packet_len / 255;
    let remainder = packet_len % 255;
    let mut laces = Vec::with_capacity(full + 1);
    laces.resize(full, 255);
    laces.push(remainder as u8);
    laces
}

pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let pages = parse_pages(&clean)?;
    let used: HashSet<u32> = pages.iter().map(|page| page.serial).collect();
    let mut serial = u32::from_le_bytes(*b"c2pa");
    while used.contains(&serial) {
        serial = serial.wrapping_add(1);
    }

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

    // RFC 3533 requires every logical stream's BOS page to precede the first
    // non-BOS page in a multiplexed physical stream. Insert the C2PA stream
    // after the source's initial run of BOS pages, not after the audio EOS;
    // appending it would form an unknown chained stream that common decoders
    // such as FFmpeg reject.
    let insert_at = pages
        .iter()
        .find(|page| page.header_type & BOS == 0)
        .map(|page| page.start)
        .unwrap_or(clean.len());
    let page_count = laces.len().div_ceil(255);
    let mut manifest_pages = Vec::with_capacity(packet.len() + 27 * page_count + laces.len());
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
        manifest_pages.extend_from_slice(&build_page(
            header_type,
            granule,
            serial,
            page_index as u32,
            page_laces,
            &packet[body_offset..body_end],
        ));
        body_offset = body_end;
    }

    let mut out = Vec::with_capacity(clean.len() + manifest_pages.len());
    out.extend_from_slice(&clean[..insert_at]);
    out.extend_from_slice(&manifest_pages);
    out.extend_from_slice(&clean[insert_at..]);
    Ok(out)
}

pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let pages = parse_pages(data)?;
    let manifests = manifest_serials(data, &pages)?;
    Ok(pages
        .into_iter()
        .filter(|page| manifests.contains(&page.serial))
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
        let pages = parse_pages(&embedded).unwrap();
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
}
