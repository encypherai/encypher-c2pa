// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Standard MIDI Files (MIDI 1.0, C2PA 2.5 "Embedding manifests into Standard
//! MIDI Files"): the store is the data of a Sequencer-Specific Meta Event
//! (`FF 7F`) whose data field starts with the C2PA extended manufacturer
//! identifier `00 43 32`, in the designated track chunk (Format 0: the sole
//! track; Format 1: the last; Format 2: the first).
//!
//! The reader walks every event of every track, honouring running status, so
//! a second C2PA event anywhere in the file is seen: the clause treats more
//! than one as no manifest located. Only the store bytes after the identifier
//! are the data-hash carrier; the event framing, its length, and the
//! identifier stay hashed.
//!
//! MIDI 2.0 Clip Files (UMP) have no `FF 7F` event and are not this carrier.

use crate::c2pa_formats::util::be_u32;
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Midi;
/// The C2PA extended manufacturer identifier (`00` + ASCII "C2").
const C2PA_MANUFACTURER_ID: [u8; 3] = [0x00, 0x43, 0x32];
/// A track holds at most this many events before the reader refuses it; the
/// bound keeps a crafted file from turning one parse into unbounded work.
const MAX_EVENTS_PER_FILE: usize = 16 * 1024 * 1024;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// The store span inside the file, and the track that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct C2paEvent {
    track: usize,
    store_start: usize,
    store_len: usize,
}

/// Read a MIDI variable-length quantity (at most four bytes).
fn read_vlq(data: &[u8], pos: &mut usize, end: usize) -> Result<u32, FormatError> {
    let mut value = 0u32;
    for _ in 0..4 {
        if *pos >= end {
            return Err(FormatError::Truncated(FMT));
        }
        let byte = data[*pos];
        *pos += 1;
        value = (value << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("variable-length quantity exceeds four bytes"))
}

struct Parsed {
    format: u16,
    /// `[start, end)` of each `MTrk` chunk's event data, in file order.
    tracks: Vec<(usize, usize)>,
}

fn parse_chunks(data: &[u8]) -> Result<Parsed, FormatError> {
    if data.get(..4) != Some(b"MThd") {
        return Err(invalid("missing MThd header chunk"));
    }
    let header_len = be_u32(data, 4).ok_or(FormatError::Truncated(FMT))? as usize;
    if header_len < 6 {
        return Err(invalid("MThd chunk shorter than six bytes"));
    }
    let header_end = 8usize
        .checked_add(header_len)
        .filter(|end| *end <= data.len())
        .ok_or(FormatError::Truncated(FMT))?;
    let format = u16::from_be_bytes([data[8], data[9]]);
    let declared_tracks = u16::from_be_bytes([data[10], data[11]]) as usize;
    if format > 2 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "MThd format is not 0, 1, or 2",
        });
    }
    if declared_tracks == 0 || (format == 0 && declared_tracks != 1) {
        return Err(invalid("MThd track count is inconsistent with its format"));
    }
    let mut tracks = Vec::with_capacity(declared_tracks);
    let mut pos = header_end;
    while pos < data.len() {
        let kind = data.get(pos..pos + 4).ok_or(FormatError::Truncated(FMT))?;
        let len = be_u32(data, pos + 4).ok_or(FormatError::Truncated(FMT))? as usize;
        let body = pos + 8;
        let end = body
            .checked_add(len)
            .filter(|end| *end <= data.len())
            .ok_or(FormatError::Truncated(FMT))?;
        // Unknown ("alien") chunk types are skipped, as the SMF specification
        // requires of a reader.
        if kind == b"MTrk" {
            tracks.push((body, end));
        }
        pos = end;
    }
    if tracks.len() != declared_tracks {
        return Err(invalid(
            "MTrk chunk count differs from the MThd track count",
        ));
    }
    Ok(Parsed { format, tracks })
}

/// Walk one track's events, reporting every C2PA `FF 7F` event. A track must
/// end with exactly one End of Track event and nothing after it.
fn scan_track(
    data: &[u8],
    track: usize,
    (start, end): (usize, usize),
    events: &mut usize,
    found: &mut Vec<C2paEvent>,
) -> Result<(), FormatError> {
    let mut pos = start;
    let mut running_status: Option<u8> = None;
    loop {
        if pos >= end {
            return Err(invalid("track ends without an End of Track event"));
        }
        *events += 1;
        if *events > MAX_EVENTS_PER_FILE {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "event count exceeds the verifier bound",
            });
        }
        read_vlq(data, &mut pos, end)?;
        let first = *data.get(pos).ok_or(FormatError::Truncated(FMT))?;
        match first {
            0xff => {
                pos += 1;
                let kind = *data
                    .get(pos)
                    .filter(|_| pos < end)
                    .ok_or(FormatError::Truncated(FMT))?;
                pos += 1;
                let len = read_vlq(data, &mut pos, end)? as usize;
                let body_end = pos
                    .checked_add(len)
                    .filter(|e| *e <= end)
                    .ok_or(FormatError::Truncated(FMT))?;
                // Meta and system-exclusive events cancel running status.
                running_status = None;
                if kind == 0x2f {
                    if len != 0 {
                        return Err(invalid("End of Track event carries data"));
                    }
                    if body_end != end {
                        return Err(invalid("bytes follow the End of Track event"));
                    }
                    return Ok(());
                }
                if kind == 0x7f && data[pos..body_end].starts_with(&C2PA_MANUFACTURER_ID) {
                    found.push(C2paEvent {
                        track,
                        store_start: pos + C2PA_MANUFACTURER_ID.len(),
                        store_len: len - C2PA_MANUFACTURER_ID.len(),
                    });
                }
                pos = body_end;
            }
            0xf0 | 0xf7 => {
                pos += 1;
                let len = read_vlq(data, &mut pos, end)? as usize;
                pos = pos
                    .checked_add(len)
                    .filter(|e| *e <= end)
                    .ok_or(FormatError::Truncated(FMT))?;
                running_status = None;
            }
            0xf1..=0xfe => {
                return Err(invalid("system common or real-time message in a track"));
            }
            0x80..=0xef => {
                running_status = Some(first);
                pos += 1;
                pos = skip_channel_data(first, pos, end)?;
            }
            _ => {
                let status = running_status.ok_or(invalid("data byte without running status"))?;
                pos = skip_channel_data(status, pos, end)?;
            }
        }
    }
}

fn skip_channel_data(status: u8, pos: usize, end: usize) -> Result<usize, FormatError> {
    let count = match status & 0xf0 {
        0xc0 | 0xd0 => 1,
        _ => 2,
    };
    pos.checked_add(count)
        .filter(|e| *e <= end)
        .ok_or(FormatError::Truncated(FMT))
}

/// The located store span: `None` when the designated track carries no C2PA
/// event, or when the file carries more than one (the clause treats that as
/// no manifest located).
fn locate(data: &[u8]) -> Result<Option<C2paEvent>, FormatError> {
    let parsed = parse_chunks(data)?;
    let mut found = Vec::new();
    let mut events = 0usize;
    for (index, span) in parsed.tracks.iter().enumerate() {
        scan_track(data, index, *span, &mut events, &mut found)?;
    }
    let designated = match parsed.format {
        1 => parsed.tracks.len() - 1,
        _ => 0,
    };
    Ok(match found.as_slice() {
        [only] if only.track == designated => Some(*only),
        _ => None,
    })
}

pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(locate(data)?
        .map(|event| data[event.store_start..event.store_start + event.store_len].to_vec()))
}

/// The single data-hash exclusion: the store bytes after the identifier.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(locate(data)?
        .map(|event| DataHashExclusion {
            start: event.store_start,
            length: event.store_len,
        })
        .into_iter()
        .collect())
}

/// Test fixtures: an SMF with `tracks` tracks of the given format, the C2PA
/// event (if any) inserted before End of Track in track `c2pa_track`.
#[cfg(test)]
pub(crate) fn sample_asset(format: u16, tracks: usize, c2pa: &[(usize, &[u8])]) -> Vec<u8> {
    fn vlq(mut value: u32) -> Vec<u8> {
        let mut out = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            out.insert(0, ((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        out
    }
    let mut out = b"MThd".to_vec();
    out.extend_from_slice(&6u32.to_be_bytes());
    out.extend_from_slice(&format.to_be_bytes());
    out.extend_from_slice(&(tracks as u16).to_be_bytes());
    out.extend_from_slice(&96u16.to_be_bytes());
    for track in 0..tracks {
        // Note on, then a running-status note off, so the walker must honour
        // running status to reach the meta events.
        let mut body = vec![0x00, 0x90, 0x3c, 0x40, 0x60, 0x3c, 0x00];
        for (target, store) in c2pa {
            if *target == track {
                body.push(0x00);
                body.extend_from_slice(&[0xff, 0x7f]);
                body.extend(vlq((store.len() + 3) as u32));
                body.extend_from_slice(&C2PA_MANUFACTURER_ID);
                body.extend_from_slice(store);
            }
        }
        body.extend_from_slice(&[0x10, 0xff, 0x2f, 0x00]);
        out.extend_from_slice(b"MTrk");
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &[u8] = b"jumbf-store-bytes";

    #[test]
    fn designated_track_follows_the_smf_format() {
        // Format 0: sole track; Format 1: last; Format 2: first.
        for (format, tracks, target) in [(0u16, 1usize, 0usize), (1, 3, 2), (2, 3, 0)] {
            let asset = sample_asset(format, tracks, &[(target, STORE)]);
            assert_eq!(
                extract(&asset).unwrap().as_deref(),
                Some(STORE),
                "format {format}"
            );
            let spans = exclusions(&asset).unwrap();
            assert_eq!(spans.len(), 1, "one exclusion");
            let span = spans[0];
            assert_eq!(&asset[span.start..span.start + span.length], STORE);
            // The identifier stays hashed: it sits immediately before the span.
            assert_eq!(&asset[span.start - 3..span.start], &C2PA_MANUFACTURER_ID);
        }
    }

    #[test]
    fn a_c2pa_event_outside_the_designated_track_is_not_located() {
        let asset = sample_asset(1, 3, &[(0, STORE)]);
        assert_eq!(extract(&asset).unwrap(), None);
        assert!(exclusions(&asset).unwrap().is_empty());
    }

    #[test]
    fn two_c2pa_events_locate_no_manifest() {
        let asset = sample_asset(1, 3, &[(2, STORE), (1, b"other")]);
        assert_eq!(extract(&asset).unwrap(), None);
        let same_track = sample_asset(0, 1, &[(0, STORE), (0, STORE)]);
        assert_eq!(extract(&same_track).unwrap(), None);
    }

    #[test]
    fn malformed_files_are_rejected() {
        let asset = sample_asset(0, 1, &[(0, STORE)]);
        // Truncated inside the last track.
        assert!(extract(&asset[..asset.len() - 2]).is_err());
        // Track count disagrees with the chunks present.
        let mut wrong_count = asset.clone();
        wrong_count[11] = 2;
        assert!(extract(&wrong_count).is_err());
        // Not an SMF.
        assert!(extract(b"RIFF....").is_err());
        // A data byte with no running status.
        let mut no_status = sample_asset(0, 1, &[]);
        let first_event = 14 + 8 + 1;
        no_status[first_event] = 0x3c;
        assert!(extract(&no_status).is_err());
    }

    #[test]
    fn a_file_without_c2pa_has_no_manifest() {
        let asset = sample_asset(1, 2, &[]);
        assert_eq!(extract(&asset).unwrap(), None);
    }
}
