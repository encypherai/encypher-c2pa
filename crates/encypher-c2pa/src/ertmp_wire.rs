// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Bounded FLV and RTMP framing for the E-RTMP verifier.
//!
//! The packet layouts follow Veovera Enhanced RTMP v2 at revision
//! `dc10175591d24d4dfd4ff1908d6b4d0215a69496`. This module only frames and
//! verifies transport. It does not contain signing keys or sign content.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use crate::{ErtmpEvent, ErtmpInput, ErtmpMediaType, ErtmpTrack};

const AUDIO_MESSAGE: u8 = 8;
const VIDEO_MESSAGE: u8 = 9;
const AGGREGATE_MESSAGE: u8 = 22;
const SET_CHUNK_SIZE: u8 = 1;
const VIDEO_METADATA: u8 = 4;
const VIDEO_MULTITRACK: u8 = 6;
const AUDIO_MULTITRACK: u8 = 5;

/// Hard bounds applied before allocating from untrusted wire lengths.
#[derive(Debug, Clone, Copy)]
pub struct ErtmpWireLimits {
    /// Maximum bytes accepted for one connection or FLV file.
    pub max_wire_bytes: usize,
    /// Maximum reassembled RTMP message or FLV tag body.
    pub max_message_bytes: usize,
    /// Maximum emitted verifier events.
    pub max_events: usize,
    /// Maximum negotiated RTMP chunk size.
    pub max_chunk_size: usize,
}

impl Default for ErtmpWireLimits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 100_000_000,
            max_message_bytes: 16 * 1024 * 1024,
            max_events: 1_000_000,
            max_chunk_size: 1024 * 1024,
        }
    }
}

/// Connection properties authenticated by the existing E-RTMP verifier.
#[derive(Debug, Clone, Copy)]
pub struct ErtmpConnectionContext {
    /// Client `capsEx` value from the connect command.
    pub client_caps_ex: u64,
    /// Server `capsEx` value from the connect response.
    pub server_caps_ex: u64,
    /// Negotiated AMF object encoding.
    pub object_encoding: u8,
}

/// FLV has no chunk-stream identity, so callers must provide the IDs from the
/// RTMP connection that the file/tag trace represents.
#[derive(Debug, Clone, Copy)]
pub struct FlvWireOptions {
    /// Connection capability context.
    pub connection: ErtmpConnectionContext,
    /// Chunk stream carrying audio tags.
    pub audio_chunk_stream_id: u32,
    /// Chunk stream carrying video tags.
    pub video_chunk_stream_id: u32,
    /// Resource bounds.
    pub limits: ErtmpWireLimits,
}

/// RTMP chunk decoder options.
#[derive(Debug, Clone, Copy)]
pub struct RtmpWireOptions {
    /// Connection capability context.
    pub connection: ErtmpConnectionContext,
    /// Chunk size in force at the start of each supplied connection.
    pub initial_chunk_size: usize,
    /// Resource bounds.
    pub limits: ErtmpWireLimits,
}

/// A framing or media-packet defect. Every defect is fatal: malformed input is
/// never converted into a partial event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErtmpWireError {
    message: String,
}

impl ErtmpWireError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ErtmpWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for ErtmpWireError {}

/// Parse one complete FLV file into ordered verifier events.
pub fn ertmp_input_from_flv(
    bytes: &[u8],
    options: FlvWireOptions,
) -> Result<ErtmpInput, ErtmpWireError> {
    if bytes.len() > options.limits.max_wire_bytes {
        return Err(ErtmpWireError::new("FLV input exceeds the wire byte limit"));
    }
    if bytes.len() < 13 || &bytes[..3] != b"FLV" || bytes[3] != 1 {
        return Err(ErtmpWireError::new("invalid or truncated FLV header"));
    }
    let data_offset = be_u32(&bytes[5..9]) as usize;
    if data_offset < 9 || data_offset.checked_add(4).is_none_or(|end| end > bytes.len()) {
        return Err(ErtmpWireError::new("invalid FLV data offset"));
    }
    if be_u32(&bytes[data_offset..data_offset + 4]) != 0 {
        return Err(ErtmpWireError::new("FLV PreviousTagSize0 is not zero"));
    }
    let mut events = Vec::new();
    let mut offset = data_offset + 4;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 15 {
            return Err(ErtmpWireError::new("truncated FLV tag"));
        }
        let tag_type = bytes[offset] & 0x1f;
        if bytes[offset] & 0xc0 != 0 {
            return Err(ErtmpWireError::new("encrypted or filtered FLV tags are unsupported"));
        }
        let data_size = be_u24(&bytes[offset + 1..offset + 4]) as usize;
        if data_size > options.limits.max_message_bytes {
            return Err(ErtmpWireError::new("FLV tag exceeds the message byte limit"));
        }
        let tag_end = offset
            .checked_add(11)
            .and_then(|value| value.checked_add(data_size))
            .and_then(|value| value.checked_add(4))
            .ok_or_else(|| ErtmpWireError::new("FLV tag length overflow"))?;
        if tag_end > bytes.len() {
            return Err(ErtmpWireError::new("truncated FLV tag body"));
        }
        if bytes[offset + 8..offset + 11] != [0, 0, 0] {
            return Err(ErtmpWireError::new("FLV tag stream id is not zero"));
        }
        let timestamp = be_u24(&bytes[offset + 4..offset + 7]) | ((bytes[offset + 7] as u32) << 24);
        let body = &bytes[offset + 11..offset + 11 + data_size];
        let previous = be_u32(&bytes[offset + 11 + data_size..tag_end]) as usize;
        if previous != 11 + data_size {
            return Err(ErtmpWireError::new("FLV PreviousTagSize does not match its tag"));
        }
        match tag_type {
            AUDIO_MESSAGE => parse_audio_message(
                body,
                timestamp,
                options.audio_chunk_stream_id,
                &mut events,
                options.limits,
            )?,
            VIDEO_MESSAGE => parse_video_message(
                body,
                timestamp,
                options.video_chunk_stream_id,
                &mut events,
                options.limits,
            )?,
            18 => {}
            other => {
                return Err(ErtmpWireError::new(format!(
                    "unsupported FLV tag type {other}"
                )))
            }
        }
        offset = tag_end;
    }
    Ok(input(options.connection, events))
}

/// Parse one or more complete RTMP connection traces. A reconnect event is
/// inserted between traces and all chunk/message state is reset at that point.
pub fn ertmp_input_from_rtmp_connections(
    connections: &[&[u8]],
    options: RtmpWireOptions,
) -> Result<ErtmpInput, ErtmpWireError> {
    if connections.is_empty() {
        return Err(ErtmpWireError::new("at least one RTMP connection is required"));
    }
    if options.initial_chunk_size == 0 || options.initial_chunk_size > options.limits.max_chunk_size {
        return Err(ErtmpWireError::new("initial RTMP chunk size is out of bounds"));
    }
    let mut events = Vec::new();
    for (index, bytes) in connections.iter().enumerate() {
        if bytes.len() > options.limits.max_wire_bytes {
            return Err(ErtmpWireError::new("RTMP connection exceeds the wire byte limit"));
        }
        if index != 0 {
            push_event(&mut events, ErtmpEvent::Reconnect, options.limits)?;
        }
        RtmpDecoder::new(options.initial_chunk_size, options.limits).decode(bytes, &mut events)?;
    }
    Ok(input(options.connection, events))
}

fn input(connection: ErtmpConnectionContext, events: Vec<ErtmpEvent>) -> ErtmpInput {
    ErtmpInput {
        client_caps_ex: connection.client_caps_ex,
        server_caps_ex: connection.server_caps_ex,
        object_encoding: connection.object_encoding,
        events,
    }
}

/// Wrap a native AMF3 `[name, ByteArray]` pair body as an enhanced video
/// Metadata message payload. Audio framing is deliberately unavailable because
/// Enhanced RTMP v2 assigns no audio Metadata packet number.
pub fn encode_video_metadata_payload(
    metadata_pair: &[u8],
    fourcc: [u8; 4],
) -> Result<Vec<u8>, ErtmpWireError> {
    validate_fourcc(fourcc)?;
    parse_amf3_pairs(metadata_pair)?;
    let mut payload = Vec::with_capacity(metadata_pair.len() + 5);
    payload.push(0x80 | (1 << 4) | VIDEO_METADATA);
    payload.extend_from_slice(&fourcc);
    payload.extend_from_slice(metadata_pair);
    Ok(payload)
}

/// Wrap one RTMP media payload as a complete FLV tag, including its back pointer.
pub fn encode_flv_tag(message_type: u8, timestamp: u32, payload: &[u8]) -> Result<Vec<u8>, ErtmpWireError> {
    if !matches!(message_type, AUDIO_MESSAGE | VIDEO_MESSAGE) {
        return Err(ErtmpWireError::new("FLV wire output supports only audio or video tags"));
    }
    let data_len = u32::try_from(payload.len())
        .ok()
        .filter(|value| *value <= 0x00ff_ffff)
        .ok_or_else(|| ErtmpWireError::new("FLV payload exceeds UI24"))?;
    let mut out = Vec::with_capacity(payload.len() + 15);
    out.push(message_type);
    put_u24(data_len, &mut out);
    put_u24(timestamp & 0x00ff_ffff, &mut out);
    out.push((timestamp >> 24) as u8);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(payload);
    out.extend_from_slice(&(11u32 + data_len).to_be_bytes());
    Ok(out)
}

/// Chunk one media payload as a complete RTMP message using a type-0 first
/// header and type-3 continuation headers.
pub fn encode_rtmp_message(
    chunk_stream_id: u32,
    message_stream_id: u32,
    message_type: u8,
    timestamp: u32,
    payload: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, ErtmpWireError> {
    if !matches!(message_type, AUDIO_MESSAGE | VIDEO_MESSAGE) {
        return Err(ErtmpWireError::new("RTMP wire output supports only audio or video messages"));
    }
    if chunk_size == 0 {
        return Err(ErtmpWireError::new("RTMP output chunk size must be positive"));
    }
    let message_len = u32::try_from(payload.len())
        .ok()
        .filter(|value| *value <= 0x00ff_ffff)
        .ok_or_else(|| ErtmpWireError::new("RTMP message payload exceeds UI24"))?;
    let extended = timestamp >= 0x00ff_ffff;
    let mut out = Vec::with_capacity(payload.len() + 32);
    put_basic_header(0, chunk_stream_id, &mut out)?;
    put_u24(if extended { 0x00ff_ffff } else { timestamp }, &mut out);
    put_u24(message_len, &mut out);
    out.push(message_type);
    out.extend_from_slice(&message_stream_id.to_le_bytes());
    if extended {
        out.extend_from_slice(&timestamp.to_be_bytes());
    }
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + chunk_size).min(payload.len());
        out.extend_from_slice(&payload[offset..end]);
        offset = end;
        if offset < payload.len() {
            put_basic_header(3, chunk_stream_id, &mut out)?;
            if extended {
                out.extend_from_slice(&timestamp.to_be_bytes());
            }
        }
    }
    Ok(out)
}

fn put_basic_header(fmt: u8, chunk_stream_id: u32, out: &mut Vec<u8>) -> Result<(), ErtmpWireError> {
    if !(2..=65_599).contains(&chunk_stream_id) {
        return Err(ErtmpWireError::new("RTMP chunk stream id is outside 2..=65599"));
    }
    if chunk_stream_id <= 63 {
        out.push((fmt << 6) | chunk_stream_id as u8);
    } else if chunk_stream_id <= 319 {
        out.push(fmt << 6);
        out.push((chunk_stream_id - 64) as u8);
    } else {
        let encoded = chunk_stream_id - 64;
        out.push((fmt << 6) | 1);
        out.push(encoded as u8);
        out.push((encoded >> 8) as u8);
    }
    Ok(())
}

#[derive(Clone)]
struct ChunkHeader {
    timestamp: u32,
    timestamp_delta: u32,
    message_length: usize,
    message_type: u8,
    message_stream_id: u32,
    extended: bool,
    absolute: bool,
}

struct ChunkState {
    header: ChunkHeader,
    payload: Vec<u8>,
}

struct RtmpDecoder {
    chunk_size: usize,
    states: HashMap<u32, ChunkState>,
    limits: ErtmpWireLimits,
}

impl RtmpDecoder {
    fn new(chunk_size: usize, limits: ErtmpWireLimits) -> Self {
        Self {
            chunk_size,
            states: HashMap::new(),
            limits,
        }
    }

    fn decode(mut self, bytes: &[u8], events: &mut Vec<ErtmpEvent>) -> Result<(), ErtmpWireError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let (fmt, csid, basic_len) = parse_basic_header(&bytes[offset..])?;
            offset += basic_len;
            let previous = self.states.get(&csid).map(|state| state.header.clone());
            let continuing = self
                .states
                .get(&csid)
                .is_some_and(|state| state.payload.len() < state.header.message_length);
            if continuing && fmt != 3 {
                return Err(ErtmpWireError::new("RTMP message was replaced before all chunks arrived"));
            }
            let (mut header, header_len) = parse_message_header(fmt, previous.as_ref(), &bytes[offset..], continuing)?;
            offset += header_len;
            if header.extended {
                if bytes.len() - offset < 4 {
                    return Err(ErtmpWireError::new("truncated RTMP extended timestamp"));
                }
                let extended = be_u32(&bytes[offset..offset + 4]);
                offset += 4;
                if !continuing {
                    if header.absolute {
                        header.timestamp = extended;
                    } else {
                        header.timestamp_delta = extended;
                        header.timestamp = previous
                            .as_ref()
                            .map_or(extended, |prior| prior.timestamp.wrapping_add(extended));
                    }
                }
            }
            if header.message_length > self.limits.max_message_bytes {
                return Err(ErtmpWireError::new("RTMP message exceeds the message byte limit"));
            }
            if !continuing {
                self.states.insert(
                    csid,
                    ChunkState {
                        payload: Vec::with_capacity(header.message_length),
                        header,
                    },
                );
            }
            let state = self.states.get_mut(&csid).ok_or_else(|| ErtmpWireError::new("missing RTMP chunk state"))?;
            let remaining = state.header.message_length - state.payload.len();
            let take = remaining.min(self.chunk_size);
            if bytes.len() - offset < take {
                return Err(ErtmpWireError::new("truncated RTMP chunk payload"));
            }
            state.payload.extend_from_slice(&bytes[offset..offset + take]);
            offset += take;
            if state.payload.len() == state.header.message_length {
                let header = state.header.clone();
                let payload = std::mem::take(&mut state.payload);
                self.message(csid, &header, &payload, events)?;
            }
        }
        if self
            .states
            .values()
            .any(|state| !state.payload.is_empty() && state.payload.len() != state.header.message_length)
        {
            return Err(ErtmpWireError::new("RTMP connection ended during a fragmented message"));
        }
        Ok(())
    }

    fn message(
        &mut self,
        csid: u32,
        header: &ChunkHeader,
        payload: &[u8],
        events: &mut Vec<ErtmpEvent>,
    ) -> Result<(), ErtmpWireError> {
        match header.message_type {
            SET_CHUNK_SIZE => {
                if payload.len() != 4 || payload[0] & 0x80 != 0 {
                    return Err(ErtmpWireError::new("invalid RTMP Set Chunk Size message"));
                }
                let size = be_u32(payload) as usize;
                if size == 0 || size > self.limits.max_chunk_size {
                    return Err(ErtmpWireError::new("negotiated RTMP chunk size is out of bounds"));
                }
                self.chunk_size = size;
            }
            AUDIO_MESSAGE => parse_audio_message(payload, header.timestamp, csid, events, self.limits)?,
            VIDEO_MESSAGE => parse_video_message(payload, header.timestamp, csid, events, self.limits)?,
            AGGREGATE_MESSAGE => parse_aggregate(payload, header.timestamp, csid, events, self.limits)?,
            _ => {}
        }
        Ok(())
    }
}

fn parse_basic_header(bytes: &[u8]) -> Result<(u8, u32, usize), ErtmpWireError> {
    let first = *bytes.first().ok_or_else(|| ErtmpWireError::new("truncated RTMP basic header"))?;
    let fmt = first >> 6;
    match first & 0x3f {
        0 => {
            let low = *bytes.get(1).ok_or_else(|| ErtmpWireError::new("truncated RTMP two-byte basic header"))?;
            Ok((fmt, 64 + low as u32, 2))
        }
        1 => {
            let low = *bytes.get(1).ok_or_else(|| ErtmpWireError::new("truncated RTMP three-byte basic header"))?;
            let high = *bytes.get(2).ok_or_else(|| ErtmpWireError::new("truncated RTMP three-byte basic header"))?;
            Ok((fmt, 64 + low as u32 + ((high as u32) << 8), 3))
        }
        csid => Ok((fmt, csid as u32, 1)),
    }
}

fn parse_message_header(
    fmt: u8,
    previous: Option<&ChunkHeader>,
    bytes: &[u8],
    continuing: bool,
) -> Result<(ChunkHeader, usize), ErtmpWireError> {
    let need = [11, 7, 3, 0][fmt as usize];
    if bytes.len() < need {
        return Err(ErtmpWireError::new("truncated RTMP message header"));
    }
    let prior = || previous.cloned().ok_or_else(|| ErtmpWireError::new("compressed RTMP header has no predecessor"));
    match fmt {
        0 => {
            let raw = be_u24(&bytes[..3]);
            Ok((ChunkHeader {
                timestamp: raw,
                timestamp_delta: 0,
                message_length: be_u24(&bytes[3..6]) as usize,
                message_type: bytes[6],
                message_stream_id: u32::from_le_bytes(bytes[7..11].try_into().expect("fixed slice")),
                extended: raw == 0x00ff_ffff,
                absolute: true,
            }, 11))
        }
        1 => {
            let prior = prior()?;
            let delta = be_u24(&bytes[..3]);
            Ok((ChunkHeader {
                timestamp: prior.timestamp.wrapping_add(delta),
                timestamp_delta: delta,
                message_length: be_u24(&bytes[3..6]) as usize,
                message_type: bytes[6],
                message_stream_id: prior.message_stream_id,
                extended: delta == 0x00ff_ffff,
                absolute: false,
            }, 7))
        }
        2 => {
            let prior = prior()?;
            let delta = be_u24(&bytes[..3]);
            Ok((ChunkHeader {
                timestamp: prior.timestamp.wrapping_add(delta),
                timestamp_delta: delta,
                extended: delta == 0x00ff_ffff,
                absolute: false,
                ..prior
            }, 3))
        }
        3 => {
            let mut prior = prior()?;
            if !continuing {
                prior.timestamp = prior.timestamp.wrapping_add(prior.timestamp_delta);
            }
            Ok((prior, 0))
        }
        _ => Err(ErtmpWireError::new("invalid RTMP chunk format")),
    }
}

fn parse_aggregate(
    payload: &[u8],
    outer_timestamp: u32,
    csid: u32,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let mut offset = 0;
    let mut first_timestamp = None;
    while offset < payload.len() {
        if payload.len() - offset < 15 {
            return Err(ErtmpWireError::new("truncated RTMP Aggregate tag"));
        }
        let tag_type = payload[offset];
        let size = be_u24(&payload[offset + 1..offset + 4]) as usize;
        if size > limits.max_message_bytes {
            return Err(ErtmpWireError::new("RTMP Aggregate tag exceeds the message limit"));
        }
        let end = offset
            .checked_add(11 + size + 4)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("truncated RTMP Aggregate body"))?;
        if payload[offset + 8..offset + 11] != [0, 0, 0]
            || be_u32(&payload[offset + 11 + size..end]) as usize != 11 + size
        {
            return Err(ErtmpWireError::new("malformed RTMP Aggregate tag"));
        }
        let timestamp = be_u24(&payload[offset + 4..offset + 7]) | ((payload[offset + 7] as u32) << 24);
        let base = *first_timestamp.get_or_insert(timestamp);
        let normalized = outer_timestamp.wrapping_add(timestamp.wrapping_sub(base));
        let body = &payload[offset + 11..offset + 11 + size];
        match tag_type {
            AUDIO_MESSAGE => parse_audio_message(body, normalized, csid, events, limits)?,
            VIDEO_MESSAGE => parse_video_message(body, normalized, csid, events, limits)?,
            18 => {}
            other => return Err(ErtmpWireError::new(format!("unsupported Aggregate tag type {other}"))),
        }
        offset = end;
    }
    Ok(())
}

fn parse_video_message(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let first = *payload.first().ok_or_else(|| ErtmpWireError::new("empty RTMP video message"))?;
    if first & 0x80 == 0 {
        let codec = first & 0x0f;
        if codec != 7 {
            return Err(ErtmpWireError::new(format!("unsupported legacy video codec id {codec}")));
        }
        if payload.len() < 5 {
            return Err(ErtmpWireError::new("truncated legacy AVC packet"));
        }
        let packet_type = payload[1];
        let body = &payload[5..];
        return emit_video_packet(packet_type, body, timestamp, signed_u24(&payload[2..5]), csid, 0, events, limits);
    }
    let mut offset = 1;
    let mut packet_type = first & 0x0f;
    while packet_type == 7 {
        let length_byte = *payload.get(offset).ok_or_else(|| ErtmpWireError::new("truncated video ModEx length"))?;
        offset += 1;
        let length = if length_byte == 0xff {
            if payload.len() - offset < 2 {
                return Err(ErtmpWireError::new("truncated video ModEx extended length"));
            }
            let value = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize + 1;
            offset += 2;
            value
        } else {
            length_byte as usize + 1
        };
        offset = offset.checked_add(length).filter(|end| *end < payload.len())
            .ok_or_else(|| ErtmpWireError::new("video ModEx data exceeds its message"))?;
        packet_type = payload[offset] & 0x0f;
        offset += 1;
    }
    if packet_type == VIDEO_MULTITRACK {
        return parse_multitrack_video(&payload[offset..], timestamp, csid, events, limits);
    }
    if payload.len() - offset < 4 {
        return Err(ErtmpWireError::new("enhanced video packet is missing FOURCC"));
    }
    validate_fourcc(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
    offset += 4;
    let (cto, body) = if packet_type == 1 {
        if payload.len() - offset < 3 {
            return Err(ErtmpWireError::new("coded video packet is missing composition offset"));
        }
        (signed_u24(&payload[offset..offset + 3]), &payload[offset + 3..])
    } else {
        (0, &payload[offset..])
    };
    emit_video_packet(packet_type, body, timestamp, cto, csid, 0, events, limits)
}

fn parse_multitrack_video(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let header = *payload.first().ok_or_else(|| ErtmpWireError::new("truncated video Multitrack header"))?;
    let mode = header >> 4;
    let packet_type = header & 0x0f;
    if mode > 2 || packet_type == VIDEO_MULTITRACK || matches!(packet_type, 5 | 7 | 8..=15) {
        return Err(ErtmpWireError::new("unsupported video Multitrack mode or inner packet type"));
    }
    let mut offset = 1;
    let shared_fourcc = if mode != 2 {
        if payload.len() - offset < 4 {
            return Err(ErtmpWireError::new("video Multitrack packet is missing shared FOURCC"));
        }
        let value: [u8; 4] = payload[offset..offset + 4].try_into().expect("fixed slice");
        validate_fourcc(value)?;
        offset += 4;
        Some(value)
    } else {
        None
    };
    while offset < payload.len() {
        if mode == 2 {
            if payload.len() - offset < 4 {
                return Err(ErtmpWireError::new("video Multitrack track is missing FOURCC"));
            }
            validate_fourcc(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
            offset += 4;
        } else if shared_fourcc.is_none() {
            return Err(ErtmpWireError::new("missing shared video FOURCC"));
        }
        let track_id = *payload.get(offset).ok_or_else(|| ErtmpWireError::new("video Multitrack track is missing track id"))?;
        offset += 1;
        let size = if mode == 0 {
            payload.len() - offset
        } else {
            if payload.len() - offset < 3 {
                return Err(ErtmpWireError::new("video Multitrack track is missing payload size"));
            }
            let value = be_u24(&payload[offset..offset + 3]) as usize;
            offset += 3;
            value
        };
        let end = offset.checked_add(size).filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("video Multitrack payload exceeds its message"))?;
        let track_payload = &payload[offset..end];
        let (cto, body) = if packet_type == 1 {
            if track_payload.len() < 3 {
                return Err(ErtmpWireError::new("multitrack coded frame is missing composition offset"));
            }
            (signed_u24(&track_payload[..3]), &track_payload[3..])
        } else {
            (0, track_payload)
        };
        emit_video_packet(packet_type, body, timestamp, cto, csid, track_id, events, limits)?;
        offset = end;
        if mode == 0 && offset != payload.len() {
            return Err(ErtmpWireError::new("OneTrack video packet contains trailing bytes"));
        }
    }
    Ok(())
}

fn emit_video_packet(
    packet_type: u8,
    body: &[u8],
    timestamp: u32,
    cto: i32,
    csid: u32,
    track_id: u8,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let track = ErtmpTrack { media_type: ErtmpMediaType::Video, track_id };
    match packet_type {
        0 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty video codec configuration"));
            }
            push_event(events, ErtmpEvent::CodecConfig { track, chunk_stream_id: csid, payload: body.to_vec() }, limits)
        }
        1 | 3 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty coded video frame"));
            }
            push_event(events, ErtmpEvent::Frame { track, chunk_stream_id: csid, timestamp, composition_time_offset: cto, coded_data: body.to_vec() }, limits)
        }
        2 => {
            if !body.is_empty() {
                return Err(ErtmpWireError::new("video SequenceEnd carries unexpected data"));
            }
            Ok(())
        }
        VIDEO_METADATA => {
            for (name, value) in parse_amf3_pairs(body)? {
                push_event(events, ErtmpEvent::Metadata { track, chunk_stream_id: csid, timestamp, name, value }, limits)?;
            }
            Ok(())
        }
        other => Err(ErtmpWireError::new(format!("unsupported video packet type {other}"))),
    }
}

fn parse_audio_message(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    if payload.is_empty() {
        return Ok(()); // RTMP silence message
    }
    let first = payload[0];
    let format = first >> 4;
    if format != 9 {
        if format == 10 {
            if payload.len() < 3 {
                return Err(ErtmpWireError::new("truncated legacy AAC packet"));
            }
            return emit_audio_packet(payload[1], &payload[2..], timestamp, csid, 0, events, limits);
        }
        if payload.len() == 1 {
            return Err(ErtmpWireError::new("legacy audio packet has no coded data"));
        }
        return emit_audio_packet(1, &payload[1..], timestamp, csid, 0, events, limits);
    }
    let mut offset = 1;
    let mut packet_type = first & 0x0f;
    while packet_type == 7 {
        let length_byte = *payload.get(offset).ok_or_else(|| ErtmpWireError::new("truncated audio ModEx length"))?;
        offset += 1;
        let length = if length_byte == 0xff {
            if payload.len() - offset < 2 {
                return Err(ErtmpWireError::new("truncated audio ModEx extended length"));
            }
            let value = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize + 1;
            offset += 2;
            value
        } else {
            length_byte as usize + 1
        };
        offset = offset.checked_add(length).filter(|end| *end < payload.len())
            .ok_or_else(|| ErtmpWireError::new("audio ModEx data exceeds its message"))?;
        packet_type = payload[offset] & 0x0f;
        offset += 1;
    }
    if packet_type == AUDIO_MULTITRACK {
        return parse_multitrack_audio(&payload[offset..], timestamp, csid, events, limits);
    }
    if matches!(packet_type, 3 | 6 | 8..=15) {
        return Err(ErtmpWireError::new(format!("unsupported or reserved audio packet type {packet_type}")));
    }
    if payload.len() - offset < 4 {
        return Err(ErtmpWireError::new("enhanced audio packet is missing FOURCC"));
    }
    offset += 4;
    emit_audio_packet(packet_type, &payload[offset..], timestamp, csid, 0, events, limits)
}

fn parse_multitrack_audio(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let header = *payload.first().ok_or_else(|| ErtmpWireError::new("truncated audio Multitrack header"))?;
    let mode = header >> 4;
    let packet_type = header & 0x0f;
    if mode > 2 || packet_type == AUDIO_MULTITRACK || matches!(packet_type, 3 | 6 | 7 | 8..=15) {
        return Err(ErtmpWireError::new("unsupported audio Multitrack mode or inner packet type"));
    }
    let mut offset = 1;
    if mode != 2 {
        if payload.len() - offset < 4 {
            return Err(ErtmpWireError::new("audio Multitrack packet is missing shared FOURCC"));
        }
        offset += 4;
    }
    while offset < payload.len() {
        if mode == 2 {
            if payload.len() - offset < 4 {
                return Err(ErtmpWireError::new("audio Multitrack track is missing FOURCC"));
            }
            offset += 4;
        }
        let track_id = *payload.get(offset).ok_or_else(|| ErtmpWireError::new("audio Multitrack track is missing track id"))?;
        offset += 1;
        let size = if mode == 0 {
            payload.len() - offset
        } else {
            if payload.len() - offset < 3 {
                return Err(ErtmpWireError::new("audio Multitrack track is missing payload size"));
            }
            let value = be_u24(&payload[offset..offset + 3]) as usize;
            offset += 3;
            value
        };
        let end = offset.checked_add(size).filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("audio Multitrack payload exceeds its message"))?;
        emit_audio_packet(packet_type, &payload[offset..end], timestamp, csid, track_id, events, limits)?;
        offset = end;
    }
    Ok(())
}

fn emit_audio_packet(
    packet_type: u8,
    body: &[u8],
    timestamp: u32,
    csid: u32,
    track_id: u8,
    events: &mut Vec<ErtmpEvent>,
    limits: ErtmpWireLimits,
) -> Result<(), ErtmpWireError> {
    let track = ErtmpTrack { media_type: ErtmpMediaType::Audio, track_id };
    match packet_type {
        0 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty audio codec configuration"));
            }
            push_event(events, ErtmpEvent::CodecConfig { track, chunk_stream_id: csid, payload: body.to_vec() }, limits)
        }
        1 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty coded audio frame"));
            }
            push_event(events, ErtmpEvent::Frame { track, chunk_stream_id: csid, timestamp, composition_time_offset: 0, coded_data: body.to_vec() }, limits)
        }
        2 | 4 => Ok(()),
        // There is intentionally no audio Metadata arm. Values 3 and 6 are
        // reserved by Enhanced RTMP v2 and must not be appropriated for C2PA.
        other => Err(ErtmpWireError::new(format!("unsupported audio packet type {other}"))),
    }
}

fn parse_amf3_pairs(mut bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ErtmpWireError> {
    if bytes.is_empty() {
        return Err(ErtmpWireError::new("empty AMF3 metadata body"));
    }
    let mut pairs = Vec::new();
    while !bytes.is_empty() {
        if bytes[0] != 0x06 {
            return Err(ErtmpWireError::new("AMF3 metadata name is not a String"));
        }
        bytes = &bytes[1..];
        let (name_header, consumed) = amf3_u29(bytes)?;
        bytes = &bytes[consumed..];
        if name_header & 1 == 0 {
            return Err(ErtmpWireError::new("AMF3 string references are unsupported in metadata pairs"));
        }
        let name_len = (name_header >> 1) as usize;
        if name_len == 0 || name_len > 128 || bytes.len() < name_len {
            return Err(ErtmpWireError::new("invalid AMF3 metadata name length"));
        }
        let name = std::str::from_utf8(&bytes[..name_len])
            .map_err(|_| ErtmpWireError::new("AMF3 metadata name is not UTF-8"))?
            .to_owned();
        bytes = &bytes[name_len..];
        if bytes.first() != Some(&0x0c) {
            return Err(ErtmpWireError::new("AMF3 metadata value is not a ByteArray"));
        }
        bytes = &bytes[1..];
        let (value_header, consumed) = amf3_u29(bytes)?;
        bytes = &bytes[consumed..];
        if value_header & 1 == 0 {
            return Err(ErtmpWireError::new("AMF3 ByteArray references are unsupported in metadata pairs"));
        }
        let value_len = (value_header >> 1) as usize;
        if bytes.len() < value_len {
            return Err(ErtmpWireError::new("truncated AMF3 metadata ByteArray"));
        }
        pairs.push((name, bytes[..value_len].to_vec()));
        bytes = &bytes[value_len..];
    }
    Ok(pairs)
}

fn amf3_u29(bytes: &[u8]) -> Result<(u32, usize), ErtmpWireError> {
    let mut value = 0u32;
    for index in 0..4 {
        let byte = *bytes.get(index).ok_or_else(|| ErtmpWireError::new("truncated AMF3 U29"))?;
        if index == 3 {
            value = (value << 8) | byte as u32;
            return Ok((value, 4));
        }
        value = (value << 7) | (byte & 0x7f) as u32;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(ErtmpWireError::new("invalid AMF3 U29"))
}

fn validate_fourcc(fourcc: [u8; 4]) -> Result<(), ErtmpWireError> {
    if matches!(&fourcc, b"vp08" | b"vp09" | b"av01" | b"avc1" | b"hvc1" | b"vvc1") {
        Ok(())
    } else {
        Err(ErtmpWireError::new(format!(
            "unsupported enhanced video FOURCC {:?}",
            String::from_utf8_lossy(&fourcc)
        )))
    }
}

fn push_event(events: &mut Vec<ErtmpEvent>, event: ErtmpEvent, limits: ErtmpWireLimits) -> Result<(), ErtmpWireError> {
    if events.len() >= limits.max_events {
        return Err(ErtmpWireError::new("E-RTMP wire event count exceeds its limit"));
    }
    events.push(event);
    Ok(())
}

fn be_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("fixed slice"))
}

fn signed_u24(bytes: &[u8]) -> i32 {
    let raw = be_u24(bytes) as i32;
    if raw & 0x0080_0000 != 0 { raw | !0x00ff_ffff } else { raw }
}

fn put_u24(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&[((value >> 16) & 0xff) as u8, ((value >> 8) & 0xff) as u8, (value & 0xff) as u8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(name: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06, ((name.len() * 2 + 1) as u8)];
        out.extend_from_slice(name.as_bytes());
        out.push(0x0c);
        out.push((value.len() * 2 + 1) as u8);
        out.extend_from_slice(value);
        out
    }

    fn context() -> ErtmpConnectionContext {
        ErtmpConnectionContext { client_caps_ex: 0x10, server_caps_ex: 0x10, object_encoding: 3 }
    }

    #[test]
    fn fragmented_rtmp_video_trace_round_trips_metadata_and_ids() {
        let config = [0x90, b'a', b'v', b'c', b'1', 1, 2, 3];
        let frame = [0x91, b'a', b'v', b'c', b'1', 0, 0, 2, 4, 5, 6];
        let metadata = encode_video_metadata_payload(&pair("c2paManifest", b"store"), *b"avc1").unwrap();
        let mut wire = encode_rtmp_message(319, 7, 9, 10, &config, 3).unwrap();
        wire.extend(encode_rtmp_message(319, 7, 9, 11, &frame, 3).unwrap());
        wire.extend(encode_rtmp_message(319, 7, 9, 11, &metadata, 3).unwrap());
        let input = ertmp_input_from_rtmp_connections(&[&wire], RtmpWireOptions {
            connection: context(), initial_chunk_size: 3, limits: ErtmpWireLimits::default(),
        }).unwrap();
        assert_eq!(input.events.len(), 3);
        match &input.events[1] {
            ErtmpEvent::Frame { chunk_stream_id, timestamp, composition_time_offset, coded_data, .. } => {
                assert_eq!((*chunk_stream_id, *timestamp, *composition_time_offset), (319, 11, 2));
                assert_eq!(coded_data, &[4, 5, 6]);
            }
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn flv_trace_and_reconnect_boundaries_are_strict() {
        let payload = [0x90, b'a', b'v', b'0', b'1', 1, 2, 3, 4];
        let tag = encode_flv_tag(9, 55, &payload).unwrap();
        let mut flv = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
        flv.extend(tag);
        let input = ertmp_input_from_flv(&flv, FlvWireOptions {
            connection: context(), audio_chunk_stream_id: 4, video_chunk_stream_id: 12,
            limits: ErtmpWireLimits::default(),
        }).unwrap();
        match &input.events[0] {
            ErtmpEvent::CodecConfig { track, chunk_stream_id, payload } => {
                assert_eq!(track.track_id, 0);
                assert_eq!(*chunk_stream_id, 12);
                assert_eq!(payload, &[1, 2, 3, 4]);
            }
            _ => panic!("expected codec config"),
        }
    }

    #[test]
    fn malformed_fragment_and_audio_metadata_codepoints_are_refused() {
        let wire = encode_rtmp_message(7, 1, 9, 0, &[0x90, b'a', b'v', b'c', b'1', 1, 2], 2).unwrap();
        let truncated = &wire[..wire.len() - 1];
        assert!(ertmp_input_from_rtmp_connections(&[truncated], RtmpWireOptions {
            connection: context(), initial_chunk_size: 2, limits: ErtmpWireLimits::default(),
        }).is_err());
        for reserved in [3u8, 6u8] {
            let audio = [0x90 | reserved, b'm', b'p', b'4', b'a', 1];
            let wire = encode_rtmp_message(4, 1, 8, 0, &audio, 128).unwrap();
            assert!(ertmp_input_from_rtmp_connections(&[&wire], RtmpWireOptions {
                connection: context(), initial_chunk_size: 128, limits: ErtmpWireLimits::default(),
            }).is_err());
        }
    }

    #[test]
    fn multitrack_video_keeps_each_track_and_shared_chunk_stream() {
        let payload = [0x96, 0x10, b'a', b'v', b'c', b'1', 1, 0, 0, 2, 8, 9, 2, 0, 0, 1, 7];
        let wire = encode_rtmp_message(70, 1, 9, 9, &payload, 128).unwrap();
        let input = ertmp_input_from_rtmp_connections(&[&wire], RtmpWireOptions {
            connection: context(), initial_chunk_size: 128, limits: ErtmpWireLimits::default(),
        }).unwrap();
        assert_eq!(input.events.len(), 2);
        for (event, id) in input.events.iter().zip([1, 2]) {
            match event {
                ErtmpEvent::CodecConfig { track, chunk_stream_id, .. } => {
                    assert_eq!(track.track_id, id);
                    assert_eq!(*chunk_stream_id, 70);
                }
                _ => panic!("expected config"),
            }
        }
    }
}
