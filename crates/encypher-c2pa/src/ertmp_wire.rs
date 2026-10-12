// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Bounded FLV and RTMP framing for the E-RTMP verifier.
//!
//! The packet layouts follow Veovera Enhanced RTMP v2 at revision
//! `dc10175591d24d4dfd4ff1908d6b4d0215a69496`. This module only frames and
//! verifies transport. It does not contain signing keys or sign content.
//! For a type-3 chunk starting a new message after a type-0 header, the
//! preceding absolute timestamp is also the inherited delta, as specified by
//! Adobe RTMP 5.3.1.2.4.

mod amf3;

use std::collections::HashMap;
use std::error::Error as StdError;
use std::fmt;

use crate::{ErtmpEvent, ErtmpInput, ErtmpMediaType, ErtmpTrack};

const SET_CHUNK_SIZE: u8 = 1;
const ABORT_MESSAGE: u8 = 2;
const ACKNOWLEDGEMENT: u8 = 3;
const WINDOW_ACKNOWLEDGEMENT_SIZE: u8 = 5;
const SET_PEER_BANDWIDTH: u8 = 6;
const AUDIO_MESSAGE: u8 = 8;
const VIDEO_MESSAGE: u8 = 9;
const AGGREGATE_MESSAGE: u8 = 22;
const AMF3_SCRIPT_DATA: u8 = 15;
const AMF0_SCRIPT_DATA: u8 = 18;
const VIDEO_METADATA: u8 = 4;
const VIDEO_MULTITRACK: u8 = 6;
const AUDIO_MULTITRACK: u8 = 5;
const PROTOCOL_CONTROL_CHUNK_STREAM_ID: u32 = 2;
const MAX_VERIFIER_EVENTS: usize = 1_000_000;

/// Hard bounds applied before allocating from untrusted wire lengths.
#[derive(Debug, Clone, Copy)]
pub struct ErtmpWireLimits {
    /// Maximum bytes accepted for one connection or FLV file.
    pub max_wire_bytes: usize,
    /// Maximum bytes accepted across all supplied RTMP connections.
    pub max_total_wire_bytes: usize,
    /// Maximum reassembled RTMP message or FLV tag body.
    pub max_message_bytes: usize,
    /// Maximum bytes buffered across incomplete RTMP messages.
    pub max_buffered_message_bytes: usize,
    /// Maximum chunk streams retaining compression or reassembly state.
    pub max_active_chunk_streams: usize,
    /// Maximum emitted verifier events.
    pub max_events: usize,
    /// Maximum aggregate bytes owned by emitted event names, payloads, and
    /// index-aligned wire contexts.
    pub max_total_event_payload_bytes: usize,
    /// Maximum negotiated RTMP chunk size.
    pub max_chunk_size: usize,
}

impl Default for ErtmpWireLimits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 100_000_000,
            max_total_wire_bytes: 100_000_000,
            max_message_bytes: 16 * 1024 * 1024,
            max_buffered_message_bytes: 32 * 1024 * 1024,
            max_active_chunk_streams: 4096,
            max_events: MAX_VERIFIER_EVENTS,
            max_total_event_payload_bytes: 100_000_000,
            max_chunk_size: 1024 * 1024,
        }
    }
}

/// Caller-supplied E-RTMP capability negotiation assertions.
#[derive(Debug, Clone, Copy)]
pub struct ErtmpConnectionContext {
    /// Client `capsEx` value from the connect command.
    pub client_caps_ex: u64,
    /// Server `capsEx` value from the connect response.
    pub server_caps_ex: u64,
    /// Negotiated AMF object encoding.
    pub object_encoding: u8,
}

/// One complete publisher-to-server RTMP connection after its handshake.
#[derive(Debug, Clone, Copy)]
pub struct RtmpWireConnection<'a> {
    /// Complete post-handshake chunk-stream bytes in publisher-to-server wire order.
    pub bytes: &'a [u8],
    /// Negotiation assertions for this connection, not an earlier connection.
    pub connection: ErtmpConnectionContext,
    /// Chunk size in force at the start of this connection trace.
    pub initial_chunk_size: usize,
}

/// Parsed verifier input plus wire identity for every event.
#[derive(Debug, Clone)]
pub struct ErtmpWireInput {
    /// Core events accepted by [`crate::verify_ertmp`].
    pub input: ErtmpInput,
    /// Wire identity aligned one-for-one with `input.events`.
    pub event_contexts: Vec<Option<ErtmpWireEventContext>>,
}

/// Wire identity for one media-derived verifier event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErtmpWireEventContext {
    /// RTMP message stream ID. FLV inputs have no such field and use `None`.
    pub message_stream_id: Option<u32>,
    /// Enhanced RTMP codec FOURCC, including mapped legacy AVC and AAC.
    pub codec_fourcc: Option<[u8; 4]>,
    /// Whether the event came from an Enhanced RTMP Multitrack packet.
    pub multitrack: bool,
}

/// FLV has no chunk-stream identity, so callers must provide the IDs from the
/// RTMP connection that the file/tag trace represents.
#[derive(Debug, Clone, Copy)]
pub struct FlvWireOptions {
    /// Caller-supplied connection capability assertions.
    pub connection: ErtmpConnectionContext,
    /// Chunk stream carrying audio tags.
    pub audio_chunk_stream_id: u32,
    /// Chunk stream carrying video tags.
    pub video_chunk_stream_id: u32,
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
) -> Result<ErtmpWireInput, ErtmpWireError> {
    validate_connection_context(options.connection)?;
    if bytes.len() > options.limits.max_wire_bytes
        || bytes.len() > options.limits.max_total_wire_bytes
    {
        return Err(ErtmpWireError::new("FLV input exceeds the wire byte limit"));
    }
    if bytes.len() < 13 || &bytes[..3] != b"FLV" || bytes[3] != 1 {
        return Err(ErtmpWireError::new("invalid or truncated FLV header"));
    }
    if bytes[4] & 0xfa != 0 {
        return Err(ErtmpWireError::new("FLV header reserved bits are nonzero"));
    }
    let data_offset = be_u32(&bytes[5..9]) as usize;
    if data_offset < 9
        || data_offset
            .checked_add(4)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(ErtmpWireError::new("invalid FLV data offset"));
    }
    if be_u32(&bytes[data_offset..data_offset + 4]) != 0 {
        return Err(ErtmpWireError::new("FLV PreviousTagSize0 is not zero"));
    }

    let mut sink = EventSink::new(options.limits);
    let mut bindings = TrackBindings::default();
    let mut offset = data_offset + 4;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 15 {
            return Err(ErtmpWireError::new("truncated FLV tag"));
        }
        let tag_byte = bytes[offset];
        if tag_byte & 0xe0 != 0 {
            return Err(ErtmpWireError::new(
                "reserved, encrypted, or filtered FLV tags are unsupported",
            ));
        }
        let tag_type = tag_byte & 0x1f;
        let data_size = be_u24(&bytes[offset + 1..offset + 4]) as usize;
        if data_size > options.limits.max_message_bytes {
            return Err(ErtmpWireError::new(
                "FLV tag exceeds the message byte limit",
            ));
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
            return Err(ErtmpWireError::new(
                "FLV PreviousTagSize does not match its tag",
            ));
        }
        match tag_type {
            AUDIO_MESSAGE => {
                if bytes[4] & 0x04 == 0 {
                    return Err(ErtmpWireError::new(
                        "FLV audio tag contradicts the header flags",
                    ));
                }
                parse_audio_message(
                    body,
                    timestamp,
                    options.audio_chunk_stream_id,
                    None,
                    &mut bindings,
                    &mut sink,
                )?;
            }
            VIDEO_MESSAGE => {
                if bytes[4] & 0x01 == 0 {
                    return Err(ErtmpWireError::new(
                        "FLV video tag contradicts the header flags",
                    ));
                }
                parse_video_message(
                    body,
                    timestamp,
                    options.video_chunk_stream_id,
                    None,
                    &mut bindings,
                    &mut sink,
                )?;
            }
            AMF3_SCRIPT_DATA | AMF0_SCRIPT_DATA => {}
            other => {
                return Err(ErtmpWireError::new(format!(
                    "unsupported FLV tag type {other}"
                )))
            }
        }
        offset = tag_end;
    }
    Ok(wire_input(options.connection, sink))
}

/// Parse complete post-handshake publisher-to-server RTMP connection traces. Each
/// trace carries its own caller-supplied negotiation assertions and initial chunk
/// size. A reconnect event is inserted between traces; chunk, message, and
/// track-to-message-stream state resets at that point.
pub fn ertmp_input_from_rtmp_connections(
    connections: &[RtmpWireConnection<'_>],
    limits: ErtmpWireLimits,
) -> Result<ErtmpWireInput, ErtmpWireError> {
    let Some(first) = connections.first() else {
        return Err(ErtmpWireError::new(
            "at least one RTMP connection is required",
        ));
    };

    let mut total_wire_bytes = 0usize;
    for trace in connections {
        validate_connection_context(trace.connection)?;
        if trace.initial_chunk_size == 0 || trace.initial_chunk_size > limits.max_chunk_size {
            return Err(ErtmpWireError::new(
                "initial RTMP chunk size is out of bounds",
            ));
        }
        if trace.bytes.len() > limits.max_wire_bytes {
            return Err(ErtmpWireError::new(
                "RTMP connection exceeds the wire byte limit",
            ));
        }
        total_wire_bytes = total_wire_bytes
            .checked_add(trace.bytes.len())
            .ok_or_else(|| ErtmpWireError::new("total RTMP wire byte count overflow"))?;
        if total_wire_bytes > limits.max_total_wire_bytes {
            return Err(ErtmpWireError::new(
                "RTMP connections exceed the total wire byte limit",
            ));
        }
    }

    let mut sink = EventSink::new(limits);
    for (index, trace) in connections.iter().enumerate() {
        if index != 0 {
            sink.push_reconnect()?;
        }
        RtmpDecoder::new(trace.initial_chunk_size, limits).decode(trace.bytes, &mut sink)?;
    }
    Ok(wire_input(first.connection, sink))
}

fn validate_connection_context(context: ErtmpConnectionContext) -> Result<(), ErtmpWireError> {
    if context.client_caps_ex & 0x10 == 0
        || context.server_caps_ex & 0x10 == 0
        || context.object_encoding != 3
    {
        return Err(ErtmpWireError::new(
            "connection did not negotiate C2PA with AMF3 on both endpoints",
        ));
    }
    Ok(())
}

fn wire_input(connection: ErtmpConnectionContext, sink: EventSink) -> ErtmpWireInput {
    ErtmpWireInput {
        input: ErtmpInput {
            client_caps_ex: connection.client_caps_ex,
            server_caps_ex: connection.server_caps_ex,
            object_encoding: connection.object_encoding,
            events: sink.events,
        },
        event_contexts: sink.event_contexts,
    }
}

struct EventSink {
    events: Vec<ErtmpEvent>,
    event_contexts: Vec<Option<ErtmpWireEventContext>>,
    payload_bytes: usize,
    limits: ErtmpWireLimits,
}

impl EventSink {
    fn new(limits: ErtmpWireLimits) -> Self {
        Self {
            events: Vec::new(),
            event_contexts: Vec::new(),
            payload_bytes: 0,
            limits,
        }
    }

    fn remaining_events(&self) -> usize {
        self.limits
            .max_events
            .min(MAX_VERIFIER_EVENTS)
            .saturating_sub(self.events.len())
    }

    fn remaining_payload_bytes(&self) -> usize {
        self.limits
            .max_total_event_payload_bytes
            .saturating_sub(self.payload_bytes)
    }

    fn claim(&mut self, bytes: usize) -> Result<(), ErtmpWireError> {
        if self.remaining_events() == 0 {
            return Err(ErtmpWireError::new(
                "E-RTMP wire event count exceeds its limit",
            ));
        }
        let bytes = bytes
            .checked_add(std::mem::size_of::<Option<ErtmpWireEventContext>>())
            .ok_or_else(|| ErtmpWireError::new("event ownership byte count overflow"))?;
        let next = self
            .payload_bytes
            .checked_add(bytes)
            .ok_or_else(|| ErtmpWireError::new("event payload byte count overflow"))?;
        if next > self.limits.max_total_event_payload_bytes {
            return Err(ErtmpWireError::new(
                "E-RTMP event payload bytes exceed their limit",
            ));
        }
        self.events
            .try_reserve(1)
            .map_err(|_| ErtmpWireError::new("unable to allocate E-RTMP event"))?;
        self.event_contexts
            .try_reserve(1)
            .map_err(|_| ErtmpWireError::new("unable to allocate E-RTMP event context"))?;
        self.payload_bytes = next;
        Ok(())
    }

    fn push_reconnect(&mut self) -> Result<(), ErtmpWireError> {
        self.claim(0)?;
        self.events.push(ErtmpEvent::Reconnect);
        self.event_contexts.push(None);
        Ok(())
    }

    fn push_codec_config(
        &mut self,
        track: ErtmpTrack,
        chunk_stream_id: u32,
        payload: &[u8],
        context: ErtmpWireEventContext,
    ) -> Result<(), ErtmpWireError> {
        self.claim(payload.len())?;
        let payload = owned_bytes(payload)?;
        self.events.push(ErtmpEvent::CodecConfig {
            track,
            chunk_stream_id,
            payload,
        });
        self.event_contexts.push(Some(context));
        Ok(())
    }

    fn push_frame(
        &mut self,
        track: ErtmpTrack,
        chunk_stream_id: u32,
        timestamp: u32,
        composition_time_offset: i32,
        coded_data: &[u8],
        context: ErtmpWireEventContext,
    ) -> Result<(), ErtmpWireError> {
        self.claim(coded_data.len())?;
        let coded_data = owned_bytes(coded_data)?;
        self.events.push(ErtmpEvent::Frame {
            track,
            chunk_stream_id,
            timestamp,
            composition_time_offset,
            coded_data,
        });
        self.event_contexts.push(Some(context));
        Ok(())
    }

    fn push_metadata(
        &mut self,
        track: ErtmpTrack,
        chunk_stream_id: u32,
        timestamp: u32,
        name: &str,
        value: &[u8],
        context: ErtmpWireEventContext,
    ) -> Result<(), ErtmpWireError> {
        let owned_size = name
            .len()
            .checked_add(value.len())
            .ok_or_else(|| ErtmpWireError::new("metadata event byte count overflow"))?;
        self.claim(owned_size)?;
        let value = owned_bytes(value)?;
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.len())
            .map_err(|_| ErtmpWireError::new("unable to allocate E-RTMP metadata name"))?;
        owned_name.push_str(name);
        self.events.push(ErtmpEvent::Metadata {
            track,
            chunk_stream_id,
            timestamp,
            name: owned_name,
            value,
        });
        self.event_contexts.push(Some(context));
        Ok(())
    }
}

fn owned_bytes(bytes: &[u8]) -> Result<Vec<u8>, ErtmpWireError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ErtmpWireError::new("unable to allocate E-RTMP event payload"))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
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

struct MessageAssembly {
    header: ChunkHeader,
    payload: Vec<u8>,
    received: usize,
    retain_payload: bool,
}

struct ChunkState {
    last_header: ChunkHeader,
    assembly: Option<MessageAssembly>,
}

struct TrackBindings {
    video_message_streams: [Option<u32>; 256],
    audio_message_streams: [Option<u32>; 256],
}

impl Default for TrackBindings {
    fn default() -> Self {
        Self {
            video_message_streams: [None; 256],
            audio_message_streams: [None; 256],
        }
    }
}

impl TrackBindings {
    fn associate(
        &mut self,
        track: ErtmpTrack,
        message_stream_id: Option<u32>,
    ) -> Result<(), ErtmpWireError> {
        let Some(message_stream_id) = message_stream_id else {
            return Ok(());
        };
        if message_stream_id == 0 {
            return Err(ErtmpWireError::new(
                "RTMP media message uses control message stream zero",
            ));
        }
        let (media_type, slots) = match track.media_type {
            ErtmpMediaType::Video => ("video", &mut self.video_message_streams),
            ErtmpMediaType::Audio => ("audio", &mut self.audio_message_streams),
        };
        let slot = &mut slots[track.track_id as usize];
        match *slot {
            Some(existing) if existing != message_stream_id => Err(ErtmpWireError::new(format!(
                "{media_type} track {} is used by conflicting RTMP message streams",
                track.track_id
            ))),
            Some(_) => Ok(()),
            None => {
                *slot = Some(message_stream_id);
                Ok(())
            }
        }
    }
}

struct RtmpDecoder {
    chunk_size: usize,
    states: HashMap<u32, ChunkState>,
    buffered_bytes: usize,
    bindings: TrackBindings,
    limits: ErtmpWireLimits,
}

impl RtmpDecoder {
    fn new(chunk_size: usize, limits: ErtmpWireLimits) -> Self {
        Self {
            chunk_size,
            states: HashMap::new(),
            buffered_bytes: 0,
            bindings: TrackBindings::default(),
            limits,
        }
    }

    fn decode(mut self, bytes: &[u8], sink: &mut EventSink) -> Result<(), ErtmpWireError> {
        let mut offset = 0;
        while offset < bytes.len() {
            let (fmt, csid, basic_len) = parse_basic_header(&bytes[offset..])?;
            offset += basic_len;
            let previous = self
                .states
                .get(&csid)
                .map(|state| state.last_header.clone());
            let continuing = self
                .states
                .get(&csid)
                .is_some_and(|state| state.assembly.is_some());
            let (mut header, header_len) =
                parse_message_header(fmt, previous.as_ref(), &bytes[offset..], continuing)?;
            offset += header_len;

            if header.extended {
                if bytes.len() - offset < 4 {
                    return Err(ErtmpWireError::new("truncated RTMP extended timestamp"));
                }
                let extended = be_u32(&bytes[offset..offset + 4]);
                offset += 4;
                match fmt {
                    0 => {
                        header.timestamp = extended;
                        header.timestamp_delta = extended;
                    }
                    1 | 2 => {
                        header.timestamp_delta = extended;
                        header.timestamp = previous
                            .as_ref()
                            .map_or(extended, |prior| prior.timestamp.wrapping_add(extended));
                    }
                    3 => {
                        let expected = if continuing && header.absolute {
                            header.timestamp
                        } else {
                            header.timestamp_delta
                        };
                        if extended != expected {
                            return Err(ErtmpWireError::new(
                                "RTMP type-3 extended timestamp changed unexpectedly",
                            ));
                        }
                    }
                    _ => unreachable!("RTMP basic header format is two bits"),
                }
            }
            if continuing {
                let active = self
                    .states
                    .get(&csid)
                    .and_then(|state| state.assembly.as_ref())
                    .ok_or_else(|| ErtmpWireError::new("missing RTMP message assembly"))?;
                if header.timestamp != active.header.timestamp
                    || header.message_length != active.header.message_length
                    || header.message_type != active.header.message_type
                    || header.message_stream_id != active.header.message_stream_id
                {
                    return Err(ErtmpWireError::new(
                        "RTMP message was replaced before all chunks arrived",
                    ));
                }
                self.states
                    .get_mut(&csid)
                    .ok_or_else(|| ErtmpWireError::new("missing RTMP chunk state"))?
                    .last_header = header.clone();
            }
            if header.message_length > self.limits.max_message_bytes {
                return Err(ErtmpWireError::new(
                    "RTMP message exceeds the message byte limit",
                ));
            }
            if !matches!(
                header.message_type,
                SET_CHUNK_SIZE
                    | ABORT_MESSAGE
                    | ACKNOWLEDGEMENT
                    | 4
                    | WINDOW_ACKNOWLEDGEMENT_SIZE
                    | SET_PEER_BANDWIDTH
                    | AUDIO_MESSAGE
                    | VIDEO_MESSAGE
                    | 15..=20 | AGGREGATE_MESSAGE
            ) {
                return Err(ErtmpWireError::new(format!(
                    "undefined RTMP message type {}",
                    header.message_type
                )));
            }
            if !self.states.contains_key(&csid) {
                if self.states.len() >= self.limits.max_active_chunk_streams {
                    return Err(ErtmpWireError::new(
                        "RTMP active chunk stream count exceeds its limit",
                    ));
                }
                self.states
                    .try_reserve(1)
                    .map_err(|_| ErtmpWireError::new("unable to allocate RTMP chunk state"))?;
            }

            if !continuing {
                let retain_payload = matches!(
                    header.message_type,
                    SET_CHUNK_SIZE
                        | ABORT_MESSAGE
                        | ACKNOWLEDGEMENT
                        | WINDOW_ACKNOWLEDGEMENT_SIZE
                        | SET_PEER_BANDWIDTH
                        | AUDIO_MESSAGE
                        | VIDEO_MESSAGE
                        | AGGREGATE_MESSAGE
                );
                let assembly = MessageAssembly {
                    header: header.clone(),
                    payload: Vec::new(),
                    received: 0,
                    retain_payload,
                };
                self.states.insert(
                    csid,
                    ChunkState {
                        last_header: header,
                        assembly: Some(assembly),
                    },
                );
            }

            let completed = {
                let state = self
                    .states
                    .get_mut(&csid)
                    .ok_or_else(|| ErtmpWireError::new("missing RTMP chunk state"))?;
                let assembly = state
                    .assembly
                    .as_mut()
                    .ok_or_else(|| ErtmpWireError::new("missing RTMP message assembly"))?;
                let remaining = assembly.header.message_length - assembly.received;
                let take = remaining.min(self.chunk_size);
                if bytes.len() - offset < take {
                    return Err(ErtmpWireError::new("truncated RTMP chunk payload"));
                }
                if assembly.retain_payload {
                    let required = assembly
                        .payload
                        .len()
                        .checked_add(take)
                        .ok_or_else(|| ErtmpWireError::new("RTMP payload length overflow"))?;
                    if required > assembly.payload.capacity() {
                        let old_capacity = assembly.payload.capacity();
                        let doubled = old_capacity.saturating_mul(2).max(take);
                        let target_capacity =
                            required.max(doubled).min(assembly.header.message_length);
                        let requested_growth = target_capacity - old_capacity;
                        let next_buffered = self
                            .buffered_bytes
                            .checked_add(requested_growth)
                            .ok_or_else(|| {
                                ErtmpWireError::new("RTMP buffered byte count overflow")
                            })?;
                        if next_buffered > self.limits.max_buffered_message_bytes {
                            return Err(ErtmpWireError::new(
                                "incomplete RTMP messages exceed the buffered byte limit",
                            ));
                        }
                        assembly
                            .payload
                            .try_reserve_exact(target_capacity - assembly.payload.len())
                            .map_err(|_| {
                                ErtmpWireError::new("unable to allocate RTMP chunk payload")
                            })?;
                        let actual_growth = assembly.payload.capacity() - old_capacity;
                        self.buffered_bytes = self
                            .buffered_bytes
                            .checked_add(actual_growth)
                            .ok_or_else(|| {
                                ErtmpWireError::new("RTMP buffered byte count overflow")
                            })?;
                        if self.buffered_bytes > self.limits.max_buffered_message_bytes {
                            return Err(ErtmpWireError::new(
                                "RTMP allocation exceeds the buffered byte limit",
                            ));
                        }
                    }
                    assembly
                        .payload
                        .extend_from_slice(&bytes[offset..offset + take]);
                }
                assembly.received += take;
                offset += take;
                if assembly.received == assembly.header.message_length {
                    let completed = state
                        .assembly
                        .take()
                        .ok_or_else(|| ErtmpWireError::new("missing completed RTMP message"))?;
                    self.buffered_bytes = self
                        .buffered_bytes
                        .checked_sub(completed.payload.capacity())
                        .ok_or_else(|| ErtmpWireError::new("RTMP buffered byte count underflow"))?;
                    Some(completed)
                } else {
                    None
                }
            };

            if let Some(completed) = completed {
                if completed.retain_payload {
                    self.message(csid, &completed.header, &completed.payload, sink)?;
                }
            }
        }
        if self.states.values().any(|state| state.assembly.is_some()) {
            return Err(ErtmpWireError::new(
                "RTMP connection ended during a fragmented message",
            ));
        }
        Ok(())
    }

    fn message(
        &mut self,
        csid: u32,
        header: &ChunkHeader,
        payload: &[u8],
        sink: &mut EventSink,
    ) -> Result<(), ErtmpWireError> {
        if matches!(
            header.message_type,
            SET_CHUNK_SIZE
                | ABORT_MESSAGE
                | ACKNOWLEDGEMENT
                | WINDOW_ACKNOWLEDGEMENT_SIZE
                | SET_PEER_BANDWIDTH
        ) && (csid != PROTOCOL_CONTROL_CHUNK_STREAM_ID || header.message_stream_id != 0)
        {
            return Err(ErtmpWireError::new(
                "RTMP protocol control message is not on CSID 2 and message stream 0",
            ));
        }
        if matches!(
            header.message_type,
            AUDIO_MESSAGE | VIDEO_MESSAGE | AGGREGATE_MESSAGE
        ) && (csid == PROTOCOL_CONTROL_CHUNK_STREAM_ID || header.message_stream_id == 0)
        {
            return Err(ErtmpWireError::new(
                "RTMP media message uses a reserved control stream",
            ));
        }

        match header.message_type {
            SET_CHUNK_SIZE => {
                if payload.len() != 4 || payload[0] & 0x80 != 0 {
                    return Err(ErtmpWireError::new("invalid RTMP Set Chunk Size message"));
                }
                let size = be_u32(payload) as usize;
                if size == 0 || size > self.limits.max_chunk_size {
                    return Err(ErtmpWireError::new(
                        "negotiated RTMP chunk size is out of bounds",
                    ));
                }
                self.chunk_size = size;
            }
            ABORT_MESSAGE => {
                if payload.len() != 4 {
                    return Err(ErtmpWireError::new("invalid RTMP Abort message"));
                }
                let target = be_u32(payload);
                if !(2..=65_599).contains(&target) {
                    return Err(ErtmpWireError::new(
                        "RTMP Abort names an invalid chunk stream id",
                    ));
                }
                if let Some(state) = self.states.get_mut(&target) {
                    if let Some(assembly) = state.assembly.take() {
                        self.buffered_bytes = self
                            .buffered_bytes
                            .checked_sub(assembly.payload.capacity())
                            .ok_or_else(|| {
                                ErtmpWireError::new("RTMP buffered byte count underflow")
                            })?;
                    }
                }
            }
            ACKNOWLEDGEMENT | WINDOW_ACKNOWLEDGEMENT_SIZE => {
                if payload.len() != 4 {
                    return Err(ErtmpWireError::new(
                        "invalid RTMP four-byte protocol control message",
                    ));
                }
            }
            SET_PEER_BANDWIDTH => {
                if payload.len() != 5 || payload[4] > 2 {
                    return Err(ErtmpWireError::new(
                        "invalid RTMP Set Peer Bandwidth message",
                    ));
                }
            }
            AUDIO_MESSAGE => parse_audio_message(
                payload,
                header.timestamp,
                csid,
                Some(header.message_stream_id),
                &mut self.bindings,
                sink,
            )?,
            VIDEO_MESSAGE => parse_video_message(
                payload,
                header.timestamp,
                csid,
                Some(header.message_stream_id),
                &mut self.bindings,
                sink,
            )?,
            AGGREGATE_MESSAGE => parse_aggregate(
                payload,
                header.timestamp,
                csid,
                header.message_stream_id,
                &mut self.bindings,
                sink,
            )?,
            _ => {}
        }
        Ok(())
    }
}

fn parse_basic_header(bytes: &[u8]) -> Result<(u8, u32, usize), ErtmpWireError> {
    let first = *bytes
        .first()
        .ok_or_else(|| ErtmpWireError::new("truncated RTMP basic header"))?;
    let fmt = first >> 6;
    match first & 0x3f {
        0 => {
            let low = *bytes
                .get(1)
                .ok_or_else(|| ErtmpWireError::new("truncated RTMP two-byte basic header"))?;
            Ok((fmt, 64 + low as u32, 2))
        }
        1 => {
            let low = *bytes
                .get(1)
                .ok_or_else(|| ErtmpWireError::new("truncated RTMP three-byte basic header"))?;
            let high = *bytes
                .get(2)
                .ok_or_else(|| ErtmpWireError::new("truncated RTMP three-byte basic header"))?;
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
    let prior = || {
        previous
            .cloned()
            .ok_or_else(|| ErtmpWireError::new("compressed RTMP header has no predecessor"))
    };
    match fmt {
        0 => {
            let raw = be_u24(&bytes[..3]);
            Ok((
                ChunkHeader {
                    timestamp: raw,
                    timestamp_delta: raw,
                    message_length: be_u24(&bytes[3..6]) as usize,
                    message_type: bytes[6],
                    message_stream_id: u32::from_le_bytes(
                        bytes[7..11].try_into().expect("fixed slice"),
                    ),
                    extended: raw == 0x00ff_ffff,
                    absolute: true,
                },
                11,
            ))
        }
        1 => {
            let prior = prior()?;
            let delta = be_u24(&bytes[..3]);
            Ok((
                ChunkHeader {
                    timestamp: prior.timestamp.wrapping_add(delta),
                    timestamp_delta: delta,
                    message_length: be_u24(&bytes[3..6]) as usize,
                    message_type: bytes[6],
                    message_stream_id: prior.message_stream_id,
                    extended: delta == 0x00ff_ffff,
                    absolute: false,
                },
                7,
            ))
        }
        2 => {
            let prior = prior()?;
            let delta = be_u24(&bytes[..3]);
            Ok((
                ChunkHeader {
                    timestamp: prior.timestamp.wrapping_add(delta),
                    timestamp_delta: delta,
                    extended: delta == 0x00ff_ffff,
                    absolute: false,
                    ..prior
                },
                3,
            ))
        }
        3 => {
            let mut prior = prior()?;
            if !continuing {
                prior.timestamp = prior.timestamp.wrapping_add(prior.timestamp_delta);
                prior.absolute = false;
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
    message_stream_id: u32,
    bindings: &mut TrackBindings,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let mut offset = 0;
    let mut first_timestamp = None;
    while offset < payload.len() {
        if payload.len() - offset < 15 {
            return Err(ErtmpWireError::new("truncated RTMP Aggregate tag"));
        }
        let tag_type = payload[offset];
        let size = be_u24(&payload[offset + 1..offset + 4]) as usize;
        if size > sink.limits.max_message_bytes {
            return Err(ErtmpWireError::new(
                "RTMP Aggregate tag exceeds the message limit",
            ));
        }
        let end = offset
            .checked_add(11)
            .and_then(|value| value.checked_add(size))
            .and_then(|value| value.checked_add(4))
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("truncated RTMP Aggregate body"))?;
        if be_u32(&payload[offset + 11 + size..end]) as usize != 11 + size {
            return Err(ErtmpWireError::new("malformed RTMP Aggregate tag"));
        }
        let timestamp =
            be_u24(&payload[offset + 4..offset + 7]) | ((payload[offset + 7] as u32) << 24);
        let base = *first_timestamp.get_or_insert(timestamp);
        let normalized = outer_timestamp.wrapping_add(timestamp.wrapping_sub(base));
        let body = &payload[offset + 11..offset + 11 + size];
        match tag_type {
            AUDIO_MESSAGE => parse_audio_message(
                body,
                normalized,
                csid,
                Some(message_stream_id),
                bindings,
                sink,
            )?,
            VIDEO_MESSAGE => parse_video_message(
                body,
                normalized,
                csid,
                Some(message_stream_id),
                bindings,
                sink,
            )?,
            AMF3_SCRIPT_DATA | AMF0_SCRIPT_DATA => {}
            other => {
                return Err(ErtmpWireError::new(format!(
                    "unsupported Aggregate tag type {other}"
                )))
            }
        }
        offset = end;
    }
    Ok(())
}

fn parse_video_message(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    message_stream_id: Option<u32>,
    bindings: &mut TrackBindings,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let first = *payload
        .first()
        .ok_or_else(|| ErtmpWireError::new("empty RTMP video message"))?;
    let frame_type = (first >> 4) & 0x07;
    if first & 0x80 == 0 {
        if frame_type == 5 {
            return parse_video_command(&payload[1..]);
        }
        if !(1..=2).contains(&frame_type) {
            return Err(ErtmpWireError::new("invalid legacy video frame type"));
        }
        let codec = first & 0x0f;
        if codec != 7 {
            return Err(ErtmpWireError::new(format!(
                "unsupported legacy video codec id {codec}"
            )));
        }
        if payload.len() < 5 {
            return Err(ErtmpWireError::new("truncated legacy AVC packet"));
        }
        let packet_type = payload[1];
        if packet_type > 2 {
            return Err(ErtmpWireError::new(format!(
                "invalid legacy AVC packet type {packet_type}"
            )));
        }
        let track = video_track(0);
        bindings.associate(track, message_stream_id)?;
        return emit_video_packet(
            packet_type,
            VideoCodec::Avc,
            &payload[5..],
            timestamp,
            signed_u24(&payload[2..5]),
            csid,
            track,
            message_stream_id,
            false,
            sink,
        );
    }

    let mut offset = 1;
    let mut packet_type = first & 0x0f;
    while packet_type == 7 {
        let length_byte = *payload
            .get(offset)
            .ok_or_else(|| ErtmpWireError::new("truncated video ModEx length"))?;
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
        let mod_ex_end = offset
            .checked_add(length)
            .filter(|end| *end < payload.len())
            .ok_or_else(|| ErtmpWireError::new("video ModEx data exceeds its message"))?;
        if length < 3
            || be_u24(&payload[offset..offset + 3]) >= 1_000_000
            || payload[mod_ex_end] >> 4 != 0
        {
            return Err(ErtmpWireError::new(
                "invalid video TimestampOffsetNano ModEx",
            ));
        }
        packet_type = payload[mod_ex_end] & 0x0f;
        offset = mod_ex_end + 1;
    }

    if packet_type == VIDEO_MULTITRACK {
        return parse_multitrack_video(
            &payload[offset..],
            frame_type,
            timestamp,
            csid,
            message_stream_id,
            bindings,
            sink,
        );
    }
    if packet_type != VIDEO_METADATA {
        if frame_type == 5 {
            return parse_video_command(&payload[offset..]);
        }
        if !(1..=2).contains(&frame_type) {
            return Err(ErtmpWireError::new("invalid enhanced video frame type"));
        }
    }
    if matches!(packet_type, 7..=15) {
        return Err(ErtmpWireError::new(format!(
            "unsupported enhanced video packet type {packet_type}"
        )));
    }
    if payload.len() - offset < 4 {
        return Err(ErtmpWireError::new(
            "enhanced video packet is missing FOURCC",
        ));
    }
    let codec = video_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
    offset += 4;
    let (cto, body) = split_video_body(packet_type, codec, &payload[offset..])?;
    let track = video_track(0);
    bindings.associate(track, message_stream_id)?;
    emit_video_packet(
        packet_type,
        codec,
        body,
        timestamp,
        cto,
        csid,
        track,
        message_stream_id,
        false,
        sink,
    )
}

fn parse_video_command(bytes: &[u8]) -> Result<(), ErtmpWireError> {
    if bytes.len() != 1 || bytes[0] > 1 {
        return Err(ErtmpWireError::new("invalid video command frame"));
    }
    Ok(())
}

fn parse_multitrack_video(
    payload: &[u8],
    frame_type: u8,
    timestamp: u32,
    csid: u32,
    message_stream_id: Option<u32>,
    bindings: &mut TrackBindings,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let header = *payload
        .first()
        .ok_or_else(|| ErtmpWireError::new("truncated video Multitrack header"))?;
    let mode = header >> 4;
    let packet_type = header & 0x0f;
    if mode > 2 || packet_type == VIDEO_MULTITRACK || matches!(packet_type, 7..=15) {
        return Err(ErtmpWireError::new(
            "unsupported video Multitrack mode or inner packet type",
        ));
    }
    if packet_type != VIDEO_METADATA && !(1..=2).contains(&frame_type) {
        return Err(ErtmpWireError::new("invalid enhanced video frame type"));
    }
    let mut offset = 1;
    let shared_codec = if mode != 2 {
        if payload.len() - offset < 4 {
            return Err(ErtmpWireError::new(
                "video Multitrack packet is missing shared FOURCC",
            ));
        }
        let codec = video_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
        offset += 4;
        Some(codec)
    } else {
        None
    };
    let mut seen = [false; 256];
    while offset < payload.len() {
        let codec = if mode == 2 {
            if payload.len() - offset < 4 {
                return Err(ErtmpWireError::new(
                    "video Multitrack track is missing FOURCC",
                ));
            }
            let codec = video_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
            offset += 4;
            codec
        } else {
            shared_codec.ok_or_else(|| ErtmpWireError::new("missing shared video FOURCC"))?
        };
        let track_id = *payload
            .get(offset)
            .ok_or_else(|| ErtmpWireError::new("video Multitrack track is missing track id"))?;
        offset += 1;
        if seen[track_id as usize] {
            return Err(ErtmpWireError::new(
                "video Multitrack message repeats a track id",
            ));
        }
        seen[track_id as usize] = true;
        let size = if mode == 0 {
            payload.len() - offset
        } else {
            if payload.len() - offset < 3 {
                return Err(ErtmpWireError::new(
                    "video Multitrack track is missing payload size",
                ));
            }
            let value = be_u24(&payload[offset..offset + 3]) as usize;
            offset += 3;
            value
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("video Multitrack payload exceeds its message"))?;
        let (cto, body) = split_video_body(packet_type, codec, &payload[offset..end])?;
        let track = video_track(track_id);
        bindings.associate(track, message_stream_id)?;
        emit_video_packet(
            packet_type,
            codec,
            body,
            timestamp,
            cto,
            csid,
            track,
            message_stream_id,
            true,
            sink,
        )?;
        offset = end;
    }
    if !seen.into_iter().any(|value| value) {
        return Err(ErtmpWireError::new(
            "video Multitrack message has no tracks",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VideoCodec {
    Vp8,
    Vp9,
    Av1,
    Avc,
    Hevc,
    Vvc,
}

impl VideoCodec {
    fn fourcc(self) -> [u8; 4] {
        match self {
            Self::Vp8 => *b"vp08",
            Self::Vp9 => *b"vp09",
            Self::Av1 => *b"av01",
            Self::Avc => *b"avc1",
            Self::Hevc => *b"hvc1",
            Self::Vvc => *b"vvc1",
        }
    }
}

fn video_codec(fourcc: [u8; 4]) -> Result<VideoCodec, ErtmpWireError> {
    match &fourcc {
        b"vp08" => Ok(VideoCodec::Vp8),
        b"vp09" => Ok(VideoCodec::Vp9),
        b"av01" => Ok(VideoCodec::Av1),
        b"avc1" => Ok(VideoCodec::Avc),
        b"hvc1" => Ok(VideoCodec::Hevc),
        b"vvc1" => Ok(VideoCodec::Vvc),
        _ => Err(ErtmpWireError::new(format!(
            "unsupported enhanced video FOURCC {:?}",
            String::from_utf8_lossy(&fourcc)
        ))),
    }
}

fn split_video_body(
    packet_type: u8,
    codec: VideoCodec,
    bytes: &[u8],
) -> Result<(i32, &[u8]), ErtmpWireError> {
    if packet_type == 1 && matches!(codec, VideoCodec::Avc | VideoCodec::Hevc | VideoCodec::Vvc) {
        if bytes.len() < 3 {
            return Err(ErtmpWireError::new(
                "coded video packet is missing composition offset",
            ));
        }
        Ok((signed_u24(&bytes[..3]), &bytes[3..]))
    } else {
        Ok((0, bytes))
    }
}

#[allow(clippy::too_many_arguments)] // Wire header fields remain explicit at the decoding boundary.
fn emit_video_packet(
    packet_type: u8,
    codec: VideoCodec,
    body: &[u8],
    timestamp: u32,
    cto: i32,
    csid: u32,
    track: ErtmpTrack,
    message_stream_id: Option<u32>,
    multitrack: bool,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let context = ErtmpWireEventContext {
        message_stream_id,
        codec_fourcc: Some(codec.fourcc()),
        multitrack,
    };
    match packet_type {
        0 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty video codec configuration"));
            }
            sink.push_codec_config(track, csid, body, context)
        }
        1 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty coded video frame"));
            }
            sink.push_frame(track, csid, timestamp, cto, body, context)
        }
        2 => {
            if !body.is_empty() {
                return Err(ErtmpWireError::new(
                    "video SequenceEnd carries unexpected data",
                ));
            }
            Ok(())
        }
        3 => {
            if !matches!(codec, VideoCodec::Avc | VideoCodec::Hevc | VideoCodec::Vvc) {
                return Err(ErtmpWireError::new(
                    "CodedFramesX is invalid for this video codec",
                ));
            }
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty coded video frame"));
            }
            sink.push_frame(track, csid, timestamp, 0, body, context)
        }
        VIDEO_METADATA => {
            let remaining_events = sink.remaining_events();
            let remaining_value_bytes = sink.remaining_payload_bytes();
            amf3::for_each_metadata_pair(
                body,
                remaining_events,
                remaining_value_bytes,
                |name, value| sink.push_metadata(track, csid, timestamp, name, value, context),
            )
        }
        5 => {
            if codec != VideoCodec::Av1 || body.is_empty() {
                return Err(ErtmpWireError::new(
                    "MPEG2TSSequenceStart requires a nonempty AV1 descriptor",
                ));
            }
            sink.push_codec_config(track, csid, body, context)
        }
        other => Err(ErtmpWireError::new(format!(
            "unsupported video packet type {other}"
        ))),
    }
}

fn parse_audio_message(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    message_stream_id: Option<u32>,
    bindings: &mut TrackBindings,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    if payload.is_empty() {
        return Ok(()); // RTMP silence message
    }
    let first = payload[0];
    let format = first >> 4;
    if format != 9 {
        let track = audio_track(0);
        bindings.associate(track, message_stream_id)?;
        if format == 10 {
            if payload.len() < 2 {
                return Err(ErtmpWireError::new("truncated legacy AAC packet"));
            }
            let packet_type = payload[1];
            if packet_type > 1 {
                return Err(ErtmpWireError::new(format!(
                    "invalid legacy AAC packet type {packet_type}"
                )));
            }
            return emit_audio_packet(
                packet_type,
                AudioCodec::Aac,
                &payload[2..],
                timestamp,
                csid,
                track,
                message_stream_id,
                false,
                sink,
            );
        }
        if matches!(format, 7 | 8 | 9 | 12 | 13 | 14 | 15) {
            return Err(ErtmpWireError::new(format!(
                "unsupported legacy audio format {format}"
            )));
        }
        if payload.len() == 1 {
            return Err(ErtmpWireError::new("legacy audio packet has no coded data"));
        }
        return sink.push_frame(
            track,
            csid,
            timestamp,
            0,
            &payload[1..],
            ErtmpWireEventContext {
                message_stream_id,
                codec_fourcc: None,
                multitrack: false,
            },
        );
    }

    let mut offset = 1;
    let mut packet_type = first & 0x0f;
    while packet_type == 7 {
        let length_byte = *payload
            .get(offset)
            .ok_or_else(|| ErtmpWireError::new("truncated audio ModEx length"))?;
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
        let mod_ex_end = offset
            .checked_add(length)
            .filter(|end| *end < payload.len())
            .ok_or_else(|| ErtmpWireError::new("audio ModEx data exceeds its message"))?;
        if length < 3
            || be_u24(&payload[offset..offset + 3]) >= 1_000_000
            || payload[mod_ex_end] >> 4 != 0
        {
            return Err(ErtmpWireError::new(
                "invalid audio TimestampOffsetNano ModEx",
            ));
        }
        packet_type = payload[mod_ex_end] & 0x0f;
        offset = mod_ex_end + 1;
    }
    if packet_type == AUDIO_MULTITRACK {
        return parse_multitrack_audio(
            &payload[offset..],
            timestamp,
            csid,
            message_stream_id,
            bindings,
            sink,
        );
    }
    if matches!(packet_type, 3 | 6 | 7 | 8..=15) {
        return Err(ErtmpWireError::new(format!(
            "unsupported or reserved audio packet type {packet_type}"
        )));
    }
    if payload.len() - offset < 4 {
        return Err(ErtmpWireError::new(
            "enhanced audio packet is missing FOURCC",
        ));
    }
    let codec = audio_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
    offset += 4;
    let track = audio_track(0);
    bindings.associate(track, message_stream_id)?;
    emit_audio_packet(
        packet_type,
        codec,
        &payload[offset..],
        timestamp,
        csid,
        track,
        message_stream_id,
        false,
        sink,
    )
}

fn parse_multitrack_audio(
    payload: &[u8],
    timestamp: u32,
    csid: u32,
    message_stream_id: Option<u32>,
    bindings: &mut TrackBindings,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let header = *payload
        .first()
        .ok_or_else(|| ErtmpWireError::new("truncated audio Multitrack header"))?;
    let mode = header >> 4;
    let packet_type = header & 0x0f;
    if mode > 2 || packet_type == AUDIO_MULTITRACK || matches!(packet_type, 3 | 6 | 7 | 8..=15) {
        return Err(ErtmpWireError::new(
            "unsupported audio Multitrack mode or inner packet type",
        ));
    }
    let mut offset = 1;
    let shared_codec = if mode != 2 {
        if payload.len() - offset < 4 {
            return Err(ErtmpWireError::new(
                "audio Multitrack packet is missing shared FOURCC",
            ));
        }
        let codec = audio_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
        offset += 4;
        Some(codec)
    } else {
        None
    };
    let mut seen = [false; 256];
    while offset < payload.len() {
        let codec = if mode == 2 {
            if payload.len() - offset < 4 {
                return Err(ErtmpWireError::new(
                    "audio Multitrack track is missing FOURCC",
                ));
            }
            let codec = audio_codec(payload[offset..offset + 4].try_into().expect("fixed slice"))?;
            offset += 4;
            codec
        } else {
            shared_codec.ok_or_else(|| ErtmpWireError::new("missing shared audio FOURCC"))?
        };
        let track_id = *payload
            .get(offset)
            .ok_or_else(|| ErtmpWireError::new("audio Multitrack track is missing track id"))?;
        offset += 1;
        if seen[track_id as usize] {
            return Err(ErtmpWireError::new(
                "audio Multitrack message repeats a track id",
            ));
        }
        seen[track_id as usize] = true;
        let size = if mode == 0 {
            payload.len() - offset
        } else {
            if payload.len() - offset < 3 {
                return Err(ErtmpWireError::new(
                    "audio Multitrack track is missing payload size",
                ));
            }
            let value = be_u24(&payload[offset..offset + 3]) as usize;
            offset += 3;
            value
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| ErtmpWireError::new("audio Multitrack payload exceeds its message"))?;
        let track = audio_track(track_id);
        bindings.associate(track, message_stream_id)?;
        emit_audio_packet(
            packet_type,
            codec,
            &payload[offset..end],
            timestamp,
            csid,
            track,
            message_stream_id,
            true,
            sink,
        )?;
        offset = end;
    }
    if !seen.into_iter().any(|value| value) {
        return Err(ErtmpWireError::new(
            "audio Multitrack message has no tracks",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AudioCodec {
    Ac3,
    Eac3,
    Opus,
    Mp3,
    Flac,
    Aac,
}

impl AudioCodec {
    fn fourcc(self) -> [u8; 4] {
        match self {
            Self::Ac3 => *b"ac-3",
            Self::Eac3 => *b"ec-3",
            Self::Opus => *b"Opus",
            Self::Mp3 => *b".mp3",
            Self::Flac => *b"fLaC",
            Self::Aac => *b"mp4a",
        }
    }
}

fn audio_codec(fourcc: [u8; 4]) -> Result<AudioCodec, ErtmpWireError> {
    match &fourcc {
        b"ac-3" => Ok(AudioCodec::Ac3),
        b"ec-3" => Ok(AudioCodec::Eac3),
        b"Opus" => Ok(AudioCodec::Opus),
        b".mp3" => Ok(AudioCodec::Mp3),
        b"fLaC" => Ok(AudioCodec::Flac),
        b"mp4a" => Ok(AudioCodec::Aac),
        _ => Err(ErtmpWireError::new(format!(
            "unsupported enhanced audio FOURCC {:?}",
            String::from_utf8_lossy(&fourcc)
        ))),
    }
}

#[allow(clippy::too_many_arguments)] // Keep decoded media identity explicit at dispatch.
fn emit_audio_packet(
    packet_type: u8,
    codec: AudioCodec,
    body: &[u8],
    timestamp: u32,
    csid: u32,
    track: ErtmpTrack,
    message_stream_id: Option<u32>,
    multitrack: bool,
    sink: &mut EventSink,
) -> Result<(), ErtmpWireError> {
    let context = ErtmpWireEventContext {
        message_stream_id,
        codec_fourcc: Some(codec.fourcc()),
        multitrack,
    };
    match packet_type {
        0 => {
            if matches!(codec, AudioCodec::Ac3 | AudioCodec::Eac3 | AudioCodec::Mp3) {
                return Err(ErtmpWireError::new(
                    "SequenceStart is undefined for this enhanced audio codec",
                ));
            }
            if body.is_empty() && codec != AudioCodec::Opus {
                return Err(ErtmpWireError::new("empty audio codec configuration"));
            }
            sink.push_codec_config(track, csid, body, context)
        }
        1 => {
            if body.is_empty() {
                return Err(ErtmpWireError::new("empty coded audio frame"));
            }
            sink.push_frame(track, csid, timestamp, 0, body, context)
        }
        2 => {
            if !body.is_empty() {
                return Err(ErtmpWireError::new(
                    "audio SequenceEnd carries unexpected data",
                ));
            }
            Ok(())
        }
        4 => validate_multichannel_config(body),
        // There is intentionally no audio Metadata arm. Values 3 and 6 are
        // reserved by Enhanced RTMP v2 and must not be appropriated for C2PA.
        other => Err(ErtmpWireError::new(format!(
            "unsupported audio packet type {other}"
        ))),
    }
}

fn validate_multichannel_config(body: &[u8]) -> Result<(), ErtmpWireError> {
    if body.len() < 2 {
        return Err(ErtmpWireError::new(
            "truncated enhanced audio multichannel configuration",
        ));
    }
    let channel_order = body[0];
    let channel_count = body[1] as usize;
    let expected = match channel_order {
        0 => 2,
        1 => 6,
        2 => 2usize
            .checked_add(channel_count)
            .ok_or_else(|| ErtmpWireError::new("audio channel count overflow"))?,
        _ => return Err(ErtmpWireError::new("reserved enhanced audio channel order")),
    };
    if body.len() != expected {
        return Err(ErtmpWireError::new(
            "enhanced audio multichannel configuration has the wrong length",
        ));
    }
    Ok(())
}

fn video_track(track_id: u8) -> ErtmpTrack {
    ErtmpTrack {
        media_type: ErtmpMediaType::Video,
        track_id,
    }
}

fn audio_track(track_id: u8) -> ErtmpTrack {
    ErtmpTrack {
        media_type: ErtmpMediaType::Audio,
        track_id,
    }
}

fn be_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("fixed slice"))
}

fn signed_u24(bytes: &[u8]) -> i32 {
    let raw = be_u24(bytes) as i32;
    if raw & 0x0080_0000 != 0 {
        raw | !0x00ff_ffff
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ErtmpConnectionContext {
        ErtmpConnectionContext {
            client_caps_ex: 0x10,
            server_caps_ex: 0x10,
            object_encoding: 3,
        }
    }

    fn options(_chunk_size: usize) -> ErtmpWireLimits {
        ErtmpWireLimits::default()
    }

    fn trace(bytes: &[u8]) -> RtmpWireConnection<'_> {
        chunked_trace(bytes, 128)
    }

    fn chunked_trace(bytes: &[u8], initial_chunk_size: usize) -> RtmpWireConnection<'_> {
        RtmpWireConnection {
            bytes,
            connection: context(),
            initial_chunk_size,
        }
    }

    fn put_u24(value: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&[
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
    }

    fn put_basic_header(fmt: u8, csid: u32, out: &mut Vec<u8>) {
        match csid {
            2..=63 => out.push((fmt << 6) | csid as u8),
            64..=319 => {
                out.push(fmt << 6);
                out.push((csid - 64) as u8);
            }
            320..=65_599 => {
                let encoded = csid - 64;
                out.push((fmt << 6) | 1);
                out.push(encoded as u8);
                out.push((encoded >> 8) as u8);
            }
            _ => panic!("invalid test csid"),
        }
    }

    fn rtmp_type0(
        csid: u32,
        stream_id: u32,
        message_type: u8,
        timestamp: u32,
        payload: &[u8],
        chunk_size: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_basic_header(0, csid, &mut out);
        let extended = timestamp >= 0x00ff_ffff;
        put_u24(if extended { 0x00ff_ffff } else { timestamp }, &mut out);
        put_u24(payload.len() as u32, &mut out);
        out.push(message_type);
        out.extend_from_slice(&stream_id.to_le_bytes());
        if extended {
            out.extend_from_slice(&timestamp.to_be_bytes());
        }
        let mut offset = 0;
        while offset < payload.len() {
            let take = chunk_size.min(payload.len() - offset);
            out.extend_from_slice(&payload[offset..offset + take]);
            offset += take;
            if offset < payload.len() {
                put_basic_header(3, csid, &mut out);
                if extended {
                    out.extend_from_slice(&timestamp.to_be_bytes());
                }
            }
        }
        out
    }

    fn rtmp_type0_prefix(
        csid: u32,
        stream_id: u32,
        message_type: u8,
        timestamp: u32,
        payload: &[u8],
        prefix_len: usize,
    ) -> Vec<u8> {
        assert!(timestamp < 0x00ff_ffff);
        assert!(prefix_len < payload.len());
        let mut out = Vec::new();
        put_basic_header(0, csid, &mut out);
        put_u24(timestamp, &mut out);
        put_u24(payload.len() as u32, &mut out);
        out.push(message_type);
        out.extend_from_slice(&stream_id.to_le_bytes());
        out.extend_from_slice(&payload[..prefix_len]);
        out
    }

    fn flv_tag(tag_type: u8, timestamp: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![tag_type];
        put_u24(payload.len() as u32, &mut out);
        put_u24(timestamp & 0x00ff_ffff, &mut out);
        out.push((timestamp >> 24) as u8);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(payload);
        out.extend_from_slice(&(11u32 + payload.len() as u32).to_be_bytes());
        out
    }

    fn flv(flags: u8, tags: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"FLV\x01".to_vec();
        out.push(flags);
        out.extend_from_slice(&9u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        for tag in tags {
            out.extend_from_slice(tag);
        }
        out
    }

    fn amf_pair(name: &str, marker: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![0x06, ((name.len() * 2 + 1) as u8)];
        out.extend_from_slice(name.as_bytes());
        out.push(marker);
        if marker == 0x0c {
            out.push((value.len() * 2 + 1) as u8);
        }
        out.extend_from_slice(value);
        out
    }

    fn video_metadata(pairs: &[u8]) -> Vec<u8> {
        let mut out = vec![0x94];
        out.extend_from_slice(b"avc1");
        out.extend_from_slice(pairs);
        out
    }

    fn frame_timestamps(input: &ErtmpWireInput) -> Vec<u32> {
        input
            .input
            .events
            .iter()
            .filter_map(|event| match event {
                ErtmpEvent::Frame { timestamp, .. } => Some(*timestamp),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn completed_messages_on_one_csid_are_not_mistaken_for_fragments() {
        let config = [0x90, b'a', b'v', b'c', b'1', 1];
        let frame = [0x91, b'a', b'v', b'c', b'1', 0, 0, 2, 4, 5, 6];
        let mut metadata_pairs = amf_pair("colorInfo", 0x00, &[]);
        metadata_pairs.extend(amf_pair("c2paManifest", 0x0c, b"store"));
        let metadata = video_metadata(&metadata_pairs);
        let mut wire = rtmp_type0(319, 7, VIDEO_MESSAGE, 10, &config, 3);
        wire.extend(rtmp_type0(319, 7, VIDEO_MESSAGE, 11, &frame, 3));
        wire.extend(rtmp_type0(319, 7, VIDEO_MESSAGE, 11, &metadata, 3));
        let input =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 3)], options(3)).unwrap();
        assert_eq!(input.input.events.len(), 3);
        match &input.input.events[1] {
            ErtmpEvent::Frame {
                chunk_stream_id,
                timestamp,
                composition_time_offset,
                coded_data,
                ..
            } => {
                assert_eq!(
                    (*chunk_stream_id, *timestamp, *composition_time_offset),
                    (319, 11, 2)
                );
                assert_eq!(coded_data, &[4, 5, 6]);
            }
            _ => panic!("expected frame"),
        }
    }

    #[test]
    fn compressed_headers_inherit_deltas_and_extended_timestamps() {
        let payload = [0x2f, 0xaa];
        let mut wire = rtmp_type0(3, 1, AUDIO_MESSAGE, 10, &payload, 128);
        put_basic_header(3, 3, &mut wire);
        wire.extend_from_slice(&payload);
        put_basic_header(1, 3, &mut wire);
        put_u24(5, &mut wire);
        put_u24(payload.len() as u32, &mut wire);
        wire.push(AUDIO_MESSAGE);
        wire.extend_from_slice(&payload);
        put_basic_header(2, 3, &mut wire);
        put_u24(7, &mut wire);
        wire.extend_from_slice(&payload);
        assert_eq!(
            frame_timestamps(
                &ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap()
            ),
            [10, 20, 25, 32]
        );

        let extended = 0x0100_0001;
        let mut extended_wire = rtmp_type0(4, 1, AUDIO_MESSAGE, extended, &payload, 128);
        put_basic_header(3, 4, &mut extended_wire);
        extended_wire.extend_from_slice(&extended.to_be_bytes());
        extended_wire.extend_from_slice(&payload);
        assert_eq!(
            frame_timestamps(
                &ertmp_input_from_rtmp_connections(&[trace(&extended_wire)], options(128)).unwrap()
            ),
            [extended, extended.wrapping_mul(2)]
        );
    }

    #[test]
    fn type1_and_type2_extended_timestamp_deltas_are_applied() {
        let payload = [0x2f, 0xaa];
        let delta = 0x0100_0000u32;
        let mut wire = rtmp_type0(3, 1, AUDIO_MESSAGE, 1, &payload, 128);
        put_basic_header(1, 3, &mut wire);
        put_u24(0x00ff_ffff, &mut wire);
        put_u24(payload.len() as u32, &mut wire);
        wire.push(AUDIO_MESSAGE);
        wire.extend_from_slice(&delta.to_be_bytes());
        wire.extend_from_slice(&payload);
        put_basic_header(2, 3, &mut wire);
        put_u24(0x00ff_ffff, &mut wire);
        wire.extend_from_slice(&delta.to_be_bytes());
        wire.extend_from_slice(&payload);
        assert_eq!(
            frame_timestamps(
                &ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap()
            ),
            [1, delta + 1, delta.wrapping_mul(2) + 1]
        );
    }

    #[test]
    fn type3_continuation_requires_the_inherited_extended_value() {
        let payload = [0x2f, 1, 2, 3];
        let timestamp = 0x0100_0000;
        let mut wire = rtmp_type0(4, 1, AUDIO_MESSAGE, timestamp, &payload, 2);
        let first_extended_position = 1 + 11 + 4 + 2 + 1;
        wire[first_extended_position..first_extended_position + 4]
            .copy_from_slice(&(timestamp + 1).to_be_bytes());
        assert!(ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 2)], options(2)).is_err());
    }

    #[test]
    fn explicitly_headed_continuations_must_match_the_active_message() {
        let payload = [0x2f, 1, 2, 3];
        let mut wire = rtmp_type0_prefix(7, 1, AUDIO_MESSAGE, 1, &payload, 2);
        let mut continuation = rtmp_type0_prefix(7, 1, AUDIO_MESSAGE, 1, &payload, 2);
        let body_offset = continuation.len() - 2;
        continuation[body_offset..].copy_from_slice(&payload[2..]);
        wire.extend(continuation);
        let input =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 2)], options(2)).unwrap();
        assert_eq!(frame_timestamps(&input), [1]);

        let mut changed = rtmp_type0_prefix(7, 1, AUDIO_MESSAGE, 1, &payload, 2);
        changed.extend(rtmp_type0(7, 1, AUDIO_MESSAGE, 2, &payload[2..], 2));
        let error = ertmp_input_from_rtmp_connections(&[chunked_trace(&changed, 2)], options(2))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "RTMP message was replaced before all chunks arrived"
        );
    }

    #[test]
    fn abort_discards_only_the_named_partial_message() {
        let partial_payload = [0x2f, 1, 2, 3];
        let mut wire = rtmp_type0(7, 1, AUDIO_MESSAGE, 1, &partial_payload, 2);
        wire.truncate(1 + 11 + 2);
        wire.extend(rtmp_type0(2, 0, ABORT_MESSAGE, 0, &7u32.to_be_bytes(), 2));
        wire.extend(rtmp_type0(7, 1, AUDIO_MESSAGE, 2, &[0x2f, 9], 2));
        let input =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 2)], options(2)).unwrap();
        assert_eq!(frame_timestamps(&input), [2]);

        let misplaced = rtmp_type0(3, 0, ABORT_MESSAGE, 0, &7u32.to_be_bytes(), 128);
        assert!(ertmp_input_from_rtmp_connections(&[trace(&misplaced)], options(128)).is_err());
    }

    #[test]
    fn message_stream_track_association_rejects_collisions_and_resets_on_reconnect() {
        let config0 = [0x90, b'a', b'v', b'c', b'1', 1];
        let mut colliding = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &config0, 128);
        colliding.extend(rtmp_type0(8, 2, VIDEO_MESSAGE, 0, &config0, 128));
        assert!(ertmp_input_from_rtmp_connections(&[trace(&colliding)], options(128)).is_err());

        let frame = [0x91, b'a', b'v', b'c', b'1', 0, 0, 0, 7];
        let metadata = video_metadata(&amf_pair("c2paSegmentInfo", 0x0c, b"segment"));
        let mut cross_stream_closure = rtmp_type0(7, 1, VIDEO_MESSAGE, 4, &frame, 128);
        cross_stream_closure.extend(rtmp_type0(7, 2, VIDEO_MESSAGE, 4, &metadata, 128));
        assert!(
            ertmp_input_from_rtmp_connections(&[trace(&cross_stream_closure)], options(128),)
                .is_err()
        );

        let config1 = [0x96, 0x00, b'a', b'v', b'c', b'1', 1, 1];
        let mut unique = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &config0, 128);
        unique.extend(rtmp_type0(8, 2, VIDEO_MESSAGE, 0, &config1, 128));
        assert_eq!(
            ertmp_input_from_rtmp_connections(&[trace(&unique)], options(128))
                .unwrap()
                .input
                .events
                .len(),
            2
        );

        let first = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &config0, 128);
        let second = rtmp_type0(8, 2, VIDEO_MESSAGE, 0, &config0, 128);
        let input =
            ertmp_input_from_rtmp_connections(&[trace(&first), trace(&second)], options(128))
                .unwrap();
        assert!(matches!(input.input.events[1], ErtmpEvent::Reconnect));
        assert_eq!(input.event_contexts.len(), input.input.events.len());
        assert!(input.event_contexts[1].is_none());
    }

    #[test]
    fn aggregate_inherits_outer_message_stream_for_track_collisions() {
        let config = [0x90, b'a', b'v', b'c', b'1', 1];
        let aggregate = flv_tag(VIDEO_MESSAGE, 0, &config);
        let mut wire = rtmp_type0(7, 1, AGGREGATE_MESSAGE, 0, &aggregate, 128);
        wire.extend(rtmp_type0(8, 2, VIDEO_MESSAGE, 1, &config, 128));
        assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
    }

    #[test]
    fn every_reconnect_context_must_negotiate_c2pa_amf3() {
        let wire = rtmp_type0(
            7,
            1,
            VIDEO_MESSAGE,
            0,
            &[0x90, b'a', b'v', b'c', b'1', 1],
            128,
        );
        let bad = ErtmpConnectionContext {
            client_caps_ex: 0x10,
            server_caps_ex: 0,
            object_encoding: 3,
        };
        assert!(ertmp_input_from_rtmp_connections(
            &[
                trace(&wire),
                RtmpWireConnection {
                    bytes: &wire,
                    connection: bad,
                    initial_chunk_size: 128,
                },
            ],
            options(128),
        )
        .is_err());
    }

    #[test]
    fn codec_specific_video_layout_preserves_payloads() {
        for fourcc in [b"vp08", b"vp09", b"av01"] {
            let mut payload = vec![0x91];
            payload.extend_from_slice(fourcc);
            payload.extend_from_slice(&[1, 2, 3, 4]);
            let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 9, &payload, 128);
            let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
            match &input.input.events[0] {
                ErtmpEvent::Frame {
                    coded_data,
                    composition_time_offset,
                    ..
                } => {
                    assert_eq!(coded_data, &[1, 2, 3, 4]);
                    assert_eq!(*composition_time_offset, 0);
                }
                _ => panic!("expected frame"),
            }
        }
        for fourcc in [b"avc1", b"hvc1", b"vvc1"] {
            let mut payload = vec![0x91];
            payload.extend_from_slice(fourcc);
            payload.extend_from_slice(&[0xff, 0xff, 0xfe, 7, 8]);
            let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 9, &payload, 128);
            let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
            match &input.input.events[0] {
                ErtmpEvent::Frame {
                    coded_data,
                    composition_time_offset,
                    ..
                } => {
                    assert_eq!(coded_data, &[7, 8]);
                    assert_eq!(*composition_time_offset, -2);
                }
                _ => panic!("expected frame"),
            }
        }
    }

    #[test]
    fn multitrack_video_applies_composition_offsets_per_codec() {
        let payload = [
            0x96, 0x21, b'v', b'p', b'0', b'9', 1, 0, 0, 2, 8, 9, b'a', b'v', b'c', b'1', 2, 0, 0,
            5, 0, 0, 3, 6, 7,
        ];
        let wire = rtmp_type0(70, 1, VIDEO_MESSAGE, 9, &payload, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        match (&input.input.events[0], &input.input.events[1]) {
            (
                ErtmpEvent::Frame {
                    coded_data: first,
                    composition_time_offset: first_cto,
                    ..
                },
                ErtmpEvent::Frame {
                    coded_data: second,
                    composition_time_offset: second_cto,
                    ..
                },
            ) => {
                assert_eq!(first, &[8, 9]);
                assert_eq!(*first_cto, 0);
                assert_eq!(second, &[6, 7]);
                assert_eq!(*second_cto, 3);
            }
            _ => panic!("expected two frames"),
        }
    }

    #[test]
    fn multitrack_metadata_ignores_the_outer_frame_type() {
        let mut payload = vec![0x86, VIDEO_METADATA, b'a', b'v', b'c', b'1', 3];
        payload.extend(amf_pair("c2paSegmentInfo", 0x0c, b"segment"));
        let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 9, &payload, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert!(matches!(
            &input.input.events[0],
            ErtmpEvent::Metadata {
                track,
                name,
                value,
                ..
            } if track.track_id == 3
                && name == "c2paSegmentInfo"
                && value == b"segment"
        ));
        assert_eq!(
            input.event_contexts[0],
            Some(ErtmpWireEventContext {
                message_stream_id: Some(1),
                codec_fourcc: Some(*b"avc1"),
                multitrack: true,
            })
        );
    }

    #[test]
    fn enhanced_audio_fourcc_and_sequence_rules_are_fail_closed() {
        for fourcc in [b"ac-3", b"ec-3", b".mp3"] {
            let mut sequence = vec![0x90];
            sequence.extend_from_slice(fourcc);
            sequence.push(1);
            let wire = rtmp_type0(4, 1, AUDIO_MESSAGE, 0, &sequence, 128);
            assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
        }
        for fourcc in [b"mp4a", b"fLaC"] {
            let mut empty = vec![0x90];
            empty.extend_from_slice(fourcc);
            let wire = rtmp_type0(4, 1, AUDIO_MESSAGE, 0, &empty, 128);
            assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
        }
        let opus = [0x90, b'O', b'p', b'u', b's'];
        let wire = rtmp_type0(4, 1, AUDIO_MESSAGE, 0, &opus, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert!(matches!(
            &input.input.events[0],
            ErtmpEvent::CodecConfig { payload, .. } if payload.is_empty()
        ));

        let unknown = [0x90, b'b', b'a', b'd', b'!'];
        let wire = rtmp_type0(4, 1, AUDIO_MESSAGE, 0, &unknown, 128);
        assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
        for reserved in [3u8, 6u8] {
            let audio = [0x90 | reserved, b'm', b'p', b'4', b'a', 1];
            let wire = rtmp_type0(4, 1, AUDIO_MESSAGE, 0, &audio, 128);
            assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
        }
    }

    #[test]
    fn flv_reserved_filter_script_and_back_pointer_rules_are_enforced() {
        let config = [0x90, b'a', b'v', b'0', b'1', 1, 2, 3, 4];
        let valid = flv(
            0x01,
            &[
                flv_tag(AMF3_SCRIPT_DATA, 0, b"script"),
                flv_tag(VIDEO_MESSAGE, 55, &config),
            ],
        );
        let input = ertmp_input_from_flv(
            &valid,
            FlvWireOptions {
                connection: context(),
                audio_chunk_stream_id: 4,
                video_chunk_stream_id: 12,
                limits: ErtmpWireLimits::default(),
            },
        )
        .unwrap();
        assert_eq!(input.input.events.len(), 1);
        assert_eq!(
            input.event_contexts,
            [Some(ErtmpWireEventContext {
                message_stream_id: None,
                codec_fourcc: Some(*b"av01"),
                multitrack: false,
            })]
        );

        let mut reserved_header = valid.clone();
        reserved_header[4] |= 0x02;
        assert!(ertmp_input_from_flv(
            &reserved_header,
            FlvWireOptions {
                connection: context(),
                audio_chunk_stream_id: 4,
                video_chunk_stream_id: 12,
                limits: ErtmpWireLimits::default(),
            },
        )
        .is_err());
        let filtered = flv(0x01, &[flv_tag(0x20 | VIDEO_MESSAGE, 0, &config)]);
        assert!(ertmp_input_from_flv(
            &filtered,
            FlvWireOptions {
                connection: context(),
                audio_chunk_stream_id: 4,
                video_chunk_stream_id: 12,
                limits: ErtmpWireLimits::default(),
            },
        )
        .is_err());

        let mut bad_back_pointer = valid.clone();
        let last = bad_back_pointer.len() - 1;
        bad_back_pointer[last] ^= 1;
        assert!(ertmp_input_from_flv(
            &bad_back_pointer,
            FlvWireOptions {
                connection: context(),
                audio_chunk_stream_id: 4,
                video_chunk_stream_id: 12,
                limits: ErtmpWireLimits::default(),
            },
        )
        .is_err());
    }

    #[test]
    fn video_commands_and_legacy_avc_codepoints_are_strict() {
        let command = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &[0xd0, 1], 128);
        assert!(
            ertmp_input_from_rtmp_connections(&[trace(&command)], options(128))
                .unwrap()
                .input
                .events
                .is_empty()
        );
        let invalid_avc = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &[0x17, 4, 0, 0, 0], 128);
        assert!(ertmp_input_from_rtmp_connections(&[trace(&invalid_avc)], options(128)).is_err());
        for payload in [
            &[0x37, 0, 0, 0, 0, 1][..],
            &[0x47, 0, 0, 0, 0, 1][..],
            &[0xb1, b'a', b'v', b'c', b'1', 0, 0, 0, 1][..],
            &[0xc6, 0x01, b'a', b'v', b'c', b'1', 1, 0, 0, 0, 7][..],
        ] {
            let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, payload, 128);
            assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
        }
    }

    #[test]
    fn protocol_control_placement_and_shapes_are_strict() {
        let mut valid = rtmp_type0(2, 0, SET_CHUNK_SIZE, 0, &128u32.to_be_bytes(), 128);
        valid.extend(rtmp_type0(2, 0, ABORT_MESSAGE, 0, &7u32.to_be_bytes(), 128));
        valid.extend(rtmp_type0(
            2,
            0,
            ACKNOWLEDGEMENT,
            0,
            &1u32.to_be_bytes(),
            128,
        ));
        valid.extend(rtmp_type0(
            2,
            0,
            WINDOW_ACKNOWLEDGEMENT_SIZE,
            0,
            &1u32.to_be_bytes(),
            128,
        ));
        valid.extend(rtmp_type0(
            2,
            0,
            SET_PEER_BANDWIDTH,
            0,
            &[0, 0, 0, 1, 2],
            128,
        ));
        assert!(
            ertmp_input_from_rtmp_connections(&[trace(&valid)], options(128))
                .unwrap()
                .input
                .events
                .is_empty()
        );

        for (message_type, payload) in [
            (SET_CHUNK_SIZE, &[0, 0, 1][..]),
            (ABORT_MESSAGE, &[0, 0, 7][..]),
            (ACKNOWLEDGEMENT, &[0, 0, 1][..]),
            (WINDOW_ACKNOWLEDGEMENT_SIZE, &[0, 0, 1][..]),
            (SET_PEER_BANDWIDTH, &[0, 0, 0, 1][..]),
        ] {
            let invalid = rtmp_type0(2, 0, message_type, 0, payload, 128);
            assert!(ertmp_input_from_rtmp_connections(&[trace(&invalid)], options(128)).is_err());
        }
        let media_on_control = rtmp_type0(2, 1, AUDIO_MESSAGE, 0, &[0x2f, 1], 128);
        assert!(
            ertmp_input_from_rtmp_connections(&[trace(&media_on_control)], options(128)).is_err()
        );
        let undefined = rtmp_type0(7, 1, 7, 0, &[], 128);
        let error =
            ertmp_input_from_rtmp_connections(&[trace(&undefined)], options(128)).unwrap_err();
        assert_eq!(error.to_string(), "undefined RTMP message type 7");
    }

    #[test]
    fn aggregate_normalizes_timestamps_and_ignores_submessage_stream_ids() {
        let mut first = flv_tag(AUDIO_MESSAGE, 30, &[0x2f, 1]);
        first[8..11].copy_from_slice(&[1, 2, 3]);
        let mut second = flv_tag(AUDIO_MESSAGE, 35, &[0x2f, 2]);
        second[8..11].copy_from_slice(&[4, 5, 6]);
        let mut aggregate = first;
        aggregate.extend(second);
        let wire = rtmp_type0(7, 9, AGGREGATE_MESSAGE, 100, &aggregate, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert_eq!(frame_timestamps(&input), [100, 105]);

        let mut malformed = aggregate;
        let last = malformed.len() - 1;
        malformed[last] ^= 1;
        let wire = rtmp_type0(7, 9, AGGREGATE_MESSAGE, 100, &malformed, 128);
        assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).is_err());
    }

    #[test]
    fn audio_multitrack_modes_apply_codec_specific_sequence_rules() {
        let one_track = [0x95, 0x00, b'O', b'p', b'u', b's', 3];
        let wire = rtmp_type0(7, 1, AUDIO_MESSAGE, 0, &one_track, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert!(matches!(
            &input.input.events[0],
            ErtmpEvent::CodecConfig { track, payload, .. }
                if track.track_id == 3 && payload.is_empty()
        ));

        let many_tracks = [
            0x95, 0x10, b'm', b'p', b'4', b'a', 1, 0, 0, 1, 7, 2, 0, 0, 1, 8,
        ];
        let wire = rtmp_type0(7, 1, AUDIO_MESSAGE, 0, &many_tracks, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert_eq!(input.input.events.len(), 2);

        let many_codecs = [
            0x95, 0x20, b'O', b'p', b'u', b's', 1, 0, 0, 0, b'm', b'p', b'4', b'a', 2, 0, 0, 1, 9,
        ];
        let wire = rtmp_type0(7, 1, AUDIO_MESSAGE, 0, &many_codecs, 128);
        let input = ertmp_input_from_rtmp_connections(&[trace(&wire)], options(128)).unwrap();
        assert_eq!(input.input.events.len(), 2);
    }

    #[test]
    fn buffered_and_active_chunk_stream_limits_cover_complete_interleaved_messages() {
        let first_payload = [0x2f, 1, 2];
        let second_payload = [0x2f, 3, 4];
        let mut wire = rtmp_type0_prefix(7, 1, AUDIO_MESSAGE, 0, &first_payload, 1);
        wire.extend(rtmp_type0_prefix(
            8,
            1,
            AUDIO_MESSAGE,
            0,
            &second_payload,
            1,
        ));
        for byte in &first_payload[1..] {
            put_basic_header(3, 7, &mut wire);
            wire.push(*byte);
        }
        for byte in &second_payload[1..] {
            put_basic_header(3, 8, &mut wire);
            wire.push(*byte);
        }

        let exact_buffer_limit = ErtmpWireLimits {
            max_buffered_message_bytes: 4,
            max_active_chunk_streams: 2,
            ..Default::default()
        };
        let input =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 1)], exact_buffer_limit)
                .unwrap();
        assert_eq!(input.input.events.len(), 2);

        let one_under_buffer_limit = ErtmpWireLimits {
            max_buffered_message_bytes: 3,
            max_active_chunk_streams: 2,
            ..Default::default()
        };
        let error =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 1)], one_under_buffer_limit)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "incomplete RTMP messages exceed the buffered byte limit"
        );

        let one_under_stream_limit = ErtmpWireLimits {
            max_buffered_message_bytes: 4,
            max_active_chunk_streams: 1,
            ..Default::default()
        };
        let error =
            ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 1)], one_under_stream_limit)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "RTMP active chunk stream count exceeds its limit"
        );
    }

    #[test]
    fn abort_and_completion_release_buffer_capacity_for_reuse() {
        let payload = [0x90, b'a', b'v', b'c', b'1', 1, 2, 3];
        let mut wire = rtmp_type0_prefix(7, 1, VIDEO_MESSAGE, 0, &payload, 4);
        wire.extend(rtmp_type0(2, 0, ABORT_MESSAGE, 0, &7u32.to_be_bytes(), 4));
        wire.extend(rtmp_type0(8, 1, VIDEO_MESSAGE, 1, &payload, 4));
        wire.extend(rtmp_type0(8, 1, VIDEO_MESSAGE, 2, &payload, 4));
        let limits = ErtmpWireLimits {
            max_buffered_message_bytes: 8,
            ..Default::default()
        };
        let input = ertmp_input_from_rtmp_connections(&[chunked_trace(&wire, 4)], limits).unwrap();
        assert_eq!(input.input.events.len(), 2);
    }

    #[test]
    fn allocation_limits_apply_before_event_and_wire_copies() {
        let limits = ErtmpWireLimits {
            max_total_event_payload_bytes: 2,
            ..Default::default()
        };
        let config = rtmp_type0(
            7,
            1,
            VIDEO_MESSAGE,
            0,
            &[0x90, b'a', b'v', b'c', b'1', 1, 2, 3],
            128,
        );
        let error = ertmp_input_from_rtmp_connections(&[trace(&config)], limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "E-RTMP event payload bytes exceed their limit"
        );

        let limits = ErtmpWireLimits {
            max_total_wire_bytes: config.len(),
            ..Default::default()
        };
        let error = ertmp_input_from_rtmp_connections(&[trace(&config), trace(&config)], limits)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "RTMP connections exceed the total wire byte limit"
        );
    }

    #[test]
    fn byte_array_references_are_charged_again_at_the_wire_callback_boundary() {
        let mut pairs = amf_pair("c2paManifest", 0x0c, b"1234");
        pairs.extend_from_slice(&[0x06, 31]);
        pairs.extend_from_slice(b"c2paSegmentInfo");
        pairs.extend_from_slice(&[0x0c, 0x00]);
        let metadata = video_metadata(&pairs);
        let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &metadata, 128);
        let limits = ErtmpWireLimits {
            max_total_event_payload_bytes: std::mem::size_of::<Option<ErtmpWireEventContext>>() * 2
                + 34,
            ..Default::default()
        };
        let error = ertmp_input_from_rtmp_connections(&[trace(&wire)], limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "E-RTMP event payload bytes exceed their limit"
        );
    }

    #[test]
    fn event_limit_is_checked_before_metadata_values_are_copied() {
        let pairs = amf_pair("c2paManifest", 0x0c, b"store");
        let metadata = video_metadata(&pairs);
        let wire = rtmp_type0(7, 1, VIDEO_MESSAGE, 0, &metadata, 128);
        let limits = ErtmpWireLimits {
            max_events: 0,
            ..Default::default()
        };
        assert!(ertmp_input_from_rtmp_connections(&[trace(&wire)], limits,).is_err());
    }
}
