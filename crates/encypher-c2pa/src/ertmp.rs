// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Verification of C2PA live-media carriage over Enhanced RTMP.
//!
//! This module starts at the E-RTMP message boundary. The caller remains the
//! RTMP parser and supplies events in wire order, including normalized
//! timestamps for packets extracted from Aggregate Messages and only the
//! selected track packet from a Multitrack message. No audio Metadata packet
//! number is assumed here: the pinned E-RTMP dependency does not define one.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::c2pa_cbor::{decode, Value};
use crate::c2pa_core::{EngineProfile, SpecVersion};
use crate::c2pa_crypto::{verify_with_cose_key_with, ClaimAlgorithmList};
use crate::c2pa_formats::StreamMethod as KernelStreamMethod;
use crate::c2pa_validate::live_video::{
    validate_session_keys_with, LiveVideoApplicability, ValidatedSessionKey,
};
use crate::c2pa_validate::ValidationResults as KernelResults;
use crate::{
    parse_validation_time, resolve_profile, verify_with_manifest_store, Error, VerificationReport,
    VerifyOptions, REPORT_SCHEMA_VERSION,
};

const C2PA_CAPABILITY: u64 = 0x10;
const MAX_EVENTS: usize = 1_000_000;
const MAX_TRACKS: usize = 256;
const MAX_FRAMES_PER_SEGMENT: usize = 1_000_000;
const MAX_SEGMENT_INFOS: usize = 64;

/// E-RTMP media type. Audio and video track-id namespaces are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErtmpMediaType {
    /// A video track.
    Video,
    /// An audio track.
    Audio,
}

impl ErtmpMediaType {
    fn token(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
        }
    }
}

/// One E-RTMP track. An absent wire `trackId` is represented as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ErtmpTrack {
    /// Audio or video.
    pub media_type: ErtmpMediaType,
    /// E-RTMP multitrack id, or zero for a message without multitrack signaling.
    #[serde(default)]
    pub track_id: u8,
}

/// One caller-parsed E-RTMP event, in transmission order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErtmpEvent {
    /// The payload of a SequenceStart packet (or equivalent legacy sequence header).
    CodecConfig {
        /// Track carrying the configuration.
        track: ErtmpTrack,
        /// RTMP chunk stream carrying this track.
        chunk_stream_id: u32,
        /// Codec configuration payload only, without E-RTMP packet framing.
        payload: Vec<u8>,
    },
    /// One coded-frame packet. Protocol, configuration, metadata and control bytes
    /// must not be included. Aggregate timestamps must already be normalized.
    Frame {
        /// Track carrying the frame. For a Multitrack message this is the selected packet.
        track: ErtmpTrack,
        /// RTMP chunk stream carrying the frame.
        chunk_stream_id: u32,
        /// RTMP message timestamp.
        timestamp: u32,
        /// Signed 24-bit composition time offset, or zero when absent.
        composition_time_offset: i32,
        /// Coded media bytes only.
        coded_data: Vec<u8>,
    },
    /// One native AMF3 ByteArray [name, value] pair from a Metadata message.
    Metadata {
        /// Track on whose Metadata packet this pair arrived.
        track: ErtmpTrack,
        /// RTMP chunk stream carrying that track and this Metadata message.
        chunk_stream_id: u32,
        /// RTMP message timestamp of the Metadata message.
        timestamp: u32,
        /// Pair name. Recognized values are `c2paManifest` and `c2paSegmentInfo`.
        name: String,
        /// Native AMF3 ByteArray value, already removed from AMF framing.
        value: Vec<u8>,
    },
    /// A transport reconnection. C2PA manifest, key and sequence state survives,
    /// but no logical segment may span this boundary.
    Reconnect,
}

/// Ordered input to E-RTMP verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErtmpInput {
    /// `capsEx` sent by the client.
    pub client_caps_ex: u64,
    /// `capsEx` returned by the server.
    pub server_caps_ex: u64,
    /// AMF object encoding selected by the connection. Must be 3.
    pub object_encoding: u8,
    /// Caller-parsed events in exact transmission order.
    pub events: Vec<ErtmpEvent>,
}

/// Result for one closed logical E-RTMP segment.
#[derive(Debug, Clone, Serialize)]
pub struct ErtmpSegmentReport {
    /// Track the segment belongs to.
    pub track: ErtmpTrack,
    /// Signed per-track sequence number, when one candidate authenticated.
    pub sequence_number: Option<u64>,
    /// Manifest identifier authenticated by the accepted candidate.
    pub manifest_id: Option<String>,
    /// Lowercase hexadecimal session-key id used by the accepted candidate.
    pub key_id: Option<String>,
    /// Whether at least one consecutive rotated-key candidate validated.
    pub valid: bool,
    /// Candidate and carriage defects. Empty for a valid segment.
    pub failures: Vec<String>,
}

/// One manifest first exercised by an E-RTMP segment.
#[derive(Debug, Clone, Serialize)]
pub struct ErtmpManifestReport {
    /// Active manifest label.
    pub manifest_id: String,
    /// Ordinary C2PA verification against the initialization-data bytes that
    /// existed immediately before the first referencing SegmentInfo.
    pub report: VerificationReport,
}

/// Result of [`verify_ertmp_with_options`].
#[derive(Debug, Clone, Serialize)]
pub struct ErtmpVerificationReport {
    /// Public report schema version.
    pub schema_version: String,
    /// `valid` only when capability negotiation, every closed segment, every
    /// referenced manifest and every reconnection rule validated.
    pub integrity: String,
    /// Manifests validated at first use.
    pub manifests: Vec<ErtmpManifestReport>,
    /// Logical segments, in closure order.
    pub segments: Vec<ErtmpSegmentReport>,
    /// Stream-wide transport/state failures.
    pub failures: Vec<String>,
}

impl ErtmpVerificationReport {
    /// Serialize as compact JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(Error::Serialize)
    }

    /// Serialize as indented JSON.
    pub fn to_pretty_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(Error::Serialize)
    }
}

/// Verify ordered E-RTMP events under the explicitly selected C2PA 2.5 policy.
pub fn verify_ertmp_with_options(
    input: &ErtmpInput,
    options: &VerifyOptions,
) -> Result<ErtmpVerificationReport, Error> {
    let profile = resolve_profile(options.spec_version.as_deref(), options.strict_conformance)?;
    if profile.version != SpecVersion::V2_5 {
        return Err(Error::UnsupportedSpecVersion(
            "E-RTMP verification requires spec_version 2.5".into(),
        ));
    }
    if input.events.len() > MAX_EVENTS {
        return Err(Error::Verification(format!(
            "E-RTMP event count exceeds {MAX_EVENTS}"
        )));
    }

    let validation_time = parse_validation_time(options.validation_time.as_deref())?;
    let mut verifier = Verifier::new(profile, options, validation_time);
    if input.object_encoding != 3
        || input.client_caps_ex & C2PA_CAPABILITY == 0
        || input.server_caps_ex & C2PA_CAPABILITY == 0
    {
        verifier.fail(
            "E-RTMP C2PA carriage was used without bilateral capsEx bit 0x10 and objectEncoding 3",
        );
    }
    for event in &input.events {
        verifier.event(event)?;
    }
    verifier.finish()
}

/// [`verify_ertmp_with_options`] with 2.5 selected and all other defaults kept.
pub fn verify_ertmp(input: &ErtmpInput) -> Result<ErtmpVerificationReport, Error> {
    let options = VerifyOptions {
        spec_version: Some("2.5".into()),
        ..VerifyOptions::default()
    };
    verify_ertmp_with_options(input, &options)
}

struct Config<'a> {
    chunk_stream_id: u32,
    payload: &'a [u8],
    revision: u64,
}

struct Frame<'a> {
    chunk_stream_id: u32,
    timestamp: u32,
    composition_time_offset: i32,
    coded_data: &'a [u8],
    config_revision: u64,
}

#[derive(Default)]
struct TrackState<'a> {
    frames: Vec<Frame<'a>>,
    pending: Option<Pending>,
    last_sequence: Option<u64>,
}

struct Pending {
    track: ErtmpTrack,
    candidates: usize,
    accepted: Option<Accepted>,
    failures: Vec<String>,
}

struct Accepted {
    sequence_number: u64,
    manifest_id: String,
    key_id: Vec<u8>,
}

struct ManifestDelivery {
    store: Vec<u8>,
    keys: Vec<ValidatedSessionKey>,
    bound_initialization_sha256: Option<[u8; 32]>,
    report: Option<VerificationReport>,
}

struct Verifier<'a> {
    profile: EngineProfile,
    options: &'a VerifyOptions,
    validation_time: time::OffsetDateTime,
    configs: BTreeMap<ErtmpTrack, Config<'a>>,
    tracks: BTreeMap<ErtmpTrack, TrackState<'a>>,
    manifests: HashMap<String, ManifestDelivery>,
    key_tracks: HashMap<Vec<u8>, ErtmpTrack>,
    next_config_revision: u64,
    manifest_seen_since_reconnect: bool,
    segment_reports: Vec<ErtmpSegmentReport>,
    failures: Vec<String>,
}

impl<'a> Verifier<'a> {
    fn new(
        profile: EngineProfile,
        options: &'a VerifyOptions,
        validation_time: time::OffsetDateTime,
    ) -> Self {
        Self {
            profile,
            options,
            validation_time,
            configs: BTreeMap::new(),
            tracks: BTreeMap::new(),
            manifests: HashMap::new(),
            key_tracks: HashMap::new(),
            next_config_revision: 1,
            manifest_seen_since_reconnect: false,
            segment_reports: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, detail: impl Into<String>) {
        self.failures.push(detail.into());
    }

    fn event(&mut self, event: &'a ErtmpEvent) -> Result<(), Error> {
        match event {
            ErtmpEvent::CodecConfig {
                track,
                chunk_stream_id,
                payload,
            } => {
                if payload.is_empty() {
                    self.fail(format!(
                        "{}:{} codec configuration is empty",
                        track.media_type.token(),
                        track.track_id
                    ));
                    return Ok(());
                }
                if !self.configs.contains_key(track) && self.configs.len() >= MAX_TRACKS {
                    return Err(Error::Verification(format!(
                        "E-RTMP track count exceeds {MAX_TRACKS}"
                    )));
                }
                let revision = self.next_config_revision;
                self.next_config_revision = self.next_config_revision.saturating_add(1);
                self.configs.insert(
                    *track,
                    Config {
                        chunk_stream_id: *chunk_stream_id,
                        payload,
                        revision,
                    },
                );
            }
            ErtmpEvent::Frame {
                track,
                chunk_stream_id,
                timestamp,
                composition_time_offset,
                coded_data,
            } => {
                self.finalize_pending(*track);
                if !(-8_388_608..=8_388_607).contains(composition_time_offset) {
                    self.fail(format!(
                        "{}:{} composition time offset is outside signed 24-bit range",
                        track.media_type.token(),
                        track.track_id
                    ));
                    return Ok(());
                }
                if !self.manifest_seen_since_reconnect {
                    self.fail(
                        "coded frame arrived after reconnect before the active manifest was resent",
                    );
                }
                let (config_chunk_stream_id, config_revision) = match self.configs.get(track) {
                    Some(config) => (config.chunk_stream_id, config.revision),
                    None => {
                        self.fail(format!(
                            "{}:{} coded frame arrived before codec configuration",
                            track.media_type.token(),
                            track.track_id
                        ));
                        return Ok(());
                    }
                };
                if config_chunk_stream_id != *chunk_stream_id {
                    self.fail(format!(
                        "{}:{} codec configuration and frame use different chunk streams",
                        track.media_type.token(),
                        track.track_id
                    ));
                }
                let state = self.tracks.entry(*track).or_default();
                if state.frames.len() >= MAX_FRAMES_PER_SEGMENT {
                    return Err(Error::Verification(format!(
                        "E-RTMP segment frame count exceeds {MAX_FRAMES_PER_SEGMENT}"
                    )));
                }
                state.frames.push(Frame {
                    chunk_stream_id: *chunk_stream_id,
                    timestamp: *timestamp,
                    composition_time_offset: *composition_time_offset,
                    coded_data,
                    config_revision,
                });
            }
            ErtmpEvent::Metadata {
                track,
                chunk_stream_id,
                timestamp,
                name,
                value,
            } if name == "c2paManifest" => {
                let (manifest_id, delivery) = manifest_delivery(value, self.profile)?;
                self.manifests.insert(manifest_id, delivery);
                self.manifest_seen_since_reconnect = true;
                if let Some(config) = self.configs.get(track) {
                    if config.chunk_stream_id != *chunk_stream_id {
                        self.fail(format!(
                            "{}:{} manifest Metadata uses a different chunk stream",
                            track.media_type.token(),
                            track.track_id
                        ));
                    }
                }
                let _ = timestamp;
            }
            ErtmpEvent::Metadata {
                track,
                chunk_stream_id,
                timestamp,
                name,
                value,
            } if name == "c2paSegmentInfo" => {
                self.segment_info(*track, *chunk_stream_id, *timestamp, value)?;
            }
            ErtmpEvent::Metadata { .. } => {
                // E-RTMP requires unknown pairs to be ignored while processing
                // the remaining pairs in the Metadata message.
            }
            ErtmpEvent::Reconnect => self.reconnect(),
        }
        Ok(())
    }

    fn reconnect(&mut self) {
        let tracks: Vec<ErtmpTrack> = self.tracks.keys().copied().collect();
        for track in tracks {
            self.finalize_pending(track);
            if self
                .tracks
                .get(&track)
                .is_some_and(|state| !state.frames.is_empty())
            {
                self.fail(format!(
                    "{}:{} logical segment was not closed before reconnect",
                    track.media_type.token(),
                    track.track_id
                ));
                if let Some(state) = self.tracks.get_mut(&track) {
                    state.frames.clear();
                }
            }
        }
        self.configs.clear();
        self.manifest_seen_since_reconnect = false;
    }

    fn segment_info(
        &mut self,
        track: ErtmpTrack,
        chunk_stream_id: u32,
        timestamp: u32,
        cose_sign1: &[u8],
    ) -> Result<(), Error> {
        let has_pending = self
            .tracks
            .get(&track)
            .and_then(|state| state.pending.as_ref())
            .is_some();
        let has_frames = self
            .tracks
            .get(&track)
            .is_some_and(|state| !state.frames.is_empty());
        if !has_frames && !has_pending {
            self.fail(format!(
                "{}:{} SegmentInfo closes no coded frames",
                track.media_type.token(),
                track.track_id
            ));
            return Ok(());
        }
        if !has_pending {
            self.tracks.entry(track).or_default().pending = Some(Pending {
                track,
                candidates: 0,
                accepted: None,
                failures: Vec::new(),
            });
        }
        let candidates = self
            .tracks
            .get(&track)
            .and_then(|state| state.pending.as_ref())
            .map_or(0, |pending| pending.candidates);
        if candidates >= MAX_SEGMENT_INFOS {
            return Err(Error::Verification(format!(
                "E-RTMP segment carries more than {MAX_SEGMENT_INFOS} SegmentInfo candidates"
            )));
        }

        let result = self.authenticate_candidate(track, chunk_stream_id, timestamp, cose_sign1);
        let pending = self
            .tracks
            .get_mut(&track)
            .and_then(|state| state.pending.as_mut())
            .expect("pending segment was created above");
        pending.candidates += 1;
        match result {
            Ok(accepted) if pending.accepted.is_none() => pending.accepted = Some(accepted),
            Ok(_) => {}
            Err(detail) => pending.failures.push(detail),
        }
        Ok(())
    }

    fn authenticate_candidate(
        &mut self,
        track: ErtmpTrack,
        chunk_stream_id: u32,
        metadata_timestamp: u32,
        cose_sign1: &[u8],
    ) -> Result<Accepted, String> {
        let info = untrusted_segment_info(cose_sign1)?;
        if info.track != track {
            return Err("SegmentInfo mediaType/trackId does not match its carrying track".into());
        }
        let state = self
            .tracks
            .get(&track)
            .ok_or_else(|| "SegmentInfo track has no state".to_string())?;
        let frames = &state.frames;
        if frames.is_empty() {
            return Err("consecutive SegmentInfo candidate has no retained segment frames".into());
        }
        if frames
            .iter()
            .any(|frame| frame.chunk_stream_id != chunk_stream_id)
        {
            return Err("SegmentInfo Metadata is not on the coded frames' chunk stream".into());
        }
        if frames.last().map(|frame| frame.timestamp) != Some(metadata_timestamp) {
            return Err(
                "SegmentInfo Metadata timestamp does not equal the last frame timestamp".into(),
            );
        }
        let config = self
            .configs
            .get(&track)
            .ok_or_else(|| "SegmentInfo track has no codec configuration".to_string())?;
        if frames
            .iter()
            .any(|frame| frame.config_revision != config.revision)
        {
            return Err(
                "codec configuration changed after a segment frame and before closure".into(),
            );
        }
        if segment_digest(&info.algorithm, frames).as_deref() != Some(info.hash.as_slice()) {
            return Err("segmentHash does not match the coded frames".into());
        }

        let expected_sequence = state.last_sequence.and_then(|value| value.checked_add(1));
        if state.last_sequence.is_some() && expected_sequence != Some(info.sequence_number) {
            return Err("sequenceNumber does not increase by exactly one for this track".into());
        }

        let initialization = initialization_data(&self.configs);
        let initialization_sha256: [u8; 32] = Sha256::digest(&initialization).into();
        let delivery = self.manifests.get_mut(&info.manifest_id).ok_or_else(|| {
            "manifestId has not been delivered in c2paManifest Metadata".to_string()
        })?;
        match delivery.bound_initialization_sha256 {
            Some(bound) if bound != initialization_sha256 => {
                return Err(
                    "codec configuration differs from the configuration bound by manifestId".into(),
                )
            }
            None => {
                let report = verify_with_manifest_store(
                    &initialization,
                    &delivery.store,
                    "application/octet-stream",
                    self.options,
                )
                .map_err(|error| format!("manifest validation failed: {error}"))?;
                if report.integrity != "valid" || report.hard_binding != "match" {
                    return Err(
                        "manifest failed validation against E-RTMP initialization data".into(),
                    );
                }
                delivery.bound_initialization_sha256 = Some(initialization_sha256);
                delivery.report = Some(report);
            }
            Some(_) => {}
        }

        let validation_time = self.validation_time;
        let mut accepted_key = None;
        for key in &delivery.keys {
            let Ok(verified) =
                verify_with_cose_key_with(cose_sign1, &key.cose_key, ClaimAlgorithmList::V2_5)
            else {
                continue;
            };
            if verified.key_id.as_deref() != Some(key.key_id.as_slice())
                || verified.payload.as_slice() != info.payload.as_slice()
                || info.sequence_number < key.minimum_sequence_number
                || validation_time < key.created_at
                || validation_time > key.expires_at
            {
                continue;
            }
            if self
                .key_tracks
                .get(&key.key_id)
                .is_some_and(|owner| *owner != track)
            {
                continue;
            }
            accepted_key = Some(key.key_id.clone());
            break;
        }
        let key_id = accepted_key.ok_or_else(|| {
            "no delivered session key authenticated SegmentInfo for this track and time".to_string()
        })?;
        self.key_tracks.entry(key_id.clone()).or_insert(track);
        Ok(Accepted {
            sequence_number: info.sequence_number,
            manifest_id: info.manifest_id,
            key_id,
        })
    }

    fn finalize_pending(&mut self, track: ErtmpTrack) {
        let Some(state) = self.tracks.get_mut(&track) else {
            return;
        };
        let Some(mut pending) = state.pending.take() else {
            return;
        };
        state.frames.clear();
        let report = if let Some(accepted) = pending.accepted.take() {
            state.last_sequence = Some(accepted.sequence_number);
            ErtmpSegmentReport {
                track: pending.track,
                sequence_number: Some(accepted.sequence_number),
                manifest_id: Some(accepted.manifest_id),
                key_id: Some(hex::encode(accepted.key_id)),
                valid: true,
                failures: Vec::new(),
            }
        } else {
            if pending.failures.is_empty() {
                pending
                    .failures
                    .push("no SegmentInfo candidate authenticated".into());
            }
            ErtmpSegmentReport {
                track: pending.track,
                sequence_number: None,
                manifest_id: None,
                key_id: None,
                valid: false,
                failures: pending.failures,
            }
        };
        self.segment_reports.push(report);
    }

    fn finish(mut self) -> Result<ErtmpVerificationReport, Error> {
        let tracks: Vec<ErtmpTrack> = self.tracks.keys().copied().collect();
        for track in tracks {
            self.finalize_pending(track);
            if self
                .tracks
                .get(&track)
                .is_some_and(|state| !state.frames.is_empty())
            {
                self.fail(format!(
                    "{}:{} final logical segment has no closing SegmentInfo",
                    track.media_type.token(),
                    track.track_id
                ));
            }
        }
        if self.segment_reports.is_empty() {
            self.fail("E-RTMP input contains no closed C2PA segment");
        }
        let mut manifests: Vec<ErtmpManifestReport> = self
            .manifests
            .into_iter()
            .filter_map(|(manifest_id, delivery)| {
                delivery.report.map(|report| ErtmpManifestReport {
                    manifest_id,
                    report,
                })
            })
            .collect();
        manifests.sort_by(|left, right| left.manifest_id.cmp(&right.manifest_id));
        let valid = self.failures.is_empty()
            && self.segment_reports.iter().all(|segment| segment.valid)
            && manifests
                .iter()
                .all(|manifest| manifest.report.integrity == "valid");
        Ok(ErtmpVerificationReport {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            integrity: if valid { "valid" } else { "invalid" }.into(),
            manifests,
            segments: self.segment_reports,
            failures: self.failures,
        })
    }
}

struct SegmentInfo {
    track: ErtmpTrack,
    sequence_number: u64,
    algorithm: String,
    hash: Vec<u8>,
    manifest_id: String,
    payload: Vec<u8>,
}

fn untrusted_segment_info(cose_sign1: &[u8]) -> Result<SegmentInfo, String> {
    let decoded = decode(cose_sign1).map_err(|_| "SegmentInfo is not CBOR".to_string())?;
    let Value::Tag(18, inner) = decoded else {
        return Err("SegmentInfo is not tagged COSE_Sign1".into());
    };
    let Value::Array(mut array) = *inner else {
        return Err("SegmentInfo COSE_Sign1 shape is invalid".into());
    };
    if array.len() != 4 {
        return Err("SegmentInfo COSE_Sign1 shape is invalid".into());
    }
    let Value::Bytes(payload) = array.swap_remove(2) else {
        return Err("SegmentInfo payload is detached".into());
    };
    let Value::Map(map) =
        decode(&payload).map_err(|_| "rtmp-segment-info-map is not CBOR".to_string())?
    else {
        return Err("rtmp-segment-info-map is not a map".into());
    };
    let media_type = match unique(&map, "mediaType").and_then(Value::as_text) {
        Some("video") => ErtmpMediaType::Video,
        Some("audio") => ErtmpMediaType::Audio,
        _ => return Err("rtmp-segment-info-map mediaType is invalid".into()),
    };
    let track_id = match unique(&map, "trackId") {
        None => 0,
        Some(Value::Integer(value)) if (0..=255).contains(value) => *value as u8,
        _ => return Err("rtmp-segment-info-map trackId is invalid".into()),
    };
    let sequence_number = unsigned(unique(&map, "sequenceNumber"))
        .ok_or_else(|| "rtmp-segment-info-map sequenceNumber is invalid".to_string())?;
    let hash_map = unique(&map, "segmentHash")
        .and_then(Value::as_map)
        .ok_or_else(|| "rtmp-segment-info-map segmentHash is invalid".to_string())?;
    let algorithm = unique(hash_map, "alg")
        .and_then(Value::as_text)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "rtmp segment hash algorithm is missing".to_string())?
        .to_string();
    let hash = unique(hash_map, "hash")
        .and_then(Value::as_bytes)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "rtmp segment hash is missing".to_string())?
        .to_vec();
    let manifest_id = unique(&map, "manifestId")
        .and_then(Value::as_text)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "rtmp-segment-info-map manifestId is invalid".to_string())?
        .to_string();
    Ok(SegmentInfo {
        track: ErtmpTrack {
            media_type,
            track_id,
        },
        sequence_number,
        algorithm,
        hash,
        manifest_id,
        payload,
    })
}

fn manifest_delivery(
    manifest_store: &[u8],
    profile: EngineProfile,
) -> Result<(String, ManifestDelivery), Error> {
    let expanded = crate::c2pa_core::jumbf::expand_store(manifest_store)
        .map_err(|error| Error::Verification(error.to_string()))?;
    let parsed = crate::c2pa_core::jumbf::parse_manifest_store(expanded.bytes())
        .map_err(|error| Error::Verification(error.to_string()))?;
    let active = parsed
        .manifests
        .last()
        .ok_or_else(|| Error::Verification("c2paManifest store has no active manifest".into()))?;
    let found: Vec<_> = active
        .assertions
        .iter()
        .filter(|(label, _)| label.as_str() == "c2pa.session-keys")
        .collect();
    let [(label, assertion_cbor)] = found.as_slice() else {
        return Err(Error::Verification(
            "active E-RTMP manifest must carry exactly one c2pa.session-keys assertion".into(),
        ));
    };
    if !claim_references(active, label) {
        return Err(Error::Verification(
            "E-RTMP session-keys assertion is not claim-bound".into(),
        ));
    }
    let signer_chain = active
        .signature_cose
        .and_then(|cose| crate::c2pa_crypto::extract_x5chain(cose).ok())
        .unwrap_or_default();
    let mut results = KernelResults::default();
    let keys = validate_session_keys_with(
        LiveVideoApplicability::new(KernelStreamMethod::VerifiableSegmentInfo),
        assertion_cbor,
        &signer_chain,
        ClaimAlgorithmList::V2_5,
        &mut results,
        &format!(
            "self#jumbf=/c2pa/{}/c2pa.assertions/c2pa.session-keys",
            active.label
        ),
    );
    if !results.failure.is_empty() || keys.is_empty() {
        return Err(Error::Verification(
            results
                .failure
                .first()
                .map(|status| status.explanation.clone())
                .unwrap_or_else(|| "E-RTMP manifest has no valid session key".into()),
        ));
    }
    require_unexcluded_data_binding(manifest_store, expanded.bytes(), &parsed, profile)?;
    Ok((
        active.label.clone(),
        ManifestDelivery {
            store: manifest_store.to_vec(),
            keys,
            bound_initialization_sha256: None,
            report: None,
        },
    ))
}

fn require_unexcluded_data_binding(
    original_store: &[u8],
    _expanded_store: &[u8],
    parsed: &crate::c2pa_core::jumbf::ParsedStore<'_>,
    profile: EngineProfile,
) -> Result<(), Error> {
    let target = crate::c2pa_validate::binding_target(original_store, false, profile)
        .map_err(crate::map_validate_error)?
        .ok_or_else(|| Error::Verification("E-RTMP manifest has no unique hard binding".into()))?;
    if target.binding_assertion_label != "c2pa.hash.data"
        && !target
            .binding_assertion_label
            .starts_with("c2pa.hash.data__")
    {
        return Err(Error::Verification(
            "E-RTMP manifest hard binding is not c2pa.hash.data".into(),
        ));
    }
    let manifest = parsed
        .manifests
        .iter()
        .find(|manifest| manifest.label == target.binding_manifest_label)
        .ok_or_else(|| Error::Verification("binding manifest is absent".into()))?;
    let assertion = manifest
        .assertions
        .iter()
        .find(|(label, _)| label.as_str() == target.binding_assertion_label.as_str())
        .and_then(|(_, bytes)| decode(bytes).ok())
        .ok_or_else(|| Error::Verification("E-RTMP data hash is not decodable".into()))?;
    let map = assertion
        .as_map()
        .ok_or_else(|| Error::Verification("E-RTMP data hash is not a map".into()))?;
    if unique(map, "exclusions").is_some() {
        return Err(Error::Verification(
            "E-RTMP initialization data hash must not contain an exclusions field".into(),
        ));
    }
    Ok(())
}

fn claim_references(manifest: &crate::c2pa_core::jumbf::ParsedManifest<'_>, label: &str) -> bool {
    let Some(claim) = manifest.claim_cbor.and_then(|bytes| decode(bytes).ok()) else {
        return false;
    };
    ["assertions", "created_assertions", "gathered_assertions"]
        .iter()
        .filter_map(|field| match claim.get(field) {
            Some(Value::Array(entries)) => Some(entries.as_slice()),
            _ => None,
        })
        .flatten()
        .filter_map(|entry| entry.get("url").and_then(Value::as_text))
        .any(|url| url.rsplit('/').next() == Some(label))
}

fn initialization_data(configs: &BTreeMap<ErtmpTrack, Config<'_>>) -> Vec<u8> {
    let total = configs.values().map(|config| config.payload.len()).sum();
    let mut bytes = Vec::with_capacity(total);
    for config in configs.values() {
        bytes.extend_from_slice(config.payload);
    }
    bytes
}

fn segment_digest(algorithm: &str, frames: &[Frame<'_>]) -> Option<Vec<u8>> {
    macro_rules! digest {
        ($hasher:ty) => {{
            let mut hasher = <$hasher>::new();
            for frame in frames {
                hasher.update(frame.timestamp.to_be_bytes());
                let offset = frame.composition_time_offset as u32;
                hasher.update([
                    ((offset >> 16) & 0xff) as u8,
                    ((offset >> 8) & 0xff) as u8,
                    (offset & 0xff) as u8,
                ]);
                hasher.update(frame.coded_data);
            }
            Some(hasher.finalize().to_vec())
        }};
    }
    match algorithm.to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" => digest!(Sha256),
        "sha384" | "sha-384" => digest!(Sha384),
        "sha512" | "sha-512" => digest!(Sha512),
        _ => None,
    }
}

fn unique<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut values = map
        .iter()
        .filter(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn unsigned(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Integer(value)) if *value >= 0 => u64::try_from(*value).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_data_is_video_then_audio_in_ascending_track_order() {
        let mut configs = BTreeMap::new();
        let entries = [
            (
                ErtmpTrack {
                    media_type: ErtmpMediaType::Audio,
                    track_id: 2,
                },
                b"a2".as_slice(),
            ),
            (
                ErtmpTrack {
                    media_type: ErtmpMediaType::Video,
                    track_id: 1,
                },
                b"v1".as_slice(),
            ),
            (
                ErtmpTrack {
                    media_type: ErtmpMediaType::Audio,
                    track_id: 0,
                },
                b"a0".as_slice(),
            ),
            (
                ErtmpTrack {
                    media_type: ErtmpMediaType::Video,
                    track_id: 0,
                },
                b"v0".as_slice(),
            ),
        ];
        for (revision, (track, payload)) in entries.into_iter().enumerate() {
            configs.insert(
                track,
                Config {
                    chunk_stream_id: 4,
                    payload,
                    revision: revision as u64,
                },
            );
        }
        assert_eq!(initialization_data(&configs), b"v0v1a0a2");
    }

    #[test]
    fn segment_hash_covers_timestamp_signed_cto_and_coded_bytes() {
        let frame = Frame {
            chunk_stream_id: 6,
            timestamp: 0x0102_0304,
            composition_time_offset: -2,
            coded_data: b"frame",
            config_revision: 1,
        };
        let expected =
            Sha256::digest([&[0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xfe][..], b"frame"].concat())
                .to_vec();
        assert_eq!(segment_digest("sha256", &[frame]), Some(expected));
    }

    #[test]
    fn ertmp_refuses_non_25_policy_before_event_processing() {
        let input = ErtmpInput {
            client_caps_ex: C2PA_CAPABILITY,
            server_caps_ex: C2PA_CAPABILITY,
            object_encoding: 3,
            events: Vec::new(),
        };
        let options = VerifyOptions {
            spec_version: Some("2.2".into()),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            verify_ertmp_with_options(&input, &options),
            Err(Error::UnsupportedSpecVersion(_))
        ));
    }
}
