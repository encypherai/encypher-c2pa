// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Fragmented and live-stream verification.
//!
//! [`verify_fragmented`](crate::verify_fragmented) answers one question: does
//! this Merkle-bound stream's init segment bind the fragments I was given? It
//! now fails closed when the answer is "this manifest binds no fragments at
//! all". [`verify_stream`] is the entry a live pipeline wants: it takes the
//! encapsulation and protection method the packager declared, gates the
//! declared brands, and then reads the INIT MANIFEST - never the caller - to
//! decide whether the segments are authenticated by C2PA 2.4 session keys, by a
//! Merkle tree, or one manifest at a time.

use serde::{Deserialize, Serialize};

use crate::c2pa_formats::{
    StreamEncapsulation as KernelEncapsulation, StreamMethod as KernelMethod,
};
use crate::c2pa_validate::stream::{verify_stream_safe_with_expected_seeks, StreamVerifyOutput};
use crate::online::{self, NetworkNeed};
use crate::{
    map_validate_error, report_from_output, resolve_mime, Error, NetworkReport, ResolvedOptions,
    VerificationReport, VerifyOptions, REPORT_SCHEMA_VERSION,
};

/// How a fragmented stream is packaged.
///
/// The serialized form is the C2PA Conformance Program 0.2 Generator Product
/// spelling, so a declaration round-trips through the conforming-products list
/// unchanged. [`Self::from_token`] is ASCII case-insensitive, so a lowercase
/// CLI flag or JSON value resolves to the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamEncapsulation {
    /// Fragmented MP4: an ISOBMFF init segment plus movie-fragment media
    /// segments (DASH/HLS packaging).
    #[serde(rename = "fMP4")]
    Fmp4,
    /// Common Media Application Format, a strict profile of fragmented MP4.
    #[serde(rename = "CMAF")]
    Cmaf,
}

impl StreamEncapsulation {
    /// The declaration token (`"fMP4"`, `"CMAF"`).
    pub const fn token(self) -> &'static str {
        self.kernel().token()
    }

    /// Resolve a declaration token, ASCII case-insensitively.
    pub fn from_token(token: &str) -> Option<Self> {
        KernelEncapsulation::from_token(token).map(|value| match value {
            KernelEncapsulation::Fmp4 => Self::Fmp4,
            KernelEncapsulation::Cmaf => Self::Cmaf,
        })
    }

    const fn kernel(self) -> KernelEncapsulation {
        match self {
            Self::Fmp4 => KernelEncapsulation::Fmp4,
            Self::Cmaf => KernelEncapsulation::Cmaf,
        }
    }
}

impl std::fmt::Display for StreamEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// The C2PA protection method applied to a fragmented stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamMethod {
    /// One manifest in the init segment binds every media segment. Which
    /// binding it used - a C2PA 2.4 `c2pa.session-keys` delivery whose segments
    /// carry signed `emsg` verifiable segment information, or a
    /// `c2pa.hash.bmff.v3` Merkle tree whose segments carry an auxiliary
    /// `merkle` box - is read off that manifest, not declared by the caller.
    #[serde(rename = "verifiable-segment-info")]
    VerifiableSegmentInfo,
    /// Every segment is an independently signed BMFF asset carrying its own
    /// manifest, linked to its predecessor by a `parentOf` ingredient.
    #[serde(rename = "per-segment")]
    PerSegment,
}

impl StreamMethod {
    /// The declaration token (`"verifiable-segment-info"`, `"per-segment"`).
    pub const fn token(self) -> &'static str {
        self.kernel().token()
    }

    /// Resolve a declaration token, ASCII case-insensitively.
    pub fn from_token(token: &str) -> Option<Self> {
        KernelMethod::from_token(token).map(|value| match value {
            KernelMethod::VerifiableSegmentInfo => Self::VerifiableSegmentInfo,
            KernelMethod::PerSegment => Self::PerSegment,
        })
    }

    const fn kernel(self) -> KernelMethod {
        match self {
            Self::VerifiableSegmentInfo => KernelMethod::VerifiableSegmentInfo,
            Self::PerSegment => KernelMethod::PerSegment,
        }
    }
}

impl std::fmt::Display for StreamMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// One per-segment stream position, verified as a standalone asset.
#[derive(Debug, Clone, Serialize)]
pub struct SegmentReport {
    /// Zero-based position in the presented stream. The init segment is 0.
    pub sequence_number: usize,
    /// Active manifest label read from this segment, empty when it carries none.
    pub manifest_label: String,
    /// The predecessor this segment names, when it declares one.
    pub previous_manifest_label: Option<String>,
    /// What a consumer that received only this segment would see.
    pub report: VerificationReport,
}

/// Result of [`verify_stream`].
///
/// `schema_version` tracks [`VerificationReport`]'s, and each embedded report
/// is an ordinary report with the same schema, so an existing consumer can read
/// them without change.
#[derive(Debug, Clone, Serialize)]
pub struct StreamVerificationReport {
    /// Report schema version, matching [`VerificationReport::schema_version`].
    pub schema_version: String,
    /// The encapsulation the stream was verified under.
    pub encapsulation: StreamEncapsulation,
    /// The method the stream was verified under.
    pub method: StreamMethod,
    /// `"valid"` only when every presented byte was bound: for
    /// [`StreamMethod::VerifiableSegmentInfo`] the init manifest's own
    /// integrity (which now carries every segment's result); for
    /// [`StreamMethod::PerSegment`] every segment's integrity AND the
    /// recomputed chain.
    pub integrity: String,
    /// The init manifest's report, for [`StreamMethod::VerifiableSegmentInfo`].
    pub stream: Option<VerificationReport>,
    /// Per-segment reports, for [`StreamMethod::PerSegment`].
    pub segments: Vec<SegmentReport>,
    /// Whether the prior-manifest chain recomputed, for
    /// [`StreamMethod::PerSegment`]. `None` for the other method, which has no
    /// chain.
    pub chain_valid: Option<bool>,
    /// Why `chain_valid` is false, in stream order.
    pub chain_failures: Vec<String>,
    /// What this verification did, or could have done, on the network.
    pub network: NetworkReport,
}

impl StreamVerificationReport {
    /// Serialize as compact JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(Error::Serialize)
    }

    /// Serialize as indented JSON.
    pub fn to_pretty_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(Error::Serialize)
    }
}

/// Verify a fragmented ISO BMFF stream under a declared encapsulation and
/// protection method, with default options.
pub fn verify_stream(
    init_segment: &[u8],
    segments: &[&[u8]],
    mime_type: &str,
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
) -> Result<StreamVerificationReport, Error> {
    verify_stream_with_options(
        init_segment,
        segments,
        mime_type,
        encapsulation,
        method,
        &VerifyOptions::default(),
    )
}

/// Verify a fragmented ISO BMFF stream with explicit trust, validation-time,
/// and CAWG options.
///
/// `init_segment` is the stream's initialization segment. For
/// [`StreamMethod::VerifiableSegmentInfo`] it carries the one manifest that
/// binds the whole stream and `segments` are its media segments; for
/// [`StreamMethod::PerSegment`] it is chain position 0 and `segments` follow it
/// in playback order.
///
/// Both files' declared brands are gated against `encapsulation` first, so a
/// stream presented as CMAF whose bytes are plain fMP4 is refused rather than
/// verified under a declaration its bytes do not support. The brand gate is a
/// C2PA Conformance Program 0.2 requirement, not a C2PA 2.4 rule.
///
/// [`VerifyOptions::expected_seek_positions`] marks intentional discontinuities
/// by their zero-based indexes into `segments`.
pub fn verify_stream_with_options(
    init_segment: &[u8],
    segments: &[&[u8]],
    mime_type: &str,
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    options: &VerifyOptions,
) -> Result<StreamVerificationReport, Error> {
    verify_stream_with_options_and_expected_seeks(
        init_segment,
        segments,
        &options.expected_seek_positions,
        mime_type,
        encapsulation,
        method,
        options,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_stream_with_options_and_expected_seeks(
    init_segment: &[u8],
    segments: &[&[u8]],
    expected_seek_positions: &[usize],
    mime_type: &str,
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    options: &VerifyOptions,
) -> Result<StreamVerificationReport, Error> {
    let mime = resolve_mime(mime_type)?;
    if crate::c2pa_formats::AssetFormat::from_mime(&mime)
        != Some(crate::c2pa_formats::AssetFormat::Bmff)
    {
        return Err(Error::UnsupportedMime(mime));
    }
    let (mut report, needs) = stream_pass(
        init_segment,
        segments,
        expected_seek_positions,
        &mime,
        encapsulation,
        method,
        options,
    )?;
    let (network, evidence) = online::gather(options, &needs);
    if evidence.is_empty() {
        report.network = network;
        return Ok(report);
    }
    // A stream carries its manifest in the init segment, so a remote manifest
    // declaration does not apply here; the rest of the evidence does.
    let next = online::apply_evidence(options, &evidence);
    let (mut report, _) = stream_pass(
        init_segment,
        segments,
        expected_seek_positions,
        &mime,
        encapsulation,
        method,
        &next,
    )?;
    report.network = network;
    Ok(report)
}

/// One offline stream verification, with the network needs it recorded.
#[allow(clippy::too_many_arguments)]
fn stream_pass(
    init_segment: &[u8],
    segments: &[&[u8]],
    expected_seek_positions: &[usize],
    mime: &str,
    encapsulation: StreamEncapsulation,
    method: StreamMethod,
    options: &VerifyOptions,
) -> Result<(StreamVerificationReport, Vec<NetworkNeed>), Error> {
    let mime = mime.to_string();
    let resolved = ResolvedOptions::resolve(options)?;
    let output = verify_stream_safe_with_expected_seeks(
        &resolved.input(init_segment, &mime),
        init_segment,
        segments,
        expected_seek_positions,
        encapsulation.kernel(),
        method.kernel(),
        resolved.cawg_trust(),
        resolved.cawg_allowed_certs(),
        true,
        options.cawg_did_documents.as_ref(),
        options.cawg_ica_trusted_issuers.as_deref(),
        options.cawg_ica_trust_anchors.as_deref(),
        options.cawg_ica_status_lists.as_ref(),
    )
    .map_err(map_validate_error)?;

    Ok(match output {
        StreamVerifyOutput::VerifiableSegmentInfo(stream) => {
            let needs = online::network_needs(&stream);
            let report = report_from_output(*stream, mime, &resolved);
            (
                StreamVerificationReport {
                    schema_version: REPORT_SCHEMA_VERSION.to_string(),
                    encapsulation,
                    method,
                    integrity: report.integrity.clone(),
                    stream: Some(report),
                    segments: Vec::new(),
                    chain_valid: None,
                    chain_failures: Vec::new(),
                    network: NetworkReport::default(),
                },
                needs,
            )
        }
        StreamVerifyOutput::PerSegment(per_segment) => {
            let mut needs = Vec::new();
            let segments: Vec<SegmentReport> = per_segment
                .segments
                .into_iter()
                .map(|segment| {
                    needs.extend(online::network_needs(&segment.output));
                    SegmentReport {
                        sequence_number: segment.sequence_number,
                        manifest_label: segment.manifest_label,
                        previous_manifest_label: segment.previous_manifest_label,
                        report: report_from_output(segment.output, mime.clone(), &resolved),
                    }
                })
                .collect();
            // A per-segment stream is only as good as its weakest link: one
            // segment that does not verify, or one broken chain link, means the
            // stream as presented is not the stream that was signed.
            let integrity = if per_segment.chain_valid
                && segments
                    .iter()
                    .all(|segment| segment.report.integrity == "valid")
            {
                "valid"
            } else {
                "invalid"
            };
            (
                StreamVerificationReport {
                    schema_version: REPORT_SCHEMA_VERSION.to_string(),
                    encapsulation,
                    method,
                    integrity: integrity.to_string(),
                    stream: None,
                    segments,
                    chain_valid: Some(per_segment.chain_valid),
                    chain_failures: per_segment.chain_failures,
                    network: NetworkReport::default(),
                },
                needs,
            )
        }
    })
}
