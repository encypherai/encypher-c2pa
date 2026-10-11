// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! WARC 1.1 (`application/warc`): the C2PA Manifest Store is the block of one
//! final `c2pa-provenance` record, and every other record is bound by a
//! collection data hash (C2PA 2.5, "Embedding manifests into WARC files";
//! Validation, "Special Considerations for WARC" and "Hashing of WARC files").
//!
//! This module reads only. [`WarcArchive::parse`] accepts every stored form
//! the specification names, detected from the leading bytes:
//!
//! - uncompressed WARC, borrowed without copying;
//! - gzip, as a sequence of RFC 1952 members, either one member per record
//!   (WARC 1.1 Annex D) or one stream for the whole file;
//! - WARC-zstd (IIPC "Zstandard Compression for WARC Files" 1.0), including the
//!   shared-dictionary profile (a leading `0x184D2A5D` dictionary frame, raw or
//!   compressed) and the seekable profile (a final Zstandard seek table, which
//!   is checked against the frames it indexes).
//!
//! Compressed input is decoded once into an owned buffer. Every decoder is
//! bounded by [`WarcLimits`]: total decompressed bytes, per-record size,
//! Zstandard window, dictionary size and header size. gzip CRC-32/ISIZE and
//! Zstandard `Content_Checksum`/`Frame_Content_Size` are verified.
//!
//! Records are parsed with the `warc-record` grammar: version line, header
//! fields, blank line, `Content-Length` block bytes and the two terminating
//! CRLF sequences. The bytes of a member, as hashed by the collection, run
//! from the first byte of the version line through those two CRLFs.
//!
//! A compressed record whose decompressed block length differs from its
//! `Content-Length`, or whose decompressed size exceeds the record limit, is
//! kept as a defective member when its compression unit marks where it ends.
//! The manifest stays locatable and [`verify_collection`] rejects the binding,
//! which is the outcome the validation clause prescribes
//! (`assertion.collectionHash.mismatch`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use ruzstd::decoding::{BlockDecodingStrategy, Dictionary, FrameDecoder};

use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Warc;

const PROVENANCE_TYPE: &[u8] = b"c2pa-provenance";
const PROVENANCE_CONTENT_TYPE: &[u8] = b"application/c2pa";
const RECORD_TERMINATOR: &[u8] = b"\r\n\r\n";

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const GZIP_DEFLATE: u8 = 8;
const GZIP_FHCRC: u8 = 0x02;
const GZIP_FEXTRA: u8 = 0x04;
const GZIP_FNAME: u8 = 0x08;
const GZIP_FCOMMENT: u8 = 0x10;
const GZIP_RESERVED: u8 = 0xe0;
const INFLATE_CHUNK: usize = 64 * 1024;

const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;
const ZSTD_DICTIONARY_MAGIC: u32 = 0xEC30_A437;
const SKIPPABLE_MAGIC_MIN: u32 = 0x184D_2A50;
const SKIPPABLE_MAGIC_MAX: u32 = 0x184D_2A5F;
const DICTIONARY_FRAME_MAGIC: u32 = 0x184D_2A5D;
const SEEK_TABLE_FRAME_MAGIC: u32 = 0x184D_2A5E;
const SEEKABLE_FOOTER_MAGIC: u32 = 0x8F92_EAB1;
const SEEK_TABLE_FOOTER_LEN: usize = 9;
const SEEK_TABLE_CHECKSUM_FLAG: u8 = 0x80;
const SEEK_TABLE_RESERVED_BITS: u8 = 0x7c;
const ZSTD_MAX_BLOCK: u64 = 128 * 1024;
const ZSTD_DRAIN_STEP: usize = 1 << 20;
/// Low 32 bits of XXH64 over zero bytes: the seek-table checksum of a frame
/// that decompresses to nothing (skippable or empty frames).
const XXH64_EMPTY_LOW32: u32 = 0x51D8_E999;

/// WARC 1.1 defined fields. The first [`INTERPRETED_FIELDS`] are read by this
/// module and may not be folded over several lines.
const DEFINED_FIELDS: [&str; 21] = [
    "warc-type",
    "warc-record-id",
    "warc-date",
    "content-length",
    "content-type",
    "warc-target-uri",
    "warc-concurrent-to",
    "warc-block-digest",
    "warc-payload-digest",
    "warc-ip-address",
    "warc-refers-to",
    "warc-refers-to-target-uri",
    "warc-refers-to-date",
    "warc-truncated",
    "warc-warcinfo-id",
    "warc-filename",
    "warc-profile",
    "warc-identified-payload-type",
    "warc-segment-origin-id",
    "warc-segment-number",
    "warc-segment-total-length",
];
const FIELD_TYPE: usize = 0;
const FIELD_RECORD_ID: usize = 1;
const FIELD_DATE: usize = 2;
const FIELD_CONTENT_LENGTH: usize = 3;
const FIELD_CONTENT_TYPE: usize = 4;
const FIELD_TARGET_URI: usize = 5;
/// WARC 1.1 permits `WARC-Concurrent-To` to repeat; no other defined field.
const FIELD_CONCURRENT_TO: usize = 6;
const INTERPRETED_FIELDS: usize = 5;

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n: u32 = 0;
    while n < 256 {
        let mut c = n;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n as usize] = c;
        n += 1;
    }
    table
};

/// Resource bounds for decoding an untrusted WARC file.
///
/// The validation clause requires an implementation-defined maximum
/// decompressed record size; the other bounds keep total memory, Zstandard
/// window allocation, dictionary loading and header scanning finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WarcLimits {
    /// Largest decompressed record, version line through terminating CRLFs.
    pub max_record_bytes: usize,
    /// Largest total decompressed stream of a compressed file.
    pub max_archive_bytes: usize,
    /// Largest record header (version line through the blank line).
    pub max_header_bytes: usize,
    /// Largest Zstandard `Window_Size` accepted.
    pub max_window_bytes: u64,
    /// Largest WARC-zstd dictionary, stored and decompressed.
    pub max_dictionary_bytes: usize,
}

impl WarcLimits {
    /// 1 GiB records, 4 GiB of decompressed archive, 1 MiB headers, the
    /// 128 MiB Zstandard long-distance window and the 8 MiB dictionary size
    /// every WARC-zstd decoder must support.
    pub const DEFAULT: Self = Self {
        max_record_bytes: 1 << 30,
        max_archive_bytes: u32::MAX as usize,
        max_header_bytes: 1 << 20,
        max_window_bytes: 1 << 27,
        max_dictionary_bytes: 1 << 23,
    };
}

/// Why a decompressed record fails the bounds of the validation clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordDefect {
    /// The decompressed record exceeds [`WarcLimits::max_record_bytes`].
    TooLarge,
    /// The decompressed block length differs from the declared
    /// `Content-Length`.
    ContentLengthMismatch,
}

/// Why a collection data hash does not bind a WARC file. Every variant is an
/// `assertion.collectionHash.mismatch` under the validation clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WarcCollectionFailure {
    /// The file has no single C2PA manifest record, so no collection exists.
    ManifestNotLocated,
    /// A record failed decompression bounds or its `Content-Length`.
    RecordDefect {
        record_id: String,
        defect: RecordDefect,
    },
    /// Two records other than the manifest record share a `WARC-Record-ID`.
    DuplicateRecordId(String),
    /// Two collection entries name the same record.
    DuplicateEntry(String),
    /// A collection entry names no record in the file.
    MissingRecord(String),
    /// A record in the file is named by no collection entry.
    UnlistedRecord(String),
    /// A record's bytes do not hash to its entry's value.
    HashMismatch(String),
}

impl fmt::Display for WarcCollectionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestNotLocated => f.write_str("WARC file has no single C2PA manifest record"),
            Self::RecordDefect { record_id, defect } => match defect {
                RecordDefect::TooLarge => write!(
                    f,
                    "WARC record '{record_id}' exceeds the decompressed record limit"
                ),
                RecordDefect::ContentLengthMismatch => write!(
                    f,
                    "WARC record '{record_id}' decompressed block length differs from its Content-Length"
                ),
            },
            Self::DuplicateRecordId(id) => write!(f, "WARC-Record-ID '{id}' appears more than once"),
            Self::DuplicateEntry(id) => write!(f, "collection lists WARC record '{id}' more than once"),
            Self::MissingRecord(id) => write!(f, "collection entry '{id}' matches no WARC record"),
            Self::UnlistedRecord(id) => write!(f, "WARC record '{id}' is not covered by the collection"),
            Self::HashMismatch(id) => write!(f, "WARC record '{id}' hash mismatch"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitKind {
    Gzip,
    ZstdFrame { checksum: u32 },
    Dictionary,
    Skippable,
    SeekTable,
}

/// One self-delimiting compression unit: its stored bytes in the input and
/// the decompressed bytes it contributes to the stream.
#[derive(Debug, Clone, Copy)]
struct Unit {
    kind: UnitKind,
    stored: (usize, usize),
    output: (usize, usize),
}

#[derive(Debug, Clone, Copy)]
struct Record {
    span: (usize, usize),
    block: (usize, usize),
    record_id: (usize, usize),
    date: (usize, usize),
    has_target_uri: bool,
    provenance: bool,
    defect: Option<RecordDefect>,
}

#[derive(Debug, Clone, Copy)]
enum Located {
    None,
    One(usize),
    Ambiguous,
}

/// A parsed WARC file. Raw input is borrowed; compressed input is decoded
/// once into an owned buffer that every accessor borrows from.
pub(crate) struct WarcArchive<'a> {
    stream: Cow<'a, [u8]>,
    records: Vec<Record>,
    manifest: Located,
    duplicate_record_id: Option<usize>,
}

impl<'a> WarcArchive<'a> {
    /// Parse `data` under [`WarcLimits::DEFAULT`].
    pub fn parse(data: &'a [u8]) -> Result<Self, FormatError> {
        Self::parse_with_limits(data, WarcLimits::DEFAULT)
    }

    /// Parse `data` under explicit resource bounds.
    pub fn parse_with_limits(data: &'a [u8], limits: WarcLimits) -> Result<Self, FormatError> {
        let first = le_u32(data, 0);
        let (stream, units, zstd) = if data.starts_with(&GZIP_MAGIC) {
            let (stream, units) = decode_gzip(data, &limits)?;
            (Cow::Owned(stream), units, false)
        } else if first == Some(ZSTD_FRAME_MAGIC) || first == Some(DICTIONARY_FRAME_MAGIC) {
            let (stream, units) = decode_zstd(data, &limits)?;
            (Cow::Owned(stream), units, true)
        } else {
            (Cow::Borrowed(data), Vec::new(), false)
        };
        let records = parse_records(&stream, &units, &limits)?;
        if zstd && !records_aligned(&records, &units, stream.len()) {
            return Err(invalid(
                "a Zstandard frame contains data from more than one WARC record",
            ));
        }

        let mut provenance = records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.provenance)
            .map(|(index, _)| index);
        let manifest = match (provenance.next(), provenance.next()) {
            (None, _) => Located::None,
            (Some(index), None) => Located::One(index),
            (Some(_), Some(_)) => Located::Ambiguous,
        };
        if let Located::One(index) = manifest {
            let record = &records[index];
            match record.defect {
                Some(RecordDefect::TooLarge) => {
                    return Err(unsupported(
                        "C2PA manifest record exceeds the decompressed record limit",
                    ));
                }
                Some(RecordDefect::ContentLengthMismatch) => {
                    return Err(invalid(
                        "C2PA manifest record block differs from its Content-Length",
                    ));
                }
                None => {}
            }
            if record.block.0 == record.block.1 {
                return Err(invalid("C2PA manifest record has an empty block"));
            }
        }

        let duplicate_record_id = {
            let mut seen: HashSet<&[u8]> = HashSet::with_capacity(records.len());
            records.iter().enumerate().find_map(|(index, record)| {
                let id = &stream[record.record_id.0..record.record_id.1];
                (!record.provenance && !seen.insert(id)).then_some(index)
            })
        };

        Ok(Self {
            stream,
            records,
            manifest,
            duplicate_record_id,
        })
    }

    /// The C2PA Manifest Store: the block of the only C2PA manifest record.
    /// `None` when there is no such record or more than one, which the locator
    /// clause treats as no manifest.
    pub fn manifest_store(&self) -> Option<&[u8]> {
        match self.manifest {
            Located::One(index) => Some(self.bytes(self.records[index].block)),
            Located::None | Located::Ambiguous => None,
        }
    }

    /// Collection members in file order: every record that is not a C2PA
    /// manifest record, as `(WARC-Record-ID without angle brackets,
    /// uncompressed record bytes)`.
    pub fn members(&self) -> impl Iterator<Item = (&str, &[u8])> + '_ {
        self.records
            .iter()
            .filter(|record| !record.provenance)
            .map(move |record| (self.text(record.record_id), self.bytes(record.span)))
    }

    /// The first `WARC-Record-ID` shared by two collection members.
    pub fn duplicate_record_id(&self) -> Option<&str> {
        self.duplicate_record_id
            .map(|index| self.text(self.records[index].record_id))
    }

    /// A carrier rule the located manifest record breaks: it must be the last
    /// record, must not carry `WARC-Target-URI`, and its `WARC-Date` must be a
    /// WARC timestamp.
    pub fn placement_error(&self) -> Option<&'static str> {
        let Located::One(index) = self.manifest else {
            return None;
        };
        let record = &self.records[index];
        if index + 1 != self.records.len() {
            Some("C2PA manifest record is not the last WARC record")
        } else if record.has_target_uri {
            Some("C2PA manifest record carries a WARC-Target-URI field")
        } else if !is_w3cdtf_utc(self.bytes(record.date)) {
            Some("C2PA manifest record WARC-Date is not a UTC W3CDTF timestamp")
        } else {
            None
        }
    }

    fn bytes(&self, span: (usize, usize)) -> &[u8] {
        &self.stream[span.0..span.1]
    }

    fn text(&self, span: (usize, usize)) -> &str {
        std::str::from_utf8(self.bytes(span)).expect("record identifiers are validated ASCII")
    }

    fn defect(&self) -> Option<(&str, RecordDefect)> {
        self.records
            .iter()
            .filter(|record| !record.provenance)
            .find_map(|record| {
                record
                    .defect
                    .map(|defect| (self.text(record.record_id), defect))
            })
    }
}

/// Extract the C2PA Manifest Store, or `None` when the file has no C2PA
/// manifest record or more than one.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    Ok(WarcArchive::parse(data)?
        .manifest_store()
        .map(<[u8]>::to_vec))
}

/// WARC binds with a collection data hash, never a data hash: no exclusions.
pub(crate) fn exclusions(_data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    Ok(Vec::new())
}

/// The carrier rule the located C2PA manifest record breaks, if any.
pub(crate) fn placement_error(data: &[u8]) -> Result<Option<&'static str>, FormatError> {
    Ok(WarcArchive::parse(data)?.placement_error())
}

/// Check a collection data hash against the file, in the order the validation
/// clause prescribes: decompression bounds, unique record identifiers, then a
/// bijection between collection entries and records with matching hashes.
///
/// `entries` are the `(uri, hash)` pairs of the assertion; the caller has
/// already resolved the algorithm and rejected malformed URIs. `hash` computes
/// that algorithm over a record. Returns the number of records bound.
pub(crate) fn verify_collection<'e>(
    archive: &WarcArchive<'_>,
    entries: impl IntoIterator<Item = (&'e str, &'e [u8])>,
    mut hash: impl FnMut(&[u8]) -> Vec<u8>,
) -> Result<usize, WarcCollectionFailure> {
    if !matches!(archive.manifest, Located::One(_)) {
        return Err(WarcCollectionFailure::ManifestNotLocated);
    }
    if let Some((record_id, defect)) = archive.defect() {
        return Err(WarcCollectionFailure::RecordDefect {
            record_id: record_id.to_string(),
            defect,
        });
    }
    if let Some(id) = archive.duplicate_record_id() {
        return Err(WarcCollectionFailure::DuplicateRecordId(id.to_string()));
    }
    let mut members: HashMap<&str, (&[u8], bool)> = archive
        .members()
        .map(|(id, bytes)| (id, (bytes, false)))
        .collect();
    for (uri, expected) in entries {
        let Some((bytes, covered)) = members.get_mut(uri) else {
            return Err(WarcCollectionFailure::MissingRecord(uri.to_string()));
        };
        if *covered {
            return Err(WarcCollectionFailure::DuplicateEntry(uri.to_string()));
        }
        *covered = true;
        if hash(bytes).as_slice() != expected {
            return Err(WarcCollectionFailure::HashMismatch(uri.to_string()));
        }
    }
    if let Some((id, _)) = archive
        .members()
        .find(|(id, _)| members.get(id).is_some_and(|(_, covered)| !covered))
    {
        return Err(WarcCollectionFailure::UnlistedRecord(id.to_string()));
    }
    Ok(members.len())
}

// ---------------------------------------------------------------------------
// Record grammar
// ---------------------------------------------------------------------------

struct Header {
    block_start: usize,
    content_length: usize,
    record_id: (usize, usize),
    warc_type: (usize, usize),
    content_type: Option<(usize, usize)>,
    date: (usize, usize),
    has_target_uri: bool,
}

#[derive(Clone, Copy)]
enum PreviousField {
    None,
    Defined(usize),
    Extension,
}

fn parse_records(
    stream: &[u8],
    units: &[Unit],
    limits: &WarcLimits,
) -> Result<Vec<Record>, FormatError> {
    if stream.is_empty() {
        return Err(invalid("WARC file contains no records"));
    }
    let compressed = !units.is_empty();
    let unit_starts: Vec<usize> = units
        .iter()
        .filter(|unit| unit.output.0 != unit.output.1)
        .map(|unit| unit.output.0)
        .collect();
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < stream.len() {
        let header = parse_header(stream, pos, limits)?;
        let (end, mut defect) = match complete_end(stream, &header) {
            Some(end) => (end, None),
            None if compressed && unit_starts.binary_search(&pos).is_ok() => {
                // The record begins a compression unit, so the unit boundaries
                // mark where it ends even though its Content-Length does not.
                let after = unit_starts.partition_point(|&start| start <= header.block_start);
                let end = unit_starts[after..]
                    .iter()
                    .copied()
                    .find(|&start| stream[start..].starts_with(b"WARC/"))
                    .unwrap_or(stream.len());
                (end, Some(RecordDefect::ContentLengthMismatch))
            }
            None => {
                return Err(
                    if header.block_start.saturating_add(header.content_length) >= stream.len() {
                        truncated()
                    } else {
                        invalid("WARC record block is not followed by two CRLF sequences")
                    },
                );
            }
        };
        if compressed && end - pos > limits.max_record_bytes {
            defect = Some(RecordDefect::TooLarge);
        }
        let block_end = header
            .block_start
            .saturating_add(header.content_length)
            .min(end);
        let provenance = &stream[header.warc_type.0..header.warc_type.1] == PROVENANCE_TYPE
            && header.content_type.is_some_and(|(start, end)| {
                stream[start..end].eq_ignore_ascii_case(PROVENANCE_CONTENT_TYPE)
            });
        records.push(Record {
            span: (pos, end),
            block: (header.block_start, block_end),
            record_id: header.record_id,
            date: header.date,
            has_target_uri: header.has_target_uri,
            provenance,
            defect,
        });
        pos = end;
    }
    Ok(records)
}

fn complete_end(stream: &[u8], header: &Header) -> Option<usize> {
    let block_end = header.block_start.checked_add(header.content_length)?;
    let end = block_end.checked_add(RECORD_TERMINATOR.len())?;
    (stream.get(block_end..end)? == RECORD_TERMINATOR).then_some(end)
}

fn parse_header(stream: &[u8], start: usize, limits: &WarcLimits) -> Result<Header, FormatError> {
    let limit = stream
        .len()
        .min(start.saturating_add(limits.max_header_bytes));
    let eol = line_end(stream, start, limit)?;
    match &stream[start..eol] {
        b"WARC/1.1" | b"WARC/1.0" => {}
        version if version.starts_with(b"WARC/") => {
            return Err(unsupported("WARC version other than 1.0 or 1.1"));
        }
        _ => return Err(invalid("WARC record does not begin with a version line")),
    }
    let mut seen = [false; DEFINED_FIELDS.len()];
    let mut values: [Option<(usize, usize)>; INTERPRETED_FIELDS] = [None; INTERPRETED_FIELDS];
    let mut previous = PreviousField::None;
    let mut cursor = eol + 2;
    loop {
        let eol = line_end(stream, cursor, limit)?;
        let line = &stream[cursor..eol];
        if line.is_empty() {
            cursor = eol + 2;
            break;
        }
        if matches!(line[0], b' ' | b'\t') {
            match previous {
                PreviousField::None => {
                    return Err(invalid("WARC header continuation line without a field"));
                }
                PreviousField::Defined(index) if index < INTERPRETED_FIELDS => {
                    return Err(invalid("WARC header field read by C2PA is folded"));
                }
                PreviousField::Defined(_) | PreviousField::Extension => {}
            }
        } else {
            let colon = line
                .iter()
                .position(|&byte| byte == b':')
                .ok_or_else(|| invalid("WARC header field without a colon"))?;
            let name = &line[..colon];
            if !is_token(name) {
                return Err(invalid("WARC header field name is not a token"));
            }
            let (value_start, value_end) = trim_lws(line, colon + 1);
            previous = match DEFINED_FIELDS
                .iter()
                .position(|field| name.eq_ignore_ascii_case(field.as_bytes()))
            {
                Some(index) => {
                    if seen[index] && index != FIELD_CONCURRENT_TO {
                        return Err(invalid("WARC header field repeated in one record"));
                    }
                    seen[index] = true;
                    if index < INTERPRETED_FIELDS {
                        values[index] = Some((cursor + value_start, cursor + value_end));
                    }
                    PreviousField::Defined(index)
                }
                None => PreviousField::Extension,
            };
        }
        cursor = eol + 2;
    }

    let warc_type = values[FIELD_TYPE].ok_or_else(|| invalid("WARC record lacks WARC-Type"))?;
    if !is_token(&stream[warc_type.0..warc_type.1]) {
        return Err(invalid("WARC-Type is not a token"));
    }
    let id = values[FIELD_RECORD_ID].ok_or_else(|| invalid("WARC record lacks WARC-Record-ID"))?;
    let id_bytes = &stream[id.0..id.1];
    let bracketed = id_bytes.len() >= 2
        && id_bytes[0] == b'<'
        && id_bytes[id_bytes.len() - 1] == b'>'
        && is_record_uri(&id_bytes[1..id_bytes.len() - 1]);
    if !bracketed {
        return Err(invalid(
            "WARC-Record-ID is not an angle-bracketed absolute URI",
        ));
    }
    let date = values[FIELD_DATE]
        .filter(|(start, end)| end > start)
        .ok_or_else(|| invalid("WARC record lacks WARC-Date"))?;
    let length =
        values[FIELD_CONTENT_LENGTH].ok_or_else(|| invalid("WARC record lacks Content-Length"))?;
    let content_length = parse_decimal(&stream[length.0..length.1])
        .ok_or_else(|| invalid("Content-Length is not a decimal byte count"))?;
    Ok(Header {
        block_start: cursor,
        content_length,
        record_id: (id.0 + 1, id.1 - 1),
        warc_type,
        content_type: values[FIELD_CONTENT_TYPE],
        date,
        has_target_uri: seen[FIELD_TARGET_URI],
    })
}

/// Index of the CRLF ending the line that starts at `from`.
fn line_end(stream: &[u8], from: usize, limit: usize) -> Result<usize, FormatError> {
    let window = stream.get(from..limit.max(from)).ok_or_else(truncated)?;
    match window
        .iter()
        .position(|&byte| byte == b'\r' || byte == b'\n')
    {
        Some(offset) => {
            let at = from + offset;
            match (stream[at], stream.get(at + 1)) {
                (b'\r', Some(b'\n')) => Ok(at),
                (b'\r', None) => Err(truncated()),
                _ => Err(invalid("WARC header line not terminated by CRLF")),
            }
        }
        None if limit == stream.len() => Err(truncated()),
        None => Err(unsupported(
            "WARC record header exceeds the header size limit",
        )),
    }
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|&byte| (0x21..0x7f).contains(&byte) && !b"()<>@,;:\\\"/[]?={}".contains(&byte))
}

fn trim_lws(line: &[u8], from: usize) -> (usize, usize) {
    let mut start = from;
    let mut end = line.len();
    while start < end && matches!(line[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(line[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (start, end)
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0usize, |value, &byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(usize::from(byte - b'0'))
    })
}

/// A `WARC-Record-ID` value without its angle brackets: an absolute URI
/// (RFC 3986 scheme followed by `:`) of printable ASCII with no whitespace or
/// angle brackets.
fn is_record_uri(uri: &[u8]) -> bool {
    let printable = !uri.is_empty()
        && uri
            .iter()
            .all(|&byte| (0x21..0x7f).contains(&byte) && byte != b'<' && byte != b'>');
    let Some(colon) = uri.iter().position(|&byte| byte == b':') else {
        return false;
    };
    let scheme = &uri[..colon];
    printable
        && scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// W3CDTF in UTC, as WARC 1.1 requires for `WARC-Date`: `YYYY`, `YYYY-MM`,
/// `YYYY-MM-DD`, or a date with `Thh:mm`, `Thh:mm:ss` or `Thh:mm:ss.s` (one to
/// nine fraction digits) and a `Z` designator.
fn is_w3cdtf_utc(value: &[u8]) -> bool {
    fn number(value: &[u8], at: usize, len: usize, min: u32, max: u32) -> bool {
        value.get(at..at + len).is_some_and(|digits| {
            digits.iter().all(u8::is_ascii_digit)
                && (min..=max).contains(
                    &digits
                        .iter()
                        .fold(0u32, |acc, &digit| acc * 10 + u32::from(digit - b'0')),
                )
        })
    }
    if !number(value, 0, 4, 0, 9999) {
        return false;
    }
    match value.len() {
        4 => return true,
        7 => return value[4] == b'-' && number(value, 5, 2, 1, 12),
        10 => {
            return value[4] == b'-'
                && number(value, 5, 2, 1, 12)
                && value[7] == b'-'
                && number(value, 8, 2, 1, 31);
        }
        _ => {}
    }
    let date_time = value.len() >= 17
        && value[4] == b'-'
        && number(value, 5, 2, 1, 12)
        && value[7] == b'-'
        && number(value, 8, 2, 1, 31)
        && value[10] == b'T'
        && number(value, 11, 2, 0, 23)
        && value[13] == b':'
        && number(value, 14, 2, 0, 59);
    if !date_time {
        return false;
    }
    let rest = &value[16..];
    if rest == b"Z" {
        return true;
    }
    if rest.len() < 4 || rest[0] != b':' || !number(rest, 1, 2, 0, 60) {
        return false;
    }
    let rest = &rest[3..];
    if rest == b"Z" {
        return true;
    }
    let fraction = rest.len().saturating_sub(2);
    rest.len() >= 3
        && rest[0] == b'.'
        && rest[rest.len() - 1] == b'Z'
        && (1..=9).contains(&fraction)
        && rest[1..rest.len() - 1].iter().all(u8::is_ascii_digit)
}

fn records_aligned(records: &[Record], units: &[Unit], len: usize) -> bool {
    let starts: Vec<usize> = units.iter().map(|unit| unit.output.0).collect();
    let boundary = |pos: usize| pos == len || starts.binary_search(&pos).is_ok();
    records
        .iter()
        .all(|record| boundary(record.span.0) && boundary(record.span.1))
}

// ---------------------------------------------------------------------------
// gzip (RFC 1952)
// ---------------------------------------------------------------------------

fn decode_gzip(data: &[u8], limits: &WarcLimits) -> Result<(Vec<u8>, Vec<Unit>), FormatError> {
    let mut stream = Vec::new();
    let mut units = Vec::new();
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let mut pos = 0usize;
    while pos < data.len() {
        let output_start = stream.len();
        let end = gunzip_member(data, pos, &mut stream, &mut state, limits.max_archive_bytes)?;
        units.push(Unit {
            kind: UnitKind::Gzip,
            stored: (pos, end),
            output: (output_start, stream.len()),
        });
        pos = end;
    }
    Ok((stream, units))
}

/// Decode the member at `start` onto `out`, returning the member's end.
fn gunzip_member(
    data: &[u8],
    start: usize,
    out: &mut Vec<u8>,
    state: &mut InflateState,
    max_out: usize,
) -> Result<usize, FormatError> {
    let header = data.get(start..start + 10).ok_or_else(truncated)?;
    if header[..2] != GZIP_MAGIC || header[2] != GZIP_DEFLATE {
        return Err(invalid("gzip member is not deflate-compressed"));
    }
    let flags = header[3];
    if flags & GZIP_RESERVED != 0 {
        return Err(invalid("gzip member sets a reserved flag"));
    }
    let mut pos = start + 10;
    if flags & GZIP_FEXTRA != 0 {
        let extra = le_u16(data, pos).ok_or_else(truncated)?;
        pos += 2 + usize::from(extra);
    }
    for flag in [GZIP_FNAME, GZIP_FCOMMENT] {
        if flags & flag != 0 {
            let field = data.get(pos..).ok_or_else(truncated)?;
            let nul = field
                .iter()
                .position(|&byte| byte == 0)
                .ok_or_else(truncated)?;
            pos += nul + 1;
        }
    }
    if flags & GZIP_FHCRC != 0 {
        let stored = le_u16(data, pos).ok_or_else(truncated)?;
        if u32::from(stored) != crc32(&data[start..pos]) & 0xffff {
            return Err(invalid("gzip header CRC mismatch"));
        }
        pos += 2;
    }
    if pos > data.len() {
        return Err(truncated());
    }

    state.reset(DataFormat::Raw);
    let member_start = out.len();
    loop {
        let room = max_out.saturating_sub(out.len());
        let chunk = INFLATE_CHUNK.min(room.saturating_add(1));
        let filled = out.len();
        out.resize(filled + chunk, 0);
        let result = inflate(state, &data[pos..], &mut out[filled..], MZFlush::None);
        out.truncate(filled + result.bytes_written);
        pos += result.bytes_consumed;
        if out.len() > max_out {
            return Err(unsupported("decompressed WARC exceeds the archive limit"));
        }
        match result.status {
            Ok(MZStatus::StreamEnd) => break,
            Ok(MZStatus::Ok) if result.bytes_consumed > 0 || result.bytes_written > 0 => {}
            Ok(MZStatus::Ok) | Err(MZError::Buf) => return Err(truncated()),
            Ok(MZStatus::NeedDict) | Err(_) => {
                return Err(invalid("gzip member has a corrupt deflate stream"));
            }
        }
    }
    let crc = le_u32(data, pos).ok_or_else(truncated)?;
    let size = le_u32(data, pos + 4).ok_or_else(truncated)?;
    let member = &out[member_start..];
    if crc != crc32(member) {
        return Err(invalid("gzip member CRC-32 mismatch"));
    }
    if size != low32(member.len()) {
        return Err(invalid("gzip member ISIZE mismatch"));
    }
    Ok(pos + 8)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        let index = usize::try_from((crc ^ u32::from(byte)) & 0xff).unwrap_or(0);
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }
    !crc
}

// ---------------------------------------------------------------------------
// WARC-zstd
// ---------------------------------------------------------------------------

struct FrameInfo {
    end: usize,
    content_size: u64,
    dictionary_id: Option<u32>,
    checksum: u32,
}

fn decode_zstd(data: &[u8], limits: &WarcLimits) -> Result<(Vec<u8>, Vec<Unit>), FormatError> {
    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(limits.max_window_bytes);
    let mut stream = Vec::new();
    let mut units = Vec::new();
    let mut dictionary_id = None;
    let mut pos = 0usize;

    if le_u32(data, 0) == Some(DICTIONARY_FRAME_MAGIC) {
        let (end, user_data) = skippable_frame(data, 0)?;
        let dictionary = load_dictionary(user_data, limits)?;
        dictionary_id = Some(dictionary.id);
        decoder
            .add_dict(dictionary)
            .map_err(|_| invalid("WARC-zstd dictionary cannot be loaded"))?;
        units.push(Unit {
            kind: UnitKind::Dictionary,
            stored: (0, end),
            output: (0, 0),
        });
        pos = end;
    }

    while pos < data.len() {
        let magic = le_u32(data, pos).ok_or_else(truncated)?;
        if magic == ZSTD_FRAME_MAGIC {
            let frame = scan_zstd_frame(data, pos, limits)?;
            if frame.dictionary_id != dictionary_id {
                return Err(invalid(
                    "WARC-zstd frame Dictionary_ID does not match the file's dictionary",
                ));
            }
            let output_start = stream.len();
            decode_zstd_frame(
                &mut decoder,
                &data[pos..frame.end],
                frame.content_size,
                &mut stream,
                limits.max_archive_bytes,
            )?;
            units.push(Unit {
                kind: UnitKind::ZstdFrame {
                    checksum: frame.checksum,
                },
                stored: (pos, frame.end),
                output: (output_start, stream.len()),
            });
            pos = frame.end;
        } else if (SKIPPABLE_MAGIC_MIN..=SKIPPABLE_MAGIC_MAX).contains(&magic) {
            if pos == 0 {
                return Err(invalid("WARC-zstd file begins with an extension frame"));
            }
            if magic == DICTIONARY_FRAME_MAGIC {
                return Err(invalid("WARC-zstd dictionary frame is not the first frame"));
            }
            let (end, user_data) = skippable_frame(data, pos)?;
            let seek_table = magic == SEEK_TABLE_FRAME_MAGIC
                && user_data.len() >= SEEK_TABLE_FOOTER_LEN
                && le_u32(user_data, user_data.len() - 4) == Some(SEEKABLE_FOOTER_MAGIC);
            units.push(Unit {
                kind: if seek_table {
                    UnitKind::SeekTable
                } else {
                    UnitKind::Skippable
                },
                stored: (pos, end),
                output: (stream.len(), stream.len()),
            });
            pos = end;
        } else {
            return Err(invalid(
                "WARC-zstd file contains a frame that is neither Zstandard nor skippable",
            ));
        }
    }

    if !units
        .iter()
        .any(|unit| matches!(unit.kind, UnitKind::ZstdFrame { .. }))
    {
        return Err(invalid("WARC-zstd file contains no Zstandard frame"));
    }
    // A seek table is the file's final frame; one elsewhere is an extension
    // frame like any other.
    let last = units.len() - 1;
    if units[last].kind == UnitKind::SeekTable {
        validate_seek_table(data, &units)?;
    }
    Ok((stream, units))
}

fn skippable_frame(data: &[u8], pos: usize) -> Result<(usize, &[u8]), FormatError> {
    let size = le_u32(data, pos + 4).ok_or_else(truncated)?;
    let start = pos + 8;
    let end = start.checked_add(widen(size)).ok_or_else(truncated)?;
    let user_data = data.get(start..end).ok_or_else(truncated)?;
    Ok((end, user_data))
}

/// Read a Zstandard frame header and walk its block headers to find where the
/// frame ends, enforcing the WARC-zstd header requirements.
fn scan_zstd_frame(data: &[u8], pos: usize, limits: &WarcLimits) -> Result<FrameInfo, FormatError> {
    let descriptor = *data.get(pos + 4).ok_or_else(truncated)?;
    let content_size_flag = descriptor >> 6;
    let single_segment = descriptor & 0x20 != 0;
    if descriptor & 0x08 != 0 {
        return Err(invalid("Zstandard frame sets the reserved descriptor bit"));
    }
    if descriptor & 0x04 == 0 {
        return Err(invalid("WARC-zstd frame lacks Content_Checksum"));
    }
    let mut cursor = pos + 5;
    let window = if single_segment {
        None
    } else {
        let window_descriptor = *data.get(cursor).ok_or_else(truncated)?;
        cursor += 1;
        let exponent = u32::from(window_descriptor >> 3);
        let base = 1u64 << (10 + exponent);
        Some(base + (base / 8) * u64::from(window_descriptor & 0x07))
    };
    let id_len = [0usize, 1, 2, 4][usize::from(descriptor & 0x03)];
    let raw_id = le_uint(data, cursor, id_len).ok_or_else(truncated)?;
    cursor += id_len;
    let size_len = match content_size_flag {
        0 if single_segment => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if size_len == 0 {
        return Err(invalid("WARC-zstd frame lacks Frame_Content_Size"));
    }
    let mut content_size = le_uint(data, cursor, size_len).ok_or_else(truncated)?;
    if size_len == 2 {
        content_size += 256;
    }
    cursor += size_len;
    let window = window.unwrap_or(content_size);
    if window > limits.max_window_bytes {
        return Err(unsupported("Zstandard window exceeds the window limit"));
    }
    let block_max = window.min(ZSTD_MAX_BLOCK);
    loop {
        let block_header = le_uint(data, cursor, 3).ok_or_else(truncated)?;
        cursor += 3;
        let last = block_header & 1 != 0;
        let block_size = block_header >> 3;
        if block_size > block_max {
            return Err(invalid("Zstandard block exceeds its maximum size"));
        }
        let stored = match (block_header >> 1) & 0x03 {
            0 | 2 => block_size,
            1 => 1,
            _ => return Err(invalid("Zstandard block has the reserved block type")),
        };
        cursor = cursor
            .checked_add(usize::try_from(stored).map_err(|_| truncated())?)
            .filter(|&end| end <= data.len())
            .ok_or_else(truncated)?;
        if last {
            break;
        }
    }
    let checksum = le_u32(data, cursor).ok_or_else(truncated)?;
    let dictionary_id = u32::try_from(raw_id).ok().filter(|&id| id != 0);
    Ok(FrameInfo {
        end: cursor + 4,
        content_size,
        dictionary_id,
        checksum,
    })
}

fn decode_zstd_frame(
    decoder: &mut FrameDecoder,
    frame: &[u8],
    content_size: u64,
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<(), FormatError> {
    let corrupt = |_| invalid("Zstandard frame is corrupt");
    let target = usize::try_from(content_size)
        .ok()
        .and_then(|size| out.len().checked_add(size))
        .filter(|&target| target <= max_out)
        .ok_or_else(|| unsupported("decompressed WARC exceeds the archive limit"))?;
    let mut source = frame;
    decoder.reset(&mut source).map_err(corrupt)?;
    loop {
        let finished = decoder
            .decode_blocks(
                &mut source,
                BlockDecodingStrategy::UptoBytes(ZSTD_DRAIN_STEP),
            )
            .map_err(corrupt)?;
        decoder
            .collect_to_writer(&mut *out)
            .map_err(|_| invalid("Zstandard frame output cannot be collected"))?;
        if out.len() > target {
            return Err(invalid("Zstandard frame exceeds its Frame_Content_Size"));
        }
        if finished {
            break;
        }
    }
    if out.len() != target {
        return Err(invalid(
            "Zstandard frame is shorter than its Frame_Content_Size",
        ));
    }
    if !source.is_empty() {
        return Err(invalid("Zstandard frame length differs from its blocks"));
    }
    if decoder.get_checksum_from_data() != decoder.get_calculated_checksum() {
        return Err(invalid("Zstandard Content_Checksum mismatch"));
    }
    Ok(())
}

/// Load the dictionary carried by a WARC-zstd dictionary frame: a Zstandard
/// dictionary, or one Zstandard frame (without a dictionary) that decodes to
/// one.
fn load_dictionary(user_data: &[u8], limits: &WarcLimits) -> Result<Dictionary, FormatError> {
    if user_data.len() > limits.max_dictionary_bytes {
        return Err(unsupported(
            "WARC-zstd dictionary exceeds the dictionary limit",
        ));
    }
    let decompressed;
    let raw = match le_u32(user_data, 0) {
        Some(ZSTD_DICTIONARY_MAGIC) => user_data,
        Some(ZSTD_FRAME_MAGIC) => {
            let frame = scan_zstd_frame(user_data, 0, limits)?;
            if frame.end != user_data.len() {
                return Err(invalid(
                    "compressed WARC-zstd dictionary is not exactly one Zstandard frame",
                ));
            }
            if frame.dictionary_id.is_some() {
                return Err(invalid("compressed WARC-zstd dictionary uses a dictionary"));
            }
            let mut decoder = FrameDecoder::new();
            decoder.set_max_window_size(limits.max_window_bytes);
            let mut out = Vec::new();
            decode_zstd_frame(
                &mut decoder,
                user_data,
                frame.content_size,
                &mut out,
                limits.max_dictionary_bytes,
            )?;
            decompressed = out;
            &decompressed[..]
        }
        _ => return Err(invalid("WARC-zstd dictionary frame holds no dictionary")),
    };
    if le_u32(raw, 0) != Some(ZSTD_DICTIONARY_MAGIC) {
        return Err(invalid("WARC-zstd dictionary frame holds no dictionary"));
    }
    let dictionary =
        Dictionary::decode_dict(raw).map_err(|_| invalid("WARC-zstd dictionary is malformed"))?;
    if dictionary.id == 0 {
        return Err(invalid("WARC-zstd dictionary has a zero Dictionary_ID"));
    }
    Ok(dictionary)
}

/// Check the final seek table against the frames it indexes: entry sizes and
/// checksums must describe every preceding frame exactly. Entries may start at
/// the first frame or after the dictionary frame.
fn validate_seek_table(data: &[u8], units: &[Unit]) -> Result<(), FormatError> {
    let table = units[units.len() - 1];
    let user_data = &data[table.stored.0 + 8..table.stored.1];
    let footer = user_data.len() - SEEK_TABLE_FOOTER_LEN;
    let count = widen(le_u32(user_data, footer).ok_or_else(truncated)?);
    let descriptor = user_data[footer + 4];
    if descriptor & SEEK_TABLE_RESERVED_BITS != 0 {
        return Err(invalid(
            "Zstandard seek table sets reserved descriptor bits",
        ));
    }
    let checksums = descriptor & SEEK_TABLE_CHECKSUM_FLAG != 0;
    let entry_len = if checksums { 12 } else { 8 };
    if count.checked_mul(entry_len) != Some(footer) {
        return Err(invalid(
            "Zstandard seek table size does not match its frame count",
        ));
    }
    let indexed = &units[..units.len() - 1];
    let entries_match = |frames: &[Unit]| {
        frames.len() == count
            && frames.iter().enumerate().all(|(index, frame)| {
                let at = index * entry_len;
                let compressed = le_u32(user_data, at).map(widen);
                let decompressed = le_u32(user_data, at + 4).map(widen);
                let sizes = compressed == Some(frame.stored.1 - frame.stored.0)
                    && decompressed == Some(frame.output.1 - frame.output.0);
                let checksum = !checksums
                    || match (frame.kind, le_u32(user_data, at + 8)) {
                        (UnitKind::ZstdFrame { checksum }, Some(stored)) => stored == checksum,
                        (_, Some(stored)) => stored == XXH64_EMPTY_LOW32 || stored == 0,
                        (_, None) => false,
                    };
                sizes && checksum
            })
    };
    let after_dictionary = indexed
        .first()
        .is_some_and(|unit| unit.kind == UnitKind::Dictionary);
    if entries_match(indexed) || (after_dictionary && entries_match(&indexed[1..])) {
        Ok(())
    } else {
        Err(invalid(
            "Zstandard seek table does not describe the file's frames",
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

fn unsupported(detail: &'static str) -> FormatError {
    FormatError::UnsupportedVariant {
        format: FMT,
        detail,
    }
}

fn truncated() -> FormatError {
    FormatError::Truncated(FMT)
}

fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_uint(data: &[u8], off: usize, len: usize) -> Option<u64> {
    let bytes = data.get(off..off.checked_add(len)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte)),
    )
}

fn widen(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// `len` modulo 2^32, as gzip ISIZE records it.
fn low32(len: usize) -> u32 {
    let wide = u64::try_from(len).unwrap_or(u64::MAX) & 0xFFFF_FFFF;
    u32::try_from(wide).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    //! The verifier never writes WARC files, so the fixtures below assemble
    //! records, gzip members, WARC-zstd frames, dictionaries and seek tables
    //! by hand from their published layouts.

    use super::*;
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};
    use sha2::{Digest, Sha256};

    const STORE: &[u8] = b"\x00\x00\x00\x10jumbc2pa-store-1";
    const DATE: &str = "2026-10-11T08:30:00Z";
    const PROVENANCE_ID: &str = "urn:uuid:7c0e7a8e-5b1c-4e5f-9a51-0c2a5a1f2b01";
    const DICTIONARY_ID: u32 = 40_000;

    fn record(id: &str, warc_type: &str, extra: &[(&str, &str)], block: &[u8]) -> Vec<u8> {
        let mut header = format!(
            "WARC/1.1\r\nWARC-Type: {warc_type}\r\nWARC-Record-ID: <{id}>\r\nWARC-Date: 2026-10-01T12:00:00Z\r\n"
        );
        for (name, value) in extra {
            header.push_str(&format!("{name}: {value}\r\n"));
        }
        header.push_str(&format!("Content-Length: {}\r\n\r\n", block.len()));
        let mut bytes = header.into_bytes();
        bytes.extend_from_slice(block);
        bytes.extend_from_slice(RECORD_TERMINATOR);
        bytes
    }

    fn manifest_record(id: &str, store: &[u8]) -> Vec<u8> {
        record(
            id,
            "c2pa-provenance",
            &[("Content-Type", "application/c2pa")],
            store,
        )
    }

    /// A warcinfo, a response, a segmented response with its continuation, a
    /// revisit, then the final C2PA manifest record.
    fn signed_records() -> Vec<Vec<u8>> {
        vec![
            record(
                "urn:uuid:00000000-0000-4000-8000-000000000001",
                "warcinfo",
                &[("Content-Type", "application/warc-fields")],
                b"software: test\r\nformat: WARC File Format 1.1\r\n",
            ),
            record(
                "urn:uuid:00000000-0000-4000-8000-000000000002",
                "response",
                &[
                    ("WARC-Target-URI", "https://example.org/"),
                    ("Content-Type", "application/http;msgtype=response"),
                ],
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>first</html>",
            ),
            record(
                "urn:uuid:00000000-0000-4000-8000-000000000003",
                "response",
                &[
                    ("WARC-Target-URI", "https://example.org/big"),
                    ("WARC-Segment-Number", "1"),
                ],
                b"HTTP/1.1 200 OK\r\n\r\nsegment-one",
            ),
            record(
                "urn:uuid:00000000-0000-4000-8000-000000000004",
                "continuation",
                &[
                    ("WARC-Target-URI", "https://example.org/big"),
                    (
                        "WARC-Segment-Origin-ID",
                        "<urn:uuid:00000000-0000-4000-8000-000000000003>",
                    ),
                    ("WARC-Segment-Number", "2"),
                    ("WARC-Segment-Total-Length", "30"),
                ],
                b"segment-two",
            ),
            record(
                "urn:uuid:00000000-0000-4000-8000-000000000005",
                "revisit",
                &[
                    ("WARC-Target-URI", "https://example.org/"),
                    (
                        "WARC-Refers-To",
                        "<urn:uuid:00000000-0000-4000-8000-000000000002>",
                    ),
                ],
                b"",
            ),
            manifest_record(PROVENANCE_ID, STORE),
        ]
    }

    fn sha256(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }

    /// The collection a generator signs: every record but the manifest record.
    fn entries(records: &[Vec<u8>]) -> Vec<(String, Vec<u8>)> {
        let bytes = records.concat();
        let archive = WarcArchive::parse(&bytes).unwrap();
        archive
            .members()
            .map(|(id, bytes)| (id.to_string(), sha256(bytes)))
            .collect()
    }

    fn verify_with(
        asset: &[u8],
        entries: &[(String, Vec<u8>)],
        limits: WarcLimits,
    ) -> Result<usize, WarcCollectionFailure> {
        let archive = WarcArchive::parse_with_limits(asset, limits).unwrap();
        verify_collection(
            &archive,
            entries
                .iter()
                .map(|(id, hash)| (id.as_str(), hash.as_slice())),
            sha256,
        )
    }

    fn verify(asset: &[u8], entries: &[(String, Vec<u8>)]) -> Result<usize, WarcCollectionFailure> {
        verify_with(asset, entries, WarcLimits::DEFAULT)
    }

    fn owned_members(asset: &[u8]) -> Vec<(String, Vec<u8>)> {
        let archive = WarcArchive::parse(asset).unwrap_or_else(|error| panic!("{error}"));
        archive
            .members()
            .map(|(id, bytes)| (id.to_string(), bytes.to_vec()))
            .collect()
    }

    fn gzip_member(plain: &[u8]) -> Vec<u8> {
        let deflated = miniz_oxide::deflate::compress_to_vec(plain, 6);
        let mut member = vec![0x1f, 0x8b, GZIP_DEFLATE, 0, 0, 0, 0, 0, 0, 0xff];
        member.extend_from_slice(&deflated);
        member.extend_from_slice(&crc32(plain).to_le_bytes());
        member.extend_from_slice(&low32(plain.len()).to_le_bytes());
        member
    }

    fn per_record_gzip(records: &[Vec<u8>]) -> Vec<u8> {
        records
            .iter()
            .flat_map(|record| gzip_member(record))
            .collect()
    }

    /// A WARC-zstd frame: the encoder's blocks and checksum under a header
    /// that adds the mandatory 8-byte `Frame_Content_Size` and, with a
    /// dictionary, its ID. Raw blocks are used with a dictionary because they
    /// decode identically whatever dictionary is loaded.
    fn zstd_frame(plain: &[u8], dictionary_id: Option<u32>) -> Vec<u8> {
        let level = if dictionary_id.is_some() {
            CompressionLevel::Uncompressed
        } else {
            CompressionLevel::Fastest
        };
        let encoded = compress_to_vec(plain, level);
        assert_eq!(encoded[4], 0x04, "encoder header: window + checksum only");
        let mut frame = ZSTD_FRAME_MAGIC.to_le_bytes().to_vec();
        frame.push(0xc4 | if dictionary_id.is_some() { 0x03 } else { 0 });
        frame.push(encoded[5]);
        if let Some(id) = dictionary_id {
            frame.extend_from_slice(&id.to_le_bytes());
        }
        frame.extend_from_slice(&u64::try_from(plain.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(&encoded[6..]);
        frame
    }

    fn skippable(magic: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = magic.to_le_bytes().to_vec();
        frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// A minimal valid Zstandard dictionary: two-symbol literal Huffman table,
    /// single-symbol FSE tables (accuracy log 5), repeat offsets 1/4/8.
    fn test_dictionary() -> Vec<u8> {
        let mut dictionary = ZSTD_DICTIONARY_MAGIC.to_le_bytes().to_vec();
        dictionary.extend_from_slice(&DICTIONARY_ID.to_le_bytes());
        dictionary.extend_from_slice(&[0x80, 0x10]);
        for _ in 0..3 {
            dictionary.extend_from_slice(&[0xf0, 0x03]);
        }
        for offset in [1u32, 4, 8] {
            dictionary.extend_from_slice(&offset.to_le_bytes());
        }
        dictionary.extend_from_slice(b"WARC/1.1\r\nWARC-Type: response\r\nContent-Length: ");
        dictionary
    }

    /// `(frame bytes, decompressed length, checksum)` for each frame.
    type Frames = Vec<(Vec<u8>, usize, u32)>;

    fn zstd_frames(records: &[Vec<u8>], dictionary: Option<bool>) -> Frames {
        let mut frames = Frames::new();
        let dictionary_id = dictionary.map(|compressed| {
            let raw = test_dictionary();
            let payload = if compressed {
                zstd_frame(&raw, None)
            } else {
                raw
            };
            frames.push((
                skippable(DICTIONARY_FRAME_MAGIC, &payload),
                0,
                XXH64_EMPTY_LOW32,
            ));
            DICTIONARY_ID
        });
        for record in records {
            let frame = zstd_frame(record, dictionary_id);
            let checksum = le_u32(&frame, frame.len() - 4).unwrap();
            frames.push((frame, record.len(), checksum));
        }
        frames
    }

    fn concat(frames: &Frames) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|(frame, _, _)| frame.clone())
            .collect()
    }

    fn seek_table(frames: &[(Vec<u8>, usize, u32)], checksums: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        for (frame, decompressed, checksum) in frames {
            payload.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_le_bytes());
            payload.extend_from_slice(&u32::try_from(*decompressed).unwrap().to_le_bytes());
            if checksums {
                payload.extend_from_slice(&checksum.to_le_bytes());
            }
        }
        payload.extend_from_slice(&u32::try_from(frames.len()).unwrap().to_le_bytes());
        payload.push(if checksums {
            SEEK_TABLE_CHECKSUM_FLAG
        } else {
            0
        });
        payload.extend_from_slice(&SEEKABLE_FOOTER_MAGIC.to_le_bytes());
        skippable(SEEK_TABLE_FRAME_MAGIC, &payload)
    }

    fn seekable(frames: &Frames, checksums: bool, skip: usize) -> Vec<u8> {
        let mut file = concat(frames);
        file.extend(seek_table(&frames[skip..], checksums));
        file
    }

    fn every_stored_form(records: &[Vec<u8>]) -> Vec<(&'static str, Vec<u8>)> {
        let plain = zstd_frames(records, None);
        let dictionary = zstd_frames(records, Some(false));
        vec![
            ("raw", records.concat()),
            ("per-record gzip", per_record_gzip(records)),
            ("whole-file gzip", gzip_member(&records.concat())),
            ("zstd", concat(&plain)),
            ("zstd dictionary", concat(&dictionary)),
            (
                "zstd compressed dictionary",
                concat(&zstd_frames(records, Some(true))),
            ),
            ("zstd seekable", seekable(&plain, true, 0)),
            ("zstd seekable no checksums", seekable(&plain, false, 0)),
            ("zstd seekable dictionary", seekable(&dictionary, true, 0)),
            (
                "zstd seekable after dictionary",
                seekable(&dictionary, true, 1),
            ),
        ]
    }

    #[test]
    fn members_are_complete_uncompressed_records_except_the_manifest() {
        let records = signed_records();
        let asset = records.concat();
        let archive = WarcArchive::parse(&asset).unwrap();
        assert!(matches!(archive.stream, Cow::Borrowed(_)));
        assert_eq!(archive.manifest_store(), Some(STORE));
        assert_eq!(archive.placement_error(), None);
        let members: Vec<_> = archive.members().collect();
        assert_eq!(members.len(), records.len() - 1);
        for ((id, bytes), original) in members.iter().zip(&records) {
            assert_eq!(*bytes, original.as_slice());
            assert!(bytes.starts_with(b"WARC/1.1\r\n"));
            assert!(bytes.ends_with(b"\r\n\r\n"));
            assert!(id.starts_with("urn:uuid:") && !id.contains('<'));
        }
        assert_eq!(verify(&asset, &entries(&records)), Ok(records.len() - 1));
    }

    #[test]
    fn every_stored_form_yields_identical_members_and_binding() {
        let records = signed_records();
        let expected = owned_members(&records.concat());
        let signed = entries(&records);
        for (name, asset) in every_stored_form(&records) {
            assert_eq!(owned_members(&asset), expected, "{name}");
            assert_eq!(extract(&asset).unwrap().as_deref(), Some(STORE), "{name}");
            assert_eq!(placement_error(&asset).unwrap(), None, "{name}");
            assert_eq!(verify(&asset, &signed), Ok(records.len() - 1), "{name}");
        }
    }

    #[test]
    fn record_split_over_frames_and_extension_frames_are_accepted() {
        let records = signed_records();
        let (head, tail) = records[1].split_at(20);
        let mut asset = zstd_frame(&records[0], None);
        asset.extend(zstd_frame(head, None));
        asset.extend(skippable(0x184D_2A50, b"padding"));
        asset.extend(zstd_frame(tail, None));
        asset.extend(zstd_frame(&[], None));
        for record in &records[2..] {
            asset.extend(zstd_frame(record, None));
        }
        assert_eq!(owned_members(&asset), owned_members(&records.concat()));
    }

    #[test]
    fn tampered_block_or_header_fails_the_collection() {
        let records = signed_records();
        let signed = entries(&records);
        let mut block = records.concat();
        let at = block
            .windows(5)
            .position(|window| window == b"first")
            .unwrap();
        block[at] = b'F';
        assert_eq!(
            verify(&block, &signed),
            Err(WarcCollectionFailure::HashMismatch(
                "urn:uuid:00000000-0000-4000-8000-000000000002".into()
            ))
        );
        let header = String::from_utf8(records.concat()).unwrap().replacen(
            "WARC-Segment-Number: 2",
            "WARC-Segment-Number: 3",
            1,
        );
        assert_eq!(
            verify(header.as_bytes(), &signed),
            Err(WarcCollectionFailure::HashMismatch(
                "urn:uuid:00000000-0000-4000-8000-000000000004".into()
            ))
        );
    }

    #[test]
    fn manifest_record_bytes_are_outside_the_collection() {
        let records = signed_records();
        let signed = entries(&records);
        let mut updated = records.clone();
        let last = updated.len() - 1;
        updated[last] = manifest_record("urn:uuid:update", b"\x00\x00\x00\x09jumbother");
        assert_eq!(verify(&updated.concat(), &signed), Ok(records.len() - 1));
        let mut listed = signed.clone();
        listed.push((PROVENANCE_ID.to_string(), sha256(&records[last])));
        assert_eq!(
            verify(&records.concat(), &listed),
            Err(WarcCollectionFailure::MissingRecord(PROVENANCE_ID.into()))
        );
    }

    #[test]
    fn added_removed_and_duplicated_records_fail_the_collection() {
        let records = signed_records();
        let signed = entries(&records);
        let last = records.len() - 1;

        let mut added = records[..last].to_vec();
        added.push(record("urn:uuid:added", "resource", &[], b"late"));
        added.push(records[last].clone());
        assert_eq!(
            verify(&added.concat(), &signed),
            Err(WarcCollectionFailure::UnlistedRecord(
                "urn:uuid:added".into()
            ))
        );

        let removed: Vec<Vec<u8>> = records[1..].to_vec();
        assert_eq!(
            verify(&removed.concat(), &signed),
            Err(WarcCollectionFailure::MissingRecord(
                "urn:uuid:00000000-0000-4000-8000-000000000001".into()
            ))
        );

        let mut duplicated = records[..last].to_vec();
        duplicated.push(records[1].clone());
        duplicated.push(records[last].clone());
        assert_eq!(
            verify(&duplicated.concat(), &signed),
            Err(WarcCollectionFailure::DuplicateRecordId(
                "urn:uuid:00000000-0000-4000-8000-000000000002".into()
            ))
        );

        let mut repeated = signed.clone();
        repeated.push(signed[0].clone());
        assert_eq!(
            verify(&records.concat(), &repeated),
            Err(WarcCollectionFailure::DuplicateEntry(signed[0].0.clone()))
        );
    }

    #[test]
    fn manifest_record_location_rules() {
        let records = signed_records();
        let last = records.len() - 1;

        let mut not_last = records.clone();
        not_last.swap(last - 1, last);
        assert_eq!(extract(&not_last.concat()).unwrap().as_deref(), Some(STORE));
        assert_eq!(
            placement_error(&not_last.concat()).unwrap(),
            Some("C2PA manifest record is not the last WARC record")
        );

        let mut twice = records.clone();
        twice.push(manifest_record("urn:uuid:second", STORE));
        assert_eq!(extract(&twice.concat()).unwrap(), None);
        let twice_bytes = twice.concat();
        let archive = WarcArchive::parse(&twice_bytes).unwrap();
        assert_eq!(
            verify_collection(&archive, std::iter::empty(), sha256),
            Err(WarcCollectionFailure::ManifestNotLocated)
        );

        let mut targeted = records.clone();
        targeted[last] = record(
            PROVENANCE_ID,
            "c2pa-provenance",
            &[
                ("Content-Type", "application/c2pa"),
                ("WARC-Target-URI", "https://example.org/"),
            ],
            STORE,
        );
        assert_eq!(
            placement_error(&targeted.concat()).unwrap(),
            Some("C2PA manifest record carries a WARC-Target-URI field")
        );

        let mut undated = records.clone();
        undated[last] = String::from_utf8(records[last].clone())
            .unwrap()
            .replacen("2026-10-01T12:00:00Z", "yesterday", 1)
            .into_bytes();
        assert_eq!(
            placement_error(&undated.concat()).unwrap(),
            Some("C2PA manifest record WARC-Date is not a UTC W3CDTF timestamp")
        );

        let mut empty = records.clone();
        empty[last] = manifest_record(PROVENANCE_ID, b"");
        assert!(extract(&empty.concat()).is_err());

        let mut other_type = records[..last].to_vec();
        other_type.push(record(
            PROVENANCE_ID,
            "c2pa-provenance",
            &[("Content-Type", "application/octet-stream")],
            STORE,
        ));
        assert_eq!(extract(&other_type.concat()).unwrap(), None);
        assert!(owned_members(&other_type.concat())
            .iter()
            .any(|(id, _)| id == PROVENANCE_ID));
        assert_eq!(extract(&records[..last].concat()).unwrap(), None);
    }

    #[test]
    fn content_length_mismatch_in_a_compressed_record_is_a_collection_failure() {
        let mut records = signed_records();
        let signed = entries(&records);
        let block_len =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>first</html>".len();
        let declared = format!("Content-Length: {block_len}\r\n");
        let understated = format!("Content-Length: {}\r\n", block_len - 1);
        let text = String::from_utf8(records[1].clone()).unwrap();
        assert!(text.contains(&declared));
        records[1] = text.replacen(&declared, &understated, 1).into_bytes();

        for asset in [
            per_record_gzip(&records),
            concat(&zstd_frames(&records, None)),
        ] {
            assert_eq!(extract(&asset).unwrap().as_deref(), Some(STORE));
            assert!(matches!(
                verify(&asset, &signed),
                Err(WarcCollectionFailure::RecordDefect {
                    defect: RecordDefect::ContentLengthMismatch,
                    ..
                })
            ));
        }
        assert!(WarcArchive::parse(&records.concat()).is_err());
        assert!(WarcArchive::parse(&gzip_member(&records.concat())).is_err());
    }

    #[test]
    fn oversized_compressed_record_is_a_collection_failure() {
        let records = signed_records();
        let signed = entries(&records);
        // The 305-byte response record exceeds it; the 214-byte manifest
        // record does not.
        assert_eq!(records[1].len(), 305);
        assert!(records[records.len() - 1].len() < 260);
        let limits = WarcLimits {
            max_record_bytes: 260,
            ..WarcLimits::DEFAULT
        };
        let asset = per_record_gzip(&records);
        assert_eq!(
            verify_with(&asset, &signed, limits),
            Err(WarcCollectionFailure::RecordDefect {
                record_id: "urn:uuid:00000000-0000-4000-8000-000000000002".into(),
                defect: RecordDefect::TooLarge,
            })
        );
        assert_eq!(verify(&asset, &signed), Ok(records.len() - 1));
    }

    #[test]
    fn decompression_is_bounded() {
        let records = signed_records();
        let tiny = WarcLimits {
            max_archive_bytes: 64,
            ..WarcLimits::DEFAULT
        };
        for asset in [
            per_record_gzip(&records),
            concat(&zstd_frames(&records, None)),
        ] {
            assert!(matches!(
                WarcArchive::parse_with_limits(&asset, tiny),
                Err(FormatError::UnsupportedVariant { .. })
            ));
        }
        let narrow = WarcLimits {
            max_window_bytes: 1024,
            ..WarcLimits::DEFAULT
        };
        assert!(
            WarcArchive::parse_with_limits(&concat(&zstd_frames(&records, None)), narrow).is_err()
        );
        let small_dictionary = WarcLimits {
            max_dictionary_bytes: 16,
            ..WarcLimits::DEFAULT
        };
        assert!(WarcArchive::parse_with_limits(
            &concat(&zstd_frames(&records, Some(false))),
            small_dictionary
        )
        .is_err());
        let short_header = WarcLimits {
            max_header_bytes: 32,
            ..WarcLimits::DEFAULT
        };
        assert!(matches!(
            WarcArchive::parse_with_limits(&records.concat(), short_header),
            Err(FormatError::UnsupportedVariant { .. })
        ));
    }

    #[test]
    fn corrupt_gzip_is_rejected() {
        let records = signed_records();
        let mut asset = per_record_gzip(&records);
        let crc_at = gzip_member(&records[0]).len() - 8;
        asset[crc_at] ^= 0xff;
        assert!(WarcArchive::parse(&asset).is_err());
        let whole = gzip_member(&records.concat());
        assert!(matches!(
            WarcArchive::parse(&whole[..whole.len() - 3]),
            Err(FormatError::Truncated(_))
        ));
        let mut reserved = whole.clone();
        reserved[3] = 0x20;
        assert!(WarcArchive::parse(&reserved).is_err());
    }

    #[test]
    fn warc_zstd_frame_rules_are_enforced() {
        let records = signed_records();
        let frame = zstd_frame(&records[0], None);

        let bare = compress_to_vec(&records[0][..], CompressionLevel::Fastest);
        assert!(WarcArchive::parse(&bare).is_err(), "no Frame_Content_Size");

        let mut unchecked = frame.clone();
        unchecked[4] &= !0x04;
        unchecked.truncate(unchecked.len() - 4);
        assert!(
            WarcArchive::parse(&unchecked).is_err(),
            "no Content_Checksum"
        );

        let mut wrong = frame.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0xff;
        assert!(WarcArchive::parse(&wrong).is_err(), "checksum mismatch");

        let joined = zstd_frame(&records[..2].concat(), None);
        assert!(
            WarcArchive::parse(&joined).is_err(),
            "frame spans two records"
        );

        let mut leading = skippable(0x184D_2A50, b"padding");
        leading.extend_from_slice(&frame);
        assert!(
            WarcArchive::parse(&leading).is_err(),
            "leading extension frame"
        );

        let mut mixed = skippable(DICTIONARY_FRAME_MAGIC, &test_dictionary());
        mixed.extend_from_slice(&frame);
        assert!(
            WarcArchive::parse(&mixed).is_err(),
            "frame without dictionary ID"
        );
        assert!(
            WarcArchive::parse(&zstd_frame(&records[0], Some(DICTIONARY_ID))).is_err(),
            "dictionary ID without a dictionary"
        );
        let mut late = frame.clone();
        late.extend(skippable(DICTIONARY_FRAME_MAGIC, &test_dictionary()));
        assert!(
            WarcArchive::parse(&late).is_err(),
            "dictionary frame not first"
        );

        let mut zero_id = test_dictionary();
        zero_id[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut zero = skippable(DICTIONARY_FRAME_MAGIC, &zero_id);
        zero.extend(zstd_frame(&records[0], None));
        assert!(WarcArchive::parse(&zero).is_err(), "zero dictionary ID");
    }

    #[test]
    fn seek_table_must_describe_the_frames() {
        let frames = zstd_frames(&signed_records(), None);
        let body = concat(&frames);
        let good = seekable(&frames, true, 0);
        assert!(WarcArchive::parse(&good).is_ok());
        let first_entry = body.len() + 8;
        for offset in [0, 4, 8] {
            let mut wrong = good.clone();
            wrong[first_entry + offset] ^= 0x01;
            assert!(WarcArchive::parse(&wrong).is_err(), "entry field {offset}");
        }
        let mut short = body.clone();
        short.extend(seek_table(&frames[1..], true));
        assert!(WarcArchive::parse(&short).is_err(), "missing first frame");
        let mut reserved = good.clone();
        let descriptor = reserved.len() - 5;
        reserved[descriptor] |= 0x04;
        assert!(WarcArchive::parse(&reserved).is_err(), "reserved bits");
    }

    #[test]
    fn empty_frame_checksum_constant_matches_xxh64() {
        let empty = compress_to_vec(&[0u8; 0][..], CompressionLevel::Fastest);
        assert_eq!(le_u32(&empty, empty.len() - 4), Some(XXH64_EMPTY_LOW32));
    }

    #[test]
    fn header_grammar_is_strict() {
        let good = record("urn:x:1", "resource", &[], b"abc");
        let text = String::from_utf8(good).unwrap();
        let cases = [
            text.replacen("\r\nWARC-Date", "\nWARC-Date", 1),
            text.replacen("WARC-Date: 2026-10-01T12:00:00Z\r\n", "", 1),
            text.replacen("WARC-Record-ID: <urn:x:1>", "WARC-Record-ID: urn:x:1", 1),
            text.replacen(
                "WARC-Record-ID: <urn:x:1>",
                "WARC-Record-ID: <no scheme>",
                1,
            ),
            text.replacen("WARC-Type: resource", "WARC-Type: resource\r\n more", 1),
            text.replacen(
                "Content-Length: 3",
                "Content-Length: 3\r\nContent-Length: 3",
                1,
            ),
            text.replacen("Content-Length: 3", "Content-Length: three", 1),
            text.replacen("WARC/1.1", "WARC/0.18", 1),
            text.replacen("abc\r\n\r\n", "abc\r\n", 1),
            format!("{text}trailing"),
            String::new(),
        ];
        for case in cases {
            assert!(WarcArchive::parse(case.as_bytes()).is_err(), "{case:?}");
        }
        let lenient = text.replacen(
            "WARC-Type: resource",
            "warc-type:resource\r\nX-Extension: a\r\n b\r\nWARC-Concurrent-To: <urn:x:2>\r\nWARC-Concurrent-To: <urn:x:3>",
            1,
        );
        assert_eq!(owned_members(lenient.as_bytes()).len(), 1);
        let v1_0 = text.replacen("WARC/1.1", "WARC/1.0", 1);
        assert_eq!(owned_members(v1_0.as_bytes()).len(), 1);
    }

    #[test]
    fn w3cdtf_dates() {
        for date in [
            "2026",
            "2026-10",
            "2026-10-11",
            "2026-10-11T08:30Z",
            "2026-10-11T08:30:00Z",
            "2026-10-11T08:30:60.123456789Z",
        ] {
            assert!(is_w3cdtf_utc(date.as_bytes()), "{date}");
        }
        for date in [
            "2026-10-11 08:30:00",
            "2026-13-11T08:30:00Z",
            "2026-10-11T08:30:00+02:00",
            "2026-10-11T08:30:00.Z",
            "2026-10-11T08:30:00.1234567890Z",
            "26-10-11",
        ] {
            assert!(!is_w3cdtf_utc(date.as_bytes()), "{date}");
        }
    }
}
