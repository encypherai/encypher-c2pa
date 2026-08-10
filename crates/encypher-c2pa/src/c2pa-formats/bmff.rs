//! ISOBMFF (MP4/MOV/M4A/AVIF/HEIC/HEIF): JUMBF in a top-level C2PA `uuid` box.
//!
//! C2PA reserves the user-type UUID `d8fec3d6-1b0e-483c-9297-5828877ec481`. The
//! manifest store is the payload of a top-level `uuid` box carrying that UUID,
//! immediately following the 16-byte UUID. Box headers are walked without
//! copying payloads; only the manifest bytes are materialized.

#[cfg(test)]
use crate::c2pa_formats::util::{be_u16, be_u24, iso_box_header};
use crate::c2pa_formats::util::{be_u32, be_u64, walk_iso_boxes, IsoBox};
use crate::c2pa_formats::{AssetFormat, DataHashExclusion, FormatError};

const FMT: AssetFormat = AssetFormat::Bmff;
const TYPE_UUID: &[u8; 4] = b"uuid";
#[cfg(test)]
const TYPE_FTYP: &[u8; 4] = b"ftyp";

/// Sanity-check that `data` looks like ISOBMFF: a parseable first box, and the
/// presence of an `ftyp` is conventional but `mdat`/`moov`-first files exist, so
/// we only require a structurally valid leading box.
fn check_bmff(data: &[u8]) -> Result<(), FormatError> {
    let mut ok = false;
    walk_iso_boxes(data, FMT, |b| {
        if b.start == 0 {
            ok = true;
        }
    })?;
    if !ok {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "no parseable top-level box",
        });
    }
    Ok(())
}

/// Identify a C2PA `uuid` box.
fn is_c2pa_uuid(data: &[u8], b: &IsoBox) -> bool {
    &b.box_type == TYPE_UUID
        && b.payload_start + 16 <= b.end
        && data[b.payload_start..b.payload_start + 16] == crate::c2pa_formats::C2PA_BMFF_UUID
}

fn xpath_box_types(xpaths: &[String]) -> Vec<[u8; 4]> {
    xpaths
        .iter()
        .filter_map(|p| {
            let b = p.trim_start_matches('/').as_bytes();
            (b.len() == 4).then_some([b[0], b[1], b[2], b[3]])
        })
        .collect()
}

/// Extract the manifest store from the C2PA `uuid` box payload.
///
/// Per the C2PA BMFF spec the `uuid` box payload is not the bare JUMBF: after
/// the 16-byte C2PA UUID it carries a 4-byte version+flags field, a
/// null-terminated purpose label (`manifest`), and reserved/merkle offset bytes
/// before the top-level `jumb` manifest store. c2pa-rs 0.78.4 emits exactly
/// this layout. Rather than hard-code the prefix length (which varies with the
/// presence of merkle data), we locate the start of the `jumb` box by its
/// `LBox + "jumb"` header within the payload.
pub(crate) fn extract(data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    check_bmff(data)?;
    let mut found = None;
    walk_iso_boxes(data, FMT, |b| {
        if found.is_none() && is_c2pa_uuid(data, b) {
            let payload = &data[b.payload_start + 16..b.end];
            if let Some(store) = jumbf_from_uuid_payload(payload) {
                found = Some(store.to_vec());
            }
        }
    })?;
    Ok(found)
}

/// Locate the top-level `jumb` manifest store within a C2PA `uuid` box payload
/// (the bytes after the 16-byte UUID), skipping the version/flags + label +
/// reserved prefix. Returns exactly the declared `jumb` box span, excluding
/// any following carrier bytes.
pub(crate) fn jumbf_from_uuid_payload(payload: &[u8]) -> Option<&[u8]> {
    // The manifest store is a `jumb` superbox: a 4-byte big-endian LBox
    // immediately precedes the ASCII `jumb` TBox. Find the first complete
    // such box and honor its ordinary, extended, or size-to-end declaration.
    let mut i = 0usize;
    while i + 8 <= payload.len() {
        if &payload[i + 4..i + 8] == b"jumb" {
            let lbox =
                u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
            let (header_len, declared_len) = match lbox {
                0 => (8, Some(payload.len() - i)),
                1 => (
                    16,
                    payload.get(i + 8..i + 16).and_then(|bytes| {
                        let bytes: [u8; 8] = bytes.try_into().ok()?;
                        usize::try_from(u64::from_be_bytes(bytes)).ok()
                    }),
                ),
                len => (8, Some(len as usize)),
            };
            if let Some(declared_len) = declared_len {
                if declared_len >= header_len {
                    if let Some(end) = i
                        .checked_add(declared_len)
                        .filter(|&end| end <= payload.len())
                    {
                        return Some(&payload[i..end]);
                    }
                }
            }
        }
        i += 1;
    }
    None
}
/// Resolve `c2pa.hash.bmff.v2` / `c2pa.hash.bmff.v3` box-path exclusions to byte ranges for hashing.
///
/// This is the range-only form of the BMFF exclusion planner: it accepts xpath
/// strings, applies the same nested/indexed path matcher used by
/// [`bmff_hash_with_exclusions`], and returns sorted `(start, length)` spans.
/// The legacy `/uuid` shorthand matches only the C2PA UUID carrier in both
/// this range API and the full exclusion-map hashing path.
pub fn bmff_exclusion_ranges(
    data: &[u8],
    xpaths: &[String],
) -> Result<Vec<(usize, usize)>, FormatError> {
    let exclusions: Vec<BmffExclusionMap> = xpaths
        .iter()
        .map(|xpath| BmffExclusionMap {
            xpath: xpath.clone(),
            length: None,
            data: Vec::new(),
            subset: Vec::new(),
            version: None,
            flags: None,
            exact: true,
        })
        .collect();
    let BmffHashPlan { ranges, .. } = normalized_bmff_ranges(data, &exclusions)?;
    Ok(ranges
        .into_iter()
        .map(|(start, end)| (start, end - start))
        .collect())
}
/// Resolve multiple BMFF box paths against one parsed box tree.
///
/// Results preserve input-path order and box order. Each inner vector contains
/// every full-box `(start, length)` span matched by that path. Aggregate
/// path-by-box matching is rejected before scanning when it exceeds the shared
/// verifier work bound.
pub fn bmff_box_ranges(
    data: &[u8],
    xpaths: &[&str],
) -> Result<Vec<Vec<(usize, usize)>>, FormatError> {
    if xpaths.len() > MAX_BMFF_EXCLUSION_RANGES {
        return Err(bmff_exclusion_matching_exceeds_bounds());
    }
    let parsed_xpaths = xpaths
        .iter()
        .map(|xpath| parse_bmff_xpath(xpath))
        .collect::<Result<Vec<_>, _>>()?;
    let mut boxes = Vec::new();
    collect_hash_boxes(data, 0, data.len(), &[], 0, true, &mut boxes)?;
    if parsed_xpaths
        .len()
        .checked_mul(boxes.len())
        .is_none_or(|checks| checks > MAX_BMFF_EXCLUSION_MATCH_CHECKS)
    {
        return Err(bmff_exclusion_matching_exceeds_bounds());
    }
    Ok(parsed_xpaths
        .iter()
        .map(|xpath| {
            boxes
                .iter()
                .filter(|candidate| path_matches(&candidate.path, xpath))
                .map(|candidate| (candidate.start, candidate.end - candidate.start))
                .collect()
        })
        .collect())
}

/// A parsed auxiliary C2PA `'merkle'` box from a fragment (or flat fMP4) file.
///
/// Per C2PA spec A.5.4, each fragment carries a C2PA `uuid` box with
/// `box_purpose = "merkle"` immediately preceding its `moof`. The payload is
/// CBOR (`bmff-merkle-map`): which Merkle tree the fragment belongs to
/// (`uniqueId` + `localId`), its zero-based leaf index (`location`), and the
/// proof hashes needed to climb from the leaf to the row stored in the
/// manifest's BMFF v2/v3 hash assertion (leaf-most first). Trailing zero
/// padding after the CBOR (used to keep aux boxes fixed-size) is tolerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmffMerkleBox {
    /// `uniqueId`: differentiates Merkle trees across files.
    pub unique_id: i128,
    /// `localId`: the track id (fragmented) or mdat index (non-fragmented).
    pub local_id: i128,
    /// `location`: zero-based index into the leaf-most Merkle tree row.
    pub location: usize,
    /// Proof hashes, leaf-most (peer of this node) to root-most (child of the
    /// row stored in the manifest). Empty when the manifest stores the leaf row.
    pub proof: Vec<Vec<u8>>,
}

/// Parse every auxiliary C2PA `'merkle'` box in `data` (spec A.5.4.2).
///
/// Walks top-level boxes; for each C2PA `uuid` box whose null-terminated
/// purpose label is `merkle`, decodes the leading CBOR `bmff-merkle-map`
/// (ignoring fixed-size zero padding). Boxes whose CBOR cannot be decoded or
/// whose required fields are missing are returned as errors by value so the
/// validator can report `assertion.bmffHash.malformed` precisely.
pub fn bmff_merkle_boxes(
    data: &[u8],
) -> Result<Vec<Result<BmffMerkleBox, &'static str>>, FormatError> {
    let mut found = Vec::new();
    let mut too_many = false;
    let mut limit_error = None;
    let mut total_proof_hashes = 0usize;
    let mut total_proof_bytes = 0usize;
    walk_iso_boxes(data, FMT, |b| {
        if too_many || limit_error.is_some() || !is_c2pa_uuid(data, b) {
            return;
        }
        // Payload after the 16-byte UUID: 4-byte version+flags, then the
        // null-terminated purpose label, then the purpose-specific data.
        let p = &data[b.payload_start + 16..b.end];
        if p.len() < 4 {
            return;
        }
        let after_vf = &p[4..];
        let Some(nul) = after_vf.iter().position(|&c| c == 0) else {
            return;
        };
        if &after_vf[..nul] != b"merkle" {
            return;
        }
        if found.len() >= MAX_BMFF_MERKLE_BOXES {
            too_many = true;
            return;
        }
        let cbor = &after_vf[nul + 1..];
        let parsed = parse_merkle_map(cbor);
        if let Ok(merkle_box) = &parsed {
            let next_hashes = total_proof_hashes.checked_add(merkle_box.proof.len());
            let next_bytes = merkle_box
                .proof
                .iter()
                .try_fold(total_proof_bytes, |total, hash| {
                    total.checked_add(hash.len())
                });
            let (Some(next_hashes), Some(next_bytes)) = (next_hashes, next_bytes) else {
                limit_error = Some("BMFF merkle proof data exceeds verifier bound");
                return;
            };
            if next_hashes > MAX_BMFF_MERKLE_TOTAL_PROOF_HASHES
                || next_bytes > MAX_BMFF_MERKLE_TOTAL_PROOF_BYTES
            {
                limit_error = Some("BMFF merkle proof data exceeds verifier bound");
                return;
            }
            total_proof_hashes = next_hashes;
            total_proof_bytes = next_bytes;
        }
        found.push(parsed);
    })?;
    if let Some(detail) = limit_error {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail,
        });
    }
    if too_many {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "BMFF merkle box count exceeds verifier bound",
        });
    }
    Ok(found)
}

/// Decode one `bmff-merkle-map` from the aux box payload (padding tolerated).
fn parse_merkle_map(cbor: &[u8]) -> Result<BmffMerkleBox, &'static str> {
    use crate::c2pa_cbor::{decode_prefix, Value};
    let bounded = &cbor[..cbor.len().min(MAX_BMFF_MERKLE_ENCODED_BYTES)];
    let (v, consumed) = decode_prefix(bounded).map_err(|_| "merkle box CBOR invalid")?;
    if cbor[consumed..].iter().any(|byte| *byte != 0) {
        return Err("merkle box has non-zero bytes after CBOR");
    }
    let int = |k: &str| match v.get(k) {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    };
    let unique_id = int("uniqueId").ok_or("merkle box missing uniqueId")?;
    let local_id = int("localId").ok_or("merkle box missing localId")?;
    let location = int("location")
        .and_then(|n| usize::try_from(n).ok())
        .ok_or("merkle box missing location")?;
    let proof = match v.get("hashes") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_BMFF_MERKLE_PROOF_HASHES {
                return Err("merkle box proof exceeds verifier bound");
            }
            let mut out = Vec::with_capacity(items.len());
            let mut proof_bytes = 0usize;
            for it in items {
                match it {
                    Value::Bytes(h) => {
                        proof_bytes = proof_bytes
                            .checked_add(h.len())
                            .filter(|bytes| *bytes <= MAX_BMFF_MERKLE_PROOF_BYTES)
                            .ok_or("merkle box proof bytes exceed verifier bound")?;
                        out.push(h.clone());
                    }
                    _ => return Err("merkle box hashes entry is not a byte string"),
                }
            }
            out
        }
        Some(_) => return Err("merkle box hashes is not an array"),
    };
    Ok(BmffMerkleBox {
        unique_id,
        local_id,
        location,
        proof,
    })
}

/// Compute a fragment file's Merkle LEAF hash (spec A.5.4.1.2): a plain digest
/// over all bytes of the fragment except data excluded by the assertion's
/// exclusion list (the fragment's own auxiliary C2PA `uuid` box is excluded by
/// the standard `/uuid` entry). Unlike the main-asset BMFF hash, leaf hashes
/// carry NO box-offset markers.
pub fn bmff_fragment_leaf_hash(
    fragment: &[u8],
    alg: &str,
    exclusions: &[BmffExclusionMap],
) -> Result<Vec<u8>, FormatError> {
    let mut hasher = BmffHasher::new(alg).ok_or(FormatError::UnsupportedVariant {
        format: FMT,
        detail: "unsupported bmff hash algorithm",
    })?;
    let BmffHashPlan { ranges, .. } = normalized_bmff_ranges(fragment, exclusions)?;
    let mut pos = 0usize;
    for (start, end) in ranges {
        if start > pos {
            hasher.update(&fragment[pos..start]);
        }
        pos = pos.max(end);
    }
    if pos < fragment.len() {
        hasher.update(&fragment[pos..]);
    }
    Ok(hasher.finalize())
}

/// The payload spans `(start, len)` of every top-level `mdat` box, in file
/// order (monolithic chunked-mdat merkle validation: `localId` is the
/// zero-based `mdat` index per spec A.5.4.2).
pub fn bmff_mdat_payloads(data: &[u8]) -> Result<Vec<(usize, usize)>, FormatError> {
    let mut spans = Vec::new();
    let mut too_many = false;
    walk_iso_boxes(data, FMT, |b| {
        if &b.box_type == b"mdat" {
            if spans.len() >= MAX_BMFF_HASH_BOXES {
                too_many = true;
            } else {
                spans.push((b.payload_start, b.end - b.payload_start));
            }
        }
    })?;
    if too_many {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "BMFF mdat count exceeds verifier bound",
        });
    }
    Ok(spans)
}

/// One byte sequence that must match at a box-relative offset before a BMFF
/// exclusion applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmffDataMap {
    pub offset: usize,
    pub value: Vec<u8>,
}

/// A box-relative byte range excluded instead of the whole matched box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmffSubsetMap {
    pub offset: usize,
    /// Zero means from `offset` through the end of the box.
    pub length: usize,
}

/// Normalized BMFF v2/v3 exclusion map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmffExclusionMap {
    pub xpath: String,
    pub length: Option<usize>,
    pub data: Vec<BmffDataMap>,
    pub subset: Vec<BmffSubsetMap>,
    pub version: Option<u8>,
    pub flags: Option<u32>,
    pub exact: bool,
}

const HASH_CONTAINER_TYPES: [&[u8; 4]; 15] = [
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"moof", b"traf", b"edts", b"udta", b"dinf",
    b"tref", b"treg", b"mvex", b"mfra", b"schi",
];
const MAX_BMFF_HASH_DEPTH: usize = 16;
const MAX_BMFF_XPATH_BYTES: usize = 1024;
const MAX_BMFF_HASH_BOXES: usize = 100_000;
const MAX_BMFF_EXCLUSION_MATCH_CHECKS: usize = 1_000_000;
const MAX_BMFF_EXCLUSION_RANGES: usize = 100_000;
const MAX_BMFF_EXCLUSION_DATA_QUALIFIERS: usize = 4_096;
const MAX_BMFF_EXCLUSION_DATA_BYTES: usize = 1 << 20;
const MAX_BMFF_EXCLUSION_SUBSETS: usize = 4_096;
const MAX_BMFF_MERKLE_BOXES: usize = 100_000;
const MAX_BMFF_MERKLE_ENCODED_BYTES: usize = 16 << 10;
const MAX_BMFF_MERKLE_PROOF_HASHES: usize = 64;
const MAX_BMFF_MERKLE_PROOF_BYTES: usize = 4096;
const MAX_BMFF_MERKLE_TOTAL_PROOF_HASHES: usize = 262_144;
const MAX_BMFF_MERKLE_TOTAL_PROOF_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, Copy)]
struct HashPathComponent {
    box_type: [u8; 4],
    occurrence: usize,
    c2pa_uuid: bool,
}

#[derive(Debug, Clone, Copy)]
struct BmffXpathComponent {
    box_type: [u8; 4],
    occurrence: Option<usize>,
    c2pa_uuid: bool,
}

#[derive(Debug)]
struct HashBox {
    path: Vec<HashPathComponent>,
    start: usize,
    end: usize,
    version: Option<u8>,
    flags: Option<u32>,
    top_level: bool,
}

struct BmffRootContribution {
    start: usize,
    included_spans: Vec<(usize, usize)>,
}

struct BmffHashPlan {
    ranges: Vec<(usize, usize)>,
    roots: Vec<BmffRootContribution>,
}

fn is_full_box(box_type: &[u8; 4]) -> bool {
    matches!(
        box_type,
        b"pdin"
            | b"mvhd"
            | b"tkhd"
            | b"mdhd"
            | b"hdlr"
            | b"nmhd"
            | b"elng"
            | b"stsd"
            | b"stdp"
            | b"stts"
            | b"ctts"
            | b"cslg"
            | b"stss"
            | b"stsh"
            | b"elst"
            | b"dref"
            | b"stsz"
            | b"stz2"
            | b"stsc"
            | b"stco"
            | b"co64"
            | b"padb"
            | b"subs"
            | b"saiz"
            | b"saio"
            | b"mehd"
            | b"trex"
            | b"mfhd"
            | b"tfhd"
            | b"trun"
            | b"tfra"
            | b"mfro"
            | b"tfdt"
            | b"leva"
            | b"trep"
            | b"assp"
            | b"sbgp"
            | b"sgpd"
            | b"csgp"
            | b"cprt"
            | b"tsel"
            | b"kind"
            | b"meta"
            | b"xml "
            | b"bxml"
            | b"iloc"
            | b"pitm"
            | b"ipro"
            | b"infe"
            | b"iinf"
            | b"iref"
            | b"ipma"
            | b"schm"
            | b"fiin"
            | b"fpar"
            | b"fecr"
            | b"gitn"
            | b"fire"
            | b"stri"
            | b"stsg"
            | b"stvi"
            | b"csch"
            | b"sidx"
            | b"ssix"
            | b"prft"
            | b"srpp"
            | b"vmhd"
            | b"smhd"
            | b"srat"
            | b"chnl"
            | b"dmix"
            | b"txtC"
            | b"mime"
            | b"uri "
            | b"uriI"
            | b"hmhd"
            | b"sthd"
            | b"vvhd"
            | b"medc"
    )
}

fn meta_has_full_box_header(data: &[u8], payload_start: usize, end: usize) -> bool {
    if payload_start + 8 > end {
        return true;
    }
    let child_size = be_u32(data, payload_start).unwrap_or(0) as usize;
    !(child_size >= 8 && payload_start.saturating_add(child_size) <= end)
}

fn invalid_bmff_xpath() -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail: "BMFF exclusion xpath is invalid",
    }
}

fn bmff_exclusion_matching_exceeds_bounds() -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail: "BMFF exclusion matching exceeds verifier bounds",
    }
}

fn is_c2pa_type_selector(selector: &str) -> bool {
    matches!(
        selector.trim(),
        "type=c2pa"
            | "type='c2pa'"
            | "type=\"c2pa\""
            | "@type=c2pa"
            | "@type='c2pa'"
            | "@type=\"c2pa\""
    )
}

fn parse_bmff_xpath_component(component: &str) -> Result<BmffXpathComponent, FormatError> {
    let bytes = component.as_bytes();
    if bytes.len() < 4 || !bytes[..4].iter().all(|b| b.is_ascii()) {
        return Err(invalid_bmff_xpath());
    }
    if bytes.len() > 4 && !component.is_ascii() {
        return Err(invalid_bmff_xpath());
    }

    let mut box_type = [0u8; 4];
    box_type.copy_from_slice(&bytes[..4]);
    let mut occurrence = None;
    let mut c2pa_uuid = false;
    let mut rest = &component[4..];
    while !rest.is_empty() {
        if !rest.starts_with('[') {
            return Err(invalid_bmff_xpath());
        }
        let close = rest.find(']').ok_or_else(invalid_bmff_xpath)?;
        let selector = rest[1..close].trim();
        if selector.is_empty() {
            return Err(invalid_bmff_xpath());
        }
        if selector.bytes().all(|b| b.is_ascii_digit()) {
            let index = selector
                .parse::<usize>()
                .ok()
                .filter(|index| *index > 0)
                .ok_or_else(invalid_bmff_xpath)?;
            if occurrence.replace(index).is_some() {
                return Err(invalid_bmff_xpath());
            }
        } else if is_c2pa_type_selector(selector) {
            if c2pa_uuid {
                return Err(invalid_bmff_xpath());
            }
            c2pa_uuid = true;
        } else {
            return Err(invalid_bmff_xpath());
        }
        rest = &rest[close + 1..];
    }
    if c2pa_uuid && box_type != *TYPE_UUID {
        return Err(invalid_bmff_xpath());
    }
    Ok(BmffXpathComponent {
        box_type,
        occurrence,
        c2pa_uuid,
    })
}

fn parse_bmff_xpath(xpath: &str) -> Result<Vec<BmffXpathComponent>, FormatError> {
    if !xpath.starts_with('/') || xpath.len() > MAX_BMFF_XPATH_BYTES {
        return Err(invalid_bmff_xpath());
    }
    let mut components = Vec::new();
    for component in xpath.split('/').skip(1) {
        if component.is_empty() {
            return Err(invalid_bmff_xpath());
        }
        if components.len() >= MAX_BMFF_HASH_DEPTH {
            return Err(invalid_bmff_xpath());
        }
        components.push(parse_bmff_xpath_component(component)?);
    }
    if components.is_empty() {
        return Err(invalid_bmff_xpath());
    }
    if components.len() == 1
        && components[0].box_type == *TYPE_UUID
        && components[0].occurrence.is_none()
        && !components[0].c2pa_uuid
    {
        components[0].c2pa_uuid = true;
    }
    Ok(components)
}

fn path_matches(path: &[HashPathComponent], xpath: &[BmffXpathComponent]) -> bool {
    path.len() == xpath.len()
        && path.iter().zip(xpath).all(|(actual, expected)| {
            actual.box_type == expected.box_type
                && expected
                    .occurrence
                    .is_none_or(|occurrence| occurrence == actual.occurrence)
                && (!expected.c2pa_uuid || actual.c2pa_uuid)
        })
}

fn collect_hash_boxes(
    data: &[u8],
    lo: usize,
    hi: usize,
    parent_path: &[HashPathComponent],
    depth: usize,
    top_level: bool,
    out: &mut Vec<HashBox>,
) -> Result<(), FormatError> {
    if depth >= MAX_BMFF_HASH_DEPTH || out.len() > MAX_BMFF_HASH_BOXES {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "BMFF box tree exceeds verifier bounds",
        });
    }
    let mut boxes = Vec::new();
    let mut too_many_boxes = false;
    walk_boxes_range(data, lo, hi, &mut |b| {
        if out.len() + boxes.len() >= MAX_BMFF_HASH_BOXES {
            too_many_boxes = true;
        } else {
            boxes.push((b.box_type, b.start, b.payload_start, b.end));
        }
    })?;
    if too_many_boxes {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "BMFF box count exceeds verifier bound",
        });
    }
    let mut occurrences = std::collections::BTreeMap::<[u8; 4], usize>::new();
    for (box_type, start, payload_start, end) in boxes {
        let b = IsoBox {
            box_type,
            start,
            payload_start,
            end,
        };
        if out.len() >= MAX_BMFF_HASH_BOXES {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "BMFF box count exceeds verifier bound",
            });
        }
        let occurrence = occurrences.entry(b.box_type).or_insert(0);
        *occurrence += 1;
        let c2pa_uuid = &b.box_type == TYPE_UUID && is_c2pa_uuid(data, &b);
        let mut path = Vec::with_capacity(parent_path.len() + 1);
        path.extend_from_slice(parent_path);
        path.push(HashPathComponent {
            box_type: b.box_type,
            occurrence: *occurrence,
            c2pa_uuid,
        });
        let ext_start = if c2pa_uuid {
            b.payload_start.checked_add(16)
        } else if is_full_box(&b.box_type) {
            Some(b.payload_start)
        } else {
            None
        };
        let (version, flags) = ext_start
            .filter(|start| start + 4 <= b.end)
            .map(|start| {
                (
                    Some(data[start]),
                    Some(u32::from_be_bytes([
                        0,
                        data[start + 1],
                        data[start + 2],
                        data[start + 3],
                    ])),
                )
            })
            .unwrap_or((None, None));
        out.push(HashBox {
            path: path.clone(),
            start: b.start,
            end: b.end,
            version,
            flags,
            top_level,
        });

        let child_start = if &b.box_type == b"meta" {
            if meta_has_full_box_header(data, b.payload_start, b.end) {
                b.payload_start + 4
            } else {
                b.payload_start
            }
        } else if HASH_CONTAINER_TYPES.contains(&&b.box_type) {
            b.payload_start
        } else {
            continue;
        };
        if child_start < b.end {
            collect_hash_boxes(data, child_start, b.end, &path, depth + 1, false, out)?;
        }
    }
    Ok(())
}

fn exclusion_matches(
    data: &[u8],
    b: &HashBox,
    exclusion: &BmffExclusionMap,
    xpath: &[BmffXpathComponent],
) -> bool {
    if !path_matches(&b.path, xpath)
        || exclusion
            .length
            .is_some_and(|length| length != b.end - b.start)
    {
        return false;
    }
    if exclusion
        .version
        .is_some_and(|expected| b.version != Some(expected))
    {
        return false;
    }
    if let Some(expected) = exclusion.flags {
        let Some(actual) = b.flags else {
            return false;
        };
        if (exclusion.exact && expected != actual)
            || (!exclusion.exact && (actual & expected) != expected)
        {
            return false;
        }
    }
    exclusion.data.iter().all(|item| {
        b.start
            .checked_add(item.offset)
            .and_then(|start| start.checked_add(item.value.len()).map(|end| (start, end)))
            .is_some_and(|(start, end)| end <= b.end && data[start..end] == item.value)
    })
}

fn normalized_bmff_ranges(
    data: &[u8],
    exclusions: &[BmffExclusionMap],
) -> Result<BmffHashPlan, FormatError> {
    let mut boxes = Vec::new();
    collect_hash_boxes(data, 0, data.len(), &[], 0, true, &mut boxes)?;
    let parsed_exclusions = exclusions
        .iter()
        .map(|exclusion| parse_bmff_xpath(&exclusion.xpath).map(|xpath| (exclusion, xpath)))
        .collect::<Result<Vec<_>, _>>()?;
    let total_data_qualifiers = exclusions
        .iter()
        .try_fold(0usize, |total, exclusion| {
            total.checked_add(exclusion.data.len())
        })
        .ok_or_else(bmff_exclusion_matching_exceeds_bounds)?;
    let total_subset_entries = exclusions
        .iter()
        .try_fold(0usize, |total, exclusion| {
            total.checked_add(exclusion.subset.len())
        })
        .ok_or_else(bmff_exclusion_matching_exceeds_bounds)?;
    let total_data_bytes = exclusions
        .iter()
        .flat_map(|exclusion| &exclusion.data)
        .try_fold(0usize, |total, qualifier| {
            total.checked_add(qualifier.value.len())
        })
        .ok_or_else(bmff_exclusion_matching_exceeds_bounds)?;
    if total_data_qualifiers > MAX_BMFF_EXCLUSION_DATA_QUALIFIERS
        || total_data_bytes > MAX_BMFF_EXCLUSION_DATA_BYTES
        || total_subset_entries > MAX_BMFF_EXCLUSION_SUBSETS
    {
        return Err(bmff_exclusion_matching_exceeds_bounds());
    }
    let work_exceeds = |units: usize| {
        units > 0
            && boxes
                .len()
                .checked_mul(units)
                .is_none_or(|checks| checks > MAX_BMFF_EXCLUSION_MATCH_CHECKS)
    };
    if parsed_exclusions
        .len()
        .checked_mul(boxes.len())
        .is_none_or(|checks| checks > MAX_BMFF_EXCLUSION_MATCH_CHECKS)
        || work_exceeds(total_data_qualifiers)
        || work_exceeds(total_data_bytes)
        || work_exceeds(total_subset_entries)
    {
        return Err(bmff_exclusion_matching_exceeds_bounds());
    }
    let mut ranges = Vec::new();
    for (exclusion, xpath) in &parsed_exclusions {
        for b in boxes
            .iter()
            .filter(|candidate| exclusion_matches(data, candidate, exclusion, xpath))
        {
            if exclusion.subset.is_empty() {
                if ranges.len() >= MAX_BMFF_EXCLUSION_RANGES {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "BMFF exclusion range count exceeds verifier bound",
                    });
                }
                ranges.push((b.start, b.end));
                continue;
            }
            let box_len = b.end - b.start;
            for subset in &exclusion.subset {
                if subset.offset >= box_len {
                    continue;
                }
                let start = b.start + subset.offset;
                let end = if subset.length == 0 {
                    b.end
                } else {
                    start
                        .checked_add(subset.length)
                        .map_or(b.end, |end| end.min(b.end))
                };
                if start == end {
                    continue;
                }
                if ranges.len() >= MAX_BMFF_EXCLUSION_RANGES {
                    return Err(FormatError::InvalidStructure {
                        format: FMT,
                        detail: "BMFF exclusion range count exceeds verifier bound",
                    });
                }
                ranges.push((start, end));
            }
        }
    }
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if end > data.len() || start > end {
            return Err(FormatError::InvalidStructure {
                format: FMT,
                detail: "BMFF exclusion lies outside the asset",
            });
        }
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else if start != end {
            merged.push((start, end));
        }
    }

    let mut roots = Vec::new();
    let mut range_cursor = 0usize;
    for b in boxes.iter().filter(|b| b.top_level) {
        while range_cursor < merged.len() && merged[range_cursor].1 <= b.start {
            range_cursor += 1;
        }
        let mut included_spans = Vec::new();
        let mut pos = b.start;
        let mut i = range_cursor;
        while i < merged.len() && merged[i].0 < b.end {
            let (excluded_start, excluded_end) = merged[i];
            if pos < excluded_start {
                included_spans.push((pos, excluded_start.min(b.end)));
            }
            if excluded_end > pos {
                pos = excluded_end.min(b.end);
            }
            if pos >= b.end {
                break;
            }
            i += 1;
        }
        if pos < b.end {
            included_spans.push((pos, b.end));
        }
        if !included_spans.is_empty() {
            roots.push(BmffRootContribution {
                start: b.start,
                included_spans,
            });
        }
    }

    Ok(BmffHashPlan {
        ranges: merged,
        roots,
    })
}

/// A multi-algorithm SHA hasher used for BMFF hard-binding computation.
///
/// Kept private to this module: BMFF is the only format whose hard binding is
/// computed structurally (with box-offset markers) rather than over a plain
/// byte range, so it owns its hashing primitive.
enum BmffHasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl BmffHasher {
    fn new(alg: &str) -> Option<Self> {
        use sha2::Digest;
        Some(match alg {
            "sha256" => Self::Sha256(sha2::Sha256::new()),
            "sha384" => Self::Sha384(sha2::Sha384::new()),
            "sha512" => Self::Sha512(sha2::Sha512::new()),
            _ => return None,
        })
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        use sha2::Digest;
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha384(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Compute a `c2pa.hash.bmff.v2` / `c2pa.hash.bmff.v3` hard-binding hash over `data`.
///
/// The BMFF hash is **not** a plain "whole file minus excluded byte ranges"
/// digest. Per the C2PA BMFF-based hash algorithm (V2 and V3), the asset is
/// hashed box-by-box: for every top-level box that is *not* fully excluded, the
/// box's 8-byte big-endian start offset is hashed first (the "BMFF offset
/// marker"), immediately followed by the box's bytes. Fully-excluded boxes
/// contribute nothing — neither a marker nor their bytes. This is what c2pa-rs
/// (`bmff_to_jumbf_exclusions` + `hash_stream_by_alg`) produces, so the result
/// is byte-exact with the reference implementation.
///
/// `xpaths` are the assertion's exclusion box paths (e.g. `/ftyp`, `/uuid`,
/// `/mfra`, `/free`, `/skip`). The `/uuid` path excludes **only** the C2PA
/// manifest box (identified by its user-type UUID at the payload start, which is
/// exactly the `data`/`offset` match the assertion encodes); any other `uuid`
/// box is content and is hashed normally. Streams the asset without copying box
/// payloads. Returns `None`-equivalent via [`FormatError::UnsupportedVariant`]
/// for an unknown hash algorithm.
pub fn bmff_hash(data: &[u8], alg: &str, xpaths: &[String]) -> Result<Vec<u8>, FormatError> {
    let mut hasher = BmffHasher::new(alg).ok_or(FormatError::UnsupportedVariant {
        format: FMT,
        detail: "unsupported bmff hash algorithm",
    })?;
    let wanted = xpath_box_types(xpaths);
    walk_iso_boxes(data, FMT, |b| {
        // A box is fully excluded when its type matches an exclusion path; for
        // `/uuid` only the C2PA manifest box matches (the assertion's data/offset
        // qualifier), so other `uuid` boxes remain content and are hashed.
        let excluded =
            wanted.contains(&b.box_type) && (&b.box_type != TYPE_UUID || is_c2pa_uuid(data, b));
        if excluded {
            return;
        }
        // BMFF offset marker: 8-byte big-endian box start offset, then the box.
        hasher.update(&(b.start as u64).to_be_bytes());
        hasher.update(&data[b.start..b.end]);
    })?;
    Ok(hasher.finalize())
}

/// Chunk size for streaming box payloads through the hasher (1 MiB). Bounds
/// peak memory to this regardless of asset size, so hours-long video can be
/// hashed without loading the whole file.
const STREAM_CHUNK: usize = 1 << 20;

/// Compute a BMFF V2/V3 hash using the assertion's complete exclusion maps,
/// including nested xpaths, match qualifiers, and partial-box subsets.
pub fn bmff_hash_with_exclusions(
    data: &[u8],
    alg: &str,
    exclusions: &[BmffExclusionMap],
) -> Result<Vec<u8>, FormatError> {
    let mut hasher = BmffHasher::new(alg).ok_or(FormatError::UnsupportedVariant {
        format: FMT,
        detail: "unsupported bmff hash algorithm",
    })?;
    let BmffHashPlan { roots, .. } = normalized_bmff_ranges(data, exclusions)?;
    for root in roots {
        hasher.update(&(root.start as u64).to_be_bytes());
        for (start, end) in root.included_spans {
            hasher.update(&data[start..end]);
        }
    }
    Ok(hasher.finalize())
}

/// Streaming equivalent of [`bmff_hash`] for assets too large to hold in memory.
///
/// Reads only top-level box headers (and the first 24 bytes of each `uuid` box,
/// to identify the C2PA manifest box) by seeking, then hashes each non-excluded
/// top-level box by streaming its bytes through the hasher in [`STREAM_CHUNK`]
/// blocks. Produces the byte-identical digest [`bmff_hash`] would for the same
/// asset: the same 8-byte big-endian offset markers followed by the box bytes.
///
/// `reader` must be positioned at the start of the asset; it is seeked freely.
pub fn bmff_hash_reader<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    alg: &str,
    xpaths: &[String],
) -> Result<Vec<u8>, FormatError> {
    use std::io::SeekFrom;

    let mut hasher = BmffHasher::new(alg).ok_or(FormatError::UnsupportedVariant {
        format: FMT,
        detail: "unsupported bmff hash algorithm",
    })?;
    let wanted = xpath_box_types(xpaths);

    let total_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|_| FormatError::Truncated(FMT))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| FormatError::Truncated(FMT))?;

    let mut pos: u64 = 0;
    let mut chunk = vec![0u8; STREAM_CHUNK];
    while pos + 8 <= total_len {
        reader
            .seek(SeekFrom::Start(pos))
            .map_err(|_| FormatError::Truncated(FMT))?;
        let mut hdr = [0u8; 16];
        // Read up to 16 header bytes (8 minimum; 16 for the 64-bit size form).
        let avail = (total_len - pos).min(16) as usize;
        reader
            .read_exact(&mut hdr[..avail])
            .map_err(|_| FormatError::Truncated(FMT))?;

        let size32 = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
        let mut box_type = [0u8; 4];
        box_type.copy_from_slice(&hdr[4..8]);
        let end: u64 = if size32 == 1 {
            if avail < 16 {
                return Err(FormatError::Truncated(FMT));
            }
            let large = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            if large < 16 || pos + large > total_len {
                return Err(FormatError::Truncated(FMT));
            }
            pos + large
        } else if size32 == 0 {
            total_len
        } else {
            if size32 < 8 || pos + size32 > total_len {
                return Err(FormatError::Truncated(FMT));
            }
            pos + size32
        };

        // Decide exclusion. For `/uuid`, only the C2PA manifest box is excluded;
        // read the 16-byte user-type UUID (right after the 8-byte header) to test.
        let mut excluded = wanted.contains(&box_type);
        if excluded && &box_type == TYPE_UUID {
            let mut user_uuid = [0u8; 16];
            reader
                .seek(SeekFrom::Start(pos + 8))
                .map_err(|_| FormatError::Truncated(FMT))?;
            if reader.read_exact(&mut user_uuid).is_err()
                || user_uuid != crate::c2pa_formats::C2PA_BMFF_UUID
            {
                excluded = false;
            }
        }

        if !excluded {
            // Offset marker, then the full box bytes streamed in bounded chunks.
            hasher.update(&pos.to_be_bytes());
            reader
                .seek(SeekFrom::Start(pos))
                .map_err(|_| FormatError::Truncated(FMT))?;
            let mut remaining = (end - pos) as usize;
            while remaining > 0 {
                let n = remaining.min(STREAM_CHUNK);
                reader
                    .read_exact(&mut chunk[..n])
                    .map_err(|_| FormatError::Truncated(FMT))?;
                hasher.update(&chunk[..n]);
                remaining -= n;
            }
        }

        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(hasher.finalize())
}

/// Remove every existing C2PA `uuid` box, leaving all other top-level boxes
/// and their order untouched. A no-op when the asset has no manifest.
///
/// Removing bytes shifts everything after the removed box, so the absolute
/// file offsets in `stco`/`co64`/`iloc`/`tfhd` tables are re-based by the net
/// removed length (see [`patch_absolute_offsets`]).
#[cfg(test)]
pub(crate) fn strip(asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    check_bmff(asset)?;
    let mut out = Vec::with_capacity(asset.len());
    let mut cursor = 0usize;
    walk_iso_boxes(asset, FMT, |b| {
        if is_c2pa_uuid(asset, b) {
            out.extend_from_slice(&asset[cursor..b.start]);
            cursor = b.end;
        }
    })?;
    out.extend_from_slice(&asset[cursor..]);
    let removed = asset.len() - out.len();
    if removed > 0 {
        patch_absolute_offsets(&mut out, -(removed as i64))?;
    }
    Ok(out)
}

/// Build the exact top-level C2PA UUID carrier for a manifest store.
#[cfg(test)]
pub(crate) fn build_c2pa_uuid_box(manifest_store: &[u8]) -> Vec<u8> {
    // Box payload (c2pa-rs BMFF layout): C2PA UUID (16) + version+flags (4) +
    // null-terminated purpose label "manifest" (9) + 8 reserved/merkle-offset
    // bytes + the JUMBF manifest store.
    const LABEL: &[u8] = b"manifest\0";
    let prefix_len = 4 + LABEL.len() + 8;
    let payload_len = 16 + prefix_len + manifest_store.len();
    let header = iso_box_header(TYPE_UUID, payload_len);
    let mut boxed = Vec::with_capacity(header.len() + payload_len);
    boxed.extend_from_slice(&header);
    boxed.extend_from_slice(&crate::c2pa_formats::C2PA_BMFF_UUID);
    boxed.extend_from_slice(&[0, 0, 0, 0]);
    boxed.extend_from_slice(LABEL);
    boxed.extend_from_slice(&[0u8; 8]);
    boxed.extend_from_slice(manifest_store);
    boxed
}

/// Insert a C2PA `uuid` box after `ftyp` (or at the start if absent).
///
/// Any C2PA `uuid` box already present is stripped first: prior insertion
/// always landed the new box first in file order, so a first-match reader
/// happened to pick up the fresh manifest, but the stale box was never
/// actually removed (permanent orphan bytes, and one insertion-point change
/// away from silently flipping to a stale-wins bug).
///
/// Inserting the box shifts every byte after `ftyp`, so the media data the
/// `meta/iloc` (HEIF/AVIF items), `stco`/`co64` (chunk offsets), and `tfhd`
/// (fragment base offsets) tables point at moves by the box length. Those
/// tables hold ABSOLUTE file offsets; without re-basing them, readers decode
/// manifest bytes as media payload (blank AVIF images with valid manifests).
/// [`patch_absolute_offsets`] applies the same adjustment set as c2pa-rs's
/// `adjust_known_offsets`.
#[cfg(test)]
pub(crate) fn embed(asset: &[u8], manifest_store: &[u8]) -> Result<Vec<u8>, FormatError> {
    let clean = strip(asset)?;
    let mut insert_at = 0usize;
    walk_iso_boxes(&clean, FMT, |b| {
        if &b.box_type == TYPE_FTYP && b.start == 0 {
            insert_at = b.end;
        }
    })?;

    let boxed = build_c2pa_uuid_box(manifest_store);

    let mut out = Vec::with_capacity(clean.len() + boxed.len());
    out.extend_from_slice(&clean[..insert_at]);
    out.extend_from_slice(&boxed);
    out.extend_from_slice(&clean[insert_at..]);
    patch_absolute_offsets(&mut out, boxed.len() as i64)?;
    Ok(out)
}

/// The C2PA `uuid` box byte span as a single exclusion.
pub(crate) fn exclusions(data: &[u8]) -> Result<Vec<DataHashExclusion>, FormatError> {
    let mut ex = Vec::new();
    walk_iso_boxes(data, FMT, |b| {
        if is_c2pa_uuid(data, b) {
            ex.push(DataHashExclusion {
                start: b.start,
                length: b.end - b.start,
            });
        }
    })?;
    Ok(ex)
}

// ---------------------------------------------------------------------------
// Absolute file-offset re-basing (stco / co64 / meta iloc / tfhd)
// ---------------------------------------------------------------------------

/// Container boxes descended into when hunting offset tables. Plain
/// containers: children start at the payload. (`meta` is a FullBox and is
/// special-cased: children start 4 bytes in, after version+flags.)
#[cfg(test)]
const OFFSET_CONTAINERS: [&[u8; 4]; 8] = [
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"moof", b"traf", b"mfra",
];

/// Defensive recursion bound; real BMFF trees are < 8 deep on these paths.
#[cfg(test)]
const MAX_BOX_DEPTH: usize = 16;

/// An offset-bearing box found by [`collect_offset_boxes`]: its kind plus the
/// `(payload_start, end)` span of its payload within the file.
#[cfg(test)]
enum OffsetBoxKind {
    Stco,
    Co64,
    Iloc,
    Tfhd,
}

/// Walk boxes within `data[lo..hi)` (same header rules as `walk_iso_boxes`:
/// 32-bit sizes, the 64-bit `largesize` escape, and size 0 = to-end-of-range).
fn walk_boxes_range(
    data: &[u8],
    lo: usize,
    hi: usize,
    f: &mut dyn FnMut(&IsoBox),
) -> Result<(), FormatError> {
    let mut pos = lo;
    while pos + 8 <= hi {
        let size32 = be_u32(data, pos).ok_or(FormatError::Truncated(FMT))? as u64;
        let mut box_type = [0u8; 4];
        box_type.copy_from_slice(&data[pos + 4..pos + 8]);
        let (payload_start, end) = if size32 == 1 {
            let large = be_u64(data, pos + 8).ok_or(FormatError::Truncated(FMT))?;
            let end = pos
                .checked_add(large as usize)
                .filter(|&e| (large as usize) >= 16 && e <= hi)
                .ok_or(FormatError::Truncated(FMT))?;
            (pos + 16, end)
        } else if size32 == 0 {
            (pos + 8, hi)
        } else {
            let end = pos
                .checked_add(size32 as usize)
                .filter(|&e| (size32 as usize) >= 8 && e <= hi)
                .ok_or(FormatError::Truncated(FMT))?;
            (pos + 8, end)
        };
        f(&IsoBox {
            box_type,
            start: pos,
            payload_start,
            end,
        });
        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(())
}

/// Recursively collect every `stco`/`co64`/`iloc`/`tfhd` payload span under
/// `data[lo..hi)`, descending into the known container boxes.
#[cfg(test)]
fn collect_offset_boxes(
    data: &[u8],
    lo: usize,
    hi: usize,
    depth: usize,
    out: &mut Vec<(OffsetBoxKind, usize, usize)>,
) -> Result<(), FormatError> {
    if depth > MAX_BOX_DEPTH {
        return Err(FormatError::InvalidStructure {
            format: FMT,
            detail: "box nesting exceeds depth bound",
        });
    }
    let mut spans: Vec<([u8; 4], usize, usize)> = Vec::new();
    walk_boxes_range(data, lo, hi, &mut |b| {
        spans.push((b.box_type, b.payload_start, b.end));
    })?;
    for (box_type, payload_start, end) in spans {
        match &box_type {
            b"stco" => out.push((OffsetBoxKind::Stco, payload_start, end)),
            b"co64" => out.push((OffsetBoxKind::Co64, payload_start, end)),
            b"iloc" => out.push((OffsetBoxKind::Iloc, payload_start, end)),
            b"tfhd" => out.push((OffsetBoxKind::Tfhd, payload_start, end)),
            b"meta" => {
                // FullBox: 4 bytes of version+flags precede the child boxes.
                if payload_start + 4 <= end {
                    collect_offset_boxes(data, payload_start + 4, end, depth + 1, out)?;
                }
            }
            t if OFFSET_CONTAINERS.contains(&t) => {
                collect_offset_boxes(data, payload_start, end, depth + 1, out)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Apply `delta` to the big-endian u32 at `off`, failing on wrap.
#[cfg(test)]
fn apply_delta_u32(data: &mut [u8], off: usize, delta: i64) -> Result<(), FormatError> {
    let cur = be_u32(data, off).ok_or(FormatError::Truncated(FMT))? as i64;
    let new = cur
        .checked_add(delta)
        .filter(|v| (0..=u32::MAX as i64).contains(v))
        .ok_or(FormatError::InvalidStructure {
            format: FMT,
            detail: "offset adjustment out of u32 range",
        })?;
    data[off..off + 4].copy_from_slice(&(new as u32).to_be_bytes());
    Ok(())
}

/// Apply `delta` to the big-endian u64 at `off`, failing on wrap.
#[cfg(test)]
fn apply_delta_u64(data: &mut [u8], off: usize, delta: i64) -> Result<(), FormatError> {
    let cur = be_u64(data, off).ok_or(FormatError::Truncated(FMT))?;
    let new = if delta < 0 {
        cur.checked_sub(delta.unsigned_abs())
    } else {
        cur.checked_add(delta as u64)
    }
    .ok_or(FormatError::InvalidStructure {
        format: FMT,
        detail: "offset adjustment out of u64 range",
    })?;
    data[off..off + 8].copy_from_slice(&new.to_be_bytes());
    Ok(())
}

/// Re-base a `stco` (u32) or `co64` (u64) chunk-offset table by `delta`.
#[cfg(test)]
fn patch_chunk_offsets(
    data: &mut [u8],
    payload_start: usize,
    end: usize,
    wide: bool,
    delta: i64,
) -> Result<(), FormatError> {
    // FullBox: version+flags (4), then entry_count (4), then the entries.
    let count = be_u32(data, payload_start + 4).ok_or(FormatError::Truncated(FMT))? as usize;
    let entry_size = if wide { 8 } else { 4 };
    let entries_start = payload_start + 8;
    let needed = count
        .checked_mul(entry_size)
        .and_then(|n| entries_start.checked_add(n))
        .ok_or(FormatError::Truncated(FMT))?;
    if needed > end {
        return Err(FormatError::Truncated(FMT));
    }
    for i in 0..count {
        let off = entries_start + i * entry_size;
        if wide {
            apply_delta_u64(data, off, delta)?;
        } else {
            apply_delta_u32(data, off, delta)?;
        }
    }
    Ok(())
}

/// Re-base a `tfhd` fragment header's `base_data_offset` (present only when
/// flag bit 0 is set) by `delta`.
#[cfg(test)]
fn patch_tfhd(
    data: &mut [u8],
    payload_start: usize,
    end: usize,
    delta: i64,
) -> Result<(), FormatError> {
    let flags = be_u24(data, payload_start + 1).ok_or(FormatError::Truncated(FMT))?;
    if flags & 1 == 0 {
        return Ok(()); // no base_data_offset field
    }
    // version+flags (4) + track_ID (4), then base_data_offset (u64).
    let off = payload_start + 8;
    if off + 8 > end {
        return Err(FormatError::Truncated(FMT));
    }
    apply_delta_u64(data, off, delta)
}

/// Re-base a `meta`/`iloc` item-location table by `delta` (ISO 14496-12 8.11.3).
///
/// Only `construction_method == 0` (file-absolute) locations are touched:
/// the item's `base_offset` when present, otherwise each nonzero
/// `extent_offset` (extent offsets are base-relative when a base exists).
/// `idat`-relative (method 1) and item-relative (method 2) locations do not
/// move when file bytes shift.
#[cfg(test)]
fn patch_iloc(
    data: &mut [u8],
    payload_start: usize,
    end: usize,
    delta: i64,
) -> Result<(), FormatError> {
    let take_u16 = |data: &[u8], pos: &mut usize| -> Result<u16, FormatError> {
        let v = be_u16(data, *pos).ok_or(FormatError::Truncated(FMT))?;
        *pos += 2;
        Ok(v)
    };
    let version = *data.get(payload_start).ok_or(FormatError::Truncated(FMT))?;
    if version > 2 {
        return Err(FormatError::UnsupportedVariant {
            format: FMT,
            detail: "iloc version > 2",
        });
    }
    let sizes = data
        .get(payload_start + 4..payload_start + 6)
        .ok_or(FormatError::Truncated(FMT))?;
    let offset_size = (sizes[0] >> 4) as usize;
    let length_size = (sizes[0] & 0x0f) as usize;
    let base_offset_size = (sizes[1] >> 4) as usize;
    let index_size = (sizes[1] & 0x0f) as usize;
    for s in [offset_size, length_size, base_offset_size, index_size] {
        if s != 0 && s != 4 && s != 8 {
            return Err(FormatError::UnsupportedVariant {
                format: FMT,
                detail: "iloc field size not 0/4/8",
            });
        }
    }

    let mut pos = payload_start + 6;
    let item_count = if version < 2 {
        take_u16(data, &mut pos)? as u32
    } else {
        let v = be_u32(data, pos).ok_or(FormatError::Truncated(FMT))?;
        pos += 4;
        v
    };

    for _ in 0..item_count {
        // item_ID
        pos += if version < 2 { 2 } else { 4 };
        // construction_method (low nibble of the second reserved byte).
        let construction_method = if version >= 1 {
            let b = *data.get(pos + 1).ok_or(FormatError::Truncated(FMT))?;
            pos += 2;
            b & 0x0f
        } else {
            0
        };
        // data_reference_index
        pos += 2;
        let base_offset_pos = pos;
        let base_offset = match base_offset_size {
            0 => 0u64,
            4 => be_u32(data, pos).ok_or(FormatError::Truncated(FMT))? as u64,
            8 => be_u64(data, pos).ok_or(FormatError::Truncated(FMT))?,
            _ => unreachable!("validated above"),
        };
        pos += base_offset_size;
        if construction_method == 0 && base_offset != 0 {
            match base_offset_size {
                4 => apply_delta_u32(data, base_offset_pos, delta)?,
                8 => apply_delta_u64(data, base_offset_pos, delta)?,
                _ => unreachable!("nonzero base_offset implies size 4 or 8"),
            }
        }
        let extent_count = take_u16(data, &mut pos)?;
        for _ in 0..extent_count {
            if (version == 1 || version == 2) && index_size > 0 {
                pos += index_size;
            }
            let extent_offset_pos = pos;
            let extent_offset = match offset_size {
                0 => 0u64,
                4 => be_u32(data, pos).ok_or(FormatError::Truncated(FMT))? as u64,
                8 => be_u64(data, pos).ok_or(FormatError::Truncated(FMT))?,
                _ => unreachable!("validated above"),
            };
            pos += offset_size;
            if construction_method == 0 && base_offset == 0 && extent_offset != 0 {
                match offset_size {
                    4 => apply_delta_u32(data, extent_offset_pos, delta)?,
                    8 => apply_delta_u64(data, extent_offset_pos, delta)?,
                    _ => unreachable!("nonzero extent_offset implies size 4 or 8"),
                }
            }
            pos += length_size;
        }
        if pos > end {
            return Err(FormatError::Truncated(FMT));
        }
    }
    Ok(())
}

/// Re-base every absolute file offset in `data`'s offset tables by `delta`.
///
/// BMFF offset tables address media payload by ABSOLUTE file position, so
/// inserting or removing a top-level box (the C2PA `uuid` manifest box)
/// invalidates them: `stco`/`co64` (chunk offsets, progressive MP4/MOV/M4A),
/// `meta`/`iloc` (item locations, HEIF/AVIF stills), and `tfhd`
/// `base_data_offset` (fragmented BMFF). This is the same adjustment set
/// c2pa-rs applies (`adjust_known_offsets`); `tfra`/`saio` (seek index /
/// encryption aux offsets) are not emitted by the still/progressive assets we
/// sign and are left untouched, matching the exclusion-based hash which never
/// covers them differently.
///
/// Offsets are adjusted unconditionally (parity with c2pa-rs): media payload
/// always sits after `ftyp`, which is the only insertion point used.
#[cfg(test)]
fn patch_absolute_offsets(data: &mut [u8], delta: i64) -> Result<(), FormatError> {
    if delta == 0 {
        return Ok(());
    }
    let mut boxes = Vec::new();
    collect_offset_boxes(data, 0, data.len(), 0, &mut boxes)?;
    for (kind, payload_start, end) in boxes {
        match kind {
            OffsetBoxKind::Stco => patch_chunk_offsets(data, payload_start, end, false, delta)?,
            OffsetBoxKind::Co64 => patch_chunk_offsets(data, payload_start, end, true, delta)?,
            OffsetBoxKind::Iloc => patch_iloc(data, payload_start, end, delta)?,
            OffsetBoxKind::Tfhd => patch_tfhd(data, payload_start, end, delta)?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_formats::tests::dummy_manifest_store;

    fn iso_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = iso_box_header(box_type, payload.len());
        v.extend_from_slice(payload);
        v
    }

    /// Minimal MP4: ftyp + a small mdat.
    fn tiny_mp4() -> Vec<u8> {
        let mut v = iso_box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2");
        v.extend_from_slice(&iso_box(b"mdat", &[0xDE, 0xAD, 0xBE, 0xEF]));
        v
    }

    #[test]
    fn roundtrip() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_mp4(), &store).unwrap();
        assert_eq!(
            extract(&embedded).unwrap().as_deref(),
            Some(store.as_slice())
        );
    }

    #[test]
    fn extraction_excludes_bytes_after_declared_jumbf_span() {
        let ordinary = dummy_manifest_store();
        let extended_size = u64::try_from(ordinary.len() + 8).unwrap();
        let mut extended = Vec::with_capacity(ordinary.len() + 8);
        extended.extend_from_slice(&1u32.to_be_bytes());
        extended.extend_from_slice(&ordinary[4..8]);
        extended.extend_from_slice(&extended_size.to_be_bytes());
        extended.extend_from_slice(&ordinary[8..]);

        for store in [ordinary, extended] {
            let mut carrier_payload = Vec::new();
            carrier_payload.extend_from_slice(&crate::c2pa_formats::C2PA_BMFF_UUID);
            carrier_payload.extend_from_slice(&[0u8; 4]);
            carrier_payload.extend_from_slice(b"manifest\0");
            carrier_payload.extend_from_slice(&[0u8; 8]);
            carrier_payload.extend_from_slice(&store);
            carrier_payload.extend_from_slice(b"carrier padding");

            let mut embedded = tiny_mp4();
            embedded.extend_from_slice(&iso_box(TYPE_UUID, &carrier_payload));
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
    }

    #[test]
    fn re_embed_replaces_manifest() {
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

        let first = embed(&tiny_mp4(), &first_store).unwrap();
        let second = embed(&first, &second_store).unwrap();
        assert_eq!(
            extract(&second).unwrap().as_deref(),
            Some(second_store.as_slice())
        );
        let mut uuid_count = 0;
        walk_iso_boxes(&second, FMT, |b| {
            if is_c2pa_uuid(&second, b) {
                uuid_count += 1;
            }
        })
        .unwrap();
        assert_eq!(
            uuid_count, 1,
            "re-embed must leave exactly one C2PA uuid box"
        );
    }

    #[test]
    fn uuid_box_after_ftyp() {
        let store = dummy_manifest_store();
        let embedded = embed(&tiny_mp4(), &store).unwrap();
        let mut types = Vec::new();
        walk_iso_boxes(&embedded, FMT, |b| types.push(b.box_type)).unwrap();
        assert_eq!(types[0], *b"ftyp");
        assert_eq!(types[1], *b"uuid");
    }

    #[test]
    fn bare_asset_has_no_manifest() {
        assert_eq!(extract(&tiny_mp4()).unwrap(), None);
    }

    #[test]
    fn rejects_truncated_box() {
        // Declares size 0x1000 but only a few bytes present.
        let bad = [0x00, 0x00, 0x10, 0x00, b'f', b't', b'y', b'p'];
        assert!(extract(&bad).is_err());
    }

    /// The BMFF hash prepends each non-excluded top-level box's 8-byte BE start
    /// offset before its bytes; excluded boxes contribute nothing.
    #[test]
    fn bmff_hash_applies_offset_markers() {
        use sha2::{Digest, Sha256};
        let asset = tiny_mp4(); // ftyp [0,?), mdat [ftyp_end, end)
        let mut ftyp_end = 0usize;
        let mut mdat = (0usize, 0usize);
        walk_iso_boxes(&asset, FMT, |b| {
            if &b.box_type == b"ftyp" {
                ftyp_end = b.end;
            } else if &b.box_type == b"mdat" {
                mdat = (b.start, b.end);
            }
        })
        .unwrap();
        // Exclude /ftyp: only mdat is hashed, with its offset marker.
        let actual = bmff_hash(&asset, "sha256", &["/ftyp".to_string()]).unwrap();
        let mut h = Sha256::new();
        h.update((mdat.0 as u64).to_be_bytes());
        h.update(&asset[mdat.0..mdat.1]);
        assert_eq!(actual.as_slice(), &h.finalize()[..]);
        assert_eq!(ftyp_end, mdat.0);

        // With no exclusions, both boxes are hashed (each with its marker), so
        // the digest differs from the ftyp-excluded one.
        let all = bmff_hash(&asset, "sha256", &[]).unwrap();
        assert_ne!(all, actual);
    }

    #[test]
    fn partial_root_subset_still_hashes_offset_marker() {
        use sha2::{Digest, Sha256};

        let asset = tiny_mp4();
        let mut mdat = (0usize, 0usize);
        walk_iso_boxes(&asset, FMT, |b| {
            if &b.box_type == b"mdat" {
                mdat = (b.start, b.end);
            }
        })
        .unwrap();
        let exclusions = [BmffExclusionMap {
            xpath: "/mdat".into(),
            length: None,
            data: Vec::new(),
            subset: vec![BmffSubsetMap {
                offset: 0,
                length: 1,
            }],
            version: None,
            flags: None,
            exact: true,
        }];

        let actual = bmff_hash_with_exclusions(&asset, "sha256", &exclusions).unwrap();
        let mut expected = Sha256::new();
        expected.update(0u64.to_be_bytes());
        expected.update(&asset[..mdat.0]);
        expected.update((mdat.0 as u64).to_be_bytes());
        expected.update(&asset[mdat.0 + 1..mdat.1]);
        assert_eq!(actual.as_slice(), &expected.finalize()[..]);

        let mut without_marker = Sha256::new();
        without_marker.update(0u64.to_be_bytes());
        without_marker.update(&asset[..mdat.0]);
        without_marker.update(&asset[mdat.0 + 1..mdat.1]);
        assert_ne!(actual.as_slice(), &without_marker.finalize()[..]);
    }

    #[test]
    fn bmff_hash_rejects_unknown_alg() {
        assert!(bmff_hash(&tiny_mp4(), "md5", &[]).is_err());
    }

    #[test]
    fn bmff_hash_reader_matches_in_memory() {
        use std::io::Cursor;
        let asset = tiny_mp4();
        // With and without a uuid exclusion + various algs, the streaming reader
        // must produce the byte-identical digest to the in-memory path.
        for alg in ["sha256", "sha384", "sha512"] {
            for xpaths in [vec![], vec!["/ftyp".to_string(), "/uuid".to_string()]] {
                let in_mem = bmff_hash(&asset, alg, &xpaths).unwrap();
                let mut cur = Cursor::new(asset.clone());
                let streamed = bmff_hash_reader(&mut cur, alg, &xpaths).unwrap();
                assert_eq!(in_mem, streamed, "alg={alg} xpaths={xpaths:?}");
            }
        }
    }

    #[test]
    fn bmff_hash_reader_excludes_c2pa_uuid_only() {
        use std::io::Cursor;
        // Embed a C2PA manifest (adds a C2PA uuid box), then both paths must
        // agree while excluding that uuid box under the /uuid xpath.
        let asset = embed(&tiny_mp4(), &dummy_manifest_store()).unwrap();
        let xpaths = vec!["/uuid".to_string()];
        let in_mem = bmff_hash(&asset, "sha256", &xpaths).unwrap();
        let mut cur = Cursor::new(asset.clone());
        let streamed = bmff_hash_reader(&mut cur, "sha256", &xpaths).unwrap();
        assert_eq!(in_mem, streamed);
    }

    /// FullBox wrapper: version+flags prefix then child payload.
    fn full_box(box_type: &[u8; 4], children: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; 4]; // version + flags
        payload.extend_from_slice(children);
        iso_box(box_type, &payload)
    }

    const AV1_PAYLOAD: &[u8] = b"AV1PAYLOADBYTES!";

    /// Minimal AVIF-shaped still: ftyp + meta(iloc v0) + mdat, with the iloc
    /// extent pointing at the mdat payload (file-absolute, base_offset_size 0).
    fn tiny_avif() -> Vec<u8> {
        let ftyp = iso_box(b"ftyp", b"avif\x00\x00\x00\x00avifmif1");
        // iloc v0: offset_size=4, length_size=4, base_offset_size=0; 1 item.
        let build = |extent_offset: u32| {
            let mut iloc_children = vec![0x44u8, 0x00];
            iloc_children.extend_from_slice(&1u16.to_be_bytes()); // item_count
            iloc_children.extend_from_slice(&1u16.to_be_bytes()); // item_ID
            iloc_children.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
            iloc_children.extend_from_slice(&1u16.to_be_bytes()); // extent_count
            iloc_children.extend_from_slice(&extent_offset.to_be_bytes());
            iloc_children.extend_from_slice(&(AV1_PAYLOAD.len() as u32).to_be_bytes());
            let mut iloc_payload = vec![0u8; 4]; // FullBox version+flags
            iloc_payload.extend_from_slice(&iloc_children);
            let meta = full_box(b"meta", &iso_box(b"iloc", &iloc_payload));
            let mut v = ftyp.clone();
            v.extend_from_slice(&meta);
            let mdat_payload_at = v.len() + 8;
            v.extend_from_slice(&iso_box(b"mdat", AV1_PAYLOAD));
            (v, mdat_payload_at as u32)
        };
        // Two passes: first to learn the mdat payload offset, second to point at it.
        let (_, target) = build(0);
        let (v, confirm) = build(target);
        assert_eq!(target, confirm);
        v
    }

    /// Resolve the iloc extent offset in `data` (layout from `tiny_avif`).
    fn iloc_extent_offset(data: &[u8]) -> u32 {
        let iloc = data
            .windows(4)
            .position(|w| w == b"iloc")
            .expect("iloc present");
        // size(4)+type(4) precede payload; extent_offset sits after
        // v/f(4) + sizes(2) + item_count(2) + item_ID(2) + dref(2) + extent_count(2).
        let off = iloc + 4 + 4 + 2 + 2 + 2 + 2 + 2;
        u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
    }

    /// After embedding, the iloc extent must still address the media payload:
    /// this is the AVIF blank-image regression (manifest bytes decoded as AV1).
    #[test]
    fn embed_rebases_iloc_extent_to_moved_mdat() {
        let asset = tiny_avif();
        let off = iloc_extent_offset(&asset) as usize;
        assert_eq!(&asset[off..off + AV1_PAYLOAD.len()], AV1_PAYLOAD);

        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let new_off = iloc_extent_offset(&embedded) as usize;
        assert_ne!(new_off, off, "insertion after ftyp must shift the extent");
        assert_eq!(
            &embedded[new_off..new_off + AV1_PAYLOAD.len()],
            AV1_PAYLOAD,
            "iloc extent must follow the media payload after embedding"
        );
    }

    /// Stripping the manifest must restore the original bytes exactly,
    /// including the un-shifted offset tables.
    #[test]
    fn strip_restores_original_bytes_including_offsets() {
        for asset in [tiny_avif(), tiny_stco_mp4().0] {
            let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
            assert_eq!(strip(&embedded).unwrap(), asset);
        }
    }

    /// Re-embedding (sign over signed) must keep the pointer valid: the strip
    /// inside `embed` un-shifts, the fresh insertion re-shifts.
    #[test]
    fn re_embed_keeps_iloc_extent_valid() {
        let asset = tiny_avif();
        let first = embed(&asset, &dummy_manifest_store()).unwrap();
        let second_assertion =
            crate::c2pa_core::jumbf::assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second_manifest = crate::c2pa_core::jumbf::build_manifest(
            "urn:c2pa:test:0003",
            &[second_assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        let second_store = crate::c2pa_core::jumbf::build_manifest_store(&[second_manifest]);
        let second = embed(&first, &second_store).unwrap();
        let off = iloc_extent_offset(&second) as usize;
        assert_eq!(&second[off..off + AV1_PAYLOAD.len()], AV1_PAYLOAD);
    }

    const CHUNK_PAYLOAD: &[u8] = b"CHUNKDATA";

    /// Minimal progressive MP4 with a real moov/trak/mdia/minf/stbl/stco chain
    /// whose single chunk offset addresses the mdat payload. Returns the bytes
    /// and the chunk offset.
    fn tiny_stco_mp4() -> (Vec<u8>, u32) {
        let ftyp = iso_box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2");
        let build = |chunk_offset: u32| {
            let mut stco_children = Vec::new();
            stco_children.extend_from_slice(&1u32.to_be_bytes()); // entry_count
            stco_children.extend_from_slice(&chunk_offset.to_be_bytes());
            let stco = full_box(b"stco", &stco_children);
            let moov = iso_box(
                b"moov",
                &iso_box(
                    b"trak",
                    &iso_box(b"mdia", &iso_box(b"minf", &iso_box(b"stbl", &stco))),
                ),
            );
            let mut v = ftyp.clone();
            v.extend_from_slice(&moov);
            let mdat_payload_at = v.len() + 8;
            v.extend_from_slice(&iso_box(b"mdat", CHUNK_PAYLOAD));
            (v, mdat_payload_at as u32)
        };
        let (_, target) = build(0);
        let (v, confirm) = build(target);
        assert_eq!(target, confirm);
        (v, target)
    }

    #[test]
    fn bmff_hash_honors_nested_match_and_subset_maps() {
        let (asset, _) = tiny_stco_mp4();
        let stco_type = asset.windows(4).position(|w| w == b"stco").unwrap();
        let stco_start = stco_type - 4;
        let exclusions = [BmffExclusionMap {
            xpath: "/moov/trak/mdia/minf/stbl/stco".to_string(),
            length: Some(20),
            data: vec![BmffDataMap {
                offset: 4,
                value: b"stco".to_vec(),
            }],
            subset: vec![BmffSubsetMap {
                offset: 16,
                length: 4,
            }],
            version: Some(0),
            flags: Some(0),
            exact: true,
        }];
        let expected = bmff_hash_with_exclusions(&asset, "sha256", &exclusions).unwrap();

        let mut changed_excluded_bytes = asset.clone();
        changed_excluded_bytes[stco_start + 16..stco_start + 20]
            .copy_from_slice(&0x0102_0304u32.to_be_bytes());
        assert_eq!(
            bmff_hash_with_exclusions(&changed_excluded_bytes, "sha256", &exclusions).unwrap(),
            expected,
            "bytes selected by a subset map must not affect the digest"
        );
        assert_ne!(
            bmff_hash(&changed_excluded_bytes, "sha256", &[]).unwrap(),
            bmff_hash(&asset, "sha256", &[]).unwrap(),
            "the same edit must affect an unqualified whole-file BMFF hash"
        );

        let mut wrong_match = exclusions[0].clone();
        wrong_match.data[0].value = b"nope".to_vec();
        assert_ne!(
            bmff_hash_with_exclusions(&changed_excluded_bytes, "sha256", &[wrong_match]).unwrap(),
            expected,
            "a failed data qualifier must leave the box included"
        );
    }

    /// Read the single stco entry (layout from `tiny_stco_mp4`).
    fn stco_entry(data: &[u8]) -> u32 {
        let stco = data
            .windows(4)
            .position(|w| w == b"stco")
            .expect("stco present");
        let off = stco + 4 + 4 + 4; // type tail + v/f + entry_count
        u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
    }

    /// stco chunk offsets must be re-based when the manifest box is inserted.
    #[test]
    fn embed_rebases_stco_chunk_offsets() {
        let (asset, chunk_off) = tiny_stco_mp4();
        assert_eq!(
            &asset[chunk_off as usize..chunk_off as usize + CHUNK_PAYLOAD.len()],
            CHUNK_PAYLOAD
        );
        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let new_off = stco_entry(&embedded) as usize;
        assert_ne!(new_off, chunk_off as usize);
        assert_eq!(
            &embedded[new_off..new_off + CHUNK_PAYLOAD.len()],
            CHUNK_PAYLOAD,
            "stco entry must follow the chunk after embedding"
        );
    }

    /// iloc construction_method 1 (idat-relative) offsets do not address file
    /// positions and must NOT be re-based.
    #[test]
    fn embed_leaves_idat_relative_iloc_untouched() {
        let ftyp = iso_box(b"ftyp", b"avif\x00\x00\x00\x00avifmif1");
        // iloc v1, one item, construction_method=1 (idat), extent_offset=7.
        let mut iloc_children = vec![0x44u8, 0x00];
        iloc_children.extend_from_slice(&1u16.to_be_bytes()); // item_count
        iloc_children.extend_from_slice(&1u16.to_be_bytes()); // item_ID
        iloc_children.extend_from_slice(&[0x00, 0x01]); // reserved + construction_method=1
        iloc_children.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
        iloc_children.extend_from_slice(&1u16.to_be_bytes()); // extent_count
        iloc_children.extend_from_slice(&7u32.to_be_bytes()); // extent_offset (idat-relative)
        iloc_children.extend_from_slice(&3u32.to_be_bytes()); // extent_length
        let mut iloc_payload = vec![1u8, 0, 0, 0]; // FullBox version=1
        iloc_payload.extend_from_slice(&iloc_children);
        let meta = full_box(b"meta", &iso_box(b"iloc", &iloc_payload));
        let mut asset = ftyp;
        asset.extend_from_slice(&meta);
        asset.extend_from_slice(&iso_box(b"mdat", AV1_PAYLOAD));

        let embedded = embed(&asset, &dummy_manifest_store()).unwrap();
        let iloc = embedded.windows(4).position(|w| w == b"iloc").unwrap();
        // v1 layout: extent_offset after v/f(4)+sizes(2)+count(2)+id(2)+cm(2)+dref(2)+extents(2).
        let off = iloc + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2;
        assert_eq!(
            u32::from_be_bytes(embedded[off..off + 4].try_into().unwrap()),
            7,
            "idat-relative extent offset must not move"
        );
    }

    #[test]
    fn indexed_and_unindexed_xpaths_match_sibling_occurrences() {
        let first_pssh = iso_box(b"pssh", b"first");
        let second_pssh = iso_box(b"pssh", b"second");
        let first_moov = iso_box(b"moov", &first_pssh);
        let second_moov = iso_box(b"moov", &second_pssh);
        let mut asset = first_moov.clone();
        asset.extend_from_slice(&second_moov);

        let first_start = 8;
        let second_start = first_moov.len() + 8;
        assert_eq!(
            bmff_exclusion_ranges(&asset, &["/moov[1]/pssh".into()]).unwrap(),
            vec![(first_start, first_pssh.len())]
        );
        assert_eq!(
            bmff_exclusion_ranges(&asset, &["/moov/pssh".into()]).unwrap(),
            vec![
                (first_start, first_pssh.len()),
                (second_start, second_pssh.len())
            ]
        );

        let mut siblings = first_pssh.clone();
        siblings.extend_from_slice(&second_pssh);
        let one_moov = iso_box(b"moov", &siblings);
        assert_eq!(
            bmff_exclusion_ranges(&one_moov, &["/moov/pssh[2]".into()]).unwrap(),
            vec![(8 + first_pssh.len(), second_pssh.len())]
        );
    }

    #[test]
    fn batch_box_ranges_preserve_path_order_and_share_work_bound() {
        let first = iso_box(b"free", b"first");
        let second = iso_box(b"free", b"second");
        let mut asset = first.clone();
        asset.extend_from_slice(&second);
        assert_eq!(
            bmff_box_ranges(&asset, &["/free[2]", "/free[1]"]).unwrap(),
            vec![vec![(first.len(), second.len())], vec![(0, first.len())],]
        );

        let excessive = vec!["/free"; MAX_BMFF_EXCLUSION_MATCH_CHECKS / 2 + 1];
        assert!(matches!(
            bmff_box_ranges(&asset, &excessive),
            Err(FormatError::InvalidStructure {
                detail: "BMFF exclusion matching exceeds verifier bounds",
                ..
            })
        ));
    }

    #[test]
    fn legacy_uuid_xpath_normalizes_to_the_c2pa_carrier() {
        let mut foreign_payload = vec![0xA5; 16];
        foreign_payload.extend_from_slice(b"foreign");
        let foreign = iso_box(b"uuid", &foreign_payload);
        let c2pa = build_c2pa_uuid_box(&[]);
        let c2pa_start = foreign.len();
        let mut asset = foreign;
        asset.extend_from_slice(&c2pa);

        assert_eq!(
            bmff_exclusion_ranges(&asset, &["/uuid".into()]).unwrap(),
            vec![(c2pa_start, c2pa.len())]
        );
        let full_map = BmffExclusionMap {
            xpath: "/uuid".into(),
            length: None,
            data: Vec::new(),
            subset: Vec::new(),
            version: None,
            flags: None,
            exact: true,
        };
        assert_eq!(
            normalized_bmff_ranges(&asset, &[full_map]).unwrap().ranges,
            vec![(c2pa_start, c2pa_start + c2pa.len())]
        );
    }

    #[test]
    fn fragment_leaf_hash_applies_qualified_nested_subset_exclusions() {
        let trun = iso_box(b"trun", &[0, 0, 0, 0, 1, 2, 3, 4]);
        let traf = iso_box(b"traf", &trun);
        let fragment = iso_box(b"moof", &traf);
        let trun_type = fragment
            .windows(4)
            .position(|bytes| bytes == b"trun")
            .unwrap();
        let trun_start = trun_type - 4;
        let exclusions = [BmffExclusionMap {
            xpath: "/moof/traf/trun".into(),
            length: Some(trun.len()),
            data: vec![BmffDataMap {
                offset: 4,
                value: b"trun".to_vec(),
            }],
            subset: vec![BmffSubsetMap {
                offset: 14,
                length: 2,
            }],
            version: Some(0),
            flags: Some(0),
            exact: true,
        }];
        let expected = bmff_fragment_leaf_hash(&fragment, "sha256", &exclusions).unwrap();

        let mut excluded_change = fragment.clone();
        excluded_change[trun_start + 14..trun_start + 16].copy_from_slice(&[9, 9]);
        assert_eq!(
            bmff_fragment_leaf_hash(&excluded_change, "sha256", &exclusions).unwrap(),
            expected
        );

        let mut included_change = fragment;
        included_change[trun_start + 13] ^= 0xFF;
        assert_ne!(
            bmff_fragment_leaf_hash(&included_change, "sha256", &exclusions).unwrap(),
            expected
        );
    }

    #[test]
    fn subset_exclusions_clip_to_the_matched_box() {
        let asset = iso_box(b"free", &[1, 2, 3, 4]);
        let clipped = BmffExclusionMap {
            xpath: "/free".into(),
            length: None,
            data: Vec::new(),
            subset: vec![BmffSubsetMap {
                offset: asset.len() - 1,
                length: 4,
            }],
            version: None,
            flags: None,
            exact: true,
        };
        assert_eq!(
            normalized_bmff_ranges(&asset, &[clipped.clone()])
                .unwrap()
                .ranges,
            vec![(asset.len() - 1, asset.len())]
        );

        let expected = bmff_hash_with_exclusions(&asset, "sha256", &[clipped.clone()]).unwrap();
        let mut changed_excluded_tail = asset.clone();
        *changed_excluded_tail.last_mut().unwrap() ^= 0xFF;
        assert_eq!(
            bmff_hash_with_exclusions(&changed_excluded_tail, "sha256", &[clipped]).unwrap(),
            expected
        );
    }

    #[test]
    fn subset_start_beyond_the_matched_box_is_empty() {
        let asset = iso_box(b"free", &[1, 2, 3, 4]);
        let beyond = BmffExclusionMap {
            xpath: "/free".into(),
            length: None,
            data: Vec::new(),
            subset: vec![BmffSubsetMap {
                offset: asset.len() + 1,
                length: 0,
            }],
            version: None,
            flags: None,
            exact: true,
        };
        assert!(normalized_bmff_ranges(&asset, &[beyond.clone()])
            .unwrap()
            .ranges
            .is_empty());
        assert_eq!(
            bmff_hash_with_exclusions(&asset, "sha256", &[beyond]).unwrap(),
            bmff_hash_with_exclusions(&asset, "sha256", &[]).unwrap()
        );
    }

    #[test]
    fn qualifier_and_subset_matching_work_is_globally_bounded() {
        let mut asset = Vec::new();
        for _ in 0..300 {
            asset.extend_from_slice(&iso_box(b"free", &[]));
        }
        let base = BmffExclusionMap {
            xpath: "/free".into(),
            length: None,
            data: Vec::new(),
            subset: Vec::new(),
            version: None,
            flags: None,
            exact: true,
        };
        let mut qualified = base.clone();
        qualified.data = vec![
            BmffDataMap {
                offset: 8,
                value: Vec::new(),
            };
            4_000
        ];
        let mut byte_heavy = base.clone();
        byte_heavy.data = vec![BmffDataMap {
            offset: 8,
            value: vec![0; 4_000],
        }];
        let mut subset = base;
        subset.subset = vec![
            BmffSubsetMap {
                offset: 8,
                length: 0,
            };
            4_000
        ];
        for exclusion in [qualified, byte_heavy, subset] {
            assert!(matches!(
                normalized_bmff_ranges(&asset, &[exclusion]),
                Err(FormatError::InvalidStructure {
                    detail: "BMFF exclusion matching exceeds verifier bounds",
                    ..
                })
            ));
        }
    }

    #[test]
    fn auxiliary_merkle_proof_count_and_bytes_are_bounded() {
        use crate::c2pa_cbor::{encode, Profile, Value};

        let encode_map = |hashes: Vec<Value>| {
            let map = Value::Map(vec![
                (Value::Text("uniqueId".into()), Value::Integer(1)),
                (Value::Text("localId".into()), Value::Integer(2)),
                (Value::Text("location".into()), Value::Integer(0)),
                (Value::Text("hashes".into()), Value::Array(hashes)),
            ]);
            encode(&map, Profile::LegacyPipelineBDefinite).unwrap()
        };
        let too_many = encode_map(vec![
            Value::Bytes(vec![0; 32]);
            MAX_BMFF_MERKLE_PROOF_HASHES + 1
        ]);
        assert_eq!(
            parse_merkle_map(&too_many),
            Err("merkle box proof exceeds verifier bound")
        );

        let too_many_bytes = encode_map(vec![
            Value::Bytes(vec![0; 65]);
            MAX_BMFF_MERKLE_PROOF_HASHES
        ]);
        assert_eq!(
            parse_merkle_map(&too_many_bytes),
            Err("merkle box proof bytes exceed verifier bound")
        );
    }

    #[test]
    fn auxiliary_merkle_cbor_decode_is_bounded() {
        use crate::c2pa_cbor::{encode, Profile, Value};

        let oversized = Value::Map(vec![
            (Value::Text("uniqueId".into()), Value::Integer(1)),
            (Value::Text("localId".into()), Value::Integer(2)),
            (Value::Text("location".into()), Value::Integer(0)),
            (
                Value::Text("hashes".into()),
                Value::Array(vec![Value::Integer(0); MAX_BMFF_MERKLE_ENCODED_BYTES]),
            ),
        ]);
        let cbor = encode(&oversized, Profile::LegacyPipelineBDefinite).unwrap();
        assert_eq!(parse_merkle_map(&cbor), Err("merkle box CBOR invalid"));
    }

    #[test]
    fn auxiliary_merkle_total_proof_count_is_bounded() {
        use crate::c2pa_cbor::{encode, Profile, Value};

        let map = Value::Map(vec![
            (Value::Text("uniqueId".into()), Value::Integer(1)),
            (Value::Text("localId".into()), Value::Integer(2)),
            (Value::Text("location".into()), Value::Integer(0)),
            (
                Value::Text("hashes".into()),
                Value::Array(vec![Value::Bytes(Vec::new()); MAX_BMFF_MERKLE_PROOF_HASHES]),
            ),
        ]);
        let cbor = encode(&map, Profile::LegacyPipelineBDefinite).unwrap();
        let mut payload = crate::c2pa_formats::C2PA_BMFF_UUID.to_vec();
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(b"merkle\0");
        payload.extend_from_slice(&cbor);
        let one_box = iso_box(b"uuid", &payload);
        let box_count = MAX_BMFF_MERKLE_TOTAL_PROOF_HASHES / MAX_BMFF_MERKLE_PROOF_HASHES + 1;
        let mut asset = Vec::with_capacity(one_box.len() * box_count);
        for _ in 0..box_count {
            asset.extend_from_slice(&one_box);
        }
        assert!(matches!(
            bmff_merkle_boxes(&asset),
            Err(FormatError::InvalidStructure {
                detail: "BMFF merkle proof data exceeds verifier bound",
                ..
            })
        ));
    }

    #[test]
    fn auxiliary_merkle_box_count_is_bounded() {
        let mut payload = crate::c2pa_formats::C2PA_BMFF_UUID.to_vec();
        payload.extend_from_slice(&[0; 4]);
        payload.extend_from_slice(b"merkle\0");
        let one_box = iso_box(b"uuid", &payload);
        let mut asset = Vec::with_capacity(one_box.len() * (MAX_BMFF_MERKLE_BOXES + 1));
        for _ in 0..=MAX_BMFF_MERKLE_BOXES {
            asset.extend_from_slice(&one_box);
        }
        assert!(matches!(
            bmff_merkle_boxes(&asset),
            Err(FormatError::InvalidStructure {
                detail: "BMFF merkle box count exceeds verifier bound",
                ..
            })
        ));
    }

    #[test]
    fn exclusion_box_cartesian_product_is_bounded() {
        let mut asset = Vec::new();
        for _ in 0..1_001 {
            asset.extend_from_slice(&iso_box(b"free", &[]));
        }
        let exclusion = BmffExclusionMap {
            xpath: "/free".into(),
            length: None,
            data: Vec::new(),
            subset: Vec::new(),
            version: None,
            flags: None,
            exact: false,
        };
        let exclusions = vec![exclusion; 1_000];
        assert!(matches!(
            normalized_bmff_ranges(&asset, &exclusions),
            Err(FormatError::InvalidStructure {
                detail: "BMFF exclusion matching exceeds verifier bounds",
                ..
            })
        ));
    }
}
