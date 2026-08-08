//! ISOBMFF (MP4/MOV/M4A/AVIF/HEIC/HEIF): JUMBF in a top-level C2PA `uuid` box.
//!
//! C2PA reserves the user-type UUID `d8fec3d6-1b0e-483c-9297-5828877ec481`. The
//! manifest store is the payload of a top-level `uuid` box carrying that UUID,
//! immediately following the 16-byte UUID. Box headers are walked without
//! copying payloads; only the manifest bytes are materialized.

#[cfg(test)]
use crate::c2pa_formats::util::iso_box_header;
#[cfg(test)]
use crate::c2pa_formats::util::{be_u16, be_u24, be_u32, be_u64};
use crate::c2pa_formats::util::{walk_iso_boxes, IsoBox};
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
/// reserved prefix. Returns the slice from the `jumb` box's LBox onward.
pub(crate) fn jumbf_from_uuid_payload(payload: &[u8]) -> Option<&[u8]> {
    // The manifest store is a `jumb` superbox: a 4-byte big-endian LBox
    // immediately precedes the ASCII `jumb` TBox. Find the first such header.
    let mut i = 0usize;
    while i + 8 <= payload.len() {
        if &payload[i + 4..i + 8] == b"jumb" {
            // sanity: LBox must be plausible (>= 8 and within payload, or
            // extended size marker 1, or 0 = to-end).
            let lbox =
                u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
            let plausible = lbox == 0
                || lbox == 1
                || (lbox as usize >= 8 && i + lbox as usize <= payload.len());
            if plausible {
                return Some(&payload[i..]);
            }
        }
        i += 1;
    }
    None
}
/// Resolve `c2pa.hash.bmff*` box-path exclusions to byte ranges for hashing.
///
/// BMFF hash assertions exclude whole top-level boxes by xpath (e.g. `/ftyp`,
/// `/mfra`, and the C2PA `/uuid` box). This walks the top-level boxes and
/// returns the `(start, length)` span of every box whose type matches one of
/// the excluded paths. For `/uuid` only the C2PA manifest box is excluded
/// (other `uuid` boxes are content and must be hashed). Ranges are returned
/// sorted by start offset.
pub fn bmff_exclusion_ranges(
    data: &[u8],
    xpaths: &[String],
) -> Result<Vec<(usize, usize)>, FormatError> {
    // Map each xpath like "/ftyp" to its 4-byte box type.
    let wanted: Vec<[u8; 4]> = xpaths
        .iter()
        .filter_map(|p| {
            let name = p.trim_start_matches('/');
            let b = name.as_bytes();
            if b.len() == 4 {
                Some([b[0], b[1], b[2], b[3]])
            } else {
                None
            }
        })
        .collect();
    let mut ranges = Vec::new();
    walk_iso_boxes(data, FMT, |b| {
        let matches_path = wanted.contains(&b.box_type);
        if !matches_path {
            return;
        }
        // For `uuid`, only exclude the C2PA manifest box.
        if &b.box_type == TYPE_UUID && !is_c2pa_uuid(data, b) {
            return;
        }
        ranges.push((b.start, b.end - b.start));
    })?;
    ranges.sort_by_key(|(s, _)| *s);
    Ok(ranges)
}

/// A parsed auxiliary C2PA `'merkle'` box from a fragment (or flat fMP4) file.
///
/// Per C2PA spec A.5.4, each fragment carries a C2PA `uuid` box with
/// `box_purpose = "merkle"` immediately preceding its `moof`. The payload is
/// CBOR (`bmff-merkle-map`): which Merkle tree the fragment belongs to
/// (`uniqueId` + `localId`), its zero-based leaf index (`location`), and the
/// proof hashes needed to climb from the leaf to the row stored in the
/// manifest's `c2pa.hash.bmff*` assertion (leaf-most first). Trailing zero
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
    walk_iso_boxes(data, FMT, |b| {
        if !is_c2pa_uuid(data, b) {
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
        let cbor = &after_vf[nul + 1..];
        found.push(parse_merkle_map(cbor));
    })?;
    Ok(found)
}

/// Decode one `bmff-merkle-map` from the aux box payload (padding tolerated).
fn parse_merkle_map(cbor: &[u8]) -> Result<BmffMerkleBox, &'static str> {
    use crate::c2pa_cbor::{decode_prefix, Value};
    let (v, _consumed) = decode_prefix(cbor).map_err(|_| "merkle box CBOR invalid")?;
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
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Value::Bytes(h) => out.push(h.clone()),
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
    xpaths: &[String],
) -> Result<Vec<u8>, FormatError> {
    let mut hasher = BmffHasher::new(alg).ok_or(FormatError::UnsupportedVariant {
        format: FMT,
        detail: "unsupported bmff hash algorithm",
    })?;
    let excl = bmff_exclusion_ranges(fragment, xpaths)?;
    let mut pos = 0usize;
    for (start, len) in excl {
        if start > pos {
            hasher.update(&fragment[pos..start]);
        }
        pos = pos.max(start + len);
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
    walk_iso_boxes(data, FMT, |b| {
        if &b.box_type == b"mdat" {
            spans.push((b.payload_start, b.end - b.payload_start));
        }
    })?;
    Ok(spans)
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

/// Compute a `c2pa.hash.bmff` (V2/V3, non-merkle) hard-binding hash over `data`.
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
    // Map each xpath like "/ftyp" to its 4-byte box type.
    let wanted: Vec<[u8; 4]> = xpaths
        .iter()
        .filter_map(|p| {
            let b = p.trim_start_matches('/').as_bytes();
            (b.len() == 4).then(|| [b[0], b[1], b[2], b[3]])
        })
        .collect();
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
    let wanted: Vec<[u8; 4]> = xpaths
        .iter()
        .filter_map(|p| {
            let b = p.trim_start_matches('/').as_bytes();
            (b.len() == 4).then(|| [b[0], b[1], b[2], b[3]])
        })
        .collect();

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
#[cfg(test)]
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
}
