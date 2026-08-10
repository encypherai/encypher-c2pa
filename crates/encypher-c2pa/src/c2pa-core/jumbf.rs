//! JUMBF (ISO 19566-5) box serializer and parser for C2PA manifest stores.
//!
//! The parser and serializer are byte-compatible with the C2PA JUMBF layout.
//! Box format:
//! `LBox(4 BE) | TBox(4) | payload`, with extended size when total >= 2^32
//! (LBox=1, then XLBox(8)).

use thiserror::Error;

/// C2PA JUMBF type UUID suffix shared by all C2PA box types.
const UUID_SUFFIX: [u8; 12] = [
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71,
];

/// Build a 16-byte C2PA type UUID from its 4-byte ASCII prefix.
const fn type_uuid(prefix: [u8; 4]) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0] = prefix[0];
    u[1] = prefix[1];
    u[2] = prefix[2];
    u[3] = prefix[3];
    let mut i = 0;
    while i < 12 {
        u[4 + i] = UUID_SUFFIX[i];
        i += 1;
    }
    u
}

/// Manifest store superbox UUID (`c2pa`).
pub const UUID_MANIFEST_STORE: [u8; 16] = type_uuid(*b"c2pa");
/// Manifest superbox UUID (`c2ma`).
pub const UUID_MANIFEST: [u8; 16] = type_uuid(*b"c2ma");
/// Legacy standard manifest superbox UUID (`c2md`), accepted for compatibility.
pub const UUID_LEGACY_MANIFEST: [u8; 16] = type_uuid(*b"c2md");
/// Update manifest superbox UUID (`c2um`).
pub const UUID_UPDATE_MANIFEST: [u8; 16] = type_uuid(*b"c2um");
/// Compressed manifest superbox UUID (`c2cm`).
pub const UUID_COMPRESSED_MANIFEST: [u8; 16] = type_uuid(*b"c2cm");
/// Assertion store superbox UUID (`c2as`).
pub const UUID_ASSERTION_STORE: [u8; 16] = type_uuid(*b"c2as");
/// Claim superbox UUID (`c2cl`).
pub const UUID_CLAIM: [u8; 16] = type_uuid(*b"c2cl");
/// Claim signature superbox UUID (`c2cs`).
pub const UUID_CLAIM_SIGNATURE: [u8; 16] = type_uuid(*b"c2cs");
/// CBOR-content assertion box UUID (`cbor`).
pub const UUID_CBOR_CONTENT: [u8; 16] = type_uuid(*b"cbor");

const TYPE_JUMB: &[u8; 4] = b"jumb";
const TYPE_JUMD: &[u8; 4] = b"jumd";
const TYPE_CBOR: &[u8; 4] = b"cbor";
const LABEL_MANIFEST_STORE: &str = "c2pa";
const LABEL_ASSERTION_STORE: &str = "c2pa.assertions";
const LABEL_CLAIM_V1: &str = "c2pa.claim";
const LABEL_CLAIM_V2: &str = "c2pa.claim.v2";
const LABEL_CLAIM_SIGNATURE: &str = "c2pa.signature";
const MAX_MANIFESTS_PER_STORE: usize = 1_024;
const MAX_ASSERTIONS_PER_MANIFEST: usize = 4_096;
/// A C2PA assertion store may contain the maximum assertion count directly.
/// The same bound is conservative for manifest stores, manifests, and
/// individual assertion superboxes while preventing unbounded child vectors.
const MAX_CHILD_BOXES_PER_SUPERBOX: usize = MAX_ASSERTIONS_PER_MANIFEST;

/// Description box toggle: requestable.
const TOGGLE_REQUESTABLE: u8 = 0x01;
/// Description box toggle: label present.
const TOGGLE_LABEL_PRESENT: u8 = 0x02;
/// Description box toggle: private (salt sub-box present). Write path only.
#[cfg(test)]
const TOGGLE_PRIVATE: u8 = 0x10;

/// Error parsing a JUMBF structure.
#[derive(Debug, Error, PartialEq)]
pub enum JumbfError {
    /// Not enough bytes for a box header at the given offset.
    #[error("truncated box header at offset {0}")]
    TruncatedHeader(usize),
    /// A declared box size ran past the end of the buffer.
    #[error("box length {0} overruns buffer")]
    LengthOverrun(u64),
    /// Expected a specific box type but found another.
    #[error("expected box type {expected:?}, found {found:?}")]
    UnexpectedType {
        /// The 4-byte type that was expected.
        expected: [u8; 4],
        /// The 4-byte type that was found.
        found: [u8; 4],
    },
    /// The superbox UUID did not match the expected C2PA type.
    #[error("unexpected superbox uuid")]
    UnexpectedUuid,
    /// Bytes remained after the declared top-level box.
    #[error("{0} trailing bytes after top-level JUMBF box")]
    TrailingBytes(usize),
    /// A collection exceeded a verifier resource bound.
    #[error("{0}")]
    ResourceLimit(&'static str),
    /// A JUMBF path is ambiguous because a sibling label is duplicated.
    #[error("ambiguous JUMBF label: {0}")]
    AmbiguousLabel(String),
    /// A canonical C2PA superbox UUID appeared under the wrong JUMBF label.
    #[error("expected JUMBF label {expected}, found {found}")]
    UnexpectedLabel {
        /// Label required for this UUID.
        expected: &'static str,
        /// Label present in the description box.
        found: String,
    },
    /// Required C2PA JUMBF structure was absent or appeared more than once.
    #[error("invalid C2PA JUMBF structure: {0}")]
    InvalidStructure(&'static str),
    /// A standard-defined manifest kind is recognized but not implemented.
    #[error("unsupported C2PA manifest type: {0}")]
    UnsupportedManifestType(&'static str),
}

/// Wrap `payload` in an ISOBMFF box with a 4-byte type code. Write path only.
#[cfg(test)]
fn box_bytes(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 8 + payload.len();
    let mut out = Vec::with_capacity(total + 8);
    if (total as u64) < (1u64 << 32) {
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(payload);
    } else {
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(box_type);
        out.extend_from_slice(&((total + 8) as u64).to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

/// Build a JUMBF description box (`jumd`). Write path only.
#[cfg(test)]
fn description_box(type_uuid: &[u8; 16], label: &str, salt: Option<&[u8]>) -> Vec<u8> {
    let mut toggles = TOGGLE_REQUESTABLE | TOGGLE_LABEL_PRESENT;
    if salt.is_some() {
        toggles |= TOGGLE_PRIVATE;
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(type_uuid);
    payload.push(toggles);
    payload.extend_from_slice(label.as_bytes());
    payload.push(0x00);
    if let Some(s) = salt {
        payload.extend_from_slice(&box_bytes(b"c2sh", s));
    }
    box_bytes(TYPE_JUMD, &payload)
}

/// Build a JUMBF superbox (`jumb`): a description box followed by content boxes.
///
/// JUMBF assembly is not part of the verification surface. The reader parses
/// these structures; only in-repo fixture generation writes them. This module
/// is private to the crate and the item is `cfg(test)`, so it is unreachable
/// from a consumer and absent from the shipped build.
#[cfg(test)]
pub fn superbox(
    type_uuid: &[u8; 16],
    label: &str,
    content: &[Vec<u8>],
    salt: Option<&[u8]>,
) -> Vec<u8> {
    let mut inner = description_box(type_uuid, label, salt);
    for c in content {
        inner.extend_from_slice(c);
    }
    box_bytes(TYPE_JUMB, &inner)
}

/// Wrap CBOR bytes in a CBOR content box (`cbor`). Fixture generation only.
#[cfg(test)]
pub fn cbor_box(cbor: &[u8]) -> Vec<u8> {
    box_bytes(TYPE_CBOR, cbor)
}

/// Build an assertion superbox containing a single CBOR content box.
/// Fixture generation only.
#[cfg(test)]
pub fn assertion_box(label: &str, cbor: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    superbox(&UUID_CBOR_CONTENT, label, &[cbor_box(cbor)], salt)
}

/// Return the JUMBF *content* of a superbox: its payload after its complete
/// `LBox+TBox` or `LBox+TBox+XLBox` header. This is the byte range hashed for
/// `assertion.hashedURI` bindings (C2PA spec 14.2.3).
///
/// The declared box length bounds the returned payload. Legal size-to-end boxes
/// consume the remaining input. Truncated, overrunning, and non-`jumb` boxes are
/// rejected rather than being hashed with an assumed 8-byte header.
pub fn superbox_content(superbox_bytes: &[u8]) -> Result<&[u8], JumbfError> {
    let parsed = parse_box(superbox_bytes, 0)?;
    if &parsed.box_type != TYPE_JUMB {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMB,
            found: parsed.box_type,
        });
    }
    Ok(parsed.payload)
}

/// Build a single C2PA manifest (assertion store + claim + signature) with a
/// v2 claim box (`c2pa.claim.v2`). Fixture generation only.
#[cfg(test)]
pub fn build_manifest(
    manifest_label: &str,
    assertion_boxes: &[Vec<u8>],
    claim_cbor: &[u8],
    signature_cose: &[u8],
) -> Vec<u8> {
    build_manifest_with_claim_label(
        manifest_label,
        assertion_boxes,
        claim_cbor,
        signature_cose,
        "c2pa.claim.v2",
    )
}

/// Build a single C2PA manifest with an explicit claim box label.
///
/// `claim_label` is `"c2pa.claim.v2"` for 2.x claims and `"c2pa.claim"` for
/// the legacy 1.x claim-v1 generation used by backward-compatibility fixtures.
/// Fixture generation only.
#[cfg(test)]
pub fn build_manifest_with_claim_label(
    manifest_label: &str,
    assertion_boxes: &[Vec<u8>],
    claim_cbor: &[u8],
    signature_cose: &[u8],
    claim_label: &str,
) -> Vec<u8> {
    let assertion_store = superbox(
        &UUID_ASSERTION_STORE,
        "c2pa.assertions",
        assertion_boxes,
        None,
    );
    let claim = superbox(&UUID_CLAIM, claim_label, &[cbor_box(claim_cbor)], None);
    let sig = superbox(
        &UUID_CLAIM_SIGNATURE,
        "c2pa.signature",
        &[cbor_box(signature_cose)],
        None,
    );
    superbox(
        &UUID_MANIFEST,
        manifest_label,
        &[assertion_store, claim, sig],
        None,
    )
}

/// Build a complete C2PA manifest store from manifest superboxes (active last).
/// Fixture generation only.
#[cfg(test)]
pub fn build_manifest_store(manifests: &[Vec<u8>]) -> Vec<u8> {
    superbox(&UUID_MANIFEST_STORE, "c2pa", manifests, None)
}

/// Extract raw manifest superboxes from a C2PA manifest store, preserving
/// store order.
pub fn manifest_superboxes_from_store(data: &[u8]) -> Result<Vec<&[u8]>, JumbfError> {
    let top = parse_box(data, 0)?;
    if &top.box_type != TYPE_JUMB {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMB,
            found: top.box_type,
        });
    }
    let store = parse_superbox_description(top.payload)?;
    if store.type_uuid != UUID_MANIFEST_STORE {
        return Err(JumbfError::UnexpectedUuid);
    }
    if store.label != LABEL_MANIFEST_STORE {
        return Err(JumbfError::UnexpectedLabel {
            expected: LABEL_MANIFEST_STORE,
            found: store.label,
        });
    }

    let mut pos = store.content_offset;
    let mut child_count = 0usize;
    let mut manifests = Vec::new();
    while pos < top.payload.len() {
        if child_count >= MAX_CHILD_BOXES_PER_SUPERBOX {
            return Err(JumbfError::ResourceLimit(
                "superbox child count exceeds verifier bound",
            ));
        }
        child_count += 1;
        let b = parse_box(top.payload, pos)?;
        if b.box_type == *TYPE_JUMB {
            let child = parse_superbox_description(b.payload)?;
            if matches!(child.type_uuid, UUID_MANIFEST | UUID_LEGACY_MANIFEST) {
                if manifests.len() >= MAX_MANIFESTS_PER_STORE {
                    return Err(JumbfError::ResourceLimit(
                        "manifest count exceeds verifier bound",
                    ));
                }
                manifests.push(&top.payload[pos..b.next]);
            } else if child.type_uuid == UUID_UPDATE_MANIFEST {
                return Err(JumbfError::UnsupportedManifestType("c2um"));
            } else if child.type_uuid == UUID_COMPRESSED_MANIFEST {
                return Err(JumbfError::UnsupportedManifestType("c2cm"));
            }
        }
        pos = b.next;
    }
    Ok(manifests)
}

// ---- Parser ----

/// A parsed ISOBMFF box: type, payload slice, and offset of the next box.
struct ParsedBox<'a> {
    box_type: [u8; 4],
    payload: &'a [u8],
    next: usize,
}

/// Parse a single ISOBMFF box at `offset`.
fn parse_box(data: &[u8], offset: usize) -> Result<ParsedBox<'_>, JumbfError> {
    if offset + 8 > data.len() {
        return Err(JumbfError::TruncatedHeader(offset));
    }
    let size = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let mut box_type = [0u8; 4];
    box_type.copy_from_slice(&data[offset + 4..offset + 8]);

    if size == 1 {
        if offset + 16 > data.len() {
            return Err(JumbfError::TruncatedHeader(offset));
        }
        let xl = u64::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let xl_size = usize::try_from(xl).map_err(|_| JumbfError::LengthOverrun(xl))?;
        let end = offset
            .checked_add(xl_size)
            .ok_or(JumbfError::LengthOverrun(xl))?;
        if end > data.len() || xl_size < 16 {
            return Err(JumbfError::LengthOverrun(xl));
        }
        Ok(ParsedBox {
            box_type,
            payload: &data[offset + 16..end],
            next: end,
        })
    } else if size == 0 {
        Ok(ParsedBox {
            box_type,
            payload: &data[offset + 8..],
            next: data.len(),
        })
    } else {
        let end = offset
            .checked_add(size as usize)
            .ok_or(JumbfError::LengthOverrun(size as u64))?;
        if end > data.len() || (size as usize) < 8 {
            return Err(JumbfError::LengthOverrun(size as u64));
        }
        Ok(ParsedBox {
            box_type,
            payload: &data[offset + 8..end],
            next: end,
        })
    }
}

struct ParsedSuperboxDescription {
    type_uuid: [u8; 16],
    label: String,
    content_offset: usize,
}

fn parse_superbox_description(payload: &[u8]) -> Result<ParsedSuperboxDescription, JumbfError> {
    let desc = parse_box(payload, 0)?;
    if &desc.box_type != TYPE_JUMD {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMD,
            found: desc.box_type,
        });
    }
    if desc.payload.len() < 18 {
        return Err(JumbfError::TruncatedHeader(0));
    }
    let mut type_uuid = [0u8; 16];
    type_uuid.copy_from_slice(&desc.payload[..16]);
    let toggles = desc.payload[16];
    if toggles & (TOGGLE_REQUESTABLE | TOGGLE_LABEL_PRESENT)
        != TOGGLE_REQUESTABLE | TOGGLE_LABEL_PRESENT
    {
        return Err(JumbfError::InvalidStructure(
            "C2PA JUMBF description is not labelled and requestable",
        ));
    }
    let label_bytes = &desc.payload[17..];
    let null = label_bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(JumbfError::InvalidStructure(
            "JUMBF label is not null-terminated",
        ))?;
    let label = std::str::from_utf8(&label_bytes[..null])
        .map_err(|_| JumbfError::InvalidStructure("JUMBF label is not valid UTF-8"))?;
    if label.is_empty()
        || label.chars().any(|character| {
            character <= '\u{001f}'
                || ('\u{007f}'..='\u{009f}').contains(&character)
                || matches!(character, '/' | ';' | '?' | '#' | '\u{feff}' | '\u{ffff}')
        })
    {
        return Err(JumbfError::InvalidStructure(
            "JUMBF label contains a forbidden character",
        ));
    }
    Ok(ParsedSuperboxDescription {
        type_uuid,
        label: label.to_owned(),
        content_offset: desc.next,
    })
}

/// A parsed JUMBF superbox: its type UUID, label, and content boxes.
pub struct Superbox<'a> {
    /// 16-byte type UUID from the description box.
    pub type_uuid: [u8; 16],
    /// Null-terminated UTF-8 label.
    pub label: String,
    /// Content boxes as (type, payload) pairs.
    pub content: Vec<([u8; 4], &'a [u8])>,
}

/// Parse the inner payload of a `jumb` superbox (after the `jumb` header).
fn parse_superbox_payload(payload: &[u8]) -> Result<Superbox<'_>, JumbfError> {
    let description = parse_superbox_description(payload)?;
    let mut content = Vec::new();
    let mut pos = description.content_offset;
    while pos < payload.len() {
        if content.len() >= MAX_CHILD_BOXES_PER_SUPERBOX {
            return Err(JumbfError::ResourceLimit(
                "superbox child count exceeds verifier bound",
            ));
        }
        let b = parse_box(payload, pos)?;
        content.push((b.box_type, b.payload));
        pos = b.next;
    }
    Ok(Superbox {
        type_uuid: description.type_uuid,
        label: description.label,
        content,
    })
}

/// Parse a top-level `jumb` superbox from raw bytes.
pub fn parse_superbox(data: &[u8]) -> Result<Superbox<'_>, JumbfError> {
    let b = parse_box(data, 0)?;
    if &b.box_type != TYPE_JUMB {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMB,
            found: b.box_type,
        });
    }
    if b.next != data.len() {
        return Err(JumbfError::TrailingBytes(data.len() - b.next));
    }
    parse_superbox_payload(b.payload)
}

/// A parsed C2PA manifest: label, assertions (label -> CBOR bytes), raw
/// assertion JUMBF (label -> superbox payload, for hash verification), claim
/// CBOR, and signature COSE bytes.
pub struct ParsedManifest<'a> {
    /// Manifest URN label.
    pub label: String,
    /// Raw manifest JUMBF superbox payload (for ingredient `activeManifest` hashes).
    pub manifest_jumbf: &'a [u8],
    /// Assertion label -> CBOR content bytes.
    pub assertions: Vec<(String, &'a [u8])>,
    /// Assertion label -> raw superbox payload (for `assertion.hashedURI`).
    pub assertion_jumbf: Vec<(String, &'a [u8])>,
    /// Claim CBOR bytes.
    pub claim_cbor: Option<&'a [u8]>,
    /// Claim signature COSE_Sign1 bytes.
    pub signature_cose: Option<&'a [u8]>,
    /// Number of claim boxes found in this manifest. A conforming manifest has
    /// exactly one; more than one is a `claim.multiple` violation.
    pub claim_count: usize,
    /// Label of the (first) claim box: `"c2pa.claim.v2"` for 2.x claims,
    /// `"c2pa.claim"` for the legacy 1.x claim-v1 generation.
    pub claim_box_label: Option<String>,
}

/// A parsed manifest store: the active manifest is the last entry.
pub struct ParsedStore<'a> {
    /// Manifests in store order.
    pub manifests: Vec<ParsedManifest<'a>>,
}

/// Parse a C2PA manifest store from JUMBF bytes.
pub fn parse_manifest_store(data: &[u8]) -> Result<ParsedStore<'_>, JumbfError> {
    let store = parse_superbox(data)?;
    if store.type_uuid != UUID_MANIFEST_STORE {
        return Err(JumbfError::UnexpectedUuid);
    }
    if store.label != LABEL_MANIFEST_STORE {
        return Err(JumbfError::UnexpectedLabel {
            expected: LABEL_MANIFEST_STORE,
            found: store.label,
        });
    }
    let mut manifests = Vec::new();
    let mut manifest_labels = std::collections::BTreeSet::new();
    for (ctype, cpayload) in &store.content {
        if ctype == TYPE_JUMB {
            if let Some(m) = parse_manifest(cpayload)? {
                if manifests.len() >= MAX_MANIFESTS_PER_STORE {
                    return Err(JumbfError::ResourceLimit(
                        "manifest count exceeds verifier bound",
                    ));
                }
                if !manifest_labels.insert(m.label.clone()) {
                    return Err(JumbfError::AmbiguousLabel(m.label));
                }
                manifests.push(m);
            }
        }
    }
    Ok(ParsedStore { manifests })
}

fn parse_manifest(payload: &[u8]) -> Result<Option<ParsedManifest<'_>>, JumbfError> {
    let parsed = parse_superbox_payload(payload)?;
    if parsed.type_uuid == UUID_UPDATE_MANIFEST {
        return Err(JumbfError::UnsupportedManifestType("c2um"));
    }
    if parsed.type_uuid == UUID_COMPRESSED_MANIFEST {
        return Err(JumbfError::UnsupportedManifestType("c2cm"));
    }
    if !matches!(parsed.type_uuid, UUID_MANIFEST | UUID_LEGACY_MANIFEST) {
        return Ok(None);
    }
    let mut m = ParsedManifest {
        label: parsed.label.clone(),
        manifest_jumbf: payload,
        assertions: Vec::new(),
        assertion_jumbf: Vec::new(),
        claim_cbor: None,
        signature_cose: None,
        claim_count: 0,
        claim_box_label: None,
    };
    let mut assertion_labels = std::collections::BTreeSet::new();
    let mut direct_child_labels = std::collections::BTreeSet::new();
    let mut assertion_store_count = 0usize;
    for (ctype, cpayload) in &parsed.content {
        if ctype != TYPE_JUMB {
            continue;
        }
        let inner = parse_superbox_payload(cpayload)?;
        if inner.type_uuid == UUID_ASSERTION_STORE {
            assertion_store_count += 1;
            if assertion_store_count > 1 {
                return Err(JumbfError::InvalidStructure(
                    "manifest contains multiple assertion store superboxes",
                ));
            }
            if inner.label != LABEL_ASSERTION_STORE {
                return Err(JumbfError::UnexpectedLabel {
                    expected: LABEL_ASSERTION_STORE,
                    found: inner.label,
                });
            }
        } else if inner.type_uuid == UUID_CLAIM
            && inner.label != LABEL_CLAIM_V1
            && inner.label != LABEL_CLAIM_V2
        {
            return Err(JumbfError::UnexpectedLabel {
                expected: "c2pa.claim or c2pa.claim.v2",
                found: inner.label,
            });
        } else if inner.type_uuid == UUID_CLAIM_SIGNATURE && inner.label != LABEL_CLAIM_SIGNATURE {
            return Err(JumbfError::UnexpectedLabel {
                expected: LABEL_CLAIM_SIGNATURE,
                found: inner.label,
            });
        }
        if !direct_child_labels.insert(inner.label.clone()) {
            return Err(JumbfError::AmbiguousLabel(inner.label));
        }
        if inner.type_uuid == UUID_ASSERTION_STORE {
            for (atype, apayload) in &inner.content {
                if atype == TYPE_JUMB {
                    let assertion = parse_superbox_payload(apayload)?;
                    if m.assertion_jumbf.len() >= MAX_ASSERTIONS_PER_MANIFEST {
                        return Err(JumbfError::ResourceLimit(
                            "assertion count exceeds verifier bound",
                        ));
                    }
                    if !assertion_labels.insert(assertion.label.clone()) {
                        return Err(JumbfError::AmbiguousLabel(assertion.label));
                    }
                    m.assertion_jumbf.push((assertion.label.clone(), apayload));
                    for (act, acp) in &assertion.content {
                        if act == TYPE_CBOR {
                            m.assertions.push((assertion.label.clone(), acp));
                            break;
                        }
                    }
                }
            }
        } else if inner.type_uuid == UUID_CLAIM {
            m.claim_count += 1;
            if inner.content.len() != 1 || inner.content[0].0 != *TYPE_CBOR {
                return Err(JumbfError::InvalidStructure(
                    "claim superbox must contain exactly one CBOR content box",
                ));
            }
            if m.claim_box_label.is_none() {
                m.claim_cbor = Some(inner.content[0].1);
                m.claim_box_label = Some(inner.label.clone());
            }
        } else if inner.type_uuid == UUID_CLAIM_SIGNATURE {
            if inner.content.len() != 1 || inner.content[0].0 != *TYPE_CBOR {
                return Err(JumbfError::InvalidStructure(
                    "claim signature superbox must contain exactly one CBOR content box",
                ));
            }
            m.signature_cose = Some(inner.content[0].1);
        }
    }
    if assertion_store_count == 0 {
        return Err(JumbfError::InvalidStructure(
            "manifest is missing required c2pa.assertions assertion store",
        ));
    }
    Ok(Some(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extended_box_bytes(ordinary: &[u8]) -> Vec<u8> {
        assert_eq!(
            u32::from_be_bytes(ordinary[..4].try_into().unwrap()) as usize,
            ordinary.len()
        );
        let extended_size = u64::try_from(ordinary.len().checked_add(8).unwrap()).unwrap();
        let mut extended = Vec::with_capacity(ordinary.len() + 8);
        extended.extend_from_slice(&1u32.to_be_bytes());
        extended.extend_from_slice(&ordinary[4..8]);
        extended.extend_from_slice(&extended_size.to_be_bytes());
        extended.extend_from_slice(&ordinary[8..]);
        extended
    }

    fn relabel_unique(data: &mut [u8], from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let offset = {
            let mut matches = data
                .windows(from.len())
                .enumerate()
                .filter_map(|(offset, candidate)| (candidate == from.as_bytes()).then_some(offset));
            let offset = matches.next().expect("source label must be present");
            assert!(matches.next().is_none(), "source label must be unique");
            offset
        };
        data[offset..offset + to.len()].copy_from_slice(to.as_bytes());
    }

    #[test]
    fn superbox_content_parses_ordinary_extended_and_size_to_end() {
        let payload = b"manifest payload";
        let ordinary = box_bytes(TYPE_JUMB, payload);
        assert_eq!(superbox_content(&ordinary).unwrap(), payload);
        let mut ordinary_with_trailing_box = ordinary.clone();
        ordinary_with_trailing_box.extend_from_slice(b"ignored");
        assert_eq!(
            superbox_content(&ordinary_with_trailing_box).unwrap(),
            payload
        );

        let extended = extended_box_bytes(&ordinary);
        assert_eq!(superbox_content(&extended).unwrap(), payload);
        let mut extended_with_trailing_box = extended.clone();
        extended_with_trailing_box.extend_from_slice(b"ignored");
        assert_eq!(
            superbox_content(&extended_with_trailing_box).unwrap(),
            payload
        );

        let mut size_to_end = Vec::with_capacity(payload.len() + 8);
        size_to_end.extend_from_slice(&0u32.to_be_bytes());
        size_to_end.extend_from_slice(TYPE_JUMB);
        size_to_end.extend_from_slice(payload);
        assert_eq!(superbox_content(&size_to_end).unwrap(), payload);
    }

    #[test]
    fn superbox_content_rejects_malformed_headers_and_lengths() {
        assert!(matches!(
            superbox_content(&[0, 0, 0]),
            Err(JumbfError::TruncatedHeader(0))
        ));

        let wrong_type = box_bytes(b"free", b"payload");
        assert!(matches!(
            superbox_content(&wrong_type),
            Err(JumbfError::UnexpectedType { .. })
        ));

        let ordinary_overrun = [0, 0, 0, 9, b'j', b'u', b'm', b'b'];
        assert!(matches!(
            superbox_content(&ordinary_overrun),
            Err(JumbfError::LengthOverrun(9))
        ));

        let mut extended_overrun = Vec::new();
        extended_overrun.extend_from_slice(&1u32.to_be_bytes());
        extended_overrun.extend_from_slice(TYPE_JUMB);
        extended_overrun.extend_from_slice(&17u64.to_be_bytes());
        assert!(matches!(
            superbox_content(&extended_overrun),
            Err(JumbfError::LengthOverrun(17))
        ));
    }

    #[test]
    fn manifest_superboxes_borrow_store_bytes() {
        let manifest = build_manifest("urn:c2pa:borrowed", &[], &[0xa0], &[0xd2, 0x84]);
        let store = build_manifest_store(std::slice::from_ref(&manifest));

        let spans = manifest_superboxes_from_store(&store).unwrap();

        assert_eq!(spans.as_slice(), &[manifest.as_slice()]);
        let store_start = store.as_ptr() as usize;
        let store_end = store_start + store.len();
        let span_start = spans[0].as_ptr() as usize;
        let span_end = span_start + spans[0].len();
        assert!(span_start >= store_start && span_end <= store_end);
    }

    #[test]
    fn manifest_superboxes_enforce_manifest_count() {
        let manifests = (0..=MAX_MANIFESTS_PER_STORE)
            .map(|index| {
                superbox(
                    &UUID_MANIFEST,
                    &format!("urn:c2pa:manifest-{index}"),
                    &[],
                    None,
                )
            })
            .collect::<Vec<_>>();
        let store = build_manifest_store(&manifests);

        assert!(matches!(
            manifest_superboxes_from_store(&store),
            Err(JumbfError::ResourceLimit(
                "manifest count exceeds verifier bound"
            ))
        ));
    }

    #[test]
    fn superbox_parser_rejects_excessive_children() {
        let child = box_bytes(b"free", &[]);
        let children = vec![child; MAX_CHILD_BOXES_PER_SUPERBOX + 1];
        let store = superbox(&UUID_MANIFEST_STORE, "c2pa", &children, None);

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::ResourceLimit(
                "superbox child count exceeds verifier bound"
            ))
        ));
    }

    #[test]
    fn roundtrip_manifest_store() {
        let assertion = assertion_box("c2pa.actions.v2", &[0xa0], None); // empty CBOR map
        let claim = &[0xbf, 0xff]; // indefinite empty map
        let sig = &[0xd2, 0x84]; // dummy COSE-ish
        let manifest = build_manifest("urn:c2pa:test", &[assertion], claim, sig);
        let store = build_manifest_store(&[manifest]);

        let parsed = parse_manifest_store(&store).unwrap();
        assert_eq!(parsed.manifests.len(), 1);
        let m = &parsed.manifests[0];
        assert_eq!(m.label, "urn:c2pa:test");
        assert_eq!(m.assertions.len(), 1);
        assert_eq!(m.assertions[0].0, "c2pa.actions.v2");
        assert_eq!(m.claim_cbor, Some(&[0xbf, 0xff][..]));
        assert_eq!(m.signature_cose, Some(&[0xd2, 0x84][..]));
    }

    #[test]
    fn manifest_store_requires_exact_top_level_framing() {
        let manifest = build_manifest("urn:c2pa:framing", &[], &[0xa0], &[0xd2, 0x84]);
        let ordinary = build_manifest_store(&[manifest]);
        let extended = extended_box_bytes(&ordinary);

        assert_eq!(parse_manifest_store(&extended).unwrap().manifests.len(), 1);

        for mut framed in [ordinary.clone(), extended] {
            framed.extend_from_slice(b"suffix");
            assert!(matches!(
                parse_manifest_store(&framed),
                Err(JumbfError::TrailingBytes(6))
            ));
        }

        let mut size_to_end = ordinary;
        size_to_end[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            parse_manifest_store(&size_to_end).unwrap().manifests.len(),
            1
        );
        size_to_end.extend_from_slice(b"suffix");
        assert!(parse_manifest_store(&size_to_end).is_err());
    }

    #[test]
    fn rejects_relabelled_manifest_store_root() {
        let manifest = build_manifest("urn:c2pa:root-label", &[], &[0xa0], &[0xd2, 0x84]);
        let store = superbox(&UUID_MANIFEST_STORE, "evil", &[manifest], None);

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::UnexpectedLabel {
                expected: LABEL_MANIFEST_STORE,
                found,
            }) if found == "evil"
        ));
        assert!(matches!(
            manifest_superboxes_from_store(&store),
            Err(JumbfError::UnexpectedLabel {
                expected: LABEL_MANIFEST_STORE,
                found,
            }) if found == "evil"
        ));
    }

    #[test]
    fn rejects_relabelled_assertion_store() {
        let manifest = build_manifest("urn:c2pa:assertion-label", &[], &[0xa0], &[0xd2, 0x84]);
        let mut store = build_manifest_store(&[manifest]);
        relabel_unique(&mut store, LABEL_ASSERTION_STORE, "evil.assertions");

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::UnexpectedLabel {
                expected: LABEL_ASSERTION_STORE,
                found,
            }) if found == "evil.assertions"
        ));
    }

    #[test]
    fn rejects_absent_assertion_store() {
        let claim = superbox(&UUID_CLAIM, LABEL_CLAIM_V2, &[cbor_box(&[0xa0])], None);
        let signature = superbox(
            &UUID_CLAIM_SIGNATURE,
            LABEL_CLAIM_SIGNATURE,
            &[cbor_box(&[0xd2, 0x84])],
            None,
        );
        let manifest = superbox(
            &UUID_MANIFEST,
            "urn:c2pa:missing-assertion-store",
            &[claim, signature],
            None,
        );
        let store = build_manifest_store(&[manifest]);

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::InvalidStructure(
                "manifest is missing required c2pa.assertions assertion store"
            ))
        ));
    }

    #[test]
    fn rejects_multiple_assertion_stores() {
        let first = superbox(&UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, &[], None);
        let second = superbox(&UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, &[], None);
        let claim = superbox(&UUID_CLAIM, LABEL_CLAIM_V2, &[cbor_box(&[0xa0])], None);
        let signature = superbox(
            &UUID_CLAIM_SIGNATURE,
            LABEL_CLAIM_SIGNATURE,
            &[cbor_box(&[0xd2, 0x84])],
            None,
        );
        let manifest = superbox(
            &UUID_MANIFEST,
            "urn:c2pa:multiple-assertion-stores",
            &[first, second, claim, signature],
            None,
        );
        let store = build_manifest_store(&[manifest]);

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::InvalidStructure(
                "manifest contains multiple assertion store superboxes"
            ))
        ));
    }

    #[test]
    fn rejects_relabelled_claim() {
        let manifest = build_manifest("urn:c2pa:claim-label", &[], &[0xa0], &[0xd2, 0x84]);
        let mut store = build_manifest_store(&[manifest]);
        relabel_unique(&mut store, LABEL_CLAIM_V2, "evil.claim.v2");

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::UnexpectedLabel {
                expected: "c2pa.claim or c2pa.claim.v2",
                found,
            }) if found == "evil.claim.v2"
        ));
    }

    #[test]
    fn rejects_relabelled_claim_signature() {
        let manifest = build_manifest("urn:c2pa:signature-label", &[], &[0xa0], &[0xd2, 0x84]);
        let mut store = build_manifest_store(&[manifest]);
        relabel_unique(&mut store, LABEL_CLAIM_SIGNATURE, "evil.signature");

        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::UnexpectedLabel {
                expected: LABEL_CLAIM_SIGNATURE,
                found,
            }) if found == "evil.signature"
        ));
    }

    #[test]
    fn parses_canonical_v1_and_v2_claim_boxes() {
        for claim_label in [LABEL_CLAIM_V1, LABEL_CLAIM_V2] {
            let manifest = build_manifest_with_claim_label(
                &format!("urn:c2pa:{claim_label}"),
                &[],
                &[0xa0],
                &[0xd2, 0x84],
                claim_label,
            );
            let store = build_manifest_store(&[manifest]);

            let parsed = parse_manifest_store(&store).unwrap();
            let manifest = &parsed.manifests[0];
            assert_eq!(manifest.claim_count, 1);
            assert_eq!(manifest.claim_box_label.as_deref(), Some(claim_label));
            assert_eq!(manifest.claim_cbor, Some(&[0xa0][..]));
            assert_eq!(manifest.signature_cose, Some(&[0xd2, 0x84][..]));
        }
    }

    #[test]
    fn rejects_duplicate_signatures_in_any_order() {
        let assertion_store = superbox(&UUID_ASSERTION_STORE, "c2pa.assertions", &[], None);
        let claim = superbox(&UUID_CLAIM, "c2pa.claim.v2", &[cbor_box(&[0xa0])], None);
        let injected = superbox(
            &UUID_CLAIM_SIGNATURE,
            "c2pa.signature",
            &[cbor_box(&[0x01])],
            None,
        );
        let authentic = superbox(
            &UUID_CLAIM_SIGNATURE,
            "c2pa.signature",
            &[cbor_box(&[0xd2, 0x84])],
            None,
        );

        for (first, second) in [(injected.clone(), authentic.clone()), (authentic, injected)] {
            let manifest = superbox(
                &UUID_MANIFEST,
                "urn:c2pa:duplicate-signature",
                &[assertion_store.clone(), claim.clone(), first, second],
                None,
            );
            let store = build_manifest_store(&[manifest]);
            assert!(matches!(
                parse_manifest_store(&store),
                Err(JumbfError::AmbiguousLabel(label)) if label == "c2pa.signature"
            ));
        }
    }

    #[test]
    fn rejects_duplicate_direct_child_labels() {
        let assertion_store = superbox(&UUID_ASSERTION_STORE, "c2pa.assertions", &[], None);
        let claim = superbox(&UUID_CLAIM, "c2pa.claim.v2", &[cbor_box(&[0xa0])], None);
        let signature = superbox(
            &UUID_CLAIM_SIGNATURE,
            "c2pa.signature",
            &[cbor_box(&[0xd2, 0x84])],
            None,
        );
        let shared_first = superbox(&UUID_CBOR_CONTENT, "shared", &[], None);
        let shared_second = superbox(&UUID_CBOR_CONTENT, "shared", &[], None);

        let cases = [
            (
                "c2pa.claim.v2",
                vec![assertion_store.clone(), claim.clone(), claim, signature],
            ),
            ("shared", vec![shared_first, shared_second]),
        ];

        for (duplicate_label, children) in cases {
            let manifest = superbox(&UUID_MANIFEST, "urn:c2pa:duplicate-child", &children, None);
            let store = build_manifest_store(&[manifest]);
            assert!(matches!(
                parse_manifest_store(&store),
                Err(JumbfError::AmbiguousLabel(label)) if label == duplicate_label
            ));
        }
    }

    #[test]
    fn accepts_legacy_standard_manifest_uuid() {
        let standard = build_manifest("urn:c2pa:legacy", &[], &[0xa0], &[0xd2, 0x84]);
        let payload = parse_box(&standard, 0).unwrap().payload;
        let parsed = parse_superbox_payload(payload).unwrap();
        let assertion_store = superbox(&UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, &[], None);
        let claim = superbox(&UUID_CLAIM, LABEL_CLAIM_V2, &[cbor_box(&[0xa0])], None);
        let signature = superbox(
            &UUID_CLAIM_SIGNATURE,
            LABEL_CLAIM_SIGNATURE,
            &[cbor_box(&[0xd2, 0x84])],
            None,
        );
        assert_eq!(parsed.label, "urn:c2pa:legacy");
        let legacy = superbox(
            &UUID_LEGACY_MANIFEST,
            "urn:c2pa:legacy",
            &[assertion_store, claim, signature],
            None,
        );
        let store = build_manifest_store(&[legacy]);
        assert_eq!(parse_manifest_store(&store).unwrap().manifests.len(), 1);
    }

    #[test]
    fn rejects_recognized_unimplemented_manifest_types() {
        for (uuid, expected) in [
            (UUID_UPDATE_MANIFEST, "c2um"),
            (UUID_COMPRESSED_MANIFEST, "c2cm"),
        ] {
            let manifest = superbox(&uuid, "urn:c2pa:unsupported", &[], None);
            let store = build_manifest_store(&[manifest]);
            assert!(matches!(
                parse_manifest_store(&store),
                Err(JumbfError::UnsupportedManifestType(kind)) if kind == expected
            ));
        }
    }

    #[test]
    fn rejects_non_requestable_or_illegal_labels() {
        let manifest = build_manifest("urn:c2pa:toggles", &[], &[0xa0], &[0xd2, 0x84]);
        let mut store = build_manifest_store(&[manifest]);
        let label_offset = store
            .windows(LABEL_ASSERTION_STORE.len())
            .position(|bytes| bytes == LABEL_ASSERTION_STORE.as_bytes())
            .unwrap();
        store[label_offset - 1] &= !TOGGLE_REQUESTABLE;
        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::InvalidStructure(
                "C2PA JUMBF description is not labelled and requestable"
            ))
        ));

        let manifest = build_manifest("urn:c2pa:illegal", &[], &[0xa0], &[0xd2, 0x84]);
        let mut store = build_manifest_store(&[manifest]);
        relabel_unique(&mut store, "urn:c2pa:illegal", "urn/c2pa:illegal");
        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::InvalidStructure(
                "JUMBF label contains a forbidden character"
            ))
        ));
    }

    #[test]
    fn rejects_multiple_claim_or_signature_content_boxes() {
        let assertion_store = superbox(&UUID_ASSERTION_STORE, LABEL_ASSERTION_STORE, &[], None);
        for (uuid, label, expected) in [
            (
                UUID_CLAIM,
                LABEL_CLAIM_V2,
                "claim superbox must contain exactly one CBOR content box",
            ),
            (
                UUID_CLAIM_SIGNATURE,
                LABEL_CLAIM_SIGNATURE,
                "claim signature superbox must contain exactly one CBOR content box",
            ),
        ] {
            let malformed = superbox(&uuid, label, &[cbor_box(&[0xa0]), cbor_box(&[0xa1])], None);
            let counterpart = if uuid == UUID_CLAIM {
                superbox(
                    &UUID_CLAIM_SIGNATURE,
                    LABEL_CLAIM_SIGNATURE,
                    &[cbor_box(&[0xd2, 0x84])],
                    None,
                )
            } else {
                superbox(&UUID_CLAIM, LABEL_CLAIM_V2, &[cbor_box(&[0xa0])], None)
            };
            let manifest = superbox(
                &UUID_MANIFEST,
                "urn:c2pa:extra-content",
                &[assertion_store.clone(), malformed, counterpart],
                None,
            );
            let store = build_manifest_store(&[manifest]);
            assert!(matches!(
                parse_manifest_store(&store),
                Err(JumbfError::InvalidStructure(detail)) if detail == expected
            ));
        }
    }

    #[test]
    fn uuid_prefixes_correct() {
        assert_eq!(&UUID_MANIFEST_STORE[..4], b"c2pa");
        assert_eq!(&UUID_MANIFEST[..4], b"c2ma");
        assert_eq!(&UUID_CLAIM[..4], b"c2cl");
        assert_eq!(&UUID_MANIFEST_STORE[4..], &UUID_SUFFIX);
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(
            parse_box(&[0, 0, 0], 0),
            Err(JumbfError::TruncatedHeader(_))
        ));
    }

    #[test]
    fn rejects_length_overrun() {
        // claims size 0xffff but only a few bytes present
        let data = [0x00, 0x00, 0xff, 0xff, b'j', b'u', b'm', b'b'];
        assert!(matches!(
            parse_box(&data, 0),
            Err(JumbfError::LengthOverrun(_))
        ));
    }

    #[test]
    fn rejects_duplicate_manifest_labels() {
        let claim = &[0xa0];
        let sig = &[0xd2, 0x84];
        let first = build_manifest("urn:c2pa:duplicate", &[], claim, sig);
        let second = build_manifest("urn:c2pa:duplicate", &[], claim, sig);
        let store = build_manifest_store(&[first, second]);
        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::AmbiguousLabel(label)) if label == "urn:c2pa:duplicate"
        ));
    }

    #[test]
    fn rejects_duplicate_assertion_labels() {
        let first = assertion_box("c2pa.actions.v2", &[0xa0], None);
        let second = assertion_box("c2pa.actions.v2", &[0xa0], None);
        let manifest = build_manifest("urn:c2pa:test", &[first, second], &[0xa0], &[0xd2, 0x84]);
        let store = build_manifest_store(&[manifest]);
        assert!(matches!(
            parse_manifest_store(&store),
            Err(JumbfError::AmbiguousLabel(label)) if label == "c2pa.actions.v2"
        ));
    }
}
