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

/// Description box toggle: label present + requestable.
const TOGGLE_REQUESTABLE: u8 = 0x03;
/// Description box toggle: private (salt sub-box present).
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
}

/// Wrap `payload` in an ISOBMFF box with a 4-byte type code.
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

/// Build a JUMBF description box (`jumd`).
fn description_box(type_uuid: &[u8; 16], label: &str, salt: Option<&[u8]>) -> Vec<u8> {
    let mut toggles = TOGGLE_REQUESTABLE;
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

/// Wrap CBOR bytes in a CBOR content box (`cbor`).
pub fn cbor_box(cbor: &[u8]) -> Vec<u8> {
    box_bytes(TYPE_CBOR, cbor)
}

/// Build an assertion superbox containing a single CBOR content box.
pub fn assertion_box(label: &str, cbor: &[u8], salt: Option<&[u8]>) -> Vec<u8> {
    superbox(&UUID_CBOR_CONTENT, label, &[cbor_box(cbor)], salt)
}

/// Return the JUMBF *content* of a superbox: its payload after the 8-byte
/// `LBox+TBox` header. This is the byte range hashed for `assertion.hashedURI`
/// bindings (C2PA spec 14.2.3), so a signer must hash exactly these bytes.
///
/// Returns the input unchanged if it is too short to contain a box header.
pub fn superbox_content(superbox_bytes: &[u8]) -> &[u8] {
    if superbox_bytes.len() < 8 {
        return superbox_bytes;
    }
    &superbox_bytes[8..]
}

/// Build a single C2PA manifest (assertion store + claim + signature) with a
/// v2 claim box (`c2pa.claim.v2`).
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
pub fn build_manifest_store(manifests: &[Vec<u8>]) -> Vec<u8> {
    superbox(&UUID_MANIFEST_STORE, "c2pa", manifests, None)
}

/// Extract raw manifest superboxes from a C2PA manifest store, preserving
/// store order.
pub fn manifest_superboxes_from_store(data: &[u8]) -> Result<Vec<Vec<u8>>, JumbfError> {
    let top = parse_box(data, 0)?;
    if &top.box_type != TYPE_JUMB {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMB,
            found: top.box_type,
        });
    }
    let store = parse_superbox_payload(top.payload)?;
    if store.type_uuid != UUID_MANIFEST_STORE {
        return Err(JumbfError::UnexpectedUuid);
    }

    let desc = parse_box(top.payload, 0)?;
    let mut pos = desc.next;
    let mut manifests = Vec::new();
    while pos < top.payload.len() {
        let b = parse_box(top.payload, pos)?;
        if b.box_type == *TYPE_JUMB {
            let full = &top.payload[pos..b.next];
            let parsed = parse_superbox(full)?;
            if parsed.type_uuid == UUID_MANIFEST {
                manifests.push(full.to_vec());
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
        let end = offset
            .checked_add(xl as usize)
            .ok_or(JumbfError::LengthOverrun(xl))?;
        if end > data.len() || (xl as usize) < 16 {
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
    let desc = parse_box(payload, 0)?;
    if &desc.box_type != TYPE_JUMD {
        return Err(JumbfError::UnexpectedType {
            expected: *TYPE_JUMD,
            found: desc.box_type,
        });
    }
    if desc.payload.len() < 17 {
        return Err(JumbfError::TruncatedHeader(0));
    }
    let mut type_uuid = [0u8; 16];
    type_uuid.copy_from_slice(&desc.payload[..16]);
    // toggles at [16], label starts at [17], null-terminated
    let label_bytes = &desc.payload[17..];
    let null = label_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(label_bytes.len());
    let label = String::from_utf8_lossy(&label_bytes[..null]).into_owned();

    let mut content = Vec::new();
    let mut pos = desc.next;
    while pos < payload.len() {
        let b = parse_box(payload, pos)?;
        content.push((b.box_type, b.payload));
        pos = b.next;
    }
    Ok(Superbox {
        type_uuid,
        label,
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
    parse_superbox_payload(b.payload)
}

/// A parsed C2PA manifest: label, assertions (label -> CBOR bytes), raw
/// assertion JUMBF (label -> superbox payload, for hash verification), claim
/// CBOR, and signature COSE bytes.
pub struct ParsedManifest<'a> {
    /// Manifest URN label.
    pub label: String,
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
    let mut manifests = Vec::new();
    for (ctype, cpayload) in &store.content {
        if ctype == TYPE_JUMB {
            if let Some(m) = parse_manifest(cpayload)? {
                manifests.push(m);
            }
        }
    }
    Ok(ParsedStore { manifests })
}

fn parse_manifest(payload: &[u8]) -> Result<Option<ParsedManifest<'_>>, JumbfError> {
    let parsed = parse_superbox_payload(payload)?;
    if parsed.type_uuid != UUID_MANIFEST {
        return Ok(None);
    }
    let mut m = ParsedManifest {
        label: parsed.label.clone(),
        assertions: Vec::new(),
        assertion_jumbf: Vec::new(),
        claim_cbor: None,
        signature_cose: None,
        claim_count: 0,
        claim_box_label: None,
    };
    for (ctype, cpayload) in &parsed.content {
        if ctype != TYPE_JUMB {
            continue;
        }
        let inner = parse_superbox_payload(cpayload)?;
        if inner.type_uuid == UUID_ASSERTION_STORE {
            for (atype, apayload) in &inner.content {
                if atype == TYPE_JUMB {
                    let assertion = parse_superbox_payload(apayload)?;
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
            if m.claim_box_label.is_none() {
                m.claim_box_label = Some(inner.label.clone());
            }
            for (act, acp) in &inner.content {
                if act == TYPE_CBOR && m.claim_cbor.is_none() {
                    m.claim_cbor = Some(acp);
                }
            }
        } else if inner.type_uuid == UUID_CLAIM_SIGNATURE {
            // The signature superbox MUST be labeled exactly `c2pa.signature`.
            // A box carrying the claim-signature UUID under any other label is
            // not a usable signature (the verifier reports claimSignature.missing).
            if inner.label != "c2pa.signature" {
                continue;
            }
            for (act, acp) in &inner.content {
                if act == TYPE_CBOR {
                    m.signature_cose = Some(acp);
                    break;
                }
            }
        }
    }
    Ok(Some(m))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
