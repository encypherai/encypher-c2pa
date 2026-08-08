//! CBOR encoding with explicit profiles for C2PA byte-parity.
//!
//! C2PA hash bindings depend on the exact CBOR byte encoding of claims and
//! assertions. Explicit, test-frozen profiles preserve byte parity across
//! legacy and current encoders.
//!
//! - [`Profile::LegacyC2paRs0784Indefinite`]: Pipeline A. c2pa-rs 0.78.4 via
//!   `ciborium`, which emits indefinite-length maps (0xbf), arrays (0x9f) and
//!   byte strings (0x5f). This is the dominant on-the-wire encoding for the 19
//!   c2pa-python formats.
//! - [`Profile::LegacyPipelineBDefinite`]: Pipeline B. Python `cbor2.dumps`,
//!   which emits definite-length items.
//! - [`Profile::CanonicalForHashedSubstructures`]: deterministic canonical CBOR
//!   (RFC 8949 §4.2), used only where the spec hashes canonical CBOR, e.g. CAWG
//!   hard-binding referenced-assertion hashes.
//!
//! The [`Value`] type is a CBOR data model that preserves byte-string vs text
//! distinction and map ordering, which `serde_json::Value` cannot.

use std::collections::BTreeMap;

mod decode;
mod encode;
mod value;

pub use decode::{decode, decode_prefix, DecodeError};
pub use encode::EncodeError;
pub use value::Value;

/// CBOR encoding profile. Selects length-encoding and ordering rules so output
/// matches a specific legacy emitter or the canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// c2pa-rs 0.78.4 / ciborium: indefinite-length maps, arrays, byte strings.
    LegacyC2paRs0784Indefinite,
    /// Pipeline B / Python cbor2: definite-length items, insertion order.
    LegacyPipelineBDefinite,
    /// RFC 8949 §4.2 canonical: definite-length, sorted keys, shortest ints.
    CanonicalForHashedSubstructures,
}

impl Profile {
    /// True when this profile emits indefinite-length headers for maps/arrays/bstr.
    pub fn indefinite(self) -> bool {
        matches!(self, Profile::LegacyC2paRs0784Indefinite)
    }

    /// True when map keys must be sorted by canonical byte ordering.
    pub fn sort_keys(self) -> bool {
        matches!(self, Profile::CanonicalForHashedSubstructures)
    }
}

/// Encode a [`Value`] to CBOR bytes using the given profile.
///
/// A serialization primitive, not a C2PA producer. Verification depends on it:
/// COSE signature checking rebuilds the `Sig_structure` and encodes it to
/// recover the exact bytes the signature covers (see `c2pa-crypto::cose`), and
/// [`canonical_sha256`] encodes canonically to hash CAWG substructures.
pub fn encode(value: &Value, profile: Profile) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode::encode_into(&mut out, value, profile)?;
    Ok(out)
}

/// Convenience: SHA-256 of the canonical-CBOR encoding of `value`.
///
/// Used for CAWG hard-binding where the spec hashes canonical CBOR.
pub fn canonical_sha256(value: &Value) -> Result<[u8; 32], EncodeError> {
    use sha2::{Digest, Sha256};
    let bytes = encode(value, Profile::CanonicalForHashedSubstructures)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().into())
}

/// A CBOR map with ordering preserved (insertion order for legacy profiles).
pub type Map = Vec<(Value, Value)>;

/// Build a CBOR text-keyed map from an ordered list of (key, value) pairs.
pub fn map_from_pairs(pairs: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Value::Text(k), v))
            .collect(),
    )
}

/// Sort a map's entries by canonical key ordering (RFC 8949 §4.2.1):
/// keys are compared by their encoded byte representation, shortest first.
pub fn canonical_sort(map: &mut Map) {
    let mut keyed: BTreeMap<Vec<u8>, (Value, Value)> = BTreeMap::new();
    for (k, v) in map.drain(..) {
        let enc = encode(&k, Profile::CanonicalForHashedSubstructures).unwrap_or_default();
        let sort_key = {
            let mut sk = Vec::with_capacity(enc.len() + 8);
            sk.extend_from_slice(&(enc.len() as u64).to_be_bytes());
            sk.extend_from_slice(&enc);
            sk
        };
        keyed.insert(sort_key, (k, v));
    }
    map.extend(keyed.into_values());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_vs_indefinite_map_header() {
        let v = map_from_pairs([("a".into(), Value::Integer(1))]);
        let def = encode(&v, Profile::LegacyPipelineBDefinite).unwrap();
        let indef = encode(&v, Profile::LegacyC2paRs0784Indefinite).unwrap();
        // definite single-entry map header is 0xa1; indefinite is 0xbf..0xff
        assert_eq!(def[0], 0xa1);
        assert_eq!(indef[0], 0xbf);
        assert_eq!(*indef.last().unwrap(), 0xff);
    }

    #[test]
    fn canonical_sorts_keys() {
        // "b" (1 char) and "aa" (2 chars): canonical orders shorter key first
        let v = Value::Map(vec![
            (Value::Text("aa".into()), Value::Integer(1)),
            (Value::Text("b".into()), Value::Integer(2)),
        ]);
        let enc = encode(&v, Profile::CanonicalForHashedSubstructures).unwrap();
        // first key after map header 0xa2 should be "b" (0x61 0x62)
        assert_eq!(enc[0], 0xa2);
        assert_eq!(&enc[1..3], &[0x61, 0x62]);
    }

    #[test]
    fn roundtrip_bytes_preserved() {
        let v = Value::Map(vec![
            (
                Value::Text("sig".into()),
                Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            ),
            (Value::Text("n".into()), Value::Integer(-5)),
        ]);
        for p in [
            Profile::LegacyPipelineBDefinite,
            Profile::CanonicalForHashedSubstructures,
        ] {
            let enc = encode(&v, p).unwrap();
            let dec = decode(&enc).unwrap();
            // byte string survives as Bytes, not Text
            if let Value::Map(m) = &dec {
                let sig = m
                    .iter()
                    .find(|(k, _)| *k == Value::Text("sig".into()))
                    .unwrap();
                assert_eq!(sig.1, Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
            } else {
                panic!("expected map");
            }
        }
    }
}
