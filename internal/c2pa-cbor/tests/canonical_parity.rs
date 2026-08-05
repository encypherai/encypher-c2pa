//! Byte-parity proof: `Profile::CanonicalForHashedSubstructures`
//! `canonical_sha256` must match Python `cbor2.dumps(value, canonical=True)`.
//!
//! This is the highest-risk CAWG parity item. The `cawg.identity` assertion's
//! `signer_payload.referenced_assertions[0].hash` is the SHA-256 over the
//! canonical CBOR (RFC 8949 section 4.2.1) of the `c2pa.hash.data` assertion's
//! data map. If canonical CBOR diverges by a single byte, hard-binding
//! verification fails.
//!
//! Expected hex below was generated with Python `cbor2` from the same logical
//! values:
//!
//! ```python
//! import cbor2, hashlib
//! enc = cbor2.dumps(value, canonical=True)
//! print(enc.hex(), hashlib.sha256(enc).hexdigest())
//! ```
//!
//! Each `value` Python literal is reproduced in the matching builder below.
//! `cbor2` canonical ordering (RFC 8949 §4.2.1 / RFC 7049 §3.9): map keys are
//! sorted by their *encoded* bytes, length-first then bytewise-lexicographic;
//! integers use shortest form; byte/text strings use definite length.

// Doc comments below align multi-line Python literals for readability; the
// alignment intentionally overindents list continuations.
#![allow(clippy::doc_overindented_list_items)]

use c2pa_cbor::{canonical_sha256, encode, Map, Profile, Value};

/// Encode `v` canonically and return lowercase hex.
fn canon_hex(v: &Value) -> String {
    hex::encode(encode(v, Profile::CanonicalForHashedSubstructures).unwrap())
}

/// Build a map from already-typed key/value pairs (keys may be ints or text).
fn map(pairs: Vec<(Value, Value)>) -> Value {
    Value::Map(pairs as Map)
}

fn txt(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn int(n: i128) -> Value {
    Value::Integer(n)
}

/// `bytes(range(n))` equivalent (Python pattern used in the vectors).
fn range_bytes(n: usize) -> Value {
    Value::Bytes((0..n).map(|i| (i % 256) as u8).collect())
}

/// 1. The real `c2pa.hash.data` data dict that CAWG hard-binding hashes.
///    Python:
///    {
///      "exclusions": [{"start": 1234, "length": 5678}, {"start": 99, "length": 1}],
///      "alg": "sha256",
///      "hash": bytes(range(32)),
///      "pad": b"",
///      "name": "jumbf manifest",
///      "url": "self#jumbf=c2pa.assertions",
///    }
fn hash_data_value() -> Value {
    map(vec![
        (
            txt("exclusions"),
            Value::Array(vec![
                map(vec![(txt("start"), int(1234)), (txt("length"), int(5678))]),
                map(vec![(txt("start"), int(99)), (txt("length"), int(1))]),
            ]),
        ),
        (txt("alg"), txt("sha256")),
        (txt("hash"), range_bytes(32)),
        (txt("pad"), Value::Bytes(vec![])),
        (txt("name"), txt("jumbf manifest")),
        (txt("url"), txt("self#jumbf=c2pa.assertions")),
    ])
}

const HASH_DATA_HEX: &str = "a663616c676673686132353663706164406375726c781a73656c66236a756d62663d633270612e617373657274696f6e7364686173685820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f646e616d656e6a756d6266206d616e69666573746a6578636c7573696f6e7382a26573746172741904d2666c656e67746819162ea26573746172741863666c656e67746801";
const HASH_DATA_SHA256: &str = "b1887b0641f876bd527d174cb110caad5ea70a37e13c57c5e87e6d7ba491ec6d";

#[test]
fn canonical_matches_cbor2_hash_data() {
    assert_eq!(canon_hex(&hash_data_value()), HASH_DATA_HEX);
}

/// 1b. The CAWG `signer_payload` the identity COSE_Sign1 signs over. These are
///     the exact bytes fed to the `Sig_structure`, so a single-byte divergence
///     breaks bidirectional COSE interop (the engine and Python
///     `cose_signer.sign_cawg_identity_payload` must agree). Built in source
///     order (`referenced_assertions` then `sig_type`); the canonical profile
///     MUST reorder the top-level keys so `sig_type` (length-8 key) precedes
///     `referenced_assertions` (length-20 key) per RFC 8949 §4.2.1 length-first
///     ordering — this vector proves that reordering matches cbor2.
///     Python:
///     {
///       "referenced_assertions": [
///         {"url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
///          "hash": bytes([0x11])*32, "alg": "sha256"}
///       ],
///       "sig_type": "cawg.x509.cose",
///     }
fn cawg_signer_payload_value() -> Value {
    map(vec![
        (
            txt("referenced_assertions"),
            Value::Array(vec![map(vec![
                (txt("url"), txt("self#jumbf=c2pa.assertions/c2pa.hash.data")),
                (txt("hash"), Value::Bytes(vec![0x11u8; 32])),
                (txt("alg"), txt("sha256")),
            ])]),
        ),
        (txt("sig_type"), txt("cawg.x509.cose")),
    ])
}

const CAWG_SIGNER_PAYLOAD_HEX: &str = "a2687369675f747970656e636177672e783530392e636f7365757265666572656e6365645f617373657274696f6e7381a363616c67667368613235366375726c782973656c66236a756d62663d633270612e617373657274696f6e732f633270612e686173682e64617461646861736858201111111111111111111111111111111111111111111111111111111111111111";
const CAWG_SIGNER_PAYLOAD_SHA256: &str =
    "60bf2b1feebb2b5abfb6de341d935528721c1d766d6eaf121d384b93313f1b6a";

#[test]
fn canonical_matches_cbor2_cawg_signer_payload() {
    assert_eq!(
        canon_hex(&cawg_signer_payload_value()),
        CAWG_SIGNER_PAYLOAD_HEX
    );
    assert_eq!(
        hex::encode(canonical_sha256(&cawg_signer_payload_value()).unwrap()),
        CAWG_SIGNER_PAYLOAD_SHA256
    );
}

/// 2. Mixed int/text keys + mixed lengths: exercises length-first key ordering.
///    Python:
///    {1:"one", 10:"ten", 100:"hundred", -1:"negone", "a":1, "bb":2, "ccc":3, "z":26}
#[test]
fn canonical_matches_cbor2_mixed_keys() {
    let v = map(vec![
        (int(1), txt("one")),
        (int(10), txt("ten")),
        (int(100), txt("hundred")),
        (int(-1), txt("negone")),
        (txt("a"), int(1)),
        (txt("bb"), int(2)),
        (txt("ccc"), int(3)),
        (txt("z"), int(26)),
    ]);
    assert_eq!(
        canon_hex(&v),
        "a801636f6e650a6374656e20666e65676f6e6518646768756e64726564616101617a181a626262026363636303"
    );
}

/// 3. Byte strings at head-encoding boundaries (<24, =24, 255, 256).
///    Python:
///    {"b0":b"", "b1":b"\x01", "b23":bytes(range(23)), "b24":bytes(range(24)),
///     "b255":bytes(i%256 for i in range(255)), "b256":bytes(i%256 for i in range(256))}
#[test]
fn canonical_matches_cbor2_bstr_lengths() {
    let v = map(vec![
        (txt("b0"), Value::Bytes(vec![])),
        (txt("b1"), Value::Bytes(vec![1])),
        (txt("b23"), range_bytes(23)),
        (txt("b24"), range_bytes(24)),
        (txt("b255"), range_bytes(255)),
        (txt("b256"), range_bytes(256)),
    ]);
    let expected = "a66262304062623141016362323357000102030405060708090a0b0c0d0e0f10111213141516636232345818000102030405060708090a0b0c0d0e0f1011121314151617646232353558ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe6462323536590100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    assert_eq!(canon_hex(&v), expected);
}

/// 4. Integer boundaries (shortest form) incl. negatives.
///    Python list:
///    [0,23,24,255,256,65535,65536,4294967295,4294967296,
///     -1,-24,-25,-256,-257,-65536,-65537]
#[test]
fn canonical_matches_cbor2_ints() {
    let v = Value::Array(
        [
            0i128, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296, -1, -24, -25, -256,
            -257, -65536, -65537,
        ]
        .into_iter()
        .map(int)
        .collect(),
    );
    assert_eq!(
        canon_hex(&v),
        "900017181818ff19010019ffff1a000100001affffffff1b00000001000000002037381838ff39010039ffff3a00010000"
    );
}

/// 5. Nested arrays/maps, bools, null, large + negative ints.
///    Python:
///    {"arr":[1,[2,3],{"k":b"\xaa\xbb"},"s"],
///     "m":{"inner":{"deep":[True,False,None]}},
///     "neg":-123456789, "big":9007199254740993}
#[test]
fn canonical_matches_cbor2_nested() {
    let v = map(vec![
        (
            txt("arr"),
            Value::Array(vec![
                int(1),
                Value::Array(vec![int(2), int(3)]),
                map(vec![(txt("k"), Value::Bytes(vec![0xaa, 0xbb]))]),
                txt("s"),
            ]),
        ),
        (
            txt("m"),
            map(vec![(
                txt("inner"),
                map(vec![(
                    txt("deep"),
                    Value::Array(vec![Value::Bool(true), Value::Bool(false), Value::Null]),
                )]),
            )]),
        ),
        (txt("neg"), int(-123456789)),
        (txt("big"), int(9007199254740993)),
    ]);
    assert_eq!(
        canon_hex(&v),
        "a4616da165696e6e6572a1646465657083f5f4f6636172728401820203a1616b42aabb6173636269671b0020000000000001636e65673a075bcd14"
    );
}

/// 6. Higher-level: the hash CAWG actually binds to. `canonical_sha256` of the
///    `c2pa.hash.data` data dict must equal SHA-256 of the cbor2 canonical bytes.
#[test]
fn canonical_sha256_matches_cawg_hard_binding_hash() {
    let got = canonical_sha256(&hash_data_value()).unwrap();
    assert_eq!(hex::encode(got), HASH_DATA_SHA256);
}
