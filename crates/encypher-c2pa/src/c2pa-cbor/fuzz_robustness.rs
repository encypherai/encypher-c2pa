//! Deterministic robustness tests for the CBOR decoder (adversarial input).
//!
//! The CBOR decoder parses untrusted claim/assertion/COSE bytes. It must never
//! panic, recurse without bound, or over-allocate. These tests feed random and
//! hostile byte strings and assert the decoder returns `Ok`/`Err` cleanly.

use crate::c2pa_cbor::decode;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

#[test]
fn decoder_never_panics_on_random_bytes() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for _ in 0..5000 {
        let len = (rng.next() % 1024) as usize;
        let _ = decode(&rng.bytes(len));
    }
}

#[test]
fn decoder_rejects_deep_nesting_without_stack_overflow() {
    // Nested indefinite arrays far beyond the depth guard.
    let mut data = vec![0x9f; 10_000]; // 0x9f = indefinite array start
    data.extend(std::iter::repeat_n(0xff, 10_000));
    // Must return an error (DepthExceeded), not overflow the stack.
    assert!(decode(&data).is_err());
}

#[test]
fn decoder_rejects_hostile_length_prefixes() {
    let cases: &[Vec<u8>] = &[
        // byte string claiming 2^32-1 bytes with no body.
        vec![0x5a, 0xFF, 0xFF, 0xFF, 0xFF],
        // text string claiming 2^64-1 bytes.
        vec![0x7b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        // array claiming 2^32-1 elements.
        vec![0x9a, 0xFF, 0xFF, 0xFF, 0xFF],
        // map claiming huge entry count.
        vec![0xbb, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        // truncated head.
        vec![0x18],
        vec![0x9f],
    ];
    for c in cases {
        // Must not panic or hang; must not allocate gigabytes.
        let _ = decode(c);
    }
}

#[test]
fn decoder_handles_all_single_byte_inputs() {
    for b in 0u16..=255 {
        let _ = decode(&[b as u8]);
    }
}
