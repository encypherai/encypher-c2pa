//! Deterministic robustness tests for the format parsers (adversarial input).
//!
//! Adversarial input is the #1 C2PA attack surface: a validator must never
//! panic, hang, or over-allocate on malformed assets. These tests feed a large
//! corpus of pseudo-random and structurally-hostile byte strings to every
//! `extract_manifest` path and assert the parser returns `Ok`/`Err` without
//! panicking. They run on stable Rust in CI; `fuzz/` holds the cargo-fuzz
//! targets for deeper coverage-guided runs.

use crate::c2pa_formats::{extract_manifest, AssetFormat};

/// A small deterministic PRNG (xorshift64*) — no external dependency, fully
/// reproducible so a failure is debuggable.
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

const FORMATS: &[AssetFormat] = &[
    AssetFormat::Jpeg,
    AssetFormat::Png,
    AssetFormat::Bmff,
    AssetFormat::Riff,
    AssetFormat::Tiff,
    AssetFormat::Gif,
    AssetFormat::Svg,
    AssetFormat::Pdf,
    AssetFormat::Zip,
    AssetFormat::Id3,
    AssetFormat::Flac,
    AssetFormat::Ogg,
    AssetFormat::Font,
    AssetFormat::Jxl,
];

/// Format magic prefixes — exercises the "looks valid then turns hostile" path,
/// which is where length/offset parsing bugs hide.
const MAGICS: &[&[u8]] = &[
    &[0xFF, 0xD8, 0xFF],               // JPEG SOI
    b"\x89PNG\r\n\x1a\n",              // PNG
    b"RIFF",                           // RIFF
    b"II*\x00",                        // TIFF LE
    b"MM\x00*",                        // TIFF BE
    b"GIF89a",                         // GIF
    b"<?xml version=\"1.0\"?><svg",    // SVG
    b"%PDF-1.7",                       // PDF
    b"PK\x03\x04",                     // ZIP
    b"ID3\x04\x00",                    // ID3
    b"fLaC",                           // FLAC
    b"OggS",                           // Ogg
    b"\x00\x01\x00\x00",               // SFNT/OTF
    b"\x00\x00\x00\x0cJXL \r\n\x87\n", // JXL
    b"\x00\x00\x00\x18ftypisom",       // BMFF
];

#[test]
fn parsers_never_panic_on_random_bytes() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for &fmt in FORMATS {
        for _ in 0..200 {
            let len = (rng.next() % 4096) as usize;
            let data = rng.bytes(len);
            // Must not panic; result is irrelevant.
            let _ = extract_manifest(fmt, &data);
        }
    }
}

#[test]
fn parsers_never_panic_on_magic_prefixed_garbage() {
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    for &fmt in FORMATS {
        for magic in MAGICS {
            for _ in 0..50 {
                let mut data = magic.to_vec();
                let tail = (rng.next() % 2048) as usize;
                data.extend(rng.bytes(tail));
                let _ = extract_manifest(fmt, &data);
            }
        }
    }
}

#[test]
fn parsers_never_panic_on_hostile_lengths() {
    // Boxes/chunks that declare enormous lengths must be rejected, not OOM.
    let cases: &[Vec<u8>] = &[
        // BMFF box with size 0xFFFFFFFF and no body.
        vec![0xFF, 0xFF, 0xFF, 0xFF, b'u', b'u', b'i', b'd'],
        // BMFF 64-bit largesize escape with absurd size.
        vec![
            0, 0, 0, 1, b'm', b'd', b'a', b't', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
        // PNG chunk claiming 4GiB length.
        {
            let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
            v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // length
            v.extend_from_slice(b"caBX");
            v
        },
        // RIFF claiming huge chunk size.
        {
            let mut v = b"RIFF".to_vec();
            v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
            v.extend_from_slice(b"WEBP");
            v
        },
        // JPEG APP11 segment with max length and no body.
        vec![0xFF, 0xD8, 0xFF, 0xEB, 0xFF, 0xFF],
        // Deeply truncated everything.
        vec![],
        vec![0x00],
    ];
    for &fmt in FORMATS {
        for c in cases {
            let _ = extract_manifest(fmt, c);
        }
    }
}
