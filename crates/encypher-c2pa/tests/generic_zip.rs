// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use encypher_c2pa::{supported_mime_types, verify};

const ZIP_MIMES: [&str; 2] = ["application/zip", "application/x-zip-based"];

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    fs::read(path).expect("generic ZIP fixture must be readable")
}

#[test]
fn generic_zip_mimes_verify_collection_hash_match_and_mismatch() {
    let signed = fixture("signed_generic.zip");
    let tampered = fixture("tampered_signed_generic.zip");

    for mime in ZIP_MIMES {
        let valid = verify(&signed, mime).expect("signed generic ZIP must produce a report");
        assert_eq!(valid.integrity, "valid", "{mime}");
        assert_eq!(valid.signature, "valid", "{mime}");
        assert_eq!(valid.hard_binding, "match", "{mime}");

        let invalid = verify(&tampered, mime).expect("tampered generic ZIP must produce a report");
        assert_eq!(invalid.integrity, "invalid", "{mime}");
        assert_eq!(invalid.signature, "valid", "{mime}");
        assert_eq!(invalid.hard_binding, "mismatch", "{mime}");
    }
}

#[test]
fn generic_zip_mimes_are_discoverable() {
    let supported = supported_mime_types();
    for mime in ZIP_MIMES {
        assert!(
            supported.contains(&mime),
            "supported MIME list omits {mime}"
        );
    }
}
