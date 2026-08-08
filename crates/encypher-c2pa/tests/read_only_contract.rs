//! Verification never modifies what it is given.
//!
//! This is the SDK's central promise and, unlike everything else about it, the
//! promise is observable: hash the input before and after and the digest must
//! not move. The public-surface gate cannot check this. It locks the NAMES and
//! KINDS of public items, so an already-approved function can have its body
//! rewritten to write bytes and the inventory stays byte-for-byte identical - a
//! reviewer demonstrated exactly that by making `verify_file` splice a real PNG
//! `caBX` chunk into its own input while the gate still reported PASS.
//!
//! These tests close that gap from the other side: whatever the shape of the
//! API, the observable behaviour of every public entry point is checked. They
//! cover the failure paths too, because an error return is the easiest place
//! for a side effect to hide.

use std::fs;
use std::path::Path;

use encypher_c2pa::{verify, verify_file, verify_with_options, VerifyOptions};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

/// Copy a fixture into a scratch file so a mutation would be observable on disk
/// rather than on a temporary buffer.
///
/// Each caller gets its OWN directory. Rust runs these tests concurrently, and
/// a shared directory made the sibling-file assertion observe another test's
/// scratch file mid-run.
fn scratch(case: &str, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("encypher-readonly-{}-{case}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("seed scratch file");
    path
}

#[test]
fn verify_does_not_mutate_its_input_buffer() {
    for (name, mime) in [
        ("signed_test.jpg", "image/jpeg"),
        ("signed_test.mp4", "video/mp4"),
    ] {
        let data = fixture(name);
        let before = digest(&data);
        let _ = verify(&data, mime);
        assert_eq!(
            before,
            digest(&data),
            "verify() modified its input buffer for {name}",
        );
    }
}

#[test]
fn verify_does_not_mutate_on_the_error_path() {
    // An unsupported MIME type and truncated bytes both return Err. A side
    // effect on the way out would be easy to miss precisely because nobody
    // inspects the input after a failure.
    let data = fixture("signed_test.jpg");

    let before = digest(&data);
    assert!(verify(&data, "application/x-not-a-real-type").is_err());
    assert_eq!(before, digest(&data), "verify() mutated input on error");

    let truncated = data[..data.len() / 3].to_vec();
    let before = digest(&truncated);
    let _ = verify(&truncated, "image/jpeg");
    assert_eq!(
        before,
        digest(&truncated),
        "verify() mutated a truncated input",
    );
}

#[test]
fn verify_with_options_does_not_mutate_its_input_buffer() {
    let data = fixture("signed_test.jpg");
    let before = digest(&data);
    let _ = verify_with_options(&data, "image/jpeg", &VerifyOptions::default());
    assert_eq!(before, digest(&data), "verify_with_options() mutated input");
}

#[test]
fn verify_file_does_not_touch_the_file_it_reads() {
    let data = fixture("signed_test.jpg");
    let path = scratch("reads", "signed.jpg", &data);
    let before = digest(&data);

    let _ = verify_file(&path, None, &VerifyOptions::default());

    let after = fs::read(&path).expect("file still readable");
    assert_eq!(
        before,
        digest(&after),
        "verify_file() modified the file on disk",
    );
    assert_eq!(
        data.len(),
        after.len(),
        "verify_file() changed the file size"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn verify_file_does_not_touch_the_file_on_the_error_path() {
    // Unsigned content: verification returns a report with no provenance, or an
    // error for an unknown type. Neither may write.
    let data = b"not an asset, just bytes".to_vec();
    let path = scratch("errors", "unsigned.jpg", &data);
    let before = digest(&data);

    let _ = verify_file(&path, Some("image/jpeg"), &VerifyOptions::default());
    let after = fs::read(&path).expect("file still readable");
    assert_eq!(
        before,
        digest(&after),
        "verify_file() wrote to a file that failed verification",
    );

    let _ = verify_file(
        &path,
        Some("application/x-not-a-real-type"),
        &VerifyOptions::default(),
    );
    let after = fs::read(&path).expect("file still readable");
    assert_eq!(
        before,
        digest(&after),
        "verify_file() wrote to a file with an unsupported MIME type",
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn verify_file_creates_no_sibling_files() {
    // A writer that does not touch the input could still drop a manifest beside
    // it. Assert the directory is unchanged.
    let data = fixture("signed_test.jpg");
    let path = scratch("siblings", "solo.jpg", &data);
    let dir = path.parent().expect("scratch parent").to_path_buf();

    let before: Vec<_> = {
        let mut v: Vec<_> = fs::read_dir(&dir)
            .expect("scratch listing")
            .map(|e| e.expect("dir entry").file_name())
            .collect();
        v.sort();
        v
    };

    let _ = verify_file(&path, None, &VerifyOptions::default());

    let after: Vec<_> = {
        let mut v: Vec<_> = fs::read_dir(&dir)
            .expect("scratch listing")
            .map(|e| e.expect("dir entry").file_name())
            .collect();
        v.sort();
        v
    };

    assert_eq!(before, after, "verify_file() created or removed a file");
    let _ = fs::remove_file(&path);
}
