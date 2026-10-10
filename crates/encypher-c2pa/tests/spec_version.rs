// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! `VerifyOptions::spec_version` selects the validation policy without
//! drifting the default.

use std::path::Path;

use encypher_c2pa::{
    detached_manifest_evidence, detached_manifest_evidence_with_options, verify_with_options,
    Error, VerifyOptions, C2PA_PROFILE, C2PA_PROFILE_2_5,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name),
    )
    .expect("fixture")
}

fn options(spec_version: Option<&str>) -> VerifyOptions {
    let mut options = VerifyOptions {
        spec_version: spec_version.map(str::to_string),
        validation_time: Some("2026-01-01T00:00:00Z".into()),
        online: Some(false),
        ..VerifyOptions::default()
    };
    options.telemetry.enabled = Some(false);
    options
}

#[test]
fn none_and_explicit_2_4_produce_identical_reports() {
    let asset = fixture("signed_test.jpg");
    let default = verify_with_options(&asset, "image/jpeg", &options(None)).unwrap();
    let explicit = verify_with_options(&asset, "image/jpeg", &options(Some("2.4"))).unwrap();
    assert_eq!(default.to_json().unwrap(), explicit.to_json().unwrap());
    assert_eq!(default.profile, C2PA_PROFILE);
    assert_eq!(
        default.manifest_report["engine_profile"]["spec_version"],
        "2.4"
    );
    // The historical ladder is unchanged: no 2.5 rung under the default.
    let rungs = default.manifest_report.to_string();
    assert!(!rungs.contains("\"version\":\"2.5\""));
}

#[test]
fn explicit_2_5_reaches_kernel_and_report() {
    let asset = fixture("signed_test.jpg");
    let report = verify_with_options(&asset, "image/jpeg", &options(Some("2.5"))).unwrap();
    assert_eq!(report.profile, C2PA_PROFILE_2_5);
    assert_eq!(
        report.manifest_report["engine_profile"]["spec_version"],
        "2.5"
    );
    assert_eq!(
        report.manifest_report["engine_profile"]["operating_mode"],
        "regular"
    );
}

#[test]
fn unknown_and_unsupported_selections_fail_closed() {
    for (spec, strict) in [("2.6", false), ("2.4.0", false), ("", false), ("2.5", true)] {
        let mut options = options(Some(spec));
        options.strict_conformance = strict;
        let error = options.validate().expect_err("selection must be refused");
        assert!(
            matches!(error, Error::UnsupportedSpecVersion(_)),
            "{spec:?}"
        );
        assert_eq!(error.code(), "unsupported_spec_version");
        // Refused before the asset is parsed, whatever the bytes are.
        let error = verify_with_options(b"not an asset", "image/jpeg", &options).unwrap_err();
        assert_eq!(error.code(), "unsupported_spec_version");
        let error =
            encypher_c2pa::verify_with_manifest_store(b"not an asset", b"", "image/jpeg", &options)
                .unwrap_err();
        assert_eq!(error.code(), "unsupported_spec_version");
    }
}

#[test]
fn detached_evidence_default_is_the_2_4_locator() {
    let asset = fixture("signed_test.jpg");
    let legacy = detached_manifest_evidence(&asset, "image/jpeg").unwrap();
    let explicit =
        detached_manifest_evidence_with_options(&asset, "image/jpeg", &options(Some("2.4")))
            .unwrap();
    assert_eq!(legacy, explicit);
    let proposed =
        detached_manifest_evidence_with_options(&asset, "image/jpeg", &options(Some("2.5")))
            .unwrap();
    // JPEG locates its store identically in both revisions.
    assert_eq!(legacy, proposed);
}

#[test]
fn unresolved_xml_comment_carriage_is_not_admitted_as_2_5() {
    for mime in ["application/xml", "text/xml"] {
        let error = verify_with_options(b"<root/>", mime, &options(Some("2.5")))
            .expect_err("the draft XML-comment carrier is not well formed");
        assert_eq!(error.code(), "unsupported_mime");
        let legacy = verify_with_options(b"<root/>", mime, &options(Some("2.4"))).unwrap();
        let default = verify_with_options(b"<root/>", mime, &options(None)).unwrap();
        assert_eq!(legacy.to_json().unwrap(), default.to_json().unwrap());
        let error =
            detached_manifest_evidence_with_options(b"<root/>", mime, &options(Some("2.5")))
                .unwrap_err();
        assert_eq!(error.code(), "unsupported_mime");
    }
}
