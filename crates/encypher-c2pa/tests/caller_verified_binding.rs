// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Contract of the store-level CAWG evaluator a caller uses when it has
//! already verified the asset's content binding itself.

#![cfg(feature = "caller-verified-binding")]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use encypher_c2pa::{
    detached_manifest_evidence, verify_with_options, CawgEvaluation, CawgEvaluator, CawgProfile,
    CawgStoreHost, Error, TelemetryOptions, VerifyOptions,
};

fn vector(path: &str) -> Vec<u8> {
    fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/cawg").join(path))
        .unwrap_or_else(|error| panic!("{path}: {error}"))
}

fn text(path: &str) -> String {
    String::from_utf8(vector(path)).expect("PEM is UTF-8")
}

fn offline(options: VerifyOptions) -> VerifyOptions {
    VerifyOptions {
        no_default_trust: true,
        online: Some(false),
        telemetry: TelemetryOptions {
            enabled: Some(false),
            ..TelemetryOptions::default()
        },
        ..options
    }
}

fn generous() -> CawgProfile {
    CawgProfile::new("2.4", false, false).expect("2.4 regular core-spec")
}

fn strict() -> CawgProfile {
    CawgProfile::new("2.4", true, true).expect("2.4 conformance program")
}

fn store_of(asset: &[u8], mime: &str) -> Vec<u8> {
    detached_manifest_evidence(asset, mime)
        .expect("manifest evidence")
        .expect("embedded manifest store")
        .manifest_store
}

fn codes(evaluation: &CawgEvaluation) -> Vec<String> {
    match evaluation {
        CawgEvaluation::Evaluated {
            validation_results, ..
        } => validation_results
            .success
            .iter()
            .chain(&validation_results.informational)
            .chain(&validation_results.failure)
            .map(|status| status.code.clone())
            .collect(),
        other => panic!("expected an evaluation, got {other:?}"),
    }
}

const ES256_JPEG: &str = "generated/identity-1.2/assets/x509-es256-jpeg.jpg";
const C2PA_RS_JPEG: &str =
    "external/contentauth-c2pa-rs/d7f13829/assets/cli__tests__fixtures__C_with_CAWG_data.jpg";

fn es256_options() -> VerifyOptions {
    offline(VerifyOptions {
        allowed_list_pem: Some(text("generated/identity-1.2/trust/claim-allowed.pem")),
        cawg_allowed_certs_pem: Some(text("generated/identity-1.2/trust/cawg-allowed.pem")),
        validation_time: Some("2026-08-06T00:00:00Z".into()),
        ..VerifyOptions::default()
    })
}

/// The evaluator returns exactly the identity step's statuses: the same
/// `cawg.*` outcome the full verifier reports for the same trust inputs, and
/// nothing about the C2PA claim itself.
#[test]
fn evaluates_the_identity_of_a_store_whose_binding_the_caller_verified() {
    let asset = vector(ES256_JPEG);
    let store = store_of(&asset, "image/jpeg");
    let evaluator = CawgEvaluator::new(&es256_options(), &generous()).expect("evaluator");

    let evaluation = evaluator
        .evaluate_with_caller_verified_binding(&store, CawgStoreHost::Asset)
        .expect("evaluation");
    let returned = codes(&evaluation);

    assert!(returned.contains(&"cawg.identity.trusted".to_string()), "{returned:?}");
    assert!(
        returned
            .iter()
            .all(|code| code.starts_with("cawg.") || code.starts_with("com.encypher.cawg.")),
        "only identity-step statuses leave the evaluator: {returned:?}"
    );

    let full = verify_with_options(&asset, "image/jpeg", &es256_options()).expect("full verify");
    let mut expected: Vec<String> = full.cawg_statuses().iter().map(|s| s.code.clone()).collect();
    let mut actual = returned.clone();
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected, "same identity outcome as the full verifier");

    let CawgEvaluation::Evaluated {
        manifest_label,
        store_manifest_sha256,
        ..
    } = evaluation
    else {
        unreachable!()
    };
    assert_eq!(
        Some(manifest_label.as_str()),
        full.manifest_report["active_manifest"].as_str()
    );
    assert!(store_manifest_sha256
        .iter()
        .any(|(label, _)| *label == manifest_label));
}

/// Statuses the pipeline records outside the identity step (here the
/// training-mining signal) are not the evaluator's to report, and the CAWG
/// 1.1 field-order signal is kept only under the generous posture.
#[test]
fn returns_only_the_identity_step_slice_and_follows_the_profile() {
    let asset = vector(C2PA_RS_JPEG);
    let store = store_of(&asset, "image/jpeg");
    let options = offline(VerifyOptions {
        validation_time: Some("2025-05-01T00:00:00Z".into()),
        ..VerifyOptions::default()
    });

    let generous_codes = codes(
        &CawgEvaluator::new(&options, &generous())
            .expect("evaluator")
            .evaluate_with_caller_verified_binding(&store, CawgStoreHost::Asset)
            .expect("evaluation"),
    );
    assert!(generous_codes.contains(&"cawg.x509.signature.validated".to_string()));
    assert!(generous_codes.contains(&"com.encypher.cawg.legacyProfile".to_string()));
    assert!(
        !generous_codes
            .iter()
            .any(|code| code.starts_with("com.encypher.cawg.trainingMining")),
        "training-mining is not an identity-step status: {generous_codes:?}"
    );

    let strict_codes = codes(
        &CawgEvaluator::new(&options, &strict())
            .expect("evaluator")
            .evaluate_with_caller_verified_binding(&store, CawgStoreHost::Asset)
            .expect("evaluation"),
    );
    assert!(!strict_codes.contains(&"com.encypher.cawg.legacyProfile".to_string()));
    assert!(!strict_codes.contains(&"cawg.x509.signature.validated".to_string()));
}

#[test]
fn a_store_without_a_manifest_closes_the_gate_with_claim_missing() {
    let evaluator = CawgEvaluator::new(&es256_options(), &generous()).expect("evaluator");
    let asset = vector(ES256_JPEG);
    let store = store_of(&asset, "image/jpeg");
    // The same store with every manifest removed: keep the store superbox
    // header and description box, drop the children.
    let emptied = empty_store_like(&store);
    match evaluator.evaluate_with_caller_verified_binding(&emptied, CawgStoreHost::Asset) {
        Ok(CawgEvaluation::StoreGateClosed { code, .. }) => assert_eq!(code, "claim.missing"),
        other => panic!("expected StoreGateClosed, got {other:?}"),
    }
}

#[test]
fn a_store_over_the_size_bound_is_refused_before_parsing() {
    let evaluator = CawgEvaluator::new(&es256_options(), &generous()).expect("evaluator");
    let oversized = vec![0_u8; 64 * 1024 * 1024 + 1];
    let error = evaluator
        .evaluate_with_caller_verified_binding(&oversized, CawgStoreHost::Asset)
        .expect_err("over the bound");
    assert!(matches!(error, Error::Verification(_)), "{error}");
}

#[test]
fn options_the_evaluator_cannot_honour_are_rejected() {
    let reject = |options: VerifyOptions, field: &str| {
        let error = CawgEvaluator::new(&options, &generous()).expect_err(field);
        assert!(
            matches!(&error, Error::Verification(message) if message.contains(field)),
            "{field}: {error}"
        );
    };
    reject(
        offline(VerifyOptions {
            strict_conformance: true,
            ..VerifyOptions::default()
        }),
        "strict_conformance",
    );
    reject(
        VerifyOptions {
            online: Some(true),
            ..offline(VerifyOptions::default())
        },
        "online",
    );
    reject(
        offline(VerifyOptions {
            external_data: Some(HashMap::from([("https://x".into(), "AA==".into())])),
            ..VerifyOptions::default()
        }),
        "external_data",
    );
}

#[test]
fn unknown_spec_versions_are_rejected() {
    for version in ["1.3", "2.5", ""] {
        let error = CawgProfile::new(version, false, false).expect_err(version);
        assert!(
            matches!(&error, Error::Verification(message) if message.contains("spec_version")),
            "{version}: {error}"
        );
    }
    for version in ["1.4", "2.0", "2.1", "2.2", "2.3", "2.4"] {
        CawgProfile::new(version, false, false).unwrap_or_else(|e| panic!("{version}: {e}"));
    }
}

/// A manifest store superbox with the same description box and no children.
fn empty_store_like(store: &[u8]) -> Vec<u8> {
    let description_len = u32::from_be_bytes(store[8..12].try_into().unwrap()) as usize;
    let payload = &store[8..8 + description_len];
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
    out.extend_from_slice(b"jumb");
    out.extend_from_slice(payload);
    out
}
