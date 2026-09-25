// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! CAWG Metadata Assertion 1.1 validation.
//!
//! The specification registers no validation status codes. The dispatch layer
//! therefore reports this validator through `com.encypher.cawg.metadata.*`
//! extension codes.

use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::AssertionContentType;
use serde_json::json;

use super::ValidationResults;

pub(crate) const CAWG_METADATA_INVALID: &str = "com.encypher.cawg.metadata.invalid";

pub(super) fn validate_and_report(
    content_type: Option<AssertionContentType>,
    assertion_jumbf: Option<&[u8]>,
    decoded: Option<&Value>,
    url: String,
    results: &mut ValidationResults,
) {
    if let Err(reason) = validate_json_ld(content_type, assertion_jumbf, decoded) {
        results.push_failure_with_details(
            CAWG_METADATA_INVALID,
            url,
            "CAWG metadata assertion does not conform to version 1.1".into(),
            json!({ "reason": reason }),
        );
    }
}

/// Validate the normative CAWG Metadata 1.1 shape.
///
/// The assertion has a JSON JUMBF type, carries exactly one JSON content box,
/// and the JSON-LD object supplies a non-empty `@context`. A nested JUMBF
/// protection box is not a content box and does not change the count.
pub(super) fn validate_json_ld(
    content_type: Option<AssertionContentType>,
    assertion_jumbf: Option<&[u8]>,
    decoded: Option<&Value>,
) -> Result<(), &'static str> {
    if content_type != Some(AssertionContentType::Json) {
        return Err("cawg.metadata must use the JSON JUMBF content type");
    }
    let jumbf = assertion_jumbf.ok_or("cawg.metadata has no assertion superbox")?;
    if json_content_box_count(jumbf)? != 1 {
        return Err("cawg.metadata must contain exactly one JSON content box");
    }
    let Value::Map(fields) = decoded.ok_or("cawg.metadata JSON could not be decoded")? else {
        return Err("cawg.metadata JSON-LD must be an object");
    };
    let context = fields.iter().find_map(|(key, value)| match key {
        Value::Text(key) if key == "@context" => Some(value),
        _ => None,
    });
    if !context.is_some_and(valid_context) {
        return Err("cawg.metadata must include a non-empty JSON-LD @context");
    }
    if !fields
        .iter()
        .any(|(key, _)| !matches!(key, Value::Text(key) if key == "@context"))
    {
        return Err("cawg.metadata must contain at least one metadata value");
    }
    Ok(())
}

fn valid_context(value: &Value) -> bool {
    match value {
        Value::Text(value) => !value.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
        Value::Array(values) => {
            let mut supplies_context = false;
            for value in values {
                match value {
                    Value::Null => {}
                    Value::Text(value) if !value.is_empty() => supplies_context = true,
                    Value::Map(entries) if !entries.is_empty() => supplies_context = true,
                    _ => return false,
                }
            }
            supplies_context
        }
        _ => false,
    }
}

fn json_content_box_count(mut bytes: &[u8]) -> Result<usize, &'static str> {
    let (description_type, description_size) = parse_box(bytes)?;
    if &description_type != b"jumd" {
        return Err("cawg.metadata assertion is missing its JUMBF description box");
    }
    bytes = &bytes[description_size..];

    let mut json_boxes = 0usize;
    while !bytes.is_empty() {
        let (box_type, size) = parse_box(bytes)?;
        match &box_type {
            b"json" => json_boxes += 1,
            // JUMBF Protection boxes are superboxes, not content boxes.
            b"jumb" => {}
            _ => {
                return Err("cawg.metadata contains a content box other than its JSON content box")
            }
        }
        bytes = &bytes[size..];
    }
    Ok(json_boxes)
}

fn parse_box(bytes: &[u8]) -> Result<([u8; 4], usize), &'static str> {
    let size = bytes
        .get(..4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_be_bytes)
        .ok_or("cawg.metadata contains a truncated JUMBF box")?;
    let box_type = bytes
        .get(4..8)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or("cawg.metadata contains a truncated JUMBF box")?;
    let (header_size, size) = match size {
        0 => (8usize, bytes.len()),
        1 => {
            let extended = bytes
                .get(8..16)
                .and_then(|value| <[u8; 8]>::try_from(value).ok())
                .map(u64::from_be_bytes)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("cawg.metadata contains an invalid extended JUMBF box")?;
            (16, extended)
        }
        size => (
            8,
            usize::try_from(size).map_err(|_| "cawg.metadata JUMBF box is too large")?,
        ),
    };
    if size < header_size || size > bytes.len() {
        return Err("cawg.metadata contains an invalid JUMBF box length");
    }
    Ok((box_type, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c2pa_cbor::Value;
    use crate::c2pa_core::jumbf::AssertionContentType;

    fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }

    fn box_bytes(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + payload.len());
        bytes.extend_from_slice(&u32::try_from(8 + payload.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn assertion_payload(content: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut bytes = box_bytes(b"jumd", b"description");
        for (kind, payload) in content {
            bytes.extend(box_bytes(kind, payload));
        }
        bytes
    }

    #[test]
    fn metadata_requires_exactly_one_json_content_box_and_context() {
        let valid = map(vec![
            ("@context", Value::Text("https://schema.org".into())),
            ("name", Value::Text("Example".into())),
        ]);
        let one_json = assertion_payload(&[(
            b"json",
            br#"{"@context":"https://schema.org","name":"Example"}"#,
        )]);
        assert!(validate_json_ld(
            Some(AssertionContentType::Json),
            Some(&one_json),
            Some(&valid),
        )
        .is_ok());

        let two_json = assertion_payload(&[(b"json", b"{}"), (b"json", b"{}")]);
        assert!(validate_json_ld(
            Some(AssertionContentType::Json),
            Some(&two_json),
            Some(&valid),
        )
        .is_err());
        assert!(validate_json_ld(
            Some(AssertionContentType::Cbor),
            Some(&one_json),
            Some(&valid),
        )
        .is_err());
        assert!(validate_json_ld(
            Some(AssertionContentType::Json),
            Some(&one_json),
            Some(&map(vec![])),
        )
        .is_err());
        assert!(validate_json_ld(
            Some(AssertionContentType::Json),
            Some(&one_json),
            Some(&map(vec![(
                "@context",
                Value::Text("https://schema.org".into()),
            )])),
        )
        .is_err());
    }

    #[test]
    fn metadata_context_must_supply_a_namespace() {
        let one_json = assertion_payload(&[(b"json", b"{}")]);
        for context in [
            Value::Null,
            Value::Text(String::new()),
            Value::Map(Vec::new()),
            Value::Array(vec![Value::Null]),
        ] {
            assert!(validate_json_ld(
                Some(AssertionContentType::Json),
                Some(&one_json),
                Some(&map(vec![("@context", context)])),
            )
            .is_err());
        }
    }

    #[test]
    fn dispatch_reports_effective_use_without_changing_manifest_integrity() {
        use crate::c2pa_cbor::{encode, Profile};
        use crate::c2pa_core::jumbf::{
            superbox, superbox_content, ParsedManifest, UUID_CBOR_CONTENT, UUID_JSON_CONTENT,
        };
        use crate::c2pa_core::{EngineProfile, SpecVersion};

        let metadata_json = br#"{"title":"missing context"}"#;
        let metadata_box = superbox(
            &UUID_JSON_CONTENT,
            "cawg.metadata",
            &[box_bytes(b"json", metadata_json)],
            None,
        );
        let metadata_jumbf = superbox_content(&metadata_box).unwrap();

        let training_value = map(vec![(
            "entries",
            map(vec![(
                "cawg.ai_training",
                map(vec![("use", Value::Text("constrained".into()))]),
            )]),
        )]);
        let training_cbor =
            encode(&training_value, Profile::LegacyPipelineBDefinite).expect("CBOR");
        let training_box = superbox(
            &UUID_CBOR_CONTENT,
            "cawg.training-mining",
            &[box_bytes(b"cbor", &training_cbor)],
            None,
        );
        let training_jumbf = superbox_content(&training_box).unwrap();

        let manifest = ParsedManifest {
            label: "urn:c2pa:cawg-content".into(),
            manifest_jumbf: &[],
            assertions: vec![
                ("cawg.metadata".into(), metadata_json),
                ("cawg.training-mining".into(), &training_cbor),
            ],
            assertion_jumbf: vec![
                ("cawg.metadata".into(), metadata_jumbf),
                ("cawg.training-mining".into(), training_jumbf),
            ],
            claim_cbor: None,
            signature_cose: None,
            claim_count: 1,
            claim_box_label: Some("c2pa.claim.v2".into()),
        };
        let reference = |label: &str| {
            map(vec![
                (
                    "url",
                    Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
                ),
                ("hash", Value::Bytes(vec![0; 32])),
            ])
        };
        let claim = map(vec![(
            "created_assertions",
            Value::Array(vec![
                reference("cawg.metadata"),
                reference("cawg.training-mining"),
            ]),
        )]);
        let refs = super::super::ClaimAssertionRefs::build(
            &manifest,
            &claim,
            super::super::ClaimGeneration::V2,
        );
        let mut results = super::super::ValidationResults::default();

        super::super::verify_cawg_content_assertions(&manifest, &refs, &mut results);

        let metadata_status = results
            .failure
            .iter()
            .find(|status| status.code == CAWG_METADATA_INVALID)
            .expect("metadata failure");
        assert!(metadata_status.url.ends_with("/cawg.metadata"));
        assert_eq!(
            metadata_status.details.as_ref().unwrap()["reason"],
            "cawg.metadata must include a non-empty JSON-LD @context"
        );
        let effective = results
            .informational
            .iter()
            .find(|status| {
                status.code
                    == super::super::cawg_training_mining::CAWG_TRAINING_MINING_EFFECTIVE_USE
            })
            .expect("effective-use status");
        assert_eq!(
            effective.details.as_ref().unwrap()["entries"]["cawg.ai_training"]["effectiveUse"],
            "notAllowed"
        );
        let report = super::super::validation_results_json(&results);
        assert_eq!(
            report["activeManifest"]["informational"][0]["details"]["entries"]["cawg.ai_training"]
                ["effectiveUse"],
            "notAllowed"
        );
        assert_eq!(
            super::super::compute_state(&results, EngineProfile::strict(SpecVersion::V2_4),),
            super::super::ValidationState::Valid
        );
    }
}
