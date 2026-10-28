// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! PDF incremental-update validation.

use super::{
    spec25, verify_detached_with_cawg_options, verify_with_fragments_mode, CawgTrustInputs,
    StatusCode, ValidateError, ValidationState, VerifyInput, VerifyOutput, MANIFEST_INACCESSIBLE,
};
use crate::c2pa_formats::{
    pdf_object_manifest_stores, AssetFormat, PdfManifestStoreSection, PdfObjectManifestStore,
};
use serde_json::{json, Value as Json};

/// Attach validation of every retained PDF manifest store, oldest first.
///
/// Each store is verified against the exact historical rendition ending at its
/// own update section. A malformed later store is represented as a failure for
/// that section and cannot discard an earlier valid result.
pub(super) fn attach(
    out: &mut VerifyOutput,
    input: &VerifyInput<'_>,
    cawg_inputs: CawgTrustInputs<'_>,
    sections: &[PdfManifestStoreSection],
    inventory_error: Option<&str>,
) -> Result<(), ValidateError> {
    if let Some(error) = inventory_error {
        if let Some(report) = out.report_json.as_object_mut() {
            report.insert(
                "pdf_incremental_history".into(),
                Json::Array(vec![json!({
                    "validation_state": "Invalid",
                    "validation_status": [{
                        "code": MANIFEST_INACCESSIBLE,
                        "url": "self#jumbf",
                        "explanation": error,
                    }],
                })]),
            );
        }
    }
    let mut history = Vec::with_capacity(sections.len());
    for section in sections {
        if let Some(defect) = section.defect {
            history.push(json!({
                "section_index": section.section_index,
                "section_end": section.section_end,
                "validation_state": "Invalid",
                "validation_status": [{
                    "code": MANIFEST_INACCESSIBLE,
                    "url": "self#jumbf",
                    "explanation": defect,
                }],
            }));
            continue;
        }
        if section.section_end == input.data.len() {
            history.push(json!({
                "section_index": section.section_index,
                "section_end": section.section_end,
                "validation_state": out.validation_state.as_str(),
                "report": out.report_json.clone(),
            }));
            continue;
        }
        let Some(rendition) = input.data.get(..section.section_end) else {
            history.push(json!({
                "section_index": section.section_index,
                "section_end": section.section_end,
                "validation_state": "Invalid",
                "validation_status": [{
                    "code": MANIFEST_INACCESSIBLE,
                    "url": "self#jumbf",
                    "explanation": "PDF update boundary exceeds asset",
                }],
            }));
            continue;
        };
        let historical_input = VerifyInput {
            data: rendition,
            ..*input
        };
        let historical = verify_with_fragments_mode(&historical_input, &[], cawg_inputs, false)?;
        history.push(json!({
            "section_index": section.section_index,
            "section_end": section.section_end,
            "validation_state": historical.validation_state.as_str(),
            "report": historical.report_json,
        }));
    }
    if let Some(report) = out.report_json.as_object_mut() {
        if !history.is_empty() {
            report.insert("pdf_incremental_history".into(), Json::Array(history));
        }
    }
    if spec25::applies(input.profile)
        && AssetFormat::from_mime(input.mime) == Some(AssetFormat::Pdf)
    {
        attach_object_manifests(out, input, cawg_inputs)?;
    }
    Ok(())
}

fn object_failure(owner: &PdfObjectManifestStore, explanation: &str) -> StatusCode {
    StatusCode {
        code: MANIFEST_INACCESSIBLE.into(),
        url: format!(
            "self#pdf-object={}:{}",
            owner.owner_number, owner.owner_generation
        ),
        explanation: explanation.into(),
        details: None,
    }
}

/// Verify each object-level association as an independent detached asset. The
/// owning object's exact coverage bytes replace the PDF document bytes; no
/// catalog result is reused.
fn attach_object_manifests(
    out: &mut VerifyOutput,
    input: &VerifyInput<'_>,
    cawg_inputs: CawgTrustInputs<'_>,
) -> Result<(), ValidateError> {
    let inventory = match pdf_object_manifest_stores(input.data) {
        Ok(inventory) => inventory,
        Err(error) => {
            let status = StatusCode {
                code: MANIFEST_INACCESSIBLE.into(),
                url: "self#pdf-objects".into(),
                explanation: error.to_string(),
                details: None,
            };
            out.results.failure.push(status.clone());
            out.validation_state = ValidationState::Invalid;
            if let Some(report) = out.report_json.as_object_mut() {
                report.insert(
                    "pdf_object_manifests".into(),
                    Json::Array(vec![json!({
                        "validation_state": "Invalid",
                        "validation_status": [status],
                    })]),
                );
            }
            return Ok(());
        }
    };
    if inventory.is_empty() {
        return Ok(());
    }
    let mut reports = Vec::with_capacity(inventory.len());
    for object in &inventory {
        let identity = json!({
            "object_number": object.owner_number,
            "generation": object.owner_generation,
        });
        if let Some(defect) = object.defect {
            let status = object_failure(object, defect);
            out.results.failure.push(status.clone());
            out.validation_state = ValidationState::Invalid;
            reports.push(json!({
                "owner": identity,
                "validation_state": "Invalid",
                "validation_status": [status],
            }));
            continue;
        }
        let (Some(store), Some(coverage)) = (object.store(input.data), object.coverage(input.data))
        else {
            let status =
                object_failure(object, "PDF object association has no verifiable coverage");
            out.results.failure.push(status.clone());
            out.validation_state = ValidationState::Invalid;
            reports.push(json!({
                "owner": identity,
                "validation_state": "Invalid",
                "validation_status": [status],
            }));
            continue;
        };
        let verified = verify_detached_with_cawg_options(
            store,
            coverage,
            "application/octet-stream",
            input,
            cawg_inputs,
        )?;
        if matches!(
            verified.validation_state,
            ValidationState::Invalid | ValidationState::None
        ) {
            out.validation_state = ValidationState::Invalid;
        }
        out.results.success.extend(verified.results.success.clone());
        out.results
            .informational
            .extend(verified.results.informational.clone());
        out.results.failure.extend(verified.results.failure.clone());
        out.network_needs
            .extend(verified.network_needs.iter().cloned());
        reports.push(json!({
            "owner": identity,
            "validation_state": verified.validation_state.as_str(),
            "report": verified.report_json,
        }));
    }
    if let Some(report) = out.report_json.as_object_mut() {
        report.insert("pdf_object_manifests".into(), Json::Array(reports));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{verify, EngineProfile, VerifyInput, MANIFEST_INACCESSIBLE};
    use crate::c2pa_core::jumbf::{assertion_box, build_manifest, build_manifest_store};
    use crate::c2pa_formats::{embed_manifest, AssetFormat};

    fn minimal_pdf() -> Vec<u8> {
        let mut pdf = Vec::new();
        let mut offsets = [0usize; 4];
        pdf.extend_from_slice(b"%PDF-1.7\n");
        offsets[1] = pdf.len();
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        offsets[2] = pdf.len();
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        offsets[3] = pdf.len();
        pdf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
        );
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
        for offset in &offsets[1..] {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        pdf
    }

    fn store() -> Vec<u8> {
        let assertion = assertion_box("c2pa.actions.v2", &[0xa0], None);
        let manifest = build_manifest(
            "urn:c2pa:test:history",
            &[assertion],
            &[0xa0],
            &[0xd2, 0x84],
        );
        build_manifest_store(&[manifest])
    }

    #[test]
    fn malformed_later_store_is_reported_without_discarding_earlier_history() {
        let first =
            embed_manifest(AssetFormat::Pdf, &minimal_pdf(), &store()).expect("first update");
        let second = embed_manifest(AssetFormat::Pdf, &first, b"not a manifest store")
            .expect("second update");
        let input = VerifyInput {
            data: &second,
            mime: "application/pdf",
            claim_signer_trust: None,
            tsa_trust: None,
            allowed_certs: None,
            validation_time: None,
            profile: EngineProfile::GENEROUS,
            evidence: Default::default(),
            cawg_strict_encoding: false,
        };

        let output = verify(&input).expect("structural defect becomes a report");
        assert!(output.results.has_failure(MANIFEST_INACCESSIBLE));
        let history = output
            .report_json
            .get("pdf_incremental_history")
            .and_then(serde_json::Value::as_array)
            .expect("incremental history");
        assert_eq!(history.len(), 2);
        assert!(history[0].get("report").is_some());
        assert_eq!(
            history[1].pointer("/validation_status/0/code"),
            Some(&serde_json::Value::String(MANIFEST_INACCESSIBLE.into()))
        );
    }
}
