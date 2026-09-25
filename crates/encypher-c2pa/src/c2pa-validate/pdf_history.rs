// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! PDF incremental-update validation.

use super::{
    verify_with_fragments_mode, CawgTrustInputs, ValidateError, VerifyInput, VerifyOutput,
    MANIFEST_INACCESSIBLE,
};
use crate::c2pa_formats::PdfManifestStoreSection;
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
        return Ok(());
    }
    if sections.is_empty() {
        return Ok(());
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
        report.insert("pdf_incremental_history".into(), Json::Array(history));
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
