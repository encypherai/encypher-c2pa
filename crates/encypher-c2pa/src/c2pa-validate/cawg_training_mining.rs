// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! CAWG Training and Data Mining Assertion 1.1 validation.
//!
//! The specification registers no validation status codes. The dispatch layer
//! therefore reports this validator through
//! `com.encypher.cawg.trainingMining.*` extension codes.

use std::collections::BTreeSet;

use crate::c2pa_cbor::Value;
use crate::c2pa_core::jumbf::AssertionContentType;
use serde_json::{json, Map, Value as Json};

use super::ValidationResults;

pub(crate) const CAWG_TRAINING_MINING_INVALID: &str = "com.encypher.cawg.trainingMining.invalid";
pub(crate) const CAWG_TRAINING_MINING_EFFECTIVE_USE: &str =
    "com.encypher.cawg.trainingMining.effectiveUse";

pub(super) fn validate_and_report(
    content_type: Option<AssertionContentType>,
    decoded: Option<&Value>,
    url: String,
    results: &mut ValidationResults,
) {
    match validate_training_mining(content_type, decoded) {
        Ok(details) => results.push_informational_with_details(
            CAWG_TRAINING_MINING_EFFECTIVE_USE,
            url,
            "effective uses after applying CAWG constrained-use semantics".into(),
            details,
        ),
        Err(reason) => results.push_failure_with_details(
            CAWG_TRAINING_MINING_INVALID,
            url,
            "CAWG training and data mining assertion does not conform to version 1.1".into(),
            json!({ "reason": reason }),
        ),
    }
}

const STANDARD_USES: [&str; 4] = [
    "cawg.data_mining",
    "cawg.ai_inference",
    "cawg.ai_training",
    "cawg.ai_generative_training",
];

/// Validate CAWG Training and Data Mining 1.1 and return the effective-use
/// projection that consumers need to apply the assertion.
pub(super) fn validate_training_mining(
    content_type: Option<AssertionContentType>,
    decoded: Option<&Value>,
) -> Result<Json, String> {
    if content_type != Some(AssertionContentType::Cbor) {
        return Err("cawg.training-mining must use the CBOR JUMBF content type".into());
    }
    let Value::Map(fields) =
        decoded.ok_or_else(|| "cawg.training-mining CBOR could not be decoded".to_string())?
    else {
        return Err("cawg.training-mining must be a CBOR map".into());
    };

    let mut entries = None;
    let mut root_keys = BTreeSet::new();
    for (key, value) in fields {
        let Value::Text(key) = key else {
            return Err("cawg.training-mining contains a non-text map key".into());
        };
        if !root_keys.insert(key.as_str()) {
            return Err(format!(
                "cawg.training-mining contains duplicate field '{key}'"
            ));
        }
        match key.as_str() {
            "entries" => entries = Some(value),
            "metadata" => {
                if !matches!(value, Value::Map(_)) {
                    return Err("cawg.training-mining metadata must be a map".into());
                }
            }
            _ => {
                return Err(format!(
                    "cawg.training-mining contains unknown field '{key}'"
                ))
            }
        }
    }

    let Value::Map(entries) =
        entries.ok_or_else(|| "cawg.training-mining is missing entries".to_string())?
    else {
        return Err("cawg.training-mining entries must be a map".into());
    };
    if entries.is_empty() {
        return Err("cawg.training-mining entries must not be empty".into());
    }

    let mut effective_entries = Map::new();
    let mut entry_keys = BTreeSet::new();
    for (key, value) in entries {
        let Value::Text(key) = key else {
            return Err("cawg.training-mining contains a non-text entry label".into());
        };
        if !entry_keys.insert(key.as_str()) {
            return Err(format!(
                "cawg.training-mining contains duplicate entry '{key}'"
            ));
        }
        if STANDARD_USES.contains(&key.as_str()) {
            effective_entries.insert(key.clone(), effective_standard_use(key, value)?);
            continue;
        }
        if key.starts_with("cawg.") {
            return Err(format!(
                "cawg.training-mining entry '{key}' uses the reserved cawg namespace"
            ));
        }
        if !valid_custom_label(key) {
            return Err(format!(
                "cawg.training-mining custom entry '{key}' is not a valid namespaced label"
            ));
        }
        // The CDDL deliberately declares custom entry values as `any`. Their
        // semantics belong to the namespace owner, so this validator neither
        // constrains them nor invents an effective-use interpretation.
    }

    Ok(json!({ "entries": effective_entries }))
}

fn effective_standard_use(label: &str, value: &Value) -> Result<Json, String> {
    let Value::Map(fields) = value else {
        return Err(format!(
            "cawg.training-mining entry '{label}' must be a map"
        ));
    };
    let mut use_value = None;
    let mut constraint = None;
    let mut keys = BTreeSet::new();
    for (key, value) in fields {
        let Value::Text(key) = key else {
            return Err(format!(
                "cawg.training-mining entry '{label}' contains a non-text field"
            ));
        };
        if !keys.insert(key.as_str()) {
            return Err(format!(
                "cawg.training-mining entry '{label}' contains duplicate field '{key}'"
            ));
        }
        match key.as_str() {
            "use" => {
                use_value = value.as_text();
                if use_value.is_none() {
                    return Err(format!(
                        "cawg.training-mining entry '{label}' use must be text"
                    ));
                }
            }
            "constraint_info" => {
                constraint = value.as_text();
                if constraint.is_none_or(str::is_empty) {
                    return Err(format!(
                        "cawg.training-mining entry '{label}' constraint_info must be non-empty text"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "cawg.training-mining entry '{label}' contains unknown field '{key}'"
                ))
            }
        }
    }
    let declared = use_value
        .ok_or_else(|| format!("cawg.training-mining entry '{label}' is missing its use field"))?;
    if !matches!(declared, "allowed" | "notAllowed" | "constrained") {
        return Err(format!(
            "cawg.training-mining entry '{label}' has unknown use '{declared}'"
        ));
    }
    let effective = if declared == "constrained" && constraint.is_none() {
        "notAllowed"
    } else {
        declared
    };
    let mut details = Map::new();
    details.insert("declaredUse".into(), Json::String(declared.into()));
    details.insert("effectiveUse".into(), Json::String(effective.into()));
    if let Some(constraint) = constraint {
        details.insert("constraintInfo".into(), Json::String(constraint.into()));
    }
    Ok(Json::Object(details))
}

fn valid_custom_label(label: &str) -> bool {
    if label.contains("__") {
        return false;
    }
    let mut components = label.split('.');
    let Some(namespace) = components.next() else {
        return false;
    };
    let Some(first_label_component) = components.next() else {
        return false;
    };
    valid_label_component(namespace)
        && valid_label_component(first_label_component)
        && components.all(valid_label_component)
}

fn valid_label_component(component: &str) -> bool {
    let mut bytes = component.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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

    fn assertion(entries: Vec<(&str, Value)>) -> Value {
        map(vec![("entries", map(entries))])
    }

    fn entry(use_value: &str, constraint: Option<&str>) -> Value {
        let mut fields = vec![("use", Value::Text(use_value.into()))];
        if let Some(constraint) = constraint {
            fields.push(("constraint_info", Value::Text(constraint.into())));
        }
        map(fields)
    }

    #[test]
    fn constrained_without_information_is_effectively_not_allowed() {
        let value = assertion(vec![
            ("cawg.ai_training", entry("constrained", None)),
            ("cawg.data_mining", entry("constrained", Some("CC BY 4.0"))),
            ("cawg.ai_inference", entry("allowed", None)),
        ]);
        let details = validate_training_mining(Some(AssertionContentType::Cbor), Some(&value))
            .expect("valid assertion");

        assert_eq!(
            details["entries"]["cawg.ai_training"]["declaredUse"],
            "constrained"
        );
        assert_eq!(
            details["entries"]["cawg.ai_training"]["effectiveUse"],
            "notAllowed"
        );
        assert_eq!(
            details["entries"]["cawg.data_mining"]["effectiveUse"],
            "constrained"
        );
        assert_eq!(
            details["entries"]["cawg.data_mining"]["constraintInfo"],
            "CC BY 4.0"
        );
        assert_eq!(
            details["entries"]["cawg.ai_inference"]["effectiveUse"],
            "allowed"
        );
    }

    #[test]
    fn training_mining_enforces_required_shape_and_reserved_labels() {
        assert!(validate_training_mining(
            Some(AssertionContentType::Json),
            Some(&assertion(vec![(
                "cawg.ai_training",
                entry("allowed", None)
            )])),
        )
        .is_err());
        assert!(
            validate_training_mining(Some(AssertionContentType::Cbor), Some(&map(vec![])),)
                .is_err()
        );
        assert!(validate_training_mining(
            Some(AssertionContentType::Cbor),
            Some(&assertion(vec![])),
        )
        .is_err());
        assert!(validate_training_mining(
            Some(AssertionContentType::Cbor),
            Some(&assertion(vec![(
                "cawg.future_use",
                entry("allowed", None)
            )])),
        )
        .is_err());
        assert!(validate_training_mining(
            Some(AssertionContentType::Cbor),
            Some(&assertion(vec![("not a label", entry("allowed", None))])),
        )
        .is_err());
        assert!(validate_training_mining(
            Some(AssertionContentType::Cbor),
            Some(&assertion(vec![(
                "cawg.ai_training",
                entry("sometimes", None)
            )])),
        )
        .is_err());
    }

    #[test]
    fn valid_custom_entries_remain_open_for_extension_data() {
        let value = assertion(vec![(
            "com.example.archive",
            map(vec![("policy", Value::Text("internal".into()))]),
        )]);
        let details = validate_training_mining(Some(AssertionContentType::Cbor), Some(&value))
            .expect("custom entries use the CDDL extension point");
        assert_eq!(details["entries"], serde_json::json!({}));
    }
}
