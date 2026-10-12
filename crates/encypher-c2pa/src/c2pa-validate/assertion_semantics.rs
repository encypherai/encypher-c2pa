// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use super::Value;
use serde_json::Value as Json;

/// Project a parsed JSON assertion payload into the CBOR value model the
/// semantic phase reads.
///
/// C2PA 2.4 Validation, Specific Assertion Validation, selects the checks for an
/// assertion by its label; the JUMBF content type it arrived in does not excuse
/// them. Standard assertions are specified as CBOR (C2PA 2.4 Standard C2PA
/// Assertions: "Unless otherwise mentioned, all assertions documented in this
/// standard set of assertions shall be serialized as CBOR"), so a JSON payload
/// carrying such a label is already irregular; projecting it keeps the one
/// dispatch path instead of silently skipping the required validation.
///
/// Returns `None` once `remaining_nodes` is exhausted, mirroring the CBOR
/// decoder's node budget. Nesting depth needs no separate guard: `serde_json`
/// enforces its own recursion limit while parsing the payload into `Json`.
pub(super) fn value_from_json(json: &Json, remaining_nodes: &mut usize) -> Option<Value> {
    if *remaining_nodes == 0 {
        return None;
    }
    *remaining_nodes -= 1;
    Some(match json {
        Json::Null => Value::Null,
        Json::Bool(flag) => Value::Bool(*flag),
        Json::Number(number) => match (number.as_i64(), number.as_u64()) {
            (Some(signed), _) => Value::Integer(signed.into()),
            (None, Some(unsigned)) => Value::Integer(unsigned.into()),
            (None, None) => Value::Float(number.as_f64().unwrap_or(f64::NAN)),
        },
        Json::String(text) => Value::Text(text.clone()),
        Json::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| value_from_json(item, remaining_nodes))
                .collect::<Option<Vec<Value>>>()?,
        ),
        Json::Object(fields) => Value::Map(
            fields
                .iter()
                .map(|(key, value)| {
                    if *remaining_nodes == 0 {
                        return None;
                    }
                    *remaining_nodes -= 1;
                    Some((
                        Value::Text(key.clone()),
                        value_from_json(value, remaining_nodes)?,
                    ))
                })
                .collect::<Option<Vec<(Value, Value)>>>()?,
        ),
    })
}

const IPTC_DIGITAL_SOURCE_TYPE_PREFIX: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/";

const C2PA_DIGITAL_SOURCE_TYPES: &[&str] = &[
    "http://c2pa.org/digitalsourcetype/empty",
    "http://c2pa.org/digitalsourcetype/trainedAlgorithmicData",
];

pub(super) fn ingredient_shape_error(ingredient: &Value) -> Option<String> {
    match ingredient.get("relationship").and_then(Value::as_text) {
        Some("parentOf" | "inputTo" | "componentOf") => {}
        None => return Some("ingredient has no relationship field".into()),
        Some(other) => return Some(format!("ingredient has invalid relationship '{other}'")),
    }
    if (ingredient.get("activeManifest").is_some() || ingredient.get("c2pa_manifest").is_some())
        && ingredient.get("digitalSourceType").is_some()
    {
        return Some("ingredient carries both activeManifest and digitalSourceType".into());
    }
    None
}

fn valid_digital_source_type(value: &str) -> bool {
    let value = value.trim();
    value
        .strip_prefix(IPTC_DIGITAL_SOURCE_TYPE_PREFIX)
        .is_some_and(|term| !term.is_empty() && !term.contains(['/', '#', '?']))
        || C2PA_DIGITAL_SOURCE_TYPES.contains(&value)
}

pub(super) fn action_shape_errors(
    action: &Value,
    software_agent_count: usize,
    v2: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(source_type) = action.get("digitalSourceType") {
        if !source_type.as_text().is_some_and(valid_digital_source_type) {
            errors.push("digitalSourceType is not a registered IPTC or C2PA value".into());
        }
    }

    let software_agent = action.get("softwareAgent");
    let software_agent_index = action.get("softwareAgentIndex");
    if software_agent.is_some() && software_agent_index.is_some() {
        errors.push("softwareAgent and softwareAgentIndex are mutually exclusive".into());
    }
    if let Some(index) = software_agent_index {
        let valid = matches!(index, Value::Integer(value)
            if *value >= 0
                && usize::try_from(*value)
                    .is_ok_and(|index| index < software_agent_count));
        if !v2 || !valid {
            errors.push("softwareAgentIndex does not name a softwareAgents entry".into());
        }
    }

    if let Some(changes) = action.get("changes") {
        let valid = if v2 {
            matches!(changes, Value::Array(items) if items.iter().all(|item| matches!(item, Value::Map(_))))
        } else {
            matches!(changes, Value::Text(_))
        };
        if !valid {
            errors.push("changes has the wrong shape for the actions assertion version".into());
        }
    }
    errors
}

pub(super) fn alternative_content_shape_error(
    parameters: &Value,
    multi_asset_part_count: Option<usize>,
) -> Option<String> {
    let part_index = parameters.get("multiAssetPartIndex");
    let embedded = parameters.get("embeddedOriginalPreservationImage");
    if part_index.is_some() == embedded.is_some() {
        return Some(
            "alternative content must contain exactly one representation reference".into(),
        );
    }
    if let Some(index) = part_index {
        let Some(part_count) = multi_asset_part_count else {
            return Some("multiAssetPartIndex requires a c2pa.hash.multi-asset assertion".into());
        };
        let valid = matches!(index, Value::Integer(value)
            if *value >= 0 && usize::try_from(*value).is_ok_and(|index| index < part_count));
        if !valid {
            return Some("multiAssetPartIndex is outside the multi-asset parts array".into());
        }
    }
    if let Some(reference) = embedded {
        if reference.get("url").and_then(Value::as_text).is_none()
            || reference.get("hash").and_then(Value::as_bytes).is_none()
        {
            return Some("embeddedOriginalPreservationImage is not a complete hashed URI".into());
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;

    fn map(items: Vec<(&str, Value)>) -> Value {
        Value::Map(
            items
                .into_iter()
                .map(|(key, value)| (Value::Text(key.into()), value))
                .collect(),
        )
    }

    /// The complete IPTC vocabulary published on 2024-10-23, including its
    /// retired terms. The production predicate intentionally accepts new
    /// single-segment terms in the authoritative namespace as IPTC registers
    /// them; this table prevents a current or historical registered term from
    /// being lost.
    const REGISTERED_IPTC_DIGITAL_SOURCE_TYPES: &[&str] = &[
        "digitalCapture",
        "computationalCapture",
        "negativeFilm",
        "positiveFilm",
        "print",
        "minorHumanEdits",
        "humanEdits",
        "algorithmicallyEnhanced",
        "softwareImage",
        "digitalArt",
        "digitalCreation",
        "dataDrivenMedia",
        "trainedAlgorithmicMedia",
        "algorithmicMedia",
        "screenCapture",
        "virtualRecording",
        "composite",
        "compositeCapture",
        "compositeSynthetic",
        "compositeWithTrainedAlgorithmicMedia",
    ];

    #[test]
    fn ingredient_relationship_and_source_are_validated() {
        let missing = map(vec![]);
        assert!(ingredient_shape_error(&missing).is_some());

        let unknown = map(vec![("relationship", Value::Text("derivedFrom".into()))]);
        assert!(ingredient_shape_error(&unknown).is_some());

        let contradictory = map(vec![
            ("relationship", Value::Text("parentOf".into())),
            ("c2pa_manifest", map(vec![])),
            ("digitalSourceType", Value::Text("digitalCapture".into())),
        ]);
        assert!(ingredient_shape_error(&contradictory).is_some());

        for relationship in ["parentOf", "inputTo", "componentOf"] {
            let valid = map(vec![("relationship", Value::Text(relationship.into()))]);
            assert_eq!(ingredient_shape_error(&valid), None);
        }
    }

    #[test]
    fn every_registered_digital_source_type_is_valid_for_actions_and_ingredients() {
        assert_eq!(REGISTERED_IPTC_DIGITAL_SOURCE_TYPES.len(), 20);
        assert_eq!(C2PA_DIGITAL_SOURCE_TYPES.len(), 2);

        for source_type in REGISTERED_IPTC_DIGITAL_SOURCE_TYPES
            .iter()
            .map(|term| format!("{IPTC_DIGITAL_SOURCE_TYPE_PREFIX}{term}"))
            .chain(
                C2PA_DIGITAL_SOURCE_TYPES
                    .iter()
                    .map(|uri| (*uri).to_string()),
            )
        {
            let action = map(vec![(
                "digitalSourceType",
                Value::Text(format!(" {source_type} ")),
            )]);
            assert!(
                action_shape_errors(&action, 0, true).is_empty(),
                "{source_type}"
            );

            let ingredient = map(vec![
                ("relationship", Value::Text("componentOf".into())),
                ("digitalSourceType", Value::Text(source_type.clone())),
            ]);
            assert_eq!(ingredient_shape_error(&ingredient), None, "{source_type}");
        }
    }

    #[test]
    fn iptc_namespace_policy_remains_forward_compatible() {
        let future_term = map(vec![(
            "digitalSourceType",
            Value::Text(format!(
                "{IPTC_DIGITAL_SOURCE_TYPE_PREFIX}futureRegisteredTerm"
            )),
        )]);
        assert!(action_shape_errors(&future_term, 0, true).is_empty());

        for invalid_suffix in ["", "nested/term", "term#fragment", "term?query"] {
            let invalid = map(vec![(
                "digitalSourceType",
                Value::Text(format!("{IPTC_DIGITAL_SOURCE_TYPE_PREFIX}{invalid_suffix}")),
            )]);
            assert_eq!(action_shape_errors(&invalid, 0, true).len(), 1);
        }
    }

    #[test]
    fn unregistered_c2pa_digital_source_types_and_aliases_are_rejected() {
        for source_type in [
            "http://c2pa.org/digitalsourcetype/trainedAlgorithmicMedia",
            "http://c2pa.org/digitalsourcetype/unknown",
            "https://c2pa.org/digitalsourcetype/empty",
            "c2pa.trainedAlgorithmicData",
        ] {
            let action = map(vec![("digitalSourceType", Value::Text(source_type.into()))]);
            assert_eq!(action_shape_errors(&action, 0, true).len(), 1);
        }
    }

    #[test]
    fn action_fields_reject_invalid_v2_semantics() {
        let action = map(vec![
            ("action", Value::Text("c2pa.created".into())),
            ("digitalSourceType", Value::Text("not-a-source-type".into())),
            ("softwareAgent", map(vec![])),
            ("softwareAgentIndex", Value::Integer(0.into())),
            ("changes", Value::Text("all".into())),
        ]);
        let errors = action_shape_errors(&action, 1, true);
        assert_eq!(errors.len(), 3);
    }

    #[test]
    fn action_software_agent_index_is_bounded() {
        let action = map(vec![
            ("action", Value::Text("c2pa.edited".into())),
            ("softwareAgentIndex", Value::Integer(2.into())),
        ]);
        assert!(action_shape_errors(&action, 2, true)
            .iter()
            .any(|error| error.contains("softwareAgentIndex")));
    }

    #[test]
    fn alternative_content_requires_exactly_one_representation() {
        let neither = map(vec![]);
        assert!(alternative_content_shape_error(&neither, Some(1)).is_some());

        let both = map(vec![
            ("multiAssetPartIndex", Value::Integer(0.into())),
            ("embeddedOriginalPreservationImage", map(vec![])),
        ]);
        assert!(alternative_content_shape_error(&both, Some(1)).is_some());

        let out_of_bounds = map(vec![("multiAssetPartIndex", Value::Integer(1.into()))]);
        assert!(alternative_content_shape_error(&out_of_bounds, Some(1)).is_some());

        let valid = map(vec![("multiAssetPartIndex", Value::Integer(0.into()))]);
        assert_eq!(alternative_content_shape_error(&valid, Some(1)), None);
    }
}
