// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

// Included in ingredient_graph's unit tests to reuse the real COSE signer and
// JUMBF builders without exposing signing capabilities in the public crate.
mod redaction_lineage {
    use super::*;
    use crate::c2pa_core::{OperatingMode, SpecVersion};
    use crate::c2pa_core::jumbf::redacted_assertion_box;

    const GRAND: &str = "urn:c2pa:00000000-0000-4000-8000-000000000003";
    const OTHER: &str = "urn:c2pa:00000000-0000-4000-8000-000000000004";
    const SECRET: &str = "org.example.secret";

    fn policies() -> [EngineProfile; 2] {
        [EngineProfile::GENEROUS, EngineProfile::new(SpecVersion::V2_5, OperatingMode::Regular)]
    }

    fn set(value: &mut Value, key: &str, replacement: Option<Value>) {
        let Value::Map(fields) = value else { panic!("map required") };
        fields.retain(|(name, _)| name.as_text() != Some(key));
        if let Some(replacement) = replacement {
            fields.push((Value::Text(key.into()), replacement));
        }
    }

    fn uri(manifest: &str, label: &str) -> String {
        format!("self#jumbf=/c2pa/{manifest}/c2pa.assertions/{label}")
    }

    fn absolute(assertion: &Assertion, manifest: &str) -> Value {
        let mut reference = assertion.reference();
        set(&mut reference, "url", Some(Value::Text(uri(manifest, &assertion.label))));
        reference
    }

    fn secret() -> Assertion {
        Assertion::new(SECRET, &vmap(vec![("secret", Value::Text("private text".into()))]))
    }

    // Sign the original declaration set while storing only the surviving boxes.
    fn node(signer: &Signer, label: &str, extras: Vec<Assertion>, removed: &[Assertion], redactions: &[String]) -> (Vec<u8>, Vec<u8>) {
        let binding = Assertion::new("c2pa.hash.data", &data_hash());
        let mut actions = created_actions();
        if let Some(Value::Array(items)) = match &mut actions {
            Value::Map(fields) => fields.iter_mut().find(|(key, _)| key.as_text() == Some("actions")).map(|(_, value)| value),
            _ => None,
        } {
            for url in redactions {
                items.push(vmap(vec![
                    ("action", Value::Text("c2pa.redacted".into())),
                    ("reason", Value::Text("c2pa.PII.present".into())),
                    ("parameters", vmap(vec![("redacted", Value::Text(url.clone()))])),
                ]));
            }
        }
        let actions = Assertion::new("c2pa.actions.v2", &actions);
        let mut assertions = vec![binding, actions];
        assertions.extend(extras);
        let mut references: Vec<Value> = assertions.iter().map(Assertion::reference).collect();
        references.extend(removed.iter().map(Assertion::reference));
        let mut claim = claim(references);
        if !redactions.is_empty() {
            set(&mut claim, "redacted_assertions", Some(Value::Array(redactions.iter().cloned().map(Value::Text).collect())));
        }
        let bytes = enc(&claim);
        let cose = signer.sign(&bytes);
        let boxes: Vec<Vec<u8>> = assertions.into_iter().map(|assertion| assertion.jumbf).collect();
        (build_manifest(label, &boxes, &bytes, &cose), cose)
    }

    fn link(label: &str, target: &str, manifest: &[u8], cose: &[u8]) -> Assertion {
        Assertion::new(label, &ingredient(target, manifest, cose, "componentOf", None))
    }

    fn failures(out: &VerifyOutput) -> Vec<String> {
        let mut codes: Vec<String> = out.results.failure.iter().map(|status| status.code.clone()).collect();
        for delta in deltas(out) {
            codes.extend(delta_codes(delta, "failure").into_iter().map(str::to_string));
        }
        codes
    }

    fn assert_no_redaction_binding_failures(out: &VerifyOutput) {
        let codes = failures(out);
        for code in ["assertion.action.redactionMismatch", "assertion.missing", "assertion.hashedURI.mismatch", "hashedURI.missing", "hashedURI.mismatch", "ingredient.manifest.mismatch", "ingredient.claimSignature.missing", "ingredient.claimSignature.mismatch"] {
            assert!(!codes.iter().any(|actual| actual == code), "{code}: {codes:?}");
        }
    }

    #[test]
    fn spec_shaped_redacted_action_resolves_removed_and_zero_filled_ingredient_assertions() {
        let signer = Signer::conformant();
        for zeroed in [false, true] {
            let removed = secret();
            let mut extras = Vec::new();
            if zeroed {
                extras.push(Assertion { label: SECRET.into(), jumbf: redacted_assertion_box(SECRET, 64) });
            }
            let (child, signature) = node(&signer, INGREDIENT, extras, if zeroed { &[] } else { std::slice::from_ref(&removed) }, &[]);
            // A zero-filled box still needs the original assertion's hash in the claim.
            let child = if zeroed {
                let store = build_manifest_store(std::slice::from_ref(&child));
                let parsed = parse_manifest_store(&store).expect("parse temporary store");
                let mut original_claim = crate::c2pa_cbor::decode(parsed.manifests[0].claim_cbor.unwrap()).unwrap();
                let Value::Array(mut refs) = original_claim.get("created_assertions").unwrap().clone() else { unreachable!() };
                *refs.last_mut().unwrap() = removed.reference();
                set(&mut original_claim, "created_assertions", Some(Value::Array(refs)));
                let bytes = enc(&original_claim);
                let cose = signer.sign(&bytes);
                let binding = Assertion::new("c2pa.hash.data", &data_hash());
                let actions = Assertion::new("c2pa.actions.v2", &created_actions());
                let child = build_manifest(INGREDIENT, &[binding.jumbf, actions.jumbf, redacted_assertion_box(SECRET, 64)], &bytes, &cose);
                (child, cose)
            } else { (child, signature) };
            let (active, _) = node(&signer, ACTIVE, vec![link("c2pa.ingredient.v3", INGREDIENT, &child.0, &child.1)], &[], &[uri(INGREDIENT, SECRET)]);
            for profile in policies() {
                let out = verify_store_under(&[child.0.clone(), active.clone()], profile);
                assert_no_redaction_binding_failures(&out);
                assert!(out.results.success.iter().any(|status| status.code == "ingredient.claimSignature.validated"));
                assert!(!out.results.success.iter().any(|status| status.code == "ingredient.manifest.validated"));
            }
        }
    }

    #[test]
    fn two_level_lineage_and_broken_signature_declarant_are_indexed() {
        let signer = Signer::conformant();
        let (grand, grand_sig) = node(&signer, GRAND, vec![], &[secret()], &[]);
        for broken in [false, true] {
            let (middle, signature) = node(&signer, INGREDIENT, vec![link("c2pa.ingredient.v3", GRAND, &grand, &grand_sig)], &[], &[uri(GRAND, SECRET)]);
            let (middle, signature) = if broken {
                let store = build_manifest_store(std::slice::from_ref(&middle));
                let parsed = parse_manifest_store(&store).unwrap();
                let manifest = &parsed.manifests[0];
                let mut bad = signature.clone();
                *bad.last_mut().unwrap() ^= 1;
                let boxes = vec![Assertion::new("c2pa.hash.data", &data_hash()).jumbf,
                    Assertion::new("c2pa.actions.v2", &crate::c2pa_cbor::decode(manifest.assertions.iter().find(|(label, _)| label == "c2pa.actions.v2").unwrap().1).unwrap()).jumbf,
                    link("c2pa.ingredient.v3", GRAND, &grand, &grand_sig).jumbf];
                (build_manifest(INGREDIENT, &boxes, manifest.claim_cbor.unwrap(), &bad), bad)
            } else { (middle, signature) };
            let (active, _) = node(&signer, ACTIVE, vec![link("c2pa.ingredient.v3", INGREDIENT, &middle, &signature)], &[], &[]);
            for profile in policies() {
                let out = verify_store_under(&[grand.clone(), middle.clone(), active.clone()], profile);
                assert_no_redaction_binding_failures(&out);
                assert_eq!(failures(&out).iter().any(|code| code == "claimSignature.mismatch"), broken);
            }
        }
    }

    #[test]
    fn passenger_declarations_and_missing_without_declarations_do_not_exempt_targets() {
        let signer = Signer::conformant();
        let (child, signature) = node(&signer, INGREDIENT, vec![], &[secret()], &[]);
        let (passenger, _) = node(&signer, OTHER, vec![], &[], &[uri(INGREDIENT, SECRET)]);
        let (active, _) = node(&signer, ACTIVE, vec![link("c2pa.ingredient.v3", INGREDIENT, &child, &signature)], &[], &[]);
        for profile in policies() {
            for boxes in [vec![child.clone(), active.clone()], vec![child.clone(), passenger.clone(), active.clone()]] {
                let out = verify_store_under(&boxes, profile);
                assert!(failures(&out).iter().any(|code| code == "assertion.missing"));
                assert!(out.results.success.iter().any(|status| status.code == "ingredient.manifest.validated"));
            }
        }
    }

    #[test]
    fn self_redaction_is_rejected_and_does_not_exempt_the_claim_binding() {
        let signer = Signer::conformant();
        let (active, _) = node(&signer, ACTIVE, vec![], &[secret()], &[uri(ACTIVE, SECRET)]);
        for profile in policies() {
            let out = verify_store_under(std::slice::from_ref(&active), profile);
            assert!(out.results.failure.iter().any(|status| status.code == "assertion.selfRedacted"));
        }
    }

    #[test]
    fn forbidden_targets_fail_in_the_target_delta_not_the_declarant() {
        let signer = Signer::conformant();
        for (label, code) in [("c2pa.actions.v2", "assertion.action.redacted"), ("c2pa.hash.data", "assertion.hardBinding.redacted")] {
            for remove_box in [false, true] {
                let (original, signature) = node(&signer, INGREDIENT, vec![], &[], &[]);
                let child = if remove_box {
                    let store = build_manifest_store(std::slice::from_ref(&original));
                    let parsed = parse_manifest_store(&store).unwrap();
                    let assertions = [
                        Assertion::new("c2pa.hash.data", &data_hash()),
                        Assertion::new("c2pa.actions.v2", &created_actions()),
                    ];
                    let boxes: Vec<Vec<u8>> = assertions.into_iter()
                        .filter(|assertion| assertion.label != label).map(|assertion| assertion.jumbf).collect();
                    build_manifest(INGREDIENT, &boxes, parsed.manifests[0].claim_cbor.unwrap(), &signature)
                } else { original };
                let (active, _) = node(&signer, ACTIVE, vec![link("c2pa.ingredient.v3", INGREDIENT, &child, &signature)], &[], &[uri(INGREDIENT, label)]);
                for profile in policies() {
                    let out = verify_store_under(&[child.clone(), active.clone()], profile);
                    assert!(!out.results.failure.iter().any(|status| status.code == code));
                    assert!(deltas(&out).iter().any(|delta| delta_codes(delta, "failure").contains(&code)));
                    assert_eq!(failures(&out).iter().any(|actual| actual == "assertion.notRedacted"), !remove_box);
                    assert!(!failures(&out).iter().any(|actual| actual == "assertion.missing"));
                }
            }
        }
    }

    #[test]
    fn redacted_manifest_requires_matching_signature_for_every_active_manifest_hash() {
        let signer = Signer::conformant();
        let (child, signature) = node(&signer, INGREDIENT, vec![], &[secret()], &[]);
        let (other, other_sig) = node(&signer, OTHER, vec![], &[], &[]);
        for manifest_matches in [false, true] {
            for mode in ["valid", "absent", "wrong-hash", "wrong-manifest"] {
                let mut value = ingredient(INGREDIENT, &child, &signature, "componentOf", None);
                if !manifest_matches {
                    let mut reference = value.get("activeManifest").unwrap().clone();
                    set(&mut reference, "hash", Some(Value::Bytes(vec![0; 32])));
                    set(&mut value, "activeManifest", Some(reference));
                }
                match mode {
                    "absent" => set(&mut value, "claimSignature", None),
                    "wrong-hash" => {
                        let mut reference = value.get("claimSignature").unwrap().clone();
                        set(&mut reference, "hash", Some(Value::Bytes(vec![0; 32])));
                        set(&mut value, "claimSignature", Some(reference));
                    }
                    "wrong-manifest" => {
                        let wrong = ingredient(OTHER, &other, &other_sig, "componentOf", None);
                        set(&mut value, "claimSignature", wrong.get("claimSignature").cloned());
                    }
                    _ => {}
                }
                let (active, _) = node(&signer, ACTIVE, vec![Assertion::new("c2pa.ingredient.v3", &value)], &[], &[uri(INGREDIENT, SECRET)]);
                for profile in policies() {
                    let out = verify_store_under(&[child.clone(), other.clone(), active.clone()], profile);
                    let codes = failures(&out);
                    assert!(!codes.iter().any(|code| code == "ingredient.manifest.mismatch"), "{mode}: {codes:?}");
                    assert_eq!(codes.iter().any(|code| code == "ingredient.claimSignature.missing"), mode == "absent", "{mode}: {codes:?}");
                    assert_eq!(codes.iter().any(|code| code == "ingredient.claimSignature.mismatch"), matches!(mode, "wrong-hash" | "wrong-manifest"), "{mode}: {codes:?}");
                    assert_eq!(out.results.success.iter().any(|status| status.code == "ingredient.claimSignature.validated"), mode == "valid");
                    assert!(!out.results.success.iter().any(|status| status.code == "ingredient.manifest.validated"));
                }
            }
        }
    }

    #[test]
    fn diamond_declarations_are_independent_of_edge_and_store_order() {
        let signer = Signer::conformant();
        let (grand, grand_sig) = node(&signer, GRAND, vec![], &[secret()], &[]);
        let (left, left_sig) = node(&signer, INGREDIENT, vec![link("c2pa.ingredient.v3", GRAND, &grand, &grand_sig)], &[], &[]);
        let (right, right_sig) = node(&signer, OTHER, vec![link("c2pa.ingredient.v3", GRAND, &grand, &grand_sig)], &[], &[uri(GRAND, SECRET)]);
        for reverse_links in [false, true] {
            for reverse_store in [false, true] {
                let mut links = vec![link("c2pa.ingredient.v3", INGREDIENT, &left, &left_sig), link("c2pa.ingredient.v3__1", OTHER, &right, &right_sig)];
                if reverse_links { links.reverse(); }
                let (active, _) = node(&signer, ACTIVE, links, &[], &[]);
                let mut boxes = vec![grand.clone(), left.clone(), right.clone()];
                if reverse_store { boxes.reverse(); }
                boxes.push(active);
                for profile in policies() { assert_no_redaction_binding_failures(&verify_store_under(&boxes, profile)); }
            }
        }
    }

    #[test]
    fn thumbnails_icons_and_cawg_references_never_gain_redaction_exemptions() {
        let signer = Signer::conformant();
        let removed = secret();
        let (child, signature) = node(&signer, INGREDIENT, vec![], std::slice::from_ref(&removed), &[]);
        let reference = absolute(&removed, INGREDIENT);
        for field in ["thumbnail", "icon", "cawg"] {
            let mut value = ingredient(INGREDIENT, &child, &signature, "componentOf", None);
            let mut extras = Vec::new();
            if field == "thumbnail" { set(&mut value, "thumbnail", Some(reference.clone())); }
            if field == "icon" {
                extras.push(Assertion::new("c2pa.actions.v2__1", &vmap(vec![("actions", Value::Array(vec![vmap(vec![
                    ("action", Value::Text("org.example.checked".into())),
                    ("softwareAgent", vmap(vec![("name", Value::Text("fixture".into())), ("icon", reference.clone())])),
                ])]))])));
            }
            if field == "cawg" {
                let payload = vmap(vec![("sig_type", Value::Text("cawg.x509.cose".into())), ("referenced_assertions", Value::Array(vec![reference.clone()]))]);
                extras.push(Assertion::new("cawg.identity", &vmap(vec![("signature", Value::Bytes(signer.sign(&enc(&payload)))), ("signer_payload", payload)])));
            }
            extras.push(Assertion::new("c2pa.ingredient.v3", &value));
            for declared_redacted in [false, true] {
                let redactions = if declared_redacted { vec![uri(INGREDIENT, SECRET)] } else { vec![] };
                let (active, _) = node(&signer, ACTIVE, extras.clone(), &[], &redactions);
                for profile in policies() {
                    let out = verify_store_under(&[child.clone(), active.clone()], profile);
                    let codes = failures(&out);
                    if declared_redacted || field != "cawg" {
                        assert!(codes.iter().any(|code| code == "hashedURI.missing"), "{field}: {codes:?}");
                    } else {
                        assert!(codes.iter().any(|code| code == "assertion.missing"), "{field}: {codes:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn related_assertions_are_exempt_only_at_25_and_still_obey_target_eligibility() {
        let signer = Signer::conformant();
        let removed = Assertion::new("org.example.ingredient", &vmap(vec![("name", Value::Text("removed".into()))]));
        let (child, child_sig) = node(&signer, INGREDIENT, vec![], std::slice::from_ref(&removed), &[]);
        // A later declarant redacts an assertion in the active action's manifest.
        // Keep that manifest reachable as an ingredient so its generic walker runs.
        for ingredient_related in [false, true] {
            let related = Value::Array(vec![removed.reference()]);
            let extra = if ingredient_related {
                Assertion::new("c2pa.ingredient.v3", &vmap(vec![("relationship", Value::Text("componentOf".into())), ("relatedAssertions", related)]))
            } else {
                Assertion::new("c2pa.actions.v2__1", &vmap(vec![("actions", Value::Array(vec![vmap(vec![
                    ("action", Value::Text("c2pa.edited.metadata".into())),
                    ("parameters", vmap(vec![("relatedAssertions", related)])),
                ])]))]))
            };
            let (middle, middle_sig) = node(&signer, OTHER, vec![extra], std::slice::from_ref(&removed), &[]);
            let (active, _) = node(&signer, ACTIVE, vec![link("c2pa.ingredient.v3", OTHER, &middle, &middle_sig), link("c2pa.ingredient.v3__1", INGREDIENT, &child, &child_sig)], &[], &[uri(OTHER, &removed.label), uri(INGREDIENT, &removed.label)]);
            for profile in policies() {
                let out = verify_store_under(&[child.clone(), middle.clone(), active.clone()], profile);
                let codes = failures(&out);
                assert_eq!(codes.iter().any(|code| code == "hashedURI.missing"),
                    !ingredient_related && profile.version != SpecVersion::V2_5, "{codes:?}");
                let informational: Vec<&str> = deltas(&out).into_iter().flat_map(|delta| delta_codes(delta, "informational")).collect();
                assert_eq!(informational.contains(&"assertion.redacted"), profile.version == SpecVersion::V2_5);
            }
        }
    }

    fn extra_action(kind: &str, parameters: Value) -> Assertion {
        Assertion::new("c2pa.actions.v2__1", &vmap(vec![("actions", Value::Array(vec![vmap(vec![
            ("action", Value::Text(kind.into())),
            ("reason", Value::Text("c2pa.PII.present".into())),
            ("parameters", parameters),
        ])]))]))
    }

    #[test]
    fn redacted_action_cannot_borrow_a_descendants_declaration_or_a_present_box() {
        let signer = Signer::conformant();
        let (child, signature) = node(&signer, INGREDIENT, vec![], &[secret()], &[]);
        let (declarant, declarant_sig) = node(&signer, OTHER, vec![], &[], &[uri(INGREDIENT, SECRET)]);
        for target in [uri(INGREDIENT, SECRET), uri(ACTIVE, SECRET)] {
            let action = extra_action("c2pa.redacted", vmap(vec![("redacted", Value::Text(target))]));
            let (active, _) = node(&signer, ACTIVE, vec![secret(), action,
                link("c2pa.ingredient.v3", INGREDIENT, &child, &signature),
                link("c2pa.ingredient.v3__1", OTHER, &declarant, &declarant_sig)], &[], &[]);
            for profile in policies() {
                let out = verify_store_under(&[child.clone(), declarant.clone(), active.clone()], profile);
                assert!(out.results.failure.iter().any(|status| status.code == "assertion.action.redactionMismatch"));
            }
        }
    }

    #[test]
    fn active_related_assertions_skip_the_digest_only_at_25() {
        let signer = Signer::conformant();
        let removed = Assertion::new("org.example.ingredient", &vmap(vec![("name", Value::Text("removed".into()))]));
        let (declarant, signature) = node(&signer, INGREDIENT, vec![], &[], &[uri(ACTIVE, &removed.label)]);
        for ingredient_related in [false, true] {
            let extra = if ingredient_related {
                Assertion::new("c2pa.ingredient.v3__1", &vmap(vec![
                    ("relationship", Value::Text("componentOf".into())),
                    ("relatedAssertions", Value::Array(vec![removed.reference()])),
                ]))
            } else {
                extra_action("c2pa.edited.metadata", vmap(vec![
                    ("relatedAssertions", Value::Array(vec![removed.reference()])),
                ]))
            };
            let (active, _) = node(&signer, ACTIVE, vec![extra,
                link("c2pa.ingredient.v3", INGREDIENT, &declarant, &signature)], std::slice::from_ref(&removed), &[]);
            for profile in policies() {
                let out = verify_store_under(&[declarant.clone(), active.clone()], profile);
                assert_eq!(out.results.failure.iter().any(|status| status.code == "hashedURI.missing"),
                    !ingredient_related && profile.version != SpecVersion::V2_5, "{:?}", failures(&out));
                assert_eq!(out.results.informational.iter().any(|status| status.code == "assertion.redacted"),
                    profile.version == SpecVersion::V2_5);
                if profile.version == SpecVersion::V2_5 {
                    assert_no_redaction_binding_failures(&out);
                    assert!(!out.results.failure.iter().any(|status| matches!(status.code.as_str(),
                        "assertion.action.malformed" | "assertion.ingredient.malformed")));
                }
            }
        }
    }

    #[test]
    fn action_ingredient_redaction_exemptions_are_limited_to_named_actions_and_locations() {
        let signer = Signer::conformant();
        let removed = Assertion::new("c2pa.ingredient.v3__1", &vmap(vec![
            ("relationship", Value::Text("componentOf".into())),
        ]));
        for kind in ["c2pa.placed", "c2pa.transcoded", "c2pa.repackaged", "c2pa.deleted", "c2pa.removed", "org.example.checked"] {
            for foreign in [false, true] {
                let expected_25 = match kind {
                    "c2pa.placed" | "c2pa.transcoded" | "c2pa.repackaged" => !foreign,
                    "c2pa.deleted" | "c2pa.removed" => foreign,
                    _ => false,
                };
                let target_manifest = if foreign { INGREDIENT } else { ACTIVE };
                let child_redactions = if foreign { vec![] } else { vec![uri(ACTIVE, &removed.label)] };
                let (child, signature) = node(&signer, INGREDIENT, vec![],
                    if foreign { std::slice::from_ref(&removed) } else { &[] },
                    &child_redactions);
                let reference = if foreign { absolute(&removed, INGREDIENT) } else { removed.reference() };
                let action = extra_action(kind, vmap(vec![("ingredients", Value::Array(vec![reference]))]));
                let redactions = if foreign { vec![uri(INGREDIENT, &removed.label)] } else { vec![] };
                let (active, _) = node(&signer, ACTIVE, vec![action,
                    link("c2pa.ingredient.v3", INGREDIENT, &child, &signature)],
                    if foreign { &[] } else { std::slice::from_ref(&removed) }, &redactions);
                for profile in policies() {
                    let out = verify_store_under(&[child.clone(), active.clone()], profile);
                    let expected = profile.version == SpecVersion::V2_5 && expected_25;
                    assert_eq!(out.results.failure.iter().any(|status| status.code == "hashedURI.missing"), !expected,
                        "{kind}, target {target_manifest}, {:?}: {:?}", profile.version, failures(&out));
                    if expected {
                        assert!(!out.results.failure.iter().any(|status| matches!(status.code.as_str(),
                            "assertion.action.ingredientMismatch" | "assertion.action.ingredientLocationMismatch")));
                        assert!(out.results.informational.iter().any(|status| status.code == "assertion.redacted"));
                    }
                }
            }
        }
    }

    #[test]
    fn redacted_ingredient_related_targets_still_require_the_ingredient_suffix() {
        let signer = Signer::conformant();
        let removed = secret();
        let (child, signature) = node(&signer, INGREDIENT, vec![], &[], &[uri(ACTIVE, SECRET)]);
        let related = Assertion::new("c2pa.ingredient.v3__1", &vmap(vec![
            ("relationship", Value::Text("componentOf".into())),
            ("relatedAssertions", Value::Array(vec![removed.reference()])),
        ]));
        let (active, _) = node(&signer, ACTIVE, vec![related,
            link("c2pa.ingredient.v3", INGREDIENT, &child, &signature)], &[removed], &[]);
        let out = verify_store_under(&[child, active], policies()[1]);
        assert!(out.results.failure.iter().any(|status| status.code == "assertion.ingredient.malformed"));
        assert!(!out.results.failure.iter().any(|status| status.code == "hashedURI.missing"));
    }

    #[test]
    fn nonzero_redacted_assertions_fail_without_running_their_content_validator() {
        let signer = Signer::conformant();
        let label = "c2pa.ingredient.v3__1";
        let malformed = Assertion { label: label.into(), jumbf: assertion_box(label, &[0xff], None) };
        let (child, signature) = node(&signer, INGREDIENT, vec![], &[], &[uri(ACTIVE, label)]);
        let (active, _) = node(&signer, ACTIVE, vec![malformed,
            link("c2pa.ingredient.v3", INGREDIENT, &child, &signature)], &[], &[]);
        for profile in policies() {
            let out = verify_store_under(&[child.clone(), active.clone()], profile);
            assert!(out.results.failure.iter().any(|status| status.code == "assertion.notRedacted"));
            assert!(!out.results.failure.iter().any(|status| matches!(status.code.as_str(),
                "assertion.cbor.invalid" | "assertion.ingredient.malformed")));
        }
    }

    #[test]
    fn update_inherited_binding_reuses_the_lineage_redaction_index() {
        let signer = Signer::conformant();
        let (declarant, declarant_sig) = node(&signer, OTHER, vec![], &[], &[uri(INGREDIENT, SECRET)]);
        let (parent, parent_sig) = node(&signer, INGREDIENT,
            vec![link("c2pa.ingredient.v3", OTHER, &declarant, &declarant_sig)], &[secret()], &[]);
        let parent_link = Assertion::new("c2pa.ingredient.v3",
            &ingredient(INGREDIENT, &parent, &parent_sig, "parentOf", None));
        let actions = Assertion::new("c2pa.actions.v2", &vmap(vec![("actions", Value::Array(vec![vmap(vec![
            ("action", Value::Text("c2pa.opened".into())),
            ("parameters", vmap(vec![("ingredients", Value::Array(vec![parent_link.reference()]))])),
        ])]))]));
        let active = update_manifest_box(&signer, ACTIVE,
            &[actions.clone(), parent_link.clone()], vec![actions.reference(), parent_link.reference()]);
        for profile in policies() {
            let out = verify_store_under(&[declarant.clone(), parent.clone(), active.clone()], profile);
            assert_no_redaction_binding_failures(&out);
            assert!(out.results.success.iter().any(|status| status.code == "ingredient.claimSignature.validated"));
        }
    }

    #[test]
    fn signed_parent_action_related_assertions_reach_the_child_ingredient_delta() {
        let signer = Signer::conformant();
        for schema_path in [false, true] {
            let private = secret();
            let binding = Assertion::new("c2pa.hash.data", &data_hash());
            let mut actions = created_actions();
            let mut items = actions.get("actions").unwrap().clone();
            let Value::Array(list) = &mut items else { unreachable!() };
            let references = Value::Array(vec![absolute(&private, INGREDIENT)]);
            if schema_path {
                set(&mut list[0], "parameters", Some(vmap(vec![("relatedAssertions", references)])));
            } else {
                // An action-item extension with this name is not the schema's
                // parameters.relatedAssertions reference field.
                set(&mut list[0], "relatedAssertions", Some(references));
            }
            set(&mut actions, "actions", Some(items));
            let actions = Assertion::new("c2pa.actions.v2", &actions);
            let claim_bytes = enc(&claim(vec![binding.reference(), actions.reference(), private.reference()]));
            let signature = signer.sign(&claim_bytes);
            // Remove only the private box. The parent's signed claim, actions
            // assertion and COSE signature retain their original bytes.
            let parent = build_manifest(INGREDIENT,
                &[binding.jumbf, actions.jumbf], &claim_bytes, &signature);

            let parent_link = Assertion::new("c2pa.ingredient.v3",
                &ingredient(INGREDIENT, &parent, &signature, "parentOf", None));
            let target = uri(INGREDIENT, SECRET);
            let actions = Assertion::new("c2pa.actions.v2", &vmap(vec![
                ("allActionsIncluded", Value::Bool(true)),
                ("actions", Value::Array(vec![
                    vmap(vec![
                        ("action", Value::Text("c2pa.opened".into())),
                        ("parameters", vmap(vec![
                            ("ingredients", Value::Array(vec![parent_link.reference()])),
                        ])),
                    ]),
                    vmap(vec![
                        ("action", Value::Text("c2pa.redacted".into())),
                        ("reason", Value::Text("c2pa.PII.present".into())),
                        ("parameters", vmap(vec![("redacted", Value::Text(target.clone()))])),
                    ]),
                ])),
            ]));
            let binding = Assertion::new("c2pa.hash.data", &data_hash());
            let mut child_claim = claim(vec![actions.reference(), parent_link.reference(), binding.reference()]);
            set(&mut child_claim, "redacted_assertions", Some(Value::Array(vec![Value::Text(target.clone())])));
            let claim_bytes = enc(&child_claim);
            let signature = signer.sign(&claim_bytes);
            let child = build_manifest(ACTIVE,
                &[actions.jumbf, parent_link.jumbf, binding.jumbf], &claim_bytes, &signature);

            for profile in policies() {
                let out = verify_store_under(&[parent.clone(), child.clone()], profile);
                let edge = format!("self#jumbf=/c2pa/{ACTIVE}/c2pa.assertions/c2pa.ingredient.v3");
                let delta = deltas(&out).into_iter().find(|delta|
                    delta["ingredientAssertionURI"].as_str() == Some(edge.as_str()))
                    .expect("child-to-parent ingredient delta");
                assert!(delta_codes(delta, "success").contains(&"claimSignature.validated"));
                let informational = delta["validationDeltas"]["informational"].as_array().unwrap();
                assert_eq!(informational.iter().any(|status|
                    status["code"] == "assertion.redacted" && status["url"] == target),
                    schema_path && profile.version == SpecVersion::V2_5,
                    "schema_path={schema_path}, policy={:?}, delta={delta}", profile.version);
                assert_eq!(delta_codes(delta, "failure").contains(&"hashedURI.missing"),
                    schema_path && profile.version != SpecVersion::V2_5);
                if profile.version == SpecVersion::V2_5 {
                    assert!(delta_codes(delta, "failure").is_empty(), "{delta}");
                    assert_no_redaction_binding_failures(&out);
                }
            }
        }
    }
}
