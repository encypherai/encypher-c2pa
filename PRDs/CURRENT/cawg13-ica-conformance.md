# CAWG Identity 1.3 ICA Conformance Closure

**Status:** plan gate
**Current Goal:** every CAWG Identity 1.3 rule on an identity claims aggregation (ICA) credential that a validator can check is checked by `cawg_ica.rs` and defended by a test that fails when the rule is dropped.

## Overview

A coverage audit of the ICA validator against CAWG Identity 1.3 (tag `v1.3`) found two kinds of gap. Most rules are implemented but untested: a regression in the type, provider, name, username, address, URI, method, base64-alphabet, or time-stamp paths would pass CI. A smaller set is not implemented: three `verifiedIdentities` conditions, the order of two status codes, and the out-of-band signal naming the rejected entry. This PRD covers the implementation changes. The test additions need no design.

## Behaviour changes

| # | Change | Spec source (v1.3) | Newly rejects? |
|---|---|---|---|
| 1 | `verifiedIdentities[].type` and `.method` must match the labels ABNF: two or more period-separated components, each `1(DIGIT / ALPHA) *(DIGIT / ALPHA / "-" / "_")`. | technical-description.adoc: "Other string values MAY be used ... subject to restrictions described in Labels" (type and method); labels.adoc ABNF | Yes |
| 2 | `verifiedIdentities[].uri` and `provider.id` must be RFC 3986 `URI` productions (absolute URI; ASCII only; valid percent-encoding, authority, port). Today only the scheme prefix is checked. | "it must be a valid URI"; "it MUST be a valid URI" | Yes |
| 3 | `cawg.crypto_wallet` `address` must be ASCII alphanumeric. | "MUST be the unique alphanumeric string" | Yes |
| 4 | `cawg.social_media` `username` stays non-empty text; the alphanumeric wording is **not** enforced. Deliberate interop deviation from CAWG-ID13-ICA-TECH-A-020 (a 1.3 MUST); see Spec questions. | same wording as 3 | No |
| 5 | `cawg.ica.signer_payload.mismatch` is emitted before the `verifiedIdentities` codes. | validating.adoc orders "Verify binding to C2PA asset" before "Verify verified identities"; "SHALL follow the steps ... in the order presented" | No (order only) |
| 6 | `cawg.ica.verified_identities.invalid` carries `details.invalid_entries: [{index, field}]`, `field` naming the property that broke a condition. | validating.adoc NOTE: RECOMMENDED out-of-band signal naming the entry | No (additive detail) |
| 7 | `credentialSchema` is not fetched or evaluated. The hand-written checks implement the prose; the decision is recorded here and at `parse_ica_credential`. | validating.adoc: RECOMMENDED | No |

### Why 4 differs from 3

Adobe production credentials put display names with spaces in `cawg.social_media` `username`: `"Eric Scouten"` in `contributed/adobe-cai-prod-ica-es-266-1236.jpg` and `"Gavin Peacock"` in the c2pa-cpp `C_with_CAWG_data.jpg` fixture, both from LinkedIn federated login. Enforcing the literal text would reject every LinkedIn-backed Adobe credential. No observed credential carries a `cawg.crypto_wallet` `address`, and the address formats in common use (hex, base58, bech32) are alphanumeric. The username wording is a spec defect to raise upstream, not a rule to enforce.

### Why 7 is a decision, not an omission

The v1.3 schemas (`docs/modules/ROOT/attachments/ica/schema/vc{1.1,2.0}/index.json`) cannot be used as a gate:

- They reference `#/definitions/...`, but define `$defs`, so a strict JSON Schema 2020-12 processor fails on the unresolvable references.
- They require `uri` for `cawg.social_media`, which the prose only RECOMMENDS. The public verifier's own conformant fixtures would fail.
- Production Adobe credentials cite `https://cawg.io/identity/1.1/ica/schema/`, which is neither listed URL. Resolving it would require the network, which this verifier does not use for validation.

## Interop impact on the vector corpus

Every `verifiedIdentities` entry in `tests/vectors/cawg` (public) and `packages/encypher-c2pa/tests/vectors/cawg` (commercial: Adobe contributed sample, c2pa-rs `d7f13829` fixtures, c2pa-cpp fixture) was extracted and checked:

| Field | Values seen | Effect of 1-3 |
|---|---|---|
| `type` | `cawg.social_media`, `cawg.document_verification`, `cawg.affiliation`, `cawg.crypto_wallet` | all pass the ABNF |
| `method` | `cawg.federated_login`, `cawg.idv` | pass |
| `uri`, `provider.id` | `https://` URLs (LinkedIn redirect, Behance, Instagram, example hosts) | pass RFC 3986 |
| `address` | none. The c2pa-rs `cawg.crypto_wallet` entry has no address and already fails | unchanged |

No corpus expectation changes. Out-of-corpus risks: an issuer using a single-component custom type (`"passport"`), a non-ASCII IRI, or a CAIP-10 address (`eip155:1:0xab...`) would now get `cawg.ica.verified_identities.invalid`. All three already violate the 1.3 text.

## Out of scope

- Service-level uniqueness of `username`/`address`, the "primary" contact semantics of `uri`, and the match between `name` and identity documents: issuer attestations a validator cannot observe.
- Rejecting undefined `cawg.*` labels. labels.adoc reserves them, but a validator cannot tell who assigned a label, minor versions may add values, and Adobe production already emits the undefined `method: "cawg.idv"`.
- The status-list bit order (owned by the status-list fix).
- The retained commercial kernel.

## Verification

TDD in `crates/encypher-c2pa/src/c2pa-validate/cawg_ica.rs` and `report.rs`. `cargo test -p encypher-c2pa` plus the CLI corpus suite (`crates/encypher-c2pa-cli/tests/cawg_corpus.rs`).

## Spec questions (issue drafts for cawg/identity-assertion)

1. **Social media `username` is not alphanumeric in production (CAWG-ID13-ICA-TECH-A-020).** technical-description.adoc says the `cawg.social_media` `username` "MUST be the unique alphanumeric string that can be used to identity the named actor within this service." Adobe's production aggregator emits LinkedIn display names such as `"Eric Scouten"` (a space), and common handles contain `.`, `_`, or `-`. Proposed text: "MUST be a non-empty string that the identity provider uses to identify the named actor within this service." The same question applies to the `cawg.crypto_wallet` `address` wording (TECH-A-023) for formats such as CAIP-10. Until the text changes, this verifier enforces non-empty text for `username` and ASCII alphanumeric for `address`.
2. **ICA JSON schemas are not usable as validators (VALIDATING-B-002, TECHNICAL-B-026).** The v1.3 schemas reference `#/definitions/nonEmptyString` but declare `$defs`; they require `uri` for `cawg.social_media`, which the prose only RECOMMENDS; and production credentials cite `https://cawg.io/identity/1.1/ica/schema/`, which is neither listed URL. Which is authoritative when schema and prose disagree?
3. **The normative example breaks its own rules.** The `cawg.web_site` entry in the credential example has `uri: "named-actor-site.example"` (not a URI) and no `provider`.
