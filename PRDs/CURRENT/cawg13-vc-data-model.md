# CAWG Identity 1.3 ICA: W3C VC Data Model Conformance (TEAM_467)

**Status:** plan gate
**Base:** `feat/cawg13-ica-conformance` at `34619e9` (TEAM_462, PR #28; code identical to `284ff58`)
**Branch:** `feat/cawg13-vc-data-model`
**Current Goal:** close CAWG-ID13-ICA-TECH-A-004 in the public verifier. Every W3C Verifiable Credentials Data Model requirement (v1.1 and v2.0, both admitted by CAWG Identity 1.3) that an identity-claims-aggregation validator can check on the credential it receives is checked by `cawg_ica.rs` and defended by a test that signs a credential breaking that one rule. Requirements that need JSON-LD processing or network retrieval are named, with the decision taken for each.

## Overview

TECH-A-004 says an ICA "MUST meet all requirements for a verifiable credential as described in the W3C Verifiable credentials data model (either version 1.1 or version 2.0)". VC 2.0 section 1.3 turns that into a verifier duty: a conforming verifier "MUST check that each required property satisfies the normative requirements for that property, and MUST produce errors when non-conforming documents are detected". VC 1.1 section 1.3: "Conforming processors MUST produce errors when non-conforming documents are consumed."

The public verifier's `parse_ica_credential` checks a hand-picked subset: context order and membership, `type` strings, the issuer by way of the DID, one credential subject, and date parsing through RFC 3339. It also rejects object-valued `@context` entries, which both VC versions allow. This PRD enumerates the normative statements of both specifications, classifies each, and specifies the checks that close the gap.

Sources read: VC Data Model 2.0 (W3C Recommendation, 2025-05-15) and VC Data Model 1.1 (W3C Recommendation, 2022-03-03), every MUST/REQUIRED/MUST NOT statement in each; CAWG Identity 1.3 (`cawg-identity-assertion` tag `8851770`, "DIF Ratified Specification") ICA technical description and validating procedure; the published CAWG ICA JSON-LD context (`https://cawg.io/identity/1.1/ica/context/`, identical to `docs/modules/ROOT/attachments/ica/context/index.json`).

## JSON-LD expansion decision

**Decision: no JSON-LD expansion. The verifier performs VC 2.0 "type-specific credential processing" (section 6.3) and treats the known contexts as fixed.**

- VC 2.0 section 6.3: "type-specific credential processing is allowed as long as the document being consumed or produced is a conforming document." Its rule is that `@context` values are in the expected order and the known context contents are fixed. The verifier matches the VC base context and the CAWG context by exact URL and never loads them, which VC 2.0 appendix B.1 requires for the base context ("MUST treat the base context value ... as already retrieved").
- VC 1.1 section 5.3 addresses JSON-based processors directly: they "MUST process the `@context` key, ensuring the expected values exist in the expected order". The JSON-LD redefinition error it imposes on "JSON-LD-based processors" does not bind a JSON-based processor.
- Expansion cannot fail on an undefined term here. The VC 2.0 base context and the CAWG ICA context both declare `@vocab`, so every term expands. VC 2.0 section 5.2's `undefined-terms/v2` rule therefore never triggers.
- The verifier is offline and never fetches. An unknown context URL cannot be expanded without retrieving it, and a JSON-LD processor would add a large dependency and a network document loader to a verification-only crate.

What is lost without expansion, and how each gap is handled:

| Needs JSON-LD | Handling |
|---|---|
| Meaning of terms defined by an unknown context **URL** | Accepted without dereferencing. CAWG TECH-A-005 says the `@context` "MUST contain at least" the two entries, so extra contexts are permitted. The issuer is trusted and signed them. The verifier reads the VC and CAWG terms by name and reports the signed JSON verbatim. |
| Effect of an **inline** (object) context | Checkable on the credential, so it is checked (V-06, V-07): an inline context may not define a term this validator reads, and may not carry a scoped `@context`. Either would change what that term means under JSON-LD. For a `@protected` VC term, JSON-LD processing would stop with an error. |
| JSON-LD expansion errors (VC 2.0 B.1: "If such operations are performed and result in an error ... MUST result in a verification failure") | Conditional on performing expansion; not performed. |
| Verifying an embedded Data Integrity `proof` (RDF canonicalization) | Not verified and not relied on. CAWG secures the ICA with the COSE_Sign1 envelope (VC-JOSE-COSE), which is verified. `proof` objects get the structural check in V-35. |
| Full JSON-LD compacted-form check (VC 2.0 6.1) | Partial: top-level `@id`/`@type` are rejected (V-36), because compaction against the base context always uses the `id`/`type` aliases. |

## Requirement table

Legend: **Checked** means the rule is enforced after this PRD (**existing** means it was already enforced; **new** means this PRD adds it). **JSON-LD** means the rule cannot be checked without JSON-LD processing; the decision is given. **N/A** means the rule binds issuers, holders, presentations, or specification authors, not a validator of a received credential. Every "Checked" failure reports `cawg.ica.invalid_verifiable_credential` with an explanation naming the property, unless a CAWG code is named. CAWG says an unparseable credential stops validation with that code, and VC 2.0 section 7.1 maps a non-conforming document to `MALFORMED_VALUE_ERROR`.

### Contexts

| ID | Requirement (VC 2.0 / VC 1.1) | Class | How |
|---|---|---|---|
| V-01 | Credential MUST include `@context` (2.0 4.3; 1.1 4.1) | Checked (existing) | Missing or not an array is rejected. |
| V-02 | First item MUST be the data model's base context URL (2.0 4.3; 1.1 4.1). JSON processors MUST ensure the expected values are in the expected order (1.1 5.3) | Checked (existing, TEAM_462) | `contexts[0]` selects `2.0` or `1.1`. The CAWG context must be present. |
| V-03 | Subsequent items are "any combination of URLs and objects" (2.0 4.3), or "URIs or objects" (1.1 4.1) | Checked (**new**) | **Fixes a TEAM_462 over-rejection:** an object entry is now accepted. A string entry must be an RFC 3986 URI; before, any string was accepted. |
| V-04 | Each object entry is "processable as a JSON-LD Context" (2.0 4.3) | Checked (**new**, partial) | JSON-LD 1.1 context-definition keyword types: `@version` = 1.1; `@vocab`, `@base`, `@language` string or null; `@direction` `"ltr"`, `"rtl"`, or null; `@protected`, `@propagate` boolean; `@import` a URI. Every other key is a term whose definition is a string, null, or an object. The internals of a term definition object need JSON-LD processing (JSON-LD row above). |
| V-05 | `@context` is an "ordered set" (2.0 4.3; Infra ordered set): no repeated item | Checked (**new**) | A repeated string entry is rejected. |
| V-06 | Exactly one data-model base context. CAWG TECH-A-005: the v1 URL "_or_" the v2 URL, "depending on which version ... is being used" | Checked (**new**) | A credential listing both base contexts is rejected. Both are `@protected` and define the same terms with different vocabularies. |
| V-07 | Application developers MUST understand every context that affects the meaning of the terms they use (2.0 4.3). JSON-LD processors MUST error on redefinition of a protected term (1.1 5.3) | Checked for inline contexts (**new**); JSON-LD for URL contexts | An inline context that defines a term the validator reads is rejected, as is one whose term definition carries a scoped `@context`. The terms read are the VC terms in this table, the ICA types, `BitstringStatusListEntry` and its fields, and the CAWG `credentialSubject` and `verifiedIdentities` fields. Unknown URL contexts are accepted undereferenced (JSON-LD row above). |
| V-08 | Base context treated as already retrieved; digest pinned (2.0 B.1) | Checked (existing, by construction) | Matched by exact URL; never fetched. |
| V-09 | `undefined-terms/v2` MUST be last when terms are undefined (2.0 5.2) | N/A | Never triggers: the CAWG context declares `@vocab`, so no term is undefined. |
| V-10 | Expansion errors MUST fail verification "if such operations are performed" (2.0 B.1) | JSON-LD | Expansion is not performed (see decision). |

### Identifiers and types

| ID | Requirement | Class | How |
|---|---|---|---|
| V-11 | `id`, if present, MUST be a single URL (2.0 4.4); a single URI (1.1 4.2, 6) | Checked (**new**) | Checked on the credential, each credential subject, and each `credentialStatus`, `credentialSchema`, `evidence`, `termsOfUse`, `refreshService`, and `relatedResource` object: an RFC 3986 URI string. |
| V-12 | `type` MUST be present (2.0 4.5; 1.1 4.3) | Checked (existing) | |
| V-13 | `type` values MUST be "terms and absolute URL strings" (2.0 4.5); they "be, or map to ... URIs" (1.1 4.3) | Checked (existing: strings; **new**: form) | Each member is a non-empty string and not an `@` keyword. A member containing `:` must be an RFC 3986 URI (an absolute or compact IRI). A member without `:` is a term, which the `@vocab` of the base and CAWG contexts always defines. |
| V-14 | The credential's type includes `VerifiableCredential` (2.0 4.5 table; 1.1 4.3 table) and a narrower type (1.1 MUST, 2.0 SHOULD) | Checked (existing, TECH-A-006) | Both ICA types are required. |
| V-15 | `credentialStatus`, `termsOfUse`, `evidence`, `refreshService`, and `credentialSchema` objects MUST have a type (2.0 4.5 table; 1.1 4.3 table, which also lists `proof`) | Checked (**new**) | See V-24 to V-35. Each `type` meets V-13. |

### Names, issuer, subject

| ID | Requirement | Class | How |
|---|---|---|---|
| V-16 | `name` and `description`, if present, MUST be a string or a language value object (2.0 4.6). Multiple language value objects MAY form an array (2.0 11.1) | Checked (**new**, VC 2.0 credentials) | Accepted forms: a string, a language value object, or a non-empty array of them. VC 1.1 does not define these properties. |
| V-17 | A language value object MUST have a string `@value`, MUST NOT have keys beyond `@value`, `@language`, and `@direction`, and `@direction` is a base direction (2.0 11.1) | Checked (**new**) | `@language` BCP 47 well-formedness is a SHOULD and is not enforced. |
| V-18 | `issuer` MUST be present and be a URL or an object with an `id` URL (2.0 4.7; 1.1 4.5) | Checked (existing, **new** URI check) | CAWG routes this case to `cawg.ica.invalid_issuer` ("not a DID"). New: a DID string that is not an RFC 3986 URI, such as one containing a space, is now `cawg.ica.invalid_issuer`; before, it went on to resolution. |
| V-19 | `credentialSubject` MUST be present: a set of objects, each the subject of one or more claims (2.0 4.8; 1.1 4.4) | Checked (existing) | An object or an array holding one object. More than one subject is rejected as ambiguous. This is a CAWG policy, not a VC rule: the ICA's one subject carries `c2paAsset` and `verifiedIdentities`. The one-or-more-claims rule is subsumed, because those two properties are required. |
| V-20 | Subject `id`, if present, is a URL | Checked (**new**) | As V-11. |

### Validity

| ID | Requirement | Class | How |
|---|---|---|---|
| V-21 | `validFrom` and `validUntil`, if present, MUST be an XML Schema `dateTimeStamp` (2.0 4.9) | Checked (**new**, strict) | An XSD 1.1 lexical check replaces RFC 3339 parsing. RFC 3339 through `time` also accepted any separator byte (such as a space), lowercase `z`, offsets up to `±23:59`, and second `60`. XSD requires `T`, `Z` or an offset within `±14:00`, and a time zone; `24:00:00` means the end of the day. Failures report the CAWG codes `cawg.ica.valid_from.invalid` and `cawg.ica.valid_until.invalid`. |
| V-22 | `validFrom` MUST be at or before `validUntil` (2.0 4.9) | Checked (**new**) | Reported as `cawg.ica.valid_until.invalid`. Before, such a credential already failed at every validation time, but the code depended on the time used. Now the explanation names the ordering. |
| V-23 | VC 1.1 `issuanceDate` MUST exist and be an XSD `dateTime`; `expirationDate`, if present, an XSD `dateTime` (1.1 4.6, 4.8) | Checked (existing: presence; **new**: lexical form) | An XSD `dateTime` makes the time zone optional, and one without a zone was wrongly rejected as malformed. It is now accepted and compared fail-closed across the ±14 h zone range XSD defines: the effective date is read at its latest possible instant and the expiration date at its earliest. |

### Status, schema, and extension properties

| ID | Requirement | Class | How |
|---|---|---|---|
| V-24 | `credentialStatus`, if present, is one object or a set of objects, each with a REQUIRED `type` and an optional URL `id` (2.0 4.10) | Checked (**new**) | A non-object entry or a missing type now reports `cawg.ica.invalid_verifiable_credential`. Before, the verifier skipped the entry and reported `cawg.ica.revocation.unsupported`. |
| V-25 | 1.1: `credentialStatus` MUST include an `id` URI and a `type` (1.1 4.9) | Checked (**new**, VC 1.1 credentials) | |
| V-26 | `credentialSchema`: one or more objects, each with a `type` and an `id` URL (2.0 4.11; 1.1 5.4) | Checked (**new**) | Structure only. Evaluating the schema is a CAWG RECOMMENDED step that TEAM_462 row 7 records as not performed, with reasons. No VC MUST requires evaluation. |
| V-27 | `refreshService`: one or more, each with a type (2.0 5.4); 1.1 also requires an `id` URI (1.1 5.6) | Checked (**new**) | |
| V-28 | `termsOfUse`: one or more policies, each with a type (2.0 5.5; 1.1 5.7) | Checked (**new**) | |
| V-29 | `evidence`: one object or a set, each with a REQUIRED `type` and an optional URL `id` (2.0 5.6; 1.1 5.8) | Checked (**new**) | |
| V-30 | `relatedResource`: one or more objects; `id` REQUIRED, a URL, unique in the list; at least one of `digestSRI` and `digestMultibase` (2.0 5.3) | Checked (**new**) | `digestSRI` must match the SRI `hash-expression` grammar (`sha256`, `sha384`, or `sha512`, `-`, base64). `digestMultibase` must be a non-empty string or strings. Decoding the multihash matters only when a resource is retrieved (V-31). |
| V-31 | A verifier that retrieves a related resource MUST compute and compare its digest (2.0 5.3) | N/A | The verifier never retrieves resources. |
| V-32 | Reserved `confidenceMethod` and `renderMethod` values MUST specify a `type` (2.0 5.10) | Checked (**new**) | |

### Securing and syntax

| ID | Requirement | Class | How |
|---|---|---|---|
| V-33 | Secured by at least one securing mechanism; the verifier MUST perform verification (2.0 1.3, 4.12, 7.1). A proof mechanism MUST be expressed (1.1 4.7) | Checked (existing) | COSE_Sign1 is verified against the issuer DID key (`cawg.ica.signature_mismatch`). |
| V-34 | Media type `application/vc` (2.0 1.3) | Checked (existing) | `cawg.ica.invalid_content_type`. |
| V-35 | An embedded `proof` MUST give its method in `type` (1.1 4.7; Data Integrity 1.0) | Checked (**new**, structure) | Each `proof` object needs a type. The proof is not verified (JSON-LD row above). |
| V-36 | JSON-LD compacted form MUST be used for `application/vc` (2.0 6.1) | Checked (**new**, partial) | A top-level `@id` or `@type` key is rejected. |
| V-37 | JSON value mapping: "Other values MUST be represented as a String" (1.1 6.1); single-valued `id`, `issuer`, and dates (1.1 6) | Checked (subsumed) | The per-property rules above require strings where the model has strings. |
| V-38 | Verification returns a conforming document, or `MALFORMED_VALUE_ERROR` (2.0 7.1) | Checked | Mapped to `cawg.ica.invalid_verifiable_credential`. CAWG makes problem details a MAY. |

### Not applicable

| ID | Requirement | Why |
|---|---|---|
| V-39 | Presentations, `holder`, and enveloped VC/VP objects (2.0 4.13; 1.1 4.10) | An ICA is a credential, not a presentation. |
| V-40 | Zero-knowledge proof rules (2.0 5.7; 1.1 5.8) | Issuer and holder mechanics. |
| V-41 | JWT encoding and decoding (1.1 6.3.1) | The ICA is enveloped in COSE, not JWT. |
| V-42 | Rules for vocabulary authors, ecosystem transformations, and securing-mechanism and status-list specification authors (2.0 5.2, 5.11, 5.13, 4.10 privacy MUST NOT; 1.1 serialization determinism) | These bind specification authors. |
| V-43 | Issuer MUSTs: include required properties, secure the document (2.0 1.3) | Issuer duties; the validator-side mirror is V-12, V-18, V-19, V-33. |
| V-44 | SHOULDs: avoid `@vocab`, prefer UTC `dateTimeStamp`, BCP 47 language tags (2.0 5.2, 5.8, 11.1) | Not MUSTs. The CAWG context itself sets `@vocab`. |

## Implementation

All in `crates/encypher-c2pa/src/c2pa-validate/cawg_ica.rs`:

- `parse_ica_credential` keeps its role. A new `vc_data_model_defect(object, vc_version) -> Option<&'static str>` holds V-03 to V-07, V-11, V-13, V-15 to V-17, V-20, V-24 to V-30, V-32, V-35, and V-36. It returns the explanation that becomes the `cawg.ica.invalid_verifiable_credential` text. It reuses the existing `is_uri`.
- The issuer string must pass `is_uri` before DID parsing (V-18). Otherwise it is treated as having no DID, which reports `cawg.ica.invalid_issuer` through the existing path.
- `parse_validity` becomes an XSD `dateTime`/`dateTimeStamp` parser (V-21, V-23). The zone is required for VC 2.0 and optional for VC 1.1, with the fail-closed bound for zoneless values. Years outside 0000-9999 are rejected as malformed, because `time` cannot represent them without the `large-dates` feature. XSD allows them; no credential uses them.
- V-22 adds `valid_until < valid_from` to the `valid_until.invalid` comparison.

## Tests (TDD)

Each negative case is a complete credential, edited to break one rule and signed by the trusted `did:jwk` issuer (`validate_edited` / `validate_dates`). The signature, trust, and identity checks pass, so the named code is the only failure. The cases are grouped into table-driven tests by property family: contexts, identifiers and types, names, status, schema and extensions, and dates. Positive coverage: a credential that uses every optional property in conforming form validates, with an inline context object, an extra URL context, `id`, language-tagged `name` and `description`, `credentialSchema`, `evidence`, `termsOfUse`, `refreshService`, `relatedResource`, an offset `validFrom`, and a `24:00:00` `validUntil`. So does a VC 1.1 credential with a zoneless `issuanceDate`. The positive credential is the regression for the TEAM_462 object-context rejection.

## Interop evidence

Extracted every ICA credential payload from the vectors:

- 23 in the public corpus `tests/vectors/cawg`: 22 c2pa-rs `d7f13829` fixtures (20 synthetic `did:jwk`/`did:web` credentials and 2 Adobe stage), and the c2pa-cpp `C_with_CAWG_data.jpg` Adobe production credential.
- 1 more in the commercial `packages/encypher-c2pa/tests/vectors/cawg`: the contributed Adobe production credential `adobe-cai-prod-ica-es-266-1236.jpg`.

| Property | Values seen | Effect of this PRD |
|---|---|---|
| `@context` | always `[v2 base, CAWG ICA]` | pass |
| `type` | always `[VerifiableCredential, IdentityClaimsAggregationCredential]` | pass |
| top-level `id` | absent in all | n/a |
| `credentialSubject.id` | Adobe: `did:web:connected-identities.identity(-stage).adobe.com:user:<hex>`; c2pa-rs synthetic: absent | RFC 3986 URI: pass |
| `credentialSchema` | Adobe: `[{"id": "https://cawg.io/identity/1.1/ica/schema/", "type": "JSONSchema"}]` | pass V-26 |
| `validFrom` / `validUntil` | `...Z`, some with 6-digit fractions, from `1900-01-01T12:00:00Z` to `2200-01-01T12:00:00Z`; one fixture omits `validFrom` | pass V-21; the missing one stays `valid_from.missing` |
| `credentialStatus`, `evidence`, `termsOfUse`, `refreshService`, `relatedResource`, `proof`, `name`, `description` | absent in all | n/a |
| issuer | `did:jwk:...`, `did:web:...`, and deliberately bad `not-did:jwk:...` and `did:example:...` | the bad two keep their current codes |

Expected corpus effect: none. The CLI corpus gates (`crates/encypher-c2pa-cli/tests/cawg_corpus.rs`) are the proof, and they run unchanged.

Comparison with c2pa-rs (`sdk/src/identity/claim_aggregation/w3c_vc/credential.rs`, the implementation behind the fixtures): it parses VC 2.0 only. It types `@context` as `NEVec<IriBuf>`, so it rejects object contexts, which this PRD accepts. It requires `id: UriBuf`, string `type` members, and a URI-string `issuer` (no object form). It reads `validFrom`/`validUntil` through chrono RFC 3339. It does not check context order or `credentialStatus` structure. This verifier stays at least as strict as c2pa-rs everywhere except object contexts and object issuers, which the VC text allows.

## Out of scope

- JSON-LD expansion, canonicalization, and dereferencing unknown contexts (decision above).
- Bitstring Status List entry fields beyond the VC `type`/`id` rules. The status-list work owns them.
- The retained commercial kernel. TECH-A-004 names both validator repositories, so the matrix row stays `partial` for the retained validator.

## Verification

`cargo test -p encypher-c2pa cawg_ica`, then `cargo test -p encypher-c2pa-cli --test cawg_corpus`, run by the builder on the changed code only. The lead runs the global gates.
