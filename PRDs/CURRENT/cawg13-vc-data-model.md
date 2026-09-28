# CAWG Identity 1.3 ICA: W3C VC Data Model Conformance (TEAM_467)

**Status:** plan gate, cycle 2 (cycle 1 failed; see "Cycle 1 findings and resolutions")
**Base:** `feat/cawg13-ica-conformance` at `34619e9` (TEAM_462, PR #28; code identical to `284ff58`)
**Branch:** `feat/cawg13-vc-data-model`
**Current Goal:** close CAWG-ID13-ICA-TECH-A-004 in the public verifier, for credentials whose contexts the verifier understands. For those credentials, `cawg_ica.rs` checks every W3C Verifiable Credentials Data Model requirement (v1.1 and v2.0, both admitted by CAWG Identity 1.3) that an identity-claims-aggregation validator can check on the credential it receives. Each rule is defended by a test that signs a credential breaking that one rule. A credential with a context the verifier does not understand fails closed with a documented reason. TECH-A-004 is not claimed for such credentials.

## Overview

TECH-A-004 says an ICA "MUST meet all requirements for a verifiable credential as described in the W3C Verifiable credentials data model (either version 1.1 or version 2.0)". VC 2.0 section 1.3 makes that a verifier duty: a conforming verifier "MUST check that each required property satisfies the normative requirements for that property, and MUST produce errors when non-conforming documents are detected". VC 1.1 section 1.4 says: "Conforming processors MUST produce errors when non-conforming documents are consumed."

At the base commit, `parse_ica_credential` checks a hand-picked subset: context order and membership, `type` strings, the issuer by way of the DID, one credential subject, and date parsing through RFC 3339. It also rejects object-valued `@context` entries, which both VC versions allow. This PRD enumerates the normative statements of both specifications, classifies each one, and specifies the checks that close the gap.

Sources read: VC Data Model 2.0 (W3C Recommendation, 2025-05-15) and VC Data Model 1.1 (W3C Recommendation, 2022-03-03), every MUST/REQUIRED/MUST NOT statement in each; VC Data Integrity 1.0 section 2.6 (`digestMultibase`); JSON-LD 1.1 section 9.15 (context definitions); XML Schema 1.1 Part 2 `dateTime`/`dateTimeStamp`; CAWG Identity 1.3 (`cawg-identity-assertion` `8851770`, the peeled `v1.3` tag), ICA technical description and validating procedure; the three context documents pinned below.

## Context model: pinned contexts, no expansion, fail closed

**Decision.** The verifier does VC 2.0 section 6.3 "type-specific credential processing". It understands exactly three contexts, each pinned by the SHA-256 of its served bytes. It never retrieves a context, performs no JSON-LD expansion, and fails closed on any context URL outside the pinned set.

### Pinned contexts

| URL | SHA-256 of pinned bytes | Source of the digest |
|---|---|---|
| `https://www.w3.org/2018/credentials/v1` | `ab4ddd9a531758807a79a5b450510d61ae8d147eab966cc9a200c07095b0cdcc` | VC 1.1 appendix B.1; matches the served bytes |
| `https://www.w3.org/ns/credentials/v2` | `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734` | VC 2.0 appendix B.1; matches the served bytes |
| `https://cawg.io/identity/1.1/ica/context/` | `750c94af1c3d7e587dc19f3a06ef1e9bfe8412a1e94ef15037ae83f3baeb82e9` | served bytes, fetched 2026-09-28 |

The three documents are vendored byte-for-byte under `crates/encypher-c2pa/src/c2pa-validate/contexts/`, with their license notices: the W3C Software and Document License for the VC contexts, and Apache-2.0 for the CAWG context under the repository's `license.md`. A unit test asserts each digest. The term data the verifier needs is derived from the vendored bytes at first use, so the pinned documents are the single source for the protected-term set.

**The two CAWG context versions.** The CAWG v1.3 tag's `docs/modules/ROOT/attachments/ica/context/index.json` has SHA-256 `9763ec56f4e1b3aabb69685b5d48e8475a6f6038f4bf40e1684e649c8761b064`. It defines 15 terms: `address`, `c2paAsset`, `cawg`, `method`, `name`, `provider`, `referenced_assertions`, `role`, `schema`, `sig_type`, `uri`, `username`, `verifiedAt`, `verifiedIdentities`, and `xsd`. The served document (`750c94af...`) defines those 15 plus `expected_partial_claim`, `expected_claim_generator`, and `expected_countersigners`. The verifier reads `verifiedIdentities` and, within each entry, `name`, `username`, `uri`, `provider`, `verifiedAt`, `method`, and `address`. It compares `c2paAsset` byte-exactly to `signer_payload`, whose keys are `referenced_assertions`, `sig_type`, `role`, and, when present, the three `expected_*` fields. The served bytes define every one of these terms. The tag attachment lacks the three `expected_*` terms. That is why the served bytes are pinned. Neither document defines `IdentityClaimsAggregationCredential`, and neither VC base context declares `@vocab` (VC 2.0 appendix E: "Removed @vocab from the base context"). The type, and every `verifiedIdentities[].type` value, resolves only through the CAWG context's `@vocab` (`https://www.w3.org/ns/credentials/examples#`).

### Unknown context URLs fail closed

Any `@context` URL outside the pinned set yields `cawg.ica.invalid_verifiable_credential` with `details: {"reason": "unsupported_context", "contexts": [<each unknown URL>]}`, and validation stops.

Why this code: CAWG "Parse the verifiable credential" requires the validator to parse the credential under VC section 6, "Syntaxes". If it "is unable to parse the credential using either version", it "MUST stop validation at this point and issue the failure code `cawg.ica.invalid_verifiable_credential`". Under section 6.3, a type-specific processor accepts only "specific @context values which the implementation is engineered ahead of time to understand". Section 4.3 requires understanding every context "to the extent that it affects the meaning of the terms used". An unretrieved context can redefine every unprotected CAWG term, because the CAWG context sets no `@protected`. A COSE signature binds the URL string, not the resource. A validator that has not retrieved the context therefore cannot parse such a credential with known semantics. The registered code is the one CAWG assigns to that outcome. `details.reason` tells it apart from a malformed credential, so a relying party can fetch and pin the context and re-run. An informational `com.encypher.*` code was rejected: CAWG requires `cawg.ica.credential_valid` whenever no failure code is issued, so withholding success needs a failure code.

Interop count: 0 of the 24 real ICA credentials extracted from the vectors (Interop evidence below) carries a context outside the pinned set. All 24 use exactly `[v2, CAWG ICA]`.

### What is lost without expansion

| Needs JSON-LD or retrieval | Handling |
|---|---|
| Meaning of an unknown context URL | Fail closed (above). TECH-A-004 is not claimed. |
| Inline context features outside the supported profile (below) | Rejected with the malformed explanation. The explanation is labeled "outside the supported inline-context profile", so it is not presented as a VC syntax error. |
| Expansion errors (VC 2.0 B.1: "If such operations are performed and result in an error ... MUST result in a verification failure") | Conditional on performing expansion. None is performed, and the profile excludes the constructs whose errors cannot be predicted locally. |
| Verifying an embedded Data Integrity `proof` (RDF canonicalization) | Not verified and not relied on. CAWG secures the ICA with the COSE_Sign1 envelope (VC-JOSE-COSE), which is verified. `proof` objects get the structural check in V-35. |

### Supported inline-context profile (V-04, V-07)

An object item in `@context` is accepted when it meets **all** of the following. **(S)** marks full local JSON-LD 1.1 syntax, which a JSON-LD processor would also reject. **(P)** marks a supported-profile limitation of this verifier, which is not a VC syntax error.

1. **(S) Context-definition keywords.** `@version` is the number `1.1`. `@base` is a string or null. `@language` is a string or null. `@direction` is `"ltr"`, `"rtl"`, or null. `@protected` and `@propagate` are booleans. `@type` is an object whose only keys are `@container: "@set"` and an optional boolean `@protected`. Any other JSON-LD keyword used as a key (`@id`, `@context`, `@graph`, and so on) is a keyword redefinition. A key of keyword form that is not a keyword (`@foo`) is ignored, as JSON-LD ignores it.
2. **(S) Term definitions.** A term's value is null, a string, or an expanded term definition. A string or `@id` value is a keyword, a term, a compact IRI, or an absolute IRI; it is never a number or other non-string. An expanded term definition may contain only `@id`, `@reverse`, `@type`, `@language`, `@direction`, `@container`, `@context`, `@nest`, `@prefix`, `@propagate`, `@protected`, and `@index`, with JSON-LD 1.1's value types. `@id` is a string or null. `@reverse` is a string and excludes `@id` and `@nest`. `@type` is `@id`, `@json`, `@none`, `@vocab`, or an IRI or term. `@container` is one of, or an array of, `@list`, `@set`, `@language`, `@index`, `@id`, `@graph`, and `@type`. `@prefix`, `@propagate`, and `@protected` are booleans. `@nest` and `@index` are strings.
3. **(P) `@import`** is rejected. It loads a remote context this verifier does not retrieve.
4. **(P) `@vocab`** (including null) is rejected in an item that follows the CAWG context URL. `IdentityClaimsAggregationCredential`, every `verifiedIdentities[].type` value, and every `role` value resolve through CAWG's `@vocab`, so a later `@vocab` changes their IRIs. A `@vocab` placed before the CAWG context is overridden by it and is accepted.
5. **(P) Protected terms.** A term defined anywhere in the three pinned documents, or read through CAWG's `@vocab` (`IdentityClaimsAggregationCredential`, the credential's `verifiedIdentities[].type` values, and `c2paAsset.role` values), may be defined inline only when its definition is JSON-identical to a definition of that term in a pinned document. This is JSON-LD's protected-term rule, applied to every term the verifier depends on, whether or not the pinned context protects it. Example: `{"id": "@id"}` is accepted.
6. **(P) Scoped contexts.** A term definition carrying `@context` is accepted only when the term is not protected under rule 5 and does not appear as a `type` value of the credential, its subject, or its status entries. A property-scoped context on an extension term then affects only that term's values, which the verifier does not read. Such a scoped context is validated recursively under rules 1 to 3. A string (remote) scoped context is rejected under rule 3.
7. **(S for VC 2.0, P for VC 1.1) Embedded contexts.** An `@context` key anywhere below the top level of the credential is rejected. JSON-LD compaction emits `@context` only at the top level, so under VC 2.0 section 6.1 this is a compacted-form error.

## Requirement table

Legend: **Checked** means the rule is enforced after this PRD (**existing**: already enforced; **new**: added here). **JSON-LD** means it cannot be checked without JSON-LD processing; the decision is given. **N/A** means the rule binds issuers, holders, presentations, or specification authors, not a validator of a received credential. Every "Checked" failure reports `cawg.ica.invalid_verifiable_credential` with an explanation naming the property, unless a CAWG code is named. CAWG requires that code for an unparseable credential, and VC 2.0 section 7.1 maps a non-conforming document to `MALFORMED_VALUE_ERROR`.

**Identifier datatypes (V-11 and every "URL" below).** VC 2.0 uses the WHATWG URL Standard. The check is `url::Url::parse` with a syntax-violation callback, and any reported violation fails it. This approximates the Standard's "valid URL string", so `https://example.org/café` is accepted and `http:` (no host) is rejected. VC 1.1 and CAWG say "URI". There the check is the existing RFC 3986 `is_uri` (ASCII). The VC version is selected by `@context[0]`.

### Contexts

| ID | Requirement (VC 2.0 / VC 1.1) | Class | How |
|---|---|---|---|
| V-01 | Credential MUST include `@context` (2.0 4.3; 1.1 4.1) | Checked (existing) | Missing or not an array is rejected. |
| V-02 | First item MUST be the base context URL (2.0 4.3; 1.1 4.1). JSON-based processors MUST ensure the expected values are in the expected order (1.1 5.3) | Checked (existing, TEAM_462) | `contexts[0]` selects `2.0` or `1.1`. The CAWG URL must be present. |
| V-03 | Subsequent items are "any combination of URLs and objects" (2.0 4.3), or "URIs or objects" (1.1 4.1) | Checked (**new**) | **Fixes the TEAM_462 over-rejection:** object items are accepted under the profile above. A string item must be a URL (2.0) or URI (1.1), and a pinned one. Any other value, null included, is rejected. |
| V-04 | Each object item is "processable as a JSON-LD Context" (2.0 4.3) | Checked (**new**) | Profile rules 1 and 2 (S). |
| V-05 | `@context` is an ordered set (2.0 4.3), so no item repeats | Checked (**new**) | A repeated string item is rejected. |
| V-06 | Exactly one base context. CAWG TECH-A-005: the v1 URL "_or_" the v2 URL, "depending on which version ... is being used" | Checked (**new**) | A credential listing both is rejected. |
| V-07 | Developers MUST understand every context affecting the terms they use (2.0 4.3). JSON-LD processors MUST error on protected-term redefinition (1.1 5.3) | Checked (**new**) | Unknown URLs fail closed with `unsupported_context`. Inline items follow profile rules 3 to 7. |
| V-08 | Base context treated as already retrieved; digest published (2.0 B.1; 1.1 B.1) | Checked (**new**, by construction) | Vendored bytes are pinned by digest; nothing is fetched. |
| V-09 | `undefined-terms/v2` MUST be the last item when terms are undefined (2.0 5.2) | N/A under the profile | CAWG's `@vocab` maps every otherwise-undefined term. Profile rule 4 forbids resetting it after the CAWG item. A credential that lists `undefined-terms/v2` fails closed as an unpinned context. |
| V-10 | Expansion errors MUST fail verification "if such operations are performed" (2.0 B.1) | JSON-LD | Not performed (see "What is lost"). |

### Identifiers and types

| ID | Requirement | Class | How |
|---|---|---|---|
| V-11 | `id`, if present, MUST be a single URL (2.0 4.4) or a single URI (1.1 4.2, 6) | Checked (**new**) | Checked on the credential, the credential subject, and each `credentialStatus`, `credentialSchema`, `evidence`, `termsOfUse`, `refreshService`, and `relatedResource` object, using the version's datatype. |
| V-12 | `type` MUST be present (2.0 4.5; 1.1 4.3) | Checked (existing) | |
| V-13 | `type` values MUST be "terms and absolute URL strings" (2.0 4.5); they "be, or map to ... URIs" (1.1 4.3) | Checked (existing: strings; **new**: form) | Each member is a non-empty string and not an `@` keyword. A member containing `:` must be a URL (2.0) or URI (1.1); a compact IRI such as `cawg:Foo` also parses as one. A member without `:` is a term, which the CAWG context's `@vocab` maps, since profile rule 4 keeps that mapping in force. |
| V-14 | The credential's type includes `VerifiableCredential` (2.0 4.5; 1.1 4.3) and a narrower type (1.1 MUST, 2.0 SHOULD) | Checked (existing, TECH-A-006) | Both ICA types are required. |
| V-15 | `credentialStatus`, `termsOfUse`, `evidence`, `refreshService`, and `credentialSchema` objects MUST have a type (2.0 4.5 table; 1.1 4.3 table, which also lists `proof`) | Checked (**new**) | See V-24 to V-35. Each `type` meets V-13. |

### Names, issuer, subject

| ID | Requirement | Class | How |
|---|---|---|---|
| V-16 | Credential-level `name` and `description`, if present, MUST be a string or a language value object (2.0 4.6), or an array of them (2.0 11.1) | Checked (**new**; top-level only, VC 2.0 only) | Nested `name` fields are out of scope. The CAWG `provider.name` natural-language map keeps its own CAWG rule. VC 1.1 does not define these properties. |
| V-17 | A language value object MUST have a string `@value`, MUST NOT have keys beyond `@value`, `@language`, and `@direction`, and `@direction` is a base direction (2.0 11.1) | Checked (**new**) | `@language` BCP 47 well-formedness is a SHOULD and is not enforced; a non-string `@language` is rejected. |
| V-18 | `issuer` MUST be present and be a URL or an object with an `id` URL (2.0 4.7); a URI or object with `id` (1.1 4.5) | Checked (existing, **new** datatype) | CAWG routes this case to `cawg.ica.invalid_issuer` ("not a DID"). A DID-shaped string that fails the version's datatype, such as one with a space, is now `cawg.ica.invalid_issuer` followed by `cawg.ica.untrusted_issuer`. Before, it went on to resolution and reported `cawg.ica.invalid_did_document`. |
| V-19 | `credentialSubject` MUST be present: a set of objects, each the subject of one or more claims (2.0 4.8; 1.1 4.4) | Checked (existing) | An object or an array holding one object. More than one subject is rejected. This is CAWG policy, not a VC rule: the ICA's one subject carries `c2paAsset` and `verifiedIdentities`. |
| V-20 | Subject `id`, if present, is a URL (2.0) or URI (1.1) | Checked (**new**) | As V-11. |

### Validity

| ID | Requirement | Class | How |
|---|---|---|---|
| V-21 | `validFrom` and `validUntil`, if present, MUST be an XML Schema `dateTimeStamp` (2.0 4.9) | Checked (**new**, strict) | An XSD 1.1 lexical parser replaces RFC 3339. It requires `T`, then `Z` or an offset within `±14:00`; seconds 00-59; `24:00:00` (fraction all zeros) is the next day's midnight. The year is `-?` followed by four or more digits, with no leading zero beyond four digits, and is unbounded (see V-45). The previous parser accepted any separator byte, lowercase `z`, offsets to `±23:59`, and second `60`. A present JSON `null` is malformed, since only an absent property is "not present" and compaction never emits null. Failures report `cawg.ica.valid_from.invalid` and `cawg.ica.valid_until.invalid`. |
| V-22 | `validFrom` MUST be at or before `validUntil` (2.0 4.9) | Checked (**new**) | Reported as `cawg.ica.valid_until.invalid` with the explanation "earlier than its effective date", at any validation time. |
| V-23 | VC 1.1 `issuanceDate` MUST exist and be an XSD `dateTime`; `expirationDate`, if present, an XSD `dateTime` (1.1 4.6, 4.8) | Checked (existing: presence; **new**: form) | An XSD `dateTime` makes the zone optional. A zoneless value was wrongly rejected as malformed before. VC 1.1 has no UTC rule, and XSD 1.1 (section 3.3.7, order relation) orders a zoneless value only partially against zoned instants, within ±14:00. The verifier reads it at the end of that range that can only reject more: the effective date at local+14 h (latest), the expiration at local-14 h (earliest). One extra branch buys the XSD semantics; UTC would accept a credential XSD calls not-yet-valid. |
| V-24a | VC 2.0 5.8: "Time values that are incorrectly serialized without an offset MUST be interpreted as UTC" | Checked (**new**) | A zoneless VC 2.0 `validFrom` or `validUntil` breaks V-21 (4.9 requires `dateTimeStamp`), so an error is produced. The value is interpreted as UTC, and the explanation says so ("lacks a time zone; read as UTC ... a dateTimeStamp is required"). The failure code does not depend on that interpretation. |
| V-45 | XSD value space: years beyond 9999 and before 0000, and fractional seconds to any precision | Checked (**new**) | Values are compared as exact nanoseconds since the epoch (`i128`), from a proleptic-Gregorian day count, instead of `OffsetDateTime`. Validation times convert exactly. A year with more than 18 digits saturates to `±10^18` years, which preserves its order against every representable validation time. Fractions beyond 9 digits round toward rejection: an effective date rounds up, an expiration date rounds down. |

### Status, schema, and extension properties

| ID | Requirement | Class | How |
|---|---|---|---|
| V-24 | `credentialStatus`, if present, is one object or a set of objects, each with a REQUIRED `type` and an optional URL `id` (2.0 4.10) | Checked (**new**) | A non-object entry or a missing type now reports `cawg.ica.invalid_verifiable_credential`. Before, the verifier skipped the entry and reported `cawg.ica.revocation.unsupported`. |
| V-25 | 1.1: `credentialStatus` MUST include an `id` URI and a `type` (1.1 4.9) | Checked (**new**) | |
| V-26 | `credentialSchema`: one or more objects, each with a `type` and an `id` URL/URI (2.0 4.11; 1.1 5.4) | Checked (**new**) | Structure only. TEAM_462 row 7 records schema evaluation, a CAWG RECOMMENDED step, as not performed. No VC MUST requires evaluation. |
| V-27 | `refreshService`: one or more, each with a type (2.0 5.4); 1.1 also requires an `id` URI (1.1 5.5) | Checked (**new**) | |
| V-28 | `termsOfUse`: one or more policies, each with a type (2.0 5.5; 1.1 5.6) | Checked (**new**) | |
| V-29 | `evidence`: one object or a set, each with a REQUIRED `type` and an optional `id` (2.0 5.6; 1.1 5.7) | Checked (**new**) | |
| V-30 | `relatedResource`: one or more objects; `id` REQUIRED, a URL, unique in the list; at least one of `digestSRI` and `digestMultibase` (2.0 5.3) | Checked (**new**) | `digestSRI` is a string or a non-empty array of SRI `hash-expression`s: `sha256`, `sha384`, or `sha512`, then `-`, then base64 (with `+/` or `-_`, at most two `=`), then an optional `?` option-expression of visible ASCII. `digestMultibase` is a string or a non-empty array (Data Integrity 2.6: "a single string value, or an list of string values, each of which is a Multibase-encoded Multihash value"). Each value is decoded locally: the multibase prefixes `z` (base58btc), `u`/`U` (base64url), `m`/`M` (base64), `f`/`F` (base16), and `b`/`B` (base32) are supported, and any other prefix is profile (P). The multihash must hold a minimal unsigned-varint code, a varint length equal to the remaining bytes, and the registered length for sha2-256 (`0x12`, 32), sha2-384 (`0x20`, 48), and sha2-512 (`0x13`, 64). |
| V-31 | A verifier that "makes use of a resource based on the id of a relatedResource object" MUST compute its digest and error on mismatch (2.0 5.3) | Checked (**new**) for the pinned contexts; N/A otherwise | The verifier makes use of exactly three resources, the pinned contexts. When a `relatedResource.id` equals a pinned URL, every digest given is computed over the vendored bytes and must match: SHA-256/384/512 for SRI, and multihash codes `0x12`/`0x20`/`0x13`. A digest in an algorithm the verifier cannot compute is a mismatch (fail closed). Other ids are never retrieved. |
| V-32 | Reserved `confidenceMethod` and `renderMethod` values MUST specify a `type` (2.0 5.10) | Checked (**new**, VC 2.0) | |

### Securing and syntax

| ID | Requirement | Class | How |
|---|---|---|---|
| V-33 | Secured by at least one securing mechanism, and the verifier MUST perform verification (2.0 1.3, 4.12, 7.1). A proof mechanism MUST be expressed (1.1 4.7) | Checked (existing) | COSE_Sign1 is verified against the issuer DID key (`cawg.ica.signature_mismatch`). |
| V-34 | Media type `application/vc` (2.0 1.3) | Checked (existing) | `cawg.ica.invalid_content_type`. |
| V-35 | An embedded `proof` MUST give its method in `type` (1.1 4.7; Data Integrity 1.0) | Checked (**new**, structure) | The proof itself is not verified ("What is lost"). |
| V-36 | JSON-LD compacted form MUST be used for `application/vc` (2.0 6.1) | Checked (**new**, VC 2.0) | A top-level `@id` or `@type` is rejected, and so is an embedded `@context` (profile rule 7). |
| V-37 | JSON value mapping: "Other values MUST be represented as a String" (1.1 6.1); single-valued `id`, `issuer`, and dates (1.1 6) | Checked (subsumed) | The per-property rules above. |
| V-38 | Verification returns a conforming document, or `MALFORMED_VALUE_ERROR` (2.0 7.1) | Checked | Mapped to `cawg.ica.invalid_verifiable_credential`. CAWG makes problem details a MAY. |

### Not applicable

| ID | Requirement | Why |
|---|---|---|
| V-39 | Presentations, `holder`, and enveloped VC/VP objects (2.0 4.13; 1.1 4.10) | An ICA is a credential. |
| V-40 | Zero-knowledge proof rules (2.0 5.7; 1.1 5.8) | Issuer and holder mechanics. |
| V-41 | JWT encoding and decoding (1.1 6.3.1) | The ICA is enveloped in COSE. |
| V-42 | Rules for vocabulary authors, ecosystem transformations, and securing-mechanism and status-list specification authors (2.0 5.2, 5.11, 5.13, 4.10 privacy MUST NOT; 1.1 1.4 serialization determinism) | These bind specification authors. |
| V-43 | Issuer MUSTs: include required properties, secure the document (2.0 1.3) | Issuer duties, mirrored by V-12, V-18, V-19, and V-33. |
| V-44 | SHOULDs: avoid `@vocab`, serialize times as `dateTimeStamp`, use BCP 47 language tags (2.0 5.2, 5.8, 11.1) | Not MUSTs. The 5.8 MUST is V-24a. |

## Implementation

- New module `crates/encypher-c2pa/src/c2pa-validate/vc_data_model.rs` holds the VC data-model checks. It contains the pinned contexts (`include_bytes!` of the vendored files; term data derived once in a `OnceLock`), the profile validator, the URL/URI datatype predicates, the typed-object and language-value checks, `relatedResource` with the SRI, multibase, and multihash decoders and the pinned-digest comparison, and the XSD date parser returning exact nanoseconds. `cawg_ica.rs` stays the orchestration point. It reuses `is_uri` (made `pub(super)`) and `base64_decode`.
- `parse_ica_credential` returns `Result<IcaCredential, CredentialDefect>`, where `CredentialDefect` is `Malformed(&'static str)` or `UnsupportedContext(Vec<String>)`. The first reports `cawg.ica.invalid_verifiable_credential` as today. The second reports it with `details.reason = "unsupported_context"` and `details.contexts`.
- `ValidityField` becomes `Missing | Malformed(&'static str) | Parsed(i128)`, comparing against `OffsetDateTime::unix_timestamp_nanos()`.
- New direct dependency: `url = "2"` (WHATWG URL; already in `Cargo.lock` through the optional `ureq`). Its effect on the browser WASM package size (gzip, before and after) and on `--no-default-features` builds is reported in the completion packet.
- `docs/REPORT_SCHEMA.md` documents `details.reason`/`details.contexts`. `CHANGELOG.md` records every behavior change.

## Tests (TDD)

Each negative case is a complete credential, edited to break one rule and signed by the trusted `did:jwk` issuer (`validate_edited` / `validate_dates`). The signature, trust, and identity checks pass, so the named code is the only failure. The table-driven tests, grouped by property family, are:

- **Contexts.** Unknown URL, with `details.reason` and `details.contexts` asserted; non-URL string; null; number; repeat; both base contexts.
- **Inline-context syntax (S).** Numeric `@id` in a term definition; `@version: 1.0`; bad `@direction`; keyword redefinition; an unknown key in an expanded term definition; bad `@container`; `@reverse` together with `@id`.
- **Inline-context profile (P), rejection.** `@vocab` replaced after CAWG; `@vocab: null` after CAWG; `@import`; a non-identical redefinition of a VC term, a CAWG term, and `IdentityClaimsAggregationCredential`; a type-scoped context on a type the credential uses; a string scoped context; `@context` embedded in `credentialSubject` and in a `verifiedIdentities` entry.
- **Inline-context profile, acceptance.** `{"id": "@id"}` (identical to pinned); a `@vocab` placed before the CAWG URL; a property-scoped context on an unused extension term; extension term and type definitions.
- **Identifiers and types.** VC 2.0 `https://example.org/café` accepted and `http:` rejected; a VC 1.1 non-ASCII id rejected as a URI; `id` with two values; bad subject id; empty, keyword, and non-URL type members; top-level `@id`/`@type` (VC 2.0).
- **Names.** Number, empty array, non-string member, missing or non-string `@value`, extra key, bad `@direction`.
- **Status, schema, and extensions.** Every row V-24 to V-32 and V-35, including `digestSRI` as an array, an unsupported multibase prefix, a malformed base58 string, a truncated multihash, and a wrong sha2-256 length. A `relatedResource` for the v2 context URL with the correct B.1 digest is accepted; the same entry with a wrong digest is rejected.
- **Dates.** Space separator, lowercase `t`/`z`, `+15:00`, second `60`, `24:00:01`, zoneless VC 2.0 (UTC explanation asserted), and `null`. Also: `24:00:00` equality at the validation instant; `+14:00` accepted; year `10000` accepted as a future `validUntil`; year `-0001` accepted as a past `validFrom`; `9999-12-31T24:00:00Z` rollover; a 12-digit fraction rounded toward rejection at both bounds; `validFrom` after `validUntil`; and VC 1.1 zoneless dates in both directions, each 1 s inside and 1 s outside the ±14 h bound.

Positive coverage: one VC 2.0 credential uses every optional property in conforming form, including an accepted inline context object. This is the regression for the TEAM_462 object-context rejection. The existing VC 1.1 tests keep passing.

## Interop evidence

Every ICA credential payload was extracted from the vectors:

- 23 in the public corpus `tests/vectors/cawg`: 22 c2pa-rs `d7f13829` fixtures (20 synthetic `did:jwk`/`did:web` credentials and 2 Adobe stage), and the c2pa-cpp `C_with_CAWG_data.jpg` Adobe production credential.
- 1 more in the commercial `packages/encypher-c2pa/tests/vectors/cawg`: the contributed Adobe production credential `adobe-cai-prod-ica-es-266-1236.jpg`. It is not redistributable, so the public corpus gate does not run it.

| Property | Values seen | Effect |
|---|---|---|
| `@context` | always exactly `[v2 base, CAWG ICA]` | pass; 0 unsupported contexts |
| `type` | always `[VerifiableCredential, IdentityClaimsAggregationCredential]` | pass |
| top-level `id` | absent in all | n/a |
| `credentialSubject.id` | Adobe: `did:web:connected-identities.identity(-stage).adobe.com:user:<hex>`; c2pa-rs synthetic: absent | valid URL: pass |
| `credentialSchema` | Adobe: `[{"id": "https://cawg.io/identity/1.1/ica/schema/", "type": "JSONSchema"}]` | pass V-26 |
| `validFrom` / `validUntil` | `...Z`, some with 6-digit fractions, from `1900-01-01T12:00:00Z` to `2200-01-01T12:00:00Z`; one fixture omits `validFrom` | pass V-21; the missing one stays `valid_from.missing` |
| `credentialStatus`, `evidence`, `termsOfUse`, `refreshService`, `relatedResource`, `proof`, `name`, `description` | absent in all | n/a |
| issuer | `did:jwk:...`, `did:web:...`, and deliberately bad `not-did:jwk:...` and `did:example:...` | all pass the URL datatype; the bad two keep their codes |

Verification of that evidence:

1. The public CLI corpus gate (`crates/encypher-c2pa-cli/tests/cawg_corpus.rs`) must pass unchanged.
2. A private smoke run of the changed public CLI against the contributed Adobe credential (`--time 2026-08-05T00:00:00Z`, pinned Adobe DID document) must give byte-identical JSON reports before and after the change. The cycle 1 draft produced identical reports. Its CAWG code set is `cawg.ica.invalid_did_document`, `cawg.ica.signer_payload.mismatch`, and `cawg.ica.untrusted_issuer`, all pre-existing and outside this PRD. That outcome gets re-run and recorded in the completion packet.

Comparison with c2pa-rs (`sdk/src/identity/claim_aggregation/w3c_vc/credential.rs`, the implementation behind the fixtures):

- It parses VC 2.0 only.
- It types `@context` as `NEVec<IriBuf>`, so it rejects object contexts, and it does not check that the v2 URL comes first.
- It has `id: Option<UriBuf>`, so `id` is optional and a URI when present.
- It requires string `type` members and a URI-string `issuer`; the object form is rejected.
- It reads `validFrom`/`validUntil` through chrono `DateTime<FixedOffset>` (RFC 3339).
- It does not check `credentialStatus` structure.

This verifier is at least as strict everywhere except three deliberate relaxations, each allowed by the VC text: object contexts under the profile, object issuers, and `24:00:00`.

## Cycle 1 findings and resolutions

| Finding (reviewer) | Resolution |
|---|---|
| Unknown context URLs accepted without understood semantics (Astra high, ThinkOpenAI high, Opus low) | Pinned-context model; unknown URL fails closed with `unsupported_context`; TECH-A-004 not claimed for them |
| Inline guard bypassable by `@vocab`/`@vocab: null`, `@import`, embedded `@context`; accepts `{"x":{"@id":42}}`; rejects identical `{"id":"@id"}` (all three) | Supported inline-context profile rules 1 to 7, with acceptance and rejection tests at each boundary |
| False claim that the VC v2 base context declares `@vocab` (Opus medium, Astra) | Corrected: only the CAWG context does (VC 2.0 appendix E); V-09 and V-13 now rest on profile rule 4 |
| RFC 3986 used for VC 2.0 URLs (Astra, ThinkOpenAI) | Version-specific datatypes; `url` crate for VC 2.0 |
| `digestMultibase` only non-empty; `digestSRI` single string only (Astra, ThinkOpenAI, Opus) | Local multibase and multihash decoding; SRI string or array |
| V-31 N/A although the base context is "made use of" (Opus) | Pinned-context `relatedResource` digests are checked |
| VC 2.0 5.8 zoneless-UTC MUST missing (Opus, ThinkOpenAI) | V-24a |
| ±14 h rule unexplained; no negative zoneless tests; fraction rounding unstated; `null` treated as absent (Opus, ThinkOpenAI) | V-23, V-45, V-21 wording; both-direction tests |
| Year range 0000-9999 rejects valid XSD values (Astra, ThinkOpenAI) | V-45: exact `i128` nanoseconds, unbounded lexical years |
| c2pa-rs comparison errors; VC 1.1 section numbers off by one (Opus) | Corrected (1.4, 5.5, 5.6, 5.7, 5.8) |
| V-16/V-36 scope implicit (Opus) | V-16 top-level VC 2.0 only; V-36 VC 2.0 only |
| Protected-term list hand-written (Opus) | Derived from the vendored pinned documents |
| Adobe contributed vector not exercised (Opus, ThinkOpenAI) | Private before/after smoke run, recorded in the packet |

## Out of scope

- JSON-LD expansion, canonicalization, and retrieving contexts.
- Bitstring Status List entry fields beyond the VC `type`/`id` rules. The status-list work owns them.
- The retained commercial kernel. TECH-A-004 names both validator repositories, so the matrix row stays `partial` for the retained validator.

## Verification

`cargo test -p encypher-c2pa`, `cargo test -p encypher-c2pa-cli --test cawg_corpus`, a `--no-default-features` build of `encypher-c2pa`, the WASM package size (gzip, before and after), and the private Adobe smoke run. The lead runs the global gates.
