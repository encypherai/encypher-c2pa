# CAWG Identity 1.3 ICA: W3C VC Data Model Conformance (TEAM_467)

**Status:** plan gate, cycle 4 (cycles 1 to 3 failed; see "Gate findings and resolutions")
**Base:** `feat/cawg13-ica-conformance` at `34619e9` (TEAM_462, PR #28; code identical to `284ff58`)
**Branch:** `feat/cawg13-vc-data-model`
**Current Goal:** close CAWG-ID13-ICA-TECH-A-004 in the public verifier, for credentials whose contexts the verifier understands. For those credentials, `cawg_ica.rs` checks every W3C Verifiable Credentials Data Model requirement (v1.1 and v2.0, both admitted by CAWG Identity 1.3) that an identity-claims-aggregation validator can check on the credential it receives. Each rule is defended by a test that signs a credential breaking that one rule. A credential with a context the verifier does not understand fails closed with a documented reason. TECH-A-004 is not claimed for such credentials.

## Overview

TECH-A-004 says an ICA "MUST meet all requirements for a verifiable credential as described in the W3C Verifiable credentials data model (either version 1.1 or version 2.0)". VC 2.0 section 1.3 makes that a verifier duty: a conforming verifier "MUST check that each required property satisfies the normative requirements for that property, and MUST produce errors when non-conforming documents are detected". VC 1.1 section 1.4 says: "Conforming processors MUST produce errors when non-conforming documents are consumed."

At the base commit, `parse_ica_credential` checks a hand-picked subset: context order and membership, `type` strings, the issuer by way of the DID, one credential subject, and date parsing through RFC 3339. It also rejects object-valued `@context` entries, which both VC versions allow. This PRD enumerates the normative statements of both specifications, classifies each one, and specifies the checks that close the gap.

Sources read: VC Data Model 2.0 (W3C Recommendation, 2025-05-15) and VC Data Model 1.1 (W3C Recommendation, 2022-03-03), every MUST/REQUIRED/MUST NOT statement in each; VC Data Integrity 1.0 section 2.6 (`digestMultibase`); JSON-LD 1.1 section 9.15 (context definitions); XML Schema 1.1 Part 2 `dateTime`/`dateTimeStamp`; CAWG Identity 1.3 (`cawg-identity-assertion` `8851770`, the peeled `v1.3` tag), ICA technical description and validating procedure; the three context documents pinned below.

## Context model: pinned contexts, no expansion, fail closed

**Decision.** The verifier does VC 2.0 section 6.3 "type-specific credential processing". It understands exactly three contexts, each pinned by the SHA-256 of its served bytes. It never retrieves a context and performs no JSON-LD expansion. The supported profile is narrow: `@context` must list only pinned URLs. In practice that means `[VC base, CAWG ICA]`, since the base context must come first (V-02), items may not repeat (V-05), and only one base context is allowed (V-06). Anything else fails closed.

### Pinned contexts

| URL | SHA-256 of pinned bytes | Source of the digest |
|---|---|---|
| `https://www.w3.org/2018/credentials/v1` | `ab4ddd9a531758807a79a5b450510d61ae8d147eab966cc9a200c07095b0cdcc` | VC 1.1 appendix B.1; matches the served bytes |
| `https://www.w3.org/ns/credentials/v2` | `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734` | VC 2.0 appendix B.1; matches the served bytes |
| `https://cawg.io/identity/1.1/ica/context/` | `750c94af1c3d7e587dc19f3a06ef1e9bfe8412a1e94ef15037ae83f3baeb82e9` | served bytes, fetched 2026-09-28 |

The three documents are vendored byte-for-byte under `crates/encypher-c2pa/src/c2pa-validate/contexts/`, with their license notices: the W3C Software and Document License for the VC contexts, and Apache-2.0 for the CAWG context under the repository's `license.md`. A unit test asserts each digest. The term data the verifier needs is derived from the vendored bytes at first use, so the pinned documents are the single source for the protected-term set.

**The two CAWG context versions.** The CAWG v1.3 tag's `docs/modules/ROOT/attachments/ica/context/index.json` has SHA-256 `9763ec56f4e1b3aabb69685b5d48e8475a6f6038f4bf40e1684e649c8761b064`. It defines 15 terms: `address`, `c2paAsset`, `cawg`, `method`, `name`, `provider`, `referenced_assertions`, `role`, `schema`, `sig_type`, `uri`, `username`, `verifiedAt`, `verifiedIdentities`, and `xsd`. The served document (`750c94af...`) defines those 15 plus `expected_partial_claim`, `expected_claim_generator`, and `expected_countersigners`. The verifier reads `verifiedIdentities` and, within each entry, `name`, `username`, `uri`, `provider`, `verifiedAt`, `method`, and `address`. It compares `c2paAsset` byte-exactly to `signer_payload`, whose keys are `referenced_assertions`, `sig_type`, `role`, and, when present, the three `expected_*` fields. The served bytes define every one of these terms. The tag attachment lacks the three `expected_*` terms. That is why the served bytes are pinned. Neither document defines `IdentityClaimsAggregationCredential`, and neither VC base context declares `@vocab` (VC 2.0 appendix E: "Removed @vocab from the base context"). The type, and every `verifiedIdentities[].type` value, resolves only through the CAWG context's `@vocab` (`https://www.w3.org/ns/credentials/examples#`).

### Profile limits fail closed with `unsupported_context`

Each of the following yields `cawg.ica.invalid_verifiable_credential` with `details: {"reason": "unsupported_context", "contexts": [...]}`, and validation stops:

1. A string `@context` item outside the pinned set. `contexts` lists each such URL.
2. An object-valued (inline) `@context` item. `contexts` lists `"<inline>"` for each one.
3. An `@context` member on any JSON object in the credential body, whether node, value, or list object. Expansion processes `@context` wherever it appears. The top-level `@context` value itself and the values of `@json`-typed terms (below) are excluded. `contexts` lists `"<embedded>"`.

These are profile limitations of type-specific processing (VC 2.0 section 6.3), not claims that the credential breaks VC syntax. VC 2.0 section 4.3 allows object items and VC 1.1 section 4.1 allows "URIs or objects". V-03 is therefore recorded as **partial**, with this rationale.

**Why the profile does not accept inline contexts.** Cycles 1 and 2 of the plan gate tried a supported subset of JSON-LD context definitions. Reviewers reproduced, with jsonld.js 8.3.3, cases where that subset diverged from JSON-LD in both directions: null `@container`, container combinations, cyclic IRI mappings, and `@propagate` in term definitions. They also found extension terms aliasing a consumed predicate: `otherIssuer` mapped to `https://www.w3.org/2018/credentials#issuer` merges into `issuer` under compaction. Fully closing those gaps means reimplementing the JSON-LD Create Term Definition algorithm and IRI expansion. Failing closed is simpler and is safe for every real credential (0 of 24 use an inline context).

**`@json` terms in the pinned contexts.** The VC v2 context types three terms `@json`:

- `_sd`, at the top level, so it applies to every node.
- `jsonSchema`, in the type-scoped context of `JsonSchema`, so it applies on nodes typed `JsonSchema`. Type-scoped contexts do not propagate.
- `jwk`, in the property-scoped context of `cnf`, which propagates through that value's subtree.

The VC v1 and CAWG contexts define none. The value of an `@json` term is an opaque JSON literal. Any member inside it, `@context` or `@nest` included, is data and is not inspected. These three entries are a static table in the code. A unit test asserts that the vendored bytes contain exactly these `@json` definitions, in exactly these scopes.

**Why `invalid_verifiable_credential`.** CAWG "Parse the verifiable credential" requires the validator to parse the credential under VC section 6, "Syntaxes". If it "is unable to parse the credential using either version", it "MUST stop validation at this point and issue the failure code `cawg.ica.invalid_verifiable_credential`". Under section 6.3, a type-specific processor accepts only "specific @context values which the implementation is engineered ahead of time to understand". Section 4.3 requires understanding every context "to the extent that it affects the meaning of the terms used". An unretrieved context can redefine every unprotected CAWG term, because the CAWG context sets no `@protected`. A COSE signature binds the URL string, not the resource. A validator that has not retrieved the context therefore cannot parse such a credential with known semantics. The registered code is the one CAWG assigns to that outcome. `details.reason` tells it apart from a malformed credential, so a relying party can fetch and pin the context and re-run. An informational `com.encypher.*` code was rejected: CAWG requires `cawg.ica.credential_valid` whenever no failure code is issued, so withholding success needs a failure code.

Interop count: 0 of the 24 real ICA credentials extracted from the vectors (see "Interop evidence") carries an unpinned, inline, or embedded context. All 24 use exactly `[v2, CAWG ICA]`, and none has an IRI-keyed property.

### What is lost without expansion

| Needs JSON-LD or retrieval | Handling |
|---|---|
| Meaning of an unknown context URL | Fail closed (above). TECH-A-004 is not claimed. |
| Inline or embedded contexts | Fail closed (above), as a profile limitation; V-03 partial. |
| Expansion errors (VC 2.0 B.1: "If such operations are performed and result in an error ... MUST result in a verification failure") | Conditional on performing expansion. None is performed. With only the pinned `[base, CAWG]` pair accepted, the processed context is fixed and was checked once, offline, when the documents were pinned. |
| Verifying an embedded Data Integrity `proof` (RDF canonicalization) | Not verified and not relied on. CAWG secures the ICA with the COSE_Sign1 envelope (VC-JOSE-COSE), which is verified. `proof` objects get the structural check in V-35. |

### Revocation interop cost of failing closed

Two ICAs that CAWG handles with a revocation code stop here with `unsupported_context` instead:

- A VC 2.0 ICA using `StatusList2021Entry`, which needs `https://w3id.org/vc/status-list/2021/v1`.
- A VC 1.1 ICA using `BitstringStatusListEntry`, the type CAWG recommends (validating.adoc:136). It needs a status context that v1 lacks.

For both, CAWG prescribes `cawg.ica.revocation.unsupported`, and validation MAY continue (validating.adoc:127). The verifier reports that it cannot parse the credential with known semantics, and it continues no further. No real credential carries a status entry. CHANGELOG records the cost.

### Body shape rules (V-36)

The parser reads properties by their literal term keys. JSON-LD can attach a value to the same property through another key: an IRI, a keyword such as `@nest`, or a second `@id` alias. For the verifier's reading to match what the signed graph asserts, the body must use only the shapes that compaction under the pinned pair produces. The walk covers every JSON object in the body, excluding the top-level `@context` value and `@json` values, and applies the following rules. Each failure is `cawg.ica.invalid_verifiable_credential` with an explanation naming the key. It is labeled a compacted-form error (VC 2.0 6.1) or a profile limitation (VC 1.1, and the superset cases noted).

- **V-36a, keyword keys.** A key beginning with `@` is rejected, with two exceptions.
  - A value object may carry `@value`, `@language`, and `@direction`: an object that has `@value`, whose other keys are among `@language`, `@direction`, and `type`. `type` is the pinned alias compaction writes for a typed literal's `@type`.
  - A list object may carry `@list`: an object whose only key is `@list`. Compaction emits one for a list value of an extension term with no list container. It is a value, not a node, so it cannot add properties to any node. Its items are walked.

  Every other keyword key is rejected: `@id`, `@type`, `@nest`, `@graph`, `@reverse`, `@included`, `@index`, `@set`, and keyword-form non-keywords such as `@foo`. Compaction under the pinned pair emits none of them. The pinned contexts alias `@id` to `id` (and CAWG also to `uri`) and `@type` to `type`, and no pinned term uses `@nest`, `@included`, or `@reverse`. `@nest` is the concrete risk: JSON-LD 1.1 API Expansion steps 13.4 and 14 merge `"@nest": {"issuer": ...}` into the enclosing node, so a second issuer or a second `verifiedIdentities` set would reach JSON-LD consumers unseen by this verifier. A nested `@type` beside `type` merges extra types in the same way. This rule replaces the earlier top-level-only `@id`/`@type` check.
- **V-36b, IRI keys.** A body key containing `:` whose expansion equals the IRI of a term defined in the active pinned pair (v2 + CAWG, or v1 + CAWG) is rejected. Following JSON-LD 1.1 (section 4.4 Compact IRIs, and the API's IRI expansion), a key `prefix:suffix` is expanded as a compact IRI when `suffix` does not begin with `//` and `prefix` is a term usable as a prefix. That means a simple term definition, whose term contains no `:` or `/`, mapping to an IRI that ends in a gen-delim character (`:`, `/`, `?`, `#`, `[`, `]`, `@`), or a term definition with `@prefix: true`. Any other key with `:` is taken as an absolute IRI. The term and prefix tables are the union over every scope of the pinned pair. Examples: a top-level `"https://www.w3.org/2018/credentials#issuer"`, and `"cawg:verifiedIdentities"` in `credentialSubject`. On the credential node, where the matching term is in scope, this is a VC 2.0 6.1 compacted-form error. On a node where the term is out of scope, the check is a superset of compaction: for example, `issuer` lives in `VerifiableCredential`'s non-propagating type-scoped context, so compaction would keep `credentials#issuer` as a full IRI inside `credentialSubject`. Such matches are rejected as a profile limitation, not a 6.1 violation. An extension IRI key that no pinned term maps to, such as `https://vocab.example/credentials#exampleClaim`, is accepted.
- **V-36c, one node identifier.** Keys expanding to `@id` in the pinned pair are `id` and, through the CAWG context, `uri`. A node carrying both is rejected; JSON-LD reports it as colliding keywords. Every `id` or `uri` value on a node is a single URL (VC 2.0) or URI (VC 1.1), so V-11 covers `uri` wherever it sets a node identifier, including top-level and `credentialSubject`.
- **V-36d, no node merging (profile).** A nested node whose identifier (`id` or `uri`) equals the credential's `id` or the credential subject's `id` is rejected. In the RDF graph such a node merges into the credential or its subject. An `evidence` entry with the subject's DID and a `verifiedIdentities` member would add identities the verifier never read.

## Requirement table

Legend: **Checked** means the rule is enforced after this PRD (**existing**: already enforced; **new**: added here). **JSON-LD** means it cannot be checked without JSON-LD processing; the decision is given. **N/A** means the rule binds issuers, holders, presentations, or specification authors, not a validator of a received credential. Every "Checked" failure reports `cawg.ica.invalid_verifiable_credential` with an explanation naming the property, unless a CAWG code is named. CAWG requires that code for an unparseable credential, and VC 2.0 section 7.1 maps a non-conforming document to `MALFORMED_VALUE_ERROR`.

**Identifier datatypes (V-11 and every "URL" below).** VC 2.0 uses the WHATWG URL Standard. The check is `url::Url::parse` with a syntax-violation callback, and any reported violation fails it. This approximates the Standard's "valid URL string", so `https://example.org/café` is accepted and `http:` (no host) is rejected. VC 1.1 and CAWG say "URI". There the check is the existing RFC 3986 `is_uri` (ASCII). The VC version is selected by `@context[0]`.

### Contexts

| ID | Requirement (VC 2.0 / VC 1.1) | Class | How |
|---|---|---|---|
| V-01 | Credential MUST include `@context` (2.0 4.3; 1.1 4.1) | Checked (existing) | Missing or not an array is rejected. |
| V-02 | First item MUST be the base context URL (2.0 4.3; 1.1 4.1). JSON-based processors MUST ensure the expected values are in the expected order (1.1 5.3) | Checked (existing, TEAM_462) | `contexts[0]` selects `2.0` or `1.1`. The CAWG URL must be present. |
| V-03 | Subsequent items are "any combination of URLs and objects" (2.0 4.3), or "URIs or objects" (1.1 4.1) | **Partial** (profile) | A string item must be a URL (2.0) or URI (1.1) and a pinned URL. An object item is a conforming VC form the profile does not support. It fails closed with `unsupported_context` (see "Why the profile does not accept inline contexts"). TEAM_462 had rejected object items as malformed; they are now reported as a profile limitation. Null or any other value is malformed. |
| V-04 | Each object item is "processable as a JSON-LD Context" (2.0 4.3) | N/A under the profile | No object item is accepted. |
| V-05 | `@context` is an ordered set (2.0 4.3), so no item repeats | Checked (**new**) | A repeated string item is rejected. |
| V-06 | Exactly one base context. CAWG TECH-A-005: the v1 URL "_or_" the v2 URL, "depending on which version ... is being used" | Checked (**new**) | A credential listing both is rejected. |
| V-07 | Developers MUST understand every context affecting the terms they use (2.0 4.3). JSON-LD processors MUST error on protected-term redefinition (1.1 5.3) | Checked (**new**) | Only the pinned, understood pair is accepted. Unpinned, inline, and embedded contexts fail closed with `unsupported_context`. |
| V-08 | Base context treated as already retrieved; digest published (2.0 B.1; 1.1 B.1) | Checked (**new**, by construction) | Vendored bytes are pinned by digest; nothing is fetched. |
| V-09 | `undefined-terms/v2` MUST be the last item when terms are undefined (2.0 5.2) | N/A under the profile | The CAWG context's `@vocab` maps every term the pinned pair leaves undefined, and nothing can follow it to reset that. A credential that lists `undefined-terms/v2` fails closed as an unpinned context. |
| V-10 | Expansion errors MUST fail verification "if such operations are performed" (2.0 B.1) | JSON-LD | Not performed (see "What is lost"). |

### Identifiers and types

| ID | Requirement | Class | How |
|---|---|---|---|
| V-11 | `id`, if present, MUST be a single URL (2.0 4.4) or a single URI (1.1 4.2, 6) | Checked (**new**) | Checked on every node object in the body, using the version's datatype, and on the CAWG `@id` alias `uri` wherever it appears (V-36c). This covers the credential, its subject, and each `credentialStatus`, `credentialSchema`, `evidence`, `termsOfUse`, `refreshService`, and `relatedResource` object. |
| V-12 | `type` MUST be present (2.0 4.5; 1.1 4.3) | Checked (existing) | |
| V-13 | `type` values MUST be "terms and absolute URL strings" (2.0 4.5); they "be, or map to ... URIs" (1.1 4.3) | Checked (existing: strings; **new**: form) | Each member is a non-empty string and not an `@` keyword. A member containing `:` must be a URL (2.0) or URI (1.1); a compact IRI such as `cawg:Foo` also parses as one. A member without `:` is a term, which the CAWG context's `@vocab` maps. |
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
| V-21 | `validFrom` and `validUntil`, if present, MUST be an XML Schema `dateTimeStamp` (2.0 4.9) | Checked (**new**, strict) | An XSD 1.1 lexical parser replaces RFC 3339. It requires `T`, then `Z` or an offset within `±14:00`; seconds 00-59; `24:00:00` (fraction all zeros) is the next day's midnight. The day of month must exist in that month under the proleptic Gregorian leap rule (the XSD 1.1 Part 2 day-of-month value constraint; year 0000 is a leap year, and negative years follow the same rule). VC 2.0 5.8 warns that its reproduced regex "allows for 31 days in every month". The year is `-?` followed by four or more digits, with no leading zero beyond four digits (see V-45). The previous parser accepted any separator byte, lowercase `z`, offsets to `±23:59`, and second `60`. A present JSON `null` is malformed, since only an absent property is "not present" and compaction never emits null. Failures report `cawg.ica.valid_from.invalid` and `cawg.ica.valid_until.invalid`. |
| V-22 | `validFrom` MUST be at or before `validUntil` (2.0 4.9) | Checked (**new**, VC 2.0 only) | The two values are compared exactly (V-45). A violation reports `cawg.ica.valid_until.invalid` with the explanation "earlier than its effective date", at any validation time. VC 1.1 has no ordering MUST, so V-22 does not run for 1.1. |
| V-23 | VC 1.1 `issuanceDate` MUST exist and be an XSD `dateTime`; `expirationDate`, if present, an XSD `dateTime` (1.1 4.6, 4.8) | Checked (existing: presence; **new**: form) | An XSD `dateTime` makes the zone optional. A zoneless value was wrongly rejected as malformed before. VC 1.1 has no UTC rule, and XSD 1.1 (section 3.3.7, order relation) orders a zoneless value only partially against zoned instants, within ±14:00. When comparing against a validation time, the verifier reads it at the end of that range that can only reject more: the effective date at local+14 h (latest), the expiration at local-14 h (earliest). One extra branch buys the XSD semantics; UTC would accept a credential XSD calls not-yet-valid. |
| V-24a | VC 2.0 5.8: "Time values that are incorrectly serialized without an offset MUST be interpreted as UTC" | Checked (**new**) | A zoneless VC 2.0 `validFrom` or `validUntil` breaks V-21 (4.9 requires `dateTimeStamp`), so an error is produced. The value is interpreted as UTC, and the explanation says so ("lacks a time zone; read as UTC ... a dateTimeStamp is required"). The failure code does not depend on that interpretation. |
| V-45 | XSD value space: years beyond 9999 and before 0000, and fractional seconds to any precision | Checked (**new**) | Each date is normalized to UTC as an exact value: `i128` seconds since the epoch (from a proleptic-Gregorian day count, with the zone offset applied), plus the fraction's decimal digits with trailing zeros trimmed. Values order by seconds, then by the trimmed fraction digits compared lexically, which is exact because both sides are trimmed. Validation times convert the same way: nanoseconds become a 9-digit fraction with trailing zeros trimmed, so `00:00:00.5Z` equals a validation instant at 500,000,000 ns. No value is rounded or saturated, so both V-22 and the validation-time comparisons are exact at any precision. The year may have up to 30 digits, which keeps the seconds value inside `i128`. A longer year is outside the supported range and reports the invalid code with that explanation, as a documented profile limit. |

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
| V-36 | JSON-LD compacted form MUST be used for `application/vc` (2.0 6.1) | Checked (**new**; VC 2.0 as syntax, VC 1.1 and out-of-scope matches as profile) | The body shape rules V-36a to V-36d: keyword keys, IRI keys, one node identifier, and no node merging. An embedded `@context` fails closed as `unsupported_context`. |
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

- New module `crates/encypher-c2pa/src/c2pa-validate/vc_data_model.rs` holds the VC data-model checks:
  - The pinned contexts: `include_bytes!` of the vendored files, with term IRIs and prefixes derived once in a `OnceLock`. The three `@json` scopes are a static table checked against the vendored bytes by a unit test.
  - The context-list check and the body walk: embedded `@context`, and rules V-36a to V-36d.
  - The URL and URI datatype predicates.
  - The typed-object and language-value checks.
  - `relatedResource`, with the SRI syntax check, the base58btc, base32, and base16 decoders, the multihash parser, and the pinned-digest comparison.
  - The exact XSD date parser.

  `cawg_ica.rs` stays the orchestration point. Its existing `base64_decode(input, url_alphabet)` is reused for the four base64 multibase forms, so no second base64 decoder is added, and its `is_uri` is made `pub(super)`.
- `parse_ica_credential` returns `Result<IcaCredential, CredentialDefect>`, where `CredentialDefect` is `Malformed(&'static str)` or `UnsupportedContext(Vec<String>)`. The first reports `cawg.ica.invalid_verifiable_credential` as today. The second reports it with `details.reason = "unsupported_context"` and `details.contexts`.
- `ValidityField` becomes `Missing | Malformed(&'static str) | Parsed(XsdInstant)`. `XsdInstant` is the exact `(i128 seconds, trimmed fraction digits)` value of V-45 with a total order. A VC 1.1 zoneless value keeps its local reading, and the ±14 h bound is applied only when comparing against a validation time.
- New direct dependency: `url = "2"` (WHATWG URL; already in `Cargo.lock` through the optional `ureq`). Its effect on the browser WASM package size (gzip, before and after) and on `--no-default-features` builds is reported in the completion packet.
- `docs/REPORT_SCHEMA.md` documents `details.reason`/`details.contexts`. `CHANGELOG.md` records every behavior change.

## Tests (TDD)

Each negative case is a complete credential, edited to break one rule and signed by the trusted `did:jwk` issuer (`validate_edited` / `validate_dates`). The signature, trust, and identity checks pass, so the named code is the only failure. The table-driven tests, grouped by property family, are:

- **Contexts.** An unknown URL, an inline object item, and `@context` embedded in `credentialSubject`, in a `verifiedIdentities` entry, and in a value object, each with `details.reason` and `details.contexts` asserted. Also a non-URL string, null, a number, a repeat, and both base contexts (malformed).
- **`@json` literals.** Accepted: `credentialSchema: {"id": ..., "type": "JsonSchema", "jsonSchema": {"@context": "literal", "@nest": {"issuer": "x"}}}`, and a top-level `"_sd": [{"@context": "literal"}]`. Rejected: the same `jsonSchema` member on a node not typed `JsonSchema`, where it is not `@json`.
- **Keyword keys (V-36a).** Rejected: a top-level `"@nest": {"issuer": "did:example:other"}`; `"@nest": {"verifiedIdentities": [...]}` in `credentialSubject`; `"@type"` beside `type` on a `verifiedIdentities` entry; top-level `@id` and `@type`; `@graph`, `@reverse`, and `@included` members; and `@foo`. Accepted: language value objects in `name`/`description`; a typed value object `{"@value": "...", "type": "..."}` and an `@list` object in an extension property.
- **IRI keys (V-36b).** Rejected: a top-level `"https://www.w3.org/2018/credentials#issuer"`; `"cawg:verifiedIdentities"` and `"https://cawg.io/identity/1.1/ica/#verifiedIdentities"` in `credentialSubject`; `"https://schema.org/name"` in a `verifiedIdentities` entry; and, for VC 1.1, `"cred:issuer"` through v1's scoped `cred` prefix. Accepted: `"https://vocab.example/credentials#exampleClaim"`.
- **Node identifiers (V-36c, V-36d).** Rejected: `id` plus `uri` on one `verifiedIdentities` entry; a top-level `uri` that is not a URL; an `evidence` entry whose `id` equals the subject's `id`.
- **Identifiers and types.** VC 2.0 `https://example.org/café` accepted and `http:` rejected; a VC 1.1 non-ASCII id rejected as a URI; `id` with two values; bad subject id; empty, keyword, and non-URL type members.
- **Names.** Number, empty array, non-string member, missing or non-string `@value`, extra key, bad `@direction`.
- **Status, schema, and extensions.** Every row V-24 to V-32 and V-35, including `digestSRI` as an array, an unsupported multibase prefix, a malformed base58 string, a truncated multihash, and a wrong sha2-256 length. A `relatedResource` for the v2 context URL with the correct B.1 digest is accepted; the same entry with a wrong digest is rejected.
- **Dates.** Rejected: space separator, lowercase `t`/`z`, `+15:00`, second `60`, `24:00:01`, zoneless VC 2.0 (UTC explanation asserted), `null`, and a 31-digit year. Leap days: `2023-02-29` and `2100-02-29` rejected; `2024-02-29` and `0000-02-29` accepted. Also: `24:00:00` equality at the validation instant; `+14:00` accepted; year `10000` accepted as a future `validUntil`; year `-0001` accepted as a past `validFrom`; `9999-12-31T24:00:00Z` rollover.
- **Exact ordering (V-22).** These cases assert whether the "earlier than its effective date" failure appears, independent of validation-time failures. Not flagged: `validFrom` `...00.1234567891Z` with `validUntil` `...00.1234567892Z`; equal 12-digit fractions; years `1000000000000000000` then `2000000000000000000`. Flagged: `validUntil` one sub-nanosecond digit earlier than `validFrom`; the same two years inverted; `validFrom` after `validUntil` at a validation time inside neither bound. Not flagged: a VC 1.1 credential with `expirationDate` before `issuanceDate`. Against validation times: a `validFrom` 12-digit fraction one sub-nanosecond after the validation instant fails; a `validUntil` of `...00.5Z` against a validation instant at `.500000000` passes (sub-second equality).
- **VC 1.1 zoneless dates** in both directions, each 1 s inside and 1 s outside the ±14 h bound.

Positive coverage: one VC 2.0 credential uses every optional property in conforming form, including `id`, language-tagged `name`/`description`, `credentialSchema`, `evidence`, `termsOfUse`, `refreshService`, `relatedResource` (both digest forms, plus a v2-context entry with the B.1 digest), `confidenceMethod`, `renderMethod`, `proof`, an offset `validFrom`, and a `24:00:00` `validUntil`. The existing VC 1.1 tests keep passing.

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

This verifier is at least as strict everywhere except two deliberate relaxations, each allowed by the VC text: object issuers and `24:00:00`.

## Gate findings and resolutions

### Cycle 1

| Finding (reviewer) | Resolution |
|---|---|
| Unknown context URLs accepted without understood semantics (Astra high, ThinkOpenAI high, Opus low) | Pinned-context model; unknown URL fails closed with `unsupported_context`; TECH-A-004 not claimed for them |
| Inline guard bypassable by `@vocab`/`@vocab: null`, `@import`, embedded `@context`, and more (all three) | Superseded in cycle 2: inline contexts are not supported |
| False claim that the VC v2 base context declares `@vocab` (Opus medium, Astra) | Corrected: only the CAWG context does (VC 2.0 appendix E) |
| RFC 3986 used for VC 2.0 URLs (Astra, ThinkOpenAI) | Version-specific datatypes; `url` crate for VC 2.0 |
| `digestMultibase` only non-empty; `digestSRI` single string only (Astra, ThinkOpenAI, Opus) | Local multibase and multihash decoding; SRI string or array |
| V-31 N/A although the base context is "made use of" (Opus) | Pinned-context `relatedResource` digests are checked |
| VC 2.0 5.8 zoneless-UTC MUST missing (Opus, ThinkOpenAI) | V-24a |
| ±14 h rule unexplained; no negative zoneless tests; `null` treated as absent (Opus, ThinkOpenAI) | V-23, V-21 wording; both-direction tests |
| Year range 0000-9999 rejects valid XSD values (Astra, ThinkOpenAI) | V-45 |
| c2pa-rs comparison errors; VC 1.1 section numbers off by one (Opus) | Corrected (1.4, 5.5, 5.6, 5.7, 5.8) |
| V-16/V-36 scope implicit (Opus) | V-16 top-level VC 2.0 only; V-36 labeled per version |
| Adobe contributed vector not exercised (Opus, ThinkOpenAI) | Private before/after smoke run, recorded in the packet |

### Cycle 2

| Finding (reviewer) | Resolution |
|---|---|
| Inline-context grammar diverges from JSON-LD 1.1 both ways: null `@container`, container combinations, cycles, `@propagate`, IRI-mapping errors (Astra medium, Opus medium) | Owner decision: drop inline contexts. Object items fail closed with `unsupported_context` as a profile limitation; V-03 partial, V-04 N/A |
| Extension alias `otherIssuer` to `credentials#issuer` (Astra medium, Opus medium, both security) | No inline contexts, so no aliases. IRI-keyed body properties are rejected (V-36b) |
| Rule 7 conflicted with scoped contexts and `@json` literals (Astra, Opus) | Embedded-context rule scoped to node objects; `@json` values (from the pinned v2 context: `_sd`, `JsonSchema/jsonSchema`, `cnf/jwk`) are skipped, with tests |
| Rounded and saturated values misorder V-22 pairs (Astra medium, Opus low) | V-45 exact `(seconds, fraction digits)` values; no rounding or saturation; V-22 VC 2.0 only; sub-nanosecond and extended-year tests |
| Day-of-month and leap-year rule unstated; no leap-day tests (Opus low) | V-21 wording; four leap-day tests |
| Nested type-scoped contexts (Opus low) | Moot: no inline contexts |
| Revocation-context interop cost unrecorded (Opus low) | "Revocation interop cost of failing closed"; CHANGELOG |
| Reuse the existing base64 decoder (Opus simplification) | Implementation note |

### Cycle 3

| Finding (reviewer) | Resolution |
|---|---|
| `@nest` (and nested `@type`, `@graph`, `@reverse`, `@included`) attaches a second issuer or identity set that the literal-key parser never reads (Astra medium, Opus medium, both security) | V-36a keyword-key rule, with value-object and list-object exceptions justified; signed `@nest`, nested-`@type`, and `@json`-literal-with-`@nest` tests |
| CAWG `uri` aliases `@id`; `id` + `uri` collide; `uri` escapes the V-11 datatype check (Opus medium) | V-36c; V-11 extended to `uri` |
| Embedded-`@context` rule limited to node objects (Opus medium) | Applies to every JSON object in the body |
| V-36b ignores scope; prefix rule not worded per JSON-LD 1.1 (Opus low) | Superset check kept; out-of-scope matches labeled as profile; prefix rule restated per JSON-LD 1.1 section 4.4 |
| Validation-time fraction not trimmed (Opus low) | V-45 trims both sides; sub-second equality test |
| Node-identifier merging unrecorded (Opus low) | V-36d rejects it |
| Generic `@json` scope engine heavier than needed (Opus simplification) | Static three-entry table with a digest-anchored unit test |

## Out of scope

- JSON-LD expansion, canonicalization, and retrieving contexts.
- Bitstring Status List entry fields beyond the VC `type`/`id` rules. The status-list work owns them.
- The retained commercial kernel. TECH-A-004 names both validator repositories, so the matrix row stays `partial` for the retained validator.

## Verification

`cargo test -p encypher-c2pa`, `cargo test -p encypher-c2pa-cli --test cawg_corpus`, a `--no-default-features` build of `encypher-c2pa`, the WASM package size (gzip, before and after), and the private Adobe smoke run. The lead runs the global gates.
