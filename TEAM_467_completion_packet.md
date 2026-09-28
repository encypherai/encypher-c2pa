# TEAM_467 completion packet: CAWG ICA W3C VC data model (TECH-A-004)

**Frozen implementation SHA:** `d9cf7a3467d322e387dd50c119446fa65a8f367a` on `feat/cawg13-vc-data-model` (public after push), stacked on `feat/cawg13-ica-conformance` (`34619e9`, PR #28)
**PR:** https://github.com/encypherai/encypher-c2pa/pull/31 (base `feat/cawg13-ica-conformance`; not merged)
**PRD:** `PRDs/CURRENT/cawg13-vc-data-model.md` (plan gate cleared at cycle 5, `788b7051d`; cycle 5 lows folded in at `c3ca873`)

## What changed

| Commit | Change |
|---|---|
| `c3ca873` | PRD: cycle 5 lows folded in |
| `ec92487` | VC v1, VC v2, and CAWG ICA 1.1 contexts vendored byte for byte under `crates/encypher-c2pa/src/c2pa-validate/contexts/` (sha256 `ab4ddd9a...`, `59955ced...`, `750c94af...`); `.gitattributes -text`; NOTICE attribution; `url = "2.5"` direct dependency |
| `5b01101` | New `c2pa-validate/vc_data_model.rs`; `cawg_ica.rs` parser and validity rewrite; tests; CHANGELOG; REPORT_SCHEMA |
| `9fd93fb` | NOTICE mirrored into the crate and binding directories (the CI `cmp NOTICE` gate) |
| `d9cf7a3` | Completion cycle 1: pre-decode digest bounds; exact CAWG alias exemptions; pinned Bitstring Status List v1 context and status compatibility; allocation and pre-authentication list-work reductions; signed regressions; PRD, CHANGELOG, and NOTICE updates |

Behavior, per PRD row:

- **Context list.** It must begin with the VC base, include CAWG ICA, and may include W3C Bitstring Status List v1 after the base. An unpinned URL, inline object, or body `@context` reports `cawg.ica.invalid_verifiable_credential` with `details: {reason: "unsupported_context", contexts}`. Reporting stops at the first unknown context.
- **Body walk (V-36a to V-36d).**
  - Keyword keys are rejected, except in value objects (which must pass JSON-LD Expansion step 15) and in `@list` objects.
  - IRI and compact-IRI keys that name a pinned term are rejected.
  - A node may not carry both `id` and `uri`; identifiers use the version's datatype. CAWG's separate check exempts only `identity.uri` and `provider.id`, not `identity.id` or `provider.uri`.
  - Each normalized identifier may be described only once. The exception is `credentialSubject.verifiedIdentities[i].provider`, needed for the Adobe prod credential. `relatedResource` integrity references do not count, unless they name a validated node.
  - The `@json` terms `_sd`, `JsonSchema/jsonSchema` (literal type term), and `cnf/jwk` are skipped for VC 2.0 only.
- **Datatypes.** Identifiers are WHATWG URLs in VC 2.0 and RFC 3986 URIs in VC 1.1 (V-11, V-13, V-18, V-20).
- **Properties.** Covered: `name`/`description` language values, typed objects (status, schema, refresh, terms, evidence, proof, confidence/render), and `relatedResource` (SRI syntax, multibase z/u/U/m/M/f/F/b/B, multihash structure, pinned-context digest match). Encoded digests are capped at 140 characters before decoding.
- **Dates.** Exact XSD values (`i128` seconds plus trimmed fraction digits): leap days, `24:00:00`, years of up to 30 digits, `null` as malformed. VC 2.0 zoneless dates are invalid, with the UTC explanation. VC 1.1 zoneless dates are compared fail-closed at ±14 h. The V-22 ordering check runs for VC 2.0 only.

## Commands and results (observed)

| Gate | Result |
|---|---|
| `cargo fmt --all` | applied before commit `d9cf7a3` |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, no warnings |
| `cargo test --workspace` | 914 tests passed across 22 suites; no failures |
| `cargo build -p encypher-c2pa --no-default-features` (host) | ok |
| `cargo build -p encypher-c2pa --no-default-features --target wasm32-unknown-unknown` | ok |
| WASM package (`wasm-pack build --target web --release`, `bindings/wasm`) | pre-feature 3,078,171 B raw / 1,202,257 B gzip -9; cycle-1 frozen build 3,311,997 B / 1,293,494 B (+233,826 raw, +91,237 gzip, +7.6%). The cycle-1 fixes reduce the first completion build by 14,730 raw / 9,106 gzip bytes despite adding status/v1. |
| Private Adobe smoke (`adobe-cai-prod-ica-es-266-1236.jpg`, `--time 2026-08-05T00:00:00Z`, pinned Adobe DID doc) | JSON report byte-identical to the base-code report (`cmp` equal). CAWG codes before and after are the same pre-existing trio: `invalid_did_document`, `signer_payload.mismatch`, and `untrusted_issuer` |
| Mutation check (`/tmp/vc467/mutate.sh`) | 7 of 7 mutations caught: no body walk, no unsupported-context rule, no provider exception, no V-22, no leap rule, untrimmed validation fraction, zoneless read as UTC |
| Real-credential inventory (`/tmp/vc467/ica_inventory.json`, script `/tmp/vc467/extract_ica_inventory.py`) | 24 credentials: 0 unpinned/inline contexts, 0 keyword or IRI keys, 1 repeated description (the Adobe provider pair, admitted by the exception) |
| PR #31 CI | all 7 checks green on cycle-1 head `13532ed`, run [36369702922](https://github.com/encypherai/encypher-c2pa/actions/runs/36369702922): Rust core/CLI, Rust 1.88, Browser WASM, public API, Go, Python wheel, and musllinux |

## Coverage claim for CAWG-ID13-ICA-TECH-A-004

The public verifier covers the row for credentials using the pinned VC base and CAWG contexts, optionally with status/v1. Every VC 1.1/2.0 requirement classified as checkable in the PRD (V-01 to V-45) is enforced and tested. The row stays **partial** overall because:

- **Profile limits.** Inline, unpinned, and embedded contexts fail closed (V-03 partial, owner-approved). Bitstring status remains supported: VC 1.1 requires status/v1; VC 2.0 defines the terms in its base and may list status/v1 redundantly. The unsupported StatusList2021 context still stops with `unsupported_context`.
- **JSON-LD-only items.** Expansion errors are never produced because expansion is not performed (V-10), and embedded Data Integrity proofs are not verified.
- **Retained kernel.** The retained commercial kernel is untouched.

## Completion cycle-1 delta

The Astra and Opus completion reviews held correctness and security below 9.5. This delta resolves every named blocker and low:

1. A 140-character limit is checked before every multibase decoder and before SRI base64 decoding. Signed 64 KiB multibase and SRI inputs assert the fixed rejection explanation. All multibase paths (base58, base64, base16, and base32) share the bound.
2. CAWG's alias exemption is exact: Identity + `uri`, Provider + `id`. Signed VC 1.1 and VC 2.0 negatives cover `identity.id` and `provider.uri`.
3. `https://www.w3.org/ns/credentials/status/v1` is vendored byte for byte at SHA-256 `fda5add353231e6a6884a46b12e6c75464281900cb348284d9c360f62381d9f7`. Its terms join the active protected-term set only when listed. Signed revoked and not-revoked checks pass for VC 1.1 `[v1, status/v1, CAWG]` and VC 2.0 with status/v1 listed redundantly. VC 1.1 without status/v1 reports `revocation.unsupported`.
4. Digest string iteration no longer allocates a `Vec`. Related-resource duplicate ids use a `HashSet`. Context duplicate checking is linear, and an unknown context stops at the first entry, bounding report growth.
5. Every table-driven invalid-VC case asserts an explanation fragment. The duplicated type-membership helper was removed, and the validity closure now formats normally.

## Risks

- WASM gzip remains about 90 KB above the pre-feature baseline, mostly from the `url` crate and IDNA tables.
- `identity.uri` and `provider.id` retain CAWG's RFC 3986 check and `verified_identities.invalid` code. Their opposite aliases use the VC version's datatype.
