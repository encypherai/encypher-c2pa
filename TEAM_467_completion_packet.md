# TEAM_467 completion packet: CAWG ICA W3C VC data model (TECH-A-004)

**Frozen SHA:** `9fd93fbf25184ba295cb14c1dff8ffb3588dbb53` on `feat/cawg13-vc-data-model` (public), stacked on `feat/cawg13-ica-conformance` (`34619e9`, PR #28)
**PR:** https://github.com/encypherai/encypher-c2pa/pull/31 (base `feat/cawg13-ica-conformance`; not merged)
**PRD:** `PRDs/CURRENT/cawg13-vc-data-model.md` (plan gate cleared at cycle 5, `788b7051d`; cycle 5 lows folded in at `c3ca873`)

## What changed

| Commit | Change |
|---|---|
| `c3ca873` | PRD: cycle 5 lows folded in |
| `ec92487` | VC v1, VC v2, and CAWG ICA 1.1 contexts vendored byte for byte under `crates/encypher-c2pa/src/c2pa-validate/contexts/` (sha256 `ab4ddd9a...`, `59955ced...`, `750c94af...`); `.gitattributes -text`; NOTICE attribution; `url = "2.5"` direct dependency |
| `5b01101` | New `c2pa-validate/vc_data_model.rs`; `cawg_ica.rs` parser and validity rewrite; tests; CHANGELOG; REPORT_SCHEMA |
| `9fd93fb` | NOTICE mirrored into the crate and binding directories (the CI `cmp NOTICE` gate) |

Behavior, per PRD row:

- **Context list.** It must be `[VC base, CAWG ICA]` (V-02 to V-07). An unpinned URL, an inline object, or an `@context` inside the body reports `cawg.ica.invalid_verifiable_credential` with `details: {reason: "unsupported_context", contexts}`.
- **Body walk (V-36a to V-36d).**
  - Keyword keys are rejected, except in value objects (which must pass JSON-LD Expansion step 15) and in `@list` objects.
  - IRI and compact-IRI keys that name a pinned term are rejected.
  - A node may not carry both `id` and `uri`, and each identifier must use the version's datatype.
  - Each normalized identifier may be described only once. The exception is `credentialSubject.verifiedIdentities[i].provider`, needed for the Adobe prod credential. `relatedResource` integrity references do not count, unless they name a validated node.
  - The `@json` terms `_sd`, `JsonSchema/jsonSchema` (literal type term), and `cnf/jwk` are skipped for VC 2.0 only.
- **Datatypes.** Identifiers are WHATWG URLs in VC 2.0 and RFC 3986 URIs in VC 1.1 (V-11, V-13, V-18, V-20).
- **Properties.** Covered: `name`/`description` language values, typed objects (status, schema, refresh, terms, evidence, proof, confidence/render), and `relatedResource` (SRI syntax, multibase z/u/U/m/M/f/F/b/B, multihash structure, pinned-context digest match).
- **Dates.** Exact XSD values (`i128` seconds plus trimmed fraction digits): leap days, `24:00:00`, years of up to 30 digits, `null` as malformed. VC 2.0 zoneless dates are invalid, with the UTC explanation. VC 1.1 zoneless dates are compared fail-closed at ±14 h. The V-22 ordering check runs for VC 2.0 only.

## Commands and results (observed)

| Gate | Result |
|---|---|
| `cargo fmt --all` | applied before commit `5b01101` |
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, no warnings |
| `cargo test --workspace` | all suites ok: 816 lib tests; CLI `cawg_corpus` 12/12; no FAILED |
| `cargo build -p encypher-c2pa --no-default-features` (host) | ok |
| `cargo build -p encypher-c2pa --no-default-features --target wasm32-unknown-unknown` | ok |
| WASM package (`wasm-pack build --target web --release`, `bindings/wasm`) | before 3,078,171 B raw / 1,202,257 B gzip -9; after 3,326,727 B / 1,302,600 B (+248,556 raw, +100,343 gzip, +8.3%; `url` + IDNA tables, plus the embedded contexts) |
| Private Adobe smoke (`adobe-cai-prod-ica-es-266-1236.jpg`, `--time 2026-08-05T00:00:00Z`, pinned Adobe DID doc) | JSON report byte-identical to the base-code report (`cmp` equal). CAWG codes before and after are the same pre-existing trio: `invalid_did_document`, `signer_payload.mismatch`, and `untrusted_issuer` |
| Mutation check (`/tmp/vc467/mutate.sh`) | 7 of 7 mutations caught: no body walk, no unsupported-context rule, no provider exception, no V-22, no leap rule, untrimmed validation fraction, zoneless read as UTC |
| Real-credential inventory (`/tmp/vc467/ica_inventory.json`, script `/tmp/vc467/extract_ica_inventory.py`) | 24 credentials: 0 unpinned/inline contexts, 0 keyword or IRI keys, 1 repeated description (the Adobe provider pair, admitted by the exception) |
| PR #31 CI | first run failed only on the NOTICE mirror check; fixed in `9fd93fb`; rerun pending at packet time |

## Coverage claim for CAWG-ID13-ICA-TECH-A-004

The public verifier covers the row for credentials using the pinned `[VC base, CAWG ICA]` contexts. Every VC 1.1/2.0 requirement classified as checkable in the PRD (V-01 to V-45) is enforced and tested. The row stays **partial** overall because:

- **Profile limits.** Inline contexts, unpinned contexts, and embedded contexts fail closed rather than being processed (V-03 partial, owner-approved). An ICA that needs a status-list context stops with `unsupported_context` instead of `revocation.unsupported`.
- **JSON-LD-only items.** Expansion errors are never produced because expansion is not performed (V-10), and embedded Data Integrity proofs are not verified.
- **Retained kernel.** The retained commercial kernel is untouched.

## Risks

- WASM gzip grows by about 100 KB, because of the `url` crate and its IDNA tables.
- `uri`/`provider.id` on identities and providers keep the CAWG RFC 3986 check and code (`verified_identities.invalid`), not the VC 2.0 URL datatype.
