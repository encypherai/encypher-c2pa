# CAWG Identity Leaf Fingerprint

**Date:** 2026-09-28
**Status:** PLAN GATE PENDING - CYCLE 1 FINDINGS APPLIED
**Owner:** PublicLeafFingerprint
**Base:** `feat/cawg13-x509-conformance` at `3596a547f`
**Dependency:** TEAM_466 / PR #30 (`feat/cawg-identity-subject-details` at `d5dd24e`)

## Problem

Browser consumers need a credential-unique identity key but do not decode certificates. The verifier already selects an `x5chain` leaf and uses that certificate's public key for CAWG X.509 validation, yet its terminal statuses do not identify the selected certificate. A trusted revoked credential also terminates before TEAM_466's certificate subject details are attached, so a consumer cannot display the credential-bound actor name.

## Contract

Add `details.credential_sha256`, lowercase hex SHA-256 of the exact DER bytes of the `x5chain` leaf selected by the existing CAWG X.509 validator, to these terminal statuses when `x509_cert::Certificate::from_der(leaf)` succeeds:

- `cawg.identity.trusted`
- `cawg.identity.well-formed`
- `cawg.x509.credential.untrusted`
- `cawg.identity.credential_revoked`

The existing `extract_x5chain` selection rule is unchanged. It accepts integer label 33 or legacy text label `x5chain` from either the protected or unprotected COSE header bucket; integer 33 wins over text when the forms differ across buckets, while the same selected label in both buckets is malformed. The fingerprint names the certificate whose key the validator selected to verify the signature. It does not claim that the certificate bytes came from the protected bucket. Do not hash a re-encoded certificate or another certificate in the chain.

"Parsed leaf" means exactly that `x509_cert::Certificate::from_der(leaf)` succeeds. A non-certificate byte string that `extract_x5chain` accepts can still terminate as `cawg.x509.credential.untrusted`, but receives no fingerprint. A decodable certificate that fails the CAWG leaf profile receives the fingerprint on that untrusted terminal. ICA statuses receive none.

For every `cawg.identity.credential_revoked` status whose `details.chain_trusted` is JSON `true`, also attach TEAM_466's `subject_organization` and `subject_common_name` from the selected leaf and `certificate_trusted: true`. Reuse `cert.rs::name_attribute` through the existing terminal-details helper: first matching O/CN only, omit an unusable first match, strip the defined controls, omit empty values, and omit rather than truncate values over 256 UTF-8 bytes. Here `certificate_trusted` reports chain trust only; it does not mean the credential is current or valid, and callers must still branch on the revoked status code.

A `cawg.identity.credential_revoked` status with `chain_trusted: false`, including anchorless document-signing acceptance, gets the fingerprint but no subject fields and no `certificate_trusted`. Every CA-revoked `cawg.x509.credential.untrusted` status gets only the fingerprint when the leaf parsed, regardless of whether its `chain_trusted` detail is true. Configured-untrusted terminals likewise get the fingerprint only. `cawg.x509.algorithm.unsupported`, `cawg.x509.signature.mismatch`, `cawg.x509.signature.outside_validity`, and every other status outside the four-code list get no fingerprint even if leaf extraction occurred.

The fingerprint is descriptive evidence, not a trust verdict or standalone proof that the certificate bytes were COSE-protected. The existing selector can accept an unprotected-bucket certificate; a same-key certificate substitution can therefore change this identifier without changing signature verification. Consumers must correlate the exact assertion label and terminal verdict and must not infer trust from the digest alone. Tightening X.509 selection to a protected bucket is outside this additive reporting change.

The change adds JSON fields only. It adds no Rust public item and does not change header selection, terminal selection, trust, signature, revocation, endpoint, or network behavior.

## Implementation

1. Immediately after existing leaf selection, perform one explicit `x509_cert::Certificate::from_der(leaf)` decode. Retain that result for both fingerprint eligibility and TEAM_466 subject extraction, removing the helper's later decode. Compute the SHA-256 once over the original selected DER only when the decode succeeds.
2. Keep one small digest insertion step for digest-only terminals. Keep the terminal-details helper for subject plus `certificate_trusted`; extend it to reuse the retained parsed certificate and digest, and update its comment to name trusted, well-formed, and chain-trusted revoked callers.
3. Pass the optional digest into `report_identity_ca_revoked` so all four call sites attach the digest when eligible but never attach subject fields or `certificate_trusted`.
4. Update `docs/REPORT_SCHEMA.md` with selector provenance, status presence, the unprotected-bucket limitation, and the revoked chain-trust meaning. Update `CHANGELOG.md` under Unreleased.
5. Extend the packed npm smoke in `scripts/test-wasm.mjs` so the installed `@encypherai/c2pa` artifact proves the fields survive the WASM binding.

## Tests and Proof

TDD coverage in the CAWG validator and COSE modules will assert:

- trusted, well-formed, configured-untrusted, chain-trusted revoked, and chain-untrusted/anchorless revoked terminals carry `credential_sha256`, equal to an independently computed SHA-256 of the selected leaf DER;
- an unprotected-only `x5chain` pins the fingerprint to that selected leaf without changing its verdict;
- conflicting cross-bucket label forms pin the existing precedence in both directions: unprotected integer 33 beats protected text, and protected integer 33 beats unprotected text, with unchanged verdicts;
- a non-certificate selected leaf terminates untrusted without `credential_sha256`, while a decodable CA-profile leaf terminates untrusted with it;
- trusted and well-formed retain their TEAM_466 subject fields and respective `certificate_trusted` values;
- stapled and online chain-trusted leaf revocation carry sanitized O/CN and `certificate_trusted: true`;
- chain-untrusted and anchorless revoked terminals carry no subject fields or `certificate_trusted`;
- each of the four `report_identity_ca_revoked` sites carries the digest only, including a `chain_trusted: true` case, with no subject fields or `certificate_trusted`;
- ICA terminals and excluded X.509 failures carry none of the new fields, with `cawg.x509.signature.mismatch` as the parsed-leaf exclusion regression;
- the existing sanitizer tests continue to prove first-match behavior and the 256-byte omission bound for names also used by revoked terminals.

The binding smoke will build release WASM, pack and install the npm tarball, and verify a real corpus asset. It will use Node `X509Certificate.raw` plus `createHash("sha256")` to independently derive the expected fingerprint and assert it on trusted, well-formed, and parsed-leaf untrusted statuses. The existing configured-untrusted fixture must carry the digest but no subject fields or `certificate_trusted`; ICA must carry none of the X.509 fields. No redistributable revoked CAWG corpus asset exists, so revoked field transport is proved in Rust; the WASM binding passes the same `serde_json::Value` details object without a status-specific projection.

Required final commands:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- the repository `cawg_corpus` test
- release WASM build and `node scripts/test-wasm.mjs`

## Landing

PR landing order is #27, then #30, then this PR. This branch currently targets `feat/cawg13-x509-conformance` and merges #30 at `eb8a25c`; the PR body must state the #30 dependency and link the merge-resolution hunks in `cawg.rs`, `CHANGELOG.md`, `docs/REPORT_SCHEMA.md`, and `scripts/test-wasm.mjs` for explicit review. After #27 and #30 land, rebase this branch onto `public-main` before human merge so squash merges cannot duplicate dependency commits. This agent opens but does not merge the PR.

## Acceptance Criteria

1. All four named terminal X.509 status codes expose the digest of the exact validator-selected, successfully decoded leaf.
2. Chain-trusted revoked credentials expose TEAM_466-sanitized O/CN with `certificate_trusted: true`; anchorless, configured-untrusted, and CA-revoked untrusted statuses do not expose those attributing fields.
3. COSE bucket and label precedence remain unchanged and are visible in fingerprint regression tests.
4. ICA, undecodable-leaf terminals, and excluded X.509 failures expose no fingerprint or subject fields.
5. REPORT_SCHEMA, CHANGELOG, focused Rust tests, corpus proof, and packed WASM smoke agree with the contract.
6. The public PR is based on `feat/cawg13-x509-conformance`, states and links its PR #30 dependency and merge resolutions, passes all checks, and remains unmerged.
