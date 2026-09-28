# CAWG Identity Leaf Fingerprint

**Date:** 2026-09-28
**Status:** PLAN GATE PENDING
**Owner:** PublicLeafFingerprint
**Base:** `feat/cawg13-x509-conformance` at `3596a547f`
**Dependency:** TEAM_466 / PR #30 (`feat/cawg-identity-subject-details` at `d5dd24e`)

## Problem

Browser consumers need a credential-unique identity key but do not decode certificates. The verifier already parses and validates the protected-header `x5chain` leaf, yet its terminal CAWG X.509 statuses do not identify that leaf. A trusted revoked credential also terminates before TEAM_466's certificate subject details are attached, so a consumer cannot display the credential-bound actor name.

## Contract

Add `details.credential_sha256`, lowercase hex SHA-256 of the exact DER bytes of the protected-header `x5chain` leaf used by validation, to these terminal X.509 identity statuses whenever that leaf was parsed:

- `cawg.identity.trusted`
- `cawg.identity.well-formed`
- `cawg.x509.credential.untrusted`
- `cawg.identity.credential_revoked`

Do not hash a re-encoded certificate or another certificate in the chain. ICA statuses and failures reached before a leaf is parsed receive no credential fingerprint.

For every `cawg.identity.credential_revoked` status whose `details.chain_trusted` is JSON `true`, also attach TEAM_466's `subject_organization` and `subject_common_name` from the validated leaf and `certificate_trusted: true`. Reuse `cert.rs::name_attribute` through the existing terminal-details helper: first matching O/CN only, omit an unusable first match, strip the defined controls, omit empty values, and omit rather than truncate values over 256 UTF-8 bytes. A revoked status with `chain_trusted: false`, including anchorless document-signing acceptance, gets no subject fields and no `certificate_trusted`. Configured-untrusted failures keep subject fields and `certificate_trusted` absent, even though they carry `credential_sha256` when the leaf was parsed.

The change is additive JSON only. It adds no Rust public item and does not change terminal selection, trust, signature, revocation, endpoint, or network behavior.

## Implementation

1. Compute the leaf digest once from the already extracted `leaf` DER and add it to terminal details without reparsing or re-encoding the certificate.
2. Extend the existing TEAM_466 terminal-details helper rather than adding another subject decoder. Invoke it for trusted, well-formed, and chain-trusted revoked terminals. Add only the digest to parsed-leaf untrusted and untrusted/anchorless revoked terminals.
3. Update `docs/REPORT_SCHEMA.md` with field provenance, status presence, and the revoked subject-trust rule.
4. Update `CHANGELOG.md` under Unreleased.
5. Extend the packed npm smoke in `scripts/test-wasm.mjs` so the installed `@encypherai/c2pa` artifact proves the fields survive the WASM binding.

## Tests and Proof

TDD coverage in the CAWG validator module will assert:

- every trusted, well-formed, configured-untrusted, chain-trusted revoked, and chain-untrusted/anchorless revoked terminal carries `credential_sha256`, equal to an independently computed SHA-256 of the protected-header leaf DER;
- trusted and well-formed retain their TEAM_466 subject fields and respective `certificate_trusted` values;
- every chain-trusted revoked path, for stapled and online leaf revocation, carries available sanitized O/CN and `certificate_trusted: true`;
- configured-untrusted and `chain_trusted: false` revoked paths carry no subject fields and no `certificate_trusted`;
- ICA terminal statuses and failures before a leaf is parsed carry none of the new X.509 fields;
- the existing sanitizer edge tests continue to cover first-match behavior and the 256-byte omission bound for names now emitted on revoked terminals.

The binding smoke will build release WASM, pack and install the npm tarball, verify a real corpus asset, and assert `credential_sha256` plus the applicable subject and trust fields on terminal X.509 status details. It will also assert those fields are absent from ICA and parsed-leaf failure shapes where the contract requires absence.

Required final commands:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- the repository `cawg_corpus` test
- release WASM build and `node scripts/test-wasm.mjs`

## Acceptance Criteria

1. All four named terminal X.509 status codes expose the digest of the exact parsed protected-header leaf whenever one exists.
2. Chain-trusted revoked credentials expose TEAM_466-sanitized O/CN with `certificate_trusted: true`; anchorless and other untrusted revoked credentials do not.
3. ICA and pre-leaf failures expose no X.509 fingerprint or subject fields.
4. REPORT_SCHEMA, CHANGELOG, focused Rust tests, corpus proof, and packed WASM smoke agree with the contract.
5. The feature is pushed as a public PR based on `feat/cawg13-x509-conformance`, states its PR #30 dependency, passes all PR checks, and is not merged by this agent.
