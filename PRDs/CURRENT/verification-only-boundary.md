# Verification-Only Boundary

**Status:** implementation complete, awaiting completion gate
**Current Goal:** the published SDK offers no way to produce a C2PA asset, and that property is enforced by CI rather than by reviewer attention.

## Overview

The public SDK is described as verification-only. It was not. Every published
release from `1.0.0-rc.1` through `1.0.0-rc.11` exposed the complete
manifest-production chain: claim construction, CBOR encoding, JUMBF assembly,
manifest-store assembly, container carrier framing, and container embedding for
eighteen formats. Only the COSE signature itself was absent.

This was demonstrated, not inferred. Using only the published
`encypher-c2pa-formats` crate from crates.io, a signed JPEG was stripped to a
1,306-byte manifest-free asset and the manifest re-embedded, producing a file
the verifier accepts (`integrity: valid`, `hard binding: match`). Splicing that
manifest onto a modified image correctly fails (`assertion.dataHash.mismatch`),
so the cryptography held and no forgery was possible — but the container writer
was real, complete, and public.

The README meanwhile stated the repository contained "no manifest embedding".

### Why the existing gate missed it

`KERNEL_GOVERNANCE.md` check 4 sweeps the published set for five strings:
`leaf_pointer`, `prepared`, `defined_sequences`, `adtech_jws`, `signer`.
`embed_manifest` contains none of them. A denylist can only catch what someone
already thought to name, so a complete manifest factory shipped through four
releases untouched.

## Objectives

1. Remove manifest construction and container writing from the published API.
2. Preserve verification test coverage, which currently generates its own inputs.
3. Replace the name-shaped gate with one that cannot be defeated by renaming.
4. Make the README's boundary claim true.

## Design

**Public API removal, not source deletion.** The write code is C2PA spec
boilerplate (JUMBF superbox nesting is §11), not proprietary material. Encypher's
actual moat — CAWG identity signing, key management, trust policy, hash-mode
carrier protocol, watermarking — is not in this repository at all. Deleting the
source outright would require importing a per-format signed fixture corpus from
the monorepo, since only two signed fixtures exist publicly and format tests
build their own inputs. That cost buys nothing the API removal does not.

So write-side items are gated behind a `test-support` Cargo feature that is off
by default and enabled only through in-repo dev-dependencies.

**Scope correction found during implementation.** `c2pa_cbor::encode` was
initially gated as a writer. It is not: COSE signature verification rebuilds the
`Sig_structure` and encodes it to recover the exact bytes the signature covers
(`c2pa-crypto/src/cose.rs:32`). A CBOR encoder is a serialization primitive, not
a C2PA producer. It was restored, and the invariant sharpened to: *no public
item may construct a C2PA manifest structure or write one into an asset
container.*

**Gate design.** An inventory, not a denylist. `scripts/check-public-surface.mjs`
walks each published crate from its `lib.rs` through file-backed `pub mod`
declarations, inventories public `pub use` re-exports, descends into local
modules behind those re-exports, records public fields, enum variants, inherent
methods, and trait implementations, skips items behind `#[cfg(test)]` or
`#[cfg(feature = "test-support")]`, and fails closed on inline public modules,
`#[path]` public modules, wildcard re-exports, and module-level macro
invocations. It diffs the result against the reviewed `public-surface.txt`. Any
item added under that model fails the build until a human adds it deliberately.

## WBS

- [x] Audit the true public write surface (12 items across 3 crates; the 624
      lines of per-format writers were already private via `mod`, not `pub mod`)
- [x] Confirm no production verification path depends on any writer (both
      validator call sites are inside `#[cfg(test)]` modules)
- [x] Gate `c2pa-core::jumbf` builders (6) and `c2pa-core::claim` builders (2)
- [x] Gate `c2pa-formats` writers (3) and 71 orphaned private write helpers
- [x] Restore `c2pa-cbor::encode` after establishing verification requires it
- [x] Add explicit dev-dependencies so per-package tests work without relying on
      workspace feature unification
- [x] Build the public-surface inventory gate and wire it into CI
- [x] Correct the README boundary claim
- [ ] Completion gate to the bar

## Success Criteria

- Default build of every published crate exposes zero manifest constructors and
  zero container writers; `public-surface.txt` holds 648 reviewed items.
- `cargo test --workspace` passes with the same 302 tests as before the change.
- Each of the 8 packages builds and tests independently (no reliance on
  workspace feature unification).
- `cargo clippy --workspace --all-targets -- -D warnings` is clean in the
  default configuration.
- The gate fails on a writer becoming public, including one named to evade a
  denylist.

## Verification

| Check | Result |
|---|---|
| Gate catches un-gated `embed_manifest` | FAIL as designed, item named |
| Gate catches renamed writer `materialise` | FAIL as designed; old 5-symbol sweep misses it |
| Gate catches re-exported private-module writer | FAIL as designed, `security_probe_writer` named |
| Gate catches public writer method/field/variant drift | FAIL as designed, inventory covers public type members |
| Public surface inventory | 648 items, zero writers |
| Per-package tests (8 packages) | 0 errors, 302 passed |

## Completion Notes

Shipped in commit `7b0a8db` on branch `feat/verification-only`.

- Removed eleven public write items from the default build: six JUMBF and
  manifest-store builders and two claim builders in `encypher-c2pa-core`, and
  three container writers (`embed_manifest`, `strip_manifest`,
  `build_manifest_carrier`) in `encypher-c2pa-formats`. All now compile only
  under the `test-support` feature. The 71 orphaned private write helpers across
  the format modules were gated alongside; they were already private, not public
  API.
- One deviation from plan: `encypher-c2pa-cbor::encode` was gated as a writer in
  the initial audit, then restored. COSE verification re-encodes the
  `Sig_structure` to recover the bytes a signature covers, so a CBOR encoder is a
  verification dependency. The invariant was sharpened accordingly: no public
  item may construct a manifest structure or write one into a container.
- Source kept, not deleted. JUMBF nesting is C2PA spec boilerplate and the format
  readers need generated inputs to test against; deleting would force importing a
  per-format signed fixture corpus for no gain.
- Added the inventory gate `scripts/check-public-surface.mjs` and the reviewed
  `public-surface.txt` (169 items). Wired into `.github/workflows/ci.yml`;
  `release.yml` runs the same CI as a required `verify` job before publishing.
- Added explicit `test-support` dev-dependencies to `c2pa-core`, `c2pa-formats`,
  and `c2pa-validate` so each package tests independently without relying on
  workspace feature unification.
- Corrected the README boundary claim in two places: the "It does not sign media"
  paragraph and the "Security boundary" section.

Files touched: 29 (see `git show --stat 7b0a8db`). No database migrations.
Public API removals live in `internal/c2pa-core/src/{claim,jumbf}.rs` and
`internal/c2pa-formats/src/lib.rs`; the remaining format modules carry only the
mechanical `#[cfg(feature = "test-support")]` gates on already-private helpers.

## Review Loop State

bar: 9.5  max-cycles: 5  worktree: ../encypher-c2pa-worktrees/verification-only
branch: feat/verification-only
plan gate: n/a (implementation-first; entered the loop at Phase 5 per the
  skill's entry table — work claimed complete)
completion gate: not yet run
