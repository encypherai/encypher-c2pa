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

**Gate design.** An inventory, not a denylist, and derived from the compiler
rather than from source text. `scripts/check-public-surface.mjs` runs
`cargo rustdoc --output-format json` for each published lib and reads rustdoc's
own view of the public API, so re-exports, macro expansion, impl methods,
fields and variants are resolved by rustc instead of guessed. It records named
items, inherent methods, public fields, enum variants, and explicit trait impls
on local types (one line per type/trait pair), and passes
`--document-hidden-items` because `#[doc(hidden)] pub` is still callable
downstream. Auto-trait and blanket impls are excluded: the compiler derives
those from other crates' generic impls rather than this repo authoring them.
The result is diffed against the reviewed `public-surface.txt`, and any
addition fails the build until a human adds it deliberately.

rustdoc JSON is nightly-only with an unstable schema. CI pins
`nightly-2026-08-07`, and the script asserts rustdoc's `format_version` on every
run so a schema change fails loudly instead of silently emitting a wrong
inventory. Every failure path exits non-zero with a named reason: the gate
cannot tell "no public writers" from "could not look", so it treats the second
as failure.

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
  zero container writers; `public-surface.txt` holds 844 reviewed items.
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
| Gate catches re-exported private-module writer | FAIL as designed, `smug::writer` named |
| Gate catches `#[doc(hidden)] pub` writer | FAIL as designed, `hidden_embed_png` named |
| Gate catches explicit trait-impl writer | FAIL as designed, `AssetFormat: BitOr (trait impl)` named |
| Public surface inventory | 844 items, zero writers |
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
completion gate: cycle 3 in progress

  cycle 1 (gpt55/opus per dimension):
    correctness    8.0 / 9.6  -> not cleared
    simplification 7.2 / 9.3  -> not cleared
    security       8.0 / 9.4  -> not cleared

  Both reviewers converged independently on one root cause: the gate was a
  hand-rolled Rust source scanner, and it was the wrong tool. GPT-5.5
  demonstrated a third evasion (a multiline `impl ... where` header puts the
  opening brace on its own line, which the impl regex did not match, so public
  methods went unrecorded - proven by compiling a consumer and calling the
  smuggled writer). Opus independently identified macro-generated public items
  as a blind spot no source scanner can close, and flagged that the inventory
  locked shape rather than semantics. GPT-5.5 also found the inventory polluted
  with private-module internals: `encode::encode_into` was listed as public
  while a consumer calling it gets E0603.

  Three reviewers had now each found a different hole in the same scanner. That
  is not a defect to patch, it is evidence the approach does not converge.

  cycle 2 changes:
    - Replaced the ~600-line source scanner with rustdoc JSON extraction, which
      is rustc's own view of the public API. Re-exports, macro-generated items,
      impl methods, fields and variants are resolved by the compiler, so the
      whole class of lexing and reachability holes cannot exist.
    - Pinned nightly-2026-08-07 in CI and asserted rustdoc's `format_version`
      (61) on every run, so an unstable-schema change fails loudly instead of
      silently producing a wrong inventory.
    - Inventory regenerated from the compiler view: 602 accurate entries,
      replacing 648 that had included private-module internals.
    - Documented that `compute_data_hash_exclusions` is load-bearing for
      verification despite its signing-flavoured name, so a later reviewer does
      not gate it by mistake (Opus, low).
    - Corrected SECURITY.md's alpha-era support statement (Opus, low).
    - Corrected the README's "every publicly reachable item" claim to describe
      the actual rustdoc-derived mechanism (Opus, low).

  cycle 2 (gpt55/opus per dimension):
    correctness    7.0 / 9.7  -> not cleared
    simplification 7.4 / 9.6  -> not cleared
    security       -   / 9.5  -> not cleared

  Opus cleared all three and confirmed the rustdoc rewrite resolved its
  cycle-1 medium outright. GPT-5.5 found two further evasions in the NEW gate
  and demonstrated both end to end with a default-feature consumer:
    - `#[doc(hidden)] pub` items are callable downstream, but rustdoc omits
      them by default, so the gate read their absence as "not public". Its
      probe embedded a real PNG `caBX` chunk through one while the gate passed.
    - Explicit trait impls on our own public types were skipped entirely. Its
      probe added `impl BitOr<(&[u8], &[u8])> for AssetFormat` that wrote a PNG
      manifest chunk; the gate passed and a consumer extracted 50 bytes.
  Both were design errors in the extraction, not lexing bugs - the previous
  gate had the same two holes and nobody had reached them yet.

  cycle 3 changes:
    - Pass `--document-hidden-items` to rustdoc so `#[doc(hidden)] pub` items
      are inventoried. Verified the flag does not admit private items:
      `encode_into` (E0603 for a consumer) is still absent.
    - Inventory explicit trait impls on local types, one line per type/trait
      pair rather than per method: the trait already fixes the method set, and
      per-method entries would bury the pair in derive noise. Auto-trait and
      blanket impls stay excluded - the compiler derives those from other
      crates' generic impls rather than this repo authoring them.
    - Inventory grew 602 -> 844, the 242 additions being real trait impls
      (`Debug`, `Display`, `Error`, `PartialEq`, ...) that were public all
      along and simply unrecorded.
    - Corrected the PRD's gate-design section and inventory counts, which still
      described the deleted source-walking design (GPT-5.5, medium).

  Evasion battery, all seven classes caught by the current gate:
    B evasively-named writer, C brace-in-string-literal, D pub use smuggle,
    E multiline impl-where, F macro-generated item,
    G #[doc(hidden)] pub writer, H explicit trait-impl writer.
    E and F could never be caught by source scanning; G and H were live holes
    in the rustdoc gate until cycle 3.
