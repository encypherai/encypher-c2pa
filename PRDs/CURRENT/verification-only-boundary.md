# Verification-Only Boundary

**Status:** implementation complete, completion gate in progress (cycle 14)
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
manifest onto a modified image correctly fails
(`assertion.dataHash.mismatch`), so the cryptography held and no forgery was
possible - but the container writer was real, complete, and public.

The README meanwhile stated the repository contained "no manifest embedding".

### Root cause

The SDK published eight packages: six implementation crates totalling 22,890
lines, a facade, and a CLI. Nothing consumed the six - the C, Python and WASM
bindings and the CLI all depend only on the facade, which defines its own public
types and leaks no internal type in a public signature. Those six were 758 of
931 public API entries, 81% of the reviewed surface.

Publishing them is what made the writers reachable. `pub fn embed_manifest` in a
published crate is callable by anyone; the same function in a private module is
not. The first attempt at this feature hid the writers behind a `test-support`
Cargo feature, which was treating the symptom.

### Why the existing gate missed it

`KERNEL_GOVERNANCE.md` check 4 sweeps the published set for five strings:
`leaf_pointer`, `prepared`, `defined_sequences`, `adtech_jws`, `signer`.
`embed_manifest` contains none of them. A denylist can only catch what someone
already thought to name, so a complete manifest factory shipped through four
releases untouched.

## Objectives

1. Remove manifest construction and container writing from the published API.
2. Preserve verification test coverage, which generates its own inputs.
3. Replace the name-shaped gate with one that cannot be defeated by renaming.
4. Make the README's boundary claim true.

## Design

**Consolidation.** The six implementation crates are now private modules of
`encypher-c2pa`, under `crates/encypher-c2pa/src/c2pa-{cbor,core,crypto,formats,trust,validate}/`,
declared with `#[path]`. The domains are not flattened: the facade and validate
both define `verify` and `ValidationResults`, and the six directories keep the
kernel comparable file-for-file with the production copy.

This deletes the problem rather than guarding it. Writers are `cfg(test)` items
inside private modules, so they are unreachable from outside the crate by
construction and absent from the published artifact entirely. The `test-support`
feature introduced by the first attempt is gone; no Cargo feature can expose
them.

**Kernel mirror.** The six modules are the same engine that runs in Encypher's
production signing service. The public verifier exercises a subset; the rest is
reached by the private signer (`c2pa-sign`, `c2pa-cli`), which was verified to
call `build_claim_cbor`, the JUMBF builders, `build_manifest_store`,
`build_manifest_carrier` and `embed_manifest`. Deleting what this crate does not
call would fork the shared source, so dead code in those modules is suppressed
at the six module declarations with a documented reason. `allow` rather than
`expect` because the dead set differs between the lib and test compilations, so
a single `expect` cannot be fulfilled in both.

**Scope correction found during implementation.** `c2pa_cbor::encode` was
initially gated as a writer. It is not: COSE signature verification rebuilds the
`Sig_structure` and encodes it to recover the exact bytes the signature covers.
A CBOR encoder is a serialization primitive, not a C2PA producer. The invariant
was sharpened to: *no public item may construct a C2PA manifest structure or
write one into an asset container.*

**wasm32 correctness.** The elliptic-curve stack reaches `getrandom`
transitively, which refuses to build on wasm32 without a backend. The browser
binding declared this itself, meaning the published library did not build for a
target the README claims. It is now declared on the library.

**Gate design.** An inventory, not a denylist, derived from the compiler rather
than from source text. `scripts/check-public-surface.mjs` runs
`cargo rustdoc --output-format json` and reads rustdoc's own view of the public
API, so re-exports, macro expansion, impl methods, fields and variants are
resolved by rustc instead of guessed. It walks every crate-local item
exhaustively; an unknown item kind, an unnameable impl receiver, a glob
re-export, or any item the walk fails to reach is a FAILURE rather than a silent
omission.

Two axes beyond the item graph are covered because rustdoc only ever describes
the configuration it was asked to build:

- **Features.** The feature map is locked to what `cargo metadata` resolves, not
  what a TOML file spells, so implicit features created by optional dependencies
  are visible. Definitions are locked, not just names.
- **Targets.** The surface is the union over every (target, feature)
  combination a consumer can build - host under all three feature
  configurations, plus wasm32 with no features, which is what the browser
  binding uses.

**What the gate does not cover.** It locks the SHAPE of the API. An approved
item whose body is rewritten to write bytes leaves the inventory unchanged. That
axis is covered from the other side by `crates/encypher-c2pa/tests/read_only_contract.rs`,
which asserts every public entry point leaves its input byte-identical across
success and failure paths and creates no sibling files.

## WBS

- [x] Audit the true public write surface
- [x] Confirm no production verification path depends on any writer
- [x] Consolidate the six crates into private modules of the facade
- [x] Remove the `test-support` feature; writers become `cfg(test)`
- [x] Rehome integration tests and fixtures as unit-test children
- [x] Collapse the release graph to two published packages
- [x] Build the compiler-derived, exhaustive, fail-closed surface gate
- [x] Extend the gate across the feature and target matrices
- [x] Add non-mutation contract tests for the behaviour axis
- [x] Make the library build for wasm32 standalone
- [x] Correct the README, CHANGELOG and SECURITY boundary claims
- [x] Establish what the drift gate actually is (it does not exist - see Open)
- [ ] Completion gate to the bar

## Success Criteria

- Default build of the published library exposes zero manifest constructors and
  zero container writers; `public-surface.txt` holds 172 reviewed items.
- `cargo test --workspace` passes: 319 tests.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- Exactly two publishable packages remain.
- The gate fails on a writer becoming public through any of: a plain addition, a
  renamed addition, a re-export, a macro, `#[doc(hidden)]`, a trait impl on a
  value or reference receiver, an enum variant field, a trait default method, an
  implicit or redefined Cargo feature, or a target-conditional `cfg`.
- The contract tests fail if an approved item's body starts writing.
- The sandboxed suite fails if verification attempts any filesystem mutation, if
  the filter permits a syscall absent from the permission lists, or if a gated
  syscall can reach ALLOW without passing its gate.

## Verification

| Check | Result |
|---|---|
| Public surface inventory | 172 items, zero writers |
| Workspace tests | 319 passed, 0 failed |
| ...of which library unit tests | 277 |
| ...seccomp capability suite | 9 |
| ...non-mutation contract suite | 8 |
| ...CLI, CAWG corpus, API, footers, FFI | 25 |
| clippy `-D warnings` | 0 errors |
| CLI on a real signed MP4 | integrity valid, signature valid, hard binding match |
| `cargo package` | 67 files, 996.6 KiB |
| wasm32 target | clean |
| MSRV 1.88 | clean |
| Publishable packages | `encypher-c2pa`, `encypher-c2pa-cli` |
| Gate vs. target-gated writer | FAIL as designed, item named |
| Gate vs. implicit/redefined feature | FAIL as designed, resolved-vs-approved diff |
| Contract tests vs. mutated `verify_file` | FAIL as designed, while the surface gate passes |
| Sandbox vs. writer via alias, `File::options`, `OpenOptions`, `remove_file`, subprocess, `set_times` | SIGSYS on all six |
| Sandbox vs. inherited `O_RDWR` descriptor | none survives `close_range` |
| Sandbox vs. inherited `MAP_SHARED` mapping | unmapped before the filter; backing file unchanged |
| Policy check vs. unlisted `renameat2`, plain and conditional | FAIL as designed |
| Policy check vs. `RET_ALLOW\|1`, `RET_LOG`, `RET_TRACE`, `RET_USER_NOTIF` | FAIL as designed |
| Policy check vs. `openat`/`ioctl` allowed past their gates | FAIL as designed, missing constraint named |

## Review Loop State

bar: 9.5  max-cycles: 5 (extended by operator)  worktree: ../encypher-c2pa-worktrees/verification-only
branch: feat/verification-only
plan gate: n/a (implementation-first; entered at Phase 5 per the skill's entry table)

Reviewers: `reviewer-gpt55` and `reviewer-opus` for cycles 1-5, `reviewer-sol56`
(GPT-5.6 Sol) from cycle 6 at operator request.

completion gate: STOPPED at cycle 10, not cleared - see 'Why the loop stopped'

  cycle 1  gpt55/opus   correctness 8.0/9.6  simplification 7.2/9.3  security 8.0/9.4  -> not cleared
  cycle 2  gpt55/opus   correctness 7.0/9.7  simplification 7.4/9.6  security  - /9.5  -> not cleared
  cycle 3      - /opus  correctness  - /9.6  simplification  - /9.3  security  - /9.0  -> not cleared
  cycle 4  gpt55/opus   correctness 7.5/9.6  simplification 7.8/9.5  security 7.2/9.5  -> not cleared
  cycle 5  gpt55/opus   correctness 8.0/9.7  simplification 9.5/9.6  security 8.0/9.6  -> not cleared
  cycle 6  sol56        correctness 6.8      simplification 8.8      security 7.4      -> not cleared
  cycle 7  sol56        correctness 8.0      simplification 8.4      security 8.0      -> not cleared
  cycle 8  sol56        correctness 6.8      simplification  -       security  -       -> not cleared
  cycle 9  sol56        correctness 6.6      simplification  -       security  -       -> not cleared
  cycle 10 sol56        correctness 6.0      simplification 8.2      security 6.0      -> STOPPED

  cycle 11 sol56        correctness 6.2      simplification 6.8      security  -       -> not cleared
  cycle 12 sol56        correctness 6.4      simplification 7.8      security  -       -> not cleared
  cycle 13 sol56        correctness 7.3      simplification 8.6      security 7.6      -> not cleared
  cycle 14 sol56        correctness 8.8      simplification 8.9      security 8.7      -> not cleared

  The loop was stopped after cycle 10 and then restarted, and the restart was
  the right call.

  At cycle 10 the scores had gone 6.8, 8.0, 6.8, 6.6, 6.0 - falling while
  fifteen evasions were found and fixed. The cause was real: the fixes for
  cycles 8-10 grew a hand-written Rust attribute parser and a write-effect
  denylist over source text, and each addition was fresh attack surface. The
  reviewer had said twice that no source-level control can establish "no public
  item writes", and it was right.

  So instead of a sixteenth patch, the control moved a layer down.
  `tests/no_write_capability.rs` runs the public entry points under seccomp.
  That reframed the loop: cycles 11 and 12 are no longer about whether a text
  scanner can be made exhaustive, they are about whether a kernel-level
  allowlist is sound. Both cycles found genuine defects in it, and both were
  fixable rather than fundamental:

    16. the filter was a syscall DENYLIST, so io_uring bypassed it entirely -
        a ring performs openat and write as submission entries. Also missing:
        setxattr, utimensat, mknod, fallocate, pwrite64. Inverted to
        default-deny.
    17. `write`/`writev` were permitted to fd 1-2 so the child could print. A
        harness that redirects stdout into a file hands a writer a live
        descriptor; the reviewer changed a file that way. They are now absent
        entirely - the child reports by exit status.
    18. an inherited `O_RDWR` descriptor plus `mmap(MAP_SHARED)` rewrote a file
        without one denied syscall. No syscall filter can see that. The child
        now closes every inherited descriptor before the filter goes on.
    19. `ioctl` with `FS_IOC_SETFLAGS` toggled `FS_NODUMP_FL` on a READ-ONLY
        descriptor, so "the descriptor is read-only" is not a safety property.
        `ioctl` is now gated by request, not by descriptor.

    20. an inherited `MAP_SHARED` file mapping outlived `close_range`. Closing
        a descriptor does not remove the mapping made through it: the permitted
        `mprotect` restored `PROT_WRITE` on the surviving VMA and an ordinary
        store changed the file, with no syscall for the filter to refuse. The
        child now parses `/proc/self/maps` and unmaps every shared file-backed
        mapping before installing the filter.
    21. the self-consistency check ran one way only - every listed syscall must
        appear in the program - so a permission wired into the filter and never
        listed was invisible. The reviewer demonstrated it by adding a bare
        `renameat2` permission and renaming a real file while all tests passed.
        A test now interprets the assembled BPF and asks its verdict for every
        syscall number; an ALLOW appearing in no list fails the build.
    22. that reverse check sampled three concrete argument profiles, so it did
        not establish a statement about all arguments. The reviewer guarded an
        unlisted `renameat2` permission on `args[0] == 3`, which no profile hit,
        had the child open directories until it held fd 3, and renamed a real
        file with every test green. Arguments are now symbolic: both sides of an
        undetermined comparison are explored and every reachable path for an
        unlisted syscall must end in KILL.
    23. the maps parser read field 4 believing it was the pathname. Field 4 is
        the inode. It behaved only because nothing on the host maps a file
        shared; an anonymous shared mapping has inode 0, which is neither empty
        nor bracketed, so the guard would have passed it and the allocator's own
        memory would have been unmapped. The decision now uses the inode, which
        also settles the pathname-with-spaces case that no amount of field
        counting can.

  Most of those are pinned by tests requiring SIGSYS. Two are not, because they
  are closed by something other than the filter and asserting SIGSYS would prove
  nothing: the inherited mapping is closed by unmapping, so its test reproduces
  the attack and checks the backing file is unchanged, and the unlisted
  permission is closed by interpreting the program rather than running it.

  ELEVEN distinct evasions were found in this gate and fixed, each demonstrated
  end to end with a working consumer rather than asserted:

    1. brace inside a string literal desynced the source scanner's depth
       tracking, hiding every later item - it was concealing two genuinely
       public items, so the original inventory was simply wrong
    2. a writer in a private module re-exported with `pub use`
    3. a multiline `impl ... where` header, whose opening brace the impl regex
       did not match
    4. `#[doc(hidden)] pub`, which rustdoc omits by default
    5. explicit trait impls on local types, skipped entirely
    6. reference receivers (`for &Type`), silently dropped - fail-open
    7. struct-like enum variant FIELDS, never walked
    8. Cargo features: rustdoc only emits the configuration it was asked for
    9. implicit features created by optional dependencies, invisible to a
       hand-written TOML parser
   10. redefinition of an already-approved feature to pull in writers
   11. `#[cfg(target_arch = "wasm32")]` items, invisible to a host-only run

  Evasions 1-3 killed the hand-rolled source scanner, replaced by rustdoc JSON.
  Evasions 4-7 forced the walk to become exhaustive with fail-closed defaults.
  Evasions 8-10 added the feature axis, locked via `cargo metadata`. Evasion 11
  added the target axis.

  Cycle 7 also demonstrated that the inventory is behaviour-blind: an approved
  `verify_file` was rewritten to splice a real PNG `caBX` chunk into its own
  input while the gate still reported PASS. That is not fixable by a name/kind
  inventory, so the guarantee is now documented honestly and the behaviour axis
  is covered by contract tests instead. Both controls were verified to fail on
  the exact attack they exist for.

  cycle 8 changes (in review):
    - consolidated the six crates into private modules; surface 931 -> 171
    - deleted the `test-support` feature; writers are private `cfg(test)`
    - release publishes 2 packages, not 8
    - gate unions across the (target, feature) matrix - closes evasion 11
    - added 6 non-mutation contract tests - closes the behaviour gap
    - made the library build standalone on wasm32
    - corrected the drift-gate parity claim, which was overstated: the private
      projection has NOT been updated for this layout

## Open

- **There is no kernel drift gate, and there never was.** I searched the
  monorepo: `scripts/check_kernel_drift.py` does not exist, and the only drift
  gates in `.github/workflows` cover the Next.js build and WordPress plugin
  fixtures. Earlier notes here described it as stale; it is absent. The public
  kernel and the production kernel are compared by review alone.

  Building one is harder than the earlier framing assumed, because the two
  trees are a derivative pair rather than copies - production carries manifest
  construction and container writing and this repo does not, so production
  `c2pa-formats` is roughly twice the size and equality is the wrong test. A
  useful gate would map production paths onto this layout and diff the shared
  functions, modelling the intended removals. That is a real piece of work in a
  separate repo and it is not started.

  It should gate a release. It does not gate this branch, which changes no
  kernel logic - the consolidation moved files and narrowed visibility.
- The six crates.io packages keep every existing version through `1.0.0-rc.11`
  and are deliberately NOT yanked: older `encypher-c2pa` releases exact-pin
  them, and yanking would break fresh resolution of those versions.
