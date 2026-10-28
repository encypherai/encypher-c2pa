# C2PA 2.5: integrate approved public verifier fixes

Status: Implementation, verification and completion review cleared. Public feature-branch landing authorized; commercial release and deployment gates remain separate.

## Current Goal

Integrate the public verifier revision pinned by approved commercial main into the existing C2PA 2.5 feature branch. Preserve both the published-version support and upstream security/correctness fixes. Commit and push only the feature branch; no main merge, release, tag, package publication, or deployment.

## Source authority

- Worktree: `/home/agentdesk/code/encypher-c2pa-worktrees/c2pa-spec25-optin`.
- Branch: `feat/c2pa-spec25-optin`.
- Feature starting commit: `82f79fa856e170e43e724d7b039282094d1a7c24`.
- Approved commercial main: `6df857d2a28596f80465b25d01d9ff6482da6718`.
- Public target pinned by that main: v1.8.0, `c618dccd397d1e8ac0c86d7918cde5cc60f65bcf`.
- Merge base: `25945232b6ed8ff909699f00d428a62bdddec38a`.
- Nonmutating merge preview: 17 conflicted paths; 22 feature-only and 4 target-only commits.
- The exact target is being merged into the feature branch without a commit. Working source conflicts are resolved; the index remains unmerged until final review and staging.
- Commercial verification remains pinned to its existing immutable public revision until this integration is independently approved and committed.

This is a prerequisite integration, not a claim that commercial landing is cleared. Commercial main synchronization, guarded SDK edits, audit-owner signoff, approved CI tooling adoption, and staging validation remain separate gates.

## Invariants

1. Keep default verification at C2PA 2.4, explicit retained 2.2, and explicit published 2.5. Do not infer a requested profile from untrusted declarations.
2. Preserve report schema 1.0 and established validation status codes. Additive supported-version behavior must not silently change frozen 2.2/2.4 vectors.
3. Preserve upstream constant-time ECDSA dependencies and the RUSTSEC-2026-0387 correction. Do not restore the older dependency stack to simplify conflict resolution.
4. Legacy ES algorithms retain their upstream digest/curve semantics. C2PA 2.5 ESP algorithms enforce their designated curve. Preserve the feature's version-specific algorithm policy and ML-DSA behavior without widening older profiles.
5. Preserve upstream bounded whole-segment traversal, caller-supplied trusted presentation times, and timescale/duration validation. Reject duplicate IDs within a segment or across different segment bytes; retain exact whole-segment replay when authenticated sequence/seek rules permit it. Untrusted `iat` values are not a trusted presentation-time source.
6. Preserve upstream external/whole-file binding finality and source-evidence checks alongside feature profile handling. Do not stop parsing early merely to make fixtures pass.
7. Keep the public surface verification-only, with no signing, hosted policy, secrets, or remote trust lookup added to exported APIs.
8. Preserve binding options and validation semantics across Rust, CLI, C, Go, Python, and WASM. Combine upstream inputs with feature selectors rather than selecting one entire side.
9. Do not regenerate frozen conformance fixtures or expected outcomes to hide changed behavior. Regenerate derived public-surface inventory only through its owning script, and review its semantic changes.
10. No generated-file guard bypass, test weakening, advisory waiver, or source changes during verification.

## Approach and ownership

The parent owns this plan, the merge operation, final integration, generated inventories, verification, review, and commits. Implementation uses the requested GPT-6.1 Sol medium coding role. Writers receive disjoint files, skip builds/tests/formatters while editing, and coordinate any interface changes before committing to them.

After the prospective plan gate clears, merge the exact public target into the feature branch without committing. Resolve conflicts by preserving the union of required behavior, not by wholesale ours/theirs selection.

### Slice A: crypto and dependency compatibility

Own all workspace Cargo manifests and dependency changes, `c2pa-crypto/cose.rs`, `c2pa-crypto/session.rs`, and `c2pa-validate/cawg_ica.rs`, plus focused crypto regressions in those files or their existing test locations. Adopt upstream p256/p384/p521 0.14 and ECDSA 0.17 interfaces while preserving feature algorithms and profile policies. Preserve upstream CAWG verification fixes. Keep existing externally consumed crypto entrypoint contracts unless a coordinated change is demonstrably necessary. The parent regenerates the lockfile after all manifest edits.

### Slice B: formats, validation, and binding behavior

Own `c2pa-formats/lib.rs`, `c2pa-formats/text.rs`, `c2pa-validate/lib.rs`, `c2pa-validate/live_video.rs`, `c2pa-validate/stream.rs`, the crate's public `src/lib.rs`, runtime binding sources (including Go and Python), and relevant behavioral regressions. Preserve whole-file/source-evidence validation and bounded stream semantics while threading explicit profiles through every affected path. Retain both upstream trusted-time inputs and feature version selectors. Audit nonconflicting callers too; Git's lack of conflict is not evidence of semantic compatibility.

### Required merge decisions

**Detached admission and finality.** Use one authoritative classification pipeline shared by ordinary detached, graph-input, online discovery/reverification, and CAWG-backed detached paths. Reuse the existing format-resolution helpers instead of adding a parallel MIME switch. Canonicalize with upstream detached aliases, apply designated external-media byte checks including AAC/BMFF distinction, and propagate malformed-media errors without falling back. Preserve ordinary reader/profile handling and 2.5 text-carrier selection. Only remaining syntactically valid, eligible 2.5 MIME types may become `Opaque`; do not widen retained profiles to arbitrary unknown types. Keep `Opaque` for that intended 2.5 support, but apply the same whole-file finality as `ExternalMedia`: neither accepts nonempty exclusions or rescues a failed primary binding through a multi-asset fallback. For other formats retain the 2.5 `created_assertions` fallback restriction. Preserve detached rendition's absent carrier and profile-versioned native exclusion geometry. The 2.5 early-return path must pass the same admission checks. A caller changing a MIME string must not regain a weaker detached-only binding policy. Avoid redundant byte scans within a validation pass.

The two detached-only variants intentionally distinguish checked designated media from eligible unknown 2.5 bytes; their whole-file finality is shared by contract. The refusal matrix is a hard completion gate, not an optional test suggestion.

**Crypto/stream interface.** Slice A retains `verify_with_cose_key_with(cose_sign1: &[u8], cose_key: &[u8], list: ClaimAlgorithmList) -> Result<VerifiedCoseKeySignature, CryptoError>`. Slice B supplies the selected list at every session verification call, retaining upstream's `in_window(key, assessment_time)` gate before signature verification. Assessment time comes from caller-trusted per-segment presentation times when supplied, otherwise validation time; signed `iat` has independent constraints and never replaces caller assessment time. The collection-level `validate_emsg_segments` structure carries the selected algorithms through every segment rather than calling a default-policy helper.

Extend upstream `validate_emsg_segments` with `ClaimAlgorithmList` and thread it into `validate_emsg_segment_with`; do not reintroduce an implicit default-policy call.

**Legacy and new ECDSA semantics.** Legacy ES takes upstream digest-by-algorithm, curve-by-key semantics in both certificate and COSE_Key paths. This deliberately corrects the feature's current session-key curve pinning for legacy ES; do not restore that pinning during review. ESP uses the same coherent prehash implementation with a required curve. Preserve optional COSE_Key `alg`, rejecting duplicates and mismatches when present. Preserve certificate-path legacy DER signature acceptance without extending it to ESP. Session COSE_Key signatures retain their existing fixed-width-only acceptance for both ES and ESP; do not add DER support there. Adapt the feature's existing unified certificate helper to new traits rather than keeping upstream's duplicate early ES path. Retain the signature/SPKI generations needed by RSA and Ed25519. Compose CAWG certificate-profile handling with the upstream prehash fix, including nonconflicted bodies. Preserve upstream TLS/root lockfile security corrections as well as ECDSA changes. Do not lower or drop existing Rust 1.88 minimum declarations.

Split the feature's fused ES/ESP session match arms into legacy curve-by-key and ESP required-curve handling. Retain both the upstream ECDSA helper behavior and the feature's `COSE_KTY_AKP`/ML-DSA handling.

**Stream integrity and replay.** Preserve upstream collection-wide state, authenticated starting floor for rotated streams, continuity across keys, and full structural traversal after a valid event. Recognize C2PA version-0 events with the required value. Preserve fully qualified `/emsg` exclusions, exclusion of the carrying C2PA event, and refusal to exclude unrelated events. Refuse segment-info `bmffHash` containing `merkle`. An authentic signature does not excuse a malformed tail, broad exclusion, expired assessment window, or unannounced discontinuity.

**Bindings and test unions.** Keep both `spec_version` and `stream_presentation_times` throughout public Rust, C JSON/header contracts, Go, Python, WASM, CLI, and caller-verified-binding paths. Preserve absent versus explicitly empty time lists, wrong-count/malformed refusals, and unsupported-mode refusals. Do not add `omitempty` to Go's presentation-times JSON tag. Preserve Python's bare-string refusal and independent option-preflight cases. Keep graph inputs in the detached pass. Merge the session, text, and validator test modules by behavioral coverage, not by selecting an entire side. Text resolution must retain revision-specific locator rules and upstream A.9.4 preceding-line-terminator geometry without rewriting frozen vectors.

The competing session algorithm, live-video window/policy, facade admission, CAWG imports, validator binding, and option-field hunks require semantic resolution. Blind ours/theirs/both resolution is prohibited there, including the large test-module conflicts.

### Parent integration

Resolve changelog and derived public-surface inventory. Inspect all merged manifest versions and every affected binding's caller contracts. Regenerate Cargo.lock using the resulting manifests, with no unrelated dependency upgrade. Keep tests that cover different consumer-visible cases; remove only obsolete source-text/wiring assertions if encountered. Update existing README/report/format documentation where observable behavior changes require it.

Do not update the commercial public-verifier pin until this combined public source has passed its checks and review. A later pin update must be accompanied by commercial adapter/native smoke checks and does not substitute for full commercial main synchronization.

## WBS

- [x] Complete independent prospective analysis and plan scoring: both analysis roles cleared amendments; cycle 1 passed every dimension at 10.0/9.6 (GPT-5.5/Opus).
- [x] Merge the exact approved public revision into the feature branch and resolve crypto/dependency conflicts.
- [x] Resolve formats, validation, and binding conflicts without losing either side's required behavior.
- [x] Regenerate lockfile and public-surface inventory through owning tooling; review the resulting public contract.
- [x] Run the repository's complete applicable automated gates, with source frozen.
- [x] Exercise the rebuilt CLI on genuine 2.5 fixtures and retained-profile fixtures; verify a real tamper/refusal path.
- [x] Review implementation, finalize existing docs, and complete simplification/security review.
- [ ] Clear independent completion scoring and commit/push the feature branch only.

## Verification and success criteria

Read the actual GitHub workflows and owning scripts before selecting commands; CONTRIBUTING.md is a minimum, not an exhaustive CI inventory. Use bounded build parallelism and do not run resource-heavy public checks against the active commercial CI gate without checking the owning admission policy.

Required automated coverage:

- Workspace tests, formatting, default clippy, and explicit `caller-verified-binding` clippy/tests from `.github/workflows/ci.yml`.
- Rust 1.88 workspace and `caller-verified-binding` checks. Correct CONTRIBUTING.md's stale 1.85 minimum, citing the existing manifest `rust-version` as source of truth.
- `cargo audit` without new advisory ignores; license/NOTICE copy checks; release-helper unit tests.
- Public-surface checks with pinned `nightly-2026-08-07`, covering the existing host/WASM feature matrix. Review generated changes against the union of the feature and approved upstream inventories; any genuinely new export requires separate justification and review.
- Go tests against the rebuilt C library; Python wheel build, binding tests and verification smoke; x86_64 and aarch64 musllinux wheel builds with the existing Alpine x86_64 runtime smoke; WASM build/package/runtime checks.
- Existing genuine C2PA 2.5 fixtures and frozen 2.2/2.4 vectors, unchanged.
- Certificate and session COSE_Key coverage for legacy ES256 with P-384 acceptance, ESP256 with P-384 refusal, allowed algorithms by explicit profile, existing ML-DSA cases, and optional/mismatched/duplicate COSE_Key algorithm labels.
- Detached refusal matrix: designated external media and unknown MIME, each under 2.2/2.4/2.5, against nonempty exclusions and multi-asset rescue attempts. Retained profiles may reject unknown MIME at admission. Include malformed designated bytes, aliases, AAC/BMFF distinction, and a valid genuinely unknown 2.5 whole-file binding that remains supported.
- Stream coverage for expired keys at caller presentation time, independent signed-time bounds, malformed trailing segments, qualified versus broad event exclusions, unrelated events, Merkle refusal, and timescale/duration bounds.
- Replay coverage: exact whole-segment replay with declared seek succeeds; unannounced discontinuity and repeated IDs within a segment or across differing segment bytes fail; rotated initialization starts at the authenticated floor and preserves cross-key continuity.
- Binding time-input coverage: absent, empty, wrong-count, malformed, and unsupported Merkle/per-segment/VerifyFragmented inputs retain distinct behavior. Exercise Go nil-versus-empty through the actual JSON bridge and verification result, not a serializer echo test; preserve Python bare-string refusal.
- Source-evidence/external binding finality and option propagation through actual verification behavior across the detached entrypoints, including online and graph paths. Preserve both independent text regression families.

Retain existing adequate tests. Add regression tests only for uncertain or previously uncovered consumer-visible cases; reproduce any newly found bug before fixing it when practical. A merge conflict alone is not an executable failing test.

Actual runtime proof must include rebuilt CLI output, explicit profiles, expected trust/integrity distinctions, and a negative/tamper path. A valid signature does not imply trusted provenance or CPL certification. Record exact commands and observed results before claiming completion.

The completion gate requires both independent analysis roles followed by both independent scorers at >=9.5 in correctness, simplification, and security. Failures, missing binding checks, or unresolved semantic conflicts prevent clearance. No retrospective plan approval or invented scores.

## Risks and boundaries

- Dependency upgrades change crypto traits and prehash interfaces. Passing only default P-256 cases can miss legacy mixed-curve behavior.
- Large validator merges can silently drop limits, external binding finality, or profile propagation even when compilation succeeds.
- Main binding additions and feature selectors must coexist; public-surface inventory is evidence to inspect, not permission to expand signing capabilities.
- The combined public commit does not fix the commercial signer's older dependency stack by itself.
- Repository main can advance independently. This integration targets the exact approved pin above; later authority changes require a fresh delta assessment, not an automatic claim of freshness.
- Any inaccessible ownership or tool-guard prerequisite is reported explicitly, never bypassed.

## Implementation and verification evidence

- Adopted the published constant-time crypto stack without unrelated dependency upgrades. Regenerated lockfile adds only the seven dependencies required by the feature's ML-DSA and compressed-content support.
- Restored the published `CawgEvaluation::Evaluated::store_manifest_sha256` raw tuple field, replacing the feature's unreleased rename. The regenerated 937-item public inventory differs from the union of both source inventories only by removal of that unreleased replacement field. Commercial adapter migration remains a separate pin-update prerequisite.
- Parent reproduced an unintended expansion of session signature acceptance to DER, then verified the fixed-width-only regression after repair. Legacy certificate DER behavior remains unchanged.
- Independent security review found graph-fragment verification silently ignored present `stream_presentation_times`. The real Merkle fixture reproduced acceptance before the fix; after repair, absent times still verify and empty, matching-count, wrong-count and malformed lists all refuse with `InvalidValidationTime`. The hunter independently confirmed the repair.
- Matrix runs `artifact://2603` and `artifact://2616` passed their invoked commands: default and optional-feature clippy/tests, Rust 1.88 checks, advisory audit without new ignores, surface/license checks, release-helper tests, Python/WASM bindings, both musllinux architectures and actual Alpine verification. Their Go result was cached and is not accepted as proof of fresh native linkage.
- Actual CLI verified freshly signed 2.5 JPEG and text with explicit fixture-root trust. Retained 2.2 and default/explicit 2.4 passed; the two 2.4 outputs matched. Tampered bound text returned exit 2 with invalid integrity, valid signature and `assertion.dataHash.mismatch`. Detailed results: `local://c2pa25-public-cli-smoke.json`.
- Simplification removed the obsolete detached classification helper, duplicate MIME normalization and unused implicit-policy segment/session wrappers. Tests name their selected algorithm list explicitly. The live CAWG default-policy caller remains unchanged. The CAWG detached documentation now states profile-specific admission and malformed-media refusal.
- Security hunters `C25CryptoSecurity` and `C25BindingSecurity` found no confirmed exploitable vulnerability in the scoped crypto, binding and streaming changes. The graph option defect above was a repaired correctness issue. This is not a whole-product security certification.
- Updated CONTRIBUTING.md's stale minimum to the manifest's Rust 1.88 requirement and recorded behavioral fixes in CHANGELOG.md. No frozen fixture, expected conformance result or advisory waiver was changed.
- Mandatory Astra analysis identified the cached Go evidence gap. CI, contributor instructions and the local gate now use `go test -a -count=1` after rebuilding the C archive. Final matrix `artifact://2627` passed, including fresh Go linkage/execution, both musllinux builds and Alpine runtime. All six CLI cases passed again on that build and retained their expected reports (`local://c2pa25-public-cli-final.json`). Pinned actionlint 1.7.12 also accepted the amended CI workflow.
- Completion review subsequently found that external-evidence preflight skipped indexed presentation-time validation and detached verification still normalized MIME repeatedly across layers. The paired public-method regression failed before repair: `validate_with_external_data` returned `Ok` for malformed index 1. Both repairs passed subsequent verification. Gate scripts echo commands so the artifact identifies each invoked check.
- Reviewer `C25PublicCompleteGpt` reported actual runtime `openai-codex/gpt-5.6-sol`, despite the configured GPT-5.5 role. Its findings are retained, but it is not evidence that a GPT-5.5 completion review ran. Opus 5.5 scored correctness 9.6, simplification 9.5 and security 9.7 on the preceding snapshot; those scores do not approve subsequent repairs.
- Both completion repairs now pass the full traced matrix (`artifact://2637`). Independent analysis caught an embedded AAC alias regression during normalization; the public discovery regression failed before repair under 2.5 and passes after ordinary embedded normalization was restored. It compares store presence, resource frontier and stop reason across aliases under 2.2/2.4/2.5.
- Both mandatory analysis roles confirmed the final preflight, canonicalization and AAC corrections in source without remaining actionable findings. The final build passed all six actual CLI cases with unchanged expected reports, including tampered-text refusal. Node exercised WASM `verifyOnline`: malformed indexed presentation time failed before any fetch. The initial smoke assertion expected an object error, but the adapter's existing contract is a string; the corrected smoke asserted that contract and passed.

## Review Loop State

bar: 9.5
max-cycles: 5
plan gate: CLEARED (cycle 1)
  correctness: 10.0/9.6 (GPT-5.5/Opus), both pass
  simplification: 10.0/9.6, both pass
  security: 10.0/9.6, both pass
completion gate: CLEARED (cycle 4; GPT-5.6 Sol / Opus: correctness 9.5/10.0, simplification 10.0/9.7, security 10.0/10.0)

Cycle 2 (actual GPT-5.6 Sol / Opus 5.5): correctness 10.0/9.8, simplification 9.2/9.6, security 10.0/9.7. The remaining medium finding was seven facade format lookups that normalized already-canonical MIME again. Those calls and the canonical XML-carrier check now reuse the existing canonical-only lookup. Raw-input kernel and registry boundaries retain their existing normalizer contracts.

Cycle 3 verification: full command-echoing matrix `artifact://2642` passed on the final canonical-lookup delta and kernel precondition comments. Fresh execution of all six CLI scenarios matched the prior expected reports, including tampered-text refusal (`local://c2pa25-public-cli-final.json`). Fresh WASM `verifyOnline` execution returned indexed `invalid_validation_time` with zero fetches and exit 0 (`local://c2pa25-wasm-preflight-smoke.json`). Both evidence files identify matrix 2642. Independent rescoring requested; no completion clearance inferred from passing verification.

Cycle 3 scores (actual GPT-5.6 Sol / Claude Opus 5.5): correctness 10.0/10.0, simplification 10.0/9.7, security 10.0/10.0; both verdicts pass in every dimension. Both reviewers inspected the final source, matrix 2642 and the fresh CLI/WASM evidence. No medium-or-higher finding remains. Opus retains one low, optional simplification note: the consistent presentation-time refusal appears at three entry points. No helper refactor was added solely to remove that small duplication. These scores cover only the public integration and do not satisfy the required GPT-5.5 identity or any commercial, release or staging gate.

Historical model-routing blocker: `reviewer-gpt55.md` requested GPT-5.5, but public and private scorer runs reported GPT-5.6 Sol. Escalation: `08c8c135-eaaf-4a81-ac03-afd1e6f9da07`. The user subsequently corrected the stale requirement and approved GPT-5.6 Sol for this review. Scores retain actual model identities; this clears the public review prerequisite without asserting that GPT-5.5 ran.

Landing request, October 28: user requested landing. Existing public draft PR is https://github.com/encypherai/encypher-c2pa/pull/44; its head matches local `82f79fa856e170e43e724d7b039282094d1a7c24`. Public main and the pending merge parent both remain `c618dccd397d1e8ac0c86d7918cde5cc60f65bcf`. Working source has no conflict markers; the index intentionally remains unmerged pending clearance.

Completion cycle 4: new independent reviewers inspected source and matrix 2642. Actual GPT-5.6 Sol scored correctness 9.5, simplification 10.0, security 10.0; actual Opus (`anthropic/claude-opus-4-8`) scored 10.0, 9.7, 10.0. Both passed every dimension. The configured GPT-5.5 agent still reported GPT-5.6 Sol, so the required identity remains unsatisfied. The supported eval agent interface also exposes no model override. No gate bypass, commit or push was performed. The low README scope omission was corrected to name selectable 2.2/2.4/2.5 policies and the unchanged 2.4 default; executable source is unchanged. A fresh offline CLI MP4 smoke returned exit 0, default profile 2.4, valid integrity/signature, matching binding, and trust not evaluated.

User policy correction, October 28: "5.6 sol is better than 5.5. our docs are out of date." GPT-5.6 Sol is accepted as the OpenAI reviewer for this landing. Combined with the independently passing Opus review and completed mandatory analyses, cycle 4 clears the 9.5 completion bar. Earlier blocker statements above record their historical state, not an outstanding requirement. No commercial gate is waived.

Independent analysis: C25ThinkAstra and C25ThinkFable inspected source, identified admission/stream/crypto/binding risks, and confirmed the amended contracts address their actionable findings. Scorers: C25PublicPlanGpt and C25PublicPlanOpus. Opus's low-severity clarifications are recorded above: explicit collection-helper parameter propagation, split ES/ESP session arms, distinct admission roles with shared finality, and a mandatory refusal matrix.

The plan scores above are prospective. Public implementation completion is separately approved by cycle 4.

Implementation review clarification: the source snapshots accept DER only in the legacy certificate path, not the session COSE_Key path. Parent found an unintended session DER expansion in Slice A's first implementation and requested a failing-before regression followed by repair. The repaired fixed-width-only session contract passed verification and completion review.
