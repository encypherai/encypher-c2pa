# CAWG Identity 1.3 X.509 Conformance

**Status:** plan gate
**Goal:** make the public verifier apply CAWG Identity 1.3 revocation and identity-reference rules, with one documented outside-window deviation pending upstream clarification, then close the assigned public-side coverage gaps with observable regressions.

## Behavior changes

### 1. Embedded revocation is terminal

A qualifying embedded OCSP response that says the identity leaf is revoked
rejects the identity with `cawg.identity.credential_revoked`. Online evidence
cannot erase that result. This holds for every online outcome: absent,
unreachable, received-but-invalid, good, revoked, unknown, or outside-window.
Online evidence is considered only when the embedded leaf result is not
revoked. CA revocation remains `cawg.x509.credential.untrusted`.

This is a fail-closed reading of an ambiguity in X509VALB-003. The stapled
procedure says a qualifying revoked response MUST reject, while the online
procedure can later establish historical non-revocation. A later good online
answer does not disprove that the signed manifest carried a qualifying revoked
answer, and silently overriding signed evidence would let optional network
input change a terminal verdict. The PR will reference an upstream issue draft
asking CAWG to state the intended precedence.

The full leaf decision table is:

| Embedded leaf | Online absent | unreachable | invalid response | good | revoked | unknown | outside window |
|---|---|---|---|---|---|---|---|
| none | `ocsp.skipped` | `ocsp.inaccessible` | Encypher unusable-response info | `ocsp.not_revoked` | `identity.credential_revoked` | `ocsp.unknown` | Encypher outside-window info |
| qualifying good | `ocsp.not_revoked` | not-revoked + inaccessible | not-revoked + Encypher unusable-response info | `ocsp.not_revoked` | `identity.credential_revoked` | not-revoked + unknown | not-revoked + Encypher outside-window info |
| qualifying revoked | terminal `identity.credential_revoked` | same | same | same | same | same | same |
| unusable staple | `ocsp.skipped` | `ocsp.inaccessible` | Encypher unusable-response info | `ocsp.not_revoked` | `identity.credential_revoked` | `ocsp.unknown` | Encypher outside-window info |

Each online column gets an identity-level regression against a revoked staple.
The good-staple rows also prove failed extra assurance does not erase embedded
non-revocation.

### 2. Online OCSP result and provenance

`cawg.x509.ocsp.inaccessible` means exactly that the caller attempted the
responder and received no response. The validation adapter records provenance
once as one of: no attempt, unreachable, or received response plus its parsed
verdict. It does not turn an unreachable marker into the same value returned by
the DER evaluator.

The CAWG identity lane applies this decision table to a received response:

| RFC 6960 / response state | Effective time | CAWG identity result |
|---|---|---|
| Requirements 1-4 fail (malformed, unauthorized, wrong certificate) | any | non-evidence plus `com.encypher.cawg.x509.ocsp.unusable_response`; no `ocsp.inaccessible`; retain the unresolved network need |
| `unknown` | any | `cawg.x509.ocsp.unknown` |
| `good` or `revoked/removeFromCRL`, with `nextUpdate` present | trusted timestamp if present, otherwise current time | not revoked only when `thisUpdate < effective < nextUpdate` |
| same status at either equality boundary or outside the open interval | trusted timestamp if present, otherwise current time | non-evidence plus `com.encypher.cawg.x509.ocsp.outside_window`; never inaccessible or revoked |
| same status with `nextUpdate` absent | any | outside-window non-evidence; the online procedure does not borrow the embedded procedure's `producedAt + 24h` rule |
| revoked for another reason | trusted timestamp present | not revoked only when `thisUpdate < attested < nextUpdate` and `revocationTime > attested`; otherwise revoked |
| revoked for another reason | no trusted timestamp | current time is not substituted for the historical exception; revoked |
| no response after an attempted query | any | `cawg.x509.ocsp.inaccessible` |

The outside-window result deliberately declines the literal "otherwise
revoked" reading for authenticated `good` responses. A live fetch normally has
`thisUpdate` near the fetch time, so the literal reading would mark almost every
older, correctly time-stamped identity revoked. OCSP permits HTTP and these
requests carry no nonce, so it would also let an on-path actor replay a stale
authentic good response to force revocation. The embedded procedure explicitly
accepts an attested time earlier than `thisUpdate`; the online text omits that
case. TEAM_461 treats the omission as a spec defect, reports it under an
Encypher informational code, and supplies an upstream issue draft rather than
claiming `ocsp.inaccessible`.

`OnlineVerdict` gains distinct `OutsideWindow` and `Unusable` outcomes.
`evaluate_online_ocsp` wraps those received verdicts separately from an
`Unreachable` provenance outcome. When one signed OCSP response contains
several matching `SingleResponse` values, only an actual revoked `certStatus`
is contradictory and dominates; an outside-window entry does not outrank a
qualifying good entry.

Window policy splits by lane before `SingleResponse` verdicts are reduced.
`online.rs` receives an internal policy enum:

- **C2PA claim signer:** preserve today's semantics exactly. Equality at
  `thisUpdate` is inside; `nextUpdate` is exclusive; an absent `nextUpdate`
  uses the current `producedAt + 24h` bound; stale and unreachable keep the
  existing `signingCredential.ocsp.inaccessible` outcome.
- **CAWG identity:** use the strict open interval and absent-`nextUpdate`
  behavior in the table above, producing `OutsideWindow` where C2PA produces
  its current `Unusable` or accepted result.

Claim-lane regressions pin `effective == thisUpdate`, absent `nextUpdate`
inside 24 hours, stale response, and unreachable responder before CAWG changes
land. CAWG applies its narrower result mapping only after lane-specific
evaluation. CA-chain handling remains unchanged except that provenance cannot
manufacture revocation.

SDK fetches refused before I/O (endpoint policy/SSRF) are not marked
unreachable; the second verification pass reports `ocsp.skipped` and retains
the unresolved network need. An oversized body means bytes were received but
could not be accepted: record `Unusable`, emit the same namespaced
`unusable_response` code as invalid caller-supplied bytes, and retain the
network need. `OutsideWindow` likewise retains the need so a later fresh query
can settle status. A true transport/server failure is `Unreachable`, emits
`ocsp.inaccessible`, and records no duplicate need.

### 3. Acyclic identity references

A `referenced_assertions` entry may name another CAWG identity assertion.
Build the identity-reference graph once per manifest, using
`assertion_label_for_manifest` as the single edge-resolution predicate. Compute
bounded transitive reachability iteratively with one `u64` bitset per node,
never recursive DFS. A node is a cycle member exactly when it reaches itself,
which is equivalent to membership in a non-trivial strongly connected
component or a self-edge. The graph admits at most
`MAX_IDENTITY_ASSERTIONS` (64) nodes; the existing preflight rejects a manifest
above that limit before graph work. Reject only cycle members. An assertion
that merely reaches a separate
cycle is not itself a cycle member. Cross-manifest references do not add local
graph edges; their hashes still undergo the existing reached-claim check.
Malformed referenced identities contribute no outgoing edges and fail their
own shape/hash checks.

Independent failures still apply (hash mismatch, duplicate, or hard binding).
Tests cover a real signed, claim-hash-bound A-to-B success; A-to-A;
A-to-B-to-A; an A-to-B-to-C chain where only B/C cycle; a shared-descendant
DAG; a 64-node acyclic chain; and the existing over-64 preflight, which must
stop before graph traversal. The clean cutover deletes the blanket
`referenced_identity` rejection, its `identity_assertion_reference` reason, and
the recursive per-assertion cycle walk.

### 4. Claimed-time status scope

`cawg.x509.time_of_signing.outside_validity` is reserved for a usable protected
`iat` outside at least one certificate validity period in the identity chain.
Once the validator elects to validate a usable `iat`, CAWG requires exactly one
inside/outside validity code. The optional chronology check against trusted
`genTime` is separate and cannot suppress or replace that mandated code.

| Protected `iat` | Chain window | Trusted timestamp relation | Status |
|---|---|---|---|
| absent | any | any | none |
| malformed / non-NumericDate | any | any | none |
| usable | outside any chain certificate | any | `outside_validity` |
| usable | inside every chain certificate | absent, `iat <= genTime`, or `iat > genTime` | `inside_validity` |

When `iat > genTime`, emit `inside_validity` plus the namespaced informational
code `com.encypher.cawg.x509.time_of_signing.after_timestamp`; the optional
chronology result cannot replace the mandated certificate-validity code.
Certificate `notBefore` and `notAfter` boundaries, equality with `genTime`,
malformed `iat`, and `iat > genTime` get direct tests. This is a production
behavior change in `report_time_of_signing`, not a tests-only clarification.

## Test-only conformance work

Add focused regressions for the remaining assigned public gaps: unsupported
identity COSE algorithm; `sigTst2` cardinality and source precedence;
CAWG-prefixed time-stamp failure and success codes; identity-chain validity at
trusted `genTime` and current-time fallback; embedded and multi-manifest OCSP
selection and response order; and bounded multi-`SingleResponse` matching.

## Implementation

Keep behavior in the existing private verifier modules:

- `crates/encypher-c2pa/src/c2pa-validate/cawg.rs`
- `crates/encypher-c2pa/src/c2pa-validate/lib.rs`
- `crates/encypher-c2pa/src/c2pa-trust/ocsp.rs`
- `crates/encypher-c2pa/src/c2pa-trust/ocsp/online.rs`
- `crates/encypher-c2pa/src/online.rs`

No public API or report schema shape changes. Add the namespaced informational
codes `com.encypher.cawg.x509.ocsp.outside_window`,
`com.encypher.cawg.x509.ocsp.unusable_response`, and
`com.encypher.cawg.x509.time_of_signing.after_timestamp`. Preserve the 64-entry
OCSP bound and fail closed only on contradictory actual certificate statuses,
not on freshness misses.

## Documentation

- Correct `CHANGELOG.md` where it says all nested identity references are
  rejected, and record all three additive namespaced informational codes.
- Narrow `docs/TRUST_MODEL.md` definitions of CAWG `ocsp.inaccessible` to an
  attempted query that received no response.
- Update the `cawg.rs` status comment and the `online.rs` module/verdict docs so
  they distinguish unreachable, invalid received evidence, and outside-window.
- Include the staple-precedence rationale and the upstream issue draft below in
  the pull request body.

## Upstream issue draft

**Title:** Clarify online OCSP handling for trusted signing times before
`thisUpdate`, and precedence over a qualifying revoked staple

**Body:** CAWG Identity 1.3 accepts embedded OCSP evidence when an attested
signing time is earlier than `thisUpdate`, but the online procedure only names
the open `(thisUpdate,nextUpdate)` interval. A normal live OCSP response
therefore cannot establish status for most archived, time-stamped identities.
The final "otherwise revoked" branch could also make a stale authentic `good`
response force a revoked verdict. A second ambiguity arises when a signed
staple says revoked, but an online `revoked` response has a
`revocationTime` after the trusted signing time and therefore establishes
historical non-revocation. Please clarify whether outside-window good responses
are non-evidence, and whether a qualifying signed revoked staple remains
terminal when optional online evidence would establish historical
non-revocation.

## Acceptance

- Red-to-green behavior tests cite CAWG-ID13-X509VALB-003, -006, -011, -032,
  and CAWG-ID13-ASSERTION-CREATION-017.
- Test-only rows cite their exact X509-VALIDATING-A or X509VALB ids.
- Invert `referenced_identity_assertion_is_rejected`; retain self-cycle and add
  multi-node/SCC/DAG cases.
- Replace the CAWG meaning of
  `a_response_whose_window_has_closed_is_no_answer_at_all` with strict-boundary
  coverage while keeping the C2PA-lane
  `a_stale_response_reads_as_no_answer_rather_than_a_revocation` result
  unchanged.
- Keep CAWG-ID13-X509VALB-011 `partial` for the documented outside-window
  deviation until CAWG resolves the upstream ambiguity.
- Add a regression for every column of the stapled-revoked decision table.
- The affected crate tests pass.
- The branch is committed and opened as a public pull request.
