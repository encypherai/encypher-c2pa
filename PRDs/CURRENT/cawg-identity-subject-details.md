# CAWG Identity Certificate Subject Details

**Date:** 2026-09-28
**Status:** IMPLEMENTED - COMPLETION REVIEW
**Owner:** PublicIdentitySubject
**Release:** 1.3.1

## Problem

The public verifier validates the X.509 credential behind a CAWG identity but does not expose the validated leaf certificate's subject organization or common name. Browser readers therefore cannot display the named actor from credential-bound evidence. One current reader instead parses an organization name from a CAWG role string, which fails when conformant signers emit a bare role such as `cawg.publisher`.

## Contract

Add three optional machine-readable fields to the terminal X.509 identity status details:

- `subject_organization`: the leaf subject's first X.509 `O` attribute in DER order across RDNs and AVAs, when usable.
- `subject_common_name`: the leaf subject's first X.509 `CN` attribute in DER order across RDNs and AVAs, when usable.
- `certificate_trusted`: whether the terminal X.509 result is trusted under the active trust policy. This repeats the terminal code deliberately so a consumer holding only `details` can gate safely. `false` on `cawg.identity.well-formed` means no trust evaluation was possible because no CAWG material was configured, not that an evaluated chain was rejected.

The fields appear only on the authoritative terminal status:

- `cawg.identity.trusted`: `certificate_trusted: true`, with available O/CN.
- `cawg.identity.well-formed`: `certificate_trusted: false`, with available O/CN. This status is possible only when no CAWG trust material was configured. The signature and certificate profile validated, but the subject is not represented as trusted.

A configured chain that fails trust continues to terminate as `cawg.x509.credential.untrusted`. It receives no O/CN fields. ICA statuses receive none because their identity evidence is not an X.509 leaf.

All languages and the browser receive the fields through the existing JSON `details` object. No binding-specific option or public Rust item is added, so `public-surface.txt` remains unchanged.

### Consumer Handoff

A reader MUST select the containing manifest, match the exact identity assertion label to the terminal status whose `url` is that label, and read `subject_organization`, `subject_common_name`, and `certificate_trusted` only from that status. It MUST NOT search statuses globally or pair one identity assertion with another identity's subject. A failure for the same assertion label takes precedence over any success retained in the report. Multiple identities remain separate records.

The fields are sanitized display strings, not stable identity keys. Consumers MUST render them as escaped text, isolate their bidirectional direction, and show certificate trust independently from the name. They SHOULD NOT present `subject_*` as the named actor or as a verified organization unless `certificate_trusted` is true. They MUST NOT infer identity equivalence from string equality or make homoglyph-safety claims. A stable leaf-certificate identifier is outside this slice; these display fields must not substitute for one.

## Subject Encoding and Bounds

Only `O` (OID 2.5.4.10) and `CN` (OID 2.5.4.3) are needed. CAWG UX guidance calls for a company name and verification context; it does not require country or organizational unit. Adding `C` or `OU` would expose more identity data without serving the reader's actor-name use case.

Selection is first-match and fail-closed: inspect RDNs and their AVAs in decoded DER order, stop at the first matching OID, and never fall through to another matching attribute. If that first value is unusable, omit the field.

Each value:

1. accepts RFC 5280 DirectoryString PrintableString and UTF8String tags; IA5String is accepted only as compatibility leniency;
2. omits BMPString and TeletexString, unknown tags, and byte content that is not valid UTF-8. `der` 0.7.10 rejects UniversalString while parsing the certificate, so a UniversalString subject never reaches the field decoder;
3. has exactly these display controls removed: C0 (`U+0000`-`U+001F`), DEL and C1 (`U+007F`-`U+009F`), Arabic letter mark (`U+061C`), zero-width space (`U+200B`), left-to-right and right-to-left marks (`U+200E`, `U+200F`), line and paragraph separators (`U+2028`, `U+2029`), bidi embedding and override controls (`U+202A`-`U+202E`), bidi isolate controls (`U+2066`-`U+2069`), and byte-order mark/zero-width no-break space (`U+FEFF`);
4. preserves all other Unicode, including non-Latin scripts and the script-significant ZWNJ/ZWJ (`U+200C`, `U+200D`);
5. is omitted if empty after sanitization;
6. is omitted rather than truncated if the sanitized UTF-8 value exceeds 256 bytes.

The bound prevents a certificate from expanding report output or UI work with an attacker-sized subject. Omitting an oversized value avoids presenting a partial identity. The sanitizer reduces terminal, invisible-text, and bidi-control hazards. It does not make visually confusable names equivalent or safe to use as identity keys.

## Implementation

1. Replace the existing report name decoder in `crates/encypher-c2pa/src/c2pa-validate/cert.rs` with one shared, strict, bounded `name_attribute` helper and migrate `signature_info` to it in the same change.
2. Call that helper from `crates/encypher-c2pa/src/c2pa-validate/cawg.rs`; do not introduce another X.509 name decoder.
The separate `c2pa-trust` Common Name reader is intentionally unchanged: it identifies configured trust anchors internally and never populates a public display field.
3. Leave rejection details and ICA output unchanged.
4. Document the additive report fields in `docs/REPORT_SCHEMA.md` and the trust distinction in `docs/TRUST_MODEL.md`.
5. Add the 1.3.1 release note and update the repository's coordinated package versions for Rust, CLI, Python, C, and WASM. No package is published from this worktree.

## Tests and Proof

TDD coverage in the CAWG validator module will prove:

- a trusted fixture with known O/CN reports both fields and `certificate_trusted: true`;
- the no-trust `well-formed` result reports the same fields with `certificate_trusted: false`;
- a configured but untrusted chain reports no subject fields;
- every C0, C1, and named bidi/invisible code point is stripped while ZWNJ/ZWJ and non-Latin scripts are preserved;
- exactly 256 UTF-8 bytes are kept, 257 are omitted, and a multibyte character crossing the boundary is omitted intact;
- invalid UTF-8, BMPString, and TeletexString are omitted, while UniversalString is rejected during certificate parsing;
- if the first O or CN is control-only or oversized, the field is omitted even when a later matching attribute is usable;
- ICA statuses remain free of these X.509 subject fields;
- the packed Node smoke uses the frozen, redistributable `x509-es256-jpeg.jpg` corpus vector with its recorded claim and identity certificates. It exercises the same assertion as trusted, well-formed with no CAWG trust material, and rejected against an unrelated configured CAWG certificate. Exact `status.url` matching proves each outcome belongs to `cawg.identity`; the configured rejection exposes no subject fields. The existing corpus index records the fixture source, license, expected status codes, and SHA-256.

After the focused Rust test is green, run the repository suite required for this public change, build the release browser WASM package, and run a Node smoke against the packed `@encypherai/c2pa` package. The smoke will verify a real CAWG X.509 fixture and read O/CN from terminal status details.

The plan originally called for a new multi-identity binary fixture. It was dropped after both current and pinned c2pa-rs generators emitted an invalid hard binding when two dynamic identity assertions were added. No invalid asset was retained. The replacement in-crate test builds two signed identity assertions with distinct X.509 leaves in one parsed manifest, trusts only the first chain, and proves exact-label terminal binding plus same-label failure precedence after the rejected identity has already recorded a lower-level signature success.

## Delivery

Open a public PR without merging. A human maintainer must merge, tag `v1.3.1`, let the release workflow publish `@encypherai/c2pa@1.3.1`, and record the npm integrity digest. The commercial content-provenance reader can bump its exact dependency only after that registry publication exists.

## Acceptance Criteria

1. Trusted X.509 CAWG terminal details expose bounded, control-free UTF-8 O/CN and `certificate_trusted: true`.
2. Well-formed/no-root details expose the same evidence only with `certificate_trusted: false`.
3. Configured untrusted chains and ICA results do not expose X.509 subject fields.
4. Rust and browser package proof pass.
5. Version and release notes identify 1.3.1, the public PR is open, and no package is published by this agent.
