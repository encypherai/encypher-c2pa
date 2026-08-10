# Changelog

All notable changes to this project are recorded here.

## 1.0.0-rc.12 - 2026-08-10

- Consolidated the six implementation crates (`encypher-c2pa-cbor`, `-core`, `-crypto`, `-formats`, `-trust`, `-validate`) into private modules of `encypher-c2pa`. They had no consumer, accounted for 81% of the public API surface, and publishing them is what forced manifest construction to hide behind a Cargo feature. Their existing versions through `1.0.0-rc.11` remain on crates.io and are not yanked; older releases of `encypher-c2pa` exact-pin them. New releases publish only `encypher-c2pa` and `encypher-c2pa-cli`.
- Removed manifest construction and container writing from the published API. Claim building, JUMBF and manifest-store assembly, `embed_manifest`, `strip_manifest`, and `build_manifest_carrier` now live in private modules and compile only under `cfg(test)`. The SDK reads and verifies C2PA manifests and exposes no way to produce one. The `test-support` feature introduced for this purpose is gone; module privacy replaces it.
- Breaking change for anyone depending on the six implementation crates directly. There are no known consumers. Use `encypher-c2pa`.
- Added `scripts/check-public-surface.mjs`, a CI gate that enumerates every publicly reachable item and diffs it against the reviewed `public-surface.txt`. Any newly public item fails the build until a reviewer adds it deliberately, so a renamed writer cannot slip through the way a name-based check would. The gate runs on every pull request and before every release.
- Added pinned, offline c2pa-rs core and CAWG interoperability corpora with fixed source commits, checksums, normative expected status codes, and CI enforcement.
- Fixed legacy ES256 verification, claim-v1 RFC 3161 timestamp handling, manifest-carrier exclusion normalization, and ingredient active-manifest and claim-signature authentication.
- Completed BMFF hard-binding verification across the full nested box tree: `c2pa.hash.bmff` V2 and V3 exclusion maps now resolve container boxes at any depth, apply each map's `data` match conditions and `subset` byte ranges, and read full-box version and flags, under bounded tree depth and box counts.
- Enforced the mandatory C2PA 2.x actions structure on standard manifests: a created actions assertion must be present, its first action must be `c2pa.created` or `c2pa.opened` (a `c2pa.created` action requires a `digitalSourceType`), and exactly one such inception action may appear and only in first position; otherwise verification reports `assertion.action.malformed`.
- Hardened untrusted-input verification: claim-v1 timestamps no longer anchor signer-certificate validity, positive stapled OCSP status now requires a trusted signing timestamp and the C2PA `producedAt` freshness window, ambiguous JUMBF labels fail closed, assertion and reference collections are bounded and indexed, and BMFF exclusion and Merkle chunk processing use bounded work and checked arithmetic.
- Completed C2PA 2.4 assertion integrity checks: undeclared assertions fail closed, canonical JUMBF paths and cardinalities are enforced, one primary hard binding is separated from the `c2pa.hash.multi-asset` fallback, and the operative binding is carried into CAWG identity validation.
- Added full bounded multi-asset validation for byte-range and BMFF-box locators with part-specific data, BMFF, and general-box hash methods. Ingredient, assertion, CBOR, JUMBF, BMFF Merkle, x5chain, CAWG identity, and embedded OCSP processing now have aggregate work, allocation, count, and byte limits.
- Made embedded revocation evaluation store-wide and order-independent, with verified revocation taking precedence over good status, exact BasicOCSPResponse typing, bounded responder selection, and the C2PA embedded-evidence timing policy.
- Added a release gate that requires the Git tag, workspace package version, and CLI's exact library dependency to match before any crate, wheel, or browser package is published.

## 1.0.0-rc.11 - 2026-08-08

- Corrected the browser install command to use the package's active `latest` tag. The `next` tag intentionally trails while no stable release exists because npm OIDC publishing can assign only one tag per publish.

## 1.0.0-rc.10 - 2026-08-08

- Removed the signing-specific `prehashed_binding` extractor and `PrehashedBinding` type from the published validator. The generic detached `verify_prehashed_manifest` verifier remains public.
- Renamed the validator's signing-workflow error variant to `ValidateError::HardBinding` and made its diagnostics describe the malformed C2PA hard binding.
- Fixed npm trusted publishing so the active release candidate can reclaim `latest` while no stable release exists. Once a stable version holds `latest`, later prereleases publish to `next`.

## 1.0.0-rc.1 - 2026-08-05

- Added CAWG Identity 1.2 validation: X.509 COSE identity assertions and identity-claims-aggregation (ICA) verifiable credentials, with countersigner topology checks and spec status codes (`cawg.identity.*`, `cawg.ica.*`).
- Made CAWG outcomes assertion-scoped: `cawg.*` codes report the identity assertion's own verdict and never change the C2PA manifest's validation state or integrity verdict.
- Added a pinned offline DID-document store for `did:web` ICA issuers (`--cawg-did-documents`, `cawg_did_documents`); absent issuers fail closed with `cawg.ica.did_unavailable`. `did:jwk` resolves by pure local decoding.
- Added CAWG trust surfaces: `--cawg-trust`/`cawg_trust_pem` anchors, `--cawg-allowed`/`cawg_allowed_certs_pem` end-entity allow-list, and the `--cawg-document-signing-require-anchor` policy switch.
- Added `--cawg-strict-encoding`: refuse CAWG 1.1-era legacy encodings; by default they verify and surface the informational `com.encypher.cawg.legacyProfile` status.
- Added full RFC 3161 timestamp verification against caller-supplied TSA anchors (`--tsa-trust`); a trusted timestamp anchors certificate-validity evaluation, enabling verification of assets signed by since-expired certificates.
- Broadened the claim-signer EKU policy to the reference set (C2PA claim signing, both document-signing OIDs, emailProtection, Microsoft C2PA), with sole-EKU rules for timeStamping/OCSPSigning, and stopped a credential-profile failure from suppressing downstream signature, hashed-URI, and hard-binding results.
- Added the C2PA v2 manifest-label grammar check (`claim.malformed`), hashed-URI cross-manifest hardening, curve-derived ECDSA verification, and an empty-PEM trust-list guard (observed with the empty IPTC VNPL anchor list: fail closed, never crash).
- Made every CLI trust flag repeatable with PEM-bundle merging, renamed `--allowed-certs`/`--validation-time` to the engine-consistent `--allowed`/`--time` (old names remain as aliases), and documented the fetch-then-pin IPTC three-list recipe (C2PA conformance trust list, C2PA TSA list, IPTC VNPL) for news content.
- Shipped the offline CAWG interoperability corpus (pinned c2pa-rs/c2pa-cpp fixtures under their upstream licenses, Encypher-generated CAWG 1.2 vectors, frozen did:web documents, trust PEMs) plus a Rust corpus gate that runs in `cargo test --workspace` with no network and no Python. Real-world IPTC news vectors ship as a fetch-on-demand index with pinned digests and frozen trust lists; their binaries are excluded pending redistribution confirmation.
- Extended the Python `verify()` keywords, the C `options_json`, and the browser WASM options object with the same CAWG parameters; report statuses now carry a machine-readable `details` field and `VerificationReport::cawg_statuses()` collects `cawg.*` outcomes. All API changes are additive.
- Confirmed telemetry remains opt-in and off by default; verification itself never touches the network.

## 0.1.0-alpha.1 - 2026-08-03

- Published an offline, verification-only C2PA 2.4 engine.
- Added one stable report schema across Rust, CLI, Python, Go/C, and browser WASM.
- Kept cryptographic integrity separate from caller-controlled trust, revocation, freshness, policy, and managed receipts.
- Added format readers for image, video, audio, document, font, archive, and structured-text carriers.
- Added claim, assertion, ingredient-chain, COSE signature, hard-binding, static trust, and embedded OCSP validation.
- Added signed JPEG and MP4 public contract fixtures plus malformed and tamper coverage in the core suites.
- Added native Rust and CLI packages, an ABI3 Python wheel, Go/C bindings, and a self-contained browser WASM package.
- Added RustSec auditing, fuzz-derived parser tests, private vulnerability reporting, dependency updates, and release automation.
- Added first-use failure telemetry consent with a saved per-user setting, explicit APIs for every binding, bounded payloads, non-blocking native delivery, browser delivery, and a rate-limited anonymous ingest contract.
- Documented the consent flow, default-off behavior, trust boundary, report contract, supported formats, and security policy.