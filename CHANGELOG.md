# Changelog

All notable changes to this project are recorded here.

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