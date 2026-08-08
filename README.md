<div align="center">
  <a href="https://encypher.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/encypherai/encypher-c2pa/main/docs/assets/encypher-lockup-white.png">
      <img src="https://raw.githubusercontent.com/encypherai/encypher-c2pa/main/docs/assets/encypher-lockup-navy.png" alt="Encypher" height="60">
    </picture>
  </a>

  <h1>Encypher C2PA</h1>

  <p>
    <a href="https://crates.io/crates/encypher-c2pa"><img src="https://img.shields.io/crates/v/encypher-c2pa.svg" alt="crates.io"></a>
    <a href="https://docs.rs/encypher-c2pa"><img src="https://img.shields.io/docsrs/encypher-c2pa" alt="docs.rs"></a>
    <a href="https://github.com/encypherai/encypher-c2pa/actions/workflows/ci.yml"><img src="https://github.com/encypherai/encypher-c2pa/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://pypi.org/project/encypher-c2pa/"><img src="https://img.shields.io/pypi/v/encypher-c2pa.svg" alt="PyPI"></a>
    <a href="https://www.npmjs.com/package/@encypherai/c2pa"><img src="https://img.shields.io/npm/v/%40encypherai%2Fc2pa.svg" alt="npm"></a>
    <a href="https://github.com/encypherai/encypher-c2pa/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  </p>
</div>

Local-first, verification-only C2PA + CAWG SDK for Rust, Python, Go, and browser JavaScript, by [Encypher](https://encypher.com).

The verifier reads local bytes. It does not upload the asset, fetch a trust list, or require an account. Cryptographic integrity and trust are separate fields in every report. On first interactive use, the SDK asks whether it may send bounded, anonymous failure telemetry and saves the answer.

> Release candidate: report schema `1.0`, engine profile `c2pa-2.4`, CAWG identity 1.2. Pin exact package versions until the stable 1.0.0 tag.

## What it does

- Extracts C2PA manifests from images, video, audio, documents, fonts, archives, and structured text.
- Verifies claim signatures, hashed-URI references, and format-specific hard bindings.
- Walks ingredient and manifest chains included in the asset.
- Validates CAWG identity assertions (X.509 COSE and identity-claims-aggregation credentials, offline `did:web`/`did:jwk` resolution) per CAWG Identity 1.2.
- Evaluates trust only against PEM material supplied by the caller.
- Reports revocation and freshness as unknown or not checked when the asset lacks usable evidence.
- Runs through one Rust core in the CLI, Python wheel, Go binding, and browser WASM package.
- Optionally reports bounded validation failure codes, without sending customer content.

It does not sign media. The published API contains no signing keys, no COSE signing paths, and nothing that constructs a C2PA manifest or writes one into an asset. The verification kernel lives in private modules of this crate, so that code is unreachable from outside it by construction rather than by configuration, and the writers are additionally `cfg(test)`, so they are not compiled into the released artifact at all. For managed signing, policy, durable receipts, or hosted trust decisions, use the [Encypher API](https://api.encypher.com/docs).

**Scope: open standards only.** The SDK verifies C2PA manifests and CAWG identity assertions. It does not detect or read Encypher's proprietary provenance markers (invisible text provenance, durable soft bindings, marker registries); content carrying those markers verifies here as ordinary C2PA content. For proprietary-marker detection and the full provenance record, use the [Encypher API](https://api.encypher.com/docs).

## Install

Tagged releases publish the packages below. For an unreleased checkout, use [Build from source](#build-from-source).

### CLI

```bash
cargo install encypher-c2pa-cli --version 1.0.0-rc.11
encypher-c2pa verify composition.mp4
encypher-c2pa verify composition.mp4 --json
encypher-c2pa formats
```

Exit codes: `0` valid integrity, `2` absent or invalid provenance, `3` unsupported MIME type, `1` operational or input error.

### Rust

```toml
[dependencies]
encypher-c2pa = "=1.0.0-rc.11"
```

```rust
use encypher_c2pa::verify;

let bytes = std::fs::read("composition.mp4")?;
let report = verify(&bytes, "video/mp4")?;
println!("integrity={} trust={}", report.integrity, report.trust.status);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Python

```bash
pip install --pre encypher-c2pa
```

```python
from encypher_c2pa import verify

report = verify("composition.mp4")
print(report["integrity"])
print(report["trust"]["status"])
```

The wheel supports Python 3.9 and later through the stable ABI.

### Browser JavaScript

```bash
npm install @encypherai/c2pa
```

```js
import init, { verify } from "@encypherai/c2pa";

await init();
const file = document.querySelector("input[type=file]").files[0];
const report = verify(new Uint8Array(await file.arrayBuffer()), file.type);
console.log(report.integrity, report.trust.status);
```

The browser package performs verification in WebAssembly. See [`examples/browser`](https://github.com/encypherai/encypher-c2pa/tree/main/examples/browser).

### Go

The Go binding uses the repository's stable C ABI. Build the static library before testing a source checkout:

```bash
cargo build -p encypher-c2pa-ffi --release
cd bindings/go
go test ./...
```

```go
report, err := c2pa.Verify(asset, "video/mp4", nil)
if err != nil {
    return err
}
fmt.Println(report.Integrity, report.Trust.Status)
```

The Go binding is a source distribution in this release. Its first interactive verification uses the shared native telemetry preference described below.

## Optional failure telemetry

Telemetry is off by default. On the first interactive verification, the SDK shows the data contract, asks once, and saves the answer. Native bindings share the per-user config file. Browser JavaScript uses local storage. Non-interactive processes do not prompt and remain off until configured.

Telemetry fires only for invalid provenance or an operational validation error. Each event contains:

- schema, SDK, SDK version, and engine profile;
- the canonical MIME type;
- `invalid_provenance` or `verification_error`;
- at most eight bounded validation status codes.

Events never contain asset bytes, manifests, reports, filenames, paths, URLs, certificates, keys, trust material, account IDs, or machine IDs. Native clients use a bounded best-effort queue, so telemetry never blocks verification. See [Privacy](https://github.com/encypherai/encypher-c2pa/blob/main/docs/PRIVACY.md) for the full contract.

```bash
encypher-c2pa telemetry on
encypher-c2pa telemetry off
encypher-c2pa telemetry status
```

```python
from encypher_c2pa import configure_telemetry

configure_telemetry(True)
```

```go
err := c2pa.ConfigureTelemetry(true)
```

```javascript
configureTelemetry(true);
```

An explicit per-call value overrides the saved native preference. In Python, `verify(..., telemetry=True)` also saves that choice. Automated native deployments may set `ENCYPHER_C2PA_TELEMETRY=on` or `off` without writing a config file.

## Trust is caller-controlled: bring your own trust lists

Default verification proves integrity. It does not declare that an organization should trust the signer.

Verification performs no network fetches: no OCSP or CRL retrieval, no live DID resolution, no download of a default trust list. Revocation evidence is read only from OCSP responses stapled into the manifest. Every trust decision is made against caller-supplied PEM bundles, so a run is deterministic and works air-gapped: the same asset, trust lists, and validation time always produce the same report.

Six inputs control trust. Each is optional; omitting one skips that check (the report then carries no corresponding trust verdict rather than a fake "trusted").

| CLI flag | `VerifyOptions` field / Python keyword | Gates |
|---|---|---|
| `--trust` | `trust_pem` | Claim-signing trust anchors: the claim signer's chain must terminate at one of these CAs (`signingCredential.trusted` / `.untrusted`). |
| `--tsa-trust` | `tsa_trust_pem` | Timestamp-authority anchors: RFC 3161 timestamps count only when the TSA chains to one of these (`timeStamp.trusted` / `.untrusted`). |
| `--allowed` | `allowed_list_pem` | Allowed leaf certificates: an exact end-entity allow-list accepted even without a chain to an anchor. |
| `--cawg-trust` | `cawg_trust_pem` | CAWG identity trust anchors for X.509-backed identity assertions (`cawg.identity.trusted`). |
| `--cawg-allowed` | `cawg_allowed_certs_pem` | CAWG allowed certificates: exact end-entity allow-list for identity signers. |
| `--cawg-did-documents` | `cawg_did_documents` | Pinned offline DID-document store for `did:web` identity-claims-aggregation issuers: JSON files holding a DID document, an array of documents, or a `DID -> document` map. An issuer absent from the store fails closed with `cawg.ica.did_unavailable` (`did:jwk` issuers need no store; they resolve by pure local decoding). |

Two switches tighten CAWG policy. `--cawg-document-signing-require-anchor` (`cawg_document_signing_require_anchor`) stops accepting a document-signing credential on its EKU alone; it must chain to a `--cawg-trust` anchor or appear on `--cawg-allowed`. `--cawg-strict-encoding` (`cawg_strict_encoding`) refuses CAWG 1.1-era legacy encodings; without it they verify and are surfaced through the informational `com.encypher.cawg.legacyProfile` status.

CAWG identity outcomes are assertion-scoped: `cawg.*` codes report the identity assertion's own verdict and never flip the C2PA manifest's `validation_state` or integrity verdict. A tampered identity assertion still fails the manifest through the C2PA-level hashed-URI check.

Every CLI trust flag is repeatable; repeated occurrences merge, so separate bundles (your own CA, the C2PA official list, a partner list) need no preprocessing. Pass `--time` (Rust/Python: `validation_time`, RFC 3339) to evaluate certificate validity at a fixed instant for fully reproducible verification.

```rust
use encypher_c2pa::{verify_with_options, VerifyOptions};

let options = VerifyOptions {
    trust_pem: Some(std::fs::read_to_string("anchors.pem")?),
    cawg_trust_pem: Some(std::fs::read_to_string("cawg-anchors.pem")?),
    validation_time: Some("2026-08-03T12:00:00Z".into()),
    ..Default::default()
};
let report = verify_with_options(&bytes, "video/mp4", &options)?;
for status in report.cawg_statuses() {
    println!("{}: {}", status.code, status.explanation);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Validating news content with the published trust lists

News-industry C2PA content is anchored by published PEM lists: the C2PA conformance program trust list (claim-signing anchors), the C2PA conformance TSA trust list (RFC 3161 timestamp-authority anchors), the IPTC Verified News Publishers List (VNPL, end-entity certificates of vetted newsrooms), and the Encypher-hosted lists (the Encypher C2PA root and TSA issuing CA, and the Encypher Verified Organizations List of identity anchors). Verification never fetches, so the recipe is fetch-then-pin: download the lists once, commit or cache them, and pass the pinned copies.

```bash
# 1. Fetch (once, or on your refresh cadence)
curl -o c2pa-trust.pem \
  https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem
curl -o c2pa-tsa-trust.pem \
  https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.pem
curl -o vnpl-end-entity.pem https://trust.iptc.org/end-entity-list.pem
curl -o encypher-root.pem https://api.encypher.com/ca/repository/root-ca.crt
curl -o encypher-tsa.pem https://api.encypher.com/ca/repository/tsa-issuing-ca.crt
curl -o evol-anchors.pem https://trust.encypher.com/anchor-list.pem

# 2. Verify against the pinned lists
encypher-c2pa verify article-photo.jpg \
  --trust c2pa-trust.pem --trust encypher-root.pem \
  --tsa-trust c2pa-tsa-trust.pem --tsa-trust encypher-tsa.pem \
  --cawg-trust evol-anchors.pem \
  --cawg-allowed vnpl-end-entity.pem \
  --time 2026-08-05T00:00:00Z --json
```

`--trust` gates the claim signer, `--tsa-trust` gates RFC 3161 timestamps, `--cawg-trust` gates identity-assertion signers by CA anchor, and `--cawg-allowed` accepts identity signers by exact end-entity certificate. Every flag is repeatable and repeated bundles merge, so the C2PA, IPTC, and Encypher lists combine without preprocessing. A timestamp from a TSA outside the pinned anchors correctly reports `timeStamp.untrusted`, matching the reference implementation. With the Encypher lists pinned, content signed through the Encypher platform verifies as trusted under the same recipe. The VNPL anchor list and the Encypher end-entity list may legitimately be empty today; an empty PEM file is rejected with a clean error, so only pass files that contain certificates.

Pinned copies of these three lists ship with the real-world corpus under [`tests/vectors/cawg/realworld/`](https://github.com/encypherai/encypher-c2pa/tree/main/tests/vectors/cawg/realworld). The news assets themselves are redistribution-pending and are not in the repository; `python3 tests/vectors/cawg/realworld/manage_realworld.py fetch` downloads them from the pinned URLs and verifies the recorded digests. The shipped CAWG interoperability corpus under [`tests/vectors/cawg/`](https://github.com/encypherai/encypher-c2pa/tree/main/tests/vectors/cawg) (pinned c2pa-rs / c2pa-cpp fixtures plus Encypher-generated CAWG 1.2 vectors) runs fully offline in `cargo test --workspace`.

The top-level report keeps these conclusions apart:

```json
{
  "schema_version": "1.0",
  "profile": "c2pa-2.4",
  "integrity": "valid",
  "signature": "valid",
  "hard_binding": "match",
  "trust": {
    "status": "not_evaluated",
    "basis": "none",
    "validation_time": "2026-08-03T12:00:00Z",
    "revocation": {
      "status": "not_checked",
      "source": "none",
      "responder_signature": "not_applicable"
    },
    "freshness": { "status": "unknown", "as_of": null }
  },
  "policy": null,
  "managed_receipt": null
}
```

See [Trust model](https://github.com/encypherai/encypher-c2pa/blob/main/docs/TRUST_MODEL.md) and [Report schema](https://github.com/encypherai/encypher-c2pa/blob/main/docs/REPORT_SCHEMA.md).

## Optional: query the Encypher API

Verification stays local by default and makes no network call. Pass `--encypher-api` to `verify` to also look the asset up in Encypher's public provenance record. The SDK computes a SHA-256 digest of the exact asset bytes and sends only that digest. It does not upload the asset, the manifest, or any file path.

The lookup runs after local verification and never changes the local verdict or the process exit code. In `--json` mode the response attaches under a new top-level `encypher_api` key. In human mode it prints a trailing `encypher api:` block reporting found or not found, plus the verification URL when Encypher has a record. A network error, a non-success status, or an unreadable response yields an error object and a stderr warning, never a failure.

```bash
encypher-c2pa verify article-photo.jpg --encypher-api --json
```

The response is Encypher's own record, separate from the local verdict: a match there is not a trust decision about the signer, and an absence there does not weaken a valid local report.

## Format coverage

`encypher-c2pa formats` prints the canonical MIME types covered by the current C2PA 2.4 engine profile. The current build reports 69 MIME types. Container readers cover JPEG, PNG, WebP, TIFF/DNG, GIF, SVG, JPEG XL, ISO BMFF media, RIFF media, FLAC, MP3, PDF, ZIP-derived documents, fonts, EPUB, and text.

Text coverage is every method C2PA 2.4 defines, through the published [`c2pa-text`](https://crates.io/crates/c2pa-text) crate: A.8 unstructured text (the invisible variation-selector wrapper on `text/plain`, CSV, JSON, and social-post content), A.9 structured text (the ASCII-armour comment block for Markdown, XML/XHTML, YAML, TOML, CSS, JavaScript, Python, and every comment syntax `c2pa-text` defines), and A.7 HTML (the inline `application/c2pa` script element). Encypher's proprietary text markers are not part of C2PA and are deliberately not read here; they are served by the [Encypher API](https://api.encypher.com/docs).

Coverage means the verifier has a reader and C2PA hard-binding path for the MIME type. It does not mean every malformed or vendor-specific variant can be recovered. See [Format coverage](https://github.com/encypherai/encypher-c2pa/blob/main/docs/FORMATS.md).

## Build from source

Prerequisites: Rust 1.88 or later. Python packaging requires `uv` and `maturin`. Browser packaging requires `wasm-pack` and the `wasm32-unknown-unknown` Rust target.

```bash
cargo test --workspace
cargo run -p encypher-c2pa-cli -- verify tests/fixtures/signed_test.jpg

maturin build --release --manifest-path bindings/python/Cargo.toml

rustup target add wasm32-unknown-unknown
cd bindings/wasm
wasm-pack build . --target web --release --out-dir pkg
node ../../scripts/package-wasm.mjs
node ../../scripts/test-wasm.mjs
```

## Security boundary

The public repository contains verification, parsing, format handling, signature checks, static caller-supplied trust evaluation, and the opt-in failure telemetry client. It excludes signing keys, managed trust policy, registry lookups, proprietary watermarking and fingerprinting, customer workflows, service credentials, and telemetry backends.

Manifest construction and container writing are not part of the published API. The verification kernel lives in private modules of the single published library, so that code is unreachable from outside the crate by construction rather than by configuration, and the writers are additionally `cfg(test)` so they are not compiled into the released artifact at all. No Cargo feature can expose them.

Two CI controls defend this. Both are useful and neither is a proof, so it is
worth being exact about what each one checks.

`scripts/check-public-surface.mjs` locks the SHAPE of the API. It takes the
public surface from rustdoc's own output, so re-exports, macro expansion, impl
methods, fields and variants are resolved by the compiler rather than inferred,
and diffs it against a reviewed inventory (`public-surface.txt`). It reads four
configurations and unions them: the host under no features, under `telemetry`
alone, and under defaults, plus `wasm32-unknown-unknown` under no features,
which is what the browser binding builds. The Cargo feature map is locked to an
approved set derived from `cargo metadata`, so a feature added implicitly by an
optional dependency, or an approved feature redefined to pull in more, fails.
Within that scope the walk refuses rather than guesses: an item kind it cannot
name, an impl receiver it cannot resolve, or any item it fails to reach is a
failure. A source-level tripwire additionally rejects public items behind a
`cfg` the extraction structurally cannot observe - `cfg(doc)`, or a target
outside those four - because rustdoc cannot report on the conditions rustdoc
itself runs under.

What that control cannot see is conduct. An already-approved function whose body
is rewritten to write bytes leaves the inventory byte-for-byte unchanged.
`crates/encypher-c2pa/tests/read_only_contract.rs` covers that from the other
side: for `verify`, `verify_with_options` and `verify_file`, it asserts the
input is byte-identical afterwards and that no file is created or removed in the
directory being read, across every extension in `SUPPORTED_EXTENSIONS` and every
MIME from `supported_mime_types()`, on success and failure paths alike. It reads
those lists from the crate rather than copying them, so a newly supported format
is covered the moment it is added. It does not observe writes elsewhere on the
filesystem, and it constrains the behaviour it exercises rather than proving a
general property.

Between them a boundary violation has to defeat a compiler-derived surface lock
and an observable behaviour test, instead of depending on a reviewer noticing.

Default verification makes no network request. Opt-in failure telemetry follows the fixed privacy boundary described in [Privacy](https://github.com/encypherai/encypher-c2pa/blob/main/docs/PRIVACY.md).

Report security issues through [GitHub private vulnerability reporting](https://github.com/encypherai/encypher-c2pa/security/advisories/new). See [SECURITY.md](https://github.com/encypherai/encypher-c2pa/blob/main/SECURITY.md).

## Project status

The implementation is independent of `c2pa-rs` at runtime. Interoperability tests use C2PA-conformant fixtures and public validation status codes. The format-specific code uses the public [`c2pa-text`](https://crates.io/crates/c2pa-text) crate for standardized structured-text carriers.

C2PA and Content Credentials are standards and marks of their respective owners. This project is not a certification claim.

## License

[Apache License 2.0](https://github.com/encypherai/encypher-c2pa/blob/main/LICENSE). Redistributions and derivative works must
retain the [NOTICE](https://github.com/encypherai/encypher-c2pa/blob/main/NOTICE) file naming Encypher Corporation, as required by
Section 4(d) of the license. Third-party test vectors under
`tests/vectors/` retain their upstream licenses, pinned alongside the
assets.
