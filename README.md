# Encypher C2PA

Local-first, verification-only C2PA SDK for Rust, Python, Go, and browser JavaScript.

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

It does not sign media: this repository contains no signing code at all — no signing keys, no COSE signing paths, no embedding of new manifests. For managed signing, policy, durable receipts, or hosted trust decisions, use the [Encypher API](https://api.encypher.com/docs).

## Install

Tagged releases publish the packages below. Registry publication is gated and does not run from an ordinary source push. For an unreleased checkout, use [Build from source](#build-from-source).

### CLI

```bash
cargo install encypher-c2pa-cli --version 1.0.0-rc.1
encypher-c2pa verify composition.mp4
encypher-c2pa verify composition.mp4 --json
encypher-c2pa formats
```

Exit codes: `0` valid integrity, `2` absent or invalid provenance, `3` unsupported MIME type, `1` operational or input error.

### Rust

```toml
[dependencies]
encypher-c2pa = "=1.0.0-rc.1"
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
pip install encypher-c2pa==1.0.0rc1
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
npm install @encypher/c2pa@1.0.0-rc.1
```

```js
import init, { verify } from "@encypher/c2pa";

await init();
const file = document.querySelector("input[type=file]").files[0];
const report = verify(new Uint8Array(await file.arrayBuffer()), file.type);
console.log(report.integrity, report.trust.status);
```

The browser package performs verification in WebAssembly. See [`examples/browser`](examples/browser).

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

Telemetry is off by default and stays off until a person opts in: a trust tool must not phone home silently. On the first interactive verification, the SDK explains the data contract, asks once, and saves the answer. Native bindings share the per-user config file. Browser JavaScript uses local storage. Non-interactive processes do not prompt; they remain off until configured.

Telemetry fires only for invalid provenance or an operational validation error. Each event contains:

- schema, SDK, SDK version, and engine profile;
- the canonical MIME type;
- `invalid_provenance` or `verification_error`;
- at most eight bounded validation status codes.

Events never contain asset bytes, manifests, reports, filenames, paths, URLs, certificates, keys, trust material, account IDs, or machine IDs. Native clients use a bounded best-effort queue, so telemetry never blocks verification. See [Privacy](docs/PRIVACY.md) for the full contract.

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

### Validating news content with the IPTC trust stack

News-industry C2PA content is anchored by three published PEM lists: the C2PA conformance program trust list (claim-signing anchors), the C2PA conformance TSA trust list (RFC 3161 timestamp-authority anchors), and the IPTC Verified News Publishers List (VNPL, end-entity certificates of vetted newsrooms). Verification never fetches, so the recipe is fetch-then-pin: download the lists once, commit or cache them, and pass the pinned copies.

```bash
# 1. Fetch (once, or on your refresh cadence)
curl -o c2pa-trust.pem \
  https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem
curl -o c2pa-tsa-trust.pem \
  https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TSA-TRUST-LIST.pem
curl -o vnpl-end-entity.pem https://trust.iptc.org/end-entity-list.pem

# 2. Verify against the pinned lists
encypher-c2pa verify article-photo.jpg \
  --trust c2pa-trust.pem \
  --tsa-trust c2pa-tsa-trust.pem \
  --cawg-allowed vnpl-end-entity.pem \
  --time 2026-08-05T00:00:00Z --json
```

`--trust` gates the claim signer against the conformance anchors; `--tsa-trust` gates RFC 3161 timestamps against the conformance TSA anchors (a timestamp from a public TSA outside that list, such as DigiCert's public responder, correctly reports `timeStamp.untrusted`, matching the reference implementation); `--cawg-allowed` accepts CAWG identity signers whose end-entity certificate appears on the VNPL. If IPTC publishes CA anchors for identity signers, pass that bundle via `--cawg-trust`; the flags combine. The VNPL anchor list may legitimately be empty today; an empty PEM file is rejected with a clean error rather than silently trusting nothing, so only pass files that contain certificates.

Pinned copies of these three lists ship with the real-world corpus under [`tests/vectors/cawg/realworld/`](tests/vectors/cawg/realworld/). The news assets themselves are redistribution-pending and are not in the repository; `python3 tests/vectors/cawg/realworld/manage_realworld.py fetch` downloads them from the pinned URLs and verifies the recorded digests. The shipped CAWG interoperability corpus under [`tests/vectors/cawg/`](tests/vectors/cawg/) (pinned c2pa-rs / c2pa-cpp fixtures plus Encypher-generated CAWG 1.2 vectors) runs fully offline in `cargo test --workspace`.

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

See [Trust model](docs/TRUST_MODEL.md) and [Report schema](docs/REPORT_SCHEMA.md).

## Format coverage

`encypher-c2pa formats` prints the canonical MIME types covered by the current C2PA 2.4 engine profile. The current build reports 68 MIME types. Container readers cover JPEG, PNG, WebP, TIFF/DNG, GIF, SVG, JPEG XL, ISO BMFF media, RIFF media, FLAC, MP3, PDF, ZIP-derived documents, fonts, EPUB, and structured text.

Coverage means the verifier has a reader and C2PA hard-binding path for the MIME type. It does not mean every malformed or vendor-specific variant can be recovered. See [Format coverage](docs/FORMATS.md).

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

Default verification makes no network request. Opt-in failure telemetry follows the fixed privacy boundary described in [Privacy](docs/PRIVACY.md).

Report security issues through [GitHub private vulnerability reporting](https://github.com/encypherai/encypher-c2pa/security/advisories/new). See [SECURITY.md](SECURITY.md).

## Project status

The implementation is independent of `c2pa-rs` at runtime. Interoperability tests use C2PA-conformant fixtures and public validation status codes. The format-specific code uses the public [`c2pa-text`](https://crates.io/crates/c2pa-text) crate for standardized structured-text carriers.

C2PA and Content Credentials are standards and marks of their respective owners. This project is not a certification claim.

## License

Apache-2.0 or MIT, at your option. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
