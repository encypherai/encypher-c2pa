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

> Stable report schema `1.0`, engine profile `c2pa-2.4`, CAWG identity 1.2.

## What it does

- Extracts C2PA manifests from images, video, audio, documents, fonts, archives, and structured text.
- Verifies claim signatures, hashed-URI references, and format-specific hard bindings.
- Verifies fragmented BMFF streams (fMP4 and CMAF) from an initialization segment plus any available media-segment subset.
- Walks ingredient and manifest chains included in the asset.
- Validates CAWG identity assertions (X.509 COSE and identity-claims-aggregation credentials, offline `did:web`/`did:jwk` resolution) per CAWG Identity 1.2.
- Evaluates trust against bundled snapshots plus caller PEM, with an explicit custom-only mode.
- Reports revocation and freshness as unknown or not checked when the asset lacks usable evidence.
- Runs through one Rust core in the CLI, Python wheel, Go binding, and browser WASM package.
- Optionally reports bounded validation failure codes, without sending customer content.

It does not sign media. The published API contains no signing keys, no COSE signing paths, and nothing that constructs a C2PA manifest or writes one into an asset. The verification kernel lives in private modules of this crate, so that code is unreachable from outside it by construction rather than by configuration, and the writers are additionally `cfg(test)`, so they are not compiled into the released artifact at all. For managed signing, policy, durable receipts, or hosted trust decisions, use the [Encypher API](https://api.encypher.com/docs).

**Scope: open standards only.** The SDK verifies C2PA manifests and CAWG identity assertions. It does not detect or read Encypher's proprietary provenance markers (invisible text provenance, durable soft bindings, marker registries); content carrying those markers verifies here as ordinary C2PA content. For proprietary-marker detection and the full provenance record, use the [Encypher API](https://api.encypher.com/docs).

## Install

Tagged releases publish the packages below. For an unreleased checkout, use [Build from source](#build-from-source).

### CLI

```bash
cargo install encypher-c2pa-cli --version 1.0.3
encypher-c2pa verify composition.mp4
encypher-c2pa verify composition.mp4 --json
encypher-c2pa formats
```

Exit codes: `0` valid integrity, `2` absent or invalid provenance, `3` unsupported MIME type, `1` operational or input error.

### Rust

```toml
[dependencies]
encypher-c2pa = "1.0.3"
```

```rust
use encypher_c2pa::{verify_file, VerifyOptions};

let report = verify_file("composition.mp4", None, &VerifyOptions::default())?;
println!("integrity={} trust={}", report.integrity, report.trust.status);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Python

```bash
pip install encypher-c2pa
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

The Go source binding supports Linux and macOS and uses the repository's stable
C ABI. Build the static library before testing a source checkout:

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

Path-based convenience APIs in Rust, Python, and Go accept regular files up to 128 MiB; byte-slice APIs remain bounded only by caller memory.

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

An explicit per-call value overrides the saved native preference. In Python, `verify(..., telemetry=True)` attempts to save that choice; if the preference store is unavailable, the explicit value still governs that verification. Automated native deployments may set `ENCYPHER_C2PA_TELEMETRY=on` or `off` without writing a config file.

## Bundled trust lists by default

Default verification evaluates both integrity and signer trust, but keeps those conclusions separate. Every install compiles a pinned `2026-08-11` snapshot into the Rust library, CLI, Python wheel, Go/C library, and browser WASM package. Verification remains local and deterministic; it makes no trust-list, AIA, OCSP, CRL, DID, ingredient, or assertion network request.

| Packaged source | Default use |
|---|---|
| C2PA Trust List | Claim-signing trust anchors |
| C2PA TSA Trust List | RFC 3161 timestamp-authority anchors |
| IPTC Verified News Publishers end-entity list | Directly allowed claim-signing and CAWG identity certificates |
| IPTC Verified News Publishers anchor list | CAWG identity anchors; empty at this snapshot |
| Mozilla Root Store with the Email trust bit | CAWG 1.2 interim X.509 identity anchors |
| Encypher C2PA Root CA | Claim-signing trust anchor |
| Encypher C2PA TSA Issuing CA | Timestamp-authority anchor |
| Encypher Verified Organizations List | CAWG identity trust anchor |

The Mozilla and IPTC CAWG sources implement the CAWG Identity 1.2 interim X.509 trust configuration in section 8.2.4.1. The validator also enforces that section's EKU, certificate-policy, timestamp, and 31 March 2027 cutoff rules.

The exact source URLs and SHA-256 digests live in [`default_trust/sources.json`](https://github.com/encypherai/encypher-c2pa/blob/main/crates/encypher-c2pa/src/default_trust/sources.json). `DEFAULT_TRUST_SNAPSHOT_DATE` exposes the snapshot date to Rust callers. A new SDK release is required to refresh these packaged bytes.

Caller-supplied PEM bundles extend the packaged defaults. Set `no_default_trust: true` (Python: `no_default_trust=True`, Go: `NoDefaultTrust: true`, CLI: `--no-default-trust`) to ignore every packaged list and evaluate only caller-supplied material.

| CLI flag | `VerifyOptions` field / Python keyword | Gates |
|---|---|---|
| `--trust` | `trust_pem` | Additional claim-signing trust anchors |
| `--tsa-trust` | `tsa_trust_pem` | Additional timestamp-authority anchors |
| `--allowed` | `allowed_list_pem` | Additional directly allowed claim-signing certificates |
| `--cawg-trust` | `cawg_trust_pem` | Additional CAWG X.509 identity anchors |
| `--cawg-allowed` | `cawg_allowed_certs_pem` | Directly allowed CAWG identity certificates |
| `--cawg-did-documents` | `cawg_did_documents` | Pinned offline DID documents for `did:web` ICA issuers |
| `--no-default-trust` | `no_default_trust` | Disable all packaged trust snapshots |

Every CLI trust flag is repeatable and repeated bundles merge. CAWG document-signing credentials must chain to a CAWG anchor or match a CAWG allowed certificate; certificate profile alone never establishes trust. `--cawg-strict-encoding` (`cawg_strict_encoding`) refuses CAWG 1.1-era legacy encodings. CAWG identity outcomes remain assertion-scoped: they never turn a valid C2PA integrity result into a trust result.

```bash
# Out-of-box verification uses the packaged snapshot.
encypher-c2pa verify article-photo.jpg --json

# A closed deployment can replace the defaults with its own pinned policy.
encypher-c2pa verify article-photo.jpg \
  --no-default-trust \
  --trust organization-anchors.pem \
  --tsa-trust organization-tsa-anchors.pem \
  --time 2026-08-11T00:00:00Z --json
```

Revocation evidence is read only from OCSP responses stapled into the manifest. The offline verifier cannot prove that a packaged or caller-supplied list is still current, so `freshness.status` remains `unknown`.

The top-level report keeps these conclusions apart:

```json
{
  "schema_version": "1.0",
  "profile": "c2pa-2.4",
  "integrity": "valid",
  "signature": "valid",
  "hard_binding": "match",
  "trust": {
    "status": "not_valid_for_supplied_material",
    "basis": "bundled_static_material",
    "validation_time": "2026-08-11T12:00:00Z",
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

Verification stays local by default and makes no network call. For an explicit server-side cross-check, set `ENCYPHER_API_KEY` and pass `--encypher-api` to `verify`. The request contains the exact asset SHA-256, byte length, MIME type, and a bounded summary of the local verdict. When the format exposes the embedded C2PA manifest in one contiguous carrier, it also contains that manifest store and carrier so Encypher can validate the detached evidence independently. The complete asset, filename, and file path stay local.

The API validates any detached manifest and compares its binding and exact file digest with Encypher's provenance records. Formats without contiguous detached evidence send no manifest data; the exact file digest can still be matched. The response never changes the local verdict or process exit code. In `--json` mode it attaches under a new top-level `encypher_api` key. In human mode it prints a trailing `encypher api:` block. A network error, non-success status, or unreadable response yields an error object and a stderr warning, never a verification failure.

```bash
encypher-c2pa verify article-photo.jpg --encypher-api --json
```

The response is Encypher's own record, separate from the local verdict: a match there is not a trust decision about the signer, and an absence there does not weaken a valid local report.

## Format coverage

`encypher-c2pa formats` prints the 71 canonical MIME types covered by the installed C2PA 2.4 engine profile. Container readers cover JPEG, PNG, WebP, TIFF/DNG, GIF, SVG, JPEG XL, ISO BMFF media, RIFF media, FLAC, MP3, PDF, ZIP-derived documents, fonts, EPUB, and text. The C2PA 2.4 set includes OpenDocument Graphics (`application/vnd.oasis.opendocument.graphics`) and tab-separated values (`text/tab-separated-values`).

Text coverage is every method C2PA 2.4 defines, through the published [`c2pa-text`](https://crates.io/crates/c2pa-text) crate: A.8 unstructured text (the invisible variation-selector wrapper on `text/plain`, CSV, TSV, JSON, and social-post content), A.9 structured text (the ASCII-armour comment block for Markdown, XML/XHTML, YAML, TOML, CSS, JavaScript, Python, and every comment syntax `c2pa-text` defines), and A.7 HTML (the inline `application/c2pa` script element). Encypher's proprietary text markers are not part of this SDK.

### Fragmented BMFF

For fMP4 and CMAF, the ordinary MIME type remains `video/mp4`. Pass the signed initialization segment as the asset and each available `.m4s` media segment as a fragment. The verifier checks the initialization-segment hash and each supplied fragment's A.5.4 Merkle leaf. It does not require the complete stream.

```bash
encypher-c2pa verify init.mp4 \
  --fragment seg-0.m4s \
  --fragment seg-1.m4s \
  --mime video/mp4
```

Rust uses `verify_fragmented` or `verify_fragmented_with_options`. Python uses `verify(init, "video/mp4", fragments=[...])`. Browser WASM exports `verifyFragmented(init, fragments, "video/mp4", options)`. The C ABI exposes `encypher_c2pa_verify_fragmented`.

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

The public repository contains verification, parsing, format handling, signature checks, pinned packaged trust snapshots, caller-supplied trust evaluation, and the opt-in failure telemetry client. It excludes signing keys, managed trust policy, registry lookups, proprietary watermarking and fingerprinting, customer workflows, service credentials, and telemetry backends.

Manifest construction and container writing are not part of the published API. The verification kernel lives in private modules of the single published library, so that code is unreachable from outside the crate by construction rather than by configuration, and the writers are additionally `cfg(test)` so they are not compiled into the released artifact at all. No Cargo feature can expose them.

Three CI controls defend this. Each is useful and none is a proof, so it is
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

A third control asks the kernel instead of the source.
`crates/encypher-c2pa/tests/no_write_capability.rs` forks a child, installs a
seccomp filter, and runs `verify`, `verify_with_options` and `verify_file`
inside it. Be precise about the coverage, because it is uneven: there are
signed fixtures for JPEG and MP4 only, and those are the cases asserted to come
back present, with valid integrity and a matching hard binding, so a run that
quietly stopped parsing cannot pass for a clean one. Every other MIME in
`supported_mime_types()` and every extension in `SUPPORTED_EXTENSIONS` is
driven through the same entry points on unsigned, truncated and absent input,
which exercises format dispatch and the error paths rather than a successful
parse. Error paths are worth covering here: they are the easiest place for a
side effect to hide.

The filter is an allowlist, not a denylist, and that distinction is the whole
control. The first version enumerated mutating syscalls; a reviewer asked what
it did about io_uring, and the answer was nothing - a ring performs `openat`
and `write` as submission entries, so refusing those numbers refuses nothing.
Now anything outside a fixed list of readers, memory operations and clocks
kills the process, and a test calls `io_uring_setup` inside the sandbox to
prove the default really is deny. Aliases, re-export paths, generic
`io::Write` indirection, macro expansion, `unsafe`, a dependency writing on the
library's behalf and shelling out to a subprocess are all equally impossible.
Four of those routes are pinned by name in a regression test; the rest are
refused by the default-deny allowlist rather than by any rule written for them,
which is the point of a default-deny allowlist.

Two details matter. It kills on the attempt rather than returning `EPERM`,
because an earlier version returned an error and a discarded
`let _ = write(..)` sailed through: the write failed, the result was dropped,
verification finished and the test reported success. Refusing the syscall shows
verification does not depend on writing; killing shows it does not try. And the
allowlist is split in two - the six syscalls the scenario actually makes,
each proved necessary on every CI run by removing it and requiring the run to
die, and a declared headroom tier for portability across libc and kernel
versions. None of the headroom entries can create or modify a file. Splitting
it means a permission cannot sit in the list unexplained: removing any entry
from the exercised tier must break the run.

Each gate is checked against the kernel too, not against a description of the
filter. Three canaries confirm that `openat` with `O_CREAT` dies, `open` with
`O_WRONLY` dies and `ioctl` with a request other than `TCGETS` dies, while a
read-only `openat` still succeeds - so the gates are gating rather than
banning, and there is no model of the kernel that could drift away from it.

Between them a boundary violation has to defeat a compiler-derived surface
lock, an observable behaviour test, and a kernel that will not permit the
syscall - instead of depending on a reviewer noticing.

Default verification makes no network request. Opt-in failure telemetry follows the fixed privacy boundary described in [Privacy](https://github.com/encypherai/encypher-c2pa/blob/main/docs/PRIVACY.md).

Report security issues through [GitHub private vulnerability reporting](https://github.com/encypherai/encypher-c2pa/security/advisories/new). See [SECURITY.md](https://github.com/encypherai/encypher-c2pa/blob/main/SECURITY.md).

## Project status

The implementation is independent of `c2pa-rs` at runtime; it shares no verification code with any other implementation. Interoperability is checked offline against pinned third-party vectors, core C2PA media from `contentauth/c2pa-rs` and the CAWG identity corpus, with expected outcomes derived from C2PA 2.4 status-code semantics rather than another implementation's output. The format-specific code uses the public [`c2pa-text`](https://crates.io/crates/c2pa-text) crate for standardized structured-text carriers.

C2PA and Content Credentials are standards and marks of their respective owners. This project is not a certification claim.

## License

[Apache License 2.0](https://github.com/encypherai/encypher-c2pa/blob/main/LICENSE). Redistributions and derivative works must
retain the [NOTICE](https://github.com/encypherai/encypher-c2pa/blob/main/NOTICE) file naming Encypher Corporation, as required by
Section 4(d) of the license. Third-party test vectors under
`tests/vectors/` retain their upstream licenses, pinned alongside the
assets.
