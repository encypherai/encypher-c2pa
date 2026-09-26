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

Check the Content Credentials on a file without sending the file anywhere. Encypher C2PA reads the provenance record embedded in an image, video, audio file, document, font, or text, and tells you two things separately: whether the record and the content are intact, and whether you trust whoever signed it.

Verification runs on your machine. It needs no account, and verifying a file makes no network request unless you allow online checks. The command line also checks once a day for a newer release, which you can turn off (see [Updates](#updates)). Teams that mark AI-generated output for the EU AI Act (Article 50) or the California AI Transparency Act can use it to confirm that what they ship still verifies after it leaves their systems.

The SDK implements the open standards: [C2PA 2.4](https://spec.c2pa.org/specifications/specifications/2.4/index.html) manifests and [CAWG Identity 1.3](https://cawg.io/identity/1.3/) assertions. One Rust core serves the command line, Rust, Python, browser JavaScript, Go, and C.

## Quick start

### Command line

```bash
cargo install encypher-c2pa-cli --version 1.2.0
encypher-c2pa verify photo.jpg
encypher-c2pa verify photo.jpg --json
encypher-c2pa formats
```

The MIME type comes from the file extension; pass `--mime` for a file whose name does not say what it is. Exit codes: `0` integrity valid, `2` provenance absent or invalid, `3` unsupported MIME type, `1` operational or input error.

### Rust

```toml
[dependencies]
encypher-c2pa = "1.2.0"
```

```rust
use encypher_c2pa::{verify_file, VerifyOptions};

let report = verify_file("photo.jpg", None, &VerifyOptions::default())?;
println!("integrity={} trust={}", report.integrity, report.trust.status);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Python

```bash
pip install encypher-c2pa
```

```python
from encypher_c2pa import verify

report = verify("photo.jpg")
print(report["integrity"], report["trust"]["status"])
```

The wheel supports Python 3.9 and later on Linux (glibc and musl, x86_64 and aarch64), macOS, and Windows x64.

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

Verification runs in WebAssembly inside the page. See [`examples/browser`](https://github.com/encypherai/encypher-c2pa/tree/main/examples/browser).

### Go

The Go binding is a source distribution for Linux and macOS. It links the C ABI, so build the static library first:

```bash
cargo build -p encypher-c2pa-ffi --release
cd bindings/go && go test ./...
```

```go
report, err := c2pa.Verify(asset, "video/mp4", nil)
if err != nil {
    return err
}
fmt.Println(report.Integrity, report.Trust.Status)
```

The C ABI is declared in [`bindings/c/include/encypher_c2pa.h`](https://github.com/encypherai/encypher-c2pa/blob/main/bindings/c/include/encypher_c2pa.h). Every returned string must be released with `encypher_c2pa_free_string`.

Path-based APIs in Rust, Python, and Go read regular files up to 128 MiB. Byte-buffer APIs are bounded only by caller memory.

## Reading a report

Every report answers the integrity question and the trust question in separate fields, because they fail for different reasons. A photo can be untouched since signing and still be signed by someone you do not trust.

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
    "revocation": { "status": "not_checked", "source": "none", "responder_signature": "not_applicable" },
    "freshness": { "status": "unknown", "as_of": null }
  },
  "validation_results": { "success": [], "informational": [], "failure": [] }
}
```

- `integrity`: the claim signature verifies, every referenced assertion matches its hash, and the content matches its hard binding (the hash that ties the manifest to the file's bytes).
- `trust`: whether the signing certificate chains to an anchor you accept, evaluated at `validation_time`.
- `validation_results`: the C2PA and CAWG status codes behind both conclusions. Consumers should branch on these codes rather than on explanation text.

The report schema is `1.0` and stable. See [Report schema](https://github.com/encypherai/encypher-c2pa/blob/main/docs/REPORT_SCHEMA.md).

## What it verifies

- Manifest stores embedded in 71 media types across images, video, audio, documents, archives, fonts, and structured text, including Brotli-compressed stores and update manifests.
- Claim signatures, including RFC 3161 timestamps and OCSP responses stapled into the manifest. Signing, timestamp, and CAWG certificates are checked against the C2PA certificate profile and an RFC 5280 path to a trusted anchor.
- Hashed references from the claim to each assertion, and the ingredient links that tie a manifest to the ones before it.
- Hard bindings: data hash, BMFF hash (including Merkle trees for fragmented MP4), general box hash, ZIP collection hash, and multi-asset hash.
- Live video streams signed under C2PA 2.4, segment by segment.
- Every manifest in a PDF's incremental-update history, each against the version of the file that introduced it.
- CAWG identity assertions signed with X.509 certificates or identity claims aggregation credentials, with `did:jwk` resolution and `did:web` documents you pin or, with online checks allowed, fetch. X.509 identity signatures report the registered CAWG Identity 1.3 `cawg.x509.*` codes. CAWG results apply to the identity assertion only; they never change the C2PA integrity verdict.

`encypher-c2pa formats` prints the supported MIME types. [Format coverage](https://github.com/encypherai/encypher-c2pa/blob/main/docs/FORMATS.md) lists them with the binding each uses. Text support covers every method C2PA 2.4 defines (plain-text wrapper, structured-text comment block, and HTML script element) through the [`c2pa-text`](https://crates.io/crates/c2pa-text) crate.

### Video streams

For fMP4 and CMAF, pass the signed initialization segment as the asset and each available media segment as a fragment. The MIME type stays `video/mp4`. The verifier checks the initialization-segment hash and each supplied segment's Merkle leaf, so a partial recording can be verified: supply the fragments you have, in playback order. Fragments not yet available at the end are not a failure, but a gap or a reordering inside the supplied run is, because C2PA 2.4 requires a validator to flag a sequence that does not match the signed one. When a player seeks on purpose, pass the index of each fragment that starts after the jump (`--expected-seek <N>`, `expected_seek_positions`); every fragment is still authenticated. A segment that no binding in the manifest covers fails verification; it is never reported as matched.

```bash
encypher-c2pa verify init.mp4 --fragment seg-0.m4s --fragment seg-1.m4s --mime video/mp4
```

Live streams signed under C2PA 2.4 bind each segment differently, so they take a declared encapsulation and protection method. With `verifiable-segment-info`, the initialization manifest carries session keys, and every segment's signed segment information must verify under them. With `per-segment`, each segment carries its own manifest, and the verifier recomputes the chain from each segment to the one before it. Which of the two a stream actually uses is read from the stream, not taken from the caller, and a stream whose bytes contradict its declared encapsulation is refused.

```bash
encypher-c2pa verify init.mp4 --fragment seg-0.m4s --fragment seg-1.m4s \
  --mime video/mp4 --encapsulation cmaf --segment-mode per-segment --json
```

| Surface | Fragmented recording | Live stream |
|---|---|---|
| Rust | `verify_fragmented` | `verify_stream` |
| Python | `verify(init, "video/mp4", fragments=[...])` | `verify_stream(init, segments, encapsulation=, method=)` |
| WebAssembly | `verifyFragmented` | `verifyStream` |
| Go | `VerifyFragmented` | `VerifyStream` |
| C | `encypher_c2pa_verify_fragmented` | `encypher_c2pa_verify_stream` |

The stream report carries a top-level `integrity`, the initialization manifest's report, a report per segment, and, for per-segment streams, whether the chain holds.

## Trust

Each install carries a pinned trust snapshot dated `2026-09-24`, compiled into every package. Trust material is never fetched: no trust list, no certificate chain, no CRL. With online checks off, which is the default, verification is entirely local and deterministic. Turning them on adds revocation status, a remote manifest store, a DID document, or external content as evidence; the trust snapshot is still the one on disk.

| Packaged source | Used for |
|---|---|
| C2PA Trust List | Claim-signing anchors |
| C2PA TSA Trust List | Timestamp-authority anchors |
| IPTC Verified News Publishers, end-entity list | Directly allowed claim-signing and CAWG identity certificates, interim S/MIME rules |
| IPTC Verified News Publishers, anchor list | CAWG identity anchors, interim S/MIME rules (empty in this snapshot) |
| Mozilla Root Store, email trust bit | CAWG identity anchors, interim S/MIME rules (section 8.2.4.1) |
| Encypher C2PA Root CA | Claim-signing anchor |
| Encypher C2PA TSA Issuing CA | Timestamp-authority anchor |
| Encypher Verified Organizations List | CAWG identity anchor, base trust model |

CAWG Identity 1.3 ties its interim S/MIME conditions to the Mozilla and IPTC
lists by name, so they apply to those two sources only. An identity that
chains to the Encypher Verified Organizations root, or to an anchor you
supply, is accepted under the base trust model: `emailProtection` with one of
the six approved CA/Browser Forum S/MIME certificate policies, no 31 March
2027 cutoff and no time-stamp condition. Every other check is unchanged.

Source URLs and SHA-256 digests are in [`default_trust/sources.json`](https://github.com/encypherai/encypher-c2pa/blob/main/crates/encypher-c2pa/src/default_trust/sources.json). A new release refreshes the snapshot.

Your own PEM bundles extend the snapshot. To evaluate only your own material, set `no_default_trust`.

| CLI flag | Option | Purpose |
|---|---|---|
| `--trust` | `trust_pem` | Claim-signing anchors |
| `--tsa-trust` | `tsa_trust_pem` | Timestamp-authority anchors |
| `--allowed` | `allowed_list_pem` | Directly allowed claim-signing certificates |
| `--cawg-trust` | `cawg_trust_pem` | CAWG X.509 identity anchors |
| `--cawg-allowed` | `cawg_allowed_certs_pem` | Directly allowed CAWG identity certificates |
| `--trust-anchor-not-before`, `--trust-anchor-not-after` | `trust_anchor_not_before`, `trust_anchor_not_after` | Validity window for your own anchors (RFC 3339) |
| `--cawg-did-documents` | `cawg_did_documents` | Pinned DID documents for `did:web` issuers |
| `--cawg-ica-trusted-issuer` | `cawg_ica_trusted_issuers` | Identity-aggregation issuer DIDs you trust directly |
| `--cawg-ica-trust-anchor` | `cawg_ica_trust_anchors` | DIDs an issuer may reach through `controller` links in pinned DID documents |
| `--cawg-ica-status-lists` | `cawg_ica_status_lists` | Revocation status lists, as a JSON map of list URI to base64 bitstring |
| `--no-default-trust` | `no_default_trust` | Ignore every packaged snapshot |
| `--time` | `validation_time` | RFC 3339 validation instant |

Trust flags repeat, and repeated bundles merge. Python keyword arguments and the WebAssembly options object use the same names; Go uses the CamelCase equivalents, such as `NoDefaultTrust`.

Each anchor serves one purpose. A claim-signing anchor cannot validate a timestamp authority, and a timestamp anchor cannot validate a claim signer. An identity-aggregation credential is trusted only when its issuer is listed or reaches a listed anchor, and a credential that names a revocation list is checked against the lists you supply; a missing list is reported, not assumed good.

```bash
encypher-c2pa verify photo.jpg \
  --no-default-trust \
  --trust org-anchors.pem \
  --tsa-trust org-tsa-anchors.pem \
  --time 2026-08-11T00:00:00Z --json
```

A verifier that has not been allowed online cannot prove that a trust list is current, so `freshness.status` is `unknown`, and revocation is read only from responses stapled into the manifest. Allowing online checks lets the verifier ask the OCSP responder named by the certificate. See [Trust model](https://github.com/encypherai/encypher-c2pa/blob/main/docs/TRUST_MODEL.md).

## Manifests stored outside the file

By default the SDK reads; it does not fetch. When an asset names its manifest by URL, the report returns the URL as `manifest.inaccessible` and stops there. Fetch the manifest yourself if you choose, then verify it with `verify_with_manifest_store`. The same entry point verifies a `.c2pa` sidecar, with the same trust material, validation time, and posture as an embedded manifest.

```bash
encypher-c2pa verify photo.jpg --manifest photo.c2pa
```

To have the store fetched for you, allow online checks (below).

## Online checks (opt-in)

Some questions cannot be answered from the file alone. Where the manifest lives, whether a signing certificate has been revoked, what an identity issuer's DID document says, what the content stored outside the asset is: each needs a server. Nothing is fetched unless you say so.

Every report carries a `network` block. Offline, it lists what a fetch would settle, so you can see what allowing one would do:

```json
"network": {
  "enabled": false,
  "needed": [{"kind": "remote_manifest", "uri": "https://manifests.example.com/photo.c2pa"}],
  "requests": []
}
```

Allow it for one run, or save the answer:

```bash
encypher-c2pa verify photo.jpg --online     # this run only
encypher-c2pa verify photo.jpg --offline    # this run only, whatever is saved
encypher-c2pa online on                     # allow from now on
encypher-c2pa online ask                    # ask each time a fetch is needed
encypher-c2pa online off                    # never
encypher-c2pa online status
```

With `ask`, or before you have answered, a run that needs a fetch prints each purpose and host, says that contacting them tells those servers the file is being checked, and offers `[y] yes, this time  [N] no  [a] always  [v] never`. A run with nobody at the terminal never prompts and stays offline.

`ENCYPHER_C2PA_ONLINE=on` or `off` is the operator's switch. It applies to every surface and outranks the saved answer.

Libraries never read the saved answer and never prompt, because the machine calling them may be checking files sent in by strangers. Pass the option instead:

```python
encypher_c2pa.verify("photo.jpg", online=True)
```

```rust
let options = VerifyOptions { online: Some(true), ..Default::default() };
```

```go
allow := true
report, err := c2pa.Verify(asset, "image/jpeg", &c2pa.Options{Online: &allow})
```

In the browser, `verify` stays synchronous and offline; `await verifyOnline(bytes, mime, options)` does the same verification and fetches through the page's own `fetch`, so the page's CORS and Content-Security-Policy rules apply.

What each host learns is one request for one URL: that somebody is checking a file that references it. The SDK never sends asset bytes. An OCSP request carries a certificate serial number and issuer hashes, nothing more. Full detail is in [Privacy](https://github.com/encypherai/encypher-c2pa/blob/main/docs/PRIVACY.md).

The fetcher is narrow on purpose: https only, except OCSP responders, whose answers are signed and verified; at most 3 redirects, each re-checked; 5-second connect and 10-second total timeouts; at most 16 requests per verification; size caps of 64 MiB for a manifest store or external content, 64 KiB for an OCSP response, 256 KiB for a DID document; no cookies, no credentials, a fixed `encypher-c2pa/<version>` user agent. Every hostname is resolved through a filter that refuses loopback, private, link-local (including `169.254.169.254`), carrier-NAT, unique-local, multicast, and documentation addresses, and the connection uses the address that was vetted. Set `--online-allow-private-networks` (`online_allow_private_networks`) for an intranet deployment: that lifts the address filter and accepts plaintext http. Do not set it where files arrive from strangers.

What stays caller-supplied, and why: ICA status-list credentials, because a credential has to be verified as a credential before it can be trusted; trust lists, because their currency is a snapshot policy rather than a fetch; and AIA `caIssuers` chain completion.

Build without the fetcher entirely with `--no-default-features --features telemetry`, if you need to be able to prove a binary cannot reach the network for verification.

## Updates

Each release carries verification fixes and a refreshed trust snapshot, so an old copy judges files against old trust lists. The command line checks for a newer release once a day, when a person is at the terminal, and offers to install it:

```text
encypher-c2pa 1.2.1 is available. You have 1.2.0, with trust lists dated 2026-09-24.
Releases carry verification fixes and refreshed trust lists.
Update now? [y] yes  [N] not now  [s] skip this version  [o] stop checking
```

`y` runs `cargo install encypher-c2pa-cli --version 1.2.1 --locked`, then runs your command again on the new version. `s` skips that release; a later one is still offered. `o` turns the check off.

The check is one request for the crate's public entry in the crates.io index. It carries no file, path, or identifier, gives up after two seconds, and fails silently. Runs with nobody at the terminal (pipes, CI, cron) never check, and `--offline` skips the check for that run. The libraries never check; update them through your package manager.

```bash
encypher-c2pa update                 # check and install now
encypher-c2pa update-check off       # or: on, status
```

The setting is saved in `update.json` in the configuration directory (`~/.config/encypher/` on Linux and macOS, `%APPDATA%\Encypher\` on Windows, or `ENCYPHER_C2PA_CONFIG_DIR`). `{"check": false}` turns the check off. `ENCYPHER_C2PA_UPDATE_CHECK=on` or `off` overrides the file.

## Verification posture

By default the verifier applies the C2PA 2.4 validation rules. A few rules that content written under C2PA 1.x could not have followed, such as the links from an action to its ingredients, apply to that content only in strict mode.

Set `strict_conformance` (`--strict-conformance`) to apply the C2PA Conformance Program as well. Strict mode turns the program's additional requirements into failures, such as a trusted timestamp and usable revocation information, and requires CAWG Identity 1.3 deterministic encoding of identity signatures. It also adds the report's Content Credentials JSON (`content_credentials`), the form conformance rubrics evaluate.

Where the two postures differ, the default report says so with an informational status. For example, an identity signature over the CAWG 1.1 field order, which c2pa-rs still writes, verifies by default with `com.encypher.cawg.legacyProfile`. To refuse that encoding without taking on the rest of strict mode, set `cawg_strict_encoding` (`--cawg-strict-encoding`).

## Failure telemetry (opt-in)

Telemetry is off until you turn it on. On the first interactive run, the SDK shows what it would send and asks once. Non-interactive processes never prompt and stay off.

An event is sent only when provenance is invalid or verification fails. It contains the SDK name and version, the engine profile, the MIME type, the outcome, and at most eight status codes. It never contains the file, the manifest, the report, a filename or path, a certificate or key, trust material, or any account or machine identifier. Sending never blocks verification. The full contract is in [Privacy](https://github.com/encypherai/encypher-c2pa/blob/main/docs/PRIVACY.md).

```bash
encypher-c2pa telemetry on      # or: off, status
```

Python uses `configure_telemetry(True)`, Go `c2pa.ConfigureTelemetry(true)`, and JavaScript `configureTelemetry(true)`. Native deployments can set `ENCYPHER_C2PA_TELEMETRY=on` or `off` instead. A per-call setting overrides the saved preference.

## Optional cross-check with the Encypher API

`--encypher-api` asks the [Encypher API](https://api.encypher.com/docs) whether Encypher holds a provenance record for the file. Set `ENCYPHER_API_KEY` first.

```bash
encypher-c2pa verify photo.jpg --encypher-api --json
```

The request carries the file's SHA-256, size, MIME type, and a summary of the local result. When the format keeps the manifest in one contiguous block, it also carries that manifest store so the API can validate it independently. The file itself, its name, and its path stay local.

The answer is attached under `encypher_api` and never changes the local verdict or exit code. A match there is Encypher's record, not a trust decision about the signer. A network error produces a warning, not a failed verification.

## Scope

This SDK verifies open-standard Content Credentials. It does not sign media, build manifests, or write into files, and the published API has no path that could. [Verification boundary](https://github.com/encypherai/encypher-c2pa/blob/main/docs/VERIFICATION_BOUNDARY.md) describes the three CI controls that enforce this.

It also does not read Encypher's proprietary provenance markers, such as sentence-level text provenance or durable soft bindings. Content that carries them verifies here as ordinary C2PA content. Signing, marker detection, hosted trust policy, and durable receipts are available through the [Encypher API](https://api.encypher.com/docs).

## Standards status

The verifier shares no code with other C2PA implementations. Interoperability is tested offline against pinned vectors: core media from `contentauth/c2pa-rs`, the CAWG identity corpus, and generated conformance vectors. Expected results come from the C2PA 2.4 status-code definitions, not from another implementation's output.

The C2PA 2.4 and CAWG Identity 1.3 labels describe what the verifier targets. They are not a conformance certification. C2PA and Content Credentials are marks of their respective owners.

## Build from source

Requires Rust 1.88 or later. Python packaging needs `uv` and `maturin`. Browser packaging needs `wasm-pack` and the `wasm32-unknown-unknown` target.

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

Contribution rules are in [CONTRIBUTING.md](https://github.com/encypherai/encypher-c2pa/blob/main/CONTRIBUTING.md). The architecture is described in [Architecture](https://github.com/encypherai/encypher-c2pa/blob/main/docs/ARCHITECTURE.md).

## Security

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/encypherai/encypher-c2pa/security/advisories/new). Parser limits and the threat model are in [SECURITY.md](https://github.com/encypherai/encypher-c2pa/blob/main/SECURITY.md).

## License

Copyright 2026 Encypher Corporation. Licensed under the [Apache License 2.0](https://github.com/encypherai/encypher-c2pa/blob/main/LICENSE).

Redistributions and derivative works must keep the [NOTICE](https://github.com/encypherai/encypher-c2pa/blob/main/NOTICE) file, which attributes the software to Encypher Corporation (Section 4(d)), and the copyright and license header in each source file (Section 4(c)). The license does not grant use of the Encypher name or logo (Section 6). Third-party test vectors under `tests/vectors/` keep their upstream licenses, recorded next to each asset.
