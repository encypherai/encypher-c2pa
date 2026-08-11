# Architecture

One Rust verification core serves every language binding.

```mermaid
flowchart LR
  Asset[Caller asset bytes] --> Facade[encypher-c2pa facade]
  Trust[Caller PEM and validation time] --> Facade
  Consent[Explicit telemetry consent] --> Facade
  Facade --> Format[Container readers]
  Facade --> Claim[Claim and JUMBF parser]
  Facade --> Crypto[Signature verification]
  Facade --> Binding[Hard-binding verification]
  Facade --> TrustEval[Static trust evaluation]
  Format --> Report[Report schema 1.0]
  Claim --> Report
  Crypto --> Report
  Binding --> Report
  TrustEval --> Report
  Facade -. Invalid result only .-> FailureEvent[Bounded failure event]
  FailureEvent --> TelemetryEndpoint[Configurable telemetry endpoint]
  Report --> CLI[CLI]
  Report --> Python[Python ABI3]
  Report --> CABI[C ABI and Go]
  Report --> WASM[Browser WASM]
```

## Public facade

`crates/encypher-c2pa` owns the stable API, report mapping, and all verifier implementation modules. Consumers depend only on this crate.

## Verification core

- `crates/encypher-c2pa/src/c2pa-cbor`: exact CBOR profiles used by C2PA claims and assertions.
- `crates/encypher-c2pa/src/c2pa-core`: JUMBF, claims, assertions, spec versions, and engine profiles.
- `crates/encypher-c2pa/src/c2pa-formats`: format detection, manifest extraction, and hard-binding byte ranges.
- `crates/encypher-c2pa/src/c2pa-crypto`: COSE signature algorithms and certificate extraction.
- `crates/encypher-c2pa/src/c2pa-trust`: packaged and caller-supplied certificate-chain evaluation.
- `crates/encypher-c2pa/src/c2pa-validate`: manifest-store traversal and validation status production.

These are private modules, not separately published crates.

No support crate contains a network client. The public facade's default `telemetry` feature provides the opt-in native transport; WASM disables that feature and uses the browser transport only after explicit consent.

## Bindings

- `crates/encypher-c2pa-cli`: file-oriented CLI with JSON and human output; `--telemetry` opts in.
- `bindings/python`: PyO3 adapter. CPU work releases the Python GIL; `telemetry=True` opts in.
- `bindings/c`: panic-contained C ABI returning an owned JSON envelope. `VerifyOptions` JSON carries telemetry consent.
- `bindings/go`: typed cgo wrapper over the C ABI.
- `bindings/wasm`: wasm-bindgen adapter returning a native JavaScript object and posting consented failures with browser `fetch`.

All bindings delegate semantics to the Rust facade. They do not reinterpret validation statuses.

## Resource boundaries

The public v1 API accepts an in-memory byte slice. File helpers read the file before verification. Browser verification also copies the selected `ArrayBuffer` into WASM memory. These choices keep the first public API small and deterministic, but they make memory use proportional to asset size.

Do not use the browser binding for multi-gigabyte compositions. A future streaming API must preserve each format's exclusion and offset invariants before it can replace the byte-slice contract.

The core caps pathological data-hash exclusion lists before parsing or hashing their ranges. Parsers use checked arithmetic and reject truncated or malformed structures.

## Release graph

The workflow publishes `encypher-c2pa`, waits for its immutable crates.io version, then publishes the exact-pinned `encypher-c2pa-cli`. Separate jobs build Python wheels and an sdist for PyPI and browser WASM for npm. A GitHub Release is created only after all three registries succeed. C and Go remain source bindings in this repository; v1 does not publish separate C/Go archives or standalone CLI binaries.
