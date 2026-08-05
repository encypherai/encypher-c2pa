# Contributing

## Scope

The public API is verification-only. Changes that add a public signing surface, hosted policy, account flows, telemetry beyond the fixed opt-in validation-failure contract, proprietary watermarking, or remote trust lookups belong elsewhere.

Good contributions include:

- C2PA parser and validator fixes;
- public format interoperability fixtures;
- clearer validation statuses and report docs;
- deterministic malformed-input tests;
- Rust, Python, Go, C, and WASM binding fixes;
- memory and CPU improvements that preserve validation semantics.

## Development

Install Rust 1.85 or later.

```bash
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

For Python:

```bash
maturin build --manifest-path bindings/python/Cargo.toml
```

For browser WASM:

```bash
rustup target add wasm32-unknown-unknown
cd bindings/wasm
wasm-pack build . --target web --release --out-dir pkg
node ../../scripts/package-wasm.mjs
node ../../scripts/test-wasm.mjs
```

For Go:

```bash
cargo build -p encypher-c2pa-ffi --release
cd bindings/go
go test ./...
```

## Tests

Tests must defend an observable contract. Include a fixture or generator for parser and interoperability changes. A tamper test must show that a plausible byte change no longer validates. Avoid source-text assertions and network-dependent tests.

Fixtures must be redistributable. Add source, license, and expected status information when importing a third-party asset.

## Report compatibility

`schema_version: "1.0"` is public. Additive fields are allowed. Renames, removals, type changes, and semantic changes require a new major schema version and migration notes.

Validation consumers branch on status codes. Preserve stable C2PA codes when fixing explanations.

## Pull requests

Keep one concern per pull request. Explain the broken invariant, the chosen fix, and the command that proves it. Run format, lint, and the affected suites before requesting review.

By contributing, you agree that your contribution is licensed under Apache-2.0 or MIT, at the user's option.
