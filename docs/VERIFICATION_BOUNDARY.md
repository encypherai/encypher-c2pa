# Verification-only boundary

The published SDK reads and verifies C2PA manifests. It cannot sign media, build a manifest, or write one into an asset. Three CI controls hold that line. Each checks a different thing, and none is a proof on its own.

## 1. The public API surface

`scripts/check-public-surface.mjs` reads the public surface from rustdoc's own JSON output, so re-exports, macro expansion, impl methods, fields, and variants are resolved by the compiler rather than inferred. It compares that surface with the reviewed inventory in `public-surface.txt`, and any unreviewed public item fails the build.

The check unions four build configurations: the host with no features, the host with `telemetry` only, the host with default features, and `wasm32-unknown-unknown` with no features (the browser build). The Cargo feature map is locked to an approved set taken from `cargo metadata`, so a new feature, or a redefined one, fails. The walk refuses anything it cannot name or reach. A source tripwire rejects public items behind a `cfg` that rustdoc cannot observe, such as `cfg(doc)` or a target outside the four above.

This control locks the shape of the API. It cannot see an approved function whose body starts writing bytes.

## 2. Observable behavior

`crates/encypher-c2pa/tests/read_only_contract.rs` runs `verify`, `verify_with_options`, and `verify_file` across every extension in `SUPPORTED_EXTENSIONS` and every MIME type from `supported_mime_types()`, on success and failure paths. It asserts that the input is byte-identical afterwards and that no file is created or removed in the directory being read. The lists come from the crate, so a newly supported format is covered as soon as it is added. The test does not observe writes elsewhere on the filesystem.

## 3. The kernel

`crates/encypher-c2pa/tests/no_write_capability.rs` forks a child, installs a seccomp allowlist, and runs the same entry points inside it. Any syscall outside the list kills the process. The list holds two tiers:

- The syscalls the scenario actually makes. CI removes each one in turn and requires the run to die, so no entry sits in the list unexplained.
- A headroom tier for portability across libc and kernel versions. No headroom entry can create or modify a file.

Canary tests confirm the gates against the running kernel. `openat` with `O_CREAT` dies, `open` with `O_WRONLY` dies, `ioctl` with any request other than `TCGETS` dies, and `io_uring_setup` dies. A read-only `openat` still succeeds. The filter kills on the attempt rather than returning `EPERM`, so a discarded write error cannot pass unnoticed.

Signed JPEG and MP4 fixtures are asserted to verify inside the sandbox with valid integrity. Every other supported MIME type runs on unsigned, truncated, and absent input, which exercises format dispatch and the error paths.

## What the boundary excludes

The repository contains parsing, format handling, signature and binding checks, packaged trust snapshots, caller-supplied trust evaluation, and the opt-in failure telemetry client. It does not contain signing keys, managed trust policy, registry lookups, proprietary watermarking or fingerprinting, customer workflows, service credentials, or telemetry backends. Manifest construction and container writers live in private modules and compile only under `cfg(test)`, where they generate fixtures.
