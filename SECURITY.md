# Security policy

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/encypherai/encypher-c2pa/security/advisories/new). Do not open a public issue for a parser crash, signature bypass, trust bypass, out-of-bounds access, denial of service, or credential exposure.

Include:

- affected package and version;
- asset or minimal reproducer;
- expected and observed validation result;
- impact and attack preconditions;
- whether the asset may be shared with maintainers.

We will acknowledge a complete report within three business days. We coordinate fixes and disclosure with the reporter. We do not require an NDA.

## Supported versions

Only the latest stable release receives security fixes. Release candidates and older stable releases are unsupported once a newer stable release is available.

## Security properties

- Asset parsing, trust resolution, and validation make no network requests unless online checks are allowed. Libraries require an explicit `online` option or `ENCYPHER_C2PA_ONLINE`; only the command line reads a saved choice or asks. Allowed fetches go to public addresses only, with size, time, redirect, and request-count limits, and never carry asset bytes. With saved or explicit consent, post-verification failure telemetry may send one bounded HTTPS request. Disable the default `online` and `telemetry` features for a library build with no egress.
- The command line checks the crates.io index for a newer release once a day, only when a person is at the terminal. The request carries no file, path, or identifier. An update installs only when the person answers yes, and only through `cargo install` from crates.io. Turn it off with `encypher-c2pa update-check off`, `{"check": false}` in `update.json`, or `ENCYPHER_C2PA_UPDATE_CHECK=off`.
- No embedded URL is fetched unless online checks are allowed, and trust lists are never fetched.
- No default operating-system or Encypher trust store is consulted.
- Trust requires explicit caller-supplied PEM material.
- Malformed trust material fails closed.
- Rust parser and verifier crates forbid unsafe code. The small C ABI contains reviewed pointer conversion at the boundary and catches Rust panics before they cross FFI.
- Data-hash exclusion lists are capped before range parsing and hashing.
- Manifest stores are limited to 64 MiB and JUMBF labels to 1,024 bytes before JUMBF parser-owned allocation.
- Integrity, trust, revocation, freshness, policy, and managed receipts remain separate report axes.
- Verification is in-memory. A service that accepts untrusted uploads must enforce its deployment-specific asset-size limit before calling the SDK; parser bounds limit amplification, not the caller-owned asset buffer.

## Out of scope

- Bugs in applications that ignore the report contract, such as treating `integrity: valid` as signer trust.
- Availability of package registries or GitHub.
- Signing-key management, hosted policy, and production Encypher services. Those are not in this repository.

## Test assets

A malicious sample may contain personal or licensed content. State sharing restrictions in the report. If the sample cannot be shared, provide a generator or a byte-level description that reproduces the fault.
