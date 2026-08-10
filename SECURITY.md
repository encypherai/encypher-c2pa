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

- Asset parsing, trust resolution, and validation make no network requests. With saved or explicit consent, post-verification failure telemetry may send one bounded HTTPS request. Disable the default `telemetry` feature or set the per-call telemetry option to `false` for no egress.
- No embedded URL is fetched.
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
