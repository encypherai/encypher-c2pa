# Typed CAWG Trust Configurations

**Status:** implemented; completion fixes verified (885 Rust tests, Go, Python, CLI, formatting, Clippy, and public-surface gate)
**Completion Gate:** cleared at cycle 3 on `fd98287bc5a7a929a8687efa51c89283eed6575d` - Astra 10/9.5/10; Opus 9.6/9.5/9.8.
**Current Goal:** a caller can hand the verifier the Mozilla email root store and the IPTC lists as interim S/MIME sources, so the 31 March 2027 cutoff and the trusted-time-stamp condition apply to them, and each source can carry its own trust window.

## Overview

CAWG Identity 1.3 (x509/trust-model) has the validator keep a trust configuration per accepted EKU. Its interim additions accept `id-kp-emailProtection` credentials from two named sources, the Mozilla root store with the email trust bit and the IPTC Verified News Publishers lists, and only while the time of validation, or a trusted time stamp, is on or before 31 March 2027.

The bundled snapshot already tags those sources `SmimeInterim`. A caller that runs with `no_default_trust` and supplies fresh copies has no way to say what they are: everything in `cawg_trust_pem` and `cawg_allowed_certs_pem` is tagged `CallerSupplied`, the base model, with no cutoff. The hosted Encypher verifier does exactly this, so after the cutoff an untimestamped S/MIME identity chaining to a Mozilla email root would still read `cawg.identity.trusted`.

Three related gaps:

1. One anchor pool serves both EKUs. The facade always requires an anchor for `id-kp-documentSigning`, and a Mozilla email root or IPTC anchor satisfies that requirement, although the interim section configures those sources for `emailProtection` only.
2. Condition 4 says each interim list may mix CA and end-entity certificates. Callers route PEM by the list it came from, so a CA in an end-entity list is only matched directly and never anchors a chain.
3. Direct allowed-list matches ignore the configuration's `notBefore`/`notAfter`. 1.3 x509/validating says a configuration carrying either bound MUST NOT validate a signature outside it.

## Design

### New option

```rust
pub struct VerifyOptions {
    // ...
    /// Typed CAWG trust configurations, one per source.
    pub cawg_trust_configurations: Option<Vec<CawgTrustConfiguration>>,
}

pub struct CawgTrustConfiguration {
    pub profile: CawgTrustProfile,          // "base" | "smime_interim"
    pub certificates_pem: String,           // CA and end-entity certificates may mix
    pub not_before: Option<String>,         // RFC 3339, this configuration only
    pub not_after: Option<String>,
}
```

- `base`: an entry the validator configured itself. Accepts `id-kp-documentSigning`. As permitted local policy, it also accepts `id-kp-emailProtection` with one of the six CA/B Forum policies, without interim conditions. Direct matches report `trust_source: allowed_list`; anchored document-signing matches report `document_signing`; anchored S/MIME matches report `caller_supplied`.
- `smime_interim`: one of the two interim sources. Accepts `id-kp-emailProtection` with one of the six policies, only under interim condition 1. Direct matches report `trust_source: allowed_list`; anchored matches report `smime_interim`.
- Each certificate is placed by content, not by list: a CA certificate (BasicConstraints `cA = TRUE`) becomes a chain anchor, and so does a self-issued X.509 v1 certificate (subject equals issuer) with no BasicConstraints extension. Any other certificate is a direct match. A self-issued v3 end-entity certificate without BasicConstraints remains a direct match and cannot issue credentials.
- Bounds belong to the configuration. The global `trust_anchor_not_before`/`trust_anchor_not_after` keep bounding only `cawg_trust_pem`, `cawg_allowed_certs_pem`, and the claim/TSA inputs.
- `cawg_trust_pem` and `cawg_allowed_certs_pem` stay, unchanged in meaning. Removing them is a breaking change under the report compatibility policy.
- Configurations are appended after `cawg_trust_pem`/`cawg_allowed_certs_pem`, in the order given.
- Accepting `emailProtection` under `base` is local validator policy, not a normative base-model rule. The 1.3 trust model has the validator keep a list of accepted EKUs, each with its own policies and anchors, and mandates only `id-kp-documentSigning`; it neither requires nor forbids a validator-configured `emailProtection` entry. The six-policy restriction on `base` is this verifier's choice, borrowed from the interim section. It is how the bundled Encypher Verified Organizations root is already treated.

### Errors

Configurations are validated when options are resolved, before any asset is read, and a bad entry fails the whole call:

- An unknown `profile`, a missing `certificates_pem`, or an unknown key is refused while the options are parsed, like every other malformed option: `invalid_options` from the JSON bindings (C, WASM, Python, Go), a compile error for Rust callers (`CawgTrustProfile` is an enum). The serde message names the offending value.
- An empty `certificates_pem`, PEM with no certificate, an undecodable certificate, an unparseable `not_before`/`not_after`, or `not_before` later than `not_after` is `Error::InvalidTrust` (`invalid_trust_material`), naming the entry and field, e.g. `cawg_trust_configurations[2].certificates_pem: no certificates`. An empty list is never a silent no-op: a caller that means "no certificates from this source" omits the entry.

### Evaluation changes (`identity_certificate_trust`)

Eligible anchors are chosen before the chain is searched, never after. The path builder stops at its first trusted path, so filtering the anchor it returned would let a refused interim path hide a valid base path through a different intermediate or root. `validate_chain` gains an anchor predicate (`validate_chain_admitting`); only anchors that pass it can terminate a path.

- `id-kp-documentSigning`: only base-eligible entries count, for both the direct match and the chain. Base eligibility is `!cawg_source.interim()`, so caller `base` entries, `cawg_trust_pem`/`cawg_allowed_certs_pem`, and the bundled Encypher Verified Organizations root are all eligible; bundled and caller `smime_interim` entries are not. A credential that also carries `emailProtection` with an approved policy is then offered to the emailProtection entry instead of failing.
- `id-kp-emailProtection` (approved policy required): base-eligible entries are searched first, direct match then chain. Only if none accepts are `smime_interim` entries searched, and only they are subject to the interim time condition. A credential with both a refused interim path and a valid base path is accepted on the base path.
- Every CAWG entry, direct or anchor, is eligible only inside its configured window, measured at the attested instant (trusted time stamp, else validation time).
- Duplicates: a certificate configured more than once is represented, for a given EKU search, by the first entry that is in force at the evaluation instant and eligible for that search. An out-of-window or ineligible duplicate never shadows a later one. Because base is searched before interim, the same certificate listed as both `base` and `smime_interim` is always evaluated under base rules for `emailProtection`, whatever the order.
- The interim time condition is unchanged: validation time before 2027-04-01T00:00:00Z, or a trusted time stamp attesting a time before it.

### Behaviour changes callers will see

- With default trust, an `id-kp-documentSigning` identity that reached trust only through a bundled Mozilla or IPTC certificate now reads `cawg.x509.credential.untrusted` with `document_signing_anchor_required` (the facade always requires a documentSigning anchor).
- A caller-bounded `cawg_allowed_certs_pem` entry no longer accepts a signature outside `trust_anchor_not_before`/`trust_anchor_not_after`.
- A credential that has both an interim and a base path reports the base entry's `trust_source`.

### Binding and documentation surfaces

- Rust: `VerifyOptions::cawg_trust_configurations`, `CawgTrustConfiguration`, `CawgTrustProfile`; `public-surface.txt` updated.
- JSON bindings (C `options_json`, WASM `options`, Python `verify`/`verify_stream` kwarg `cawg_trust_configurations`, Go `Options.CAWGTrustConfigurations`): same JSON shape; Go round-trip test extended.
- CLI: `--cawg-trust-configurations <FILE>`, a JSON array in the same shape, repeatable (arrays concatenate in flag order); README option table row.
- docs/TRUST_MODEL.md: the two profiles, per-configuration windows, EKU scoping, base-before-interim search, duplicate rule, errors. CHANGELOG entry under Unreleased, including the two behaviour changes above.

No status code is added or renamed. `trust_source` gains no new value.

## Tests (red first)

Each test cites its requirement id. Configuration tests run the options JSON the bindings send through `ResolvedOptions::resolve` and the identity lane; entry-rule tests call `identity_certificate_trust` directly.

- An untimestamped S/MIME identity whose anchor arrives as `smime_interim` is trusted before the cutoff, refused with `trusted_timestamp_required` after it, and accepted after it with a trusted time stamp from before it; the same anchor as `base` stays trusted after the cutoff (023/025/027, consumer side of 024).
- An `smime_interim` certificate, direct or anchor, does not satisfy the documentSigning anchor requirement; a `base` one does. A documentSigning + emailProtection credential refused as documentSigning is accepted by the interim emailProtection entry before the cutoff (018).
- Masking: a cross-certified issuing CA with one path to an interim root and one to a base root is accepted on the base path after the cutoff without a time stamp. An in-force CA from a non-admitted profile may bridge to an admitted anchor, but may not terminate the path itself (018/025).
- Duplicates: the same root listed `smime_interim` first and `base` second is evaluated under base rules; an out-of-window first entry does not shadow an in-window second (018, DELTA-009).
- A CA certificate inside a configuration anchors a chain, a self-issued X.509 v1 root without BasicConstraints anchors a chain, and a self-issued v3 end entity without BasicConstraints stays a direct match (031).
- A configuration window refuses chained and direct matches outside it, measured at the trusted time stamp when there is one (DELTA-009).
- Errors: empty `certificates_pem`, unparseable bound, and `not_before` > `not_after` each fail resolution with `invalid_trust_material` naming the entry index; an unknown profile fails option parsing. Public path entry points resolve these options before opening an asset, detached manifest, or stream segment.
- Go round-trip carries `cawg_trust_configurations`, and Go `VerifyFile` returns an indexed trust-material error before opening a missing asset. Python `verify` and `verify_stream` validate and forward the kwarg; two repeated CLI files concatenate in order, with a semantic error in the second file naming its concatenated entry index.

## Out of scope

Any change to the bundled snapshot contents, the report schema, or CAWG ICA trust.
