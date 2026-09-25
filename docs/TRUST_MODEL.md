# Trust model

The verifier answers two different questions.

1. Did the signed claim and hard binding survive unchanged?
2. Does the configured trust policy accept the signing identity at the validation time?

The first question is local cryptography. The second is organizational policy. The SDK does not merge them.

## Default behavior

Every package compiles the same pinned trust snapshot into the verifier. The `2026-09-24` snapshot contains:

- C2PA Trust List claim-signing anchors;
- C2PA TSA Trust List timestamp-authority anchors;
- IPTC Verified News Publishers end-entity certificates for claim and CAWG identity checks;
- the Mozilla Email-trusted root store and IPTC anchor list for the CAWG Identity 1.3 interim X.509 trust model;
- the Encypher C2PA root, TSA issuing CA, and Verified Organizations identity anchor.

The CAWG trust configuration is a list of entries, as CAWG Identity 1.3 defines it: accepted extended key usages, each with its accepted certificate policies and trust anchors. The specification names two sources for its interim S/MIME additions, the Mozilla email root store and the IPTC Verified News Publishers lists, and only those entries carry the interim conditions: `emailProtection`, one of the six approved CA/Browser Forum S/MIME certificate policies, and either a validation time on or before 31 March 2027 or a trusted time stamp establishing that the identity assertion was issued by then. The Encypher Verified Organizations anchor, and any anchor or end-entity certificate you supply, is an entry the validator configured itself. It accepts `id-kp-documentSigning`, and `emailProtection` with the same six policies, under the base trust model: no cutoff and no time-stamp condition. Chain building, the certificate profile, and revocation are identical for every entry, and the report names the entry that accepted the credential in the `trust_source` detail (`encypher_verified_organizations`, `caller_supplied`, `smime_interim`, `allowed_list`, or `document_signing`).

The IPTC CAWG anchor list was empty at snapshot time; its end-entity list was not. Under CAWG Identity 1.3, an identity credential that reaches none of the configured CAWG anchors is rejected with the failure code `cawg.x509.credential.untrusted`. With no CAWG trust material configured at all there is no root of trust to reach, and the assertion keeps the `cawg.identity.well-formed` success code. Either way the C2PA integrity verdict is unchanged.

No trust-list fetch occurs at install time or verification time. The exact source URLs and SHA-256 digests are recorded in `crates/encypher-c2pa/src/default_trust/sources.json`; Rust callers can read `DEFAULT_TRUST_SNAPSHOT_DATE`.

Integrity and trust remain separate. A credential can have valid integrity while failing to chain to a packaged anchor:

```json
{
  "integrity": "valid",
  "trust": {
    "status": "not_valid_for_supplied_material",
    "basis": "bundled_static_material"
  }
}
```

## Caller-supplied material

`VerifyOptions` accepts five independent PEM bundles:

- `trust_pem`: additional claim-signing trust anchors.
- `tsa_trust_pem`: additional timestamp-authority trust anchors.
- `allowed_list_pem`: additional claim-signing end-entity certificates.
- `cawg_trust_pem`: additional CAWG X.509 identity trust anchors.
- `cawg_allowed_certs_pem`: CAWG X.509 end-entity certificates accepted directly by the caller.

Caller material extends the packaged snapshot. `no_default_trust: true` disables every packaged list and evaluates only caller-supplied material. With no caller material in that mode, the report uses `trust.status = "not_evaluated"` and `trust.basis = "none"`. Under `strict_conformance` the same run also reports `signingCredential.untrusted`, because a credential absent from an empty trust list is untrusted under the C2PA rules, and a report without a trust status would read as trusted to a conformance rubric.

Each anchor carries one purpose: claim signing, time-stamping, or CAWG identity. A path may end only at an anchor whose purpose matches the certificate being checked, so a timestamp-authority anchor never validates a claim signer. `trust_anchor_not_before` and `trust_anchor_not_after` (RFC 3339) bound the anchors you supply; an anchor outside its window at the validation time cannot end a path (C2PA 2.4 VAL-CRYP-0010/0011). Packaged anchors are unbounded, because the snapshot is their window.

Every certificate on the path is checked against the C2PA certificate profile: version 3, key identifiers, key usage, extended key usage with time-stamping and OCSP signing exclusive of other purposes, approved signature algorithms and key sizes, and no unrecognized critical extension. The path itself follows RFC 5280: basic constraints, path length, name constraints, and explicit-policy requirements. Policy mapping is not implemented, so a path that needs it fails closed. Trust anchors are treated as names and keys, as RFC 5280 section 6.1 does, and are not held to the end-entity profile.

CAWG document-signing credentials require a configured CAWG anchor or allowed-list match; certificate profile alone never establishes trust. Material you pass in `cawg_trust_pem` or `cawg_allowed_certs_pem` is a validator-configured entry, so it is evaluated under the base trust model rather than under the interim S/MIME additions, which belong to the two root stores the specification names. `cawg_did_documents` supplies a pinned DID-to-document map for `did:web` identity resolution without the network; with online checks allowed, a missing document is fetched from the DID's own URL and used the same way.

An identity claims aggregation credential is trusted only when its issuer DID is listed in `cawg_ica_trusted_issuers`, or reaches a DID in `cawg_ica_trust_anchors` through `controller` links in pinned DID documents (at most 16 hops). A credential with a `credentialStatus` revocation entry is checked against `cawg_ica_status_lists`, a map from status-list URI to the decompressed bitstring in standard base64. A missing list is reported as `cawg.ica.revocation.unavailable`; it is never treated as not revoked. Status-list credentials stay caller-supplied even when online checks are allowed: a status list is itself a verifiable credential, and fetching one would mean trusting it before verifying it.

Malformed PEM is a hard input error. The verifier never converts malformed trust material into a silent `not_evaluated` result.

A supplied `validation_time` must be RFC 3339. If omitted, native bindings capture current UTC time. The browser binding captures `Date` in JavaScript and passes it explicitly to the Rust core.

## No ambient network or mutable trust

The public SDK does not:

- fetch or refresh C2PA, IPTC, or Encypher trust lists;
- follow AIA `caIssuers`, CRL, JUMBF, or ingredient URLs;
- query an Encypher API unless the CLI caller explicitly passes `--encypher-api`;
- use an operating-system certificate store;
- accept a signer because a certificate is syntactically valid;
- cache a trust decision between calls;
- contact anything at all unless online checks were allowed for that call.

Online checks are off on every surface. When they are allowed, the SDK may fetch exactly four things: the manifest store an asset names, the OCSP status of a claim signer or CAWG identity certificate, the `did:web` document of an ICA issuer, and content an assertion stores outside the asset. Nothing else is ever fetched, and nothing fetched changes how evidence is judged: a second, entirely offline pass verifies the asset with the fetched material supplied as ordinary caller evidence.

With online checks off, the verification result depends only on the asset bytes, the packaged snapshot, and explicit call options. With them on, it depends in addition on the fetched evidence, which the report's `network` block names item by item.

## Revocation and freshness

Revocation is evaluated only when usable evidence is embedded in the credential. Without such evidence, the report says `not_checked`. This is different from `not_revoked`.

Online OCSP is optional and consent-gated. With online checks off, `signingCredential.ocsp.skipped` means that no usable stapled response established the certificate's status and no responder was contacted. It does not mean that the responder returned `good`, or that the certificate was proved not revoked. Workflows that need a current status can staple an OCSP response, carry a certificate-status assertion, allow online checks, or use a hosted verification service. When online checks are allowed, the SDK asks the responder the certificate names, verifies the signed response exactly as it verifies a stapled one, and registers `*.ocsp.inaccessible` when the responder was tried and gave no usable answer.

When a manifest staples several OCSP responses for one certificate and they disagree, the default posture treats any `revoked` response as decisive. Under `strict_conformance`, a qualifying `good` response settles the status, as the C2PA 2.4 validation rules specify, and the outranked `revoked` response is reported as the informational `com.encypher.ocsp.conflictingRevokedResponse`. CAWG identity revocation stays fail-closed in both postures.

A verifier working from the packaged snapshot knows its date but cannot prove that the material is still current, and online checks do not change that: trust lists are a snapshot policy, not a fetch. `freshness.status` therefore remains `unknown` in schema 1.0. Encypher will publish a refresh release within 30 days after a packaged upstream source changes. Callers do not need to wait for that release: they can pass current lists through the caller-supplied trust options at any time.

Maintainers run `scripts/refresh-trust-snapshot --check` to compare the packaged snapshot with every live source without writing. The check reports added and removed certificate subjects per changed source and exits non-zero on drift. Run `scripts/refresh-trust-snapshot` to download all sources, pin C2PA lists to the latest commit that changed each list, rewrite the PEM files and digests, and advance the snapshot date. Verification itself never fetches trust material.

## Integrity does not prove completeness

A valid C2PA hard binding proves that the bytes covered by the signed assertion match. It does not prove that a composition declared every source used to create it. An omitted ingredient can coexist with a valid signature.

For a 20-source video, each source should appear as its own ingredient assertion. The verifier validates the ingredient links that exist. A policy layer must decide whether the declared set is complete for the workflow.

## Managed decisions

The hosted Encypher product adds policy, current trust distribution, durable evidence, and managed receipts. Those fields remain `null` in this public SDK. Their absence does not weaken the local cryptographic checks; it means no managed decision was requested.
