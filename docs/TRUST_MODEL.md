# Trust model

The verifier answers two different questions.

1. Did the signed claim and hard binding survive unchanged?
2. Does the configured trust policy accept the signing identity at the validation time?

The first question is local cryptography. The second is organizational policy. The SDK does not merge them.

## Default behavior

Every package compiles the same pinned trust snapshot into the verifier. The `2026-08-11` snapshot contains:

- C2PA Trust List claim-signing anchors;
- C2PA TSA Trust List timestamp-authority anchors;
- IPTC Verified News Publishers end-entity certificates for claim and CAWG identity checks;
- the Mozilla Email-trusted root store and IPTC anchor list for the CAWG 1.2 interim X.509 trust model;
- the Encypher C2PA root, TSA issuing CA, and Verified Organizations identity anchor.

The CAWG interim configuration remains subject to the specification's EKU, certificate-policy, trusted-timestamp, and 31 March 2027 cutoff checks. The IPTC CAWG anchor list was empty at snapshot time; its end-entity list was not.

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

Caller material extends the packaged snapshot. `no_default_trust: true` disables every packaged list and evaluates only caller-supplied material. With no caller material in that mode, the report uses `trust.status = "not_evaluated"` and `trust.basis = "none"`.

CAWG document-signing credentials require a configured CAWG anchor or allowed-list match; certificate profile alone never establishes trust. `cawg_did_documents` supplies a pinned DID-to-document map for offline `did:web` identity resolution. `cawg_strict_encoding` rejects legacy CAWG encodings.

Malformed PEM is a hard input error. The verifier never converts malformed trust material into a silent `not_evaluated` result.

A supplied `validation_time` must be RFC 3339. If omitted, native bindings capture current UTC time. The browser binding captures `Date` in JavaScript and passes it explicitly to the Rust core.

## No ambient network or mutable trust

The public SDK does not:

- fetch or refresh C2PA, IPTC, or Encypher trust lists;
- follow AIA, OCSP, CRL, JUMBF, ingredient, or assertion URLs;
- query an Encypher API unless the CLI caller explicitly passes `--encypher-api`;
- use an operating-system certificate store;
- accept a signer because a certificate is syntactically valid;
- cache a trust decision between calls.

The verification result depends only on the asset bytes, the packaged snapshot, and explicit call options.

## Revocation and freshness

Revocation is evaluated only when usable evidence is embedded in the credential. Without such evidence, the report says `not_checked`. This is different from `not_revoked`.

The offline verifier knows the packaged snapshot date but cannot prove that static material is still current. `freshness.status` therefore remains `unknown` in schema 1.0. Refreshing the defaults requires a new SDK release.

## Integrity does not prove completeness

A valid C2PA hard binding proves that the bytes covered by the signed assertion match. It does not prove that a composition declared every source used to create it. An omitted ingredient can coexist with a valid signature.

For a 20-source video, each source should appear as its own ingredient assertion. The verifier validates the ingredient links that exist. A policy layer must decide whether the declared set is complete for the workflow.

## Managed decisions

The hosted Encypher product adds policy, current trust distribution, durable evidence, and managed receipts. Those fields remain `null` in this public SDK. Their absence does not weaken the local cryptographic checks; it means no managed decision was requested.
