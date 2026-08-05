# Trust model

The verifier answers two different questions.

1. Did the signed claim and hard binding survive unchanged?
2. Does the caller accept the signing identity under a named trust set at a named time?

The first question is local cryptography. The second is organizational policy. The SDK does not merge them.

## Default behavior

With no trust options, the verifier checks signatures and asset bindings but returns:

```json
{
  "integrity": "valid",
  "trust": {
    "status": "not_evaluated",
    "basis": "none"
  }
}
```

This is a useful result. It says the credential is internally intact. It does not say the signer is known, approved, current, or authorized.

## Caller-supplied material

`VerifyOptions` accepts three independent PEM bundles:

- `trust_pem`: claim-signing trust anchors.
- `tsa_trust_pem`: timestamp-authority trust anchors.
- `allowed_list_pem`: end-entity certificates accepted directly by the caller.

Malformed PEM is a hard input error. The verifier never converts malformed trust material into a silent `not_evaluated` result.

A supplied `validation_time` must be RFC 3339. If omitted, native bindings capture current UTC time. The browser binding captures `Date` in JavaScript and passes it explicitly to the Rust core.

## No ambient network or trust

The public SDK does not:

- fetch C2PA trust lists;
- follow AIA, OCSP, CRL, JUMBF, ingredient, or assertion URLs;
- query an Encypher API;
- use an operating-system certificate store;
- accept a signer because a certificate is syntactically valid;
- cache a trust decision between calls.

Only bytes in the asset and trust material in the call can affect the result.

## Revocation and freshness

Revocation is evaluated only when usable evidence is embedded in the credential. Without such evidence, the report says `not_checked`. This is different from `not_revoked`.

The offline verifier cannot prove that old static material is current. `freshness.status` therefore remains `unknown` in schema 1.0. A caller that distributes signed trust snapshots can record and enforce its own snapshot date outside the SDK.

## Integrity does not prove completeness

A valid C2PA hard binding proves that the bytes covered by the signed assertion match. It does not prove that a composition declared every source used to create it. An omitted ingredient can coexist with a valid signature.

For a 20-source video, each source should appear as its own ingredient assertion. The verifier validates the ingredient links that exist. A policy layer must decide whether the declared set is complete for the workflow.

## Managed decisions

The hosted Encypher product adds policy, current trust distribution, durable evidence, and managed receipts. Those fields remain `null` in this public SDK. Their absence does not weaken the local cryptographic checks; it means no managed decision was requested.
