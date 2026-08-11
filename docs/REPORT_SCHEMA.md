# Verification report schema

`schema_version: "1.0"` is the cross-language public contract. Rust structs, Python dictionaries, Go structs, CLI JSON, and browser objects use the same snake-case field names.

Additive fields may appear within schema 1.x. A field removal, rename, type change, or semantic change requires a new major schema version.

## Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Public report contract version. |
| `profile` | string | Engine profile used for verification. Current value: `c2pa-2.4`. |
| `mime_type` | string | Normalized MIME type used to choose the container reader. |
| `present` | boolean | A readable active C2PA manifest is present. |
| `integrity` | string | `valid`, `invalid`, or `absent`. This is not a trust decision. |
| `signature` | string | `valid`, `invalid`, `missing`, or `unknown`. |
| `hard_binding` | string | `match`, `mismatch`, `missing`, or `unknown`. |
| `trust` | object | Trust evaluation against packaged defaults and optional caller material. |
| `policy` | object or null | Always null in the public offline verifier. Managed policy is a hosted product concern. |
| `managed_receipt` | object or null | Always null in the public offline verifier. |
| `validation_state` | string | Engine state: `Valid`, `Invalid`, `Trusted`, or `None`. |
| `validation_results` | object | Stable validation status entries split into success, informational, and failure buckets. |
| `manifest_report` | object | Detailed active-manifest and manifest-store reader report. |
| `content_credentials` | object or null | Content Credentials-shaped projection when one is available. |

`manifest_report` spends from one bounded decoded-value budget per verification. If hostile claim or assertion data exhausts it, the affected nested value is replaced by `{"_encypher_omitted": "..."}`; validation results and the surrounding report shape remain intact.

## Trust object

| Field | Values | Meaning |
|---|---|---|
| `status` | `valid_for_supplied_material`, `not_valid_for_supplied_material`, `not_evaluated` | Whether the signer validates under the static material evaluated for this run. |
| `basis` | `bundled_static_material`, `bundled_and_caller_supplied_static_material`, `caller_supplied_static_material`, `none` | Source of the trust decision. |
| `validation_time` | RFC 3339 string | Certificate validity instant used for this run. |
| `revocation.status` | `revoked`, `not_revoked`, `not_checked` | Result from usable evidence embedded in the asset. |
| `revocation.source` | `embedded_ocsp`, `none` | Evidence source. No network lookup occurs. |
| `revocation.responder_signature` | `valid`, `not_applicable` | Whether the embedded response passed the verifier's response checks. |
| `freshness.status` | `unknown` | Public v1 does not fetch a current freshness source. |
| `freshness.as_of` | RFC 3339 string or null | Evidence time when one can be stated. Public v1 returns null. |

## Validation results

Each status has:

```json
{
  "code": "assertion.dataHash.match",
  "url": "self#jumbf=/c2pa/.../c2pa.assertions/c2pa.hash.data",
  "explanation": "asset hash valid"
}
```

A status may additionally carry a `details` object with machine-readable evidence for extension codes; CAWG statuses use it for fields such as `trust_source`, `accepted_eku`, `payload_encoding`, `timestamp_trusted`, and `revocation_status`. Absent means no evidence, not failure.

Callers should branch on `code`, not `explanation`. Explanations are for people and may improve without a schema bump.

A success status proves only its named check. `claimSignature.validated` does not imply signer trust. `assertion.dataHash.match` does not imply that all expected ingredients were declared.

CAWG identity statuses (`cawg.identity.*`, `cawg.ica.*`) are assertion-scoped: they report the identity assertion's own verdict and never change `integrity` or `validation_state`. A tampered identity assertion still fails the manifest through the C2PA-level `assertion.hashedURI.mismatch`.

## Consumer guidance

- Gate tamper detection on `integrity` and inspect `validation_results.failure`.
- Gate organizational trust on `trust.status` under trust material you control.
- Preserve unknown fields when storing or forwarding reports.
- Record `schema_version`, `profile`, and `validation_time` with any downstream decision.
- Do not treat `policy: null` or `managed_receipt: null` as failure. Those axes are outside the offline verifier.
