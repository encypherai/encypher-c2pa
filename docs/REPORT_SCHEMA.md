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
| `policy` | object or null | Always null in the public SDK. Managed policy is a hosted product concern. |
| `managed_receipt` | object or null | Always null in the public SDK. |
| `validation_state` | string | Engine state: `Valid`, `Invalid`, `Trusted`, or `None`. |
| `validation_results` | object | Stable validation status entries split into success, informational, and failure buckets. |
| `manifest_report` | object | Detailed active-manifest and manifest-store reader report. For a PDF with incremental updates it also carries `pdf_incremental_history`, one entry per update section that introduced a manifest store, each validated against the file as it stood at that section. The newest readable store still decides the top-level verdict. |
| `content_credentials` | object or null | C2PA 2.4 Content Credentials JSON (crJSON) view of the manifest store. Emitted only under `strict_conformance`; null otherwise. |
| `network` | object | What the verification did, or could have done, on the network. Added in 1.0 as an additive field; a report written before it is read with `enabled: false` and empty lists. |

`content_credentials` follows the C2PA 2.4 crJSON specification: `manifests` runs in reverse store order so the active manifest is `manifests[0]`, each manifest carries `label`, `assertions`, one of `claim` (v1) or `claim.v2` (v2), `signature`, and `validationResults` (with `validationTime` and `specVersion`), and CBOR byte strings appear as `b64'<base64>'`. It is a derived view for conformance evaluation, not a source of cryptographic truth; verdicts live in `validation_results`.

`manifest_report` spends from one bounded decoded-value budget per verification. If hostile claim or assertion data exhausts it, the affected nested value is replaced by `{"_encypher_omitted": "..."}`; validation results and the surrounding report shape remain intact.

## Network object

Online checks are off by default, and `network` is present either way. When they are off, `needed` still lists what a fetch would settle, so a caller can see what allowing one would do without making one.

| Field | Type | Meaning |
|---|---|---|
| `enabled` | boolean | Whether this verification was allowed to fetch. |
| `needed` | array of objects | Every network resource the file references. |
| `requests` | array of objects | Every request that was attempted. Empty when `enabled` is false. |

Each `needed` entry carries a `kind` and the fields that kind implies:

| `kind` | Fields |
|---|---|
| `remote_manifest` | `uri` |
| `ocsp` | `purpose` (`claim_signer` or `cawg_identity`), `responder_url`, `certificate_sha256`, and `assertion_label` when the purpose is `cawg_identity` |
| `did_document` | `did`, `url` |
| `external_data` | `uri`, `assertion_label` |

Each `requests` entry carries `purpose` (`remote_manifest`, `ocsp.claim_signer`, `ocsp.cawg_identity`, `did_document`, or `external_data`), `url`, `outcome`, and a one-line `detail`. `outcome` is:

| Value | Meaning |
|---|---|
| `fetched` | The body arrived and was used as evidence. |
| `failed` | The server or the network did not deliver: a DNS failure, a refused connection, an HTTP error, a cross-origin refusal in a browser, a body that was not what it claimed to be. |
| `blocked` | This SDK refused: a forbidden address, a plaintext URL, an oversized body, too many redirects. |
| `skipped` | The request was never made: the per-verification request budget was spent, or the surface cannot make that kind of request. |

```json
"network": {
  "enabled": true,
  "needed": [{"kind": "remote_manifest", "uri": "https://manifests.example.com/photo.c2pa"}],
  "requests": [{
    "purpose": "remote_manifest",
    "url": "https://manifests.example.com/photo.c2pa",
    "outcome": "fetched",
    "detail": "20416 bytes"
  }]
}
```

Fetched material is evidence, never a verdict. It is supplied to a second, entirely offline verification pass, which reaches the verdict the same way it would for material a caller had passed in.

## Trust object

| Field | Values | Meaning |
|---|---|---|
| `status` | `valid_for_supplied_material`, `not_valid_for_supplied_material`, `not_evaluated` | Whether the signer validates under the static material evaluated for this run. |
| `basis` | `bundled_static_material`, `bundled_and_caller_supplied_static_material`, `caller_supplied_static_material`, `none` | Source of the trust decision. |
| `validation_time` | RFC 3339 string | Certificate validity instant used for this run. |
| `revocation.status` | `revoked`, `not_revoked`, `not_checked` | Result from usable evidence embedded in the asset. |
| `revocation.source` | `embedded_ocsp`, `online_ocsp`, `none` | Evidence source. `online_ocsp` appears only when online checks were allowed and a responder answered. |
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

CAWG identity statuses (`cawg.identity.*`, `cawg.x509.*`, `cawg.ica.*`) are assertion-scoped: they report the identity assertion's own verdict and never change `integrity` or `validation_state`. A tampered identity assertion still fails the manifest through the C2PA-level `assertion.hashedURI.mismatch`. Their `url` is the identity assertion's label, such as `cawg.identity` or `cawg.identity__1`, because CAWG Identity 1.3 requires it; C2PA statuses keep the JUMBF URI shown above.

Extension codes use the `com.encypher.` prefix, as C2PA 2.4 requires of codes outside the registry. They mark outcomes the registry does not name, so a consumer can tell them apart from registered results:

| Code | Bucket | Meaning |
|---|---|---|
| `com.encypher.claim.specVersionNotSemver` | informational | `claim_generator_info.specVersion` is not a SemVer string. Strict mode reports `claim.malformed` instead. |
| `com.encypher.timestamp.v1SignatureUnbound` | informational | A trusted `sigTst` (v1) token established signing time; its imprint covers the claim but not the signature value. |
| `com.encypher.bmffHash.fragmentsNotEvaluated` | informational | The BMFF hash binds a fragment Merkle tree, but no fragments were supplied, so none were checked. |
| `com.encypher.assertion.boxesHash.unevaluated` | failure | A general box hash is the binding, but the container has no C2PA box convention the verifier can evaluate. It fails closed and is never reported as a match. |
| `com.encypher.cawg.legacyProfile` | informational | The identity signature verifies over the CAWG 1.1 field order, not CAWG Identity 1.3 deterministic CBOR. Strict mode reports `cawg.x509.signature.mismatch` instead. |
| `com.encypher.claim.generatorInfoMissing` | informational | A v1 claim carries `claim_generator` but no `claim_generator_info`. Strict mode reports `claim.malformed`. |
| `com.encypher.ingredient.legacyClaimHash` | informational | A legacy `c2pa_manifest` ingredient link matched the C2PA 1.0 hash over the ingredient's claim bytes. Default posture only. |
| `com.encypher.ingredient.graphLimitExceeded` | informational | Recursive ingredient validation reached its depth or manifest ceiling. Never affects validity. |
| `com.encypher.assertion.boxesHash.overlappingRestartSegments` | informational | A JPEG box hash matched the overlapping restart layout c2pa-rs writes rather than the C2PA 2.4 layout. Default posture only. |
| `com.encypher.cawg.metadata.invalid`, `com.encypher.cawg.trainingMining.invalid` | failure (assertion-scoped) | The CAWG metadata or training-and-mining assertion is malformed. Never changes C2PA integrity. |
| `com.encypher.cawg.trainingMining.effectiveUse` | informational | `details.entries` maps each standard use to `declaredUse`, `effectiveUse`, and any `constraintInfo`. |
| `com.encypher.ocsp.conflictingRevokedResponse` | informational | Strict mode only: a qualifying `good` OCSP response outranked a stapled `revoked` one. |
| `com.encypher.conformance.trustedTimeStampMissing` | failure | Strict mode only: the Conformance Program requires a trusted timestamp. |
| `com.encypher.conformance.revocationInformationMissing` | failure | Strict mode only: the Conformance Program requires usable revocation information. The default posture reports `signingCredential.ocsp.skipped`. |
| `com.encypher.conformance.outOfScope` | informational | Strict mode only: the asset's MIME type is outside the Conformance Program scope for the target spec version. |
| `com.encypher.conformance.specVersionNonConformant` | failure | Strict mode only: the manifest does not conform to the target spec version, for example a v1 claim under a 2.4 target. |

CAWG X.509 identity signatures report the registered `cawg.x509.*` codes from the CAWG Identity 1.3 status-code table: `algorithm.unsupported`, `credential.trusted` / `credential.untrusted`, `signature.validated` / `signature.mismatch`, `signature.inside_validity` / `signature.outside_validity`, `time_stamp.trusted` / `.validated` / `.malformed` / `.mismatch` / `.untrusted` / `.outside_validity` / `.credential_invalid`, `time_of_signing.inside_validity` / `.outside_validity`, and `ocsp.not_revoked` / `ocsp.skipped`. A revoked identity leaf is `cawg.identity.credential_revoked`, and an identity credential that can only be validated over the network is `cawg.identity.network_traffic_blocked`.

Live-stream reports use the registered `livevideo.*` codes. Supplying fragments that no binding in the active manifest covers is `livevideo.segment.invalid`, with `integrity: invalid` and `hard_binding: mismatch`.

`validation_results` may also carry `ingredientDeltas`, a list of `{ingredientAssertionURI, validationDeltas{success, informational, failure}}` produced by recursive ingredient validation (at most 16 edges and 64 manifests). Ingredient bytes are not present, so an ingredient's hard binding is not evaluated; its claim, claim signature, bindings, and links are. Entries the signer recorded but this run did not re-derive carry `details.source = "recorded"`. Ingredient results never change the active verdict.

A report for an asset whose manifest is only referenced by URL carries `manifest.inaccessible` with `details.remote_manifest_uri` and `details.declared_in`.

## Consumer guidance

- Gate tamper detection on `integrity` and inspect `validation_results.failure`.
- Gate organizational trust on `trust.status` under trust material you control.
- Preserve unknown fields when storing or forwarding reports.
- Record `schema_version`, `profile`, and `validation_time` with any downstream decision.
- Do not treat `policy: null` or `managed_receipt: null` as failure. Those axes are outside the public SDK.
