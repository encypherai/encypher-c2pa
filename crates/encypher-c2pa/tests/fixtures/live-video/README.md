# Live-video stream fixtures

Signed, offline fMP4 and CMAF streams used by `tests/live_video_stream.rs`.
Nothing here is fetched at test time and no test reaches the network.

Each directory holds one stream: `init.mp4` (the initialization segment) plus
`seg-0.m4s`, `seg-1.m4s`, and `seg-2.m4s` in playback order. `segments.json`
records the declared encapsulation, method, spec version, and each file's size
and SHA-256, so a corrupted checkout is caught before it is read as a
verification failure.

| Directory | Encapsulation | Method | Spec | Binding the init manifest carries |
| --- | --- | --- | --- | --- |
| `fmp4-verifiable-segment-info` | fMP4 | verifiable-segment-info | 2.4 | `c2pa.session-keys`; each segment carries a signed `emsg` |
| `cmaf-verifiable-segment-info` | CMAF | verifiable-segment-info | 2.4 | `c2pa.session-keys`; each segment carries a signed `emsg` |
| `fmp4-per-segment` | fMP4 | per-segment | 2.4 | none: every segment is independently signed and chained |
| `cmaf-per-segment` | CMAF | per-segment | 2.4 | none: every segment is independently signed and chained |
| `fmp4-merkle-2.2` | fMP4 | verifiable-segment-info | 2.2 | `c2pa.hash.bmff.v3` Merkle tree; each segment carries a `merkle` box |

## Provenance

All five streams are Encypher-owned and signed by Encypher's private C2PA
signing engine (`encypherai-commercial`), which is the generator this SDK
verifies against in production.

- The four spec-2.4 streams are copied verbatim from that repository's C2PA
  Conformance Program 0.2 corpus, under
  `tests/conformance/fixtures-0.2/applications/encypher-enterprise-api/live-video/`.
- `fmp4-merkle-2.2` was produced from the `fmp4-verifiable-segment-info` media
  with that engine's CLI:

  ```
  encypher-c2pa sign init.mp4 --mime video/mp4 --spec 2.2 \
    --key <claim-signing key> --cert <claim-signing cert> \
    --encapsulation fmp4 --segment-mode verifiable-segment-info \
    --fragment seg-0.m4s --fragment seg-1.m4s --fragment seg-2.m4s \
    --fragment-out-dir out --out out/init.mp4 --segments-out out/segments.json
  ```

  Its `path` entries were rewritten to be relative to this directory.

## Trust

The signing certificates are Encypher test certificates and chain to no
bundled anchor, so every stream here reports `signingCredential.untrusted` and
a trust status of `not_valid_for_supplied_material`. That is expected: these
fixtures exercise integrity and the live-video status codes, not trust. Under
the default (generous) posture an untrusted signer does not invalidate a
manifest, so a clean stream still reports `integrity: valid`.

## Do not regenerate casually

`tests/live_video_stream.rs` flips the last byte of `seg-1.m4s` to assert that
tampering is caught. Replacing these bytes replaces the evidence for PRD items
1.1 and 5.9; regenerate only alongside the test that reads them.
