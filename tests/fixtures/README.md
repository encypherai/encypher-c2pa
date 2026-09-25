# Test fixtures

- `signed_test.jpg`: Encypher-generated JPEG with an embedded C2PA 2.2 claim.
- `signed_test.mp4`: Encypher-generated MP4 with an embedded C2PA 2.2 claim.
- `signed_test.c2pa`: the C2PA Manifest Store of `signed_test.jpg`, extracted verbatim and kept beside it as an external (sidecar) manifest. It binds to `signed_test.jpg` and to nothing else.

These fixtures are synthetic, contain no customer data, and are distributed under this repository's Apache-2.0 license. Their signing certificates are test credentials and are not trusted production identities.

The default public contract tests expect valid cryptographic integrity and rejection under the packaged production trust snapshot because these test certificates are deliberately absent. Opt-out tests set `no_default_trust` and expect `trust.status = "not_evaluated"`.
