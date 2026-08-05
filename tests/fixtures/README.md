# Test fixtures

- `signed_test.jpg`: Encypher-generated JPEG with an embedded C2PA 2.2 claim.
- `signed_test.mp4`: Encypher-generated MP4 with an embedded C2PA 2.2 claim.

Both fixtures are synthetic, contain no customer data, and are distributed under this repository's Apache-2.0 OR MIT license. Their signing certificates are test credentials and are not trusted production identities.

The public contract tests expect valid cryptographic integrity and `trust.status = "not_evaluated"` unless a test supplies its own trust material.
