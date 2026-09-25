# c2pa-rs compressed-manifest vectors

Signed by `c2patool 0.27.21` (c2pa-rs 0.90.21) with `core.prefer_compress_manifests = true`, using the c2pa-rs ES256 test certificate (`sdk/tests/fixtures/certs/es256.*`, MIT OR Apache-2.0). c2pa-rs pairs compression with a general box hash, so each store holds one `c2cm` manifest whose `brob` box is the raw Brotli stream of the manifest superbox, bound by `c2pa.hash.boxes`.

| File | Source image | SHA-256 |
|---|---|---|
| `compressed_boxhash.jpg` | 64x48 Pillow JPEG, no restart markers | `0c1e3191b7da2114d844fd30a1dc93733221ea954f20d76601dc2ac523eb3d11` |
| `compressed_boxhash.png` | 64x48 Pillow PNG | `50c9cd51c896d530979ec2071b59f1dba54bafec2c47f666c36b89edc1f01d9b` |

Manifest definition: one `c2pa.actions.v2` assertion with `c2pa.created` and `digitalSourceType` `digitalCapture`.
