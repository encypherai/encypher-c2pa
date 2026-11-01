# crJSON schema fixture

`crJSON.schema.json` is copied verbatim from the C2PA specification repository:

- Repository: https://github.com/c2pa-org/specifications (`specs-core`)
- Tag: `2.4`, commit `712d8baf6c7c482d754dce5919f7f4f4b443d7e6`
- Path: `docs/modules/crJSON/partials/crJSON.schema.json`

Retrieved with:

```
git -C specs-core show 2.4:docs/modules/crJSON/partials/crJSON.schema.json
```

It is vendored so `crjson_schema.rs` can check the verifier's
`content_credentials` output offline, with no network access at test time.
Refresh it from the tag above when the specification revision changes.

`crJSON-2.5.schema.json` is copied verbatim from the same repository:

- Tag: `2.5`, commit `d538a73795b64f2c9d0c1a332b7ae38728070413`
- Path: `docs/modules/crJSON/partials/crJSON.schema.json`
- SHA-256: `7066f486ee41ef1feb5d30c581bf5bde56b6053f48793c09efa6b3ef2825a2be`

Retrieved with:

```
git -C specs-core show 2.5:docs/modules/crJSON/partials/crJSON.schema.json
```

The two schemas remain separate: retained 2.4 output is checked against 2.4,
and explicitly selected 2.5 output against 2.5.
