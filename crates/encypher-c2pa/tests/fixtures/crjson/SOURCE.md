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
