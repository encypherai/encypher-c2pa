# Format coverage

Run `encypher-c2pa formats` to read the canonical MIME types covered by the installed `c2pa-2.4` engine profile.

## Images

`image/avif`, `image/gif`, `image/heic`, `image/heic-sequence`, `image/heif`, `image/heif-sequence`, `image/jpeg`, `image/jxl`, `image/png`, `image/svg+xml`, `image/tiff`, `image/webp`, `image/x-adobe-dng`

## Video and audio

`application/mp4`, `video/mp4`, `video/quicktime`, `video/x-m4v`, `video/x-msvideo`, `audio/flac`, `audio/mp4`, `audio/mpeg`, `audio/ogg`, `audio/wav`

## Documents and archives

`application/epub+zip`, `application/oxps`, `application/pdf`, `application/vnd.ms-excel.sheet.binary.macroenabled.12`, `application/vnd.ms-excel.sheet.macroenabled.12`, `application/vnd.ms-excel.template.macroenabled.12`, `application/vnd.ms-powerpoint.presentation.macroenabled.12`, `application/vnd.ms-powerpoint.slideshow.macroenabled.12`, `application/vnd.ms-powerpoint.template.macroenabled.12`, `application/vnd.ms-visio.drawing`, `application/vnd.ms-visio.drawing.macroenabled.12`, `application/vnd.ms-visio.stencil`, `application/vnd.ms-visio.stencil.macroenabled.12`, `application/vnd.ms-visio.template`, `application/vnd.ms-visio.template.macroenabled.12`, `application/vnd.ms-word.document.macroenabled.12`, `application/vnd.ms-word.template.macroenabled.12`, `application/vnd.ms-xpsdocument`, `application/vnd.oasis.opendocument.graphics`, `application/vnd.oasis.opendocument.presentation`, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.text`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`, `application/vnd.openxmlformats-officedocument.presentationml.slideshow`, `application/vnd.openxmlformats-officedocument.presentationml.template`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/vnd.openxmlformats-officedocument.spreadsheetml.template`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.openxmlformats-officedocument.wordprocessingml.template`

## Fonts and structured text

`application/font-sfnt`, `application/javascript`, `application/json`, `application/toml`, `application/xhtml+xml`, `application/xml`, `application/yaml`, `application/x-font-ttf`, `font/otf`, `font/sfnt`, `font/ttf`, `text/css`, `text/csv`, `text/html`, `text/markdown`, `text/plain`, `text/tab-separated-values`, `text/x-python`, `text/xml`

## What coverage means

A listed MIME type has a container reader and a C2PA hard-binding path in this build. The exact binding depends on the format:

- JPEG APP11 and PNG/WebP/TIFF-family manifest carriers, TIFF covering both classic TIFF and BigTIFF;
- ISO BMFF box hashing for MP4, MOV, HEIF, HEIC, AVIF, M4A, and related formats, plus C2PA A.5.4 Merkle verification for fragmented fMP4 and CMAF streams;
- RIFF and chunk hashing for WAV and AVI;
- native carriers for FLAC, MP3, GIF, SVG, JPEG XL, PDF, fonts, and EPUB;
- ZIP package processing for office documents;
- standardized structured-text carriers.

Coverage does not promise recovery from arbitrary container corruption. Unsupported variants return a typed error or a failed validation status. The engine never accepts a format by extension alone: callers provide a MIME type, and file helpers use an extension only to select that MIME type.

`image/tiff` and `image/x-adobe-dng` cover classic TIFF (magic 42) and BigTIFF (magic 43, 8-byte offsets, 20-byte IFD entries, 8-byte entry counts) in both byte orders. The manifest store is read from IFD tag 52545 with tag type UNDEFINED, in either placement the specification allows: the dedicated last IFD of C2PA 2.2 A.3.5, and the single-page in-IFD form C2PA 2.4 A.3.6 adds. A differently typed tag 52545 entry, a cyclic or overlapping IFD chain, an IFD pointed inside the fixed header, and a directory larger than the verifier's budget are all refused rather than read.

Fragmented verification takes the signed initialization segment and the media segments available, in playback order. Missing trailing segments are not a failure; an unsignalled gap or reordering inside the supplied run is `assertion.bmffHash.mismatch`, unless the caller marks the jump with `expected_seek_positions`. Both fMP4 and CMAF use `video/mp4`; they are verification modes, not additional MIME types. Supplied segments that no binding covers fail verification.

Live streams signed under C2PA 2.4 are verified with the stream entry points (`verify_stream`, `--encapsulation`). Both methods are covered: `verifiable-segment-info`, where session keys in the initialization manifest authenticate each segment's signed segment information, and `per-segment`, where each segment carries a manifest chained to the one before it. The declared encapsulation is checked against the brands in the segment bytes.

Any carrier may hold a Brotli-compressed manifest store (`brob`), which is expanded under a size bound before validation, and an update manifest (`c2um`), which inherits its hard binding from the first standard manifest in its authenticated parent chain.

PDF discovery resolves the document catalog through classic trailers and through PDF 1.5 cross-reference streams, with bounded parsing that fails closed on a malformed stream. PDF incremental history is followed through the classic cross-reference `/Prev` chain. Each manifest store is validated against the file as it stood at the update section that introduced it. A cross-reference stream, or a chain that cannot be inventoried, is recorded in the report as history the verifier could not inspect; it does not overturn the verdict on the newest readable store.

Format-specific rules the verifier applies:

- JPEG box hashes assign each restart marker the entropy data after it, per C2PA 2.4; the default posture also accepts the overlapping layout c2pa-rs writes.
- A manifest referenced from XMP `dcterms:provenance` is reported, and fetched only when online checks are allowed; XMP is read from each format's standard location.
- General box hash covers JPEG, PNG, JPEG XL, fonts, GIF, RIFF (WAV, WebP, AVI), and Ogg, following the per-format rules in C2PA 2.4. A box hash on any other container cannot be evaluated and fails closed with `com.encypher.assertion.boxesHash.unevaluated`.
- A data-hash exclusion that covers the manifest carrier may contain only the store and zeroed padding. For JPEG the excluded length must equal the total length of the C2PA APP11 segments.
- BMFF files are read by `box_purpose`: an `update` store appended as the last box is the active manifest store, with the `original` store behind it.
- Font manifests are read through the C2PA font table record. A table that carries only a remote manifest URI reports `manifest.inaccessible` with the URI unless online checks are allowed, in which case the store is fetched and verified.
- Unstructured text is hashed as C2PA 2.4 specifies: the wrapper bytes are removed, the remainder is NFC-normalized, and the UTF-8 bytes are hashed.
- A collection hash requires every listed member; unlisted files are allowed. For ZIP packages the central-directory hash still detects files added after signing.
- Under `strict_conformance`, carrier placement is also checked: the GIF block before the first image descriptor, the TIFF entry in the last main IFD, the SVG element under the root `metadata` element, and the BMFF store box after `ftyp` and before `moov` and `mdat`.

### C2PA 2.5 policy (`spec_version: "2.5"`)

The proposed 2.5 policy reads the carriers 2.5 adds: Standard MIDI Files (`audio/midi`, sole/last/first track by SMF format, `FF 7F 00 43 32` event), standalone TTML (`application/ttml+xml`, namespace-matched `/tt:tt/tt:head/tt:metadata/c2pa:manifest`), ONNX (`application/onnx`, `metadata_props` `c2pa:manifest` value), SafeTensors (`application/safetensors`, `__metadata__.c2pa:manifest` value), Parquet (`application/vnd.apache.parquet`, footer `key_value_metadata`; encrypted-footer files carry none), BlockFact (`image/vnd.blockfact.facti`, `audio/vnd.blockfact.facta`, `video/vnd.blockfact.factv`, `C2PA` extension block), WARC (`application/warc`, collection binding by `WARC-Record-ID`), append-only text and JSON Lines checkpoints (`c2pa.hash.segment`, including the predecessor chain), WebVTT (`text/vtt`) and every other `text/*` structured-text type. A duplicate carrier in any of these locates no manifest. MIDI, ONNX, SafeTensors and JSONL have no registered media type; the spellings above are this SDK's non-normative choice. Generic XML-comment embedding is unsupported under 2.5 for every XML-derived type without a dedicated carrier (XML, XHTML, RSS, Atom): its armor contains `--`, which XML forbids inside comments ([upstream issue 2590](https://github.com/c2pa-org/specs-core/issues/2590)). Separately supplied manifest stores remain readable for those types, and for any well-formed media type as opaque bytes. E-RTMP live carriage is not read: it needs a transport input and an audio metadata packet type the referenced E-RTMP specification does not yet define.

- Unstructured text: any trailing padding byte is admitted and the whole variation-selector run is the wrapper's byte range. A candidate that does not decode is ignored, and zero or several valid wrappers locate no manifest instead of reporting `manifest.text.*`.
- Detached text: hash the supplied asset's exact bytes. Embedded-wrapper exclusions and NFC normalization do not apply to a separately supplied manifest store.
- Structured text: one `BEGIN`/`END` pair, reference trimmed of space, tab, CR and LF only, and only a valid `data:application/c2pa;base64,` reference embeds a store. Anything else locates no manifest instead of reporting `manifest.structuredText.*`.
- HTML: only elements inside `head` count; more than one there locates no manifest.
- Placement checked in the regular 2.5 posture: the PNG `caBX` chunk before the first `IDAT`, the BMFF manifest box after `ftyp` and before the first `mdat`/`moov` or adjacent to `moov` (an `update` box last), and the TIFF entry in the first or last IFD. A violation reports `general.error`.
- BMFF: excluding `ftyp` becomes an optional exclusion (`assertion.bmffHash.additionalExclusionsPresent`), and a fragmented hash carrying both `hash` and `merkle` is `assertion.bmffHash.malformed`.
- An unreadable manifest store reports `manifest.inaccessible.malformed`.

## Test fixtures

`tests/fixtures/signed_test.jpg` and `signed_test.mp4` exercise the public report contract, together with `signed_bigtiff_le_single_page.tif` (C2PA 2.4 A.3.6, the entry inside the single main IFD) and `signed_bigtiff_be_multi_page.tif` (2.2 A.3.5, a big-endian multi-page asset with a dedicated last IFD). The deeper engine suite covers format extraction, claim parsing, signature algorithms, data hash, BMFF hash, boxes hash, collection hash, multipart bindings, ingredients, trust, OCSP, and malformed input boundaries.
