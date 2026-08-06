# Format coverage

The `c2pa-2.4` profile exposes 69 canonical MIME types. Run `encypher-c2pa formats` to read the list from the installed build.

## Images

`image/avif`, `image/gif`, `image/heic`, `image/heic-sequence`, `image/heif`, `image/heif-sequence`, `image/jpeg`, `image/jxl`, `image/png`, `image/svg+xml`, `image/tiff`, `image/webp`, `image/x-adobe-dng`

## Video and audio

`application/mp4`, `video/mp4`, `video/quicktime`, `video/x-m4v`, `video/x-msvideo`, `audio/flac`, `audio/mp4`, `audio/mpeg`, `audio/ogg`, `audio/wav`

## Documents and archives

`application/epub+zip`, `application/oxps`, `application/pdf`, `application/vnd.ms-excel.sheet.binary.macroenabled.12`, `application/vnd.ms-excel.sheet.macroenabled.12`, `application/vnd.ms-excel.template.macroenabled.12`, `application/vnd.ms-powerpoint.presentation.macroenabled.12`, `application/vnd.ms-powerpoint.slideshow.macroenabled.12`, `application/vnd.ms-powerpoint.template.macroenabled.12`, `application/vnd.ms-visio.drawing`, `application/vnd.ms-visio.drawing.macroenabled.12`, `application/vnd.ms-visio.stencil`, `application/vnd.ms-visio.stencil.macroenabled.12`, `application/vnd.ms-visio.template`, `application/vnd.ms-visio.template.macroenabled.12`, `application/vnd.ms-word.document.macroenabled.12`, `application/vnd.ms-word.template.macroenabled.12`, `application/vnd.ms-xpsdocument`, `application/vnd.oasis.opendocument.presentation`, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.text`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`, `application/vnd.openxmlformats-officedocument.presentationml.slideshow`, `application/vnd.openxmlformats-officedocument.presentationml.template`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/vnd.openxmlformats-officedocument.spreadsheetml.template`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.openxmlformats-officedocument.wordprocessingml.template`

## Fonts and structured text

`application/font-sfnt`, `application/javascript`, `application/json`, `application/toml`, `application/xhtml+xml`, `application/xml`, `application/yaml`, `application/x-font-ttf`, `font/otf`, `font/sfnt`, `font/ttf`, `text/css`, `text/csv`, `text/html`, `text/markdown`, `text/plain`, `text/x-python`, `text/xml`

## What coverage means

A listed MIME type has a container reader and a C2PA hard-binding path in this build. The exact binding depends on the format:

- JPEG APP11 and PNG/WebP/TIFF-family manifest carriers;
- ISO BMFF box hashing for MP4, MOV, HEIF, HEIC, AVIF, M4A, and related formats;
- RIFF and chunk hashing for WAV and AVI;
- native carriers for FLAC, MP3, GIF, SVG, JPEG XL, PDF, fonts, and EPUB;
- ZIP package processing for office documents;
- standardized structured-text carriers.

Coverage does not promise recovery from arbitrary container corruption. Unsupported variants return a typed error or a failed validation status. The engine never accepts a format by extension alone: callers provide a MIME type, and file helpers use an extension only to select that MIME type.

## Test fixtures

`tests/fixtures/signed_test.jpg` and `signed_test.mp4` exercise the public report contract. The deeper engine suite covers format extraction, claim parsing, signature algorithms, data hash, BMFF hash, boxes hash, collection hash, multipart bindings, ingredients, trust, OCSP, and malformed input boundaries.
