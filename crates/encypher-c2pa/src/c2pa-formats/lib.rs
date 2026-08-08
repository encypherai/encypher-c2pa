//! Format-specific C2PA manifest extraction and container parsing.
//!
//! A C2PA manifest store is a JUMBF superbox. Each asset format defines where
//! that opaque byte sequence lives. Verification uses [`extract_manifest`] to
//! recover the exact bytes before claim, assertion, signature, and hard-binding
//! checks run.
//!
//! The internal module also retains standards-only container writers used by
//! its round-trip tests. The public `encypher-c2pa` facade exposes verification
//! only.
//!
//! Supported readers cover JPEG, PNG, BMFF, FLAC, RIFF, GIF, SVG, JXL, ZIP,
//! ID3, TIFF/DNG, Font/SFNT, PDF, Ogg, and C2PA text wrappers.

#![forbid(unsafe_code)]

use thiserror::Error;

mod bmff;
mod flac;
mod font;
mod gif;
mod id3;
mod jpeg;
mod jxl;
mod ogg;
mod pdf;
mod png;
mod riff;
mod svg;
mod text;
pub(crate) mod text_standard;
mod tiff;
mod util;
mod zip;

/// A C2PA-carrying asset container format.
///
/// Each variant identifies a family of MIME types that share a single
/// manifest-embedding mechanism (e.g. all RIFF-based formats use a `C2PA`
/// chunk, all ISOBMFF-based formats use a C2PA `uuid` box).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetFormat {
    /// JPEG (`image/jpeg`): JUMBF in `APP11` (`0xFFEB`) marker segments.
    Jpeg,
    /// PNG (`image/png`): JUMBF in a `caBX` chunk.
    Png,
    /// ISOBMFF family (MP4/MOV/M4A/AVIF/HEIC/HEIF): JUMBF in a top-level C2PA
    /// `uuid` box.
    Bmff,
    /// RIFF family (WAV/AVI/WebP): JUMBF in a `C2PA` chunk.
    Riff,
    /// TIFF / DNG: JUMBF in IFD tag `0xCD41`. Extract only.
    Tiff,
    /// GIF: JUMBF in an Application Extension block.
    Gif,
    /// SVG: JUMBF base64-encoded in an XML processing instruction.
    Svg,
    /// PDF: embedded file stream. Not yet implemented.
    Pdf,
    /// ZIP/OPC family (EPUB, OOXML, OpenDocument, OpenXPS): JUMBF in entry
    /// `META-INF/content_credential.c2pa`.
    Zip,
    /// MP3: JUMBF in an ID3v2 `GEOB` frame.
    Id3,
    /// FLAC: JUMBF in an ID3v2 `GEOB` frame prepended to the FLAC stream.
    Flac,
    /// Ogg Vorbis: JUMBF in a dedicated Ogg logical bitstream.
    Ogg,
    /// SFNT fonts (OTF/TTF): JUMBF in a `C2PA` table. Extract only.
    Font,
    /// JPEG XL: JUMBF as a top-level `jumb` box in the ISOBMFF container.
    Jxl,
    /// Text, unstructured (C2PA 2.4 A.8): variation-selector wrapper appended to
    /// the UTF-8 text. Used for `text/plain` and social-post content.
    TextUnstructured,
    /// Text, structured (C2PA 2.4 A.9): ASCII-armour manifest block wrapped in
    /// the host language's comment syntax, so the signed asset stays
    /// syntactically valid. Used for Markdown, XML, and config (YAML/TOML/CSS/
    /// JS). `comment_prefix`/`comment_suffix` are the host comment delimiters
    /// (e.g. `<!--`/`-->`, `/*`/`*/`, `//`/``); both empty embeds a bare block
    /// (formats without a comment syntax, e.g. JSON).
    TextStructured {
        comment_prefix: &'static str,
        comment_suffix: &'static str,
    },
    /// HTML (C2PA 2.4 A.7): inline `<script type="application/c2pa">` element.
    TextHtml,
    /// EXPERIMENTAL host-less C2PA manifest store (`application/c2pa`). The
    /// bytes are a JUMBF manifest store with no host asset. Proposed compound
    /// parent manifests bind to `componentOf` children through a
    /// `c2pa.compound.content` assertion. This is not part of a ratified C2PA
    /// version. `extract` returns the bytes verbatim; `embed` and data-hash
    /// exclusions are not applicable.
    C2paStore,
}

/// C2PA user-type UUID for the unique BMFF manifest carrier.
pub const C2PA_BMFF_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// Canonical C2PA 2.4 `c2pa.hash.bmff.v3` top-level exclusions.
///
/// The `/uuid` assertion entry is further qualified by the C2PA UUID. Public
/// normalized geometry reports the paths while the carrier span is reported
/// separately.
pub const BMFF_HASH_EXCLUSION_PATHS: &[&str] = &["/uuid", "/ftyp", "/mfra", "/free", "/skip"];

/// Canonical MIME types supported by caller-supplied hard-binding digests.
///
/// This is the engine source of truth consumed by the CLI export, API
/// artifact, and CMS clients. Aliases are canonicalized before membership is
/// tested, so the list itself contains canonical values only.
pub const HASH_MODE_MIMES: &[&str] = &[
    "application/mp4",
    "audio/mp4",
    "audio/wav",
    "image/avif",
    "image/heic",
    "image/heic-sequence",
    "image/heif",
    "image/heif-sequence",
    "image/jpeg",
    "image/png",
    "image/webp",
    "video/mp4",
    "video/quicktime",
    "video/x-m4v",
    "video/x-msvideo",
];

/// Return whether a MIME type canonicalizes to a v1 hash-mode family.
pub fn supports_hash_mode(mime: &str) -> bool {
    let canonical = crate::c2pa_core::spec::canonicalize_mime(mime);
    HASH_MODE_MIMES.contains(&canonical.as_str())
}

impl AssetFormat {
    /// Map a MIME type string to its [`AssetFormat`], covering every MIME type
    /// in the C2PA conformance asset matrix. Returns `None` for unrecognized
    /// types.
    ///
    /// Matching is case-sensitive on the canonical lowercase MIME strings the
    /// conformance suite emits; callers that accept user input should lowercase
    /// first.
    pub fn from_mime(mime: &str) -> Option<Self> {
        // Strip any `; charset=…` parameter and apply the certified alias
        // canonicalization (audio/MPA->audio/mpeg, audio/aac->audio/mp4) so an
        // aliased input resolves to the same format — and signs to the same
        // bytes — as its canonical form.
        let canon = crate::c2pa_core::spec::canonicalize_mime(mime);
        Some(match canon.as_str() {
            "image/jpeg" => Self::Jpeg,
            "image/png" => Self::Png,
            "image/webp" => Self::Riff,
            "image/tiff" | "image/x-adobe-dng" => Self::Tiff,
            // Raw camera files are TIFF-structured: route to the TIFF reader for
            // verification. They are deliberately absent from FORMAT_REGISTRY, so
            // the profile-gated signing resolver refuses them (read-only),
            // matching c2pa-rs's TiffIO raw handling.
            "image/x-sony-arw" | "image/x-nikon-nef" => Self::Tiff,
            "image/avif"
            | "image/heic"
            | "image/heic-sequence"
            | "image/heif"
            | "image/heif-sequence"
            | "video/mp4"
            | "video/quicktime"
            | "audio/mp4"
            | "video/x-m4v"
            | "application/mp4" => Self::Bmff,
            "image/gif" => Self::Gif,
            "image/svg+xml" => Self::Svg,
            "image/jxl" => Self::Jxl,
            "video/x-msvideo" | "audio/wav" => Self::Riff,
            "audio/mpeg" => Self::Id3,
            "audio/flac" => Self::Flac,
            "audio/ogg" => Self::Ogg,
            "application/pdf" => Self::Pdf,
            "application/epub+zip"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            | "application/vnd.openxmlformats-officedocument.wordprocessingml.template"
            | "application/vnd.ms-word.document.macroenabled.12"
            | "application/vnd.ms-word.template.macroenabled.12"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            | "application/vnd.openxmlformats-officedocument.spreadsheetml.template"
            | "application/vnd.ms-excel.sheet.macroenabled.12"
            | "application/vnd.ms-excel.template.macroenabled.12"
            | "application/vnd.ms-excel.sheet.binary.macroenabled.12"
            | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            | "application/vnd.openxmlformats-officedocument.presentationml.template"
            | "application/vnd.openxmlformats-officedocument.presentationml.slideshow"
            | "application/vnd.ms-powerpoint.presentation.macroenabled.12"
            | "application/vnd.ms-powerpoint.template.macroenabled.12"
            | "application/vnd.ms-powerpoint.slideshow.macroenabled.12"
            | "application/vnd.ms-visio.drawing"
            | "application/vnd.ms-visio.drawing.macroenabled.12"
            | "application/vnd.ms-visio.stencil"
            | "application/vnd.ms-visio.stencil.macroenabled.12"
            | "application/vnd.ms-visio.template"
            | "application/vnd.ms-visio.template.macroenabled.12"
            | "application/vnd.oasis.opendocument.text"
            | "application/vnd.oasis.opendocument.spreadsheet"
            | "application/vnd.oasis.opendocument.presentation"
            | "application/oxps"
            | "application/vnd.ms-xpsdocument" => Self::Zip,
            "font/otf"
            | "font/ttf"
            | "font/sfnt"
            | "application/font-sfnt"
            | "application/x-font-ttf" => Self::Font,
            // Text (C2PA 2.4): route by family to the embedding method. Plain
            // text, CSV and JSON have no comment convention, so they use the
            // unstructured (A.8) variation-selector method (matching c2pa-text's
            // `recommended_method`). Structured (A.9) comment delimiters come
            // from the `c2pa-text` SSOT (`comment_syntax`), so the engine and
            // the published reference crate can never drift; `None` there means
            // the type has no comment convention and is unsupported here.
            "text/plain" | "text/csv" | "application/json" => Self::TextUnstructured,
            "text/html" => Self::TextHtml,
            // Python: c2pa-text's `recommended_method` routes it to the
            // structured (A.9) method, but its `comment_syntax` table carries
            // no Python entry. `#` is Python's comment syntax (the same
            // delimiters c2pa-text uses for YAML/TOML); extraction scans the
            // armour delimiters directly, so verification is unaffected by
            // the delimiter choice.
            "text/x-python" => Self::TextStructured {
                comment_prefix: "#",
                comment_suffix: "",
            },
            // EXPERIMENTAL: host-less compound manifest store (PR #2058).
            "application/c2pa" => Self::C2paStore,
            other => match c2pa_text::structured::comment_syntax(other) {
                Some((comment_prefix, comment_suffix)) => Self::TextStructured {
                    comment_prefix,
                    comment_suffix,
                },
                None => return None,
            },
        })
    }

    /// Resolve a MIME type to its [`AssetFormat`] **only if the given engine
    /// profile permits it**. Returns `None` when the type is unrecognized OR is
    /// out of scope for `profile` (e.g. text/font/ZIP under a conformance
    /// profile).
    ///
    /// This is the choke point that makes the conformance/regular distinction
    /// load-bearing: under `Conformance` only the certified set resolves, so a
    /// caller cannot accidentally sign/verify an out-of-program format on the
    /// certified path.
    pub fn from_mime_for_profile(
        mime: &str,
        profile: crate::c2pa_core::EngineProfile,
    ) -> Option<Self> {
        if !profile.permits_mime(mime) {
            return None;
        }
        Self::from_mime(mime)
    }
}

/// A contiguous byte range to exclude from a `c2pa.hash.data` hash binding.
///
/// `start` is the byte offset within the asset and `length` the number of bytes
/// covered. Exclusions mark where the manifest (and any placeholder padding)
/// sits, so the data hash is stable across the two-pass signing flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHashExclusion {
    /// Byte offset of the excluded range within the asset.
    pub start: usize,
    /// Number of bytes excluded.
    pub length: usize,
}

/// An error parsing or rewriting an asset container.
///
/// Note the distinction from a *missing* manifest: [`extract_manifest`] returns
/// `Ok(None)` for a well-formed asset that simply has no C2PA data, and only
/// produces a `FormatError` when the container bytes are malformed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    /// Operation is not implemented for this format (e.g. PDF embedding).
    #[error("operation not implemented for format {0:?}")]
    NotImplemented(AssetFormat),

    /// The bytes are not a valid container of the expected format.
    #[error("not a valid {format:?} asset: {detail}")]
    InvalidStructure {
        /// The format that was expected.
        format: AssetFormat,
        /// Human-readable reason.
        detail: &'static str,
    },

    /// The data ended before a structure could be fully parsed.
    #[error("unexpected end of data while parsing {0:?}")]
    Truncated(AssetFormat),

    /// The manifest is too large for this format's container limits.
    #[error("manifest of {got} bytes exceeds the {max}-byte limit for {format:?}")]
    ManifestTooLarge {
        /// The format whose limit was exceeded.
        format: AssetFormat,
        /// The container's maximum payload size.
        max: usize,
        /// The manifest size that was rejected.
        got: usize,
    },

    /// A recognized container variant that this crate does not support.
    #[error("unsupported {format:?} variant: {detail}")]
    UnsupportedVariant {
        /// The owning format.
        format: AssetFormat,
        /// What about the variant is unsupported.
        detail: &'static str,
    },
}

/// Re-export: resolve BMFF box-path exclusions to byte ranges (for bmffHash).
pub(crate) use bmff::bmff_exclusion_ranges;

/// Re-export: compute the BMFF V2/V3 (non-merkle) hard-binding hash with the
/// box-offset markers the C2PA algorithm requires (for bmffHash sign/verify).
pub(crate) use bmff::bmff_hash;

/// Re-export: streaming, bounded-memory BMFF hash for assets too large to hold
/// in memory (hours-long video). Byte-identical to [`bmff_hash`].
pub(crate) use bmff::bmff_hash_reader;

/// Re-export: parse auxiliary C2PA `'merkle'` boxes from fragment files and
/// compute fragment Merkle leaf hashes (fragmented BMFF verification).
pub(crate) use bmff::{bmff_fragment_leaf_hash, bmff_merkle_boxes, BmffMerkleBox};

/// One named span of an asset for the general box hash (`c2pa.hash.boxes`).
///
/// Produced by [`box_spans`]: the asset is segmented into its box-like
/// structures per the C2PA conventions (spec 18.4 examples): JPEG marker
/// segments (`SOI`, `APP0`, `DQT`, …, `SOS`, `RST0`, `EOI`), PNG signature +
/// chunks (`PNGh`, `IHDR`, …). The contiguous run of segments carrying the
/// C2PA Manifest Store is merged into a single span named `C2PA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxSpan {
    /// The C2PA box identifier (e.g. `APP0`, `IHDR`, `C2PA`).
    pub name: String,
    /// Byte offset of the span's first byte.
    pub start: usize,
    /// One-past-the-end byte offset.
    pub end: usize,
}

/// Segment `data` into named spans for `c2pa.hash.boxes` validation.
///
/// Returns `Ok(None)` for container formats whose box-hash segmentation is
/// not implemented (the validator reports those informationally rather than
/// risking a false mismatch).
pub fn box_spans(format: AssetFormat, data: &[u8]) -> Result<Option<Vec<BoxSpan>>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::box_spans(data).map(Some),
        AssetFormat::Png => png::box_spans(data).map(Some),
        _ => Ok(None),
    }
}

/// Re-export ZIP collection helpers for `c2pa.hash.collection.data`.
pub(crate) use zip::{
    zip_central_directory_hash_parts, zip_entry_data, zip_entry_hash_span, zip_entry_local_span,
    zip_entry_names,
};

/// Re-export: the payload spans of every top-level `mdat` box, in file order
/// (monolithic chunked-mdat merkle validation).
pub(crate) use bmff::bmff_mdat_payloads;

/// Extract the raw JUMBF manifest-store bytes from `data`.
///
/// Returns `Ok(Some(bytes))` with the manifest-store superbox (suitable for
/// [`crate::c2pa_core::jumbf::parse_manifest_store`]), `Ok(None)` if the asset is valid
/// but has no manifest, or `Err` if the container is malformed.
pub fn extract_manifest(format: AssetFormat, data: &[u8]) -> Result<Option<Vec<u8>>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::extract(data),
        AssetFormat::Png => png::extract(data),
        AssetFormat::Bmff => bmff::extract(data),
        AssetFormat::Riff => riff::extract(data),
        AssetFormat::Tiff => tiff::extract(data),
        AssetFormat::Gif => gif::extract(data),
        AssetFormat::Svg => svg::extract(data),
        AssetFormat::Pdf => pdf::extract(data),
        AssetFormat::Zip => zip::extract(data),
        AssetFormat::Id3 => id3::extract(data),
        AssetFormat::Flac => flac::extract(data),
        AssetFormat::Ogg => ogg::extract(data),
        AssetFormat::Font => font::extract(data),
        AssetFormat::Jxl => jxl::extract(data),
        AssetFormat::TextUnstructured => text::extract(text::TextMethod::Unstructured, data),
        AssetFormat::TextStructured { .. } => text::extract(text::TextMethod::Structured, data),
        AssetFormat::TextHtml => text::extract(text::TextMethod::Html, data),
        // The bytes ARE the manifest store; return verbatim (empty => no manifest).
        AssetFormat::C2paStore => {
            if data.is_empty() {
                Ok(None)
            } else {
                Ok(Some(data.to_vec()))
            }
        }
    }
}

/// Remove any existing manifest from `asset`, returning a clean copy safe to
/// re-embed into. A no-op (returns `asset` unchanged) when the asset has no
/// manifest, and for formats whose [`embed_manifest`] already replaces
/// cleanly on its own (TIFF, Font/SFNT, ID3/MP3) or that don't expose a
/// separate strip primitive (PDF's incremental-update model preserves prior
/// generations verbatim by design; the text methods delegate to the external
/// `c2pa-text` crate).
///
/// Container writing is not part of the verification surface; this exists for
/// in-repo fixture generation only. Private module plus `cfg(test)`.
#[cfg(test)]
pub fn strip_manifest(format: AssetFormat, asset: &[u8]) -> Result<Vec<u8>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::strip(asset),
        AssetFormat::Png => png::strip(asset),
        AssetFormat::Bmff => bmff::strip(asset),
        AssetFormat::Riff => riff::strip(asset),
        AssetFormat::Gif => gif::strip(asset),
        AssetFormat::Svg => svg::strip(asset),
        AssetFormat::Zip => zip::strip(asset),
        AssetFormat::Flac => flac::strip(asset),
        AssetFormat::Ogg => ogg::strip(asset),
        AssetFormat::Jxl => jxl::strip(asset),
        AssetFormat::Tiff
        | AssetFormat::Font
        | AssetFormat::Id3
        | AssetFormat::Pdf
        | AssetFormat::TextUnstructured
        | AssetFormat::TextStructured { .. }
        | AssetFormat::TextHtml
        | AssetFormat::C2paStore => Ok(asset.to_vec()),
    }
}

/// Frame a raw C2PA manifest store as the exact carrier bytes accepted by
/// [`embed_manifest`].
///
/// Only the v1 hash-mode families are accepted. Fixture generation only.
#[cfg(test)]
pub fn build_manifest_carrier(
    format: AssetFormat,
    manifest_store: &[u8],
) -> Result<Vec<u8>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::build_app11_segments(manifest_store),
        AssetFormat::Png => Ok(png::build_cabx_chunk(manifest_store)),
        AssetFormat::Riff => riff::build_c2pa_chunk(manifest_store),
        AssetFormat::Bmff => Ok(bmff::build_c2pa_uuid_box(manifest_store)),
        other => Err(FormatError::NotImplemented(other)),
    }
}

/// Insert `manifest_store` into `asset`, returning the new asset bytes.
///
/// Container writing is not part of the verification surface. This SDK reads
/// C2PA structures and never produces them; the writer exists only so in-repo
/// tests can build inputs for the readers. It lives in a private module and is
/// `cfg(test)`, so no Cargo feature can expose it and it is not compiled into
/// the published library at all.
#[cfg(test)]
pub fn embed_manifest(
    format: AssetFormat,
    asset: &[u8],
    manifest_store: &[u8],
) -> Result<Vec<u8>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::embed(asset, manifest_store),
        AssetFormat::Png => png::embed(asset, manifest_store),
        AssetFormat::Bmff => bmff::embed(asset, manifest_store),
        AssetFormat::Riff => riff::embed(asset, manifest_store),
        AssetFormat::Tiff => tiff::embed(asset, manifest_store),
        AssetFormat::Gif => gif::embed(asset, manifest_store),
        AssetFormat::Svg => svg::embed(asset, manifest_store),
        AssetFormat::Pdf => pdf::embed(asset, manifest_store),
        AssetFormat::Zip => zip::embed(asset, manifest_store),
        AssetFormat::Id3 => id3::embed(asset, manifest_store),
        AssetFormat::Flac => flac::embed(asset, manifest_store),
        AssetFormat::Ogg => ogg::embed(asset, manifest_store),
        AssetFormat::Font => font::embed(asset, manifest_store),
        AssetFormat::Jxl => jxl::embed(asset, manifest_store),
        AssetFormat::TextUnstructured => {
            text::embed(text::TextMethod::Unstructured, asset, manifest_store)
        }
        AssetFormat::TextStructured {
            comment_prefix,
            comment_suffix,
        } => text::embed_structured(asset, manifest_store, comment_prefix, comment_suffix),
        AssetFormat::TextHtml => text::embed(text::TextMethod::Html, asset, manifest_store),
        // A host-less manifest store has no container to embed into.
        AssetFormat::C2paStore => Err(FormatError::NotImplemented(AssetFormat::C2paStore)),
    }
}

/// Compute the byte ranges to exclude from a `c2pa.hash.data` assertion for an
/// asset that already contains an embedded manifest.
///
/// Despite the signing-flavoured name, this is load-bearing for VERIFICATION
/// and is deliberately public and un-gated: the verifier calls it to resolve
/// the manifest carrier span while checking `c2pa.hash.data`
/// (`c2pa-validate/src/lib.rs`). Do not mistake it for orphaned writer surface.
///
/// It is also the second pass of two-pass signing, where a signer hashes an
/// asset containing a placeholder manifest while excluding the ranges returned
/// here, so the hash does not depend on the manifest's own bytes.
///
/// Returns an empty `Vec` if the asset contains no manifest.
pub fn compute_data_hash_exclusions(
    format: AssetFormat,
    asset_with_placeholder: &[u8],
) -> Result<Vec<DataHashExclusion>, FormatError> {
    match format {
        AssetFormat::Jpeg => jpeg::exclusions(asset_with_placeholder),
        AssetFormat::Png => png::exclusions(asset_with_placeholder),
        AssetFormat::Bmff => bmff::exclusions(asset_with_placeholder),
        AssetFormat::Riff => riff::exclusions(asset_with_placeholder),
        AssetFormat::Flac => flac::exclusions(asset_with_placeholder),
        AssetFormat::Ogg => ogg::exclusions(asset_with_placeholder),
        AssetFormat::TextUnstructured => {
            text::exclusions(text::TextMethod::Unstructured, asset_with_placeholder)
        }
        AssetFormat::TextStructured { .. } => {
            text::exclusions(text::TextMethod::Structured, asset_with_placeholder)
        }
        AssetFormat::TextHtml => text::exclusions(text::TextMethod::Html, asset_with_placeholder),
        AssetFormat::Tiff => tiff::exclusions(asset_with_placeholder),
        AssetFormat::Gif => gif::exclusions(asset_with_placeholder),
        AssetFormat::Svg => svg::exclusions(asset_with_placeholder),
        AssetFormat::Pdf => pdf::exclusions(asset_with_placeholder),
        AssetFormat::Zip => zip::exclusions(asset_with_placeholder),
        AssetFormat::Id3 => id3::exclusions(asset_with_placeholder),
        AssetFormat::Font => font::exclusions(asset_with_placeholder),
        AssetFormat::Jxl => jxl::exclusions(asset_with_placeholder),
        // No host bytes: a compound store has no data-hash binding.
        AssetFormat::C2paStore => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small but structurally valid manifest store for round-trip tests.
    pub(crate) fn dummy_manifest_store() -> Vec<u8> {
        use crate::c2pa_core::jumbf::{assertion_box, build_manifest, build_manifest_store};
        let assertion = assertion_box("c2pa.actions.v2", &[0xa0], None);
        let manifest = build_manifest("urn:c2pa:test:0001", &[assertion], &[0xa0], &[0xd2, 0x84]);
        build_manifest_store(&[manifest])
    }

    #[test]
    fn from_mime_covers_conformance_matrix() {
        let cases: &[(&str, AssetFormat)] = &[
            ("image/jpeg", AssetFormat::Jpeg),
            ("image/png", AssetFormat::Png),
            ("image/webp", AssetFormat::Riff),
            ("image/tiff", AssetFormat::Tiff),
            ("image/x-adobe-dng", AssetFormat::Tiff),
            ("image/avif", AssetFormat::Bmff),
            ("image/heic", AssetFormat::Bmff),
            ("image/heif", AssetFormat::Bmff),
            ("image/heic-sequence", AssetFormat::Bmff),
            ("image/heif-sequence", AssetFormat::Bmff),
            ("video/mp4", AssetFormat::Bmff),
            ("video/quicktime", AssetFormat::Bmff),
            ("audio/mp4", AssetFormat::Bmff),
            ("video/x-m4v", AssetFormat::Bmff),
            ("application/mp4", AssetFormat::Bmff),
            ("image/gif", AssetFormat::Gif),
            ("image/svg+xml", AssetFormat::Svg),
            ("image/jxl", AssetFormat::Jxl),
            ("video/x-msvideo", AssetFormat::Riff),
            ("audio/wav", AssetFormat::Riff),
            ("audio/mpeg", AssetFormat::Id3),
            ("audio/flac", AssetFormat::Flac),
            ("audio/ogg", AssetFormat::Ogg),
            ("application/pdf", AssetFormat::Pdf),
            ("application/epub+zip", AssetFormat::Zip),
            (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                AssetFormat::Zip,
            ),
            (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                AssetFormat::Zip,
            ),
            (
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                AssetFormat::Zip,
            ),
            ("application/vnd.oasis.opendocument.text", AssetFormat::Zip),
            (
                "application/vnd.oasis.opendocument.spreadsheet",
                AssetFormat::Zip,
            ),
            (
                "application/vnd.oasis.opendocument.presentation",
                AssetFormat::Zip,
            ),
            ("application/oxps", AssetFormat::Zip),
            ("application/vnd.ms-xpsdocument", AssetFormat::Zip),
            ("font/otf", AssetFormat::Font),
            ("font/ttf", AssetFormat::Font),
        ];
        for (mime, want) in cases {
            assert_eq!(AssetFormat::from_mime(mime), Some(*want), "mime {mime}");
        }
        assert_eq!(AssetFormat::from_mime("application/octet-stream"), None);
        // MIME parameters are tolerated.
        assert_eq!(
            AssetFormat::from_mime("image/jpeg; charset=binary"),
            Some(AssetFormat::Jpeg)
        );
    }

    #[test]
    fn v2_4_registry_routes_every_mime() {
        use crate::c2pa_core::{spec::mimes_for_version, SpecVersion};

        for mime in mimes_for_version(SpecVersion::V2_4) {
            assert!(
                AssetFormat::from_mime(mime).is_some(),
                "v2.4 registry MIME has no format implementation: {mime}"
            );
        }
    }
    #[test]
    fn every_c2pa_text_type_is_registry_permitted() {
        use crate::c2pa_core::{EngineProfile, OperatingMode, SpecVersion};

        // Every text type the published c2pa-text crate handles (A.7 HTML,
        // A.8 unstructured, A.9 structured comment syntaxes, plus the alias
        // spellings our canonicalizer folds). If c2pa-text grows a type this
        // registry does not know, this test fails instead of the gate
        // silently rejecting a spec-supported text asset.
        let text_types = [
            "text/plain",
            "text/csv",
            "text/html",
            "text/markdown",
            "text/xml",
            "text/css",
            "text/x-python",
            "text/javascript",
            "text/yaml",
            "application/javascript",
            "application/json",
            "application/xml",
            "application/xhtml+xml",
            "application/yaml",
            "application/x-yaml",
            "application/toml",
        ];
        let regular = EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular);
        for mime in text_types {
            assert!(
                regular.permits_mime(mime),
                "c2pa-text supports {mime} but the v2.4 registry gate rejects it"
            );
            assert!(
                AssetFormat::from_mime(mime).is_some(),
                "c2pa-text supports {mime} but no AssetFormat routes it"
            );
        }
    }

    #[test]
    fn container_aliases_resolve_to_canonical_format() {
        let cases: &[(&str, AssetFormat)] = &[
            ("video/avi", AssetFormat::Riff),
            ("video/msvideo", AssetFormat::Riff),
            ("application/x-troff-msvideo", AssetFormat::Riff),
            ("audio/wave", AssetFormat::Riff),
            ("audio/vnd.wave", AssetFormat::Riff),
            ("audio/x-wav", AssetFormat::Riff),
            ("audio/x-flac", AssetFormat::Flac),
            ("application/ogg", AssetFormat::Ogg),
            ("image/dng", AssetFormat::Tiff),
            ("application/svg+xml", AssetFormat::Svg),
        ];
        for (mime, want) in cases {
            assert_eq!(AssetFormat::from_mime(mime), Some(*want), "alias {mime}");
        }
    }

    #[test]
    fn raw_camera_is_read_only() {
        use crate::c2pa_core::{EngineProfile, OperatingMode, SpecVersion};
        // ARW/NEF are TIFF-structured: c2pa-rs (TiffIO) verifies them but never
        // signs them. from_mime routes them to the TIFF reader, but they are
        // absent from FORMAT_REGISTRY so the profile-gated signing resolver
        // refuses them.
        let regular = EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular);
        for mime in ["image/x-sony-arw", "image/x-nikon-nef"] {
            assert_eq!(
                AssetFormat::from_mime(mime),
                Some(AssetFormat::Tiff),
                "{mime}"
            );
            assert_eq!(
                AssetFormat::from_mime_for_profile(mime, regular),
                None,
                "{mime} must be read-only (not signable)"
            );
        }
    }

    #[test]
    fn structured_text_routes_by_comment_syntax() {
        // Each comment-bearing structured MIME wraps the A.9 armour block in
        // that language's comment delimiters, so the signed asset stays valid.
        let store = dummy_manifest_store();
        let body = b"k: v\n";
        let cases: &[(&str, &str, &str)] = &[
            ("text/css", "/* -----BEGIN C2PA MANIFEST-----", "*/"),
            (
                "application/javascript",
                "// -----BEGIN C2PA MANIFEST-----",
                "-----END C2PA MANIFEST-----",
            ),
            (
                "application/xml",
                "<!-- -----BEGIN C2PA MANIFEST-----",
                "-->",
            ),
            (
                "application/yaml",
                "# -----BEGIN C2PA MANIFEST-----",
                "-----END C2PA MANIFEST-----",
            ),
        ];
        for &(mime, open_marker, end_marker) in cases {
            let fmt = AssetFormat::from_mime(mime).unwrap();
            let signed = embed_manifest(fmt, body, &store).unwrap();
            let text = String::from_utf8(signed.clone()).unwrap();
            assert!(
                text.contains(open_marker),
                "{mime}: missing `{open_marker}`"
            );
            assert!(
                text.trim_end().ends_with(end_marker),
                "{mime}: bad block tail"
            );
            // Manifest round-trips through extract.
            assert_eq!(
                extract_manifest(fmt, &signed).unwrap(),
                Some(store.clone()),
                "{mime}: extract"
            );
            // Data-hash exclusion is a single span; the source lies outside it.
            let ex = compute_data_hash_exclusions(fmt, &signed).unwrap();
            assert_eq!(ex.len(), 1, "{mime}: exclusion count");
            assert!(
                ex[0].start >= body.len(),
                "{mime}: source must be outside exclusion"
            );
        }
    }
}

#[cfg(test)]
mod fuzz_robustness;
