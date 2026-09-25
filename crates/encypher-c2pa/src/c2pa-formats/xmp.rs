// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! XMP `dcterms:provenance` discovery: the documented location of a remote
//! C2PA Manifest Store reference.
//!
//! C2PA 2.4 Manifests, Embedding a Reference to an external Manifest: "If the
//! asset has embedded XMP, and the C2PA Manifest will be stored externally, it
//! is recommended that the claim generator add a `dcterms:provenance` key to
//! the XMP, the value (a URI reference) being where to locate the active
//! manifest." C2PA 2.4 Validation, By Reference, makes reading it a validator
//! step: "If the asset has any XMP in the standard asset locations (i.e.,
//! outside the C2PA Manifest) and that XMP contains a `dcterms:provenance`
//! key, the provided URI should be used to locate the active manifest."
//!
//! This module only *reads* the declaration. Nothing here fetches: the SDK is
//! offline by contract, so the caller-visible outcome is the registered
//! `manifest.inaccessible` code carrying the URI. A caller that obtains the
//! store itself verifies it through the detached entry point.
//!
//! The per-format locators below are the standard XMP placements (XMP
//! Specification Part 3) for the container families this build reads. They are
//! deliberately self-contained: discovery must never turn a well-formed asset
//! into a container error, so every locator is total and returns nothing rather
//! than failing.

use crate::c2pa_formats::util::{be_u16, be_u32, le_u32, walk_iso_boxes};
use crate::c2pa_formats::AssetFormat;

/// The Dublin Core Terms namespace that binds the `provenance` property.
const DCTERMS_NS: &str = "http://purl.org/dc/terms/";
/// Conventional prefix, used when the packet declares no explicit binding.
const DEFAULT_PREFIX: &str = "dcterms";
/// XMP packets considered per asset. More than this is malformed in practice.
const MAX_PACKETS: usize = 8;
/// Largest XMP packet parsed. Larger packets are skipped rather than scanned.
const MAX_PACKET_BYTES: usize = 4 * 1024 * 1024;
/// Longest accepted URI. Bounds the string the report carries.
const MAX_URI_BYTES: usize = 4096;

/// JPEG APP1 XMP signature (XMP Part 3, 1.1.3).
const JPEG_XMP_SIGNATURE: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
/// PNG XMP iTXt keyword (XMP Part 3, 1.1.5).
const PNG_XMP_KEYWORD: &[u8] = b"XML:com.adobe.xmp";
/// ISOBMFF XMP `uuid` box user type (XMP Part 3, 1.1.6).
const BMFF_XMP_UUID: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];
/// GIF XMP Application Extension identifier + authentication code.
const GIF_XMP_APP_ID: &[u8; 11] = b"XMP DataXMP";
/// TIFF/DNG XMP IFD tag 700 (XMP Part 3, 1.1.4).
pub(crate) const TIFF_XMP_TAG: u16 = 0x02BC;

/// The `dcterms:provenance` URI declared by the asset's XMP, if any.
///
/// Returns the first well-formed, non-empty URI found in the format's standard
/// XMP location(s).
pub(crate) fn provenance_uri(format: AssetFormat, data: &[u8]) -> Option<String> {
    let mut packets = Vec::new();
    collect_packets(format, data, &mut packets);
    packets
        .into_iter()
        .filter(|packet| packet.len() <= MAX_PACKET_BYTES)
        .find_map(provenance_from_packet)
}

fn collect_packets<'a>(format: AssetFormat, data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    match format {
        AssetFormat::Jpeg => jpeg_packets(data, out),
        AssetFormat::Png => png_packets(data, out),
        AssetFormat::Bmff | AssetFormat::Jxl => iso_packets(format, data, out),
        AssetFormat::Riff => riff_packets(data, out),
        AssetFormat::Gif => gif_packets(data, out),
        AssetFormat::Tiff => out.extend(crate::c2pa_formats::tiff::xmp_packet(data)),
        // An SVG carries its XMP inline in the document itself.
        AssetFormat::Svg => out.push(data),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Per-format locators
// ---------------------------------------------------------------------------

/// JPEG: APP1 segments whose payload opens with the XMP signature. Only the
/// header is scanned; XMP never follows the Start of Scan.
fn jpeg_packets<'a>(data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return;
    }
    let mut pos = 2;
    while pos + 4 <= data.len() && out.len() < MAX_PACKETS {
        if data[pos] != 0xFF {
            return;
        }
        let marker = data[pos + 1];
        // Padding fill bytes, and standalone markers with no length field.
        if marker == 0xFF {
            pos += 1;
            continue;
        }
        if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            pos += 2;
            continue;
        }
        // Start of Scan or End of Image: the header is over.
        if marker == 0xDA || marker == 0xD9 {
            return;
        }
        let Some(length) = be_u16(data, pos + 2).map(usize::from) else {
            return;
        };
        if length < 2 {
            return;
        }
        let Some(end) = pos.checked_add(2 + length).filter(|&e| e <= data.len()) else {
            return;
        };
        let payload = &data[pos + 4..end];
        if marker == 0xE1 {
            if let Some(packet) = payload.strip_prefix(JPEG_XMP_SIGNATURE) {
                out.push(packet);
            }
        }
        pos = end;
    }
}

/// PNG: uncompressed `iTXt` chunks keyed `XML:com.adobe.xmp`. A compressed
/// packet is skipped rather than inflated: discovery does not decompress
/// attacker-controlled input.
fn png_packets<'a>(data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    const SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || data[..8] != SIGNATURE {
        return;
    }
    let mut pos = 8;
    while pos + 8 <= data.len() && out.len() < MAX_PACKETS {
        let Some(length) = be_u32(data, pos).and_then(|len| usize::try_from(len).ok()) else {
            return;
        };
        let type_code = &data[pos + 4..pos + 8];
        let Some(end) = pos
            .checked_add(12)
            .and_then(|base| base.checked_add(length))
            .filter(|&e| e <= data.len())
        else {
            return;
        };
        if type_code == b"iTXt" {
            let body = &data[pos + 8..end - 4];
            if let Some(packet) = png_itxt_xmp(body) {
                out.push(packet);
            }
        }
        if type_code == b"IEND" {
            return;
        }
        pos = end;
    }
}

/// `keyword\0 compression_flag compression_method language\0 translated\0 text`
fn png_itxt_xmp(body: &[u8]) -> Option<&[u8]> {
    let rest = body.strip_prefix(PNG_XMP_KEYWORD)?;
    let rest = rest.strip_prefix(b"\0")?;
    // Uncompressed only.
    if *rest.first()? != 0 {
        return None;
    }
    let rest = rest.get(2..)?;
    let language_end = rest.iter().position(|&b| b == 0)?;
    let rest = rest.get(language_end + 1..)?;
    let translated_end = rest.iter().position(|&b| b == 0)?;
    rest.get(translated_end + 1..)
}

/// ISOBMFF and JPEG XL: the XMP `uuid` box, plus the JPEG XL `xml ` box.
fn iso_packets<'a>(format: AssetFormat, data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    let _ = walk_iso_boxes(data, format, |iso| {
        if out.len() >= MAX_PACKETS || iso.payload_start > iso.end || iso.end > data.len() {
            return;
        }
        let payload = &data[iso.payload_start..iso.end];
        if &iso.box_type == b"uuid" {
            if payload.len() > 16 && payload[..16] == BMFF_XMP_UUID {
                out.push(&payload[16..]);
            }
        } else if &iso.box_type == b"xml " {
            out.push(payload);
        }
    });
}

/// RIFF (WebP, WAV, AVI): the top-level `XMP ` chunk.
fn riff_packets<'a>(data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    if data.len() < 12 || &data[..4] != b"RIFF" {
        return;
    }
    let mut pos = 12;
    while pos + 8 <= data.len() && out.len() < MAX_PACKETS {
        let Some(size) = le_u32(data, pos + 4).and_then(|len| usize::try_from(len).ok()) else {
            return;
        };
        let Some(end) = pos.checked_add(8 + size).filter(|&e| e <= data.len()) else {
            return;
        };
        if &data[pos..pos + 4] == b"XMP " {
            out.push(&data[pos + 8..end]);
        }
        // RIFF chunks are word-aligned.
        pos = end + (end & 1);
    }
}

/// GIF: the XMP Application Extension. Its packet is stored raw and closed by
/// the 258-byte magic trailer, not by GIF sub-blocks (XMP Part 3, 1.1.2).
fn gif_packets<'a>(data: &'a [u8], out: &mut Vec<&'a [u8]>) {
    if data.len() < 13 || !(data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return;
    }
    let mut pos = 0;
    while pos + 14 <= data.len() && out.len() < MAX_PACKETS {
        // Extension Introducer, Application Extension Label, block size 11.
        if data[pos] == 0x21
            && data[pos + 1] == 0xFF
            && data[pos + 2] == 0x0B
            && &data[pos + 3..pos + 14] == GIF_XMP_APP_ID
        {
            let body = &data[pos + 14..];
            // Magic trailer opens with 0x01 0xFF 0xFE.
            let end = body
                .windows(3)
                .position(|window| window == [0x01, 0xFF, 0xFE])
                .unwrap_or(body.len());
            out.push(&body[..end]);
        }
        pos += 1;
    }
}

// ---------------------------------------------------------------------------
// `dcterms:provenance` extraction
// ---------------------------------------------------------------------------

fn provenance_from_packet(packet: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(packet).ok()?;
    for prefix in dcterms_prefixes(text) {
        if let Some(uri) = provenance_for_prefix(text, &prefix) {
            return Some(uri);
        }
    }
    None
}

/// Every prefix the packet binds to the Dublin Core Terms namespace, plus the
/// conventional `dcterms` prefix as a fallback for packets with no binding in
/// the scanned fragment.
fn dcterms_prefixes(text: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("xmlns:") {
        rest = &rest[at + "xmlns:".len()..];
        let Some(equals) = rest.find('=') else { break };
        let prefix = rest[..equals].trim();
        let after = rest[equals + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        let Some(close) = after[1..].find(quote) else {
            continue;
        };
        if &after[1..1 + close] == DCTERMS_NS
            && !prefix.is_empty()
            && !prefix.contains(char::is_whitespace)
            && !prefixes.iter().any(|known| known == prefix)
        {
            prefixes.push(prefix.to_string());
        }
    }
    if !prefixes.iter().any(|known| known == DEFAULT_PREFIX) {
        prefixes.push(DEFAULT_PREFIX.to_string());
    }
    prefixes
}

/// Read `PREFIX:provenance` in either XMP serialization: an attribute on an
/// `rdf:Description`, or a child element (with a literal value or an
/// `rdf:resource` attribute).
fn provenance_for_prefix(text: &str, prefix: &str) -> Option<String> {
    let needle = format!("{prefix}:provenance");
    let mut search = 0usize;
    while let Some(at) = text[search..].find(&needle) {
        let start = search + at;
        search = start + needle.len();
        // Reject a longer property name that merely starts with "provenance".
        let after = &text[search..];
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            continue;
        }
        let opened_element = text[..start].ends_with('<');
        let trimmed = after.trim_start();
        if !opened_element {
            if let Some(value) = trimmed.strip_prefix('=') {
                if let Some(uri) = quoted_value(value.trim_start()) {
                    return Some(uri);
                }
            }
            continue;
        }
        if let Some(uri) = element_value(after, &needle) {
            return Some(uri);
        }
    }
    None
}

/// `after` begins immediately past `<PREFIX:provenance`.
fn element_value(after: &str, needle: &str) -> Option<String> {
    let tag_end = after.find('>')?;
    let attributes = &after[..tag_end];
    if let Some(at) = attributes.find("rdf:resource") {
        let rest = attributes[at + "rdf:resource".len()..].trim_start();
        if let Some(value) = rest.strip_prefix('=') {
            if let Some(uri) = quoted_value(value.trim_start()) {
                return Some(uri);
            }
        }
    }
    if attributes.trim_end().ends_with('/') {
        return None;
    }
    let body = &after[tag_end + 1..];
    let close = format!("</{needle}>");
    let body_end = body.find(&close)?;
    accept_uri(&body[..body_end])
}

/// Read a single- or double-quoted attribute value starting at `text`.
fn quoted_value(text: &str) -> Option<String> {
    let quote = text.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &text[1..];
    let close = rest.find(quote)?;
    accept_uri(&rest[..close])
}

/// Accept only a value that actually names a remote manifest location.
///
/// C2PA 2.4 Manifests, Embedding a Reference to an external Manifest, notes
/// that "a previous version of this specification also recommended using this
/// method for references to embedded manifests. Now this mechanism is only for
/// external manifests." Assets written under that older reading carry
/// `dcterms:provenance="self#jumbf=/c2pa/.../c2pa.claim"`, which points into
/// the asset itself, not to a repository. Treating one of those as a remote
/// manifest would report an asset with no provenance as having provenance
/// stored somewhere it is not.
///
/// The remote form is an absolute `http`/`https` URI: that is what the `Link`
/// header clause describes ("The URI will be a standard `http` or `https`
/// URI") and what `ext-url-type` permits. A relative reference would have to
/// be resolved against the URI the asset was retrieved from, which a local
/// verifier never has, so it is not accepted either.
fn accept_uri(raw: &str) -> Option<String> {
    if raw.len() > MAX_URI_BYTES {
        return None;
    }
    let uri = unescape_xml(raw.trim());
    if uri.contains(['<', '>']) {
        return None;
    }
    let scheme = uri.split_once("://")?.0;
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")).then_some(uri)
}

/// Resolve the five predefined XML entities and numeric character references.
/// XMP serializes a URI's `&` as `&amp;`, so a raw value is not the URI.
fn unescape_xml(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(semi) = tail.find(';').filter(|&semi| semi <= 12) else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let resolved = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix('#')
                .and_then(|digits| match digits.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => digits.parse::<u32>().ok(),
                })
                .and_then(char::from_u32),
        };
        match resolved {
            Some(character) => {
                out.push(character);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET: &str = concat!(
        r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>"#,
        r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF"#,
        r#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#,
        r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/""#,
        r#" dcterms:provenance="https://example.test/a.c2pa?v=1&amp;k=2"/>"#,
        r#"</rdf:RDF></x:xmpmeta><?xpacket end="w"?>"#,
    );

    #[test]
    fn attribute_form_resolves_entities() {
        assert_eq!(
            provenance_from_packet(PACKET.as_bytes()).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn element_form_and_rdf_resource_are_read() {
        let element = r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/">
            <dcterms:provenance>https://example.test/b.c2pa</dcterms:provenance>
            </rdf:Description>"#;
        assert_eq!(
            provenance_from_packet(element.as_bytes()).as_deref(),
            Some("https://example.test/b.c2pa")
        );
        let resource = r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/">
            <dcterms:provenance rdf:resource="https://example.test/c.c2pa"/>
            </rdf:Description>"#;
        assert_eq!(
            provenance_from_packet(resource.as_bytes()).as_deref(),
            Some("https://example.test/c.c2pa")
        );
    }

    #[test]
    fn a_non_conventional_prefix_bound_to_the_namespace_is_honored() {
        let packet = r#"<rdf:Description xmlns:terms="http://purl.org/dc/terms/"
            terms:provenance="https://example.test/d.c2pa"/>"#;
        assert_eq!(
            provenance_from_packet(packet.as_bytes()).as_deref(),
            Some("https://example.test/d.c2pa")
        );
    }

    #[test]
    fn a_packet_without_the_key_yields_nothing() {
        let packet = r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/"
            dcterms:provenanceNote="not a URI" dcterms:created="2026-01-01"/>"#;
        assert_eq!(provenance_from_packet(packet.as_bytes()), None);
    }

    /// A `self#jumbf=` value is the superseded way of pointing at a manifest
    /// embedded in this same asset. It names no repository, so an asset
    /// carrying one and no embedded store has no provenance to report - not a
    /// remote manifest that happens to be unreachable. Real assets in the
    /// c2pa-rs corpus (`no_manifest.jpg`, `video1_no_manifest.mp4`) are written
    /// this way.
    #[test]
    fn a_legacy_reference_to_an_embedded_manifest_is_not_a_remote_manifest() {
        for value in [
            "self#jumbf=/c2pa/adobe:urn:uuid:5f5bba8c-9184-44c6-b9a7-62cfda37b343/c2pa.claim",
            "manifests/relative.c2pa",
            "urn:uuid:54281c07-ad34-430e-bea5-112a18facf0b",
            "file:///etc/passwd",
            "",
        ] {
            let packet = format!(
                r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/"
                dcterms:provenance="{value}"/>"#
            );
            assert_eq!(provenance_from_packet(packet.as_bytes()), None, "{value}");
        }

        // A remote store reached over plain HTTP is still a remote store.
        let packet = r#"<rdf:Description xmlns:dcterms="http://purl.org/dc/terms/"
            dcterms:provenance="HTTP://store.test/a.c2pa"/>"#;
        assert_eq!(
            provenance_from_packet(packet.as_bytes()).as_deref(),
            Some("HTTP://store.test/a.c2pa")
        );
    }

    #[test]
    fn jpeg_app1_packet_is_located() {
        let mut jpeg = vec![0xFF, 0xD8];
        let mut payload = JPEG_XMP_SIGNATURE.to_vec();
        payload.extend_from_slice(PACKET.as_bytes());
        jpeg.extend_from_slice(&[0xFF, 0xE1]);
        jpeg.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
        jpeg.extend_from_slice(&payload);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        assert_eq!(
            provenance_uri(AssetFormat::Jpeg, &jpeg).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn png_itxt_packet_is_located_and_compressed_packets_are_skipped() {
        let png = png_with_itxt(0);
        assert_eq!(
            provenance_uri(AssetFormat::Png, &png).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
        assert_eq!(provenance_uri(AssetFormat::Png, &png_with_itxt(1)), None);
    }

    fn png_with_itxt(compression_flag: u8) -> Vec<u8> {
        let mut body = PNG_XMP_KEYWORD.to_vec();
        body.push(0);
        body.push(compression_flag);
        body.push(0);
        body.push(0); // empty language tag
        body.push(0); // empty translated keyword
        body.extend_from_slice(PACKET.as_bytes());

        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        png.extend_from_slice(b"iTXt");
        png.extend_from_slice(&body);
        png.extend_from_slice(&[0, 0, 0, 0]);
        png.extend_from_slice(&[0, 0, 0, 0]);
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&[0, 0, 0, 0]);
        png
    }

    #[test]
    fn bmff_uuid_packet_is_located() {
        let mut payload = BMFF_XMP_UUID.to_vec();
        payload.extend_from_slice(PACKET.as_bytes());
        let mut bmff = Vec::new();
        bmff.extend_from_slice(&20u32.to_be_bytes());
        bmff.extend_from_slice(b"ftyp");
        bmff.extend_from_slice(b"isom\0\0\0\0isom");
        bmff.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
        bmff.extend_from_slice(b"uuid");
        bmff.extend_from_slice(&payload);

        assert_eq!(
            provenance_uri(AssetFormat::Bmff, &bmff).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn riff_xmp_chunk_is_located() {
        let packet = PACKET.as_bytes();
        let mut riff = b"RIFF".to_vec();
        riff.extend_from_slice(&u32::try_from(packet.len() + 12).unwrap().to_le_bytes());
        riff.extend_from_slice(b"WEBP");
        riff.extend_from_slice(b"XMP ");
        riff.extend_from_slice(&u32::try_from(packet.len()).unwrap().to_le_bytes());
        riff.extend_from_slice(packet);

        assert_eq!(
            provenance_uri(AssetFormat::Riff, &riff).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn gif_application_extension_packet_is_located() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        gif.extend_from_slice(&[0x21, 0xFF, 0x0B]);
        gif.extend_from_slice(GIF_XMP_APP_ID);
        gif.extend_from_slice(PACKET.as_bytes());
        gif.extend_from_slice(&[0x01, 0xFF, 0xFE, 0x00, 0x00, 0x3B]);

        assert_eq!(
            provenance_uri(AssetFormat::Gif, &gif).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn svg_inline_xmp_is_located() {
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg"><metadata>{PACKET}</metadata></svg>"#
        );
        assert_eq!(
            provenance_uri(AssetFormat::Svg, svg.as_bytes()).as_deref(),
            Some("https://example.test/a.c2pa?v=1&k=2")
        );
    }

    #[test]
    fn a_format_without_a_standard_xmp_location_reports_nothing() {
        assert_eq!(provenance_uri(AssetFormat::Zip, PACKET.as_bytes()), None);
        assert_eq!(
            provenance_uri(AssetFormat::TextUnstructured, PACKET.as_bytes()),
            None
        );
    }

    #[test]
    fn truncated_containers_are_not_errors() {
        assert_eq!(provenance_uri(AssetFormat::Jpeg, &[0xFF, 0xD8, 0xFF]), None);
        assert_eq!(
            provenance_uri(AssetFormat::Png, b"\x89PNG\r\n\x1a\n\x00"),
            None
        );
        assert_eq!(
            provenance_uri(AssetFormat::Riff, b"RIFF\xff\xff\xff\xffWEBP"),
            None
        );
    }
}
