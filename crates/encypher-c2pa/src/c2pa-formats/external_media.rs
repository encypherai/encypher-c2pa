// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Explicit, byte-checked admission for media without an embedded C2PA carrier.
//! These checks identify container signatures; they do not validate playback.
//! C2PA 2.4 permits external manifests where embedding is not possible.

use super::{AssetFormat, FormatError};

pub(super) const EXTERNAL_MEDIA_MIMES: &[&str] = &[
    "video/webm",
    "audio/webm",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/bmp",
    "audio/aac",
    "font/woff",
    "font/woff2",
];

const FMT: AssetFormat = AssetFormat::ExternalMedia;

fn invalid(detail: &'static str) -> FormatError {
    FormatError::InvalidStructure {
        format: FMT,
        detail,
    }
}

/// Keep raw ADTS distinct from the legacy AAC-to-MP4 embedded alias.
pub(crate) fn canonicalize_detached_mime(mime: &str) -> String {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    if base.eq_ignore_ascii_case("audio/aac") {
        "audio/aac".to_string()
    } else {
        crate::c2pa_core::spec::canonicalize_mime(mime)
    }
}

pub(super) fn is_bmff(data: &[u8]) -> bool {
    data.get(4..8) == Some(b"ftyp".as_slice())
}

fn skip_id3v2(data: &[u8]) -> Result<&[u8], FormatError> {
    if !data.starts_with(b"ID3") {
        return Ok(data);
    }
    let header = data.get(..10).ok_or(FormatError::Truncated(FMT))?;
    let size_bytes = &header[6..10];
    if size_bytes.iter().any(|byte| byte & 0x80 != 0) {
        return Err(invalid("ID3v2 tag size is not synchsafe"));
    }
    let size = size_bytes
        .iter()
        .fold(0usize, |acc, byte| (acc << 7) | usize::from(*byte));
    let footer = if header[5] & 0x10 != 0 { 10 } else { 0 };
    let end = 10usize
        .checked_add(size)
        .and_then(|end| end.checked_add(footer))
        .ok_or_else(|| invalid("ID3v2 tag size overflows"))?;
    data.get(end..).ok_or(FormatError::Truncated(FMT))
}

fn check_adts(data: &[u8]) -> Result<(), FormatError> {
    let frame = skip_id3v2(data)?;
    let header = frame.get(..7).ok_or(FormatError::Truncated(FMT))?;
    if header[0] != 0xFF || header[1] & 0xF6 != 0xF0 {
        return Err(invalid("raw AAC must begin with an ADTS frame header"));
    }
    let header_len = if header[1] & 0x01 == 1 { 7 } else { 9 };
    let frame_len = (usize::from(header[3] & 0x03) << 11)
        | (usize::from(header[4]) << 3)
        | (usize::from(header[5]) >> 5);
    if frame_len < header_len {
        return Err(invalid("ADTS frame length is shorter than its header"));
    }
    Ok(())
}

fn check_ico(data: &[u8]) -> Result<(), FormatError> {
    let header = data.get(..6).ok_or(FormatError::Truncated(FMT))?;
    if header[..4] != [0x00, 0x00, 0x01, 0x00] {
        return Err(invalid("ICO must begin with an icon directory header"));
    }
    if u16::from_le_bytes([header[4], header[5]]) == 0 {
        return Err(invalid("ICO directory lists no images"));
    }
    Ok(())
}

fn check_bmp(data: &[u8]) -> Result<(), FormatError> {
    let header = data.get(..18).ok_or(FormatError::Truncated(FMT))?;
    if &header[..2] != b"BM" {
        return Err(invalid("BMP must begin with the BM file header"));
    }
    let dib = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
    if !matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124) {
        return Err(invalid("BMP DIB header size is not a defined variant"));
    }
    Ok(())
}

fn check_signature(data: &[u8], signature: &[u8], detail: &'static str) -> Result<(), FormatError> {
    if data.len() < signature.len() {
        return Err(FormatError::Truncated(FMT));
    }
    if !data.starts_with(signature) {
        return Err(invalid(detail));
    }
    Ok(())
}

// Read only the finite EBML header, not a Matroska carrier. IDs retain their
// marker bit; sizes remove it and must not use the unknown-size sentinel.
fn vint(data: &mut &[u8], id: bool) -> Result<u64, FormatError> {
    let first = *data.first().ok_or(FormatError::Truncated(FMT))?;
    let width = first.leading_zeros() as usize + 1;
    if width > if id { 4 } else { 8 } {
        return Err(invalid("EBML variable integer exceeds permitted width"));
    }
    let bytes = data.get(..width).ok_or(FormatError::Truncated(FMT))?;
    let mut value = u64::from(if id {
        first
    } else {
        first & ((1u8 << (8 - width)) - 1)
    });
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    if !id && value == (1u64 << (7 * width)) - 1 {
        return Err(invalid("EBML header element has unknown size"));
    }
    *data = &data[width..];
    Ok(value)
}

fn element<'a>(data: &mut &'a [u8]) -> Result<(u64, &'a [u8]), FormatError> {
    let id = vint(data, true)?;
    let size = usize::try_from(vint(data, false)?)
        .map_err(|_| invalid("EBML element size exceeds platform limits"))?;
    let payload = data.get(..size).ok_or(FormatError::Truncated(FMT))?;
    *data = &data[size..];
    Ok((id, payload))
}

fn webm_doc_type(mut data: &[u8]) -> Result<&[u8], FormatError> {
    let (id, mut header) = element(&mut data)?;
    if id != 0x1A45_DFA3 {
        return Err(invalid("missing finite EBML header"));
    }
    let mut doc_type = None;
    while !header.is_empty() {
        let (id, payload) = element(&mut header)?;
        if id == 0x4282 && doc_type.is_none() {
            doc_type = Some(payload);
        }
    }
    doc_type.ok_or_else(|| invalid("EBML header declares no DocType"))
}

pub(super) fn check(canonical_mime: &str, data: &[u8]) -> Result<(), FormatError> {
    match canonical_mime {
        "video/webm" | "audio/webm" => {
            let doc_type = webm_doc_type(data)?;
            let end = doc_type
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(doc_type.len());
            if &doc_type[..end] != b"webm" {
                return Err(invalid("WebM must declare the EBML DocType webm"));
            }
            Ok(())
        }
        "image/x-icon" | "image/vnd.microsoft.icon" => check_ico(data),
        "image/bmp" => check_bmp(data),
        "audio/aac" => check_adts(data),
        "font/woff" => check_signature(data, b"wOFF", "WOFF must begin with wOFF"),
        "font/woff2" => check_signature(data, b"wOF2", "WOFF2 must begin with wOF2"),
        _ => Err(FormatError::NotImplemented(FMT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_media_rejects_wrong_signatures_and_truncated_headers() {
        for mime in EXTERNAL_MEDIA_MIMES {
            assert!(
                AssetFormat::from_detached_content(mime, b"\xff\xd8JPEG").is_err(),
                "{mime}"
            );
            assert!(
                AssetFormat::from_detached_content(mime, &[]).is_err(),
                "{mime}"
            );
        }
        assert!(check_ico(&[0, 0, 2, 0, 1, 0]).is_err());
        assert!(check_ico(&[0, 0, 1, 0, 0, 0]).is_err());
    }

    #[test]
    fn external_media_aac_dispatch_preserves_legacy_bmff() {
        assert_eq!(
            AssetFormat::from_detached_content("audio/aac", b"\0\0\0\x18ftypmp42").unwrap(),
            Some(AssetFormat::Bmff)
        );
        let adts = [0xff, 0xf1, 0x50, 0x80, 0x00, 0xff, 0xfc];
        assert_eq!(
            AssetFormat::from_detached_content("AUDIO/AAC; codecs=aac", &adts).unwrap(),
            Some(FMT)
        );
        let mut tagged = b"ID3\x04\0\x10\0\0\0\0".to_vec();
        tagged.extend_from_slice(&[0; 10]);
        tagged.extend_from_slice(&adts);
        assert_eq!(
            AssetFormat::from_detached_content("audio/aac", &tagged).unwrap(),
            Some(FMT)
        );
    }

    #[test]
    fn external_media_webm_requires_finite_header_and_webm_doctype() {
        let webm = b"\x1a\x45\xdf\xa3\x87\x42\x82\x84webm";
        assert_eq!(
            AssetFormat::from_detached_content("video/webm", webm).unwrap(),
            Some(FMT)
        );
        assert!(check("video/webm", b"\x1a\x45\xdf\xa3\xff").is_err());
        assert!(check("video/webm", b"\x1a\x45\xdf\xa3\x8b\x42\x82\x88matroska").is_err());
        assert!(check("video/webm", b"\x1a\x45\xdf\xa3\x87\x42\x82\x85webm").is_err());
    }
}
