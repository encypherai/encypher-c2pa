//! C2PA unstructured-text variation-selector codec.
//!
//! C2PA Technical Specification A.8 encodes wrapper bytes with the 256
//! standardized Unicode variation selectors. This module contains only that
//! standard byte-to-selector mapping.

const VS1_START: u32 = 0xFE00;
const VS1_END: u32 = 0xFE0F;
const VS17_START: u32 = 0xE0100;
const VS17_END: u32 = 0xE01EF;

/// Map one byte to its C2PA A.8 variation selector.
pub fn byte_to_vs(byte: u8) -> char {
    let codepoint = if byte < 16 {
        VS1_START + u32::from(byte)
    } else {
        VS17_START + u32::from(byte) - 16
    };
    char::from_u32(codepoint).expect("variation selector mapping is valid Unicode")
}

/// Decode one C2PA A.8 variation selector into its byte value.
pub fn vs_to_byte(character: char) -> Option<u8> {
    let codepoint = character as u32;
    if (VS1_START..=VS1_END).contains(&codepoint) {
        Some((codepoint - VS1_START) as u8)
    } else if (VS17_START..=VS17_END).contains(&codepoint) {
        Some((codepoint - VS17_START + 16) as u8)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{byte_to_vs, vs_to_byte};

    #[test]
    fn all_byte_values_round_trip() {
        for byte in 0..=u8::MAX {
            assert_eq!(vs_to_byte(byte_to_vs(byte)), Some(byte));
        }
    }
}
