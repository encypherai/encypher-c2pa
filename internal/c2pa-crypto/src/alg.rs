//! COSE algorithm identifiers (IANA COSE Algorithms registry).

/// A COSE signature algorithm supported by this crate.
///
/// The numeric identifiers match the IANA COSE Algorithms registry and the
/// reference Python implementation (`cose_signer.py`):
/// ES256 = -7, ES384 = -35, ES512 = -36, PS256 = -37, EdDSA = -8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlg {
    /// ECDSA with SHA-256 and any C2PA-permitted NIST EC key.
    Es256,
    /// ECDSA with SHA-384 and any C2PA-permitted NIST EC key.
    Es384,
    /// ECDSA with SHA-512 and any C2PA-permitted NIST EC key.
    Es512,
    /// RSASSA-PSS with SHA-256 (MGF1-SHA256, salt length 32).
    Ps256,
    /// RSASSA-PSS with SHA-384 (MGF1-SHA384, salt length 48).
    Ps384,
    /// RSASSA-PSS with SHA-512 (MGF1-SHA512, salt length 64).
    Ps512,
    /// EdDSA (Ed25519).
    EdDsa,
}

impl CoseAlg {
    /// The COSE algorithm identifier as stored in the protected header `{1: alg}`.
    pub fn cose_id(self) -> i128 {
        match self {
            CoseAlg::Es256 => -7,
            CoseAlg::Es384 => -35,
            CoseAlg::Es512 => -36,
            CoseAlg::Ps256 => -37,
            CoseAlg::Ps384 => -38,
            CoseAlg::Ps512 => -39,
            CoseAlg::EdDsa => -8,
        }
    }

    /// Map a COSE algorithm identifier back to a [`CoseAlg`], if supported.
    pub fn from_cose_id(id: i128) -> Option<Self> {
        match id {
            -7 => Some(CoseAlg::Es256),
            -35 => Some(CoseAlg::Es384),
            -36 => Some(CoseAlg::Es512),
            -37 => Some(CoseAlg::Ps256),
            -38 => Some(CoseAlg::Ps384),
            -39 => Some(CoseAlg::Ps512),
            -8 => Some(CoseAlg::EdDsa),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_id_round_trips() {
        for alg in [
            CoseAlg::Es256,
            CoseAlg::Es384,
            CoseAlg::Es512,
            CoseAlg::Ps256,
            CoseAlg::EdDsa,
        ] {
            assert_eq!(CoseAlg::from_cose_id(alg.cose_id()), Some(alg));
        }
    }

    #[test]
    fn known_ids_match_registry() {
        assert_eq!(CoseAlg::Es256.cose_id(), -7);
        assert_eq!(CoseAlg::Es384.cose_id(), -35);
        assert_eq!(CoseAlg::Es512.cose_id(), -36);
        assert_eq!(CoseAlg::Ps256.cose_id(), -37);
        assert_eq!(CoseAlg::EdDsa.cose_id(), -8);
    }

    #[test]
    fn unknown_id_is_none() {
        assert_eq!(CoseAlg::from_cose_id(0), None);
        assert_eq!(CoseAlg::from_cose_id(-100), None);
    }
}
