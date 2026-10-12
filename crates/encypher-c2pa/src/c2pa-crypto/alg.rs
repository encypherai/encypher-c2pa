// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE algorithm identifiers (IANA COSE Algorithms registry).

/// A COSE signature algorithm known to this crate.
///
/// The numeric identifiers match the IANA COSE Algorithms registry:
/// ES256 = -7, ES384 = -35, ES512 = -36, PS256/384/512 = -37/-38/-39,
/// EdDSA = -8, ESP256/384/512 = -9/-51/-52 (RFC 9864) and
/// ML-DSA-44/65/87 = -48/-49/-50 (RFC 9964).
///
/// Knowing an algorithm is not permission to accept it: the C2PA revision in
/// force decides that through `ClaimAlgorithmList`.
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
    /// ECDSA with SHA-256 bound to P-256 (RFC 9864 fully specified).
    Esp256,
    /// ECDSA with SHA-384 bound to P-384 (RFC 9864 fully specified).
    Esp384,
    /// ECDSA with SHA-512 bound to P-521 (RFC 9864 fully specified).
    Esp512,
    /// ML-DSA-44, pure mode with an empty context (RFC 9964, FIPS 204).
    MlDsa44,
    /// ML-DSA-65, pure mode with an empty context (RFC 9964, FIPS 204).
    MlDsa65,
    /// ML-DSA-87, pure mode with an empty context (RFC 9964, FIPS 204).
    MlDsa87,
}

impl CoseAlg {
    /// Every algorithm this crate knows, in registry-table order.
    pub const ALL: [CoseAlg; 13] = [
        CoseAlg::Es256,
        CoseAlg::Es384,
        CoseAlg::Es512,
        CoseAlg::Ps256,
        CoseAlg::Ps384,
        CoseAlg::Ps512,
        CoseAlg::EdDsa,
        CoseAlg::Esp256,
        CoseAlg::Esp384,
        CoseAlg::Esp512,
        CoseAlg::MlDsa44,
        CoseAlg::MlDsa65,
        CoseAlg::MlDsa87,
    ];

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
            CoseAlg::Esp256 => -9,
            CoseAlg::Esp384 => -51,
            CoseAlg::Esp512 => -52,
            CoseAlg::MlDsa44 => -48,
            CoseAlg::MlDsa65 => -49,
            CoseAlg::MlDsa87 => -50,
        }
    }

    /// Map a COSE algorithm identifier back to a [`CoseAlg`], if known.
    pub fn from_cose_id(id: i128) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.cose_id() == id)
    }

    /// The IANA registry name (`ES256`, `ESP384`, `ML-DSA-65`, ...).
    pub fn iana_name(self) -> &'static str {
        match self {
            CoseAlg::Es256 => "ES256",
            CoseAlg::Es384 => "ES384",
            CoseAlg::Es512 => "ES512",
            CoseAlg::Ps256 => "PS256",
            CoseAlg::Ps384 => "PS384",
            CoseAlg::Ps512 => "PS512",
            CoseAlg::EdDsa => "EdDSA",
            CoseAlg::Esp256 => "ESP256",
            CoseAlg::Esp384 => "ESP384",
            CoseAlg::Esp512 => "ESP512",
            CoseAlg::MlDsa44 => "ML-DSA-44",
            CoseAlg::MlDsa65 => "ML-DSA-65",
            CoseAlg::MlDsa87 => "ML-DSA-87",
        }
    }

    /// True for the algorithms C2PA 2.5 added to the claim-signature list
    /// (the RFC 9864 ESP identifiers and RFC 9964 ML-DSA).
    pub fn introduced_in_c2pa_2_5(self) -> bool {
        matches!(
            self,
            CoseAlg::Esp256
                | CoseAlg::Esp384
                | CoseAlg::Esp512
                | CoseAlg::MlDsa44
                | CoseAlg::MlDsa65
                | CoseAlg::MlDsa87
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_id_round_trips() {
        for alg in CoseAlg::ALL {
            assert_eq!(CoseAlg::from_cose_id(alg.cose_id()), Some(alg));
        }
    }

    #[test]
    fn known_ids_match_registry() {
        let expected = [
            (CoseAlg::Es256, -7, "ES256"),
            (CoseAlg::Es384, -35, "ES384"),
            (CoseAlg::Es512, -36, "ES512"),
            (CoseAlg::Ps256, -37, "PS256"),
            (CoseAlg::Ps384, -38, "PS384"),
            (CoseAlg::Ps512, -39, "PS512"),
            (CoseAlg::EdDsa, -8, "EdDSA"),
            (CoseAlg::Esp256, -9, "ESP256"),
            (CoseAlg::Esp384, -51, "ESP384"),
            (CoseAlg::Esp512, -52, "ESP512"),
            (CoseAlg::MlDsa44, -48, "ML-DSA-44"),
            (CoseAlg::MlDsa65, -49, "ML-DSA-65"),
            (CoseAlg::MlDsa87, -50, "ML-DSA-87"),
        ];
        for (alg, id, name) in expected {
            assert_eq!(alg.cose_id(), id);
            assert_eq!(alg.iana_name(), name);
        }
    }

    #[test]
    fn unknown_id_is_none() {
        assert_eq!(CoseAlg::from_cose_id(0), None);
        assert_eq!(CoseAlg::from_cose_id(-100), None);
        // RFC 9864 also registers fully specified Ed25519 (-19) and Ed448
        // (-53); the C2PA 2.5 list names only EdDSA (-8), Ed25519 instance.
        assert_eq!(CoseAlg::from_cose_id(-19), None);
        assert_eq!(CoseAlg::from_cose_id(-53), None);
    }
}
