//! Error type for COSE verification.

use crate::c2pa_cbor::{DecodeError, EncodeError};

/// Errors produced while verifying COSE_Sign1 structures.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The COSE `alg` header value does not map to a supported algorithm.
    #[error("unsupported COSE algorithm id: {0}")]
    UnsupportedAlg(i128),

    /// CBOR encoding failed while building a COSE structure.
    #[error("CBOR encode failed: {0}")]
    Encode(#[from] EncodeError),

    /// CBOR decoding failed while parsing a COSE structure.
    #[error("CBOR decode failed: {0}")]
    Decode(#[from] DecodeError),

    /// The COSE_Sign1 structure was malformed (wrong tag, shape, or missing field).
    #[error("malformed COSE_Sign1: {0}")]
    Malformed(String),

    /// An end-entity certificate could not be parsed or its public key extracted.
    #[error("certificate parse failed: {0}")]
    CertParse(String),

    /// Signature verification failed (bad signature, wrong key, or tampered payload).
    #[error("signature verification failed: {0}")]
    Verify(String),
}
