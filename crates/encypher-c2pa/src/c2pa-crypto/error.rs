// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Error type for COSE verification.

use crate::c2pa_cbor::{DecodeError, EncodeError};

/// Errors produced while verifying COSE_Sign1 structures.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The COSE `alg` header value is unknown, or is not on the claim
    /// signature list of the C2PA revision being applied.
    #[error("unsupported COSE algorithm id: {0}")]
    UnsupportedAlg(i128),

    /// An X.509 AlgorithmIdentifier names a signature algorithm this crate
    /// does not verify (certificates, OCSP responses, CMS SignerInfos).
    #[error("unsupported X.509 signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),

    /// CBOR encoding failed while building a COSE structure.
    #[error("CBOR encode failed: {0}")]
    Encode(#[from] EncodeError),

    /// CBOR decoding failed while parsing a COSE structure.
    #[error("CBOR decode failed: {0}")]
    Decode(#[from] DecodeError),

    /// The COSE_Sign1 structure was malformed (wrong tag, shape, or missing field).
    #[error("malformed COSE_Sign1: {0}")]
    Malformed(String),

    /// The `COSE_Sign1` payload field was not `nil`. C2PA signs claims in
    /// detached content mode, so any carried payload (including an empty byte
    /// string) is a non-conformant claim signature.
    #[error("COSE_Sign1 payload is not nil (detached content mode is required)")]
    PayloadNotDetached,

    /// An end-entity certificate could not be parsed or its public key extracted.
    #[error("certificate parse failed: {0}")]
    CertParse(String),

    /// A COSE_Key could not be parsed or does not match its declared algorithm.
    #[error("COSE_Key parse failed: {0}")]
    KeyParse(String),

    /// Signature verification failed (bad signature, wrong key, or tampered payload).
    #[error("signature verification failed: {0}")]
    Verify(String),
}
