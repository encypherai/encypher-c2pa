// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE_Sign1 verification and header extraction for C2PA claims.
//!
//! The verifier reconstructs the detached RFC 9052 `Sig_structure`, validates
//! the signature with the certificate public key, and exposes the certificate,
//! timestamp, and OCSP headers needed by the C2PA trust layer.

mod alg;
mod cose;
mod error;
mod session;
mod timestamp;

pub(crate) use alg::CoseAlg;
pub(crate) use cose::{
    extract_claim_tsa_tokens, extract_cose_alg, extract_tsa_tokens, extract_x5chain,
    timestamp_input, timestamp_input_v1, verify_claim, visit_ocsp_staples, ClaimTimestampVersion,
};
pub(crate) use error::CryptoError;
pub(crate) use session::{cose_key_id, verify_with_cose_key};
pub(crate) use timestamp::{
    parse_timestamp_header, protected_iat, timestamp_assertion_input, TimestampHeader,
    TimestampHeaderDefect, TimestampHeaderEvidence, TimestampHeaderVersion,
};

#[cfg(test)]
mod rsassa_pss_spki;
