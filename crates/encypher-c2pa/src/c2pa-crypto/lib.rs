// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! COSE_Sign1 verification and header extraction for C2PA claims.
//!
//! The verifier reconstructs the detached RFC 9052 `Sig_structure`, validates
//! the signature with the certificate public key, and exposes the certificate,
//! timestamp, and OCSP headers needed by the C2PA trust layer. It also
//! verifies the X.509 signatures (certificates, OCSP, CMS) that layer checks.

mod alg;
mod cose;
mod error;
mod mldsa;
mod session;
mod timestamp;
mod x509_signature;

pub(crate) use alg::CoseAlg;
pub(crate) use cose::{
    extract_claim_tsa_tokens, extract_cose_alg, extract_tsa_tokens, extract_x5chain,
    timestamp_input, timestamp_input_v1, verify_claim, verify_claim_with, visit_ocsp_staples,
    ClaimAlgorithmList, ClaimTimestampVersion,
};
pub(crate) use error::CryptoError;
pub(crate) use mldsa::ml_dsa_spki_alg;
pub(crate) use session::{cose_key_id, verify_with_cose_key, verify_with_cose_key_with};
pub(crate) use timestamp::{
    parse_timestamp_header, protected_iat, timestamp_assertion_input, TimestampHeader,
    TimestampHeaderDefect, TimestampHeaderEvidence, TimestampHeaderVersion,
};
pub(crate) use x509_signature::verify_x509_signature;

#[cfg(test)]
mod rsassa_pss_spki;
