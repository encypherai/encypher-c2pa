//! Regression: COSE verification with an id-RSASSA-PSS SubjectPublicKeyInfo.
//!
//! 1.x-era C2PA signing certificates in the wild carry an id-RSASSA-PSS
//! (1.2.840.113549.1.1.10) SPKI rather than rsaEncryption; RustCrypto's
//! `rsa::RsaPublicKey::from_public_key_der` rejects that form, which used to
//! fail every such signature with `claimSignature.mismatch`. The verifier now
//! accepts both SPKI forms (`rsa_public_key_from_spki` in `cose.rs`).
//!
//! Fixtures are SELF-GENERATED, verify-only, and contain NO private key:
//! an RSA-PSS 4096 keypair was created with openssl (`genpkey -algorithm
//! RSA-PSS`), self-signed into `pss_spki_cert.{pem,der}`, used once by our own
//! CLI signer to produce `pss_spki.cose` over `pss_spki.claim.cbor`, and then
//! destroyed. Regenerating the fixtures requires repeating those steps; the
//! SPKI-OID guard test below fails loudly if a regenerated cert silently
//! stops carrying the id-RSASSA-PSS form.

use crate::c2pa_crypto::verify_claim;

const CERT_DER: &[u8] = include_bytes!("fixtures/pss_spki_cert.der");
const COSE: &[u8] = include_bytes!("fixtures/pss_spki.cose");
const CLAIM: &[u8] = include_bytes!("fixtures/pss_spki.claim.cbor");

#[test]
fn fixture_cert_spki_is_rsassa_pss() {
    // Guard: the fixture only exercises the regression while its SPKI stays
    // id-RSASSA-PSS (1.2.840.113549.1.1.10).
    const ID_RSASSA_PSS_OID_DER: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    ];
    assert!(
        CERT_DER
            .windows(ID_RSASSA_PSS_OID_DER.len())
            .any(|w| w == ID_RSASSA_PSS_OID_DER),
        "fixture certificate no longer carries an id-RSASSA-PSS SPKI"
    );
}

#[test]
fn ps256_cose_verifies_against_rsassa_pss_spki_cert() {
    verify_claim(COSE, CLAIM, CERT_DER)
        .expect("PS256 COSE must verify against an id-RSASSA-PSS SPKI certificate");
}

#[test]
fn ps256_cose_rejects_tampered_claim_with_rsassa_pss_spki_cert() {
    let mut bad = CLAIM.to_vec();
    bad[10] ^= 0xFF;
    assert!(verify_claim(COSE, &bad, CERT_DER).is_err());
}
