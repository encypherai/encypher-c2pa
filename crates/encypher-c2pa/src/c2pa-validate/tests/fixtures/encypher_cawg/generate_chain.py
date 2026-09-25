#!/usr/bin/env python3
# Copyright 2026 Encypher Corporation
# SPDX-License-Identifier: Apache-2.0

"""Generate the CAWG identity TEST chain vendored beside this script.

The certificates are built by the production issuance profile in
``encypher_pki.cawg_identity`` so the verifier is tested against the exact
shapes Encypher issues: a P-384 root CA with pathlen 1, an emailProtection
issuing CA with pathlen 0, and an organization named-actor leaf carrying the
Organization-validated Strict certificate policy (2.23.140.1.5.2.3).

Nothing here is production key material. Keys are minted only to issue the
certificate fixtures and are never written to disk. The subject common names
carry TEST, so a fixture certificate can never be
confused with the Encypher Organizational Identity Root CA 2026 that
``default_trust/encypher-identity-root.pem`` carries.

Run it against the commercial PKI package, which this repository does not
depend on and does not vendor:

    PYTHONPATH=<encypherai-commercial>/packages/encypher-pki/src \\
        uv run --with cryptography python generate_chain.py

Regenerating mints fresh keys and random serial numbers, so the vendored
certificates change wholesale. The Rust profile test pins behavior, not bytes,
so that is safe. Signing tests mint a separate equivalent chain in memory.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ObjectIdentifier

from encypher_pki.cawg_identity import (
    generate_cawg_identity_issuing_certificate,
    generate_cawg_identity_organization_certificate,
    generate_cawg_identity_root_certificate,
)

# Fixed issuance instant. The leaf profile caps validity at 366 days, so the
# Rust tests validate at 2027-06-01, which is inside every window below and
# past the 31 March 2027 interim S/MIME cutoff.
ISSUED_AT = datetime(2027, 1, 1, tzinfo=timezone.utc)

# Mailbox-validated. CAWG Identity 1.3 lists the six Organization, Sponsor and
# Individual policies and calls out that this one is not among them.
MAILBOX_VALIDATED_POLICY_OID = ObjectIdentifier("2.23.140.1.5.1.1")

HERE = Path(__file__).resolve().parent


def write(name: str, text: str) -> None:
    (HERE / name).write_text(text, encoding="ascii")


def pem(certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def main() -> None:
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = generate_cawg_identity_root_certificate(
        root_key.public_key(),
        private_key=root_key,
        common_name="Encypher Organizational Identity TEST Root CA",
        now=ISSUED_AT,
    )

    issuing_key = ec.generate_private_key(ec.SECP384R1())
    issuing = generate_cawg_identity_issuing_certificate(
        issuing_key.public_key(),
        root,
        root_private_key=root_key,
        common_name="Encypher CAWG Identity TEST Issuing CA",
        now=ISSUED_AT,
    )

    leaf_key = ec.generate_private_key(ec.SECP384R1())
    leaf = generate_cawg_identity_organization_certificate(
        leaf_key.public_key(),
        issuing,
        issuing_private_key=issuing_key,
        organization_name="Encypher Fixture Publisher",
        country_code="US",
        email_address="identity@fixture.encypher.test",
        common_name="Encypher Fixture Publisher TEST",
        now=ISSUED_AT,
    )

    mailbox_key = ec.generate_private_key(ec.SECP384R1())
    mailbox_leaf = generate_cawg_identity_organization_certificate(
        mailbox_key.public_key(),
        issuing,
        issuing_private_key=issuing_key,
        organization_name="Encypher Fixture Publisher",
        country_code="US",
        email_address="mailbox@fixture.encypher.test",
        common_name="Encypher Fixture Mailbox Policy TEST",
        policy_oid=MAILBOX_VALIDATED_POLICY_OID,
        now=ISSUED_AT,
    )

    write("root.pem", pem(root))
    write("issuing-ca.pem", pem(issuing))
    write("leaf.pem", pem(leaf))
    write("leaf-mailbox-policy.pem", pem(mailbox_leaf))


if __name__ == "__main__":
    main()
