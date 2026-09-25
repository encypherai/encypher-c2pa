# CAWG identity TEST chain

Test material only. No certificate here is trusted by the packaged snapshot,
and no key here protects anything.

## What these files are

| File | Contents |
| --- | --- |
| `root.pem` | P-384 identity root CA, `pathlen:1`, policy 2.23.140.1.5.2.3 |
| `issuing-ca.pem` | P-384 issuing CA below the root, `pathlen:0`, EKU `emailProtection` |
| `leaf.pem` | Organization named-actor leaf, EKU `emailProtection`, policy 2.23.140.1.5.2.3 |
| `leaf-mailbox-policy.pem` | The same leaf profile carrying Mailbox-validated 2.23.140.1.5.1.1, which CAWG Identity 1.3 does not accept |

## Where they come from

`generate_chain.py` calls the production issuance profile,
`encypher_pki.cawg_identity` in the `encypher-pki` package of the
`encypherai-commercial` repository, through
`generate_cawg_identity_root_certificate`,
`generate_cawg_identity_issuing_certificate`, and
`generate_cawg_identity_organization_certificate`. Every extension, curve,
path length, key usage, EKU, AIA, CRL distribution point, and certificate
policy is that profile's own default, so these fixtures carry the exact shapes
Encypher issues.

Three arguments differ from production issuance, and only these three:

1. The subject common names carry TEST.
2. The issuance instant is pinned to 2027-01-01, which places the leaf's
   366-day window around the 2027-06-01 validation time the Rust tests use.
   That date is past the 31 March 2027 interim S/MIME cutoff, which is the
   point: the Encypher trust configuration entry must accept the leaf there
   while the interim entry must not.
3. `leaf-mailbox-policy.pem` passes `policy_oid=2.23.140.1.5.1.1` to the same
   leaf function.

Regenerating mints new keys and serial numbers, but writes certificates only,
so the PEMs change wholesale. The Rust profile test asserts validation behavior
rather than bytes. The command is in the script's docstring.

## What the tests do with them

`c2pa-validate/cawg.rs` keeps these certificates for profile and path
acceptance against the exact `encypher_pki` output. Signing tests mint an
equivalent P-384 chain in memory with `rcgen`, including the same CA path
lengths, key usages, `emailProtection` EKU, and certificate policies. No test
private key is persisted under `crates/`.
