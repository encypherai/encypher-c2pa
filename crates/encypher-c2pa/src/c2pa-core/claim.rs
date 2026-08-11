//! C2PA Claim v2 construction (CBOR).
//!
//! Claim v2 allows only these fields:
//! `instanceID`,
//! `claim_generator_info`, `signature`, `created_assertions`,
//! `gathered_assertions`, `dc:title`, `redacted_assertions`, `alg`, `alg_soft`,
//! `metadata`. v1 fields (`claim_generator`, `dc:format`, `assertions`) are
//! rejected.
//!
//! Assertion hashing (C2PA spec 14.2.3): the hash is over the referenced box's
//! JUMBF content (description + content boxes), excluding the superbox
//! `LBox+TBox` header.

#[cfg(test)]
use crate::c2pa_cbor::encode;
use crate::c2pa_cbor::{map_from_pairs, Profile, Value};
#[cfg(test)]
use sha2::{Digest, Sha256};

/// Hash algorithm identifier strings per C2PA spec.
pub const HASH_ALG_SHA256: &str = "sha256";

/// A claim-generator-info entry: name, version, optional spec version.
#[derive(Debug, Clone)]
pub struct ClaimGeneratorInfo {
    /// Generator product name, e.g. `"Encypher Enterprise API/1.0"`.
    pub name: String,
    /// Generator version string.
    pub version: String,
    /// C2PA spec version, e.g. `"2.2"`.
    pub spec_version: Option<String>,
    /// Optional `org.contentauth.c2pa_rs` compat value (e.g. `"0.78.4"`).
    /// Preserved for byte-parity with the certified baseline.
    pub c2pa_rs: Option<String>,
}

impl ClaimGeneratorInfo {
    /// Build the CBOR map for this generator-info entry.
    ///
    /// Field order matches the Pipeline B / c2pa-rs SSOT: name, version,
    /// (org.contentauth.c2pa_rs), (specVersion).
    pub fn to_value(&self) -> Value {
        let mut pairs: Vec<(String, Value)> = vec![
            ("name".into(), Value::Text(self.name.clone())),
            ("version".into(), Value::Text(self.version.clone())),
        ];
        if let Some(rs) = &self.c2pa_rs {
            pairs.push(("org.contentauth.c2pa_rs".into(), Value::Text(rs.clone())));
        }
        if let Some(sv) = &self.spec_version {
            pairs.push(("specVersion".into(), Value::Text(sv.clone())));
        }
        map_from_pairs(pairs)
    }
}

/// An assertion to be referenced and hashed in the claim.
pub struct AssertionRef<'a> {
    /// Assertion label, e.g. `"c2pa.actions.v2"`.
    pub label: &'a str,
    /// The assertion's JUMBF content (description + content boxes, WITHOUT the
    /// superbox LBox+TBox header) — this is what gets hashed per spec 14.2.3.
    pub jumbf_content: &'a [u8],
}

/// Compute the SHA-256 of an assertion's JUMBF content. Write path only.
#[cfg(test)]
fn hash_assertion(content: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(content);
    h.finalize().to_vec()
}

/// Build a hashed-URI reference value for one assertion. Write path only.
#[cfg(test)]
fn assertion_ref_value(label: &str, content: &[u8]) -> Value {
    map_from_pairs([
        (
            "url".into(),
            Value::Text(format!("self#jumbf=c2pa.assertions/{label}")),
        ),
        ("hash".into(), Value::Bytes(hash_assertion(content))),
        ("alg".into(), Value::Text(HASH_ALG_SHA256.into())),
    ])
}

/// Options for building a claim.
pub struct ClaimOptions<'a> {
    /// Manifest URN label, e.g. `"urn:c2pa:<uuid>"`.
    pub manifest_label: &'a str,
    /// Instance ID, e.g. `"urn:uuid:<uuid>"`. Injected for deterministic tests.
    pub instance_id: &'a str,
    /// Claim generator info.
    pub generator: &'a ClaimGeneratorInfo,
    /// Optional asset title.
    pub title: Option<&'a str>,
    /// Hash algorithm identifier (currently `"sha256"`).
    pub alg: &'a str,
    /// CBOR encoder profile — selects Pipeline A (indefinite) vs B (definite).
    pub profile: Profile,
}

/// Build the claim as a CBOR [`Value`] (before encoding).
///
/// The `created_assertions` array holds hashed references to each assertion.
///
/// Claim construction is not part of the verification surface; it exists for
/// in-repo fixture generation only. Private module plus `cfg(test)`, so it is
/// unreachable from a consumer and absent from the shipped build.
#[cfg(test)]
pub fn build_claim_value(opts: &ClaimOptions, assertions: &[AssertionRef]) -> Value {
    let refs: Vec<Value> = assertions
        .iter()
        .map(|a| assertion_ref_value(a.label, a.jumbf_content))
        .collect();

    let mut pairs: Vec<(String, Value)> = vec![
        (
            "instanceID".into(),
            Value::Text(opts.instance_id.to_string()),
        ),
        ("claim_generator_info".into(), opts.generator.to_value()),
        (
            "signature".into(),
            Value::Text(format!(
                "self#jumbf=/c2pa/{}/c2pa.signature",
                opts.manifest_label
            )),
        ),
        ("created_assertions".into(), Value::Array(refs)),
        ("alg".into(), Value::Text(opts.alg.to_string())),
    ];
    if let Some(t) = opts.title {
        pairs.push(("dc:title".into(), Value::Text(t.to_string())));
    }
    map_from_pairs(pairs)
}

/// Build the CBOR-encoded claim bytes using the options' profile.
///
/// Fixture generation only; see [`build_claim_value`].
#[cfg(test)]
pub fn build_claim_cbor(
    opts: &ClaimOptions,
    assertions: &[AssertionRef],
) -> Result<Vec<u8>, crate::c2pa_cbor::EncodeError> {
    let claim = build_claim_value(opts, assertions);
    encode(&claim, opts.profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_info() -> ClaimGeneratorInfo {
        ClaimGeneratorInfo {
            name: "Encypher Enterprise API/1.0".into(),
            version: "1.0".into(),
            spec_version: Some("2.2".into()),
            c2pa_rs: Some("0.78.4".into()),
        }
    }

    #[test]
    fn claim_has_required_v2_fields_only() {
        let gen = gen_info();
        let opts = ClaimOptions {
            manifest_label: "urn:c2pa:abc",
            instance_id: "urn:uuid:def",
            generator: &gen,
            title: Some("Test"),
            alg: HASH_ALG_SHA256,
            profile: Profile::LegacyPipelineBDefinite,
        };
        let assertions = [AssertionRef {
            label: "c2pa.actions.v2",
            jumbf_content: b"dummy",
        }];
        let claim = build_claim_value(&opts, &assertions);
        // Required fields present
        assert!(claim.get("instanceID").is_some());
        assert!(claim.get("claim_generator_info").is_some());
        assert!(claim.get("signature").is_some());
        assert!(claim.get("created_assertions").is_some());
        assert!(claim.get("alg").is_some());
        assert!(claim.get("dc:title").is_some());
        // v1-only fields MUST be absent
        assert!(claim.get("claim_generator").is_none());
        assert!(claim.get("dc:format").is_none());
        assert!(claim.get("assertions").is_none());
    }

    #[test]
    fn signature_uri_references_manifest() {
        let gen = gen_info();
        let opts = ClaimOptions {
            manifest_label: "urn:c2pa:xyz",
            instance_id: "urn:uuid:1",
            generator: &gen,
            title: None,
            alg: HASH_ALG_SHA256,
            profile: Profile::LegacyPipelineBDefinite,
        };
        let claim = build_claim_value(&opts, &[]);
        assert_eq!(
            claim.get("signature").and_then(|v| v.as_text()),
            Some("self#jumbf=/c2pa/urn:c2pa:xyz/c2pa.signature")
        );
    }

    #[test]
    fn assertion_hash_is_sha256_of_content() {
        let content = b"hello assertion";
        let mut h = Sha256::new();
        h.update(content);
        let expected = h.finalize().to_vec();
        let v = assertion_ref_value("c2pa.actions.v2", content);
        assert_eq!(
            v.get("hash").and_then(|x| x.as_bytes()),
            Some(&expected[..])
        );
    }

    #[test]
    fn generator_info_preserves_c2pa_rs_compat_field() {
        let gen = gen_info();
        let v = gen.to_value();
        assert_eq!(
            v.get("org.contentauth.c2pa_rs").and_then(|x| x.as_text()),
            Some("0.78.4")
        );
        assert_eq!(v.get("specVersion").and_then(|x| x.as_text()), Some("2.2"));
    }

    #[test]
    fn profile_controls_claim_encoding() {
        let gen = gen_info();
        let opts_def = ClaimOptions {
            manifest_label: "urn:c2pa:a",
            instance_id: "urn:uuid:b",
            generator: &gen,
            title: None,
            alg: HASH_ALG_SHA256,
            profile: Profile::LegacyPipelineBDefinite,
        };
        let def = build_claim_cbor(&opts_def, &[]).unwrap();
        // definite map header in 0xa0..0xb7 range
        assert!((0xa0..=0xb7).contains(&def[0]));

        let opts_indef = ClaimOptions {
            profile: Profile::LegacyC2paRs0784Indefinite,
            ..opts_def
        };
        let indef = build_claim_cbor(&opts_indef, &[]).unwrap();
        assert_eq!(indef[0], 0xbf); // indefinite map
    }
}
