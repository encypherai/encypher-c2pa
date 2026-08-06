#!/usr/bin/env python3
"""Fetch, index, and verify the pinned external CAWG interoperability corpus.

Normal CI uses ``check`` and performs no network access. ``fetch`` is a maintainer
operation that downloads only immutable Git revisions, then verifies the SHA-256
values already recorded in corpus.json. ``update`` rewrites corpus.json from the
curated table and local bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parent
INDEX: Final = ROOT / "corpus.json"
RS_COMMIT: Final = "d7f13829ff4416c9254534885aa6f2ffc71d98f1"
CPP_COMMIT: Final = "357f0fc5deb07ad629856728699804d67bf4f1c0"
VALIDATION_TIME: Final = "2025-05-01T00:00:00Z"
# Some fixture credentials declare a validFrom after the default clock; those
# vectors pin a later clock so the observation reflects the targeted failure
# mode rather than a clock artifact.
LATE_VALIDATION_TIME: Final = "2025-09-01T00:00:00Z"

X509_EXPECTED: Final = {
    "duplicate_assertion_reference": ["cawg.identity.assertion.duplicate"],
    "extra_assertion_claim_v1": ["cawg.identity.assertion.mismatch"],
    "extra_field": ["cawg.identity.well-formed"],
    "invalid_sig_type": ["cawg.identity.sig_type.unknown"],
    "malformed_cbor": ["cawg.identity.cbor.invalid"],
    "no_hard_binding": ["cawg.identity.hard_binding_missing"],
    "pad1_invalid": ["cawg.identity.pad.invalid"],
    "pad2_invalid": ["cawg.identity.pad.invalid"],
}
# What this SDK observes today; kept separate so any future divergence is an
# explicit, reviewed override rather than a silent expectation change.
X509_OBSERVED: Final = {**X509_EXPECTED}
# Upstream c2pa-rs (pinned commit) test expectations where they differ from our
# normative codes: the extra_field test asserts ZERO logged items (no failure
# and, temporarily, no success status), while our verifier reports its
# well-formed/trusted verdict explicitly.
X509_UPSTREAM: Final = {**X509_EXPECTED, "extra_field": []}
ICA_EXPECTED: Final = {
    "did_doc_without_assertion_method": ["cawg.ica.invalid_did_document"],
    "invalid_content_type": ["cawg.ica.invalid_content_type"],
    "invalid_content_type_assigned": ["cawg.ica.invalid_content_type"],
    "invalid_cose_sign1": ["cawg.ica.invalid_cose_sign1"],
    "invalid_cose_sign_alg": ["cawg.ica.invalid_alg"],
    "invalid_issuer_did": ["cawg.ica.invalid_issuer"],
    "invalid_time_stamp": ["cawg.ica.time_stamp.invalid"],
    "invalid_vc": ["cawg.ica.invalid_verifiable_credential"],
    "missing_content_type": ["cawg.ica.invalid_content_type"],
    "missing_cose_sign_alg": ["cawg.ica.invalid_alg"],
    "missing_vc": ["cawg.ica.invalid_verifiable_credential"],
    "signature_mismatch": ["cawg.ica.signature_mismatch"],
    "signer_payload_mismatch": ["cawg.ica.signer_payload.mismatch"],
    "success": ["cawg.ica.credential_valid"],
    "unresolvable_did": ["cawg.ica.did_unavailable"],
    "unsupported_did_method": ["cawg.ica.did_unsupported_method"],
    "valid_from_after_time_stamp": [
        "cawg.ica.time_stamp.validated",
        "cawg.ica.valid_from.invalid",
    ],
    "valid_from_in_future": ["cawg.ica.valid_from.invalid"],
    "valid_from_missing": ["cawg.ica.valid_from.missing"],
    "valid_time_stamp": [
        "cawg.ica.time_stamp.validated",
        "cawg.ica.credential_valid",
    ],
    "valid_until_in_future": ["cawg.ica.credential_valid"],
    "valid_until_in_past": ["cawg.ica.valid_until.invalid"],
}
# What this SDK observes today. did:web ICA vectors resolve through the pinned
# offline DID-document store under did/ (fetched once from the public
# .well-known endpoints and frozen); an issuer absent from the store fails
# closed with cawg.ica.did_unavailable.
ICA_OBSERVED: Final = {**ICA_EXPECTED}
# Pinned DID documents (relative to this directory) per fixture, passed to the
# verifier through --cawg-did-documents.
DID_ADOBE_PROD: Final = "did/connected-identities.identity.adobe.com.json"
DID_ADOBE_STAGE: Final = "did/connected-identities.identity-stage.adobe.com.json"
DID_NO_ASSERTION_METHOD: Final = "did/cawg-test-data.github.io_test-case_no-assertion-method.json"
ICA_DID_DOCUMENTS: Final = {
    "did_doc_without_assertion_method": (DID_NO_ASSERTION_METHOD,),
}
ICA_VALIDATION_TIMES: Final = {
    # VC validFrom is 2025-08-04T21:53Z; validate after it so the observation
    # is the DID-resolution failure alone.
    "unresolvable_did": LATE_VALIDATION_TIME,
}


@dataclass(frozen=True)
class Vector:
    vector_id: str
    repository: str
    commit: str
    source_path: str
    local_path: str
    license_expression: str
    credential_type: str
    spec_profile: str
    audit_state: str
    upstream_required_codes: tuple[str, ...] = ()
    normative_required_codes: tuple[str, ...] = ()
    observed_required_codes: tuple[str, ...] = ()
    notes: str | None = None
    validation_time: str = VALIDATION_TIME
    did_documents: tuple[str, ...] = ()

    @property
    def raw_url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.repository}/{self.commit}/{self.source_path}"


def _flat(source_path: str) -> str:
    return source_path.replace("/", "__")


def _rs_vector(
    source_path: str,
    *,
    vector_id: str,
    credential_type: str,
    spec_profile: str,
    audit_state: str,
    upstream: list[str] | tuple[str, ...] = (),
    normative: list[str] | tuple[str, ...] = (),
    observed: list[str] | tuple[str, ...] = (),
    notes: str | None = None,
    validation_time: str = VALIDATION_TIME,
    did_documents: tuple[str, ...] = (),
) -> Vector:
    return Vector(
        vector_id=vector_id,
        repository="contentauth/c2pa-rs",
        commit=RS_COMMIT,
        source_path=source_path,
        local_path=f"external/contentauth-c2pa-rs/{RS_COMMIT[:8]}/assets/{_flat(source_path)}",
        license_expression="Apache-2.0 OR MIT",
        credential_type=credential_type,
        spec_profile=spec_profile,
        audit_state=audit_state,
        upstream_required_codes=tuple(upstream),
        normative_required_codes=tuple(normative),
        observed_required_codes=tuple(observed),
        notes=notes,
        validation_time=validation_time,
        did_documents=tuple(did_documents),
    )


def vectors() -> list[Vector]:
    result: list[Vector] = []
    validation_base = "sdk/src/identity/tests/fixtures/validation_method"
    for name, expected in X509_EXPECTED.items():
        observed = X509_OBSERVED[name]
        notes = None
        if name == "extra_field":
            notes = (
                "Top-level extra field is tolerated per CAWG 1.2 §5.2; the COSE signature "
                "verifies over the stored (serde field-order, definite-length) signer_payload "
                "bytes. No failure codes; well-formed rather than trusted because the "
                "emailProtection-EKU test leaf lacks the trusted timestamp required by the "
                "CAWG 1.2 interim S/MIME policy."
            )
        result.append(
            _rs_vector(
                f"{validation_base}/{name}.jpg",
                vector_id=f"c2pa-rs-x509-{name.replace('_', '-')}",
                credential_type="x509",
                spec_profile="CAWG Identity 1.1 draft-derived",
                audit_state="known-upstream-divergence" if observed != expected else "imported",
                upstream=X509_UPSTREAM[name],
                normative=expected,
                observed=observed,
                notes=notes,
            )
        )

    ica_base = "sdk/src/identity/tests/fixtures/claim_aggregation/ica_validation"
    for name, expected in ICA_EXPECTED.items():
        observed = ICA_OBSERVED[name]
        notes = None
        if name == "success":
            notes = "Legacy CAWG 1.1 context; c2paAsset hashes are JSON byte arrays of the base64 text rather than the base64 strings required by CAWG Identity 1.2; both encodings decode to the same digest. The validator surfaces both legacy aspects via the informational com.encypher.cawg.legacyProfile status (refused under --cawg-strict-encoding)."
        elif name == "unsupported_did_method":
            notes = "Present in the pinned fixture tree but not consumed by the pinned upstream test module."
        elif name == "did_doc_without_assertion_method":
            notes = "did:web issuer resolved through the pinned DID document published at cawg-test-data.github.io; the document deliberately lacks an assertionMethod."
        elif name == "unresolvable_did":
            notes = "VC validFrom (2025-08-04) postdates the default corpus clock; validated at the late clock so only the DID-resolution failure is observed."
        result.append(
            _rs_vector(
                f"{ica_base}/{name}.jpg",
                vector_id=f"c2pa-rs-ica-{name.replace('_', '-')}",
                credential_type="ica",
                spec_profile="CAWG Identity 1.1 draft-derived",
                audit_state="known-upstream-divergence" if observed != expected else "imported",
                upstream=expected,
                normative=expected,
                observed=observed,
                notes=notes,
                validation_time=ICA_VALIDATION_TIMES.get(name, VALIDATION_TIME),
                did_documents=ICA_DID_DOCUMENTS.get(name, ()),
            )
        )

    for name in ("adobe_connected_identities", "ims_multiple_manifests"):
        result.append(
            _rs_vector(
                f"sdk/src/identity/tests/fixtures/claim_aggregation/{name}.jpg",
                vector_id=f"c2pa-rs-ica-interop-{name.replace('_', '-')}",
                credential_type="ica",
                spec_profile="legacy interoperability sample",
                audit_state="imported",
                normative=["cawg.ica.credential_valid"],
                observed=["cawg.ica.credential_valid"],
                notes=(
                    "Issued by Adobe's stage connected-identities aggregator; validates "
                    "offline against the pinned did:web document fetched from the public "
                    ".well-known endpoint (2026-08-04). Use the fixed validation clock so "
                    "the enclosing C2PA claim is inside certificate validity."
                ),
                did_documents=(DID_ADOBE_STAGE,),
            )
        )

    result.append(
        _rs_vector(
            "cli/tests/fixtures/C_with_CAWG_data.jpg",
            vector_id="c2pa-rs-cli-cawg-data",
            credential_type="x509",
            spec_profile="legacy non-deterministic signer_payload encoding",
            audit_state="imported",
            normative=["cawg.identity.well-formed"],
            observed=["cawg.identity.well-formed"],
            notes=(
                "COSE signature verifies over the stored (serde field-order) signer_payload "
                "encoding, which the validator accepts alongside canonical CBOR and surfaces "
                "via the informational com.encypher.cawg.legacyProfile status (refused under "
                "--cawg-strict-encoding). Well-formed "
                "rather than trusted: the identity leaf carries no trusted timestamp, so the "
                "CAWG 1.2 interim S/MIME policy withholds trust."
            ),
        )
    )
    result.append(
        Vector(
            vector_id="c2pa-cpp-cawg-data",
            repository="contentauth/c2pa-cpp",
            commit=CPP_COMMIT,
            source_path="tests/fixtures/C_with_CAWG_data.jpg",
            local_path=f"external/contentauth-c2pa-cpp/{CPP_COMMIT[:8]}/assets/C_with_CAWG_data.jpg",
            license_expression="Apache-2.0",
            credential_type="ica",
            spec_profile="legacy Adobe connected-identities sample",
            audit_state="imported",
            normative_required_codes=("cawg.ica.credential_valid",),
            observed_required_codes=("cawg.ica.credential_valid",),
            notes=(
                "Legacy did:web sample issued by Adobe's production connected-identities "
                "aggregator; validates offline against the pinned did:web document fetched "
                "from the public .well-known endpoint (2026-08-04). Validated at the late "
                "clock because the VC validFrom (2025-05-30) postdates the default corpus clock."
            ),
            validation_time=LATE_VALIDATION_TIME,
            did_documents=(DID_ADOBE_PROD,),
        )
    )
    return sorted(result, key=lambda item: item.vector_id)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(vector: Vector) -> dict[str, object]:
    path = ROOT / vector.local_path
    if not path.is_file():
        raise FileNotFoundError(f"missing vector: {path}")
    data = path.read_bytes()
    entry: dict[str, object] = {
        "id": vector.vector_id,
        "path": vector.local_path,
        "sha256": _sha256(data),
        "size": len(data),
        "mime_type": "image/jpeg",
        "source": {
            "repository": vector.repository,
            "commit": vector.commit,
            "path": vector.source_path,
            "url": vector.raw_url,
        },
        "license": vector.license_expression,
        "credential_type": vector.credential_type,
        "spec_profile": vector.spec_profile,
        "audit_state": vector.audit_state,
        "fixed_validation_time": vector.validation_time,
        "trust": {
            "claim_allowed_list": "trust/c2pa-rs-claim-trust.pem",
            "cawg_allowed_list": "trust/c2pa-rs-cawg-trust.pem",
            **({"did_documents": list(vector.did_documents)} if vector.did_documents else {}),
        },
        "upstream_expected": {"required_codes": list(vector.upstream_required_codes)},
        "normative_expected": {"required_codes": list(vector.normative_required_codes)},
        "current_sdk_observation": {"required_codes": list(vector.observed_required_codes)},
    }
    if vector.notes:
        entry["notes"] = vector.notes
    return entry


def update() -> None:
    corpus = vectors()
    document = {
        "schema_version": 1,
        "description": "Pinned external CAWG interoperability vectors; not an official conformance corpus.",
        "network_policy": "offline",
        "vector_count": len(corpus),
        "sources": [
            {
                "repository": "contentauth/c2pa-rs",
                "commit": RS_COMMIT,
                "license": "Apache-2.0 OR MIT",
                "license_files": [
                    f"external/contentauth-c2pa-rs/{RS_COMMIT[:8]}/LICENSE-APACHE",
                    f"external/contentauth-c2pa-rs/{RS_COMMIT[:8]}/LICENSE-MIT",
                ],
            },
            {
                "repository": "contentauth/c2pa-cpp",
                "commit": CPP_COMMIT,
                "license": "Apache-2.0",
                "license_files": [
                    f"external/contentauth-c2pa-cpp/{CPP_COMMIT[:8]}/LICENSE",
                ],
            },
        ],
        "vectors": [_entry(vector) for vector in corpus],
    }
    INDEX.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def _load_index() -> dict[str, object]:
    if not INDEX.is_file():
        raise FileNotFoundError(f"missing index: {INDEX}; run update after populating assets")
    return json.loads(INDEX.read_text())


def check() -> None:
    document = _load_index()
    expected = {vector.vector_id: vector for vector in vectors()}
    entries = document.get("vectors")
    if not isinstance(entries, list):
        raise ValueError("corpus.json vectors must be an array")
    if document.get("vector_count") != len(expected) or len(entries) != len(expected):
        raise ValueError(f"expected {len(expected)} indexed vectors")
    seen: set[str] = set()
    for entry in entries:
        vector_id = entry["id"]
        if vector_id in seen or vector_id not in expected:
            raise ValueError(f"duplicate or unknown vector id: {vector_id}")
        seen.add(vector_id)
        vector = expected[vector_id]
        path = ROOT / entry["path"]
        data = path.read_bytes()
        if entry["sha256"] != _sha256(data) or entry["size"] != len(data):
            raise ValueError(f"digest or size mismatch: {vector_id}")
        source = entry["source"]
        if source["commit"] != vector.commit or source["path"] != vector.source_path:
            raise ValueError(f"source provenance mismatch: {vector_id}")
        for did_path in entry.get("trust", {}).get("did_documents", []):
            document_path = ROOT / did_path
            if tuple(entry["trust"]["did_documents"]) != vector.did_documents:
                raise ValueError(f"did-document list mismatch: {vector_id}")
            parsed = json.loads(document_path.read_text())
            if not str(parsed.get("id", "")).startswith("did:"):
                raise ValueError(f"pinned DID document lacks a DID id: {did_path}")
    if seen != set(expected):
        raise ValueError(f"missing vector ids: {sorted(set(expected) - seen)}")


def fetch() -> None:
    indexed = {entry["id"]: entry for entry in _load_index()["vectors"]}
    for vector in vectors():
        path = ROOT / vector.local_path
        if path.is_file():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(vector.raw_url, timeout=60) as response:
            data = response.read()
        expected = indexed[vector.vector_id]
        if _sha256(data) != expected["sha256"] or len(data) != expected["size"]:
            raise ValueError(f"downloaded bytes do not match pinned index: {vector.vector_id}")
        path.write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "fetch", "update"), nargs="?", default="check")
    args = parser.parse_args()
    if args.command == "update":
        update()
    elif args.command == "fetch":
        fetch()
        check()
    else:
        check()


if __name__ == "__main__":
    main()
