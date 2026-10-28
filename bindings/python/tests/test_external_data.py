# Copyright 2026 Encypher Corporation
# SPDX-License-Identifier: Apache-2.0

import base64
from pathlib import Path
from typing import Any, Mapping

import pytest

import encypher_c2pa


FIXTURES = Path(__file__).with_name("fixtures")
SIGNED_ASSET = FIXTURES / "external-reference.jpg"
EXTERNAL_BODY = FIXTURES / "external-body.txt"
EXTERNAL_URI = "https://e.example/python-external-evidence.txt"


@pytest.fixture(autouse=True)
def _disable_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENCYPHER_C2PA_TELEMETRY", "off")


def _results(report: Mapping[str, Any]) -> Mapping[str, Any]:
    return report["validation_results"]

def _status(
    report: Mapping[str, Any], bucket: str, code: str
) -> Mapping[str, Any]:
    matches = [
        status
        for status in _results(report).get(bucket, [])
        if status.get("code") == code
        and status.get("details", {}).get("uri") == EXTERNAL_URI
    ]
    assert len(matches) == 1, (bucket, code, _results(report))
    return matches[0]


def _needed_external_uris(report: Mapping[str, Any]) -> set[str]:
    return {
        need["uri"]
        for need in report["network"]["needed"]
        if need.get("kind") == "external_data"
    }


def test_supplied_external_bytes_change_the_real_verifier_result() -> None:
    asset = SIGNED_ASSET.read_bytes()
    body = EXTERNAL_BODY.read_bytes()

    missing = encypher_c2pa.verify(asset, "image/jpeg", online=False)
    missing_status = _status(missing, "failure", "assertion.inaccessible")
    assert missing_status["details"]["retrieval"] == "not_attempted"
    assert missing["network"]["enabled"] is False
    assert missing["network"]["requests"] == []
    assert EXTERNAL_URI in _needed_external_uris(missing)

    supplied = encypher_c2pa.verify(
        asset,
        "image/jpeg",
        online=False,
        external_data={EXTERNAL_URI: base64.b64encode(body).decode("ascii")},
        external_data_media_types={EXTERNAL_URI: "text/plain"},
    )
    accessible = _status(supplied, "success", "assertion.accessible")
    assert accessible["details"]["retrieval"] == "caller_supplied"
    _status(supplied, "success", "assertion.hashedURI.match")
    assert EXTERNAL_URI not in _needed_external_uris(supplied)

    altered = encypher_c2pa.verify(
        asset,
        "image/jpeg",
        online=False,
        external_data={
            EXTERNAL_URI: base64.b64encode(body + b"altered\n").decode("ascii")
        },
        external_data_media_types={EXTERNAL_URI: "text/plain"},
    )
    _status(altered, "success", "assertion.accessible")
    _status(altered, "failure", "assertion.hashedURI.mismatch")
    assert not any(
        status.get("code") == "assertion.hashedURI.match"
        and status.get("details", {}).get("uri") == EXTERNAL_URI
        for status in _results(altered).get("success", [])
    )


def test_unreachable_is_distinct_from_not_attempted_without_fetching() -> None:
    asset = SIGNED_ASSET.read_bytes()
    report = encypher_c2pa.verify(
        asset,
        "image/jpeg",
        online=False,
        external_data_unreachable=[EXTERNAL_URI],
    )

    inaccessible = _status(report, "failure", "assertion.inaccessible")
    assert inaccessible["details"]["retrieval"] == "unavailable"
    assert report["network"]["enabled"] is False
    assert report["network"]["requests"] == []
    assert EXTERNAL_URI not in _needed_external_uris(report)


@pytest.mark.parametrize("entrypoint", ["verify", "verify_stream"])
def test_unknown_policy_wins_before_asset_read_with_external_evidence(
    entrypoint: str, tmp_path: Path
) -> None:
    missing = tmp_path / ("missing.mp4" if entrypoint == "verify_stream" else "missing.jpg")
    evidence = {EXTERNAL_URI: base64.b64encode(b"evidence").decode("ascii")}

    with pytest.raises(ValueError, match="unsupported_spec_version"):
        if entrypoint == "verify_stream":
            encypher_c2pa.verify_stream(
                missing,
                [tmp_path / "missing.m4s"],
                "video/mp4",
                spec_version="2.6",
                external_data=evidence,
                external_data_media_types={EXTERNAL_URI: "application/octet-stream"},
                external_data_unreachable=["https://e.example/unreachable"],
            )
        else:
            encypher_c2pa.verify(
                missing,
                "image/jpeg",
                spec_version="2.6",
                external_data=evidence,
                external_data_media_types={EXTERNAL_URI: "application/octet-stream"},
                external_data_unreachable=["https://e.example/unreachable"],
            )


def test_raw_options_entrypoint_still_accepts_external_evidence_before_path_read(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing.c2pa"

    with pytest.raises(ValueError, match=r"^verification_error:"):
        encypher_c2pa.verify_manifest_store_only(
            missing,
            options={"external_data": {EXTERNAL_URI: "not base64"}},
        )
