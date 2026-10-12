#!/usr/bin/env python3
"""Exercise Python evidence options against the real external append fixture.

Run this with the newly built wheel installed:

    python bindings/python/tests/smoke_external_append.py \
      /path/to/append-checkpoint

The directory must contain the ``cli-external-*`` artifacts emitted by the
C2PA 2.5 native append smoke fixture.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import encypher_c2pa

FIRST_URI = "https://evidence.example/checkpoint/cli-1.c2pa"


def _json(directory: Path, name: str) -> Any:
    return json.loads((directory / name).read_text(encoding="utf-8"))


def _statuses(report: Mapping[str, Any], bucket: str) -> list[Mapping[str, Any]]:
    return report["validation_results"].get(bucket, [])


def _has_code(report: Mapping[str, Any], bucket: str, code: str) -> bool:
    return any(status.get("code") == code for status in _statuses(report, bucket))


def _status(report: Mapping[str, Any], bucket: str, code: str) -> Mapping[str, Any]:
    matches = [
        status for status in _statuses(report, bucket) if status.get("code") == code
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one {bucket} {code}, got {matches!r}")
    return matches[0]


def _needed_uris(report: Mapping[str, Any]) -> set[str]:
    return {
        need["uri"]
        for need in report["network"]["needed"]
        if need.get("kind") == "external_data"
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("fixture_dir", type=Path)
    arguments = parser.parse_args()
    directory = arguments.fixture_dir.resolve()

    asset = (directory / "cli-external-final.txt").read_bytes()
    all_data = _json(directory, "cli-external-data.json")
    all_media_types = _json(directory, "cli-external-data-media-types.json")
    active_data = _json(directory, "cli-external-active-only-data.json")
    active_media_types = _json(
        directory, "cli-external-active-only-media-types.json"
    )
    unreachable = _json(directory, "cli-external-unreachable.json")
    wrong_data = _json(directory, "cli-external-wrong-predecessor-data.json")

    valid = encypher_c2pa.verify(
        asset,
        "text/plain",
        spec_version="2.5",
        online=False,
        external_data=all_data,
        external_data_media_types=all_media_types,
    )
    assert valid["profile"] == "c2pa-2.5"
    assert valid["integrity"] == "valid"
    assert sum(
        status.get("code") == "assertion.segmentHash.match"
        for status in _statuses(valid, "success")
    ) >= 2

    not_attempted = encypher_c2pa.verify(
        asset,
        "text/plain",
        spec_version="2.5",
        online=False,
        external_data=active_data,
        external_data_media_types=active_media_types,
    )
    missing = _status(not_attempted, "informational", "manifest.inaccessible")
    assert "was not supplied" in missing["explanation"]
    assert FIRST_URI in _needed_uris(not_attempted)

    inaccessible = encypher_c2pa.verify(
        asset,
        "text/plain",
        spec_version="2.5",
        online=False,
        external_data=active_data,
        external_data_media_types=active_media_types,
        external_data_unreachable=unreachable,
    )
    failed_fetch = _status(inaccessible, "informational", "manifest.inaccessible")
    assert "could not be retrieved" in failed_fetch["explanation"]
    assert FIRST_URI not in _needed_uris(inaccessible)

    wrong = encypher_c2pa.verify(
        asset,
        "text/plain",
        spec_version="2.5",
        online=False,
        external_data=wrong_data,
        external_data_media_types=all_media_types,
    )
    assert wrong["integrity"] == "invalid"
    assert _has_code(wrong, "failure", "assertion.segmentHash.mismatch")

    print(
        json.dumps(
            {
                "valid_integrity": valid["integrity"],
                "not_attempted_network_need": FIRST_URI in _needed_uris(not_attempted),
                "unreachable_network_need": FIRST_URI in _needed_uris(inaccessible),
                "wrong_predecessor_integrity": wrong["integrity"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
