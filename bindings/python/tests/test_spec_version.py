# Copyright 2026 Encypher Corporation
# SPDX-License-Identifier: Apache-2.0

import json
import sys
import types

import pytest

native = types.ModuleType("encypher_c2pa._native")
native.extensions_json = lambda: json.dumps([["jpg", "image/jpeg"]])
native.formats_json = lambda: "[]"
native.get_telemetry_preference = lambda: None
native.set_telemetry_preference = lambda enabled: None
native.validate_options = lambda *args: None
native.verify_bytes = lambda *args: "{}"
native.verify_detached_bytes = lambda *args: "{}"
native.verify_fragmented_bytes = lambda *args: "{}"
native.verify_stream_bytes = lambda *args: "{}"
sys.modules.setdefault("encypher_c2pa._native", native)

import encypher_c2pa


def _capture(monkeypatch: pytest.MonkeyPatch) -> dict:
    seen: dict = {}

    def validate(options_json: str) -> None:
        seen["validated"] = json.loads(options_json)

    def verify_bytes(data, mime_type, options_json):
        seen["verified"] = json.loads(options_json)
        return "{}"

    monkeypatch.setattr(encypher_c2pa, "_validate_options", validate)
    monkeypatch.setattr(encypher_c2pa, "verify_bytes", verify_bytes)
    return seen


@pytest.mark.parametrize("spec_version", [None, "2.4", "2.5"])
def test_verify_forwards_spec_version_to_validation_and_verification(
    monkeypatch: pytest.MonkeyPatch, spec_version
) -> None:
    seen = _capture(monkeypatch)
    encypher_c2pa.verify(b"\xff\xd8", "image/jpeg", spec_version=spec_version)
    assert seen["validated"]["spec_version"] == spec_version
    assert seen["verified"]["spec_version"] == spec_version


def test_verify_validates_spec_version_before_reading_a_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    def reject(options_json: str) -> None:
        if json.loads(options_json)["spec_version"] not in (None, "2.4", "2.5"):
            raise ValueError("unsupported_spec_version: spec_version \"9.9\" is not one of \"2.4\", \"2.5\"")

    monkeypatch.setattr(encypher_c2pa, "_validate_options", reject)
    with pytest.raises(ValueError, match="unsupported_spec_version"):
        encypher_c2pa.verify(tmp_path / "missing.jpg", spec_version="9.9")
