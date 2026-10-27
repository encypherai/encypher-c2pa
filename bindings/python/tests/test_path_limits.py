# Copyright 2026 Encypher Corporation
# SPDX-License-Identifier: Apache-2.0

import errno
import json
import os
import sys
import types
from pathlib import Path

import pytest

native = types.ModuleType("encypher_c2pa._native")
native.extensions_json = lambda: json.dumps(
    [
        ["jpg", "image/jpeg"],
        ["dng", "image/x-adobe-dng"],
        ["odg", "application/vnd.oasis.opendocument.graphics"],
        ["tsv", "text/tab-separated-values"],
    ]
)
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
from encypher_c2pa import _read_path


PATH_LIMIT = 128 * 1024 * 1024


def test_path_reader_accepts_exact_boundary_with_small_seam(tmp_path: Path) -> None:
    asset = tmp_path / "exact.jpg"
    asset.write_bytes(b"1234")
    assert _read_path(asset, limit=4) == b"1234"


def test_path_reader_detects_growth_at_limit_plus_one(tmp_path: Path) -> None:
    asset = tmp_path / "grown.jpg"
    asset.write_bytes(b"12345")
    with pytest.raises(OSError) as raised:
        _read_path(asset, limit=4)
    assert raised.value.errno == errno.EFBIG


def test_verify_rejects_sparse_asset_over_path_limit(tmp_path: Path) -> None:
    asset = tmp_path / "oversized.jpg"
    with asset.open("wb") as handle:
        handle.truncate(PATH_LIMIT + 1)

    with pytest.raises(OSError, match="128 MiB path limit") as raised:
        encypher_c2pa.verify(asset, "image/jpeg")
    assert raised.value.errno == errno.EFBIG


@pytest.mark.skipif(os.name != "posix", reason="requires a POSIX character device")
def test_verify_rejects_non_regular_source_without_reading_it() -> None:
    with pytest.raises(OSError, match="not a regular file") as raised:
        encypher_c2pa.verify(Path("/dev/zero"), "image/jpeg")
    assert raised.value.errno == errno.EINVAL


@pytest.mark.parametrize("enabled", [True, False])
def test_verify_uses_explicit_telemetry_when_preference_save_fails(
    monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    calls = []

    def fail_to_save(_enabled: bool) -> None:
        raise ValueError("preference store unavailable")

    def capture_verify(asset, mime_type, options_json):
        calls.append((asset, mime_type, json.loads(options_json)))
        return "{}"

    monkeypatch.setattr(encypher_c2pa, "set_telemetry_preference", fail_to_save)
    monkeypatch.setattr(encypher_c2pa, "verify_bytes", capture_verify)

    encypher_c2pa.verify(b"asset", "image/jpeg", telemetry=enabled)

    assert calls[0][2]["telemetry"]["enabled"] is enabled


def test_configure_telemetry_still_reports_preference_save_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_to_save(_enabled: bool) -> None:
        raise ValueError("preference store unavailable")

    monkeypatch.setattr(encypher_c2pa, "set_telemetry_preference", fail_to_save)

    with pytest.raises(ValueError, match="preference store unavailable"):
        encypher_c2pa.configure_telemetry(True)


def test_verify_uses_core_dng_mime_before_platform_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = tmp_path / "raw.DNG"
    asset.write_bytes(b"asset")
    observed = {}

    monkeypatch.setattr(
        encypher_c2pa.mimetypes,
        "guess_type",
        lambda _name: ("application/octet-stream", None),
    )

    def capture_verify(data, mime_type, _options_json):
        observed["mime_type"] = mime_type
        return "{}"

    monkeypatch.setattr(encypher_c2pa, "verify_bytes", capture_verify)

    encypher_c2pa.verify(asset)

    assert observed["mime_type"] == "image/x-adobe-dng"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("drawing.odg", "application/vnd.oasis.opendocument.graphics"),
        ("data.tsv", "text/tab-separated-values"),
    ],
)
def test_new_extensions_use_the_public_registry(
    name: str, expected: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / name
    path.write_bytes(b"asset")
    observed = {}

    def capture_verify(_data, mime_type, _options_json):
        observed["mime_type"] = mime_type
        return "{}"

    monkeypatch.setattr(encypher_c2pa, "verify_bytes", capture_verify)
    monkeypatch.setattr(
        encypher_c2pa.mimetypes,
        "guess_type",
        lambda _name: ("application/octet-stream", None),
    )

    encypher_c2pa.verify(path)
    assert observed["mime_type"] == expected


@pytest.mark.parametrize("entrypoint", ["verify", "verify_stream"])
def test_invalid_options_win_over_missing_asset_paths(
    entrypoint: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / ("missing.mp4" if entrypoint == "verify_stream" else "missing.jpg")

    def reject(_options_json: str) -> None:
        raise ValueError(
            "invalid_trust_material: "
            "cawg_trust_configurations[0].certificates_pem: no certificates"
        )

    monkeypatch.setattr(encypher_c2pa, "_validate_options", reject)
    with pytest.raises(ValueError, match="invalid_trust_material"):
        if entrypoint == "verify_stream":
            encypher_c2pa.verify_stream(
                missing,
                [tmp_path / "missing.m4s"],
                "video/mp4",
                cawg_trust_configurations=[
                    {"profile": "base", "certificates_pem": ""}
                ],
            )
        else:
            encypher_c2pa.verify(
                missing,
                "image/jpeg",
                cawg_trust_configurations=[
                    {"profile": "base", "certificates_pem": ""}
                ],
            )


def test_a_bare_string_is_not_a_sequence_of_presentation_times() -> None:
    with pytest.raises(TypeError, match="stream_presentation_times"):
        encypher_c2pa.verify_stream(
            b"init",
            [b"seg-0"],
            "video/mp4",
            stream_presentation_times="2026-10-26T22:30:00Z",
        )
