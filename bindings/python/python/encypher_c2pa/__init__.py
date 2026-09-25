# Copyright 2026 Encypher Corporation
# SPDX-License-Identifier: Apache-2.0

"""Local-first, verification-only C2PA SDK."""

from __future__ import annotations

import errno
import json
import mimetypes
import os
import stat
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Union

from ._native import (
    extensions_json as _extensions_json,
    formats_json,
    get_telemetry_preference,
    set_telemetry_preference,
    verify_bytes,
    verify_detached_bytes,
    verify_fragmented_bytes,
    verify_stream_bytes,
)

__all__ = [
    "configure_telemetry",
    "supported_mime_types",
    "telemetry_enabled",
    "verify",
    "verify_stream",
]
__version__ = "1.1.0"

Asset = Union[bytes, bytearray, memoryview, str, Path]
_MAX_PATH_ASSET_BYTES = 128 * 1024 * 1024
_SUPPORTED_EXTENSIONS = dict(json.loads(_extensions_json()))


def _read_path(path: Path, limit: int = _MAX_PATH_ASSET_BYTES) -> bytearray:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(errno.EINVAL, "asset path is not a regular file", path)
        if metadata.st_size > limit:
            raise OSError(
                errno.EFBIG,
                f"asset exceeds the 128 MiB path limit ({limit} bytes)",
                path,
            )

        expected = metadata.st_size
        buffer = bytearray(expected + 1)
        used = 0
        with os.fdopen(fd, "rb", buffering=0, closefd=False) as asset_file:
            view = memoryview(buffer)
            while used < expected:
                count = asset_file.readinto(view[used:expected])
                if not count:
                    break
                used += count
            if used == expected and asset_file.readinto(view[expected : expected + 1]):
                raise OSError(errno.EFBIG, "asset grew while being read", path)
        view.release()
        del buffer[used:]
        return buffer
    finally:
        os.close(fd)

def _infer_mime_type(path: Path) -> Optional[str]:
    extension = path.suffix.removeprefix(".").lower()
    return _SUPPORTED_EXTENSIONS.get(extension) or mimetypes.guess_type(path.name)[0]


def verify(
    asset: Asset,
    mime_type: Optional[str] = None,
    fragments: Optional[Sequence[Asset]] = None,
    *,
    manifest_store: Optional[Asset] = None,
    expected_seek_positions: Optional[Sequence[int]] = None,
    trust_pem: Optional[str] = None,
    tsa_trust_pem: Optional[str] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    trust_anchor_not_before: Optional[str] = None,
    trust_anchor_not_after: Optional[str] = None,
    no_default_trust: bool = False,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_ica_trusted_issuers: Optional[Sequence[str]] = None,
    cawg_ica_trust_anchors: Optional[Sequence[str]] = None,
    cawg_ica_status_lists: Optional[Mapping[str, str]] = None,
    cawg_strict_encoding: bool = False,
    strict_conformance: bool = False,
    validation_time: Optional[str] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
    online: Optional[bool] = None,
    online_allow_private_networks: bool = False,
) -> Mapping[str, Any]:
    """Verify one asset locally and return a JSON-compatible report.

    Bundled C2PA, IPTC, and Encypher trust snapshots are used by default;
    caller-supplied PEM bundles extend them. Set ``no_default_trust=True`` to
    evaluate only caller-supplied trust material. CAWG named-actor credentials
    are evaluated against the packaged Mozilla Email, IPTC VNPL, and Encypher
    identity lists plus ``cawg_trust_pem``/``cawg_allowed_certs_pem``.
    ``trust_anchor_not_before``/``trust_anchor_not_after`` are RFC 3339
    instants bounding when the caller-supplied anchors are trusted;
    ``cawg_did_documents`` maps a primary DID (e.g. ``did:web:example.com``)
    to its DID document for offline ``did:web`` ICA resolution;
    ``cawg_ica_trusted_issuers`` and ``cawg_ica_trust_anchors`` supply explicit
    ICA trust configuration; and ``cawg_ica_status_lists`` supplies offline
    decompressed status bitstrings as base64. ``cawg_strict_encoding=True``
    refuses the CAWG field-order signer payload that c2pa-rs writes.
    ``strict_conformance=True`` applies the C2PA 2.4 Conformance Program
    posture, including CAWG Identity 1.3 deterministic signer-payload encoding. On first interactive use,
    telemetry should be enabled and saves the answer. Passing
    ``telemetry=True`` or ``False`` attempts to save that preference; the
    explicit value still governs this verification if persistence fails.
    ``expected_seek_positions`` contains zero-based indexes into ``fragments``
    where the player expects a discontinuity. It is ignored when ``fragments``
    is omitted.
    ``manifest_store`` verifies the asset against a C2PA Manifest Store held
    outside it: a ``.c2pa`` sidecar, or a store fetched from the URI the asset
    declares in its XMP ``dcterms:provenance`` key. Pass bytes or a path. This
    SDK never fetches it for you. It cannot be combined with ``fragments``.
    Telemetry sends bounded failure codes, never asset bytes, manifests, paths,
    keys, trust material, or account identifiers.
    ``online`` allows this call to fetch what the asset references: a manifest
    store held elsewhere, certificate revocation status, a ``did:web``
    document, externally stored content. It is off unless you pass ``True`` or
    the operator sets ``ENCYPHER_C2PA_ONLINE=on``. A library never reads the
    per-user choice saved by the command line and never prompts, because the
    machine running this code may be checking files sent in by strangers.
    Whatever is fetched is evidence only; the verdict still comes from the
    same offline checks. The returned report carries a ``network`` block
    listing what could be fetched and what was.
    ``online_allow_private_networks=True`` is intranet mode: it lets those
    fetches reach loopback and private addresses and accept plaintext http.
    """
    if isinstance(asset, (str, Path)):
        path = Path(asset)
        data = _read_path(path)
        if mime_type is None:
            mime_type = _infer_mime_type(path)
    elif isinstance(asset, (bytes, bytearray, memoryview)):
        data = asset
    else:
        raise TypeError("asset must be bytes or a filesystem path")

    if not mime_type:
        raise ValueError("mime_type is required when it cannot be inferred from a path")

    if telemetry is not None:
        try:
            set_telemetry_preference(bool(telemetry))
        except Exception:
            pass

    options = {
        "trust_pem": trust_pem,
        "tsa_trust_pem": tsa_trust_pem,
        "allowed_list_pem": allowed_list_pem,
        "cawg_trust_pem": cawg_trust_pem,
        "cawg_allowed_certs_pem": cawg_allowed_certs_pem,
        "trust_anchor_not_before": trust_anchor_not_before,
        "trust_anchor_not_after": trust_anchor_not_after,
        "no_default_trust": bool(no_default_trust),
        "cawg_did_documents": dict(cawg_did_documents) if cawg_did_documents else None,
        "cawg_ica_trusted_issuers": list(cawg_ica_trusted_issuers)
        if cawg_ica_trusted_issuers
        else None,
        "cawg_ica_trust_anchors": list(cawg_ica_trust_anchors)
        if cawg_ica_trust_anchors
        else None,
        "cawg_ica_status_lists": dict(cawg_ica_status_lists)
        if cawg_ica_status_lists
        else None,
        "expected_seek_positions": list(expected_seek_positions)
        if expected_seek_positions
        else [],
        "cawg_strict_encoding": bool(cawg_strict_encoding),
        "strict_conformance": bool(strict_conformance),
        "validation_time": validation_time,
        "online": online,
        "online_allow_private_networks": bool(online_allow_private_networks),
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    if manifest_store is not None:
        if fragments is not None:
            raise ValueError("manifest_store cannot be combined with fragments")
        if isinstance(manifest_store, (str, Path)):
            store = _read_path(Path(manifest_store))
        elif isinstance(manifest_store, (bytes, bytearray, memoryview)):
            store = manifest_store
        else:
            raise TypeError("manifest_store must be bytes or a filesystem path")
        report = verify_detached_bytes(data, store, mime_type, json.dumps(options))
    elif fragments is None:
        report = verify_bytes(data, mime_type, json.dumps(options))
    else:
        fragment_data = []
        for fragment in fragments:
            if isinstance(fragment, (str, Path)):
                fragment_data.append(_read_path(Path(fragment)))
            elif isinstance(fragment, (bytes, bytearray, memoryview)):
                fragment_data.append(fragment)
            else:
                raise TypeError("each fragment must be bytes or a filesystem path")
        report = verify_fragmented_bytes(
            data, fragment_data, mime_type, json.dumps(options)
        )
    return json.loads(report)


def verify_stream(
    init_segment: Asset,
    segments: Sequence[Asset],
    mime_type: Optional[str] = None,
    *,
    encapsulation: str = "fMP4",
    method: str = "verifiable-segment-info",
    expected_seek_positions: Optional[Sequence[int]] = None,
    trust_pem: Optional[str] = None,
    tsa_trust_pem: Optional[str] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    no_default_trust: bool = False,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_ica_trusted_issuers: Optional[Sequence[str]] = None,
    cawg_ica_trust_anchors: Optional[Sequence[str]] = None,
    cawg_ica_status_lists: Optional[Mapping[str, str]] = None,
    cawg_strict_encoding: bool = False,
    strict_conformance: bool = False,
    validation_time: Optional[str] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
    online: Optional[bool] = None,
    online_allow_private_networks: bool = False,
) -> Mapping[str, Any]:
    """Verify a fragmented fMP4/CMAF stream and return a JSON-compatible report.

    ``init_segment`` is the stream's initialization segment and ``segments``
    are its media segments in playback order. ``encapsulation`` is ``"fMP4"``
    or ``"CMAF"`` (case-insensitive); both files' declared brands are checked
    against it, so a stream presented under the wrong one is refused rather
    than verified.

    ``method`` is ``"verifiable-segment-info"`` (one init manifest binds the
    whole stream) or ``"per-segment"`` (each segment carries its own manifest
    and is chained to its predecessor). Which binding a
    ``verifiable-segment-info`` stream used - C2PA 2.4 session keys or a Merkle
    tree - is read from the init manifest, never taken from the caller.
    ``expected_seek_positions`` contains zero-based indexes into ``segments``
    where the player expects a discontinuity.

    The returned report carries a top-level ``integrity``, the init manifest's
    report under ``stream``, per-segment reports under ``segments``, and the
    recomputed ``chain_valid`` for per-segment streams. Trust and telemetry
    options behave exactly as in :func:`verify`.
    """
    if isinstance(init_segment, (str, Path)):
        path = Path(init_segment)
        init_data: Any = _read_path(path)
        if mime_type is None:
            mime_type = _infer_mime_type(path)
    elif isinstance(init_segment, (bytes, bytearray, memoryview)):
        init_data = init_segment
    else:
        raise TypeError("init_segment must be bytes or a filesystem path")

    if not mime_type:
        raise ValueError("mime_type is required when it cannot be inferred from a path")

    segment_data = []
    for segment in segments:
        if isinstance(segment, (str, Path)):
            segment_data.append(_read_path(Path(segment)))
        elif isinstance(segment, (bytes, bytearray, memoryview)):
            segment_data.append(segment)
        else:
            raise TypeError("each segment must be bytes or a filesystem path")

    if telemetry is not None:
        try:
            set_telemetry_preference(bool(telemetry))
        except Exception:
            pass

    options = {
        "trust_pem": trust_pem,
        "tsa_trust_pem": tsa_trust_pem,
        "allowed_list_pem": allowed_list_pem,
        "cawg_trust_pem": cawg_trust_pem,
        "cawg_allowed_certs_pem": cawg_allowed_certs_pem,
        "no_default_trust": bool(no_default_trust),
        "cawg_did_documents": dict(cawg_did_documents) if cawg_did_documents else None,
        "cawg_ica_trusted_issuers": list(cawg_ica_trusted_issuers)
        if cawg_ica_trusted_issuers
        else None,
        "cawg_ica_trust_anchors": list(cawg_ica_trust_anchors)
        if cawg_ica_trust_anchors
        else None,
        "cawg_ica_status_lists": dict(cawg_ica_status_lists)
        if cawg_ica_status_lists
        else None,
        "expected_seek_positions": list(expected_seek_positions)
        if expected_seek_positions
        else [],
        "cawg_strict_encoding": bool(cawg_strict_encoding),
        "strict_conformance": bool(strict_conformance),
        "validation_time": validation_time,
        "online": online,
        "online_allow_private_networks": bool(online_allow_private_networks),
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    return json.loads(
        verify_stream_bytes(
            init_data,
            segment_data,
            mime_type,
            encapsulation,
            method,
            json.dumps(options),
        )
    )


def configure_telemetry(enabled: bool) -> None:
    """Save the failure telemetry preference for future native SDK calls."""
    set_telemetry_preference(bool(enabled))


def telemetry_enabled() -> Optional[bool]:
    """Return the saved preference, or ``None`` before the user has answered."""
    return get_telemetry_preference()


def supported_mime_types() -> tuple[str, ...]:
    """Return canonical MIME types covered by this build's C2PA 2.4 profile."""
    return tuple(json.loads(formats_json()))
