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
    verify_fragmented_bytes,
)

__all__ = [
    "configure_telemetry",
    "supported_mime_types",
    "telemetry_enabled",
    "verify",
]
__version__ = "1.0.4"

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
    trust_pem: Optional[str] = None,
    tsa_trust_pem: Optional[str] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    no_default_trust: bool = False,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_strict_encoding: bool = False,
    validation_time: Optional[str] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
) -> Mapping[str, Any]:
    """Verify one asset locally and return a JSON-compatible report.

    Bundled C2PA, IPTC, and Encypher trust snapshots are used by default;
    caller-supplied PEM bundles extend them. Set ``no_default_trust=True`` to
    evaluate only caller-supplied trust material. CAWG named-actor credentials
    are evaluated against the packaged Mozilla Email, IPTC VNPL, and Encypher
    identity lists plus ``cawg_trust_pem``/``cawg_allowed_certs_pem``;
    ``cawg_did_documents`` maps a primary DID (e.g. ``did:web:example.com``)
    to its DID document for
    offline ``did:web`` ICA resolution (absent issuers fail closed), and
    ``cawg_strict_encoding`` refuses CAWG 1.1-era legacy encodings. On first
    interactive use, the SDK asks whether failure
    telemetry should be enabled and saves the answer. Passing
    ``telemetry=True`` or ``False`` attempts to save that preference; the
    explicit value still governs this verification if persistence fails.
    Telemetry sends bounded failure codes, never asset bytes, manifests, paths,
    keys, trust material, or account identifiers.
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
        "no_default_trust": bool(no_default_trust),
        "cawg_did_documents": dict(cawg_did_documents) if cawg_did_documents else None,
        "cawg_strict_encoding": bool(cawg_strict_encoding),
        "validation_time": validation_time,
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    if fragments is None:
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


def configure_telemetry(enabled: bool) -> None:
    """Save the failure telemetry preference for future native SDK calls."""
    set_telemetry_preference(bool(enabled))


def telemetry_enabled() -> Optional[bool]:
    """Return the saved preference, or ``None`` before the user has answered."""
    return get_telemetry_preference()


def supported_mime_types() -> tuple[str, ...]:
    """Return canonical MIME types covered by this build's C2PA 2.4 profile."""
    return tuple(json.loads(formats_json()))
