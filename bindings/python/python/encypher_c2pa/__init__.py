"""Local-first, verification-only C2PA SDK."""

from __future__ import annotations

import json
import mimetypes
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from ._native import (
    formats_json,
    get_telemetry_preference,
    set_telemetry_preference,
    verify_bytes,
)

__all__ = [
    "configure_telemetry",
    "supported_mime_types",
    "telemetry_enabled",
    "verify",
]
__version__ = "1.0.0"

Asset = Union[bytes, bytearray, memoryview, str, Path]


def verify(
    asset: Asset,
    mime_type: Optional[str] = None,
    *,
    trust_pem: Optional[str] = None,
    tsa_trust_pem: Optional[str] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_strict_encoding: bool = False,
    validation_time: Optional[str] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
) -> Mapping[str, Any]:
    """Verify one asset locally and return a JSON-compatible report.

    ``asset`` may be bytes or a local path. Trust is evaluated only against
    static PEM material supplied by the caller. CAWG named-actor credentials
    are evaluated against ``cawg_trust_pem``/``cawg_allowed_certs_pem``;
    ``cawg_did_documents`` maps a primary DID (e.g. ``did:web:example.com``)
    to its DID document for offline ``did:web`` ICA resolution (absent
    issuers fail closed), and ``cawg_strict_encoding`` refuses CAWG 1.1-era
    legacy encodings. On first interactive use, the
    SDK asks whether failure telemetry should be enabled and saves the answer.
    Passing ``telemetry=True`` or ``False`` changes that saved preference.
    Telemetry sends bounded failure codes, never asset bytes, manifests, paths,
    keys, trust material, or account identifiers.
    """
    if isinstance(asset, (str, Path)):
        path = Path(asset)
        data = path.read_bytes()
        if mime_type is None:
            mime_type = mimetypes.guess_type(path.name)[0]
    elif isinstance(asset, (bytes, bytearray, memoryview)):
        data = bytes(asset)
    else:
        raise TypeError("asset must be bytes or a filesystem path")

    if not mime_type:
        raise ValueError("mime_type is required when it cannot be inferred from a path")

    if telemetry is not None:
        configure_telemetry(telemetry)

    options = {
        "trust_pem": trust_pem,
        "tsa_trust_pem": tsa_trust_pem,
        "allowed_list_pem": allowed_list_pem,
        "cawg_trust_pem": cawg_trust_pem,
        "cawg_allowed_certs_pem": cawg_allowed_certs_pem,
        "cawg_did_documents": dict(cawg_did_documents) if cawg_did_documents else None,
        "cawg_strict_encoding": bool(cawg_strict_encoding),
        "validation_time": validation_time,
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    report = verify_bytes(data, mime_type, json.dumps(options))
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
