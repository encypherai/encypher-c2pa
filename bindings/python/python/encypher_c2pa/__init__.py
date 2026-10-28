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
    binding_target_bytes as _binding_target_bytes,
    extensions_json as _extensions_json,
    formats_json,
    get_telemetry_preference,
    set_telemetry_preference,
    resolve_soft_binding_bytes as _resolve_soft_binding_bytes,
    request_soft_binding_receipt_verification_json as _request_soft_binding_receipt_verification_json,
    validate_options as _validate_options,
    verify_bytes,
    verify_detached_bytes,
    verify_manifest_store_only_bytes as _verify_manifest_store_only_bytes,
    verify_caller_binding_bytes as _verify_caller_binding_bytes,
    verify_ertmp_events,
    verify_fragmented_bytes,
    verify_stream_bytes,
)

__all__ = [
    "binding_target",
    "configure_telemetry",
    "supported_mime_types",
    "resolve_soft_binding",
    "request_soft_binding_receipt_verification",
    "telemetry_enabled",
    "verify",
    "verify_ertmp",
    "verify_manifest_store_only",
    "verify_with_caller_verified_binding",
    "verify_stream",
]
__version__ = "1.8.0"

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
    claim_trust_sources: Optional[Sequence[Mapping[str, Any]]] = None,
    tsa_trust_pem: Optional[str] = None,
    tsa_trust_sources: Optional[Sequence[Mapping[str, Any]]] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    cawg_trust_configurations: Optional[Sequence[Mapping[str, Any]]] = None,
    trust_anchor_not_before: Optional[str] = None,
    trust_anchor_not_after: Optional[str] = None,
    no_default_trust: bool = False,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_ica_trusted_issuers: Optional[Sequence[str]] = None,
    cawg_ica_trust_anchors: Optional[Sequence[str]] = None,
    cawg_ica_status_lists: Optional[Mapping[str, str]] = None,
    cawg_strict_encoding: bool = False,
    strict_conformance: bool = False,
    spec_version: Optional[str] = None,
    validation_time: Optional[str] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
    online: Optional[bool] = None,
    external_data: Optional[Mapping[str, str]] = None,
    external_data_media_types: Optional[Mapping[str, str]] = None,
    external_data_unreachable: Optional[Sequence[str]] = None,
    online_allow_private_networks: bool = False,
) -> Mapping[str, Any]:
    """Verify one asset locally and return a JSON-compatible report.

    Bundled C2PA, IPTC, and Encypher trust snapshots are used by default;
    caller-supplied PEM bundles extend them. Set ``no_default_trust=True`` to
    evaluate only caller-supplied trust material. CAWG named-actor credentials
    are evaluated against the packaged Mozilla Email, IPTC VNPL, and Encypher
    identity lists plus ``cawg_trust_pem``/``cawg_allowed_certs_pem`` and
    ``cawg_trust_configurations``: typed CAWG Identity 1.3 trust sources, each
    ``{"profile": "base" | "smime_interim", "certificates_pem": ...,
    "not_before": ..., "not_after": ...}``. ``smime_interim`` entries (the
    Mozilla email roots, the IPTC lists) accept S/MIME identities only until
    31 March 2027 or with a trusted time stamp from before it.
    ``trust_anchor_not_before``/``trust_anchor_not_after`` are RFC 3339
    instants bounding when the caller-supplied anchors are trusted;
    ``cawg_did_documents`` maps a primary DID (e.g. ``did:web:example.com``)
    to its DID document for offline ``did:web`` ICA resolution;
    ``cawg_ica_trusted_issuers`` and ``cawg_ica_trust_anchors`` supply explicit
    ICA trust configuration; and ``cawg_ica_status_lists`` supplies offline
    decompressed status bitstrings as base64. ``cawg_strict_encoding=True``
    refuses the CAWG field-order signer payload that c2pa-rs writes.
    ``strict_conformance=True`` applies the published Conformance Program
    posture under the 2.2 and 2.4 policies. Under ``spec_version="2.5"`` it
    applies strict technical validation with the core-spec compliance bar and
    makes no certified or Conformance Program claim. ``spec_version`` selects
    the C2PA validation policy: ``"2.2"``, ``None`` or ``"2.4"`` (the default,
    with identical reports), or ``"2.5"`` for the published standard, which reports
    ``profile: "c2pa-2.5"``. Any other value raises ``ValueError`` with the
    ``unsupported_spec_version`` code before the asset is read. On first interactive use,
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
    ``external_data`` supplies content the manifest names by URI. Its values
    are standard base64 strings, not raw bytes. ``external_data_media_types``
    records the observed media type for each supplied URI.
    ``external_data_unreachable`` records URIs whose retrieval was attempted
    but produced no usable body; omitting a URI means retrieval was not
    attempted. These inputs are evidence only. They do not enable ``online``
    and this SDK does not fetch an omitted resource unless online verification
    is separately enabled.
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
    options = {
        "trust_pem": trust_pem,
        "claim_trust_sources": [dict(entry) for entry in claim_trust_sources]
        if claim_trust_sources
        else None,
        "tsa_trust_pem": tsa_trust_pem,
        "tsa_trust_sources": [dict(entry) for entry in tsa_trust_sources]
        if tsa_trust_sources
        else None,
        "allowed_list_pem": allowed_list_pem,
        "cawg_trust_pem": cawg_trust_pem,
        "cawg_allowed_certs_pem": cawg_allowed_certs_pem,
        "cawg_trust_configurations": [dict(entry) for entry in cawg_trust_configurations]
        if cawg_trust_configurations
        else None,
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
        "spec_version": spec_version,
        "validation_time": validation_time,
        "external_data": dict(external_data)
        if external_data is not None
        else None,
        "external_data_media_types": dict(external_data_media_types)
        if external_data_media_types is not None
        else None,
        "external_data_unreachable": list(external_data_unreachable)
        if external_data_unreachable is not None
        else None,
        "online": online,
        "online_allow_private_networks": bool(online_allow_private_networks),
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    options_json = json.dumps(options)
    _validate_options(options_json)

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
    if manifest_store is not None:
        if fragments is not None:
            raise ValueError("manifest_store cannot be combined with fragments")
        if isinstance(manifest_store, (str, Path)):
            store = _read_path(Path(manifest_store))
        elif isinstance(manifest_store, (bytes, bytearray, memoryview)):
            store = manifest_store
        else:
            raise TypeError("manifest_store must be bytes or a filesystem path")
        report = verify_detached_bytes(data, store, mime_type, options_json)
    elif fragments is None:
        report = verify_bytes(data, mime_type, options_json)
    else:
        fragment_data = []
        for fragment in fragments:
            if isinstance(fragment, (str, Path)):
                fragment_data.append(_read_path(Path(fragment)))
            elif isinstance(fragment, (bytes, bytearray, memoryview)):
                fragment_data.append(fragment)
            else:
                raise TypeError("each fragment must be bytes or a filesystem path")
        report = verify_fragmented_bytes(data, fragment_data, mime_type, options_json)
    return json.loads(report)

def verify_manifest_store_only(
    manifest_store: Asset,
    *,
    options: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    """Validate a manifest store without claiming any asset-content match."""
    options_json = json.dumps(dict(options or {}))
    _validate_options(options_json)
    if isinstance(manifest_store, (str, Path)):
        store = _read_path(Path(manifest_store))
    elif isinstance(manifest_store, (bytes, bytearray, memoryview)):
        store = manifest_store
    else:
        raise TypeError("manifest_store must be bytes or a filesystem path")
    return json.loads(_verify_manifest_store_only_bytes(store, options_json))

def binding_target(
    manifest_store: Asset,
    *,
    hostless: bool = False,
    options: Optional[Mapping[str, Any]] = None,
) -> Optional[Mapping[str, Any]]:
    """Derive the exact hard-binding target a trusted caller must compare."""
    options_json = json.dumps(dict(options or {}))
    _validate_options(options_json)
    if isinstance(manifest_store, (str, Path)):
        store = _read_path(Path(manifest_store))
    elif isinstance(manifest_store, (bytes, bytearray, memoryview)):
        store = manifest_store
    else:
        raise TypeError("manifest_store must be bytes or a filesystem path")
    return json.loads(_binding_target_bytes(store, hostless, options_json))


def verify_with_caller_verified_binding(
    manifest_store: Asset,
    content_mime: str,
    target: Mapping[str, Any],
    *,
    matched: bool,
    engine: str,
    explanation: Optional[str] = None,
    hostless: bool = False,
    options: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    """Validate a store using an exact content comparison made by the caller."""
    options_json = json.dumps(dict(options or {}))
    _validate_options(options_json)
    if matched and explanation is not None:
        raise ValueError("explanation is only valid for a mismatch")
    if not matched and not explanation:
        raise ValueError("a mismatch requires explanation")
    verdict: Any = "Match" if matched else {"Mismatch": {"explanation": explanation}}
    target_json = json.dumps(dict(target))
    verdict_json = json.dumps(verdict)
    if isinstance(manifest_store, (str, Path)):
        store = _read_path(Path(manifest_store))
    elif isinstance(manifest_store, (bytes, bytearray, memoryview)):
        store = manifest_store
    else:
        raise TypeError("manifest_store must be bytes or a filesystem path")
    return json.loads(
        _verify_caller_binding_bytes(
            store,
            content_mime,
            hostless,
            target_json,
            verdict_json,
            engine,
            options_json,
        )
    )


def verify_ertmp(
    input_events: Mapping[str, Any],
    *,
    options: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    """Verify caller-parsed Enhanced RTMP events in exact transmission order.

    ``input_events`` carries bilateral ``capsEx``, ``object_encoding`` and an
    ordered ``events`` array. Aggregate timestamps must already be normalized,
    and Multitrack events must contain only the selected track packet. The
    verifier never guesses an undefined audio Metadata packet number.
    """
    resolved_options = dict(options or {})
    resolved_options.setdefault("spec_version", "2.5")
    options_json = json.dumps(resolved_options)
    _validate_options(options_json)
    return json.loads(verify_ertmp_events(json.dumps(dict(input_events)), options_json))


def resolve_soft_binding(
    asset: Asset,
    mime_type: Optional[str],
    service_root: str,
    query: Mapping[str, Any],
    *,
    allowed_origins: Sequence[str],
    options: Optional[Mapping[str, Any]] = None,
    allow_private_networks: bool = False,
    max_results: int = 10,
    fetch_status: bool = False,
    fetch_receipts: bool = False,
) -> Mapping[str, Any]:
    """Recover and verify manifests through a soft-binding resolution service.

    ``query`` selects one tagged route: ``binding_get``, ``binding_post``,
    ``content``, or ``reference``. Content and reference disclosure require
    their matching explicit consent value. Every discovery, federation, and
    repository origin must appear exactly in ``allowed_origins``. Redirects
    are refused. The service's advertised version never selects local policy.
    """
    if not allowed_origins:
        raise ValueError("allowed_origins must contain at least one exact origin")
    verify_options = dict(options or {})
    verify_options_json = json.dumps(verify_options)
    _validate_options(verify_options_json)
    resolver_options = {
        "allowed_origins": list(allowed_origins),
        "allow_private_networks": bool(allow_private_networks),
        "max_results": int(max_results),
        "fetch_status": bool(fetch_status),
        "fetch_receipts": bool(fetch_receipts),
    }
    query_json = json.dumps(dict(query))
    resolver_options_json = json.dumps(resolver_options)
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
    return json.loads(
        _resolve_soft_binding_bytes(
            data,
            mime_type,
            service_root,
            query_json,
            verify_options_json,
            resolver_options_json,
        )
    )

def request_soft_binding_receipt_verification(
    service_root: str,
    manifest_id: str,
    receipt: Mapping[str, Any],
    *,
    allowed_origins: Sequence[str],
    options: Optional[Mapping[str, Any]] = None,
    allow_private_networks: bool = False,
) -> Mapping[str, Any]:
    """Return a repository's report about a supplied receipt.

    ``server_reported_verified`` is operational evidence. It is not a local
    cryptographic receipt verdict.
    """
    if not allowed_origins:
        raise ValueError("allowed_origins must contain at least one exact origin")
    resolver_options = {
        "allowed_origins": list(allowed_origins),
        "allow_private_networks": bool(allow_private_networks),
    }
    verify_options = dict(options or {})
    _validate_options(json.dumps(verify_options))
    return json.loads(
        _request_soft_binding_receipt_verification_json(
            service_root,
            manifest_id,
            json.dumps(dict(receipt)),
            json.dumps(verify_options),
            json.dumps(resolver_options),
        )
    )


def verify_stream(
    init_segment: Asset,
    segments: Sequence[Asset],
    mime_type: Optional[str] = None,
    *,
    encapsulation: str = "fMP4",
    method: str = "verifiable-segment-info",
    expected_seek_positions: Optional[Sequence[int]] = None,
    trust_pem: Optional[str] = None,
    claim_trust_sources: Optional[Sequence[Mapping[str, Any]]] = None,
    tsa_trust_pem: Optional[str] = None,
    tsa_trust_sources: Optional[Sequence[Mapping[str, Any]]] = None,
    allowed_list_pem: Optional[str] = None,
    cawg_trust_pem: Optional[str] = None,
    cawg_allowed_certs_pem: Optional[str] = None,
    cawg_trust_configurations: Optional[Sequence[Mapping[str, Any]]] = None,
    no_default_trust: bool = False,
    cawg_did_documents: Optional[Mapping[str, Any]] = None,
    cawg_ica_trusted_issuers: Optional[Sequence[str]] = None,
    cawg_ica_trust_anchors: Optional[Sequence[str]] = None,
    cawg_ica_status_lists: Optional[Mapping[str, str]] = None,
    cawg_strict_encoding: bool = False,
    strict_conformance: bool = False,
    spec_version: Optional[str] = None,
    validation_time: Optional[str] = None,
    stream_presentation_times: Optional[Sequence[str]] = None,
    telemetry: Optional[bool] = None,
    telemetry_endpoint: Optional[str] = None,
    online: Optional[bool] = None,
    external_data: Optional[Mapping[str, str]] = None,
    external_data_media_types: Optional[Mapping[str, str]] = None,
    external_data_unreachable: Optional[Sequence[str]] = None,
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

    ``stream_presentation_times`` is one trusted RFC 3339 instant per entry in
    ``segments``, in the same order. Each session-key segment's key window is
    checked at its own instant instead of ``validation_time``, which still
    governs certificate trust; sequence continuity is still enforced across
    segments signed under different keys. The verifier takes these instants on
    the caller's word and never reads them from the segments, so supply them
    only from a record you control. ``None`` checks every segment at
    ``validation_time`` (default now); a time stamp on the init manifest does
    not date later segments. A malformed instant or a count that differs from
    ``len(segments)`` raises; Merkle-bound and per-segment streams refuse it.

    The returned report carries a top-level ``integrity``, the init manifest's
    report under ``stream``, per-segment reports under ``segments``, and the
    recomputed ``chain_valid`` for per-segment streams. Trust, telemetry,
    caller-supplied external resource evidence, and ``spec_version`` behave
    exactly as in :func:`verify`.
    """
    if isinstance(stream_presentation_times, (str, bytes)):
        raise TypeError("stream_presentation_times must be a sequence of RFC 3339 strings")
    options = {
        "trust_pem": trust_pem,
        "claim_trust_sources": [dict(entry) for entry in claim_trust_sources]
        if claim_trust_sources
        else None,
        "tsa_trust_pem": tsa_trust_pem,
        "tsa_trust_sources": [dict(entry) for entry in tsa_trust_sources]
        if tsa_trust_sources
        else None,
        "allowed_list_pem": allowed_list_pem,
        "cawg_trust_pem": cawg_trust_pem,
        "cawg_allowed_certs_pem": cawg_allowed_certs_pem,
        "cawg_trust_configurations": [dict(entry) for entry in cawg_trust_configurations]
        if cawg_trust_configurations
        else None,
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
        "spec_version": spec_version,
        "validation_time": validation_time,
        "stream_presentation_times": list(stream_presentation_times)
        if stream_presentation_times is not None
        else None,
        "online": online,
        "external_data": dict(external_data)
        if external_data is not None
        else None,
        "external_data_media_types": dict(external_data_media_types)
        if external_data_media_types is not None
        else None,
        "external_data_unreachable": list(external_data_unreachable)
        if external_data_unreachable is not None
        else None,
        "online_allow_private_networks": bool(online_allow_private_networks),
        "telemetry": {
            "enabled": telemetry,
            "endpoint": telemetry_endpoint,
            "sdk_name": "python",
        },
    }
    options_json = json.dumps(options)
    _validate_options(options_json)

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
    return json.loads(
        verify_stream_bytes(
            init_data,
            segment_data,
            mime_type,
            encapsulation,
            method,
            options_json,
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
