#!/usr/bin/env python3
"""Regenerate the signed external-reference fixture with a real signing CLI.

Example, from the repository root, using any test-only C2PA claim key and its
certificate:

    python bindings/python/tests/generate_external_data_fixture.py \
      --signer /path/to/encypher-c2pa \
      --source /path/to/unsigned.jpg \
      --key /path/to/claim.key.pem \
      --cert /path/to/claim.cert.pem

The helper uses only the standard library. It writes canonical CBOR assertions,
then asks the signing CLI to bind them and the source image into the checked-in
fixture. The private key is neither copied nor retained.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).with_name("fixtures")
OUTPUT = FIXTURES / "external-reference.jpg"
BODY_OUTPUT = FIXTURES / "external-body.txt"
EXTERNAL_URI = "https://e.example/python-external-evidence.txt"
EXTERNAL_BODY = b"caller-supplied external evidence for the Python binding\n"


def _cbor_length(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def _cbor(value: Any) -> bytes:
    if isinstance(value, bytes):
        return _cbor_length(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_length(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _cbor_length(4, len(value)) + b"".join(_cbor(item) for item in value)
    if isinstance(value, dict):
        encoded = [(_cbor(key), _cbor(item)) for key, item in value.items()]
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _cbor_length(5, len(encoded)) + b"".join(
            key + item for key, item in encoded
        )
    raise TypeError(f"fixture CBOR encoder does not support {type(value).__name__}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--signer", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--body-output", type=Path, default=BODY_OUTPUT)
    arguments = parser.parse_args()

    actions = {
        "actions": [
            {
                "action": "c2pa.created",
                "when": "2026-10-12T00:00:00Z",
                "softwareAgent": {
                    "name": "Encypher Python binding fixture",
                    "version": "1",
                },
                "digitalSourceType": (
                    "http://cv.iptc.org/newscodes/digitalsourcetype/"
                    "digitalCapture"
                ),
            }
        ]
    }
    external_reference = {
        "label": "com.encypher.python.external-evidence",
        "location": {
            "url": EXTERNAL_URI,
            "alg": "sha256",
            "hash": hashlib.sha256(EXTERNAL_BODY).digest(),
        },
    }

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.body_output.parent.mkdir(parents=True, exist_ok=True)
    arguments.body_output.write_bytes(EXTERNAL_BODY)
    with tempfile.TemporaryDirectory(prefix="encypher-python-external-") as directory:
        scratch = Path(directory)
        actions_path = scratch / "actions.cbor"
        external_path = scratch / "external-reference.cbor"
        actions_path.write_bytes(_cbor(actions))
        external_path.write_bytes(_cbor(external_reference))
        command = [
            str(arguments.signer),
            "sign",
            str(arguments.source),
            "--mime",
            "image/jpeg",
            "--spec",
            "2.4",
            "--key",
            str(arguments.key),
            "--cert",
            str(arguments.cert),
            "--out",
            str(arguments.output),
            "--instance-id",
            "urn:uuid:8fa1c7ce-e4a2-4ae3-8f18-4e58d30b6d52",
            "--manifest-label",
            "urn:c2pa:bd2fc6e4-b486-4eab-8ac6-e591d96921a5",
            "--extra-assertion-cbor",
            f"c2pa.actions.v2={actions_path}",
            "--extra-assertion-cbor",
            f"c2pa.external-reference={external_path}",
        ]
        subprocess.run(command, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
