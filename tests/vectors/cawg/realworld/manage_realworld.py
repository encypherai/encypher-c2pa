#!/usr/bin/env python3
"""Manage the pinned real-world news-content corpus (IPTC sample content).

Assets are published by IPTC expressly as validation sample content at
https://iptc.org/std/MediaProvenance/SampleContent/ and pinned here by
sha256 + size. `check` is fully offline; `fetch` re-downloads missing
assets from the pinned URLs and verifies the pinned digests;
`fetch --refresh-trust` additionally re-downloads the trust lists (which
age) and rewrites their pinned digests in index.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parent
INDEX: Final = ROOT / "index.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_index() -> dict:
    if not INDEX.is_file():
        raise FileNotFoundError(f"missing index: {INDEX}")
    return json.loads(INDEX.read_text())


def _verify_pinned(path: Path, pinned: dict, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing {label}: {path}")
    data = path.read_bytes()
    if _sha256(data) != pinned["sha256"] or len(data) != pinned["size"]:
        raise ValueError(f"digest or size mismatch for {label}: {path}")


def check() -> None:
    document = _load_index()
    if document.get("network_policy") != "offline":
        raise ValueError("index network_policy must be offline")
    vectors = document["vectors"]
    if document.get("vector_count") != len(vectors):
        raise ValueError("vector_count does not match vectors array")
    seen: set[str] = set()
    for entry in vectors:
        vector_id = entry["id"]
        if vector_id in seen:
            raise ValueError(f"duplicate vector id: {vector_id}")
        seen.add(vector_id)
        _verify_pinned(ROOT / entry["path"], entry, vector_id)
    for name, pinned in document["trust"].items():
        _verify_pinned(ROOT / pinned["path"], pinned, name)
    print(f"ok: {len(vectors)} vectors and {len(document['trust'])} trust lists verified")


def fetch(refresh_trust: bool) -> None:
    document = _load_index()
    for entry in document["vectors"]:
        path = ROOT / entry["path"]
        if path.is_file():
            continue
        with urllib.request.urlopen(entry["source_url"], timeout=120) as response:
            data = response.read()
        if _sha256(data) != entry["sha256"] or len(data) != entry["size"]:
            raise ValueError(f"downloaded bytes do not match pinned index: {entry['id']}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if refresh_trust:
        for pinned in document["trust"].values():
            with urllib.request.urlopen(pinned["source_url"], timeout=120) as response:
                data = response.read()
            (ROOT / pinned["path"]).write_bytes(data)
            pinned["sha256"] = _sha256(data)
            pinned["size"] = len(data)
        INDEX.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "fetch"), nargs="?", default="check")
    parser.add_argument(
        "--refresh-trust",
        action="store_true",
        help="with fetch: re-download the trust lists and re-pin their digests",
    )
    args = parser.parse_args()
    if args.command == "fetch":
        fetch(args.refresh_trust)
    check()


if __name__ == "__main__":
    main()
