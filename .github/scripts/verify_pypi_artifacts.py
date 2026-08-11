#!/usr/bin/env python3
"""Compare local Python distributions with one PyPI version response."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}")


def local_artifacts(root: Path) -> dict[str, str]:
    if not root.is_dir():
        raise ValueError(f"artifact directory is missing: {root}")
    artifacts: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"local artifact path is a symbolic link: {path}")
        if not path.is_file():
            continue
        if path.name in artifacts:
            raise ValueError(f"duplicate local artifact name: {path.name!r}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        artifacts[path.name] = digest.hexdigest()
    if not artifacts:
        raise ValueError("local artifact set is empty")
    return artifacts


def remote_artifacts(metadata: Any) -> dict[str, str]:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("urls"), list):
        raise ValueError("PyPI returned invalid version metadata")
    artifacts: dict[str, str] = {}
    for artifact in metadata["urls"]:
        if not isinstance(artifact, dict):
            raise ValueError("PyPI returned an invalid artifact entry")
        name = artifact.get("filename")
        digests = artifact.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise ValueError("PyPI returned invalid artifact metadata")
        if name in artifacts:
            raise ValueError(f"PyPI returned duplicate artifact name: {name!r}")
        artifacts[name] = digest
    return artifacts


def compare_artifacts(local: dict[str, str], remote: dict[str, str]) -> str:
    mismatched = {
        name: (digest, local.get(name))
        for name, digest in remote.items()
        if local.get(name) != digest
    }
    if mismatched:
        raise ValueError(f"PyPI contains extra or mismatched artifacts: {mismatched!r}")
    return "complete" if remote == local else "subset"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    with args.metadata.open(encoding="utf-8") as stream:
        metadata = json.load(stream)
    state = compare_artifacts(local_artifacts(args.artifacts), remote_artifacts(metadata))
    print(state)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"PyPI artifact comparison failed: {error}")
