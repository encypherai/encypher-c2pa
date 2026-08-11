#!/usr/bin/env python3
"""Validate the GitHub release bound to an interrupted release run."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def verify_release_checkpoint(
    releases: Any,
    tag: str,
    commit: str,
    version: str,
) -> dict[str, int | bool]:
    if not isinstance(releases, list):
        raise ValueError("GitHub releases response is not an array")
    matches = [
        release
        for release in releases
        if isinstance(release, dict) and release.get("tag_name") == tag
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one release checkpoint for {tag!r}, found {len(matches)}")

    release = matches[0]
    expected = {
        "tag_name": tag,
        "target_commitish": commit,
        "name": f"Encypher C2PA {version}",
        "prerelease": "-" in version,
    }
    observed = {key: release.get(key) for key in expected}
    if observed != expected:
        raise ValueError(f"release checkpoint mismatch: {observed!r} != {expected!r}")

    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise ValueError(f"release checkpoint has invalid id {release_id!r}")

    draft = release.get("draft")
    published_at = release.get("published_at")
    if draft is True:
        if published_at is not None:
            raise ValueError("draft release checkpoint has a publication time")
    elif draft is False:
        if not isinstance(published_at, str) or not published_at:
            raise ValueError("published release checkpoint has no publication time")
    else:
        raise ValueError(f"release checkpoint has invalid draft state {draft!r}")

    return {"release_id": release_id, "was_draft": draft}


def main() -> int:
    if len(sys.argv) != 5:
        raise ValueError("usage: verify_release_checkpoint.py RELEASES TAG COMMIT VERSION")
    path, tag, commit, version = sys.argv[1:]
    releases = json.loads(Path(path).read_text(encoding="utf-8"))
    print(json.dumps(verify_release_checkpoint(releases, tag, commit, version)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"release checkpoint check failed: {error}")
