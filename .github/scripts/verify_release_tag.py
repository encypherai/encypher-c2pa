#!/usr/bin/env python3
"""Fail unless the triggering Git tag still peels to the workflow commit."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_MAX_TAG_DEPTH = 16


def _object(payload: Any, context: str) -> tuple[str, str]:
    if not isinstance(payload, dict):
        raise ValueError(f"{context} response is not an object")
    value = payload.get("object")
    if not isinstance(value, dict):
        raise ValueError(f"{context} has no object")
    object_type = value.get("type")
    sha = value.get("sha")
    if object_type not in ("commit", "tag"):
        raise ValueError(f"{context} has invalid object type {object_type!r}")
    if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
        raise ValueError(f"{context} has invalid object SHA {sha!r}")
    return object_type, sha


def verify_tag_binding(
    tag_name: str,
    expected_sha: str,
    ref: Any,
    load_tag: Callable[[str], Any],
    *,
    max_depth: int = _MAX_TAG_DEPTH,
) -> None:
    if not tag_name or tag_name.startswith("/") or "\0" in tag_name:
        raise ValueError(f"invalid tag name {tag_name!r}")
    if _SHA.fullmatch(expected_sha) is None:
        raise ValueError(f"invalid workflow SHA {expected_sha!r}")
    expected_ref = f"refs/tags/{tag_name}"
    if not isinstance(ref, dict) or ref.get("ref") != expected_ref:
        actual_ref = ref.get("ref") if isinstance(ref, dict) else None
        raise ValueError(f"Git ref mismatch: {actual_ref!r} != {expected_ref!r}")

    object_type, sha = _object(ref, expected_ref)
    seen: set[str] = set()
    depth = 0
    while object_type == "tag":
        if sha in seen:
            raise ValueError(f"annotated tag cycle at {sha}")
        if depth >= max_depth:
            raise ValueError(f"annotated tag depth exceeds {max_depth}")
        seen.add(sha)
        payload = load_tag(sha)
        if not isinstance(payload, dict) or payload.get("sha") != sha:
            actual = payload.get("sha") if isinstance(payload, dict) else None
            raise ValueError(f"annotated tag object mismatch: {actual!r} != {sha!r}")
        object_type, sha = _object(payload, f"annotated tag {sha}")
        depth += 1

    if sha != expected_sha:
        raise ValueError(f"tag {tag_name!r} peels to {sha}, not workflow commit {expected_sha}")


def main() -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    tag_name = os.environ["GITHUB_REF_NAME"]
    expected_sha = os.environ["GITHUB_SHA"]
    token = os.environ["GH_TOKEN"]
    base = f"https://api.github.com/repos/{repository}"

    def request(path: str) -> Any:
        req = urllib.request.Request(
            base + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "encypher-c2pa-release-workflow/1.0",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    raise ValueError(f"GitHub returned HTTP {response.status} for {path}")
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise ValueError(f"GitHub returned HTTP {error.code} for {path}") from error
        except urllib.error.URLError as error:
            raise ValueError(f"GitHub request failed for {path}: {error.reason}") from error

    encoded_tag = urllib.parse.quote(tag_name, safe="")
    ref = request(f"/git/ref/tags/{encoded_tag}")
    verify_tag_binding(tag_name, expected_sha, ref, lambda sha: request(f"/git/tags/{sha}"))
    print(f"verified refs/tags/{tag_name} peels to workflow commit {expected_sha}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, ValueError) as error:
        raise SystemExit(f"release tag binding check failed: {error}")
