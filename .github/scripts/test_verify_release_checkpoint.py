#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path

_PATH = Path(__file__).with_name("verify_release_checkpoint.py")
_SPEC = importlib.util.spec_from_file_location("verify_release_checkpoint", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
verify_release_checkpoint = _MODULE.verify_release_checkpoint

COMMIT = "a" * 40


def release(**overrides):
    value = {
        "id": 123,
        "tag_name": "v1.0.0",
        "target_commitish": COMMIT,
        "name": "Encypher C2PA 1.0.0",
        "draft": True,
        "prerelease": False,
        "published_at": None,
    }
    value.update(overrides)
    return value


class VerifyReleaseCheckpointTests(unittest.TestCase):
    def test_accepts_unpublished_draft(self):
        self.assertEqual(
            verify_release_checkpoint([release()], "v1.0.0", COMMIT, "1.0.0"),
            {"release_id": 123, "was_draft": True},
        )

    def test_accepts_already_published_release(self):
        self.assertEqual(
            verify_release_checkpoint(
                [release(draft=False, published_at="2026-08-11T12:53:29Z")],
                "v1.0.0",
                COMMIT,
                "1.0.0",
            ),
            {"release_id": 123, "was_draft": False},
        )

    def test_rejects_published_release_without_timestamp(self):
        with self.assertRaisesRegex(ValueError, "no publication time"):
            verify_release_checkpoint(
                [release(draft=False)], "v1.0.0", COMMIT, "1.0.0"
            )

    def test_rejects_draft_with_timestamp(self):
        with self.assertRaisesRegex(ValueError, "draft release"):
            verify_release_checkpoint(
                [release(published_at="2026-08-11T12:53:29Z")],
                "v1.0.0",
                COMMIT,
                "1.0.0",
            )

    def test_rejects_wrong_release_identity(self):
        with self.assertRaisesRegex(ValueError, "checkpoint mismatch"):
            verify_release_checkpoint(
                [release(target_commitish="b" * 40)], "v1.0.0", COMMIT, "1.0.0"
            )

    def test_rejects_duplicate_tag(self):
        with self.assertRaisesRegex(ValueError, "found 2"):
            verify_release_checkpoint(
                [release(), release(id=456)], "v1.0.0", COMMIT, "1.0.0"
            )


if __name__ == "__main__":
    unittest.main()
