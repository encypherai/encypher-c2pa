#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path

_PATH = Path(__file__).with_name("verify_release_tag.py")
_SPEC = importlib.util.spec_from_file_location("verify_release_tag", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
verify_tag_binding = _MODULE.verify_tag_binding

COMMIT = "a" * 40
TAG_ONE = "b" * 40
TAG_TWO = "c" * 40


def ref(object_type="commit", sha=COMMIT, name="v1.0.0"):
    return {"ref": f"refs/tags/{name}", "object": {"type": object_type, "sha": sha}}


def tag(sha, object_type, target):
    return {"sha": sha, "object": {"type": object_type, "sha": target}}


class VerifyTagBindingTests(unittest.TestCase):
    def test_lightweight_tag_matches_commit(self):
        verify_tag_binding("v1.0.0", COMMIT, ref(), lambda _: self.fail("unexpected load"))

    def test_nested_annotated_tag_peels_to_commit(self):
        objects = {
            TAG_ONE: tag(TAG_ONE, "tag", TAG_TWO),
            TAG_TWO: tag(TAG_TWO, "commit", COMMIT),
        }
        verify_tag_binding("v1.0.0", COMMIT, ref("tag", TAG_ONE), objects.__getitem__)

    def test_moved_tag_fails(self):
        with self.assertRaisesRegex(ValueError, "not workflow commit"):
            verify_tag_binding("v1.0.0", COMMIT, ref(sha="d" * 40), lambda _: None)

    def test_wrong_ref_fails(self):
        with self.assertRaisesRegex(ValueError, "Git ref mismatch"):
            verify_tag_binding("v1.0.0", COMMIT, ref(name="v2.0.0"), lambda _: None)

    def test_annotated_tag_cycle_fails(self):
        objects = {TAG_ONE: tag(TAG_ONE, "tag", TAG_ONE)}
        with self.assertRaisesRegex(ValueError, "cycle"):
            verify_tag_binding("v1.0.0", COMMIT, ref("tag", TAG_ONE), objects.__getitem__)

    def test_annotated_tag_depth_fails(self):
        objects = {TAG_ONE: tag(TAG_ONE, "tag", TAG_TWO)}
        with self.assertRaisesRegex(ValueError, "depth"):
            verify_tag_binding(
                "v1.0.0",
                COMMIT,
                ref("tag", TAG_ONE),
                objects.__getitem__,
                max_depth=1,
            )

    def test_invalid_object_type_fails(self):
        with self.assertRaisesRegex(ValueError, "invalid object type"):
            verify_tag_binding("v1.0.0", COMMIT, ref("tree"), lambda _: None)


if __name__ == "__main__":
    unittest.main()
