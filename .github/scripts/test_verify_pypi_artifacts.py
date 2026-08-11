#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path

_PATH = Path(__file__).with_name("verify_pypi_artifacts.py")
_SPEC = importlib.util.spec_from_file_location("verify_pypi_artifacts", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
compare_artifacts = _MODULE.compare_artifacts
remote_artifacts = _MODULE.remote_artifacts

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
LOCAL = {"package.whl": DIGEST_A, "package.tar.gz": DIGEST_B}


def artifact(name, digest):
    return {"filename": name, "digests": {"sha256": digest}}


class VerifyPyPIArtifactsTests(unittest.TestCase):
    def test_complete_set(self):
        self.assertEqual(compare_artifacts(LOCAL, dict(LOCAL)), "complete")

    def test_exact_subset(self):
        self.assertEqual(compare_artifacts(LOCAL, {"package.whl": DIGEST_A}), "subset")

    def test_digest_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, "mismatched"):
            compare_artifacts(LOCAL, {"package.whl": DIGEST_B})

    def test_extra_remote_artifact_fails(self):
        with self.assertRaisesRegex(ValueError, "mismatched"):
            compare_artifacts(LOCAL, {"other.whl": DIGEST_A})

    def test_duplicate_remote_artifact_fails(self):
        metadata = {"urls": [artifact("package.whl", DIGEST_A)] * 2}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            remote_artifacts(metadata)

    def test_invalid_remote_metadata_fails(self):
        cases = [
            None,
            {},
            {"urls": [None]},
            {"urls": [{"filename": "package.whl"}]},
            {"urls": [artifact("", DIGEST_A)]},
            {"urls": [artifact("package.whl", "not-a-sha256")]},
        ]
        for metadata in cases:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                remote_artifacts(metadata)


if __name__ == "__main__":
    unittest.main()
