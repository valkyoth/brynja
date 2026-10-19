#!/usr/bin/env python3
"""Reject package evidence bloat without losing runtime/build inputs."""
import unittest

from hmac_package import REQUIRED, OPTIONAL, validate_members


class PackageTests(unittest.TestCase):
    def test_runtime_archive(self):
        validate_members(REQUIRED)
        validate_members(REQUIRED | OPTIONAL)

    def test_required_inputs(self):
        for name in REQUIRED:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_members(REQUIRED - {name})

    def test_evidence_and_standalone_tests_stay_in_git(self):
        for name in ("evidence.json", "assurance/result.json", "native-capture.tar.gz",
                     "tests/vectors.rs", "scripts/check.py", "security/review.toml",
                     "src/tests/huge-fixture.json", "src/unreviewed.rs", "target/output",
                     "../outside", "/absolute", "src/../README.md", "src\\lib.rs"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_members([*REQUIRED, name])

    def test_duplicate(self):
        with self.assertRaises(ValueError):
            validate_members([*REQUIRED, "src/lib.rs"])


if __name__ == "__main__":
    unittest.main()
