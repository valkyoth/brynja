#!/usr/bin/env python3
"""Fail-closed checks for exact core guard artifact replay."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "guard_artifacts", Path(__file__).with_name("check-aes-fault-guard-artifacts.py"))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


class GuardArtifactTests(unittest.TestCase):
    def test_unknown_elf_rejected_before_subprocess(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unknown.elf"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00")
            with patch.object(S.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "unreviewed guard test ELF"):
                    S.inspect(path)
                run.assert_not_called()

    def test_both_distinct_artifacts_required(self):
        path = Path("/tmp/test.elf")
        digest = next(iter(S.PINNED))
        with patch.object(S, "inspect", return_value=(path, digest)), \
             patch.object(S.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "both distinct"):
                S.replay([path, path])
            run.assert_not_called()

    def test_every_named_guard_case_required(self):
        digest = next(iter(S.PINNED))
        valid = {"binary_sha256": digest,
                 "observations": [{"case": name} for name in S.GUARD.CASES]}
        S.validate_result(valid, digest)
        for result in ({"binary_sha256": digest, "observations": valid["observations"][:-1]},
                       {"binary_sha256": "wrong", "observations": valid["observations"]},
                       {"binary_sha256": digest, "observations": [valid["observations"][0]] * 7}):
            with self.assertRaises(ValueError):
                S.validate_result(result, digest)

    def test_record_pins_fixture_and_artifacts(self):
        S.check_record()
        with patch.object(S.GUARD, "TEST", "different-fixture"):
            with self.assertRaisesRegex(ValueError, "record drift"):
                S.check_record()


if __name__ == "__main__":
    unittest.main()
