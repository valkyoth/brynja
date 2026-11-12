#!/usr/bin/env python3
"""Fail-closed completion and scoped registration tests; no hardware execution."""
import importlib.util
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("aes_kernel_candidate", Path(__file__).with_name("check-aes-kernel-candidate.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class KernelCandidateTests(unittest.TestCase):
    def output(self):
        return "\n".join((*RUNNER.MARKERS, "test result: ok. 5 passed; 0 failed; 0 ignored;"))

    def test_complete_output(self):
        RUNNER.validate_output(self.output())

    def test_missing_or_duplicate_marker(self):
        for marker in RUNNER.MARKERS:
            for text in (self.output().replace(marker, ""), self.output() + "\n" + marker):
                with self.assertRaises(ValueError):
                    RUNNER.validate_output(text)

    def test_partial_or_ignored_population(self):
        for text in ("", self.output().replace("5 passed", "4 passed"),
                     self.output().replace("0 failed", "1 failed"),
                     self.output().replace("0 ignored", "1 ignored"),
                     self.output() + "\ntest result: ok. 5 passed; 0 failed; 0 ignored;"):
            with self.assertRaises(ValueError):
                RUNNER.validate_output(text)

    def test_marker_must_be_a_whole_line(self):
        with self.assertRaises(ValueError):
            RUNNER.validate_output(self.output().replace(RUNNER.MARKERS[0], "skipped " + RUNNER.MARKERS[0]))

    def test_scoped_registrations(self):
        registry = tomllib.loads((ROOT / "verification/checks.toml").read_text())
        checks = {c["id"]: c for c in registry["checks"] if c.get("category") == "kernel-candidate"}
        self.assertEqual(set(checks), {f"kernel-{arch}-{version}" for arch in ("x86", "arm-qemu")
                                     for version in ("msrv", "current")})
        for arch in ("x86", "arm-qemu"):
            for version, toolchain, group in (("msrv", "1.90.0", "hkdf-msrv"),
                                               ("current", "1.99.1", "compiler")):
                check = checks[f"kernel-{arch}-{version}"]
                expected = ["python3", "scripts/aes/check-aes-kernel-candidate.py", "--toolchain", toolchain]
                if arch == "arm-qemu":
                    expected.append("--qemu-aarch64")
                    self.assertIn("aes-kernel-qemu", check["inputs"])
                    self.assertIn("emulation", check["establishes"])
                self.assertEqual(check["command"], expected)
                self.assertIn(group, check["inputs"])
                self.assertIn("aes-kernel-candidate", check["inputs"])
                self.assertEqual(check["success"]["exact_tests"], 5)
                self.assertEqual(check["success"]["unique_lines"], list(RUNNER.MARKERS))
                self.assertIn("not public acceleration", check["establishes"])
        paths = registry["groups"]["aes-kernel-candidate"]["paths"]
        for path in ("crates/brynja-crypto-cpu/src/aes", "assurance/aes-kernel-candidate",
                     "crates/brynja-crypto/tests/fixtures/aes128",
                     "crates/brynja-crypto/tests/fixtures/aes192",
                     "crates/brynja-crypto/tests/fixtures/aes256",
                     "scripts/aes/check-aes-kernel-candidate.py",
                     "scripts/aes/test-aes-kernel-candidate.py"):
            self.assertIn(path, paths)


if __name__ == "__main__":
    unittest.main()
