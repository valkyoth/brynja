#!/usr/bin/env python3
"""Fail-closed static runner and registry regression tests."""
import importlib.util
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("aes_static", Path(__file__).with_name("check-aes-static.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class StaticTests(unittest.TestCase):
    def test_baseline_probe_requires_complete_arm_target_feature_bundle(self):
        source = (ROOT / 'assurance/aes-kernel-candidate/probe.rs').read_text()
        arm = source.split('#[cfg(target_arch = "aarch64")]', 1)[1].split(';', 1)[0]
        self.assertEqual(' '.join(arm.split()),
            'let supported = cfg!(target_endian = "little") '
            '&& std::arch::is_aarch64_feature_detected!("aes") '
            '&& std::arch::is_aarch64_feature_detected!("pmull") '
            '&& std::arch::is_aarch64_feature_detected!("neon")')

    def output(self):
        return "\n".join((*RUNNER.KAT_MARKERS, "test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"))

    def test_complete_population_and_markers(self):
        RUNNER.validate_tests(self.output(), 13, RUNNER.KAT_MARKERS)

    def test_wrong_failed_ignored_or_duplicated_population(self):
        for text in ("", self.output().replace("13 passed", "12 passed"),
                     self.output().replace("0 failed", "1 failed"),
                     self.output().replace("0 ignored", "1 ignored"), self.output() * 2):
            with self.assertRaises(ValueError):
                RUNNER.validate_tests(text, 13, RUNNER.KAT_MARKERS)

    def test_missing_or_repeated_corpus(self):
        for marker in RUNNER.KAT_MARKERS:
            for text in (self.output().replace(marker, ""), self.output() + "\n" + marker,
                         self.output().replace(marker, "not executed " + marker)):
                with self.assertRaises(ValueError):
                    RUNNER.validate_tests(text, 13, RUNNER.KAT_MARKERS)

    def test_baseline_cannot_count_as_accelerated(self):
        text = "test result: ok. 1 passed; 0 failed; 0 ignored;"
        with self.assertRaises(ValueError):
            RUNNER.validate_tests(text, 13, RUNNER.KAT_MARKERS)
        RUNNER.validate_tests(text, 1)

    def test_registry_exact_modes_and_input_closure(self):
        registry = tomllib.loads((ROOT / "verification/checks.toml").read_text())
        checks = {c["id"]: c for c in registry["checks"] if c.get("category") == "aes-static"}
        self.assertEqual(set(checks), {f"static-{mode}-{endpoint}" for mode in ("native", "baseline", "arm-qemu")
                                     for endpoint in ("msrv", "current")})
        for mode in ("native", "baseline", "arm-qemu"):
            for endpoint, toolchain in (("msrv", "1.90.0"), ("current", "1.99.1")):
                check = checks[f"static-{mode}-{endpoint}"]
                self.assertEqual(check["command"], ["python3", "scripts/aes/check-aes-static.py",
                                                  "--mode", mode, "--toolchain", toolchain])
                self.assertTrue({"cpu-source", "aes-build", "aes-static-execution", "hash-core",
                                 "sha2-source", "sha3-source", "hmac-source", "kmac-source",
                                 "tuplehash-source", "parallelhash-source"} <= set(check["inputs"]))
                self.assertEqual(check["success"]["exact_tests"], 7 if mode == "baseline" else 26)
                markers = [f"AES_STATIC_PASS: {mode} {toolchain}"]
                if mode != "baseline":
                    markers += list(RUNNER.KAT_MARKERS)
                    markers += [RUNNER.STARTUP_MARKER, *RUNNER.FAULT_MARKERS]
                self.assertEqual(check["success"]["unique_lines"], markers)
                if mode == "arm-qemu":
                    self.assertIn("aes-kernel-qemu", check["inputs"])
                self.assertIn("not final", check["establishes"])

    def test_expansion_failure_and_startup_markers_are_required(self):
        markers = (RUNNER.STARTUP_MARKER, *RUNNER.FAULT_MARKERS)
        text = '\n'.join((*markers, 'test result: ok. 4 passed; 0 failed; 0 ignored;'))
        RUNNER.validate_tests(text, 4, markers)
        for marker in markers:
            for bad in (text.replace(marker, ''), text + '\n' + marker,
                        text.replace(marker, 'test unrelated ... ' + marker)):
                with self.assertRaises(ValueError): RUNNER.validate_tests(bad, 4, markers)


if __name__ == "__main__":
    unittest.main()
