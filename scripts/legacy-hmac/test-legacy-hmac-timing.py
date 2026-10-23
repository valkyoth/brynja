#!/usr/bin/env python3
"""Population, failure preservation, CPU admission and compiled preflight tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import legacy_hmac_timing as timing
import legacy_hmac_timing_runner as runner


def output(route="portable", family="sha1", arch="x86_64", signal=False):
    lines = []
    for width in (10, timing.WIDTHS[family]):
        for key in (32, 200):
            for mode in ("verify", "key"):
                for sample in range(timing.SAMPLES):
                    lines.append(f"SAMPLE {family} {mode} {key} {width} {sample} 100 {99 if signal else 100}")
    return "\n".join([*lines, timing.marker(route, family, arch)]) + "\n"


class TimingTests(unittest.TestCase):
    def test_exact_populations_and_widths(self):
        for route in timing.ROUTES:
            for family in timing.WIDTHS:
                for arch in ("x86_64", "aarch64"):
                    if route.startswith("macos-") and arch == "x86_64":
                        with self.assertRaises(ValueError):
                            timing.marker(route, family, arch)
                        continue
                    rows = timing.parse(output(route, family, arch), route, family, arch)
                    self.assertEqual(len(rows), 8)
                    self.assertFalse(any(row["signal"] for row in rows))

    def test_population_mutations(self):
        baseline = output()
        lines = baseline.splitlines()
        changes = ["", "\n".join(lines[1:]), "\n".join(lines[:-1]), baseline + lines[-1],
                   "\n".join([lines[1], lines[0], *lines[2:]]), baseline.replace("portable", "static"),
                   baseline.replace("sha1", "md5"), baseline.replace("sha1 1 8", "sha1 8 8"),
                   baseline.replace("512 4", "512 1"), baseline.replace("verify 32 10 0", "verify 32 10 1", 1),
                   baseline.replace(" 100 100", " 0 100", 1), baseline.replace(" 100 100", " -1 100", 1),
                   baseline.replace(" 100 100", " nan 100", 1), baseline.replace(" 100 100", " 1_00 100", 1),
                   baseline.replace(" 100 100", f" {2**64} 100", 1), "extra\n" + baseline]
        for changed in changes:
            with self.subTest(change=changed[:80]), self.assertRaises(ValueError):
                timing.parse(changed, "portable", "sha1", "x86_64")

    def test_constant_difference_is_signal(self):
        rows = timing.parse(output(signal=True), "portable", "sha1", "x86_64")
        self.assertTrue(all(row["signal"] and row["paired_t_abs"] is None for row in rows))
        self.assertFalse(timing.screen([(101, 100), (99, 100)] * 256)["signal"])
        for pairs in ([(1, 1)] * 511, [(True, 1)] * 512, [(1,)] * 512):
            with self.assertRaises(ValueError):
                timing.screen(pairs)

    def test_generic_probe_before_feature_build(self):
        for arch in runner.FEATURES:
            for family in timing.WIDTHS:
                with patch.object(runner, "architecture", return_value=arch), patch.object(
                    runner, "run", side_effect=["", "LEGACY_HMAC_HOST_FEATURES: " + family + "\n"]
                ) as run:
                    env, probe = runner.prepare("static", family, Path("/synthetic"), {})
                    self.assertEqual(len(run.call_args_list), 2)
                    self.assertNotIn("target-feature", run.call_args_list[0].args[1]["RUSTFLAGS"])
                    self.assertIn(runner.FEATURES[arch][family], env["RUSTFLAGS"])
                    self.assertEqual(probe["command"][-1], family)

    def test_failed_probe_and_platform_never_authorize(self):
        with patch.object(runner, "architecture", return_value="x86_64"):
            for reply in ("", "LEGACY_HMAC_HOST_FEATURES: md5", "extra\nLEGACY_HMAC_HOST_FEATURES: sha1"):
                with patch.object(runner, "run", side_effect=["", reply]), self.assertRaises(ValueError):
                    runner.prepare("static", "sha1", Path("/synthetic"), {})
            with patch.object(runner, "run", side_effect=RuntimeError("probe unavailable")), self.assertRaises(RuntimeError):
                runner.prepare("static", "sha1", Path("/synthetic"), {})
            with patch.object(runner.sys, "platform", "linux"), self.assertRaises(ValueError):
                runner.prepare("macos-compiled", "sha1", Path("/synthetic"), {})
            with patch.object(runner.sys, "platform", "darwin"), self.assertRaises(ValueError):
                runner.prepare("linux-compiled", "sha1", Path("/synthetic"), {})

    def test_ambient_flags_removed(self):
        with tempfile.TemporaryDirectory() as raw, patch.dict(os.environ, {
            "RUSTFLAGS": "-C target-cpu=native", "CARGO_ENCODED_RUSTFLAGS": "bad",
            "CARGO_BUILD_TARGET": "bad", "BRYNJA_REQUIRE_HARDENED_MD5": "0",
            "CARGO_BUILD_RUSTC_WRAPPER": "bad", "RUSTC_WRAPPER": "bad",
        }), patch.object(runner.cargo_environment, "check"):
            env = runner.environment(Path(raw))
            for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                         "BRYNJA_REQUIRE_HARDENED_MD5", "CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_WRAPPER"):
                self.assertNotIn(name, env)

    def test_observation_preserves_failures_and_signals(self):
        cases = [(output(), 0, "", None), (output(signal=True), 0, "", "timing signal"),
                 (output(), 1, "failed", "child failed"), ("partial", 0, "", "completion marker"),
                 (output(), 0, "diagnostic", "child failed"), ("partial", 124, "\ntiming deadline exceeded", "child failed")]
        for stdout, code, stderr, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as raw:
                destination = Path(raw) / "record.json"
                with patch.object(runner.cargo_environment, "private_directory", return_value=tempfile.TemporaryDirectory()), \
                     patch.object(runner, "environment", return_value={}), \
                     patch.object(runner, "prepare", return_value=({"CARGO_TARGET_DIR": raw, "RUSTFLAGS": "generic"}, None)), \
                     patch.object(runner, "sources", return_value={"synthetic": "hash"}), \
                     patch.object(runner, "digest", return_value="hash"), \
                     patch.object(runner, "run", return_value="/synthetic"), \
                     patch.object(runner, "architecture", return_value="x86_64"), \
                     patch.object(runner.platform, "platform", return_value="synthetic-test-host"), \
                     patch.object(runner.subprocess, "run",
                                  side_effect=subprocess.TimeoutExpired([], 300, output=b"partial") if code == 124 else None,
                                  return_value=subprocess.CompletedProcess([], code, stdout, stderr)) as child:
                    if error:
                        with self.assertRaisesRegex(RuntimeError, error):
                            runner.observe("portable", "sha1", destination)
                    else:
                        runner.observe("portable", "sha1", destination)
                    # macOS platform.platform() may itself spawn `file`.
                    # The mock belongs exclusively to the measured child.
                    self.assertEqual(child.call_count, 1)
                    self.assertTrue(child.call_args.kwargs["text"])
                document = json.loads(destination.read_text())
                self.assertEqual(document["host"], "synthetic-test-host")
                self.assertEqual(document["raw_output"], stdout)
                self.assertEqual(document["raw_stderr"], stderr)
                self.assertEqual(document["exit_status"], code)
                with patch.object(runner, "prepare", side_effect=AssertionError("must not build")), self.assertRaises(ValueError):
                    runner.observe("portable", "sha1", destination)


if __name__ == "__main__":
    if "--compiled" in sys.argv:
        sys.argv.remove("--compiled")
        from legacy_hmac_timing_fixture_tests import FixtureTests
    unittest.main()
