#!/usr/bin/env python3
"""Deterministic timing-analyser controls, not wall-clock pass/fail assertions."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hmac_timing as timing
from hmac_timing_fixture_tests import FixtureTests

spec = importlib.util.spec_from_file_location("hmac_timing_driver", Path(__file__).with_name("check-hmac-timing.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def fixture(route="portable", family="all"):
    lines = []
    for identity, width in timing.population(route, family).items():
        for size in (16, width):
            for key in (32, 200):
                for mode in ("verify", "key"):
                    lines.extend(f"SAMPLE {identity} {mode} {key} {size} {i} "
                                 f"{1000 + i % 2} {1001 - i % 2}"
                                 for i in range(timing.SAMPLES))
    return "\n".join([*lines, timing.marker(route, family)]) + "\n"


class TimingTests(FixtureTests, unittest.TestCase):
    def test_complete_population_and_quiet_control(self):
        rows = timing.parse(fixture())
        self.assertEqual(len(rows), 96)
        self.assertFalse(any(row["signal"] for row in rows))

    def test_explicit_route_population_cannot_be_relabelled(self):
        for route in timing.ROUTES:
            for family, count in (("sha256", 16), ("sha512", 48), ("keccak", 32)):
                source = fixture(route, family)
                self.assertEqual(len(timing.parse(source, route, family)), count)
                with self.assertRaises(ValueError):
                    timing.parse(source, "portable" if route != "portable" else "static", family)
                with self.assertRaises(ValueError):
                    timing.parse(source, route, "sha256" if family != "sha256" else "keccak")
                with self.assertRaises(ValueError):
                    timing.parse(f"HMAC_TIMING_SMOKE {count // 8} {route} {family}\n", route, family)
        for route, family in (("other", "all"), ("portable", "other"), ("static", "all"),
                              ("runtime", "all"), ("linux-compiled", "all"), ("macos-compiled", "all")):
            with self.assertRaises(ValueError):
                timing.population(route, family)

    def test_generic_probe_precedes_feature_enablement_and_rejects_failures(self):
        routes = driver.routes
        for arch in ("x86_64", "arm64"):
            for family in ("sha256", "sha512", "keccak"):
                calls = []
                def run(command, env):
                    calls.append((command, dict(env)))
                    return "" if command[0] == "rustc" else "HMAC_HOST_FEATURES: " + family + "\n"
                with patch.object(routes.platform, "machine", return_value=arch), \
                        patch.object(routes.verifier, "run", side_effect=run):
                    env, probe = routes.prepare("static", family, Path("/unused"), {"SENTINEL": "kept"})
                self.assertEqual(len(calls), 2)
                self.assertTrue(all("RUSTFLAGS" not in env for _, env in calls))
                self.assertIn("target-cpu=generic", calls[0][0])
                self.assertEqual(calls[1][0][-1], family)
                self.assertTrue(env["RUSTFLAGS"].startswith("-C target-feature="))
                self.assertEqual(env["SENTINEL"], "kept")
                self.assertEqual(probe["command"], calls[1][0])
        with patch.object(routes.sys, "platform", "darwin"), \
                patch.object(routes.platform, "machine", return_value="arm64"), \
                patch.object(routes.verifier, "run", side_effect=["", "HMAC_HOST_FEATURES: sha512\n"]):
            env, _ = routes.prepare("runtime", "sha512", Path("/unused"), {})
            self.assertNotIn("RUSTFLAGS", env, "runtime must remain a generic build")
        for failure in ("", "HMAC_HOST_FEATURES: other\n", "HMAC_HOST_FEATURES: sha256\nextra", RuntimeError("unavailable")):
            with patch.object(routes.platform, "machine", return_value="x86_64"), \
                    patch.object(routes.verifier, "run", side_effect=["", failure]), \
                    self.assertRaises((ValueError, RuntimeError)):
                routes.prepare("static", "sha256", Path("/unused"), {})
        for system, arch, route in (("linux", "x86_64", "macos-resident"),
                                    ("darwin", "arm64", "linux-protected"),
                                    ("darwin", "x86_64", "macos-compiled"),
                                    ("linux", "x86_64", "runtime")):
            with patch.object(routes.sys, "platform", system), \
                    patch.object(routes.platform, "machine", return_value=arch), \
                    patch.object(routes.verifier, "run", side_effect=AssertionError("must not run")), \
                    self.assertRaises(ValueError):
                routes.prepare(route, "sha256", Path("/unused"), {})

    def test_both_signal_directions_and_zero_variance(self):
        for pairs in ([(100, 200)] * 512, [(200, 100)] * 512,
                      [(100 + i % 2, 200) for i in range(512)]):
            self.assertTrue(timing.screen(pairs)["signal"])
        self.assertFalse(timing.screen([(100, 100)] * 512)["signal"])

    def test_incomplete_reordered_or_forged_population(self):
        source = fixture()
        lines = source.splitlines()
        mutants = (
            "\n".join(lines[1:]), "\n".join([lines[1], lines[0], *lines[2:]]),
            source.replace("SAMPLE sha224", "SAMPLE sha256", 1),
            source.replace("verify 32 16", "verify 200 16", 1),
            source.replace(" 0 1000 1001", " 0 0 1001", 1),
            source.replace(" 0 1000 1001", " 0 -1 1001", 1),
            source.replace(" 0 1000 1001", " 0 NaN 1001", 1),
            source.replace(" 0 1000 1001", " 1 1000 1001", 1),
            source.replace(timing.MARKER, ""), source + timing.MARKER,
            source.replace(timing.MARKER, lines[0] + "\n" + timing.MARKER),
        )
        for mutant in mutants:
            with self.subTest(mutant=mutant[:80]), self.assertRaises(ValueError):
                timing.parse(mutant)

    def test_driver_retains_signals_but_never_accepts_a_failed_child(self):
        for outcome in ("quiet", "signal", "failed-child"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as raw:
                directory = Path(raw)
                binary = directory / "target/release/brynja-hmac-timing"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"mocked binary, not executable evidence")
                destination = directory / "observation.json"
                text = fixture()
                if outcome == "signal":
                    text = text.replace("1000 1001", "1000 2001").replace("1001 1000", "1001 2000")
                child = subprocess.CompletedProcess([], int(outcome == "failed-child"), text, "")
                with patch("sys.argv", ["check-hmac-timing.py", "--output", str(destination)]), \
                        patch.object(driver.verifier.cargo_environment, "private_directory",
                                     return_value=nullcontext(directory)), \
                        patch.object(driver.verifier, "environment",
                                     return_value={"CARGO_TARGET_DIR": str(directory / "target")}), \
                        patch.object(driver.verifier, "run", return_value="mock compiler"), \
                        patch.object(driver.platform, "platform", return_value="mock host"), \
                        patch.object(driver.platform, "machine", return_value="mock architecture"), \
                        patch.object(driver.subprocess, "run", return_value=child), \
                        patch.object(driver.subprocess, "check_output",
                                     side_effect=["0" * 40 + "\n", b""]), redirect_stdout(io.StringIO()):
                    if outcome == "failed-child":
                        with self.assertRaises(RuntimeError):
                            driver.main()
                        self.assertFalse(destination.exists())
                        continue
                    if outcome == "signal":
                        with self.assertRaises(SystemExit):
                            driver.main()
                    else:
                        driver.main()
                record = json.loads(destination.read_text())
                self.assertEqual(record["signals"], 96 if outcome == "signal" else 0)
                self.assertEqual(len(record["campaigns"]), 96)
                self.assertEqual(record["raw_output"], text)
                self.assertEqual(record["exit_status"], 0)

    def test_driver_refuses_to_overwrite_an_observation_before_building(self):
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "observation.json"
            destination.write_text("retain failed observation")
            with patch("sys.argv", ["check-hmac-timing.py", "--output", str(destination)]), \
                    patch.object(driver.verifier, "run", side_effect=AssertionError("must not run")), \
                    self.assertRaisesRegex(ValueError, "overwrite"):
                driver.main()
            self.assertEqual(destination.read_text(), "retain failed observation")


if __name__ == "__main__":
    unittest.main()
