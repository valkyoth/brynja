#!/usr/bin/env python3
"""Fake-verifier regressions; never execute a proof or cryptographic test."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hkdf_kani", Path(__file__).with_name("check-hkdf-kani.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def invoke(self, suite, result=None, failure=False):
        commands = []

        def run(command, env):
            commands.append(command)
            if command[-1] == "--version":
                return "Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 6.11.0"
            if failure:
                raise RuntimeError("fake verifier failure")
            return result or "Complete - 1 successfully verified harnesses, 0 failures, 1 total."

        output = io.StringIO()
        with (patch.object(driver.sys, "argv", ["check-hkdf-kani.py", suite]),
              patch.object(driver.verifier, "tool", return_value={"version": "0.68.0", "execution_toolchain": "1.90.0"}),
              patch.object(driver.verifier, "environment", return_value={}),
              patch.object(driver.verifier.cargo_environment, "private_directory", return_value=nullcontext("/tmp")),
              patch.object(driver.verifier, "run", side_effect=run), redirect_stdout(output)):
            driver.main()
        return commands, output.getvalue()

    def test_modern_selection_is_exact_and_excludes_legacy(self):
        commands, output = self.invoke("modern")
        self.assertEqual(len(commands), 5)
        self.assertEqual([c[-2:] for c in commands[1:]],
                         [["proofs::" + n, "--exact"] for n in driver.HARNESSES["modern"]])
        self.assertIn("PASS; 4 proofs", output)

    def test_legacy_selection_excludes_modern(self):
        commands, output = self.invoke("legacy")
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[1][-2:], ["proofs::" + driver.HARNESSES["legacy"][0], "--exact"])
        self.assertIn("PASS; 1 proofs", output)

    def test_missing_or_wrong_population_is_not_success(self):
        for result in ("No harnesses", "Complete - 0 successfully verified harnesses, 1 failures, 1 total.",
                       "Complete - 2 successfully verified harnesses, 0 failures, 2 total."):
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.invoke("modern", result=result)

    def test_verifier_failure_propagates(self):
        with self.assertRaises(RuntimeError):
            self.invoke("modern", failure=True)

    def test_policy_only_does_not_execute(self):
        with (patch.object(driver.sys, "argv", ["check-hkdf-kani.py", "modern", "--policy-only"]),
              patch.object(driver.verifier, "run") as run, redirect_stdout(io.StringIO()) as output):
            driver.main()
            run.assert_not_called()
            self.assertIn("NOT executed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
