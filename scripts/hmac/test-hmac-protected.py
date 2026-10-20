#!/usr/bin/env python3
"""Acceptance tests must not mistake skipped tests or compile errors for proof."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("protected_acceptance", Path(__file__).with_name("check-hmac-protected.py"))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class ProtectedAcceptanceTests(unittest.TestCase):
    def test_population_requires_every_native_test(self):
        checks.population(subprocess.CompletedProcess([], 0, "test result: ok. 3 passed; 0 failed; 0 ignored;"), 3)
        for summary in ("0 passed; 0 failed; 3 ignored;", "2 passed; 0 failed; 1 ignored;",
                        "2 passed; 1 failed; 0 ignored;", "0 tests"):
            with self.subTest(summary=summary), self.assertRaises(ValueError):
                checks.population(subprocess.CompletedProcess([], 0, "test result: ok. " + summary), 3)

    def test_mutants_need_successful_compilation_and_actual_failed_test(self):
        for mode in ("compile-error", "crash", "wrong-population", "behavioral"):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                destination = root / "crates/brynja-crypto-cpu-std/src/strict_hmac"
                shutil.copytree(checks.ROOT / "crates/brynja-crypto-cpu-std/src/strict_hmac", destination)
                before = {path: path.read_bytes() for path in destination.rglob("*.rs")}
                calls = []

                def run(command, *_args, **kwargs):
                    calls.append(command)
                    if "--no-run" in command:
                        if mode == "compile-error":
                            raise RuntimeError("compiler rejected mutant")
                        return subprocess.CompletedProcess(command, 0, "", "")
                    self.assertFalse(kwargs["success"])
                    output = ("test result: FAILED. 0 passed; 1 failed; 0 ignored;"
                              if mode == "behavioral" else "test result: FAILED. 0 passed; 0 failed; 1 ignored;"
                              if mode == "wrong-population" else "signal")
                    return subprocess.CompletedProcess(command, 101, output, "")

                with patch.object(checks.host, "run", side_effect=run), redirect_stdout(io.StringIO()):
                    if mode == "behavioral":
                        checks.mutants(root, {})
                        self.assertEqual(len(calls), 8)
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            checks.mutants(root, {})
                for path, original in before.items():
                    self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
