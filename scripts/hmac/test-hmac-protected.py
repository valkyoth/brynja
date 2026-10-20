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
import hmac_owner_profile as profiles

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

    def test_compiled_mutants_require_executed_behavioral_failure(self):
        for mode in ("compile-error", "crash", "ignored", "behavioral"):
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
                            raise RuntimeError("compile error")
                        return subprocess.CompletedProcess(command, 0, "", "")
                    self.assertFalse(kwargs["success"])
                    self.assertEqual(command[-3:], ["--", "--ignored", "--exact"])
                    output = ("test result: FAILED. 0 passed; 1 failed; 0 ignored;"
                              if mode == "behavioral" else "test result: ok. 0 passed; 0 failed; 1 ignored;"
                              if mode == "ignored" else "signal")
                    return subprocess.CompletedProcess(command, 101, output, "")
                with patch.object(checks.host, "run", side_effect=run):
                    if mode == "behavioral":
                        checks.compiled.mutants(checks.host, root, {}, ["cargo", "test"])
                        self.assertEqual(len(calls), 8)
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            checks.compiled.mutants(checks.host, root, {}, ["cargo", "test"])
                for path, original in before.items():
                    self.assertEqual(path.read_bytes(), original)

    def test_native_selection_is_explicit_and_complete(self):
        for arch, expected in (("x86_64", "+sha512,+avx2,+avx"),
                               ("aarch64", "+neon,+sha3")):
            with patch.object(checks.compiled.platform, "machine", return_value=arch), \
                    patch.object(profiles.sys, "platform", "linux"):
                env = checks.compiled.native_environment({"RUSTFLAGS": "-C target-cpu=native"}, "sha512")
                self.assertEqual(env["RUSTFLAGS"], "-C target-feature=" + expected)
                self.assertEqual(env["BRYNJA_HMAC_PROTECTED_KERNEL"], "sha512")
                with self.assertRaises(ValueError):
                    checks.compiled.native_environment({}, "portable")
        with patch.object(checks.compiled.platform, "machine", return_value="riscv64"):
            with self.assertRaises(ValueError):
                checks.compiled.native_environment({}, "sha256")

    def test_profiles_cannot_claim_the_other_platform(self):
        for system, arch in (("linux", "x86_64"), ("linux", "aarch64"),
                             ("darwin", "arm64"), ("darwin", "x86_64"),
                             ("win32", "AMD64"), ("linux", "arm64")):
            for owner in (profiles.PROTECTED, profiles.RESIDENT):
                allowed = ((owner == profiles.PROTECTED and system == "linux"
                            and arch in ("x86_64", "aarch64")) or
                           (owner == profiles.RESIDENT and system == "darwin" and arch == "arm64"))
                with self.subTest(system=system, arch=arch, owner=owner), \
                        patch.object(profiles.sys, "platform", system), \
                        patch.object(profiles.platform, "machine", return_value=arch):
                    if allowed:
                        for kernel in ("sha256", "sha512", "keccak"):
                            env = checks.compiled.native_environment({}, kernel, owner)
                            self.assertEqual(env["BRYNJA_HMAC_PROTECTED_KERNEL"], kernel)
                            if owner == profiles.RESIDENT:
                                self.assertIn("+neon", env["RUSTFLAGS"])
                    else:
                        with self.assertRaises(ValueError):
                            checks.compiled.native_environment({}, "sha256", owner)

    def test_shared_consumers_change_namespace_only(self):
        for name in ("acceptance.rs", "compiled.rs"):
            text = (checks.ROOT / "assurance/hmac-protected" / name).read_text()
            self.assertEqual(profiles.PROTECTED.source(text), text)
            resident = profiles.RESIDENT.source(text)
            self.assertNotIn("strict_hmac", resident)
            self.assertEqual(resident.replace("macos_resident::hmac", "strict_hmac"), text)
        with self.assertRaises(ValueError):
            profiles.RESIDENT.source("unrelated fixture")

    def test_negative_profiles_remove_their_own_feature(self):
        for owner in (profiles.PROTECTED, profiles.RESIDENT):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                (root / "src").mkdir()
                manifest = root / "Cargo.toml"
                manifest.write_text(f'brynja-crypto-cpu-std = {{version="=0.1.1", features = ["{owner.feature}"]}}')
                calls = []
                def run(command, *_args, **kwargs):
                    calls.append((root / "src/lib.rs").read_text())
                    return subprocess.CompletedProcess(command, 1 if kwargs.get("success") is False else 0, "", "")
                with patch.object(checks.host, "run", side_effect=run), \
                        patch.object(checks, "diagnostic_rejection") as reject, redirect_stdout(io.StringIO()):
                    checks.negatives(root, {}, owner)
                self.assertEqual(len(calls), 26)
                self.assertEqual(reject.call_count, 25)
                self.assertEqual(reject.call_args.args[1],
                                 "E0433" if owner == profiles.RESIDENT else "E0432")
                self.assertTrue(all(f"::{owner.module}::" in source for source in calls))
                self.assertNotIn("features", manifest.read_text())

    def test_resident_mutants_use_resident_sources_and_tests(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            destination = root / "crates/brynja-crypto-cpu-std/src/macos_resident/hmac"
            shutil.copytree(checks.ROOT / "crates/brynja-crypto-cpu-std/src/macos_resident/hmac", destination)
            before = {path: path.read_bytes() for path in destination.rglob("*.rs")}
            calls = []
            def run(command, *_args, **kwargs):
                calls.append(command)
                self.assertIn("macos-resident-hmac", command)
                self.assertTrue(any(arg.startswith("macos_resident::hmac::tests::native::") for arg in command))
                self.assertFalse(any("strict_hmac" in arg for arg in command))
                return subprocess.CompletedProcess(command, 0 if "--no-run" in command else 101,
                    "test result: FAILED. 0 passed; 1 failed; 0 ignored;", "")
            with patch.object(checks.host, "run", side_effect=run), redirect_stdout(io.StringIO()):
                checks.mutants(root, {}, profiles.RESIDENT)
            self.assertEqual(len(calls), 8)
            for path, original in before.items():
                self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
