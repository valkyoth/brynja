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
    def test_packaged_hmac_population_and_restoration(self):
        expected = "test result: ok. 3 passed; 0 failed; 1 ignored;"
        for bad in (None, "", "test result: ok. 2 passed; 0 failed; 1 ignored;",
                    "test result: ok. 2 passed; 0 failed; 2 ignored;",
                    "test result: FAILED. 2 passed; 1 failed; 1 ignored;", "runner-error"):
            for failure_profile in (0, 1):
                with self.subTest(bad=bad, profile=failure_profile), tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    (root / "src").mkdir()
                    manifest, library = root / "Cargo.toml", root / "src/lib.rs"
                    original = '[dependencies]\nhost = { features = ["runtime-execution"] }\n'
                    manifest.write_text(original)
                    library.write_text("// original consumer\n")
                    calls = []
                    diagnostics = iter(("E0515", "E0451", "E0308", "E0599"))

                    def run(command, *_args, **kwargs):
                        if "test" in command:
                            index = len(calls)
                            calls.append(command)
                            self.assertEqual("--release" in command, index == 1)
                            self.assertIn("portable_policy_matches_leaf_for_all_algorithms_and_boundaries",
                                          (root / "tests/hmac.rs").read_text())
                            output = expected
                            if bad is not None and index == failure_profile:
                                if bad == "runner-error":
                                    raise RuntimeError("test runner failed")
                                output = bad
                            return subprocess.CompletedProcess(command, 0, output, "")
                        diagnostic = (f"error[{next(diagnostics)}] hmac"
                                      if kwargs.get("success") is False else "")
                        return subprocess.CompletedProcess(command, bool(diagnostic), "", diagnostic)

                    with patch.object(checks.host, "run", side_effect=run), redirect_stdout(io.StringIO()):
                        if bad is None:
                            checks.host.hmac_consumer(root, {}, [])
                            self.assertEqual(len(calls), 2)
                            self.assertIsNone(next(diagnostics, None))
                        else:
                            with self.assertRaises((ValueError, RuntimeError)) as raised:
                                checks.host.hmac_consumer(root, {}, [])
                            self.assertEqual(len(calls), failure_profile + 1)
                            if bad != "runner-error":
                                self.assertIn(bad, str(raised.exception))
                    self.assertEqual(manifest.read_text(), original)
                    self.assertEqual(library.read_text(), "// original consumer\n")
                    self.assertFalse((root / "tests/hmac.rs").exists())

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
                        self.assertEqual(len(calls), 10)
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
                        self.assertEqual(len(calls), 10)
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

    def test_preentry_regression_executes_both_profiles_and_rejects_skips(self):
        for owner, module in ((profiles.PROTECTED, "protected_memory::platform::thread::tests"),
                              (profiles.RESIDENT, "macos_resident::resource::darwin::tests")):
            for summary, valid in (("1 passed; 0 failed; 0 ignored;", True),
                                   ("0 passed; 0 failed; 1 ignored;", False),
                                   ("0 passed; 0 failed; 0 ignored;", False)):
                result = subprocess.CompletedProcess([], 0, "test result: ok. " + summary)
                with patch.object(checks.host, "run", return_value=result) as run, redirect_stdout(io.StringIO()):
                    if valid:
                        checks.compiled.preentry(checks.host, Path("/workspace"), {}, "sha256", checks.population, owner)
                        self.assertEqual(run.call_count, 2)
                        for index, call in enumerate(run.call_args_list):
                            command = call.args[0]
                            self.assertIn(owner.feature + "-acceleration", command)
                            self.assertEqual(command[-4:], [module + "::hmac_preentry_failures_preserve_session",
                                                           "--", "--ignored", "--exact"])
                            self.assertEqual("--release" in command, index == 1)
                    else:
                        with self.assertRaisesRegex(ValueError, "population changed"):
                            checks.compiled.preentry(checks.host, Path("/workspace"), {}, "sha256", checks.population, owner)
            with patch.object(checks.host, "run", side_effect=AssertionError("unexpected SHA-256 test")):
                for kernel in ("sha512", "keccak"):
                    checks.compiled.preentry(checks.host, Path("/workspace"), {}, kernel, checks.population, owner)

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
                manifest.write_text(f'brynja-crypto-cpu-std = {{version="=0.2.0", features = ["{owner.feature}"]}}')
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
            self.assertEqual(len(calls), 10)
            for path, original in before.items():
                self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
