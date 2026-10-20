"""Fail-closed populations, compiled-mutation outcomes and private test hooks."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import hmac_execution_faults as faults

spec = importlib.util.spec_from_file_location(
    "hmac_hosted_native_tests", Path(__file__).with_name("check-hmac-hosted-native.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def output(code, passed=1, failed=0, ignored=0, marker=""):
    status = "ok" if not failed else "FAILED"
    return SimpleNamespace(returncode=code, stderr="",
                           stdout=f"test result: {status}. {passed} passed; {failed} failed; {ignored} ignored;\n{marker}\n")


class FaultTests(unittest.TestCase):
    def test_test_hooks_are_private_and_leave_composition_unchanged(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            prepared = base / "prepared"
            shutil.copytree(faults.ROOT / "crates/brynja-mac-hmac/src", prepared / "src")
            fixture = base / "copy"
            faults.prepare(prepared, fixture)
            for name in ("engine.rs", "execution/adapter.rs", "execution/retained.rs"):
                self.assertEqual((prepared / "src" / name).read_bytes(),
                                 (fixture / "src" / name).read_bytes())
            original = (prepared / "src/execution/mod.rs").read_text()
            self.assertEqual((fixture / "src/execution/mod.rs").read_text(),
                             original + "\n#[cfg(test)] mod model;\n")
            before = (prepared / "src/execution/backends.rs").read_text()
            after = (fixture / "src/execution/backends.rs").read_text()
            self.assertNotIn("Synthetic", before)
            self.assertEqual(after.count("#[cfg(test)]"), 4)
            # Every new pattern match is cfg(test); source enum is not replaced.
            self.assertIn("#[cfg(test)] Synthetic(&'a super::Kernel)", after)
            self.assertEqual(after.count("#[cfg(test)] Self::Synthetic"), 3)

    def test_execution_mutants_require_executed_failure_and_restore(self):
        for failure in (None, "baseline", "compile", "crash", "survived", "ignored"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                directory = Path(raw)
                prepared = directory / "prepared"
                shutil.copytree(faults.ROOT / "crates/brynja-mac-hmac/src", prepared / "src")
                fixture = directory / "execution-composition-faults/src/execution"
                originals, calls = {}, []

                def run(argv, cwd, env):
                    self.assertEqual(cwd, directory / "execution-composition-faults")
                    self.assertEqual(argv[:4], ["cargo", "test", "--offline", "--locked"])
                    self.assertIn("runtime-execution", argv)
                    self.assertNotIn("--ignored", argv)
                    if not originals:
                        originals.update({name: (fixture / name).read_text()
                                          for name in ("mod.rs", "retained.rs")})
                    mutated = any((fixture / name).read_text() != text for name, text in originals.items())
                    calls.append(mutated)
                    if mutated:
                        if failure == "compile":
                            return SimpleNamespace(returncode=101, stdout="", stderr="compiler error")
                        if failure == "crash":
                            return output(-6, 0, 1)
                        if failure == "survived":
                            return output(0)
                        if failure == "ignored":
                            return output(101, 0, 1, 1)
                        return output(101, 0, 1)
                    count = 6 if "--exact" not in argv else 1
                    return output(0, count if failure != "baseline" else 0)

                with patch.object(faults, "result", side_effect=run), redirect_stdout(io.StringIO()):
                    if failure is None:
                        faults.check(prepared, directory, {})
                        self.assertEqual(len(calls), 35)
                        self.assertEqual(sum(calls), 11)
                    else:
                        with self.assertRaises(ValueError):
                            faults.check(prepared, directory, {})
                for name, text in originals.items():
                    self.assertEqual((fixture / name).read_text(), text)

    def test_hosted_native_population_mutants_and_restoration(self):
        for failure in (None, "marker", "baseline", "compile", "crash", "survived", "ignored"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                workspace = Path(raw)
                name = "crates/brynja-crypto-cpu-std/src/execution/hmac.rs"
                path = workspace / name
                path.parent.mkdir(parents=True)
                original = (faults.ROOT / name).read_text()
                path.write_text(original)
                calls = []

                def run(argv, cwd, env):
                    self.assertEqual(env["BRYNJA_HMAC_HOSTED_KERNEL"], "sha256")
                    self.assertNotIn("RUSTFLAGS", env)
                    self.assertEqual(cwd, workspace)
                    self.assertIn("--exact", argv)
                    self.assertIn("hmac-execution", argv)
                    mutated = path.read_text() != original
                    calls.append(mutated)
                    if mutated:
                        if failure == "compile":
                            return SimpleNamespace(returncode=101, stdout="", stderr="compiler error")
                        if failure == "crash":
                            return output(-6, 0, 1)
                        if failure == "survived":
                            return output(0)
                        return output(101, 0, 1, int(failure == "ignored"))
                    marker = ""
                    if "native_hosted_all_identities" in argv:
                        self.assertIn("--ignored", argv)
                        marker = "HMAC_NATIVE_HOSTED: sha256 2 identities; Require and Prefer"
                    return output(0, 0 if failure == "baseline" else 1,
                                  marker="" if failure == "marker" else marker)

                with patch.object(native.platform, "machine", return_value="arm64"), \
                        patch.object(native.sys, "platform", "darwin"), \
                        patch.object(native, "result", side_effect=run), redirect_stdout(io.StringIO()):
                    if failure is None:
                        native.check(workspace, {}, "sha256")
                        self.assertEqual(len(calls), 19)
                        self.assertEqual(sum(calls), 5)
                    else:
                        with self.assertRaises(ValueError):
                            native.check(workspace, {}, "sha256")
                self.assertEqual(path.read_text(), original)

    def test_hosted_runner_refuses_unsupported_platform(self):
        for machine, system in (("x86_64", "linux"), ("aarch64", "freebsd"), ("riscv64", "linux")):
            with patch.object(native.platform, "machine", return_value=machine), \
                    patch.object(native.sys, "platform", system), \
                    patch.object(native, "result", side_effect=AssertionError("must not execute")), \
                    self.assertRaisesRegex(ValueError, "requires an admitted"):
                native.check(Path("/unused"), {}, "sha256")


if __name__ == "__main__":
    unittest.main()
