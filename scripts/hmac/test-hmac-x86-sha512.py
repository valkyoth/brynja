#!/usr/bin/env python3
"""SDE driver fails closed on missing, skipped, wrong-route and failed tests."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hmac_sde", Path(__file__).with_name("check-hmac-x86-sha512.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def test_snapshot_includes_new_inputs_and_generic_probe(self):
        with patch.object(driver.subprocess, "check_output", return_value=b"Cargo.toml\0assurance/hmac-faults/host_probe.rs\0") as git:
            sources = driver.snapshot()
        argv = git.call_args.args[0]
        for token in ("--cached", "--others", "--exclude-standard", "assurance/hmac-faults/host_probe.rs"):
            self.assertIn(token, argv)
        self.assertIn("assurance/hmac-faults/host_probe.rs", sources)
        self.assertIn("scripts/hmac/check-hmac-x86-sha512.py", sources)

    def test_output_reservation_failure_and_source_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sde = directory / "sde64"
            sde.write_text("placeholder, never executed")
            sde.chmod(0o700)
            output = directory / "observation.json"
            common = ["check", "--sde", str(sde), "--output", str(output)]
            sources = {"source.rs": "before"}
            for failure in (None, RuntimeError("child failed"), subprocess.TimeoutExpired(["test"], 600), "drift"):
                # A new observation, not overwriting a failure with a retry.
                path = output.with_name("observation-" + str(len(list(directory.glob("observation-*")))) + ".json")
                args = common[:-1] + [str(path)]
                snapshots = [sources, {"source.rs": "after"}] if failure == "drift" else [sources, sources]
                with patch.object(sys, "argv", args), patch.object(driver.platform, "system", return_value="Linux"), \
                        patch.object(driver.platform, "machine", return_value="x86_64"), \
                        patch.object(driver.subprocess, "check_output", side_effect=["f" * 40, b""]), \
                        patch.object(driver, "snapshot", side_effect=snapshots), \
                        patch.object(driver.verifier.cargo_environment, "private_directory", return_value=contextlib.nullcontext(directory)), \
                        patch.object(driver, "execute", side_effect=failure if isinstance(failure, Exception) else None,
                                     return_value={"results": []}), contextlib.redirect_stdout(io.StringIO()):
                    if failure is None:
                        driver.main()
                    else:
                        with self.assertRaises((ValueError, RuntimeError, subprocess.TimeoutExpired)):
                            driver.main()
                record = json.loads(path.read_text())
                self.assertEqual(record["status"], "pass" if failure is None else "failed")
                self.assertIn("NOT native", record["claim"])
                if failure is not None:
                    self.assertIn("error", record)
            output.write_text("preserved")
            with patch.object(sys, "argv", common), patch.object(driver.platform, "system", return_value="Linux"), \
                    patch.object(driver.platform, "machine", return_value="x86_64"), \
                    patch.object(driver.subprocess, "check_output", side_effect=["f" * 40, b""]), \
                    patch.object(driver, "snapshot", return_value=sources), patch.object(driver, "execute") as execute, \
                    self.assertRaises(FileExistsError):
                driver.main()
            self.assertEqual(output.read_text(), "preserved")
            execute.assert_not_called()

    def test_test_must_run_once_and_not_be_ignored(self):
        good = "test native_sha512 ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;"
        driver.population(good, "native_sha512")
        for bad in ("", good + "\n" + good, good.replace("1 passed", "0 passed"),
                    good.replace("0 failed", "1 failed"), good.replace("0 ignored", "1 ignored"),
                    good.replace("0 measured", "1 measured"), good.replace("native_sha512", "native_sha256"),
                    good.replace(" ... ok", " ... ignored"), good.splitlines()[-1]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                driver.population(bad, "native_sha512")

    def test_artifact_identity_and_private_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "executable"
            binary.touch()
            good = {"reason": "compiler-artifact", "executable": str(binary),
                    "target": {"name": "execution"}, "profile": {"test": True}}
            line = json.dumps(good)
            self.assertEqual(driver.executable(line, "execution", root), binary)
            for bad in ("", line + "\n" + line, json.dumps(dict(good, profile={"test": False})),
                        json.dumps(dict(good, target={"name": "other"})),
                        json.dumps(dict(good, executable=None)),
                        json.dumps(dict(good, executable="executable")),
                        json.dumps(dict(good, executable=str(root / "absent"))),
                        json.dumps(dict(good, executable=__file__))):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    driver.executable(bad, "execution", root)
            link = root / "link"
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                driver.executable(json.dumps(dict(good, executable=str(link))), "execution", root)

    def test_nonzero_and_timeouts_never_become_pass_markers(self):
        for code in (1, 101, -4):
            rows = []
            with patch.object(driver.verifier.cargo_environment, "check"), \
                    patch.object(driver.subprocess, "run", return_value=subprocess.CompletedProcess(
                        ["probe"], code, stdout="HMAC_HOST_FEATURES: sha512", stderr="failure")), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
                driver.run(["probe"], {}, rows)
            self.assertEqual(rows[0]["exit_status"], code)
        with patch.object(driver.verifier.cargo_environment, "check"), \
                patch.object(driver.subprocess, "run", side_effect=subprocess.TimeoutExpired(["probe"], 600)), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.TimeoutExpired):
            driver.run(["probe"], {}, [])

    def test_actual_driver_selects_compilation_then_exact_emulated_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "binary"
            binary.touch()
            calls = []

            def observe(command, env, _records):
                calls.append((command, dict(env)))
                if command[-1] == "sha512":
                    return "HMAC_HOST_FEATURES: sha512\n"
                if command[-1] == "--message-format=json":
                    target = "execution" if "--test" in command else "brynja_crypto_cpu_std"
                    return json.dumps({"reason": "compiler-artifact", "executable": str(binary),
                                       "target": {"name": target}, "profile": {"test": True}})
                if "--ignored" in command:
                    return f"test {command[4]} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;"
                return "identity"

            with patch.object(driver.verifier, "environment", return_value={}), patch.object(driver, "run", side_effect=observe):
                result = driver.execute(Path("/tool/sde64"), ["1.90.0", "1.99.1"], directory, [])
            self.assertEqual(len(result["results"]), 8)
            executions = [(argv, env) for argv, env in calls if "--ignored" in argv]
            self.assertEqual(len(executions), 8)
            for argv, env in executions:
                self.assertEqual(argv[:4], [Path("/tool/sde64"), "-arl", "--", binary])
                self.assertEqual(argv[-3:], ["--exact", "--ignored", "--test-threads=1"])
                self.assertEqual(env["RUSTFLAGS"], driver.FLAGS)
                self.assertNotIn("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", env)
            builds = [argv for argv, _ in calls if "--no-run" in argv]
            self.assertEqual(len(builds), 8)
            self.assertTrue(all("--offline" in argv and "--locked" in argv for argv in builds))
            self.assertEqual(calls[2][0][-1], "sha512")  # Generic probe executes before accelerated builds.


if __name__ == "__main__":
    unittest.main()
