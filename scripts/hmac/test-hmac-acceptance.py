#!/usr/bin/env python3
"""The acceptance driver must distinguish executed tests from unrelated errors."""
import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hmac_acceptance import ALGORITHMS, diagnostic_rejection, negative_cases
from hmac_faults import accepted, rejected, replace_once
import hmac_adapter_native as native
from hmac_execution_fault_tests import FaultTests


def output(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def error(code):
    return json.dumps({"reason": "compiler-message", "message": {
        "level": "error", "code": {"code": code}}}) + "\n"


class AcceptanceTests(unittest.TestCase):
    def test_complete_negative_population(self):
        cases = list(negative_cases())
        self.assertEqual(len(cases), 118)
        self.assertEqual(len({name for name, _, _ in cases}), 118)
        for algorithm in ALGORITHMS:
            for bound in ("Send", "Sync", "Copy", "Clone", "core::fmt::Debug"):
                self.assertIn(f"{algorithm}/{bound}", [name for name, _, _ in cases])
            for method in ("finalize_bits_tag", "finalize_bits_secret", "verify_bits"):
                self.assertIn(f"{algorithm}/{method}/bit-order", [name for name, _, _ in cases])

    def test_diagnostic_only(self):
        diagnostic_rejection(output(101, error("E0277")), "E0277")
        for value in (output(0, error("E0277")), output(101, "E0277"),
                      output(101, "", error("E0277")), output(101, error("E0432")),
                      output(101, error("E0277") + error("E0432")),
                      output(101, error(None)), output(-9, error("E0277"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                diagnostic_rejection(value, "E0277")

    def test_positive_population(self):
        marker = "test result: ok. 5 passed; 0 failed; 0 ignored;"
        accepted(output(0, marker), 5)
        for value in (output(101, marker), output(0), output(0, marker.replace("5 passed", "4 passed")),
                      output(0, marker.replace("0 ignored", "1 ignored"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                accepted(value, 5)

    def test_mutant_must_execute(self):
        marker = "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
        rejected(output(101, marker))
        for value in (output(0, marker), output(-6, marker), output(101, error("E0425")),
                      output(101, marker.replace("1 failed", "2 failed")),
                      output(101, marker.replace("0 ignored", "1 ignored"))):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rejected(value)

    def test_exact_mutation_anchor(self):
        self.assertEqual(replace_once("x original y", "original", "mutant"), "x mutant y")
        for text in ("missing", "original original"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                replace_once(text, "original", "mutant")

    def test_native_handoff_requires_execution_population_and_mutant_failure(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        failure = "test result: FAILED. 0 passed; 1 failed; 0 ignored;\n"
        for fault in (None, "marker", "population", "compile", "survived", "crash", "host"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                prepared = directory / "execution-faults"
                (prepared / "src/execution").mkdir(parents=True)
                (prepared / "Cargo.toml").write_text("")
                (prepared / "src/lib.rs").write_text("")
                (prepared / "src/execution/mod.rs").write_text("")
                fixture = directory / "native-adapter-sha512"
                backends = fixture / "src/execution/backends.rs"
                original = "consume(($digest)(&result))\nconsume(result.digest.as_bytes())"
                (prepared / "src/execution/backends.rs").write_text(original)
                calls = []

                def run(argv, cwd, env):
                    if argv[0] == "rustc":
                        self.assertEqual(argv, [
                            "rustc", "+1.99.1", "--edition=2024", "-C", "target-cpu=generic",
                            str(native.ROOT / "assurance/hmac-faults/host_probe.rs"),
                            "-o", str(directory / "hmac-host-probe")])
                        return output()
                    if argv[0].endswith("hmac-host-probe"):
                        self.assertEqual(cwd, directory)
                        return output(1 if fault == "host" else 0, "HMAC_HOST_FEATURES: sha512\n")
                    self.assertEqual(env["RUSTFLAGS"], "-C target-feature=+sha512,+avx,+avx2")
                    self.assertEqual(env["BRYNJA_HMAC_ADAPTER_KERNEL"], "sha512")
                    self.assertEqual(cwd, fixture)
                    self.assertIn("--exact", argv)
                    calls.append(argv)
                    if backends.read_text() != original:
                        return {"compile": output(101, error("E0425")),
                                "survived": output(0, success),
                                "crash": output(-6, failure)}.get(fault, output(101, failure))
                    return output(0, (success if fault != "population" else "")
                                  + ("" if fault == "marker" else "HMAC_NATIVE_ADAPTER_HANDOFF: sha512 72\n"))

                with patch.object(native.platform, "machine", return_value="x86_64"), \
                        patch.object(native, "result", side_effect=run), redirect_stdout(io.StringIO()):
                    if fault is None:
                        native.check({}, directory, {"RUSTFLAGS": "ambient"}, "sha512")
                        self.assertEqual(len(calls), 14)
                    else:
                        with self.assertRaises(ValueError):
                            native.check({}, directory, {}, "sha512")
                if fault != "host":
                    self.assertEqual(backends.read_text(), original, "mutants must always be restored")
                self.assertEqual((prepared / "src/execution/backends.rs").read_text(), original)

    def test_native_handoff_refuses_unsupported_host_or_route(self):
        for arch, route in (("riscv64", "sha256"), ("x86_64", "implicit")):
            with patch.object(native.platform, "machine", return_value=arch), \
                    self.assertRaisesRegex(ValueError, "unsupported"):
                native.check({}, Path("/unused"), {}, route)


if __name__ == "__main__":
    unittest.main()
