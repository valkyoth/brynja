#!/usr/bin/env python3
"""RV64 candidate runner population, ISA and non-admission regressions."""
import importlib.util
from pathlib import Path
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("aes_riscv_runner", Path(__file__).with_name("check-aes-riscv.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RiscVTests(unittest.TestCase):
    def test_missing_cross_tools_or_host_root_cannot_fall_back(self):
        with patch.object(RUNNER.shutil, 'which', return_value=None), self.assertRaises(ValueError):
            RUNNER.platform_config()
        with patch.object(RUNNER.shutil, 'which', side_effect=lambda name: '/usr/bin/' + name), \
             patch.object(RUNNER.subprocess, 'check_output', return_value='/\n'), \
             patch.object(Path, 'is_dir', return_value=False), self.assertRaises(ValueError):
            RUNNER.platform_config()

    def test_execution_prefix_is_explicit_qemu_and_disables_sha(self):
        self.assertEqual(RUNNER.execution('/qemu-riscv64', '/target-runtime'), [
            '/qemu-riscv64', '-cpu', 'max,zknh=false', '-L', '/target-runtime', '-E',
            'LD_LIBRARY_PATH=/lib:/lib64:/lib64/lp64d:/usr/lib:/usr/lib64'])

    def test_each_boundary_population_is_required(self):
        text = 'test result: ok. 3 passed; 0 failed; 0 ignored;\n' + '\n'.join(RUNNER.BOUNDARY_MARKERS)
        RUNNER.STATIC.validate_tests(text, 3, RUNNER.BOUNDARY_MARKERS)
        for marker in RUNNER.BOUNDARY_MARKERS:
            for mutated in (text.replace(marker, ''), text + '\n' + marker,
                            text.replace('256 alignment pairs', '255 alignment pairs')):
                with self.assertRaises(ValueError):
                    RUNNER.STATIC.validate_tests(mutated, 3, RUNNER.BOUNDARY_MARKERS)

    def test_exact_bundle_without_sha_or_vector_dependency(self):
        flags, cpu = RUNNER.phase_config("candidate")
        self.assertEqual(flags, ["--cfg", "brynja_cpu_evidence", "-C", "target-feature=+zkne,+zknd"])
        self.assertEqual(cpu, "max,zknh=false")

    def test_ordinary_build_cannot_enable_evidence(self):
        flags, _ = RUNNER.phase_config("unadmitted")
        self.assertNotIn("brynja_cpu_evidence", flags)
        self.assertIn("target-feature=+zkne,+zknd", flags)

    def test_each_missing_half_is_disabled_in_compiler_and_emulator(self):
        for phase, missing in (("no-encrypt", "zkne"), ("no-decrypt", "zknd")):
            flags, cpu = RUNNER.phase_config(phase)
            self.assertIn("-" + missing, flags[-1])
            self.assertIn(missing + "=false", cpu)

    def test_ignored_failed_or_incomplete_population_is_not_success(self):
        valid = "test result: ok. 9 passed; 0 failed; 0 ignored;"
        marker = RUNNER.STATIC.STARTUP_MARKER
        RUNNER.STATIC.validate_tests(valid + "\n" + marker, 9, (marker,))
        for output in (valid, valid.replace("9 passed", "8 passed") + "\n" + marker,
                       valid.replace("0 ignored", "1 ignored") + "\n" + marker,
                       valid.replace("0 failed", "1 failed") + "\n" + marker,
                       valid + "\n" + marker + "\n" + marker):
            with self.assertRaises(ValueError):
                RUNNER.STATIC.validate_tests(output, 9, (marker,))

    def test_build_and_runner_overrides_are_rejected(self):
        for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "PYTHONOPTIMIZE",
                    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUNNER",
                    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER",
                    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_RUSTFLAGS"):
            self.assertIn(key, RUNNER.REJECT_ENV)

    def test_registry_has_both_endpoints_and_all_exact_phase_markers(self):
        registry = tomllib.loads((ROOT / "verification/checks.toml").read_text())
        rows = [row for row in registry["checks"] if row.get("category") == "aes-riscv"]
        self.assertEqual(len(rows), 2)
        for row, version in zip(rows, ("1.90.0", "1.99.1")):
            self.assertEqual(row["command"], ["python3", "scripts/aes/check-aes-riscv.py", "--toolchain", version])
            self.assertEqual(row["success"]["exact_tests"], 148)
            self.assertEqual(row["success"]["minimum_tests"], 148)
            self.assertEqual(row["success"]["unique_lines"], [
                *[f"AES_RISCV_PHASE_PASS: {phase} {profile}" for phase in RUNNER.PHASES
                  for profile in ("debug", "release")],
                f"AES_RISCV_QEMU_PASS: {version}; 148 tests; evidence-only candidate"])
            self.assertTrue({"aes-riscv", "aes-static-execution", "cpu-source", "aes-build",
                             "hosted-cpu-source", "hash-core", "sha2-source", "sha3-source",
                             "hmac-source", "kmac-source", "tuplehash-source", "parallelhash-source"}
                            <= set(row["inputs"]))
            self.assertTrue(set(RUNNER.REJECT_ENV) <= set(row["reject_environment"]))
            self.assertIn("not native", row["establishes"])


if __name__ == "__main__":
    unittest.main()
