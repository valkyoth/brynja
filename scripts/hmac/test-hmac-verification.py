#!/usr/bin/env python3
"""HMAC-only selection, exact verifier populations and hostile-environment tests."""
from contextlib import nullcontext, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hmac_verifiers as verifier

ROOT = verifier.ROOT
sys.path.append(str(ROOT / "scripts/release"))
import verification_commands as commands
import detached_catalog as catalog
import detached_manifest as records
import verification_carry_forward as carry
import miri_tasks


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/hmac" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


asan = load("check-hmac-asan")
kani = load("check-hmac-kani")


class ScopeTests(unittest.TestCase):
    def test_hmac_changes_do_not_select_upstream_implementations(self):
        for path in ("crates/brynja-mac-hmac/src/engine.rs", "scripts/hmac/check-hmac-asan.py",
                     "assurance/hmac-policy/Cargo.lock", "assurance/hmac-faults/fault_tests.rs",
                     "assurance/hmac-facade/acceptance.rs", "scripts/hmac/check-hmac-facade.py",
                     "assurance/hmac-strict/compiled.rs", "scripts/hmac/check-hmac-strict.py",
                     "crates/brynja-strict/src/hmac.rs", "crates/brynja-strict/src/hmac_tests.rs",
                     "assurance/hmac-cleanup/Cargo.lock", "assurance/hmac-cleanup/src/lib.rs",
                     "assurance/hmac-engine-cleanup/Cargo.lock",
                     "assurance/hmac-engine-cleanup/src/lib.rs",
                     "assurance/hmac-execution-cleanup/Cargo.lock",
                     "assurance/hmac-execution-cleanup/src/lib.rs",
                     "assurance/hmac-hosted-cleanup/Cargo.lock",
                     "assurance/hmac-hosted-cleanup/src/lib.rs",
                     "scripts/hmac/check-hmac-hosted-cleanup.py",
                     "scripts/hmac/hmac_hosted_capture.py",
                     "scripts/hmac/hmac_hosted_capture_types.py",
                     "scripts/hmac/hmac_hosted_capture_tests.py",
                     "scripts/hmac/hmac_hosted_placement.py",
                     "scripts/hmac/hmac_hosted_authority.py",
                     "scripts/hmac/hmac_hosted_authority_tests.py",
                     "scripts/hmac/hmac_hosted_keyed.py",
                     "scripts/hmac/hmac_hosted_keyed_tests.py",
                     "scripts/hmac/hmac_hosted_storage.py",
                     "scripts/hmac/hmac_hosted_scalar.py",
                     "scripts/hmac/hmac_hosted_compiled.py",
                     "scripts/hmac/hmac_hosted_retained_tests.py",
                     "scripts/hmac/hmac_hosted_output.py",
                     "scripts/hmac/hmac_hosted_output_paths.py",
                     "scripts/hmac/hmac_hosted_output_tests.py",
                     "scripts/hmac/hmac_hosted_input.py",
                     "scripts/hmac/hmac_hosted_tail.py",
                     "scripts/hmac/hmac_hosted_tail_transfer.py",
                     "scripts/hmac/hmac_hosted_input_tests.py",
                     "scripts/hmac/hmac_hosted_checkpoints.py",
                     "scripts/hmac/hmac_hosted_checkpoint_results.py",
                     "scripts/hmac/hmac_hosted_checkpoint_callees.py",
                     "scripts/hmac/hmac_hosted_checkpoint_tests.py",
                     "scripts/hmac/hmac_hosted_transaction.py",
                     "scripts/hmac/hmac_hosted_transaction_values.py",
                     "scripts/hmac/hmac_hosted_transaction_tests.py",
                     "scripts/hmac/hmac_hosted_guard_paths.py",
                     "scripts/hmac/hmac_hosted_buffers.py",
                     "scripts/hmac/hmac_hosted_callee_admission.py",
                     "scripts/hmac/hmac_hosted_constructor.py",
                     "scripts/hmac/hmac_hosted_constructor_tests.py",
                     "scripts/hmac/hmac_hosted_consumers.py",
                     "scripts/hmac/hmac_hosted_scalar_callee_tests.py",
                     "scripts/hmac/hmac_hosted_consumer_prefix.py",
                     "scripts/hmac/hmac_hosted_compiled_callee_tests.py",
                     "scripts/hmac/hmac_hosted_loan_flow.py",
                     "scripts/hmac/hmac_hosted_loan_resources.py",
                     "scripts/hmac/hmac_hosted_loan_creation.py",
                     "scripts/hmac/hmac_hosted_loans.py",
                     "scripts/hmac/hmac_hosted_loan_tests.py",
                     "scripts/hmac/hmac_hosted_verify.py",
                     "scripts/hmac/hmac_hosted_verify_tests.py",
                     "scripts/hmac/hmac_engine_construct.py",
                     "scripts/hmac/hmac_engine_construct_state.py",
                     "scripts/hmac/hmac_callee_identity.py",
                     "scripts/hmac/hmac_execution_construct.py",
                     "scripts/hmac/hmac_execution_construct_state.py",
                     "scripts/hmac/hmac_execution_construct_contracts.py",
                     "scripts/hmac/hmac_execution_final_contracts.py",
                     "scripts/hmac/hmac_execution_final.py",
                     "scripts/hmac/hmac_execution_scratch.py",
                     "scripts/hmac/hmac_execution_drop.py",
                     "scripts/hmac/hmac_execution_update.py",
                     "assurance/hmac-timing/src/main.rs", "assurance/hmac-timing/Cargo.lock",
                     "assurance/hmac-timing/src/routes.rs", "scripts/hmac/hmac_timing_routes.py",
                     "scripts/hmac/hmac_timing_fixture_tests.py",
                     "assurance/hmac-faults/adapter_tests.rs",
                     "assurance/hmac-faults/native_adapter_tests.rs",
                     "assurance/hmac-faults/execution_model.rs",
                     "assurance/hmac-faults/execution_cases.rs",
                     "scripts/hmac/hmac_execution_faults.py",
                     "scripts/hmac/check-hmac-hosted-native.py",
                     "crates/brynja-crypto-cpu-std/src/execution/hmac.rs",
                     "crates/brynja-crypto-cpu-std/tests/hmac.rs",
                     "crates/brynja-crypto-cpu-std/src/strict_hmac/worker.rs",
                     "crates/brynja-crypto-cpu-std/src/macos_resident/hmac/compiled/worker.rs"):
            with self.subTest(path=path):
                full, groups = commands.scope.select([path])
                self.assertFalse(full)
                self.assertEqual(groups, ("hmac",))
        for family in ("sha2", "sha3", "core", "static_cpu"):
            self.assertIn("hmac", commands.scope.closure({family}))
        for path in ("crates/brynja-crypto-cpu-std/src/execution/mod.rs",
                     "crates/brynja-crypto-cpu-std/src/execution/platform.rs",
                     "crates/brynja-crypto-cpu-std/src/execution/hmac_extra.rs"):
            self.assertIn("static_cpu", commands.scope.select([path])[1])

    def test_miri_keeps_all_algorithms_and_unwind_independently_schedulable(self):
        expected = {"sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
                    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                    "output_clears_during_consumer_unwind", "general_129", "general_511"}
        tasks = miri_tasks.inventory(ROOT, "hmac")
        self.assertEqual(len(tasks), len(expected) + 4)
        hosted = [argv for argv in tasks if "brynja-crypto-cpu-std" in argv]
        self.assertEqual(len(hosted), 3)
        self.assertEqual(hosted[0][-4:], ["--features", "hmac-execution", "--test", "hmac"])
        self.assertEqual(hosted[1][-4:], ["--features", "strict-hmac-acceleration", "--lib", "strict_hmac"])
        self.assertEqual(hosted[2][-4:], ["--features", "macos-resident-hmac-acceleration", "--lib", "macos_resident::hmac"])
        bounded = [argv for argv in tasks if "--test" in argv and argv not in hosted]
        self.assertEqual({argv[argv.index("--test") + 2] for argv in bounded}, expected)
        lifecycle = [argv for argv in tasks if "--lib" in argv and argv not in hosted]
        self.assertEqual(len(lifecycle), 1)
        self.assertEqual(lifecycle[0][-1], "execution::tests")
        self.assertIn("hardened-execution", lifecycle[0])
        for argv in bounded:
            self.assertEqual(argv[argv.index("-p") + 1], "brynja-mac-hmac")
            self.assertEqual(argv[argv.index("--test") + 1], "bounded")
            self.assertIn("--exact", argv)
            self.assertNotIn("--skip", argv)
        for profile in ("routine", "extended", "existing-full"):
            self.assertEqual(len(miri_tasks.task_inventory(ROOT, "hmac", profile)), 17)

    def test_sanitizer_and_matrix_ownership(self):
        sanitizer = commands.catalog(ROOT / "scripts/zeroization/check-zeroization-sanitizer.sh")
        self.assertEqual(commands.selected(sanitizer, ["hmac"]),
                         ["python3 scripts/hmac/check-hmac-asan.py"])
        matrix = [command for command, _ in commands.matrix_commands()
                  if commands.selected([command], ["hmac"]) and commands.owners(command)]
        self.assertTrue(matrix)
        self.assertTrue(all("-p brynja-mac-hmac " in command or
                            "-p brynja-crypto-cpu-std --features hmac-execution --test hmac" in command or
                            "-p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac" in command or
                            "-p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac" in command
                            for command in matrix))
        self.assertTrue(any("--test hmac" in command for command in matrix))
        self.assertTrue(any("--lib strict_hmac" in command for command in matrix))
        self.assertTrue(any("--lib macos_resident::hmac" in command for command in matrix))
        self.assertEqual(commands.owners(
            "cargo test -p brynja-crypto-cpu-std --features hmac-execution --test hmac"), {"hmac"})
        self.assertIn("static_cpu", commands.owners(
            "cargo test -p brynja-crypto-cpu-std --features hmac-execution"))
        self.assertIn("hmac", commands.owners("python3 scripts/cpu/check-hosted-execution.py"))
        self.assertEqual(commands.owners("python3 scripts/hmac/check-hmac-cleanup.py"), {"hmac"})
        self.assertEqual(commands.owners("python3 scripts/hmac/check-hmac-engine-cleanup.py"), {"hmac"})
        self.assertEqual(commands.owners("python3 scripts/hmac/check-hmac-execution-cleanup.py"), {"hmac"})
        self.assertEqual(commands.owners("python3 scripts/hmac/check-hmac-static-cleanup.py"), {"hmac"})
        checks = commands.catalog(ROOT / "scripts/checks.sh", "# BEGIN VERIFICATION CATALOG")
        for command in ('python3 scripts/hmac/check-hmac-strict.py', 'python3 scripts/hmac/test-hmac-strict.py'):
            self.assertEqual(checks.count(command), 1)
            self.assertEqual(commands.owners(command), {'hmac'})
            self.assertIn(command, commands.selected(checks, ['hmac']))
            self.assertNotIn(command, commands.selected(checks, ['md5']))
        for command in ("python3 scripts/hmac/check-hmac-static-cleanup.py",
                        "python3 scripts/hmac/check-hmac-static-cleanup.py --target aarch64-unknown-linux-gnu",
                        "python3 scripts/hmac/test-hmac-static-cleanup.py"):
            self.assertEqual(checks.count(command), 1)
            self.assertIn(command, commands.selected(checks, ["hmac"]))
            self.assertNotIn(command, commands.selected(checks, ["md5"]))
        for target in ("", " --target aarch64-unknown-linux-gnu", " --target aarch64-apple-darwin"):
            command = "python3 scripts/hmac/check-hmac-hosted-cleanup.py" + target
            self.assertEqual(checks.count(command), 1)
            self.assertEqual(commands.owners(command), {"hmac"})
        self.assertEqual(checks.count("python3 scripts/hmac/test-hmac-hosted-cleanup.py"), 1)
        self.assertEqual(commands.owners(
            "python3 scripts/hmac/check-hmac-hosted-native.py --kernel sha256"), {"hmac"})
        for family in ("sha2", "sha3", "core", "static_cpu"):
            affected = list(commands.scope.closure({family}))
            self.assertIn("python3 scripts/hmac/check-hmac-asan.py", commands.selected(sanitizer, affected))
        self.assertEqual(commands.owners("cargo test -p brynja-hash-sha2 -p brynja-crypto-cpu"),
                         {"sha2", "sha3", "kmac", "tuplehash", "parallelhash", "static_cpu"})

    def test_kani_selection_and_binary_identity_binding(self):
        own = "python3 scripts/hmac/check-hmac-kani.py"
        self.assertEqual(commands.kani_commands(["hmac"]), [own])
        self.assertEqual(commands.kani_commands([]), ["scripts/assurance/check-kani.sh --policy-only"])
        self.assertEqual(commands.kani_commands(["sha2", "hmac"]),
                         ["scripts/assurance/check-kani.sh --required-groups sha2", own])
        for groups in (["unknown"], ["hmac", "hmac"]):
            with self.assertRaises(ValueError):
                commands.kani_commands(groups)
        self.assertEqual(set(records.verifier_commands(ROOT, [{"argv": own.split()}])), {"verifier:kani"})
        self.assertEqual(records.verifier_commands(ROOT, [{"argv": [*own.split(), "--policy-only"]}]), {})
        entry = {"phase": "kani", "command": own, "argv": own.split(), "stdin": None, "environment": {}}
        old = "scripts/assurance/check-kani.sh --required-groups sha2 sha3"
        self.assertFalse(carry.covered(entry, [{**entry, "command": old, "argv": old.split()}]))
        self.assertTrue(carry.covered(entry, [entry]))

    def test_detached_hmac_selection_matches_foreground_for_each_partition_count(self):
        plan = {"groups": ["hmac"], "verifiers": {"miri": ["hmac"], "kani": ["hmac"], "asan": ["hmac"]}}
        with patch.object(catalog.plans, "authorize"), patch.object(catalog.plans, "requires_full", return_value=False):
            for shards in (1, 2, 8):
                rows = catalog.selected(plan, ["kani", "asan", "miri"], None, shards,
                                        miri_tasks=True, miri_profile="routine")
                self.assertEqual(len(rows), 19)
                self.assertEqual([row["command"] for row in rows if row["phase"] == "kani"],
                                 commands.kani_commands(["hmac"]))


class VerifierTests(unittest.TestCase):
    def test_child_failure_is_fatal_even_with_passing_markers(self):
        for code in (1, 23, -6):
            result = subprocess.CompletedProcess([], code, "test result: ok. 11 passed; 0 failed; 0 ignored;", "")
            with patch.object(verifier.cargo_environment, "check"), \
                    patch.object(verifier.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
                verifier.run(["cargo"], {})

    def test_sanitizer_enforcement_survives_hostile_parent_and_rejects_missing_population(self):
        hostile = {"ASAN_OPTIONS": "detect_leaks=0", "LSAN_OPTIONS": "exitcode=0",
                   "RUSTFLAGS": "-Copt-level=0", "CARGO_BUILD_BUILD_DIR": "/bad/cache"}
        populations = {"bounded": 13, "vectors": 7, "lifecycle": 11, "bits": 12,
                       "general": 5, "execution::tests": 4, "hmac": 2,
                       "strict_hmac::tests::metadata_admission_and_exact_tag_policy": 1,
                       "strict_hmac::compiled::tests::typed_kernel_admission_never_substitutes_a_backend": 1,
                       "macos_resident::hmac": 4}
        for missing in (None, *populations):
            calls = []

            def run(argv, env):
                self.assertEqual(env["ASAN_OPTIONS"], "detect_leaks=1:halt_on_error=1:exitcode=1")
                self.assertEqual(env["LSAN_OPTIONS"], "exitcode=23")
                self.assertEqual(env["RUSTFLAGS"], "-Zsanitizer=address")
                self.assertNotIn("CARGO_BUILD_BUILD_DIR", env)
                target = argv[argv.index("--test") + 1] if "--test" in argv else argv[argv.index("--lib") + 1]
                calls.append(target)
                count = populations[target] if target != missing else 0
                ignored = 1 if target == "hmac" else 0
                return f"test result: ok. {count} passed; 0 failed; {ignored} ignored;"

            with patch.dict(os.environ, hostile), patch.object(asan.sys, "platform", "linux"), \
                    patch.object(asan.platform, "machine", return_value="x86_64"), \
                    patch.object(verifier.cargo_environment, "private_directory", return_value=nullcontext(ROOT / "target/test-hmac-env")), \
                    patch.object(verifier.cargo_environment, "check"), patch.object(verifier, "run", side_effect=run), \
                    redirect_stdout(io.StringIO()):
                if missing is None:
                    asan.main()
                    self.assertEqual(calls, list(populations))
                else:
                    with self.assertRaisesRegex(ValueError, "population"):
                        asan.main()

    def test_kani_refuses_changed_identity_or_missing_proofs(self):
        pin = verifier.tool("kani")
        banner = f'Kani Rust Verifier {pin["version"]} (cargo plugin)\nCBMC 6.11.0'
        summary = "Complete - 2 successfully verified harnesses, 0 failures, 2 total."
        for outputs, error in ((["wrong"], "identity"), ([banner, "0 proofs"], "population"),
                               ([banner, summary], None)):
            with patch.object(sys, "argv", ["check-hmac-kani.py"]), \
                    patch.object(verifier.cargo_environment, "private_directory", return_value=nullcontext(ROOT / "target/test-hmac-env")), \
                    patch.object(verifier.cargo_environment, "check"), patch.object(verifier, "run", side_effect=outputs), \
                    redirect_stdout(io.StringIO()):
                if error:
                    with self.assertRaisesRegex(ValueError, error):
                        kani.main()
                else:
                    kani.main()

    def test_kani_inventory_rejects_unbound_source_dependencies_and_missing_harness(self):
        paths = ("Cargo.toml", "Cargo.lock", "src/lib.rs")
        originals = {name: (ROOT / "assurance/hmac-policy" / name).read_text() for name in paths}
        mutations = (("Cargo.toml", originals["Cargo.toml"] + '\n[dependencies]\n'),
                     ("Cargo.lock", originals["Cargo.lock"].replace('version = "0.0.0"', 'version = "0.0.1"')),
                     ("src/lib.rs", originals["src/lib.rs"].replace("#[kani::proof]", "", 1)),
                     ("src/lib.rs", originals["src/lib.rs"].replace("src/policy.rs", "src/copy.rs")))
        for name, mutant in mutations:
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                for path, text in originals.items():
                    file = root / "assurance/hmac-policy" / path
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text(mutant if path == name else text)
                with patch.object(verifier, "ROOT", root), self.assertRaises(ValueError):
                    kani.policy()


if __name__ == "__main__":
    unittest.main()
