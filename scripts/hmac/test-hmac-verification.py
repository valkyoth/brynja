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
                     "assurance/hmac-policy/Cargo.lock", "assurance/hmac-faults/fault_tests.rs"):
            with self.subTest(path=path):
                full, groups = commands.scope.select([path])
                self.assertFalse(full)
                self.assertEqual(groups, ("hmac",))
        for family in ("sha2", "sha3", "core", "static_cpu"):
            self.assertIn("hmac", commands.scope.closure({family}))

    def test_miri_keeps_all_algorithms_and_unwind_independently_schedulable(self):
        expected = {"sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
                    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                    "output_clears_during_consumer_unwind"}
        tasks = miri_tasks.inventory(ROOT, "hmac")
        self.assertEqual(len(tasks), len(expected))
        self.assertEqual({argv[argv.index("--test") + 2] for argv in tasks}, expected)
        for argv in tasks:
            self.assertEqual(argv[argv.index("-p") + 1], "brynja-mac-hmac")
            self.assertEqual(argv[argv.index("--test") + 1], "bounded")
            self.assertIn("--exact", argv)
            self.assertNotIn("--skip", argv)
        for profile in ("routine", "extended", "existing-full"):
            self.assertEqual(len(miri_tasks.task_inventory(ROOT, "hmac", profile)), 11)

    def test_sanitizer_and_matrix_ownership(self):
        sanitizer = commands.catalog(ROOT / "scripts/zeroization/check-zeroization-sanitizer.sh")
        self.assertEqual(commands.selected(sanitizer, ["hmac"]),
                         ["python3 scripts/hmac/check-hmac-asan.py"])
        matrix = [command for command, _ in commands.matrix_commands()
                  if commands.selected([command], ["hmac"]) and commands.owners(command)]
        self.assertTrue(matrix)
        self.assertTrue(all("-p brynja-mac-hmac " in command for command in matrix))
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
                self.assertEqual(len(rows), 13)
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
        for population in (True, False):
            calls = []

            def run(argv, env):
                self.assertEqual(env["ASAN_OPTIONS"], "detect_leaks=1:halt_on_error=1:exitcode=1")
                self.assertEqual(env["LSAN_OPTIONS"], "exitcode=23")
                self.assertEqual(env["RUSTFLAGS"], "-Zsanitizer=address")
                self.assertNotIn("CARGO_BUILD_BUILD_DIR", env)
                target = argv[argv.index("--test") + 1]
                calls.append(target)
                count = {"bounded": 11, "vectors": 7, "lifecycle": 11}[target] if population else 0
                return f"test result: ok. {count} passed; 0 failed; 0 ignored;"

            with patch.dict(os.environ, hostile), patch.object(asan.sys, "platform", "linux"), \
                    patch.object(asan.platform, "machine", return_value="x86_64"), \
                    patch.object(verifier.cargo_environment, "private_directory", return_value=nullcontext(ROOT / "target/test-hmac-env")), \
                    patch.object(verifier.cargo_environment, "check"), patch.object(verifier, "run", side_effect=run), \
                    redirect_stdout(io.StringIO()):
                if population:
                    asan.main()
                    self.assertEqual(calls, ["bounded", "vectors", "lifecycle"])
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
