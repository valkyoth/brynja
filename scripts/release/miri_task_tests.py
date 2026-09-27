"""Task splitting preserves coverage and rejects vacuous Miri success."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import detached_catalog as catalog
import detached_manifest as records
import verification_carry_forward as carry
import verification_plan as plans
import miri_tasks

ROOT = plans.ROOT
SPEC = importlib.util.spec_from_file_location("miri_task_runner", ROOT / miri_tasks.RUNNER)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class MiriTaskTests(unittest.TestCase):
    def plan(self, groups):
        return {"approval_required": False, "stage": "internal", "groups": groups,
                "verifiers": {name: groups for name in ("miri", "kani", "asan")}}

    def test_every_full_invocation_is_present_exactly_once_in_order(self):
        groups = list(plans.scope.GROUPS)
        expected = [(group, i) for group in groups for i, _ in enumerate(miri_tasks.inventory(ROOT, group))]
        for shards in (1, 2, 8):
            entries = catalog.selected(self.plan(groups), ["miri"], None, shards, miri_tasks=True)
            self.assertEqual([(entry["argv"][3], int(entry["argv"][5])) for entry in entries], expected)
            self.assertEqual(len({entry["command"] for entry in entries}), len(entries))
            self.assertEqual(set(records.verifier_commands(ROOT, entries)), {"verifier:miri"})

    @unittest.skipUnless(os.name == "posix", "shell execution fixture requires POSIX")
    def test_parser_matches_actual_shell_execution_for_every_group(self):
        spec = importlib.util.spec_from_file_location("miri_scope_fixture",
            ROOT / "scripts/zeroization/test-miri-scope.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        status, actual = module.run_profile("--full")
        self.assertEqual(status, 0)
        expected = [" ".join(argv) for group in plans.scope.GROUPS
                    for argv in miri_tasks.inventory(ROOT, group)]
        prefix = "+nightly-2026-09-11 miri test --target x86_64-unknown-linux-gnu "
        self.assertTrue(all(command.startswith(prefix) for command in actual))
        self.assertEqual([command.removeprefix(prefix) for command in actual], expected)

    def test_unknown_inventory_syntax_never_silently_drops_tests(self):
        for body in ("if true; then\nrun_miri --lib\nfi", "other_helper", "run_miri $(echo --lib)",
                     "run_miri --lib; true", "run_miri --lib | cat", "run_miri --test test_*",
                     "run_miri --test test_{a,b}", "for x in a; do\nrun_miri $x",
                     "for x in a; do\nfor y in b; do\nrun_miri $x\ndone\ndone"):
            with self.assertRaises(ValueError):
                miri_tasks.parse(body)

    def test_single_task_cannot_cover_whole_family_or_another_task(self):
        tasks = catalog.selected(self.plan(["tuplehash"]), ["miri"], None, miri_tasks=True)
        whole = catalog.selected(self.plan(["tuplehash"]), ["miri"], None)
        self.assertTrue(carry.covered(tasks[0], [tasks[0]]))
        self.assertFalse(carry.covered(tasks[1], [tasks[0]]))
        self.assertFalse(carry.covered(whole[0], tasks))
        self.assertFalse(carry.covered(tasks[0], whole))

    def test_inventory_cache_cannot_be_mutated_by_caller(self):
        original = miri_tasks.inventory(ROOT, "core")
        miri_tasks.inventory(ROOT, "core")[0].append("--skip")
        self.assertEqual(original, miri_tasks.inventory(ROOT, "core"))
        with self.assertRaises(ValueError):
            miri_tasks.inventory(ROOT, "unknown")

    def test_no_safety_or_compiler_override_is_inherited(self):
        with patch.dict(os.environ, {}, clear=True):
            env = runner.environment(ROOT)
            self.assertEqual(env["MIRIFLAGS"], "-Zmiri-report-progress=10000000")
            self.assertTrue(env["CARGO_TARGET_DIR"].endswith("target/miri-tasks"))
        for key in ("MIRIFLAGS", "RUSTFLAGS", "MIRI_SYSROOT", "RUSTC_WRAPPER", "CARGO_TARGET_DIR"):
            with patch.dict(os.environ, {key: "hostile"}, clear=True), self.assertRaises(ValueError):
                runner.environment(ROOT)

    def test_summary_is_anchored_and_requires_no_failed_tests(self):
        for text in ("test result: ok. 2 passed; 0 failed; 0 ignored;",):
            self.assertEqual(int(runner.SUMMARY.match(text)[1]), 2)
        for text in ("test result: FAILED. 2 passed; 1 failed; 0 ignored;",
                     "test result: ok. 2 passed; 1 failed; 0 ignored;", "prefix test result: ok. 1 passed; 0 failed; 0 ignored;"):
            self.assertIsNone(runner.SUMMARY.match(text))

    def test_success_exit_still_requires_nonzero_tests(self):
        args = ["runner", "--group", "core", "--task", "0"]
        for result in ((0, 0), (1, 4), (0, 3)):
            with patch.object(sys, "argv", args), patch.object(runner, "environment", return_value={}), \
                 patch.object(runner, "stream", return_value=result) as stream, \
                 patch("builtins.print"):
                if result == (0, 3):
                    self.assertEqual(runner.main(), 0)
                else:
                    with self.assertRaises(ValueError):
                        runner.main()
                argv = stream.call_args.args[0]
                for required in ("--locked", "--offline", "--nocapture", "+nightly-2026-09-11"):
                    self.assertIn(required, argv)

    def test_real_subprocess_small_output_and_exit_are_observed(self):
        # Run the streaming implementation in a separate Python process, not a
        # mocked pipe. This is a runner test, not claimed Miri evidence.
        code = ("import sys; sys.path.insert(0," + repr(str(ROOT / "scripts/zeroization")) + "); "
                "import importlib.util; from pathlib import Path; "
                "s=importlib.util.spec_from_file_location('r'," + repr(str(ROOT / miri_tasks.RUNNER)) + "); "
                "r=importlib.util.module_from_spec(s); s.loader.exec_module(r); "
                "print(r.stream([sys.executable,'-c',"
                "'print(\"test result: ok. 3 passed; 0 failed; 0 ignored;\"); raise SystemExit(7)'],Path.cwd(),{}))")
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(7, 3)", result.stdout)
