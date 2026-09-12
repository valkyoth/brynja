#!/usr/bin/env python3
"""Real-process and corruption regressions for detached verification."""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_catalog as catalog
import detached_job as jobs
import detached_manifest as records
import detached_process as processes
import detached_reuse as reuse
import verification_plan as plans
from detached_shard_tests import ShardTests


def plan(groups=("parallelhash",), *, public=False, blocked=False):
    return {"fingerprint": "a" * 64, "approval_required": blocked, "head": "b" * 40,
            "stage": "public" if public else "internal", "base": "v0.24.39",
            "groups": list(groups), "issues": [],
            "verifiers": {kind: list(groups) for kind in ("asan", "miri", "kani")}}


def command(code):
    return {"phase": "repository", "command": "test fixture", "argv": [sys.executable, "-c", code],
            "stdin": None, "environment": {}}


def fixture(directory, commands):
    directory.mkdir()
    (directory / "source").mkdir()
    manifest = {"schema": 1, "id": "test", "created": jobs.stamp(), "plan": plan(),
                "approval": None, "phases": ["repository"], "commands": commands,
                "sources": {}, "tools": {}, "seconds": 20, "log_bytes": 4096,
                "shards": 1, "workers": 1}
    records.atomic(directory / "manifest.json", manifest)
    return records.digest(manifest)


@contextlib.contextmanager
def fixture_context():
    # Only the test process mocks source/tool probes. Production has no test
    # flag, environment bypass, alternate command importer or fake-success mode.
    with patch.object(jobs, "validate_source"), patch.object(records, "tool_identity", return_value={}):
        yield


class SelectionTests(unittest.TestCase):
    def test_selected_verifier_versions_are_bound_separately_from_rust(self):
        root = Path(__file__).resolve().parents[2]
        entries = catalog.selected(plan(), ["miri", "kani"], None)
        probes = records.verifier_commands(root, entries)
        self.assertEqual(set(probes), {"verifier:miri", "verifier:kani"})
        self.assertTrue(all(argv[-1] == "--version" for argv in probes.values()))
        self.assertEqual(records.verifier_commands(root,
                         catalog.selected(plan(()), ["kani"], None)), {})
        self.assertEqual(records.verifier_commands(root,
                         catalog.selected(plan(), ["repository"], None)), {})
        def output(argv, **_):
            return b"stable\n" if argv != ["rustup", "toolchain", "list"] else b""
        with patch.object(records.subprocess, "check_output", side_effect=output):
            before = records.tool_identity(root, entries)
        for changed in probes.values():
            def drift(argv, **kwargs):
                return b"updated verifier\n" if argv == changed else output(argv, **kwargs)
            with patch.object(records.subprocess, "check_output", side_effect=drift):
                after = records.tool_identity(root, entries)
            self.assertEqual(before["rustc"], after["rustc"])
            self.assertNotEqual(before, after)
        with patch.object(records.subprocess, "check_output", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                records.tool_identity(root, entries)

    def test_foreground_reuse_never_grants_approval_or_ci_success(self):
        spec = importlib.util.spec_from_file_location("foreground_reuse", Path(__file__).with_name("run-verification.py"))
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        base = ["runner", "miri", "--detached-job", "/tmp/test-job", "--detached-receipt", "receipt"]
        for chosen_plan, args, covered, expected, executions, imports in (
            (plan(), base, True, 0, 0, 1),
            (plan(), base, False, 0, 1, 1),
            (plan(blocked=True), base, True, 3, 0, 0),
            (plan(), ["runner", "repository", "--ci", *base[2:]], True, 1, 0, 0),
            (plan(), base[:-2], True, 1, 0, 0),
        ):
            with patch.object(runner.plans, "build", return_value=chosen_plan), \
                 patch.object(runner.sys, "argv", args), patch.object(runner, "execute") as execute, \
                 patch.object(reuse, "completed", return_value=covered) as imported, \
                 patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(runner.main(), expected)
                self.assertEqual(execute.call_count, executions)
                self.assertEqual(imported.call_count, imports)

    def test_foreground_command_equivalence(self):
        spec = importlib.util.spec_from_file_location("foreground", Path(__file__).with_name("run-verification.py"))
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        for selected in (plan(), plan(()), plan(public=True), plan(blocked=True)):
            approval = selected["fingerprint"] if selected["approval_required"] else None
            for phase in catalog.PHASES:
                executed = []
                args = ["runner", phase] + (["--approve-full", approval] if approval else [])
                with patch.object(runner.plans, "build", return_value=selected), \
                     patch.object(runner.sys, "argv", args), \
                     patch.object(runner, "execute", side_effect=lambda c, s=None: executed.append((c, s))), \
                     patch.object(runner, "prepare_matrix"), \
                     patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(runner.main(), 0)
                detached = catalog.selected(selected, [phase], approval)
                self.assertEqual(executed, [(c["command"], c["stdin"]) for c in detached])

    def test_invalid_phases_and_stale_approval(self):
        for phases in ([], ["shell"], ["miri", "miri"]):
            with self.assertRaises(ValueError):
                catalog.selected(plan(), phases, None)
        with self.assertRaises(PermissionError):
            catalog.selected(plan(blocked=True), ["miri"], None)
        with self.assertRaises(ValueError):
            catalog.selected(plan(blocked=True), ["miri"], "c" * 64)


class RecordTests(unittest.TestCase):
    def test_resource_shape_and_numeric_bounds(self):
        valid = {"children_user_seconds": 1.5, "children_system_seconds": 0.25,
                 "children_max_rss_bytes": 1024, "runner_max_rss_bytes": 512}
        jobs.validate_usage(valid)
        for key in valid:
            for value in (-1, True, "1", float("inf"), float("nan")):
                with self.assertRaises(ValueError):
                    jobs.validate_usage({**valid, key: value})
            missing = dict(valid)
            del missing[key]
            with self.assertRaises(ValueError):
                jobs.validate_usage(missing)
        with self.assertRaises(ValueError):
            jobs.validate_usage({**valid, "runner_max_rss_bytes": 1.5})

    def test_source_plan_and_command_drift(self):
        manifest = {"sources": {"head": "a"}, "plan": plan(), "phases": ["miri"], "approval": None,
                    "shards": 1,
                    "commands": catalog.selected(plan(), ["miri"], None)}
        with patch.object(records, "sources", return_value=manifest["sources"]), \
             patch.object(plans, "build", return_value=manifest["plan"]):
            jobs.validate_source(manifest, Path("unused"))
            with patch.object(records, "sources", return_value={"head": "b"}), self.assertRaises(ValueError):
                jobs.validate_source(manifest, Path("unused"))
            with patch.object(plans, "build", return_value=plan(("sha2",))), self.assertRaises(ValueError):
                jobs.validate_source(manifest, Path("unused"))
            changed = {**manifest, "commands": []}
            with self.assertRaises(ValueError):
                jobs.validate_source(changed, Path("unused"))

    def test_duplicate_keys_size_and_non_regular_inputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for text in ('{"x":1,"x":2}', '[]', '{"x":NaN}', '{"x":1e999}', '{'):
                (root / "bad.json").write_text(text)
                with self.assertRaises(ValueError):
                    records.read(root / "bad.json")
            (root / "real").write_text("123456")
            with self.assertRaises(ValueError):
                records.file_hash(root / "real", 5)
            with self.assertRaises(ValueError):
                records.file_hash(root)
            with self.assertRaises(ValueError):
                records.safe_path(root / "child/../real")
            # Windows requires an elevated symlink privilege; production start
            # is unsupported there. Keep ordinary record tests cross-platform.
            if os.name == "posix":
                (root / "link").symlink_to(root / "real")
                (root / "parent").symlink_to(root, target_is_directory=True)
                for path in (root / "link", root / "parent/real"):
                    with self.assertRaises(ValueError):
                        records.file_hash(path)

    def test_frozen_dirty_source_and_tracked_deletion(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            root.mkdir()
            def git(*args):
                return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
            git("init", "-q")
            (root / "keep").write_text("original")
            (root / "deleted").write_text("original")
            git("add", ".")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "--no-gpg-sign", "-qm", "fixture")
            (root / "keep").write_text("changed")
            (root / "deleted").unlink()
            (root / "new").write_text("untracked")
            closure = records.sources(root)
            jobs.clone_inputs(root, Path(raw) / "frozen", closure)
            self.assertEqual(closure, records.sources(Path(raw) / "frozen"))
            (root / "keep").write_text("changed again")
            self.assertNotEqual(closure, records.sources(root))

    def test_bounds(self):
        for seconds, size in ((0, 1024), (86401, 1024), (True, 1024), (1, 0), (1, 2**31)):
            with self.assertRaises(ValueError):
                jobs.bounds(seconds, size)


@unittest.skipUnless(sys.platform in {"linux", "darwin"}, "POSIX detached runner")
class ProcessTests(unittest.TestCase):
    def run_command(self, code, *, seconds=3, maximum=2048, cancel=False):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            if cancel:
                (root / "cancel").touch()
            result = processes.execute([sys.executable, "-c", code], root, root / "log", root / "cancel",
                                       seconds=seconds, maximum=maximum, environment=dict(os.environ))
            self.assertLessEqual((root / "log").stat().st_size, maximum)
            return result

    def test_success_and_exit_failure(self):
        self.assertEqual(self.run_command('print("PASS")')["state"], "passed")
        result = self.run_command('print("PASS"); raise SystemExit(9)')
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["exit_code"], 9)

    def test_output_bound(self):
        self.assertEqual(self.run_command('print("x" * 1000000)')["state"], "log_limit")

    def test_timeout_and_cancellation(self):
        self.assertEqual(self.run_command('import time; time.sleep(10)', seconds=.1)["state"], "timed_out")
        self.assertEqual(self.run_command('import time; time.sleep(10)', cancel=True)["state"], "cancelled")

    def test_descendant_holds_output_after_leader_exits(self):
        code = 'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])'
        start = time.monotonic()
        self.assertEqual(self.run_command(code, seconds=.3)["state"], "timed_out")
        self.assertLess(time.monotonic() - start, 6)

    def test_running_cancellation_kills_child(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            timer = threading.Timer(.15, lambda: (root / "cancel").touch())
            timer.start()
            try:
                result = processes.execute([sys.executable, "-c", "import time; time.sleep(30)"],
                                           root, root / "log", root / "cancel", seconds=10,
                                           maximum=1024, environment=dict(os.environ))
            finally:
                timer.join()
            self.assertEqual(result["state"], "cancelled")

    def test_log_open_failure_does_not_start_command(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "log").touch()
            with self.assertRaises(FileExistsError):
                processes.execute([sys.executable, "-c", 'open("marker","w").close()'], root,
                                  root / "log", root / "cancel", seconds=1, maximum=1024,
                                  environment=dict(os.environ))
            self.assertFalse((root / "marker").exists())


@unittest.skipUnless(sys.platform in {"linux", "darwin"}, "POSIX detached runner")
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.cwd = Path.cwd()
        self.temporary = tempfile.TemporaryDirectory()
        self.job = Path(self.temporary.name) / "job"
        self.receipt = fixture(self.job, [command('print("fixture pass")')])

    def tearDown(self):
        os.chdir(self.cwd)
        self.temporary.cleanup()

    def complete(self):
        with fixture_context():
            self.assertEqual(jobs.worker(self.job, self.receipt), 0)
            self.assertFalse(jobs.collect(self.job, self.receipt, self.job / "source")["release_authorized"])

    def test_success_duplicate_start_and_cancelled_collection(self):
        self.complete()
        with self.assertRaises(FileExistsError), fixture_context():
            jobs.worker(self.job, self.receipt)
        (self.job / "cancel").touch()
        with self.assertRaises(ValueError), fixture_context():
            jobs.collect(self.job, self.receipt, self.job / "source")

    def test_manifest_tamper(self):
        value = records.read(self.job / "manifest.json")
        value["commands"] = []
        records.atomic(self.job / "manifest.json", value)
        with self.assertRaises(ValueError):
            jobs.load(self.job, self.receipt)

    def test_tool_drift_fails_before_running_commands(self):
        with patch.object(jobs, "validate_source"), patch.object(records, "tool_identity", return_value={"rustc": "drift"}):
            self.assertEqual(jobs.worker(self.job, self.receipt), 1)
        self.assertFalse((self.job / "command-0000.log").exists())
        self.assertEqual(records.read(self.job / "state.json")["state"], "failed")

    def test_collection_rejects_tools_changed_after_success(self):
        self.complete()
        with patch.object(jobs, "validate_source"), \
             patch.object(records, "tool_identity", return_value={"compiler": "changed"}), \
             self.assertRaisesRegex(ValueError, "tool identity"):
            jobs.collect(self.job, self.receipt, self.job / "source")

    def test_reuse_only_covers_complete_matching_phases_and_commands(self):
        self.complete()
        with fixture_context():
            self.assertTrue(reuse.completed(self.job, self.receipt, self.job / "source", plan(), "repository"))
            self.assertFalse(reuse.completed(self.job, self.receipt, self.job / "source", plan(), "miri"))
            self.assertTrue(reuse.completed(self.job, self.receipt, self.job / "source", plan(), "command", "test fixture"))
            self.assertFalse(reuse.completed(self.job, self.receipt, self.job / "source", plan(), "command", "test fixture --skip"))
            with self.assertRaisesRegex(ValueError, "this release plan"):
                reuse.completed(self.job, self.receipt, self.job / "source", plan(("sha2",)), "repository")
            with self.assertRaises(ValueError):
                reuse.completed(self.job, self.receipt, self.job / "source", plan(), "command")
            (self.job / "cancel").touch()
            with self.assertRaises(ValueError):
                reuse.completed(self.job, self.receipt, self.job / "source", plan(), "repository")

    def test_exit_code_corruption_even_with_rehashed_envelope(self):
        self.complete()
        original = records.read(self.job / "result.json")
        for exit_code in (7, False, "0", -9):
            value = copy.deepcopy(original)
            value["results"][0]["exit_code"] = exit_code
            records.atomic(self.job / "result.json", value)
            records.atomic(self.job / "command-0000.json", value["results"][0])
            records.atomic(self.job / "state.json", {"state": "passed", "manifest": self.receipt,
                                                    "result_sha256": records.digest(value)})
            with self.assertRaises(ValueError), fixture_context():
                jobs.collect(self.job, self.receipt, self.job / "source")

    def test_result_tamper_missing_and_truncated_log(self):
        self.complete()
        original = records.read(self.job / "result.json")
        for key, value in (("state", "running"), ("results", []), ("failure_class", "OSError")):
            changed = copy.deepcopy(original)
            changed[key] = value
            records.atomic(self.job / "result.json", changed)
            with self.assertRaises(ValueError), fixture_context():
                jobs.collect(self.job, self.receipt, self.job / "source")
        records.atomic(self.job / "result.json", original)
        (self.job / "command-0000.log").write_text("PASS")
        with self.assertRaises(ValueError), fixture_context():
            jobs.collect(self.job, self.receipt, self.job / "source")
        (self.job / "command-0000.log").unlink()
        with self.assertRaises(OSError), fixture_context():
            jobs.collect(self.job, self.receipt, self.job / "source")

    def test_rehashed_resource_omission_is_not_collectable(self):
        self.complete()
        result = records.read(self.job / "result.json")
        self.assertGreater(result["resources"]["runner_max_rss_bytes"], 0)
        result["resources"] = {}
        records.atomic(self.job / "result.json", result)
        records.atomic(self.job / "state.json", {"state": "passed", "manifest": self.receipt,
                                                "result_sha256": records.digest(result)})
        with self.assertRaisesRegex(ValueError, "resource observations"), fixture_context():
            jobs.collect(self.job, self.receipt, self.job / "source")

    def test_failed_command_stops_later_work(self):
        value = records.read(self.job / "manifest.json")
        value["commands"] = [command('raise SystemExit(7)'), command('print("must not run")')]
        records.atomic(self.job / "manifest.json", value)
        self.receipt = records.digest(value)
        with fixture_context():
            self.assertEqual(jobs.worker(self.job, self.receipt), 1)
            self.assertFalse((self.job / "command-0001.log").exists())
            with self.assertRaises(ValueError):
                jobs.collect(self.job, self.receipt, self.job / "source")

    def test_source_tool_failures_and_disk_failure_never_pass(self):
        for probe in ("validate_source", "atomic"):
            # Separate directories: failed runs are not restarted in place.
            child = Path(self.temporary.name) / probe
            receipt = fixture(child, [command('print("test")')])
            with fixture_context():
                if probe == "atomic":
                    with patch.object(records, "atomic", side_effect=OSError("disk full")), self.assertRaises(OSError):
                        jobs.worker(child, receipt)
                else:
                    with patch.object(jobs, probe, side_effect=ValueError("source changed")):
                        self.assertEqual(jobs.worker(child, receipt), 1)
                with self.assertRaises((ValueError, OSError)):
                    jobs.collect(child, receipt, child / "source")

    def test_detached_worker_survives_initiator_exit(self):
        script = str(Path(__file__).resolve())
        # The initiator exits before the command starts/finishes. The next
        # invocation collects the record without sharing a Popen or PTY handle.
        launcher = ('import subprocess,sys; subprocess.Popen([sys.executable,' + repr(script)
                    + ',"--fixture-worker",' + repr(str(self.job)) + ',' + repr(self.receipt)
                    + '],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,'
                    'start_new_session=True,close_fds=True)')
        subprocess.run([sys.executable, "-c", launcher], check=True, timeout=5)
        deadline = time.monotonic() + 10
        while not (self.job / "state.json").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        while time.monotonic() < deadline:
            state = records.read(self.job / "state.json")
            if state["state"] in jobs.TERMINAL:
                break
            time.sleep(.05)
        self.assertEqual(records.read(self.job / "state.json")["state"], "passed")
        with fixture_context():
            self.assertEqual(jobs.collect(self.job, self.receipt, self.job / "source")["state"], "validated")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--fixture-worker":
        time.sleep(.2)
        with fixture_context():
            raise SystemExit(jobs.worker(Path(sys.argv[2]), sys.argv[3]))
    unittest.main()
