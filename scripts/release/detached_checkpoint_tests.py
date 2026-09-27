"""Real subprocess regressions for interrupted schema-2 jobs."""
from __future__ import annotations

import contextlib
import copy
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_checkpoints as checkpoints
import detached_job as jobs
import detached_manifest as records
import detached_process as processes
import detached_catalog as catalog
import verification_plan as plans


@contextlib.contextmanager
def probes():
    with patch.object(jobs, "validate_source"), patch.object(records, "tool_identity", return_value={}):
        yield


@unittest.skipUnless(sys.platform in {"linux", "darwin"}, "POSIX detached runner")
class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.cwd = Path.cwd()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        os.chdir(self.cwd)
        self.temp.cleanup()

    def job(self, name, programs, *, seconds=10, resume=None, schema=2, partition=None):
        path = self.root / name
        path.mkdir()
        (path / "source").mkdir()
        commands = [{"phase": "repository", "command": code,
                     "argv": [sys.executable, "-c", code], "environment": {}, "stdin": None}
                    for code in programs]
        manifest = {"schema": schema, "id": name, "created": jobs.stamp(), "plan": {"head": "fixture", "stage": "internal"},
                    "approval": None, "phases": ["repository"], "commands": commands,
                    "sources": {}, "tools": {}, "seconds": seconds, "log_bytes": 4096,
                    "shards": 1, "workers": 1}
        if schema == 2:
            manifest["resume"] = resume
            manifest["partition"] = partition
            manifest["miri_profile"] = "routine"
        records.atomic(path / "manifest.json", manifest)
        return path, records.digest(manifest)

    def run_job(self, job):
        with probes():
            return jobs.worker(*job)

    def interrupted(self):
        marker = self.root / "already-ran"
        finish = self.root / "finish"
        programs = [f'from pathlib import Path; Path({str(marker)!r}).touch(exist_ok=False); print("done")',
                    f'from pathlib import Path; import time; time.sleep(0 if Path({str(finish)!r}).exists() else 30)']
        parent = self.job("parent", programs, seconds=1)
        self.assertEqual(self.run_job(parent), 1)
        self.assertEqual(records.read(parent[0] / "state.json")["state"], "timed_out")
        finish.touch()
        return parent, programs

    def test_resume_keeps_pass_and_restarts_interrupted_command(self):
        parent, programs = self.interrupted()
        before = records.read(parent[0] / "result.json")
        resumed = self.job("resume", programs,
                           resume={"job": str(parent[0]), "receipt": parent[1]})
        self.assertEqual(self.run_job(resumed), 0)
        with probes():
            result = jobs.collect(*resumed, resumed[0] / "source")
        self.assertEqual(result["commands"], 2)
        self.assertFalse(result["release_authorized"])
        self.assertEqual(before, records.read(parent[0] / "result.json"))
        self.assertEqual(records.read(parent[0] / "command-0000.json"),
                         records.read(resumed[0] / "command-0000.json"))

    def test_two_partition_jobs_merge_without_repeating_completed_tasks(self):
        programs = [f'from pathlib import Path; Path({str(self.root / str(i))!r}).touch(exist_ok=False)'
                    for i in range(4)]
        parents = [self.job(f"part-{i}", programs, partition=[i, 2]) for i in range(2)]
        for job in parents:
            self.assertEqual(self.run_job(job), 0)
            self.assertEqual(records.read(job[0] / "state.json")["state"], "partial")
            with probes(), self.assertRaises(ValueError):
                jobs.collect(*job, job[0] / "source")
        merged = self.job("merged", programs,
                          resume=[{"job": str(path), "receipt": receipt} for path, receipt in parents])
        self.assertEqual(self.run_job(merged), 0)
        with probes():
            self.assertEqual(jobs.collect(*merged, merged[0] / "source")["commands"], 4)

    def test_explicit_cancellation_keeps_checkpoint_and_restarts_only_interrupted_task(self):
        marker, finish = self.root / "once", self.root / "finish"
        programs = [f'from pathlib import Path; Path({str(marker)!r}).touch(exist_ok=False)',
                    f'from pathlib import Path; import time; print("started", flush=True); '
                    f'time.sleep(0 if Path({str(finish)!r}).exists() else 30)']
        parent = self.job("cancel-parent", programs)
        observed = []
        def cancel_after_pass():
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                active = parent[0] / "command-0001.log"
                if (parent[0] / "command-0000.json").exists() and active.exists() and active.stat().st_size:
                    observed.append(True)
                    break
                time.sleep(0.01)
            (parent[0] / "cancel").touch()
        observer = threading.Thread(target=cancel_after_pass)
        observer.start()
        try:
            self.assertEqual(self.run_job(parent), 1)
        finally:
            observer.join(timeout=6)
        self.assertFalse(observer.is_alive())
        self.assertEqual(observed, [True])
        before = records.read(parent[0] / "result.json")
        self.assertEqual(before["state"], "cancelled")
        self.assertEqual([record["state"] for record in before["results"]], ["passed", "cancelled"])
        finish.touch()
        child = self.job("cancel-resumed", programs,
                         resume={"job": str(parent[0]), "receipt": parent[1]})
        self.assertEqual(self.run_job(child), 0)
        with probes():
            self.assertEqual(jobs.collect(*child, child[0] / "source")["commands"], 2)
            with self.assertRaisesRegex(ValueError, "cancelled"):
                jobs.collect(*parent, parent[0] / "source")
        self.assertEqual(before, records.read(parent[0] / "result.json"))
        self.assertEqual((parent[0] / "command-0000.json").read_bytes(),
                         (child[0] / "command-0000.json").read_bytes())

    def test_resume_timeout_retains_inherited_passes_after_the_interrupted_index(self):
        finish = self.root / "finish-early"
        programs = [f'from pathlib import Path; import time; '
                    f'time.sleep(0 if Path({str(finish)!r}).exists() else 30)',
                    f'from pathlib import Path; Path({str(self.root / "once-later")!r}).touch(exist_ok=False)',
                    'print("last")']
        parent = self.job("later-parent", programs, partition=[1, 2])
        self.assertEqual(self.run_job(parent), 0)
        child = self.job("early-timeout", programs, seconds=1,
                         resume={"job": str(parent[0]), "receipt": parent[1]})
        self.assertEqual(self.run_job(child), 1)
        terminal = records.read(child[0] / "result.json")
        self.assertEqual(terminal["state"], "timed_out")
        self.assertEqual([(r["index"], r["state"]) for r in terminal["results"]],
                         [(0, "timed_out"), (1, "passed")])
        with probes():
            _, retained = checkpoints.completed(*child)
        self.assertEqual(set(retained), {1})
        finish.touch()
        grandchild = self.job("complete-chain", programs,
                              resume={"job": str(child[0]), "receipt": child[1]})
        self.assertEqual(self.run_job(grandchild), 0)
        with probes():
            self.assertEqual(jobs.collect(*grandchild, grandchild[0] / "source")["commands"], 3)
        self.assertEqual(terminal, records.read(child[0] / "result.json"))
        self.assertEqual((parent[0] / "command-0001.json").read_bytes(),
                         (grandchild[0] / "command-0001.json").read_bytes())

    def test_missing_partition_is_not_complete_and_duplicates_do_not_fill_it(self):
        programs = ['print("zero")', 'print("one")']
        job = self.job("part", programs, partition=[0, 2])
        self.assertEqual(self.run_job(job), 0)
        with probes():
            manifest, found = checkpoints.completed(*job)
            self.assertEqual(set(found), {0})
            repeated = {**manifest, "resume": [{"job": str(job[0]), "receipt": job[1]}] * 2}
            with self.assertRaisesRegex(ValueError, "duplicate"):
                checkpoints.inherited(repeated)
        with probes(), self.assertRaises(ValueError):
            jobs.collect(*job, job[0] / "source")

    def test_partition_bounds_and_exact_union(self):
        manifest = {"commands": list(range(37))}
        for count in range(1, 9):
            all_indices = [index for part in range(count)
                           for index in checkpoints.indices({**manifest, "partition": [part, count]})]
            self.assertEqual(sorted(all_indices), list(range(37)))
        for part in ([1, 1], [-1, 2], [False, 2], [0, 9], "0/2", [0], [0, 0]):
            with self.assertRaises(ValueError):
                checkpoints.indices({**manifest, "partition": part})

    def test_duplicate_results_and_unsealed_pass_fail_closed(self):
        job = self.job("complete", ['print("ok")'])
        self.assertEqual(self.run_job(job), 0)
        original = records.read(job[0] / "result.json")
        for mutant in ("duplicate", "seal"):
            terminal = copy.deepcopy(original)
            if mutant == "duplicate":
                terminal["results"] *= 2
            else:
                terminal["results"][0]["checks"] = None
                records.atomic(job[0] / "command-0000.json", terminal["results"][0])
            records.atomic(job[0] / "result.json", terminal)
            records.atomic(job[0] / "state.json", {"state": "passed", "manifest": job[1],
                                                    "result_sha256": records.digest(terminal)})
            with probes(), self.assertRaises(ValueError):
                checkpoints.completed(*job)

    def test_changed_inputs_cannot_import_checkpoints(self):
        parent, programs = self.interrupted()
        resumed = self.job("resume", programs, resume={"job": str(parent[0]), "receipt": parent[1]})
        original = records.read(resumed[0] / "manifest.json")
        for field in ("sources", "tools", "commands", "plan", "phases", "approval", "miri_profile"):
            changed = copy.deepcopy(original)
            changed[field] = ["drift"]
            with probes(), self.assertRaisesRegex(ValueError, "inputs differ"):
                checkpoints.inherited(changed)

    def test_public_manifest_rejects_routine_profile(self):
        job, _ = self.job("downgrade", ['print("ok")'])
        manifest = records.read(job / "manifest.json")
        manifest["plan"]["stage"] = "public"
        records.atomic(job / "manifest.json", manifest)
        with self.assertRaisesRegex(ValueError, "profile"):
            jobs.load(job, records.digest(manifest))

    def test_legacy_and_nonzero_failures_are_not_auto_resumable(self):
        for name, schema, code in (("legacy", 1, 'print("ok")'), ("failed", 2, 'raise SystemExit(9)')):
            job = self.job(name, [code], schema=schema)
            self.run_job(job)
            with probes(), self.assertRaises(ValueError):
                checkpoints.completed(*job)

    def test_missing_or_changed_logs_reject_reuse(self):
        job = self.job("complete", ['print("ok")'])
        self.assertEqual(self.run_job(job), 0)
        (job[0] / "command-0000.log").write_text("replaced")
        with probes(), self.assertRaisesRegex(ValueError, "integrity"):
            checkpoints.completed(*job)
        (job[0] / "command-0000.log").unlink()
        with probes(), self.assertRaises(OSError):
            checkpoints.completed(*job)

    def test_cache_cleanup_and_job_transfer_preserve_receipt(self):
        job = self.job("transfer-source", ['print("ok")'])
        self.assertEqual(self.run_job(job), 0)
        cache = job[0] / "source/target"
        cache.mkdir()
        (cache / "disposable-build-output").write_text("not evidence")
        shutil.rmtree(cache)
        destination = self.root / "transfer-copy"
        shutil.copytree(job[0], destination)
        with probes():
            self.assertEqual(jobs.collect(destination, job[1], destination / "source")["commands"], 1)
        self.assertEqual(records.read(job[0] / "manifest.json"),
                         records.read(destination / "manifest.json"))

    def test_transferred_partitions_merge_with_real_source_integrity(self):
        # Only catalog planning/tool discovery use fixture values. Git source
        # snapshots, before/after seals, child commands and collection are real.
        programs = [f'from pathlib import Path; Path({str(self.root / str(i))!r}).touch(exist_ok=False)'
                    for i in range(4)]
        parents = [self.job(f"origin-{i}", programs, partition=[i, 2]) for i in range(2)]
        source = parents[0][0] / "source"
        (source / "input").write_text("reviewed source\n")
        (source / ".gitignore").write_text("/target/\n")
        def git(*args):
            subprocess.run(["git", *args], cwd=source, check=True, capture_output=True)
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "commit", "--no-gpg-sign", "-qm", "source fixture")
        shutil.copytree(source, parents[1][0] / "source", dirs_exist_ok=True)
        closure = records.sources(source)
        template = records.read(parents[0][0] / "manifest.json")
        plan = {**template["plan"], "base": "fixture", "head": closure["head"]}
        def bind(job):
            manifest = records.read(job[0] / "manifest.json")
            manifest.update(sources=closure, plan=plan)
            records.atomic(job[0] / "manifest.json", manifest)
            return job[0], records.digest(manifest)
        parents = [bind(job) for job in parents]
        with patch.object(plans, "build", return_value=plan), \
                patch.object(catalog, "selected", return_value=template["commands"]), \
                patch.object(records, "tool_identity", return_value={}):
            transferred = []
            for index, job in enumerate(parents):
                self.assertEqual(jobs.worker(*job), 0)
                self.assertEqual(records.read(job[0] / "state.json")["state"], "partial")
                with self.assertRaises(ValueError):
                    jobs.collect(*job, job[0] / "source")
                cache = job[0] / "source/target"
                cache.mkdir()
                (cache / "disposable").write_text("not evidence")
                shutil.rmtree(cache)
                destination = self.root / f"received-{index}"
                shutil.copytree(job[0], destination)
                transferred.append((destination, job[1]))
            os.chdir(self.cwd)
            # Retain originals under a different path: no accidental dependency
            # on a remote worker's old absolute directory can satisfy collection.
            for path, _ in parents:
                path.rename(path.with_name(path.name + "-offline"))
            child = self.job("merged-transfer", programs,
                             resume=[{"job": str(path), "receipt": receipt}
                                     for path, receipt in transferred])
            shutil.copytree(transferred[0][0] / "source", child[0] / "source", dirs_exist_ok=True)
            child = bind(child)
            self.assertEqual(jobs.worker(*child), 0)
            self.assertEqual(jobs.collect(*child, child[0] / "source")["commands"], 4)
            for parent, _ in transferred:
                for record in parent.glob("command-*.json"):
                    self.assertEqual(record.read_bytes(), (child[0] / record.name).read_bytes())
            # A transferred source is still load-bearing after a successful merge.
            (transferred[0][0] / "source/input").write_text("changed after transfer\n")
            with self.assertRaisesRegex(ValueError, "source closure changed"):
                jobs.collect(*child, child[0] / "source")

    def test_post_command_source_drift_never_publishes_pass(self):
        job = self.job("drift", ['print("ok")'])
        def source_check(*_):
            if (job[0] / "command-0000.log").exists():
                raise ValueError("source drift")
        with probes(), patch.object(jobs, "validate_source", side_effect=source_check):
            self.assertEqual(jobs.worker(*job), 1)
        self.assertFalse((job[0] / "command-0000.json").exists())
        with probes(), self.assertRaises(ValueError):
            checkpoints.completed(*job)

    def test_post_command_tool_drift_never_publishes_pass(self):
        job = self.job("tool-drift", ['print("ok")'])
        def tools(*_):
            return {"changed": True} if (job[0] / "command-0000.log").exists() else {}
        with probes(), patch.object(records, "tool_identity", side_effect=tools):
            self.assertEqual(jobs.worker(*job), 1)
        self.assertFalse((job[0] / "command-0000.json").exists())

    def test_parent_log_corruption_invalidates_already_merged_result(self):
        parent = self.job("parent", ['print("ok")'])
        self.assertEqual(self.run_job(parent), 0)
        child = self.job("child", ['print("ok")'],
                         resume={"job": str(parent[0]), "receipt": parent[1]})
        self.assertEqual(self.run_job(child), 0)
        (parent[0] / "command-0000.log").write_text("corrupted")
        with probes(), self.assertRaises(ValueError):
            jobs.collect(*child, child[0] / "source")

    def test_running_worker_and_excessive_ancestry_are_rejected(self):
        job = self.job("running", ['print("ok")'])
        records.atomic(job[0] / "state.json", {"state": "running", "manifest": job[1]})
        with probes(), self.assertRaises(OSError):
            checkpoints.completed(*job)
        with probes(), self.assertRaisesRegex(ValueError, "ancestry"):
            checkpoints.completed(*job, depth=17)
        with probes(), self.assertRaisesRegex(ValueError, "ancestry"):
            checkpoints.completed(*job, budget=[0])

    def test_status_reports_current_task_without_claiming_success(self):
        job = self.job("running", ['print("ok")'])
        records.atomic(job[0] / "state.json", {"state": "running", "manifest": job[1]})
        records.atomic(job[0] / "shard-00.json", {"state": "running", "manifest": job[1],
                                                "completed": 0, "current": 0})
        (job[0] / "command-0000.log").write_text("live output\n")
        status = jobs.status(*job)
        self.assertEqual(status["state"], "running")
        self.assertTrue(status["progress_is_not_success"])
        self.assertEqual(status["progress"][0]["log_bytes"], 12)
        self.assertEqual(status["progress"][0]["command"], 'print("ok")')

    def test_small_progress_is_visible_before_exit(self):
        cancel = self.root / "cancel"
        log = self.root / "progress.log"
        failure = []
        def observe():
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if log.exists() and log.read_bytes() == b"progress\n":
                    cancel.touch()
                    return
                time.sleep(.01)
            failure.append("output was buffered")
            cancel.touch()
        observer = threading.Thread(target=observe)
        observer.start()
        try:
            result = processes.execute([sys.executable, "-c",
                'import time; print("progress", flush=True); time.sleep(30)'], self.root,
                log, cancel, seconds=5, maximum=1024, environment=dict(os.environ))
        finally:
            observer.join()
        self.assertFalse(failure)
        self.assertEqual(result["state"], "cancelled")
