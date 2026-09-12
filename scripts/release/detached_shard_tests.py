"""Shard coverage, independent process directories, cancellation and corruption."""
from __future__ import annotations

import copy
import os
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
import detached_shards as shards


class ShardTests(unittest.TestCase):
    def test_bounds_and_exact_partition(self):
        for count, workers in ((0, 1), (9, 1), (True, 1), (2, 3), (2, 0), (2, False)):
            with self.assertRaises(ValueError):
                shards.bounds(count, workers)
        commands = [{"index": i} for i in range(37)]
        for count in range(1, 9):
            parts = shards.partition(commands, count)
            flattened = sorted((pair for group in parts for pair in group), key=lambda p: p[0])
            self.assertEqual(flattened, list(enumerate(commands)))
            self.assertLessEqual(max(map(len, parts)) - min(map(len, parts)), 1)

    def test_grouped_verifiers_have_identical_semantic_coverage(self):
        groups = ["sha2", "sha3", "parallelhash"]
        plan = {"approval_required": False, "stage": "internal", "groups": groups,
                "verifiers": {p: groups for p in ("miri", "kani", "asan")}}
        for phase in catalog.PHASES:
            serial = catalog.selected(plan, [phase], None)
            parallel = catalog.selected(plan, [phase], None, 3)
            if phase in {"miri", "kani"}:
                self.assertEqual(len(serial), 1)
                self.assertEqual(len(parallel), len(groups))
                self.assertEqual(serial[0]["argv"][-3:], [item["argv"][-1] for item in parallel])
                self.assertTrue(all(item["argv"][:-1] == serial[0]["argv"][:-3] for item in parallel))
            else:
                self.assertEqual(serial, parallel)

    def setup_job(self, root, codes, count=3, workers=2):
        root.mkdir()
        for index in range(count):
            shards.source(root, index, count).mkdir()
        commands = [{"phase": "repository", "command": "fixture " + str(i),
                     "argv": [sys.executable, "-c", code], "environment": {}, "stdin": None}
                    for i, code in enumerate(codes)]
        return {"commands": commands, "shards": count, "workers": workers,
                "seconds": 10, "log_bytes": 6144}

    @unittest.skipUnless(os.name == "posix", "POSIX command groups")
    def test_reverse_completion_has_ordered_results_and_separate_builds(self):
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw) / "job"
            codes = ['import pathlib,time; time.sleep(.2); pathlib.Path("target").mkdir(); print("zero")',
                     'import pathlib; pathlib.Path("target").mkdir(); print("one")',
                     'import pathlib; pathlib.Path("target").mkdir(); print("two")']
            manifest = self.setup_job(job, codes)
            result, state = shards.run(manifest, job, "receipt", time.monotonic(), jobs.stamp, lambda *_: None)
            self.assertEqual(state, "passed")
            self.assertEqual([item["index"] for item in result], [0, 1, 2])
            for index in range(3):
                self.assertTrue((shards.source(job, index, 3) / "target").is_dir())

    @unittest.skipUnless(os.name == "posix", "POSIX command groups")
    def test_failure_cancels_running_and_queued_siblings(self):
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw) / "job"
            manifest = self.setup_job(job, ['import time; time.sleep(.1); raise SystemExit(7)',
                                           'import time; time.sleep(30)', 'print("must not run")'])
            start = time.monotonic()
            result, state = shards.run(manifest, job, "receipt", start, jobs.stamp, lambda *_: None)
            self.assertEqual(state, "failed")
            self.assertLess(time.monotonic() - start, 6)
            self.assertFalse((job / "command-0002.log").exists())
            self.assertTrue((job / "cancel").exists())
            self.assertTrue(any(item["exit_code"] == 7 for item in result))

    def test_concurrency_budget_log_partition_and_nested_receipt_removal(self):
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw) / "job"
            manifest = self.setup_job(job, ["pass"] * 6)
            lock, active, peak, budgets = threading.Lock(), 0, 0, []
            def execute(_argv, _root, log, _cancel, **kwargs):
                nonlocal active, peak
                self.assertNotIn("BRYNJA_DETACHED_JOB", kwargs["environment"])
                self.assertNotIn("BRYNJA_DETACHED_RECEIPT", kwargs["environment"])
                with lock:
                    active += 1
                    peak = max(peak, active)
                    budgets.append(kwargs["maximum"])
                time.sleep(.03)
                log.write_bytes(b"ok")
                with lock:
                    active -= 1
                return {"state": "passed", "exit_code": 0, "elapsed_seconds": .03, "log_bytes": 2}
            with patch.object(shards.process, "execute", side_effect=execute), \
                 patch.dict(os.environ, {"BRYNJA_DETACHED_JOB": "bad", "BRYNJA_DETACHED_RECEIPT": "bad"}):
                results, state = shards.run(manifest, job, "r", time.monotonic(), jobs.stamp, lambda *_: None)
            self.assertEqual((state, len(results), peak, active), ("passed", 6, 2, 0))
            self.assertEqual(sorted(budgets), [2046] * 3 + [2048] * 3)

    def test_shard_source_failure_cannot_produce_success(self):
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw) / "job"
            manifest = self.setup_job(job, ["pass"] * 3)
            def changed(_manifest, _root):
                raise ValueError("changed source")
            with self.assertRaisesRegex(ValueError, "changed source"):
                shards.run(manifest, job, "r", time.monotonic(), jobs.stamp, changed)
            self.assertTrue((job / "cancel").exists())
            self.assertFalse(list(job.glob("command-*.log")))

    def test_shard_configuration_is_receipt_bound(self):
        with tempfile.TemporaryDirectory() as raw:
            job = Path(raw)
            manifest = {"schema": 1, "id": "test", "created": "test", "plan": {}, "approval": None,
                        "phases": [], "commands": [], "sources": {}, "tools": {}, "seconds": 10,
                        "log_bytes": 4096, "shards": 3, "workers": 2}
            receipt = records.digest(manifest)
            records.atomic(job / "manifest.json", manifest)
            self.assertEqual(jobs.load(job, receipt), manifest)
            for key, value in (("shards", 1), ("workers", 1), ("workers", False), ("shards", 9)):
                changed = copy.deepcopy(manifest)
                changed[key] = value
                records.atomic(job / "manifest.json", changed)
                with self.assertRaises(ValueError):
                    jobs.load(job, receipt)
