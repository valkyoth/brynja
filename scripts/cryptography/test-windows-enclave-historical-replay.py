#!/usr/bin/env python3
"""Historical replay cannot rewrite or silently repin observations."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import windows_enclave_historical_replay as replay


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'record.json'
        self.old = dict(compared_source_root='/tmp/old-random', current_checkout_compared=False,
                        route='kmac', source_sha256={'worker.rs': 'reviewed'}, production_qualified=False)
        self.path.write_text(json.dumps(self.old))
        self.raw = self.path.read_bytes()
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def execute(self, *, code=0, stderr='', **changes):
        data = dict(self.old, compared_source_root='/tmp/new-random')
        data.update(changes)
        result = subprocess.CompletedProcess(['verify'], code, json.dumps(data), stderr)
        with patch.object(replay.subprocess, 'run', return_value=result):
            return replay.replay(Path('verify'), Path('/tmp/new-random'), self.path, self.digest)

    def test_repeat_is_deterministic_and_read_only(self):
        first = self.execute()
        second = self.execute()
        self.assertEqual(first, second)
        self.assertEqual(first['compared_source_root'], '<historical-85903ae0>')
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_semantic_and_provenance_drift_reject_without_writing(self):
        for delta in (dict(route='sha2'), dict(source_sha256={}),
                      dict(production_qualified=True), dict(current_checkout_compared=True),
                      dict(compared_source_root='/tmp/wrong'), dict(stderr='warning')):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                self.execute(**delta)
            self.assertEqual(self.path.read_bytes(), self.raw)

    def test_failure_and_timeout_preserve_record(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute(code=1)
        with patch.object(replay.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['verify'], 300)):
            with self.assertRaises(subprocess.TimeoutExpired):
                replay.replay(Path('verify'), Path('/tmp/new'), self.path, self.digest)
        self.assertEqual(self.path.read_bytes(), self.raw)

    def test_record_tamper_rejects_before_execution(self):
        self.path.write_bytes(self.raw + b' ')
        with patch.object(replay.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                replay.replay(Path('verify'), Path('/tmp/new'), self.path, self.digest)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
