#!/usr/bin/env python3
"""Collector regressions with mocked child processes; no timing observations."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('finite', Path(__file__).with_name('collect-aes-dit-finite.py'))
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class FiniteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / 'binary'
        self.binary.write_bytes(b'reviewed bytes, not an executable')
        entry = {'binary': str(self.binary), 'probe': str(self.binary),
                 'binary_sha256': worker.digest(self.binary), 'probe_sha256': worker.digest(self.binary)}
        self.plan = {'schema': 1, 'rounds': 4, 'controls': list(worker.CONTROLS),
                     'timeout_seconds': 180, 'system': 'Darwin', 'machine': 'arm64', 'cpu': None,
                     'collector_sha256': worker.digest(worker.__file__),
                     'binaries': {c: dict(entry) for c in worker.COMPILERS}}
        self.manifest = self.root / 'manifest.json'
        self.out = self.root / 'out'

    def run_collector(self, runner):
        self.manifest.write_text(json.dumps(self.plan))
        with patch.object(worker.platform, 'system', return_value=self.plan['system']), \
                patch.object(worker.platform, 'machine', return_value=self.plan['machine']), \
                patch('builtins.print'), \
                patch.object(worker.subprocess, 'run', side_effect=runner) as process:
            worker.collect(self.manifest, worker.digest(self.manifest), self.out)
        return process

    def child(self, command, **kwargs):
        kwargs['stdout'].write(b'AES_DIT_HOST_BUNDLE_PASS\n' if len(command) == 1 else b'raw data\n')
        return subprocess.CompletedProcess(command, 0)

    def test_finite_order_is_exact(self):
        expected = [(r, c, a) for r in range(1, 5) for c in worker.COMPILERS for a in worker.CONTROLS]
        self.assertEqual(worker.launches(), expected)
        self.assertEqual(len(expected), 32)

    def test_complete_collection_preserves_all_launches(self):
        calls = self.run_collector(self.child)
        self.assertEqual(calls.call_count, 34)
        self.assertEqual([c.args[0][-1] for c in calls.call_args_list[2:]],
                         [a for _, _, a in worker.launches()])
        self.assertEqual(len(list(self.out.glob('*.stdout'))), 34)
        self.assertIn('not a timing pass', (self.out / 'complete.json').read_text())
        for call in calls.call_args_list:
            self.assertEqual(call.kwargs['env'], worker.ENV)
            self.assertNotIn('shell', call.kwargs)

    def test_timeout_failure_and_stderr_do_not_trigger_retry_or_selection(self):
        count = 0
        def child(command, **kwargs):
            nonlocal count
            count += 1
            if count == 3:
                kwargs['stdout'].write(b'partial')
                raise subprocess.TimeoutExpired(command, kwargs['timeout'])
            if count == 4:
                kwargs['stderr'].write(b'failure retained')
                return subprocess.CompletedProcess(command, 7)
            return self.child(command, **kwargs)
        self.assertEqual(self.run_collector(child).call_count, 34)
        self.assertEqual((self.out / '01-round1-1.90.0-separate-values.stdout').read_bytes(), b'partial')
        data = json.loads((self.out / '01-round1-1.90.0-separate-values.json').read_text())
        self.assertIn('TimeoutExpired', data['error'])
        self.assertEqual(data['stdout_sha256'], hashlib.sha256(b'partial').hexdigest())

    def test_existing_destination_is_never_reused(self):
        self.out.mkdir()
        with self.assertRaises(FileExistsError):
            self.run_collector(lambda *a, **k: self.fail('must not launch'))

    def test_bad_declaration_hash_precedes_json(self):
        self.manifest.write_text('not json')
        with self.assertRaisesRegex(ValueError, 'declaration hash'):
            worker.collect(self.manifest, '0' * 64, self.out)
        self.assertFalse(self.out.exists())

    def test_bad_worker_hash_rejected(self):
        self.plan['collector_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'collector hash'):
            self.run_collector(lambda *a, **k: self.fail('must not launch'))

    def test_capability_failure_prevents_all_measurements(self):
        for output, status, stderr in ((b'', 2, b''), (b'wrong\n', 0, b''),
                                       (b'AES_DIT_HOST_BUNDLE_PASS\n', 0, b'warning')):
            def bad(command, **kwargs):
                self.assertEqual(len(command), 1)
                kwargs['stdout'].write(output)
                kwargs['stderr'].write(stderr)
                return subprocess.CompletedProcess(command, status)
            self.out = self.root / ('out-' + str(status) + '-' + str(len(output)) + '-' + str(len(stderr)))
            with self.assertRaisesRegex(ValueError, 'capability probe'):
                self.run_collector(bad)
            self.assertFalse((self.out / 'complete.json').exists())

    def test_changed_binary_aborts_after_first_launch(self):
        count = 0
        def changing(command, **kwargs):
            nonlocal count
            count += 1
            result = self.child(command, **kwargs)
            if len(command) > 1:
                self.binary.write_bytes(b'changed')
            return result
        with self.assertRaisesRegex(ValueError, 'artifact hash'):
            self.run_collector(changing)
        self.assertEqual(count, 3)
        self.assertFalse((self.out / 'complete.json').exists())

    def test_wrong_count_order_timeout_cpu_or_architecture_rejected(self):
        for field, value in (('rounds', 5), ('controls', list(reversed(worker.CONTROLS))),
                             ('timeout_seconds', 181), ('cpu', 0), ('machine', 'x86_64')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                worker.validate({**self.plan, field: value})

    def test_missing_or_symlinked_executable_rejected(self):
        self.binary.unlink()
        with self.assertRaises(ValueError):
            worker.validate(self.plan)
        self.binary.symlink_to(self.manifest)
        self.manifest.write_text('anything')
        with self.assertRaises(ValueError):
            worker.validate(self.plan)

    def test_linux_affinity_restored_on_probe_failure(self):
        self.plan.update(system='Linux', machine='aarch64', cpu=0)
        with patch.object(worker.os, 'sched_getaffinity', side_effect=[{0, 1}, {0}]), \
                patch.object(worker.os, 'sched_setaffinity') as affinity:
            with self.assertRaisesRegex(ValueError, 'capability probe'):
                self.run_collector(lambda command, **kwargs: subprocess.CompletedProcess(command, 2))
        self.assertEqual([c.args for c in affinity.call_args_list], [(0, {0}), (0, {0, 1})])


if __name__ == '__main__':
    unittest.main()
