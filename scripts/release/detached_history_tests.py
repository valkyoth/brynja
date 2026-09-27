"""Historical evidence corruption and relocation tests using real child jobs."""
import contextlib
import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_history as history
import detached_job as jobs
import detached_manifest as records
import detached_checkpoint_tests as fixtures


TOOLS = {key: 'recorded identity' for key in
         ('python', 'platform', 'rustc', 'cargo', 'rustup', 'python3')}
TOOLS.update(installed='test-compiler', **{'compiler:test-compiler': 'frozen compiler'})


@unittest.skipUnless(sys.platform in {'linux', 'darwin'}, 'POSIX detached runner')
class HistoryTests(unittest.TestCase):
    setUp = fixtures.CheckpointTests.setUp
    tearDown = fixtures.CheckpointTests.tearDown

    def job(self, name, *, partition=None, resume=None):
        job, _ = fixtures.CheckpointTests.job(self, name, ['print("one")', 'print("two")'],
                                      partition=partition, resume=resume)
        manifest = records.read(job / 'manifest.json')
        manifest['tools'] = TOOLS
        records.atomic(job / 'manifest.json', manifest)
        receipt = records.digest(manifest)
        with patch.object(jobs, 'validate_source'), patch.object(records, 'tool_identity', return_value=TOOLS):
            self.assertEqual(jobs.worker(job, receipt), 0)
        os.chdir(self.cwd)
        return job, receipt

    @contextlib.contextmanager
    def offline(self):
        # Only source fixtures are synthetic. Real child exit records, logs and
        # post-execution tool seals are exercised without a production bypass.
        with patch.object(jobs, 'validate_source') as source, \
             patch.object(records, 'git', return_value=b''), \
             patch.object(records, 'verifier_commands', return_value={}), \
             patch.object(records, 'tool_identity', side_effect=AssertionError('must not probe collector tools')):
            yield source

    def read(self, job):
        with self.offline():
            return history.History({job[1]: job[0]}).collect(job[1])

    def terminal(self, job, change):
        path, receipt = job
        terminal = records.read(path / 'result.json')
        change(terminal)
        records.atomic(path / 'result.json', terminal)
        records.atomic(path / 'state.json', {'state': terminal['state'], 'manifest': receipt,
                                            'result_sha256': records.digest(terminal)})

    def test_completed_history_uses_original_tools_and_checks_frozen_sources(self):
        job = self.job('passed')
        before = records.read(job[0] / 'result.json')
        with self.offline() as source:
            result = history.History({job[1]: job[0]}).collect(job[1])
            source.assert_called_once_with(records.read(job[0] / 'manifest.json'), job[0] / 'source')
        self.assertEqual(result['commands'], 2)
        self.assertFalse(result['release_authorized'])
        self.assertEqual(before, records.read(job[0] / 'result.json'))

    def test_relocated_parents_match_receipts_not_original_absolute_paths(self):
        parents = [self.job(f'parent-{i}', partition=[i, 2]) for i in range(2)]
        combined = self.job('combined', resume=[{'job': str(p), 'receipt': r} for p, r in parents])
        locations = {combined[1]: combined[0]}
        for path, receipt in parents:
            relocated = path.with_name(path.name + '-moved')
            path.rename(relocated)
            locations[receipt] = relocated
        with self.offline():
            self.assertEqual(history.History(locations).collect(combined[1])['commands'], 2)
            with self.assertRaisesRegex(ValueError, 'missing'):
                history.History({combined[1]: combined[0]}).collect(combined[1])
            (locations[parents[0][1]] / 'command-0000.log').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                history.History(locations).collect(combined[1])

    def test_log_record_seal_and_source_drift_each_reject(self):
        for index, kind in enumerate(('log', 'record', 'seal', 'source', 'dirty')):
            with self.subTest(kind=kind):
                job = self.job('drift-' + str(index))
                if kind == 'log':
                    (job[0] / 'command-0000.log').write_bytes(b'drift')
                elif kind in ('record', 'seal'):
                    value = records.read(job[0] / 'command-0000.json')
                    value['checks']['tools'] = '0' * 64
                    records.atomic(job[0] / 'command-0000.json', value)
                    if kind == 'seal':
                        self.terminal(job, lambda t: t['results'].__setitem__(0, value))
                with self.offline(), contextlib.ExitStack() as stack:
                    if kind == 'source':
                        stack.enter_context(patch.object(jobs, 'validate_source', side_effect=ValueError('source drift')))
                    if kind == 'dirty':
                        stack.enter_context(patch.object(records, 'git', return_value=b'M file'))
                    with self.assertRaises(ValueError):
                        history.History({job[1]: job[0]}).collect(job[1])

    def test_incomplete_failed_cancelled_missing_reordered_and_nan_reject(self):
        changes = [lambda t: t.update(state='partial'), lambda t: t.update(state='failed'),
                   lambda t: t.update(state='cancelled'), lambda t: t['results'].pop(),
                   lambda t: t['results'].reverse(), lambda t: t.update(elapsed_seconds=9999),
                   lambda t: t.update(failure_class='ValueError')]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                job = self.job('terminal-' + str(index))
                self.terminal(job, change)
                with self.assertRaises(ValueError):
                    self.read(job)
        job = self.job('cancel-marker')
        (job[0] / 'cancel').touch()
        with self.assertRaises(ValueError):
            self.read(job)
        terminal = records.read(job[0] / 'result.json')
        terminal['elapsed_seconds'] = float('nan')
        with self.assertRaises(ValueError):
            records.atomic(job[0] / 'result.json', terminal)

    def test_legacy_and_unsealed_records_reject(self):
        job = self.job('legacy')
        manifest = records.read(job[0] / 'manifest.json')
        manifest['schema'] = 1
        for key in ('resume', 'partition', 'miri_profile'):
            del manifest[key]
        records.atomic(job[0] / 'manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'schema-2'):
            self.read((job[0], records.digest(manifest)))
        job = self.job('unsealed')
        record = records.read(job[0] / 'command-0000.json')
        del record['checks']
        records.atomic(job[0] / 'command-0000.json', record)
        self.terminal(job, lambda t: t['results'].__setitem__(0, record))
        with self.assertRaises(ValueError):
            self.read(job)

    def test_tool_inventory_requires_every_recorded_compiler_and_selected_verifier(self):
        manifest = {'tools': TOOLS, 'commands': []}
        with patch.object(records, 'verifier_commands', return_value={}):
            history.tool_record(manifest, self.root)
            for key in TOOLS:
                value = copy.deepcopy(manifest)
                del value['tools'][key]
                with self.subTest(key=key), self.assertRaises(ValueError):
                    history.tool_record(value, self.root)
        with patch.object(records, 'verifier_commands', return_value={'verifier:miri': []}):
            with self.assertRaisesRegex(ValueError, 'verifier'):
                history.tool_record(manifest, self.root)

    def test_ancestry_bounds_and_parent_input_mismatch(self):
        job = self.job('parent')
        with self.offline():
            reader = history.History({job[1]: job[0]})
            with self.assertRaises(ValueError):
                reader.completed(job[1], depth=17)
            reader.active.add(job[1])
            with self.assertRaisesRegex(ValueError, 'cycles'):
                reader.completed(job[1])
            reader.active.clear()
            reader.visits = 128
            with self.assertRaises(ValueError):
                reader.completed(job[1])
            manifest = records.read(job[0] / 'manifest.json')
            manifest['resume'] = [{'job': str(job[0]), 'receipt': job[1]}]
            manifest['tools'] = {**TOOLS, 'rustc': 'different'}
            with self.assertRaisesRegex(ValueError, 'inputs differ'):
                history.History({job[1]: job[0]}).parents(manifest, 1)
            manifest['resume'] *= 2
            manifest['tools'] = TOOLS
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                history.History({job[1]: job[0]}).parents(manifest, 1)
