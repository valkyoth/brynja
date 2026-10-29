"""Dashboard regression checks; synthetic subprocesses only, no crypto campaign."""
import contextlib
import io
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_dashboard_catalog as catalog
import test_dashboard_store as store
import test_dashboard_run as runner
import verification_plan as plans


def entry(code='print("ok")'):
    return {'phase': 'repository', 'command': 'synthetic test',
            'argv': [sys.executable, '-c', code], 'stdin': None, 'environment': {}}


def task(code='print("ok")'):
    return {'id': 'repository-0123456789abcdef', 'label': 'fixture',
            'families': ['core'], 'bundled': False, 'entry': entry(code)}


def observation(state='passed', ended='2026-10-29T07:00:00Z'):
    return {'id': task()['id'], 'state': state, 'ended': ended,
            'phase': 'repository', 'families': ['core'], 'seconds': 5}


class DashboardTests(unittest.TestCase):
    def test_inventory_is_read_only_and_ids_unique(self):
        with patch('subprocess.Popen', side_effect=AssertionError('listing ran a process')):
            items = catalog.inventory(plans.ROOT, ['miri', 'repository', 'kani', 'asan', 'matrix'], 'routine')
        self.assertEqual(len(items), len({i['id'] for i in items}))
        self.assertTrue(any('legacy_hmac' in i['families'] for i in items))

    def test_miri_identity_follows_meaning_not_task_ordinal(self):
        first = {'argv': ['--lib', 'first', '--', '--exact'], 'environment': {}, 'marker': None}
        second = {**first, 'argv': ['--lib', 'second', '--', '--exact']}
        e = {'phase': 'miri', 'command': '', 'argv': ['python3', catalog.miri_tasks.RUNNER,
             '--group', 'kmac', '--task', '0', '--profile', 'routine']}
        with patch.object(catalog.miri_tasks, 'task_inventory', return_value=[first]):
            before = catalog.describe(e, plans.ROOT)
        with patch.object(catalog.miri_tasks, 'task_inventory', return_value=[second, first]):
            wrong = catalog.describe(e, plans.ROOT)
            moved = catalog.describe({**e, 'argv': [*e['argv'][:5], '1', *e['argv'][6:]]}, plans.ROOT)
        self.assertNotEqual(before['id'], wrong['id'])
        self.assertEqual(before['id'], moved['id'])

    def test_latest_failure_does_not_hide_behind_old_pass(self):
        rows = [observation(), observation('failed', '2026-10-29T08:00:00Z')]
        self.assertEqual(store.latest(rows)[task()['id']]['state'], 'failed')

    def test_partial_never_looks_complete_and_family_filter_is_exact(self):
        items = [task(), {**task(), 'id': 'another', 'families': ['core', 'sha2']}]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            store.render(items, [observation()], family='core')
        self.assertIn('1/2', out.getvalue())
        self.assertIn('partial', out.getvalue())
        self.assertNotIn('sha2', out.getvalue())
        self.assertIn('NOT assessed', out.getvalue())

    def test_control_characters_are_not_rendered(self):
        self.assertNotIn('\x1b', store.text('name\x1b[2J'))

    def test_history_rejects_symlink_and_public_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'link').symlink_to(root)
            with self.assertRaises(ValueError):
                store.prepare(root / 'link')
            os.chmod(root, 0o755)
            with self.assertRaises(ValueError):
                store.prepare(root)

    def test_import_rejects_invalid_receipt_before_saving(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history'
            with patch.object(store.History, 'completed', side_effect=ValueError('corrupt')):
                with self.assertRaises(ValueError):
                    store.import_job(path, Path(directory), 'bad')
            self.assertFalse(path.exists())

    def test_relocated_parents_are_passed_to_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = root / 'locations.json'
            index.write_text(json.dumps({'schema': 1, 'jobs': {'b'*64: str(root / 'parent')}}))
            with patch.object(store, 'History') as reader:
                reader.return_value.completed.side_effect = ValueError('validation still required')
                with self.assertRaises(ValueError):
                    store.import_job(root / 'dashboard', root / 'job', 'a'*64, locations=index)
                reader.assert_called_once_with({'b'*64: root / 'parent', 'a'*64: root / 'job'})
            self.assertFalse((root / 'dashboard').exists())

    def test_relocated_index_rejects_relative_paths_and_wrong_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = root / 'locations.json'
            for data in ({'schema': 1, 'jobs': {'b'*64: '../parent'}},
                         {'schema': True, 'jobs': {}},
                         {'schema': 1, 'jobs': {'bad': str(root)}}):
                index.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    store.import_job(root / 'dashboard', root / 'job', 'a'*64, locations=index)
            self.assertFalse((root / 'dashboard').exists())

    def test_cancelled_import_preserves_only_actual_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            record = {'index': 1, 'command': entry(), 'state': 'cancelled',
                      'ended': '2026-10-29T00:00:00Z', 'elapsed_seconds': 5,
                      'log': 'command-0001.log', 'log_sha256': 'a'*64}
            manifest = {'plan': {'head': 'b'*40}, 'sources': {}}
            terminal = {'state': 'cancelled', 'results': [record]}
            with patch.object(store.History, 'completed', return_value=(manifest, terminal, {})), \
                    patch.object(store, 'describe', return_value=task()):
                summary = store.import_job(Path(directory), Path(directory), 'a'*64)
            self.assertEqual(summary['passes'], 0)
            self.assertFalse(summary['release_authorized'])
            self.assertEqual(store.read(Path(directory))[0]['state'], 'cancelled')

    def execute_fixture(self, directory, code, seconds=2, sources=None):
        root = Path(directory)
        (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.99.1"\n')
        with patch.object(runner.plans, 'build', return_value={'head': 'a'*40}), \
                patch.object(runner.plans, 'environment_issues', return_value=[]), \
                patch.object(runner.records, 'sources', side_effect=sources or [{}, {}]), \
                patch.object(runner.records, 'tool_identity', return_value={'fixture': '1'}):
            return runner.run(root, root / 'history', task(code), seconds=seconds)

    def test_one_real_process_records_success_log_and_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.execute_fixture(directory, 'print("fixture success")')
            self.assertEqual(row['state'], 'passed')
            self.assertIn('fixture success', Path(row['log']).read_text())
            self.assertTrue(row['ended'])
            self.assertEqual(store.read(Path(directory) / 'history')[0]['state'], 'passed')

    def test_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.execute_fixture(directory, 'raise SystemExit(3)')
            self.assertEqual(row['state'], 'failed')
            self.assertEqual(row['exit_code'], 3)

    def test_timeout_is_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.execute_fixture(directory, 'import time; time.sleep(30)', seconds=1)
            self.assertEqual(row['state'], 'timed_out')

    def test_sigint_cancels_and_saves_without_losing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            timer = threading.Timer(.3, lambda: os.kill(os.getpid(), signal.SIGINT))
            timer.start()
            try:
                row = self.execute_fixture(directory, 'import time; time.sleep(30)', seconds=3)
            finally:
                timer.cancel()
                timer.join()
            self.assertEqual(row['state'], 'cancelled')
            self.assertEqual(store.read(Path(directory) / 'history')[0]['state'], 'cancelled')

    def test_log_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = runner.detached_process.execute(
                [sys.executable, '-c', 'print("x" * 10000)'], root,
                root / 'log', root / 'cancel', seconds=3, maximum=100,
                environment=dict(os.environ))
            self.assertEqual(result['state'], 'log_limit')
            self.assertEqual((root / 'log').stat().st_size, 100)

    def test_concurrent_edit_invalidates_success(self):
        with tempfile.TemporaryDirectory() as directory:
            row = self.execute_fixture(directory, 'print("ok")', sources=[{}, {'changed': True}])
            self.assertEqual(row['state'], 'invalidated')

    def test_existing_lock_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            history = store.prepare(Path(directory) / 'history')
            (history / 'runner.lock').write_text('someone else\n')
            with self.assertRaises(FileExistsError):
                self.execute_fixture(directory, 'print("must not run")')
            self.assertEqual((history / 'runner.lock').read_text(), 'someone else\n')


if __name__ == '__main__':
    unittest.main()
