"""Failed-parent recovery tests execute real children; never waive failures."""
from contextlib import contextmanager
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from detached_checkpoint_tests import CheckpointTests, probes
import detached_checkpoints as checkpoints
import detached_history as history
import detached_job as jobs
import detached_manifest as records
import detached_recovery as recovery
import verification_carry_forward as carry
import verification_plan as plans

POLICY = carry.disposition


@contextmanager
def environment():
    delta = {'groups': [], 'verifiers': {}, 'stage': 'internal', 'full_phases': []}
    with probes(), patch.object(history, 'tool_record'), patch.object(records, 'git', return_value=b''), \
            patch.object(plans, 'build', return_value=delta), patch.object(plans, 'changed_paths', return_value=[]), \
            patch.object(carry, 'disposition', return_value='reuse: unchanged'):
        yield


class RecoveryTests(unittest.TestCase):
    setUp = CheckpointTests.setUp
    tearDown = CheckpointTests.tearDown
    def job(self, *args, **kwargs):
        path, _ = CheckpointTests.job(self, *args, **kwargs)
        manifest = records.read(path / 'manifest.json')
        manifest['sources'] = {'head': 'old'}
        records.atomic(path / 'manifest.json', manifest)
        return path, records.digest(manifest)

    def parent(self):
        marker, repaired = self.root / 'once', self.root / 'repaired'
        programs = [f'from pathlib import Path; Path({str(marker)!r}).touch(exist_ok=False)',
                    f'from pathlib import Path; import sys; sys.exit(0 if Path({str(repaired)!r}).exists() else 1)',
                    'print("unfinished")']
        parent = self.job('parent', programs)
        with environment():
            self.assertEqual(jobs.worker(*parent), 1)
        return parent, programs, repaired

    def child(self, parent, programs, name='child'):
        child, _ = self.job(name, programs, schema=2)
        manifest = records.read(child / 'manifest.json')
        manifest.update(schema=3, recovery=[{'job': str(parent[0]), 'receipt': parent[1]}])
        manifest['sources'] = {'head': 'new'}
        records.atomic(child / 'manifest.json', manifest)
        return child, records.digest(manifest)

    def test_failure_reruns_only_missing_and_failed_preserving_parent(self):
        parent, programs, repaired = self.parent()
        before = {p.name: p.read_bytes() for p in parent[0].glob('*.json')}
        repaired.touch()
        child = self.child(parent, programs)
        with environment():
            self.assertEqual(jobs.worker(*child), 0)
            result = jobs.collect(*child, child[0] / 'source')
        self.assertEqual(result['commands'], 3)
        rows = records.read(child[0] / 'result.json')['results']
        self.assertEqual([r['state'] for r in rows], ['reused', 'passed', 'passed'])
        self.assertEqual(rows[0]['origin'], {'receipt': parent[1], 'index': 0})
        self.assertEqual(before, {p.name: p.read_bytes() for p in parent[0].glob('*.json')})

    def test_ordinary_resume_and_collection_still_reject_failure(self):
        parent, _, _ = self.parent()
        with environment():
            with self.assertRaises(ValueError):
                checkpoints.completed(*parent)
            with self.assertRaises(ValueError):
                jobs.collect(*parent, parent[0] / 'source')
            reader = history.History({parent[1]: parent[0]})
            reader.completed(parent[1], allow_failed=True)
            with self.assertRaises(ValueError):
                reader.collect(parent[1])

    def test_corrupted_pass_failed_log_and_terminal_rejected(self):
        for which in ('command-0000.log', 'command-0001.log', 'result.json'):
            with self.subTest(which=which):
                parent, _, _ = self.parent()
                path = parent[0] / which
                path.write_bytes(path.read_bytes() + b'corrupt')
                with environment(), self.assertRaises((ValueError, KeyError)):
                    history.History({parent[1]: parent[0]}).completed(parent[1], allow_failed=True)
                import shutil
                shutil.rmtree(parent[0])
                (self.root / 'once').unlink()

    def test_changed_tools_inputs_and_missing_command_never_reused(self):
        parent, programs, _ = self.parent()
        child = self.child(parent, programs)
        manifest = records.read(child[0] / 'manifest.json')
        with environment():
            self.assertEqual(set(recovery.expected(manifest, child[0] / 'source')), {0})
            changed = {**manifest, 'tools': {'changed': 'compiler'}}
            self.assertEqual(recovery.expected(changed, child[0] / 'source'), {})
            with patch.object(carry, 'disposition', return_value='run: changed implementation'):
                self.assertEqual(recovery.expected(manifest, child[0] / 'source'), {})
            changed = copy.deepcopy(manifest)
            changed['commands'][0]['argv'] += ['different']
            self.assertEqual(recovery.expected(changed, child[0] / 'source'), {})

    def test_reused_log_or_provenance_cannot_be_changed(self):
        parent, programs, repaired = self.parent()
        repaired.touch()
        child = self.child(parent, programs)
        with environment():
            self.assertEqual(jobs.worker(*child), 0)
            (child[0] / 'command-0000.log').write_text('fabricated pass')
            with self.assertRaises(ValueError):
                jobs.collect(*child, child[0] / 'source')

    def test_existing_policy_preserves_baseline_public_and_changed_input_checks(self):
        parent, programs, _ = self.parent()
        child = self.child(parent, programs)
        manifest = records.read(child[0] / 'manifest.json')
        with environment(), patch.object(carry, 'disposition', POLICY), \
                patch.object(carry.commands, 'owners', return_value={'legacy_hmac'}):
            self.assertEqual(set(recovery.expected(manifest, child[0] / 'source')), {0})
            with patch.object(carry.commands, 'owners', return_value=set()):
                self.assertEqual(recovery.expected(manifest, child[0] / 'source'), {})
            public = {**manifest, 'plan': {'stage': 'public', 'version': '1.0'}}
            self.assertEqual(recovery.expected(public, child[0] / 'source'), {})
            with patch.object(plans, 'build', return_value={'groups': ['legacy_hmac'], 'verifiers': {},
                                                          'stage': 'internal', 'full_phases': []}):
                self.assertEqual(recovery.expected(manifest, child[0] / 'source'), {})
            with patch.object(plans, 'changed_paths', return_value=[manifest['commands'][0]['argv'][0]]):
                self.assertEqual(recovery.expected(manifest, child[0] / 'source'), {})

    def test_partition_recovery_merges_without_repeating_passes(self):
        parent, programs, repaired = self.parent()
        repaired.touch()
        programs.append('print("fourth task")')
        children = []
        with environment():
            for part in range(2):
                path, _ = self.child(parent, programs, name=f'part-{part}')
                manifest = records.read(path / 'manifest.json')
                manifest['partition'] = [part, 2]
                records.atomic(path / 'manifest.json', manifest)
                receipt = records.digest(manifest)
                children.append({'job': str(path), 'receipt': receipt})
                self.assertEqual(jobs.worker(path, receipt), 0)
                self.assertEqual(records.read(path / 'state.json')['state'], 'partial')
                reader = history.History(recovery.locations(children))
                _, _, found = reader.completed(receipt)
                self.assertEqual(set(found), {0} | set(range(part, 4, 2)))
            merged, _ = self.job('merged', programs)
            manifest.update(id='merged', partition=None, resume=children)
            records.atomic(merged / 'manifest.json', manifest)
            receipt = records.digest(manifest)
            self.assertEqual(jobs.worker(merged, receipt), 0)
            self.assertEqual(jobs.collect(merged, receipt, merged / 'source')['commands'], 4)

    def test_second_failure_stays_failed_and_recovery_ancestry_survives(self):
        parent, programs, repaired = self.parent()
        child = self.child(parent, programs)
        with environment():
            self.assertEqual(jobs.worker(*child), 1)
            self.assertEqual(records.read(child[0] / 'state.json')['state'], 'failed')
            with self.assertRaises(ValueError):
                jobs.collect(*child, child[0] / 'source')
            repaired.touch()
            grandchild = self.child(child, programs, name='grandchild')
            self.assertEqual(jobs.worker(*grandchild), 0)
            self.assertEqual(jobs.collect(*grandchild, grandchild[0] / 'source')['reused_commands'], 1)
            locations = recovery.locations([{'job': str(grandchild[0]), 'receipt': grandchild[1]}])
            self.assertEqual(len(locations), 3)
            self.assertEqual(history.History(locations).collect(grandchild[1])['commands'], 3)
            with self.assertRaises(ValueError):
                history.History({grandchild[1]: grandchild[0]}).collect(grandchild[1])

    def test_source_failure_and_unsealed_pass_rejected(self):
        parent, _, _ = self.parent()
        with environment(), patch.object(jobs, 'validate_source', side_effect=ValueError('source drift')):
            with self.assertRaisesRegex(ValueError, 'source drift'):
                history.History({parent[1]: parent[0]}).completed(parent[1], allow_failed=True)
        record = records.read(parent[0] / 'command-0000.json')
        record['checks'] = None
        records.atomic(parent[0] / 'command-0000.json', record)
        terminal = records.read(parent[0] / 'result.json')
        terminal['results'][0] = record
        records.atomic(parent[0] / 'result.json', terminal)
        records.atomic(parent[0] / 'state.json', {'state': 'failed', 'manifest': parent[1],
                                                'result_sha256': records.digest(terminal)})
        with environment(), self.assertRaises(ValueError):
            history.History({parent[1]: parent[0]}).completed(parent[1], allow_failed=True)

    def test_infrastructure_failure_is_not_recoverable(self):
        parent, _, _ = self.parent()
        terminal = records.read(parent[0] / 'result.json')
        terminal['failure_class'] = 'ValueError'
        records.atomic(parent[0] / 'result.json', terminal)
        records.atomic(parent[0] / 'state.json', {'state': 'failed', 'manifest': parent[1],
                                                'result_sha256': records.digest(terminal)})
        with environment(), self.assertRaises(ValueError):
            history.History({parent[1]: parent[0]}).completed(parent[1], allow_failed=True)

    def test_missing_new_command_and_changed_origin_rejected(self):
        parent, programs, repaired = self.parent()
        repaired.touch()
        child = self.child(parent, programs)
        with environment():
            self.assertEqual(jobs.worker(*child), 0)
            terminal = records.read(child[0] / 'result.json')
            original = copy.deepcopy(terminal)
            terminal['results'].pop()
            records.atomic(child[0] / 'result.json', terminal)
            records.atomic(child[0] / 'state.json', {'state': 'passed', 'manifest': child[1],
                                                   'result_sha256': records.digest(terminal)})
            with self.assertRaises(ValueError):
                jobs.collect(*child, child[0] / 'source')
            original['results'][0]['origin']['index'] = 1  # Failed command, not the old pass.
            records.atomic(child[0] / 'command-0000.json', original['results'][0])
            records.atomic(child[0] / 'result.json', original)
            records.atomic(child[0] / 'state.json', {'state': 'passed', 'manifest': child[1],
                                                   'result_sha256': records.digest(original)})
            with self.assertRaises(ValueError):
                jobs.collect(*child, child[0] / 'source')

    def test_interrupted_recovery_resumes_without_losing_original_pass(self):
        parent, programs, repaired = self.parent()
        repaired.touch()
        finish = self.root / 'finish'
        programs[2] = f'from pathlib import Path; import time; time.sleep(0 if Path({str(finish)!r}).exists() else 30)'
        child = self.child(parent, programs)
        manifest = records.read(child[0] / 'manifest.json')
        manifest['seconds'] = 1
        records.atomic(child[0] / 'manifest.json', manifest)
        child = child[0], records.digest(manifest)
        with environment():
            self.assertEqual(jobs.worker(*child), 1)
            self.assertEqual(records.read(child[0] / 'state.json')['state'], 'timed_out')
            resumed, _ = self.job('resumed', programs)
            manifest.update(id='resumed', seconds=10, resume=[{'job': str(child[0]), 'receipt': child[1]}])
            records.atomic(resumed / 'manifest.json', manifest)
            receipt = records.digest(manifest)
            finish.touch()
            self.assertEqual(jobs.worker(resumed, receipt), 0)
            result = jobs.collect(resumed, receipt, resumed / 'source')
            self.assertEqual(result['commands'], 3)
            self.assertEqual(result['reused_commands'], 1)
