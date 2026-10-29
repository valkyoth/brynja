"""Snapshot-relative Miri coverage, independent of source/tool reuse approval."""
import copy
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import miri_coverage_identity as identity
import verification_units as units
import verification_carry_forward as carry
import detached_recovery as recovery


def entry(number=0, profile='extended', group='kmac'):
    argv = ['python3', identity.miri_tasks.RUNNER, '--group', group, '--task', str(number)]
    if profile != 'existing-full':
        argv += ['--profile', profile]
    return dict(phase='miri', command=shlex.join(argv), argv=argv, environment={}, stdin=None)


def task(name='original'):
    return dict(argv=['-p', 'brynja-mac-kmac', '--lib', name, '--', '--exact'],
                environment={'BRYNJA_MIRI_CASE': '0', 'BRYNJA_MIRI_PROFILE': 'extended'},
                marker='MIRI_CASE_PASS: ' + name + ':0')


class MiriCoverageTests(unittest.TestCase):
    def setUp(self):
        self.old, self.new = Path('/old-snapshot'), Path('/new-snapshot')
        self.catalog = patch.object(identity.miri_tasks, 'task_inventory',
            side_effect=lambda root, group, profile: [task()] if root == self.old
                        else [task('inserted'), task()])
        self.catalog.start()
        self.addCleanup(self.catalog.stop)

    def test_same_ordinal_different_meaning_rejected_before_equality_shortcut(self):
        self.assertFalse(units.covers(entry(), entry(), self.old, self.new))
        self.assertFalse(carry.covered(entry(), [entry()], roots=(self.old, self.new)))

    def test_moved_exact_task_is_covered_but_no_snapshot_context_is_not(self):
        self.assertTrue(units.covers(entry(), entry(1), self.old, self.new))
        self.assertTrue(carry.covered(entry(1), [entry()], roots=(self.old, self.new)))
        self.assertFalse(carry.covered(entry(), [entry()]))

    def test_profile_group_features_width_marker_and_bounded_designation_bind_identity(self):
        self.assertFalse(units.covers(entry(), entry(1, 'routine'), self.old, self.new))
        self.assertFalse(units.covers(entry(), entry(1, group='sha3'), self.old, self.new))
        for field, value in (
            ('argv', [*task()['argv'], '--skip', 'original']),
            ('environment', {**task()['environment'], 'BRYNJA_MIRI_WIDTH': '1'}),
            ('environment', {**task()['environment'], 'BRYNJA_MIRI_CASE': '1'}),
            ('marker', 'MIRI_CASE_PASS: wrong:0'),
            ('coverage', 'bounded-parallelhash-v1'),
        ):
            with self.subTest(field=field, value=value), patch.object(identity.miri_tasks, 'task_inventory',
                    side_effect=lambda root, *_: [task()] if root == self.old else [{**task(), field: value}]):
                self.assertFalse(units.covers(entry(), entry(), self.old, self.new))

    def test_full_suite_is_not_automatic_proof_of_new_exact_subset(self):
        broad = dict(argv=['-p', 'brynja-mac-kmac', '--tests'], environment={}, marker=None)
        with patch.object(identity.miri_tasks, 'task_inventory',
                          side_effect=lambda root, *_: [broad] if root == self.old else [task()]):
            self.assertFalse(units.covers(entry(), entry(), self.old, self.new))

    def test_altered_outer_environment_input_phase_and_command_rejected(self):
        for delta in ({'environment': {'MIRIFLAGS': '-Zmiri-disable-isolation'}},
                      {'stdin': 'replacement'}, {'phase': 'repository'}, {'command': 'other'},
                      {'extra': 'unreviewed'}):
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                units.covers(entry(), {**entry(), **delta}, self.old, self.new)

    def test_invalid_ordinals_and_unknown_catalog_fail_closed(self):
        for number in ('-1', '00', '1', '999999', '٠'):
            with self.subTest(number=number), self.assertRaises(ValueError):
                identity.Resolver(self.old).key(entry(number))
        with patch.object(identity.miri_tasks, 'task_inventory', side_effect=ValueError('unreviewed historical')):
            with self.assertRaisesRegex(ValueError, 'unreviewed historical'):
                units.covers(entry(), entry(), self.old, self.new)

    def test_non_miri_equal_commands_and_whole_group_behavior_unchanged(self):
        shell = dict(phase='miri', argv=['scripts/zeroization/check-zeroization-miri.sh', '--selected', 'kmac'],
                     command='scripts/zeroization/check-zeroization-miri.sh --selected kmac',
                     environment={}, stdin=None)
        self.assertTrue(units.covers(shell, shell, self.old, self.new))
        self.assertFalse(units.covers(shell, entry(), self.old, self.new))
        self.assertFalse(units.covers(entry(), shell, self.old, self.new))

    def test_source_driver_tool_and_checkpoint_checks_still_precede_reuse(self):
        context = dict(plan={'groups': [], 'verifiers': {'miri': []}, 'full_phases': [],
                             'evidence': {'changed_paths': []}},
                       manifest={'commands': [entry()]}, public_checkpoint=False,
                       coverage_roots=(self.old, self.new))
        self.assertTrue(carry.disposition(entry(1), context).startswith('reuse:'))
        self.assertTrue(carry.disposition(entry(), context).startswith('run:'))
        for delta in ({'public_checkpoint': True}, {'tool_drift': {'miri': ['changed']}},
                      {'plan': {**context['plan'], 'verifiers': {'miri': ['kmac']}}},
                      {'plan': {**context['plan'], 'full_phases': ['miri']}},
                      {'plan': {**context['plan'], 'evidence': {'changed_paths': [identity.miri_tasks.RUNNER]}}}):
            with self.subTest(delta=delta):
                self.assertTrue(carry.disposition(entry(1), {**context, **delta}).startswith('run:'))

    def test_recovery_preserves_real_old_index_and_log_for_moved_task_only(self):
        with tempfile.TemporaryDirectory() as directory:
            job = Path(directory) / 'old'
            (job / 'source').mkdir(parents=True)
            self.old = job / 'source'
            receipt = 'a' * 64
            previous = {'command': entry(), 'log_bytes': 10, 'log_sha256': 'b' * 64}
            old = {'tools': {}, 'sources': {'head': 'c' * 40},
                   'plan': {'stage': 'internal', 'verification_mode': 'affected'}}
            manifest = {'schema': 3, 'recovery': [{'job': str(job), 'receipt': receipt}],
                        'tools': {}, 'plan': old['plan'], 'commands': [entry(), entry(1)]}
            class Reader:
                locations = {receipt: job}
                def completed(self, *_args, **_kwargs):
                    return old, {'state': 'cancelled'}, {7: previous}
            with patch.object(recovery.records, 'git', return_value=b''), \
                    patch.object(recovery.plans, 'build', return_value={
                        'groups': [], 'verifiers': {'miri': []}, 'full_phases': []}), \
                    patch.object(recovery.plans, 'changed_paths', return_value=[]):
                result = recovery.expected(manifest, self.new, Reader())
                self.assertEqual(set(result), {1})
                self.assertEqual(result[1]['origin'], {'receipt': receipt, 'index': 7})
                self.assertEqual(result[1]['log_sha256'], previous['log_sha256'])
                changed = copy.deepcopy(manifest)
                changed['tools'] = {'miri': 'different'}
                self.assertEqual(recovery.expected(changed, self.new, Reader()), {})
