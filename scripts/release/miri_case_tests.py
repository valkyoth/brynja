"""Case coverage, profile downgrade and actual completion-marker regressions."""
from __future__ import annotations

import contextlib
import io
import os
import sys
import unittest
from unittest.mock import patch

import miri_cases
import miri_tasks
import verification_plan as plans
import verification_carry_forward as carry
import detached_catalog as catalog
from miri_task_tests import runner


class MiriCaseTests(unittest.TestCase):
    def test_miri_runner_change_does_not_select_unrelated_verifiers(self):
        with patch.object(plans.scope, 'select_repository', return_value=(False, ())) as shared, \
                patch.object(plans.miri_dependencies, 'select', return_value=(True, plans.scope.GROUPS)), \
                patch.object(plans, 'changed_paths', return_value=['scripts/zeroization/miri_cases.py']), \
                patch.object(plans, 'fingerprint', return_value='a' * 64), \
                patch.object(plans.inputs, 'snapshot', return_value=(None, None)), \
                patch.object(plans.inputs, 'git', return_value=b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'), \
                patch.dict(os.environ, {}, clear=True):
            plan = plans.build(base='v0.24.48')
        self.assertFalse(shared.call_args.kwargs['include_miri_tasks'])
        self.assertEqual(plan['verifiers']['asan'], [])
        self.assertEqual(plan['verifiers']['kani'], [])
        self.assertEqual(plan['verifiers']['miri'], list(plans.scope.GROUPS))
        self.assertTrue(plan['approval_required'])
        self.assertEqual(plan['full_phases'], ['miri'])
        self.assertEqual(catalog.selected(plan, ['asan'], plan['fingerprint']), [])
        kani = catalog.selected(plan, ['kani'], plan['fingerprint'])
        self.assertEqual([entry['argv'] for entry in kani],
                         [['scripts/assurance/check-kani.sh', '--policy-only']])
        self.assertEqual(catalog.selected(plan, ['matrix'], plan['fingerprint']), [])
        miri = catalog.selected(plan, ['miri'], plan['fingerprint'], miri_tasks=True,
                                miri_profile='routine')
        self.assertEqual(len(miri), 380)
        old = {'phase': 'asan', 'command': 'cargo test -p brynja-hash-sha2',
               'argv': ['cargo', 'test', '-p', 'brynja-hash-sha2'], 'stdin': None,
               'environment': {}}
        context = {'plan': plan, 'manifest': {'commands': [old]}, 'public_checkpoint': False}
        self.assertTrue(carry.disposition(old, context).startswith('reuse:'))

    def test_full_phase_scope_rejects_malformed_and_retains_legacy_fallback(self):
        plan = {'stage': 'internal', 'approval_required': True}
        self.assertTrue(plans.requires_full(plan, 'asan'))
        for value in (['unknown'], ['miri', 'miri'], 'miri'):
            with self.assertRaises(ValueError):
                plans.requires_full({**plan, 'full_phases': value}, 'miri')
        self.assertFalse(plans.requires_full({**plan, 'full_phases': ['miri']}, 'asan'))
        self.assertTrue(plans.requires_full({**plan, 'full_phases': ['repository']}, 'command'))

    def test_profile_task_sets_are_unique_and_fit_detached_bound(self):
        for profile, count in (('existing-full', 83), ('routine', 380), ('extended', 3468)):
            commands = miri_tasks.commands(plans.ROOT, list(plans.scope.GROUPS), profile)
            self.assertEqual(len(commands), count)
            self.assertEqual(len({tuple(command) for command in commands}), count)
            self.assertLessEqual(count, 4096)

    def test_routine_staging_covers_every_dimension_without_cartesian_product(self):
        matrix, = miri_cases.matrices('tuplehash')
        cases = matrix['routine']
        self.assertEqual(len(cases), 16)
        self.assertEqual(len(set(cases)), 16)
        for wide in range(2):
            selected = [case for case in cases if case // 448 == wide]
            self.assertEqual({case // 56 % 8 for case in selected}, set(range(8)))
            self.assertEqual({case // 7 % 8 for case in selected}, set(range(8)))
            self.assertEqual({case % 7 for case in selected}, set(range(7)))

    def test_routine_parallel_covers_widths_blocks_and_each_lifecycle_case_zero(self):
        self.assertEqual(len(miri_cases.matrices('parallelhash')), 8)
        for matrix in miri_cases.matrices('parallelhash')[:6]:
            cases = matrix['routine']
            self.assertEqual(len(cases), 8)
            self.assertEqual(len(set(cases)), 8)
            self.assertEqual({case % 8 for case in cases}, set(range(8)))
            self.assertEqual({case // 8 for case in cases}, set(range(matrix['total'] // 8)))
            self.assertIn(0, cases)

    def test_parallel_leaf_sampling_retains_every_length_and_tail_width(self):
        leaf = miri_cases.matrices('parallelhash')[-2]
        cases = leaf['routine']
        self.assertEqual(leaf['total'], 65)
        self.assertEqual(len(set(cases)), 9)
        self.assertIn(0, cases)
        self.assertEqual({(case - 1) // 8 for case in cases if case}, set(range(8)))
        self.assertEqual({(case - 1) % 8 for case in cases if case}, set(range(8)))

    def test_kmac_lifecycle_splitting_retains_every_case_in_both_profiles(self):
        _, fixed, xof = miri_cases.matrices('kmac')
        for matrix, total in ((fixed, 18), (xof, 16)):
            self.assertEqual(matrix['total'], total)
            self.assertEqual(matrix['routine'], list(range(total)))
            self.assertEqual(matrix['features'], [])

    def test_parallel_buffering_covers_all_dimensions_for_both_strengths(self):
        matrix = miri_cases.matrices('parallelhash')[-1]
        self.assertEqual(matrix['total'], 672)
        self.assertEqual(len(set(matrix['routine'])), 16)
        for wide in range(2):
            cases = [case % 336 for case in matrix['routine'] if case // 336 == wide]
            self.assertEqual({case // 48 for case in cases}, set(range(7)))
            self.assertEqual({case // 8 % 6 for case in cases}, set(range(6)))
            self.assertEqual({case % 8 for case in cases}, set(range(8)))

    def test_extended_matrix_union_has_no_omissions_or_duplicates(self):
        count = 0
        for group in ('sha1', 'md5', 'sha3', 'kmac', 'tuplehash', 'parallelhash'):
            tasks = miri_tasks.task_inventory(plans.ROOT, group, 'extended')
            for matrix in miri_cases.matrices(group):
                selected = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
                cases = [int(task['environment']['BRYNJA_MIRI_CASE']) for task in selected]
                self.assertEqual(cases, list(range(matrix['total'])))
                self.assertTrue(all(task['environment']['BRYNJA_MIRI_PROFILE'] == 'extended' for task in selected))
                self.assertTrue(all(task['argv'][-2:] == ['--', '--exact'] for task in selected))
                count += len(cases)
        self.assertEqual(count, 3372)

    def test_sha3_samples_cover_each_identity_rate_and_every_partial_width(self):
        boundary, fixed_bits, xof_bits = miri_cases.matrices('sha3')
        lengths = [0, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137,
                   143, 144, 145, 167, 168, 169, 339]
        for identity, rate in enumerate((144, 136, 104, 72)):
            selected = [lengths[i % 18] for i in boundary['routine'] if i // 18 == identity]
            self.assertEqual(selected, [0, 1, rate - 1, rate, rate + 1, 339])
        self.assertEqual(fixed_bits['routine'], list(range(28)))
        self.assertEqual(xof_bits['routine'], list(range(7)))
        for matrix in (boundary, fixed_bits, xof_bits):
            self.assertEqual(matrix['target'], ['--test', 'hardened'])

    def test_legacy_boundary_samples_retain_padding_block_chunk_and_bit_dimensions(self):
        for group in ('sha1', 'md5'):
            padding, bulk, scoped = miri_cases.matrices(group)
            self.assertTrue({0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128} <= set(padding['routine']))
            self.assertTrue({0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257} <= set(bulk['routine']))
            cases = scoped['routine']
            self.assertEqual({case // 24 for case in cases}, set(range(12)))
            self.assertEqual({case // 8 % 3 for case in cases}, set(range(3)))
            self.assertEqual({case % 8 for case in cases}, set(range(8)))
        framing = miri_cases.matrices('kmac')[0]
        self.assertEqual(framing['routine'], list(range(8)))

    def test_other_commands_and_families_keep_original_arguments(self):
        for group in plans.scope.GROUPS:
            original = miri_tasks.inventory(plans.ROOT, group)
            for profile in ('routine', 'extended'):
                tasks = miri_tasks.task_inventory(plans.ROOT, group, profile)
                for old, task in zip(original, tasks):
                    expected = list(old)
                    matrices = miri_cases.matrices(group)
                    if matrices:
                        if '--' not in expected:
                            expected.append('--')
                        for matrix in matrices:
                            expected += ['--skip', matrix['name']]
                        for name in miri_cases.singles(group):
                            expected += ['--skip', name]
                    self.assertEqual(task, {'argv': expected, 'environment': {}, 'marker': None})

    def test_sha3_moved_lifecycles_have_exact_tasks_and_leave_future_tests_discoverable(self):
        names = miri_cases.singles('sha3')
        self.assertEqual(len(set(names)), 9)
        source = (plans.ROOT / 'crates/brynja-hash-sha3/tests/hardened.rs').read_text()
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'sha3', profile)
            broad = tasks[15]['argv']
            self.assertEqual(broad[:4], ['-p', 'brynja-hash-sha3', '--test', 'hardened'])
            for name in names:
                self.assertIn('#[test]\nfn ' + name + '(', source)
                self.assertEqual(broad.count(name), 1)
                exact = [task for task in tasks if task['argv'] ==
                         ['-p', 'brynja-hash-sha3', '--test', 'hardened', name, '--', '--exact']]
                self.assertEqual(len(exact), 1)
            self.assertNotIn('zero_length_secret_xof_output_is_a_valid_empty_owner', broad)
            self.assertNotIn('future_unregistered_test', broad)

    def test_public_profile_cannot_be_downgraded(self):
        self.assertEqual(miri_cases.profile_for('internal'), 'routine')
        self.assertEqual(miri_cases.profile_for('public'), 'extended')
        for stage, profile in (('public', 'routine'), ('unknown', None), ('internal', 'skip')):
            with self.assertRaises(ValueError):
                miri_cases.profile_for(stage, profile)
        plan = {'stage': 'public', 'approval_required': False, 'groups': ['tuplehash'],
                'verifiers': {'miri': ['tuplehash']}}
        context = {'release_plan': plan, 'manifest': {'schema': 2, 'miri_profile': 'routine'}}
        required = carry.required(context, 'miri')
        self.assertTrue(all(e['argv'][-1] == 'extended' for e in required))
        old = catalog.selected({**plan, 'stage': 'internal'}, ['miri'], None,
                               miri_tasks=True, miri_profile='routine')
        self.assertFalse(any(carry.covered(e, old) for e in required))

    def test_kmac_api_singles_preserve_tests_and_future_discovery(self):
        names = miri_cases.singles('kmac')
        self.assertEqual(len(set(names)), 4)
        source = (plans.ROOT / 'crates/brynja-mac-kmac/tests/api.rs').read_text()
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'kmac', profile)
            broad = tasks[0]['argv']
            self.assertEqual(broad[:3], ['-p', 'brynja-mac-kmac', '--tests'])
            for name in names:
                self.assertIn('#[test]\nfn ' + name + '(', source)
                self.assertEqual(broad.count(name), 1)
                exact = [task for task in tasks if task['argv'] ==
                         ['-p', 'brynja-mac-kmac', '--test', 'api', name, '--', '--exact']]
                self.assertEqual(len(exact), 1)
            self.assertNotIn('secret_output_is_cleared_when_ownership_ends', broad)
            self.assertNotIn('future_unregistered_test', broad)

    def test_inherited_case_selectors_are_rejected(self):
        for key in ('BRYNJA_MIRI_CASE', 'BRYNJA_MIRI_PROFILE', 'BRYNJA_MIRI_OTHER'):
            with patch.dict(os.environ, {key: 'value'}, clear=True):
                with self.assertRaises(ValueError):
                    runner.environment(plans.ROOT)
                self.assertTrue(plans.environment_issues(dict(os.environ), '1.98.1'))

    def test_completion_requires_one_exact_marker_and_one_test(self):
        marker = 'MIRI_CASE_PASS: fixture:7'
        for lines, valid in (([marker], True), ([], False), ([marker, marker], False),
                             (['MIRI_CASE_PASS: fixture:8'], False)):
            code = '; '.join('print(' + repr(line) + ')' for line in
                [*lines, 'test result: ok. 1 passed; 0 failed; 0 ignored;'])
            output = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            with contextlib.redirect_stdout(output):
                if valid:
                    self.assertEqual(runner.stream([sys.executable, '-c', code], plans.ROOT,
                                                   dict(os.environ), marker), (0, 1))
                else:
                    with self.assertRaisesRegex(ValueError, 'coverage'):
                        runner.stream([sys.executable, '-c', code], plans.ROOT, dict(os.environ), marker)

    def test_case_selectors_are_interpreter_inputs_not_cached_compiler_environment(self):
        for index in (0, 9):
            task = {'environment': {'BRYNJA_MIRI_CASE': str(index), 'BRYNJA_MIRI_PROFILE': 'routine'}}
            with patch.dict(os.environ, {}, clear=True):
                env = runner.case_environment(plans.ROOT, task)
            self.assertNotIn('BRYNJA_MIRI_CASE', env)
            self.assertNotIn('BRYNJA_MIRI_PROFILE', env)
            self.assertEqual(env['MIRIFLAGS'], runner.PROGRESS +
                f' -Zmiri-env-set=BRYNJA_MIRI_CASE={index} -Zmiri-env-set=BRYNJA_MIRI_PROFILE=routine')
        for key, value in (('MIRIFLAGS', 'bad'), ('BRYNJA_MIRI_CASE', '0 -Zmiri-disable-validation')):
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
                runner.case_environment(plans.ROOT, {'environment': {key: value}})
