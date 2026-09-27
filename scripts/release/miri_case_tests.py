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
        self.assertEqual(len(miri), 542)
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
        for profile, count in (('existing-full', 83), ('routine', 542), ('extended', 3838)):
            commands = miri_tasks.commands(plans.ROOT, list(plans.scope.GROUPS), profile)
            self.assertEqual(len(commands), count)
            self.assertEqual(len({tuple(command) for command in commands}), count)
            self.assertLessEqual(count, 4096)

    def test_routine_staging_covers_every_dimension_without_cartesian_product(self):
        matrix = miri_cases.matrices('tuplehash')[0]
        cases = matrix['routine']
        self.assertEqual(len(cases), 16)
        self.assertEqual(len(set(cases)), 16)
        for wide in range(2):
            selected = [case for case in cases if case // 448 == wide]
            self.assertEqual({case // 56 % 8 for case in selected}, set(range(8)))
            self.assertEqual({case // 7 % 8 for case in selected}, set(range(8)))
            self.assertEqual({case % 7 for case in selected}, set(range(7)))

    def test_internal_full_sweep_fits_with_non_miri_phases(self):
        groups = list(plans.scope.GROUPS)
        plan = {'stage': 'internal', 'approval_required': False, 'groups': groups,
                'full_phases': list(catalog.PHASES),
                'verifiers': {phase: groups for phase in ('miri', 'asan', 'kani')}}
        commands = catalog.selected(plan, list(catalog.PHASES), None,
                                    miri_tasks=True, miri_profile='routine')
        self.assertEqual({command['phase'] for command in commands}, set(catalog.PHASES))
        self.assertGreater(len(commands), 542)
        self.assertLessEqual(len(commands), 4096)

    def test_routine_parallel_covers_widths_blocks_and_each_lifecycle_case_zero(self):
        self.assertEqual(len(miri_cases.matrices('parallelhash')), 21)
        for matrix in miri_cases.matrices('parallelhash')[:6]:
            cases = matrix['routine']
            self.assertEqual(len(cases), 8)
            self.assertEqual(len(set(cases)), 8)
            self.assertEqual({case % 8 for case in cases}, set(range(8)))
            self.assertEqual({case // 8 for case in cases}, set(range(matrix['total'] // 8)))
            self.assertIn(0, cases)

    def test_parallel_leaf_sampling_retains_every_length_and_tail_width(self):
        leaf = miri_cases.matrices('parallelhash')[6]
        cases = leaf['routine']
        self.assertEqual(leaf['total'], 65)
        self.assertEqual(len(set(cases)), 9)
        self.assertIn(0, cases)
        self.assertEqual({(case - 1) // 8 for case in cases if case}, set(range(8)))
        self.assertEqual({(case - 1) % 8 for case in cases if case}, set(range(8)))

    def test_kmac_lifecycle_splitting_retains_every_case_in_both_profiles(self):
        _, fixed, xof = miri_cases.matrices('kmac')[:3]
        for matrix, total in ((fixed, 18), (xof, 16)):
            self.assertEqual(matrix['total'], total)
            self.assertEqual(matrix['routine'], list(range(total)))
            self.assertEqual(matrix['features'], [])

    def test_parallel_buffering_covers_all_dimensions_for_both_strengths(self):
        matrix = miri_cases.matrices('parallelhash')[7]
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
        self.assertEqual(count, 3727)

    def test_tuple_execution_splits_keep_every_strength_width_and_xof_case(self):
        matrices = miri_cases.matrices('tuplehash')[1:3]
        self.assertEqual([matrix['total'] for matrix in matrices], [16, 2])
        for matrix in matrices:
            self.assertEqual(matrix['routine'], list(range(matrix['total'])))
            self.assertEqual(matrix['target'], ['--test', 'execution'])
            for profile in ('routine', 'extended'):
                tasks = miri_tasks.task_inventory(plans.ROOT, 'tuplehash', profile)
                self.assertEqual(tasks[1]['argv'].count(matrix['name']), 1)
                exact = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
                self.assertEqual([task['environment']['BRYNJA_MIRI_CASE'] for task in exact],
                                 [str(case) for case in range(matrix['total'])])
                self.assertTrue(all(task['argv'][:6] == ['-p', 'brynja-hash-tuple',
                                                       '--features', 'hardened-execution',
                                                       '--test', 'execution'] for task in exact))
                for retained in ('fragmented_item_bits_preserve_exact_tuple_boundaries',
                                 'unfinished_overlong_dropped_and_forgotten_items_never_reopen',
                                 'invalid_output_is_atomic_and_required_absence_is_an_error',
                                 'unwind_and_forgotten_reader_leave_the_parent_terminal',
                                 'future_unregistered_test'):
                    self.assertNotIn(retained, tasks[1]['argv'])

    def test_tuple_scoped_chunks_cover_each_strength_length_tail_and_all_widths(self):
        matrices = miri_cases.matrices('tuplehash')[3:]
        self.assertEqual([matrix['total'] for matrix in matrices], [56, 56, 48, 48])
        for matrix in matrices:
            self.assertEqual(matrix['features'], [])
            self.assertEqual(len(set(matrix['routine'])), 8)
            self.assertEqual({case // 8 for case in matrix['routine']}, set(range(6)))
            self.assertEqual({case % 8 for case in matrix['routine']}, set(range(8)))
            self.assertEqual({(case % 8 + 1) % 5 for case in matrix['routine']}, set(range(5)))
            # A bit-width label is meaningful only if input or output is nonempty.
            self.assertTrue(all(case // 8 != 0 or (case % 8 + 1) % 5 != 0
                                for case in matrix['routine']))
            for profile in ('routine', 'extended'):
                tasks = miri_tasks.task_inventory(plans.ROOT, 'tuplehash', profile)
                self.assertEqual(tasks[3]['argv'].count(matrix['name']), 1)
                exact = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
                expected = matrix['routine'] if profile == 'routine' else list(range(matrix['total']))
                self.assertEqual([int(task['environment']['BRYNJA_MIRI_CASE']) for task in exact], expected)
                self.assertTrue(all(task['argv'][:3] == ['-p', 'brynja-hash-tuple', '--lib'] for task in exact))
                for retained in ('miri_chunks_reject_incomplete_or_duplicate_output_widths',
                                 'future_unregistered_test'):
                    self.assertNotIn(retained, tasks[3]['argv'])

    def test_tuple_lifecycles_and_api_singles_keep_exact_selection_and_discovery(self):
        names = miri_cases.singles('tuplehash')
        self.assertEqual(len(set(names)), 9)
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'tuplehash', profile)
            for name in names:
                target = ['--lib'] if name.startswith('hardened_in_place::') else ['--test', 'api']
                self.assertEqual(tasks[3]['argv'].count(name), 1)
                self.assertEqual(sum(task['argv'] == ['-p', 'brynja-hash-tuple', *target, name, '--', '--exact']
                                     for task in tasks), 1)
            retained = 'forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch'
            self.assertIn(retained, tasks[2]['argv'])
            self.assertNotIn(retained, tasks[3]['argv'])
            self.assertNotIn('future_unregistered_test', tasks[3]['argv'])

    def test_official_vectors_and_scheduled_lifecycles_are_never_sampled(self):
        for matrix in [*miri_cases.matrices('kmac')[3:], *miri_cases.matrices('parallelhash')[10:12]]:
            self.assertEqual(matrix['total'], 6)
            self.assertEqual(matrix['routine'], list(range(6)))
            self.assertEqual(matrix['target'], ['--test', 'official_vectors'])
        for matrix in miri_cases.matrices('parallelhash')[8:10]:
            self.assertEqual(matrix['total'], 11)
            self.assertEqual(matrix['routine'], list(range(11)))
            self.assertEqual(matrix['features'], [])

    def test_scheduled_unwind_reuse_retains_every_case_and_future_discovery(self):
        matrices = miri_cases.matrices('parallelhash')[12:14]
        self.assertEqual(len(matrices), 2)
        for matrix in matrices:
            self.assertEqual(matrix['total'], 4)
            self.assertEqual(matrix['routine'], list(range(4)))
            self.assertEqual(matrix['features'], [])
            self.assertEqual(matrix['target'], ['--test', 'scoped_scheduled'])
            for profile in ('routine', 'extended'):
                tasks = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', profile)
                self.assertEqual(tasks[1]['argv'].count(matrix['name']), 1)
                exact = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
                self.assertEqual([task['environment']['BRYNJA_MIRI_CASE'] for task in exact], ['0', '1', '2', '3'])
                self.assertNotIn('future_unregistered_test', tasks[1]['argv'])

    def test_parallel_execution_stream_covers_each_strength_block_and_bit_width(self):
        matrix = miri_cases.matrices('parallelhash')[14]
        self.assertEqual(matrix['total'], 48)
        self.assertEqual(len(set(matrix['routine'])), 16)
        for wide in range(2):
            selected = [case % 24 for case in matrix['routine'] if case // 24 == wide]
            self.assertEqual({case // 8 for case in selected}, set(range(3)))
            self.assertEqual({case % 8 for case in selected}, set(range(8)))
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', profile)
            self.assertEqual(tasks[2]['argv'].count(matrix['name']), 1)
            exact = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
            self.assertTrue(all(task['argv'][:4] == ['-p', 'brynja-hash-parallel',
                                                  '--features', 'hardened-execution'] for task in exact))

    def test_hosted_workers_retain_all_scenarios_and_threaded_feature(self):
        matrices = miri_cases.matrices('parallelhash')[15:]
        self.assertEqual([matrix['total'] for matrix in matrices], [6, 4, 4, 6, 3, 4])
        for matrix in matrices:
            self.assertEqual(matrix['routine'], list(range(matrix['total'])))
            for profile in ('routine', 'extended'):
                tasks = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', profile)
                self.assertEqual(tasks[4]['argv'].count(matrix['name']), 1)
                exact = [task for task in tasks if task['marker'] and matrix['name'] in task['argv']]
                self.assertEqual([task['environment']['BRYNJA_MIRI_CASE'] for task in exact],
                                 [str(case) for case in range(matrix['total'])])
                self.assertTrue(all(task['argv'][:5] == ['-p', 'brynja-hash-parallel-std',
                                                      '--features', 'runtime-execution', '--lib'] for task in exact))
                for retained in ('scoped_execution_gate_rejects_overlap_and_poison',
                                 'operation_permit_rejects_reentry_without_touching_public_output',
                                 'poisoned_permit_is_terminal_and_still_clears_destinations',
                                 'storage_clear_visits_every_byte_of_every_live_slot', 'future_unregistered_test'):
                    self.assertNotIn(retained, tasks[4]['argv'])

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

    def test_parallel_api_singles_preserve_tests_and_future_discovery(self):
        names = miri_cases.singles('parallelhash')
        self.assertEqual(len(set(names)), 6)
        source = (plans.ROOT / 'crates/brynja-hash-parallel/tests/api.rs').read_text()
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', profile)
            broad = tasks[1]['argv']
            self.assertEqual(broad[:3], ['-p', 'brynja-hash-parallel', '--tests'])
            for name in names:
                self.assertIn('#[test]\nfn ' + name + '(', source)
                self.assertEqual(broad.count(name), 1)
                exact = [task for task in tasks if task['argv'] ==
                         ['-p', 'brynja-hash-parallel', '--test', 'api', name, '--', '--exact']]
                self.assertEqual(len(exact), 1)
            self.assertNotIn('zero_block_size_is_rejected_before_output', broad)
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
