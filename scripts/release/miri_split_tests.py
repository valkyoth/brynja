"""Independent scenario coverage and historical identity regressions."""
import itertools
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import miri_cases
import miri_tasks
import verification_plan as plans
import test_dashboard_catalog as dashboard
from miri_task_tests import runner


class MiriSplitTests(unittest.TestCase):
    def test_bounded_parallelhash_checkpoint_preserves_routine_and_lifecycle_population(self):
        current = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', 'extended')
        routine = miri_tasks.task_inventory(plans.ROOT, 'parallelhash', 'routine')
        self.assertEqual(current, routine)
        self.assertEqual(len(current), 173)
        matrices = miri_cases.matrices('parallelhash')
        for matrix in matrices:
            exact = [t for t in current if t['marker'] and matrix['name'] in t['argv']]
            self.assertEqual([int(t['environment']['BRYNJA_MIRI_CASE']) for t in exact], matrix['routine'])
            self.assertTrue(all(t['coverage'] == 'bounded-parallelhash-v1' for t in exact))
        # Faults, joins, ordering and output-slot cleanup still retain ALL cases.
        for matrix in matrices[8:14] + matrices[15:]:
            self.assertEqual(matrix['routine'], list(range(matrix['total'])))
        entry = dict(phase='miri', command='', argv=['python3', miri_tasks.RUNNER,
                     '--group', 'parallelhash', '--task', '5', '--profile', 'extended'])
        item = dashboard.describe(entry, plans.ROOT)
        self.assertTrue(item['label'].startswith('[bounded-parallelhash-v1]'))
        self.assertEqual(item['definition']['task']['environment']['BRYNJA_MIRI_PROFILE'], 'routine')

    def test_historical_catalog_reconstruction_keeps_original_populations(self):
        for profile, total in (('existing-full', 111), ('routine', 590), ('extended', 4122)):
            tasks = [task for group in plans.scope.GROUPS for task in miri_cases.tasks(
                group, miri_tasks.inventory(plans.ROOT, group), profile, legacy=True)]
            self.assertEqual(len(tasks), total)
            self.assertTrue(all('coverage' not in t and 'BRYNJA_MIRI_WIDTH' not in t['environment'] for t in tasks))
        parallel = miri_cases.tasks('parallelhash', miri_tasks.inventory(plans.ROOT, 'parallelhash'),
                                   'extended', legacy=True)
        self.assertEqual(len(parallel), 1105)
        self.assertTrue(all(t['environment'].get('BRYNJA_MIRI_PROFILE', 'extended') == 'extended'
                            for t in parallel))

    def test_unknown_historical_catalog_fails_closed_instead_of_reassigning_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'scripts/zeroization/miri_cases.py'
            path.parent.mkdir(parents=True)
            path.write_text('raise AssertionError("never execute archived code")')
            with self.assertRaisesRegex(ValueError, 'unreviewed historical'):
                miri_tasks.legacy_cases(root)
            path.write_bytes(Path(miri_cases.__file__).read_bytes())
            self.assertFalse(miri_tasks.legacy_cases(root))

    def test_streamed_setup_retains_all_100_combinations_in_both_profiles(self):
        matrix = miri_cases.matrices('kmac')[-1]
        self.assertEqual(matrix['total'], 100)
        expected = set(itertools.product(range(5), range(5), range(2), range(2)))
        for profile in ('routine', 'extended'):
            tasks = miri_tasks.task_inventory(plans.ROOT, 'kmac', profile)
            exact = [t for t in tasks if t['marker'] and matrix['name'] in t['argv']]
            cases = [int(t['environment']['BRYNJA_MIRI_CASE']) for t in exact]
            self.assertEqual(cases, list(range(100)))
            self.assertEqual({(c // 20, c // 4 % 5, c // 2 % 2, c % 2) for c in cases}, expected)
            self.assertTrue(all(t['argv'] == ['-p', 'brynja-mac-kmac', '--lib',
                matrix['name'], '--', '--exact'] for t in exact))
            self.assertEqual(tasks[0]['argv'].count(matrix['name']), 1)
            self.assertNotIn('setup::tests::streamed_setup_selection_rejects_invalid_cases', tasks[0]['argv'])

    def test_split_widths_cannot_inherit_an_unsplit_or_other_width_dashboard_pass(self):
        tasks = miri_tasks.task_inventory(plans.ROOT, 'tuplehash', 'extended')
        first = next(i for i, t in enumerate(tasks) if 'BRYNJA_MIRI_WIDTH' in t['environment'])
        old = tasks[first]
        old = {**old, 'environment': {k: v for k, v in old['environment'].items() if k != 'BRYNJA_MIRI_WIDTH'},
               'marker': old['marker'].split(':width=')[0]}
        entries = [dict(phase='miri', command='', argv=['python3', miri_tasks.RUNNER,
                   '--group', 'tuplehash', '--task', str(i), '--profile', 'extended']) for i in (0, 1, 2)]
        with patch.object(miri_tasks, 'task_inventory', return_value=[old, tasks[first], tasks[first+1]]):
            ids = [dashboard.describe(e, plans.ROOT)['id'] for e in entries]
        self.assertEqual(len(set(ids)), 3)

    def test_width_is_interpreter_runtime_input_not_cached_compile_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            env = runner.case_environment(plans.ROOT, {'environment': {
                'BRYNJA_MIRI_CASE': '3', 'BRYNJA_MIRI_PROFILE': 'extended', 'BRYNJA_MIRI_WIDTH': '4'}})
        self.assertNotIn('BRYNJA_MIRI_WIDTH', env)
        self.assertIn('-Zmiri-env-set=BRYNJA_MIRI_WIDTH=4', env['MIRIFLAGS'])
        with patch.dict(os.environ, {'BRYNJA_MIRI_WIDTH': '4'}, clear=True), self.assertRaises(ValueError):
            runner.environment(plans.ROOT)

    def test_parallel_native_reuse_and_same_case_output_lifecycle_remain_together(self):
        for suffix, total in (('tests.rs', 48), ('xof/tests.rs', 40)):
            source = (plans.ROOT / 'crates/brynja-hash-parallel/src/hardened_in_place' / suffix).read_text()
            self.assertIn('if selected.is_none_or(|case| case == 0) {\n                $finish(&mut workspace)?;', source)
            self.assertIn('fn $lifecycle() -> Result<(), Error>', source)
            self.assertIn('fn $finish(workspace: &mut $workspace)', source)
            matrix_body = source.split('fn $finish(')[0]
            for token in ('Public::acknowledge()', '.expose()', 'drop(', 'workspace.cleared()'):
                self.assertIn(token, matrix_body)
            self.assertIn(f'miri_selection({total})?', matrix_body)
