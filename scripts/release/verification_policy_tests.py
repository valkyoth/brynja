"""Publication is not an implementation change; explicit full checkpoints remain."""
import contextlib
import importlib.util
import io
import os
import shlex
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import detached_catalog as catalog
import verification_carry_forward as carry
import verification_commands as commands
import verification_plan as plans


class VerificationPolicyTests(unittest.TestCase):
    def build(self, stage='public', mode='affected', groups=('hmac',), broad=False):
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(plans.scope, 'select_repository', return_value=(broad, groups)), \
             patch.object(plans.miri_dependencies, 'select', return_value=(broad, groups)), \
             patch.object(plans, 'changed_paths', return_value=[]), \
             patch.object(plans.inputs, 'snapshot', return_value=(None, None)), \
             patch.object(plans.inputs, 'git', return_value=b'a' * 40), \
             patch.object(plans, 'fingerprint', return_value='f' * 64):
            root = Path(directory)
            (root / 'release-crates.toml').write_text(
                f'[release]\nversion="0.25.3"\nstage="{stage}"\n' +
                (f'verification="{mode}"\n' if mode is not None else ''))
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.99.1"\n')
            return plans.build(root, 'baseline')

    def test_publication_selects_only_changed_families(self):
        for group in ('hmac', 'legacy_hmac', 'sha2', 'kmac'):
            plan = self.build(groups=(group,))
            self.assertEqual(plan['groups'], [group])
            self.assertEqual(plan['full_phases'], [])
            self.assertFalse(plan['approval_required'])
            self.assertTrue(plans.miri_required(plan))
            self.assertEqual(plans.miri_profile(plan), 'routine')
            for selected in plan['verifiers'].values():
                self.assertEqual(selected, [group])
            tasks = catalog.selected(plan, ['miri'], None, miri_tasks=True,
                                     miri_profile=plans.miri_profile(plan))
            self.assertTrue(tasks)
            self.assertEqual({e['argv'][3] for e in tasks}, {group})

    def test_unknown_scope_still_blocks_before_execution_on_both_stages(self):
        for stage in ('internal', 'public'):
            plan = self.build(stage=stage, groups=plans.scope.GROUPS, broad=True)
            with self.assertRaises(PermissionError):
                catalog.selected(plan, ['asan'], None)
            self.assertTrue(plans.requires_full(plan, 'miri'))
        with self.assertRaises(ValueError):
            self.build(mode='skip-all')

    def test_full_checkpoint_requires_approval_and_extended_profile(self):
        for stage in ('internal', 'public'):
            plan = self.build(stage=stage, mode='full')
            self.assertEqual(set(plan['full_phases']), set(catalog.PHASES))
            self.assertEqual(plan['groups'], list(plans.scope.GROUPS))
            self.assertTrue(plans.miri_required(plan))
            self.assertEqual(plans.miri_profile(plan), 'extended')
            with self.assertRaises(ValueError):
                plans.miri_profile(plan, 'routine')
            with self.assertRaises(PermissionError):
                plans.authorize(plan, None)
            plans.authorize(plan, plan['fingerprint'])

    def test_legacy_plan_interpretation_is_not_relabelled(self):
        public = self.build(mode=None)
        self.assertNotIn('verification_mode', public)
        self.assertEqual(plans.miri_profile(public), 'extended')
        self.assertFalse(public['approval_required'])
        self.assertTrue(plans.miri_required(self.build(stage='internal', mode=None)))
        with self.assertRaises(ValueError):
            plans.miri_profile(public, 'routine')

    def test_version_and_publication_do_not_invalidate_successful_receipts(self):
        old = self.build(stage='internal')
        current = {**old, 'stage': 'public', 'version': '0.26.0'}
        self.assertFalse(plans.new_full_checkpoint(current, old))
        check = {'phase': 'miri', 'command': 'python3 scripts/zeroization/run-miri-task.py --group kmac --task 0 --profile routine', 'stdin': None, 'environment': {},
                 'argv': ['python3', 'scripts/zeroization/run-miri-task.py',
                          '--group', 'kmac', '--task', '0', '--profile', 'routine']}
        context = {'plan': self.build(groups=()), 'manifest': {'commands': [check]},
                   'coverage_roots': (plans.ROOT, plans.ROOT),
                   'public_checkpoint': plans.new_full_checkpoint(current, old)}
        self.assertTrue(carry.disposition(check, context).startswith('reuse:'))
        for changed in ({'tool_drift': {'miri': 'new interpreter'}},
                        {'manifest': {'commands': []}}, {'plan': self.build(groups=('kmac',))}):
            self.assertTrue(carry.disposition(check, {**context, **changed}).startswith('run:'))
        full = {**current, 'verification_mode': 'full'}
        self.assertTrue(plans.new_full_checkpoint(full, old))
        self.assertFalse(plans.new_full_checkpoint(full, full))
        self.assertTrue(plans.new_full_checkpoint({**full, 'version': '1.0.0'}, full))

    def test_receipts_do_not_implicitly_approve_a_new_full_run(self):
        old = self.build(stage='internal')
        release = self.build(mode='full')
        manifest = {'sources': {'head': 'b' * 40}, 'plan': old}
        with patch.object(carry.jobs, 'collect', return_value={'commands': 1}), \
             patch.object(carry.jobs, 'load', return_value=manifest), \
             patch.object(carry.plans, 'build', return_value=self.build(groups=())), \
             patch.object(carry.plans, 'changed_paths', return_value=[]), \
             patch.object(carry.records, 'git', return_value=b''):
            context = carry.prepare(Path('/tmp/unused-policy-test'), 'receipt', plans.ROOT, release)
        self.assertTrue(context['public_checkpoint'])
        with self.assertRaises(PermissionError):
            plans.authorize(context['plan'], None)
        import phase_receipts
        context.update(receipt='c' * 64, selected_phases=['miri'])
        auth = phase_receipts.authorization_plan(release, [context],
            [({'phase': 'miri'}, 'run: new full assurance checkpoint')])
        self.assertTrue(auth['approval_required'])
        self.assertEqual(auth['full_phases'], ['miri'])

    def test_optional_development_miri_does_not_disable_explicit_or_public_runs(self):
        spec = importlib.util.spec_from_file_location('policy_runner', plans.ROOT / 'scripts/release/run-verification.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        for stage, required, executions in (('internal', True, False),
                                             ('internal', False, True), ('public', True, True)):
            argv = ['runner', 'miri'] + (['--release-required'] if required else [])
            output = io.StringIO()
            with patch.object(runner.plans, 'build', return_value=self.build(stage=stage)), \
                 patch.object(runner.sys, 'argv', argv), \
                 patch.dict(os.environ, {}, clear=True), \
                 patch.object(runner, 'execute') as execute, contextlib.redirect_stdout(output):
                self.assertEqual(runner.main(), 0)
            self.assertEqual(execute.called, executions)
            if not executions:
                self.assertIn('no Miri pass claimed', output.getvalue())

    def test_routine_matrix_keeps_msrv_and_stable_and_full_is_unchanged(self):
        import tomllib
        full = commands.matrix_commands()
        routine = commands.matrix_for_plan(self.build())
        minimum = tomllib.loads((plans.ROOT / 'Cargo.toml').read_text())['workspace']['package']['rust-version']
        if minimum.count('.') == 1:
            minimum += '.0'
        stable = tomllib.loads((plans.ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel']
        versions = {shlex.split(c)[1] for c, _ in routine}
        self.assertEqual(versions, {'+' + minimum, '+' + stable})
        self.assertLess(len(routine), len(full))
        self.assertEqual(commands.matrix_for_plan(self.build(mode='full')), full)
        self.assertEqual(commands.matrix_for_plan(self.build(mode=None)), full)
        with patch.object(commands, 'matrix_commands', return_value=[]):
            with self.assertRaises(ValueError):
                commands.matrix_for_plan(self.build())

    def test_foreground_and_detached_use_same_affected_profile(self):
        plan = self.build()
        context = {'release_plan': plan, 'manifest': {'miri_profile': 'extended'}}
        required = carry.required(context, 'miri')
        self.assertTrue(required)
        self.assertTrue(all(e['argv'][-1] == 'routine' for e in required))
        import detached_job
        # Keep both detached entry points on the same profile selector.
        source = Path(detached_job.__file__).read_text()
        self.assertIn('plans.miri_profile(plan, miri_profile)', source)
        self.assertIn('plans.miri_profile(manifest["plan"], manifest["miri_profile"])', source)


def run():
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(VerificationPolicyTests))
    if not result.wasSuccessful():
        raise AssertionError('release verification policy regression')


if __name__ == '__main__':
    run()
