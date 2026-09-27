"""Phase routing, incompatible tools and foreground approval regressions."""
import contextlib
import copy
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import detached_manifest as records
import phase_receipts as phases
import verification_carry_forward as carry
from verification_carry_forward_tests import entry, plan


class PhaseReceiptTests(unittest.TestCase):
    def test_registry_rejects_malformed_missing_duplicate_and_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job = root / 'job'
            job.mkdir()
            path = root / 'registry.json'
            value = {'schema': 1, 'phases': {'miri': 'a' * 64}, 'jobs': {'a' * 64: str(job)}}
            records.atomic(path, value)
            self.assertEqual(phases.load(path)['jobs']['a' * 64], job)
            mutations = [lambda v: v.update(schema=True), lambda v: v.update(phases={}),
                         lambda v: v['phases'].update(unknown='a' * 64),
                         lambda v: v['phases'].update(miri='b' * 64),
                         lambda v: v['phases'].update(miri=[]),
                         lambda v: v['jobs'].update({'b' * 64: str(job)}),
                         lambda v: v['jobs'].update({'a' * 64: 'relative'}),
                         lambda v: v['jobs'].update({'a' * 64: str(root / 'absent')}),
                         lambda v: v.update(extra='not allowed')]
            for change in mutations:
                changed = copy.deepcopy(value)
                change(changed)
                records.atomic(path, changed)
                with self.assertRaises(ValueError):
                    phases.load(path)
            records.atomic(path, value)
            if os.name == 'posix':
                linked = root / 'linked'
                linked.symlink_to(job, target_is_directory=True)
                value['jobs']['a' * 64] = str(linked)
                records.atomic(path, value)
                with self.assertRaises(ValueError):
                    phases.load(path)
            path.write_text('{"schema":1,"schema":1}')
            with self.assertRaises(ValueError):
                phases.load(path)

    def test_registry_routes_each_phase_to_its_own_evidence_and_keeps_delta_checks(self):
        miri = entry('python3 scripts/zeroization/run-miri-task.py --group sha2 --task 0 --profile routine', 'miri')
        kani = entry('scripts/assurance/check-kani.sh --required-groups sha2', 'kani')
        registry = {'phases': {'miri': 'a' * 64, 'kani': 'b' * 64},
                    'jobs': {'a' * 64: Path('/tmp/miri'), 'b' * 64: Path('/tmp/kani')}}
        def context(job, receipt, root, requested, **kwargs):
            chosen = [miri] if receipt == 'a' * 64 else [kani]
            return {'plan': plan(), 'manifest': {'commands': chosen, 'phases': [chosen[0]['phase']]},
                    'release_plan': requested, 'public_checkpoint': False}
        def required(ctx, phase, _command):
            return [miri if phase == 'miri' else kani]
        with patch.object(phases, 'load', return_value=registry), \
             patch.object(phases.history.History, 'collect', return_value={'commands': 1}), \
             patch.object(phases.history.History, '__init__', return_value=None), \
             patch.object(phases.history.History, 'cache', {}, create=True) as cache, \
             patch.object(phases, 'compatible_tools'), \
             patch.object(carry, 'prepare', side_effect=context), \
             patch.object(carry, 'required', side_effect=required), \
             patch.object(phases.catalog, 'PHASES', ('miri', 'kani')):
            cache.update({r: ({}, {}, {}) for r in registry['jobs']})
            contexts, decisions = phases.prepare(Path('/tmp/registry'), Path('/tmp/root'), plan(), 'plan')
            self.assertEqual(len(contexts), 2)
            self.assertEqual([c for c, _ in decisions], [miri, kani])
            self.assertTrue(all(d.startswith('reuse:') for _, d in decisions))
            contexts[0]['plan']['verifiers']['miri'] = ['sha2']
            self.assertTrue(carry.disposition(miri, contexts[0]).startswith('run:'))
            contexts[1]['public_checkpoint'] = True
            self.assertTrue(carry.disposition(kani, contexts[1]).startswith('run:'))
            with self.assertRaisesRegex(ValueError, 'lacks'):
                phases.prepare(Path('/tmp/registry'), Path('/tmp/root'), plan(), 'asan')
            registry['phases']['kani'] = 'a' * 64
            with self.assertRaisesRegex(ValueError, 'does not cover'):
                phases.prepare(Path('/tmp/registry'), Path('/tmp/root'), plan(), 'kani')

    def test_extra_tools_are_irrelevant_but_actual_compiler_verifier_and_platform_drift_block(self):
        tools = {'platform': sys.platform, 'rustc': 'rustc exact', 'cargo': 'cargo exact',
                 'compiler:recorded': 'compiler exact', 'verifier:miri': 'miri exact',
                 'python': 'old Python', 'rustup': 'old rustup', 'installed': 'recorded'}
        probes = {('rustc', '-vV'): b'rustc exact', ('cargo', '-V'): b'cargo exact',
                  ('rustc', '+recorded', '-vV'): b'compiler exact', ('cargo', 'miri', '--version'): b'miri exact'}
        def output(argv, **kwargs):
            self.assertEqual(kwargs['env']['RUSTUP_AUTO_INSTALL'], '0')
            return probes[tuple(argv)]  # No inventory/Python probe is allowed.
        with patch.object(records, 'verifier_commands', return_value={'verifier:miri': ['cargo', 'miri', '--version']}), \
             patch.object(phases.subprocess, 'check_output', side_effect=output):
            phases.compatible_tools({'tools': tools, 'commands': []}, Path('/tmp/source'))
            for key in ('platform', 'rustc', 'cargo', 'compiler:recorded', 'verifier:miri'):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    phases.compatible_tools({'tools': {**tools, key: 'changed'}, 'commands': []}, Path('/tmp/source'))

    def test_foreground_validates_all_receipts_and_approvals_before_any_execution(self):
        spec = importlib.util.spec_from_file_location('phase_runner', Path(__file__).with_name('run-verification.py'))
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        base = ['runner', 'miri', '--detached-receipts', '/tmp/registry']
        check = entry('test current command', 'miri')
        cases = [([], None, 0, 1), (['--check'], None, 0, 0),
                 (['--detached-job', '/tmp/single', '--detached-receipt', 'r'], None, 1, 0),
                 ([], ValueError('bad parent'), 1, 0),
                 ([], PermissionError('approval required'), 3, 0)]
        for flags, error, expected, executions in cases:
            with patch.object(sys, 'argv', base + flags), patch.dict(os.environ, {}, clear=True), \
                 patch.object(runner.plans, 'build', return_value=plan()), \
                 patch.object(phases, 'prepare', return_value=([{'plan': plan()}], [(check, 'run: changed')]),
                              side_effect=error), patch.object(runner, 'execute') as execute, \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(runner.main(), expected)
                self.assertEqual(execute.call_count, executions)
        with patch.object(sys, 'argv', ['runner', 'repository', '--ci']), \
             patch.dict(os.environ, {'BRYNJA_DETACHED_RECEIPTS': '/tmp/registry'}, clear=True), \
             patch.object(phases, 'prepare') as prepare, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(), 1)
            prepare.assert_not_called()
        with patch.object(sys, 'argv', base), patch.dict(os.environ, {}, clear=True), \
             patch.object(runner.plans, 'build', return_value=plan()), \
             patch.object(phases, 'prepare', return_value=([{'plan': plan()}, {'plan': plan(blocked=True)}],
                                                         [(check, 'run: changed')])), \
             patch.object(runner, 'execute') as execute, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(), 3)
            execute.assert_not_called()
