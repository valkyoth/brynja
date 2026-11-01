"""Scoped Kani metadata and fake verifier tests; never executes a proof."""
from contextlib import nullcontext, redirect_stdout
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import verification_kani_bindings as bindings

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('scoped_kani', ROOT / 'scripts/release/run-kani-component.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class KaniBindingTests(unittest.TestCase):
    def test_scoped_bindings_and_inventory_only_disposition(self):
        rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        with patch('subprocess.Popen', side_effect=AssertionError('Kani generation spawned a process')):
            document = bindings.build(rows)
        self.assertEqual(document, json.loads((ROOT / 'verification/kani-checks.json').read_text()))
        self.assertEqual(len(document['checks']), 9)
        self.assertEqual({c['component'] for c in document['checks']}, set(bindings.PACKAGES))
        references = [r for r in rows if r['phase'] == 'inventory-only']
        self.assertEqual({r['families'][0] for r in references}, bindings.INVENTORY_ONLY)
        for check in document['checks']:
            groups = [document['groups'][g] for g in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertTrue(all((ROOT / p).exists() for p in paths))
            self.assertNotIn('scripts/assurance/check-kani.sh', paths)
            self.assertNotIn('scripts/release/verification_kani_bindings.py', paths)
            self.assertEqual(check['success']['unique_lines'], check['success']['contains'])
            for dependency in bindings.PACKAGES[check['component']]:
                self.assertIn(f'crates/{dependency}/src', paths)
            if check['component'] in bindings.PROOFS:
                steps = json.loads(check['command'][-1])
                self.assertEqual(steps, [[argv, count] for argv, count in bindings.PROOFS[check['component']]])
        original = next(r for r in rows if r['phase'] == 'kani')
        changed = copy.deepcopy(original)
        changed['command'].append('--policy-only')
        with self.assertRaises(ValueError):
            bindings.build([changed])

    def test_existing_command_counts_and_sources_match(self):
        shell = (ROOT / 'scripts/assurance/check-kani.sh').read_text()
        self.assertEqual(sum(n for steps in bindings.PROOFS.values() for _, n in steps), 32)
        for family, steps in bindings.PROOFS.items():
            package = steps[0][0][1]
            actual = sum(p.read_text().count('#[kani::proof]') for p in (ROOT / 'crates' / package / 'src').rglob('*.rs'))
            self.assertEqual(actual, sum(n for _, n in steps), family)
            for argv, _ in steps:
                self.assertIn('cargo kani ' + ' '.join(argv), shell)

    def test_zero_failed_duplicate_or_wrong_summary_never_passes(self):
        for output in ['', 'SKIP', 'Complete - 0 successfully verified harnesses, 0 failures, 0 total.',
                'Complete - 2 successfully verified harnesses, 1 failures, 3 total.',
                'Complete - 3 successfully verified harnesses, 0 failures, 3 total.\n' * 2,
                'Complete - 4 successfully verified harnesses, 0 failures, 4 total.']:
            with self.assertRaises(ValueError):
                runner.verified(output, 3)
        runner.verified('Complete - 3 successfully verified harnesses, 0 failures, 3 total.', 3)

    def test_two_step_run_stops_on_failure_and_uses_isolated_offline_setup(self):
        steps = bindings.PROOFS['sha2']
        for fail in [False, True]:
            calls = []
            def run(command, env):
                calls.append(command)
                self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
                self.assertEqual(env['RUSTUP_AUTO_INSTALL'], '0')
                if command[-1] == '--version':
                    return f'Kani Rust Verifier {bindings.VERSION} (cargo plugin)\nCBMC 6.11.0'
                count = steps[len(calls) - 2][1]
                return f'Complete - {0 if fail else count} successfully verified harnesses, 0 failures, {count} total.'
            verifier = SimpleNamespace(run=run, environment=lambda path: {},
                cargo_environment=SimpleNamespace(private_directory=lambda root: nullcontext('/fake/private/target')))
            output = io.StringIO()
            with redirect_stdout(output):
                if fail:
                    with self.assertRaises(ValueError):
                        runner.execute('sha2', steps, verifier)
                else:
                    runner.execute('sha2', steps, verifier)
            self.assertEqual(len(calls), 2 if fail else 3)
            self.assertEqual(bindings.marker('sha2') in output.getvalue(), not fail)
            self.assertTrue(all('--workspace' not in command for command in calls))

    def test_invalid_selection_or_tool_version_never_reaches_proof(self):
        verifier = SimpleNamespace(run=lambda *args: 'wrong version', environment=lambda path: {},
            cargo_environment=SimpleNamespace(private_directory=lambda root: nullcontext('/fake/private/target')))
        for steps in [[], [(['--workspace'], 1)], [(['-p', 'fake'], 0)]]:
            with self.assertRaisesRegex(ValueError, 'selection'):
                runner.execute('md5', steps, verifier)
        with self.assertRaisesRegex(ValueError, 'version'):
            runner.execute('md5', bindings.PROOFS['md5'], verifier)
