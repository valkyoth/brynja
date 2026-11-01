"""Acceptance registration and fake-child controls, no cryptographic execution."""
import ast
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import verification_acceptance_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy
from verification_package_tests import covered

ROOT = Path(__file__).resolve().parents[2]


class AcceptanceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_four_exact_regression_selectors_never_execute_on_export(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no real children')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 4)
        validate_inputs(doc)
        for check in doc['checks']:
            row = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(row['command'], check['command'])
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            for field, value in [('command', row['command'] + ['--write']),
                                 ('environment', {'RUSTFLAGS': '-Ctarget-cpu=native'}), ('stdin', 'extra')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_existing_policy_inventories_and_new_source_paths_are_covered(self):
        sources = {
            'test-portable-acceptance.py': ('scripts/sp800185/portable_acceptance.py', 'FILES'),
            'test-execution-acceptance.py': ('scripts/sp800185/execution_acceptance.py', 'FILES'),
            'test-legacy-acceptance.py': ('scripts/legacy-hash/legacy_acceptance.py', 'FILES'),
            'test-legacy-final-acceptance.py': ('scripts/legacy-hash/legacy_final_acceptance.py', 'inventory'),
        }
        with patch('subprocess.Popen', side_effect=AssertionError('no real children')):
            for check in self.doc['checks']:
                source, field = sources[Path(check['command'][1]).name]
                with patch.object(sys, 'path', [str(ROOT / Path(source).parent), *sys.path]):
                    module = policy('binding_acceptance_' + field + Path(source).stem, source)
                paths = getattr(module, field)
                if callable(paths):
                    paths = paths()  # Path enumeration, not validation.
                groups = [self.doc['groups'][key] for key in check['inputs']]
                for path in paths:
                    self.assertTrue(covered(str(path), groups), (source, path))
                self.assertTrue(covered(str(module.FIXTURE) + '/src/new_case.rs', groups))
                self.assertFalse(covered('verification/results.json', groups))
                self.assertFalse(covered('docs/VERIFICATION_RESULTS.md', groups))
                self.assertFalse(covered('Cargo.lock', groups))
                for key in ('HASHES', 'FROZEN', 'SNAPSHOT'):
                    if hasattr(module, key):
                        self.assertTrue(covered(str(getattr(module, key)), groups))

    def test_sp800185_portable_compiles_all_42_mutants_with_restored_controls(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/sp800185'), *sys.path]):
            module = policy('binding_portable_mutants', 'scripts/sp800185/test-portable-acceptance.py')
        state = {'builds': [], 'errors': []}
        def run(command, **kwargs):
            if command[0] == 'cargo':
                self.assertIn('--locked', command)
                self.assertIn('--offline', command)
                source = Path(command[-1]).parent / 'src'
                changed = [p.stem for p in source.glob('*.rs') if 'let mut corrupted' in p.read_text()]
                self.assertLessEqual(len(changed), 1)
                state['error'] = {'cshake': 'Cshake', 'kmac': 'Kmac', 'tuplehash': 'TupleHash',
                                  'parallelhash': 'ParallelHash'}.get(next(iter(changed), ''))
                state['builds'].append(state['error'])
                return subprocess.CompletedProcess(command, 0, '', '')
            error = state['error']
            state['errors'].append(error)
            return subprocess.CompletedProcess(command, int(error is not None),
                '' if error else 'public API acceptance: PASS',
                'SP 800-185 portable public API acceptance: FAIL: ' + error if error else '')
        with patch('subprocess.Popen', side_effect=AssertionError('no real compiler')), \
                patch.object(module.subprocess, 'run', side_effect=run):
            self.assertEqual(module.live_output_mutations(), 42)
        self.assertEqual(state['builds'], state['errors'])
        self.assertEqual(len(state['builds']), 44)
        self.assertIsNone(state['builds'][0])
        self.assertIsNone(state['builds'][-1])
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'compile failure')), \
                self.assertRaisesRegex(AssertionError, 'failed to compile'):
            module.live_output_mutations()

    def test_sp800185_execution_preserves_four_corruptions_and_capture_is_mocked(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/sp800185'), *sys.path]):
            module = policy('binding_execution_mutants', 'scripts/sp800185/test-execution-acceptance.py')
        errors = []
        state = {}
        def run(command, **kwargs):
            if command[0] == 'cargo':
                self.assertIn('--offline', command)
                text = (Path(command[-1]).parent / 'src/parallel.rs').read_text()
                state['error'] = ('Parallel' if 'actual[0] ^= 1;' in text else
                                  'Failure' if '$output[0] ^= 1;' in text else None)
                return subprocess.CompletedProcess(command, 0, '', '')
            error = 'arguments' if '--unexpected' in command else state['error']
            errors.append(error)
            return subprocess.CompletedProcess(command, 2 if error == 'arguments' else int(error is not None),
                '' if error else '\n'.join(module.acceptance.REPORT),
                'SP 800-185 execution acceptance: FAIL: ' + error if error else '')
        with patch('subprocess.Popen', side_effect=AssertionError('no real compiler')), \
                patch.object(module.subprocess, 'run', side_effect=run):
            module.executable_tests()
        self.assertEqual(errors, [None, 'arguments', 'Parallel', 'Parallel', 'Parallel', 'Failure', None])
        with patch('subprocess.Popen', side_effect=AssertionError('no real native capture')), \
                contextlib.redirect_stdout(io.StringIO()):
            module.capture_tests()
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'compile failure')), \
                self.assertRaisesRegex(AssertionError, 'compile failure'):
            module.executable_tests()

    def test_legacy_batch_controls_execute_two_profiles_and_do_not_accept_compile_failure(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/legacy-hash'), *sys.path]):
            module = policy('binding_final_batch', 'scripts/legacy-hash/final_batch_mutations.py')
        seen = []
        def run(command, **kwargs):
            self.assertIn('--offline', command)
            self.assertEqual(command[-2:], ['--', '--exact'])
            text = (Path(command[command.index('--manifest-path') + 1]).parent / 'src/batch.rs').read_text()
            seen.append(('--release' in command, text))
            noop = 'let report = brynja_legacy_md5::Md5BatchReport::default();' in text
            reused = text.count('output = wanted.map(|lane| lane.map(|byte| !byte));') == 2
            rejected = (noop and not reused) or 'report.vector_blocks = 1;' in text
            return subprocess.CompletedProcess(command, int(rejected),
                '1 failed; hardened batch differs' if rejected else '1 passed; 0 failed', '')
        output = io.StringIO()
        with patch('subprocess.Popen', side_effect=AssertionError('no real compiler')), \
                patch.object(module.subprocess, 'run', side_effect=run), contextlib.redirect_stdout(output):
            module.run_tests()
        self.assertEqual([release for release, _ in seen], [False] * 5 + [True] * 5)
        self.assertEqual(len(set(text for _, text in seen)), 5)
        spec = bindings.definitions()[('python3', 'scripts/legacy-hash/test-legacy-final-acceptance.py')]
        self.assertIn(output.getvalue().strip(), spec['markers'])
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'compile error')), \
                self.assertRaisesRegex(AssertionError, 'positive control failed'):
            module.run_tests()

    def test_legacy_policy_counts_are_not_inferred_from_a_generic_pass(self):
        script = ROOT / 'scripts/legacy-hash/test-legacy-final-acceptance.py'
        tree = ast.parse(script.read_text())
        initial = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'mutations' for t in n.targets))
        self.assertEqual(len(initial.elts) + len(bindings.GATES) + 4, 43)
        script = ROOT / 'scripts/sp800185/test-portable-acceptance.py'
        tree = ast.parse(script.read_text())
        cases = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'cases' for t in n.targets))
        self.assertEqual(len(cases.elts) + 14 + 1, 28)
