"""Binding regressions: inspect original definitions, never execute the checks."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import verification_legacy_policy_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


def policy(name, path):
    # These reviewed modules define constants/functions only. Do not call their
    # validate/main routines, which would rerun the original assessment.
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assignment(path, name):
    tree = ast.parse((ROOT / path).read_text())
    return next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))


class LegacyPolicyBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)
        cls.data = json.loads(bindings.DATA.read_text())

    def test_eleven_selectors_are_preserved_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 11)
        validate_inputs(doc)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        for c in doc['checks']:
            row = next(r for r in self.rows if r['id'] == c['id'])
            self.assertEqual(c['command'], row['command'])

    def test_write_flags_and_unknown_configuration_are_rejected(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for key, value in [('command', row['command'] + ['--write']),
                               ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, key: value}])

    def test_original_inventory_paths_and_addition_sensitive_directories(self):
        declarations = [
            ('md5', 'scripts/md5/md5_policy.py', 'BOUND'),
            ('sha1', 'scripts/sha1/sha1_policy.py', 'BOUND'),
            ('md5-cpu', 'scripts/md5/md5_cpu_policy.py', 'BOUND'),
            ('sha1-cpu', 'scripts/sha1/cpu_policy.py', 'BOUND'),
            ('sha512-t-contract', 'scripts/sha2/sha512_t_contract.py', 'BOUND'),
            ('md5-execution', 'scripts/md5/md5_execution_policy.py', 'paths'),
            ('acceleration-availability', 'scripts/cpu/acceleration_availability.py', 'paths'),
        ]
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            for key, script, field in declarations:
                p = policy('binding_' + key.replace('-', '_'), script)
                names = getattr(p, field)
                if callable(names):
                    names = names(ROOT)  # Source enumeration only, not validate.
                paths = self.data[key]['paths']
                for name in names:
                    self.assertTrue(any(name == s or name.startswith(s + '/') for s in paths), (key, name))
                self.assertIn(script, paths)
                self.assertNotIn('Cargo.lock', paths)
                self.assertFalse(any(s.startswith(('verification/', 'target/')) for s in paths))
        for key, directory in [('md5', 'crates/brynja-legacy-md5/src'),
                               ('sha1', 'crates/brynja-legacy-sha1/src'),
                               ('md5-cpu', 'crates/brynja-legacy-md5/src/cpu'),
                               ('md5-cpu', 'crates/brynja-legacy-md5/src/batch'),
                               ('sha1-cpu', 'crates/brynja-legacy-sha1/src/cpu')]:
            self.assertIn(directory, self.data[key]['paths'])

    def test_original_mutation_counts_and_contract_population(self):
        for family in ('md5', 'sha1'):
            p = policy('binding_' + family, f'scripts/{family}/{family}_policy.py')
            initial = assignment(f'scripts/{family}/test-{family}.py', 'mutations')
            self.assertEqual(len(initial.left.elts) + len(p.REGIONS) + len(p.TOKENS['hardened_in_place.rs']) + 5, 56)
        self.assertEqual(len(assignment('scripts/md5/test-md5-cpu.py', 'CASES').elts), 36)
        self.assertEqual(len(assignment('scripts/sha1/test-sha1-cpu.py', 'cases').elts) + 6, 60)
        p = policy('binding_md5_execution', 'scripts/md5/md5_execution_policy.py')
        self.assertEqual(sum(map(len, p.GATES.values())) + sum(map(len, p.CHECKS.values())), 64)
        tree = ast.parse((ROOT / 'scripts/sha2/test-sha512-t-contract.py').read_text())
        self.assertEqual(sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in ast.walk(tree)), 7)

    def test_compilation_and_source_only_scopes_are_distinct(self):
        for c in self.doc['checks']:
            key, _, mode = bindings.definitions()[tuple(c['command'])]
            groups = [self.doc['groups'][k] for k in c['inputs']]
            tools = [t for g in groups for t in g.get('tools', [])]
            if mode == 'model-mutants':
                self.assertEqual({t['program'] for t in tools}, {'python3', 'cargo', 'rustc', 'clippy-driver'})
                self.assertEqual(c['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
                self.assertEqual(c['environment']['CARGO_NET_OFFLINE'], 'true')
                self.assertNotIn('exact_tests', c['success'])  # Child output is captured, not streamed.
                self.assertEqual(len(c['success']['unique_lines']), 2)
                continue
            if mode != 'compiled':
                self.assertEqual(tools, [{'program': 'python3'}])
                continue
            self.assertEqual(c['success']['exact_tests'], 2)
            self.assertEqual(c['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertEqual(c['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual({t['toolchain'] for t in tools if 'toolchain' in t}, {'1.99.1'})
            locks = {p for g in groups for lock in g.get('locks', []) for p in lock['packages']}
            self.assertEqual(locks, {'brynja-core', 'brynja-hash-core', 'brynja-legacy-' + key})
            tree = ast.parse((ROOT / c['command'][1]).read_text())
            literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)]
            self.assertIn('--release', literals)
            self.assertIn('invalid_', literals)

    def acceleration_driver(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cpu'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')):
            return policy('binding_acceleration_mutants', 'scripts/cpu/test-acceleration-availability.py')

    def test_acceleration_mutation_counts_match_the_original_driver(self):
        tree = ast.parse((ROOT / 'scripts/cpu/test-acceleration-availability.py').read_text())
        counts = {}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.endswith('_mutations'):
                mutations = next(n.value for n in ast.walk(node) if isinstance(n, ast.Assign)
                                 and any(isinstance(t, ast.Name) and t.id == 'mutations' for t in n.targets))
                counts[node.name] = len(mutations.keys if isinstance(mutations, ast.Dict) else mutations.elts)
        self.assertEqual(counts, {'policy_mutations': 18, 'compiled_mutations': 9,
                                 'gate_mutations': 6, 'lint_mutations': 5})

    def test_acceleration_compiler_orchestration_uses_positive_and_negative_controls(self):
        driver = self.acceleration_driver()
        original = (ROOT / driver.contract.FIXTURE / 'src/selection.rs').read_text()
        calls = []

        def fake(argv, root):
            calls.append(argv)
            changed = (root / 'src/selection.rs').read_text() != original
            failed = changed and '--no-run' not in argv
            return subprocess.CompletedProcess(argv, int(failed), 'test result: FAILED' if failed else '', '')

        with patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')), \
                patch.object(driver, 'run', side_effect=fake):
            self.assertEqual(driver.compiled_mutations(), 18)
        self.assertEqual(len(calls), 38)  # Two positives, eighteen compile/run pairs.
        for start in (0, 19):
            self.assertNotIn('--no-run', calls[start])
            for index in range(start + 1, start + 19, 2):
                self.assertEqual(calls[index], calls[index + 1] + ['--no-run'])
        self.assertTrue(all('--release' not in c for c in calls[:19]))
        self.assertTrue(all('--release' in c for c in calls[19:]))

    def test_acceleration_cannot_accept_a_surviving_or_uncompiled_mutant(self):
        driver = self.acceleration_driver()
        for compile_error in (False, True):
            def fake(argv, root):
                return subprocess.CompletedProcess(argv, int(compile_error and '--no-run' in argv), '', '')
            with patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')), \
                    patch.object(driver, 'run', side_effect=fake), self.assertRaises(AssertionError):
                driver.compiled_mutations()

    def test_acceleration_lint_checks_require_the_specific_error(self):
        driver = self.acceleration_driver()
        lints = iter(('panic', 'unwrap_used', 'expect_used', 'indexing_slicing', 'arithmetic_side_effects'))
        calls = []

        def fake(argv, root):
            calls.append(argv)
            if len(calls) == 1 or argv[1] == 'check':
                return subprocess.CompletedProcess(argv, 0, '', '')
            output = json.dumps({'message': {'level': 'error', 'code': {'code': 'clippy::' + next(lints)}}})
            return subprocess.CompletedProcess(argv, 1, output, '')

        with patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')), \
                patch.object(driver, 'run', side_effect=fake):
            self.assertEqual(driver.lint_mutations(), 5)
        self.assertEqual([c[1] for c in calls], ['clippy'] + ['check', 'clippy'] * 5)
        calls.clear()

        def wrong_error(argv, root):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, int(len(calls) > 2), '{}', '')

        with patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')), \
                patch.object(driver, 'run', side_effect=wrong_error), self.assertRaises(AssertionError):
            driver.lint_mutations()
