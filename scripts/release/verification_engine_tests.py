"""Static binding regressions; never import/execute the compiler checkers."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_assessment_bindings as assessments
import verification_engine_bindings as engines

ROOT = Path(__file__).resolve().parents[2]


def methods(path):
    return {n.name for n in ast.walk(ast.parse((ROOT / path).read_text()))
            if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')}


class EngineBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        known = engines.definitions()
        with patch('subprocess.Popen', side_effect=AssertionError('must not execute')):
            cls.doc = assessments.build([r for r in rows if tuple(r['command']) in known])

    def test_exact_engine_commands_and_runtime_dependency_scope(self):
        self.assertEqual(len(self.doc['checks']), 7)
        self.assertEqual({tuple(c['command']) for c in self.doc['checks']}, set(engines.definitions()))
        for check in self.doc['checks']:
            groups = [self.doc['groups'][key] for key in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertFalse(any('brynja-crypto-cpu' in p or 'hosted' in p for p in paths))
            modern = check['component'] == 'hmac'
            leaf = 'brynja-mac-hmac' if modern else 'brynja-legacy-hmac'
            hashes = ('sha2', 'sha3') if modern else ('md5', 'sha1')
            self.assertIn('crates/' + leaf + '/src', paths)
            for name in hashes:
                package = 'brynja-hash-' + name if modern else 'brynja-legacy-' + name
                self.assertIn('crates/' + package + '/src', paths)
            self.assertIn('scripts/repository/facade_cargo_environment.py', paths)
            self.assertNotIn('Cargo.lock', paths)
            self.assertEqual(check['platform'], 'linux-x86_64')

    def test_compiler_and_panic_completion_lines_match_actual_driver(self):
        for check in self.doc['checks']:
            spec = engines.definitions()[tuple(check['command'])]
            script = check['command'][1].replace('/test-', '/check-')
            tree = ast.parse((ROOT / script).read_text())
            collect = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'collect')
            printed = next(n.value.args[0] for n in collect.body if isinstance(n, ast.Expr)
                           and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                           and n.value.func.id == 'print')
            argv = check['command']
            target = argv[argv.index('--target') + 1] if '--target' in argv else 'x86_64-unknown-linux-gnu'
            is_test = '/test-' in argv[1]
            panics = ('unwind',) if is_test else ('abort', 'unwind')
            expected = []
            for compiler in spec['compilers']:
                for panic in panics:
                    values = dict(compiler=compiler, target=target, panic=panic)
                    expected.append(''.join(n.value if isinstance(n, ast.Constant)
                                            else values[n.value.id] for n in printed.values))
            actual = [line for line in check['success']['unique_lines'] if line != 'OK']
            self.assertEqual(actual, expected)
            tools = [t for k in check['inputs'] for t in self.doc['groups'][k].get('tools', [])]
            self.assertEqual({t['toolchain'] for t in tools if 'toolchain' in t}, set(spec['compilers']))

    def test_unittest_population_includes_inherited_constructor_cases(self):
        for check in self.doc['checks']:
            script = check['command'][1]
            if '/test-' not in script:
                continue
            names = methods(script)
            if check['component'] == 'hmac':
                inherited = methods('scripts/hmac/hmac_constructor_tests.py')
                self.assertEqual(len(inherited), 8)
                self.assertFalse(names & inherited)
                names |= inherited
            count = 27 if check['component'] == 'hmac' else 9
            self.assertEqual(len(names), count)
            self.assertIn(f'\nRan {count} tests in ', check['success']['contains'])
            self.assertIn('OK', check['success']['unique_lines'])

    def test_shared_checker_imports_are_in_the_declared_inputs(self):
        # Check only these known helpers, not a general dependency resolver.
        roots = [ROOT / 'scripts/hmac', ROOT / 'scripts/legacy-hmac', ROOT / 'scripts/repository']
        for check in self.doc['checks']:
            paths = {p for key in check['inputs'] for p in self.doc['groups'][key].get('paths', [])}
            for path in sorted(p for p in paths if p.endswith('.py')):
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [n.name for n in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module]
                    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                          and node.func.attr == 'load' and node.args and isinstance(node.args[0], ast.Constant)
                          and isinstance(node.args[0].value, str) and node.args[0].value.startswith('hmac_')):
                        names = [node.args[0].value]
                    for name in names:
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertIn(candidate.relative_to(ROOT).as_posix(), paths, (path, name))

    def test_mutation_fixtures_preserve_raw_toml_and_lock_inputs(self):
        for check in self.doc['checks']:
            if '/test-' not in check['command'][1]:
                continue
            spec = engines.definitions()[tuple(check['command'])]
            paths = {p for k in check['inputs'] for p in self.doc['groups'][k].get('paths', [])}
            for filename in ('Cargo.toml', 'Cargo.lock', 'src'):
                self.assertIn('assurance/' + spec['fixture'] + '/' + filename, paths)
