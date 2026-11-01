"""Static hosted binding regressions; no compiler or checker import/execution."""
import ast
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_hosted_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class HostedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.data = json.loads(bindings.DATA.read_text())
        cls.doc = bindings.build(cls.rows)

    def test_exact_selections_do_not_execute_or_expand(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no discovery/execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 59)
        expected = {s['id']: s['command'] for d in self.data.values() for s in d['selections']}
        self.assertEqual({c['id']: c['command'] for c in doc['checks']}, expected)
        validate_inputs(doc)
        self.assertEqual(sum(len(c['command']) - 2 for c in doc['checks']), 171)

    def test_selected_methods_resolve_through_real_mixins_without_duplicates(self):
        for family, definition in self.data.items():
            script = definition['selections'][0]['command'][1]
            tree = ast.parse((ROOT / script).read_text())
            imports = {alias.asname or alias.name: node.module for node in tree.body
                       if isinstance(node, ast.ImportFrom) for alias in node.names}
            cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
            methods = [n.name for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
            for base in cls.bases:
                if not isinstance(base, ast.Name):
                    continue  # unittest.TestCase
                module = (ROOT / script).parent / (imports[base.id] + '.py')
                source = ast.parse(module.read_text())
                mixin = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == base.id)
                self.assertEqual(mixin.bases, [])
                methods += [n.name for n in mixin.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
            self.assertEqual(len(methods), len(set(methods)))
            selected = [arg.split('.')[1] for s in definition['selections'] for arg in s['command'][2:]]
            self.assertEqual(len(selected), len(set(selected)))
            self.assertEqual(set(selected), set(methods), family)

    def test_unreviewed_arguments_identity_environment_and_stdin_reject(self):
        ids = {c['id'] for c in self.doc['checks']}
        for original in (r for r in self.rows if r['id'] in ids):
            for field, value in [('id', 'unreviewed'), ('environment', {'RUSTFLAGS': 'unsafe'}),
                                 ('stdin', 'unknown'), ('command', original['command'][:2]),
                                 ('command', original['command'] + ['--write'])]:
                row = copy.deepcopy(original)
                row[field] = value
                with self.assertRaises(ValueError):
                    bindings.build([row])

    def test_exact_counts_demangler_and_compilers(self):
        for check in self.doc['checks']:
            count = len(check['command']) - 2
            self.assertIn(f'\nRan {count} ' + ('test' if count == 1 else 'tests') + ' in ', check['success']['contains'])
            self.assertEqual(check['success']['unique_lines'], ['OK'])
            groups = [self.doc['groups'][k] for k in check['inputs']]
            tools = [t for g in groups for t in g.get('tools', [])]
            self.assertIn({'program': 'c++filt'}, tools)
            self.assertIn({'program': 'llvm-cxxfilt', 'optional': True}, tools)
            expected = {'1.99.1'}
            if check['component'] == 'legacy_hmac' or any('.test_msrv_' in x for x in check['command'][2:]):
                expected.add('1.90.0')
            self.assertEqual({t['toolchain'] for t in tools if 'toolchain' in t}, expected)

    def test_shared_imports_are_bound_and_not_discovered_at_runtime(self):
        roots = [ROOT / 'scripts' / p for p in ('hmac', 'legacy-hmac', 'repository', 'cryptography')]
        for definition in self.data.values():
            paths = set(definition['helpers'])
            for path in paths:
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module]
                    elif isinstance(node, ast.Call) and node.args:
                        function = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', None)
                        value = node.args[0]
                        if function == 'load' and isinstance(value, ast.Constant) and isinstance(value.value, str):
                            names = [value.value]
                        if function == 'with_name' and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.endswith('.py'):
                            candidate = Path(path).parent / value.value
                            if (ROOT / candidate).exists():
                                self.assertIn(candidate.as_posix(), paths)
                    for name in names:
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertIn(candidate.relative_to(ROOT).as_posix(), paths, (path, name))

    def test_fixture_dependency_graph_and_mutation_metadata_scopes(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertIn('crates/brynja-crypto-cpu-std/src', paths)
            self.assertIn('crates/brynja-crypto-cpu/src', paths)
            if check['component'] == 'hmac':
                self.assertNotIn('crates/brynja-legacy-hmac/src', paths)
                self.assertIn('crates/brynja-mac-hmac/Cargo.toml', paths)
            else:
                self.assertNotIn('crates/brynja-mac-hmac/src', paths)
                self.assertIn('crates/brynja-legacy-hmac-std/Cargo.toml', paths)
            self.assertNotIn('Cargo.lock', paths)
            self.assertFalse(any(p.startswith(('verification/', 'docs/', 'target/')) for p in paths))
