"""Static migration checks; do not import or run the compiler suites."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_assessment_bindings as assessments
import verification_md5_checker_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class Md5CheckerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        known = bindings.definitions()
        cls.rows = [r for r in rows if tuple(r['command']) in known]
        cls.doc = assessments.build(cls.rows)

    def test_exact_suite_set_is_nonexecuting_and_preserves_catalog_identity(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = assessments.build(self.rows)
        self.assertEqual(len(doc['checks']), 18)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check, row in zip(doc['checks'], self.rows, strict=True):
            self.assertEqual(check['id'], row['id'])
            self.assertEqual(check['command'], row['command'])
            self.assertEqual(check['component'], 'legacy_hmac')
            self.assertIn('not native execution', check['establishes'])
            self.assertEqual(check['platform'], 'linux-x86_64')

    def test_counts_include_all_test_classes_and_disallow_skips(self):
        for check in self.doc['checks']:
            tree = ast.parse((ROOT / check['command'][1]).read_text())
            classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
            self.assertTrue(classes)
            count = 0
            for cls in classes:
                # No imported mixin or inherited test population may be missed.
                self.assertEqual([ast.unparse(base) for base in cls.bases], ['unittest.TestCase'])
                methods = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
                self.assertEqual(len(methods), len({n.name for n in methods}))
                count += len(methods)
            self.assertIn(f'\nRan {count} tests in ', check['success']['contains'])
            self.assertEqual(check['success']['unique_lines'], ['OK'])
            self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr.startswith('skip') for n in ast.walk(tree)))

    def test_compilers_and_fixture_are_explicit_not_whole_workspace(self):
        for check in self.doc['checks']:
            source = (ROOT / check['command'][1]).read_text()
            tree = ast.parse(source)
            compilers = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                         and isinstance(n.value, str) and n.value in ('1.90.0', '1.99.1')}
            groups = [self.doc['groups'][key] for key in check['inputs']]
            self.assertEqual({t['toolchain'] for g in groups for t in g.get('tools', []) if 'toolchain' in t}, compilers)
            paths = {p for g in groups for p in g.get('paths', [])}
            for name in ('brynja-core', 'brynja-hash-core', 'brynja-legacy-md5', 'brynja-legacy-sha1', 'brynja-legacy-hmac'):
                self.assertIn('crates/' + name + '/src', paths)
            self.assertFalse(any('brynja-crypto-cpu' in p or 'brynja-mac-hmac' in p or 'hosted' in p for p in paths))
            self.assertNotIn('Cargo.lock', paths)
            for name in ('Cargo.toml', 'Cargo.lock', 'src'):
                self.assertIn('assurance/' + bindings.FIXTURE + '/' + name, paths)
            self.assertIn('check-legacy-hmac-md5-cleanup.py', source)

    def test_shared_helper_imports_and_source_contracts_are_bound(self):
        check = self.doc['checks'][0]
        paths = {p for key in check['inputs'] for p in self.doc['groups'][key].get('paths', [])}
        roots = [ROOT / 'scripts/legacy-hmac', ROOT / 'scripts/hmac', ROOT / 'scripts/repository']
        for path in sorted(p for p in paths if p.endswith('.py')):
            for node in ast.walk(ast.parse((ROOT / path).read_text())):
                names = []
                if isinstance(node, ast.Import):
                    names = [n.name for n in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                elif isinstance(node, ast.Call) and node.args:
                    function = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', None)
                    arg = node.args[0]
                    if function == 'load' and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        names = [arg.value]
                for name in names:
                    for root in roots:
                        candidate = root / (name + '.py')
                        if candidate.exists():
                            self.assertIn(candidate.relative_to(ROOT).as_posix(), paths, (path, name))
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith('crates/'):
                    self.assertTrue(any(node.value == p or node.value.startswith(p + '/') for p in paths), (path, node.value))

    def test_native_driver_and_unreviewed_selections_are_not_added(self):
        known = bindings.definitions()
        self.assertNotIn(('python3', bindings.DRIVER), known)
        self.assertNotIn(('python3', bindings.DIRECTORY + 'test-legacy-hmac-md5-native.py'), known)
        for row in self.rows:
            for extra in ('--native', '--simd', '--toolchain', 'Subset.test_only_one'):
                with self.assertRaises(ValueError):
                    assessments.build([{**row, 'command': row['command'] + [extra]}])
            with self.assertRaises(ValueError):
                assessments.build([{**row, 'environment': {'RUSTFLAGS': 'unreviewed'}}])

    def test_generated_reports_and_other_suites_are_not_inputs(self):
        for check in self.doc['checks']:
            paths = {p for key in check['inputs'] for p in self.doc['groups'][key].get('paths', [])}
            self.assertEqual({p for p in paths if '/test-' in p}, {check['command'][1]})
            self.assertFalse(any(p.startswith(('verification/', 'docs/', 'target/')) for p in paths))
