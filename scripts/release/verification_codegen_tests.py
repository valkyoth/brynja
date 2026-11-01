"""Static leaf codegen registration tests; no compiler invocation."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_codegen_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class CodegenBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)
        cls.helpers = json.loads(bindings.DATA.read_text())

    def test_finite_commands_and_source_inputs_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no compiler execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 12)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check in doc['checks']:
            self.assertEqual(check['command'], next(r['command'] for r in self.rows if r['id'] == check['id']))
            self.assertEqual(check['success']['contains'], check['success']['unique_lines'])
            self.assertIn('not a native test', check['establishes'])

    def test_original_profiles_cannot_be_silently_changed(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for field, value in [('command', row['command'] + ['--native']),
                                 ('environment', {'RUSTFLAGS': 'unreviewed'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])
        for check in self.doc['checks']:
            _, versions, _, markers = bindings.definitions()[tuple(check['command'])]
            tools = [t for k in check['inputs'] for t in self.doc['groups'][k].get('tools', [])]
            self.assertEqual({t['toolchain'] for t in tools if 'toolchain' in t}, set(versions))
            self.assertTrue(all(any(v in m for m in markers) for v in versions))

    def test_imported_helpers_and_no_global_lock_or_unrelated_source(self):
        for script, helpers in self.helpers.items():
            paths = set(helpers)
            roots = [(ROOT / script).parent, ROOT / 'scripts/cryptography', ROOT / 'assurance/register-cleanup']
            for path in helpers:
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                             else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertIn(candidate.relative_to(ROOT).as_posix(), paths)
        for check in self.doc['checks']:
            paths = {p for k in check['inputs'] for p in self.doc['groups'][k].get('paths', [])}
            self.assertNotIn('Cargo.lock', paths)
            self.assertNotIn('crates/brynja-mac-hmac/src', paths)
            self.assertNotIn('crates/brynja-legacy-hmac/src', paths)
            if check['component'] in ('md5', 'sha1'):
                self.assertNotIn('crates/brynja-crypto-cpu-std/src', paths)
            self.assertFalse(any(p.startswith(('verification/', 'target/', 'docs/')) for p in paths))

    def test_markers_match_prints_in_bound_helpers(self):
        # Inspect only syntax: never import checkers or execute their assertions.
        def render(node, values):
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, ast.Name):
                return values[node.id]
            if isinstance(node, ast.Attribute):
                return values[node.attr]
            if isinstance(node, ast.JoinedStr):
                return ''.join(str(render(n.value, values)) if isinstance(n, ast.FormattedValue) else n.value for n in node.values)
            raise KeyError('not a literal diagnostic')
        for argv, (_, versions, _, markers) in bindings.definitions().items():
            printed = []
            for path in self.helpers[argv[1]]:
                printed += [n.args[0] for n in ast.walk(ast.parse((ROOT / path).read_text()))
                            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'print' and n.args]
            rendered = set()
            for version in versions:
                for target in (bindings.HOST, bindings.ARM):
                    for panic in ('abort', 'unwind'):
                        for node in printed:
                            try:
                                rendered.add(render(node, dict(compiler=version, toolchain=version, target=target, panic=panic)))
                            except KeyError:
                                pass
            self.assertTrue(set(markers) <= rendered, (argv, set(markers) - rendered))
