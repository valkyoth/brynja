"""Source-policy binding tests, separate from release-policy regressions."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_policy_bindings as bindings
from verification_additional_tests import validate_inputs

ROOT = Path(__file__).resolve().parents[2]


class PolicyBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_thirteen_commands_are_bound_without_running_or_importing_checkers(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 13)
        validate_inputs(doc)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        for c in doc['checks']:
            r = next(r for r in self.rows if r['id'] == c['id'])
            self.assertEqual(c['command'], r['command'])
            for field, value in [('command', r['command'] + ['--write']), ('stdin', 'unreviewed'),
                                 ('environment', {'PYTHONOPTIMIZE': '1'})]:
                with self.assertRaises(ValueError):
                    bindings.build([{**r, field: value}])

    def test_bound_imports_and_literal_path_references(self):
        # Inspect syntax only. Read-only policy files can refer to scripts as
        # data without importing/executing those scripts' dependency closures.
        for c in self.doc['checks']:
            paths = {p for k in c['inputs'] for p in self.doc['groups'][k].get('paths', [])}
            directory = (ROOT / c['command'][1]).parent
            for script in [c['command'][1], *[p for p in paths if p.endswith('_policy.py')]]:
                for n in ast.walk(ast.parse((ROOT / script).read_text())):
                    names = ([a.name for a in n.names] if isinstance(n, ast.Import)
                             else [n.module] if isinstance(n, ast.ImportFrom) and n.module else [])
                    for name in names:
                        helper = directory / (name + '.py')
                        if helper.exists():
                            self.assertIn(helper.relative_to(ROOT).as_posix(), paths)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'Path' and n.args:
                        arg = n.args[0]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and (ROOT / arg.value).is_file():
                            self.assertTrue(any(arg.value == p or arg.value.startswith(p + '/') for p in paths), (script, arg.value))
            self.assertNotIn('Cargo.lock', paths)
            self.assertNotIn('verification/results.json', paths)
            self.assertNotIn('docs/VERIFICATION_RESULTS.md', paths)

    def test_completion_markers_follow_existing_prints(self):
        for c in self.doc['checks']:
            tree = ast.parse((ROOT / c['command'][1]).read_text())
            literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            for marker in c['success']['unique_lines']:
                if marker in literals:
                    continue
                self.assertTrue(marker.startswith(('KMAC execution policy rejects 98 ',
                    'TupleHash execution policy rejects 148 ', 'Scoped TupleHash policy rejects 110 ',
                    'Borrowed ParallelHash framing/leaf policy rejects 227 ', 'Scoped thread handoff rejects 91 ')), marker)
