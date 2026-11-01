"""Static compiler-profile registration checks; never invoke a real compiler."""
import ast
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import verification_compiler_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_hosted_tests import HostedBindingTests

ROOT = Path(__file__).resolve().parents[2]


class CompilerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.data = json.loads(bindings.DATA.read_text())
        cls.doc = bindings.build(cls.rows)

    def test_exact_finite_commands_and_inputs_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no verifier execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 28)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check in doc['checks']:
            original = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(check['command'], original['command'])
            self.assertIn('no native backend execution', check['establishes'])

    def test_new_arguments_environment_or_stdin_reject(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for field, value in [('command', row['command'] + ['--write']),
                                 ('environment', {'RUSTFLAGS': 'unreviewed'}), ('stdin', 'unknown')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_mutation_suites_keep_actual_counts_including_mixins(self):
        for path, spec in self.data.items():
            if 'tests' not in spec:
                continue
            tree = ast.parse((ROOT / path).read_text())
            imports = {a.asname or a.name: n.module for n in tree.body
                       if isinstance(n, ast.ImportFrom) for a in n.names}
            methods = []
            for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
                methods += [n.name for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
                for base in cls.bases:
                    if not isinstance(base, ast.Name):
                        continue
                    module = (ROOT / path).parent / (imports[base.id] + '.py')
                    mixin = next(n for n in ast.parse(module.read_text()).body if isinstance(n, ast.ClassDef) and n.name == base.id)
                    self.assertEqual(mixin.bases, [])
                    methods += [n.name for n in mixin.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
            self.assertEqual(len(methods), len(set(methods)))
            self.assertEqual(len(methods), spec['tests'])
            check = next(c for c in self.doc['checks'] if c['command'] == ['python3', path])
            self.assertEqual(check['success'], {'contains': [f'\nRan {len(methods)} tests in '], 'unique_lines': ['OK']})

    def test_helpers_are_closed_under_actual_imports(self):
        # Reuse the static AST closure test, not original checker imports.
        HostedBindingTests.test_shared_imports_are_bound_and_not_discovered_at_runtime(self)

    def test_profile_markers_match_existing_print_statements(self):
        def literal(node, values):
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, ast.Name):
                return values[node.id]
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                return values[node.attr]
            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
                return not literal(node.operand, values)
            if isinstance(node, ast.JoinedStr):
                return ''.join(str(literal(n.value, values)) if isinstance(n, ast.FormattedValue) else n.value for n in node.values)
            raise AssertionError(ast.dump(node))
        for argv, spec in bindings.definitions().items():
            if 'tests' in spec:
                continue
            tree = ast.parse((ROOT / argv[1]).read_text())
            printed = [n.args[0] for n in ast.walk(tree) if isinstance(n, ast.Call)
                       and isinstance(n.func, ast.Name) and n.func.id == 'print' and n.args]
            target = argv[argv.index('--target') + 1] if '--target' in argv else bindings.TARGETS[0]
            transcripts = []
            for compiler in spec['compilers']:
                for panic in ('abort', 'unwind'):
                    values = dict(compiler=compiler, target=target, panic=panic, generic='--generic' in argv,
                                  simd='--simd' in argv, outlined='diagnostic', population='diagnostic')
                    transcripts += [literal(n, values) for n in printed]
            for marker in spec['success']['contains']:
                self.assertEqual(sum(line.startswith(marker) for line in transcripts), 1, (argv, marker))

    def test_scopes_exclude_other_runtime_and_global_lock(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            unrelated = 'brynja-mac-hmac' if check['component'] == 'legacy_hmac' else 'brynja-legacy-hmac'
            self.assertNotIn('crates/' + unrelated + '/src', paths)
            self.assertNotIn('Cargo.lock', paths)
            self.assertFalse(any(p.startswith(('verification/', 'docs/', 'target/')) for p in paths))
            self.assertTrue(all(t['toolchain'] in ('1.90.0', '1.99.1') for g in groups
                                for t in g.get('tools', []) if 'toolchain' in t))
