"""Owner binding regressions using declarations and fake compiler children."""
import ast
import contextlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import verification_owner_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy
from verification_package_tests import covered

ROOT = Path(__file__).resolve().parents[2]


class OwnerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def selected(self, suffix):
        check = next(c for c in self.doc['checks'] if c['command'][1].endswith(suffix))
        return check, [self.doc['groups'][key] for key in check['inputs']]

    def test_six_exact_selectors_without_execution_or_write_options(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no verification')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 6)
        validate_inputs(doc)
        for check in doc['checks']:
            row = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(row['command'], check['command'])
            for field, value in [('command', row['command'] + ['--write']),
                                 ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'extra')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_real_unittest_populations_including_imported_legacy_owners(self):
        for argv, spec in bindings.definitions().items():
            if 'count' not in spec:
                continue
            paths = [argv[1]]
            if argv[1].endswith('test-hmac-owner-contract.py'):
                paths.append('scripts/cryptography/legacy_hmac_owner_tests.py')
            count = sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_')
                        for path in paths for n in ast.walk(ast.parse((ROOT / path).read_text())))
            self.assertEqual(count, spec['count'])
            check, _ = self.selected(argv[1])
            self.assertEqual(check['success']['unique_lines'], ['OK'])

    def test_profile_scope_covers_original_pins_targets_and_new_owner_code(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cryptography'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            model = policy('binding_owner_model', 'scripts/cryptography/api_profile_model.py')
        for suffix in ('check-api-profiles.py', 'test-api-profiles.py', 'test-hmac-owner-contract.py'):
            _, groups = self.selected(suffix)
            for path in model.contracts.REVIEWED_SOURCE_PATHS:
                self.assertTrue(covered(path, groups), (suffix, path))
            for tree in (*model.contracts.hmac_owner_contract.SOURCE_TREES,
                         *model.contracts.hmac_owner_contract.compatibility.SOURCE_TREES):
                self.assertTrue(covered(tree + '/new/nested/owner.rs', groups), tree)
            self.assertFalse(covered('crates/brynja-tls/src/new_aes.rs', groups))
            tools = [t for group in groups for t in group.get('tools', [])]
            self.assertEqual(tools, [{'program': 'python3'}])
        check, groups = self.selected('check-api-profiles.py')
        for path in (model.REGISTER, model.COVERAGE):
            self.assertTrue(covered(path.relative_to(ROOT).as_posix(), groups))
        for suffix in ('test-api-profiles.py', 'test-hmac-owner-contract.py'):
            _, groups = self.selected(suffix)
            self.assertFalse(covered('docs/cryptographic-api-profile-register.md', groups))

    def test_compiler_inventory_toolchains_and_failure_propagation_are_original(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cryptography'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            compiler = policy('binding_owner_compiler', 'scripts/cryptography/secret_owner_compiler.py')
            tests, calls = compiler.compiler_inventory()
            check, groups = self.selected('check-secret-owner-compiler.py')
            self.assertEqual(set(tests), set(calls))
            self.assertEqual(len(tests), 10)
            self.assertTrue(set(tests) <= bindings.COMPILER_PACKAGES)
            tools = {(t['program'], t.get('toolchain')) for g in groups for t in g.get('tools', [])}
            self.assertEqual(tools, {('python3', None), *((p, c) for p in ('cargo', 'rustc') for c in compiler.TOOLCHAINS)})
            output = io.StringIO()
            with patch.object(compiler, 'check_contract_tests') as discover, \
                    patch.object(compiler, 'check_mir') as mir, contextlib.redirect_stdout(output):
                self.assertEqual(compiler.main(), 0)
            self.assertEqual(discover.call_count, 20)
            self.assertEqual(mir.call_count, 20)
            self.assertEqual(output.getvalue().strip(), check['success']['unique_lines'][0])
            for failing in ('check_contract_tests', 'check_mir'):
                output = io.StringIO()
                with patch.object(compiler, 'check_contract_tests'), patch.object(compiler, 'check_mir'), \
                        patch.object(compiler, failing, side_effect=compiler.CompilerContractError('synthetic')), \
                        contextlib.redirect_stdout(output), self.assertRaises(compiler.CompilerContractError):
                    compiler.main()
                self.assertEqual(output.getvalue(), '')
            self.assertFalse(covered(bindings.PROFILE, groups))
            self.assertFalse(covered('docs/VERIFICATION_RESULTS.md', groups))

    def test_compiler_discovery_rejects_zero_missing_and_failed_children(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cryptography'), *sys.path]):
            compiler = policy('binding_owner_discovery', 'scripts/cryptography/secret_owner_compiler.py')
        for status, text in ((0, ''), (0, 'other: test\n'), (1, 'wanted: test\n')):
            with patch.object(compiler, 'command', return_value=SimpleNamespace(returncode=status, stdout=text)), \
                    self.assertRaises(compiler.CompilerContractError):
                compiler.check_contract_tests('1.90.0', 'synthetic', {'wanted'}, Path('/unused'))
        with patch.object(compiler, 'command', return_value=SimpleNamespace(returncode=0, stdout='wanted: test\n')):
            compiler.check_contract_tests('1.90.0', 'synthetic', {'wanted'}, Path('/unused'))

    def test_metadata_only_rows_exclude_rust_implementations_except_wrapper_parity(self):
        for suffix in ('test-legacy-hmac-package.py', 'test-legacy-hmac-hosted-package.py'):
            check, groups = self.selected(suffix)
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertTrue(covered('crates/brynja-legacy-hmac/Cargo.toml', groups))
            self.assertFalse(covered('crates/brynja-legacy-hmac/src/engine.rs', groups))
            self.assertFalse(covered('crates/brynja-hash-sha2/src/compress.rs', groups))
            self.assertFalse(covered('Cargo.lock', groups))
            tree = ast.parse((ROOT / check['command'][1]).read_text())
            commands = [n for n in ast.walk(tree) if isinstance(n, ast.List) and n.elts
                        and isinstance(n.elts[0], ast.Constant) and n.elts[0].value == 'cargo']
            self.assertEqual(len(commands), 1)
            self.assertEqual(ast.literal_eval(commands[0])[:2], ['cargo', 'metadata'])
            self.assertIn('--offline', ast.literal_eval(commands[0]))

    def test_referenced_helper_imports_are_declared(self):
        roots = [ROOT / 'scripts' / p for p in ('cryptography', 'legacy-hmac', 'repository', 'sha2', 'md5', 'sha1')]
        for check in self.doc['checks']:
            groups = [self.doc['groups'][key] for key in check['inputs']]
            spec = bindings.definitions()[tuple(check['command'])]
            if spec['kind'] == 'profile':
                # The other 620 reviewed paths are read as bytes, not imported.
                paths = {check['command'][1], *bindings.PROFILE_HELPERS}
            else:
                paths = {p for group in groups for p in group.get('paths', []) if p.endswith('.py')}
            for path in paths:
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                             else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertTrue(covered(candidate.relative_to(ROOT).as_posix(), groups),
                                                (check['command'], path, name))
