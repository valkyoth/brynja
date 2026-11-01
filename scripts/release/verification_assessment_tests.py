"""Static registration tests. No oracle, compiler, sanitizer or proof executes."""
import ast
import copy
import contextlib
import io
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import verification_assessment_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy

ROOT = Path(__file__).resolve().parents[2]


class AssessmentBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_exact_commands_generate_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('must not execute')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 39)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check in doc['checks']:
            original = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(check['command'], original['command'])
            self.assertEqual(check['environment']['PYTHONOPTIMIZE'], '0')
            self.assertEqual(check['category'], 'repository')

    def test_execution_oracle_bindings_keep_population_modes_and_route_checks(self):
        for family in ('kmac', 'tuplehash'):
            script = f'scripts/{family}/check-{family}-execution.py'
            spec = bindings.definitions()[('python3', script)]
            with patch.object(sys, 'path', [str(ROOT / 'scripts' / family), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('no crypto/compiler campaign')):
                module = policy('binding_execution_' + family, script)
                oracle = module.oracle_module()
                # Exercise only case construction, replacing the crypto oracle.
                with patch.object(oracle, 'kmac' if family == 'kmac' else 'tuple_hash', return_value=b'\0'):
                    self.assertEqual(len(oracle.cases()), 256)
                crate = 'brynja-mac-kmac' if family == 'kmac' else 'brynja-hash-tuple'
                official = (ROOT / 'crates' / crate / 'tests/official_vectors.rs').read_text()
                pattern = next(n.value for n in ast.walk(ast.parse((ROOT / script).read_text()))
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith('check_'))
                self.assertEqual(len(re.findall(pattern, official)), 12)
                case = (('kmac128', b'', 0, b'', 0, b'', 0, 8, b'\0') if family == 'kmac'
                        else ('tuple128', b'', 0, [], 8, b'\0'))
                fake = SimpleNamespace(verify_oracle=lambda: None, cases=lambda: [case] * 256)
                def execute(command, env, request=None, success=True):
                    self.assertEqual(command[1], '+1.98.1')
                    self.assertIn('--locked', command)
                    self.assertIn('--offline', command)
                    return SimpleNamespace(stdout='00\n' * 268 if success else '',
                        stderr=family.upper() + '_EXECUTION_ROUTE: Portable')
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(module, 'oracle_module', return_value=fake))
                    stack.enter_context(patch.object(module, 'official', return_value=[case] * 12))
                    stack.enter_context(patch.object(module, 'execute', side_effect=execute))
                    if family == 'kmac':
                        production = stack.enter_context(patch.object(module.kmac_production_oracle, 'campaign'))
                    for mode, marker in zip(('portable', 'prefer-portable'), spec['markers']):
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            module.campaign(mode)
                        self.assertEqual(output.getvalue().strip(), marker)
                    if family == 'kmac':
                        self.assertEqual(production.call_count, 2)
                    for output, route in [('00\n' * 267, family.upper() + '_EXECUTION_ROUTE: Portable'),
                                          ('00\n' * 268, ''), ('ff\n' * 268, family.upper() + '_EXECUTION_ROUTE: Portable')]:
                        with patch.object(module, 'execute', return_value=SimpleNamespace(stdout=output, stderr=route)):
                            with self.assertRaises(RuntimeError):
                                module.campaign('portable')

    def test_unreviewed_scope_or_mutating_options_are_rejected(self):
        selected = {tuple(c['command']) for c in self.doc['checks']}
        for row in self.rows:
            if tuple(row['command']) not in selected:
                continue
            for flag in ('--write', '--native', '--static', '--toolchain'):
                changed = {**row, 'command': row['command'] + [flag]}
                with self.assertRaises(ValueError):
                    bindings.build([changed])
            for field, value in [('environment', {'RUSTFLAGS': 'unreviewed'}), ('stdin', 'unknown')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])
        row = copy.deepcopy(next(r for r in self.rows if '--policy-only' in r['command'] and '/hmac/' in r['command'][1]))
        row['command'].remove('--policy-only')
        with self.assertRaises(ValueError):
            bindings.build([row])

    def test_inventory_and_mocked_checks_never_require_crypto_toolchains(self):
        for check in self.doc['checks']:
            if not ('--policy-only' in check['command'] or check['command'][1].endswith('test-keccak-batch-asan.py')):
                continue
            groups = [self.doc['groups'][k] for k in check['inputs']]
            self.assertFalse(any(g.get('locks') for g in groups))
            self.assertEqual({t['program'] for g in groups for t in g.get('tools', [])}, {'python3'})
            self.assertFalse(any(p.startswith('crates/') and '/src' in p for g in groups for p in g.get('paths', [])))
            if '--policy-only' in check['command']:
                self.assertIn('NOT executed', check['success']['unique_lines'][0])

    def test_existing_unittest_counts_and_no_skip_signal(self):
        tests = [c for c in self.doc['checks'] if '/test-' in c['command'][1]
                 and '-engine-cleanup.py' not in c['command'][1]]
        self.assertEqual(len(tests), 21)
        for check in tests:
            tree = ast.parse((ROOT / check['command'][1]).read_text())
            count = sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in ast.walk(tree))
            self.assertIn(f'\nRan {count} tests in ', check['success']['contains'])
            self.assertIn('OK', check['success']['unique_lines'])
            self.assertNotIn('OK (skipped=', check['success']['unique_lines'])

    def test_parallelhash_requires_every_existing_mode_and_no_native_claim(self):
        check = next(c for c in self.doc['checks'] if c['component'] == 'parallelhash')
        source = (ROOT / check['command'][1]).read_text()
        assignment = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == 'modes' for t in n.targets))
        self.assertEqual(tuple(ast.literal_eval(assignment.value)), bindings.MODES)
        markers = check['success']['unique_lines']
        self.assertEqual(len(markers), 16)
        self.assertEqual(sum('profile=debug' in m for m in markers), 7)
        self.assertEqual(sum('profile=release' in m for m in markers), 7)
        self.assertTrue(all('cases=256' in m for m in markers[:14]))
        self.assertTrue(all('NOT REQUESTED' in m for m in markers[-2:]))
        paths = {p for key in check['inputs'] for p in self.doc['groups'][key].get('paths', [])}
        self.assertTrue(set(bindings.CSHAKE) <= paths)
        self.assertIn('crates/brynja-hash-parallel-std/src', paths)
        self.assertIn('crates/brynja-crypto-cpu/src', paths)

    def test_scratch_profiles_and_external_runtime_sources_are_bound(self):
        for check in self.doc['checks']:
            spec = bindings.definitions()[tuple(check['command'])]
            if spec.get('fixture') not in ('hmac-cleanup', 'legacy-hmac-cleanup'):
                continue
            groups = [self.doc['groups'][key] for key in check['inputs']]
            self.assertEqual({t['toolchain'] for g in groups for t in g.get('tools', []) if 'toolchain' in t}, set(spec['compilers']))
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertFalse(any('brynja-crypto-cpu' in p for p in paths))
            self.assertIn('scripts/repository/facade_cargo_environment.py', paths)
            fixture = ROOT / ('assurance/' + spec['fixture'] + '/src/lib.rs')
            for relative in re.findall(r'#\[path = "([^"]+)"\]', fixture.read_text()):
                self.assertIn((fixture.parent / relative).resolve().relative_to(ROOT).as_posix(), paths)
            markers = [m for m in check['success']['unique_lines'] if 'cleanup: PASS' in m]
            expected = 1 if '/test-' in check['command'][1] else 2 * len(spec['compilers'])
            self.assertEqual(len(markers), expected)
            for compiler in spec['compilers']:
                self.assertTrue(any(compiler in m for m in markers))

    def test_vector_reproduction_only_tracks_oracle_and_stored_vectors(self):
        check = next(c for c in self.doc['checks'] if c['command'][1].endswith('cshake_execution_vectors.py'))
        groups = [self.doc['groups'][key] for key in check['inputs']]
        paths = {p for g in groups for p in g.get('paths', [])}
        self.assertEqual(paths, {check['command'][1], *bindings.CSHAKE,
                                'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt'})
        lines = (ROOT / 'crates/brynja-hash-sha3/tests/vectors/cshake-execution.txt').read_text().splitlines()
        self.assertEqual(sum(bool(line) and not line.startswith('#') for line in lines), 628)
        self.assertFalse(any(g.get('locks') or g.get('toml') for g in groups))
        self.assertEqual({t['program'] for g in groups for t in g.get('tools', [])}, {'python3'})
