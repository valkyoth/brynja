"""Scope and orchestration tests; all compiler/fixture execution is synthetic."""
from contextlib import nullcontext, redirect_stdout
import ast
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import verification_control_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy

ROOT = Path(__file__).resolve().parents[2]


class ControlBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def test_exact_commands_are_registered_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 2)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for row in (r for r in self.rows if r['id'] in {c['id'] for c in doc['checks']}):
            for field, value in [('command', row['command'] + ['--write']),
                                 ('environment', {'RUSTFLAGS': 'changed'}), ('stdin', 'changed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_populations_include_the_compiled_timing_mixin(self):
        for argv, spec in bindings.definitions().items():
            modules = [argv[1]]
            if argv[1] == bindings.TIMING:
                modules += ['scripts/hmac/hmac_timing_fixture_tests.py']
            count = sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_')
                        for path in modules for n in ast.walk(ast.parse((ROOT / path).read_text())))
            self.assertEqual(count, spec['count'])
            check = next(c for c in self.doc['checks'] if c['command'] == list(argv))
            self.assertIn(f'\nRan {count} tests in ', check['success']['contains'])
            self.assertIn('OK', check['success']['unique_lines'])
        tree = ast.parse((ROOT / 'scripts/hmac/hmac_timing_fixture_tests.py').read_text())
        mutants = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'mutants' for t in n.targets))
        self.assertEqual(len(mutants.elts), 4)
        self.assertIn(bindings.definitions()[('python3', bindings.TIMING)]['marker'],
                      [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)])

    def test_imports_are_explicit_and_closed(self):
        roots = [ROOT / 'scripts' / p for p in ('hmac', 'sha2', 'repository', 'cryptography')]
        for spec in bindings.definitions().values():
            paths = set(spec['helpers'])
            for path in paths:
                tree = ast.parse((ROOT / path).read_text())
                for node in ast.walk(tree):
                    names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                             else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        for root in roots:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertIn(candidate.relative_to(ROOT).as_posix(), paths)

    def test_compiler_and_source_closures_do_not_expand_to_other_families(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', [])}
            self.assertNotIn('Cargo.lock', paths)
            self.assertNotIn('crates/brynja-legacy-hmac/src', paths)
            self.assertFalse(any(p.startswith(('verification/', 'target/')) for p in paths))
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(check['platform'], 'linux-x86_64')
            if check['command'][1] == bindings.CPU:
                self.assertIn('assurance/general-sha512-t/src', paths)
                self.assertIn('assurance/general-sha512-t/profile.rs', paths)
                self.assertIn('crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt', paths)
                self.assertNotIn('crates/brynja-hash-sha3/src', paths)
            else:
                self.assertIn('crates/brynja-mac-hmac/src', paths)
                self.assertIn('assurance/hmac-faults/host_probe.rs', paths)
                self.assertIn('assurance/hmac-timing/Cargo.toml', paths)

    def test_timing_control_compiles_before_rejecting_each_mutant_and_restores(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/hmac'), *sys.path]):
            module = policy('binding_timing_controls', 'scripts/hmac/hmac_timing_fixture_tests.py')
        class Case(module.FixtureTests, unittest.TestCase):
            pass
        original = (ROOT / 'assurance/hmac-timing/src/routes.rs').read_text()
        builds, executions = [], []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / 'fixture/src/routes.rs'

            def build(command, env, fixture):
                self.assertIn('--offline', command)
                self.assertIn('--locked', command)
                self.assertEqual(command[:3], ['cargo', '+1.99.1', 'build'])
                builds.append(path.read_text())
                return ''

            def run(command, **kwargs):
                text = path.read_text()
                self.assertEqual(builds[-1], text, 'must compile each changed source before execution')
                executions.append(text)
                rejected = text != original or command[1:3] != ['portable', 'all']
                return subprocess.CompletedProcess(command, int(rejected),
                    '' if rejected else 'HMAC_TIMING_SMOKE 12 portable all\n',
                    'correctness preflight failed' if rejected else '')

            with patch('subprocess.Popen', side_effect=AssertionError('no real compiler')), \
                    patch.object(module.verifier.cargo_environment, 'private_directory', return_value=nullcontext(raw)), \
                    patch.object(module.verifier, 'environment', return_value={}), \
                    patch.object(module.verifier, 'run', side_effect=build), \
                    patch.object(module.subprocess, 'run', side_effect=run), redirect_stdout(io.StringIO()):
                Case().test_real_compiled_preflight_rejects_vacuous_measurements()
            self.assertEqual(len(builds), 9)  # Baseline; four mutant/restored pairs.
            self.assertEqual(sum(t != original for t in builds), 4)
            self.assertEqual(sum(t != original for t in executions), 4)
            self.assertEqual(path.read_text(), original)
