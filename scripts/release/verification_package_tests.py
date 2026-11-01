"""Static scope and mocked package-harness checks, never cryptographic runs."""
import ast
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import verification_package_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy

ROOT = Path(__file__).resolve().parents[2]


def covered(name, groups):
    paths = [p for g in groups for p in g.get('paths', [])]
    patterns = [p for g in groups for p in g.get('patterns', [])]
    return any(name == p or name.startswith(p + '/') for p in paths) or any(
        ROOT / name in ROOT.glob(p) for p in patterns)


class PackageBindingTests(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        with patch('subprocess.Popen', side_effect=AssertionError('no campaign')):
            self.doc = bindings.build(self.rows)

    def test_seventeen_exact_default_commands_and_no_native_flag_expansion(self):
        self.assertEqual(len(self.doc['checks']), 17)
        validate_inputs(self.doc)
        for check in self.doc['checks']:
            self.assertEqual(check['platform'], 'linux-x86_64')
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertTrue(check['success']['unique_lines'])
            row = next(r for r in self.rows if r['id'] == check['id'])
            for key, value in [('command', row['command'] + ['--native']),
                               ('environment', {'RUSTFLAGS': '-Ctarget-cpu=native'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, key: value}])

    def test_package_closures_and_selected_lock_rows_not_whole_workspace(self):
        for check in self.doc['checks']:
            spec = bindings.definitions()[tuple(check['command'])]
            groups = [self.doc['groups'][k] for k in check['inputs']]
            locks = {p for g in groups for lock in g.get('locks', []) for p in lock['packages']}
            self.assertEqual(locks, spec['packages'])
            self.assertTrue(all(covered('crates/' + p + '/Cargo.toml', groups) for p in locks))
            self.assertFalse(covered('crates/unrelated-aes/src/lib.rs', groups))
            self.assertFalse(covered('verification/results.json', groups))
            self.assertFalse(covered('docs/VERIFICATION_RESULTS.md', groups))
            if not spec['policy']:
                self.assertFalse(covered('Cargo.lock', groups))
                self.assertFalse(covered('Cargo.toml', groups))
            toolchains = {t['toolchain'] for g in groups for t in g.get('tools', []) if 'toolchain' in t}
            self.assertEqual(toolchains, {spec['compiler']})
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], spec['compiler'])

    def test_original_review_and_batch_policy_inputs_are_covered(self):
        for check in self.doc['checks']:
            argv = tuple(check['command'])
            groups = [self.doc['groups'][k] for k in check['inputs']]
            if argv[1] in ('scripts/sha2/check-sha2-execution.py', 'scripts/sha3/check-sha3-execution.py'):
                review = ROOT / argv[1].replace('check-', '').replace('.py', '-reviewed.toml')
                for name in tomllib.loads(review.read_text())['files']:
                    self.assertTrue(covered(name, groups), name)
            spec = bindings.definitions()[argv]
            if spec['policy']:
                family = 'sha3' if 'keccak' in argv[1] else 'sha2'
                stem = 'keccak' if family == 'sha3' else ('sha256' if 'sha256' in argv[1] else 'sha512')
                with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
                    module = policy('binding_package_' + stem, f'scripts/{family}/{stem}_batch_policy.py')
                    for name in module.paths(ROOT):
                        self.assertTrue(covered(name, groups), name)

    def test_copied_fixture_external_inputs_are_covered(self):
        for check in self.doc['checks']:
            spec = bindings.definitions()[tuple(check['command'])]
            groups = [self.doc['groups'][k] for k in check['inputs']]
            for fixture in spec['fixtures']:
                for source in (ROOT / 'assurance' / fixture).rglob('*.rs'):
                    if 'target' in source.parts:
                        continue
                    for name in re.findall(r'(?:include(?:_str|_bytes)?!\(\s*|#\[path\s*=\s*)"([^"]+)"', source.read_text()):
                        target = (source.parent / name).resolve().relative_to(ROOT).as_posix()
                        self.assertTrue(covered(target, groups), (check['id'], target))

    def test_public_api_policy_and_packaging_lists_match_declared_closures(self):
        for family, stem in [('sha2', 'sha256'), ('sha2', 'sha2'), ('sha3', 'sha3')]:
            with patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
                module = policy('binding_public_' + stem, f'scripts/{family}/{stem}_public_api.py')
            expected = {p[0] for p in module.PACKAGING_PACKAGES}
            for mode in ('check', 'test'):
                argv = ('python3', f'scripts/{family}/{mode}-{stem}-public-api.py')
                spec = bindings.definitions()[argv]
                if stem == 'sha256' and mode == 'test':
                    self.assertEqual(spec['packages'], set(bindings.FACADE_PACKAGES))
                else:
                    self.assertEqual(spec['packages'], expected)
                check = next(c for c in self.doc['checks'] if tuple(c['command']) == argv)
                groups = [self.doc['groups'][k] for k in check['inputs']]
                for path in module.FILES:
                    self.assertTrue(covered(str(path), groups), str(path))
                source = ast.parse((ROOT / argv[1]).read_text())
                literals = {n.value for n in ast.walk(source) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
                self.assertIn(spec['markers'][0], literals)

    def test_original_ownership_probes_with_fake_compiler_keep_exact_populations(self):
        # Invoke only the existing negative-source generators. Every compiler
        # result is synthetic; missing diagnostics must still be rejected.
        for family in ('kmac', 'tuplehash'):
            path = f'scripts/{family}/check-{family}-execution-package.py'
            with patch.object(sys, 'path', [str(ROOT / 'scripts' / family), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
                module = policy('binding_package_' + family, path)
                with tempfile.TemporaryDirectory() as temporary:
                    consumer = Path(temporary)
                    (consumer / 'src').mkdir()
                    source = consumer / 'src/main.rs'
                    source.write_text('fn main() {}')
                    fake = SimpleNamespace(stderr=' '.join(f'error[{code}]' for code in
                        ('E0277', 'E0382', 'E0499', 'E0308', 'E0061', 'E0500', 'E0599', 'E0515')))
                    with patch.object(module.shared, 'run', return_value=fake) as calls, \
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        module.negatives(consumer, {})
                    self.assertEqual(source.read_text(), 'fn main() {}')
                    expected = f'Packaged {"KMAC" if family == "kmac" else "TupleHash"} execution ownership: PASS; rejected={calls.call_count}'
                    self.assertIn(expected, bindings.definitions()[('python3', path)]['markers'])
                    self.assertEqual(output.getvalue().strip(), expected)
                    with patch.object(module.shared, 'run', return_value=SimpleNamespace(stderr='')):
                        with self.assertRaises(ValueError):
                            module.negatives(consumer, {})
                    self.assertEqual(source.read_text(), 'fn main() {}')

    def test_static_mutation_counts_and_parallel_ownership_match_original_generators(self):
        for family, function, prefix in [
            ('kmac', 'mutations', 'Packaged KMAC compiled cleanup/overflow mutants: PASS; rejected='),
            ('tuplehash', 'mutations', 'Packaged TupleHash compiled cleanup/overflow mutants: PASS; rejected='),
            ('tuplehash', 'scoped_mutations', 'Packaged scoped TupleHash mutants: PASS; rejected='),
            ('parallelhash', 'main', 'ParallelHash package execution: PASS; compiled regressions=')]:
            path = f'scripts/{family}/check-{family}-execution-package.py'
            tree = ast.parse((ROOT / path).read_text())
            body = next(n.body for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function)
            if family == 'parallelhash':
                body = next(n.body for n in body if isinstance(n, ast.With))
            # Evaluate literal/comprehension inventory assignments only. No
            # function calls, filesystem access, native branches or compiler.
            nodes = [n for n in body if isinstance(n, (ast.Assign, ast.AugAssign)) and
                any(isinstance(t, ast.Name) and t.id == 'cases' for t in
                    (n.targets if isinstance(n, ast.Assign) else [n.target]))]
            self.assertFalse(any(isinstance(n, (ast.Call, ast.Attribute)) for s in nodes for n in ast.walk(s)))
            state = {}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), '<literal inventory>', 'exec'), {'__builtins__': {}}, state)
            self.assertIn(prefix + str(len(state['cases']) * 2), bindings.definitions()[('python3', path)]['markers'])
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')), \
                patch.object(sys, 'path', [str(ROOT / 'scripts/parallelhash'), *sys.path]):
            module = policy('binding_package_parallel', 'scripts/parallelhash/check-parallelhash-execution-package.py')
            count = 2 * (4 + len(module.scoped_negatives()))
        self.assertIn(f'Streaming/scoped ownership rejects {count} compiled probes',
            bindings.definitions()[('python3', 'scripts/parallelhash/check-parallelhash-execution-package.py')]['markers'])
