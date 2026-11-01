"""Check registration fidelity without executing crypto or original campaigns."""
import ast
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
import verification_hardened_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy, assignment

ROOT = Path(__file__).resolve().parents[2]


def original(family):
    path = {'md5': 'scripts/md5/md5_hardened_policy.py', 'sha1': 'scripts/sha1/hardened_policy.py',
            'sha2': 'scripts/sha2/sha2_hardened.py', 'sha3': 'scripts/sha3/sha3_hardened.py'}[family]
    with patch.object(sys, 'path', [str(ROOT / 'scripts/md5'), *sys.path]), \
            patch('subprocess.Popen', side_effect=AssertionError('no execution')):
        return policy('binding_hardened_' + family, path)


class HardenedBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)
        cls.data = json.loads(bindings.DATA.read_text())

    def test_five_exact_selectors_without_execution(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 5)
        self.assertEqual({tuple(c['command']) for c in doc['checks']}, set(bindings.definitions()))
        validate_inputs(doc)
        for check in doc['checks']:
            row = next(r for r in self.rows if r['id'] == check['id'])
            self.assertEqual(check['command'], row['command'])

    def test_unreviewed_flags_environment_and_stdin_are_rejected(self):
        ids = {c['id'] for c in self.doc['checks']}
        for row in (r for r in self.rows if r['id'] in ids):
            for key, value in [('command', row['command'] + ['--write']),
                               ('environment', {'PYTHONOPTIMIZE': '1'}), ('stdin', 'unreviewed')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, key: value}])

    def test_every_original_policy_input_is_bound(self):
        for family in self.data:
            p = original(family)
            names = (p.paths(ROOT) if family == 'md5' else p.inventory(ROOT) if family == 'sha1' else p.FILES)
            paths = self.data[family]['paths']
            for name in map(str, names):
                self.assertTrue(any(name == s or name.startswith(s + '/') for s in paths), (family, name))
            self.assertNotIn('Cargo.lock', paths)
            self.assertFalse(any(s.startswith(('verification/', 'target/')) for s in paths))
            if family in ('md5', 'sha1'):
                self.assertIn(p.REVIEW, paths)
                for package in ('brynja-core', 'brynja-hash-core', 'brynja-legacy-' + family,
                                'brynja-legacy-' + family + '-std'):
                    self.assertIn('crates/' + package + '/src', paths)
            if family == 'md5':
                self.assertTrue(set(p.GATES) <= set(paths))
        # The SHA-1 checker really hashes this raw manifest. Do not silently
        # discard a premise; this affects only its legacy source-review row.
        self.assertIn('Cargo.toml', self.data['sha1']['paths'])

    def test_synthetic_codegen_imports_are_declared_without_compiler_tools(self):
        imports = json.loads((ROOT / 'scripts/release/verification_codegen_inputs.json').read_text())
        for family in ('md5', 'sha1'):
            script = f'scripts/{family}/check-{family}-hardened-codegen.py'
            self.assertTrue(set(imports[script]) <= set(self.data[family]['paths']))
            check = next(c for c in self.doc['checks'] if c['component'] == family)
            tools = [t for k in check['inputs'] for t in self.doc['groups'][k].get('tools', [])]
            self.assertEqual(tools, [{'program': 'python3'}])
        tree = ast.parse((ROOT / 'scripts/md5/test-md5-hardened.py').read_text())
        calls = [ast.unparse(n) for n in ast.walk(tree) if isinstance(n, ast.Call)]
        self.assertTrue(any("patch.object(asan.subprocess, 'run', side_effect=run)" == c for c in calls))

    def test_original_structural_population_matches_completion_markers(self):
        md5 = original('md5')
        self.assertEqual(sum(map(len, md5.CHECKS.values())) + sum(map(len, md5.GATES.values())) + 7, 152)
        sha1 = original('sha1')
        initial = assignment('scripts/sha1/test-sha1-hardened.py', 'cases')
        self.assertEqual(len(initial.elts) + len(sha1.BORROWED_ENGINE) + len(sha1.SCOPED) + 6
                         + sum(map(len, sha1.STRICT.values())) + 5 + 2, 85)
        self.assertEqual(len(sha1.inventory(ROOT)), 168)

    def test_acceptance_commands_keep_test_and_cross_target_steps(self):
        for family in ('sha2', 'sha3'):
            p = original(family)
            # Exercise orchestration only; every subprocess is synthetic. This
            # neither compiles the fixture nor executes its tests.
            with patch.object(p.subprocess, 'run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = 'synthetic output\n'
                output = p.run_acceptance()
            calls = run.call_args_list
            self.assertEqual(len(calls), 4 if family == 'sha2' else 3)
            self.assertEqual(output, 'synthetic output\n' * len(calls))
            manifest = 'assurance/' + family + '-hardened-api/Cargo.toml'
            expected = [['cargo', 'test', '--locked', '-p', 'brynja-hash-' + family, '--test', 'hardened'],
                        ['cargo', 'test', '--locked', '--manifest-path', manifest],
                        ['cargo', 'check', '--locked', '--manifest-path', manifest, '--target', 'thumbv7em-none-eabi']]
            if family == 'sha2':
                expected.insert(0, ['cargo', 'test', '--locked', '-p', 'brynja-hash-sha2', '--lib', 'hardened::tests::checked_length_'])
            self.assertEqual([c.args[0] for c in calls], expected)
            self.assertTrue(all(c.kwargs['timeout'] == 240 for c in calls))

    def test_required_test_names_and_populations_match_sources(self):
        for family, names in [('sha2', bindings.SHA2_TESTS), ('sha3', bindings.SHA3_TESTS)]:
            source = (ROOT / f'crates/brynja-hash-{family}/tests/hardened.rs').read_text()
            self.assertEqual(set(re.findall(r'#\[test\]\s*fn (\w+)', source)), set(names))
            fixture = (ROOT / f'assurance/{family}-hardened-api/src/lib.rs').read_text()
            self.assertEqual(re.findall(r'#\[test\]\s*fn (\w+)', fixture), ['downstream_hardened_apis_are_usable'])
            c = next(c for c in self.doc['checks'] if c['command'][1] == f'scripts/{family}/check-{family}-hardened.py')
            self.assertEqual(c['success']['exact_tests'], 15 if family == 'sha2' else 14)
            self.assertEqual(len(c['success']['unique_lines']), c['success']['exact_tests'] + 1)
        source = (ROOT / 'crates/brynja-hash-sha2/src/hardened/tests.rs').read_text()
        self.assertEqual(set(re.findall(r'finalization_case!\(\s*(checked_length_\w+)', source)),
                         {'checked_length_' + n for n in ('sha224', 'sha256', 'sha384', 'sha512', 'sha512_224', 'sha512_256')})

    def test_compiled_checks_pin_tools_and_only_selected_lock_rows(self):
        for c in self.doc['checks']:
            family, mode, _ = bindings.definitions()[tuple(c['command'])]
            if mode == 'source':
                continue
            self.assertEqual(c['environment']['RUSTUP_TOOLCHAIN'], '1.99.1')
            self.assertEqual(c['environment']['CARGO_NET_OFFLINE'], 'true')
            groups = [self.doc['groups'][k] for k in c['inputs']]
            locks = {p for g in groups for lock in g.get('locks', []) for p in lock['packages']}
            expected = {'brynja-core', 'brynja-hash-core', 'brynja-hash-' + family}
            if mode == 'acceptance':
                expected.add('brynja-' + family + '-hardened-api-fixture')
            self.assertEqual(locks, expected)
            self.assertTrue(all(t.get('toolchain') == '1.99.1' for g in groups for t in g.get('tools', [])
                                if t['program'] != 'python3'))

    def test_compiled_mutants_require_both_original_completion_markers(self):
        script = 'scripts/sha2/test-sha2-hardened.py'
        source = (ROOT / script).read_text()
        strings = {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        _, mode, markers = bindings.definitions()[('python3', script)]
        self.assertEqual(mode, 'mutants')
        self.assertTrue(set(markers) <= strings)
        for text in ('for mode in ([], ["--release"]):', 'len(mutants) != 6', '"6 passed" not in positive.stdout',
                     'result.returncode == 0 or "test result: FAILED" not in result.stdout'):
            self.assertIn(text, source)
