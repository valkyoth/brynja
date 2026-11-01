"""Acceptance-wrapper bindings tested with fake children, never qualification."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
import tomllib
from unittest.mock import patch
import verification_execution_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy
from verification_package_tests import covered

ROOT = Path(__file__).resolve().parents[2]


class ExecutionBindingTests(unittest.TestCase):
    def setUp(self):
        self.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        with patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            self.doc = bindings.build(self.rows)

    def groups(self, check):
        return [self.doc['groups'][k] for k in check['inputs']]

    def test_eleven_exact_commands_reject_flag_environment_and_stdin_expansion(self):
        self.assertEqual(len(self.doc['checks']), 11)
        validate_inputs(self.doc)
        for check in self.doc['checks']:
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            self.assertEqual(check['platform'], 'linux-x86_64')
            row = next(r for r in self.rows if r['id'] == check['id'])
            for field, value in [('command', row['command'] + ['--write']),
                                 ('command', row['command'] + ['--native-x86']),
                                 ('environment', {'RUSTFLAGS': '-Ctarget-cpu=native'}), ('stdin', 'unknown')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_selected_archive_closures_and_explicit_toolchains(self):
        for check in self.doc['checks']:
            spec = bindings.definitions()[tuple(check['command'])]
            groups = self.groups(check)
            self.assertEqual({p for g in groups for lock in g.get('locks', []) for p in lock['packages']},
                             spec['packages'])
            self.assertEqual({t['toolchain'] for g in groups for t in g.get('tools', []) if 'toolchain' in t},
                             set(spec['versions']))
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'], spec['compiler'])
            for group in groups:
                for tool in group.get('tools', []):
                    if tool['program'] in ('clippy-driver', 'rustdoc'):
                        self.assertEqual(tool['toolchain'], spec['compiler'])
            for name in ('crates/unrelated-aes/src/lib.rs', 'verification/results.json', 'docs/VERIFICATION_RESULTS.md'):
                self.assertFalse(covered(name, groups), name)
        source_check = next(c for c in self.doc['checks'] if c['command'][1] ==
                            'scripts/sha2/test-sha2-hardened-execution.py')
        groups = self.groups(source_check)
        self.assertFalse(covered('crates/brynja-mac-hmac/src/engine.rs', groups))
        self.assertTrue(covered('crates/brynja-mac-hmac/Cargo.toml', groups))
        self.assertTrue(covered('crates/brynja-hash-sha2/src/new_module.rs', groups))

    def test_original_default_wrapper_selectors_and_failures_with_fake_children(self):
        for check in self.doc['checks']:
            script = check['command'][1]
            if not any('/' + f + '/' in script for f in ('md5', 'sha1')):
                continue
            family = Path(script).parent.name
            with patch.object(sys, 'path', [str(ROOT / 'scripts' / family), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
                module = policy('binding_default_' + Path(script).stem.replace('-', '_'), script)
                with patch.object(sys, 'argv', [script]), patch.object(module.policy, 'validate'), \
                        patch.object(module.subprocess, 'run') as child, contextlib.redirect_stdout(io.StringIO()) as output:
                    module.main()
                spec = bindings.definitions()[tuple(check['command'])]
                self.assertIn(spec['markers'][0], output.getvalue().splitlines())
                self.assertGreater(len(child.call_args_list), 3)
                for call in child.call_args_list:
                    command = call.args[0]
                    self.assertTrue(call.kwargs['check'])
                    self.assertNotIn('--write', command)
                    self.assertNotIn('--native', command)
                    if command[0] == 'python3':
                        self.assertTrue(covered(command[1], self.groups(check)), command)
                    if '--manifest-path' in command:
                        path = command[command.index('--manifest-path') + 1]
                        self.assertTrue(covered(path, self.groups(check)), path)
                with patch.object(sys, 'argv', [script]), patch.object(module.policy, 'validate'), \
                        patch.object(module.subprocess, 'run', side_effect=RuntimeError('failed child')), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaisesRegex(RuntimeError, 'failed child'):
                        module.main()
                self.assertNotIn(spec['markers'][0], output.getvalue())

    def test_hardened_package_negative_populations_and_wrong_diagnostics(self):
        for family, stem, count in [('sha2', 'sha2-hardened-execution', 12), ('sha3', 'keccak-hardened', 54)]:
            script = f'scripts/{family}/check-{stem}.py'
            with patch.object(sys, 'path', [str(ROOT / 'scripts' / family), *sys.path]), \
                    patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
                module = policy('binding_hardened_' + family, script)
                with tempfile.TemporaryDirectory() as directory:
                    consumer = Path(directory)
                    (consumer / 'src').mkdir()
                    path = consumer / 'src' / ('main.rs' if family == 'sha2' else 'lib.rs')
                    path.write_text('original source\n')
                    owner = module if family == 'sha2' else module.ordinary
                    good = SimpleNamespace(stderr=' '.join(f'error[{code}]' for code in ('E0382', 'E0277', 'E0599', 'E0308')))
                    with patch.object(owner, 'run', return_value=good) as child, \
                            contextlib.redirect_stdout(io.StringIO()) as output:
                        module.negatives(consumer, {})
                    self.assertEqual(child.call_count, count)
                    self.assertIn(output.getvalue().strip(), bindings.definitions()[('python3', script)]['markers'])
                    self.assertEqual(path.read_text(), 'original source\n')
                    with patch.object(owner, 'run', return_value=SimpleNamespace(stderr='')):
                        with self.assertRaises(ValueError):
                            module.negatives(consumer, {})
                    self.assertEqual(path.read_text(), 'original source\n')

    def test_modern_policy_inventories_and_new_matching_helpers_are_in_scope(self):
        for check in self.doc['checks']:
            script = check['command'][1]
            for family, stem in [('sha2', 'sha2-hardened-execution'), ('sha3', 'keccak-hardened')]:
                if f'scripts/{family}/' not in script:
                    continue
                review = f'security/{stem}-reviewed.json'
                groups = self.groups(check)
                for name in [review, *json.loads((ROOT / review).read_text())['sha256']]:
                    self.assertTrue(covered(name, groups), name)
                self.assertIn(f'scripts/{family}/*{stem}*.py', [p for g in groups for p in g.get('patterns', [])])

    def test_original_keccak_pin_and_default_environment_do_not_select_native_routes(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/sha3'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            module = policy('binding_keccak_pin', 'scripts/sha3/check-keccak-hardened.py')
            with patch.object(module, 'original_run') as child:
                module.pinned_run(['cargo', 'test', '--offline'], ROOT, {})
            self.assertEqual(child.call_args.args[0], ['cargo', '+1.98.1', 'test', '--offline'])
            env = module.environment(Path('/synthetic'))
            self.assertEqual(env['BRYNJA_KECCAK_PROPERTY_SEED'], '17037')
            self.assertEqual(env['BRYNJA_KECCAK_PROPERTY_CASES'], '64')
            self.assertNotIn('RUSTFLAGS', env)

    def test_cpu_archive_inventories_and_hosted_classification_controls(self):
        for kind in ('hosted', 'static'):
            argv = ('python3', f'scripts/cpu/check-{kind}-execution.py')
            check = next(c for c in self.doc['checks'] if tuple(c['command']) == argv)
            groups = self.groups(check)
            review = f'security/{kind}-cpu-execution-reviewed.json'
            for name in [review, *json.loads((ROOT / review).read_text())['sha256']]:
                self.assertTrue(covered(name, groups), name)
            self.assertEqual(check['environment']['RUSTUP_TOOLCHAIN'],
                tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel'])
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cpu'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            module = policy('binding_hosted_classifier', 'scripts/cpu/check-hosted-execution.py')
            with tempfile.TemporaryDirectory() as directory:
                consumer = Path(directory)
                (consumer / 'src').mkdir()
                manifest, source = consumer / 'Cargo.toml', consumer / 'src/lib.rs'
                manifest.write_text('[dependencies]\n')
                source.write_text('// baseline\n')
                with patch.object(module, 'run', return_value=SimpleNamespace(stderr='error[E0308] PublicData')) as child, \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    module.classification_negatives(consumer, {}, [])
                self.assertEqual(child.call_count, 10)
                self.assertIn(output.getvalue().strip(), bindings.definitions()[
                    ('python3', 'scripts/cpu/check-hosted-execution.py')]['markers'])
                with patch.object(module, 'run', return_value=SimpleNamespace(stderr='error[E0308] OtherType')):
                    with self.assertRaises(ValueError):
                        module.classification_negatives(consumer, {}, [])
                self.assertEqual(manifest.read_text(), '[dependencies]\n')
                self.assertEqual(source.read_text(), '// baseline\n')

    def test_static_default_selection_and_documentation_population_without_compiling(self):
        with patch.object(sys, 'path', [str(ROOT / 'scripts/cpu'), *sys.path]), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            module = policy('binding_static_default', 'scripts/cpu/check-static-execution.py')
            with patch.object(sys, 'argv', ['check-static-execution.py']), patch.object(module, 'validate'), \
                    patch.object(module.static_execution_docs, 'regressions'), \
                    patch.object(module, 'package', return_value=Path('/fake/package')), \
                    patch.object(module, 'check_package') as check, patch.object(module, 'mutations', return_value=7), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                module.main()
            check.assert_called_once()
            self.assertEqual(check.call_args.kwargs, {})  # No specialized ISA or QEMU.
            self.assertIn(output.getvalue().strip(), bindings.definitions()[
                ('python3', 'scripts/cpu/check-static-execution.py')]['markers'])
            count = len(module.static_execution_docs.DOCS) * len(module.static_execution_docs.CLAIMS) + 10 + 3
            self.assertIn(f'Static reachability documentation rejects {count} semantic regressions',
                bindings.definitions()[('python3', 'scripts/cpu/check-static-execution.py')]['markers'])
