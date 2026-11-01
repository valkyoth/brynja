"""Final binding regressions: fake compilers only, never a crypto campaign."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import verification_final_bindings as bindings
from verification_additional_tests import validate_inputs
from verification_legacy_policy_tests import policy
from verification_package_tests import covered

ROOT = Path(__file__).resolve().parents[2]
IMPORT_ROOTS = [ROOT / 'scripts' / p for p in
                ('hmac', 'legacy-hmac', 'repository', 'sha2', 'cryptography', 'cpu', 'md5', 'sha1')]


class StopBeforeCompiler(Exception):
    pass


class FinalBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = json.loads((ROOT / 'verification/catalog.json').read_text())['entries']
        cls.doc = bindings.build(cls.rows)

    def selected(self, suffix):
        check = next(c for c in self.doc['checks'] if c['command'][1].endswith(suffix))
        return check, [self.doc['groups'][k] for k in check['inputs']]

    def load(self, script):
        # Loading definitions is allowed; all child process execution is guarded
        # by each test. The exporter itself never imports these modules.
        with patch.object(sys, 'path', [*map(str, IMPORT_ROOTS), *sys.path]):
            return policy('binding_final_' + Path(script).stem.replace('-', '_'), script)

    def test_eight_commands_only_and_compiler_normalization_is_explicit(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no verification')):
            doc = bindings.build(self.rows)
        self.assertEqual(len(doc['checks']), 8)
        validate_inputs(doc)
        for check in doc['checks']:
            row = next(r for r in self.rows if r['id'] == check['id'])
            spec = bindings.definitions()[tuple(row['command'])]
            self.assertEqual(check['command'], row['command'] + (['--toolchain', '1.99.1'] if spec['pin'] else []))
            self.assertEqual(check['environment']['RUSTUP_AUTO_INSTALL'], '0')
            self.assertEqual(check['environment']['CARGO_NET_OFFLINE'], 'true')
            for field, value in [('command', row['command'] + ['--native']),
                                 ('command', row['command'] + ['--write']),
                                 ('environment', {'RUSTFLAGS': '-Ctarget-cpu=native'}), ('stdin', 'extra')]:
                with self.assertRaises(ValueError):
                    bindings.build([{**row, field: value}])

    def test_sources_are_selected_archives_not_whole_workspace_or_reporting(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            spec = bindings.definitions()[tuple(check['command'][:2])]
            for name in spec['packages']:
                self.assertTrue(covered('crates/' + name + '/new_nested/file.rs', groups))
            for name in ('crates/unrelated-aes/src/lib.rs', 'Cargo.lock', 'verification/results.json',
                         'docs/VERIFICATION_RESULTS.md', 'tools/brynja-verify/src/report.rs'):
                self.assertFalse(covered(name, groups), (check['id'], name))
            locks = {p for g in groups for lock in g.get('locks', [])
                     if lock['path'] == 'Cargo.lock' for p in lock['packages']}
            self.assertEqual(locks, spec['packages'])
            toolchains = {t['toolchain'] for g in groups for t in g.get('tools', []) if 'toolchain' in t}
            self.assertEqual(toolchains, set(spec['compilers']))

    def test_original_package_populations_match_scopes(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            for script, field in [('scripts/hmac/check-hmac-package.py', 'NAMES'),
                                  ('scripts/legacy-hmac/check-legacy-hmac-package.py', 'NAMES'),
                                  ('scripts/legacy-hmac/check-legacy-hmac-hosted-package.py', 'ARCHIVES')]:
                module = self.load(script)
                self.assertEqual(set(getattr(module, field)), bindings.definitions()[('python3', script)]['packages'])
            protected = self.load('scripts/hmac/check-hmac-protected.py')
            self.assertEqual(set(protected.host.PACKAGES), bindings.HOSTED)
            strict = self.load('scripts/hmac/check-hmac-strict.py')
            self.assertEqual({p[0] for p in strict.scalar.specifications(strict.api)}, bindings.STRICT)
            facade = self.load('scripts/hmac/check-hmac-facade.py')
            expected = {p[0] for p in facade.api.archives.specifications(facade.api.packaging)}
            expected.update(facade.combined.ADDITIONAL)
            expected.add('brynja-hash-parallel-std')
            self.assertEqual(expected, bindings.definitions()[('python3', 'scripts/hmac/check-hmac-facade.py')]['packages'])

    def test_imported_helper_closures_are_declared(self):
        for check in self.doc['checks']:
            groups = [self.doc['groups'][k] for k in check['inputs']]
            paths = {p for g in groups for p in g.get('paths', []) if p.endswith('.py')}
            # Review-pinned CPU capture scripts in the general policy are read
            # as bytes, not executed/imported by this scalar check.
            if '/sha2/' in check['command'][1]:
                paths = {check['command'][1], *bindings.GENERAL_HELPERS}
            for path in paths:
                for node in ast.walk(ast.parse((ROOT / path).read_text())):
                    names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                             else [node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    for name in names:
                        for root in IMPORT_ROOTS:
                            candidate = root / (name + '.py')
                            if candidate.exists():
                                self.assertTrue(covered(candidate.relative_to(ROOT).as_posix(), groups),
                                                (check['command'], path, name))

    def test_explicit_package_toolchain_survives_sanitizing_environment(self):
        for script in ('scripts/hmac/check-hmac-package.py',
                       'scripts/legacy-hmac/check-legacy-hmac-package.py',
                       'scripts/legacy-hmac/check-legacy-hmac-hosted-package.py'):
            module = self.load(script)
            api = module.api if hasattr(module, 'api') else module
            for selected in (None, '1.99.1'):
                seen = []
                def package(_directory):
                    seen.append(dict(os.environ))
                    raise StopBeforeCompiler()
                with tempfile.TemporaryDirectory() as raw, \
                        patch.dict(os.environ, {'RUSTUP_TOOLCHAIN': 'ambient-wrong', 'RUSTFLAGS': '-Cwrong'}, clear=False), \
                        patch.object(sys, 'argv', [script] + (['--toolchain', selected] if selected else [])), \
                        patch.object(api.cargo_environment, 'private_directory', return_value=contextlib.nullcontext(raw)), \
                        patch.object(api.cargo_environment, 'check'), \
                        patch.object(api.packaging, 'package_roots', side_effect=package), \
                        patch('platform.system', return_value='Linux'), patch('platform.machine', return_value='x86_64'), \
                        patch('platform.libc_ver', return_value=('glibc', '2.39')), \
                        patch('subprocess.Popen', side_effect=AssertionError('no compiler')), \
                        self.assertRaises(StopBeforeCompiler):
                    module.main()
                self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0].get('RUSTUP_TOOLCHAIN'), selected)
                self.assertNotIn('RUSTFLAGS', seen[0])
                if selected:
                    self.assertEqual(seen[0]['RUSTUP_AUTO_INSTALL'], '0')
                    self.assertEqual(seen[0]['CARGO_NET_OFFLINE'], 'true')

    def test_protected_compiler_pin_reaches_child_environment(self):
        module = self.load('scripts/hmac/check-hmac-protected.py')
        for selected in (None, '1.99.1'):
            seen = []
            def run(_argv, _cwd, env):
                seen.append(env)
                raise StopBeforeCompiler()
            with tempfile.TemporaryDirectory() as raw, \
                    patch.object(sys, 'argv', ['check'] + (['--toolchain', selected] if selected else [])), \
                    patch.dict(os.environ, {'RUSTUP_TOOLCHAIN': 'ambient-wrong', 'RUSTFLAGS': '-Cwrong'}), \
                    patch.object(type(module.PROTECTED), 'require_host'), \
                    patch.object(module.verifier.cargo_environment, 'private_directory', return_value=contextlib.nullcontext(raw)), \
                    patch.object(module.host, 'isolated', return_value=Path(raw)), \
                    patch.object(module.host, 'run', side_effect=run), \
                    patch('subprocess.Popen', side_effect=AssertionError('no compiler')), self.assertRaises(StopBeforeCompiler):
                module.main()
            self.assertEqual(seen[0].get('RUSTUP_TOOLCHAIN'), selected)
            self.assertNotIn('RUSTFLAGS', seen[0])

    def test_facade_packaging_matches_explicit_consumer_compiler(self):
        module = self.load('scripts/hmac/check-hmac-facade.py')
        seen = []
        def package(*_args):
            seen.append(dict(os.environ))
            raise StopBeforeCompiler()
        with tempfile.TemporaryDirectory() as raw, \
                patch.object(module.api.parallelhash, 'package_roots', side_effect=package), \
                patch('subprocess.Popen', side_effect=AssertionError('no compiler')), self.assertRaises(StopBeforeCompiler):
            module.execute(Path(raw), '1.99.1', 'x86_64-unknown-none')
        self.assertEqual(seen[0]['RUSTUP_TOOLCHAIN'], '1.99.1')
        self.assertEqual(seen[0]['RUSTUP_AUTO_INSTALL'], '0')
        self.assertEqual(seen[0]['CARGO_NET_OFFLINE'], 'true')

    def test_hmac_public_population_and_negative_signals_are_exact(self):
        module = self.load('scripts/hmac/check-hmac-package.py')
        self.assertEqual(len(list(module.hmac_acceptance.negative_cases())), 118)
        calls = []
        def run(argv, _cwd, _env):
            count = 3 if '--doc' in argv else dict(vectors=7, lifecycle=11, bounded=13,
                bits=12, general=6, tag_policy=3)[argv[argv.index('--test') + 1]]
            calls.append(('--release' in argv, count))
            return f'test result: ok. {count} passed; 0 failed; 0 ignored;'
        with patch.object(module, 'run', side_effect=run), patch('subprocess.Popen', side_effect=AssertionError('no compiler')):
            module.test_profiles(Path('/unused'), {})
        self.assertEqual(calls, [(p, n) for p in (False, True) for n in (7, 11, 13, 12, 6, 3, 3)])
        for text in ('', 'test result: ok. 0 passed; 0 failed; 7 ignored;',
                     'test result: ok. 6 passed; 0 failed; 0 ignored;'):
            with patch.object(module, 'run', return_value=text), self.assertRaises(ValueError):
                module.test_profiles(Path('/unused'), {})
        for status, output in ((0, ''), (101, 'compiler error'), (1, 'test result: FAILED. 0 passed; 1 failed; 0 ignored;')):
            fake = SimpleNamespace(returncode=status, stdout=output, stderr=output)
            with self.assertRaises(ValueError):
                module.hmac_acceptance.diagnostic_rejection(fake, 'E0277')

    def test_general_policy_population_and_tools_match_original(self):
        module = self.load('scripts/sha2/check-general-sha512-t.py')
        for suffix in ('check-general-sha512-t.py', 'test-general-sha512-t.py'):
            check, groups = self.selected(suffix)
            for name in module.policy.BOUND:
                self.assertTrue(covered(name, groups), name)
            self.assertEqual(set(module.acceptance.packages.PACKAGING_PACKAGES[i][0]
                                 for i in range(len(module.acceptance.packages.PACKAGING_PACKAGES))),
                             bindings.definitions()[tuple(check['command'])]['packages'])
        source = ast.parse((ROOT / 'scripts/sha2/test-general-sha512-t.py').read_text())
        self.assertEqual(sum(isinstance(n, ast.FunctionDef) and n.name.startswith('test_') for n in ast.walk(source)), 15)
        mutants = next(n.value for n in ast.walk(source) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'mutants' for t in n.targets))
        self.assertEqual(len(mutants.elts), 15)

    def test_general_orchestration_propagates_failures_without_executing_checks(self):
        module = self.load('scripts/sha2/check-general-sha512-t.py')
        for failed in (None, 'cargo', 'cleanup', 'lifecycle', 'acceptance', 'final'):
            output = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('no real compiler')))
                stack.enter_context(patch.object(sys, 'argv', ['check']))
                stack.enter_context(patch.object(module.policy, 'validate'))
                stack.enter_context(patch.object(module.policy.contract, 'read', return_value=b'fixture'))
                stack.enter_context(patch.object(module.oracle, 'render', return_value=b'fixture'))
                stack.enter_context(patch.object(module.digest_oracle, 'render', return_value=b'fixture'))
                children = {}
                for name in ('cleanup', 'lifecycle', 'acceptance', 'final'):
                    children[name] = stack.enter_context(patch.object(getattr(module, name), 'main' if name == 'cleanup' else 'run',
                        side_effect=ValueError('synthetic failure') if failed == name else None))
                run = stack.enter_context(patch.object(module.subprocess, 'run',
                    side_effect=subprocess.CalledProcessError(1, ['cargo']) if failed == 'cargo' else None))
                stack.enter_context(contextlib.redirect_stdout(output))
                if failed:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        module.main()
                    self.assertNotIn('public descriptors and all-510 IV oracle: PASS', output.getvalue())
                else:
                    self.assertEqual(module.main(), 0)
                    self.assertEqual(run.call_count, 3)
                    self.assertTrue(all(c.call_count == 1 for c in children.values()))
                    for call in run.call_args_list:
                        self.assertIn('--offline', call.args[0])
                        self.assertTrue(call.kwargs['check'])
