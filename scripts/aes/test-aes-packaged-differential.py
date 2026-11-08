#!/usr/bin/env python3
"""Fail-closed controls for packaged AES/OpenSSL differential acceptance."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_packaged_differential', Path(__file__).with_name('check-aes-packaged-differential.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def success():
    return ('\n'.join(f'test {name} ... ok' for name in sorted(runner.TESTS)) + '\n'
            + '\n'.join(runner.MARKERS)
            + '\ntest result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n')


class PackagedDifferentialTests(unittest.TestCase):
    def test_exact_case_and_test_populations(self):
        runner.check_output(success())
        self.assertEqual(len(runner.TESTS), 4)
        self.assertEqual(len(runner.MARKERS), 9)
        for test in runner.TESTS:
            for status in ('ignored', 'FAILED'):
                with self.subTest(test=test, status=status), self.assertRaises(ValueError):
                    runner.check_output(success().replace(f'test {test} ... ok', f'test {test} ... {status}'))
        for bad in ('', success() * 2, success().replace('4 passed', '0 passed'),
                    success().replace('0 filtered out', '1 filtered out'),
                    success().replace('test oracle_path_admission ... ok\n', ''),
                    success().replace('aes256_openssl_independent_corpus', 'unrelated')):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                runner.check_output(bad)

    def test_each_width_owner_and_public_marker_is_required_once(self):
        for marker in runner.MARKERS:
            for bad in (success().replace(marker, ''), success() + marker + '\n',
                        success().replace(marker, marker + ' incomplete')):
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    runner.check_output(bad)

    def test_fixture_is_copied_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner.prepare(root)
            self.assertEqual((root / 'tests/differential.rs').read_bytes(), runner.FIXTURE.read_bytes())

    def test_missing_or_symlinked_fixture_fails(self):
        for symlink in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = root / 'source.rs'
                if symlink:
                    fixture.symlink_to(runner.FIXTURE)
                with patch.object(runner, 'FIXTURE', fixture), self.assertRaises(ValueError):
                    runner.prepare(root / 'consumer')

    def test_both_profiles_run_ignored_corpora_and_validate_graph(self):
        with patch.object(runner.packaged.archives, 'run', side_effect=[
                SimpleNamespace(stdout='{}'), SimpleNamespace(stdout=success()), SimpleNamespace(stdout=success())]) as run, \
             patch.object(runner.packaged, 'graph') as graph, patch('builtins.print') as emit:
            runner.configuration(Path('/tmp/consumer'), Path('/tmp/root'), {}, '1.99.1', 'facade', {})
        graph.assert_called_once()
        self.assertEqual(run.call_count, 3)
        self.assertNotIn('--release', run.call_args_list[1].args[0])
        self.assertIn('--release', run.call_args_list[2].args[0])
        for call in run.call_args_list[1:]:
            for flag in ('--include-ignored', '--show-output', '--test-threads=1', '--locked', '--offline'):
                self.assertIn(flag, call.args[0])
        self.assertIn(runner.profile_marker('1.99.1', 'facade', 'debug'), [c.args[0] for c in emit.call_args_list])
        self.assertIn(runner.profile_marker('1.99.1', 'facade', 'release'), [c.args[0] for c in emit.call_args_list])

    def test_bad_result_never_prints_profile_success(self):
        with patch.object(runner.packaged.archives, 'run', side_effect=[
                SimpleNamespace(stdout='{}'), SimpleNamespace(stdout='')]), \
             patch.object(runner.packaged, 'graph'), patch('builtins.print') as emit, self.assertRaises(ValueError):
            runner.configuration(Path('/tmp/consumer'), Path('/tmp/root'), {}, '1.99.1', 'direct', {})
        self.assertFalse(any('AES_PACKAGED_DIFFERENTIAL_PROFILE' in str(c) for c in emit.call_args_list))

    @contextlib.contextmanager
    def execution(self, digest=('same', 'same')):
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary)
            stack.enter_context(patch.dict(runner.os.environ, {}, clear=True))
            select = stack.enter_context(patch.object(runner.oracle, 'select', return_value=root / 'openssl'))
            hashes = stack.enter_context(patch.object(runner.oracle, 'digest', side_effect=digest))
            preflight = stack.enter_context(patch.object(runner.oracle, 'preflight'))
            private = stack.enter_context(patch.object(runner.packaged.archives.cargo_environment, 'private_directory'))
            private.return_value.__enter__.return_value = temporary
            stack.enter_context(patch.object(runner.packaged.archives, 'isolated_env', return_value={}))
            package = stack.enter_context(patch.object(runner.packaged, 'package_sources', return_value={}))
            stack.enter_context(patch.object(runner.packaged, 'prepare'))
            stack.enter_context(patch.object(runner, 'prepare'))
            stack.enter_context(patch.object(runner.packaged.archives, 'run'))
            configuration = stack.enter_context(patch.object(runner, 'configuration'))
            output = io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(output))
            yield root, select, hashes, preflight, package, configuration, output

    def test_same_oracle_reaches_preflight_and_every_consumer(self):
        for compiler in runner.packaged.consumer.TOOLCHAINS:
            for route in runner.packaged.consumer.ROUTES:
                with self.execution() as (root, select, hashes, preflight, package, configuration, output):
                    runner.check(compiler, route)
                    select.assert_called_once()
                    self.assertEqual(hashes.call_count, 2)
                    self.assertEqual(hashes.call_args_list[0].args[0], root / 'openssl')
                    self.assertEqual(hashes.call_args_list[1].args[0], root / 'openssl')
                    env = configuration.call_args.args[-1]
                    self.assertEqual(env, {'BRYNJA_OPENSSL': str(root / 'openssl'), 'OPENSSL_CONF': '/dev/null'})
                    preflight.assert_called_once_with(root / 'openssl', env)
                    package.assert_called_once()
                    self.assertTrue(output.getvalue().endswith(runner.oracle.SUCCESS + '\n' + runner.marker(compiler, route) + '\n'))

    def test_changed_oracle_never_prints_completion(self):
        with self.execution(('before', 'after')) as (*_, output), self.assertRaises(ValueError):
            runner.check('1.99.1', 'direct')
        self.assertNotIn(runner.oracle.SUCCESS, output.getvalue())
        self.assertNotIn('AES packaged differential: PASS', output.getvalue())

    def test_failed_preflight_or_execution_never_prints_completion(self):
        for phase in ('preflight', 'configuration'):
            with self.execution() as (_, _, _, preflight, package, configuration, output), self.assertRaises(ValueError):
                (preflight if phase == 'preflight' else configuration).side_effect = ValueError('failed')
                runner.check('1.99.1', 'direct')
            if phase == 'preflight':
                package.assert_not_called()
            self.assertNotIn(runner.oracle.SUCCESS, output.getvalue())
            self.assertNotIn('AES packaged differential: PASS', output.getvalue())

    def test_oracle_environment_overrides_are_rejected_before_packaging(self):
        for name in runner.oracle.FORBIDDEN:
            with patch.dict(runner.os.environ, {name: 'untrusted'}, clear=True), \
                 patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', 'direct')
            package.assert_not_called()

    def test_unsupported_configuration_is_rejected(self):
        for compiler, route in (('stable', 'direct'), ('1.99.1', 'unknown')):
            with patch.object(runner.oracle, 'select') as select, self.assertRaises(ValueError):
                runner.check(compiler, route)
            select.assert_not_called()

    def test_four_registrations_bind_oracle_and_exact_profiles(self):
        doc = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in doc['checks'] if c['component'] == 'aes' and c['id'].startswith('packaged-diff-')}
        self.assertEqual(len(checks), 4)
        for endpoint, compiler in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for route in ('direct', 'facade'):
                check = checks[f'packaged-diff-{endpoint}-{route}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-packaged-differential.py', '--toolchain', compiler, '--route', route])
                self.assertEqual(set(check['inputs']), {'aes-packaged', 'aes-packaged-differential', 'aes-differential-runner', 'aes-oracle', 'hkdf-public-api-modern', 'compiler', 'hkdf-msrv'})
                self.assertTrue(set(runner.oracle.FORBIDDEN) <= set(check['reject_environment']))
                self.assertEqual(check['success']['exact_tests'], 8)
                self.assertEqual(check['success']['minimum_tests'], 8)
                self.assertEqual(set(check['success']['unique_lines']), {
                    runner.oracle.SUCCESS, runner.marker(compiler, route),
                    *(runner.profile_marker(compiler, route, profile) for profile in ('debug', 'release'))})
        self.assertEqual(set(doc['groups']['aes-packaged-differential']['paths']), {
            'assurance/aes-differential', 'scripts/aes/check-aes-packaged-differential.py',
            'scripts/aes/test-aes-packaged-differential.py'})


if __name__ == '__main__':
    unittest.main()
