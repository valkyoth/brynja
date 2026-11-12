#!/usr/bin/env python3
"""Fail-closed sanitizer acceptance controls; never execute the negative Rust here."""
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('accelerated_sanitizers', Path(__file__).with_name('check-aes-accelerated-sanitizers.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def successful_tests():
    return '\n'.join([*(f'test {name} ... ok' for name in sorted(r.TESTS)),
        'test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;', *sorted(r.MARKERS)])


def control(mode):
    output = ('ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 1' if mode == 'bounds' else
              'ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s)')
    return subprocess.CompletedProcess([], 23, output)


class AcceleratedSanitizerTests(unittest.TestCase):
    def test_exact_test_and_marker_population(self):
        good = successful_tests()
        r.validate_tests(good)
        for bad in ('', good.replace('... ok', '... ignored', 1), good.replace('... ok', '... FAILED', 1),
                    good.replace('13 passed', '12 passed'), good.replace('0 ignored;', '1 ignored;'),
                    good.replace('0 filtered out;', '1 filtered out;'), good + '\n' + good.splitlines()[0],
                    good.replace('native::aes192::', 'native::aes128::'),
                    good + '\n' + sorted(r.MARKERS)[0], good.replace('AES_EXECUTION_KAT_PASS:', 'absent:', 1),
                    good + '\nAES_EXECUTION_KAT_PASS: 128:1',
                    good + '\nERROR: AddressSanitizer: heap-buffer-overflow',
                    good + '\nWARNING: LeakSanitizer: disabled'):
            with self.assertRaises(ValueError): r.validate_tests(bad)

    def test_control_requires_specific_diagnosis_and_nonzero_exit(self):
        for mode in ('bounds', 'leak'):
            expected = control(mode)
            r.validate_control(mode, expected)
            for code in (0, 1, 101, -11, -6):
                with self.assertRaises(ValueError):
                    r.validate_control(mode, subprocess.CompletedProcess([], code, expected.stdout))
            for output in ('', 'panic: something failed', expected.stdout.replace('ERROR:', 'note:'),
                           control('leak' if mode == 'bounds' else 'bounds').stdout):
                with self.assertRaises(ValueError):
                    r.validate_control(mode, subprocess.CompletedProcess([], 23, output))
        with self.assertRaises(ValueError): r.validate_control('unknown', control('bounds'))

    def test_control_extent_must_match(self):
        for mode, old, new in (('bounds', 'READ of size 1', 'WRITE of size 8'),
                               ('leak', '64 byte(s)', '128 byte(s)'),
                               ('leak', '1 allocation(s)', '2 allocation(s)')):
            with self.assertRaises(ValueError):
                r.validate_control(mode, subprocess.CompletedProcess([], 23, control(mode).stdout.replace(old, new)))

    def test_adaptation_preserves_every_test_and_operation(self):
        source = (r.ROOT / 'crates/brynja-crypto/tests/aes_execution.rs').read_text()
        self.assertEqual(r.adapt(source, 'direct'), source)
        self.assertEqual(r.adapt(source, 'facade').replace('brynja::crypto::aes', 'brynja_crypto::aes'), source)
        for changed in (source.replace('brynja_crypto::aes', 'missing', 1), source + 'brynja_crypto::aes'):
            with self.assertRaises(ValueError): r.adapt(changed, 'facade')
        with self.assertRaises(ValueError): r.adapt(source, 'other')

    def test_manifest_enables_only_static_route_and_archive_patches(self):
        versions = {name: '0.1.0' for name in r.packaged.archives.MODERN}
        for route, dependency in (('direct', 'brynja-crypto'), ('facade', 'brynja')):
            manifest = tomllib.loads(r.manifest(versions, route))
            self.assertEqual(set(manifest['dependencies']), {dependency, 'brynja-crypto-cpu'})
            self.assertEqual(manifest['dependencies'][dependency]['features'], ['aes-static-execution'])
            self.assertFalse(manifest['dependencies'][dependency]['default-features'])
            self.assertEqual(manifest['dependencies']['brynja-crypto-cpu'], {'version': '=0.1.0'})
            self.assertEqual(set(manifest['patch']['crates-io']), set(versions))
            self.assertTrue(manifest['profile']['release']['overflow-checks'])

    def test_configuration_and_ambient_injection_rejected_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            with self.assertRaises(ValueError): r.check('other')
            with patch.object(r.platform, 'machine', return_value='aarch64'), self.assertRaises(ValueError):
                r.check('direct')
            for name in r.REJECT:
                with patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError): r.check('direct')
            package.assert_not_called()

    def test_missing_or_symlinked_fixture_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / 'target'
            with self.assertRaises(ValueError): r.copy_file(directory / 'missing', target)
            link = directory / 'link'
            link.symlink_to(Path(__file__).resolve())
            with self.assertRaises(ValueError): r.copy_file(link, target)
            self.assertFalse(target.exists())

    def test_execute_retains_diagnostic_and_returncode(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.subprocess, 'run', return_value=control('bounds')) as run, redirect_stdout(io.StringIO()):
                result = r.execute(['binary', 'bounds'], directory, {}, directory, 'control')
            self.assertEqual(result.returncode, 23)
            self.assertEqual((directory / 'control.log').read_text(), result.stdout)
            record = r.json.loads((directory / 'control.json').read_text())
            self.assertEqual(record, {'command': ['binary', 'bounds'], 'returncode': 23})
            self.assertEqual(run.call_args.kwargs['timeout'], 600)
            self.assertEqual(run.call_args.kwargs['stderr'], subprocess.STDOUT)

    def test_profile_controls_use_consistent_fatal_sanitizer_options(self):
        self.assertEqual(r.TOOLCHAIN, 'nightly-2026-09-11')
        self.assertEqual(r.TARGET, 'x86_64-unknown-linux-gnu')
        self.assertEqual(r.FLAGS, '-Zsanitizer=address -Ctarget-feature=+aes,+sse2')
        self.assertEqual(r.ASAN, 'detect_leaks=1:halt_on_error=1:exitcode=23')
        self.assertEqual(r.LSAN, 'exitcode=23')

    def test_bad_control_or_failed_test_never_yields_profile_pass(self):
        success = subprocess.CompletedProcess([], 0, successful_tests())
        for index in range(4):
            results = [success, control('bounds'), control('leak'), success]
            results[index] = subprocess.CompletedProcess([], 101 if index in (0, 3) else 0, results[index].stdout)
            output = io.StringIO()
            with patch.object(r, 'execute', side_effect=results) as execute, redirect_stdout(output):
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    r.run_profile(['cargo', '+' + r.TOOLCHAIN], [], Path('/tmp/probe'), {},
                                  Path('/tmp/probe'), Path('/tmp/probe'), 'direct', 'debug')
            self.assertEqual(execute.call_count, index + 1)
            self.assertNotIn('AES_ACCELERATED_SANITIZER_PROFILE_PASS:', output.getvalue())

    def test_profile_commands_keep_target_and_identical_environment(self):
        for profile in ('debug', 'release'):
            success = subprocess.CompletedProcess([], 0, successful_tests())
            env = {'RUSTFLAGS': r.FLAGS, 'ASAN_OPTIONS': r.ASAN, 'LSAN_OPTIONS': r.LSAN}
            selection = ['--locked', '--offline', '--no-default-features', '--features', 'facade']
            with patch.object(r, 'execute', side_effect=[success, control('bounds'), control('leak'), success]) as execute, redirect_stdout(io.StringIO()):
                r.run_profile(['cargo', '+' + r.TOOLCHAIN], selection, Path('/tmp/probe'), env,
                              Path('/tmp/probe'), Path('/tmp/probe'), 'facade', profile)
            calls = execute.call_args_list
            self.assertEqual(len(calls), 4)
            for call in calls:
                self.assertIs(call.args[2], env)
            for call in (calls[0], calls[3]):
                command = call.args[0]
                self.assertEqual(command[:2], ['cargo', '+' + r.TOOLCHAIN])
                self.assertEqual(command[3:3+len(selection)], selection)
                self.assertEqual(command[command.index('--target')+1], r.TARGET)
                self.assertEqual('--release' in command, profile == 'release')
            self.assertIn('sanitizer-control', calls[0].args[0])
            self.assertIn('lifecycle', calls[3].args[0])

    def test_registry_requires_both_profiles_and_all_controls(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-accelerated-sanitizers'}
        self.assertEqual(set(checks), {'accelerated-sanitizers-direct', 'accelerated-sanitizers-facade'})
        for route in ('direct', 'facade'):
            c = checks['accelerated-sanitizers-' + route]
            self.assertEqual(c['command'], ['python3', 'scripts/aes/check-aes-accelerated-sanitizers.py', '--route', route])
            self.assertTrue(set(r.REJECT) <= set(c['reject_environment']))
            self.assertTrue({'aes-accelerated-sanitizers', 'aes-build', 'aes-packaged',
                             'aes-accelerated-campaigns', 'asan-tools', 'compiler'} <= set(c['inputs']))
            expected = {f'AES_ACCELERATED_SANITIZERS_PASS: {route}; 2 profiles; 26 tests; 4 failing sanitizer controls'}
            for profile in ('debug', 'release'):
                expected.add(f'AES_ACCELERATED_SANITIZER_PROFILE_PASS: {route} {profile}; 13 tests')
                for mode in ('bounds', 'leak'):
                    expected.add(f'AES_SANITIZER_CONTROL_PASS: {route} {profile} {mode}')
            self.assertEqual(set(c['success']['unique_lines']), expected)
            self.assertEqual(c['success']['exact_tests'], 26)
            self.assertEqual(c['platform'], 'linux-x86_64')


if __name__ == '__main__':
    unittest.main()
