#!/usr/bin/env python3
"""Performance-tool regressions; these tests never collect timing samples."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('aes_performance', Path(__file__).with_name('check-aes-performance.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def output():
    lines = ['AES_FORCED_AUTHORITY: X86AesNi', r.PREFLIGHT, r.HEADER]
    for bits in (128, 192, 256):
        for owner in ('raw', 'cached'):
            for operation in r.OPERATIONS:
                for sample in range(r.SAMPLES):
                    order = ('portable', 'accelerated') if sample % 2 == 0 else ('accelerated', 'portable')
                    for backend in order:
                        lines.append(f'SAMPLE {bits} {owner} {operation} {sample} {backend} {64 * (sample + 1)}')
    return '\n'.join([*lines, r.END])


class AesPerformanceTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(r.platform, 'system', return_value='Linux'))
        self.enterContext(patch.object(r.platform, 'machine', return_value='x86_64'))

    def test_native_configuration_is_explicit_and_architecture_specific(self):
        self.assertEqual(r.native_configuration('Linux', 'x86_64'),
                         ('x86_64-unknown-linux-gnu', '-Ctarget-feature=+aes,+sse2', 'X86AesNi'))
        self.assertEqual(r.native_configuration('Linux', 'aarch64'),
                         ('aarch64-unknown-linux-gnu', '-Ctarget-feature=+aes,+neon', 'ArmAes'))
        self.assertEqual(r.native_configuration('Darwin', 'arm64'),
                         ('aarch64-apple-darwin', '-Ctarget-feature=+aes,+neon', 'ArmAes'))
        for system, machine in (('Darwin', 'x86_64'), ('Darwin', 'aarch64'), ('Linux', 'arm'), ('Linux', 'riscv64'), ('Windows', 'x86_64')):
            with self.assertRaises(ValueError):r.native_configuration(system, machine)

    def test_apple_affinity_is_explicitly_unpinned_and_never_calls_linux_api(self):
        with patch.object(r.platform, 'system', return_value='Darwin'), \
             patch.object(r.platform, 'machine', return_value='arm64'), \
             patch.object(r.os, 'sched_getaffinity', create=True) as get, \
             patch.object(r.os, 'sched_setaffinity', create=True) as set_affinity:
            with r.measurement_affinity() as cpu:
                self.assertIsNone(cpu)
            with self.assertRaisesRegex(ValueError, 'body failed'):
                with r.measurement_affinity():raise ValueError('body failed')
            get.assert_not_called();set_affinity.assert_not_called()

    def test_linux_affinity_error_never_silently_becomes_unpinned(self):
        with patch.object(r.os, 'sched_getaffinity', return_value=set(), create=True), \
             patch.object(r.os, 'sched_setaffinity', create=True) as set_affinity:
            with self.assertRaises(ValueError):
                with r.measurement_affinity():self.fail('empty affinity admitted')
            set_affinity.assert_not_called()
        with patch.object(r.os, 'sched_getaffinity', return_value={2, 3}, create=True), \
             patch.object(r.os, 'sched_setaffinity', side_effect=[OSError('pin failed'), None], create=True) as set_affinity:
            with self.assertRaises(OSError):
                with r.measurement_affinity():self.fail('failed pin admitted')
            self.assertEqual([c.args for c in set_affinity.call_args_list], [(0, {2}), (0, {2, 3})])

    def test_unsupported_measurement_platform_never_yields(self):
        for system, machine in (('Darwin', 'x86_64'), ('Windows', 'arm64')):
            with patch.object(r.platform, 'system', return_value=system), patch.object(r.platform, 'machine', return_value=machine):
                with self.assertRaises(ValueError):
                    with r.measurement_affinity():self.fail('unsupported platform admitted')

    def test_apple_host_queries_are_bounded_and_report_no_pinning(self):
        with patch.object(r.platform, 'system', return_value='Darwin'), \
             patch.object(r.platform, 'machine', return_value='arm64'), \
             patch.object(r.platform, 'platform', return_value='Darwin-test'), \
             patch.object(r.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'value\n', '')) as run:
            host = r.apple_host_info()
            self.assertIsNone(host['logical_cpu']);self.assertIn('not pinned', host['affinity'])
            self.assertEqual(run.call_count, 4)
            self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/sw_vers'])
            for call in run.call_args_list:
                self.assertEqual(call.kwargs, dict(capture_output=True, text=True, timeout=10, check=True))
            for result in (subprocess.CompletedProcess([], 0, '', ''), subprocess.CompletedProcess([], 0, 'value', 'warning')):
                run.return_value = result
                with self.assertRaises(ValueError):r.apple_host_info()

    def test_apple_performance_collects_once_and_retains_unpinned_context(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(r.platform, 'system', return_value='Darwin'), patch.object(r.platform, 'machine', return_value='arm64'), \
             patch.object(r, 'apple_host_info', return_value={'logical_cpu':None, 'affinity':'not pinned'}), \
             patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, output().replace('X86AesNi', 'ArmAes'), '')) as execute:
            path = Path(temporary)
            with redirect_stdout(io.StringIO()):r.collect(Path('/binary'), path, {}, path, 'ArmAes')
            execute.assert_called_once()
            self.assertIsNone(json.loads((path / 'host.json').read_text())['logical_cpu'])
            self.assertEqual(len(json.loads((path / 'summary.json').read_text())), 48)

    def test_arm_output_requires_arm_authority_and_preserves_all_samples(self):
        arm = output().replace('X86AesNi', 'ArmAes')
        self.assertEqual(r.parse(arm, 'ArmAes'), r.parse(output()))
        r.preflight('AES_FORCED_AUTHORITY: ArmAes\n' + r.PREFLIGHT, 'ArmAes')
        for text, kernel in ((arm, 'X86AesNi'), (output(), 'ArmAes'), (arm, 'Portable')):
            with self.assertRaises(ValueError):r.parse(text, kernel)
            with self.assertRaises(ValueError):r.preflight('\n'.join(text.splitlines()[:2]), kernel)

    def test_fixed_policy_and_all_samples_retained(self):
        self.assertEqual((r.SAMPLES, r.BATCH, r.WARMUP), (9, 64, 8))
        rows = r.parse(output())
        self.assertEqual(len(rows), 48)
        for row in rows:
            self.assertEqual(row['samples_ns'], [64 * n for n in range(1, 10)])
            self.assertEqual((row['median_ns_per_operation'], row['min_ns_per_operation'], row['max_ns_per_operation']), (5, 1, 9))

    def test_slow_or_noisy_samples_are_not_rejected_or_cropped(self):
        text = output().replace('portable 64', 'portable 999999999999999999', 1)
        row = r.parse(text)[0]
        self.assertEqual(len(row['samples_ns']), 9)
        self.assertEqual(row['samples_ns'][0], 999999999999999999)
        self.assertGreater(row['max_ns_per_operation'], 10**12)

    def test_parser_rejects_missing_duplicate_reordered_and_wrong_identity(self):
        text = output()
        lines = text.splitlines()
        bad = ['', text.replace(r.HEADER, 'wrong'), '\n'.join(lines[:-1]),
               '\n'.join(lines[:3] + lines[4:]), '\n'.join(lines[:4] + lines[3:]),
               '\n'.join(lines[:3] + [lines[4], lines[3]] + lines[5:]),
               text.replace('SAMPLE 128', 'SAMPLE 192', 1), text.replace('raw construct-clear', 'cached construct-clear', 1),
               text.replace('X86AesNi', 'ArmAes')]
        for value in ('0', '-1', 'NaN', '1.2', '10000000000000000000'):
            bad.append(text.replace('portable 64', 'portable ' + value, 1))
        for text in bad:
            with self.assertRaises(ValueError): r.parse(text)

    def test_preflight_is_exact(self):
        good = 'AES_FORCED_AUTHORITY: X86AesNi\n' + r.PREFLIGHT
        r.preflight(good)
        for text in ('', good + '\n' + r.PREFLIGHT, good.replace('48', '47'), good.replace('X86AesNi', 'ArmAes')):
            with self.assertRaises(ValueError): r.preflight(text)

    def test_unit_test_count_names_and_outcomes_are_pinned(self):
        good = '\n'.join([*(f'test {name} ... ok' for name in sorted(r.TESTS)),
            'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'])
        r.check_tests(good)
        for bad in ('', good.replace('4 passed', '3 passed'), good.replace('0 ignored', '1 ignored'),
                    good.replace('... ok', '... ignored', 1), good.replace('tests::every_route', 'other::every_route'),
                    good + '\n' + good.splitlines()[0], good + '\n' + good.splitlines()[-1]):
            with self.assertRaises(ValueError): r.check_tests(bad)

    def test_profile_is_identical_for_both_backends(self):
        versions = {name: '0.1.0' for name in r.packaged.archives.MODERN}
        for route in ('direct', 'facade'):
            doc = tomllib.loads(r.manifest(versions, route))
            self.assertEqual(doc['profile']['release'], {'overflow-checks': True, 'opt-level': 3,
                                                       'lto': 'fat', 'codegen-units': 1, 'panic': 'unwind'})
            dependency = 'brynja-crypto' if route == 'direct' else 'brynja'
            self.assertEqual(doc['dependencies'][dependency]['features'], ['aes-static-execution'])

    def test_configuration_and_environment_fail_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for compiler, route, observation in [('stable', 'direct', None), ('1.90.0', 'other', None),
                                                ('1.90.0', 'direct', '../escape'), ('1.90.0', 'direct', '')]:
                with self.assertRaises(ValueError): r.check(compiler, route, observation)
            for name in r.REJECT:
                with patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError): r.check('1.90.0', 'direct')
            with patch.object(r.platform, 'machine', return_value='riscv64'), self.assertRaises(ValueError): r.check('1.90.0', 'direct')
            package.assert_not_called()

    def test_observation_directory_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(r, 'ROOT', Path(temporary)), \
             patch.dict(r.os.environ, {}, clear=True), patch.object(r.platform, 'machine', return_value='x86_64'), \
             patch.object(r.platform, 'system', return_value='Linux'), patch.object(r.packaged, 'package_sources') as package:
            (Path(temporary) / 'target/aes-performance/already-measured').mkdir(parents=True)
            with self.assertRaises(FileExistsError): r.check('1.90.0', 'direct', 'already-measured')
            package.assert_not_called()

    def test_execute_retains_failures_and_timeout_partial_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2, 'partial', 'failure')):
                with self.assertRaises(ValueError): r.execute(['binary'], directory, {}, directory, 'failure')
            record = json.loads((directory / 'failure.json').read_text())
            self.assertEqual((record['returncode'], record['stdout'], record['stderr']), (2, 'partial', 'failure'))
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.subprocess, 'run', side_effect=subprocess.TimeoutExpired('binary', 600, output=b'partial', stderr=b'error')):
                with self.assertRaises(subprocess.TimeoutExpired): r.execute(['binary'], directory, {}, directory, 'timeout')
            record = json.loads((directory / 'timeout.json').read_text())
            self.assertTrue(record['timeout'])
            self.assertEqual((record['stdout'], record['stderr']), ('partial', 'error'))

    def test_collection_restores_affinity_and_never_retries(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for result in (subprocess.CompletedProcess([], 0, output(), ''), subprocess.CompletedProcess([], 0, 'bad', '')):
                stream = io.StringIO()
                with patch.object(r.os, 'sched_getaffinity', create=True, return_value={1, 2}), patch.object(r.os, 'sched_setaffinity', create=True) as affinity, \
                     patch.object(r, 'execute', return_value=result) as execute, redirect_stdout(stream):
                    if result.stdout == 'bad':
                        with self.assertRaises(ValueError): r.collect(Path('/binary'), directory, {}, directory)
                        self.assertNotIn('AES_PERFORMANCE_OBSERVED:', stream.getvalue())
                    else:
                        r.collect(Path('/binary'), directory, {}, directory)
                        self.assertIn('AES_PERFORMANCE_OBSERVED:', stream.getvalue())
                    self.assertEqual(execute.call_count, 1)
                    self.assertEqual(affinity.call_args_list[0].args, (0, {1}))
                    self.assertEqual(affinity.call_args_list[-1].args, (0, {1, 2}))

    def test_registry_never_measures_implicitly(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-performance-fixture']
        self.assertEqual(len(checks), 4)
        for c in checks:
            compiler, route = c['command'][3], c['command'][5]
            self.assertEqual(c['command'], ['python3', 'scripts/aes/check-aes-performance.py', '--toolchain', compiler, '--route', route])
            self.assertTrue(set(r.REJECT) <= set(c['reject_environment']))
            self.assertEqual(c['success']['exact_tests'], 4)
            self.assertEqual(c['success']['unique_lines'], [f'AES_PERFORMANCE_FIXTURE_PASS: {compiler} {route}; 4 tests; 48 cases; correctness only'])


if __name__ == '__main__':
    unittest.main()
