#!/usr/bin/env python3
"""Accelerated timing tooling regressions; no real measurements in this suite."""
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

SPEC = importlib.util.spec_from_file_location('accelerated_timing', Path(__file__).with_name('check-aes-accelerated-fixed-random.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class AesAcceleratedTimingTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(r.platform, 'system', return_value='Linux'))
        self.enterContext(patch.object(r.platform, 'machine', return_value='x86_64'))

    def test_cross_preparation_cannot_measure_or_omit_dit(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for options in ({}, {'with_controls': True, 'value_controls': True},
                            {'with_controls': True, 'value_controls': True, 'require_dit': True,
                             'observation': 'not-native'}):
                with self.assertRaises(ValueError):
                    r.check('1.99.1', 'direct', qemu_aarch64=True, **options)
            package.assert_not_called()

    def test_emulated_preflight_never_enters_measurement(self):
        with patch.object(r, 'execute') as execute, self.assertRaisesRegex(ValueError, 'emulation cannot collect'):
            r.validate_controls_and_observe(Path('/binary'), Path('/work'), {}, Path('/logs'),
                'ArmAes', Path('/openssl'), 'hash', 'hash', 'observation',
                execution_prefix=('qemu-aarch64', '-cpu', 'max'))
        execute.assert_not_called()

    def test_cross_probe_is_baseline_and_runs_under_explicit_emulator(self):
        with patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_DIT_HOST_BUNDLE_PASS\n', '')) as execute:
            r.probe_host('1.90.0', 'aarch64-unknown-linux-musl', Path('/probe'), Path('/work'), {}, Path('/logs'),
                         True, ('qemu-aarch64', '-cpu', 'max'))
            build, run = [call.args[0] for call in execute.call_args_list]
            self.assertIn('linker=rust-lld', build)
            self.assertNotIn('target-feature', ' '.join(build))
            self.assertEqual(run, ['qemu-aarch64', '-cpu', 'max', '/probe'])

    def test_required_dit_rejects_wrong_experiment_and_host_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for options in ({}, {'with_controls': True},
                            {'with_controls': True, 'value_controls': True}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    r.check('1.99.1', 'direct', require_dit=True, **options)
            package.assert_not_called()

    def test_dit_flags_are_explicit_and_target_limited(self):
        flags = '-Ctarget-feature=+aes,+neon'
        for target in ('aarch64-unknown-linux-gnu', 'aarch64-unknown-linux-musl', 'aarch64-apple-darwin'):
            self.assertEqual(r.dit_configuration(target, flags, 'ArmAes', True), flags + ',+dit')
            self.assertEqual(r.dit_configuration(target, flags, 'ArmAes', False), flags)
        for target, value, kernel in (('x86_64-unknown-linux-gnu', flags, 'X86AesNi'),
                                      ('aarch64-unknown-linux-musl', flags + ',+dit', 'ArmAes'),
                                      ('aarch64-unknown-none', flags, 'ArmAes')):
            with self.assertRaises(ValueError):
                r.dit_configuration(target, value, kernel, True)

    def test_required_dit_fixture_has_no_silent_default_and_detects_drift(self):
        source = (r.ROOT / 'assurance/aes-accelerated-campaigns/lib.rs').read_text()
        changed = r.dit_authority_fixture(source)
        self.assertIn('Authority::new_with_dit(kernel, public::execution::DitPolicy::Require)', changed)
        self.assertIn('if !result.get()?.dit_enabled()', changed)
        self.assertNotIn('Authority::new(kernel)', changed)
        self.assertEqual(changed.count('AES_FORCED_AUTHORITY:'), 1)
        for bad in (changed, source.replace('    result.get()?;', ''), source + source):
            with self.assertRaises(ValueError):
                r.dit_authority_fixture(bad)

    def test_baseline_dit_probe_rejects_missing_repeated_and_non_dit_markers(self):
        marker = 'AES_DIT_HOST_BUNDLE_PASS\n'
        for stdout, stderr, good in ((marker, '', True), ('', '', False),
                                     ('AES_STATIC_HOST_BUNDLE_PASS\n', '', False),
                                     (marker * 2, '', False), (marker, 'warning', False)):
            result = subprocess.CompletedProcess([], 0, stdout, stderr)
            with self.subTest(stdout=stdout, stderr=stderr), patch.object(r, 'execute', return_value=result) as execute:
                args = ('1.90.0', 'aarch64-unknown-linux-musl', Path('/probe'), Path('/work'), {}, Path('/logs'), True)
                if good:
                    self.assertEqual(r.probe_host(*args).name, 'dit-probe.rs')
                else:
                    with self.assertRaises(ValueError): r.probe_host(*args)
                self.assertEqual(execute.call_count, 2)
                self.assertNotIn('-Ctarget-feature', ' '.join(execute.call_args_list[0].args[0]))

    def test_probe_rejects_specialized_environment_before_execution(self):
        for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS'):
            with patch.object(r, 'execute') as execute, self.assertRaises(ValueError):
                r.probe_host('1.90.0', 'aarch64-unknown-linux-musl', Path('/probe'), Path('/work'),
                             {key: '-Ctarget-feature=+dit'}, Path('/logs'), True)
            execute.assert_not_called()

    def test_new_observations_require_shared_address_value_policy_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for options in ({}, {'with_controls': True}, {'value_controls': True},
                            {'with_controls': True, 'value_controls': True, 'isolate_dispatch': True},
                            {'with_controls': True, 'value_controls': True, 'long_batch': True},
                            {'with_controls': True, 'value_controls': True, 'slot_crossover': True}):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    r.check('1.99.1', 'direct', 'new-observation', **options)
            package.assert_not_called()

    def test_address_diagnostic_keeps_flags_without_claiming_a_pass(self):
        for control in ('separate-values', 'separate-identical'):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(r.platform, 'system', return_value='Darwin'), \
                 patch.object(r.platform, 'machine', return_value='arm64'), \
                 patch.object(r.performance, 'apple_host_info', return_value={}), \
                 patch.object(r.timing, 'parse', return_value=[{'alarm': True, 'inconclusive': True}]), \
                 patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0,
                     'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + control + '\nraw', '')) as execute:
                path, output = Path(temporary), io.StringIO()
                with redirect_stdout(output):
                    r.collect(Path('/binary'), path, {}, path, 'ArmAes', control, diagnostic_only=True)
                record = json.loads((path / 'summary.json').read_text())
                self.assertEqual((record['alarms'], record['inconclusive']), (1, 1))
                self.assertIn('diagnostic', record['comparison_role'])
                self.assertIn('not a timing pass', output.getvalue())
                self.assertNotIn('OBSERVED:', output.getvalue())
                execute.assert_called_once()

    def test_diagnostic_role_cannot_hide_shared_results_or_malformed_data(self):
        for control in (None, 'shared-values', 'shared-identical', 'unknown'):
            with patch.object(r, 'execute') as execute, self.assertRaises(ValueError):
                r.collect(Path('/binary'), Path('/unused'), {}, Path('/unused'), 'ArmAes', control, diagnostic_only=True)
            execute.assert_not_called()
        for stderr, parse_failure in (('error', None), ('', ValueError('malformed raw population'))):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(r.platform, 'system', return_value='Darwin'), \
                 patch.object(r.platform, 'machine', return_value='arm64'), \
                 patch.object(r.performance, 'apple_host_info', return_value={}), \
                 patch.object(r.timing, 'parse', side_effect=parse_failure), \
                 patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0,
                     'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: separate-values\nraw', stderr)), \
                 self.assertRaises(ValueError):
                path = Path(temporary)
                r.collect(Path('/binary'), path, {}, path, 'ArmAes', 'separate-values', diagnostic_only=True)

    def test_value_policy_routes_every_control_and_keeps_any_collection_failure(self):
        for failed_control in (None, *r.controls.CONTROLS):
            with tempfile.TemporaryDirectory() as temporary, patch.object(r.oracle, 'digest', return_value='hash'), \
                 patch.object(r.controls, 'preflight'), \
                 patch.object(r, 'execute', side_effect=lambda command, *args: subprocess.CompletedProcess(command, 0,
                     'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + command[-1] + '\nbody', '')), \
                 redirect_stdout(io.StringIO()):
                calls = []
                def collect(*args, **kwargs):
                    control = args[-1]
                    calls.append(control)
                    self.assertEqual(kwargs, {'diagnostic_only': True} if control.startswith('separate-') else {})
                    if control == failed_control:
                        raise ValueError('invalid collection or shared alarm/noise')
                path = Path(temporary)
                with patch.object(r, 'collect', side_effect=collect):
                    args = (Path('/binary'), path, {}, path, 'ArmAes', Path('/oracle'), 'hash', 'hash', 'declared')
                    if failed_control:
                        with self.assertRaises(ValueError): r.validate_controls_and_observe(*args, value_controls=True)
                    else:
                        r.validate_controls_and_observe(*args, value_controls=True)
                self.assertEqual(calls, list(r.controls.CONTROLS))
                record = json.loads((path / 'experiment.json').read_text())
                self.assertEqual(record['value_comparison'], 'shared-values')
                self.assertEqual(record['negative_control'], 'shared-identical')
                self.assertEqual(len(record['failures']), int(failed_control is not None))

    def test_apple_timing_keeps_alarms_and_noise_without_affinity_or_retry(self):
        for alarm, noise in ((False, False), (True, False), (False, True)):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(r.platform, 'system', return_value='Darwin'), patch.object(r.platform, 'machine', return_value='arm64'), \
                 patch.object(r.performance, 'apple_host_info', return_value={'logical_cpu':None, 'affinity':'not pinned'}), \
                 patch.object(r.os, 'sched_setaffinity', create=True) as affinity, \
                 patch.object(r.timing, 'parse', return_value=[{'alarm':alarm, 'inconclusive':noise}]), \
                 patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_FORCED_AUTHORITY: ArmAes\nraw', '')) as execute:
                path = Path(temporary)
                with redirect_stdout(io.StringIO()):
                    if alarm or noise:
                        with self.assertRaises(ValueError):r.collect(Path('/binary'), path, {}, path, 'ArmAes')
                    else:r.collect(Path('/binary'), path, {}, path, 'ArmAes')
                execute.assert_called_once();affinity.assert_not_called()
                summary = json.loads((path / 'summary.json').read_text())
                self.assertEqual((summary['alarms'], summary['inconclusive']), (int(alarm), int(noise)))
                self.assertIsNone(json.loads((path / 'host.json').read_text())['logical_cpu'])

    def test_apple_overhead_and_context_failure_never_retry(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(r.platform, 'system', return_value='Darwin'), patch.object(r.platform, 'machine', return_value='arm64'), \
             patch.object(r.performance, 'apple_host_info', return_value={'logical_cpu':None}) as host, \
             patch.object(r.dispatch, 'parse_overhead', return_value={'diagnostic_only':True}), \
             patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'raw', '')) as execute:
            path = Path(temporary)
            r.collect_overhead(Path('/binary'), path, {}, path)
            execute.assert_called_once()
            self.assertIsNone(json.loads((path / 'overhead-host.json').read_text())['logical_cpu'])
            execute.reset_mock();host.side_effect = subprocess.TimeoutExpired('sysctl', 10)
            with self.assertRaises(subprocess.TimeoutExpired):r.collect_overhead(Path('/binary'), path, {}, path)
            with self.assertRaises(subprocess.TimeoutExpired):r.collect(Path('/binary'), path, {}, path, 'ArmAes')
            execute.assert_not_called()

    def test_batch_fixture_changes_only_one_repetition_constant(self):
        source = r.controls.fixture(r.fixture(r.timing.FIXTURE.read_text()),
                                    (r.ROOT / 'assurance/aes-accelerated-campaigns/timing-controls.rs').read_text())
        source = r.dispatch.fixture(source, *( (r.ROOT / f'assurance/aes-accelerated-campaigns/timing-{name}.rs').read_text()
                                             for name in ('dispatch', 'overhead')))
        batched = r.batch.fixture(source)
        self.assertEqual(batched.replace('const REPEAT: usize = 1024;', 'const REPEAT: usize = 4;'), source)
        for bad in ('', source.replace('usize = 4;', 'usize = 5;', 1), source + '\nconst REPEAT: usize = 4;',
                    r.fixture(r.timing.FIXTURE.read_text())):
            with self.assertRaises(ValueError): r.batch.fixture(bad)

    def test_batch_policy_preserves_original_and_raw_durations(self):
        original = (r.timing.REPEAT, r.timing.HEADER, r.timing.parse)
        policy = r.batch.policy(r.timing)
        self.assertEqual(policy.REPEAT, 1024)
        self.assertEqual((policy.SAMPLES, policy.WARMUP, policy.SEED, policy.LIMIT, policy.MAX_CV),
                         (8192, 256, r.timing.SEED, 4.5, 1.0))
        with patch.object(r.timing, 'parse', return_value=['unchanged']) as parse:
            self.assertEqual(policy.parse(policy.HEADER + '\nraw durations\n'), ['unchanged'])
            parse.assert_called_once_with(r.timing.HEADER + '\nraw durations\n')
            parse.reset_mock()
            for bad in (r.timing.HEADER + '\nraw', policy.HEADER, policy.HEADER.replace('1024', '512') + '\nraw'):
                with self.assertRaises(ValueError): policy.parse(bad)
            parse.assert_not_called()
        self.assertEqual((r.timing.REPEAT, r.timing.HEADER, r.timing.parse), original)

    def test_batch_requires_controls_and_isolation_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for controls, isolation in ((False, False), (True, False), (False, True)):
                with self.assertRaises(ValueError): r.check('1.90.0', 'direct', with_controls=controls, isolate_dispatch=isolation, long_batch=True)
            package.assert_not_called()

    def test_batch_policy_reaches_preflight_overhead_and_each_control(self):
        policy = r.batch.policy(r.timing)
        for observation in (None, 'declared'):
            with tempfile.TemporaryDirectory() as temporary, patch.object(r.oracle, 'digest', return_value='hash'), \
                 patch.object(r.controls, 'preflight') as preflight, \
                 patch.object(r, 'execute', side_effect=lambda command, *args: subprocess.CompletedProcess(command, 0, 'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + command[-1] + '\nbody', '')), \
                 patch.object(r, 'collect_overhead') as overhead, patch.object(r, 'collect') as collect:
                directory = Path(temporary)
                r.validate_controls_and_observe(Path('/binary'), directory, {}, directory, 'ArmAes', Path('/oracle'), 'hash', 'hash', observation, True, policy)
                self.assertEqual(preflight.call_count, 4)
                self.assertTrue(all(c.args[-1] is policy for c in preflight.call_args_list))
                self.assertEqual(overhead.call_count, int(observation is not None))
                self.assertEqual(collect.call_count, 4 if observation else 0)
                self.assertTrue(all(c.kwargs == {'policy': policy} for c in overhead.call_args_list + collect.call_args_list))

    def test_batch_registry_is_correctness_only(self):
        checks = [c for c in tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())['checks']
                  if c.get('category') == 'aes-timing-batch-fixture']
        self.assertEqual(len(checks), 4)
        configurations = set()
        for check in checks:
            compiler, route = check['command'][3], check['command'][5]
            configurations.add((compiler, route))
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-fixed-random.py', '--toolchain', compiler, '--route', route, '--controls', '--isolate-dispatch', '--long-batch'])
            self.assertEqual(check['success']['exact_tests'], 10)
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_TIMING_BATCH_FIXTURE_PASS: {compiler} {route}; 10 tests; 936 vectors; correctness only'])
        self.assertEqual(configurations, {(c, route) for c in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_isolated_fixture_changes_only_timer_macro_and_main(self):
        source = r.controls.fixture(r.fixture(r.timing.FIXTURE.read_text()),
                                    (r.ROOT / 'assurance/aes-accelerated-campaigns/timing-controls.rs').read_text())
        dispatch = (r.ROOT / 'assurance/aes-accelerated-campaigns/timing-dispatch.rs').read_text()
        overhead = (r.ROOT / 'assurance/aes-accelerated-campaigns/timing-overhead.rs').read_text()
        result = r.dispatch.fixture(source, dispatch, overhead)
        self.assertIn(dispatch, result)
        self.assertTrue(result.endswith(overhead))
        self.assertEqual(result[result.index('width!(aes128,'):result.index('fn main()')],
                         source[source.index('width!(aes128,'):source.index('fn main()')])
        self.assertEqual(result[:result.index('// Test fixture only.')], source[:source.index('// Construction,')])
        for old in ('// Construction,', '\nwidth!(aes128,', 'mode.starts_with("public-")',
                    '    run(&args[0], controls::Control::parse(&args[1])?)'):
            with self.assertRaises(ValueError): r.dispatch.fixture(source.replace(old, 'drift', 1), dispatch, overhead)

    def test_isolated_requires_controls_before_any_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            with self.assertRaises(ValueError): r.check('1.90.0', 'direct', isolate_dispatch=True)
            package.assert_not_called()

    def test_isolated_registry_is_correctness_only(self):
        checks = [c for c in tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())['checks']
                  if c.get('category') == 'aes-timing-dispatch-fixture']
        self.assertEqual(len(checks), 4)
        configurations = set()
        for check in checks:
            command = check['command']
            compiler, route = command[3], command[5]
            configurations.add((compiler, route))
            self.assertEqual(command, ['python3', 'scripts/aes/check-aes-accelerated-fixed-random.py', '--toolchain', compiler, '--route', route, '--controls', '--isolate-dispatch'])
            self.assertEqual(check['success']['exact_tests'], 10)
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_TIMING_DISPATCH_FIXTURE_PASS: {compiler} {route}; 10 tests; 936 vectors; correctness only'])
        self.assertEqual(configurations, {(c, route) for c in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_isolated_test_population_is_exact(self):
        names = r.controls.TESTS | r.timing.TESTS | r.dispatch.TESTS
        text = '\n'.join([*(f'test {name} ... ok' for name in sorted(names)),
                          'test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'])
        r.controls.check_tests(text, r.timing, r.dispatch.TESTS)
        for bad in (text.replace('10 passed', '8 passed'), text.replace('... ok', '... FAILED', 1), text + '\n' + text.splitlines()[0]):
            with self.assertRaises(ValueError): r.controls.check_tests(bad, r.timing, r.dispatch.TESTS)

    def test_overhead_parser_replays_order_and_rejects_malformed_samples(self):
        lines = [f'AES_TIMING_OVERHEAD {r.timing.SAMPLES} {r.timing.REPEAT} {r.timing.WARMUP} {r.timing.SEED}']
        for campaign, name in enumerate(('timer', 'copy')):
            for sample, case in enumerate(list(r.timing.corpus(campaign))[r.timing.WARMUP:]):
                lines.append(f'OVERHEAD {name} {sample} {case[2]} {100 + sample % 3} {100 + sample % 3}')
        lines.append('AES_TIMING_OVERHEAD_END')
        text = '\n'.join(lines)
        summary = r.dispatch.parse_overhead(text, r.timing)
        self.assertTrue(summary['diagnostic_only'])
        self.assertEqual([row['control'] for row in summary['controls']], ['timer', 'copy'])
        self.assertTrue(all(not row['alarm'] for row in summary['controls']))
        first = lines[1].split()
        for replacement in ('', lines[1] + '\n' + lines[1], ' '.join([*first[:3], str(1-int(first[3])), *first[4:]]),
                            lines[1].replace('timer', 'copy'), ' '.join(first[:4] + ['0', '100']),
                            ' '.join(first[:4] + ['NaN', '100']), ' '.join(first[:4] + ['-1', '100'])):
            with self.assertRaises(ValueError): r.dispatch.parse_overhead(text.replace(lines[1], replacement, 1), r.timing)

    def test_overhead_collection_is_once_and_restores_affinity_on_failure(self):
        for failure in (None, ValueError('bad samples')):
            with tempfile.TemporaryDirectory() as temporary, patch.object(r.os, 'sched_getaffinity', create=True, return_value={2, 3}), \
                 patch.object(r.os, 'sched_setaffinity', create=True) as affinity, patch.object(r.timing, 'host_info', return_value={}), \
                 patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'raw', '')) as execute, \
                 patch.object(r.dispatch, 'parse_overhead', side_effect=failure, return_value={'diagnostic_only': True}):
                directory = Path(temporary)
                if failure:
                    with self.assertRaises(ValueError): r.collect_overhead(Path('/binary'), directory, {}, directory)
                else:
                    r.collect_overhead(Path('/binary'), directory, {}, directory)
                    self.assertEqual(json.loads((directory / 'overhead-summary.json').read_text()), {'diagnostic_only': True})
                execute.assert_called_once()
                self.assertEqual(execute.call_args.args[0], ['/binary', 'overhead', 'shared-identical'])
                self.assertEqual([c.args for c in affinity.call_args_list], [(0, {2}), (0, {2, 3})])

    def test_isolated_observation_checks_preflight_before_overhead_then_all_arms(self):
        for observation in (None, 'one-shot'):
            events = []
            with tempfile.TemporaryDirectory() as temporary, patch.object(r.oracle, 'digest', return_value='hash'), \
                 patch.object(r.controls, 'preflight', side_effect=lambda *args: events.append('preflight')), \
                 patch.object(r, 'execute', side_effect=lambda command, *args: subprocess.CompletedProcess(command, 0, 'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + command[-1] + '\nbody', '')), \
                 patch.object(r, 'collect_overhead', side_effect=lambda *args: events.append('overhead')), \
                 patch.object(r, 'collect', side_effect=lambda *args: events.append(args[-1])):
                directory = Path(temporary)
                r.validate_controls_and_observe(Path('/binary'), directory, {}, directory, 'ArmAes', Path('/oracle'), 'hash', 'hash', observation, True)
            self.assertEqual(events, ['preflight'] * 4 + (['overhead', *r.controls.CONTROLS] if observation else []))

    def test_control_adapter_is_reversible_and_never_changes_timer(self):
        original = r.fixture(r.timing.FIXTURE.read_text())
        module = (r.ROOT / 'assurance/aes-accelerated-campaigns/timing-controls.rs').read_text()
        adapted = r.controls.fixture(original, module)
        suffix = '\nmod controls {\n' + module + '\n}\n'
        self.assertTrue(adapted.endswith(suffix))
        restored = adapted[:-len(suffix)]
        for old, new, count in reversed(r.controls.substitutions()):
            self.assertEqual(restored.count(new), count)
            restored = restored.replace(new, old)
        self.assertEqual(restored, original)
        self.assertNotIn('Instant', module.split('#[cfg(test)]')[0].replace('// before calling the trial (and thus before Instant::now).', ''))

    def test_control_adapter_drift_rejected(self):
        source = r.fixture(r.timing.FIXTURE.read_text())
        for old, _, _ in r.controls.substitutions():
            with self.assertRaises(ValueError): r.controls.fixture(source.replace(old, 'changed', 1), '')

    def test_control_output_and_test_population_are_exact(self):
        for control in r.controls.CONTROLS:
            text = 'AES_TIMING_CONTROL: ' + control + '\nbody\n'
            self.assertEqual(r.controls.payload(text, control), 'body\n')
            for bad in ('', text.replace(control, 'wrong'), 'extra\n' + text):
                with self.assertRaises(ValueError): r.controls.payload(bad, control)
        good = '\n'.join([*(f'test {name} ... ok' for name in sorted(r.controls.TESTS | r.timing.TESTS)),
                         'test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'])
        r.controls.check_tests(good, r.timing)
        for bad in ('', good.replace('8 passed', '7 passed'), good.replace('... ok', '... ignored', 1),
                    good + '\n' + good.splitlines()[0]):
            with self.assertRaises(ValueError): r.controls.check_tests(bad, r.timing)

    def test_control_oracle_checks_all_values_and_classes(self):
        for control in r.controls.CONTROLS:
            expected = [r.timing.HEADER]
            calls = []
            for campaign, (bits, owner, mode) in enumerate(r.timing.CAMPAIGNS):
                cases = list(r.timing.corpus(campaign))
                for sample in (0, r.timing.SAMPLES // 2, r.timing.SAMPLES - 1):
                    for cls in (0, 1):
                        chosen = 0 if control.endswith('-identical') else cls
                        key, block = r.timing.inputs(cases[r.timing.WARMUP + sample], bits, mode, chosen)
                        calls.append((bits, key, block, mode.startswith('decrypt-')))
                        expected.append(f'VECTOR {bits} {owner} {mode} {sample} {cls} ' + bytes([len(calls) % 256] * 16).hex())
            text = '\n'.join(expected + ['AES_FIXED_RANDOM_END preflight'])
            def oracle(command, **kwargs):
                bits, key, block, inverse = calls.pop(0)
                self.assertEqual(command[2], f'-aes-{bits}-ecb')
                self.assertEqual(command[6], key.hex())
                self.assertEqual(command[7], '-d' if inverse else '-e')
                self.assertEqual(kwargs['input'], block)
                return subprocess.CompletedProcess(command, 0, bytes([(234 - len(calls)) % 256] * 16), b'')
            with patch.object(r.controls.subprocess, 'run', side_effect=oracle):
                r.controls.preflight(text, control, Path('/oracle'), {}, r.timing)
            self.assertEqual(calls, [])
            with patch.object(r.controls.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2, b'', b'error')):
                with self.assertRaises(ValueError): r.controls.preflight(text, control, Path('/oracle'), {}, r.timing)

    def test_control_experiment_completes_declared_arms_once_despite_alarms(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(r.oracle, 'digest', return_value='hash'), \
             patch.object(r.controls, 'preflight') as preflight, \
             patch.object(r, 'execute', side_effect=lambda command, *args: subprocess.CompletedProcess(command, 0, 'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + command[-1] + '\nbody', '')), \
             patch.object(r, 'collect', side_effect=[ValueError('alarm'), None, ValueError('noise'), None]) as collect, \
             redirect_stdout(io.StringIO()):
            directory = Path(temporary)
            with self.assertRaises(ValueError):
                r.validate_controls_and_observe(Path('/binary'), directory, {}, directory, 'ArmAes', Path('/oracle'), 'hash', 'hash', 'named')
            self.assertEqual(preflight.call_count, 4)
            self.assertEqual([c.args[-1] for c in collect.call_args_list], list(r.controls.CONTROLS))
            record = json.loads((directory / 'experiment.json').read_text())
            self.assertEqual([row['error'] for row in record['failures']], ['alarm', 'noise'])

    def test_controls_default_and_bad_preflight_do_not_measure(self):
        for valid in (True, False):
            with tempfile.TemporaryDirectory() as temporary, patch.object(r.oracle, 'digest', return_value='hash'), \
                 patch.object(r.controls, 'preflight', side_effect=None if valid else ValueError('bad vector')), \
                 patch.object(r, 'execute', side_effect=lambda command, *args: subprocess.CompletedProcess(command, 0, 'AES_FORCED_AUTHORITY: ArmAes\nAES_TIMING_CONTROL: ' + command[-1] + '\nbody', '')), \
                 patch.object(r, 'collect') as collect:
                args = (Path('/binary'), Path(temporary), {}, Path(temporary), 'ArmAes', Path('/oracle'), 'hash', 'hash', None if valid else 'named')
                if valid:
                    r.validate_controls_and_observe(*args)
                else:
                    with self.assertRaises(ValueError): r.validate_controls_and_observe(*args)
                collect.assert_not_called()

    def test_controls_registry_never_measures(self):
        checks = [c for c in tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())['checks']
                  if c.get('category') == 'aes-timing-controls-fixture']
        self.assertEqual(len(checks), 4)
        for check in checks:
            command = check['command']
            compiler, route = command[3], command[5]
            self.assertEqual(command, ['python3', 'scripts/aes/check-aes-accelerated-fixed-random.py', '--toolchain', compiler, '--route', route, '--controls'])
            self.assertEqual(check['success']['exact_tests'], 8)
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_TIMING_CONTROLS_FIXTURE_PASS: {compiler} {route}; 8 tests; 936 vectors; correctness only'])

    def test_fixture_adaptation_is_reversible_and_policy_unchanged(self):
        original = r.timing.FIXTURE.read_text()
        adapted = r.fixture(original)
        self.assertNotIn('brynja_aes_public_api_fixture', adapted)
        self.assertIn('$key::new(authority, ', adapted)
        self.assertEqual(adapted.count('$cached::new(authority, '), 2)
        for old, new, count in reversed(r.substitutions()):
            self.assertEqual(adapted.count(new), count)
            adapted = adapted.replace(new, old)
        self.assertEqual(adapted, original)
        self.assertEqual((r.timing.SAMPLES, r.timing.REPEAT, r.timing.WARMUP, r.timing.LIMIT, r.timing.MAX_CV),
                         (8192, 4, 256, 4.5, 1.0))
        self.assertEqual(len(r.timing.CAMPAIGNS), 39)

    def test_fixture_drift_fails_closed(self):
        original = r.timing.FIXTURE.read_text()
        for old, _, _ in r.substitutions():
            with self.subTest(anchor=old), self.assertRaises(ValueError):
                r.fixture(original.replace(old, 'unexpected-plumbing', 1))

    def test_authority_is_exact_and_parser_receives_unmodified_payload(self):
        for kernel in ('X86AesNi', 'ArmAes'):
            marker = r.performance.authority_marker(kernel)
            self.assertEqual(r.payload(marker + '\na\nb\n', kernel), 'a\nb\n')
            for bad in ('', marker, 'extra\n' + marker + '\n', marker.replace(kernel, 'Portable') + '\n'):
                with self.assertRaises(ValueError): r.payload(bad, kernel)
            with self.assertRaises(ValueError):
                r.timing.parse(r.payload(marker + '\n' + marker + '\n', kernel))

    def test_configuration_rejected_before_packaging(self):
        with patch.object(r.packaged, 'package_sources') as package:
            for compiler, route, name in [('stable', 'direct', None), ('1.90.0', 'unknown', None),
                                          ('1.90.0', 'direct', '../escape'), ('1.90.0', 'direct', '')]:
                with self.assertRaises(ValueError): r.check(compiler, route, name)
            for name in r.performance.REJECT:
                with patch.dict(r.os.environ, {name: 'injected'}), self.assertRaises(ValueError):
                    r.check('1.90.0', 'direct')
            package.assert_not_called()

    def test_existing_observation_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(r, 'ROOT', Path(temporary)), \
             patch.dict(r.os.environ, {}, clear=True), patch.object(r.oracle, 'select', return_value=Path('/oracle')), \
             patch.object(r.oracle, 'digest', return_value='digest'), \
             patch.object(r.performance, 'native_configuration', return_value=('target', 'flags', 'ArmAes')), \
             patch.object(r.packaged, 'package_sources') as package:
            path = Path(temporary) / 'target/aes-accelerated-fixed-random/retained'
            path.mkdir(parents=True)
            (path / 'measure.json').write_text('original')
            with self.assertRaises(FileExistsError): r.check('1.90.0', 'direct', 'retained', with_controls=True, value_controls=True)
            self.assertEqual((path / 'measure.json').read_text(), 'original')
            package.assert_not_called()

    def test_collection_retains_alarm_and_noise_before_failing_without_retry(self):
        for alarm, noise in ((False, False), (True, False), (False, True), (True, True)):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                rows = [{'alarm': alarm, 'inconclusive': noise}]
                stream = io.StringIO()
                with patch.object(r.os, 'sched_getaffinity', create=True, return_value={1, 3}), \
                     patch.object(r.os, 'sched_setaffinity', create=True) as affinity, \
                     patch.object(r.timing, 'host_info', return_value={'logical_cpu': 1}), \
                     patch.object(r.timing, 'parse', return_value=rows), \
                     patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_FORCED_AUTHORITY: ArmAes\nraw', '')) as execute, \
                     redirect_stdout(stream):
                    if alarm or noise:
                        with self.assertRaises(ValueError): r.collect(Path('/binary'), directory, {}, directory, 'ArmAes')
                        self.assertNotIn('OBSERVED:', stream.getvalue())
                    else:
                        r.collect(Path('/binary'), directory, {}, directory, 'ArmAes')
                        self.assertIn('OBSERVED:', stream.getvalue())
                    execute.assert_called_once()
                    self.assertEqual(affinity.call_args_list[0].args, (0, {1}))
                    self.assertEqual(affinity.call_args_list[-1].args, (0, {1, 3}))
                summary = json.loads((directory / 'summary.json').read_text())
                self.assertEqual(summary, {'campaigns': rows, 'alarms': int(alarm), 'inconclusive': int(noise)})

    def test_collection_restores_affinity_on_process_and_parse_failures(self):
        for error in (ValueError('bad output'), subprocess.TimeoutExpired('binary', 600)):
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(r.os, 'sched_getaffinity', create=True, return_value={2, 4}), \
                 patch.object(r.os, 'sched_setaffinity', create=True) as affinity, \
                 patch.object(r.timing, 'host_info', return_value={}), \
                 patch.object(r, 'execute', side_effect=error) as execute:
                with self.assertRaises(type(error)):
                    r.collect(Path('/binary'), Path(temporary), {}, Path(temporary), 'ArmAes')
                execute.assert_called_once()
                self.assertEqual(affinity.call_args_list[-1].args, (0, {2, 4}))

    def test_raw_failures_and_timeouts_are_saved_by_shared_executor(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.performance.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2, 'partial samples', 'failure')):
                with self.assertRaises(ValueError): r.execute(['binary'], directory, {}, directory, 'failure')
            self.assertEqual(json.loads((directory / 'failure.json').read_text())['stdout'], 'partial samples')
            with patch.object(r.packaged.archives.cargo_environment, 'check'), \
                 patch.object(r.performance.subprocess, 'run', side_effect=subprocess.TimeoutExpired('binary', 600, output=b'partial')):
                with self.assertRaises(subprocess.TimeoutExpired): r.execute(['binary'], directory, {}, directory, 'timeout')
            self.assertEqual(json.loads((directory / 'timeout.json').read_text())['stdout'], 'partial')

    def test_registry_is_correctness_only_and_covers_both_routes_and_compilers(self):
        registry = tomllib.loads((r.ROOT / 'verification/checks.toml').read_text())
        checks = [c for c in registry['checks'] if c.get('category') == 'aes-accelerated-timing-fixture']
        self.assertEqual(len(checks), 4)
        configurations = set()
        for check in checks:
            compiler, route = check['command'][3], check['command'][5]
            configurations.add((compiler, route))
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-fixed-random.py', '--toolchain', compiler, '--route', route])
            self.assertEqual(check['success']['exact_tests'], 4)
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_TIMING_FIXTURE_PASS: {compiler} {route}; 4 tests; 234 vectors; correctness only'])
            self.assertTrue(set(r.performance.REJECT) <= set(check['reject_environment']))
            self.assertIn('aes-accelerated-timing', check['inputs'])
            self.assertIn('aes-fixed-random', check['inputs'])
        self.assertEqual(configurations, {(c, route) for c in ('1.90.0', '1.99.1') for route in ('direct', 'facade')})

    def test_default_does_not_measure_and_failed_preflight_never_measures(self):
        for observation in (None, 'named'):
            for valid in (True, False):
                with patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_FORCED_AUTHORITY: ArmAes\nbody', '')), \
                     patch.object(r.timing, 'preflight', side_effect=None if valid else ValueError('wrong vector')) as preflight, \
                     patch.object(r.oracle, 'digest', return_value='digest'), patch.object(r, 'collect') as collect:
                    args = (Path('/binary'), Path('/directory'), {}, Path('/artifacts'), 'ArmAes', Path('/oracle'), 'digest', 'digest', observation)
                    if valid:
                        r.validate_and_observe(*args)
                    else:
                        with self.assertRaises(ValueError): r.validate_and_observe(*args)
                    self.assertEqual(collect.call_count, int(valid and observation is not None))
                    preflight.assert_called_once_with('body', Path('/oracle'), {})

    def test_binary_and_oracle_identity_are_checked_even_after_alarm(self):
        for failure in (None, ValueError('alarm'), subprocess.TimeoutExpired('binary', 600)):
            with patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_FORCED_AUTHORITY: ArmAes\nbody', '')), \
                 patch.object(r.timing, 'preflight'), patch.object(r.oracle, 'digest', return_value='digest') as digest, \
                 patch.object(r, 'collect', side_effect=failure):
                args = (Path('/binary'), Path('/directory'), {}, Path('/artifacts'), 'ArmAes', Path('/oracle'), 'digest', 'digest', 'named')
                if failure:
                    with self.assertRaises(type(failure)): r.validate_and_observe(*args)
                else:
                    r.validate_and_observe(*args)
                self.assertEqual([call.args[0] for call in digest.call_args_list],
                                 [Path('/binary'), Path('/oracle'), Path('/binary'), Path('/oracle')])
        with patch.object(r, 'execute', return_value=subprocess.CompletedProcess([], 0, 'AES_FORCED_AUTHORITY: ArmAes\nbody', '')), \
             patch.object(r.timing, 'preflight'), patch.object(r.oracle, 'digest', return_value='changed'), \
             patch.object(r, 'collect') as collect:
            with self.assertRaises(ValueError): r.validate_and_observe(*args)
            collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
