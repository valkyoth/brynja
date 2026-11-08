#!/usr/bin/env python3
"""Fail-closed controls for the fixed/random harness, not timing measurements."""
import contextlib
import importlib.util
import io
import math
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_fixed_random', Path(__file__).with_name('check-aes-fixed-random.py'))
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


class FixedRandomTests(unittest.TestCase):
    def short_policy(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(timing, 'SAMPLES', 4))
        stack.enter_context(patch.object(timing, 'WARMUP', 2))
        return stack

    def output(self, pairs=None):
        pairs = pairs or [(100, 101), (101, 100), (100, 101), (101, 100)]
        lines = [timing.HEADER]
        for campaign, (bits, owner, mode) in enumerate(timing.CAMPAIGNS):
            cases = list(timing.corpus(campaign))[timing.WARMUP:]
            for sample, (case, pair) in enumerate(zip(cases, pairs)):
                lines.append(f'SAMPLE {bits} {owner} {mode} {sample} {case[2]} {pair[0]} {pair[1]}')
        return '\n'.join(lines + ['AES_FIXED_RANDOM_END measure'])

    def test_policy_is_fixed_and_all_widths_owners_operations_present(self):
        self.assertEqual((timing.SAMPLES, timing.REPEAT, timing.WARMUP, timing.LIMIT, timing.MAX_CV),
                         (8192, 4, 256, 4.5, 1.0))
        self.assertEqual(len(set(timing.CAMPAIGNS)), 39)
        for bits in (128, 192, 256):
            for owner in ('ephemeral', 'cached'):
                self.assertEqual({m for b, o, m in timing.CAMPAIGNS if (b, o) == (bits, owner)}, set(timing.MODES))
            self.assertIn((bits, 'cached-import', 'import-key'), timing.CAMPAIGNS)

    def test_generator_and_class_isolation(self):
        with patch.object(timing, 'SEED', 0):
            case = next(timing.corpus(0))
            self.assertEqual(case[0][:8].hex(), 'afcd1d7b39a820e2')
            self.assertEqual(case[0][8:16].hex(), 'f465b9a16a9e786e')
        cases = list(timing.corpus(0))
        self.assertEqual(len(cases), 8448)
        self.assertEqual(cases, list(timing.corpus(0)))
        self.assertNotEqual(cases, list(timing.corpus(1)))
        self.assertEqual({c[2] for c in cases}, {0, 1})
        for bits, _, mode in timing.CAMPAIGNS:
            fixed = timing.inputs(cases[256], bits, mode, 0)
            random = timing.inputs(cases[256], bits, mode, 1)
            self.assertEqual(tuple(map(len, fixed)), (bits // 8, 16))
            varied = 0 if mode.endswith('-key') else 1
            self.assertEqual(fixed[varied], bytes(len(fixed[varied])))
            self.assertNotEqual(fixed[varied], random[varied])
            self.assertEqual(fixed[1 - varied], random[1 - varied])

    def test_statistics_known_answers_and_singular_signal(self):
        with self.short_policy():
            row = timing.screen([(1, 2), (2, 3), (3, 4), (4, 5)])
            self.assertAlmostEqual(row['welch_abs_t'], math.sqrt(1.2))
            self.assertIsNone(row['paired_abs_t'])
            self.assertTrue(row['alarm'])
            neutral = timing.screen([(100, 101), (101, 100)] * 2)
            self.assertEqual(neutral['welch_abs_t'], 0)
            self.assertEqual(neutral['paired_abs_t'], 0)
            self.assertFalse(neutral['alarm'])
            self.assertFalse(neutral['inconclusive'])

    def test_noise_constant_samples_and_invalid_populations_do_not_pass(self):
        with self.short_policy():
            self.assertTrue(timing.screen([(1, 1), (1, 1), (1, 1), (10000, 10000)])['inconclusive'])
            self.assertTrue(timing.screen([(100, 100)] * 4)['inconclusive'])
            for pairs in ([], [(1, 1)] * 3, [(0, 1)] * 4, [(-1, 1)] * 4,
                          [(True, 1)] * 4, [(1.0, 1)] * 4, [(10**19, 1)] * 4):
                with self.assertRaises(ValueError):
                    timing.screen(pairs)

    def test_strict_parser_rejects_missing_duplicate_order_and_bad_values(self):
        with self.short_policy():
            good = self.output()
            self.assertEqual(len(timing.parse(good)), 39)
            lines = good.splitlines()
            bad = [good.replace(timing.HEADER, 'OTHER'), '\n'.join(lines[:-1]),
                   '\n'.join(lines[:2] + lines[3:]), '\n'.join(lines[:2] + lines[1:]),
                   good.replace('SAMPLE 128', 'SAMPLE 256', 1)]
            for field, value in ((4, '8'), (5, '2'), (6, '0'), (7, 'nan'), (6, '-1')):
                altered = lines.copy()
                words = altered[1].split(); words[field] = value
                altered[1] = ' '.join(words); bad.append('\n'.join(altered))
            for output in bad:
                with self.assertRaises(ValueError):
                    timing.parse(output)

    def test_alarm_and_noise_print_analysis_but_never_success(self):
        with self.short_policy():
            for pairs in ([(100, 200), (101, 201)] * 2, [(100, 100)] * 4):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream), self.assertRaises(ValueError):
                    timing.finish(self.output(pairs))
                self.assertIn('"campaigns"', stream.getvalue())
                self.assertNotIn(timing.MARKER, stream.getvalue())
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                timing.finish(self.output())
            self.assertEqual(stream.getvalue().count(timing.MARKER), 1)

    def test_preflight_binds_generated_inputs_to_one_oracle(self):
        with self.short_policy():
            expected = [timing.HEADER]
            calls = []
            for campaign, (bits, owner, mode) in enumerate(timing.CAMPAIGNS):
                cases = list(timing.corpus(campaign))
                for sample in (0, 2, 3):
                    for cls in (0, 1):
                        key, block = timing.inputs(cases[2 + sample], bits, mode, cls)
                        calls.append((key, block, mode.startswith('decrypt-')))
                        expected.append(f'VECTOR {bits} {owner} {mode} {sample} {cls} ' + '42' * 16)
            good = '\n'.join(expected + ['AES_FIXED_RANDOM_END preflight'])
            result = subprocess.CompletedProcess([], 0, b'B' * 16, b'')
            with patch.object(timing.subprocess, 'run', return_value=result) as run:
                timing.preflight(good, Path('/trusted/openssl'), {'OPENSSL_CONF': '/dev/null'})
                self.assertEqual(len(run.call_args_list), 234)
                for call, (key, block, inverse) in zip(run.call_args_list, calls):
                    command = call.args[0]
                    self.assertEqual(command[0], '/trusted/openssl')
                    self.assertEqual(command[-2:], [key.hex(), '-d' if inverse else '-e'])
                    self.assertEqual(call.kwargs['input'], block)
                with self.assertRaises(ValueError):
                    timing.preflight(good.replace('4242', '4343', 1), Path('/trusted/openssl'), {})
            with patch.object(timing.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
                with self.assertRaises(ValueError):
                    timing.preflight(good, Path('/trusted/openssl'), {})

    def test_collect_preserves_raw_output_and_stops_on_failed_preflight(self):
        stream = io.StringIO()
        result = subprocess.CompletedProcess([], 0, 'RAW PREFLIGHT\n', '')
        with patch.object(timing.subprocess, 'run', return_value=result) as run, \
                patch.object(timing, 'preflight', side_effect=ValueError('bad oracle')), \
                contextlib.redirect_stdout(stream), self.assertRaises(ValueError):
            timing.collect(Path('/binary'), {}, Path('/openssl'))
        self.assertEqual(run.call_count, 1)
        self.assertIn('RAW PREFLIGHT', stream.getvalue())
        self.assertNotIn(timing.MARKER, stream.getvalue())

    def test_collect_retains_timeout_output_without_success(self):
        stream = io.StringIO()
        with patch.object(timing.subprocess, 'run', side_effect=subprocess.TimeoutExpired('binary', 600, output=b'PARTIAL\n')), \
                contextlib.redirect_stdout(stream), self.assertRaisesRegex(ValueError, 'timeout'):
            timing.collect(Path('/binary'), {}, Path('/openssl'))
        self.assertEqual(stream.getvalue(), 'PARTIAL\n')

    def test_preparation_copies_fixture_and_pins_final_link_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            manifest = directory / 'Cargo.toml'
            manifest.write_text('[profile.release]\noverflow-checks=true\n')
            timing.prepare(directory)
            self.assertEqual((directory / 'src/bin/fixed-random.rs').read_bytes(), timing.FIXTURE.read_bytes())
            self.assertEqual(tomllib.loads(manifest.read_text())['profile']['release'],
                             {'overflow-checks': True, 'opt-level': 3, 'lto': 'fat', 'codegen-units': 1, 'panic': 'abort'})
            manifest.write_text('')
            with self.assertRaises(ValueError):
                timing.prepare(directory)
            for name in ('missing', 'link'):
                path = directory / name
                if name == 'link':
                    path.symlink_to(timing.FIXTURE)
                with patch.object(timing, 'FIXTURE', path), self.assertRaises(ValueError):
                    timing.prepare(directory)

    def test_harness_test_population_exact(self):
        good = '\n'.join(f'test {name} ... ok' for name in sorted(timing.TESTS)) + '\n' + \
            'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
        timing.check_tests(good)
        for bad in (good.replace(' ... ok', ' ... ignored', 1), good + good,
                    good.replace('4 passed', '0 passed'), '\n'.join(good.splitlines()[1:])):
            with self.assertRaises(ValueError):
                timing.check_tests(bad)

    def test_unsupported_configuration_and_overrides_rejected_before_build(self):
        with self.assertRaises(ValueError):
            timing.check('nightly')
        with patch.object(timing.platform, 'system', return_value='Windows'), self.assertRaises(ValueError):
            timing.check('1.99.1')
        for name in (*timing.packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH', *timing.oracle.FORBIDDEN):
            with patch.dict(os.environ, {name: 'unexpected'}, clear=True), \
                    patch.object(timing.packaged, 'package_sources') as build, self.assertRaises(ValueError):
                timing.check('1.99.1')
            build.assert_not_called()

    def test_registrations_pin_profile_population_and_input_closure(self):
        doc = tomllib.loads((timing.ROOT / 'verification/checks.toml').read_text())
        selected = [c for c in doc['checks'] if c['component'] == 'aes' and c['category'] == 'timing-fixed-random']
        self.assertEqual({c['id'] for c in selected}, {
            'packaged-fixed-random-msrv', 'packaged-fixed-random-current',
            'packaged-fixed-random-arm-msrv', 'packaged-fixed-random-arm-current'})
        self.assertEqual(set(doc['groups']['aes-fixed-random']['paths']), {
            'assurance/aes-fixed-random', 'scripts/aes/check-aes-fixed-random.py', 'scripts/aes/test-aes-fixed-random.py'})
        for check in selected:
            compiler = '1.90.0' if check['id'].endswith('msrv') else '1.99.1'
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-fixed-random.py', '--toolchain', compiler])
            arch = 'aarch64' if '-arm-' in check['id'] else 'x86_64'
            self.assertEqual(check['platform'], 'linux-' + arch)
            self.assertEqual(check['success']['exact_tests'], 4)
            self.assertEqual(check['success']['minimum_tests'], 4)
            self.assertEqual(check['log_bytes'], 67108864)
            self.assertEqual(set(check['inputs']), {'aes-packaged', 'aes-fixed-random', 'aes-differential-runner',
                'aes-oracle', 'hkdf-public-api-modern', 'compiler', 'hkdf-msrv'})
            self.assertTrue(set(timing.oracle.FORBIDDEN) <= set(check['reject_environment']))
            self.assertEqual(check['success']['unique_lines'], ['Independent AES fixed/random preflight: PASS',
                timing.MARKER, f'AES fixed/random completed: {compiler}; native {arch}-unknown-linux-gnu; {timing.PROFILE}'])

    def test_orchestration_restores_affinity_and_rejects_changed_executables(self):
        for failure in (None, 'collect', 'oracle', 'binary'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, contextlib.ExitStack() as stack:
                root = Path(temp)
                binary = root / 'target/x86_64-unknown-linux-gnu/release/fixed-random'
                binary.parent.mkdir(parents=True); binary.write_bytes(b'fixture')
                stack.enter_context(patch.dict(os.environ, {}, clear=True))
                stack.enter_context(patch.object(timing.platform, 'system', return_value='Linux'))
                stack.enter_context(patch.object(timing.platform, 'machine', return_value='x86_64'))
                private = stack.enter_context(patch.object(timing.packaged.archives.cargo_environment, 'private_directory'))
                private.return_value.__enter__.return_value = temp
                stack.enter_context(patch.object(timing.packaged.archives, 'isolated_env', return_value={'CARGO_TARGET_DIR': str(root / 'target')}))
                stack.enter_context(patch.object(timing.packaged, 'package_sources', return_value={}))
                stack.enter_context(patch.object(timing.packaged, 'prepare'))
                stack.enter_context(patch.object(timing, 'prepare'))
                graph = stack.enter_context(patch.object(timing.packaged, 'graph'))
                stack.enter_context(patch.object(timing.oracle, 'select', return_value=root / 'openssl'))
                stack.enter_context(patch.object(timing.oracle, 'preflight'))
                stack.enter_context(patch.object(timing.oracle, 'digest', side_effect=['same', 'changed' if failure == 'oracle' else 'same']))
                good = '\n'.join(f'test {name} ... ok' for name in timing.TESTS) + '\n' + \
                    'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
                run = stack.enter_context(patch.object(timing.packaged.archives, 'run',
                    side_effect=lambda cmd, *_: SimpleNamespace(stdout=good if 'test' in cmd else '{}')))
                stack.enter_context(patch.object(timing, 'host_info', return_value={}))
                stack.enter_context(patch.object(timing.os, 'sched_getaffinity', return_value={2, 3}))
                affinity = stack.enter_context(patch.object(timing.os, 'sched_setaffinity'))
                collect = stack.enter_context(patch.object(timing, 'collect'))
                if failure == 'collect':
                    collect.side_effect = ValueError('alarm')
                if failure == 'binary':
                    collect.side_effect = lambda *_: binary.write_bytes(b'changed')
                output = io.StringIO(); stack.enter_context(contextlib.redirect_stdout(output))
                if failure:
                    with self.assertRaises(ValueError):
                        timing.check('1.99.1')
                    self.assertNotIn('AES fixed/random completed:', output.getvalue())
                else:
                    timing.check('1.99.1')
                    self.assertIn('AES fixed/random completed:', output.getvalue())
                self.assertEqual([c.args for c in affinity.call_args_list], [(0, {2}), (0, {2, 3})])
                graph.assert_called_once()
                build = next(c.args[0] for c in run.call_args_list if 'build' in c.args[0])
                self.assertIn('--release', build)
                self.assertEqual(build[-2:], ['--target', 'x86_64-unknown-linux-gnu'])
                self.assertEqual(collect.call_count, 1)  # No retry after any failure.


if __name__ == '__main__':
    unittest.main()
