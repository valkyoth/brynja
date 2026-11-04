#!/usr/bin/env python3
"""Synthetic AES timing runner regressions; no timing or crypto execution."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('aes_timing', Path(__file__).with_name('check-aes-timing.py'))
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


def samples(left='1000', right='1000'):
    return '\n'.join([f'SAMPLE {mode} {i} {left} {right}' for mode in timing.MODES
                      for i in range(timing.SAMPLES)] + ['AES_TIMING_END measure'])


class TimingTests(unittest.TestCase):
    def test_exact_population_and_build_policy(self):
        timing.policy()
        self.assertEqual(timing.MODES, ('encrypt-key', 'encrypt-block', 'decrypt-key', 'decrypt-block', 'public-key', 'public-block'))
        rows = timing.parse(samples())
        self.assertEqual(len(rows), 6)
        self.assertFalse(any(row['signal'] for row in rows))

    def test_missing_extra_duplicate_and_reordered_samples(self):
        output = samples()
        lines = output.splitlines()
        for bad in ('', '\n'.join(lines[1:]), output + '\n' + lines[-1],
                    '\n'.join([lines[1], lines[0], *lines[2:]]),
                    output.replace('SAMPLE encrypt-key 1 ', 'SAMPLE encrypt-key 0 ', 1),
                    output.replace('encrypt-key', 'unknown', 1)):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                timing.parse(bad)

    def test_invalid_values(self):
        for value in ('0', '-1', 'nan', 'inf', '1.5', 'True', '1' * 40):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timing.parse(samples().replace('1000', value, 1))

    def test_constant_and_variable_signals(self):
        self.assertTrue(all(row['signal'] and row['paired_t_abs'] is None
                            for row in timing.parse(samples('1100'))))
        self.assertTrue(timing.statistics.screen([(1200 + i % 3, 1000) for i in range(timing.SAMPLES)])['signal'])

    def test_alarm_cannot_print_success(self):
        with patch('builtins.print') as emit, self.assertRaisesRegex(ValueError, 'do not retry-to-pass'):
            timing.finish(samples('1100'))
        self.assertEqual(emit.call_count, 1)
        self.assertNotIn(timing.MARKER, emit.call_args.args[0])

    def test_balanced_samples_report_observation_only(self):
        with patch('builtins.print') as emit:
            timing.finish(samples())
        self.assertEqual(emit.call_args_list[1].args[0], timing.MARKER)
        self.assertIn('not constant-time', emit.call_args_list[2].args[0])

    def test_preflight_checks_both_classes_and_every_mode(self):
        expected = '\n'.join([f'VECTOR {mode} {cls} ' + ('ab' * 16)
                              for mode in timing.MODES for cls in (0, 1)] + ['AES_TIMING_END preflight'])
        with patch.object(timing, 'oracle_preflight') as control, \
             patch.object(timing, 'openssl_block', return_value=b'\xab' * 16) as oracle:
            timing.preflight(expected, {})
            control.assert_called_once()
            self.assertEqual(oracle.call_count, 12)
            self.assertEqual(sum(call.args[2] for call in oracle.call_args_list), 4)
            self.assertEqual(oracle.call_args_list[0].args[:2], (b'\0' * 16, b'\x37' * 16))
            self.assertEqual(oracle.call_args_list[2].args[:2], (b'\x37' * 16, b'\0' * 16))
            for bad in (expected.split('\n', 1)[1], expected.replace('ab', 'ac', 1),
                        expected + '\nextra', expected.replace(' 0 ', ' 1 ', 1)):
                with self.assertRaises(ValueError):
                    timing.preflight(bad, {})

    def test_oracle_wrong_answer_or_failed_process_rejected(self):
        with patch.object(timing, 'openssl_block', return_value=b'\0' * 16), self.assertRaises(ValueError):
            timing.oracle_preflight({})
        for status, out, err in ((1, b'x' * 16, b''), (0, b'x' * 15, b''), (0, b'x' * 16, b'warning')):
            with patch.object(timing.subprocess, 'run', return_value=SimpleNamespace(returncode=status, stdout=out, stderr=err)), \
                 self.assertRaises(ValueError):
                timing.openssl_block(b'\0' * 16, b'\0' * 16, False, {})

    def test_failed_preflight_prevents_measurement(self):
        result = SimpleNamespace(returncode=0, stdout='bad preflight', stderr='')
        with patch.object(timing.subprocess, 'run', return_value=result) as run, \
             patch.object(timing, 'preflight', side_effect=ValueError('bad')), patch('builtins.print'), \
             self.assertRaises(ValueError):
            timing.collect(Path('/tmp/aes-timing'), {})
        self.assertEqual(run.call_count, 1)

    def test_failed_measurement_never_finishes_or_retries(self):
        results = [SimpleNamespace(returncode=0, stdout='preflight', stderr=''),
                   SimpleNamespace(returncode=1, stdout=samples(), stderr='failure')]
        with patch.object(timing.subprocess, 'run', side_effect=results) as run, \
             patch.object(timing, 'preflight'), patch.object(timing, 'finish') as finish, \
             patch('builtins.print'), self.assertRaises(ValueError):
            timing.collect(Path('/tmp/aes-timing'), {})
        self.assertEqual(run.call_count, 2)
        finish.assert_not_called()


if __name__ == '__main__':
    unittest.main()
