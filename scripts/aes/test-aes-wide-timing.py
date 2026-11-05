#!/usr/bin/env python3
"""Negative controls for the wide timing harness; no statistical reruns."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

spec = importlib.util.spec_from_file_location('aes_wide_timing', Path(__file__).with_name('check-aes-wide-timing.py'))
timing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timing)


def samples(left='1000', right='1000'):
    return '\n'.join([timing.HEADER] +
                     [f'SAMPLE {bits} {owner} {mode} {i} {left} {right}'
                      for bits, owner, mode in timing.CAMPAIGNS for i in range(timing.SAMPLES)] +
                     ['AES_WIDE_TIMING_END measure'])


def vectors():
    return '\n'.join([timing.HEADER] +
                     [f'VECTOR {bits} {owner} {mode} {cls} ' + 'ab' * 16
                      for bits, owner, mode in timing.CAMPAIGNS for cls in (0, 1)] +
                     ['AES_WIDE_TIMING_END preflight'])


class WideTimingTests(unittest.TestCase):
    def test_exact_campaigns_build_and_sampling_policy(self):
        timing.base.policy()
        modes = ('encrypt-key', 'encrypt-block', 'decrypt-key', 'decrypt-block', 'public-key', 'public-block')
        expected = tuple((bits, owner, mode) for bits in (192, 256)
                         for owner in ('ephemeral', 'cached', 'cached-import')
                         for mode in (('import-key',) if owner == 'cached-import' else modes))
        self.assertEqual(timing.CAMPAIGNS, expected)
        self.assertEqual((timing.SAMPLES, timing.REPEAT, timing.WARMUP, timing.LIMIT), (512, 4, 32, 10.0))
        rows = timing.parse(samples())
        self.assertEqual(len(rows), 26)
        self.assertFalse(any(row['signal'] for row in rows))

    def test_missing_extra_reordered_and_duplicate_data_rejected(self):
        text = samples()
        lines = text.splitlines()
        for bad in ('', '\n'.join(lines[1:]), text + '\nextra',
                    '\n'.join([lines[0], lines[2], lines[1], *lines[3:]]),
                    text.replace('encrypt-key 1 ', 'encrypt-key 0 ', 1),
                    text.replace('SAMPLE 192', 'SAMPLE 128', 1),
                    text.replace('cached-import', 'cached', 1),
                    text.replace('POLICY 512 4 32', 'POLICY 512 1 0')):
            with self.subTest(bad=bad[:100]), self.assertRaises(ValueError):
                timing.parse(bad)

    def test_each_campaign_is_required(self):
        text = samples()
        for bits, owner, mode in timing.CAMPAIGNS:
            with self.subTest(bits=bits, owner=owner, mode=mode), self.assertRaises(ValueError):
                timing.parse(text.replace(f'SAMPLE {bits} {owner} {mode} 0 ', 'SAMPLE 0 missing mode 0 ', 1))

    def test_invalid_times_rejected(self):
        for value in ('0', '-1', 'nan', 'inf', '1.5', 'True', '1' * 40):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timing.parse(samples().replace('1000', value, 1))

    def test_alarms_cannot_print_success(self):
        with patch('builtins.print') as emit, self.assertRaisesRegex(ValueError, 'do not retry-to-pass'):
            timing.finish(samples('1100'))
        self.assertEqual(emit.call_count, 1)
        self.assertNotIn(timing.MARKER, emit.call_args.args[0])

    def test_balanced_data_claims_only_observation(self):
        with patch('builtins.print') as emit:
            timing.finish(samples())
        self.assertEqual(emit.call_args_list[1].args[0], timing.MARKER)
        self.assertIn('not constant-time', emit.call_args_list[2].args[0])

    def test_preflight_checks_every_width_owner_direction_and_class(self):
        with patch.object(timing, 'oracle_preflight') as control, \
             patch.object(timing, 'openssl_block', return_value=b'\xab' * 16) as oracle:
            timing.preflight(vectors(), {})
            control.assert_called_once()
            self.assertEqual(oracle.call_count, 52)
            self.assertEqual(sum(entry.args[2] for entry in oracle.call_args_list), 16)
            for (bits, owner, mode), pair in zip(timing.CAMPAIGNS,
                    zip(oracle.call_args_list[::2], oracle.call_args_list[1::2]), strict=True):
                for cls, entry in enumerate(pair):
                    value = 0xff if cls else 0
                    self.assertEqual(entry.args[:3], (
                        bytes([value if mode.endswith('-key') else 0x37]) * (bits // 8),
                        bytes([value if mode.endswith('-block') else 0x37]) * 16,
                        mode.startswith('decrypt-')))
            for bad in (vectors().replace('ab', 'ac', 1), vectors() + '\nextra',
                        vectors().replace(' 0 ', ' 1 ', 1), vectors().replace('POLICY 512', 'POLICY 511')):
                with self.assertRaises(ValueError):
                    timing.preflight(bad, {})

    def test_oracle_mechanism_is_exact_and_failures_rejected(self):
        for size in (24, 32):
            for decrypt in (False, True):
                with patch.object(timing.subprocess, 'run', return_value=SimpleNamespace(
                        returncode=0, stdout=b'x' * 16, stderr=b'')) as run:
                    timing.openssl_block(bytes(size), bytes(16), decrypt, {})
                command = run.call_args.args[0]
                self.assertIn(f'-aes-{size * 8}-ecb', command)
                self.assertEqual('-d' in command, decrypt)
        with patch.object(timing, 'openssl_block', return_value=bytes(16)), self.assertRaises(ValueError):
            timing.oracle_preflight({})
        for status, output, error in ((1, b'x' * 16, b''), (0, b'x' * 15, b''), (0, b'x' * 16, b'warning')):
            with patch.object(timing.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=status, stdout=output, stderr=error)), self.assertRaises(ValueError):
                timing.openssl_block(bytes(24), bytes(16), False, {})
        for key_size, block_size in ((16, 16), (25, 16), (32, 15)):
            with patch.object(timing.subprocess, 'run') as run, self.assertRaises(ValueError):
                timing.openssl_block(bytes(key_size), bytes(block_size), False, {})
            run.assert_not_called()

    def test_failed_preflight_prevents_measurement(self):
        result = SimpleNamespace(returncode=0, stdout='bad', stderr='')
        with patch.object(timing.subprocess, 'run', return_value=result) as run, \
             patch.object(timing, 'preflight', side_effect=ValueError('bad')), \
             patch('builtins.print'), self.assertRaises(ValueError):
            timing.collect(Path('/tmp/wide'), {})
        self.assertEqual(run.call_count, 1)

    def test_measurement_failures_retain_output_without_retry(self):
        for status, error, finish_error in ((1, 'failure', None), (0, '', ValueError('alarm'))):
            results = [SimpleNamespace(returncode=0, stdout='preflight', stderr=''),
                       SimpleNamespace(returncode=status, stdout='retained samples', stderr=error)]
            with patch.object(timing.subprocess, 'run', side_effect=results) as run, \
                 patch.object(timing, 'preflight'), patch.object(timing, 'finish', side_effect=finish_error) as finish, \
                 patch('builtins.print') as emit, self.assertRaises(ValueError):
                timing.collect(Path('/tmp/wide'), {})
            self.assertEqual(run.call_count, 2)
            self.assertIn(call('retained samples', end='', flush=True), emit.call_args_list)
            self.assertEqual(finish.call_count, 0 if status else 1)

    def test_affinity_restored_after_alarm(self):
        with patch.object(timing.base, 'policy'), \
             patch.object(timing.platform, 'system', return_value='Linux'), \
             patch.object(timing.platform, 'machine', return_value='x86_64'), \
             patch.object(timing.os, 'sched_getaffinity', return_value={7, 8}), \
             patch.object(timing.os, 'sched_setaffinity') as affinity, \
             patch.object(timing.verifier.cargo_environment, 'private_directory') as directory, \
             patch.object(timing.verifier, 'environment', return_value={'CARGO_TARGET_DIR': '/tmp/wide'}), \
             patch.object(timing.verifier, 'run', return_value='metadata'), \
             patch.object(Path, 'read_bytes', return_value=b'binary'), \
             patch.object(timing, 'collect', side_effect=ValueError('alarm')), \
             patch('sys.argv', ['check-aes-wide-timing.py']), patch('builtins.print'), \
             self.assertRaisesRegex(ValueError, 'alarm'):
            directory.return_value.__enter__.return_value = '/tmp/wide'
            timing.main()
        self.assertEqual(affinity.call_args_list, [call(0, {7}), call(0, {7, 8})])


if __name__ == '__main__':
    unittest.main()
