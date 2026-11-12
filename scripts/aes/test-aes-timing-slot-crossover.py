#!/usr/bin/env python3
"""Synthetic crossover validation; no native timing collection."""
from collections import Counter
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import tomllib
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('crossover_runner', Path(__file__).with_name('check-aes-accelerated-fixed-random.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
c, policy = runner.crossover, runner.timing


def measurement():
    lines = [c.header(policy)]
    for bits, mode, campaign in c.CAMPAIGNS:
        order = c.patterns(campaign)[c.WARMUP:]
        for control in c.CONTROLS:
            for slot in (0, 1):
                lines.append(f'SLOT {bits} {mode} {control} {slot} {1024 + 48 * slot} {1056 + 48 * slot}')
            for sample, pattern in enumerate(order):
                n = 1000 + sample % 2
                lines.append(f'CROSS_SAMPLE {bits} {mode} {control} {sample} {pattern} {n} {n} {n} {n}')
    return '\n'.join(lines + ['AES_SLOT_CROSSOVER_END crossover-measure'])


def vectors():
    lines = [c.header(policy)]
    for bits, mode, _ in c.CAMPAIGNS:
        for control in c.CONTROLS:
            for sample in (0, c.SAMPLES // 2, c.SAMPLES - 1):
                for pattern in range(8):
                    for cls, slot in c.cells(pattern):
                        lines.append(f'CROSS_VECTOR {bits} {mode} {control} {sample} {pattern} {cls} {slot} ' + 'ab' * 16)
    return '\n'.join(lines + ['AES_SLOT_CROSSOVER_END crossover-preflight'])


class CrossoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = measurement()

    def test_public_schedule_matches_rust_regression_vectors(self):
        for campaign, expected in ((22, 0x9bfc8429a8dcdd83), (37, 0x26aa75705d94d25b), (36, 0x3be3a5b4f308420d)):
            order = c.patterns(campaign)
            h = 0xcbf29ce484222325
            for value in order:
                h = ((h ^ value) * 0x100000001b3) & ((1 << 64) - 1)
            self.assertEqual(h, expected)
            for section in (order[:c.WARMUP], order[c.WARMUP:]):
                self.assertEqual(Counter(section), {i: len(section) // 8 for i in range(8)})

    def test_every_pattern_visits_four_cells(self):
        for pattern in range(8):
            self.assertEqual(sorted(c.cells(pattern)), [(0, 0), (0, 1), (1, 0), (1, 1)])
        for invalid in (-1, 8, True, '0'):
            with self.assertRaises(ValueError):
                c.cells(invalid)

    def test_complete_population_retained_without_a_pass_claim(self):
        result = c.parse(self.output, policy)
        self.assertEqual(len(result['campaigns']), 6)
        self.assertEqual(sum(row['cell_durations'] for row in result['campaigns']), 196608)
        self.assertNotIn('passed', result)
        for row in result['campaigns']:
            self.assertEqual(sum(x['rounds'] for x in row['order_patterns']), c.SAMPLES)
            self.assertEqual(sum(x['rounds'] for x in row['chronological_eighths']), c.SAMPLES)
            self.assertFalse(any(x['alarm'] for x in row['conditional_comparisons'].values()))

    def test_missing_extra_and_reordered_records_rejected(self):
        lines = self.output.splitlines()
        for bad in ('\n'.join(lines[1:]), self.output + '\nextra', '\n'.join([lines[0], lines[2], lines[1], *lines[3:]]),
                    '\n'.join([*lines[:3], lines[4], lines[3], *lines[5:]])):
            with self.assertRaises(ValueError):
                c.parse(bad, policy)

    def test_wrong_policy_completion_campaign_and_pattern_rejected(self):
        for old, new in ((c.header(policy), 'wrong policy'), ('END crossover-measure', 'END crossover-preflight'),
                         ('192 decrypt-block values 0', '256 decrypt-block values 0'),
                         (self.output.splitlines()[3], self.output.splitlines()[3].replace(' 0 ', ' 1 ', 1))):
            with self.assertRaises(ValueError):
                c.parse(self.output.replace(old, new, 1), policy)

    def test_invalid_durations_and_changed_addresses_rejected(self):
        for value in ('0', '-1', 'nan', '1.5', '1' * 20):
            with self.assertRaises(ValueError):
                c.parse(self.output.replace('1000 1000 1000 1000', value + ' 1000 1000 1000', 1), policy)
        for old, new in (('1024 1056', '1024 1024'), ('1072 1104', '1073 1104'), ('1024 1056', '-1 1056')):
            with self.assertRaises(ValueError):
                c.parse(self.output.replace(old, new, 1), policy)

    def test_address_layout_requires_disjoint_fixed_stride_slots(self):
        c.addresses([(1024, 1056), (1072, 1104)])
        c.addresses([(1040, 1024), (1088, 1072)])
        for bad in ([], [(1, 2)], [(1024, 1050), (1072, 1098)], [(1024, 1060), (1072, 1108)],
                    [(0, 32), (48, 80)], [(2**64, 2**64 + 32), (2**64 + 48, 2**64 + 80)]):
            with self.assertRaises(ValueError):
                c.addresses(bad)

    def test_synthetic_class_signal_is_not_a_slot_signal(self):
        result = c.describe([(1010 + i % 2, 1010 + i % 2, 1000 + i % 2, 1000 + i % 2)
                             for i in range(c.SAMPLES)], policy)
        flags = {name: row['alarm'] for name, row in result['conditional_comparisons'].items()}
        self.assertEqual(flags, dict(class_at_slot0=True, class_at_slot1=True, slot_with_fixed=False, slot_with_random=False))
        self.assertEqual(result['interaction_fixed_minus_random_slot0_minus_slot1_ns'], 0)

    def test_synthetic_slot_signal_is_not_a_class_signal(self):
        result = c.describe([(1010 + i % 2, 1000 + i % 2, 1010 + i % 2, 1000 + i % 2)
                             for i in range(c.SAMPLES)], policy)
        flags = {name: row['alarm'] for name, row in result['conditional_comparisons'].items()}
        self.assertEqual(flags, dict(class_at_slot0=False, class_at_slot1=False, slot_with_fixed=True, slot_with_random=True))

    def test_interaction_and_noise_are_not_hidden(self):
        rows = [(1010 + i % 2, 1000 + i % 2, 1000 + i % 2, 1000 + i % 2) for i in range(c.SAMPLES)]
        self.assertEqual(c.describe(rows, policy)['interaction_fixed_minus_random_slot0_minus_slot1_ns'], 10)
        rows[0] = (10**10, 1000, 1000, 1000)
        self.assertTrue(c.describe(rows, policy)['conditional_comparisons']['class_at_slot0']['inconclusive'])

    def test_preflight_checks_all_576_cells_in_order_and_correct_oracle_inputs(self):
        with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr=b'', stdout=b'\xab' * 16)) as oracle:
            c.preflight(vectors(), '/oracle', {}, policy)
            self.assertTrue(any('-d' in call.args[0] for call in oracle.call_args_list))
            self.assertTrue(any('-aes-192-ecb' in call.args[0] for call in oracle.call_args_list))
            self.assertTrue(any('-aes-256-ecb' in call.args[0] for call in oracle.call_args_list))
            for call in oracle.call_args_list:
                self.assertEqual(len(call.kwargs['input']), 16)
            self.assertGreater(oracle.call_count, 3)
            self.assertLess(oracle.call_count, 576)  # Cache only identical oracle queries.
            for bad in (vectors().replace('ab', 'ac', 1), vectors().replace(' 0 0 ', ' 1 0 ', 1), vectors() + '\nextra'):
                with self.assertRaises(ValueError):
                    c.preflight(bad, '/oracle', {}, policy)

    def test_oracle_failures_do_not_validate(self):
        for code, stderr, output in ((1, b'', b'\xab' * 16), (0, b'warning', b'\xab' * 16), (0, b'', b'\xab' * 15)):
            with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stderr=stderr, stdout=output)), self.assertRaises(ValueError):
                c.preflight(vectors(), '/oracle', {}, policy)

    def test_failed_process_stderr_and_wrong_authority_rejected(self):
        for code, stderr, output in ((1, '', ''), (False, '', ''), (0, 'warning', ''), (0, '', 'wrong\n')):
            with self.assertRaises(ValueError):
                c.validate_preflight(SimpleNamespace(returncode=code, stderr=stderr, stdout=output),
                                     '/oracle', {}, 'ArmAes', runner.payload, policy)

    def test_fixture_only_changes_entrypoint_and_appends_modules(self):
        source = runner.fixture(policy.FIXTURE.read_text())
        result = c.fixture(source, '// slots', '// driver')
        self.assertEqual(source.split('fn main()')[0], result.split('fn main()')[0])
        self.assertIn('crossover_driver::run(&args[0])', result)
        with self.assertRaises(ValueError):
            c.fixture(source.replace('run(&args[0])', 'changed'), '', '')

    def test_exact_rust_test_population(self):
        expected = c.TESTS | policy.TESTS
        output = '\n'.join(f'test {name} ... ok' for name in sorted(expected))
        output += '\ntest result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
        c.check_tests(output, policy)
        for bad in (output.replace(' ... ok', ' ... FAILED', 1), output.replace('0 ignored', '1 ignored'), output + output):
            with self.assertRaises(ValueError):
                c.check_tests(bad, policy)

    def test_observations_and_mixed_experiments_rejected_before_any_execution(self):
        for options in ({'observation': 'must-not-run'}, {'with_controls': True}, {'isolate_dispatch': True}, {'long_batch': True}):
            with patch.object(runner, 'execute') as execute, self.assertRaisesRegex(ValueError, 'correctness-only'):
                runner.check('1.90.0', 'direct', slot_crossover=True, **options)
            execute.assert_not_called()

    def test_registered_checks_are_correctness_only_and_fingerprint_controls(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = [x for x in registry['checks'] if x.get('category') == 'aes-timing-crossover-fixture']
        self.assertEqual(len(checks), 4)
        for check in checks:
            self.assertIn('--slot-crossover', check['command'])
            self.assertNotIn('--observation', check['command'])
            self.assertNotIn('--controls', check['command'])
            self.assertEqual(check['success']['exact_tests'], 13)
            self.assertIn('aes-timing-crossover', check['inputs'])
            self.assertIn('aes-accelerated-timing', check['inputs'])
        paths = registry['groups']['aes-timing-crossover']['paths']
        for name in ('timing-slot-crossover.rs', 'timing-slot-driver.rs'):
            self.assertIn('assurance/aes-accelerated-campaigns/' + name, paths)
        self.assertIn('scripts/aes/aes_timing_slot_crossover.py', paths)
        self.assertIn('scripts/aes/aes_timing_slot_crossover.py', registry['groups']['aes-accelerated-timing']['paths'])


if __name__ == '__main__':
    unittest.main()
