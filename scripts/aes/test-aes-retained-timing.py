#!/usr/bin/env python3
"""Synthetic offline-analysis regressions; no AES or sample collection."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('retained', Path(__file__).with_name('analyze-aes-retained-timing.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RetainedTests(unittest.TestCase):
    def test_constant_difference_is_not_zero_signal(self):
        result = r.block_summary([2] * 128, 64)
        self.assertEqual(result['mean_difference_ns'], 2)
        self.assertTrue(result['zero_standard_error'])
        self.assertIsNone(result['descriptive_signed_ratio'])
        self.assertEqual(result['positive_blocks'], 2)

    def test_signed_block_math(self):
        result = r.block_summary([-2, -2, 4, 4], 2)
        self.assertEqual(result['mean_difference_ns'], 1)
        self.assertEqual(result['standard_error_of_block_means_ns'], 3)
        self.assertEqual(result['descriptive_signed_ratio'], 1 / 3)
        self.assertEqual(result['negative_blocks'], 1)

    def test_no_partial_blocks_or_single_block(self):
        for size in (0, -1, 3, 4, 8):
            with self.subTest(size=size), self.assertRaises(ValueError):
                r.block_summary([1, 2, 3, 4], size)

    def test_lagged_sequences(self):
        self.assertEqual(r.lag_correlation([1, 2, 3, 4], 1), 1)
        self.assertEqual(r.lag_correlation([1, -1, 1, -1], 1), -1)
        self.assertIsNone(r.lag_correlation([4] * 8, 1))
        for lag in (0, -1, 8):
            with self.assertRaises(ValueError):
                r.lag_correlation([4] * 8, lag)

    def test_all_samples_counted_and_transitions_explicit(self):
        rows = [(i % 2, 101 + i % 3, 100) for i in range(8192)]
        data = r.describe(rows)
        self.assertEqual(data['pairs'], 8192)
        self.assertEqual(sum(x['pairs'] for x in data['order_strata']), 8192)
        self.assertEqual(sum(x['pairs'] for x in data['order_transitions']), 8191)
        self.assertEqual(len(data['chronological_eighth_means_ns']), 8)
        for block in data['block_descriptions']:
            self.assertEqual(block['blocks'] * block['pairs_per_block'], 8192)
            self.assertEqual(block['mean_difference_ns'], data['mean_difference_ns'])
        self.assertEqual(data['duration_modes_ns_and_counts'][1], [(100, 8192)])
        self.assertTrue(all(x['mean_difference_ns'] is None for x in data['order_transitions'] if x['pairs'] == 0))

    def test_wrong_population_rejected(self):
        for rows in ([], [(0, 10, 11)] * 8191, [(2, 10, 11)] * 8192):
            with self.assertRaises(ValueError):
                r.describe(rows)

    def test_order_and_time_strata_keep_sign(self):
        data = r.describe([(i % 2, 98, 100) for i in range(8192)])
        self.assertEqual(data['chronological_eighth_means_ns'], [-2] * 8)
        self.assertTrue(all(x['mean_difference_ns'] == -2 for x in data['order_strata']))

    def load(self, record, expected=None, control=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'measure.json'
            raw = json.dumps(record).encode()
            path.write_bytes(raw)
            return r.load_measure(path, expected or hashlib.sha256(raw).hexdigest(), control)

    def test_hash_checked_before_json_or_statistics(self):
        with patch.object(r.policy, 'parse') as parse, self.assertRaisesRegex(ValueError, 'hash mismatch'):
            self.load({}, '0' * 64)
        parse.assert_not_called()

    def test_failed_process_or_stderr_rejected(self):
        for status, stderr in ((1, ''), (False, ''), (0, 'warning')):
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                self.load({'returncode': status, 'stderr': stderr, 'stdout': ''})

    def test_authority_and_control_markers_rejected(self):
        for output, control in (('', None), ('AES_FORCED_AUTHORITY: X86AesNi\n', None),
                                ('AES_FORCED_AUTHORITY: ArmAes\nwrong\n', 'separate-values')):
            with self.assertRaises(ValueError):
                self.load({'returncode': 0, 'stderr': '', 'stdout': output}, control=control)

    def test_incomplete_population_delegates_to_strict_policy(self):
        with self.assertRaises(ValueError):
            self.load({'returncode': 0, 'stderr': '', 'stdout': 'AES_FORCED_AUTHORITY: ArmAes\n' + r.policy.HEADER + '\n'})

    def test_no_acceptance_flags_in_description(self):
        data = r.describe([(i % 2, 101, 100) for i in range(8192)])
        self.assertNotIn('alarm', data)
        self.assertNotIn('passed', data)
        self.assertIn('not a new acceptance test', r.NOTICE)


if __name__ == '__main__':
    unittest.main()
