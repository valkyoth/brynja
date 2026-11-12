#!/usr/bin/env python3
"""Synthetic descriptions only; frozen timing criteria remain unchanged."""
import importlib.util
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sensitivity', Path(__file__).with_name('describe-aes-dit-sensitivity.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DitSensitivityTests(unittest.TestCase):
    def test_cutoff_scales_match_exact_alternating_population(self):
        n = d.policy.SAMPLES
        result = d.describe([(10, 12), (12, 10)] * (n // 2))
        self.assertAlmostEqual(result['welch_observed_cutoff_scale_ns'], 4.5 * math.sqrt(2 / (n - 1)))
        self.assertAlmostEqual(result['paired_observed_cutoff_scale_ns'], 4.5 * math.sqrt(4 / (n - 1)))
        self.assertEqual(result['untrimmed_difference_ns'], 0)

    def test_degenerate_errors_not_a_zero_effect_guarantee(self):
        result = d.describe([(12, 10)] * d.policy.SAMPLES)
        self.assertTrue(result['degenerate_standard_error'])
        self.assertEqual(result['paired_observed_cutoff_scale_ns'], 0)
        self.assertEqual(result['untrimmed_difference_ns'], 2)

    def test_trim_is_descriptive_and_does_not_mutate_population(self):
        n = d.policy.SAMPLES
        pairs = [(10, 20)] * (n - 81) + [(1000000, 20)] * 81
        before = list(pairs)
        verdict = d.policy.screen(pairs)
        result = d.describe(pairs)
        self.assertEqual(result['posthoc_trim_each_tail_count'], 81)
        self.assertEqual(result['posthoc_trimmed_class_mean_difference_ns'], -10)
        self.assertEqual(result['posthoc_trimmed_paired_difference_ns'], -10)
        self.assertNotEqual(result['untrimmed_difference_ns'], -10)
        self.assertEqual(pairs, before)
        self.assertEqual(d.policy.screen(pairs), verdict)
        self.assertNotIn('alarm', result)

    def test_one_more_outlier_is_not_silently_trimmed(self):
        pairs = [(10, 20)] * (d.policy.SAMPLES - 82) + [(1000000, 20)] * 82
        self.assertGreater(d.describe(pairs)['posthoc_trimmed_paired_difference_ns'], -10)

    def test_shift_does_not_change_standard_error(self):
        original = [(10, 12), (12, 10)] * (d.policy.SAMPLES // 2)
        before = d.describe(original)
        after = d.describe([(a + 7, b) for a, b in original])
        for key in ('welch_observed_cutoff_scale_ns', 'paired_observed_cutoff_scale_ns'):
            self.assertEqual(before[key], after[key])
        self.assertEqual(after['untrimmed_difference_ns'], 7)

    def test_invalid_population_rejected(self):
        for pairs in ([], [(1, 2)] * (d.policy.SAMPLES - 1), [(0, 2)] * d.policy.SAMPLES,
                      [(True, 2)] * d.policy.SAMPLES, [(1,)] * d.policy.SAMPLES):
            with self.assertRaises(ValueError):
                d.describe(pairs)

    def test_original_record_checked_before_reanalysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'run.json').write_text('{}')
            with patch.object(d.analysis, 'measurement') as parse, self.assertRaisesRegex(ValueError, 'record changed'):
                d.describe_run(root, {'launch': 'run', 'control': 'shared-values', 'record_sha256': '0' * 64})
            parse.assert_not_called()


if __name__ == '__main__':
    unittest.main()
