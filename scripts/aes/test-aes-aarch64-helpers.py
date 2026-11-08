#!/usr/bin/env python3
"""Fail-closed normalization and exact-policy controls for four ARM helpers."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_helpers_tested', Path(__file__).with_name('aes_aarch64_helpers.py'))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def fixture():
    # Deliberately not an AES implementation or approved stream.
    return ['lsl x9, x2, #4', 'cmp x9, #176', 'b.hs .LBB1_2',
            'ldrb w10, [x0]', 'eor w10, w10, w11', 'strb w10, [x0]',
            '.LBB1_2:', 'mov w0, w8', 'ret']


class Aarch64HelperTests(unittest.TestCase):
    def test_exact_policy_configuration_and_population(self):
        self.assertEqual(set(helpers.POLICY), {(c, p) for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for (compiler, panic), policies in helpers.POLICY.items():
            self.assertEqual(set(policies), set(helpers.ROLES))
            for role, item in policies.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'sha256'})
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    helpers.check(fixture(), 'inverse', role, compiler, panic)
        for role, compiler, panic in (('expand', '1.90.0', 'abort'), ('mix', 'stable', 'abort'),
                                     ('mix', '1.99.1', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                helpers.check(fixture(), 'inverse', role, compiler, panic)

    def test_branch_binding_survives_renaming_not_retargeting(self):
        original = fixture()
        renamed = [line.replace('.LBB1_2', '.LBB999_888') for line in original]
        self.assertEqual(helpers.observe(original, 'inverse'), helpers.observe(renamed, 'inverse'))
        changed = original.copy()
        changed[6], changed[5] = changed[5], changed[6]
        self.assertNotEqual(helpers.observe(original, 'inverse'), helpers.observe(changed, 'inverse'))
        for bad in (original + ['.LBB1_2:'], original[:-1] + ['.LBB2_1:', '.LBB3_1:', 'ret'],
                    original + ['.LBB2_1:'], [line for line in original if not line.endswith(':')],
                    [line.replace('.LBB1_2', '.Loutside') for line in original], original[:-1]):
            with self.assertRaises(ValueError):
                helpers.observe(bad, 'inverse')

    def test_call_target_is_bound_not_just_normalized(self):
        original = ['bl selected_inverse'] + fixture()
        observed = helpers.observe(original, 'selected_inverse')
        self.assertEqual(observed['calls'], 1)
        self.assertEqual(observed, helpers.observe(['bl other_selected_inverse'] + fixture(), 'other_selected_inverse'))
        for bad in (['bl other'] + fixture(), ['blr x0'] + fixture(), ['br x0'] + fixture()):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                helpers.observe(bad, 'selected_inverse')

    def test_immediates_and_addresses_are_part_of_the_digest(self):
        original = fixture()
        expected = helpers.observe(original, 'inverse')
        for before, after in (('#176', '#175'), ('[x0]', '[x3]'), ('w10, w10, w11', 'w10, w10, w12')):
            changed = [line.replace(before, after) for line in original]
            self.assertNotEqual(expected, helpers.observe(changed, 'inverse'))
        for instruction in ('.word 0', '.inst 0', 'nop', 'svc #0', 'ldr w10, [x0, x10]',
                            'lsl w0, w0, w1', 'udiv w0, w0, w1', 'mov sp, x0',
                            'cbz w10, .LBB1_2', 'tbz w0, #0, .LBB1_2',
                            'b.hs, .LBB1_2', 'cbz w1 .LBB1_2', 'tbz w1, #0,, .LBB1_2'):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                helpers.observe([instruction] + original, 'inverse')

    def test_twelve_controls_for_each_configuration(self):
        original = fixture()
        synthetic = helpers.observe(original, 'inverse')
        for compiler, panic in helpers.POLICY:
            for role in helpers.ROLES:
                with patch.dict(helpers.POLICY, {(compiler, panic): {role: synthetic}}):
                    self.assertEqual(helpers.mutations(original, 'inverse', role, compiler, panic), 12)


if __name__ == '__main__':
    unittest.main()
