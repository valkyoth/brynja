#!/usr/bin/env python3
"""Fail-closed tests for expansion, round control and scratch-call binding."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_rounds_tested', Path(__file__).with_name('aes_aarch64_rounds.py'))
rounds = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rounds)
CALLEES = {r: 'selected_' + r for r in ('inverse', 'substitute', 'mix', 'add_key', 'wide_add_key', 'clear')}


def fixture():
    # Synthetic parser fixture, deliberately NOT a reviewed AES body.
    return ['cmp x1, #16', 'b.ne .LBB1_2', '.LBB1_1:',
            'ldurb w8, [x22, #-7]', 'eor w8, w8, w9', 'strb w8, [x19]',
            'sub x0, x29, #4', 'mov w1, #4', 'bl selected_clear',
            '.LBB1_2:', 'mov w0, wzr', 'ret']


class Aarch64RoundTests(unittest.TestCase):
    def test_policy_population_and_no_synthetic_acceptance(self):
        policies = json.loads(rounds.POLICY_PATH.read_text())
        self.assertEqual(set(policies), {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for config, items in policies.items():
            self.assertEqual(set(items), set(rounds.ROLES))
            for role, item in items.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'clears', 'sha256'})
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                self.assertEqual(item['clears'], 1 if role.startswith('expand') else 4)
                self.assertEqual(item['calls'], 9 if role == 'expand256' else 5 if role.startswith('expand') else 12)
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    rounds.check(fixture(), CALLEES, role, *config.split('/'))
        for args in (('mix', '1.90.0', 'abort'), ('expand', 'stable', 'abort'), ('expand', '1.99.1', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                rounds.check(fixture(), CALLEES, *args)

    def test_external_clearing_requires_unique_declaration(self):
        selected = {r: (symbol, '', '') for r, symbol in CALLEES.items() if r != 'clear'}
        declaration = 'declare i8 @selected_clear(ptr, i64)\n'
        self.assertEqual(rounds.bind(selected, declaration, 'selected_clear'), CALLEES)
        for bad in ('', 'define i8 @selected_clear(ptr, i64)\n', declaration * 2,
                    'declare i8 @selected_clear_suffix(ptr, i64)\n', '; ' + declaration):
            with self.assertRaisesRegex(ValueError, 'clearing declaration'):
                rounds.bind(selected, bad, 'selected_clear')
        selected['inverse'] = ('selected_clear', '', '')
        with self.assertRaisesRegex(ValueError, 'ambiguous call identity'):
            rounds.bind(selected, declaration, 'selected_clear')

    def test_role_specific_callee_binding(self):
        original = fixture()
        expected = rounds.observe(original, CALLEES, 'expand')
        self.assertEqual(expected['clears'], 1)
        renamed = {**CALLEES, 'clear': 'other_clear'}
        self.assertEqual(expected, rounds.observe([x.replace('selected_clear', 'other_clear') for x in original], renamed, 'expand'))
        for role, wrong in (('expand', 'selected_mix'), ('transform', 'selected_wide_add_key'),
                            ('transform192', 'selected_add_key'), ('transform256', 'selected_inverse')):
            with self.assertRaisesRegex(ValueError, 'unreviewed call target'):
                rounds.observe(['bl ' + wrong] + original, CALLEES, role)
        for bad in ({**CALLEES, 'clear': 'selected_inverse'}, {**CALLEES, 'clear': 'invalid!'}):
            with self.assertRaisesRegex(ValueError, 'call identity'):
                rounds.observe(original, bad, 'expand')

    def test_local_branches_bind_instruction_destinations(self):
        original = fixture()
        expected = rounds.observe(original, CALLEES, 'expand')
        renamed = [x.replace('.LBB1_', '.LBB99_') for x in original]
        self.assertEqual(expected, rounds.observe(renamed, CALLEES, 'expand'))
        changed = original.copy()
        changed[1] = 'b.ne .LBB1_1'
        self.assertNotEqual(expected, rounds.observe(changed, CALLEES, 'expand'))
        for bad in (original + ['.LBB1_1:'], original + ['.LBB2_1:'], original[:-1],
                    original[:-1] + ['.LBB2_1:', '.LBB3_1:', 'ret'],
                    [x for x in original if not x.endswith(':')]):
            with self.assertRaises(ValueError):
                rounds.observe(bad, CALLEES, 'expand')

    def test_operands_and_clear_calls_are_hashed(self):
        original = fixture()
        expected = rounds.observe(original, CALLEES, 'expand')
        for before, after in (('cmp x1, #16', 'cmp x1, #24'), ('[x22, #-7]', '[x22, #-6]'),
                              ('[x22', '[x3'), ('w8, w8, w9', 'w8, w8, w10'),
                              ('mov w1, #4', 'mov w1, #0'), ('sub x0, x29, #4', 'mov x0, x3')):
            changed = [x.replace(before, after) for x in original]
            self.assertNotEqual(expected, rounds.observe(changed, CALLEES, 'expand'))
        changed = [x for x in original if x != 'bl selected_clear']
        self.assertEqual(rounds.observe(changed, CALLEES, 'expand')['clears'], 0)
        self.assertNotEqual(expected, rounds.observe(changed, CALLEES, 'expand'))

    def test_unknown_instructions_and_malformed_branches_fail(self):
        for line in ('blr x0', 'br x0', '.inst 0', '.word 0', 'nop', 'svc #0', 'udiv w0, w0, w1',
                     'ldr w0, [x0, x1]', 'lsl w0, w0, w1', 'mov sp, x0', 'bl unexpected',
                     'b.hs, .LBB1_2', 'tbz w2 #0, .LBB1_2', 'cbz w0 .LBB1_2',
                     'cbz w8, .LBB1_2', 'tbnz w8, #0, .LBB1_2'):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'unreviewed'):
                rounds.observe([line] + fixture(), CALLEES, 'expand')

    def test_sixteen_mutation_controls_per_role_and_configuration(self):
        original = fixture()
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in rounds.ROLES:
                    synthetic = {compiler + '/' + panic: {role: rounds.observe(original, CALLEES, role)}}
                    with patch.object(rounds.Path, 'read_text', return_value=json.dumps(synthetic)):
                        self.assertEqual(rounds.mutations(original, CALLEES, role, compiler, panic), 16)


if __name__ == '__main__':
    unittest.main()
