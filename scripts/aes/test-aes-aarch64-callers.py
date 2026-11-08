#!/usr/bin/env python3
"""Direction, ABI forwarding, cached admission and guard-transfer regressions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_callers_tested', Path(__file__).with_name('aes_aarch64_callers.py'))
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)
CALLEES = {r: 'selected_' + r for r in ('key128', 'key192', 'key256', 'cached128',
                                      'begin', 'guard_drop', 'secret192', 'secret256')}


def fixture(role):
    # Synthetic wide parser fixture, intentionally not a production stream.
    size = '208' if '192' in role else '240'
    return ['mov x0, x2', 'mov w1, #16', 'bl selected_begin', 'cbz w8, .LBB1_1',
            'str x8, [x20]', 'ret', '.LBB1_1:', 'str x8, [sp, #16]',
            'cbz x21, .LBB1_2', 'cmp x22, #' + size, 'b.ne .LBB1_2',
            'mov x2, x19', 'mov w4, ' + ('#1' if role.endswith('_decrypt') else 'wzr'),
            'bl selected_secret' + role[6:9], 'ret', '.LBB1_2:', 'bl selected_guard_drop', 'ret']


def symbols(v0=False):
    result = {}
    for role in k.ROLES:
        owner, op = role.split('_')
        bits = owner[-3:]
        kind = '17Aes' + bits + 'ExpandedKey' if owner.startswith('cached') else '9Aes' + bits + 'Key'
        wide = '4wide' if bits != '128' else ''
        if v0:
            name = '_RNvMs_Nt' + ('Nt' if wide else '') + 'Cabc_13brynja_crypto3aes' + wide + 'NtB5_' + kind + '13' + op + '_block'
        else:
            name = '_ZN13brynja_crypto3aes' + wide + kind + '13' + op + '_block17h0123456789abcdefE'
        result[role] = name
    return result


class Aarch64CallerTests(unittest.TestCase):
    def test_twelve_exact_symbols_no_aliases_or_namespace_mixups(self):
        for v0 in (False, True):
            selected = symbols(v0)
            definitions = {n: ('', '') for n in selected.values()}
            self.assertEqual(k.select(definitions, {}), selected)
            for name in selected.values():
                with self.assertRaisesRegex(ValueError, 'population'):
                    k.select({n: v for n, v in definitions.items() if n != name}, {})
                with self.assertRaisesRegex(ValueError, 'aliases'):
                    k.select(definitions, {name: 'elsewhere'})
            name = selected['cached192_encrypt']
            with self.assertRaisesRegex(ValueError, 'namespace'):
                k.select({**definitions, name.replace('4wide', ''): ('', '')}, {})
            extra = name.replace('Cabc', 'Cdef') if v0 else name.replace('h0123', 'h1234')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                k.select({**definitions, extra: ('', '')}, {})
            with self.assertRaisesRegex(ValueError, 'unrecognized'):
                k.select({**definitions, name.replace('Aes192', 'Aes512'): ('', '')}, {})

    def test_forwarding_has_exact_abi_and_direction(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in k.ROLES:
                    if k.wide(role):
                        continue
                    target = role.split('_')[0]
                    lines = ['mov x4, x2', 'mov x3, x1',
                             'mov w5, ' + ('#1' if role.endswith('_decrypt') else 'wzr'),
                             'ldp x1, x2, [x0]', 'mov x0, x8', 'b selected_' + target]
                    result = k.check(lines, CALLEES, role, compiler, panic)
                    self.assertEqual(result['tail_call'], target)
                    self.assertEqual(result['inverse'], role.endswith('_decrypt'))
                    self.assertEqual(k.mutations(lines, CALLEES, role, compiler, panic), 12)
                    for changed in (lines + ['ret'], ['nop'] + lines, ['.LBB1_1:'] + lines,
                                    lines[:-1] + ['bl selected_' + target]):
                        with self.assertRaisesRegex(ValueError, 'forwarding stream changed'):
                            k.check(changed, CALLEES, role, compiler, panic)

    def test_wide_policy_population_rejects_synthetic_streams(self):
        policy = json.loads(k.POLICY_PATH.read_text())
        self.assertEqual(set(policy), {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for config, roles in policy.items():
            self.assertEqual(set(roles), {r for r in k.ROLES if k.wide(r)})
            for role, item in roles.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'sha256'})
                self.assertEqual(item['calls'], dict.fromkeys(k.edges(role), 1))
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    k.check(fixture(role), CALLEES, role, *config.split('/'))

    def test_twenty_wide_mutations_per_role_and_profile(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in k.ROLES:
                    if not k.wide(role):
                        continue
                    lines = fixture(role)
                    policy = {compiler + '/' + panic: {role: k.observe(lines, CALLEES, role)}}
                    with patch.object(k.Path, 'read_text', return_value=json.dumps(policy)):
                        self.assertEqual(k.mutations(lines, CALLEES, role, compiler, panic), 20)

    def test_labels_and_calls_bind_exact_positions_and_widths(self):
        role = 'cached192_encrypt'
        lines = fixture(role)
        original = k.observe(lines, CALLEES, role)
        self.assertEqual(original, k.observe([x.replace('.LBB1_', '.LBB123_') for x in lines], CALLEES, role))
        for changed in (lines + ['.LBB1_1:'], lines + ['.LBB9_9:'], ['.LBB9_0:', '.LBB9_1:'] + lines):
            with self.assertRaises(ValueError):
                k.observe(changed, CALLEES, role)
        with self.assertRaisesRegex(ValueError, 'unknown branch'):
            k.observe([x.replace('cbz x21, .LBB1_2', 'cbz x21, .LBB9_9') for x in lines], CALLEES, role)
        with self.assertRaisesRegex(ValueError, 'unreviewed call'):
            k.observe([x.replace('bl selected_secret192', 'bl selected_secret256') for x in lines], CALLEES, role)
        with self.assertRaisesRegex(ValueError, 'ambiguous call'):
            k.observe(lines, {**CALLEES, 'begin': CALLEES['guard_drop']}, role)

    def test_fail_closed_grammar_profiles_and_terminals(self):
        role = 'cached256_decrypt'
        lines = fixture(role)
        for instruction in ('br x0', 'blr x0', 'ldr q0, [x0, x1]', '.inst 0', 'nop',
                            'udiv w0, w0, w1', 'mov sp, x0', '.Ltmp1:', '.Lfunc_begin1:'):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                k.observe([instruction] + lines, CALLEES, role)
        for compiler, panic in (('stable', 'abort'), ('1.90.0', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                k.check(lines, CALLEES, role, compiler, panic)
        with self.assertRaisesRegex(ValueError, 'unreviewed role'):
            k.check(lines, CALLEES, 'cached512_encrypt', '1.90.0', 'abort')
        with self.assertRaisesRegex(ValueError, 'terminal'):
            k.observe(lines + ['ret'], CALLEES, role)


if __name__ == '__main__':
    unittest.main()
