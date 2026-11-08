#!/usr/bin/env python3
"""Constructor admission, ownership transfer and cleanup policy regressions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_constructors_tested', Path(__file__).with_name('aes_aarch64_constructors.py'))
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)
CALLEES = {r: 'selected_' + r for r in ('begin', 'write', 'finish', 'guard_drop',
    'expand', 'expand192', 'expand256', 'clear', 'resume', 'panic_cleanup')}


def fixture(role, panic, compiler='1.99.1'):
    # Deliberately synthetic; none of these can pass real instruction policies.
    bits = int(role[-3:])
    size = bits // 8 if role.startswith('key') else {128: 176, 192: 208, 256: 240}[bits]
    lines = ['mov w1, #' + str(size), 'bl selected_begin',
             ('cbz w8,' if compiler == '1.99.1' else 'b.ne') + ' .LBB1_1',
             'mov w8, #1', 'str x8, [x19]', 'ret', '.LBB1_1:',
             'str x8, [sp, #16]', 'mov x1, x20']
    if role.startswith('cached'):
        lines += ['mov w1, #' + str(bits // 8), 'bl selected_expand' + ('' if bits == 128 else str(bits))]
    lines += ['mov w2, #' + str(size), 'bl selected_write', 'b.ne .LBB1_2',
              'bl selected_finish', 'str xzr, [x19]', 'stp x9, x8, [x19, #8]',
              '.LBB1_2:']
    if role.startswith('cached'):
        lines += ['mov w1, #' + str(size), 'bl selected_clear']
    lines += ['bl selected_guard_drop', 'ret']
    if panic == 'unwind':
        lines = ['.Lfunc_begin1:', '.Ltmp1:'] + lines + ['.LBB1_3:', '.Ltmp2:']
        if role.startswith('cached'):
            lines += ['mov w21, wzr', 'tbz w21, #0, .LBB1_4', 'bl selected_clear']
        lines += ['bl selected_guard_drop', '.LBB1_4:', 'bl selected_resume', 'bl selected_panic_cleanup']
    return lines


def symbols(v0=False):
    result = {}
    for role in k.ROLES:
        bits = role[-3:]
        owner = ('17Aes' + bits + 'ExpandedKey' if role.startswith('cached') else '9Aes' + bits + 'Key')
        wide = '4wide' if bits != '128' else ''
        if v0:
            name = '_RNvMs_Nt' + ('Nt' if wide else '') + 'Cabc_13brynja_crypto3aes' + wide + 'NtB5_' + owner + '3new'
        else:
            name = '_ZN13brynja_crypto3aes' + wide + owner + '3new17h0123456789abcdefE'
        result[role] = name
    return result


class Aarch64ConstructorTests(unittest.TestCase):
    def test_exact_population_and_namespace(self):
        for v0 in (False, True):
            selected = symbols(v0)
            definitions = {n: ('', '') for n in selected.values()}
            self.assertEqual(k.select(definitions, {}), selected)
            for name in selected.values():
                with self.assertRaisesRegex(ValueError, 'population'):
                    k.select({n: v for n, v in definitions.items() if n != name}, {})
                with self.assertRaisesRegex(ValueError, 'aliases'):
                    k.select(definitions, {name: 'elsewhere'})
            name = selected['key192']
            with self.assertRaisesRegex(ValueError, 'namespace'):
                k.select({**definitions, name.replace('4wide', ''): ('', '')}, {})
            extra = name.replace('Cabc', 'Cdef') if v0 else name.replace('h0123', 'h1234')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                k.select({**definitions, extra: ('', '')}, {})
            with self.assertRaisesRegex(ValueError, 'unrecognized'):
                k.select({**definitions, name.replace('Aes192', 'Aes512'): ('', '')}, {})

    def test_exact_policies_reject_synthetic_bodies(self):
        policy = json.loads(k.POLICY_PATH.read_text())
        self.assertEqual(set(policy), {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for config, roles in policy.items():
            compiler, panic = config.split('/')
            self.assertEqual(set(roles), set(k.ROLES))
            for role, item in roles.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'metadata_labels', 'sha256'})
                self.assertEqual(set(item['calls']), set(k.edges(role, panic)))
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    k.check(fixture(role, panic, compiler), CALLEES, role, compiler, panic)

    def test_twenty_five_mutations_per_role_and_profile(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in k.ROLES:
                    lines = fixture(role, panic, compiler)
                    policy = {compiler + '/' + panic: {role: k.observe(lines, CALLEES, role, panic)}}
                    with patch.object(k.Path, 'read_text', return_value=json.dumps(policy)):
                        self.assertEqual(k.mutations(lines, CALLEES, role, compiler, panic), 25)

    def test_width_and_owner_specific_calls(self):
        for role in k.ROLES:
            lines = fixture(role, 'abort')
            other = 'expand192' if role.endswith('128') else 'expand'
            for target in (other, 'resume', 'panic_cleanup'):
                with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                    k.observe(['bl ' + CALLEES[target]] + lines, CALLEES, role, 'abort')
            if role.startswith('key'):
                with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                    k.observe(['bl selected_clear'] + lines, CALLEES, role, 'abort')
        with self.assertRaisesRegex(ValueError, 'ambiguous call'):
            k.observe(fixture('key128', 'abort'), {**CALLEES, 'write': CALLEES['begin']}, 'key128', 'abort')

    def test_labels_preserve_destinations_and_reject_bad_positions(self):
        lines = fixture('key128', 'abort')
        original = k.observe(lines, CALLEES, 'key128', 'abort')
        self.assertEqual(original, k.observe([x.replace('.LBB1_', '.LBB123_') for x in lines], CALLEES, 'key128', 'abort'))
        for changed in (lines + ['.LBB1_1:'], lines + ['.LBB9_9:'],
                        ['.LBB9_0:', '.LBB9_1:'] + lines):
            with self.assertRaises(ValueError):
                k.observe(changed, CALLEES, 'key128', 'abort')
        with self.assertRaisesRegex(ValueError, 'unknown branch'):
            k.observe([x.replace('cbz w8, .LBB1_1', 'cbz w8, .LBB9_9') for x in lines], CALLEES, 'key128', 'abort')

    def test_eh_ownership_flags_and_cleanup_are_preserved(self):
        lines = fixture('cached128', 'unwind')
        original = k.observe(lines, CALLEES, 'cached128', 'unwind')
        self.assertEqual(original, k.observe([x.replace('.Ltmp', '.Ltmp99') for x in lines], CALLEES, 'cached128', 'unwind'))
        changed = lines.copy()
        changed.remove('.Ltmp2:')
        changed.insert(changed.index('bl selected_resume'), '.Ltmp2:')
        self.assertNotEqual(original, k.observe(changed, CALLEES, 'cached128', 'unwind'))
        for old, new in (('mov w21, wzr', 'mov w21, #1'),
                         ('tbz w21, #0, .LBB1_4', 'tbnz w21, #0, .LBB1_4')):
            self.assertNotEqual(original, k.observe([x.replace(old, new) for x in lines], CALLEES, 'cached128', 'unwind'))
        for target in ('guard_drop', 'clear', 'resume'):
            changed = lines.copy()
            changed.pop(max(i for i, line in enumerate(changed) if line == 'bl selected_' + target))
            self.assertNotEqual(original, k.observe(changed, CALLEES, 'cached128', 'unwind'))
        with self.assertRaisesRegex(ValueError, 'misplaced'):
            k.observe(['mov w0, #1'] + lines, CALLEES, 'cached128', 'unwind')

    def test_fail_closed_grammar_profiles_and_terminals(self):
        lines = fixture('key128', 'abort')
        for instruction in ('br x0', 'blr x0', 'ldr q0, [x0, x1]', '.inst 0', 'nop',
                            'udiv w0, w0, w1', 'mov sp, x0', 'cbz x0, .LBB1_1'):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                k.observe([instruction] + lines, CALLEES, 'key128', 'abort')
        for role, panic in (('key512', 'abort'), ('key128', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                k.observe(lines, CALLEES, role, panic)
        with self.assertRaisesRegex(ValueError, 'unreviewed compiler'):
            k.check(lines, CALLEES, 'key128', 'stable', 'abort')
        with self.assertRaisesRegex(ValueError, 'terminal'):
            k.observe(lines + ['mov w0, #1'], CALLEES, 'key128', 'abort')


if __name__ == '__main__':
    unittest.main()
