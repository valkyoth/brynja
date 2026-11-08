#!/usr/bin/env python3
"""Public release ordering, call identity and cleanup review regressions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_public_tested', Path(__file__).with_name('aes_aarch64_public.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
CALLEES = {r: 'selected_' + r for r in ('expand', 'expand192', 'expand256', 'transform',
                                      'transform192', 'transform256', 'clear', 'resume', 'panic_cleanup')}


def fixture(role, panic):
    # Parser fixtures only. These deliberately do not match production policy.
    transform = next(r for r in p.edges(role, panic) if r.startswith('transform'))
    lines = ['cbz x1, .LBB1_2', 'bl ' + CALLEES[transform], 'mov w20, w0',
             'tbnz w0, #0, .LBB1_1', 'ldr q0, [sp]', 'str q0, [x19]',
             '.LBB1_1:', 'mov x0, sp', 'mov w1, #16', 'bl selected_clear',
             'mov w0, w20', '.LBB1_2:', 'ret']
    if panic == 'unwind':
        lines = ['.Lfunc_begin1:', '.Ltmp1:'] + lines + [
            '.LBB1_3:', '.Ltmp2:', 'mov x0, sp', 'mov w1, #16', 'bl selected_clear',
            'bl selected_resume', 'bl selected_panic_cleanup']
    return lines


def symbols(v0=False):
    result = {}
    for role in p.ROLES:
        bits = role[-3:]
        owner = ('17Aes' + bits + 'ExpandedKey' if role.startswith('cached') else '9Aes' + bits + 'Key')
        wide = '4wide' if bits != '128' else ''
        if v0:
            name = '_RNvMs_Nt' + ('Nt' if wide else '') + 'Cabc_13brynja_crypto3aes' + wide + 'NtB5_' + owner + '20encrypt_block_public'
        else:
            name = '_ZN13brynja_crypto3aes' + wide + owner + '20encrypt_block_public17h0123456789abcdefE'
        result[role] = name
    return result


class Aarch64PublicTests(unittest.TestCase):
    def test_exact_symbols_population_namespace_and_aliases(self):
        for v0 in (False, True):
            selected = symbols(v0)
            definitions = {n: ('', '') for n in selected.values()}
            self.assertEqual(p.select(definitions, {}), selected)
            for role, name in selected.items():
                with self.assertRaisesRegex(ValueError, 'population'):
                    p.select({n: v for n, v in definitions.items() if n != name}, {})
                with self.assertRaisesRegex(ValueError, 'aliases'):
                    p.select(definitions, {name: 'elsewhere'})
            name = selected['key192']
            with self.assertRaisesRegex(ValueError, 'namespace'):
                p.select({**definitions, name.replace('4wide', ''): ('', '')}, {})
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                extra = name.replace('Cabc', 'Cdef') if v0 else name.replace('h0123', 'h1234')
                p.select({**definitions, extra: ('', '')}, {})
            with self.assertRaisesRegex(ValueError, 'unrecognized'):
                p.select({**definitions, name.replace('Aes192', 'Aes512'): ('', '')}, {})

    def test_policy_population_and_fixture_rejection(self):
        policy = json.loads(p.POLICY_PATH.read_text())
        self.assertEqual(set(policy), {c + '/' + mode for c in ('1.90.0', '1.99.1') for mode in ('abort', 'unwind')})
        for config, roles in policy.items():
            compiler, panic = config.split('/')
            self.assertEqual(set(roles), set(p.ROLES))
            for role, item in roles.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'metadata_labels', 'sha256'})
                self.assertEqual(set(item['calls']), set(p.edges(role, panic)))
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    p.check(fixture(role, panic), CALLEES, role, compiler, panic)
        with self.assertRaisesRegex(ValueError, 'unreviewed compiler'):
            p.check(fixture('key128', 'abort'), CALLEES, 'key128', 'stable', 'abort')

    def test_eighteen_mutations_for_every_profile_and_role(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in p.ROLES:
                    lines = fixture(role, panic)
                    policy = {compiler + '/' + panic: {role: p.observe(lines, CALLEES, role, panic)}}
                    with patch.object(p.Path, 'read_text', return_value=json.dumps(policy)):
                        self.assertEqual(p.mutations(lines, CALLEES, role, compiler, panic), 18)

    def test_width_specific_calls_and_no_cached_expansion(self):
        for role in p.ROLES:
            lines = fixture(role, 'abort')
            with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                p.observe(['bl selected_resume'] + lines, CALLEES, role, 'abort')
            other = 'transform192' if role.endswith('128') else 'transform'
            with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                p.observe(['bl ' + CALLEES[other]] + lines, CALLEES, role, 'abort')
            if role.startswith('cached'):
                with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                    p.observe(['bl selected_expand'] + lines, CALLEES, role, 'abort')
        with self.assertRaisesRegex(ValueError, 'ambiguous call'):
            p.observe(fixture('cached128', 'abort'), {**CALLEES, 'clear': CALLEES['transform']}, 'cached128', 'abort')

    def test_labels_bind_positions_not_compiler_numbers(self):
        lines = fixture('cached128', 'abort')
        original = p.observe(lines, CALLEES, 'cached128', 'abort')
        self.assertEqual(original, p.observe([x.replace('.LBB1_', '.LBB987_') for x in lines], CALLEES, 'cached128', 'abort'))
        for changed in (lines + ['.LBB1_4:'], lines + ['.LBB1_1:'],
                        ['.LBB9_0:'] + lines[:6] + ['.LBB9_1:'] + lines[6:]):
            with self.assertRaises(ValueError):
                p.observe(changed, CALLEES, 'cached128', 'abort')
        with self.assertRaisesRegex(ValueError, 'unknown branch'):
            p.observe([x.replace('cbz x1, .LBB1_2', 'cbz x1, .LBB9_9') for x in lines], CALLEES, 'cached128', 'abort')

    def test_eh_positions_and_cleanup_are_not_discarded(self):
        lines = fixture('key128', 'unwind')
        original = p.observe(lines, CALLEES, 'key128', 'unwind')
        self.assertEqual(original, p.observe([x.replace('.Ltmp', '.Ltmp88').replace('.Lfunc_begin1', '.Lfunc_begin9') for x in lines], CALLEES, 'key128', 'unwind'))
        changed = lines.copy()
        changed.remove('.Ltmp2:')
        changed.insert(changed.index('bl selected_resume'), '.Ltmp2:')
        self.assertNotEqual(original, p.observe(changed, CALLEES, 'key128', 'unwind'))
        for target in ('selected_resume', 'selected_clear'):
            changed = lines.copy()
            index = max(i for i, line in enumerate(changed) if line == 'bl ' + target)
            changed.pop(index)
            self.assertNotEqual(original, p.observe(changed, CALLEES, 'key128', 'unwind'))
        with self.assertRaisesRegex(ValueError, 'misplaced'):
            p.observe(['mov w0, #1'] + lines, CALLEES, 'key128', 'unwind')

    def test_unknown_grammar_and_profiles_fail_closed(self):
        lines = fixture('key128', 'abort')
        for instruction in ('br x0', 'blr x0', 'ldr q0, [x0, x1]', '.inst 0', 'nop',
                            'udiv w0, w0, w1', 'mov sp, x0', 'cbnz x1, .LBB1_2'):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                p.observe([instruction] + lines, CALLEES, 'key128', 'abort')
        for role, panic in (('key512', 'abort'), ('key128', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
                p.observe(lines, CALLEES, role, panic)


if __name__ == '__main__':
    unittest.main()
