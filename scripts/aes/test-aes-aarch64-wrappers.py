#!/usr/bin/env python3
"""Binding, result/cleanup and fail-closed controls for six ARM wrappers."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_wrappers_tested', Path(__file__).with_name('aes_aarch64_wrappers.py'))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
CALLEES = {r: 'selected_' + r for r in set(sum(w.EDGES.values(), ())) | {'resume', 'panic_cleanup'}}


def fixture(panic='abort'):
    # Deliberately not an approved cryptographic implementation.
    lines = ['mov w1, #16', 'bl selected_clear', 'cmp w8, #1', 'b.ne .LBB1_2',
             '.LBB1_1:', 'mov w8, #1', 'str x8, [x19]', 'bl selected_guard_drop',
             '.LBB1_2:', 'ret']
    if panic == 'unwind':
        return ['.Lfunc_begin1:', '.Ltmp0:'] + lines[:2] + ['.Ltmp1:'] + lines[2:] + [
            '.LBB1_3:', '.Ltmp2:', 'bl selected_resume', '.Ltmp3:', 'bl selected_panic_cleanup']
    return lines


def selection_fixture():
    portable = {r: ('portable_' + r, '', '') for r in ('expand', 'expand192', 'expand256', 'transform', 'transform192', 'transform256')}
    owners = {'key128': '9Aes128Key', 'cached128': '17Aes128ExpandedKey', 'key192': '9Aes192Key', 'key256': '9Aes256Key'}
    wrappers = {r: '_ZN13brynja_crypto3aes' + ('4wide' if r in ('key192', 'key256') else '')
                + owner + '9transform17h' + 'a' * 16 + 'E' for r, owner in owners.items()}
    definitions = {name: ('', '') for name in wrappers.values()}
    for bits, digest in ((192, 'b'), (256, 'c')):
        name = '_ZN13brynja_crypto3aes4wide6secret17h' + digest * 16 + 'E'
        wrappers['secret' + str(bits)] = name
        definitions[name] = ('', 'call void @portable_transform' + str(bits) + '()')
    externals = {r: '_ZN11brynja_core13secret_memory26SecretRegionInitialization' + str(len(r)) + r
                 + '17h' + 'a' * 16 + 'E' for r in ('begin', 'write', 'finish')}
    externals['clear'] = 'external_clear'
    externals['guard_drop'] = '_ZN96_$LT$brynja_core..secret_memory..SecretRegionInitialization$u20$as$u20$core..ops..drop..Drop$GT$4drop17h' + 'a' * 16 + 'E'
    externals['panic_cleanup'] = '_ZN4core9panicking16panic_in_cleanup17h' + 'a' * 16 + 'E'
    llvm = ''.join('declare void @"' + n + '"()\n' for n in externals.values())
    return definitions, portable, wrappers, externals, llvm


class Aarch64WrapperTests(unittest.TestCase):
    def test_exact_policy_population_and_synthetic_rejection(self):
        policies = json.loads(w.POLICY_PATH.read_text())
        self.assertEqual(set(policies), {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for config, items in policies.items():
            compiler, panic = config.split('/')
            self.assertEqual(set(items), set(w.ROLES))
            for role, item in items.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'metadata_labels', 'sha256'})
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                self.assertEqual(set(item['calls']), set(w.EDGES[role]) | ({'resume', 'panic_cleanup'} if panic == 'unwind' else set()))
                self.assertEqual(item['metadata_labels'] == 0, panic == 'abort')
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    w.check(fixture(panic), CALLEES, role, compiler, panic)
        for role, compiler, panic in (('other', '1.90.0', 'abort'), ('key128', 'stable', 'abort'), ('key128', '1.99.1', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                w.check(fixture(), CALLEES, role, compiler, panic)

    def test_selector_binds_owners_widths_and_external_declarations(self):
        definitions, portable, wrappers, externals, llvm = selection_fixture()
        for panic in ('abort', 'unwind'):
            found, callees = w.select(definitions, {}, llvm, portable, panic, 'external_clear')
            self.assertEqual(found, wrappers)
            for role in ('begin', 'write', 'finish', 'clear', 'guard_drop'):
                self.assertEqual(callees[role], externals[role])
            self.assertEqual('resume' in callees, panic == 'unwind')
        for role in ('begin', 'write', 'finish', 'clear', 'guard_drop', 'panic_cleanup'):
            declaration = 'declare void @"' + externals[role] + '"()\n'
            for bad in (llvm.replace(declaration, ''), llvm + declaration,
                        llvm.replace(declaration, declaration.replace('"()', '_suffix"()'))):
                with self.assertRaisesRegex(ValueError, 'external declaration'):
                    w.select(definitions, {}, bad, portable, 'unwind', 'external_clear')

    def test_selector_rejects_population_aliases_namespace_and_width_confusion(self):
        definitions, portable, wrappers, _, llvm = selection_fixture()
        for role in w.ROLES:
            changed = definitions.copy()
            del changed[wrappers[role]]
            with self.assertRaisesRegex(ValueError, 'population'):
                w.select(changed, {}, llvm, portable, 'abort', 'external_clear')
        for name, body, reason in (
            ('_ZN13brynja_crypto3aes9Aes512Key9transform17h' + 'a' * 16 + 'E', '', 'unrecognized'),
            (wrappers['key128'].replace('3aes9', '3aes4wide9'), '', 'namespace'),
            (wrappers['key128'].replace('a' * 16, 'd' * 16), '', 'duplicate'),
        ):
            with self.assertRaisesRegex(ValueError, reason):
                w.select({**definitions, name: ('', body)}, {}, llvm, portable, 'abort', 'external_clear')
        with self.assertRaisesRegex(ValueError, 'aliases'):
            w.select(definitions, {wrappers['key128']: 'elsewhere'}, llvm, portable, 'abort', 'external_clear')
        changed = definitions.copy()
        changed[wrappers['secret192']] = ('', 'call void @portable_transform192()\ncall void @portable_transform256()')
        with self.assertRaisesRegex(ValueError, 'ambiguous wide'):
            w.select(changed, {}, llvm, portable, 'abort', 'external_clear')
        del changed[wrappers['secret192']]
        wrong = '_RINvNtNtCexample_13brynja_crypto3aes4wide6secretKj20_Kjf0_Kje_EB6_'
        changed[wrong] = ('', 'call void @portable_transform192()')
        with self.assertRaisesRegex(ValueError, 'generic width'):
            w.select(changed, {}, llvm, portable, 'abort', 'external_clear')

    def test_call_normalization_never_admits_unbound_callees(self):
        original = fixture()
        expected = w.observe(original, CALLEES, 'key128', 'abort')
        renamed = {**CALLEES, 'clear': 'another_clear'}
        self.assertEqual(expected, w.observe([x.replace('selected_clear', 'another_clear') for x in original], renamed, 'key128', 'abort'))
        for role, target in (('key128', 'selected_transform256'), ('cached128', 'selected_expand'),
                             ('key192', 'selected_secret256'), ('secret192', 'selected_begin')):
            with self.assertRaisesRegex(ValueError, 'unreviewed call'):
                w.observe(['bl ' + target] + original, CALLEES, role, 'abort')
        with self.assertRaisesRegex(ValueError, 'ambiguous call'):
            w.observe(original, {**CALLEES, 'clear': CALLEES['guard_drop']}, 'key128', 'abort')

    def test_branch_and_eh_positions_are_preserved(self):
        original = fixture('unwind')
        expected = w.observe(original, CALLEES, 'key128', 'unwind')
        renamed = [x.replace('.LBB1_', '.LBB99_').replace('.Ltmp', '.Ltmp9').replace('.Lfunc_begin1', '.Lfunc_begin99') for x in original]
        self.assertEqual(expected, w.observe(renamed, CALLEES, 'key128', 'unwind'))
        changed = original.copy()
        i = changed.index('.Ltmp1:')
        changed[i], changed[i+1] = changed[i+1], changed[i]
        self.assertNotEqual(expected, w.observe(changed, CALLEES, 'key128', 'unwind'))
        for bad in (original + ['.Ltmp0:'], original + ['.Ltmp99:'], original[:-1],
                    original[1:] + ['.Lfunc_begin1:'], [x for x in original if x != '.LBB1_2:'],
                    original[:2] + ['.Lbad:'] + original[2:]):
            with self.assertRaises(ValueError):
                w.observe(bad, CALLEES, 'key128', 'unwind')
        with self.assertRaisesRegex(ValueError, 'unreviewed label'):
            w.observe(['.Ltmp0:'] + fixture(), CALLEES, 'key128', 'abort')

    def test_cleanup_and_status_operands_cannot_change(self):
        original = fixture()
        expected = w.observe(original, CALLEES, 'key128', 'abort')
        for before, after in (('mov w1, #16', 'mov w1, #0'), ('str x8, [x19]', 'str xzr, [x19]'),
                              ('cmp w8, #1', 'cmp w8, #0'), ('b.ne .LBB1_2', 'b.ne .LBB1_1'),
                              ('str x8, [x19]', 'str x8, [x20]')):
            self.assertNotEqual(expected, w.observe([x.replace(before, after) for x in original], CALLEES, 'key128', 'abort'))

    def test_unreviewed_operations_fail_closed(self):
        for line in ('blr x0', 'br x0', '.inst 0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]',
                     'lsl w0, w0, w1', 'mov sp, x0', 'bl wrong_guard_drop', 'b.eq, .LBB1_2',
                     'cbz w8 .LBB1_2', 'tbnz w8, #0, .LBB1_2'):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'unreviewed'):
                w.observe([line] + fixture(), CALLEES, 'key128', 'abort')

    def test_sixteen_mutations_per_role_and_profile(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for role in w.ROLES:
                    lines = fixture(panic)
                    synthetic = {compiler + '/' + panic: {role: w.observe(lines, CALLEES, role, panic)}}
                    with patch.object(w.Path, 'read_text', return_value=json.dumps(synthetic)):
                        self.assertEqual(w.mutations(lines, CALLEES, role, compiler, panic), 16)


if __name__ == '__main__':
    unittest.main()
