#!/usr/bin/env python3
"""Core dependency identity, bounds, transfer and erasure policy regressions."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_core_tested', Path(__file__).with_name('aes_aarch64_core.py'))
k = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k)
SELECTED = {r: 'selected_' + r for r in k.ROLES}


def fixture(role, compiler='1.90.0'):
    # Non-production parser fixtures; intentionally cannot pass real policies.
    middle = {
        'begin': ['mov x20, x0', 'mov x21, x1', 'bl selected_zeroize', 'str xzr, [x19, #24]', 'mov w8, #1'],
        'write': ['b.hs .LBB1_2', 'cmp x19, x10', 'add x0, x8, x9', 'bl selected_copy', 'str x19, [x20, #16]'],
        'finish': ['stp x0, x1, [x8, #8]', 'mov w9, #769', 'strb wzr, [x8]', 'b selected_zeroize'],
        'clear': ['bl selected_zeroize', 'mov w0, #4' if compiler == '1.90.0' else 'mov w0, #255',
                  'mov w0, wzr', 'ldp x29, x30, [sp], #16'],
        'guard_drop': ['mov x8, x0', 'ldr x0, [x0]', 'ldr x1, [x8, #8]', 'b selected_zeroize'],
        'copy': ['add x5, x5, #8', 'strb w4, [x0, x5]', 'mov x4, xzr', 'mov x5, xzr', 'mov x6, xzr'],
        'zeroize': ['subs x1, x1, #1', 'strb wzr, [x0], #1' if compiler == '1.90.0' else 'strb wzr, [x0]', 'b.ne .LBB1_2'],
    }[role]
    return ['cbz x1, .LBB1_2'] + middle + ['.LBB1_2:', 'ret']


def selection_fixture():
    selected = SELECTED.copy()
    selected['copy'] = '_ZN11brynja_core22secret_memory_transfer10copy_bytes17haabbE'
    selected['zeroize'] = '_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17haabbE'
    definitions = {n: ('', '') for n in selected.values()}
    return selected, definitions, 'target triple = "aarch64-unknown-linux-gnu"\n'


class Aarch64CoreTests(unittest.TestCase):
    def test_exact_policy_population_and_no_fixture_acceptance(self):
        policy = json.loads(k.POLICY_PATH.read_text())
        self.assertEqual(set(policy), {'assembly', 'zeroize_llvm'})
        self.assertEqual(set(policy['zeroize_llvm']), {'1.90.0', '1.99.1'})
        self.assertEqual(set(policy['assembly']), {c + '/' + p for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for config, roles in policy['assembly'].items():
            self.assertEqual(set(roles), set(k.ROLES))
            for role, item in roles.items():
                self.assertEqual(set(item), {'instructions', 'branches', 'calls', 'sha256'})
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                self.assertEqual(set(item['calls']), {('b' if role in ('finish', 'guard_drop') else 'bl') + ' @' + r for r in k.EDGES[role]})
                with self.assertRaisesRegex(ValueError, 'instruction stream changed'):
                    k.check(fixture(role), SELECTED, role, *config.split('/'))
        for c, p in (('stable', 'abort'), ('1.90.0', 'other')):
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                k.check(fixture('begin'), SELECTED, 'begin', c, p)

    def test_exact_external_symbols_must_have_real_definitions(self):
        selected, definitions, llvm = selection_fixture()
        self.assertEqual(k.select(llvm, definitions, {}, selected), selected)
        for role, name in selected.items():
            changed = definitions.copy()
            del changed[name]
            with self.assertRaisesRegex(ValueError, 'missing'):
                k.select(llvm, changed, {}, selected)
            with self.assertRaisesRegex(ValueError, 'aliased'):
                k.select(llvm, definitions, {name: 'other'}, selected)
        with self.assertRaisesRegex(ValueError, 'wrong target'):
            k.select(llvm.replace('aarch64', 'x86_64'), definitions, {}, selected)
        with self.assertRaisesRegex(ValueError, 'wrong target'):
            k.select(llvm * 2, definitions, {}, selected)
        changed = definitions.copy()
        changed[selected['copy'].replace('haabb', 'hccdd')] = ('', '')
        with self.assertRaisesRegex(ValueError, 'ambiguous helper'):
            k.select(llvm, changed, {}, selected)
        with self.assertRaisesRegex(ValueError, 'ambiguous core identity'):
            k.select(llvm, definitions, {}, {**selected, 'clear': selected['begin']})

    def test_local_labels_and_tail_calls_are_bound(self):
        original = fixture('finish')
        expected = k.observe(original, SELECTED, 'finish')
        renamed = [x.replace('.LBB1_2', '.Ltmp99') for x in original]
        self.assertEqual(expected, k.observe(renamed, SELECTED, 'finish'))
        replaced = [x.replace('b selected_zeroize', 'bl selected_zeroize') for x in original]
        self.assertNotEqual(expected, k.observe(replaced, SELECTED, 'finish'))
        for bad in (original + ['.LBB1_2:'], original + ['.Ltmp9:'],
                    original[:-1] + ['.Ltmp9:', 'ret'], original[1:],
                    [x for x in original if x != '.LBB1_2:']):
            # Removing the entry branch remains parseable but changes its hash.
            if bad == original[1:]:
                self.assertNotEqual(expected, k.observe(bad, SELECTED, 'finish'))
            else:
                with self.assertRaises(ValueError):
                    k.observe(bad, SELECTED, 'finish')
        with self.assertRaisesRegex(ValueError, 'unreviewed call'):
            k.observe(['b selected_copy'] + original, SELECTED, 'finish')
        with self.assertRaisesRegex(ValueError, 'unreviewed call'):
            k.observe(['bl selected_zeroize'] + fixture('copy'), SELECTED, 'copy')

    def test_zero_store_and_register_erasure_remain_in_fingerprint(self):
        for role, old, new in (('zeroize', 'strb wzr, [x0], #1', 'strb w8, [x0], #1'),
                               ('copy', 'mov x4, xzr', 'mov x4, x0'),
                               ('copy', 'mov x5, xzr', 'mov x5, x0'),
                               ('copy', 'mov x6, xzr', 'mov x6, x0'),
                               ('write', 'cmp x19, x10', 'cmp x19, x9')):
            original = fixture(role)
            self.assertNotEqual(k.observe(original, SELECTED, role), k.observe([x.replace(old, new) for x in original], SELECTED, role))

    def test_zeroizer_llvm_preserves_volatile_and_compiler_fence(self):
        body = 'entry:\n store volatile i8 0, ptr %p, align 1\n fence syncscope("singlethread") seq_cst\n ret void\n'
        self.assertEqual(k.llvm_digest(body), k.llvm_digest(body.replace('entry:', 'entry: ; harmless comment').replace(' ret', '   ret')))
        with self.assertRaisesRegex(ValueError, 'zeroizer LLVM changed'):
            k.check_llvm(body, '1.90.0')
        for c in ('1.90.0', '1.99.1'):
            with patch.object(k.Path, 'read_text', return_value=json.dumps({'zeroize_llvm': {c: k.llvm_digest(body)}})):
                self.assertEqual(k.llvm_mutations(body, c), 2)
        with self.assertRaisesRegex(ValueError, 'unreviewed compiler'):
            k.check_llvm(body, 'stable')

    def test_unreviewed_instructions_fail_closed(self):
        for line in ('blr x0', 'udiv w0, w0, w1', 'ldr w0, [x0, x1]', 'lsl w0, w0, w1',
                     '.inst 0', 'mov sp, x0', 'bl wrong_zeroize', 'nop', 'svc #0',
                     'cbz x1 .LBB1_2', 'b.ne, .LBB1_2', 'add x0, x1'):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'unreviewed'):
                k.observe([line] + fixture('clear'), SELECTED, 'clear')

    def test_fifteen_mutations_per_body_and_configuration(self):
        for c in ('1.90.0', '1.99.1'):
            for p in ('abort', 'unwind'):
                for role in k.ROLES:
                    lines = fixture(role, c)
                    synthetic = {'assembly': {c + '/' + p: {role: k.observe(lines, SELECTED, role)}}}
                    with patch.object(k.Path, 'read_text', return_value=json.dumps(synthetic)):
                        self.assertEqual(k.mutations(lines, SELECTED, role, c, p), 15)


if __name__ == '__main__':
    unittest.main()
