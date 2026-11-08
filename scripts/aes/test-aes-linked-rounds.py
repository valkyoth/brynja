#!/usr/bin/env python3
"""Round-role, branch encoding and cleanup-policy regression tests."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


rounds = module('rounds', 'aes_linked_rounds.py')
fixture_module = module('round_fixture', 'test-aes-linked-substitute.py')
review = rounds.image_review


def fixture():
    image = bytearray(fixture_module.fixture()[5])
    raw = bytes.fromhex('4883fe1085f67500be04000000e826000000e8190000004981fcb300000075e8c3')
    image[0x200:0x200 + len(raw)] = raw
    image[0x238] = 0xc3
    lines = ['cmpq $16, %rsi', 'testl %esi, %esi', 'jne 0x1008 <6expand+0x8>',
             'movl $4, %esi', 'callq 0x1038 <zeroize>', 'callq 0x1030 <inverse>',
             'cmpq $179, %r12', 'jne 0x1008 <6expand+0x8>', 'retq']
    return [lines, raw, [4, 2, 2, 5, 5, 5, 7, 2, 1], '6expand', 0x1000, bytes(image),
            {'inverse': ('inverse', 0x1030, 1), 'zeroize': ('zeroize', 0x1038, 1)}]


class LinkedRoundsTests(unittest.TestCase):
    def test_reviewed_roles_complete_for_each_compiler(self):
        for entries in rounds.POLICY.values():
            rounds.population(list(entries))
            for role, row in entries.items():
                self.assertEqual(row['calls'], 12 if role.startswith('transform') else
                                 9 if role == 'expand256' else 5)

    def test_synthetic_policy_separate_and_all_mutations_rejected(self):
        args = fixture()
        actual, _ = review.observe(*args)
        for compiler in rounds.POLICY:
            with self.assertRaisesRegex(ValueError, 'reviewed round body changed'):
                rounds.check(*args, 'expand128', compiler)
        with patch.object(rounds, 'POLICY', {'test': {'expand128': actual}}):
            self.assertEqual(rounds.check(*args, 'expand128', 'test')['role'], 'expand128')
            self.assertEqual(rounds.mutations(*args, 'expand128', 'test'), 8)

    def test_widths_selected_independently_of_opaque_symbol_hashes(self):
        for bits, key, last in ((128, 16, 160), (192, 24, 192), (256, 32, 224)):
            prefix = '4wide' if bits != 128 else ''
            self.assertEqual(rounds.role_for([f'cmpq ${key}, %rsi'], prefix + '6expand'), f'expand{bits}')
            self.assertEqual(rounds.role_for([f'movdqu {last}(%r14), %xmm0'] * 2,
                                            prefix + '9transform'), f'transform{bits}')
        with self.assertRaisesRegex(ValueError, 'generic width mismatch'):
            rounds.role_for(['cmpq $24, %rsi'], '_RI4wide6expandKj20_Kjf0_Kje_EB8_')

    def test_missing_duplicate_or_inconsistent_widths_fail(self):
        for roles in (rounds.ROLES[:-1], (*rounds.ROLES, rounds.ROLES[0]),
                      (*rounds.ROLES[:-1], rounds.ROLES[0])):
            with self.assertRaisesRegex(ValueError, 'missing/duplicate'):
                rounds.population(roles)
        for lines, name in (([], '6expand'), (['cmpq $24, %rsi'], '6expand'),
                            (['cmpq $16, %rsi'], '4wide6expand'), ([], 'unknown'),
                            (['movdqu 160(%r14), %xmm0'], '9transform'),
                            (['movdqu 192(%r14), %xmm0', 'movdqu 224(%r14), %xmm0'], '4wide9transform')):
            with self.subTest(name=name, lines=lines), self.assertRaises(ValueError):
                rounds.role_for(lines, name)

    def test_wrong_role_compiler_or_call_population_fails(self):
        args = fixture()
        for role, compiler, reason in (('expand192', '1.90.0', 'role mismatch'),
                                       ('expand128', 'unknown', 'unreviewed'),
                                       ('unknown', '1.90.0', 'unreviewed')):
            with self.assertRaisesRegex(ValueError, reason):
                rounds.check(*args, role, compiler)
        for targets in ({}, {'inverse': args[-1]['inverse']}, {**args[-1], 'extra': ('other', 0x103c, 1)}):
            with self.assertRaisesRegex(ValueError, 'target population'):
                rounds.check(*args[:-1], targets, 'expand128', '1.90.0')

    def test_all_admitted_branch_encodings_and_backward_targets(self):
        for op, short, near in (('je', b'\x74', b'\x0f\x84'), ('jne', b'\x75', b'\x0f\x85'),
                                ('ja', b'\x77', b'\x0f\x87'), ('jbe', b'\x76', b'\x0f\x86'),
                                ('jb', b'\x72', b'\x0f\x82'), ('jae', b'\x73', b'\x0f\x83'),
                                ('jmp', b'\xeb', b'\xe9')):
            for prefix, width in ((short, 1), (near, 4)):
                for target in (1, 2 + len(prefix) + width):
                    raw = b'\x90\x90' + prefix + (target - 2 - len(prefix) - width).to_bytes(width, 'little', signed=True) + b'\xc3'
                    image = bytearray(fixture()[5])
                    image[0x200:0x200 + len(raw)] = raw
                    args = [['nop', 'nop', f'{op} 0x{0x1000 + target:x} <branch+0x{target:x}>', 'retq'],
                            raw, [1, 1, len(prefix) + width, 1], 'branch', 0x1000, bytes(image)]
                    with self.subTest(op=op, width=width, target=target):
                        review.observe(*args)
                        bad = list(args)
                        bad[0] = [*args[0][:2], f'{op} 0x1003 <branch+0x3>', 'retq']
                        with self.assertRaisesRegex(ValueError, 'branch destination mismatch'):
                            review.observe(*bad)
                        bad = list(args)
                        bad[0] = [*args[0][:2], args[0][2].replace(op, 'jne' if op != 'jne' else 'je', 1), 'retq']
                        with self.assertRaisesRegex(ValueError, 'branch destination mismatch'):
                            review.observe(*bad)


if __name__ == '__main__':
    unittest.main()
