#!/usr/bin/env python3
"""Negative controls for exact linked substitution call and image binding."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


sub = module('linked_substitute', 'aes_linked_substitute.py')
elf = module('linked_mix_test_fixture', 'test-aes-linked-mix.py')
review = sub.image_review


def fixture(start=0x1000, pool=0x3000):
    image = bytearray(elf.fixture(start, pool)[-1])
    raw = bytes.fromhex('85f60f840a000000e823000000e908000000660fef0d')
    raw += (pool - start - 26).to_bytes(4, 'little', signed=True) + b'\xc3'
    image[0x200:0x200 + len(raw)] = raw
    image[0x230] = 0xc3
    lines = ['testl %esi, %esi', f'je 0x{start + 18:x} <substitute+0x12>',
             f'callq 0x{start + 48:x} <inverse>', f'jmp 0x{start + 26:x} <substitute+0x1a>',
             f'pxor {pool - start - 26}(%rip), %xmm1 # 0x{pool:x} <pool>', 'retq']
    return [lines, raw, [2, 6, 5, 5, 8, 1], 'substitute', start, bytes(image), ('inverse', start + 48, 1)]


def observe(args):
    return review.observe(*args[:-1], {'inverse': args[-1]})[0]


def replace_code(args, offset, value):
    raw, image = bytearray(args[1]), bytearray(args[5])
    raw[offset:offset + len(value)] = value
    image[0x200:0x200 + len(raw)] = raw
    args[1], args[5] = bytes(raw), bytes(image)


class LinkedSubstituteTests(unittest.TestCase):
    def test_synthetic_policy_is_separate_and_negative_controls_fail(self):
        args = fixture()
        actual = observe(args)
        self.assertEqual((actual['calls'], actual['constant_loads']), (1, 1))
        for compiler in sub.POLICY:
            with self.assertRaisesRegex(ValueError, 'reviewed substitution changed'):
                sub.check(*args, compiler)
        with patch.object(sub, 'POLICY', {'test': actual}):
            self.assertEqual(sub.check(*args, 'test')['role'], 'substitute')
            self.assertEqual(sub.mutations(*args, 'test'), 6)

    def test_relocated_code_call_and_pool_have_identical_identity(self):
        actual = observe(fixture())
        for start, pool in ((0x8000, 0x3000), (0x4000, 0x6000)):
            self.assertEqual(observe(fixture(start, pool)), actual)

    def test_unadmitted_or_ambiguous_calls_fail(self):
        args = fixture()
        for targets in (None, {}, {'wrong': ('other', 0x1030, 1)},
                        {'one': args[-1], 'two': args[-1]}):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                review.observe(*args[:-1], targets)

    def test_callee_requires_nonoverlapping_executable_extent(self):
        for target in (('inverse', 0x1000, 1), ('inverse', 0x1030, 0),
                       ('inverse', 0x1030, 17), ('inverse', 0x3000, 1)):
            args = fixture()
            args[-1] = target
            with self.subTest(target=target), self.assertRaises(ValueError):
                observe(args)

    def test_call_must_land_on_entry_not_inside_callee(self):
        args = fixture()
        args[0][2] = 'callq 0x1031 <inverse>'
        replace_code(args, 9, (36).to_bytes(4, 'little', signed=True))
        with self.assertRaisesRegex(ValueError, 'call destination mismatch'):
            observe(args)

    def test_indirect_jump_and_bad_displacements_are_not_calls(self):
        args = fixture()
        args[0][2] = 'callq *%rax'
        with self.assertRaisesRegex(ValueError, 'unsupported call'):
            observe(args)
        args = fixture()
        replace_code(args, 8, b'\xe9')
        with self.assertRaisesRegex(ValueError, 'unsupported call'):
            observe(args)
        args = fixture()
        replace_code(args, 9, b'\x24')
        with self.assertRaisesRegex(ValueError, 'call destination mismatch'):
            observe(args)

    def test_local_branch_requires_instruction_boundary(self):
        args = fixture()
        args[0][1] = 'je 0x1013 <substitute+0x13>'
        replace_code(args, 4, (11).to_bytes(4, 'little', signed=True))
        with self.assertRaisesRegex(ValueError, 'branch destination mismatch'):
            observe(args)
        args = fixture()
        args[0][3] = 'jmp 0x101b <substitute+0x1b>'
        replace_code(args, 14, (9).to_bytes(4, 'little', signed=True))
        with self.assertRaisesRegex(ValueError, 'branch destination mismatch'):
            observe(args)

    def test_affine_constant_and_fixed_operands_are_bound(self):
        args = fixture()
        policy = observe(args)
        with patch.object(sub, 'POLICY', {'test': policy}):
            image = bytearray(args[5])
            image[0x10f] ^= 1
            changed = list(args)
            changed[5] = bytes(image)
            with self.assertRaisesRegex(ValueError, 'reviewed substitution changed'):
                sub.check(*changed, 'test')
            for replacement in ('testl %eax, %eax', 'movq %rax, %rsp', 'rolb %cl, %al'):
                changed = list(args)
                changed[0] = [replacement, *args[0][1:]]
                with self.assertRaisesRegex(ValueError, 'reviewed substitution changed'):
                    sub.check(*changed, 'test')
        with self.assertRaisesRegex(ValueError, 'unreviewed substitution compiler'):
            sub.check(*args, 'unknown')


if __name__ == '__main__':
    unittest.main()
