#!/usr/bin/env python3
"""Synthetic ELF/relocation negative controls; not AES functional vectors."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('linked_mix', Path(__file__).with_name('aes_linked_mix.py'))
mix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mix)


def fixture(start=0x1000, pool=0x3000):
    image = bytearray(0x400)
    image[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', image, 16, 3, 62, 1)
    struct.pack_into('<Q', image, 32, 64)
    struct.pack_into('<HHH', image, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 4, 0x100, pool, 0, 64, 64, 16)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 5, 0x200, start, 0, 64, 64, 16)
    image[0x100:0x140] = bytes(range(64))
    lines = ['testl %esi, %esi', f'je 0x{start + 33:x} <mix+0x21>']
    raw, sizes = bytearray.fromhex('85f60f8419000000'), [2, 6]
    for op, register, opcode, pool_offset in (('movdqa', 3, 0x6f, 0), ('movd', 11, 0x6e, 16), ('pand', 0, 0xdb, 32)):
        prefix = b'\x66' + (b'\x44' if register >= 8 else b'') + bytes((15, opcode, 5 | ((register % 8) << 3)))
        size = len(prefix) + 4
        target = pool + pool_offset
        delta = target - (start + len(raw) + size)
        lines.append(f'{op} {delta}(%rip), %xmm{register} # 0x{target:x} <pool+0x{pool_offset:x}>')
        raw += prefix + delta.to_bytes(4, 'little', signed=True)
        sizes.append(size)
    lines.append('retq')
    raw += b'\xc3'
    sizes.append(1)
    image[0x200:0x200 + len(raw)] = raw
    return lines, bytes(raw), sizes, 'mix', start, bytes(image)


class LinkedMixTests(unittest.TestCase):
    def test_mapped_bytes_and_constants_are_bound(self):
        args = fixture()
        actual, locations = mix.observe(*args)
        self.assertEqual(locations, [(0x100, 16), (0x110, 4), (0x120, 16)])
        self.assertEqual((actual['instructions'], actual['symbol_bytes']), (6, 34))
        # A synthetic program must never satisfy the real reviewed AES policy.
        for compiler in mix.POLICY:
            with self.assertRaisesRegex(ValueError, 'reviewed mix changed'):
                mix.check(*args, compiler)
        with patch.object(mix, 'POLICY', {'test': actual}):
            self.assertEqual(mix.check(*args, 'test')['role'], 'mix')
            self.assertEqual(mix.mutations(*args, 'test'), 7)

    def test_relocation_preserves_only_verified_constant_identity(self):
        expected, _ = mix.observe(*fixture())
        for start, pool in ((0x8000, 0x3000), (0x5000, 0x9000)):
            actual, _ = mix.observe(*fixture(start, pool))
            self.assertEqual(actual, expected)

    def test_elf_header_and_table_fail_closed(self):
        image = fixture()[-1]
        cases = [b'', image[:63], image[:150]]
        for offset, fmt, value in ((4, 'B', 1), (5, 'B', 2), (6, 'B', 0),
                                   (16, 'H', 1), (18, 'H', 183), (20, 'I', 0),
                                   (32, 'Q', 0), (32, 'Q', 2**64 - 1), (52, 'H', 0),
                                   (54, 'H', 55), (56, 'H', 0), (56, 'H', 65535)):
            changed = bytearray(image)
            struct.pack_into('<' + fmt, changed, offset, value)
            cases.append(bytes(changed))
        for changed in cases:
            with self.subTest(changed=changed[:64]), self.assertRaises(ValueError):
                mix.segments(changed)

    def test_load_bounds_overlap_and_overflow_fail(self):
        args = list(fixture())
        for offset, value in ((72, 0x400), (96, 65), (104, 63),
                              (80, 2**64 - 32), (136, 0x3000)):
            image = bytearray(args[-1])
            struct.pack_into('<Q', image, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                mix.observe(*args[:-1], bytes(image))

    def test_permissions_and_file_backing_are_required(self):
        args = fixture()
        # Writable or executable constants, writable code and BSS-only tails.
        for offset, fmt, value in ((68, 'I', 6), (68, 'I', 5), (124, 'I', 7),
                                   (96, 'Q', 40), (152, 'Q', 10)):
            image = bytearray(args[-1])
            struct.pack_into('<' + fmt, image, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(ValueError, 'mapping'):
                mix.observe(*args[:-1], bytes(image))

    def test_instruction_partition_is_exact(self):
        args = list(fixture())
        for sizes in ([2], [0, 8, 8, 9, 8, 1], [16, 6, 8, 9, 8, 1],
                      [True, 7, 8, 9, 8, 1], [2, 6, 8, 9, 8, 2]):
            args[2] = sizes
            with self.assertRaisesRegex(ValueError, 'partition'):
                mix.observe(*args)

    def test_rip_opcode_register_and_displacement_are_validated(self):
        original = fixture()
        for old, new in (('movdqa', 'movdqu'), ('%xmm3', '%xmm4'),
                         ('%xmm3', '%xmm19'), ('# 0x3000', '# 0x3001'),
                         ('8176(%rip)', '8177(%rip)')):
            args = list(original)
            args[0] = [line.replace(old, new) for line in args[0]]
            self.assertNotEqual(args[0], original[0])
            with self.subTest(old=old, new=new), self.assertRaises(ValueError):
                mix.observe(*args)

    def test_branch_target_annotation_and_encoding_agree(self):
        original = fixture()
        for old, new in (('0x1021', '0x1020'), ('+0x21', '+0x20'), ('<mix+', '<other+')):
            args = list(original)
            args[0] = [line.replace(old, new) for line in args[0]]
            with self.subTest(old=old), self.assertRaises(ValueError):
                mix.observe(*args)
        args = list(original)
        raw, image = bytearray(args[1]), bytearray(args[-1])
        raw[4] ^= 1
        image[0x204] ^= 1
        args[1], args[-1] = bytes(raw), bytes(image)
        with self.assertRaisesRegex(ValueError, 'branch destination'):
            mix.observe(*args)

    def test_constant_changes_affect_policy_not_just_instruction_hash(self):
        args = fixture()
        before, _ = mix.observe(*args)
        for pos in (0x100, 0x10f, 0x110, 0x113, 0x120, 0x12f):
            image = bytearray(args[-1])
            image[pos] ^= 1
            after, _ = mix.observe(*args[:-1], bytes(image))
            self.assertEqual(before['encoding_sha256'], after['encoding_sha256'])
            self.assertNotEqual(before['text_sha256'], after['text_sha256'])

    def test_unreviewed_configuration_and_altered_operands_fail(self):
        args = fixture()
        actual, _ = mix.observe(*args)
        with self.assertRaisesRegex(ValueError, 'unreviewed compiler'):
            mix.check(*args, 'unknown')
        with patch.object(mix, 'POLICY', {'test': actual}):
            for replacement in ('testl %eax, %eax', 'callq *%rax', 'shlb %cl, %al', 'movb (%rdi,%rax), %al'):
                changed = [replacement, *args[0][1:]]
                reason = 'unsupported call' if replacement.startswith('call') else 'reviewed mix changed'
                with self.assertRaisesRegex(ValueError, reason):
                    mix.check(changed, *args[1:], 'test')


if __name__ == '__main__':
    unittest.main()
