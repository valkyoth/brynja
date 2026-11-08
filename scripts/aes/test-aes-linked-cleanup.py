#!/usr/bin/env python3
"""Cleanup symbol, callback admission, PLT binding and mutation regressions."""
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


cleanup = module('cleanup', 'aes_linked_cleanup.py')
elf = module('cleanup_elf', 'test-aes-linked-mix.py')


def table(current=False):
    names = []
    for role in cleanup.WIDTHS:
        name = ('14cleanup_' if role.startswith('key') else '17cleanup_') + role
        names.append(f'_RNvCsABC_9lifecycle{name}' if current else
                     f'_ZN9lifecycle{name}17h0000000000000000E')
    return '\n'.join(f'{0x1000 + i * 256:016x} 0000000000000010 t {n}' for i, n in enumerate(names))


def fixture(panic='abort', slot=0):
    """Synthetic non-AES caller: never accepted by the production policy."""
    rows = [('55', 'pushq %rbp'),
            ('4c890424' if slot == 0 else '4c89442408', f'movq %r8, {"" if slot == 0 else "8"}(%rsp)'),
            ('ff1424' if slot == 0 else 'ff542408', f'callq *{"" if slot == 0 else "8"}(%rsp)'),
            ('4885ff', 'testq %rdi, %rdi'), ('branch', 'je')]
    for _ in range(4 if panic == 'unwind' else 2):
        rows.extend([('488b742410', 'movq 16(%rsp), %rsi'), ('call', 'zeroize')])
    rows.extend([('48c7042410000000', 'movq $16, (%rsp)'), ('5d', 'popq %rbp'), ('c3', 'retq')])
    sizes = [2 if code == 'branch' else 5 if code == 'call' else len(bytes.fromhex(code)) for code, _ in rows]
    raw, lines = bytearray(), []
    for (code, text), size in zip(rows, sizes):
        if code == 'call':
            code = (b'\xe8' + struct.pack('<i', 0x1100 - 0x1000 - len(raw) - size)).hex()
            text = 'callq 0x1100 <zeroize>'
        elif code == 'branch':
            dest = sum(sizes) - 1
            code = bytes((0x74, dest - len(raw) - size)).hex()
            text = f'je 0x{0x1000 + dest:x} <cleanup+0x{dest:x}>'
        raw.extend(bytes.fromhex(code))
        lines.append(text)
    image = bytearray(elf.fixture()[-1])
    struct.pack_into('<QQ', image, 152, 0x180, 0x180)
    image[0x200:0x200 + len(raw)] = raw
    targets = {'zeroize': ('zeroize', 0x1100, 1)}
    if panic == 'unwind':
        targets['resume'] = ('resume', 0x1110, 1)
    return [lines, bytes(raw), sizes, 'cleanup', 0x1000, bytes(image), targets]


def plt_fixture():
    image = bytearray(elf.fixture()[-1])
    struct.pack_into('<H', image, 56, 3)
    struct.pack_into('<QQ', image, 152, 0x140, 0x140)
    struct.pack_into('<IIQQQQQQ', image, 176, 1, 6, 0x380, 0x4000, 0, 16, 16, 8)
    image[0x310:0x320] = b'\xff\x25' + struct.pack('<i', 0x4000 - 0x1116) + b'\x68\x01\0\0\0\xe9' + struct.pack('<i', 0x1100 - 0x1120)
    plt = 'file format elf64-x86-64\nDisassembly of section .plt:\n0000000000001100 <.plt>:\n0000000000001110 <_Unwind_Resume@plt>:\n'
    relocations = '0000000000004008 R_X86_64_JUMP_SLOT __cxa_finalize\n0000000000004000 R_X86_64_JUMP_SLOT _Unwind_Resume\n'
    return plt, relocations, bytes(image)


class LinkedCleanupTests(unittest.TestCase):
    def test_cleanup_population_is_exact(self):
        for current in (False, True):
            value = table(current)
            self.assertEqual(set(cleanup.candidates(value)), set(cleanup.WIDTHS))
            rows = value.splitlines()
            for bad in ('\n'.join(rows[:-1]), value + '\n' + rows[0], value.replace(' t ', ' D '),
                        value.replace('0000000000000010', '0000000000000000'),
                        value.replace('0000000000001100', '0000000000001001'),
                        value.replace('14cleanup_key128', '14cleanup_key999'),
                        value.replace('9lifecycle14', '9lifecycleBAD14')):
                with self.assertRaises(ValueError):
                    cleanup.candidates(bad)

    def test_callback_is_explicit_opt_in_and_byte_bound(self):
        for slot, operand in ((0, 'callq *(%rsp)'), (8, 'callq *8(%rsp)')):
            args = fixture(slot=slot)
            with self.assertRaisesRegex(ValueError, 'unsupported call'):
                cleanup.image_review.observe(*args)
            actual, _ = cleanup.image_review.observe(*args, indirect_callback=operand)
            self.assertEqual(actual['indirect_calls'], 1)
            with self.assertRaisesRegex(ValueError, 'unsupported callback'):
                cleanup.image_review.observe(*args, indirect_callback='callq *%rax')
            lines = args[0].copy()
            lines[2] = 'nop'
            with self.assertRaisesRegex(ValueError, 'callback population'):
                cleanup.image_review.observe(lines, *args[1:], indirect_callback=operand)
            lines[2] = 'callq *8(%rsp)' if slot == 0 else 'callq *(%rsp)'
            with self.assertRaisesRegex(ValueError, 'callback encoding'):
                cleanup.image_review.observe(lines, *args[1:], indirect_callback=lines[2])
            with self.assertRaisesRegex(ValueError, 'callback population'):
                # Two genuine encoded callback instructions are still invalid.
                raw = args[1] + bytes.fromhex('ff1424' if slot == 0 else 'ff542408')
                sizes = args[2] + [3 if slot == 0 else 4]
                image = bytearray(args[5]); image[0x200:0x200 + len(raw)] = raw
                cleanup.image_review.observe(args[0] + [operand], raw, sizes, *args[3:5],
                                             bytes(image), args[6], indirect_callback=operand)

    def test_all_cleanup_negative_controls(self):
        self.assertEqual(set(cleanup.POLICY), {(c, p) for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for (compiler, panic), entries in cleanup.POLICY.items():
            self.assertEqual(set(entries), set(cleanup.WIDTHS))
            operand = cleanup.callback(compiler, panic)
            args = fixture(panic, 8 if '8(' in operand else 0)
            with self.assertRaisesRegex(ValueError, 'reviewed cleanup changed'):
                cleanup.check(*args, 'key128', compiler, panic)
            actual, _ = cleanup.image_review.observe(*args, indirect_callback=operand)
            with patch.dict(cleanup.POLICY, {(compiler, panic): {'key128': actual}}):
                self.assertEqual(cleanup.mutations(*args, 'key128', compiler, panic), 12 if panic == 'unwind' else 10)
                with self.assertRaisesRegex(ValueError, 'target population'):
                    cleanup.check(*args[:-1], {}, 'key128', compiler, panic)

    def test_resume_is_bound_to_plt_encoding_and_relocation(self):
        plt, relocations, image = plt_fixture()
        self.assertEqual(cleanup.resume_target(plt, relocations, image), ('_Unwind_Resume@plt', 0x1110, 16))
        for bad in (plt.replace('x86-64', 'aarch64'), plt.replace('_Unwind_Resume@plt', 'wrong@plt'),
                    plt + '0000000000001110 <_Unwind_Resume@plt>:\n'):
            with self.assertRaises(ValueError):
                cleanup.resume_target(bad, relocations, image)
        for bad in (relocations.replace('_Unwind_Resume', 'wrong'), relocations + relocations,
                    relocations.replace('0000000000004000', '0000000000004010'),
                    '\n'.join(reversed(relocations.splitlines())), relocations + 'R_X86_64_JUMP_SLOT malformed'):
            with self.assertRaises(ValueError):
                cleanup.resume_target(plt, bad, image)
        for offset in (0x310, 0x312, 0x316, 0x317, 0x31b, 0x31c):
            changed = bytearray(image); changed[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'PLT encoding'):
                cleanup.resume_target(plt, relocations, bytes(changed))
        changed = bytearray(image); struct.pack_into('<I', changed, 180, 5)
        with self.assertRaisesRegex(ValueError, 'mapping'):
            cleanup.resume_target(plt, relocations, bytes(changed))


if __name__ == '__main__':
    unittest.main()
