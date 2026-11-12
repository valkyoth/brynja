#!/usr/bin/env python3
"""Independent byte-backed secret-output caller and cleanup controls."""
import importlib.util
from pathlib import Path
import re
import tomllib
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


secret = module('accelerated_secret_review', 'aes_accelerated_linked_secret.py')
public_tests = module('accelerated_secret_fixture', 'test-aes-accelerated-public.py')
runner = public_tests.runner

# Transcribed inspected 1.99.1 stream. Only relocations and public schedule
# bounds are synthesized. Does not read target artifacts or regenerate policy.
BODY = '''55|pushq %rbp
4157|pushq %r15
4156|pushq %r14
4154|pushq %r12
53|pushq %rbx
4883ec10|subq $16, %rsp
4489c5|movl %r8d, %ebp
4889cb|movq %rcx, %rbx
4989d7|movq %rdx, %r15
4989f4|movq %rsi, %r12
4989fe|movq %rdi, %r14
be10000000|movl $16, %esi
4889cf|movq %rcx, %rdi
call|zeroize
498b0424|movq (%r12), %rax
0fb64808|movzbl 8(%rax), %ecx
85c9|testl %ecx, %ecx
0f8488000000|je @+c0
83f901|cmpl $1, %ecx
0f8583000000|jne @+c4
498b542408|movq 8(%r12), %rdx
b104|movb $4, %cl
483b10|cmpq (%rax), %rdx
7579|jne @+c6
0fb64809|movzbl 9(%rax), %ecx
80e901|subb $1, %cl
7370|jae @+c6
498b742410|movq 16(%r12), %rsi
4885f6|testq %rsi, %rsi
0f8483000000|je @+e7
49817c2418{encoded}|cmpq ${extent}, 24(%r12)
7578|jne @+e7
410f1007|movups (%r15), %xmm0
0f290424|movaps %xmm0, (%rsp)
400fb6d5|movzbl %bpl, %edx
4989e7|movq %rsp, %r15
4c89ff|movq %r15, %rdi
call|kernel
ba10000000|movl $16, %edx
4889df|movq %rbx, %rdi
4c89fe|movq %r15, %rsi
call|copy
be10000000|movl $16, %esi
4c89ff|movq %r15, %rdi
call|zeroize
49895e08|movq %rbx, 8(%r14)
49c7461010000000|movq $16, 16(%r14)
41c60600|movb $0, (%r14)
4883c410|addq $16, %rsp
5b|popq %rbx
415c|popq %r12
415e|popq %r14
415f|popq %r15
5d|popq %rbp
c3|retq
b102|movb $2, %cl
eb02|jmp @+c6
b103|movb $3, %cl
41884e01|movb %cl, 1(%r14)
41c60601|movb $1, (%r14)
be10000000|movl $16, %esi
4889df|movq %rbx, %rdi
4883c410|addq $16, %rsp
5b|popq %rbx
415c|popq %r12
415e|popq %r14
415f|popq %r15
5d|popq %rbp
tail|zeroize
6641c70601ff|movw $65281, (%r14) # imm = 0xFF01
c6400802|movb $2, 8(%rax)
48c70003000000|movq $3, (%rax)
ebd4|jmp @+ce'''
COPY = '''4989d0|movq %rdx, %r8
31c9|xorl %ecx, %ecx
4c89c2|movq %r8, %rdx
4883fa08|cmpq $8, %rdx
7216|jb @+24
488b040e|movq (%rsi,%rcx), %rax
4889040f|movq %rax, (%rdi,%rcx)
4883c108|addq $8, %rcx
4883ea08|subq $8, %rdx
4883fa08|cmpq $8, %rdx
73ea|jae @+e
4885d2|testq %rdx, %rdx
740f|je @+38
0fb6040e|movzbl (%rsi,%rcx), %eax
88040f|movb %al, (%rdi,%rcx)
48ffc1|incq %rcx
48ffca|decq %rdx
75f1|jne @+29
31c0|xorl %eax, %eax
31c9|xorl %ecx, %ecx
31d2|xorl %edx, %edx
c3|retq'''


def fixture(wrong_width=False, tail_role='zeroize'):
    table, assembly, image = public_tests.fixture()
    image = bytearray(image)
    kernels = dict(zip((128, 192, 256), secret.kernels.select(table, secret.TARGET)))
    zeroize = secret.public.candidates(table)['zeroize']
    copy = ('_ZN11brynja_core22secret_memory_transfer10copy_bytes17h0000000000000000E', 0x1d00, 63)
    rows = [(copy, [s.split('|') for s in COPY.splitlines()], {})]
    for bits, start in ((128, 0x1a00), (192, 0x1b00), (256, 0x1c00)):
        extent = {128: 176, 192: 208, 256: 240}[bits]
        row = (f'_ZN13brynja_crypto3aes9execution17Aes{bits}ExpandedKey6secret17h0000000000000000E', start, 250)
        instructions = [s.split('|') for s in BODY.format(extent=extent, encoded=extent.to_bytes(4, 'little').hex()).splitlines()]
        rows.append((row, instructions, {'zeroize': zeroize, 'copy': copy,
                    'kernel': kernels[192 if wrong_width and bits == 128 else bits]}))
    for (symbol, start, size), instructions, targets in rows:
        table += f'\n{start:016x} {size:016x} t {symbol}'
        assembly += f'{start:016x} <{symbol}>:\n'
        raw = bytearray()
        for encoded, text in instructions:
            if encoded in ('call', 'tail'):
                tail = encoded == 'tail'
                name, address, _ = targets[tail_role if tail else text]
                encoded = (bytes([0xe9 if tail else 0xe8]) + (address - start - len(raw) - 5).to_bytes(4, 'little', signed=True)).hex()
                text = ('jmp' if tail else 'callq') + f' 0x{address:x} <{name}>'
            text = re.sub(r'@\+([0-9a-f]+)', lambda m: f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', text)
            data = bytes.fromhex(encoded)
            assembly += f' {start + len(raw):x}: {data.hex(" ")} \t{text}\n'
            raw.extend(data)
        assert len(raw) == size
        image[start - 0x1000:start - 0x1000 + size] = raw
        assembly += '\n'
    return table, assembly, bytes(image)


class AcceleratedSecretTests(unittest.TestCase):
    def test_complete_wrappers_copy_clear_and_mutations(self):
        for panic in ('abort', 'unwind'):
            result = secret.inspect(*fixture(), '1.99.1', panic)
            self.assertEqual([r['bits'] for r in result['wrappers']], [128, 192, 256])
            self.assertEqual([r['tail_calls'] for r in result['wrappers']], [1, 1, 1])
            self.assertEqual(result['rejected_wrapper_mutations'], 969)
            self.assertEqual(result['rejected_copy_mutations'], 8)
            self.assertEqual(result['rejected_zeroize_mutations'], 3)

    def test_wrong_width_and_redirected_tail_are_rejected(self):
        for options in ({'wrong_width': True}, {'tail_role': 'copy'}, {'tail_role': 'kernel'}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, 'call destination mismatch'):
                secret.inspect(*fixture(**options), '1.99.1', 'abort')

    def test_admission_direction_result_owner_and_clearing_are_bound(self):
        table, assembly, image = fixture()
        for old, new in (('cmpq $176, 24(%r12)', 'cmpq $160, 24(%r12)'),
                         ('cmpq (%rax), %rdx', 'cmpq %rdx, %rdx'),
                         ('movzbl %bpl, %edx', 'xorl %edx, %edx'),
                         ('movl $16, %edx', 'movl $0, %edx'),
                         ('movq %r15, %rsi', 'movq %rbx, %rsi'),
                         ('movl $16, %esi', 'movl $0, %esi'),
                         ('movq %rbx, 8(%r14)', 'movq %r15, 8(%r14)'),
                         ('movq $16, 16(%r14)', 'movq $32, 16(%r14)'),
                         ('movb $0, (%r14)', 'movb $1, (%r14)'),
                         ('movq $3, (%rax)', 'movq $2, (%rax)')):
            with self.subTest(old=old), self.assertRaisesRegex(ValueError, 'stream changed'):
                secret.inspect(table, assembly.replace(old, new), image, '1.99.1', 'abort')

    def test_exact_symbol_population_and_extent(self):
        table, _, _ = fixture()
        for changed in ('\n'.join(table.splitlines()[:-1]), table + '\n' + table.splitlines()[-1],
                        table.replace('Aes128ExpandedKey6secret', 'Aes999ExpandedKey6secret'),
                        table.replace('00000000000000fa', '0000000000000000'),
                        table.replace('0000000000001b00', '0000000000001a01'), table.replace(' t ', ' D ')):
            with self.assertRaises(ValueError):
                secret.candidates(changed)

    def test_helpers_and_profiles_are_bound(self):
        table, assembly, image = fixture()
        for offset, reason in ((0x900, 'zeroize decoded bytes'), (0xd00, 'decoded bytes differ')):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaisesRegex(ValueError, reason):
                secret.inspect(table, assembly, bytes(changed), '1.99.1', 'abort')
        for tc, panic in (('stable', 'abort'), ('1.99.1', 'other'), ('1.90.0', 'abort'), ('1.90.0', 'unwind')):
            with self.assertRaises(ValueError):
                secret.inspect(table, assembly, image, tc, panic)

    def test_secret_review_rejects_other_modes_before_packaging(self):
        for mode, admission, capture, public in (('arm-qemu', 'static', False, False),
                ('arm-qemu', 'hosted', False, False), ('native', 'static', True, False),
                ('native', 'static', False, True)):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', mode, admission, capture, public, review_cached_secret=True)
            package.assert_not_called()

    def test_registry_pins_secret_review_and_helpers(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-secret'}
        self.assertEqual(set(checks), {'accelerated-secret-linked-msrv', 'accelerated-secret-linked-current'})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = checks['accelerated-secret-linked-' + endpoint]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                '--toolchain', tc, '--mode', 'native', '--admission', 'static', '--review-cached-secret'])
            self.assertIn('aes-accelerated-secret', check['inputs'])
            self.assertIn('aes-accelerated-linked', check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_SECRET_LINKED_PASS: {tc}; four consumers; x86 cached secret wrappers, kernels, copy and volatile clear'])
        paths = registry['groups']['aes-accelerated-secret']['paths']
        for file in ('aes_linked_mix.py', 'aes_linked_cleanup.py', 'aes_linked_helpers.py',
                     'aes_linked_wrappers.py', 'aes_accelerated_linked_public.py', 'aes_accelerated_linked_secret.py'):
            self.assertIn('scripts/aes/' + file, paths)


if __name__ == '__main__':
    unittest.main()
