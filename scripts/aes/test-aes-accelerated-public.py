#!/usr/bin/env python3
"""Byte-backed caller admission, publication, cleanup and call-binding controls."""
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


public = module('accelerated_public_tests', 'aes_accelerated_linked_public.py')
kernel_tests = module('accelerated_public_kernel_fixture', 'test-aes-accelerated-linked.py')
runner = kernel_tests.runner

# Independent fixture transcription of the inspected 1.99.1 body. Relocations
# are synthesized; no compiler, target directory or generated policy is needed.
BODY = '''488b0f|movq (%rdi), %rcx
0fb64108|movzbl 8(%rcx), %eax
85c0|testl %eax, %eax
746b|je @+76
83f801|cmpl $1, %eax
7569|jne @+79
4c8b4708|movq 8(%rdi), %r8
b004|movb $4, %al
4c3b01|cmpq (%rcx), %r8
756e|jne @+89
0fb64109|movzbl 9(%rcx), %eax
2c01|subb $1, %al
7366|jae @+89
488b4710|movq 16(%rdi), %rax
4885c0|testq %rax, %rax
7450|je @+7c
48817f18{encoded}|cmpq ${extent}, 24(%rdi)
7546|jne @+7c
4156|pushq %r14
53|pushq %rbx
4883ec18|subq $24, %rsp
0f1006|movups (%rsi), %xmm0
0f290424|movaps %xmm0, (%rsp)
4889e3|movq %rsp, %rbx
4889df|movq %rbx, %rdi
4889c6|movq %rax, %rsi
4989d6|movq %rdx, %r14
31d2|xorl %edx, %edx
call|kernel
0f280424|movaps (%rsp), %xmm0
410f1106|movups %xmm0, (%r14)
be10000000|movl $16, %esi
4889df|movq %rbx, %rdi
call|zeroize
b0fe|movb $-2, %al
4883c418|addq $24, %rsp
5b|popq %rbx
415e|popq %r14
c3|retq
b002|movb $2, %al
c3|retq
b003|movb $3, %al
c3|retq
c6410802|movb $2, 8(%rcx)
48c70103000000|movq $3, (%rcx)
b0ff|movb $-1, %al
c3|retq'''
CLEAR = ('4885f6 7463 4889f1 4889f8 4883e107 741a 4889f8 6666662e0f1f840000000000 '
         'c60000 48ffc0 48ffc9 75f5 4883fe08 7237 4801f7 6666662e0f1f840000000000 '
         'c60000 c6400100 c6400200 c6400300 c6400400 c6400500 c6400600 c6400700 '
         '4883c008 4839f8 75d8 c3').split()


def fixture(wrong_width=False):
    table, assembly, image, bodies = kernel_tests.fixture(public.TARGET)
    image = bytearray(image)
    kernels = dict(zip((128, 192, 256), (b[3] for b in bodies)))
    zeroize = ('_ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h0000000000000000E', 0x1900, 105)
    rows = [(zeroize, list(zip(CLEAR, public.helpers.expected('zeroize', '1.99.1'))), {})]
    for bits in (128, 192, 256):
        extent = {128: 176, 192: 208, 256: 240}[bits]
        row = (f'_ZN13brynja_crypto3aes9execution17Aes{bits}ExpandedKey20encrypt_block_public17h0000000000000000E',
               {128: 0x1500, 192: 0x1600, 256: 0x1700}[bits], 138)
        instructions = [s.split('|') for s in BODY.format(extent=extent, encoded=extent.to_bytes(4, 'little').hex()).splitlines()]
        rows.append((row, instructions, {'zeroize': zeroize, 'kernel': kernels[192 if wrong_width and bits == 128 else bits]}))
    for (symbol, start, size), instructions, targets in rows:
        table += f'\n{start:016x} {size:016x} t {symbol}'
        assembly += f'{start:016x} <{symbol}>:\n'
        raw = bytearray()
        for encoded, text in instructions:
            if encoded == 'call':
                name, address, _ = targets[text]
                encoded = (b'\xe8' + (address - start - len(raw) - 5).to_bytes(4, 'little', signed=True)).hex()
                text = f'callq 0x{address:x} <{name}>'
            text = re.sub(r'@\+([0-9a-f]+)', lambda m: f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', text)
            data = bytes.fromhex(encoded)
            assembly += f' {start + len(raw):x}: {data.hex(" ")} \t{text}\n'
            raw.extend(data)
        assert len(raw) == size
        image[start - 0x1000:start - 0x1000 + size] = raw
        assembly += '\n'
    return table, assembly, bytes(image)


class AcceleratedPublicTests(unittest.TestCase):
    def test_complete_real_current_wrappers_and_mutation_populations(self):
        for panic in ('abort', 'unwind'):
            result = public.inspect(*fixture(), '1.99.1', panic)
            self.assertEqual([r['bits'] for r in result['wrappers']], [128, 192, 256])
            self.assertEqual(result['rejected_wrapper_mutations'], 555)
            self.assertEqual(result['rejected_zeroize_mutations'], 3)

    def test_symbols_require_exact_owners_and_full_population(self):
        table, _, _ = fixture()
        rows = table.splitlines()
        for changed in ('\n'.join(rows[:-1]), table + '\n' + rows[-1], table.replace(' t ', ' D '),
                        table.replace('Aes128ExpandedKey', 'Aes999ExpandedKey'),
                        table.replace('000000000000008a', '0000000000000000'),
                        table.replace('0000000000001600', '0000000000001501')):
            with self.assertRaises(ValueError):
                public.candidates(changed)

    def test_valid_but_wrong_width_kernel_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'call destination mismatch'):
            public.inspect(*fixture(wrong_width=True), '1.99.1', 'abort')

    def test_admission_publication_and_clearing_changes_fail(self):
        table, assembly, image = fixture()
        for old, new in (('cmpq $176', 'cmpq $160'), ('xorl %edx, %edx', 'movl $1, %edx'),
                         ('movups %xmm0, (%r14)', 'movups %xmm0, (%rsi)'),
                         ('movl $16, %esi', 'movl $0, %esi'),
                         ('movq $3, (%rcx)', 'movq $2, (%rcx)'),
                         ('cmpq (%rcx), %r8', 'cmpq %r8, %r8')):
            with self.subTest(old=old), self.assertRaisesRegex(ValueError, 'stream changed'):
                public.inspect(table, assembly.replace(old, new), image, '1.99.1', 'abort')

    def test_helper_bytes_and_compiler_profiles_are_bound(self):
        table, assembly, image = fixture()
        changed = bytearray(image)
        changed[0x900] ^= 1
        with self.assertRaisesRegex(ValueError, 'zeroize decoded bytes'):
            public.inspect(table, assembly, bytes(changed), '1.99.1', 'abort')
        for compiler, panic in (('stable', 'abort'), ('1.99.1', 'other'), ('1.90.0', 'abort'), ('1.90.0', 'unwind')):
            with self.assertRaises(ValueError):
                public.inspect(table, assembly, image, compiler, panic)

    def test_public_review_rejects_emulation_and_capture_before_packaging(self):
        for mode, admission, capture in (('arm-qemu', 'static', False), ('arm-qemu', 'hosted', False),
                                         ('native', 'static', True)):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', mode, admission, capture, review_cached_public=True)
            package.assert_not_called()

    def test_registry_pins_public_review_and_transitive_helpers(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c.get('category') == 'aes-linked-public'}
        self.assertEqual(set(checks), {'accelerated-public-linked-msrv', 'accelerated-public-linked-current'})
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            check = checks['accelerated-public-linked-' + endpoint]
            self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                '--toolchain', tc, '--mode', 'native', '--admission', 'static', '--review-cached-public'])
            self.assertIn('aes-accelerated-public', check['inputs'])
            self.assertIn('aes-accelerated-linked', check['inputs'])
            self.assertEqual(check['success']['unique_lines'], [f'AES_ACCELERATED_PUBLIC_LINKED_PASS: {tc}; four consumers; x86 cached public wrappers, kernels and volatile clear'])
        paths = registry['groups']['aes-accelerated-public']['paths']
        for file in ('aes_linked_mix.py', 'aes_linked_cleanup.py', 'aes_linked_helpers.py', 'aes_accelerated_linked_public.py'):
            self.assertIn('scripts/aes/' + file, paths)


if __name__ == '__main__':
    unittest.main()
