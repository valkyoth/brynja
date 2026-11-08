#!/usr/bin/env python3
"""Fail-closed symbol selection, call graph and cleanup review regressions."""
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


wrappers = module('wrappers', 'aes_linked_wrappers.py')
elf = module('wrapper_elf', 'test-aes-linked-mix.py')


def table(current=False):
    if current:
        names = ['_RNvMs2_NtCsABC_13brynja_crypto3aesNtB5_9Aes128Key9transform',
                 '_RNvMs3_NtCsABC_13brynja_crypto3aesNtB5_17Aes128ExpandedKey9transform',
                 '_RNvMNtNtCsABC_13brynja_crypto3aes4wideNtB2_9Aes192Key9transform',
                 '_RNvMs0_NtNtCsABC_13brynja_crypto3aes4wideNtB5_9Aes256Key9transform',
                 '_RINvNtNtCsABC_13brynja_crypto3aes4wide6secretKj18_Kjd0_Kjc_EB6_',
                 '_RINvNtNtCsABC_13brynja_crypto3aes4wide6secretKj20_Kjf0_Kje_EB6_',
                 '_RNvNtCsABC_11brynja_core22secret_memory_transfer10copy_bytes']
    else:
        names = [f'_ZN13brynja_crypto3aes{role}17h{i:016x}E' for i, role in enumerate(
            ('9Aes128Key9transform', '17Aes128ExpandedKey9transform', '4wide9Aes192Key9transform',
             '4wide9Aes256Key9transform', '4wide6secret', '4wide6secret'))]
        names.append('_ZN11brynja_core22secret_memory_transfer10copy_bytes17h0000000000000000E')
    return '\n'.join(f'{0x1000 + i * 256:016x} 0000000000000010 t {name}' for i, name in enumerate(names))


def fixture():
    raw = bytes.fromhex('55be10000000e82d00000084c0741149c70601000000ba10000000e8100000005dc3')
    image = bytearray(elf.fixture()[-1])
    image[0x200:0x200 + len(raw)] = raw
    lines = ['pushq %rbp', 'movl $16, %esi', 'callq 0x1038 <zeroize>', 'testb %al, %al',
             'je 0x1020 <wrapper+0x20>', 'movq $1, (%r14)', 'movl $16, %edx',
             'callq 0x1030 <copy>', 'popq %rbp', 'retq']
    targets = {'zeroize': ('zeroize', 0x1038, 1), 'copy': ('copy', 0x1030, 1),
               'expand128': ('expand', 0x1039, 1), 'transform128': ('transform', 0x103a, 1)}
    return [lines, raw, [1, 5, 5, 2, 2, 7, 5, 5, 1, 1], 'wrapper', 0x1000, bytes(image), targets]


class LinkedWrapperTests(unittest.TestCase):
    def test_exact_population_under_both_manglings(self):
        for current in (False, True):
            selected, secrets = wrappers.candidates(table(current))
            self.assertEqual(set(selected), {'key128', 'cached128', 'key192', 'key256', 'copy'})
            self.assertEqual(len(secrets), 2)
            rows = table(current).splitlines()
            for changed in ('\n'.join(rows[:-1]), '\n'.join(rows + [rows[0]]),
                            '\n'.join(rows[:-3] + rows[-2:]), table(current).replace(' t ', ' D '),
                            table(current).replace('0000000000000010', '0000000000000000'),
                            table(current).replace('0000000000001100', '0000000000001001'),
                            table(current).replace('9Aes128Key', '9Aes999Key'),
                            table(current).replace('4wide9Aes192Key', '9Aes192Key').replace('4wideNtB2_', 'NtB2_'),
                            table(current) + '\n' + rows[-2].replace('0000000000001500', '0000000000001800')):
                with self.subTest(current=current, changed=changed[-100:]), self.assertRaises(ValueError):
                    wrappers.candidates(changed)

    def test_wide_width_requires_exact_transform_call(self):
        targets = {'transform192': ('round192', 0x2000, 20), 'transform256': ('round256', 0x3000, 20)}
        for bits in (192, 256):
            line = f'callq 0x{targets[f"transform{bits}"][1]:x} <round{bits}>'
            self.assertEqual(wrappers.secret_role([line], 'legacy', targets), f'secret{bits}')
        for lines in ([], ['callq 0x2001 <round192>'], ['callq 0x2000 <other>'],
                      ['callq 0x2000 <round192>'] * 2,
                      ['callq 0x2000 <round192>', 'callq 0x3000 <round256>']):
            with self.assertRaisesRegex(ValueError, 'binding'):
                wrappers.secret_role(lines, 'legacy', targets)
        with self.assertRaisesRegex(ValueError, 'generic width'):
            wrappers.secret_role(['callq 0x2000 <round192>'], '_RIwrongKj20_Kjf0_Kje_', targets)

    def test_pinned_profile_population_and_width_specific_call_identity(self):
        self.assertEqual(set(wrappers.POLICY), {(c, p) for c in ('1.90.0', '1.99.1') for p in ('abort', 'unwind')})
        for entries in wrappers.POLICY.values():
            self.assertEqual(set(entries), set(wrappers.EDGES))
            self.assertNotEqual(entries['secret192']['text_sha256'], entries['secret256']['text_sha256'])
            self.assertEqual(entries['secret192']['encoding_sha256'], entries['secret256']['encoding_sha256'])

    def test_synthetic_wrapper_policy_and_all_negative_controls(self):
        args = fixture()
        actual, _ = wrappers.image_review.observe(*args)
        for compiler, panic in wrappers.POLICY:
            with self.assertRaisesRegex(ValueError, 'reviewed wrapper changed'):
                wrappers.check(*args, 'key128', compiler, panic)
        with patch.object(wrappers, 'POLICY', {('test', 'unwind'): {'key128': actual}}):
            self.assertEqual(wrappers.mutations(*args, 'key128', 'test', 'unwind'), 8)
            with self.assertRaisesRegex(ValueError, 'target population'):
                wrappers.check(*args[:-1], {}, 'key128', 'test', 'unwind')
        with self.assertRaisesRegex(ValueError, 'configuration'):
            wrappers.check(*args, 'key128', 'unknown', 'unwind')

    def test_reviewed_copy_stream_and_all_negative_controls(self):
        raw = bytes.fromhex('4989d031c94c89c24883fa087216488b040e4889040f4883c1084883ea084883fa0873ea4885d2740f0fb6040e88040f48ffc148ffca75f131c031c931d2c3')
        lines = ['movq %rdx, %r8', 'xorl %ecx, %ecx', 'movq %r8, %rdx', 'cmpq $8, %rdx',
                 'jb 0x1024 <copy+0x24>', 'movq (%rsi,%rcx), %rax', 'movq %rax, (%rdi,%rcx)',
                 'addq $8, %rcx', 'subq $8, %rdx', 'cmpq $8, %rdx', 'jae 0x100e <copy+0xe>',
                 'testq %rdx, %rdx', 'je 0x1038 <copy+0x38>', 'movzbl (%rsi,%rcx), %eax',
                 'movb %al, (%rdi,%rcx)', 'incq %rcx', 'decq %rdx', 'jne 0x1029 <copy+0x29>',
                 'xorl %eax, %eax', 'xorl %ecx, %ecx', 'xorl %edx, %edx', 'retq']
        image = bytearray(elf.fixture()[-1])
        image[0x200:0x200 + len(raw)] = raw
        sizes = [3, 2, 3, 4, 2, 4, 4, 4, 4, 4, 2, 3, 2, 4, 3, 3, 3, 2, 2, 2, 2, 1]
        for compiler, panic in wrappers.POLICY:
            self.assertEqual(wrappers.mutations(lines, raw, sizes, 'copy', 0x1000,
                                               bytes(image), {}, 'copy', compiler, panic), 8)


if __name__ == '__main__':
    unittest.main()
