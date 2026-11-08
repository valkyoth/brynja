#!/usr/bin/env python3
"""Negative controls for exact final-linked round-key and zeroizer templates."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('linked_helpers_tested', Path(__file__).with_name('aes_linked_helpers.py'))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def fixture(role, compiler):
    size, _ = helpers.ENCODINGS['wide_add_key_' + compiler if role == 'wide_add_key' else role]
    lines = []
    for line in helpers.expected(role, compiler):
        if ' @+' in line:
            opcode, offset = line.split(' @+')
            line = f'{opcode} 0x{0x1000 + int(offset, 16):x} <helper+0x{offset}>'
        lines.append(line)
    return lines, b'\x90' * size


class LinkedHelperTests(unittest.TestCase):
    def test_exact_templates_and_instruction_populations(self):
        for compiler in helpers.COMPILERS:
            for role, count in (('add_key', 10), ('wide_add_key', 97 if compiler == '1.90.0' else 83), ('zeroize', 28)):
                lines, raw = fixture(role, compiler)
                self.assertEqual(len(lines), count)
                self.assertEqual(helpers.normalize(lines, 'helper', 0x1000, len(raw)), helpers.expected(role, compiler))

    def test_synthetic_bytes_only_accepted_with_explicit_test_policy(self):
        for compiler in helpers.COMPILERS:
            for role in helpers.ROLES:
                lines, raw = fixture(role, compiler)
                with self.assertRaisesRegex(ValueError, 'instruction encoding changed'):
                    helpers.check(lines, raw, 'helper', 0x1000, role, compiler)
                key = 'wide_add_key_' + compiler if role == 'wide_add_key' else role
                with patch.dict(helpers.ENCODINGS, {key: (len(raw), hashlib.sha256(raw).hexdigest())}):
                    self.assertEqual(helpers.check(lines, raw, 'helper', 0x1000, role, compiler)['role'], role)
                    self.assertEqual(helpers.mutations(lines, raw, 'helper', 0x1000, role, compiler), 3)

    def test_secret_index_and_secret_branch_substitution_rejected(self):
        lines, raw = fixture('wide_add_key', '1.99.1')
        for before, after in (('leaq 1(%rcx), %r8', 'leaq 1(%r8), %r8'),
                              ('cmpq %rdx, %rcx', 'cmpq %r8, %rcx'),
                              ('xorl %eax, %eax', 'movl %r8d, %eax'),
                              ('movzbl (%rsi,%r8), %r8d', 'movzbl (%rsi,%rax), %r8d')):
            changed = [after if line == before else line for line in lines]
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, 'instruction template changed'):
                helpers.check(changed, raw, 'helper', 0x1000, 'wide_add_key', '1.99.1')

    def test_changed_clear_value_stride_or_branch_is_rejected(self):
        lines, raw = fixture('zeroize', '1.90.0')
        for before, after in (('movb $0, (%rax)', 'movb $1, (%rax)'),
                              ('addq $8, %rax', 'addq $16, %rax'),
                              ('testq %rsi, %rsi', 'testq %rax, %rax'),
                              ('movb $0, 7(%rax)', 'nop')):
            changed = [after if line == before else line for line in lines]
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, 'instruction template changed'):
                helpers.check(changed, raw, 'helper', 0x1000, 'zeroize', '1.90.0')

    def test_narrow_bounds_and_vector_destinations_are_pinned(self):
        lines, raw = fixture('add_key', '1.90.0')
        for before, after in (('cmpq $176, %rdx', 'cmpq $240, %rdx'),
                              ('movups %xmm1, (%rdi)', 'movups %xmm0, (%rsi)'),
                              ('setae %al', 'setb %al')):
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, 'instruction template changed'):
                helpers.check([after if l == before else l for l in lines], raw, 'helper', 0x1000, 'add_key', '1.90.0')

    def test_branch_number_annotation_and_extent_must_agree(self):
        for line in ('jae 0x0 <helper+0x1a>', 'jae 0x101a <other+0x1a>',
                     'jae 0x2000 <helper+0x1000>', 'jae 0x101a <helper>', 'jae *%rax'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                helpers.normalize([line], 'helper', 0x1000, 37)
        self.assertEqual(helpers.normalize(['jae 0x101a <helper+0x1a>'], 'helper', 0x1000, 37), ['jae @+1a'])

    def test_unsupported_scope_or_extra_operations_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
            helpers.expected('add_key', 'stable')
        with self.assertRaisesRegex(ValueError, 'unreviewed configuration'):
            helpers.expected('transform', '1.90.0')
        lines, raw = fixture('zeroize', '1.90.0')
        for changed in (lines[:-1], lines + ['retq'], ['callq attacker'] + lines, lines + ['.byte 0']):
            with self.assertRaisesRegex(ValueError, 'instruction template changed'):
                helpers.check(changed, raw, 'helper', 0x1000, 'zeroize', '1.90.0')


if __name__ == '__main__':
    unittest.main()
