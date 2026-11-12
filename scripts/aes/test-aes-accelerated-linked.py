#!/usr/bin/env python3
"""Negative controls for actual-byte final-linked AES kernel review."""
import importlib.util
from pathlib import Path
import re
import struct
import tomllib
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('accelerated_linked', HERE / 'check-aes-accelerated-linked.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
review = runner.packaged.module('accelerated_review_test', HERE / 'aes_accelerated_linked_kernels.py')


def fixture(target, widths=(128, 192, 256)):
    arm = target.startswith('aarch64')
    image = bytearray(0x1000)
    image[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', image, 16, 2, 183 if arm else 62, 1)
    struct.pack_into('<Q', image, 32, 64)
    struct.pack_into('<HHH', image, 52, 64, 56, 1)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0, 0x1000, 0, len(image), len(image), 0x1000)
    assembly = 'fixture: file format ' + review.TARGETS[target][1] + '\n\n'
    nm, bodies = [], []
    for index, bits in enumerate(widths):
        start = 0x1100 + 0x100 * index
        symbol = f'_ZN17brynja_crypto_cpu3aes{review.TARGETS[target][2]}9transform17h{index:016x}E'
        normalized, raw, sizes = review.template(target, bits)
        lines = [re.sub(r'@\+([0-9a-f]+)', lambda m: f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', line)
                 for line in normalized]
        image[start - 0x1000:start - 0x1000 + len(raw)] = raw
        row = (symbol, start, len(raw))
        bodies.append((lines, raw, sizes, row))
        nm.append(f'{start:016x} {len(raw):016x} t {symbol}')
        assembly += f'{start:016x} <{symbol}>:\n'
        cursor = 0
        for line, size in zip(lines, sizes):
            data = raw[cursor:cursor + size]
            encoded = f'{int.from_bytes(data, "little"):08x}' if arm else data.hex(' ')
            assembly += f' {start + cursor:x}: {encoded} \t{line}\n'
            cursor += size
        assembly += '\n'
    return '\n'.join(nm), assembly, bytes(image), bodies


class AcceleratedLinkedTests(unittest.TestCase):
    def test_apple_capture_has_its_own_native_target_and_symbol_format(self):
        self.assertEqual(runner.execution_configuration('apple-native', 'Darwin', 'arm64'),
                         ('aarch64-apple-darwin', True, False))
        self.assertEqual(runner.inspection_configuration('aarch64-apple-darwin'),
                         ('.macho', ['--defined-only']))
        for target in ('aarch64-unknown-linux-musl', 'x86_64-unknown-linux-gnu'):
            self.assertEqual(runner.inspection_configuration(target),
                             ('.elf', ['--print-size', '--defined-only']))
        for system, machine in (('Linux', 'aarch64'), ('Darwin', 'x86_64'), ('Linux', 'arm64')):
            with self.assertRaises(ValueError):
                runner.execution_configuration('apple-native', system, machine)
        with self.assertRaises(ValueError):
            runner.inspection_configuration('unknown')

    def test_apple_cannot_claim_elf_review_or_mix_capture_with_review(self):
        flags = ('review_cached_public', 'review_cached_secret', 'review_ephemeral_secret',
                 'review_ephemeral_public', 'review_lifecycle', 'review_arm_cleanup',
                 'review_arm_constructors', 'review_arm_cached', 'review_arm_ephemeral')
        with patch.object(runner.platform, 'system', return_value='Darwin'), \
             patch.object(runner.platform, 'machine', return_value='arm64'):
            for admission in ('static', 'hosted'):
                for options in ({}, *({'capture_only': True, flag: True} for flag in flags)):
                    with self.subTest(admission=admission, options=options), \
                         patch.object(runner.packaged, 'package_sources') as package, \
                         self.assertRaises(ValueError):
                        runner.check('1.99.1', 'apple-native', admission, **options)
                    package.assert_not_called()

    def test_native_arm_is_explicit_and_never_an_emulated_or_other_target_claim(self):
        self.assertEqual(runner.execution_configuration('arm-native', 'Linux', 'aarch64'),
                         ('aarch64-unknown-linux-musl', True, False))
        self.assertEqual(runner.execution_configuration('arm-qemu', 'Linux', 'x86_64'),
                         ('aarch64-unknown-linux-musl', True, True))
        self.assertEqual(runner.execution_configuration('native', 'Linux', 'x86_64'),
                         ('x86_64-unknown-linux-gnu', False, False))
        for mode, system, machine in (
                ('arm-native', 'Linux', 'x86_64'), ('arm-native', 'Darwin', 'arm64'),
                ('arm-native', 'Linux', 'arm'), ('native', 'Linux', 'aarch64'),
                ('arm-qemu', 'Linux', 'aarch64'), ('native', 'Darwin', 'x86_64'),
                ('unknown', 'Linux', 'x86_64')):
            with self.assertRaises(ValueError):
                runner.execution_configuration(mode, system, machine)

    def test_native_arm_rejects_x86_review_and_capture_review_combinations(self):
        with patch.object(runner.platform, 'system', return_value='Linux'), \
             patch.object(runner.platform, 'machine', return_value='aarch64'):
            for flag in ('review_cached_public', 'review_cached_secret', 'review_ephemeral_secret',
                         'review_ephemeral_public', 'review_lifecycle'):
                with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                    runner.check('1.99.1', 'arm-native', 'static', **{flag: True})
                package.assert_not_called()
            for flag in ('review_arm_cleanup', 'review_arm_constructors', 'review_arm_cached', 'review_arm_ephemeral'):
                with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                    runner.check('1.99.1', 'arm-native', 'hosted', capture_only=True, **{flag: True})
                package.assert_not_called()

    def test_exact_instruction_encoding_width_and_mutation_populations(self):
        for target in review.TARGETS:
            nm, asm, image, _ = fixture(target)
            result = review.inspect(nm, asm, image, target)
            self.assertEqual([r['bits'] for r in result['kernels']], [128, 192, 256])
            self.assertEqual({r['instructions'] for r in result['kernels']}, {32 if target.startswith('x86') else 38})
            self.assertEqual(result['rejected_mutations'], 465 if target.startswith('x86') else 570)

    def test_branch_annotations_cannot_disagree_with_addresses_or_extent(self):
        for target in review.TARGETS:
            _, _, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            i = next(i for i, line in enumerate(lines) if '<' in line)
            for value in (re.sub(r'0x[0-9a-f]+ <', '0x0 <', lines[i]),
                          lines[i].replace(row[0], 'other'), 'jmp *%rax',
                          'b 0x2100 <' + row[0] + '+0x1000>'):
                changed = list(lines)
                changed[i] = value
                with self.assertRaises(ValueError):
                    review.check(changed, raw, sizes, row, image, target)

    def test_memory_round_bound_and_erasure_changes_fail(self):
        for target in review.TARGETS:
            _, _, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            for old, new in (('(%rdi)', '(%rsp)'), ('%xmm1, %xmm1', '%xmm0, %xmm1'),
                             ('$160', '$176'), ('[x0]', '[sp]'), ('#160', '#176'),
                             ('movi v0.16b, #0', 'movi v0.16b, #1'), ('msr NZCV, xzr', 'nop')):
                if not any(old in line for line in lines):
                    continue
                with self.assertRaisesRegex(ValueError, 'template changed'):
                    review.check([line.replace(old, new) for line in lines], raw, sizes, row, image, target)

    def test_disassembly_bytes_must_match_immutable_executable_mapping(self):
        for target in review.TARGETS:
            _, _, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            # ET_EXEC -> ET_DYN is valid, not a negative control.
            for offset in (0x100, 18, 32, 52, 54, 56, 68):
                changed = bytearray(image)
                changed[offset] ^= 1
                with self.subTest(target=target, offset=offset), self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, bytes(changed), target)
            for kind in (0, 1, 4):
                changed = bytearray(image)
                changed[16:18] = kind.to_bytes(2, 'little')
                with self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, bytes(changed), target)
            changed = bytearray(image)
            changed[16:18] = (3).to_bytes(2, 'little')
            review.check(lines, raw, sizes, row, bytes(changed), target)
            with self.assertRaisesRegex(ValueError, 'decoded bytes'):
                review.check(lines, raw[:-1] + bytes([raw[-1] ^ 1]), sizes, row, image, target)

    def test_decoder_rejects_missing_duplicate_noncontiguous_and_wrong_target(self):
        for target in review.TARGETS:
            nm, asm, _, bodies = fixture(target)
            row = bodies[0][3]
            for broken in ('', asm + asm, asm.replace(f'{row[1]:016x} <', '0000000000000000 <', 1),
                           asm.replace(' 1100:', ' 1101:', 1),
                           asm.replace(review.TARGETS[target][1], 'wrong-architecture'),
                           asm.replace(asm.splitlines()[3] + '\n', '', 1)):
                with self.assertRaises(ValueError):
                    review.decode(broken, row, target)
            for broken in ('', nm + '\n' + nm.splitlines()[0], '\n'.join(nm.splitlines()[:-1]),
                           nm.replace(' t ', ' D ', 1), nm.replace('9transform', '10transform', 1)):
                with self.assertRaises(ValueError):
                    review.select(broken, target)

    def test_equal_number_of_wrong_widths_is_not_accepted(self):
        for target in review.TARGETS:
            nm, asm, image, _ = fixture(target, (128, 128, 256))
            with self.assertRaisesRegex(ValueError, 'width population'):
                review.inspect(nm, asm, image, target)

    def test_execution_markers_are_exact_and_architecture_specific(self):
        for arm in (False, True):
            lines = []
            for bits in (128, 192, 256):
                lines += ['AES_FORCED_AUTHORITY: ' + ('ArmAes' if arm else 'X86AesNi'),
                          f'AES_ACCELERATED_LINKED_KAT: {bits}; six operations; clearing and quarantine checked']
            text = '\n'.join(lines)
            runner.output_check(text, arm)
            for bad in ('', text + '\n' + lines[-1], '\n'.join(lines[:-1]),
                        text.replace('quarantine checked', 'skipped')):
                with self.assertRaises(ValueError):
                    runner.output_check(bad, arm)
            with self.assertRaises(ValueError):
                runner.output_check(text, not arm)

    def test_ambient_and_invalid_configuration_rejected_before_packaging(self):
        for args in (('stable', 'native', 'static'), ('1.99.1', 'native', 'hosted')):
            with patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check(*args)
            package.assert_not_called()
        for name in (*runner.packaged.archives.REJECT_ENV, 'PYTHONOPTIMIZE', 'PYTHONPATH'):
            with patch.dict(runner.os.environ, {name: 'untrusted'}), \
                 patch.object(runner.packaged, 'package_sources') as package, self.assertRaises(ValueError):
                runner.check('1.99.1', 'native', 'static')
            package.assert_not_called()

    def test_registry_requires_review_not_capture_only(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        checks = {c['id']: c for c in registry['checks'] if c['component'] == 'aes' and c['category'] == 'aes-linked-kernel'}
        expected = {f'accelerated-linked-{mode}-{admission}-{endpoint}'
                    for mode, admission in (('native', 'static'), ('arm-qemu', 'static'), ('arm-qemu', 'hosted'))
                    for endpoint in ('msrv', 'current')}
        self.assertEqual(set(checks), expected)
        for endpoint, tc in (('msrv', '1.90.0'), ('current', '1.99.1')):
            for mode, admission in (('native', 'static'), ('arm-qemu', 'static'), ('arm-qemu', 'hosted')):
                check = checks[f'accelerated-linked-{mode}-{admission}-{endpoint}']
                self.assertEqual(check['command'], ['python3', 'scripts/aes/check-aes-accelerated-linked.py',
                    '--toolchain', tc, '--mode', mode, '--admission', admission])
                self.assertIn('aes-accelerated-linked', check['inputs'])
                self.assertIn('hkdf-public-api-modern', check['inputs'])
                self.assertEqual(check['success']['unique_lines'], [
                    f'AES_ACCELERATED_LINKED_PASS: {tc} {mode} {admission}; four consumers; kernel bodies only'])


if __name__ == '__main__':
    unittest.main()
