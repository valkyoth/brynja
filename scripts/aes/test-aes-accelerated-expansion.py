#!/usr/bin/env python3
"""Negative controls for final-linked hardware expansion, not synthetic evidence."""
import importlib.util
from pathlib import Path
import re
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('round_kernel_tests', HERE / 'test-aes-accelerated-linked.py')
round_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(round_tests)
runner = round_tests.runner
review = runner.packaged.module('expansion_review_tests', HERE / 'aes_accelerated_linked_expansion.py')


def fixture(target, widths=(128, 192, 256), v0=False):
    nm, assembly, original, _ = round_tests.fixture(target)
    image, bodies = bytearray(original), []
    arm = target.startswith('aarch64')
    architecture = '14aarch64_expand' if arm else '10x86_expand'
    for index, bits in enumerate(widths):
        start = 0x1500 + index * 0x100
        shape = {128: '10_Kjb0', 192: '18_Kjd0', 256: '20_Kjf0'}[bits]
        symbol = (f'_RINvNtNtCfixture{index}_17brynja_crypto_cpu3aes{architecture}6expandKj{shape}_EB6_'
                  if v0 else f'_ZN17brynja_crypto_cpu3aes{architecture}6expand17h{index:016x}E')
        normalized, raw, sizes = review.template(target, bits)
        lines = [re.sub(r'@\+([0-9a-f]+)', lambda m: f'0x{start + int(m[1], 16):x} <{symbol}+0x{m[1]}>', line)
                 for line in normalized]
        image[start - 0x1000:start - 0x1000 + len(raw)] = raw
        row = symbol, start, len(raw)
        bodies.append((lines, raw, sizes, row))
        nm += f'\n{start:016x} {len(raw):016x} t {symbol}'
        assembly += f'{start:016x} <{symbol}>:\n'
        cursor = 0
        for line, size in zip(lines, sizes):
            data = raw[cursor:cursor + size]
            encoded = f'{int.from_bytes(data, "little"):08x}' if arm else data.hex(' ')
            assembly += f' {start + cursor:x}: {encoded} \t{line}\n'
            cursor += size
        assembly += '\n'
    return nm, assembly, bytes(image), bodies


class AcceleratedExpansionTests(unittest.TestCase):
    def test_every_instruction_and_byte_is_checked_for_all_widths(self):
        for target in review.TARGETS:
            for v0 in (False, True):
                nm, asm, image, _ = fixture(target, v0=v0)
                result = review.inspect(nm, asm, image, target)
                arm = target.startswith('aarch64')
                self.assertEqual([r['bits'] for r in result['expansions']], [128, 192, 256])
                self.assertEqual({(r['instructions'], r['symbol_bytes']) for r in result['expansions']},
                                 {(49, 196) if arm else (45, 145)})
                self.assertEqual(result['rejected_mutations'], 735 if arm else 570)

    def test_branch_targets_and_annotations_are_not_wildcards(self):
        for target in review.TARGETS:
            _, _, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            for index, line in enumerate(lines):
                if '<' not in line:
                    continue
                for replacement in (re.sub(r'0x[0-9a-f]+ <', '0x0 <', line),
                                    line.replace(row[0], 'another_symbol'),
                                    re.sub(r'0x[0-9a-f]+ <.*', f'0x{row[1]+1:x} <{row[0]}+0x1>', line),
                                    'jmp *%rax' if target.startswith('x86') else 'br x12'):
                    changed = list(lines)
                    changed[index] = replacement
                    with self.assertRaises(ValueError):
                        review.check(changed, raw, sizes, row, image, target)

    def test_secret_address_branch_spill_and_erasure_changes_fail(self):
        for target in review.TARGETS:
            _, _, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            for old, new in (('(%rsi,%rax)', '(%rsi,%rdx)'), ('(%rdi,%rax)', '(%rsp,%rax)'),
                             ('testq %r8, %r8', 'testq %rdx, %rdx'), ('rorl $8', 'rorl $16'),
                             ('aeskeygenassist $0', 'aeskeygenassist $1'), ('%xmm0, %xmm0', '%xmm1, %xmm0'),
                             ('[x1, x9]', '[x1, x12]'), ('[x0, x9]', '[sp, x9]'),
                             ('cbz x10,', 'cbz x12,'), ('#176', '#192'),
                             ('aese v0.16b, v1.16b', 'aese v0.16b, v0.16b'),
                             ('movi v0.16b, #0', 'movi v0.16b, #1'), ('msr NZCV, xzr', 'nop')):
                if not any(old in line for line in lines):
                    continue
                with self.assertRaises(ValueError):
                    review.check([line.replace(old, new) for line in lines], raw, sizes, row, image, target)

    def test_executable_bytes_mapping_and_full_extent_are_required(self):
        for target in review.TARGETS:
            _, asm, image, bodies = fixture(target)
            lines, raw, sizes, row = bodies[0]
            for offset in (0x500, 18, 32, 52, 54, 56, 68):
                changed = bytearray(image)
                changed[offset] ^= 1
                with self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, bytes(changed), target)
            with self.assertRaises(ValueError):
                review.check(lines[:-1], raw[:-1], sizes[:-1], row, image, target)
            for changed in (asm + asm, asm.replace(' 1500:', ' 1501:', 1),
                            asm.replace(review.TARGETS[target][1], 'wrong-target')):
                with self.assertRaises(ValueError):
                    review.kernels.decode(changed, row, target)

    def test_missing_extra_wrong_architecture_or_overlapping_symbols_fail(self):
        for target in review.TARGETS:
            nm, _, _, bodies = fixture(target)
            symbol, start, size = bodies[0][3]
            selected = next(line for line in nm.splitlines() if symbol in line)
            other_arch = '14aarch64_expand' if target.startswith('x86') else '10x86_expand'
            for changed in ('', nm + '\n' + selected, nm.replace(selected, ''),
                            nm.replace('10x86_expand' if target.startswith('x86') else '14aarch64_expand', other_arch),
                            nm.replace(selected, selected.replace(' t ', ' D ')),
                            nm.replace(selected, selected.replace(f'{size:016x}', f'{size+256:016x}', 1))):
                with self.assertRaises(ValueError):
                    review.select(changed, target)
            with self.assertRaises(ValueError):
                review.select(nm.replace('6expand', '7expand'), target)

    def test_duplicate_widths_and_invalid_v0_shapes_fail(self):
        for target in review.TARGETS:
            nm, asm, image, _ = fixture(target, (128, 128, 256))
            with self.assertRaisesRegex(ValueError, 'width population'):
                review.inspect(nm, asm, image, target)
            nm, _, _, _ = fixture(target, v0=True)
            for changed in (nm.replace('Kj10_Kjb0', 'Kj10_Kjd0'), nm.replace('Kj20_Kjf0', 'Kj28_Kjf0')):
                with self.assertRaises(ValueError):
                    review.select(changed, target)

    def test_runner_requires_both_round_and_expansion_review(self):
        for target in review.TARGETS:
            nm, asm, image, _ = fixture(target)
            result = runner.kernel_reviews(nm, asm, image, target)
            self.assertEqual(set(result), {'kernel_review', 'expansion_review'})
            for missing in ('transform', '_expand'):
                filtered = '\n'.join(line for line in nm.splitlines() if missing not in line)
                with self.assertRaises(ValueError):
                    runner.kernel_reviews(filtered, asm, image, target)

    def test_registry_binds_templates_tests_and_review_document(self):
        registry = tomllib.loads((runner.ROOT / 'verification/checks.toml').read_text())
        paths = registry['groups']['aes-accelerated-linked']['paths']
        for name in ('scripts/aes/aes_accelerated_linked_expansion.py',
                     'scripts/aes/test-aes-accelerated-expansion.py',
                     'docs/assurance/aes-accelerated-linked-expansion.md'):
            self.assertIn(name, paths)
        checks = [c for c in registry['checks'] if c['component'] == 'aes' and c['category'] == 'aes-linked-kernel']
        self.assertEqual(len(checks), 6)
        for check in checks:
            self.assertIn('hardware expansion', check['establishes'])
            self.assertIn('aes-accelerated-linked', check['inputs'])


if __name__ == '__main__':
    unittest.main()
