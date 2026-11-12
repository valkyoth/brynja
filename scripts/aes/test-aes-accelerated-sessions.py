#!/usr/bin/env python3
"""Session closure controls. Synthetic policies cannot approve real binaries."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


review = module('session_review_tests', 'aes_accelerated_linked_sessions.py')
prior = module('session_kernel_fixture', 'test-aes-accelerated-linked.py')


def fixture(v0=False):
    table, assembly, original, kernels = prior.fixture(review.TARGET)
    image, cases = bytearray(original), []
    for index, bits in enumerate((128, 192, 256)):
        for inverse, direction in enumerate(('encrypt', 'decrypt')):
            start = 0x1500 + index * 0x100 + inverse * 0x40
            name = (f'_RNvMs_NtCs123_17brynja_crypto_cpu3aesNtB2_7Session10{direction}{bits}' if v0 else
                    f'_ZN17brynja_crypto_cpu3aes7Session10{direction}{bits}17h0000000000000000E')
            callee = kernels[index][3]
            raw = b'\xba' + inverse.to_bytes(4, 'little') + b'\xe8' + (callee[1] - start - 10).to_bytes(4, 'little', signed=True) + b'\xc3'
            lines = [f'movl ${inverse}, %edx', f'callq 0x{callee[1]:x} <{callee[0]}>', 'retq']
            sizes, row = [5, 5, 1], (name, start, len(raw))
            table += f'\n{start:016x} {len(raw):016x} t {name}'
            assembly += f'{start:016x} <{name}>:\n'
            cursor = 0
            for line, size in zip(lines, sizes):
                assembly += f' {start + cursor:x}: {raw[cursor:cursor + size].hex(" ")} \t{line}\n'
                cursor += size
            assembly += '\n'
            image[start - 0x1000:start - 0x1000 + len(raw)] = raw
            cases.append((lines, raw, sizes, row, {'kernel': callee}, direction, bits))
    return table, assembly, bytes(image), cases


def test_policy(image, cases):
    return {direction: review.image_review.observe(lines, raw, sizes, row[0], row[1], image, targets)[0]
            for lines, raw, sizes, row, targets, direction, _ in cases}


class AcceleratedSessionTests(unittest.TestCase):
    def test_synthetic_bodies_never_satisfy_real_policies(self):
        _, _, image, cases = fixture()
        for lines, raw, sizes, row, targets, direction, _ in cases:
            for compiler, panic in review.POLICY:
                with self.assertRaises(ValueError):
                    review.check(lines, raw, sizes, row, image, targets, direction, compiler, panic)

    def test_all_text_and_byte_mutations_with_test_only_policy(self):
        _, _, image, cases = fixture()
        with patch.object(review, 'POLICY', {('test', 'abort'): test_policy(image, cases)}):
            for lines, raw, sizes, row, targets, direction, _ in cases:
                self.assertEqual(review.mutations(lines, raw, sizes, row, image, targets, direction, 'test', 'abort'),
                                 len(lines) + len(raw))

    def test_wrong_width_direction_and_extra_edges_rejected(self):
        _, _, image, cases = fixture()
        with patch.object(review, 'POLICY', {('test', 'abort'): test_policy(image, cases)}):
            for lines, raw, sizes, row, targets, direction, bits in cases:
                other = cases[2 if bits == 128 else 0][4]
                for wrong in (other, {}, {**targets, 'resume': ('resume', 0x1900, 1)}):
                    with self.assertRaises(ValueError):
                        review.check(lines, raw, sizes, row, image, wrong, direction, 'test', 'abort')
                with self.assertRaisesRegex(ValueError, 'stream changed'):
                    review.check(lines, raw, sizes, row, image, targets,
                                 'decrypt' if direction == 'encrypt' else 'encrypt', 'test', 'abort')

    def test_both_symbol_grammars_and_population_fail_closed(self):
        for v0 in (False, True):
            table, _, _, _ = fixture(v0)
            self.assertEqual(set(review.candidates(table)), {(d, b) for d in ('encrypt', 'decrypt') for b in (128, 192, 256)})
            for changed in ('\n'.join(table.splitlines()[:-1]), table + '\n' + table.splitlines()[-1],
                            table.replace('10encrypt128', '10encrypt999'), table.replace(' t ', ' D '),
                            table.replace('0000000000001540', '0000000000001501'),
                            table.replace('10encrypt128', '10encrypt128.clone')):
                with self.assertRaises(ValueError):
                    review.candidates(changed)

    def test_full_inspection_binds_each_width_and_callee(self):
        for v0 in (False, True):
            table, assembly, image, cases = fixture(v0)
            with patch.object(review, 'POLICY', {('test', 'abort'): test_policy(image, cases)}):
                result = review.inspect(table, assembly, image, 'test', 'abort')
                self.assertEqual(len(result['sessions']), 6)
                self.assertEqual(result['rejected_mutations'], 84)
                # Both textual and encoded references are valid, but the wrong
                # width body must not be admitted under the 128-bit symbol.
                swapped = table.replace('10encrypt128', '10encryptTEMP').replace('10encrypt256', '10encrypt128').replace('10encryptTEMP', '10encrypt256')
                swapped_asm = assembly.replace('10encrypt128', '10encryptTEMP').replace('10encrypt256', '10encrypt128').replace('10encryptTEMP', '10encrypt256')
                with self.assertRaises(ValueError):
                    review.inspect(swapped, swapped_asm, image, 'test', 'abort')

    def test_kernel_rejection_and_unwind_import_cannot_be_skipped(self):
        table, assembly, image, _ = fixture()
        with patch.object(review.kernels, 'check', side_effect=ValueError('bad kernel')) as dependency:
            with self.assertRaisesRegex(ValueError, 'bad kernel'):
                review.inspect(table, assembly, image, '1.99.1', 'abort')
            dependency.assert_called_once()
        with patch.object(review.cached.public.cleanup, 'resume_target', side_effect=ValueError('bad import')) as dependency:
            with self.assertRaisesRegex(ValueError, 'bad import'):
                review.inspect(table, assembly, image, '1.90.0', 'unwind', 'wrong relocations')
            dependency.assert_called_once()

    def test_exact_policy_population(self):
        expected = {('1.90.0', 'abort'): 489, ('1.90.0', 'unwind'): 813,
                    ('1.99.1', 'abort'): 489, ('1.99.1', 'unwind'): 489}
        self.assertEqual(set(review.POLICY), set(expected))
        for config, policies in review.POLICY.items():
            self.assertEqual(set(policies), {'encrypt', 'decrypt'})
            self.assertEqual(3 * sum(p['instructions'] + p['symbol_bytes'] for p in policies.values()), expected[config])
            self.assertEqual({p['constant_loads'] for p in policies.values()}, {0})


if __name__ == '__main__':
    unittest.main()
