#!/usr/bin/env python3
"""Exact-byte and target-binding controls for Apple retained cleanup bodies."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('apple_cleanup_test_fixture',
    Path(__file__).with_name('test-aes-apple-linked-kernels.py'))
fixture_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture_module)
runner = fixture_module.runner
review = runner.cleanup_review


def fixture(compiler='1.99.1', panic='abort'):
    legacy = compiler == '1.90.0'
    names = (['__ZN11brynja_core22secret_memory_volatile23zeroize_region_volatile17h1111111111111111E',
              '__ZN30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key17h2222222222222222E',
              '__ZN30brynja_aes_accelerated_fixture9lifecycle13destroy_block17h3333333333333333E'] if legacy else
             ['__RNvNtCtest_11brynja_core22secret_memory_volatile23zeroize_region_volatile',
              '__RNvNtNtCtest_30brynja_aes_accelerated_fixture9lifecycle6aes12811destroy_key',
              '__RNvNtCtest_30brynja_aes_accelerated_fixture9lifecycle13destroy_block'])
    clear = fixture_module.BASE + 0x400 + 1044
    extra = [(symbol, lambda address, role=role:
              review.template(role, compiler, panic, address, clear))
             for symbol, role in zip(names, review.ROLES)]
    return fixture_module.fixture(legacy, extra)


class AppleCleanupTests(unittest.TestCase):
    def test_all_configurations_and_kernel_dependency(self):
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                for admission in ('static', 'hosted'):
                    result = review.inspect(fixture(compiler, panic)[0], compiler, panic, admission)
                    self.assertEqual(len(result['cleanup_bodies']), 3)
                    self.assertEqual(len(result['kernel_review']['bodies']), 6)
                    sizes = [r['size'] for r in result['cleanup_bodies']]
                    self.assertEqual(sizes, [20, 12, 12] if compiler == '1.90.0' else
                                     [24, 24, 24] if panic == 'unwind' else [24, 12, 12])

    def test_every_cleanup_byte_rejected_in_all_four_profiles(self):
        count = 0
        for compiler in ('1.90.0', '1.99.1'):
            for panic in ('abort', 'unwind'):
                image, bodies = fixture(compiler, panic)
                for offset, size in bodies[-3:]:
                    for i in range(size):
                        altered = bytearray(image)
                        altered[offset + i] ^= 1
                        with self.assertRaisesRegex(ValueError, 'cleanup encoding/extent changed'):
                            review.inspect(altered, compiler, panic, 'static')
                        count += 1
        self.assertEqual(count, 208)

    def test_clear_semantics_are_explicit_not_learned(self):
        self.assertEqual(review.template('zeroize', '1.90.0', 'abort', 0).hex(),
                         '810000b41f140038210400f1c1ffff54c0035fd6')
        self.assertEqual(review.template('zeroize', '1.99.1', 'unwind', 0).hex(),
                         'a10000b41f00003900040091210400f1a1ffff54c0035fd6')

    def test_tail_branch_must_target_first_instruction_of_checked_clear(self):
        image, _ = fixture()
        row = review.select(image)['destroy_key']
        altered = bytearray(image)
        word = struct.unpack_from('<I', altered, row[3] + 4)[0]
        struct.pack_into('<I', altered, row[3] + 4, word + 1)
        with self.assertRaisesRegex(ValueError, 'cleanup encoding/extent changed'):
            review.inspect(altered, '1.99.1', 'abort', 'static')
        altered = bytearray(image)
        struct.pack_into('<I', altered, row[3] + 4, word | 0x80000000)  # BL instead of B
        with self.assertRaisesRegex(ValueError, 'cleanup encoding/extent changed'):
            review.inspect(altered, '1.99.1', 'abort', 'static')

    def test_branch_range_alignment_and_missing_target(self):
        for target in (None, 3, 2**27 + 4, -(2**27) - 8):
            with self.assertRaises(ValueError):
                review.template('destroy_key', '1.90.0', 'abort', 0, target)

    def test_missing_duplicate_or_aliased_cleanup_symbols(self):
        image, _ = fixture()
        for offset, fmt, value in ((268, '<I', 8), (0x1070, '<I', struct.unpack_from('<I', image, 0x1060)[0]),
                                   (0x1078, '<Q', struct.unpack_from('<Q', image, 0x1068)[0])):
            altered = bytearray(image)
            struct.pack_into(fmt, altered, offset, value)
            with self.assertRaises(ValueError):
                review.inspect(altered, '1.99.1', 'abort', 'static')

    def test_extra_body_and_unknown_role_rejected(self):
        image, _ = fixture()
        altered = image.replace(b'11destroy_key', b'11destroy_bad', 1)
        with self.assertRaises(ValueError):
            review.inspect(altered, '1.99.1', 'abort', 'static')
        with self.assertRaises(ValueError):
            review.template('unknown', '1.99.1', 'abort', 0)

    def test_wrong_profile_and_changed_kernel_cannot_pass(self):
        image, _ = fixture()
        for config in (('1.90.0', 'abort', 'static'), ('1.99.1', 'unwind', 'static'),
                       ('unknown', 'abort', 'static'), ('1.99.1', 'abort', 'unknown')):
            with self.assertRaises(ValueError):
                review.inspect(image, *config)
        image[0x400] ^= 1
        with self.assertRaisesRegex(ValueError, 'complete function encoding/extent changed'):
            review.inspect(image, '1.99.1', 'abort', 'static')

    def test_runner_cleanup_is_explicit_and_hash_bound(self):
        image, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.macho'
            path.write_bytes(image)
            expected = hashlib.sha256(image).hexdigest()
            self.assertIn('cleanup_bodies', runner.check(path, expected, cleanup=('1.99.1', 'abort', 'static')))
            self.assertNotIn('cleanup_bodies', runner.check(path, expected))
            for config in ((), ('1.99.1',), ('bad', 'abort', 'static')):
                with self.assertRaises(ValueError):
                    runner.check(path, expected, cleanup=config)
            with patch.object(review, 'inspect') as inspect, self.assertRaises(ValueError):
                runner.check(path, '0' * 64, cleanup=('1.99.1', 'abort', 'static'))
            inspect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
