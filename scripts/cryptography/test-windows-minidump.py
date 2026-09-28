#!/usr/bin/env python3
"""Synthetic dumps test the parser, not Windows dump-exclusion behavior."""
import struct
import unittest

import windows_minidump as dump
from windows_protection_probe import ProbeError


def fixture(regions=((0x10000, b'\xa5' * 32), (0x20000, b'\x5a' * 32))):
    size = 16 + 16 * len(regions)
    payload = 44 + size
    header = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
    directory = struct.pack('<III', 9, size, 44)
    table = struct.pack('<QQ', len(regions), payload)
    table += b''.join(struct.pack('<QQ', address, len(data)) for address, data in regions)
    return header + directory + table + b''.join(data for _, data in regions)


class Tests(unittest.TestCase):
    def test_included_excluded_and_wrong_markers(self):
        both = fixture()
        self.assertTrue(dump.observe(both, 0x10000, 32, 0xa5)['complete_marker'])
        self.assertTrue(dump.observe(both, 0x20000, 32, 0x5a)['complete_marker'])
        self.assertFalse(dump.observe(both, 0x10000, 32, 0x5a)['complete_marker'])
        control_only = fixture(((0x20000, b'\x5a' * 32),))
        self.assertEqual(dump.observe(control_only, 0x10000, 32, 0xa5),
                         {'included_bytes': 0, 'expected_bytes': 32, 'complete_marker': False})
        self.assertTrue(dump.observe(control_only, 0x20000, 32, 0x5a)['complete_marker'])

    def test_address_selection_not_global_substring(self):
        blob = fixture(((0x20000, b'\xa5' * 32),))
        self.assertEqual(dump.observe(blob, 0x10000, 32, 0xa5)['included_bytes'], 0)

    def test_split_partial_and_out_of_order_ranges(self):
        split = fixture(((0x10010, b'\xa5' * 16), (0x10000, b'\xa5' * 16)))
        self.assertTrue(dump.observe(split, 0x10000, 32, 0xa5)['complete_marker'])
        partial = fixture(((0x10010, b'\xa5' * 16),))
        self.assertEqual(dump.observe(partial, 0x10000, 32, 0xa5)['included_bytes'], 16)
        self.assertFalse(dump.observe(partial, 0x10000, 32, 0xa5)['complete_marker'])

    def test_all_truncations_fail(self):
        blob = fixture()
        for size in range(len(blob)):
            with self.subTest(size=size), self.assertRaises(ProbeError):
                dump.memory_ranges(blob[:size])

    def test_malformed_headers_and_ranges(self):
        # Field offset, format, bad value. Every mutant reaches the real parser.
        for offset, fmt, value in ((0, '<I', 0), (4, '<I', 0), (8, '<I', 0),
                                   (8, '<I', 129), (12, '<I', 0xffffffff), (24, '<Q', 0),
                                   (32, '<I', 5), (36, '<I', 15), (40, '<I', 0xffffffff),
                                   (44, '<Q', 0), (44, '<Q', 65537), (52, '<Q', 0),
                                   (52, '<Q', 2**64 - 1),
                                   (60, '<Q', 2**64 - 1), (68, '<Q', 2**64 - 1),
                                   (76, '<Q', 0x10001)):
            blob = bytearray(fixture())
            struct.pack_into(fmt, blob, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ProbeError):
                dump.memory_ranges(blob)

    def test_zero_sized_native_descriptors_never_add_coverage(self):
        for index in range(3):
            regions = [(0x10000, b'\xa5' * 32), (0x20000, b'\x5a' * 32)]
            # Empty entries may even name addresses inside a nonempty range.
            regions.insert(index, (0x10001, b''))
            blob = fixture(regions)
            self.assertEqual(len(dump.memory_ranges(blob)), 2)
            self.assertTrue(dump.observe(blob, 0x10000, 32, 0xa5)['complete_marker'])
            self.assertTrue(dump.observe(blob, 0x20000, 32, 0x5a)['complete_marker'])
        blob = fixture(((0x10000, b''), (2**64 - 1, b'')))
        self.assertEqual(dump.memory_ranges(blob), [])
        self.assertEqual(dump.observe(blob, 0x10000, 32, 0xa5),
                         {'included_bytes': 0, 'expected_bytes': 32, 'complete_marker': False})

    def test_duplicate_stream_rejected(self):
        blob = bytearray(fixture())
        struct.pack_into('<I', blob, 8, 2)
        blob[44:56] = blob[32:44]
        with self.assertRaisesRegex(ProbeError, 'exactly one'):
            dump.memory_ranges(blob)

    def test_target_bounds(self):
        for address, size, value in ((-1, 32, 0), (0, 0, 0), (0, 65537, 0),
                                     (2**64 - 1, 32, 0), (0, 32, 256), (False, 32, 0)):
            with self.subTest(address=address, size=size, value=value), self.assertRaises(ProbeError):
                dump.observe(fixture(), address, size, value)


if __name__ == '__main__':
    unittest.main()
