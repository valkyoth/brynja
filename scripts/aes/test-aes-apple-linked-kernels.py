#!/usr/bin/env python3
"""Synthetic Mach-O mapping/extent controls; no Apple host or binary required."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('apple_linked_tests_runner',
    Path(__file__).with_name('check-aes-apple-linked.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
review = runner.review

BASE = 0x100000000


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def fixture(legacy=False, extra=()):
    image = bytearray(0x2000)
    code = bytearray()
    symbols, addresses, bodies = [], [], []
    for role in ('transform', 'expand'):
        for bits in (128, 192, 256):
            module, method = ('7aarch64', '9transform') if role == 'transform' else ('14aarch64_expand', '6expand')
            generics = ({128: 'b', 192: 'd', 256: 'f'} if role == 'transform'
                        else {128: '10_Kjb0', 192: '18_Kjd0', 256: '20_Kjf0'})[bits]
            symbol = (f'__ZN17brynja_crypto_cpu3aes{module}{method}17h{bits:016x}E' if legacy else
                      f'__RINvNtNtCtest_17brynja_crypto_cpu3aes{module}{method}Kj{generics}_EB6_')
            address = BASE + 0x400 + len(code)
            template = review.expansion.kernels.template if role == 'transform' else review.expansion.template
            raw = template(review.TARGET, bits)[1]
            bodies.append((0x400 + len(code), len(raw)))
            code.extend(raw)
            addresses.append(address)
            symbols.append((symbol, address))
    for symbol, build in extra:
        address = BASE + 0x400 + len(code)
        raw = build(address)
        bodies.append((0x400 + len(code), len(raw)))
        code.extend(raw)
        addresses.append(address)
        symbols.append((symbol, address))
    addresses.append(BASE + 0x400 + len(code))
    code.extend(bytes.fromhex('c0035fd6'))
    image[0x400:0x400 + len(code)] = code
    strings = bytearray(b' \0')
    for i, (symbol, address) in enumerate(symbols):
        struct.pack_into('<IBBHQ', image, 0x1000 + 16 * i, len(strings), 0xe, 1, 0, address)
        strings.extend(symbol.encode() + b'\0')
    image[0x1100:0x1100 + len(strings)] = strings
    deltas, previous = bytearray(), BASE
    for address in addresses:
        deltas.extend(uleb(address - previous))
        previous = address
    deltas.append(0)
    image[0x1800:0x1800 + len(deltas)] = deltas
    commands = 152 + 72 + 24 + 16
    struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0, 2, 4, commands, 0, 0)
    struct.pack_into('<II16sQQQQiiII', image, 32,
                     0x19, 152, b'__TEXT', BASE, 0x1000, 0, 0x1000, 5, 5, 1, 0)
    struct.pack_into('<16s16sQQ8I', image, 104,
                     b'__text', b'__TEXT', BASE + 0x400, len(code), 0x400, 2, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into('<II16sQQQQiiII', image, 184,
                     0x19, 72, b'__LINKEDIT', BASE + 0x1000, 0x1000, 0x1000, 0x1000, 1, 1, 0, 0)
    struct.pack_into('<6I', image, 256, 2, 24, 0x1000, len(symbols), 0x1100, len(strings))
    struct.pack_into('<4I', image, 280, 0x26, 16, 0x1800, len(deltas))
    return image, bodies


class AppleKernelTests(unittest.TestCase):
    def reject_edit(self, offset, fmt, value):
        image, _ = fixture()
        struct.pack_into(fmt, image, offset, value)
        with self.assertRaises(ValueError):
            review.inspect(image)

    def test_complete_bodies_for_both_manglings(self):
        for legacy in (False, True):
            result = review.inspect(fixture(legacy)[0])
            self.assertEqual([(r['role'], r['bits'], r['size']) for r in result['bodies']],
                             [(role, bits, size) for role, size in (('transform', 152), ('expand', 196))
                              for bits in (128, 192, 256)])

    def test_every_body_byte_mutation_is_rejected(self):
        image, bodies = fixture()
        total = 0
        for offset, size in bodies:
            for i in range(size):
                altered = bytearray(image)
                altered[offset + i] ^= 1
                with self.assertRaisesRegex(ValueError, 'encoding/extent changed'):
                    review.inspect(altered)
                total += 1
        self.assertEqual(total, 1044)

    def test_wrong_header_architecture_subtype_kind_and_reserved(self):
        for offset, value in ((0, 0xcafebabe), (4, 0x1000007), (8, 2), (12, 1), (28, 1)):
            self.reject_edit(offset, '<I', value)

    def test_truncated_images_and_command_tables(self):
        image, _ = fixture()
        for length in (0, 31, 32, 40, 100, 150, 295, 4096, 6400):
            with self.assertRaises(ValueError):
                review.inspect(image[:length])
        for offset, value in ((16, 0), (16, 4097), (20, 0xffffffff), (20, 256), (36, 0), (36, 153)):
            self.reject_edit(offset, '<I', value)

    def test_permissions_section_mapping_and_alignment(self):
        for offset, fmt, value in ((92, '<i', 7), (88, '<i', 7), (244, '<i', 3),
                                   (152, '<I', 0x404), (136, '<Q', BASE + 0x404),
                                   (156, '<I', 32), (168, '<I', 1), (144, '<Q', 0x1000)):
            self.reject_edit(offset, fmt, value)

    def test_overlapping_segments_and_metadata(self):
        for offset, fmt, value in ((208, '<Q', BASE), (224, '<Q', 0),
                                   (272, '<I', 0x1000), (288, '<I', 0x1000),
                                   (264, '<I', 0x800), (268, '<I', 0xffffffff)):
            self.reject_edit(offset, fmt, value)

    def test_missing_duplicate_and_encrypted_load_commands(self):
        for offset, value in ((280, 0x27), (280, 2), (280, 0x2c), (280, 0x21), (256, 0x26)):
            self.reject_edit(offset, '<I', value)

    def test_function_delta_rejections(self):
        for data in (b'', b'\0', b'\x80', b'\x80\x00', b'\xff' * 11,
                     b'\x80' * 9 + b'\x02\0', uleb(0x401) + b'\0',
                     uleb(0x400) + b'\0\1', uleb(0x400), uleb(0x1000) + b'\0'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                review.starts(data, BASE, BASE + 0x400, BASE + 0x800)
        self.assertEqual(review.starts(uleb(0x400) + b'\0\0', BASE, BASE + 0x400, BASE + 0x800),
                         [BASE + 0x400])

    def test_missing_internal_and_extended_function_boundaries(self):
        image, _ = fixture()
        # First delta occupies two bytes. Change next delta from 152 to 156;
        # the first body's extra instruction must not be silently truncated.
        image[0x1802:0x1804] = uleb(156)
        image[0x1804:0x1806] = uleb(148)
        with self.assertRaisesRegex(ValueError, 'encoding/extent changed'):
            review.inspect(image)
        self.reject_edit(0x1008, '<Q', BASE + 0x404)

    def test_symbol_type_section_address_and_table_bounds(self):
        for offset, fmt, value in ((0x1000, '<I', 0xffffffff), (0x1004, '<B', 0),
                                   (0x1005, '<B', 2), (0x1008, '<Q', BASE), (276, '<I', 2)):
            self.reject_edit(offset, fmt, value)

    def test_duplicate_names_addresses_and_missing_width(self):
        image, _ = fixture()
        for start, count in ((0x1010, 4), (0x1018, 8), (0x1010, 16)):
            altered = bytearray(image)
            original = 0x1008 if start == 0x1018 else 0x1000
            altered[start:start + count] = image[original:original + count]
            with self.assertRaises(ValueError):
                review.inspect(altered)
        self.reject_edit(268, '<I', 5)

    def test_generic_width_and_wrong_architecture(self):
        image, _ = fixture()
        for old, new in ((b'transformKjb', b'transformKjd'), (b'7aarch64', b'7unknown')):
            altered = image.replace(old, new, 1)
            with self.assertRaises(ValueError):
                review.inspect(altered)

    def test_debug_records_do_not_duplicate_real_symbols(self):
        image, _ = fixture()
        image[0x1060:0x1070] = image[0x1000:0x1010]
        image[0x1064] = 0x24
        struct.pack_into('<I', image, 268, 7)
        self.assertEqual(len(review.inspect(image)['bodies']), 6)

    def test_unterminated_and_invalid_names(self):
        image, _ = fixture()
        altered = bytearray(image)
        altered[0x1100] = 0xff
        with self.assertRaises(ValueError):
            review.inspect(altered)
        altered = bytearray(image)
        size = struct.unpack_from('<I', image, 276)[0]
        altered[0x1100 + size - 1] = 65
        with self.assertRaises(ValueError):
            review.inspect(altered)

    def test_runner_binds_hash_before_parsing_and_rejects_symlinks(self):
        image, _ = fixture()
        expected = hashlib.sha256(image).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.macho'
            path.write_bytes(image)
            self.assertEqual(runner.check(path, expected)['binary_sha256'], expected)
            for wrong in ('0' * 64, '', '../bad'):
                with patch.object(review, 'inspect') as inspect, self.assertRaises(ValueError):
                    runner.check(path, wrong)
                inspect.assert_not_called()
            link = Path(directory) / 'alias'
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                runner.check(link, expected)
            with patch.object(review, 'LIMIT', len(image) - 1), self.assertRaises(ValueError):
                runner.check(path, expected)

    def test_cli_failure_never_emits_a_review_record(self):
        command = [sys.executable, str(Path(__file__).with_name('check-aes-apple-linked.py')),
                   '/missing/apple-fixture.macho', '--sha256', '0' * 64]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, '')
        self.assertIn('missing/nonregular/symlinked', completed.stderr)


if __name__ == '__main__':
    unittest.main()
