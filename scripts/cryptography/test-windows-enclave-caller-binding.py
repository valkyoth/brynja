"""Synthetic caller-byte/relocation/unwind regressions; no native qualification."""
import importlib.util
from pathlib import Path
import struct
import unittest

import windows_enclave_caller_binding as model
import windows_enclave_caller_unwind as unwind

spec = importlib.util.spec_from_file_location('wrapper_fixtures', Path(__file__).with_name('test-windows-enclave-wrapper-binding.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
put, ENTRY = fixtures.put, fixtures.ENTRY


def fixture():
    obj, image = fixtures.fixture()
    image[1056:1060] = bytes([1, 0, 0, 0])
    return obj, image


def chained():
    obj, image = fixture()
    put(image, 88 + 140, '<I', 24)
    put(image, 1024, '<III', 0x1000, 0x1010, 0x2020)
    put(image, 1036, '<III', 0x1010, 0x1021, 0x2040)
    image[1088:1092] = bytes([33, 0, 0, 0])
    put(image, 1092, '<III', 0x1000, 0x1010, 0x2020)
    return obj, image


class Tests(unittest.TestCase):
    def test_exact_bytes_extent_and_nonclaims(self):
        obj, image = fixture()
        value = model.bind(obj, image, ENTRY)
        self.assertEqual((value['rva'], value['size']), (0x1000, 33))
        self.assertEqual(set(value['reference_targets']), set(fixtures.NAMES))
        self.assertFalse(value['whole_image_qualified'])
        self.assertFalse(value['callee_semantics_qualified'])
        self.assertEqual(value['unwind'][0]['stack_bytes'], 0)

    def test_all_unrelocated_bytes_must_match(self):
        obj, image = fixture()
        masked = {offset + b for offset in (2, 8, 14, 20, 26) for b in range(4)}
        for offset in set(range(33)) - masked:
            changed = image.copy()
            changed[512 + offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'absent or ambiguous'): model.bind(obj, changed, ENTRY)

    def test_trailing_instruction_bytes_and_signed_addends(self):
        for trailing in range(6):
            for addend in (-16, 0, 16):
                obj, image = fixture()
                put(obj, 208, '<H', 4 + trailing)
                put(obj, 102, '<i', addend)
                put(image, 514, '<i', 128 + addend - (2 + 4 + trailing))
                value = model.bind(obj, image, ENTRY)
                self.assertEqual(value['reference_targets']['__chkstk'], 0x1080)

    def test_unsupported_relocations_auxiliaries_and_bounds_reject(self):
        for offset, fmt, bad in ((208, '<H', 3), (208, '<H', 10), (200, '<I', 31),
                                 (204, '<I', 1000), (8, '<I', 2**32-1), (2, '<H', 4097),
                                 (16, '<H', 1), (417, '<B', 255)):
            obj, image = fixture()
            put(obj, offset, fmt, bad)
            with self.assertRaises((ValueError, UnicodeError)): model.bind(obj, image, ENTRY)
        for data in (b'', bytes(20), fixture()[0][:400]):
            with self.assertRaises(ValueError): model.function(data, ENTRY)

    def test_duplicate_or_overlapping_relocations_reject(self):
        for offset in (2, 3, 5):
            obj, image = fixture()
            put(obj, 210, '<I', offset)
            with self.assertRaisesRegex(ValueError, 'nonoverlapping'): model.bind(obj, image, ENTRY)

    def test_selected_function_identity_and_section_permissions(self):
        # Entry is symbol5; neither a data symbol nor an interior funclet is accepted.
        for offset, fmt, bad in ((498, '<I', 1), (502, '<h', 0), (504, '<H', 0),
                                 (506, '<B', 0), (56, '<I', 0xe0500020)):
            obj, image = fixture()
            put(obj, offset, fmt, bad)
            with self.assertRaises(ValueError): model.bind(obj, image, ENTRY)
        obj, image = fixture()
        put(obj, 412, '<hH', 1, 0x20)
        with self.assertRaisesRegex(ValueError, 'single function'): model.bind(obj, image, ENTRY)
        for offset, bad in ((364, 0xe0000020), (336, 32)):
            obj, image = fixture()
            put(image, offset, '<I', bad)
            with self.assertRaisesRegex(ValueError, 'nonwritable mapped'): model.bind(obj, image, ENTRY)

    def test_repeated_symbol_references_must_agree(self):
        obj, image = fixture()
        put(obj, 214, '<I', 0)
        with self.assertRaisesRegex(ValueError, 'inconsistent symbol'): model.bind(obj, image, ENTRY)
        put(image, 520, '<i', 128 - (8 + 4))
        self.assertEqual(model.bind(obj, image, ENTRY)['reference_targets']['__chkstk'], 0x1080)

    def test_chained_secondary_cannot_allocate_another_frame(self):
        obj, image = chained()
        image[1088:1094] = bytes([33, 1, 1, 0, 1, 2])
        put(image, 1096, '<III', 0x1000, 0x1010, 0x2020)
        with self.assertRaisesRegex(ValueError, 'another fixed frame'): model.bind(obj, image, ENTRY)

    def test_ambiguous_code_and_outside_reference_reject(self):
        obj, image = fixture()
        image[768:801] = image[512:545]
        with self.assertRaisesRegex(ValueError, 'absent or ambiguous'): model.bind(obj, image, ENTRY)
        obj, image = fixture()
        put(image, 514, '<i', 0x70000000)
        with self.assertRaisesRegex(ValueError, 'outside image'): model.bind(obj, image, ENTRY)

    def test_chained_extent_requires_same_primary_without_gaps(self):
        obj, image = chained()
        result = model.bind(obj, image, ENTRY)
        self.assertEqual(len(result['unwind']), 2)
        for offset, value in ((1036, 0x1011), (1040, 0x1022), (1092, 0x1010), (1100, 0x2040)):
            changed = image.copy()
            put(changed, offset, '<I', value)
            with self.assertRaises(ValueError): model.bind(obj, changed, ENTRY)
        for offset, value in ((1088, 1), (1088, 9), (1091, 1), (1056, 2), (1056, 33)):
            changed = image.copy()
            changed[offset] = value
            with self.assertRaises(ValueError): model.bind(obj, changed, ENTRY)

    def test_unwind_counts_order_and_operands(self):
        def decode(data):
            return unwind.decode([dict(rva=0x2000, virtual_size=len(data), code=data)], (0x1000, 0x1100, 0x2000))
        # Allocate40, saveXMM6 at32, preserveRBX with push8: local48.
        data = bytes([1, 8, 4, 0, 8, 0x42, 7, 0x68, 2, 0, 1, 0x30])
        result = decode(data)
        self.assertEqual(result['stack_bytes'], 48)
        self.assertEqual(result['saved_registers'], [dict(register_class='xmm', register=6, offset=32)])
        for changed in (data[:8], bytes([1, 8, 1, 0, 8, 0x68]), bytes([1, 8, 1, 0, 8, 0x26]),
                        bytes([1, 8, 2, 0, 1, 0x02, 8, 0x02]), bytes([1, 8, 1, 0, 8, 3]),
                        bytes([1, 8, 1, 0, 8, 0]), bytes([1, 8, 2, 0, 8, 0x58, 0, 0]),
                        bytes([1, 8, 2, 0, 8, 1, 0, 0]), bytes([1, 8, 0, 0x10])):
            with self.assertRaises(ValueError): decode(changed)


if __name__ == '__main__': unittest.main()
