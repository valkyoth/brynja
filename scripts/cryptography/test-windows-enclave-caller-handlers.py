"""Synthetic COFF funclet/handler identity checks; no exception execution claim."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

import windows_enclave_caller_handlers as model

spec = importlib.util.spec_from_file_location('wrapper_fixture', Path(__file__).with_name('test-windows-enclave-wrapper-binding.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
put = fixtures.put
ENTRY, CHILD = 'parent', '?dtor$1@parent'


def fixture():
    _, image = fixtures.fixture()
    data = bytearray(4096)
    put(data, 0, '<HHIIIHH', 0x8664, 3, 0, 2048, 10, 0, 0)
    for i, (name, length, raw, reloc, count, flags) in enumerate((
            (b'.text', 56, 512, 768, 5, 0x60000020),
            (b'.pdata', 24, 1024, 1100, 6, 0x40000040),
            (b'.xdata', 20, 1280, 1350, 1, 0x40000040))):
        at = 20 + i*40
        data[at:at+8] = name.ljust(8, b'\0')
        put(data, at+8, '<IIIIIIHHI', 0, 0, length, raw, reloc, 0, count, 0, flags)
    strings = bytearray(4)
    names = (ENTRY, CHILD, '.text', '.xdata', *fixtures.NAMES, 'handler')
    for i, name in enumerate(names):
        offset = len(strings)
        strings.extend(name.encode()+b'\0')
        put(data, 2048+i*18, '<IIIhHBB', 0, offset, 48 if i == 1 else 0,
            1 if i < 3 else 3 if i == 3 else 0, 32 if i < 2 else 0, 2, 0)
    put(strings, 0, '<I', len(strings))
    data[2228:2228+len(strings)] = strings
    data[512:545] = b'\x55' + b'\xe8\0\0\0\0\x90'*5 + b'\x5d\xc3'
    data[560:568] = image[560:568] = bytes.fromhex('554889e55dc39090')
    for i in range(5): put(data, 768+i*10, '<IIH', 2+i*6, 4+i, 4)
    for i, (addend, symbol) in enumerate(((0, 0), (33, 0), (0, 3), (0, 1), (8, 1), (16, 3))):
        put(data, 1024+i*4, '<I', addend)
        put(data, 1100+i*10, '<IIH', i*4, symbol, 3)
    data[1280:1284] = bytes([25, 0, 0, 0])
    put(data, 1288, '<I', 0x55aa)
    data[1296:1300] = bytes([1, 0, 0, 0])
    put(data, 1350, '<IIH', 4, 9, 3)
    put(image, 228, '<I', 24)
    put(image, 1036, '<III', 0x1030, 0x1038, 0x2030)
    image[1056:1076] = data[1280:1300]
    put(image, 1060, '<I', 0x1100)
    return data, image


class Tests(unittest.TestCase):
    def test_parent_and_interior_funclet_have_exact_distinct_ranges(self):
        data, image = fixture()
        parent = model.bind(data, image, ENTRY)
        child = model.bind(data, image, CHILD)
        self.assertEqual((parent['rva'], parent['size']), (0x1000, 33))
        self.assertEqual((child['rva'], child['size']), (0x1030, 8))
        self.assertEqual(parent['handler']['symbol'], 'handler')
        self.assertIsNone(child['handler'])
        for r in (parent, child):
            self.assertFalse(r['handler_semantics_qualified'])
            self.assertFalse(r['whole_image_qualified'])
        self.assertEqual(parent['xdata_rva'], child['xdata_rva'])

    def test_object_runtime_bounds_types_and_completeness(self):
        for offset, fmt, bad in ((1118, '<H', 4), (1104, '<I', 9999), (1100, '<I', 1),
                                 (1110, '<I', 0), (1028, '<I', 57), (1028, '<I', 0),
                                 (1044, '<I', 21), (1144, '<I', 3), (76, '<I', 1025)):
            data, image = fixture()
            put(data, offset, fmt, bad)
            with self.assertRaises(ValueError): model.bind(data, image, ENTRY)
        for length in (0, 19, 130, 1026, 2050, 2230):
            with self.assertRaises(ValueError): model.bind(fixture()[0][:length], fixture()[1], ENTRY)

    def test_code_extent_cannot_absorb_padding_or_another_funclet(self):
        for offset, value in ((1028, 48), (1028, 56), (2074, 16)):
            data, image = fixture()
            put(data, offset, '<I', value)
            with self.assertRaises(ValueError): model.bind(data, image, ENTRY)

    def test_all_handler_payload_bytes_and_relocation_kinds_bound(self):
        data, image = fixture()
        for offset in (1056, 1057, 1058, 1059, *range(1064, 1076)):
            changed = image.copy()
            changed[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'nonrelocated'): model.bind(data, changed, ENTRY)
        for offset, fmt, bad in ((1358, '<H', 4), (1350, '<I', 18), (1354, '<I', 50)):
            changed = data.copy()
            put(changed, offset, fmt, bad)
            with self.assertRaises(ValueError): model.bind(changed, image, ENTRY)

    def test_handler_must_point_to_nonwritable_code(self):
        for target in (0x2020, 0x9000):
            data, image = fixture()
            put(image, 1060, '<I', target)
            with self.assertRaises(ValueError): model.bind(data, image, ENTRY)

    def test_unwind_codes_and_prologue_are_bounded_even_when_both_files_match(self):
        for offset, value in ((1, 34), (2, 255)):
            data, image = fixture()
            data[1280+offset] = image[1056+offset] = value
            with self.assertRaisesRegex(ValueError, 'bounded unwind'): model.bind(data, image, ENTRY)
        data, image = fixture()
        put(data, 136, '<I', 0xc0000040)
        with self.assertRaisesRegex(ValueError, 'xdata section'): model.bind(data, image, ENTRY)

    def test_interior_reference_cannot_cross_function_boundary(self):
        data, image = fixture()
        put(data, 768, '<I', 31)
        with self.assertRaisesRegex(ValueError, 'function reference'): model.bind(data, image, ENTRY)

    def test_function_code_permission_identity_and_actual_bytes(self):
        data, image = fixture()
        for offset, value in ((56, 0xe0000020), (2056, 1)):
            changed = data.copy()
            put(changed, offset, '<I', value)
            with self.assertRaises(ValueError): model.bind(changed, image, ENTRY)
        image[564] ^= 1
        with self.assertRaisesRegex(ValueError, 'one caller candidate'): model.bind(data, image, CHILD)

    def test_unsupported_unwind_version_and_chain_do_not_pass(self):
        for header in (2, 33, 57):
            data, image = fixture()
            data[1280] = image[1056] = header
            with self.assertRaisesRegex(ValueError, 'version-one'): model.bind(data, image, ENTRY)

    def test_internal_metadata_relocations_bind_section_and_code_offsets(self):
        for symbol, expected in ((0, 0x1000), (1, 0x1030), (3, 0x2020)):
            data, image = fixture()
            put(data, 1354, '<I', symbol)
            put(image, 1060, '<I', expected+1)
            with self.assertRaisesRegex(ValueError, 'reference identity'): model.bind(data, image, ENTRY)

    def test_ambiguous_code_requires_verified_incoming_constraint(self):
        data, image = fixture()
        image[800:833] = image[512:545]
        with self.assertRaisesRegex(ValueError, 'one caller candidate'): model.bind(data, image, ENTRY)
        anchor = dict(entry='already-verified-caller', image_sha256=hashlib.sha256(image).hexdigest(),
                      reference_targets={ENTRY: 0x1000})
        result = model.bind(data, image, ENTRY, [anchor])
        self.assertEqual(result['byte_candidates'], 2)
        with self.assertRaisesRegex(ValueError, 'image identity'):
            model.bind(data, image, ENTRY, [anchor | dict(image_sha256='0'*64)])
        with self.assertRaisesRegex(ValueError, 'agreement'):
            model.bind(data, image, ENTRY, [anchor, anchor | dict(reference_targets={ENTRY: 0x1120})])
        with self.assertRaisesRegex(ValueError, 'runtime extent'):
            model.bind(data, image, ENTRY, [anchor | dict(reference_targets={ENTRY: 0x1120})])


if __name__ == '__main__': unittest.main()
