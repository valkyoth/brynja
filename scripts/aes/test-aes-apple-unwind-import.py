#!/usr/bin/env python3
"""Synthetic complete-Mach-O controls for the narrow static unwind binding."""
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('import_fixture', Path(__file__).with_name('test-aes-apple-linked-kernels.py'))
fixture_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture_module)
SPEC_REVIEW = importlib.util.spec_from_file_location('import_review', Path(__file__).with_name('aes_apple_unwind_import.py'))
review = importlib.util.module_from_spec(SPEC_REVIEW)
SPEC_REVIEW.loader.exec_module(review)
BASE = fixture_module.BASE


def fixture(symbol=review.NAME):
    old, _ = fixture_module.fixture()
    image = bytearray(0x4000)
    image[0x400:0x1000] = old[0x400:0x1000]
    image[0x2000:0x3000] = old[0x1000:0x2000]
    strings_size = struct.unpack_from('<I', old, 276)[0]
    name = symbol + b'\0'
    image[0x2100 + strings_size:0x2100 + strings_size + len(name)] = name
    struct.pack_into('<IBBHQ', image, 0x2060, strings_size, 1, 0, 0x100, 0)
    lazy = b'\x71\x00\x11\x40' + name + b'\x90\0'
    image[0x2900:0x2900 + len(lazy)] = lazy
    struct.pack_into('<2I', image, 0x2a00, 6, 6)
    struct.pack_into('<3I', image, 0xe00, 0xb0000010, 0xf9400210, 0xd61f0200)
    struct.pack_into('<Q', image, 0x1000, BASE + 0xe38)
    struct.pack_into('<3I', image, 0xe38, 0x18000050, 0x17fffff9, 0)
    cmds = bytearray()

    def segment(label, address, offset, mode, sections):
        cmds.extend(struct.pack('<II16sQQQQiiII', 0x19, 72 + 80 * len(sections), label,
                                BASE + address, 0x1000 if label != b'__LINKEDIT' else 0x2000,
                                offset, 0x1000 if label != b'__LINKEDIT' else 0x2000, mode, mode, len(sections), 0))
        for section, address, size, pos, flags, first, stride in sections:
            cmds.extend(struct.pack('<16s16sQQ8I', section, label, BASE + address, size, pos,
                                    2, 0, 0, flags, first, stride, 0))
    segment(b'__TEXT', 0, 0, 5, [
        (b'__text', 0x400, 1048, 0x400, 0x80000400, 0, 0),
        (b'__stubs', 0xe00, 12, 0xe00, 0x80000408, 0, 12),
        (b'__stub_helper', 0xe20, 36, 0xe20, 0x80000400, 0, 0)])
    segment(b'__DATA', 0x1000, 0x1000, 3, [(b'__la_symbol_ptr', 0x1000, 8, 0x1000, 7, 1, 0)])
    segment(b'__LINKEDIT', 0x2000, 0x2000, 1, [])
    symcmd = 32 + len(cmds)
    cmds.extend(struct.pack('<6I', 2, 24, 0x2000, 7, 0x2100, strings_size + len(name)))
    cmds.extend(struct.pack('<4I', 0x26, 16, 0x2800, struct.unpack_from('<I', old, 292)[0]))
    dynamic = [0] * 18
    dynamic[1] = 6
    dynamic[4:6] = [6, 1]
    dynamic[12:14] = [0x2a00, 2]
    dysymcmd = 32 + len(cmds)
    cmds.extend(struct.pack('<20I', 0xb, 80, *dynamic))
    dyldcmd = 32 + len(cmds)
    cmds.extend(struct.pack('<12I', 0x80000022, 48, 0, 0, 0, 0, 0, 0, 0x2900, len(lazy), 0, 0))
    dylibcmd = 32 + len(cmds)
    payload = review.LIBRARY + b'\0'
    length = (24 + len(payload) + 7) & ~7
    cmds.extend(struct.pack('<6I', 0xc, length, 24, 0, 0, 0) + payload + b'\0' * (length - 24 - len(payload)))
    struct.pack_into('<8I', image, 0, 0xfeedfacf, 0x100000c, 0, 2, 8, len(cmds), 0x80, 0)
    image[32:32 + len(cmds)] = cmds
    return image, {'symcmd': symcmd, 'dysymcmd': dysymcmd, 'dyldcmd': dyldcmd,
                   'dylibcmd': dylibcmd, 'strings_size': strings_size}


class AppleImportTests(unittest.TestCase):
    def test_memcmp_binding_is_explicit_and_not_interchangeable_with_unwind(self):
        image,_=fixture(b'_memcmp')
        self.assertEqual(review.inspect(image,b'_memcmp')['symbol'],'_memcmp')
        with self.assertRaises(ValueError):review.inspect(image)
        with self.assertRaises(ValueError):review.inspect(fixture()[0],b'_memcmp')
        for name in (b'_bcmp',b'_wrong',b'',None):
            with self.assertRaises(ValueError):review.inspect(image,name)
        for offset in (*range(0xe00,0xe0c), *range(0x1000,0x1008), *range(0xe38,0xe44),
                       *range(0x2900,0x2900+4+len(b'_memcmp')+3)):
            changed=bytearray(image); changed[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(ValueError):review.inspect(changed,b'_memcmp')

    def test_complete_binding(self):
        result = review.inspect(fixture()[0])
        self.assertEqual(result['stub_address'], hex(BASE + 0xe00))
        self.assertEqual(result['pointer_address'], hex(BASE + 0x1000))
        self.assertEqual(result['symbol'], '__Unwind_Resume')

    def test_every_stub_byte_is_checked(self):
        image, _ = fixture()
        for offset in range(0xe00, 0xe0c):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                review.inspect(changed)

    def test_lazy_helper_initial_pointer_and_record(self):
        image, _ = fixture()
        for offset in (*range(0x1000, 0x1008), *range(0xe38, 0xe44)):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                review.inspect(changed)

    def test_indirect_symbol_index_and_symbol_identity(self):
        image, _ = fixture()
        for offset, fmt, value in ((0x2a00, '<I', 0x80000000), (0x2a04, '<I', 5),
                                   (0x2064, '<B', 0xe), (0x2065, '<B', 1),
                                   (0x2066, '<H', 0x140), (0x2066, '<H', 0x200),
                                   (0x2068, '<Q', 1)):
            changed = bytearray(image)
            struct.pack_into(fmt, changed, offset, value)
            with self.assertRaises(ValueError):
                review.inspect(changed)

    def test_library_flags_namespace_and_tables(self):
        image, meta = fixture()
        edits = [(24, '<I', 0), (meta['dylibcmd'], '<I', 0x80000018),
                 (meta['dylibcmd'] + 8, '<I', 0), (meta['dysymcmd'] + 56, '<I', 0),
                 (meta['dysymcmd'] + 60, '<I', 0xffffffff),
                 (meta['dyldcmd'] + 32, '<I', 0x1000), (meta['dyldcmd'] + 24, '<I', 1)]
        for offset, fmt, value in edits:
            changed = bytearray(image)
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                review.inspect(changed)
        with self.assertRaises(ValueError):
            review.inspect(image.replace(b'libSystem.B', b'libWrong_.B'))

    def test_lazy_opcodes_cannot_name_another_binding(self):
        image, _ = fixture()
        for offset in range(0x2900, 0x2900 + 4 + len(review.NAME) + 3):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                review.inspect(changed)

    def test_uleb_and_lazy_record_controls(self):
        for data in (b'', b'\x80', b'\x80\0', b'\xff' * 11, b'\x80' * 9 + b'\x02'):
            with self.assertRaises(ValueError):
                review.uleb(data, 0)
        segment = [{'base': BASE, 'filesz': 16}]
        valid = b'\x70\0\x11\x40__Unwind_Resume\0\x90\0'
        for data in (b'', valid + valid, valid.replace(b'\x90', b'\xa0'), valid.replace(b'\x11', b'\x12')):
            with self.assertRaises(ValueError):
                review.lazy_records(data, segment)


if __name__ == '__main__':
    unittest.main()
