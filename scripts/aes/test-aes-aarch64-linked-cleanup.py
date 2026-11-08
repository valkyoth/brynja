#!/usr/bin/env python3
"""ARM cleanup and ELF unwind-import regressions without retained AWS bundles."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tomllib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('arm_cleanup_fixtures', Path(__file__).with_name('test-aes-aarch64-linked.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
c = fixtures.runner.cleanup
r = fixtures.r
CASES = json.loads(Path(__file__).with_name('aarch64-linked-cleanup-fixtures.json').read_text())


def body_fixture(config):
    body = CASES[config]
    row, targets, raw = body['row'], body['targets'], bytes.fromhex(body['raw'])
    # Sparse synthetic RX image retaining the real call displacements. Callee
    # bodies are reviewed separately; this fixture tests caller policy binding.
    size = max(row[1]+row[2], *(a+n for _, a, n in targets.values()))
    image = bytearray(size + 0x200)
    image[:64] = fixtures.image(b'')[:64]
    struct.pack_into('<H', image, 56, 1)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0x200, 0, 0, size, size, 0x1000)
    image[0x200+row[1]:0x200+row[1]+row[2]] = raw
    return list(body['lines']), raw, row, bytes(image), targets


def import_fixture():
    image = bytearray(0xa00)
    image[:64] = fixtures.image(b'')[:64]
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0x200, 0x1000, 0, 0x200, 0x200, 0x1000)
    struct.pack_into('<H', image, 56, 3)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, 0x400, 0x2000, 0, 0x100, 0x100, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, 0x440, 0x2040, 0, 128, 128, 8)
    for i, (tag, value) in enumerate(((2, 24), (5, 0x1130), (6, 0x1100),
                                     (10, 16), (11, 24), (20, 7), (23, 0x1150), (0, 0))):
        struct.pack_into('<qQ', image, 0x440+i*16, tag, value)
    struct.pack_into('<Q', image, 40, 0x600)
    struct.pack_into('<HHH', image, 58, 64, 6, 1)
    names = b'\0.shstrtab\0.dynsym\0.dynstr\0.rela.plt\0.plt\0'
    image[0x500:0x500+len(names)] = names
    def section(index, name, kind, flags, address, offset, size, link=0, entry=0):
        struct.pack_into('<IIQQQQIIQQ', image, 0x600+index*64, names.index(name.encode()),
                         kind, flags, address, offset, size, link, 0, 8, entry)
    section(1, '.shstrtab', 3, 0, 0, 0x500, len(names))
    section(2, '.dynsym', 11, 2, 0x1100, 0x300, 48, 3, 24)
    section(3, '.dynstr', 3, 2, 0x1130, 0x330, 16)
    section(4, '.rela.plt', 4, 66, 0x1150, 0x350, 24, 2, 24)
    section(5, '.plt', 1, 6, 0x1000, 0x200, 16)
    image[0x330:0x340] = b'\0_Unwind_Resume\0'.ljust(16, b'\0')
    struct.pack_into('<IBBHQQ', image, 0x318, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into('<QQq', image, 0x350, 0x2008, (1 << 32) | 1026, 0)
    words = (0xb0000010, 0xf9400611, 0x91002210, 0xd61f0220)
    struct.pack_into('<IIII', image, 0x200, *words)
    lines = ['adrp x16, 0x2000 <pool>', 'ldr x17, [x16, #8]',
             'add x16, x16, #8', 'br x17']
    assembly = 'file format elf64-littleaarch64\n0000000000001000 <_Unwind_Resume@plt>:\n'
    assembly += ''.join(f' {0x1000+i*4:x}: {word:08x} {line}\n' for i, (word, line) in enumerate(zip(words, lines)))
    return assembly, bytes(image)


class Aarch64LinkedCleanupTests(unittest.TestCase):
    def test_real_cleanup_all_profiles_and_instruction_deletions(self):
        for config in CASES:
            compiler, panic = config.split('/')
            args = body_fixture(config)
            self.assertEqual(c.check(*args, 'key128', compiler, panic)['instructions'], 30 if panic == 'abort' else 48)
            self.assertEqual(c.mutations(*args, 'key128', compiler, panic), 62 if panic == 'abort' else 99)

    def test_indirect_callback_is_explicit_and_encoding_bound(self):
        args = body_fixture('1.90.0/abort')
        with self.assertRaises(ValueError): r.observe(*args)
        self.assertEqual(r.observe(*args, callback=True)[0]['indirect_calls'], 1)
        lines, raw, row, image, targets = args
        index = lines.index('blr x8')
        for value in ('blr x9', 'br x8', 'ret', 'nop'):
            changed = list(lines); changed[index] = value
            with self.assertRaises(ValueError):
                c.check(changed, raw, row, image, targets, 'key128', '1.90.0', 'abort')
        changed = list(lines); changed[0] = 'blr x8'
        with self.assertRaises(ValueError): r.observe(changed, raw, row, image, targets, callback=True)

    def test_scope_profile_width_and_target_population(self):
        args = body_fixture('1.90.0/abort')
        for role, compiler, panic in (('key192', '1.90.0', 'abort'), ('key128', 'stable', 'abort'),
                                     ('key128', '1.90.0', 'unwind'), ('key128', '1.99.1', 'abort')):
            with self.assertRaises(ValueError): c.check(*args, role, compiler, panic)
        policy = json.loads(c.POLICY.read_text())
        for key, value in (('schema', 2), ('target', 'x86_64'), ('profile', 'debug'), ('review', 'wrong')):
            changed = copy.deepcopy(policy); changed[key] = value
            with self.assertRaises(ValueError): c.check(*args, 'key128', '1.90.0', 'abort', changed)
        changed = copy.deepcopy(policy); del changed['configurations']['1.99.1/unwind']
        with self.assertRaises(ValueError): c.check(*args, 'key128', '1.90.0', 'abort', changed)
        with self.assertRaises(ValueError): c.check(*args[:-1], {}, 'key128', '1.90.0', 'abort')

    def test_resume_binding_and_all_encoding_and_metadata_mutations(self):
        args = import_fixture()
        self.assertEqual(c.resume_target(*args), ('_Unwind_Resume@plt', 0x1000, 16))
        self.assertEqual(c.resume_mutations(*args), 133)

    def test_resume_rejects_coherent_wrong_got_destination(self):
        assembly, image = import_fixture()
        changed = bytearray(image)
        struct.pack_into('<II', changed, 0x204, 0xf9400a11, 0x91004210)
        assembly = assembly.replace('f9400611', 'f9400a11').replace('91002210', '91004210').replace('#8', '#16')
        with self.assertRaisesRegex(ValueError, 'GOT relocation mismatch'): c.resume_target(assembly, changed)

    def test_resume_section_bounds_links_and_strings(self):
        assembly, image = import_fixture()
        for offset, fmt, value in ((40, '<Q', len(image)), (58, '<H', 63), (60, '<H', 4096),
                                  (62, '<H', 0), (0x600+4*64+40, '<I', 3),
                                  (0x600+2*64+56, '<Q', 16), (0x318+6, '<H', 1),
                                  (0x318, '<I', 16), (0x350+16, '<q', 1),
                                  (0x600+3*64+24, '<Q', 0x1140)):
            changed = bytearray(image); struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): c.resume_target(assembly, changed)
        with self.assertRaises(ValueError): c.resume_target(assembly+assembly, image)
        for data, offset in ((b'abc', 0), (b'\xff\0', 0), (b'a\0', 2)):
            with self.assertRaises(ValueError): c.cstring(data, offset)

    def test_sections_must_match_live_dynamic_import_tables(self):
        assembly, image = import_fixture()
        for offset, fmt, value in ((176, '<I', 0), (176+8, '<Q', 0x448),
                                  (0x440+8, '<Q', 48), (0x450+8, '<Q', 0x1138),
                                  (0x460+8, '<Q', 0x1118), (0x470+8, '<Q', 8),
                                  (0x480+8, '<Q', 16), (0x490+8, '<Q', 17),
                                  (0x4a0+8, '<Q', 0x1168), (0x450, '<q', 2),
                                  (0x4b0+8, '<Q', 1)):
            changed = bytearray(image); struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): c.resume_target(assembly, changed)

    def test_cleanup_cannot_overlap_helpers(self):
        selected = {role: (role, 0x2000+i*0x100, 4) for i, role in enumerate(c.WIDTHS)}
        with patch.object(c.names, 'candidates', return_value=selected):
            self.assertEqual(c.select('', {'zeroize': ('zeroize', 0x1000, 4)}), selected)
            with self.assertRaises(ValueError): c.select('', {'zeroize': ('zeroize', 0x2000, 4)})

    def test_registration_fingerprints_cleanup_review(self):
        registry = tomllib.loads((fixtures.runner.ROOT / 'verification/checks.toml').read_text())
        paths = registry['groups']['aes-arm-linked-review']['paths']
        for name in ('aes_aarch64_linked_cleanup.py', 'aarch64-linked-cleanup-review.json',
                     'aarch64-linked-cleanup-fixtures.json', 'test-aes-aarch64-linked-cleanup.py'):
            self.assertIn('scripts/aes/' + name, paths)


if __name__ == '__main__':
    unittest.main()
