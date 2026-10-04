"""Synthetic PE/COFF parser mutations, not native or signature qualification."""
import struct
import unittest

import windows_enclave_wrapper_binding as model

ENTRY = 'PublicStackFrame'
NAMES = ('__chkstk', 'PublicStackAdmit', 'PublicStackBody', 'PublicStackFinish', 'PublicStackRestore')


def put(data, offset, fmt, *values):
    struct.pack_into(fmt, data, offset, *values)


def fixture(entry=ENTRY):
    names = NAMES if entry == ENTRY else ('__chkstk', 'PublicLockedAdmit', 'PublicRustBody',
                                          'PublicLockedFinish', 'PublicGuardRestore')
    globals_ = () if entry == ENTRY else ('PublicLockedLow', 'PublicLockedHigh')
    refs = [(2 + index * 6, index) for index in range(5)]
    code = b'\x55' + b'\xe8\0\0\0\0\x90' * 5
    for symbol, count in ((5, 4), (6, 3)) if globals_ else ():
        for _ in range(count):
            refs.append((len(code) + 3, symbol))
            code += b'\x48\x8b\x05\0\0\0\0'
    code += b'\x5d\xc3'
    obj = bytearray(1024)
    strings = bytearray(4)
    symbols = (*names, *globals_, entry)
    for index, name in enumerate(symbols):
        offset = len(strings)
        strings.extend(name.encode() + b'\0')
        put(obj, 400 + index * 18, '<IIIhHBB', 0, offset, 0,
            1 if name == entry else 0, 0x20 if name == entry else 0, 2, 0)
    put(strings, 0, '<I', len(strings))
    string_offset = 400 + len(symbols) * 18
    obj[string_offset:string_offset + len(strings)] = strings
    put(obj, 0, '<HHIIIHH', 0x8664, 1, 0, 400, len(symbols), 0, 0)
    obj[20:28] = b'.text$mn'
    put(obj, 28, '<IIIIIIHHI', 0, 0, len(code), 100, 200, 0, len(refs), 0, 0x60500020)
    obj[100:100 + len(code)] = code
    for index, (offset, symbol) in enumerate(refs):
        put(obj, 200 + index * 10, '<IIH', offset, symbol, 4)
    image = bytearray(2048)
    image[:2] = b'MZ'
    put(image, 0x3c, '<I', 64)
    image[64:68] = b'PE\0\0'
    put(image, 68, '<HHIIIHH', 0x8664, 2, 0, 0, 0, 240, 0)
    put(image, 88, '<H', 0x20b)
    put(image, 88 + 108, '<I', 16)
    put(image, 88 + 136, '<II', 0x2000, 12)
    image[328:336] = b'.text\0\0\0'
    put(image, 336, '<IIIIIIHHI', 512, 0x1000, 512, 512, 0, 0, 0, 0, 0x60000020)
    image[368:376] = b'.pdata\0\0'
    put(image, 376, '<IIIIIIHHI', 512, 0x2000, 512, 1024, 0, 0, 0, 0, 0xc0000040)
    image[512:512 + len(code)] = code
    for offset, symbol in refs:
        target = 128 + symbol * 16 if symbol < 5 else 0x1090 + (symbol - 5) * 8
        put(image, 512 + offset, '<i', target - (offset + 4))
    put(image, 1024, '<III', 0x1000, 0x1000 + len(code), 0x2020)
    return obj, image


class BindingTests(unittest.TestCase):
    def test_sequential_globals_bound_without_treating_them_as_calls(self):
        obj, image = fixture('PublicLockedFrame')
        result = model.bind(obj, image, 'PublicLockedFrame')
        self.assertEqual(result['global_target_rvas'], {'PublicLockedLow': 0x2090, 'PublicLockedHigh': 0x2098})
        self.assertEqual(len(result['call_target_rvas']), 5)

    def test_global_type_identity_storage_and_alias_mutations(self):
        obj, image = fixture('PublicLockedFrame')
        refs = model.coff(obj, 'PublicLockedFrame')[1]
        globals_ = [(offset, name) for offset, name in refs if name.startswith('PublicLockedL') or name.startswith('PublicLockedH')]
        for target in (0x1000, 0x2091, 0x3000, 0x2098):
            changed = image.copy()
            offset = globals_[0][0]
            put(changed, 512 + offset, '<i', target - (0x1000 + offset + 4))
            with self.assertRaises(ValueError): model.bind(obj, changed, 'PublicLockedFrame')
        changed = image.copy()
        put(changed, 368 + 36, '<I', 0x40000040)
        with self.assertRaises(ValueError): model.bind(obj, changed, 'PublicLockedFrame')
        changed = obj.copy()
        changed[100 + globals_[0][0] - 3] = 0x90
        with self.assertRaises(ValueError): model.bind(changed, image, 'PublicLockedFrame')
        changed = image.copy()
        for offset, name in globals_:
            target = 0x2090
            put(changed, 512 + offset, '<i', target - (0x1000 + offset + 4))
        with self.assertRaisesRegex(ValueError, 'aliased wrapper globals'):
            model.bind(obj, changed, 'PublicLockedFrame')

    def test_exact_match_and_nonclaims(self):
        obj, image = fixture()
        result = model.bind(obj, image, ENTRY)
        self.assertEqual(result['rva'], 0x1000)
        self.assertEqual(result['size'], 33)
        self.assertFalse(result['whole_image_qualified'])
        self.assertFalse(result['callees_semantically_qualified'])
        self.assertEqual(set(result['call_target_rvas']), set(NAMES))

    def test_every_unrelocated_instruction_byte_bound(self):
        obj, image = fixture()
        relocation_bytes = {2 + index * 6 + byte for index in range(5) for byte in range(4)}
        for offset in range(33):
            if offset in relocation_bytes: continue
            changed = image.copy()
            changed[512 + offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
                model.bind(obj, changed, ENTRY)

    def test_unknown_duplicate_overlapping_and_noncall_relocations(self):
        obj, image = fixture()
        mutations = ((200 + 8, '<H', 5), (200 + 4, '<I', 100),
                     (210 + 4, '<I', 0), (210, '<I', 3),
                     (200, '<I', 0), (200, '<I', 5000), (20 + 32, '<H', 4),
                     (400 + 12, '<h', 1), (400 + 5 * 18 + 8, '<I', 1))
        for offset, fmt, value in mutations:
            changed = obj.copy()
            put(changed, offset, fmt, value)
            with self.assertRaises(ValueError): model.bind(changed, image, ENTRY)

    def test_format_truncation_strings_and_aux_bounds(self):
        obj, image = fixture()
        for cut in (0, 19, 59, 100, 205, 405, 510):
            with self.assertRaises(ValueError): model.bind(obj[:cut], image, ENTRY)
        for cut in (0, 63, 90, 327, 400, 600, 1030):
            with self.assertRaises(ValueError): model.bind(obj, image[:cut], ENTRY)
        for offset, fmt, value in ((0, '<H', 0xaa64), (2, '<H', 97), (16, '<H', 240),
                                  (12, '<I', 100001), (404, '<I', 1),
                                  (508, '<I', 3), (417, '<B', 100)):
            changed = obj.copy()
            put(changed, offset, fmt, value)
            with self.assertRaises(ValueError): model.bind(changed, image, ENTRY)

    def test_pe_machine_extents_execute_and_overlap_fail(self):
        obj, image = fixture()
        mutations = ((68, '<H', 0xaa64), (88, '<H', 0x10b),
                     (88 + 108, '<I', 3), (88 + 140, '<I', 11),
                     (1024, '<I', 0x1001), (1028, '<I', 0x1050),
                     (328 + 36, '<I', 0x40000040),
                     (368 + 12, '<I', 0x1001), (368 + 20, '<I', 512))
        for offset, fmt, value in mutations:
            changed = image.copy()
            put(changed, offset, fmt, value)
            with self.assertRaises(ValueError): model.bind(obj, changed, ENTRY)

    def test_call_targets_cannot_point_outside_or_into_wrapper_or_alias(self):
        obj, image = fixture()
        for delta in (-50000, 50000, -6, 128 + 16 - 6):
            changed = image.copy()
            put(changed, 514, '<i', delta)
            with self.assertRaises(ValueError): model.bind(obj, changed, ENTRY)

    def test_multiple_matches_rejected_even_without_second_function_record(self):
        obj, image = fixture()
        image[800:833] = image[512:545]
        with self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
            model.bind(obj, image, ENTRY)


if __name__ == '__main__':
    unittest.main()
