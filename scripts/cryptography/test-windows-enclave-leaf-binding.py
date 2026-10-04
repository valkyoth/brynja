"""Synthetic no-unwind identity regressions, not native helper qualification."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

import windows_enclave_leaf_binding as model

spec = importlib.util.spec_from_file_location('fixtures', Path(__file__).with_name('test-windows-enclave-wrapper-binding.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
put, ENTRY = fixtures.put, fixtures.ENTRY


def fixture(tail=False):
    obj, image = fixtures.fixture()
    code = b'\xe9\0\0\0\0' if tail else b'\x31\xc0\xc3'
    put(obj, 36, '<I', len(code))
    put(obj, 52, '<H', int(tail))
    obj[100:100+len(code)] = code
    image[512:512+len(code)] = code
    put(image, 1024, '<III', 0x1080, 0x1090, 0x2020)
    if tail:
        put(obj, 200, '<I', 1)
        put(image, 513, '<i', 0x80-5)
    return obj, image


def anchor(image, target=0x1000):
    return dict(entry='verified caller', image_sha256=hashlib.sha256(image).hexdigest(),
                reference_targets={ENTRY: target})


class Tests(unittest.TestCase):
    def test_exact_anchored_match_and_nonclaims(self):
        obj, image = fixture()
        result = model.bind(obj,image,ENTRY,[anchor(image)])
        self.assertEqual((result['rva'], result['size']), (0x1000,3))
        self.assertFalse(result['whole_image_qualified'])
        self.assertFalse(result['instruction_semantics_qualified'])

    def test_all_code_bytes_bound(self):
        obj, image = fixture()
        for offset in range(3):
            changed = image.copy()
            changed[512+offset] ^= 1
            with self.assertRaises(ValueError): model.bind(obj,changed,ENTRY,[anchor(changed)])

    def test_repeated_bytes_need_the_correct_anchor(self):
        obj, image = fixture()
        image[768:771] = image[512:515]
        result = model.bind(obj,image,ENTRY,[anchor(image)])
        self.assertEqual(result['byte_candidates'],2)
        with self.assertRaises(ValueError): model.bind(obj,image,ENTRY,[anchor(image,0x1001)])

    def test_absent_conflicting_or_wrong_image_anchors_reject(self):
        obj, image = fixture()
        for anchors in ([], [anchor(image),anchor(image,0x1100)],
                        [anchor(image) | {'image_sha256': '0'*64}]):
            with self.assertRaises(ValueError): model.bind(obj,image,ENTRY,anchors)

    def test_unwind_overlap_and_writable_or_unmapped_code_reject(self):
        obj, image = fixture()
        for offset, value in ((1024,0x1000),(1024,0x1002),(364,0xe0000020),(336,2)):
            changed = image.copy()
            put(changed,offset,'<I',value)
            with self.assertRaises(ValueError): model.bind(obj,changed,ENTRY,[anchor(changed)])

    def test_complete_tail_jump_binds_destination(self):
        obj, image = fixture(True)
        result = model.bind(obj,image,ENTRY,[anchor(image)])
        self.assertEqual(result['reference_targets'],{'__chkstk':0x1080})
        for delta in (-5,-4,0x70000000):
            changed = image.copy()
            put(changed,513,'<i',delta)
            with self.assertRaises(ValueError): model.bind(obj,changed,ENTRY,[anchor(changed)])

    def test_unknown_relocation_shapes_reject(self):
        obj, image = fixture(True)
        for offset, fmt, value in ((100,'<B',0xe8),(200,'<I',0),(208,'<H',5),(101,'<i',1)):
            changed = obj.copy()
            put(changed,offset,fmt,value)
            with self.assertRaises(ValueError): model.bind(changed,image,ENTRY,[anchor(image)])


if __name__ == '__main__': unittest.main()
