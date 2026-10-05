"""Focused saved-wrapper review regressions, not native enclave execution."""
import hashlib
import json
import unittest
from unittest.mock import patch

import windows_enclave_wrapper_return as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(s[1]) for n,s in review.BODIES.items()}
        for name,offset,hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)] = code
        for name,offset,opcode,target in review.BRANCHES:
            bodies[name][offset:offset+2] = opcode+(target-offset-2).to_bytes(1,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()}

    def test_instruction_clear_and_return_mutations(self):
        bodies = self.synthetic()
        review.check_instructions(bodies)
        sites = [(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o,2) for n,o,_,_ in review.BRANCHES]
        for name,offset,size in sites:
            for index in range(offset,offset+size):
                changed = bytearray(bodies[name]); changed[index] ^= 1
                with self.assertRaises(ValueError): review.check_instructions(bodies | {name:bytes(changed)})
        with self.assertRaises(ValueError): review.check_instructions({})

    def test_body_hash_population_and_byte_mutations(self):
        bodies = self.synthetic()
        specs = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count = 0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for name,code in bodies.items():
                for index in range(len(code)):
                    changed = bytearray(code); changed[index] ^= 1
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name:bytes(changed)})
                    count += 1
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name:changed})
            with self.assertRaises(ValueError): review.check_bodies({})
            with self.assertRaises(ValueError): review.check_bodies(bodies | {'extra':b''})
        self.assertEqual(count,1038)

    def test_reference_target_kind_addend_and_population(self):
        refs = {n:[dict(offset=1,symbol='callee',trailing=0,addend=0)] for n in review.BODIES}
        pins = {n:hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                for n,r in refs.items()}
        with patch.dict(review.REFERENCES,pins,clear=True):
            review.check_references(refs)
            for name,rows in refs.items():
                changes = [[],rows+rows]
                changes += [[rows[0] | {field:value}] for field,value in
                            (('symbol','other'),('offset',2),('addend',1),('trailing',1))]
                for changed in changes:
                    with self.assertRaises(ValueError): review.check_references(refs | {name:changed})
            with self.assertRaises(ValueError): review.check_references({})

    def cookie_fixture(self):
        row = dict(rva=0x8520,virtual_size=len(review.COOKIE),code=review.COOKIE,flags=0x60000020)
        record = dict(reference_targets={'__security_check_cookie':0x8520,'__security_cookie':0x11000})
        return row,record

    def test_cookie_success_body_and_failure_boundary(self):
        row,record = self.cookie_fixture()
        metadata = dict(rva=0xf378,virtual_size=4,code=b'\x01\0\0\0',flags=0x40000040)
        functions = [(0x8520,0x853e,0xf378)]
        result = review.cookie_check([row,metadata],functions,record)
        self.assertEqual(result['normal_return_offset'],20)
        self.assertEqual(result['fatal_tail_rva'],0x8900)
        self.assertFalse(result['failure_cleanup_qualified'])
        for index in range(len(review.COOKIE)):
            changed = bytearray(review.COOKIE); changed[index] ^= 1
            with self.assertRaises(ValueError): review.cookie_check([row | {'code':bytes(changed)},metadata],functions,record)
        for symbol in record['reference_targets']:
            changed = dict(record,reference_targets=dict(record['reference_targets']))
            changed['reference_targets'][symbol] += 1
            with self.assertRaises(ValueError): review.cookie_check([row,metadata],functions,changed)
        for wrong in ([],[(0x8520,0x853e,0)],[(0x853d,0x8540,0)],functions+functions):
            with self.assertRaises(ValueError): review.cookie_check([row,metadata],wrong,record)
        with self.assertRaises(ValueError): review.cookie_check([row,row,metadata],functions,record)
        for index in range(4):
            changed = bytearray(metadata['code']); changed[index] ^= 1
            with self.assertRaises(ValueError):
                review.cookie_check([row,metadata | {'code':bytes(changed)}],functions,record)

    def test_full_window_word_coverage_and_translation(self):
        for low in (0,4096,0x700000000000):
            result = review.geometry(review.Window(low,low+65536))
            self.assertEqual(result['words'],8192)
            self.assertEqual(result['bytes'],65536)
            self.assertEqual(result['first']['offset_from_low'],0)
            self.assertEqual(result['last']['offset_from_low'],65528)
            self.assertEqual(result['last']['bytes'],8)
            self.assertEqual(result['callback_rsp_from_low'],-4128)
            self.assertFalse(result['callback_stack_inside_cleared_window'])
        for low,high in ((1,65537),(0,65535),(4096,65536)):
            with self.assertRaises(ValueError): review.geometry(review.Window(low,high))


if __name__ == '__main__': unittest.main()
