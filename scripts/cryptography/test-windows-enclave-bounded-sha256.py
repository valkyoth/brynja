"""Offline binding/inspection regressions, not native SHA-256 execution."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_sha256 as review


def fixture(name):
    code = bytearray(review.PINS[name][0]);sites = set()
    for offset,hexcode in review.LANDMARKS[name]:
        raw = bytes.fromhex(hexcode);code[offset:offset+len(raw)] = raw
        sites.update(range(offset,offset+len(raw)))
    for offset,hexcode,target in review.BRANCHES.get(name,()):
        opcode = bytes.fromhex(hexcode);width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
        raw = opcode+(target-offset-len(opcode)-width).to_bytes(width,'little',signed=True)
        code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
    if name == review.FINAL:
        code[0x153:0x170] = bytes.fromhex('4c8db640040000ba0400000041b9040000004c89f14d89e0e800000000')
        for i in range(1,8):
            at = 0x170+30*(i-1)
            code[at:at+30] = (bytes.fromhex('4c8d86')+(1024+4*i).to_bytes(4,'little')+
                             bytes.fromhex('488d8e')+(1088+4*i).to_bytes(4,'little')+
                             bytes.fromhex('ba0400000041b904000000e800000000'))
        sites.update(range(0x153,0x242))
    return code,sites


class Tests(unittest.TestCase):
    def test_complete_body_reference_and_extent_pins(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytes(size);refs = [dict(offset=10,symbol='callee',addend=0,trailing=0)]
            with patch.dict(review.PINS,{name:(size,review.digest(code),review.digest(review.shared.encoded(refs)))}):
                review.body_check(name,code,refs)
                for index in range(size):
                    changed = bytearray(code);changed[index] ^= 1
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)
                for changed in ([],refs*2,[refs[0] | {'addend':1}],[refs[0] | {'symbol':'other'}]):
                    with self.assertRaises(ValueError): review.body_check(name,code,changed)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)

    def test_update_admission_and_error_commit_branches(self):
        self.check_instructions(review.UPDATE)

    def test_finalize_padding_render_output_error_and_wipe_paths(self):
        self.check_instructions(review.FINAL)
        code,_ = fixture(review.FINAL)
        self.assertEqual(review.render_plan(code),[dict(source=1024+4*i,destination=1088+4*i,bytes=4) for i in range(8)])

    def test_copy_length_gate_leaf_loop_and_scalar_erasure(self):
        for name in (review.COPY,review.BYTES,review.SCALAR): self.check_instructions(name)

    def check_instructions(self,name):
        code,sites = fixture(name);review.instructions(name,code)
        for index in sorted(sites):
            changed = code.copy();changed[index] ^= 1
            with self.assertRaises(ValueError): review.instructions(name,changed)

    def test_actual_round_table_rejects_every_byte_change(self):
        # The exact saved little-endian table, checked independently of code pins.
        raw = bytes.fromhex(
            '982f8a4291443771cffbc0b5a5dbb5e95bc25639f111f159a4823f92d55e1cab'
            '98aa07d8015b8312be853124c37d0c55745dbe72feb1de80a706dc9b74f19bc1'
            'c1699be48647beefc69dc10fcca10c246f2ce92daa84744adca9b05cda88f9765'
            '2513e986dc631a8c82703b0c77f59bff30be0c64791a7d55163ca066729291485'
            '0ab72738211b2efc6d2c4d130d385354730a65bb0a6a762ec9c281852c7292a1'
            'e8bfa24b661aa8708b4bc2a3516cc719e892d1240699d685350ef470a06a1016c'
            '1a419086c371e4c774827b5bcb034b30c1c394aaad84e4fca9c5bf36f2e68ee8'
            '28f746f63a5781478c8840802c78cfaffbe90eb6c50a4f7a3f9bef27871c6')
        review.table_bytes(raw)
        for i in range(256):
            changed = bytearray(raw);changed[i] ^= 1
            with self.assertRaises(ValueError): review.table_bytes(changed)
        for changed in (raw[:-1],raw+bytes(1),raw[::-1]):
            with self.assertRaises(ValueError): review.table_bytes(changed)

    def bindings(self):
        sizes = {review.UPDATE:120,review.FINAL:104,review.SCALAR:16,review.COPY:40}
        targets = {n:1000+i*100 for i,n in enumerate(review.PINS)}
        targets |= {review.owner.WIPE:11664,review.dispatch.CLEAR:11520,review.TABLE:33028}
        records = {n:dict(image_sha256='same',rva=targets[n],
                         reference_targets={e:targets[e] for e in review.EDGES[n]}) for n in review.PINS}
        for n,s in sizes.items(): records[n]['unwind'] = [dict(stack_bytes=s,chain=None)]
        anchors = {n:dict(image_sha256='same',reference_targets=targets.copy()) for n in (review.owner.PLACED,review.rehash.COMPUTE)}
        wipe = dict(image_sha256='same',rva=11664)
        clear = dict(image_sha256='same',rva=11520)
        return records,anchors,wipe,clear,dict(rva=33028)

    def test_closed_callee_inventory_and_incoming_identity(self):
        args = self.bindings();review.reconcile(*args)
        for index in (0,1):
            for name in args[index]:
                changed = copy.deepcopy(args);changed[index][name]['image_sha256'] = 'other'
                with self.assertRaises(ValueError): review.reconcile(*changed)
                edges = review.EDGES[name] if index == 0 else (review.UPDATE,review.FINAL,review.owner.WIPE,review.dispatch.CLEAR)
                for edge in edges:
                    for missing in (True,False):
                        changed = copy.deepcopy(args);refs = changed[index][name]['reference_targets']
                        if missing: del refs[edge]
                        else: refs[edge] += 1
                        with self.assertRaises(ValueError): review.reconcile(*changed)
                changed = copy.deepcopy(args);del changed[index][name]
                with self.assertRaises(ValueError): review.reconcile(*changed)
        for name in review.PINS:
            changed = copy.deepcopy(args);changed[0][name]['reference_targets']['surprise'] = 1
            with self.assertRaises(ValueError): review.reconcile(*changed)

    def test_fixed_frames_reject_unknown_or_chained_extent(self):
        args = self.bindings()
        for name,record in args[0].items():
            if name == review.BYTES: continue
            frames = record['unwind']
            for bad in ([],frames*2,[frames[0] | {'chain':{}}],[frames[0] | {'stack_bytes':0}]):
                changed = copy.deepcopy(args);changed[0][name]['unwind'] = bad
                with self.assertRaises(ValueError): review.reconcile(*changed)

    def test_operation_geometry_without_invented_leaf_alignment(self):
        result = review.geometry(review.dispatch.Window(0,65536))
        for key,value in (('update',-3616),('finalize',-3600),('copy',-3664),('scalar',-3640)):
            self.assertEqual(result[key+'_rsp_from_high'],value)
        self.assertEqual(result['deepest_operation_rsp_from_high'],-3672)
        self.assertTrue(result['finalize_wipe_tail_reuses_entry'])
        self.assertTrue(result['operation_chain_depth_reviewed'])
        self.assertFalse(result['maximum_whole_image_depth_qualified'])
        self.assertFalse(result['individual_caller_stack_copies_erased'])
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.dispatch.Window(low,low+65536)),result)


if __name__ == '__main__': unittest.main()
