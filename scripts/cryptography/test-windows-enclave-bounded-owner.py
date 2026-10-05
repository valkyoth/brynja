"""Offline owner/wipe regressions, not cryptographic execution tests."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_owner as review


def wipe_fixture():
    def imm(value): return value.to_bytes(4,'little',signed=True)
    code = bytes.fromhex('564883ec204889ce4881c1')+imm(1024)+b'\xba'+imm(64)+b'\xe8'+bytes(4)
    code += b'\xba'+imm(128)+bytes.fromhex('4889f1e800000000')
    for start,size in ((1152,16),(1168,2),(128,640),(768,128),(896,128)):
        code += bytes.fromhex('488d8e')+imm(start)+b'\xba'+imm(size)+b'\xe8'+bytes(4)
    code += bytes.fromhex('4881c6')+imm(1088)+b'\xba'+imm(64)+bytes.fromhex('4889f14883c4205ee900000000')
    refs = [dict(offset=o,symbol=review.dispatch.CLEAR,trailing=0,addend=0) for o in (21,34,51,68,85,102,119,144)]
    return code,refs


class Tests(unittest.TestCase):
    def test_decoded_wipe_rejects_every_shape_or_operand_byte_mutation(self):
        code,refs = wipe_fixture()
        self.assertEqual(review.wipe_plan(code,refs),[dict(offset=s,bytes=n) for s,n in review.RANGES])
        for index in range(len(code)):
            changed = bytearray(code);changed[index] ^= 1
            with self.assertRaises(ValueError): review.wipe_plan(changed,refs)
        for changed in (code[:-1],code+b'\0'):
            with self.assertRaises(ValueError): review.wipe_plan(changed,refs)
        for index in range(len(refs)):
            for key,value in (('offset',0),('symbol','other'),('addend',1),('trailing',1)):
                changed = copy.deepcopy(refs);changed[index][key] = value
                with self.assertRaises(ValueError): review.wipe_plan(code,changed)
        for changed in ([],refs[:-1],refs+refs[:1]):
            with self.assertRaises(ValueError): review.wipe_plan(code,changed)

    def test_coverage_is_complete_without_overlap_or_gaps(self):
        review.coverage(review.RANGES)
        self.assertEqual(sum(n for _,n in review.RANGES),1170)
        for index,(start,size) in enumerate(review.RANGES):
            for replacement in ((start,0),(start,size-1),(start,size+1),(start+1,size),(-1,size)):
                ranges = list(review.RANGES);ranges[index] = replacement
                with self.assertRaises(ValueError): review.coverage(ranges)
        with self.assertRaises(ValueError): review.coverage(review.RANGES[:-1])
        with self.assertRaises(ValueError): review.coverage(review.RANGES+((1170,1),))

    def test_complete_body_and_reference_pins(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytes(size);refs = [dict(offset=10,symbol='callee',addend=0,trailing=0)]
            with patch.dict(review.PINS,{name:(size,review.digest(code),review.digest(review.shared.encoded(refs)))}):
                review.body_check(name,code,refs)
                for index in range(size):
                    changed = bytearray(code);changed[index] ^= 1
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)
                with self.assertRaises(ValueError): review.body_check(name,code,[])
                with self.assertRaises(ValueError): review.body_check(name,code+b'\0',refs)

    def test_placement_bounds_generation_commit_and_cleanup_branches(self):
        code = bytearray(439);sites = set()
        for offset,hexcode in review.LANDMARKS:
            raw = bytes.fromhex(hexcode);code[offset:offset+len(raw)] = raw
            sites.update(range(offset,offset+len(raw)))
        for offset,hexcode,target in review.BRANCHES:
            opcode = bytes.fromhex(hexcode);width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
            raw = opcode+(target-offset-len(opcode)-width).to_bytes(width,'little',signed=True)
            code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
        review.placement_instructions(code)
        for index in sites:
            changed = bytearray(code);changed[index] ^= 1
            with self.assertRaises(ValueError): review.placement_instructions(changed)

    def bindings(self):
        clear = dict(image_sha256='same',rva=11520)
        targets = {review.dispatch.CLEAR:11520,review.WIPE:11664,review.PLACED:13552}
        anchors = {n:dict(image_sha256='same',reference_targets=targets.copy()) for n in
                   (review.borrowed.HASH,review.borrowed.RECEIVE,review.rehash.REHASH,review.rehash.COMPUTE)}
        records = {n:dict(image_sha256='same',rva=r,reference_targets=targets.copy(),
                         unwind=[dict(stack_bytes=s,chain=None)]) for n,r,s in
                   ((review.WIPE,11664,40),(review.PLACED,13552,120))}
        return records,anchors,clear

    def test_all_incoming_edges_and_shared_leaf_identity(self):
        records,anchors,clear = self.bindings();review.reconcile(records,anchors,clear)
        for group in ('records','anchors'):
            for name in records if group == 'records' else anchors:
                for field in ('image_sha256',review.dispatch.CLEAR,review.WIPE):
                    if name == review.WIPE and field == review.WIPE: continue
                    rs,ans = copy.deepcopy(records),copy.deepcopy(anchors)
                    target = (rs if group == 'records' else ans)[name]
                    if field == 'image_sha256': target[field] = 'other'
                    else: del target['reference_targets'][field]
                    with self.assertRaises(ValueError): review.reconcile(rs,ans,clear)
        for name in anchors:
            changed = copy.deepcopy(anchors);del changed[name]
            with self.assertRaises(ValueError): review.reconcile(records,changed,clear)
        changed = copy.deepcopy(anchors);changed[review.borrowed.RECEIVE]['reference_targets'][review.PLACED] += 1
        with self.assertRaises(ValueError): review.reconcile(records,changed,clear)

    def test_whole_frame_inventory(self):
        records,anchors,clear = self.bindings()
        for name in records:
            frames = records[name]['unwind']
            for wrong in ([],frames*2,[frames[0] | {'stack_bytes':0}],[frames[0] | {'chain':{}}]):
                changed = copy.deepcopy(records);changed[name]['unwind'] = wrong
                with self.assertRaises(ValueError): review.reconcile(changed,anchors,clear)

    def test_geometry_preserves_tail_and_unknown_depth_limits(self):
        result = review.geometry(review.dispatch.Window(0,65536))
        self.assertEqual(result['placement_rsp_from_high'],-3488)
        self.assertEqual(result['wipe_rsp_from_high'],-3536)
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['individual_stack_copies_erased'])
        self.assertFalse(result['clearing_tail_call_allocates_frame'])
        self.assertIsNone(result['unknown_callee']['callee_frame_bytes'])
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.dispatch.Window(low,low+65536)),result)


if __name__ == '__main__': unittest.main()
