"""Offline saved-caller regressions; these do not execute cryptographic code."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_input as review


class Tests(unittest.TestCase):
    def test_complete_bodies_and_all_bytes(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytes(size)
            refs = [dict(offset=10,symbol='clear',addend=0,trailing=0)]
            pin = (size,review.digest(code),review.digest(review.shared.encoded(refs)))
            with patch.dict(review.PINS,{name:pin}):
                review.body_check(name,code,refs)
                for index in range(size):
                    changed = bytearray(code);changed[index] ^= 1
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)
                for wrong in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.body_check(name,wrong,refs)
                for key,value in (('offset',11),('symbol','other'),('addend',1),('trailing',1)):
                    changed = [refs[0] | {key:value}]
                    with self.assertRaises(ValueError): review.body_check(name,code,changed)
                for wrong in ([],refs+refs):
                    with self.assertRaises(ValueError): review.body_check(name,code,wrong)

    def test_instruction_and_branch_mutants(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytearray(size);sites = set()
            for offset,hexcode in review.LANDMARKS[name]:
                raw = bytes.fromhex(hexcode)
                code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
            for offset,hexcode,target in review.BRANCHES[name]:
                opcode = bytes.fromhex(hexcode)
                width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
                raw = opcode+(target-offset-len(opcode)-width).to_bytes(width,'little',signed=True)
                code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
            review.instructions(name,code)
            for index in sites:
                changed = bytearray(code);changed[index] ^= 1
                with self.assertRaises(ValueError): review.instructions(name,changed)
            with self.assertRaises(ValueError): review.instructions(name,code[:100])

    def bindings(self):
        targets = {review.LIVE:43384,review.dispatch.CLEAR:11520,review.WIPE:11664}
        worker = dict(image_sha256='image',reference_targets=targets | {review.HASH:9568})
        records = {
            review.HASH:dict(image_sha256='image',rva=9568,reference_targets=targets | {review.RECEIVE:5744},
                             unwind=[dict(stack_bytes=2584,chain=None)]),
            review.RECEIVE:dict(image_sha256='image',rva=5744,reference_targets=targets.copy(),
                                unwind=[dict(stack_bytes=296,chain=None)]),
        }
        return dict(dispatcher=worker),records

    def test_incoming_edges_and_same_image(self):
        parent,records = self.bindings()
        review.reconcile(parent,records)
        for name in records:
            for key,value in (('rva',123),('image_sha256','wrong')):
                changed = copy.deepcopy(records);changed[name][key] = value
                with self.assertRaises(ValueError): review.reconcile(parent,changed)
        for name,symbol in ((review.HASH,review.RECEIVE),):
            changed = copy.deepcopy(records);del changed[name]['reference_targets'][symbol]
            with self.assertRaises(ValueError): review.reconcile(parent,changed)
        changed = copy.deepcopy(parent);del changed['dispatcher']['reference_targets'][review.HASH]
        with self.assertRaises(ValueError): review.reconcile(changed,records)

    def test_shared_storage_and_cleanup_targets(self):
        parent,records = self.bindings()
        for name in records:
            for symbol in (review.LIVE,review.dispatch.CLEAR,review.WIPE):
                for missing in (True,False):
                    changed = copy.deepcopy(records)
                    if missing: del changed[name]['reference_targets'][symbol]
                    else: changed[name]['reference_targets'][symbol] += 1
                    with self.assertRaises(ValueError): review.reconcile(parent,changed)

    def test_frame_inventory_rejects_added_fragments_or_changed_size(self):
        parent,records = self.bindings()
        for name in records:
            for frames in ([],records[name]['unwind']*2,[dict(stack_bytes=0,chain=None)],
                           [dict(stack_bytes=records[name]['unwind'][0]['stack_bytes'],chain={})]):
                changed = copy.deepcopy(records);changed[name]['unwind'] = frames
                with self.assertRaises(ValueError): review.reconcile(parent,changed)

    def test_geometry_preserves_unknown_callee_and_wrapper_dependency(self):
        result = review.geometry(review.dispatch.Window(0,65536))
        self.assertEqual(result['hash_rsp_from_high'],-3056)
        self.assertEqual(result['receive_rsp_from_high'],-3360)
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['individual_stack_copies_erased'])
        self.assertTrue(all(c['callee_frame_bytes'] is None for c in result['unknown_callees']))
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.dispatch.Window(low,low+65536)),result)
        slots = {s['name']:s for s in result['spans']}
        self.assertEqual(slots['input snapshot']['bytes'],1024)
        self.assertEqual(slots['SHA-256 workspace']['bytes'],1170)
        self.assertEqual(slots['input snapshot']['offset_from_high']+1024,slots['input header']['offset_from_high'])
        self.assertEqual(slots['input header']['offset_from_high']+32,slots['digest staging']['offset_from_high'])
        self.assertEqual(slots['digest staging']['offset_from_high']+32,slots['SHA-256 workspace']['offset_from_high'])


if __name__ == '__main__': unittest.main()
