"""Offline rehash inspection regressions, not a fresh native crypto campaign."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_rehash as review


class Tests(unittest.TestCase):
    def test_bodies_lengths_and_relocations(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytes(size);refs = [dict(offset=12,symbol='callee',addend=0,trailing=0)]
            pins = (size,review.digest(code),review.digest(review.shared.encoded(refs)))
            with patch.dict(review.PINS,{name:pins}):
                review.body_check(name,code,refs)
                for index in range(size):
                    changed = bytearray(code);changed[index] ^= 1
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.body_check(name,changed,refs)
                for key,value in (('offset',13),('symbol','other'),('addend',1),('trailing',1)):
                    with self.assertRaises(ValueError): review.body_check(name,code,[refs[0] | {key:value}])
                for changed in ([],refs+refs):
                    with self.assertRaises(ValueError): review.body_check(name,code,changed)

    def test_bounds_token_overflow_commit_cleanup_and_abort_landmarks(self):
        for name,(size,_,_) in review.PINS.items():
            code = bytearray(size);sites = set()
            for offset,hexcode in review.LANDMARKS[name]:
                raw = bytes.fromhex(hexcode);code[offset:offset+len(raw)] = raw
                sites.update(range(offset,offset+len(raw)))
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
        targets = {review.borrowed.LIVE:43384,review.dispatch.CLEAR:11520,review.borrowed.WIPE:11664}
        parent = dict(dispatcher=dict(image_sha256='same',reference_targets=targets | {review.REHASH:7264}))
        records = {
            review.REHASH:dict(image_sha256='same',rva=7264,reference_targets=targets | {review.COMPUTE:8176},
                               unwind=[dict(stack_bytes=2504,chain=None)]),
            review.COMPUTE:dict(image_sha256='same',rva=8176,reference_targets=targets.copy(),
                                unwind=[dict(stack_bytes=184,chain=None)]),
        }
        return parent,records,dict(image_sha256='same',reference_targets=targets.copy())

    def test_exact_call_edges_and_image_identity(self):
        parent,records,hashed = self.bindings();review.reconcile(parent,records,hashed)
        for name in records:
            for key,value in (('rva',1),('image_sha256','other')):
                changed = copy.deepcopy(records);changed[name][key] = value
                with self.assertRaises(ValueError): review.reconcile(parent,changed,hashed)
        changed = copy.deepcopy(parent);del changed['dispatcher']['reference_targets'][review.REHASH]
        with self.assertRaises(ValueError): review.reconcile(changed,records,hashed)
        changed = copy.deepcopy(records);del changed[review.REHASH]['reference_targets'][review.COMPUTE]
        with self.assertRaises(ValueError): review.reconcile(parent,changed,hashed)
        with self.assertRaises(ValueError): review.reconcile(parent,records,hashed | {'image_sha256':'other'})

    def test_owner_clearer_and_wipe_agree(self):
        parent,records,hashed = self.bindings()
        for name in records:
            for symbol in (review.borrowed.LIVE,review.dispatch.CLEAR,review.borrowed.WIPE):
                for missing in (True,False):
                    changed = copy.deepcopy(records)
                    if missing: del changed[name]['reference_targets'][symbol]
                    else: changed[name]['reference_targets'][symbol] += 1
                    with self.assertRaises(ValueError): review.reconcile(parent,changed,hashed)
        del hashed['reference_targets'][review.borrowed.WIPE]
        with self.assertRaises(ValueError): review.reconcile(parent,records,hashed)

    def test_frame_inventory_is_not_only_first_fragment(self):
        parent,records,hashed = self.bindings()
        for name in records:
            frames = records[name]['unwind']
            for wrong in ([],frames*2,[frames[0] | {'stack_bytes':0}],[frames[0] | {'chain':{}}]):
                changed = copy.deepcopy(records);changed[name]['unwind'] = wrong
                with self.assertRaises(ValueError): review.reconcile(parent,changed,hashed)

    def test_known_frames_do_not_claim_transitive_or_individual_erasure(self):
        result = review.geometry(review.dispatch.Window(0,65536))
        self.assertEqual(result['rehash_rsp_from_high'],-2976)
        self.assertEqual(result['compute_rsp_from_high'],-3168)
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.dispatch.Window(low,low+65536)),result)
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['individual_stack_copies_erased'])
        self.assertTrue(all(c['callee_frame_bytes'] is None for c in result['unknown_callees']))
        slots = {s['name']:s for s in result['spans']}
        self.assertEqual(slots['workspace']['bytes'],1170)
        self.assertEqual(slots['candidate digest']['bytes'],32)
        self.assertEqual(slots['staging digest']['bytes'],32)
        self.assertEqual(slots['workspace']['offset_from_high']+1170,
                         slots['rehash saved XMM6']['offset_from_high'])


if __name__ == '__main__': unittest.main()
