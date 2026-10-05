"""Review-binding/geometry regressions, not execution of the Rust slot algorithm."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_slot_review as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(spec[1]) for n,spec in review.BODIES.items()}
        refs = {}
        for name, calls in review.CALLS.items():
            refs[name] = [dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
            for offset in calls: bodies[name][offset-1:offset+4] = b'\xe8\0\0\0\0'
        for name, offset, hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)] = code
        for name, offset, opcode, target in review.BRANCHES:
            width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
            end = offset+len(opcode)+width
            bodies[name][offset:end] = opcode+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_all_named_instruction_sites(self):
        bodies,refs = self.synthetic()
        review.check_instructions(bodies,refs)
        self.assertEqual((len(review.ANCHORS),len(review.BRANCHES),sum(map(len,review.CALLS.values()))),
                         (17,19,16))
        sites = [(n,o-1,5) for n,calls in review.CALLS.items() for o in calls]
        sites += [(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1))
                  for n,o,op,_ in review.BRANCHES]
        for name,offset,size in sites:
            for index in range(offset,offset+size):
                changed = bytearray(bodies[name])
                changed[index] ^= 1
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies|{name:bytes(changed)},refs)

    def test_calls_cannot_disappear_alias_or_change_target(self):
        bodies,refs = self.synthetic()
        for name,rows in refs.items():
            variants = [rows[:-1], rows+[rows[0]]]
            for key,value in (('offset',0),('symbol','wrong'),('trailing',1),('addend',1)):
                variants.append([rows[0]|{key:value},*rows[1:]])
            for changed in variants:
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{name:changed})

    def test_population_and_body_pin(self):
        bodies,_ = self.synthetic()
        specs = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count = 0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for name,body in bodies.items():
                for changed in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError):
                    review.check_bodies({n:b for n,b in bodies.items() if n!=name})
                for i in range(len(body)):
                    changed = bytearray(body)
                    changed[i] ^= 1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:bytes(changed)})
                    count += 1
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,896)

    def test_temporary_copies_are_distinct_and_inside_window(self):
        result = review.geometry(review.Window(0,65536))
        self.assertEqual(result['frames'],dict(run=-2496,absorb=-11456,drop4=-11440))
        first,second,*_ = result['spans']
        self.assertEqual((first['offset_from_high'],first['bytes']),(-2432,992))
        self.assertEqual((second['offset_from_high'],second['bytes']),(-1440,992))
        self.assertEqual(first['offset_from_low']+first['bytes'],second['offset_from_low'])
        self.assertEqual(result['root_slot_cv_offsets'],[16,104,192,280])
        self.assertEqual(result['root_slot_dead_offsets'],[80,168,256,344])
        self.assertEqual(result['cv_clear_bytes'],64)
        for low in (4096,1<<32,(1<<64)-69632):
            self.assertEqual(result,review.geometry(review.Window(low,low+65536)))

    def test_no_transitive_or_exception_claim_from_geometry(self):
        result = review.geometry(review.Window(0,65536))
        for field in ('root_slot_placement_measured','temporary_copies_individually_erased',
                      'maximum_transitive_depth_qualified','exception_dispatch_qualified'):
            self.assertIs(result[field],False)
        for row in result['unknown_callees']:
            self.assertIsNone(row['callee_frame_bytes'])
            self.assertFalse(row['callee_spills_qualified'])

    def test_review_identity_precedes_parsing(self):
        with patch.object(review.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')

    def test_success_and_wrong_provenance_have_different_cleanup_branches(self):
        # Guard the reviewed branch table itself, not just the reconstructed code.
        branches = {(n,o):target for n,o,_,target in review.BRANCHES}
        self.assertEqual(branches['run',0x218],0x234)  # success retains the CV
        for offset in (0x3e,0x52,0x5f,0x69,0x7a,0x8e,0x9b,0xa8,0xbc,0x174,0x1f9,0x20e):
            self.assertEqual(branches['run',offset],0x21e)  # clear before Dead
        for offset in (0xd,0x15,0x1b):
            self.assertEqual(branches['absorb',offset],0x6b)  # no consume/clear
        self.assertEqual(branches['absorb',0x28],0x5a)  # admitted dead state clears
        self.assertEqual(branches['funclet',0x2a],0x35)  # conditional drop still clears CV


if __name__ == '__main__': unittest.main()
