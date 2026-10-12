#!/usr/bin/env python3
"""Actual-body regressions and independent arithmetic checks for selected leaves."""
import argparse
import copy
import json
from pathlib import Path
import random
import unittest

import windows_enclave_parallel_leaf as p
import windows_enclave_parallel_leaf_finish as f
import windows_enclave_parallel_leaf_flush as v
import windows_enclave_parallel_leaf_absorb as a

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Models(unittest.TestCase):
    def test_checked_total_word_carry_and_overflow(self):
        rng=random.Random(0x70617261)
        values=[0,1,f.MASK-1,f.MASK,f.MASK+1,f.LIMIT-1,f.LIMIT]
        pairs=[(x,y) for x in values for y in (0,1,8,f.MASK)]
        pairs += [(rng.getrandbits(128),rng.getrandbits(64)) for _ in range(10000)]
        for total,extra in pairs:
            if total+extra<=f.LIMIT:self.assertEqual(f.checked_total(total,extra),total+extra)
            else:
                with self.assertRaises(ValueError):f.checked_total(total,extra)

    def test_exact_completion_independent_big_integer_oracle(self):
        rng=random.Random(0x6c656166)
        pairs=[(n,b) for n in (0,1,7,8,9,f.MASK,f.LIMIT) for b in (1,2,7,256,1<<61,f.MASK)]
        pairs += [(rng.getrandbits(128),rng.randrange(1,1<<64)) for _ in range(10000)]
        for total,block in pairs:
            expected=(total+8*block-1)//(8*block)
            self.assertEqual(f.completion(total,block,0,expected),expected)
            self.assertLessEqual(expected,1<<125)
            for wrong in (expected+1,expected-1):
                if wrong>=0:
                    with self.assertRaises(ValueError):f.completion(total,block,0,wrong)
            for used in (1,block,1<<64,f.LIMIT):
                with self.assertRaises(ValueError):f.completion(total,block,used,expected)

    def test_zero_divisor_and_out_of_domain_values_rejected(self):
        for block in (0,-1,1<<64,True):
            with self.assertRaises(ValueError):f.completion(0,block,0,0)
        for bad in (-1,1<<128,True,1.0):
            with self.assertRaises(ValueError):f.completion(bad,1,0,0)
            with self.assertRaises(ValueError):f.right_encoded(bad)
        with self.assertRaises(ValueError):f.checked_total(0,1<<64)

    def test_full_right_encoding_all_widths_and_byte_boundaries(self):
        rng=random.Random(0x72696768)
        values={0,f.LIMIT}
        for bit in range(128):
            values.update(n for n in ((1<<bit)-1,1<<bit,(1<<bit)+1) if n<=f.LIMIT)
        values.update(rng.getrandbits(128) for _ in range(10000))
        widths=set()
        for n in sorted(values):
            width=max(1,(n.bit_length()+7)//8);widths.add(width)
            self.assertEqual(f.right_encoded(n),n.to_bytes(width,'big')+bytes([width]))
        self.assertEqual(widths,set(range(1,17)))

    def test_flush_shape_empty_exact_partial_and_u128_edges(self):
        for block in (1,2,31,f.MASK):
            for used in (0,1,block-1,block,block+1,1<<64):
                for tail in range(8):
                    for identity in range(1,5):
                        valid=used<=block and (used or tail) and (not tail or used<block)
                        if valid:
                            result=v.admitted(used,block,tail,f.LIMIT-1,identity)
                            self.assertEqual(result['next_leaves'],f.LIMIT)
                            self.assertEqual(result['cv_bytes'],32 if identity in (1,3) else 64)
                        else:
                            with self.assertRaises(ValueError):v.admitted(used,block,tail,0,identity)
        with self.assertRaises(ValueError):v.admitted(1,1,0,f.LIMIT,1)
        for identity in (0,5,True):
            with self.assertRaises(ValueError):v.admitted(1,1,0,0,identity)
        with self.assertRaises(ValueError):v.admitted(1,2,8,0,1)

    def test_branch_decoder_does_not_accept_redirect_or_truncation(self):
        f.windows(b'\x75\x02\x90\x90\xc3',[],[(0,'75',4)])
        for code in (b'\x75\x01\x90\x90\xc3',b'\x74\x02\x90\x90\xc3',b'\x75'):
            with self.assertRaises(ValueError):f.windows(code,[],[(0,'75',4)])

    def test_absorb_positive_progress_exact_flush_and_nonwrapping_counter(self):
        rng=random.Random(0x6162736f)
        for _ in range(10000):
            block=rng.randrange(1,1<<64);used=rng.randrange(block);length=rng.randrange(1,1<<64)
            result=a.step(used,block,length)
            self.assertEqual(result['take'],min(block-used,length))
            self.assertEqual(result['used'],used+result['take'])
            self.assertEqual(result['remaining'],length-result['take'])
            self.assertEqual(result['flush'],result['used']==block)
            self.assertGreater(result['take'],0);self.assertLessEqual(result['used'],f.MASK)
        for used,block in ((1,1),(2,1),(1<<64,f.MASK),(f.LIMIT,1)):
            with self.assertRaises(ValueError):a.step(used,block,1)

    def test_absorb_fragment_partition_no_lost_duplicated_or_cross_leaf_bytes(self):
        for block in (1,2,3,8,31,1024,f.MASK):
            for length in (1,2,7,32,2050):
                remaining=length;used=0;cursor=0;leaves=0
                while remaining:
                    result=a.step(used,block,remaining)
                    self.assertLessEqual(cursor+result['take'],length)
                    cursor+=result['take'];remaining=result['remaining'];used=result['used']
                    if result['flush']:used=0;leaves+=1
                self.assertEqual((cursor,leaves,used),(length,length//block,length%block))


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.functions={};cls.bodies={};cls.refs={};cls.expected={}
        for lane in ('scalar','avx2'):
            inputs,_=p.inventory.load(SAVED,ROOT,cls.spec[lane])
            functions=p.c.previous.inventory(inputs['object']);cls.functions[lane]=functions
            selected=p.names(functions,lane)
            cls.bodies[lane]={r:functions[n][0] for r,n in selected.items()}
            cls.refs[lane]={r:functions[n][1] for r,n in selected.items()}
            cls.expected[lane]=p.expected_calls(functions,lane)

    def test_selected_actual_bodies_and_parent_handler_bindings(self):
        result=p.inspect(SAVED,ROOT,True)
        self.assertFalse(result['pass_complete']);self.assertFalse(result['completion_package_closed'])
        self.assertFalse(result['whole_image_qualified']);self.assertFalse(result['new_native_run'])
        self.assertFalse(result['release_gate_changed']);self.assertFalse(result['independently_verified'])
        self.assertEqual(sum(len(r['entries']) for r in result['routes'].values()),12)
        self.assertEqual(sum(r['body_byte_mutations_rejected'] for r in result['routes'].values()),5046)
        for row in result['routes'].values():
            self.assertFalse(row['assembly_listing_used_for_semantics'])
            self.assertFalse(row['complete_sequential_path']);self.assertTrue(row['remaining'])

    def test_each_arithmetic_or_cv_instruction_byte_rejected_without_body_hash(self):
        # Bypass the whole-body hash checker deliberately: the semantic anchors
        # independently enforce widths, offsets, counters, commit order/clears.
        count=0
        for lane in self.bodies:
            for role,module in (('finish',f),('flush',v),('absorb',a)):
                code=self.bodies[lane][role]
                positions={at+i for at,text in module.ANCHORS[lane] for i in range(len(bytes.fromhex(text)))}
                for at in positions:
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):f.windows(bad,module.ANCHORS[lane],module.BRANCHES[lane])
                    count+=1
        self.assertEqual(count,2036)

    def test_each_condition_and_branch_target_rejected_without_body_hash(self):
        for lane in self.bodies:
            for role,module in (('finish',f),('flush',v),('absorb',a)):
                code=self.bodies[lane][role]
                for at,op,_ in module.BRANCHES[lane]:
                    for pos in (at,at+len(bytes.fromhex(op))):
                        bad=bytearray(code);bad[pos]^=1
                        with self.assertRaises(ValueError):f.windows(bad,module.ANCHORS[lane],module.BRANCHES[lane])

    def test_every_relocation_target_offset_addend_and_tail_checked(self):
        for lane in self.bodies:
            for role,refs in self.refs[lane].items():
                for index,_ in enumerate(refs):
                    for field,value in (('symbol','wrong'),('offset',0),('addend',1),('trailing',1)):
                        changed=copy.deepcopy(self.refs[lane]);changed[role][index][field]=value
                        with self.assertRaises(ValueError):p.calls_check(self.bodies[lane],changed,self.expected[lane])
                changed=copy.deepcopy(self.refs[lane]);changed[role]=refs[:-1]
                with self.assertRaises(ValueError):p.calls_check(self.bodies[lane],changed,self.expected[lane])
                changed=copy.deepcopy(self.refs[lane]);changed[role]=refs+refs[:1]
                with self.assertRaises(ValueError):p.calls_check(self.bodies[lane],changed,self.expected[lane])

    def test_cleanup_full_bodies_and_invoked_handlers_are_load_bearing(self):
        for lane,body in self.bodies.items():
            for role in set(body)-{'finish','flush','absorb'}:
                for at in range(len(body[role])):
                    bad=bytearray(body[role]);bad[at]^=1
                    with self.assertRaises(ValueError):p.instructions(body|{role:bad},self.refs[lane],self.expected[lane],lane)

    def test_saved_listing_cannot_substitute_its_funclet_name(self):
        functions=dict(self.functions['avx2']);actual=p.names(functions,'avx2')['finish_drop']
        functions[actual.replace('?dtor$32','?dtor$31')]=functions.pop(actual)
        with self.assertRaises(ValueError):p.names(functions,'avx2')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('saved_directory',type=Path,nargs='?')
    parser.add_argument('--source-root',type=Path,default=ROOT)
    args=parser.parse_args();SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=[__file__],verbosity=2)
