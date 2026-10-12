#!/usr/bin/env python3
"""Concurrent lifetime/ABI/COFF regressions; saved artifacts required for closure."""
import argparse
import copy
from pathlib import Path
import random
import unittest
from unittest.mock import patch

import windows_enclave_parallel_concurrent as p
import windows_enclave_parallel_concurrent_models as m

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Models(unittest.TestCase):
    def test_generation_cannot_wrap_or_reopen_sealed_gate(self):
        for generation in (0,1,0xfffffffe):
            for lanes in range(1,5):
                value=m.reserve(generation<<32,lanes)
                self.assertEqual(value>>32,generation+1)
                self.assertEqual(value&0xffff,((1<<lanes)-1)<<12)
                with self.assertRaises(ValueError):m.reserve(value,lanes)
                with self.assertRaises(ValueError):m.reserve(m.close(value),lanes)
        for value,lanes in ((0xffffffff00000000,1),(0,0),(0,5),(-1,1),(True,1)):
            with self.assertRaises(ValueError):m.reserve(value,lanes)

    def test_all_four_lane_linearized_claim_leave_close_interleavings(self):
        # Enumerate atomic gate states, including early close and either outcome
        # for each worker. This does not model the Windows scheduler or weak CPUs.
        total=0
        for lanes in range(1,5):
            first=m.reserve(0,lanes)|m.OPEN
            todo=[first];seen={first}
            while todo:
                state=todo.pop();total+=1
                successors={m.close(state)}
                self.assertFalse(m.quiescent(state) and state&m.LIVE)
                self.assertIsNone(m.enter(state,0,0))
                self.assertIsNone(m.enter(state,2,0))
                for lane in range(4):
                    bit=1<<lane;claimed=bool(state&bit)
                    entered=m.enter(state,1,lane)
                    eligible=lane<lanes and bool(state&m.OPEN) and not claimed
                    self.assertEqual(entered is not None,eligible)
                    if entered is not None:
                        self.assertTrue(entered&(bit<<4));successors.add(entered)
                        self.assertIsNone(m.enter(entered,1,lane))
                    if state&(bit<<4):
                        for success in (False,True):
                            after=m.leave(state,lane,success)
                            self.assertFalse(after&(bit<<4))
                            self.assertEqual(bool(after&(bit<<8)),success)
                            successors.add(after)
                if m.all_succeeded(state,lanes):
                    self.assertEqual(state&15,(1<<lanes)-1)
                    self.assertEqual((state>>8)&15,(1<<lanes)-1)
                    self.assertFalse(state&m.LIVE)
                for value in successors-seen:seen.add(value);todo.append(value)
        self.assertEqual(total,680)

    def test_success_receipt_does_not_replace_live_ticket_join(self):
        state=m.enter(m.reserve(0,1)|m.OPEN,1,0)
        state|=0x100  # Receipt published before Ticket::drop's separate release.
        state=m.close(state)
        self.assertFalse(m.quiescent(state));self.assertFalse(m.all_succeeded(state,1))
        with self.assertRaises(ValueError):m.retire(state,True,True,True)
        state=m.leave(state,0,True)
        self.assertTrue(m.all_succeeded(state,1))
        for args in ((False,True,True),(True,False,True),(True,True,False)):
            with self.assertRaises(ValueError):m.retire(state,*args)
        retired=m.retire(state,True,True,True)
        next_wave=m.reserve(retired,1)|m.OPEN
        self.assertIsNone(m.enter(next_wave,1,0))
        self.assertIsNotNone(m.enter(next_wave,2,0))

    def test_partial_failures_never_satisfy_receipts(self):
        for lanes in range(1,5):
            for failed in range(lanes):
                value=m.reserve(0,lanes)|m.OPEN
                for lane in range(lanes):
                    value=m.enter(value,1,lane)
                    value=m.leave(value,lane,lane!=failed)
                value=m.close(value)
                self.assertTrue(m.quiescent(value));self.assertFalse(m.all_succeeded(value,lanes))
                with self.assertRaises(ValueError):m.reserve(value,lanes)

    def test_all_bounded_leaf_geometry(self):
        for block in range(1,1025):
            for lanes in range(1,5):
                for tail in (1,7,8,block*8):
                    bits=(lanes-1)*block*8+tail;width=(bits+7)//8
                    spans=[m.leaf_range(i,block,min(block*8,bits-i*block*8),width) for i in range(lanes)]
                    self.assertEqual(spans[0][0],0);self.assertEqual(spans[-1][1],width)
                    self.assertTrue(all(a[1]==b[0] for a,b in zip(spans,spans[1:])))
        for args in ((4,1,8,4),(0,0,8,1),(0,1025,8,1025),(0,1,0,1),(0,1,9,2),(1,32,256,63)):
            with self.assertRaises(ValueError):m.leaf_range(*args)

    def test_exact_index_plan_phase_and_unused_cv_checks(self):
        for count in range(5):
            rows=[(123,i,int(i<count),i<count) for i in range(4)]
            self.assertEqual(m.ordered_reduce(rows,123,count),list(range(count)))
            for i in range(count):
                for bad in ((124,i,1,True),(123,i+1,1,True),(123,i,0,True),(123,i,2,False)):
                    with self.assertRaises(ValueError):m.ordered_reduce(rows[:i]+[bad]+rows[i+1:],123,count)
            for i in range(count,4):
                for bad in ((123,i,1,False),(123,i,0,True)):
                    with self.assertRaises(ValueError):m.ordered_reduce(rows[:i]+[bad]+rows[i+1:],123,count)

    def test_shape_completion_and_suffix_boundaries(self):
        for identity in range(1,5):
            for block in (1,32,1024):
                for leaves in (0,1,4,5,65536):
                    total=block*8*leaves
                    result=m.shape(identity,block,total,8192,8192)
                    self.assertEqual(result['leaves'],leaves);self.assertLessEqual(result['waves'],16384)
                    self.assertTrue(m.exact_finish(total,total,leaves,leaves,1))
                    for c,t,n,e,s in ((total+1,total,leaves,leaves,1),(total,total,leaves+1,leaves,1),
                            (total,total,leaves,leaves,0),(total,total,leaves,leaves,2)):
                        self.assertFalse(m.exact_finish(c,t,n,e,s))
        for args in ((0,1,0,0,0),(5,1,0,0,0),(1,0,0,0,0),(1,1025,0,0,0),
                (1,1,65536*8+1,0,0),(1,1,0,8193,0),(1,1,0,0,8193)):
            with self.assertRaises(ValueError):m.shape(*args)
        for bit in range(64):
            for v in ((1<<bit)-1,1<<bit,(1<<bit)+1):
                count=max(1,(v.bit_length()+7)//8)
                self.assertEqual(m.right_encode(v),v.to_bytes(count,'big')+bytes([count]))

    def test_widened_copy_loop_has_no_counter_wrap(self):
        rng=random.Random(0x434f5059)
        values=list(range(4097))+[(1<<61)-1]+[rng.randrange(1<<61) for _ in range(4000)]
        for length in values:
            words,tail=m.transfer_chunks(length)
            self.assertEqual(words*8+tail,length)
            self.assertLessEqual(words*8,length);self.assertLess(tail,8)
        for length in (-1,True,1<<61):
            with self.assertRaises(ValueError):m.transfer_chunks(length)


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved COFF/PE artifacts required')
        spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.x,_=p.inventory.load(SAVED,ROOT,spec['concurrent'])
        cls.y,_=p.inventory.load(SAVED,ROOT,spec['avx2'])
        cls.f=p.c.previous.inventory(cls.x['object']);cls.g=p.c.previous.inventory(cls.y['object'])
        cls.n=p.names(cls.f);cls.b={r:cls.f[n][0] for r,n in cls.n.items()}
        cls.r=p.c.previous.bind_all(cls.x['object'],cls.x['image'],cls.f)
        cls.e,cls.a=p.c.reuse.exact_reuse(cls.f,cls.g,cls.x['ir'].decode(),cls.y['ir'].decode())

    def test_conditional_route_closure_and_all_bound_predecessors(self):
        result=p.inspect_route(SAVED,ROOT,True)
        self.assertEqual(len(result['assignments']),64);self.assertEqual(result['unassigned'],[])
        self.assertEqual(result['distinct_body_bytes'],2561)
        self.assertEqual(result['distinct_instruction_mutants_rejected'],2561)
        self.assertEqual(result['exact_helper_count'],23);self.assertEqual(len(result['changed_abi']),6)
        self.assertEqual(len(result['remaining_handlers']),4)
        self.assertTrue(result['conditional_rust_family_review_complete'])
        self.assertFalse(result['whole_image_qualified'])
        self.assertEqual(result['prerequisites'],list(p.PRECONDITIONS))

    def test_each_instruction_byte_rejected_without_population_hash(self):
        count=0
        for role,code in self.b.items():
            for at in range(len(code)):
                bad=bytearray(code);bad[at]^=1
                with self.assertRaises(ValueError):p.instructions(self.b|{role:bad})
                count+=1
        self.assertEqual(count,2561)

    def test_each_branch_rejects_opcode_or_target_mutant(self):
        for role,row in p.TABLES.items():
            for at,opcode,_ in row['branches']:
                for where in (at,at+len(bytes.fromhex(opcode))):
                    bad=bytearray(self.b[role]);bad[where]^=1
                    with self.assertRaises(ValueError):p.sequential.leaf.finish.windows(bad,[],row['branches'])

    def test_exact_population_has_no_omitted_or_orphan_body(self):
        for name in self.f:
            bad=self.f.copy();del bad[name]
            with self.assertRaises(ValueError):p.assignments(bad,self.e)
        with self.assertRaises(ValueError):p.assignments(self.f|{'orphan':next(iter(self.f.values()))},self.e)

    def test_abi_differences_do_not_discard_other_attributes(self):
        for name in self.a:
            now=p.c.reuse.abi(self.x['ir'].decode(),name);old=p.c.reuse.abi(self.y['ir'].decode(),name)
            p.changed_abi(now,old,name)
            for bad in (now+' ',now.replace('noundef','',1) if 'noundef' in now else now.replace('cold',''),
                    now.replace('x86-64','x86-64-v4'),now.replace('nounwind','') if 'nounwind' in now else now+' nounwind'):
                with self.assertRaises(ValueError):p.changed_abi(bad,old,name)
        changed=dict(self.f);name=next(iter(self.a));code,refs,kind=changed[name]
        changed[name]=(code+b'\x90',refs,kind)
        with self.assertRaises(ValueError):p.abi_reuse(changed,self.x['ir'].decode(),self.g,self.y['ir'].decode(),self.a)

    def test_actual_dtor55_and_all_parent_metadata_edges(self):
        for handler,parent in p.handlers_check(self.r).items():
            bad=copy.deepcopy(self.r);bad[parent]['metadata']=[q for q in bad[parent]['metadata'] if q['symbol']!=handler]
            with self.assertRaises(ValueError):p.handlers_check(bad)
        bad=copy.deepcopy(self.r);name=self.n['finish_handler'];bad[name.replace('$55','$54')]=bad.pop(name)
        with self.assertRaises(ValueError):p.handlers_check(bad)

    def test_publication_global_identity_and_nonoverlap_are_load_bearing(self):
        p.globals_check(self.x['image'],self.r)
        for symbol in p.GLOBALS:
            bad=copy.deepcopy(self.r)
            user=next(r for r in bad.values() if symbol in r['reference_targets'])
            user['reference_targets'][symbol]+=1
            with self.assertRaises(ValueError):p.globals_check(self.x['image'],bad)
        bad=copy.deepcopy(self.r)
        for row in bad.values():row['reference_targets'].pop(p.PREFIX+'7CLAIMED',None)
        with self.assertRaises(ValueError):p.globals_check(self.x['image'],bad)

    def test_composition_operands_independently_reject_mutation(self):
        anchors=[];original=m.sequential.anchor
        def record(code,at,value):
            original(code,at,value);anchors.append((code,at,len(bytes.fromhex(value))))
        with patch.object(m.sequential,'anchor',record):m.compose(self.f,self.n,self.x['ir'].decode())
        count=0
        for code,at,length in anchors:
            name=next(n for n,v in self.f.items() if v[0]==code)
            for offset in range(at,at+length):
                changed=bytearray(code);changed[offset]^=1
                _,refs,kind=self.f[name]
                with self.assertRaises(ValueError):m.compose(self.f|{name:(changed,refs,kind)},self.n,self.x['ir'].decode())
                count+=1
        self.assertGreater(count,300)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--saved-directory',type=Path)
    args=parser.parse_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__])
