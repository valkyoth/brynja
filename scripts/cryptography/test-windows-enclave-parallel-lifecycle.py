#!/usr/bin/env python3
"""Saved sequential lifecycle regressions; synthetic models are not execution."""
import argparse
import copy
from pathlib import Path
import random
import unittest
from unittest.mock import patch

import windows_enclave_parallel_lifecycle as p
import windows_enclave_parallel_lifecycle_models as m
import windows_enclave_parallel_entry as entry
import windows_enclave_parallel_entry_models as em

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Models(unittest.TestCase):
    def test_phase_sequence_authority_and_error_precedence(self):
        sequences=[(0,0),(0,1),(1,1),(1,2),(m.MASK-1,m.MASK),(m.MASK,0),(m.MASK,m.MASK)]
        for lane in ('scalar','avx2'):
            for allowed in ((0,),(1,2),(3,4,5),(0,1,2,3),(1,2,3,4,5),(1,2,3,4,5,6)):
                for phase in range(256):
                    for previous,requested in sequences:
                        for health,kernel in ((1,4),(0,4),(2,4),(1,3)):
                            error=(2 if phase not in allowed else 1 if requested!=previous+1
                                else 7 if lane=='avx2' and (health!=1 or kernel!=4) else None)
                            got=m.admission(lane,phase,allowed,previous,requested,health,kernel)
                            self.assertEqual(got,dict(error=error,phase=7 if error is not None else phase,
                                sequence=previous if error is not None else requested,
                                cleared=error is not None,authority_revoked=lane=='avx2' and error is not None,
                                armed=error is None))

    def test_random_u64_replay_and_wrap(self):
        rng=random.Random(0x70616765)
        for _ in range(10000):
            previous=rng.getrandbits(64)
            for requested in (previous,(previous+1)&m.MASK,rng.getrandbits(64)):
                got=m.admission('scalar',3,(3,),previous,requested)
                self.assertEqual(got['armed'],requested==previous+1)
                self.assertEqual(got['sequence'],requested if got['armed'] else previous)

    def test_all_authority_bytes_and_scalar_independence(self):
        for value in range(256):
            for health,kernel in ((value,4),(1,value)):
                got=m.admission('avx2',3,(3,),0,1,health,kernel)
                self.assertEqual(got['armed'],health==1 and kernel==4)
                self.assertTrue(m.admission('scalar',3,(3,),0,1,health,kernel)['armed'])

    def test_cancel_empty_quarantined_replay_and_reuse(self):
        for lane in ('scalar','avx2'):
            for phase in range(8):
                got=m.cancel(lane,phase,8,9)
                self.assertTrue(got['cleared']);self.assertFalse(got['armed'])
                self.assertEqual(got['phase'],0 if phase in range(1,7) else 7)
                if got['error'] is None:
                    self.assertTrue(m.admission(lane,0,(0,),got['sequence'],10)['armed'])
                    self.assertEqual(m.admission(lane,0,(0,),got['sequence'],9)['error'],1)
            self.assertEqual(m.cancel(lane,3,m.MASK,0)['error'],1)

    def test_specialized_scan_and_integer_domains_are_not_unbounded(self):
        for allowed in ((),tuple(range(7)),(True,),(-1,),(256,)):
            with self.assertRaises(ValueError):m.admission('scalar',0,allowed,0,1)
        for previous,requested in ((True,1),(-1,0),(0,1<<64)):
            with self.assertRaises(ValueError):m.admission('scalar',0,(0,),previous,requested)


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.functions={};cls.bodies={};cls.refs={};cls.expected={};cls.inputs={};cls.records={}
        for lane in p.TABLES:
            inputs,_=p.inventory.load(SAVED,ROOT,cls.spec[lane]);cls.inputs[lane]=inputs
            f=p.c.previous.inventory(inputs['object']);cls.functions[lane]=f;n=p.names(f,lane)
            cls.bodies[lane]={r:f[name][0] for r,name in n.items()}
            cls.refs[lane]={r:f[name][1] for r,name in n.items()}
            cls.expected[lane]=p.expected_refs(f,lane)
            cls.records[lane]=p.c.previous.bind_all(inputs['object'],inputs['image'],f)

    def test_selected_population_and_explicit_remaining_obligations(self):
        report=p.inspect(SAVED,ROOT,True)
        for flag in ('pass_complete','completion_package_closed','whole_image_qualified',
                     'independently_verified','new_native_run','release_gate_changed'):
            self.assertFalse(report[flag])
        self.assertEqual(sum(len(r['entries']) for r in report['routes'].values()),12)
        for field in ('reviewed_instruction_bytes','body_byte_mutations_rejected'):
            self.assertEqual(sum(r[field] for r in report['routes'].values()),3011)
        for row in report['routes'].values():
            self.assertFalse(row['complete_sequential_path']);self.assertTrue(row['remaining'])
            self.assertFalse(row['semantics']['clear_is_full_page_erasure'])
            self.assertFalse(row['semantics']['resident_exception_handler_clears_full_page'])

    def test_every_instruction_byte_independently_of_body_hash(self):
        count=0
        for lane,roles in self.bodies.items():
            for role,code in roles.items():
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):p.instructions(roles|{role:bad},lane)
                    count+=1
        self.assertEqual(count,3011)

    def test_branch_opcodes_and_targets_independently_of_instruction_pins(self):
        count=0
        for lane,roles in p.TABLES.items():
            for role,contract in roles.items():
                for at,op,_ in contract['branches']:
                    for offset in (at,at+len(bytes.fromhex(op))):
                        bad=bytearray(self.bodies[lane][role]);bad[offset]^=1
                        with self.assertRaises(ValueError):
                            p.framing.leaf.finish.windows(bad,[],contract['branches'])
                        count+=1
        self.assertEqual(count,100)

    def test_every_call_phase_reference_and_relocation_shape(self):
        for lane,roles in self.refs.items():
            for role,refs in roles.items():
                for index in range(len(refs)):
                    for field,value in (('offset',0),('symbol','wrong'),('addend',1),('trailing',1)):
                        bad=copy.deepcopy(roles);bad[role][index][field]=value
                        with self.assertRaises(ValueError):p.framing.refs_check(self.bodies[lane],bad,self.expected[lane])
                for replacement in (refs[:-1],refs+refs[:1]):
                    with self.assertRaises(ValueError):
                        p.framing.refs_check(self.bodies[lane],roles|{role:replacement},self.expected[lane])

    def test_actual_readonly_cancel_phases(self):
        for lane in p.TABLES:
            args=(self.inputs[lane]['image'],self.records[lane],p.names(self.functions[lane],lane),self.expected[lane])
            self.assertEqual(p.cancellation_phases(*args),[1,2,3,4,5,6])
            for bad in (b'',bytes(range(6)),bytes(range(2,8)),bytes(range(6,0,-1))):
                with patch.object(p.c.previous,'readonly',return_value=bad):
                    with self.assertRaises(ValueError):p.cancellation_phases(*args)

    def test_invoked_handlers_cannot_be_detached_or_relabelled(self):
        records=self.records['avx2'];selected=p.names(self.functions['avx2'],'avx2')
        p.handlers_check(records,selected)
        for role in ('cancel','drop'):
            bad=copy.deepcopy(records);bad[selected[role]]['metadata']=[]
            with self.assertRaises(ValueError):p.handlers_check(bad,selected)
            bad=copy.deepcopy(records);bad[selected[role+'_handler']]['rva']+=1
            with self.assertRaises(ValueError):p.handlers_check(bad,selected)
        for lane in p.TABLES:
            for role,code in self.bodies[lane].items():
                for bad in (code[:-1],code+b'\x90'):
                    with self.assertRaises(ValueError):p.instructions(self.bodies[lane]|{role:bad},lane)

    def test_placement_operands_and_nonoverlapping_constructor_copies(self):
        code=self.bodies['avx2']['new'];g=m.placement(code)
        self.assertEqual(g['owner'],[32,3200]);self.assertEqual(g['authority_pointer_cells'],[0x830,0xc70])
        self.assertEqual(g['public_copy_source'][1],g['public_copy_temporary'][0])
        self.assertEqual(g['public_copy_temporary'][1],g['constructor_frame'])
        self.assertFalse(g['original_allocation_admission_proved'])
        for at in (0x3c,0x173,0x1bd,0x135,0x188,0x1cc,0x1d3,0x1da,0x56,0x91,0x98,0x120,0x123):
            bad=bytearray(code);bad[at]^=1
            with self.assertRaises(ValueError):m.placement(bad)

    def test_page_loop_all_bytes_and_no_unchecked_short_decode(self):
        for role,start,sib in (('new',0x1de,7),('drop',0xbe,6)):
            code=self.bodies['avx2'][role];report=m.page_loop(code,start,sib)
            self.assertEqual((report['bytes_cleared'],report['iterations']),(4096,512))
            # Every instruction/register/displacement/value/stride/limit/edge
            # byte is checked by the decoder without any whole-body hash.
            for at in range(start,start+53):
                bad=bytearray(code);bad[at]^=1
                with self.assertRaises(ValueError):m.page_loop(bad,start,sib)
            for length in range(start,start+53):
                with self.assertRaises(ValueError):m.page_loop(code[:length],start,sib)

    def test_normal_retirement_graph_does_not_claim_exception_cleanup(self):
        code=self.bodies['avx2']['drop'];g=m.retirement_graph(code)
        self.assertEqual(g['return_states'],2);self.assertEqual(g['explored_states'],20)
        self.assertFalse(g['exceptional_full_page_erasure']);self.assertTrue(g['callee_contracts_assumed'])
        with self.assertRaises(ValueError):m.retirement_graph(code,events={})
        with self.assertRaises(ValueError):m.retirement_graph(code,branches=[])


class Worker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Saved.setUpClass.__func__(cls)
        for lane,f in cls.functions.items():
            n=entry.names(f,lane)
            cls.bodies[lane]={r:f[name][0] for r,name in n.items()}
            cls.refs[lane]={r:f[name][1] for r,name in n.items()}
            cls.expected[lane]=entry.reference_contract(f,lane)

    def test_every_worker_byte_without_body_hash_and_complete_extents(self):
        count=0
        for lane,roles in self.bodies.items():
            entry.instructions(roles,lane)
            for role,code in roles.items():
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):entry.instructions(roles|{role:bad},lane)
                    count+=1
                for bad in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError):entry.instructions(roles|{role:bad},lane)
        self.assertEqual(count,1820)

    def test_worker_branch_targets_without_instruction_windows(self):
        count=0
        for lane,roles in entry.TABLES.items():
            for role,contract in roles.items():
                for at,op,_ in contract['branches']:
                    for offset in (at,at+len(bytes.fromhex(op))):
                        bad=bytearray(self.bodies[lane][role]);bad[offset]^=1
                        with self.assertRaises(ValueError):p.framing.leaf.finish.windows(bad,[],contract['branches'])
                        count+=1
        self.assertEqual(count,164)

    def test_mutable_reference_addends_tail_calls_and_exact_population(self):
        for lane,refs in self.refs.items():
            entry.refs_check(self.bodies[lane],refs,self.expected[lane])
            for role,rows in refs.items():
                for index,row in enumerate(rows):
                    for field,value in (('symbol','wrong'),('offset',row['offset']+1),
                        ('addend',row['addend']+1),('trailing',1)):
                        bad=copy.deepcopy(refs);bad[role][index][field]=value
                        with self.assertRaises(ValueError):entry.refs_check(self.bodies[lane],bad,self.expected[lane])
                with self.assertRaises(ValueError):entry.refs_check(self.bodies[lane],refs|{role:rows[:-1]},self.expected[lane])

    def test_image_globals_are_disjoint_writable_nonexecutable(self):
        for lane in self.bodies:
            image=self.inputs[lane]['image'];record=self.records[lane]['RetainedWork']
            g=entry.global_storage(image,record,lane);self.assertTrue(g['serialized_entry_is_external_precondition'])
            for name in g['identity_rvas']:
                for wrong in (0,g['identity_rvas'][name]+1,record['rva']):
                    bad=copy.deepcopy(record);bad['reference_targets'][name]=wrong
                    with self.assertRaises(ValueError):entry.global_storage(image,bad,lane)
            rows,fs=entry.pe.linked(image)
            with patch.object(entry.pe,'linked',return_value=([r|{'flags':0xe0000000} for r in rows],fs)):
                with self.assertRaises(ValueError):entry.global_storage(image,record,lane)
            if lane=='avx2':
                bad=copy.deepcopy(record);keys=list(g['identity_rvas'])
                bad['reference_targets'][keys[1]]=g['identity_rvas'][keys[0]]
                with self.assertRaises(ValueError):entry.global_storage(image,bad,lane)

    def test_actual_buffer_geometry_and_all_volatile_observation_offsets(self):
        for lane in self.bodies:
            code=self.bodies[lane]['entry'];g=em.buffers(code,lane)
            addresses=em.observed_offsets(lane)
            self.assertEqual(len(addresses),g['header_bytes']+1024)
            self.assertEqual(sorted(addresses),list(range(g['payload'][0],g['header'][1])))
            self.assertEqual(len(set(addresses)),len(addresses))
            for key in ('original_window_admission_proved','full_frame_erasure_proved'):self.assertFalse(g[key])
            for at in ((0x15d,0x16e,0x1b7) if lane=='scalar' else (0x21c,0x22d,0x27b)):
                bad=bytearray(code);bad[at]^=1
                with self.assertRaises(ValueError):em.buffers(bad,lane)

    def test_scalar_page_erasure_all_bytes_without_population_pin(self):
        code=self.bodies['scalar']['entry'];r=em.scalar_page_erase(code)
        self.assertEqual(r['bytes_cleared'],4096)
        for at in [0xbb,0xbc,*range(0xd0,0x104)]:
            bad=bytearray(code);bad[at]^=1
            with self.assertRaises(ValueError):em.scalar_page_erase(bad)

    def test_lane_specific_admission_does_not_invent_scalar_overlap_check(self):
        low,high=0x10000,0x20000
        for page in (0,1,4095,4096,low-4096,low,high-4096,high,m.MASK&~4095):
            scalar=bool(page and page%4096==0)
            self.assertEqual(em.entry_admits('scalar',page,low,high),scalar)
            self.assertEqual(em.entry_admits('avx2',page,low,high),scalar and
                page+4096<=m.MASK and (page+4096<=low or page>=high))
        self.assertTrue(em.entry_admits('scalar',low,low,high))
        self.assertFalse(em.entry_admits('avx2',low,low,high))
        for lane in self.bodies:
            for a,b in ((high,low),(low,high-1),(low,high+1)):
                self.assertFalse(em.entry_admits(lane,4096,a,b))

    def test_buffer_endpoint_overflow_and_both_window_edges(self):
        for size in (112,128,1024):
            for address in (0,1,0x10000-1,0x10000,0x20000-size,0x20000-size+1,m.MASK-size,m.MASK):
                self.assertEqual(em.within(address,size,0x10000,0x20000),
                    0x10000<=address and address+size<=0x20000)
            self.assertFalse(em.within(m.MASK-size+1,size,0,m.MASK))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('saved_directory',type=Path,nargs='?')
    parser.add_argument('--source-root',type=Path,default=ROOT)
    args=parser.parse_args();SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=[__file__],verbosity=2)
