#!/usr/bin/env python3
"""Remaining sequential bodies plus route-level composition regressions."""
import argparse
import copy
from pathlib import Path
import random
import unittest
from unittest.mock import patch

import windows_enclave_parallel_sequential as p
import windows_enclave_parallel_sequential_models as m

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Models(unittest.TestCase):
    def test_public_encoder_every_byte_boundary(self):
        values={0,1,m.LIMIT}
        for bit in range(128):
            for delta in (-1,0,1):
                v=(1<<bit)+delta
                if 0<=v<=m.LIMIT:values.add(v)
        for v in values:
            count=max(1,(v.bit_length()+7)//8)
            self.assertEqual(m.left_encode(v),bytes([count])+v.to_bytes(count,'big'))
        for v in (-1,True,1<<128):
            with self.assertRaises(ValueError):m.left_encode(v)

    def test_bit_string_all_shapes_and_canonical_tail_bytes(self):
        for length in (0,1,2,1024,(1<<61)-1,1<<61,(1<<61)+1,m.MASK):
            for last in range(10):
                for tail in range(256):
                    r=m.bit_admission(length,last,tail)
                    valid=(last==0 if length==0 else 1<=last<=8)
                    bits=(length-1)*8+last if length else 0
                    canonical=not length or last==8 or (1<=last<8 and tail<1<<last)
                    self.assertEqual(r['error'] is None,valid and bits<=m.MASK and canonical)
                    if r['error'] is None:self.assertEqual(r['bits'],bits)
                    if not length or not valid or bits>m.MASK:self.assertFalse(r['tail_read'])

    def test_bit_string_rejects_non_machine_domains(self):
        for args in ((-1,0,0),(True,0,0),(1<<64,8,0),(1,256,0),(1,8,256)):
            with self.assertRaises(ValueError):m.bit_admission(*args)

    def test_setup_prefix_extent_matches_independent_bit_concatenation(self):
        rng=random.Random(0x505245464958)
        values=[0,1,7,8,9,255,256,m.MASK,m.LIMIT-1000,m.LIMIT]+[rng.getrandbits(128) for _ in range(2000)]
        def length(v):return max(1,(v.bit_length()+7)//8)+1
        for rate in (136,168):
            for custom in values:
                total=8*(length(rate)+length(96)+length(custom))+96+custom
                expected=((total+7)//8+rate-1)//rate*rate
                if total>m.LIMIT or expected>m.LIMIT:
                    with self.assertRaises(ValueError):m.prefix_extent(custom,rate)
                else:self.assertEqual(m.prefix_extent(custom,rate),expected)

    def test_modulo136_lowering_full_u128_domain_boundaries(self):
        rng=random.Random(136)
        values=[0,1,135,136,137,m.MASK,m.MASK+1,m.LIMIT]
        values += [min(m.LIMIT,(1<<n)+d) for n in range(128) for d in (-1,0,1)]
        values += [rng.getrandbits(128) for _ in range(12000)]
        for v in values:self.assertEqual(m.modulo136(v),v%136)

    def test_complete_requires_exact_count_and_no_remaining_input(self):
        for rate in (136,168):
            for emitted in (0,1,rate-1,rate,rate+1,2*rate,m.MASK):
                for pending in range(8):
                    expected=((emitted+bool(pending)+rate-1)//rate)*rate
                    r=m.prefix_complete(0,1,emitted,pending,expected,rate)
                    self.assertEqual((r['phase'],r['emitted'],r['pending']),(2,expected,0))
                    for wrong in (expected+1,expected+rate):
                        with self.assertRaises(ValueError):m.prefix_complete(0,1,emitted,pending,wrong,rate)
                    self.assertFalse(m.prefix_complete(1,1,emitted,pending,expected,rate)['complete'])
                    self.assertFalse(m.prefix_complete(0,0,emitted,pending,expected,rate)['complete'])
        for pending in (0,1):
            with self.assertRaises(ValueError):m.prefix_complete(0,1,m.LIMIT,pending,m.LIMIT,168)

    def test_receiver_bound_protects_private_multiply_and_narrowed_abi(self):
        for length in (0,1,1023,1024):
            for total in (0,m.MASK,m.LIMIT-length*8,m.LIMIT):
                if total+length*8<=m.LIMIT:
                    self.assertEqual(m.charge_update(length,total,length),(0,total+length*8))
                else:
                    with self.assertRaises(ValueError):m.charge_update(length,total,length)
            if length:
                with self.assertRaises(ValueError):m.charge_update(length-1,0,length)
        for length in (1025,1<<61,m.MASK):
            with self.assertRaises(ValueError):m.charge_update(m.MASK,0,length)

    def test_xor_call_domain_implies_both_narrowed_shift_ranges(self):
        accepted=0
        for source in range(10):
            for count in range(10):
                for dest in range(10):
                    ok=m.xor_domain(source,count,dest)
                    self.assertEqual(ok,count>0 and source+count<=8 and dest+count<=8)
                    if ok:
                        accepted+=1;self.assertLess(dest,8);self.assertLess(source,8)
                        for byte in (0,1,0x55,0x80,0xff):
                            self.assertEqual(((byte>>source)&((1<<count)-1))<<dest,
                                sum(((byte>>(source+i))&1)<<(dest+i) for i in range(count)))
        self.assertEqual(accepted,sum(n*n for n in range(1,9)))

    def test_regions_reject_overlap_reversal_and_escape(self):
        for regions in ([(0,10),(9,20)],[(10,9)],[(0,21)],[(0,10),(0,10)]):
            with self.assertRaises(ValueError):m.ranges(regions,20)
        self.assertEqual(m.ranges([(0,10),(10,20)],20),[[0,10],[10,20]])


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved actual COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.inputs={};cls.functions={};cls.records={};cls.names={};cls.bodies={};cls.prior={}
        for lane in p.TABLES:
            x,_=p.inventory.load(SAVED,ROOT,cls.spec[lane]);f=p.c.previous.inventory(x['object'])
            cls.inputs[lane]=x;cls.functions[lane]=f;cls.names[lane]=p.names(f,lane)
            cls.records[lane]=p.c.previous.bind_all(x['object'],x['image'],f)
            cls.bodies[lane]={r:f[n][0] for r,n in cls.names[lane].items()}
            cls.prior[lane]=p.reuse.prior_inputs(SAVED,ROOT,lane)

    def test_two_route_conditional_closure_not_whole_image(self):
        for lane in p.TABLES:
            report=p.inspect_route(SAVED,ROOT,lane,self.spec[lane],True)
            self.assertTrue(report['conditional_rust_family_review_complete'])
            self.assertFalse(report['whole_image_qualified']);self.assertFalse(report['unassigned'])
            self.assertEqual(len(report['assignments']),61 if lane=='scalar' else 73)
            self.assertEqual(report['distinct_body_bytes'],10166 if lane=='scalar' else 7105)
            self.assertEqual(report['distinct_instruction_mutants_rejected'],report['distinct_body_bytes'])
            self.assertEqual(report['prerequisites'],list(p.PRECONDITIONS))

    def test_every_instruction_byte_without_population_hash(self):
        count=0
        for lane,bodies in self.bodies.items():
            for role,code in bodies.items():
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):p.instructions(bodies|{role:bad},lane)
                    count+=1
                for bad in (code[:-1],code+b'\x90'):
                    with self.assertRaises(ValueError):p.instructions(bodies|{role:bad},lane)
        self.assertEqual(count,17271)

    def test_each_branch_opcode_and_target_without_instruction_pins(self):
        for lane,rows in p.TABLES.items():
            for role,row in rows.items():
                code=self.bodies[lane][role]
                for at,opcode,_ in row['branches']:
                    for where in (at,at+len(bytes.fromhex(opcode))):
                        bad=bytearray(code);bad[where]^=1
                        with self.assertRaises(ValueError):p.leaf.finish.windows(bad,[],row['branches'])

    def test_assignment_rejects_missing_unknown_or_multiply_assigned_bodies(self):
        for lane,f in self.functions.items():
            old,ir,_,_=self.prior[lane]
            exact=p.reuse.partition(f,old,self.inputs[lane]['ir'].decode(),ir)['exact_body_reference_extent_and_abi']
            for name in f:
                bad=f.copy();del bad[name]
                with self.assertRaises(ValueError):p.assignments(bad,lane,exact)
            with self.assertRaises(ValueError):p.assignments(f|{'orphan':next(iter(f.values()))},lane,exact)
            name=next(iter(self.names[lane].values()))
            with self.assertRaises(ValueError):p.assignments(f,lane,dict(exact)|{name:{}})

    def test_exact_abi_narrowings_and_renamed_drop_reject_other_attribute_changes(self):
        lane='avx2';x=self.inputs[lane];f=self.functions[lane];n=self.names[lane]
        old,ir,_,_=self.prior[lane]
        p.abi_reuse(f,x['ir'].decode(),old,ir,lane,n)
        for role in ('state_update','xor_wrapper','xor_bits'):
            name=n[role];before=p.c.reuse.abi(ir,name);now=p.c.reuse.abi(x['ir'].decode(),name)
            p.narrowed_abi(now,before,role)
            for bad in (before,now+' ',now.replace('nonnull','',1),now.replace('+avx2','-avx2'),
                    now.replace('nounwind','',1)):
                with self.assertRaises(ValueError):p.narrowed_abi(bad,before,role)
        bad=dict(f);name=n['cshake_drop'];code,refs,kind=bad[name];bad[name]=(code+b'\x90',refs,kind)
        with self.assertRaises(ValueError):p.abi_reuse(bad,x['ir'].decode(),old,ir,lane,n)

    def test_all_new_parent_xdata_links_are_load_bearing(self):
        n=self.names['avx2'];r=self.records['avx2'];p.handlers_check(r,n,'avx2')
        for parent in p.HANDLERS:
            for mutation in ('remove','rename','redirect'):
                bad=copy.deepcopy(r);row=bad[n[parent]]
                if mutation=='remove':row['metadata']=[]
                else:
                    role='setup_handler' if parent=='setup_state' else parent+'_handler'
                    ref=next(v for v in row['metadata'] if v['symbol']==n[role])
                    ref['symbol' if mutation=='rename' else 'target_rva']='other' if mutation=='rename' else 0
                with self.assertRaises(ValueError):p.handlers_check(bad,n,'avx2')

    def test_caller_authority_guard_copy_and_output_operands_without_body_pins(self):
        offsets={'scalar':{'begin':[0x106,0x10b,0x111,0x12c], 'custom':[0x4a],
                'update':[0x5d,0x7a,0x8e], 'squeeze':[0x4e,0x96,0x113], 'state_squeeze':[0x60,0x50a]},
            'avx2':{'begin':[0xf6,0x116,0x11a,0x1a5,0x1ac,0x1b2], 'custom':[0x55,0xbf,0xc3],
                'update':[0x6a,0x85,0x89,0x90,0x9e], 'squeeze':[0x5b,0xbb,0xbf,0xce,0x117],
                'initial':[0x49,0x255,0x2bb], 'begin_handler':[0x25,0x2c],
                'custom_handler':[0x15,0x1c], 'update_handler':[0x15,0x1c],
                'squeeze_handler':[0x17,0x1e], 'setup_handler':[0x26]}}
        for lane,roles in offsets.items():
            m.compose(self.bodies[lane],lane)
            for role,positions in roles.items():
                for at in positions:
                    bad=bytearray(self.bodies[lane][role]);bad[at]^=1
                    with self.assertRaises(ValueError):m.compose(self.bodies[lane]|{role:bad},lane)

    def test_external_calls_and_linked_constants_not_implicitly_trusted(self):
        for lane in p.TABLES:
            x=self.inputs[lane];r=self.records[lane];f=self.functions[lane];n=self.names[lane]
            report=p.constants_check(x,r,f,lane,n)
            self.assertTrue(report['runtime_boundaries'])
            for row in report['runtime_boundaries'].values():self.assertEqual(row['assigned_completion_package'],8)
            bad=copy.deepcopy(r);bad[n['begin']]['reference_targets']['UndocumentedRuntime']=0
            with self.assertRaises(ValueError):p.constants_check(x,bad,f,lane,n)
            readonly=p.c.previous.readonly
            def corrupt(image,at,size):
                raw=readonly(image,at,size)
                return bytes([raw[0]^1])+raw[1:] if raw else raw
            with patch.object(p.c.previous,'readonly',side_effect=corrupt):
                with self.assertRaises(ValueError):p.constants_check(x,r,f,lane,n)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--saved-directory',type=Path);args=parser.parse_args();SAVED=args.saved_directory
    unittest.main(argv=['sequential-tests'],verbosity=2)
