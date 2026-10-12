#!/usr/bin/env python3
"""Saved request/export regressions: models supplement actual instruction checks."""
import argparse
import copy
from pathlib import Path
import random
import unittest
from unittest.mock import patch

import windows_enclave_parallel_request as p
import windows_enclave_parallel_request_models as m

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


def header(lane,operation):
    words=[12 if lane=='scalar' else 18,1,0,0,0,0,0,0,0,0,0,0,0,0]
    if operation in (100,106,108):words[2]=1
    if operation in (100,108):words[3]=1
    if lane=='avx2':words += [1,0]
    return words


def oracle(lane,op,w):
    v,n,identity,b,budget,cl,ch,length,last,width,tail,end,source,reserved=w[:14]
    rules=[v==(12 if lane=='scalar' else 18),100<=op<=108,n>0,reserved==0,
        length<=1024,width<=1024,0<=last<=8,0<=tail<=8,end in (0,1),
        (length==0)==(source==0)]
    if lane=='avx2':rules += [w[14]==1,w[15]==0]
    rules += [(length==0)==(last==0)] if op in (101,103,104) else [length==last==0]
    rules += [1<=identity<=4] if op in (100,106,108) else [identity==0]
    rules += [b>0] if op in (100,108) else [b==budget==cl==ch==0]
    if op==103:rules += [last==(8 if length else 0)]
    if op not in (104,105,106,108):rules += [width==tail==0]
    if op!=105:rules += [end==0]
    if op==105 and not end:rules += [tail==(8 if width else 0)]
    if not all(rules) or source+length>m.MASK:return 3
    if (width==0)!=(tail==0):return 4
    return None


class Models(unittest.TestCase):
    def test_each_header_word_operation_and_integer_boundary(self):
        values=(0,1,2,3,4,5,7,8,9,12,18,99,100,108,109,1023,1024,1025,m.MASK-1,m.MASK)
        for lane in p.TABLES:
            for op in (*range(97,112),m.MASK,0):
                baseline=header(lane,op)
                self.assertEqual(m.decode(lane,op,baseline),oracle(lane,op,baseline))
                for index in range(len(baseline)):
                    for value in values:
                        words=baseline.copy();words[index]=value
                        self.assertEqual(m.decode(lane,op,words),oracle(lane,op,words),(lane,op,index,value))

    def test_pairwise_payload_output_and_source_overflow(self):
        for lane in p.TABLES:
            for op in range(100,109):
                for length in (0,1,1024,1025):
                    for last in (0,1,7,8,9):
                        for source in (0,1,m.MASK-length,m.MASK):
                            w=header(lane,op);w[7]=length;w[8]=last;w[12]=source
                            self.assertEqual(m.decode(lane,op,w),oracle(lane,op,w))
                for width in (0,1,1024,1025):
                    for last in range(10):
                        for terminal in (0,1,2):
                            w=header(lane,op);w[9:12]=[width,last,terminal]
                            self.assertEqual(m.decode(lane,op,w),oracle(lane,op,w))

    def test_seeded_mixed_word_campaign_not_only_invalid_random_data(self):
        rng=random.Random(0x6578706f7274);accepted=0;rejected=0
        for lane in p.TABLES:
            for _ in range(10000):
                op=rng.randrange(100,109);w=header(lane,op)
                if op in (101,103,104):w[7],w[8],w[12]=rng.randrange(1,1025),8,rng.randrange(1,1<<60)
                if op in (104,105,106,108):w[9],w[10]=rng.randrange(1,1025),8
                if op in (100,108):w[3:7]=[rng.randrange(1,1<<64),rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64)]
                if rng.randrange(2):w[rng.randrange(len(w))]=rng.getrandbits(64)
                actual=m.decode(lane,op,w)
                self.assertEqual(actual,oracle(lane,op,w));accepted+=actual is None;rejected+=actual is not None
        self.assertGreater(accepted,5000);self.assertGreater(rejected,5000)

    def test_exact_wire_domain_rejects_unbounded_or_short_inputs(self):
        for lane in p.TABLES:
            w=header(lane,100)
            for bad in (w[:-1],w+[0],[True]+w[1:],[-1]+w[1:],[1<<64]+w[1:]):
                with self.assertRaises(ValueError):m.decode(lane,100,bad)
            for op in (-1,True,1<<64):
                with self.assertRaises(ValueError):m.decode(lane,op,w)

    def test_export_exact_shape_sequence_and_all_retained_phases(self):
        for lane in p.TABLES:
            for phase in range(8):
                for sequence in (0,7,8,9):
                    for identity in range(1,5):
                        for width,last in ((0,0),(1,1),(1024,8)):
                            shape=(identity,width,last)
                            r=m.export(lane,phase,7,sequence,shape,shape)
                            success=phase in (5,6) and sequence==8
                            self.assertEqual(r['error'] is None,success)
                            self.assertEqual(r['phase'],(4 if phase==6 else 0) if success else 7)
                            self.assertEqual(r['successful_copy_observed'],success)
                            if success:
                                events=r['events']
                                self.assertLess(events.index('fixed_output_copy'),events.index('erase_1024_output'))
                                self.assertLess(events.index('clear_shape'),events.index('publish_phase'))
                            else:self.assertNotIn('fixed_output_copy',r['events'])

    def test_copy_failure_and_post_copy_revocation_are_not_rollback(self):
        shape=(1,32,8)
        for lane in p.TABLES:
            for stored in ((2,32,8),(1,31,8),(1,32,7)):
                r=m.export(lane,5,0,1,stored,shape)
                self.assertEqual(r['phase'],7);self.assertNotIn('fixed_output_copy',r['events'])
            r=m.export(lane,5,0,1,shape,shape,copy_ok=False)
            self.assertEqual(r['error'],5);self.assertTrue(r['failed_copy_may_have_written'])
            self.assertFalse(r['output_retracted'])
            for health,kernel in ((0,4),(2,4),(1,3)):
                r=m.export(lane,6,0,1,shape,shape,post_health=health,post_kernel=kernel)
                self.assertTrue(r['successful_copy_observed']);self.assertFalse(r['output_retracted'])
                self.assertEqual(r['phase'],7 if lane=='avx2' else 4)
                self.assertEqual(r['error'],7 if lane=='avx2' else None)


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.inputs={};cls.functions={};cls.records={};cls.names={};cls.bodies={};cls.refs={}
        for lane in p.TABLES:
            x,_=p.inventory.load(SAVED,ROOT,cls.spec[lane]);cls.inputs[lane]=x
            f=p.c.previous.inventory(x['object']);cls.functions[lane]=f;n=p.names(f,lane);cls.names[lane]=n
            cls.records[lane]=p.c.previous.bind_all(x['object'],x['image'],f)
            cls.bodies[lane]={r:f[name][0] for r,name in n.items()}
            cls.refs[lane]={r:f[name][1] for r,name in n.items()}

    def test_selected_report_retains_boundaries(self):
        r=p.inspect(SAVED,ROOT,True)
        for flag in ('pass_complete','completion_package_closed','whole_image_qualified',
            'independently_verified','new_native_run','release_gate_changed'):self.assertFalse(r[flag])
        self.assertEqual(sum(len(v['entries']) for v in r['routes'].values()),4)
        for key in ('reviewed_instruction_bytes','body_byte_mutations_rejected'):
            self.assertEqual(sum(v[key] for v in r['routes'].values()),3106)
        for lane,row in r['routes'].items():
            self.assertTrue(row['remaining']);self.assertFalse(row['semantics']['copy_failure_rollback_proved'])
            self.assertEqual(row['semantics']['authority_rechecked_after_copy'],lane=='avx2')

    def test_all_instruction_bytes_without_body_hash(self):
        count=0
        for lane,bodies in self.bodies.items():
            p.instructions(bodies,lane)
            for role,code in bodies.items():
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):p.instructions(bodies|{role:bad},lane)
                    count+=1
                for bad in (code[:-1],code+b'\x90'):
                    with self.assertRaises(ValueError):p.instructions(bodies|{role:bad},lane)
        self.assertEqual(count,3106)

    def test_all_relative_branch_opcodes_and_targets_without_windows(self):
        count=0
        for lane,roles in p.TABLES.items():
            for role,contract in roles.items():
                for at,op,_ in contract['branches']:
                    for where in (at,at+len(bytes.fromhex(op))):
                        bad=bytearray(self.bodies[lane][role]);bad[where]^=1
                        with self.assertRaises(ValueError):p.life.framing.leaf.finish.windows(bad,[],contract['branches'])
                        count+=1
        self.assertEqual(count,270)

    def test_exact_relocations_cannot_redirect_transport_owner_or_live_identity(self):
        for lane,roles in self.refs.items():
            expected=p.expected_refs(self.functions[lane],lane)
            p.refs_check(self.bodies[lane],roles,expected)
            for role,refs in roles.items():
                for index in range(len(refs)):
                    for field,value in (('offset',0),('symbol','other'),('trailing',1),('addend',99)):
                        bad=copy.deepcopy(roles);bad[role][index][field]=value
                        with self.assertRaises(ValueError):p.refs_check(self.bodies[lane],bad,expected)
                if refs:
                    for bad in (refs[:-1],refs+refs[:1]):
                        with self.assertRaises(ValueError):p.refs_check(self.bodies[lane],roles|{role:bad},expected)

    def test_all_linked_dispatch_table_bytes_and_subtable_bases(self):
        count=0
        for lane,roles in p.DESTINATIONS.items():
            for role,targets in roles.items():
                x=self.inputs[lane];record=self.records[lane][self.names[lane][role]];pin=p.table_pin(lane,role)
                raw,bound=p.table_review.table(x['object'],x['image'],record,pin)
                self.assertEqual(bound['destinations'],sum(targets,[]))
                for at in range(len(raw)):
                    bad=bytearray(raw);bad[at]^=1
                    with patch.object(p.table_review,'readonly',return_value=bad):
                        with self.assertRaises(ValueError):p.table_review.table(x['object'],x['image'],record,pin)
                    count+=1
                bad=copy.deepcopy(pin);bad['operands'][0][1]+=4
                with self.assertRaises(ValueError):p.table_review.table(x['object'],x['image'],record,bad)
                bad=copy.deepcopy(pin);bad['object_hex']='00'+pin['object_hex'][2:]
                with self.assertRaises(ValueError):p.table_review.table(x['object'],x['image'],record,bad)
        self.assertEqual(count,144)

    def test_export_phase_constant_and_original_resident_are_required(self):
        for lane in p.TABLES:
            args=(self.inputs[lane]['image'],self.records[lane],self.names[lane],lane)
            self.assertEqual(p.phases_and_identity(*args),[5,6])
            for value in (b'',b'\x04\x05',b'\x06\x05',b'\x05\x06\x07'):
                with patch.object(p.c.previous,'readonly',return_value=value):
                    with self.assertRaises(ValueError):p.phases_and_identity(*args)
        records=copy.deepcopy(self.records['avx2']);row=records[self.names['avx2']['receive']]
        key=next(n for n in row['reference_targets'] if n.endswith('4LIVE'))
        row['reference_targets'][key]+=8
        with self.assertRaises(ValueError):p.phases_and_identity(self.inputs['avx2']['image'],records,self.names['avx2'],'avx2')

    def test_export_offsets_and_wipe_lengths_without_instruction_hashes(self):
        for lane,offsets in (('scalar',(0x513,0x524,0x52d,0x536,0x571,0x56c,0x576)),
            ('avx2',(0x2b5,0x2be,0x2c7,0x399,0x394,0x39e,0x2e8))):
            m.export_operands(self.bodies[lane],lane)
            for at in offsets:
                bad=bytearray(self.bodies[lane]['receive']);bad[at]^=1
                with self.assertRaises(ValueError):m.export_operands(self.bodies[lane]|{'receive':bad},lane)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--saved-directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=ROOT);args=parser.parse_args()
    SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=['test-windows-enclave-parallel-request.py'])
