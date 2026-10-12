#!/usr/bin/env python3
"""Actual root/caller byte regressions plus independently checked framing models."""
import argparse
import copy
from pathlib import Path
import random
import unittest
from unittest.mock import patch

import windows_enclave_parallel_framing as p
import windows_enclave_parallel_framing_models as m

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Models(unittest.TestCase):
    def test_output_shape_exhaustive_and_xof_zero_domain(self):
        for identity in range(1,5):
            for width in range(1026):
                for last in range(10):
                    valid=width<=1024 and ((width==last==0) or
                        (width>0 and 1<=last<=8)) and (identity<=2 or width==0)
                    if valid:
                        self.assertEqual(m.admitted_output(identity,width,last),
                            (width-1)*8+last if width else 0)
                    else:
                        with self.assertRaises(ValueError):m.admitted_output(identity,width,last)
        for identity in (0,5,True):
            with self.assertRaises(ValueError):m.admitted_output(identity,0,0)

    def test_widen_before_multiply_u64_extremes(self):
        rng=random.Random(0x726f6f74)
        values=[0,1,1024,1<<61,(1<<61)+1,m.MASK]+[rng.getrandbits(64) for _ in range(10000)]
        for width in values:
            for last in (0,1,7,8,255):
                self.assertEqual(m.output_bits(width,last),(width-1)*8+last if width else 0)
        for width,last in ((-1,0),(1<<64,0),(True,0),(0,-1),(1,256)):
            with self.assertRaises(ValueError):m.output_bits(width,last)

    def test_left_encoding_all_u64_widths_and_boundaries(self):
        rng=random.Random(0x6c656674);values={1,m.MASK}
        for bit in range(64):values.update(n for n in ((1<<bit)-1,1<<bit,(1<<bit)+1) if 0<n<=m.MASK)
        values.update(rng.randrange(1,1<<64) for _ in range(10000))
        widths=set()
        for value in values:
            width=(value.bit_length()+7)//8;widths.add(width)
            self.assertEqual(m.left_block(value),bytes([width])+value.to_bytes(width,'big'))
        self.assertEqual(widths,set(range(1,9)))
        for bad in (0,-1,1<<64,True):
            with self.assertRaises(ValueError):m.left_block(bad)

    def test_root_suffix_small_empty_partial_maximum_and_xof(self):
        for identity in range(1,5):
            for width,last in ((0,0),(1,1),(1,8),(32,7),(1024,8)):
                if identity>2 and width:continue
                bits=m.admitted_output(identity,width,last)
                width_bytes=max(1,(bits.bit_length()+7)//8)
                self.assertEqual(p.leaf.finish.right_encoded(bits),
                    bits.to_bytes(width_bytes,'big')+bytes([width_bytes]))
                self.assertLessEqual(bits,8192)
                if identity>2:self.assertEqual(p.leaf.finish.right_encoded(bits),b'\x00\x01')

    def test_relative_geometry_rejects_overlaps_and_cross_field_writes(self):
        for lane in ('scalar','avx2'):
            g=m.relative_regions(lane)
            for field,value in (('output',[g['output'][0],g['output'][1]+1]),
                                ('input',g['root']),('next_width',g['width']),
                                ('next_last',g['last']),('last',g['output'][0])):
                with patch.object(p,'geometry',return_value=g|{field:value}):
                    with self.assertRaises(ValueError):m.relative_regions(lane)

    def test_scalar_setup_copy_ranges_preserve_payload_without_claiming_frame_erasure(self):
        g=m.scalar_setup_copy_geometry();self.assertEqual(g['payload_bytes'],988)
        source=bytes((i*197+13)&255 for i in range(g['payload_bytes']))
        for frame_range in g['branch_frames'].values():
            frame=bytearray(g['allocated_frame_bytes']);owner=bytearray(0x470)
            owner[slice(*g['source_in_owner'])]=source
            frame[slice(*frame_range)]=owner[slice(*g['source_in_owner'])]
            a,b=g['original_setup_clear'];owner[a:b]=bytes(b-a)
            self.assertEqual(owner[slice(*g['source_in_owner'])],bytes(len(source)))
            frame[slice(*g['common_frame'])]=frame[slice(*frame_range)]
            # Old-variant typed drop is a separate callee obligation; do not
            # manufacture a whole-owner wipe in this payload-copy model.
            owner[slice(*g['destination_in_owner'])]=frame[slice(*g['common_frame'])]
            self.assertEqual(owner[slice(*g['destination_in_owner'])],source)
            self.assertEqual(frame[slice(*frame_range)],source)
            self.assertEqual(frame[slice(*g['common_frame'])],source)
        self.assertFalse(g['earlier_frame_copies_cleared_here'])
        self.assertEqual(g['full_window_retirement_package'],8)


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.functions={};cls.bodies={};cls.refs={};cls.expected={};cls.inputs={};cls.records={}
        for lane in ('scalar','avx2'):
            inputs,_=p.inventory.load(SAVED,ROOT,cls.spec[lane]);cls.inputs[lane]=inputs
            f=p.c.previous.inventory(inputs['object']);cls.functions[lane]=f
            n=p.names(f,lane);cls.bodies[lane]={r:f[name][0] for r,name in n.items()}
            cls.refs[lane]={r:f[name][1] for r,name in n.items()}
            cls.expected[lane]=p.expected_refs(f,lane)
            cls.records[lane]=p.c.previous.bind_all(inputs['object'],inputs['image'],f)

    def test_actual_bodies_handlers_and_nonclosure_flags(self):
        result=p.inspect(SAVED,ROOT,True)
        for flag in ('pass_complete','completion_package_closed','whole_image_qualified',
                     'new_native_run','release_gate_changed','independently_verified'):
            self.assertFalse(result[flag])
        self.assertEqual(sum(len(r['entries']) for r in result['routes'].values()),12)
        self.assertEqual(sum(r['body_byte_mutations_rejected'] for r in result['routes'].values()),6852)
        self.assertEqual(sum(r['reviewed_instruction_bytes'] for r in result['routes'].values()),6852)
        for row in result['routes'].values():
            self.assertFalse(row['assembly_listing_used_for_semantics'])
            self.assertFalse(row['complete_sequential_path']);self.assertTrue(row['remaining'])
            self.assertFalse(row['root_return_graph']['panic_cleanup_claimed'])

    def test_every_reviewed_instruction_byte_without_population_hash(self):
        count=0
        for lane,table in p.TABLES.items():
            for role,contract in table.items():
                for _,offset,text in contract['regions']:
                    for at in range(offset,offset+len(bytes.fromhex(text))):
                        bad=bytearray(self.bodies[lane][role]);bad[at]^=1
                        with self.assertRaises(ValueError):
                            p.instructions(self.bodies[lane]|{role:bad},lane)
                        count+=1
        self.assertEqual(count,6852)

    def test_branch_opcodes_and_destinations_without_instruction_windows(self):
        count=0
        for lane,table in p.TABLES.items():
            for role,contract in table.items():
                for at,op,_ in contract['branches']:
                    for pos in (at,at+len(bytes.fromhex(op))):
                        bad=bytearray(self.bodies[lane][role]);bad[pos]^=1
                        with self.assertRaises(ValueError):
                            p.leaf.finish.windows(bad,[],contract['branches'])
                        count+=1
        self.assertEqual(count,380)

    def test_each_direct_call_or_data_relocation_and_population(self):
        for lane in self.bodies:
            for role,refs in self.refs[lane].items():
                for index in range(len(refs)):
                    for field,value in (('symbol','wrong'),('offset',0),('addend',1),('trailing',1)):
                        bad=copy.deepcopy(self.refs[lane]);bad[role][index][field]=value
                        with self.assertRaises(ValueError):p.refs_check(self.bodies[lane],bad,self.expected[lane])
                for replaced in (refs[:-1],refs+refs[:1]):
                    bad=self.refs[lane]|{role:replaced}
                    with self.assertRaises(ValueError):p.refs_check(self.bodies[lane],bad,self.expected[lane])

    def test_phase_constants_are_actual_readonly_linked_bytes(self):
        for lane in self.bodies:
            f=self.functions[lane];n=p.names(f,lane)
            original=p.phase_data(self.inputs[lane]['image'],self.records[lane],n,self.expected[lane])
            self.assertEqual(original,{'finish_custom':[1,2],'finish':[3],'rehash':[5,6]})
            read=p.c.previous.readonly
            for wrong in (b'\x00',b'\x07',b'\x06\x05',b'\x02\x01',b''):
                with patch.object(p.c.previous,'readonly',return_value=wrong):
                    with self.assertRaises(ValueError):
                        p.phase_data(self.inputs[lane]['image'],self.records[lane],n,self.expected[lane])
            self.assertIs(p.c.previous.readonly,read)

    def test_root_cfg_requires_suffix_cleanup_on_every_ordinary_return(self):
        for lane in self.bodies:
            code=self.bodies[lane]['finish_root'];graph=m.root_return_graph(code,lane)
            self.assertEqual(graph['return_states'],7);self.assertEqual(graph['panic_states'],1)
            self.assertTrue(graph['all_condition_edges_explored'])
            self.assertTrue(graph['calls_assume_separately_reviewed_contracts'])
            for branches in ([],p.TABLES[lane]['finish_root']['branches'][:-1]):
                with self.assertRaises(ValueError):m.root_return_graph(code,lane,branches=branches)
            with self.assertRaises(ValueError):m.root_return_graph(code,lane,events={})

    def test_wrong_extent_missing_handler_or_listing_handler_alias_rejects(self):
        for lane in self.bodies:
            for role,code in self.bodies[lane].items():
                for wrong in (code[:-1],code+b'\x90'):
                    with self.assertRaises(ValueError):p.instructions(self.bodies[lane]|{role:wrong},lane)
            bad=dict(self.bodies[lane]);bad.pop('finish_root')
            with self.assertRaises(ValueError):p.instructions(bad,lane)
        f=dict(self.functions['avx2']);actual=p.names(f,'avx2')['finish_root_handler']
        f[actual.replace('?dtor$36','?dtor$35')]=f.pop(actual)
        with self.assertRaises(ValueError):p.names(f,'avx2')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('saved_directory',type=Path,nargs='?')
    parser.add_argument('--source-root',type=Path,default=ROOT)
    args=parser.parse_args();SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=[__file__],verbosity=2)
