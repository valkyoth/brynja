#!/usr/bin/env python3
"""Regressions for complete populations, exact reuse and honest remaining scope."""
import argparse
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_parallel_inventory as i
import windows_enclave_parallel_reuse as r

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Tests(unittest.TestCase):
    def test_manifest_is_frozen_and_has_all_three_routes(self):
        raw=i.SPEC.read_bytes();spec=i.specification(raw)
        self.assertEqual(sum(len(v['functions']) for v in spec.values()),198)
        self.assertEqual(sum(i.FUNCLETS.values()),17)
        with self.assertRaises(ValueError):i.specification(raw+b' ')

    def test_body_extent_kind_and_every_reference_are_bound(self):
        code=b'\xc3';refs=[];pin={'bytes':1,'sha256':i.digest(code),
            'references_sha256':i.digest(json.dumps(refs,sort_keys=True).encode()),'runtime':False}
        i.common.body_check((code,refs,False),pin)
        for value in ((code+b'\x90',refs,False),(b'\x90',refs,False),
                      (code,[{'offset':0,'symbol':'other'}],False),(code,refs,True)):
            with self.assertRaises(ValueError):i.common.body_check(value,pin)

    def test_reuse_requires_full_resolved_abi_not_just_bytes(self):
        f={'helper':(b'\xc3',[],False)}
        before='define void @helper(ptr %0) #0 {\nattributes #0 = { nounwind "target-features"="+avx2" }'
        after=before.replace('+avx2','+sse2')
        result=r.partition(f,f,before,before)
        self.assertEqual(set(result['exact_body_reference_extent_and_abi']),{'helper'})
        self.assertFalse(result['helper_equality_establishes_whole_path'])
        result=r.partition(f,f,after,before)
        self.assertFalse(result['exact_body_reference_extent_and_abi'])
        self.assertEqual(set(result['same_body_but_changed_abi']),{'helper'})

    def test_reuse_resolves_attribute_numbers_instead_of_dropping_attributes(self):
        f={'helper':(b'\xc3',[],False)}
        a='define void @helper() #0 {\nattributes #0 = { nounwind }'
        b=a.replace('#0','#99')
        self.assertTrue(r.partition(f,f,a,b)['exact_body_reference_extent_and_abi'])
        with self.assertRaises(ValueError):r.partition(f,f,b.splitlines()[0],a)

    def test_reuse_references_extent_and_missing_function_stay_distinct(self):
        f={'helper':(b'\xc3',[],False)};ir='define void @helper() {'
        for value in ((b'\xc3',[{'symbol':'changed'}],False),(b'\xc3',[],True),(b'\x90',[],False)):
            result=r.partition({'helper':value},f,ir,ir)
            self.assertEqual(result['distinct_bodies'],['helper'])
            self.assertFalse(result['exact_body_reference_extent_and_abi'])
        self.assertEqual(r.partition(f,{},ir,'')['distinct_bodies'],['helper'])

    def test_reachability_includes_handlers_but_rejects_orphans(self):
        rows={'entry':{'reference_targets':{'helper':10},'metadata':[{'symbol':'handler'}]},
            'helper':{'reference_targets':{}},'handler':{'reference_targets':{}}}
        self.assertEqual(i.reachability(rows,['entry']),sorted(rows))
        bad=copy.deepcopy(rows);bad['entry']['metadata']=[]
        with self.assertRaises(ValueError):i.reachability(bad,['entry'])
        with self.assertRaises(ValueError):i.reachability(rows,['absent'])
        with self.assertRaises(ValueError):i.reachability(rows|{'orphan':{'reference_targets':{}}},['entry'])


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved artifacts required')
        cls.spec=i.specification(i.SPEC.read_bytes());cls.inputs={};cls.functions={};cls.records={}
        for lane,pin in cls.spec.items():
            inputs,_=i.load(SAVED,ROOT,pin);cls.inputs[lane]=inputs
            functions=i.common.previous.inventory(inputs['object']);cls.functions[lane]=functions
            cls.records[lane]=i.common.previous.bind_all(inputs['object'],inputs['image'],functions)

    def test_every_current_body_and_all_relocations_bind(self):
        for lane,pin in self.spec.items():
            i.functions_check(self.functions[lane],pin)
            self.assertEqual(len(i.reachability(self.records[lane],pin['roots'])),i.COUNTS[lane])
            for name,row in self.records[lane].items():
                for target,address in row['reference_targets'].items():
                    if target in self.records[lane]:self.assertEqual(address,self.records[lane][target]['rva'])

    def test_missing_extra_body_and_missing_funclet_rejected(self):
        for lane,pin in self.spec.items():
            f=self.functions[lane];bad=dict(f);bad.pop(next(iter(f)))
            with self.assertRaises(ValueError):i.functions_check(bad,pin)
            with self.assertRaises(ValueError):i.functions_check(f|{'extra':next(iter(f.values()))},pin)
            if lane!='scalar':
                bad={n:v for n,v in f.items() if not n.startswith('?dtor$')}
                with self.assertRaises(ValueError):i.functions_check(bad,pin)

    def test_each_bound_body_rejects_byte_reference_or_extent_drift(self):
        count=0
        for lane,pin in self.spec.items():
            for name,(code,refs,kind) in self.functions[lane].items():
                for changed in ((bytes([code[0]^1])+code[1:],refs,kind),
                    (code,refs+[dict(offset=0,symbol='unreviewed',addend=0,trailing=0)],kind),
                    (code,refs,not kind)):
                    with self.assertRaises(ValueError):i.common.body_check(changed,pin['functions'][name])
                    count+=1
        self.assertEqual(count,594)

    def test_swapped_or_modified_artifact_identity_rejected(self):
        for lane,pin in self.spec.items():
            for field in ('object_sha256','image_sha256','assembly_sha256','ir_sha256','build_sha256'):
                with self.assertRaises(ValueError):i.load(SAVED,ROOT,pin|{field:'0'*64})
            with self.assertRaises(ValueError):i.load(SAVED,ROOT,pin|{'member':'missing.rcgu.o'})

    def test_source_count_and_source_identity_are_not_ambient(self):
        for lane,pin in self.spec.items():
            data=self.inputs[lane]['build']
            with self.assertRaises(ValueError):i.source_binding(ROOT,data,pin|{'source_count':0})
            manifest=json.loads(data);name=next(iter(manifest['source_sha256']))
            manifest['source_sha256'][name]='0'*64
            with self.assertRaises(ValueError):i.source_binding(ROOT,json.dumps(manifest),pin)

    def test_source_paths_cannot_escape_checkout(self):
        for value in ('../outside','/absolute','C:/absolute'):
            manifest={'target':'x86_64-pc-windows-msvc','source_sha256':{value:'0'*64}}
            with self.assertRaises(ValueError):i.source_binding(ROOT,json.dumps(manifest),{'source_count':1})

    def test_fresh_review_failure_propagates_not_old_pass(self):
        with patch.object(r.c,'inspect',side_effect=ValueError('prior semantic review rejected')):
            with self.assertRaisesRegex(ValueError,'prior semantic'):r.inspect(SAVED,ROOT)

    def test_selected_scheduler_cannot_invent_whole_image_qualification(self):
        with patch.object(r.root_return,'inspect',return_value=dict(
                object_sha256=i.digest(self.inputs['concurrent']['object']),
                image_sha256=i.digest(self.inputs['concurrent']['image']),whole_image_qualified=True)):
            with self.assertRaisesRegex(ValueError,'not whole-image'):r.selected_scheduler(self.inputs['concurrent'],SAVED)

    def test_concurrent_object_is_authoritative_not_listing_funclet_name(self):
        f=self.functions['concurrent'];text=self.inputs['concurrent']['assembly'].decode()
        name=next(n for n in f if n.startswith('?dtor$55') and 'Waves6finish' in n)
        self.assertNotIn('\n"'+name+'":\n',text)
        self.assertIn('\n"'+name.replace('?dtor$55','?dtor$54')+'":\n',text)
        self.assertIn(name,self.records['concurrent'])

    def test_reused_helper_constants_must_match_actual_readonly_image_bytes(self):
        for lane,pin in self.spec.items():
            inputs=self.inputs[lane]
            old,old_ir,_,_=r.prior_inputs(SAVED,ROOT,'scalar' if lane=='scalar' else 'avx2')
            exact=r.partition(self.functions[lane],old,inputs['ir'].decode(),old_ir)['exact_body_reference_extent_and_abi']
            constants=r.constant_contract(inputs['object'],inputs['image'],self.records[lane],self.functions[lane],exact)
            self.assertTrue(constants)
            original=r.c.previous.readonly
            def changed(*args):
                raw=original(*args)
                return bytes([raw[0]^1])+raw[1:]
            with patch.object(r.c.previous,'readonly',side_effect=changed):
                with self.assertRaisesRegex(ValueError,'linked helper constant'):
                    r.constant_contract(inputs['object'],inputs['image'],self.records[lane],self.functions[lane],exact)

    def test_reused_helper_mutable_relocated_or_ambiguous_constants_rejected(self):
        records={'helper':{'reference_targets':{'constant':100}}}
        rows=[dict(code=b'fixed',nrelocs=0,flags=0x40000000)]
        symbols={0:dict(name='constant',section=1,value=0)}
        for badrows,badsyms in (([rows[0]|{'nrelocs':1}],symbols),
                ([rows[0]|{'flags':0xc0000000}],symbols),(rows,{}),
                (rows,symbols|{1:symbols[0]}),(rows,{0:symbols[0]|{'value':1}})):
            with patch.object(r.c.obj,'tables',return_value=(badrows,badsyms)):
                with self.assertRaises(ValueError):r.constant_contract(b'object',b'image',records,{'helper'},['helper'])

    def test_full_replayed_map_retains_every_pending_obligation(self):
        result=r.inspect(SAVED,ROOT,True)
        self.assertFalse(result['completion_package_closed']);self.assertFalse(result['whole_image_qualified'])
        self.assertFalse(result['new_native_run']);self.assertFalse(result['release_gate_changed'])
        self.assertEqual(sum(v['body_byte_mutations_rejected'] for v in result['routes'].values()),77211)
        for lane,row in result['routes'].items():
            reuse=row['helper_reuse']
            self.assertEqual(len(reuse['exact_body_reference_extent_and_abi']),r.EXACT[lane])
            self.assertEqual(len(reuse['same_body_but_changed_abi']),r.CHANGED[lane])
            self.assertEqual(set(row['remaining_semantic_body_assignments'])|
                set(reuse['exact_body_reference_extent_and_abi']),set(self.functions[lane]))
            self.assertTrue(row['remaining_path_obligations'])
            self.assertFalse(row['complete_family_review'])
        self.assertEqual(len(result['routes']['concurrent']['selected_prior_reviews']),4)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('saved_directory',type=Path,nargs='?')
    p.add_argument('--source-root',type=Path,default=ROOT)
    args=p.parse_args();SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=[__file__],verbosity=2)
