#!/usr/bin/env python3
"""Frozen route/ABI bindings and public plan regressions; not qualification."""
import argparse
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_sha3_batch_chains as c
from windows_enclave_sha3_batch_lifecycle_tests import LifecycleTests
from windows_enclave_sha3_batch_storage_tests import StorageTests,RebindingTests
from windows_enclave_sha3_batch_worker_tests import WorkerTests,WorkerModelTests
from windows_enclave_sha3_batch_receive_tests import ReceiverTests,ReceiverModelTests
from windows_enclave_sha3_batch_update_tests import UpdateTests
from windows_enclave_sha3_batch_chunks_tests import ChunkTests,ChunkModelTests
from windows_enclave_sha3_batch_setup_end_tests import SetupEndTests

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Tests(ChunkModelTests,ReceiverModelTests,WorkerModelTests,RebindingTests,unittest.TestCase):
    def test_inventory_is_frozen_and_has_three_distinct_routes(self):
        raw=c.SPEC.read_bytes();spec=c.specification(raw)
        self.assertEqual({k:len(v['functions']) for k,v in spec.items()},c.COUNTS)
        for data in (raw+b' ',b'{}',raw.replace(b'open_avx2',b'open_____')):
            with self.assertRaises(ValueError):c.specification(data)

    def test_complete_body_extent_and_relocations_are_bound(self):
        values=(b'\x90\xc3',[dict(offset=0,symbol='target',kind=4,addend=0)],False)
        code,refs,kind=values
        pin=dict(bytes=2,sha256=c.digest(code),references_sha256=c.digest(json.dumps(refs,sort_keys=True).encode()),runtime=kind)
        c.c.body_check(values,pin)
        for changed in ((b'\x90\x90',refs,kind),(code+b'\0',refs,kind),(code,[],kind),(code,refs,True)):
            with self.assertRaises(ValueError):c.c.body_check(changed,pin)
        for key,value in [('offset',1),('symbol','other'),('kind',3),('addend',1)]:
            bad=copy.deepcopy(refs);bad[0][key]=value
            with self.assertRaises(ValueError):c.c.body_check((code,bad,kind),pin)

    def test_indirect_calls_remain_explicitly_pending(self):
        body={'root':'root:\ncallq *%rax\nretq'}
        result=c.transfers(body,{}, {})
        self.assertEqual(result['indirect_calls_pending'],{'root':['callq *%rax']})
        self.assertFalse(result['callback_argument_provenance_qualified'])

    def test_indirect_jumps_need_exact_table_population(self):
        body={'root':'root:\njmpq *%rax'};tables={'root':dict(operands=[[4,0]])}
        self.assertEqual(c.transfers(body,tables,{})['bound_jump_sites'],1)
        for bad in ({},{'root':dict(operands=[])},{'root':dict(operands=[[4,0],[8,4]])},
                    tables|{'other':dict(operands=[[0,0]])}):
            with self.assertRaises(ValueError):c.transfers(body,bad,{})

    def test_exact_reuse_keeps_reference_and_resolved_abi_contracts(self):
        prior={'helper':(b'x',[],False)}
        ir='define void @helper(ptr noalias %p) #1 {\nattributes #1 = { nounwind }'
        exact,changed=c.c.reuse.exact_reuse(prior,prior,ir,ir)
        self.assertEqual(set(exact),{'helper'});self.assertFalse(changed)
        for mutation in (ir.replace('noalias ',''),ir.replace('nounwind','noreturn')):
            exact,changed=c.c.reuse.exact_reuse(prior,prior,mutation,ir)
            self.assertFalse(exact);self.assertEqual(set(changed),{'helper'})
        for values in ((b'y',[],False),(b'x',[dict(symbol='other')],False),(b'x',[],True)):
            exact,changed=c.c.reuse.exact_reuse({'helper':values},prior,ir,ir)
            self.assertFalse(exact);self.assertFalse(changed)


class SavedTests(SetupEndTests,ChunkTests,UpdateTests,ReceiverTests,WorkerTests,StorageTests,LifecycleTests,unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved Windows artifacts not supplied')
        cls.saved=SAVED;cls.root=ROOT
        cls.spec=c.specification(c.SPEC.read_bytes());cls.routes={}
        for lane,pin in cls.spec.items():
            row,data,image,asm,ir,sources=c.binding.load(SAVED,ROOT,pin)
            functions=c.c.previous.inventory(data)
            cls.routes[lane]=(data,image,asm,ir,functions,c.c.previous.s.bodies(asm,functions))

    def test_full_saved_binding_preserves_incomplete_scope(self):
        report=c.inspect(SAVED,ROOT)
        self.assertFalse(report['completion_package_closed'])
        self.assertFalse(report['whole_image_qualified'])
        self.assertFalse(report['new_native_run'])
        self.assertTrue(report['remaining_private_review'])
        for lane,r in report['routes'].items():
            self.assertEqual(len(r['functions']),c.COUNTS[lane])
            self.assertEqual(r['cleanup_funclets'],c.FUNCLETS[lane])
            self.assertFalse(r['private_chain_complete'])
            self.assertFalse(r['transitive_depth_qualified'])
            if lane=='simd':
                self.assertIsNone(r['prior_helpers'])
                self.assertTrue(r['transfers']['indirect_calls_pending'])
            else:
                p=r['prior_helpers'];self.assertTrue(p['prior_semantics_replayed'])
                self.assertFalse(p['batch_caller_composition_qualified'])
                self.assertEqual(len(p['exact_body_reference_extent_and_abi']),30 if lane=='scalar' else 23)
                self.assertEqual(len(p['changed_abi_requiring_explicit_review']),0 if lane=='scalar' else 2)

    def test_every_emitted_body_byte_is_bound(self):
        count=0
        for lane,(_,_,_,_,functions,_) in self.routes.items():
            for name,(code,refs,kind) in functions.items():
                pin=self.spec[lane]['functions'][name]
                for at in range(len(code)):
                    bad=bytearray(code);bad[at]^=1
                    with self.assertRaises(ValueError):c.c.body_check((bad,refs,kind),pin)
                    count+=1
        self.assertGreater(count,10000)
        print('SHA-3 batch complete body byte mutations rejected:',count)

    def test_missing_and_added_emitted_functions_reject(self):
        for lane,(_,_,_,_,functions,_) in self.routes.items():
            for name in functions:
                bad=dict(functions);del bad[name]
                with patch.object(c.c.previous,'inventory',return_value=bad):
                    with self.assertRaises(ValueError):c.inspect_route(SAVED,ROOT,lane,self.spec[lane])
            with patch.object(c.c.previous,'inventory',return_value=functions|{'unreviewed':(b'x',[],False)}):
                with self.assertRaises(ValueError):c.inspect_route(SAVED,ROOT,lane,self.spec[lane])

    def test_plan_each_instruction_and_label_is_load_bearing(self):
        count=0
        for lane,(_,_,asm,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            result=c.plan.inspect(bodies,asm,ir);name=result['function']
            lines=c.c.shapes.lines(bodies[name])
            for at,line in enumerate(lines[1:],1):
                if line.startswith('.') and not line.startswith('.B'):continue
                bad=bodies|{name:'\n'.join(lines[:at]+lines[at+1:])}
                with self.assertRaises(ValueError):c.plan.inspect(bad,asm,ir)
                count+=1
        self.assertEqual(count,2*len(c.plan.EXPECTED))
        print('Sequential SHA-3 complete plan instruction/label deletions rejected:',count)

    def test_plan_identity_table_cannot_relabel_algorithms(self):
        count=0
        for lane,(_,_,asm,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            for number in (35 if lane=='avx2' else 36,):
                table=f'.LJTI{number}_0';start=asm.index(table+':\n')+len(table)+2
                lines=asm[start:].splitlines(keepends=True)
                for at in range(9):
                    bad=list(lines);bad[at]=f'\t.long\t.LBB{number}_21-{table}\n'
                    with self.assertRaises(ValueError):c.plan.inspect(bodies,asm[:start]+''.join(bad),ir)
                    count+=1
        self.assertEqual(count,18)

    def test_plan_descriptor_abi_remains_bounded_non_escaping_and_readonly(self):
        for lane,(_,_,asm,ir,_,bodies) in self.routes.items():
            if lane=='simd':continue
            name=c.plan.inspect(bodies,asm,ir)['function']
            declaration=next(l for l in ir.splitlines() if l.startswith('define ') and '@'+name+'(' in l)
            for token,replacement in [('noalias ',' '),('nofree ',' '),('nonnull ',' '),('readonly ',' '),
                    ('align 8','align 1'),('captures(none)','captures(address)'),('dereferenceable(192)','dereferenceable(191)')]:
                bad=ir.replace(declaration,declaration.replace(token,replacement))
                with self.assertRaises(ValueError):c.plan.inspect(bodies,asm,bad)

    def test_prior_review_must_replay_before_any_helper_reuse(self):
        for lane in ('scalar','avx2'):
            _,_,_,ir,functions,_=self.routes[lane]
            reviewer=c.c.scalar if lane=='scalar' else c.c.previous
            with patch.object(reviewer,'inspect',side_effect=ValueError('prior review rejected')) as call:
                with self.assertRaisesRegex(ValueError,'prior review rejected'):
                    c.reused_helpers(SAVED,ROOT,lane,functions,ir,self.spec[lane])
                call.assert_called_once_with(SAVED,ROOT)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--saved-directory',type=Path)
    args,rest=parser.parse_known_args();SAVED=args.saved_directory
    unittest.main(argv=[__file__,*rest])
