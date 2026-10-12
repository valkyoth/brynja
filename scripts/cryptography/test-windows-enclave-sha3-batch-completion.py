#!/usr/bin/env python3
"""Finite family closure rejects omitted contracts, bodies and cleanup roles."""
import argparse
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import windows_enclave_sha3_batch_chains as c
t=c.family_completion
SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved artifacts required')
        cls.routes={}
        for lane,pin in c.specification(c.SPEC.read_bytes()).items():
            _,data,image,asm,_,_=c.binding.load(SAVED,ROOT,pin)
            f=c.c.previous.inventory(data);b=c.c.previous.s.bodies(asm,f);records=c.binding.bind_all(data,image,f)
            sizes,_,vectors,_,_=c.c.frames(records,b)
            r=c.inspect_route(SAVED,ROOT,lane,pin)
            cls.routes[lane]=(records,b,sizes,vectors,r['dispatch_tables'],r['transfers']['readonly_callback_tables'],r,lane)

    def test_every_named_semantic_prerequisite_is_required(self):
        count=0
        for args in self.routes.values():
            r,lane=args[-2:];required=t.SIMD if lane=='simd' else t.SEQUENTIAL|(t.SCALAR if lane=='scalar' else t.AVX2)
            for section,fields in required.items():
                for field in fields:
                    with patch.dict(r[section],{field:False}):
                        with self.assertRaises(ValueError):t.inspect(*args)
                    count+=1
        self.assertGreater(count,90)
        print('Final family semantic prerequisite mutations rejected:',count)

    def test_unknown_or_orphan_body_and_missing_handler_rejected(self):
        for args in self.routes.values():
            records,b,sizes,vectors,tables,vtables,r,lane=args
            bad=records|{'unreviewed_helper':next(iter(records.values()))}
            with self.assertRaises(ValueError):t.assignment.functions(bad,r,lane)
            # A known-role name still cannot be accepted as an unreachable body.
            name='_RNv_unlinked_Owner5begin';row=copy.deepcopy(next(iter(records.values())))
            row['reference_targets']={};row['metadata']=[]
            with self.assertRaises(ValueError):t.assignment.population(records|{name:row},b|{name:name+':\nretq'},tables,vtables,r,lane)
            if lane!='scalar':
                bad=copy.deepcopy(records)
                for row in bad.values():row['metadata']=[]
                with self.assertRaises(ValueError):t.assignment.population(bad,b,tables,vtables,r,lane)

    def test_actual_indirect_operand_population_and_vtable_cannot_drift(self):
        records,b,_,_,tables,vtables,r,lane=self.routes['simd']
        for name,lines in t.assignment.indirect(r,lane).items():
            code=t.assignment.life.code(b[name]);at=code.index(lines[0]);code[at]='callq *%r11'
            bad=b|{name:name+':\n'+'\n'.join(code)}
            with self.assertRaises(ValueError):t.assignment.population(records,bad,tables,vtables,r,lane)
        bad=copy.deepcopy(vtables);next(iter(bad.values()))['slots']['32']='unreviewed_callback'
        with self.assertRaises(ValueError):t.assignment.population(records,b,tables,bad,r,lane)

    def test_frame_and_padding_assignment_does_not_claim_individual_erasure(self):
        for args in self.routes.values():
            records,b,sizes,vectors,tables,vtables,r,lane=args;result=t.inspect(*args)
            self.assertEqual(set(result['functions']),set(result['storage']['transient']['frames']))
            self.assertFalse(result['storage']['transient']['individual_spills_moves_padding_or_registers_erased'])
            self.assertFalse(result['whole_frame_erasure_qualified']);self.assertFalse(result['whole_image_qualified'])
            self.assertFalse(result['arbitrary_exception_or_fatal_abort_cleanup_qualified'])
            for bad in ({},sizes|{next(iter(sizes)):65536}):
                with self.assertRaises(ValueError):t.assignment.storage(records,bad,vectors,r,lane)
            bad=copy.deepcopy(vectors);bad[next(iter(bad))]=[[6,65536]]
            with self.assertRaises(ValueError):t.assignment.storage(records,sizes,bad,r,lane)

    def test_fatal_terminal_is_not_a_cleanup_return(self):
        b=self.routes['simd'][1]
        for name in t.assignment.terminals(b,'simd')['functions']:
            with self.assertRaises(ValueError):t.assignment.terminals(b|{name:b[name]+'\nretq'},'simd')
        name=t.s.one(b,r'Executor13digest_secret$')
        bad=b|{name:b[name].replace('panic_const24panic_const_add_overflow','panicking9panic_fmt')}
        with self.assertRaises(ValueError):t.assignment.terminals(bad,'simd')

    def test_replayed_handler_and_empty_pending_sets_required(self):
        args=self.routes['simd'];r=args[-2]
        for field in ('pending_callee_effect_sites','pending_non_frame_store_sites'):
            with patch.dict(r['simd_service_call_effects'],{field:[1]}):
                with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(r['simd_exception_call_effects']['final_health_cleanup'],{'authority_health_byte_cleared_on_invoked_unwind':False}):
            with self.assertRaises(ValueError):t.inspect(*args)
        with patch.dict(r['simd_executor_effect_composition'],{'call_assignments':{}}):
            with self.assertRaises(ValueError):t.inspect(*args)

    def test_all_three_routes_required_and_failure_propagates(self):
        r=c.inspect(SAVED,ROOT)
        self.assertTrue(r['completion_package_closed']);self.assertEqual(r['remaining_private_review'],[])
        self.assertEqual(sum(len(v['functions']) for v in r['routes'].values()),166)
        self.assertEqual(sum(v['cleanup_funclets'] for v in r['routes'].values()),19)
        for lane in self.routes:
            original=t.inspect
            def fail(*args):
                if args[-1]==lane:raise ValueError('family failed')
                return original(*args)
            with patch.object(t,'inspect',side_effect=fail):
                with self.assertRaisesRegex(ValueError,'family failed'):c.inspect(SAVED,ROOT)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--saved-directory',type=Path);a,rest=p.parse_known_args()
    SAVED=a.saved_directory
    unittest.main(argv=[__file__,*rest])
