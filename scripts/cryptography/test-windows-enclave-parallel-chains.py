#!/usr/bin/env python3
"""Combined family reconciliation rejects omissions and qualification overclaims."""
import argparse
import copy
from pathlib import Path
import unittest

import windows_enclave_parallel_chains as p

SAVED=None
ROOT=Path(__file__).resolve().parents[2]


class Saved(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SAVED is None:raise unittest.SkipTest('saved actual COFF/PE artifacts required')
        cls.spec=p.inventory.specification(p.inventory.SPEC.read_bytes())
        cls.routes=p.sequential.inspect(SAVED,ROOT)['routes']
        cls.routes['concurrent']=p.concurrent.inspect_route(SAVED,ROOT)
        cls.sources={};cls.records={}
        for lane,pin in cls.spec.items():
            inputs,cls.sources[lane]=p.inventory.load(SAVED,ROOT,pin)
            f=p.c.previous.inventory(inputs['object'])
            cls.records[lane]=p.c.previous.bind_all(inputs['object'],inputs['image'],f)

    def check(self,routes=None,records=None,shared=None):
        return p.reconcile(self.routes if routes is None else routes,self.spec,self.sources,
            self.records if records is None else records,p.SHARED if shared is None else shared)

    def reject(self,lane,change):
        routes=copy.deepcopy(self.routes);change(routes[lane])
        with self.assertRaises(ValueError):self.check(routes)

    def test_complete_population_conditional_only(self):
        result=self.check()
        self.assertEqual(sum(r['body_count'] for r in result.values()),198)
        self.assertEqual(sum(r['cleanup_funclets'] for r in result.values()),17)
        for lane,r in result.items():
            self.assertEqual(r['build_source_count'],self.spec[lane]['source_count'])
            self.assertTrue(r['prerequisites']);self.assertTrue(r['runtime_boundaries'])

    def test_missing_and_extra_route_never_closes(self):
        for lane in self.routes:
            with self.assertRaises(ValueError):self.check({n:r for n,r in self.routes.items() if n!=lane})
        with self.assertRaises(ValueError):self.check(self.routes|{'invented':self.routes['scalar']})

    def test_each_assignment_required_not_only_count(self):
        for lane,row in self.routes.items():
            for name in row['assignments']:
                def mutate(r):
                    value=r['assignments'].pop(name);r['assignments']['invented']=value
                self.reject(lane,mutate)
            self.reject(lane,lambda r:r['assignments'].__setitem__(next(iter(r['assignments'])),''))

    def test_reachability_and_unassigned_cannot_be_hidden(self):
        for lane in self.routes:
            self.reject(lane,lambda r:r['reachable'].pop())
            self.reject(lane,lambda r:r['reachable'].append(r['reachable'][0]))
            self.reject(lane,lambda r:r['unassigned'].append('unreviewed'))

    def test_wrong_image_object_and_source_rejected(self):
        for lane in self.routes:
            for field in ('image_sha256','object_sha256'):
                self.reject(lane,lambda r:r.__setitem__(field,'0'*64))
            self.reject(lane,lambda r:r['source_sha256'].__setitem__(next(iter(r['source_sha256'])),'0'*64))
            self.reject(lane,lambda r:r['source_sha256'].pop(next(iter(r['source_sha256']))))

    def test_all_actual_handlers_need_exact_parent_edges(self):
        count=0
        for lane,rows in self.records.items():
            for name in rows:
                if not name.startswith('?dtor$'):continue
                count+=1;records=copy.deepcopy(self.records)
                parent=name.split('@?0?',1)[1].removesuffix('@4HA')
                records[lane][parent]['metadata']=[m for m in rows[parent]['metadata'] if m['symbol']!=name]
                with self.assertRaises(ValueError):self.check(records=records)
                records=copy.deepcopy(self.records);records[lane][name]['rva']+=1
                with self.assertRaises(ValueError):self.check(records=records)
        self.assertEqual(count,17)

    def test_runtime_callers_targets_and_handoff_not_omitted(self):
        for lane,row in self.routes.items():
            for name in row['data_bindings']['runtime_boundaries']:
                self.reject(lane,lambda r:r['data_bindings']['runtime_boundaries'].pop(name))
                for field,value in (('callers',[]),('rva',0),('assigned_completion_package',7)):
                    self.reject(lane,lambda r:r['data_bindings']['runtime_boundaries'][name].__setitem__(field,value))

    def test_preconditions_cannot_disappear(self):
        for lane,row in self.routes.items():
            for index in range(len(row['prerequisites'])):
                self.reject(lane,lambda r:r['prerequisites'].pop(index))
        for name in p.SHARED:
            with self.assertRaises(ValueError):self.check(shared={n:v for n,v in p.SHARED.items() if n!=name})
            with self.assertRaises(ValueError):self.check(shared=p.SHARED|{name:'already qualified'})

    def test_scope_and_cleanup_overclaims_rejected(self):
        for lane in self.routes:
            self.reject(lane,lambda r:r.__setitem__('whole_image_qualified',True))
            self.reject(lane,lambda r:r.__setitem__('conditional_rust_family_review_complete',False))
            key='earlier_moved_values_erased_here' if lane=='concurrent' else 'earlier_moved_copies_erased_here'
            self.reject(lane,lambda r:r['caller_lifetime_composition'].__setitem__(key,True))
        self.reject('concurrent',lambda r:r['caller_lifetime_composition'].__setitem__('exception_runtime_qualified',True))

    def test_partial_mutation_campaign_cannot_be_reported_complete(self):
        for lane in self.routes:
            self.reject(lane,lambda r:r.__setitem__('distinct_instruction_mutants_rejected',1))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--saved-directory',type=Path)
    parser.add_argument('--source-root',type=Path,default=ROOT)
    args=parser.parse_args();SAVED=args.saved_directory;ROOT=args.source_root
    unittest.main(argv=[__file__],verbosity=2)
