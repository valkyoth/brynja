"""Actual outer boundaries must not turn partial SDK evidence into qualification."""
import copy
from pathlib import Path
import unittest

import windows_enclave_outer_window as r

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'release-reports/windows-local-20261004'
DISASSEMBLY=ROOT/'release-reports/windows-worker-review-20261006/stack-disassembly-20261012'


class GeometryTests(unittest.TestCase):
    def test_every_aligned_page_residue_and_both_worker_entries(self):
        for page_offset in range(0,4096,16):
            for offset,residue in ((-104,24),(-216,8)):
                with self.subTest(page_offset=page_offset,offset=offset):
                    value=r.geometry(0x100000+page_offset,offset,-25048)
                    self.assertEqual(value['worker_entry_residue'],residue)
                    self.assertEqual(value['clear_words'],8192)
                    self.assertEqual(value['clear_last_from_low']+8,value['window_bytes'])
                    self.assertEqual(value['bootstrap_from_low'],-4128)
                    self.assertFalse(value['full_stack_bound_proven'])

    def test_exact_window_limit_and_invalid_geometry(self):
        self.assertEqual(r.geometry(0x100000,-104,-65432)['known_low_from_high'],-65536)
        for args in ((0x100000,-104,-65433),(0x100001,-104,-1),(81952,-104,-1),
            (True,-104,-1),(1<<64,-104,-1),(0x100000,-105,-1),
            (0x100000,-216,1),(0x100000,-216,False)):
            with self.subTest(args=args),self.assertRaises(ValueError):r.geometry(*args)

    def test_dominance_checks_bypass_and_denial_paths(self):
        edges={0:[1,2],1:[3],2:[3],3:[4],4:[]}
        self.assertTrue(r.dominates(edges,0,3,4))
        self.assertFalse(r.dominates(edges,0,1,4))
        self.assertFalse(r.dominates(edges|{2:[4]},0,3,4))
        with self.assertRaises(ValueError):r.dominates({0:[1]},0,3,4)


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outer=r.collect(SAVED,DISASSEMBLY)
        cls.stack=r.bridge.collect(SAVED,ROOT,DISASSEMBLY)
        cls.report=r.join_prefixes(copy.deepcopy(cls.outer),cls.stack)

    def wrapper(self,lane):
        row=next(v for v in r.bridge.worker.workers.catalog.catalog()
            if ('object' in v)==(lane=='sequential'))
        name,path,_,_=r.WRAPPERS[lane]
        image=(SAVED/row['image']).read_bytes();obj=(SAVED/path).read_bytes()
        bound=r.bridge.caller.pe.bind(obj,image,name)
        ins=r.bridge.worker.decode.parse((DISASSEMBLY/(row['sha256']+'.txt')).read_text())
        return r.bridge.worker.decode.body(image,bound,ins),bound['rva']

    def test_nineteen_original_images_and_actual_entry_residues(self):
        rows=self.report['records'];self.assertEqual(len(rows),19)
        self.assertEqual(sum(v['body']['frame_bytes']==56 for v in rows),18)
        self.assertEqual(sum(v['body']['frame_bytes']==168 for v in rows),1)
        for row in rows:
            self.assertEqual(row['memory_clear_bytes'],65536)
            self.assertFalse(row['complete_stack_bound_proven'])
            self.assertFalse(row['whole_image_qualified'])
            self.assertEqual(len(row['body']['worker_calls']),2)
            for root in row['actual_entry_prefixes'].values():
                self.assertEqual(bool(root['unresolved_boundaries']),not root['closed_worker_leaf'])
                self.assertFalse(root['geometry']['full_stack_bound_proven'])
        self.assertLess(self.report['maximum_known_prefix_from_window_high'],65536)
        self.assertFalse(self.report['completion_package_closed'])

    def test_each_required_clear_and_restore_is_load_bearing(self):
        for lane in r.LAYOUT:
            code,rva=self.wrapper(lane);contract=r.instructions(code,rva,lane)
            for at in contract['mandatory_instructions']:
                with self.subTest(lane=lane,at=at),self.assertRaises(ValueError):
                    changed=dict(code);raw,text=changed[at]
                    changed[at]=(bytes([raw[0]^1])+raw[1:],text)
                    r.instructions(changed,rva,lane)

    def test_loop_stride_range_probe_register_and_return_mutations(self):
        for lane,plan in r.LAYOUT.items():
            code,rva=self.wrapper(lane)
            for at in (0x43,0x4f,0xf7,plan['clear']+3,plan['readback']+3,
                plan['clear']+10,plan['readback']+10,plan['ret'],plan['final']):
                with self.subTest(lane=lane,at=at),self.assertRaises(ValueError):
                    changed=dict(code);raw,text=changed[at]
                    changed[at]=(bytes([raw[0]^1])+raw[1:],text)
                    r.instructions(changed,rva,lane)

    def test_cfg_bypasses_readback_finish_and_register_clears_reject(self):
        from unittest.mock import patch
        for lane,plan in r.LAYOUT.items():
            code,rva=self.wrapper(lane);edges,calls=r.bridge.worker.decode.graph(code,rva,[])
            for origin,target in ((0,plan['ret']),(plan['clear'],plan['restore']),
                                  (plan['dirty'],plan['finish'])):
                with self.subTest(lane=lane,edge=(origin,target)),self.assertRaises(ValueError):
                    bad=copy.deepcopy(edges);bad[origin]=[target]
                    with patch.object(r.bridge.worker.decode,'graph',return_value=(bad,calls)):
                        r.instructions(code,rva,lane)

    def test_missing_duplicate_mismatched_and_falsely_complete_inputs_reject(self):
        for field,value in (('image_sha256','wrong'),('disassembly_sha256','wrong'),
                            ('route','wrong')):
            bad=copy.deepcopy(self.stack);bad['records'][0][field]=value
            with self.assertRaises(ValueError):r.join_prefixes(copy.deepcopy(self.outer),bad)
        for count in (18,20):
            bad=copy.deepcopy(self.stack);bad['records']=(bad['records']*2)[:count]
            with self.assertRaises(ValueError):r.join_prefixes(copy.deepcopy(self.outer),bad)
        for field,value in (('complete_stack_bytes',1),('unresolved_boundaries',{}),
                            ('known_prefix_low',-65536)):
            bad=copy.deepcopy(self.stack)
            for variants in bad['records'][0]['roots'].values():variants['24'][field]=value
            with self.assertRaises(ValueError):r.join_prefixes(copy.deepcopy(self.outer),bad)

    def test_current_wrapper_objects_and_original_bodies_cannot_be_substituted(self):
        for lane,(name,path,sha,body_sha) in r.WRAPPERS.items():
            obj=(SAVED/path).read_bytes();body,_=r.bridge.caller.function(obj,name)
            self.assertEqual(r.digest(obj),sha);self.assertEqual(r.digest(body),body_sha)
            for at in range(len(body)):
                bad=bytearray(body);bad[at]^=1
                self.assertNotEqual(r.digest(bad),body_sha)
        self.assertNotEqual(r.WRAPPERS['concurrent'][2],r.concurrent.WRAPPER_OBJECT)

    def test_current_images_do_not_already_meet_proposed_sdk_free_boundary(self):
        import windows_enclave_isolation_design as design
        for row in self.stack['records']:
            with self.subTest(route=row['route']),self.assertRaisesRegex(ValueError,'SDK/import/unknown'):
                design.compute_closure(row['function_geometry'],list(row['roots']))
        leaf=self.stack['records'][-1]
        result=design.compute_closure(leaf['function_geometry'],['PrivateWaveLeaf'])
        self.assertTrue(result['sdk_free_call_graph'])
        self.assertFalse(result['implementation_qualified'])


if __name__=='__main__':unittest.main()
