"""Nonvacuous boundary/geometry/storage regressions for the actual 08A image."""
import argparse
import copy
from pathlib import Path
import unittest

import windows_enclave_isolated_boundary as review


class GeometryTests(unittest.TestCase):
    def test_every_aligned_page_residue_and_exact_depth(self):
        for at in range(0,4096,16):
            row=review.geometry(0x100000+at)
            self.assertEqual(row['compute_entry_residue'],24)
            self.assertEqual(row['depth_from_window_high'],2584)
            self.assertEqual(row['window_high']-row['window_low'],65536)
            self.assertGreaterEqual(row['compute_low'],row['window_low'])
            self.assertLessEqual(row['probed_low'],row['bootstrap']-8)
            self.assertTrue(row['probe_is_not_sdk_depth_bound'])
            self.assertEqual(sorted(row['home_slots'].values()),[0x100010+at,0x100018+at,0x100020+at])

    def test_exact_fit_and_one_byte_overflow(self):
        row=review.geometry(0x100000,65536-40)
        self.assertEqual(row['compute_low'],row['window_low'])
        with self.assertRaises(ValueError): review.geometry(0x100000,65536-39)

    def test_invalid_geometry_never_invents_a_bound(self):
        for rbp,bound in ((False,2544),(0,2544),(81952,2544),(1<<64,2544),
                          (0x100001,2544),(0x100000,False),(0x100000,-1),
                          (0x100000,65536),(0x100000,'2544')):
            with self.assertRaises(ValueError): review.geometry(rbp,bound)


class SavedTests(unittest.TestCase):
    directory=None
    sdk=None

    @classmethod
    def setUpClass(cls):
        cls.image=(cls.directory/'signed.dll').read_bytes()
        cls.obj=(cls.directory/'normal.obj').read_bytes()
        cls.text=(cls.directory/'disassembly.txt').read_text()
        cls.record=review.inspect(cls.directory,cls.text,cls.sdk.read_bytes())
        cls.wrapper=(cls.directory/'window.obj').read_bytes()
        cls.raw,_=review.bridge.caller.pe.coff(cls.wrapper,'PublicLockedFrame')
        cls.code=review.resident.review.decode.body(cls.image,cls.record['wrapper'],
            review.resident.review.decode.parse(cls.text))

    def mutate(self,rva):
        rows,_=review.bridge.caller.pe.linked(self.image)
        row=next(r for r in rows if r['rva']<=rva<r['rva']+len(r['code']))
        value=bytearray(self.image)
        value[row['raw']+rva-row['rva']]^=1
        return bytes(value)

    def test_full_bound_is_only_the_normal_compute_window(self):
        self.assertEqual(self.record['compute_depth_from_high'],2584)
        self.assertEqual(self.record['aligned_page_residues'],256)
        self.assertEqual(len(self.record['control_storage']),24)
        self.assertTrue(self.record['complete_brynja_normal_compute_window_bound'])
        for name in ('whole_thread_stack_bound','incoming_register_payload_provenance',
                     'sdk_transport_payload_handling_qualified','asynchronous_exception_cleanup_qualified',
                     'whole_image_qualified','completion_package_closed','production_qualified',
                     'new_native_execution'):
            self.assertIs(self.record[name],False)

    def test_all_399_wrapper_bytes_are_required(self):
        for i in range(len(self.raw)):
            changed=bytearray(self.raw)
            changed[i]^=1
            with self.assertRaises(ValueError):
                review.wrapper_contract(bytes(changed),self.code,self.record['wrapper']['rva'])

    def test_all_linked_wrapper_instruction_bytes_are_required(self):
        _,refs=review.bridge.caller.pe.coff(self.wrapper,'PublicLockedFrame')
        relocations={i for at,_ in refs for i in range(at,at+4)}
        count=0
        for i in range(len(self.raw)):
            if i in relocations: continue
            with self.assertRaises(ValueError):
                review.bridge.caller.pe.bind(self.wrapper,self.mutate(self.record['wrapper']['rva']+i),
                                             'PublicLockedFrame')
            count+=1
        self.assertEqual(count,351)

    def test_every_helper_instruction_byte_is_bound(self):
        count=0
        for name,record in self.record['helpers'].items():
            raw,refs=review.bridge.caller.function(self.obj,name)
            relocations={i for ref in refs for i in range(ref['offset'],ref['offset']+4)}
            for i in range(len(raw)):
                if i in relocations: continue
                with self.assertRaises(ValueError):
                    review.bind(self.obj,self.mutate(record['rva']+i),name,record['rva'])
                count+=1
        self.assertEqual(count,1045)

    def test_dirty_branch_and_cleanup_bypasses_reject(self):
        for at,target in ((0x12c,0x12e),(0x12c,0x145),(0xba,0x149),(0x13a,0x18e)):
            changed=copy.deepcopy(self.code)
            old,text=changed[at]
            self.assertEqual(len(old),2)
            changed[at]=(old[:1]+((target-at-2)&255).to_bytes(1,'little'),text)
            with self.assertRaises(ValueError):
                review.wrapper_contract(self.raw,changed,self.record['wrapper']['rva'])

    def test_each_full_control_span_must_be_disjoint_and_owned(self):
        targets={row['name']:row['rva'] for row in self.record['control_storage']}
        for name in review.SIZES:
            with self.assertRaises(ValueError): review.storage(self.image,{k:v for k,v in targets.items() if k!=name})
            with self.assertRaises(ValueError): review.storage(self.image,targets|{name:1})
            other=next(k for k in targets if k!=name)
            with self.assertRaises(ValueError): review.storage(self.image,targets|{name:targets[other]})


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--saved',type=Path,required=True)
    parser.add_argument('--sdk',type=Path,required=True)
    args=parser.parse_args()
    SavedTests.directory,SavedTests.sdk=args.saved,args.sdk
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(t)
                             for t in (GeometryTests,SavedTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
