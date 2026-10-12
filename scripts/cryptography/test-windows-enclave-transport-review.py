"""Actual PE/COFF mutation checks for the separate transport-data canary."""
import argparse
from pathlib import Path
import unittest

import windows_enclave_transport_review as review


class Tests(unittest.TestCase):
    directory=None
    sdk=None

    @classmethod
    def setUpClass(cls):
        cls.image=(cls.directory/'signed.dll').read_bytes()
        cls.obj=(cls.directory/'normal.obj').read_bytes()
        cls.record=review.inspect(cls.directory,(cls.directory/'disassembly.txt').read_text(),
                                  cls.sdk.read_bytes())

    def mutate(self,rva):
        rows,_=review.bridge.caller.pe.linked(self.image)
        row=next(r for r in rows if r['rva']<=rva<r['rva']+len(r['code']))
        changed=bytearray(self.image)
        changed[row['raw']+rva-row['rva']]^=1
        return bytes(changed)

    def test_complete_scoped_reconciliation(self):
        self.assertEqual(self.record['native_cases'],33)
        self.assertEqual(self.record['identity_observations'],21)
        self.assertEqual(self.record['compute']['direct_sites'],56)
        self.assertEqual(self.record['compute']['indirect_sites'],0)
        self.assertEqual(len(self.record['compute']['closure']['functions']),10)
        self.assertTrue(self.record['compute']['closure']['sdk_free_call_graph'])
        for field in ('whole_image_qualified','completion_package_closed','production_qualified',
                      'os_return_registers_qualified','formatter_and_exception_transitive_payload_proof'):
            self.assertIs(self.record[field],False)

    def test_every_identity_instruction_byte_is_bound(self):
        count=0
        for name,key in [('transport_identity','identity'),('isolated_text_sdk','text_identity'),
                         ('PublicTransportIdentity','diagnostic_export')]:
            raw,refs=review.bridge.caller.function(self.obj,name)
            relocations={i for r in refs for i in range(r['offset'],r['offset']+4)}
            rva=self.record[key]['rva']
            for i in range(len(raw)):
                if i in relocations: continue
                with self.assertRaises(ValueError): review.bind(self.obj,self.mutate(rva+i),name,rva)
                count+=1
        self.assertEqual(count,726)

    def test_data_descriptors_and_expected_arrays_are_load_bearing(self):
        identity,text=self.record['identity'],self.record['text_identity']
        table=identity['reference_targets']['sdk_data']
        sites=[table+i for i in range(72)]
        for row in self.record['embedded_data'].values():
            sites += [row['expected_rva'],row['expected_rva']+row['bytes']-1]
        sites += [text['reference_targets']['sdk_expected'],
                  text['reference_targets']['sdk_expected']+0x1dc4b-1]
        for rva in sites:
            with self.assertRaises(ValueError):
                review.constants(self.mutate(rva),identity,text,self.sdk.read_bytes())
        self.assertEqual(len(sites),80)

    def test_actual_identity_edge_cannot_be_retargeted(self):
        rva=self.record['root']['rva']
        changed=self.mutate(rva+151)
        # Two references to one named identity must resolve to the same body.
        with self.assertRaises(ValueError): review.root_bind(self.obj,changed)

    def test_original_root_bytes_remain_load_bearing(self):
        raw,refs=review.bridge.caller.function(self.obj,'PublicIsolatedSha256')
        relocs={i for r in refs for i in range(r['offset'],r['offset']+4)}
        count=0
        for i in range(len(raw)):
            if i in relocs: continue
            with self.assertRaises(ValueError): review.root_bind(self.obj,self.mutate(self.record['root']['rva']+i))
            count+=1
        self.assertEqual(count,661)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--saved',type=Path,required=True)
    parser.add_argument('--sdk',type=Path,required=True)
    args=parser.parse_args()
    Tests.directory,Tests.sdk=args.saved,args.sdk
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
