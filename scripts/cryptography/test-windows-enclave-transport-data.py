"""Nonvacuous status-data, model and native-receipt regression checks."""
import argparse
import copy
import json
from pathlib import Path
import random
import unittest

import windows_enclave_transport_data as data
import windows_enclave_transport_build as build
import windows_enclave_transport_probe as probe


class Tests(unittest.TestCase):
    def test_identity_receipt_is_complete_and_fail_closed(self):
        good = [[1,0,0,0,0,0,1] for _ in range(3)]
        probe.validate(good)
        for bad in ([],good[:-1],good+[good[0]],[[True,0,0,0,0,0,1]]*3):
            with self.assertRaises(RuntimeError): probe.validate(bad)
        for i in range(3):
            for j in range(7):
                changed=copy.deepcopy(good)
                changed[i][j]^=1
                with self.assertRaises(RuntimeError): probe.validate(changed)

    def test_no_unpinned_or_partial_data_set(self):
        for value in ({},{'formats':bytes(176)}, {n:bytes(size) for n,(_,size,_) in data.SPECS.items()}):
            with self.assertRaises(ValueError): data.check(value)

    def test_public_status_is_bounded_and_not_boolean(self):
        for status in (-1,1<<32,True,None,0.0,'0'):
            with self.assertRaises(ValueError): data.convert(status,[],[])


class SavedTests(unittest.TestCase):
    sdk=None
    @classmethod
    def setUpClass(cls):
        cls.parts=data.reference(cls.sdk.read_bytes())
        cls.entries,cls.words=data.check(cls.parts)

    def test_complete_inputs_and_generated_header(self):
        self.assertEqual(len(self.entries),344)
        self.assertEqual(len(self.words),4256)
        self.assertEqual(sum(len(v) for v in self.parts.values()),11440)
        header=build.header(self.parts)
        for name in data.SPECS:
            self.assertEqual(header.count('static const unsigned char sdk_'+name+'[]'),1)
            self.assertEqual(header.count('sizeof(sdk_'+name+')'),1)
        self.assertFalse(data.inspect(self.sdk.read_bytes())['formatter_and_exception_transitive_payload_proof'])

    def test_every_saved_data_byte_is_review_bound(self):
        count=0
        for name,raw in self.parts.items():
            for i in range(len(raw)):
                changed=bytearray(raw)
                changed[i]^=1
                with self.assertRaises(ValueError): data.check(self.parts|{name:bytes(changed)})
                count+=1
        self.assertEqual(count,11440)

    def test_fixed_formats_consume_only_one_numeric_status(self):
        formats=list(data.diagnostic.FORMATS.values())
        self.assertEqual(formats[0].count(b'%'),1)
        self.assertIn(b'%lx',formats[0])
        self.assertFalse(any(b'%' in f for f in formats[1:]))

    def test_special_status_paths(self):
        for status,expected in ((0,0),(0x103,0x3e5),(0x20012345,0x20012345),
                                (0xc0070005,5),(0x80070005,5),(0xffffffff,0xffffffff)):
            self.assertEqual(data.convert(status,self.entries,self.words),(expected,False))
        self.assertEqual(data.convert(0xd000000d,self.entries,self.words),
                         data.convert(0xc000000d,self.entries,self.words))

    def test_binary_and_linear_lookup_boundaries_and_random_values(self):
        values={0,0xffffffff,0x103}
        for start,count,_,_ in self.entries:
            values.update(v for v in range(start,start+count))
            values.update(v for v in (start-1,start+count) if 0<=v<1<<32)
        rng=random.Random(0x4252594e)
        values.update(rng.getrandbits(32) for _ in range(8192))
        self.assertGreater(len(values),10000)
        for status in values:
            self.assertEqual(data.convert(status,self.entries,self.words),
                             data.convert(status,self.entries,self.words,linear=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk',type=Path)
    parser.add_argument('--native',type=Path)
    args=parser.parse_args()
    if args.native:
        record=json.loads(args.native.read_text())
        probe.validate(record['identity_samples'])
        probe.resident.validate(record['cases'])
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    if args.sdk:
        SavedTests.sdk=args.sdk
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SavedTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
