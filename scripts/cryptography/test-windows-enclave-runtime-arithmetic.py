"""Fail-closed helper identity, probe geometry, ABI and real-image regressions."""
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_runtime_arithmetic as a
import windows_enclave_runtime_abi as abi

SAVED=Path(__file__).resolve().parents[2]/'release-reports/windows-local-20261004'


class ModelTests(unittest.TestCase):
    def test_every_runtime_byte_is_bound(self):
        for name,code in a.BODIES.items():
            a.check_body(name,code)
            for i in range(len(code)):
                changed=bytearray(code);changed[i]^=1
                with self.assertRaises(ValueError):a.check_body(name,bytes(changed))
            for changed in (code[:-1],code+b'\xc3',b''):
                with self.assertRaises(ValueError):a.check_body(name,changed)
        with self.assertRaises(ValueError):a.check_body('unknown',b'')

    def test_probe_committed_limit_below_private_window(self):
        self.assertEqual(a.probe_pages(0x20000,0x7000,0xe000,0x10000),[])
        self.assertEqual(a.probe_pages(0x20000,0x7000,0x1c000,0x10000),[0x1b000,0x1a000,0x19000])
        self.assertEqual(a.probe_pages(0x20000,0x7001,0x1c000,0x10000),[0x1b000,0x1a000,0x19000,0x18000])
        self.assertEqual(a.probe_pages(0x20000,0x10000,0x1c000,0x10000)[-1],0x10000)

    def test_probe_rejects_wrap_underflow_nonpages_and_missing_home(self):
        good=(0x20000,4096,0x18000,0x10000)
        for index,value in ((0,-1),(0,True),(0,1<<64),(1,-1),(1,65537),
                            (2,0x18001),(2,0x21000),(3,0x10001),(3,0x21000)):
            args=list(good);args[index]=value
            with self.assertRaises(ValueError):a.probe_pages(*args)
        with self.assertRaises(ValueError):a.probe_pages(0x10010,0,0x10000,0x10000)

    def test_probe_all_page_and_allocation_boundaries(self):
        for limit in range(0xf000,0x21000,4096):
            for size in (0,1,4095,4096,4097,65535,65536):
                pages=a.probe_pages(0x20000,size,limit,0x10000)
                self.assertTrue(all(0x10000<=p<limit and p%4096==0 for p in pages))
                self.assertEqual(len(pages),len(set(pages)))
                self.assertEqual(bool(pages),0x20000-size<limit)

    def test_low_division_domain_and_independent_relations(self):
        for n,d in abi.operands():
            if n<1<<64 and d<1<<64:
                q,r=a.divide_low(n,d);self.assertEqual(q*d+r,n);self.assertLess(r,d)
        for n,d in ((0,0),(-1,1),(1,True),(True,1),(1<<64,1),(1,1<<64)):
            with self.assertRaises(ValueError):a.divide_low(n,d)

    def test_oracle_corpus_covers_wide_operands(self):
        pairs=abi.operands();self.assertEqual(pairs,abi.operands());self.assertEqual(len(pairs),702)
        self.assertTrue(any(a>=1<<64 and b>=1<<64 for a,b in pairs))
        self.assertTrue(any(a<b for a,b in pairs));self.assertTrue(any(a==b for a,b in pairs))
        self.assertTrue(all(0<=a<1<<128 and 0<b<1<<128 for a,b in pairs))

    def test_abi_wrapper_layout_and_negative_population(self):
        code=abi.WRAPPER
        self.assertEqual(len(code),676)
        self.assertTrue(code.startswith(bytes.fromhex('5355565741544155415641574881ece8000000')))
        self.assertTrue(code.endswith(bytes.fromhex('4881c4e8000000415f415e415d415c5f5e5d5bc3')))
        self.assertEqual(code.count(bytes.fromhex('ffd0')),1)
        self.assertEqual(len(set(abi.corruptions())),18)
        self.assertTrue(all(v.endswith(b'\xc3') for v in abi.corruptions()))

    def test_abi_failure_is_not_relabelled_success(self):
        def missing_marker(*args):pass
        with self.assertRaises(ValueError):abi.call(missing_marker,0,0,0)


class SavedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.report=a.collect(SAVED)

    def test_complete_real_population(self):
        self.assertEqual(len(self.report['records']),19)
        self.assertFalse(self.report['cumulative_stack_bound_proven'])
        self.assertFalse(self.report['whole_image_qualified'])
        names={n for r in self.report['records'] for n in r['helpers']}
        self.assertEqual(names,set(a.BODIES))
        for row in self.report['records']:
            for n,h in row['helpers'].items():
                self.assertEqual(h['sha256'],a.digest(a.BODIES[n]));self.assertTrue(h['sites'])

    def test_actual_probe_operands_and_calls_reject_mutations(self):
        row=next(r for r in a.r.catalog() if r['route']=='sha256_simd/mod.rs::open_avx2')
        data,image=a.workers.load(SAVED,row);functions,records=a.workers.bind(data,image)
        helper=a.inspect(image,functions,records)['__chkstk']
        for site in helper['sites']:
            name=site['caller'];code,refs,runtime=functions[name];at=site['offset']
            for offset in (at-5,at-1,at,at+5,at+6,at+7):
                changed=bytearray(code);changed[offset]^=0x40
                with self.assertRaises(ValueError):
                    a.inspect(image,functions | {name:(bytes(changed),refs,runtime)},records)

    def test_original_hash_required_before_runtime_review(self):
        row=a.r.catalog()[0]
        with self.assertRaises(ValueError):a.workers.load(SAVED,row | {'sha256':'0'*64})
        with patch.object(a,'BODIES',a.BODIES | {'__chkstk':b'\xc3'}):
            row=next(r for r in a.r.catalog() if 'sha_ni' in r['route'])
            data,image=a.workers.load(SAVED,row);functions,records=a.workers.bind(data,image)
            with self.assertRaises(ValueError):a.inspect(image,functions,records)


if __name__=='__main__':unittest.main()
