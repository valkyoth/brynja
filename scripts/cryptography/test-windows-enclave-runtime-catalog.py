"""Full-body selector binding, feature prerequisites and frozen route regressions."""
import itertools
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_runtime_catalog as r

SAVED=Path(__file__).resolve().parents[2]/'release-reports/windows-local-20261004'


def body(address=0x9000,shift=0x2000):
    code=bytearray(r.INIT)
    targets={role:role+shift for role in r.DATA}
    for offset,end,role in r.INIT_REFS:
        code[offset:offset+4]=(targets[role]-address-end).to_bytes(4,'little',signed=True)
    return bytes(code),targets


class Tests(unittest.TestCase):
    def test_initializer_entire_body_and_every_byte(self):
        code,targets=body()
        selectors={role:targets[role] for role in r.memory.SELECTORS}
        self.assertEqual(r.initializer(code,0x9000,selectors),targets)
        for offset in range(len(code)):
            bad=bytearray(code);bad[offset]^=1
            with self.assertRaises(ValueError,msg=str(offset)):
                r.initializer(bytes(bad),0x9000,selectors)
        for bad in (b'',code[:-1],code+b'\0'):
            with self.assertRaises(ValueError):r.initializer(bad,0x9000,selectors)

    def test_selector_identity_is_not_just_instruction_identity(self):
        code,targets=body()
        selectors={role:targets[role] for role in r.memory.SELECTORS}
        for key in r.memory.SELECTORS:
            with self.assertRaises(ValueError):
                r.initializer(code,0x9000,selectors | {key:targets[key]+1})
        aliased=bytearray(code)
        for offset,end,role in r.INIT_REFS:
            target=targets[0x11060] if role==0x118bc else targets[role]
            aliased[offset:offset+4]=(target-0x9000-end).to_bytes(4,'little',signed=True)
        with self.assertRaises(ValueError):
            r.initializer(bytes(aliased),0x9000,selectors | {0x118bc:targets[0x11060]})
        for bad in ({},selectors | {1:1},selectors | {0:1}):
            with self.assertRaises(ValueError):r.initializer(code,0x9000,bad)

    def test_loader_data_geometry_permissions_and_zero_tail(self):
        row=dict(rva=100,virtual_size=16,code=b'\x01\x02',flags=0xc0000040)
        self.assertEqual(r.initialized_data([row],100,8),b'\x01\x02'+bytes(6))
        for rows in ([],[row,row],[row | {'flags':0xe0000040}],
                     [row | {'flags':0x40000040}],[row | {'virtual_size':7}]):
            with self.assertRaises(ValueError):r.initialized_data(rows,100,8)
        for start in (99,110,116):
            with self.assertRaises(ValueError):r.initialized_data([row],start,8)

    def test_all_feature_and_xcr0_combinations(self):
        for features in itertools.product((False,True),repeat=5):
            sse,os,avx,avx2,avx512=features
            for xcr0 in range(256):
                level=r.isa_level(sse,os,avx,xcr0,avx2,avx512)
                allowed=os and avx and xcr0&6==6
                self.assertEqual(level>=3,allowed)
                self.assertEqual(level>=5,allowed and avx2)
                self.assertEqual(level==6,allowed and avx2 and avx512 and xcr0&0xe0==0xe0)
                if not allowed:self.assertEqual(level,2 if sse else 1)
        for value in (-1,True,1<<64):
            with self.assertRaises(ValueError):r.isa_level(True,True,True,value,True,True)
        with self.assertRaises(ValueError):r.isa_level(1,True,True,6,True,True)

    def test_import_unknowns_missing_and_aliases(self):
        table={'vertdll.dll':{'TlsAlloc':104},'ucrtbase_enclave.dll':{'malloc':200}}
        self.assertEqual(set(r.import_check(table)),set(table))
        for bad in ({},table | {'unexpected.dll':{'func':300}},
                    table | {'vertdll.dll':{}},table | {'vertdll.dll':{'unknown':104}},
                    table | {'vertdll.dll':{'TlsAlloc':104,'TlsFree':104}},
                    table | {'vertdll.dll':{'TlsAlloc':200}},
                    table | {'vertdll.dll':{'TlsAlloc':105}}):
            with self.assertRaises(ValueError):r.import_check(bad)


class SavedTests(unittest.TestCase):
    def test_all_nineteen_actual_images(self):
        report=r.collect(SAVED)
        self.assertEqual(report['route_count'],19)
        self.assertFalse(report['completion_package_closed'])
        for record in report['records']:
            self.assertEqual(record['initializer']['bytes'],len(r.INIT))
            self.assertFalse(record['loaded_application_iat_proven'])
            self.assertEqual(len(record['runtime']['tables']),8)

    def test_original_image_and_route_hashes_are_required(self):
        with patch.object(r,'ROUTE_HASH','0'*64):
            with self.assertRaises(ValueError):r.catalog()
        rows=r.catalog();rows[0]=rows[0] | {'sha256':'0'*64}
        with patch.object(r,'catalog',return_value=rows):
            with self.assertRaises(ValueError):r.collect(SAVED)

    def test_actual_initializer_mutants_and_loader_data(self):
        row=r.catalog()[0];image=(SAVED/row['image']).read_bytes()
        report=r.inspect(image);sections,_=r.shared.caller.pe.linked(image)
        init=report['initializer'];targets={int(k,16):v for k,v in init['targets'].items()}
        code=r.sdk.mapped(sections,init['rva'],init['bytes'])
        selectors={k:targets[k] for k in r.memory.SELECTORS}
        for offset in range(len(code)):
            bad=bytearray(code);bad[offset]^=1
            with self.assertRaises(ValueError):r.initializer(bytes(bad),init['rva'],selectors)
        original=r.initialized_data
        for role in targets:
            def changed(rows,address,size,role=role):
                value=bytearray(original(rows,address,size))
                if address==targets[role]:value[0]^=1
                return bytes(value)
            with patch.object(r,'initialized_data',side_effect=changed):
                with self.assertRaises(ValueError):r.inspect(image)


if __name__=='__main__':unittest.main()
