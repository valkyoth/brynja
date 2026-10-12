"""Real nineteen-image startup-chain and instruction/edge rejection tests."""
from pathlib import Path
import unittest

import windows_enclave_runtime_catalog as r
import windows_enclave_runtime_startup as s

SAVED=Path(__file__).resolve().parents[2]/'release-reports/windows-local-20261004'


def changed(image,rows,address,value):
    row=next(row for row in rows if row['rva']<=address<row['rva']+len(row['code']))
    offset=row['raw']+address-row['rva'];result=bytearray(image)
    result[offset]=value
    return bytes(result)


class Tests(unittest.TestCase):
    def test_all_startup_bodies_and_every_normalized_byte(self):
        for name,(address,h,refs) in s.BODIES.items():
            code=bytearray.fromhex(h)
            for offset,end,role in refs:
                code[offset:offset+4]=(role-address-end).to_bytes(4,'little',signed=True)
            targets=s.normalize(name,code,address)
            for offset in range(len(code)):
                bad=bytearray(code);bad[offset]^=1
                try:mutant=s.normalize(name,bad,address)
                except ValueError:continue
                self.assertNotEqual(mutant,targets,(name,offset))
            for bad in (b'',code[:-1],code+b'\0'):
                with self.assertRaises(ValueError):s.normalize(name,bad,address)

    def test_executable_full_span_and_permissions(self):
        row=dict(rva=100,code=bytes(10),virtual_size=10,flags=0x60000020)
        self.assertEqual(s.executable([row],100,10),bytes(10))
        for rows in ([],[row,row],[row | {'flags':0xe0000020}],
                     [row | {'flags':0x40000040}],[row | {'virtual_size':9}]):
            with self.assertRaises(ValueError):s.executable(rows,100,10)


class SavedTests(unittest.TestCase):
    def test_all_nineteen_startup_chains(self):
        for row in r.catalog():
            report=r.inspect((SAVED/row['image']).read_bytes())
            startup=report['startup']
            self.assertTrue(startup['normal_process_attach_initializes_selectors_before_application'])
            self.assertFalse(startup['loaded_startup_order_observed'])
            self.assertEqual(len(startup['bodies']),5)

    def test_actual_chain_edges_callback_and_dllmain_mutants(self):
        for row in r.catalog():
            image=(SAVED/row['image']).read_bytes();report=r.inspect(image)
            rows,_=r.sdk.pe.linked(image);init=report['initializer']['rva']
            startup=report['startup'];bodies=startup['bodies']
            sites=[bodies[name]['rva']+offset for name,offset in
                (('entry',57),('main',107),('main',221),('dispatch',61),('attach',30),('crt',16))]
            sites += [startup['pre_crt_hook_rva'],startup['application_dllmain_rva']]
            for address in sites:
                old=s.sdk.mapped(rows,address,1)[0]
                with self.assertRaises(ValueError,msg=(row['route'],address)):
                    s.inspect(changed(image,rows,address,old^1),init)
            pe_offset,=s.sdk.pe.unpack('<I',image,0x3c)
            bad=bytearray(image);bad[pe_offset+24+16]^=1
            with self.assertRaises(ValueError):s.inspect(bytes(bad),init)


if __name__=='__main__':unittest.main()
