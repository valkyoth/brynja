"""Saved unwind-frame arithmetic, drift and qualification-limit regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_unwind as unwind


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(size) for n,(_,size,_) in unwind.BODIES.items()}
        for name,instruction,target in unwind.EDGES:
            offset = instruction-unwind.BODIES[name][0]
            bodies[name][offset:offset+5] = b'\xe8'+(target-instruction-5).to_bytes(4,'little',signed=True)
        offset = 0xc926-unwind.BODIES['code_slots'][0]
        bodies['code_slots'][offset:offset+7] = b'\x48\x8d\x0d'+(
            unwind.TABLE_RVA-0xc92d).to_bytes(4,'little',signed=True)
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(unwind.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_sizes_and_byte_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(unwind.BODIES,specs,clear=True):
            self.assertEqual(unwind.mutations(bodies,unwind.TABLE),dict(body_bytes=2417,table_bytes=11))
            for name,body in bodies.items():
                for changed in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): unwind.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError):
                    unwind.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): unwind.check_bodies(bodies|{'extra':b''})

    def test_vacuous_body_and_table_campaigns_rejected(self):
        bodies,specs = self.synthetic()
        with patch.object(unwind,'check_bodies'):
            with self.assertRaises(AssertionError): unwind.mutations(bodies,unwind.TABLE)
        with patch.dict(unwind.BODIES,specs,clear=True), patch.object(unwind,'check_table'):
            with self.assertRaises(AssertionError): unwind.mutations(bodies,unwind.TABLE)

    def test_direct_transfers_and_table_reference(self):
        bodies,_ = self.synthetic()
        unwind.check_edges(bodies)
        self.assertEqual(len(unwind.EDGES),9)
        positions = [(n,a-unwind.BODIES[n][0]+i) for n,a,_ in unwind.EDGES for i in range(5)]
        positions += [('code_slots',0xc926-unwind.BODIES['code_slots'][0]+i) for i in range(7)]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): unwind.check_edges(bodies|{name:bytes(changed)})

    def test_table_size_and_content(self):
        self.assertEqual(len(unwind.TABLE),11)
        unwind.check_table(unwind.TABLE)
        for value in (b'',unwind.TABLE[:-1],unwind.TABLE+b'\x01'):
            with self.assertRaises(ValueError): unwind.check_table(value)
        for i in range(11):
            value = bytearray(unwind.TABLE)
            value[i] ^= 1
            with self.assertRaises(ValueError): unwind.check_table(bytes(value))

    def test_frames_and_caller_owned_flag_slot(self):
        for capacity in (128,256,384,512):
            result = unwind.geometry(unwind.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                for origin,extra in (('engine',0),('wide_helper',-128)):
                    adapter = -14624-capacity+shift+extra
                    row = result[path][origin]
                    self.assertEqual(row['frames'],dict(engine=adapter-176,code_slots=adapter-224,
                                                       chain_entry=adapter-224,lookup=adapter-256))
                    self.assertEqual(len(row['spans']),9)
                    spans = {s['name']:s for s in row['spans']}
                    self.assertEqual(spans['engine working flag in adapter slot']['offset_from_high'],
                                     adapter+80)
                    self.assertEqual(spans['engine working flag in adapter slot']['bytes'],4)
                    self.assertEqual(spans['code-slot input home']['offset_from_high'],adapter-176)
                    self.assertEqual(spans['adapter returned handler and address slots']['offset_from_high'],
                                     adapter+96)
                    for span in row['spans']:
                        self.assertGreaterEqual(span['offset_from_low'],0)
                        self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                    self.assertEqual(row['exceptional'],dict(direct_first_raise_from_high=adapter-1616,
                        helper_first_raise_from_high=adapter-1664,transitive_depth_bound=None,
                        cleanup_qualified=False))
                    for unknown in row['unknown_callees']:
                        self.assertIsNone(unknown['callee_frame_bytes'])
                        self.assertFalse(unknown['callee_spills_qualified'])

    def test_translation_and_capacity_validation(self):
        for capacity in (128,256,384,512):
            self.assertEqual(unwind.geometry(unwind.Window(0,65536),capacity),
                unwind.geometry(unwind.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): unwind.geometry(unwind.Window(0,65536),capacity)

    def test_identity_precedes_parsing(self):
        with patch.object(unwind.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): unwind.inspect(b'MZ-unreviewed')

    def test_sections_and_nonclaims(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        table_row = dict(rva=unwind.TABLE_RVA,virtual_size=11,code=unwind.TABLE,flags=0x40000040)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0xcf78,0xbc90)])
        with patch.dict(unwind.BODIES,specs,clear=True), \
                patch.object(unwind.locking,'inspect',return_value=previous):
            with patch.object(unwind.diagnostic.status.sdk.pe,'linked',return_value=([row,table_row],None)):
                result = unwind.inspect(b'fixture',True)
            self.assertEqual(result['mutations_rejected'],dict(body_bytes=2417,table_bytes=11))
            self.assertEqual({r['rva'] for r in result['unresolved']},{0xbc90,0xc538,0xc94c})
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'arbitrary_metadata_bounds_qualified','context_destination_bounds_qualified',
                          'sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row],[row,row,table_row],[row,table_row,table_row],
                         [row|{'flags':0xa0000000},table_row],
                         [row|{'virtual_size':1},table_row],[row|{'code':b''},table_row],
                         [row,table_row|{'virtual_size':10}],
                         [row,table_row|{'code':unwind.TABLE[:-1]}],
                         [row,table_row|{'flags':0xc0000040}],
                         [row,table_row|{'flags':0x60000040}]):
                with patch.object(unwind.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): unwind.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
