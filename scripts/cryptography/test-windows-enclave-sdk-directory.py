"""Saved-directory review drift, branch geometry and nonclaim regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_directory as directory


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(size) for n,(_,size,_) in directory.BODIES.items()}
        for name,instruction,target in directory.EDGES:
            offset = instruction-directory.BODIES[name][0]
            bodies[name][offset:offset+5] = b'\xe8'+(target-instruction-5).to_bytes(4,'little',signed=True)
        address,code = directory.HEADER_CALL
        offset = address-directory.BODIES['directory_parse'][0]
        bodies['directory_parse'][offset:offset+len(code)] = code
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(directory.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_exact_population_lengths_and_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(directory.BODIES,specs,clear=True):
            self.assertEqual(directory.mutations(bodies),668)
            for name,body in bodies.items():
                for value in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): directory.check_bodies(bodies|{name:value})
                with self.assertRaises(ValueError):
                    directory.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): directory.check_bodies(bodies|{'extra':b''})

    def test_vacuous_campaign_rejected(self):
        bodies,_ = self.synthetic()
        with patch.object(directory,'check_bodies'):
            with self.assertRaises(AssertionError): directory.mutations(bodies)

    def test_call_and_header_contract_bytes_independent_of_hashes(self):
        bodies,_ = self.synthetic()
        directory.check_edges(bodies)
        self.assertEqual(len(directory.EDGES),4)
        positions = [(n,a-directory.BODIES[n][0]+i) for n,a,_ in directory.EDGES for i in range(5)]
        address,code = directory.HEADER_CALL
        positions += [('directory_parse',address-directory.BODIES['directory_parse'][0]+i)
                      for i in range(len(code))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): directory.check_edges(bodies|{name:bytes(changed)})

    def test_frame_depth_and_sibling_not_nested(self):
        for capacity in (128,256,384,512):
            result = directory.geometry(directory.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                for origin,extra in (('engine',0),('wide_helper',-128)):
                    base = -14704-capacity+shift+extra
                    row = result[path][origin]
                    self.assertEqual(row['frames'],dict(result=base-80,parser=base-144,
                                                       header=base-224,translate=base-192))
                    self.assertEqual(row['section_leaf_entry_from_high'],base-200)
                    self.assertEqual(row['selected_low_from_high'],base-224)
                    self.assertEqual(len(row['spans']),11)
                    spans = {s['name']:s for s in row['spans']}
                    self.assertEqual(spans['directory result pointer']['offset_from_high'],base-32)
                    self.assertEqual(spans['parser NT-header result home']['offset_from_high'],base-80)
                    self.assertEqual(spans['header status offset and pointer locals']['bytes'],16)
                    for span in row['spans']:
                        self.assertGreaterEqual(span['offset_from_low'],0)
                        self.assertLessEqual(span['offset_from_high']+span['bytes'],0)

    def test_translation_and_invalid_capacities(self):
        for capacity in (128,256,384,512):
            self.assertEqual(directory.geometry(directory.Window(0,65536),capacity),
                directory.geometry(directory.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): directory.geometry(directory.Window(0,65536),capacity)

    def test_wrong_file_rejected_before_parsing(self):
        with patch.object(directory.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): directory.inspect(b'MZ-unreviewed')

    def test_sections_and_qualification_limits(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0xdf94,0xcf78,0x9650)])
        with patch.dict(directory.BODIES,specs,clear=True), \
                patch.object(directory.runtime,'inspect',return_value=previous):
            with patch.object(directory.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = directory.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],668)
            self.assertEqual(result['unresolved'],[dict(rva=r) for r in (0xcf78,0x9650)])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'arbitrary_image_bounds_qualified','sdk_self_erasure_claimed',
                          'header_optional_size_checks_active'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(directory.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): directory.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
