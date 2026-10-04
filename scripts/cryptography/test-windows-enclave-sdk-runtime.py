"""Offline saved-SDK runtime-adapter drift and bounded-frame regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_runtime as runtime


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytes(size) for n,(_,size,_) in runtime.BODIES.items()}
        for name,instruction,opcode,target in runtime.EDGES:
            body = bytearray(bodies[name])
            offset = instruction-runtime.BODIES[name][0]
            body[offset:offset+5] = bytes([opcode])+(target-instruction-5).to_bytes(
                4,'little',signed=True)
            bodies[name] = bytes(body)
        specs = {n:(runtime.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_hash_population_length_and_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(runtime.BODIES,specs,clear=True):
            runtime.check_bodies(bodies)
            self.assertEqual(runtime.mutations(bodies),1718)
            for name,body in bodies.items():
                for changed in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): runtime.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError):
                    runtime.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): runtime.check_bodies(bodies|{'extra':b''})

    def test_campaign_rejects_vacuous_checker(self):
        bodies,_ = self.synthetic()
        with patch.object(runtime,'check_bodies'):
            with self.assertRaises(AssertionError): runtime.mutations(bodies)

    def test_transfer_targets_including_tail_jump(self):
        bodies,_ = self.synthetic()
        runtime.check_edges(bodies)
        self.assertEqual(len(runtime.EDGES),11)
        self.assertIn(('flags_adapter',0x167ce,0xe9,0x167dc),runtime.EDGES)
        for name,instruction,_,_ in runtime.EDGES:
            for position in (0,1):
                changed = bytearray(bodies[name])
                changed[instruction-runtime.BODIES[name][0]+position] ^= 1
                with self.assertRaises(ValueError): runtime.check_edges(bodies|{name:bytes(changed)})

    def test_known_syscall_stub_bytes(self):
        rva,size,digest = runtime.BODIES['module_query']
        self.assertEqual((rva,size),(0x1cce0,11))
        self.assertEqual(hashlib.sha256(bytes.fromhex('4c8bd1b8230000000f05c3')).hexdigest(),digest)

    def test_all_selected_frames_and_tail_home(self):
        for capacity in (128,256,384,512):
            for path,shift in (('copy',0),('call_error',-256)):
                for origin,extra in (('engine',0),('wide_helper',128)):
                    base = -14480-capacity+shift-extra
                    row = runtime.geometry(runtime.Window(0,65536),capacity)[path][origin]
                    self.assertEqual(row['frames'],dict(lookup=base-80,module=base-176,
                        directory=base-224,unwind=base-144,flags=base-192))
                    self.assertEqual(len(row['spans']),18)
                    spans = {s['name']:s for s in row['spans']}
                    self.assertEqual(spans['flags leaf return and RBX home save']['offset_from_high'],
                                     base-200)
                    self.assertEqual(spans['flags leaf return and RBX home save']['bytes'],16)
                    self.assertEqual(spans['known invalid-context flags destination']['offset_from_high'],
                                     base+304)
                    for s in row['spans']:
                        self.assertGreaterEqual(s['offset_from_low'],0)
                        self.assertLessEqual(s['offset_from_high']+s['bytes'],0)
                    for unknown in row['unknown_callees']:
                        self.assertIsNone(unknown['callee_frame_bytes'])
                        self.assertFalse(unknown['callee_spills_qualified'])

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(runtime.geometry(runtime.Window(0,65536),capacity),
                runtime.geometry(runtime.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): runtime.geometry(runtime.Window(0,65536),capacity)

    def test_file_identity_precedes_parsing(self):
        with patch.object(runtime.conversion.formatter.diagnostic.status.sdk.pe,'linked',
                          side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): runtime.inspect(b'MZ-unreviewed')

    def test_synthetic_sections_and_nonclaims(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for n,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[n]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[])
        with patch.dict(runtime.BODIES,specs,clear=True), \
                patch.object(runtime.conversion,'inspect',return_value=previous):
            with patch.object(runtime.conversion.formatter.diagnostic.status.sdk.pe,'linked',
                              return_value=([row],None)):
                result = runtime.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],1718)
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'generic_context_bounds_qualified','kernel_query_storage_qualified',
                          'history_storage_cleared_by_window_proven'):
                self.assertIs(result[field],False)
            self.assertEqual({r['rva'] for r in result['unresolved']},
                             {0x9650,0x96e0,0xdf94,0xcf78,0xbc90,0x1160})
            self.assertIn('reviewed invalid-argument caller passes a null history pointer',
                          result['side_effects'])
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(runtime.conversion.formatter.diagnostic.status.sdk.pe,'linked',
                                  return_value=(rows,None)):
                    with self.assertRaises(ValueError): runtime.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
