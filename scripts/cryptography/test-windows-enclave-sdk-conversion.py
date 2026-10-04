"""Offline conversion/context geometry and drift tests; no SDK execution."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_conversion as conversion


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytes(size) for n,(_,size,_) in conversion.BODIES.items()}
        for name,instruction,target in conversion.EDGES:
            code = bytearray(bodies[name])
            offset = instruction-conversion.BODIES[name][0]
            code[offset:offset+5] = b'\xe8'+(target-instruction-5).to_bytes(4,'little',signed=True)
            bodies[name] = bytes(code)
        specs = {n:(conversion.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_exact_known_unsupported_leaf(self):
        rva,size,digest = conversion.BODIES['wide_unsupported']
        self.assertEqual((rva,size),(0x5468,6))
        self.assertEqual(hashlib.sha256(bytes.fromhex('b8bb0000c0c3')).hexdigest(),digest)

    def test_synthetic_hash_population_and_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(conversion.BODIES,specs,clear=True):
            conversion.check_bodies(bodies)
            self.assertEqual(conversion.mutations(bodies),641)
            for name,body in bodies.items():
                for changed in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError):
                        conversion.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError):
                    conversion.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): conversion.check_bodies(bodies|{'extra':b''})

    def test_campaign_cannot_pass_vacuously(self):
        bodies,_ = self.synthetic()
        with patch.object(conversion,'check_bodies'):
            with self.assertRaises(AssertionError): conversion.mutations(bodies)

    def test_calls_and_diagnostic_reentry(self):
        bodies,_ = self.synthetic()
        conversion.check_edges(bodies)
        self.assertIn(('invalid_argument',0x1135,0x168a4),conversion.EDGES)
        self.assertEqual(len(conversion.EDGES),10)
        for name,instruction,_ in conversion.EDGES:
            changed = bytearray(bodies[name])
            changed[instruction-conversion.BODIES[name][0]+1] ^= 1
            with self.assertRaises(ValueError):
                conversion.check_edges(bodies|{name:bytes(changed)})

    def test_geometry_including_context_destination(self):
        for capacity in (128,256,384,512):
            for name,shift in (('copy',0),('call_error',-256)):
                row = conversion.geometry(conversion.Window(0,65536),capacity)[name]
                engine = -12960-capacity+shift
                self.assertEqual(row['frames'],dict(adapter=engine-64,helper=engine-128))
                self.assertEqual(len(row['spans']),6)
                for origin,extra in (('engine',0),('wide_helper',128)):
                    invalid = row['invalid_paths'][origin]
                    base = engine-extra-1520
                    self.assertEqual(invalid['frame_from_high'],base)
                    self.assertEqual(invalid['reentry_frames'],dict(entry=base-80,
                        retry=base-160,guarded_buffer=base-496))
                    self.assertIsNone(invalid['unreviewed']['callee_frame_bytes'])
                    spans = {s['name']:s for s in invalid['spans']}
                    self.assertEqual(spans['context FXSAVE destination']['offset_from_high'],base+512)
                    self.assertEqual(spans['context FXSAVE destination']['bytes'],512)
                    self.assertEqual(spans['invalid cookie']['offset_from_high'],base+1488)
                    self.assertLessEqual(base+1024,base+1488)
                    for s in invalid['spans']+row['spans']:
                        self.assertGreaterEqual(s['offset_from_low'],0)
                        self.assertLessEqual(s['offset_from_high']+s['bytes'],0)

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(conversion.geometry(conversion.Window(0,65536),capacity),
                conversion.geometry(conversion.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError):
                conversion.geometry(conversion.Window(0,65536),capacity)

    def test_file_identity_checked_before_parsing(self):
        with patch.object(conversion.formatter.diagnostic.status.sdk.pe,'linked',
                          side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): conversion.inspect(b'MZ-unreviewed')

    def test_synthetic_inspection_and_limits(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x6000)
        for n,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[n]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[])
        with patch.dict(conversion.BODIES,specs,clear=True), \
                patch.object(conversion.formatter,'inspect',return_value=previous):
            with patch.object(conversion.formatter.diagnostic.status.sdk.pe,'linked',
                              return_value=([row],None)):
                result = conversion.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],641)
            self.assertEqual(result['conversion_leaf_return'],'0xc00000bb')
            self.assertEqual(result['thread_relative_write']['value'],42)
            self.assertFalse(result['thread_relative_write']['cleared_by_window_proven'])
            self.assertTrue(result['diagnostic_reentry']['cycle_observed'])
            self.assertFalse(result['diagnostic_reentry']['exception_safe_guard_lifecycle_qualified'])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'context_erased_by_capture_helper'):
                self.assertIs(result[field],False)
            self.assertEqual({r['rva'] for r in result['unresolved']},{0x8b60,0xc320,0xbc90,0x1160})
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(conversion.formatter.diagnostic.status.sdk.pe,'linked',
                                  return_value=(rows,None)):
                    with self.assertRaises(ValueError): conversion.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
