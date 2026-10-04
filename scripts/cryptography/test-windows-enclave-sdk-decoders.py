"""Decoder-frame, selected context-range and saved-byte drift regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_decoders as decoders


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(size) for n,(_,size,_) in decoders.BODIES.items()}
        for name,instruction,target in decoders.EDGES:
            offset = instruction-decoders.BODIES[name][0]
            bodies[name][offset:offset+5] = b'\xe8'+(target-instruction-5).to_bytes(4,'little',signed=True)
        for name,address,code in decoders.ANCHORS:
            offset = address-decoders.BODIES[name][0]
            bodies[name][offset:offset+len(code)] = code
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(decoders.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_length_and_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(decoders.BODIES,specs,clear=True):
            self.assertEqual(decoders.mutations(bodies),2534)
            for name,body in bodies.items():
                for value in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): decoders.check_bodies(bodies|{name:value})
                with self.assertRaises(ValueError):
                    decoders.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): decoders.check_bodies(bodies|{'extra':b''})

    def test_vacuous_checker_rejected(self):
        bodies,_ = self.synthetic()
        with patch.object(decoders,'check_bodies'):
            with self.assertRaises(AssertionError): decoders.mutations(bodies)

    def test_calls_frame_anchors_and_both_vector_halves(self):
        bodies,_ = self.synthetic()
        decoders.check_edges(bodies)
        self.assertEqual((len(decoders.EDGES),len(decoders.ANCHORS)),(3,3))
        positions = [(n,a-decoders.BODIES[n][0]+i) for n,a,_ in decoders.EDGES for i in range(5)]
        positions += [(n,a-decoders.BODIES[n][0]+i) for n,a,c in decoders.ANCHORS for i in range(len(c))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): decoders.check_edges(bodies|{name:bytes(changed)})

    def test_all_register_write_ranges(self):
        window = decoders.Window(0,65536)
        context = 32768
        for bank,base,width in (('gpr',0x78,8),('vector',0x1a0,16)):
            for index in range(16):
                span = decoders.context_write(window,context,bank,index)
                self.assertEqual(span['offset_from_low'],context+base+index*width)
                self.assertEqual(span['bytes'],width)
                self.assertLessEqual(span['offset_from_low']+width,context+768)
        last = decoders.context_write(window,65536-672,'vector',15)
        self.assertEqual(last['offset_from_high']+last['bytes'],0)
        with self.assertRaises(ValueError): decoders.context_write(window,65536-671,'vector',15)

    def test_bad_register_selectors_and_unknown_banks(self):
        window = decoders.Window(0,65536)
        for index in (-1,16,True,1.0,'1'):
            with self.assertRaises(ValueError): decoders.context_write(window,32768,'vector',index)
        for bank in ('unknown','xstate',''):
            with self.assertRaises(ValueError): decoders.context_write(window,32768,bank,0)
        with self.assertRaises(ValueError): decoders.context_write(window,True,'gpr',0)

    def test_frames_and_known_context_origin(self):
        for capacity in (128,256,384,512):
            rows = decoders.geometry(decoders.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                for origin,extra in (('engine',0),('wide_helper',-128)):
                    engine = -14800-capacity+shift+extra
                    row = rows[path][origin]
                    self.assertEqual(row['frames'],dict(epilogue=engine-144,opcodes=engine-160,
                        epilogue_slots=engine-192,opcode_slots=engine-208))
                    self.assertEqual(len(row['spans']),9)
                    self.assertEqual(row['known_context_base_from_high'],engine+576)
                    envelopes = row['context_write_envelopes']
                    self.assertEqual([(s['offset_from_high'],s['bytes']) for s in envelopes],
                        [(engine+696,128),(engine+824,8),(engine+992,256)])
                    for span in row['spans']+envelopes:
                        self.assertGreaterEqual(span['offset_from_low'],0)
                        self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                    self.assertEqual(row['exceptional'],dict(direct_first_raise_from_high=engine-1600,
                        helper_first_raise_from_high=engine-1648,transitive_depth_bound=None,
                        cleanup_qualified=False))

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(decoders.geometry(decoders.Window(0,65536),capacity),
                decoders.geometry(decoders.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): decoders.geometry(decoders.Window(0,65536),capacity)

    def test_identity_precedes_parsing(self):
        with patch.object(decoders.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): decoders.inspect(b'MZ-unreviewed')

    def test_sections_and_nonclaims(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0xc538,0xc94c,0xbc90)])
        with patch.dict(decoders.BODIES,specs,clear=True), \
                patch.object(decoders.unwind,'inspect',return_value=previous):
            with patch.object(decoders.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = decoders.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],2534)
            self.assertEqual(result['unresolved'],[dict(rva=0xbc90)])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'arbitrary_metadata_bounds_qualified','arbitrary_context_bounds_qualified',
                          'optional_saved_location_storage_qualified','sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(decoders.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): decoders.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
