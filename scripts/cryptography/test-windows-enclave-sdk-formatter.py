"""Synthetic pin/geometry regressions; real SDK mutations are a separate run."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_formatter as formatter


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytes(size) for n,(_,size,_) in formatter.BODIES.items()}
        for name,instruction,opcode,target in formatter.EDGES:
            rva,_,_ = formatter.BODIES[name]
            body = bytearray(bodies[name])
            offset = instruction-rva
            body[offset:offset+5] = bytes([opcode])+(target-instruction-5).to_bytes(
                4,'little',signed=True)
            bodies[name] = bytes(body)
        specs = {n:(formatter.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_synthetic_hash_and_mutation_campaign(self):
        bodies,specs = self.synthetic()
        self.assertEqual(sum(len(b) for b in bodies.values()),3030)
        with patch.dict(formatter.BODIES,specs,clear=True):
            formatter.check_bodies(bodies)
            self.assertEqual(formatter.mutations(bodies),3030)
            for name,body in bodies.items():
                for changed in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError):
                        formatter.check_bodies(bodies | {name:changed})
                with self.assertRaises(ValueError):
                    formatter.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): formatter.check_bodies(bodies|{'extra':b''})

    def test_campaign_rejects_vacuous_checker(self):
        bodies,_ = self.synthetic()
        with patch.object(formatter,'check_bodies'):
            with self.assertRaises(AssertionError): formatter.mutations(bodies)

    def test_all_direct_targets(self):
        bodies,_ = self.synthetic()
        formatter.check_edges(bodies)
        self.assertEqual(len(formatter.EDGES),19)
        for name,instruction,_,_ in formatter.EDGES:
            changed = bytearray(bodies[name])
            changed[instruction-formatter.BODIES[name][0]+1] ^= 1
            with self.assertRaises(ValueError):
                formatter.check_edges(bodies|{name:bytes(changed)})

    def test_selected_geometry_at_every_capacity(self):
        for capacity in (128,256,384,512):
            for name,shift in (('copy',0),('call_error',-256)):
                row = formatter.geometry(formatter.Window(0,65536),capacity)[name]
                self.assertEqual(row['frames'],dict(engine=-12960-capacity+shift,
                    writer_or_padder=-13008-capacity+shift,put=-13056-capacity+shift))
                self.assertEqual(row['selected_leaf_low_from_high'],-13064-capacity+shift)
                self.assertEqual(len(row['spans']),11)
                spans = {s['name']:s for s in row['spans']}
                self.assertEqual(spans['engine conversion scratch']['bytes'],512)
                self.assertEqual(spans['engine cookie']['bytes'],8)
                for span in row['spans']:
                    self.assertGreaterEqual(span['offset_from_low'],0)
                    self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                self.assertIsNone(row['unreviewed']['callee_frame_bytes'])
                self.assertFalse(row['unreviewed']['callee_spills_qualified'])

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(formatter.geometry(formatter.Window(0,65536),capacity),
                formatter.geometry(formatter.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,-1,129,513,True,128.0):
            with self.assertRaises(ValueError):
                formatter.geometry(formatter.Window(0,65536),capacity)

    def test_real_file_identity_precedes_parsing(self):
        with patch.object(formatter.diagnostic.status.sdk.pe,'linked',
                          side_effect=AssertionError('unexpected parsing')):
            with self.assertRaises(ValueError): formatter.inspect(b'MZ-unreviewed')

    def test_synthetic_inspection_and_explicit_limits(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=['test'])
        with patch.dict(formatter.BODIES,specs,clear=True), \
                patch.object(formatter.diagnostic,'inspect',return_value=previous):
            with patch.object(formatter.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = formatter.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],3030)
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','arbitrary_formats_qualified',
                          'exception_unwind_cleanup_qualified','buffer_full_wipe_on_exit_observed'):
                self.assertIs(result[field],False)
            self.assertEqual({r['rva'] for r in result['unresolved']},{0x33f4,0x1058,0xbc90,0x1160})
            self.assertEqual(result['thread_relative_read']['offset'],0x1500)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(formatter.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): formatter.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
