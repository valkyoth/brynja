"""Saved dispatch/restore and external-continuation boundary regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_dispatch as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(s) for n,(_,s,_) in review.BODIES.items()}
        for name,address,opcode,target in review.EDGES:
            offset = address-review.BODIES[name][0]
            bodies[name][offset:offset+5] = bytes([opcode])+(target-address-5).to_bytes(4,'little',signed=True)
        for name,address,hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            offset = address-review.BODIES[name][0]
            bodies[name][offset:offset+len(code)] = code
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_and_every_body_byte(self):
        bodies,specs = self.synthetic()
        with patch.dict(review.BODIES,specs,clear=True):
            self.assertEqual(review.mutations(bodies),2469)
            for name,body in bodies.items():
                for value in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:value})
                with self.assertRaises(ValueError):
                    review.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})

    def test_vacuous_checker_rejected(self):
        bodies,_ = self.synthetic()
        with patch.object(review,'check_bodies'):
            with self.assertRaises(AssertionError): review.mutations(bodies)

    def test_calls_irets_indirect_targets_and_tail_restoration(self):
        bodies,_ = self.synthetic()
        review.check_edges(bodies)
        self.assertEqual((len(review.EDGES),len(review.ANCHORS)),(24,19))
        positions = [(n,a-review.BODIES[n][0]+i) for n,a,_,_ in review.EDGES for i in range(5)]
        positions += [(n,a-review.BODIES[n][0]+i) for n,a,c in review.ANCHORS
                      for i in range(len(bytes.fromhex(c)))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): review.check_edges(bodies|{name:bytes(changed)})

    def test_sibling_frames_special_copy_and_tail_reuse(self):
        for capacity in (128,256,384,512):
            for size in (1279,1391):
                rows = review.geometry(review.Window(0,65536),capacity,size)
                for path,shift in (('copy',0),('call_error',-256)):
                    caller = -12448-capacity+shift-((size+15)&-16)
                    work = caller-576-1280
                    expected = dict(dispatch_fixed=caller-576,dispatch_dynamic=work,
                        handler=work-48,restore=caller-80,special_restore=caller-1392,
                        first_status_raise=work-1440,raise_context=work-1504,
                        tail_dispatch_fixed=work-2016)
                    row = rows[path]
                    self.assertEqual(row['frames'],expected)
                    self.assertEqual(len(row['spans']),19)
                    for span in row['spans']:
                        self.assertGreaterEqual(span['offset_from_low'],0)
                        self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                    fields = row['iret_field_writes']
                    self.assertEqual([(s['offset_from_high']-expected['restore'],s['bytes'])
                                      for s in fields],[(0,8),(8,2),(16,4),(24,8),(32,2)])
                    self.assertIsNone(row['maximum_transitive_depth'])
                    self.assertFalse(row['cleanup_qualified'])

    def test_external_entries_never_become_callee_bounds(self):
        for row in review.geometry(review.Window(0,65536),512,1279).values():
            frames = row['frames']
            entries = row['external_entries']
            self.assertEqual(len(entries),2)
            self.assertEqual([e['offset_from_high'] for e in entries],
                             [frames['handler']-8,frames['special_restore']-8])
            for entry in entries:
                self.assertEqual(entry['bytes'],40)
                self.assertIsNone(entry['callee_frame_bytes'])
                self.assertFalse(entry['callee_spills_qualified'])
            self.assertFalse(row['continuation_target_validated'])
            self.assertFalse(row['actual_runtime_allocation_observed'])

    def test_translation_and_invalid_model_inputs(self):
        for size in (1279,1391):
            self.assertEqual(review.geometry(review.Window(0,65536),512,size),
                review.geometry(review.Window(1<<32,(1<<32)+65536),512,size))
        for size in (-1,True,1.0,0xffffffff):
            with self.assertRaises(ValueError): review.geometry(review.Window(0,65536),512,size)
        for capacity in (0,129,True):
            with self.assertRaises(ValueError): review.geometry(review.Window(0,65536),capacity,1279)

    def test_identity_precedes_parsing(self):
        with patch.object(review.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): review.inspect(b'MZ-unreviewed')

    def test_sections_and_qualification_stays_false(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0x1b40,0x8790,0x1650,0x1b50,0xbf30)])
        with patch.dict(review.BODIES,specs,clear=True), \
                patch.object(review.context,'inspect',return_value=previous):
            with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = review.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],2469)
            self.assertEqual([r['rva'] for r in result['unresolved']],
                             [0xbf30]+[r for r,_ in review.UNREVIEWED])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'exception_unwind_cleanup_qualified','external_callback_cleanup_qualified',
                          'continuation_targets_validated','arbitrary_context_bounds_qualified',
                          'sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): review.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
