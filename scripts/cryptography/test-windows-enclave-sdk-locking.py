"""Lock-frame drift, tail-call accounting and exceptional-limit regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_locking as locking


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(size) for n,(_,size,_) in locking.BODIES.items()}
        for name,instruction,opcode,target in locking.EDGES:
            offset = instruction-locking.BODIES[name][0]
            bodies[name][offset:offset+5] = bytes([opcode])+(target-instruction-5).to_bytes(
                4,'little',signed=True)
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(locking.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_lengths_and_all_byte_mutations(self):
        bodies,specs = self.synthetic()
        with patch.dict(locking.BODIES,specs,clear=True):
            self.assertEqual(locking.mutations(bodies),1216)
            for name,body in bodies.items():
                for value in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): locking.check_bodies(bodies|{name:value})
                with self.assertRaises(ValueError):
                    locking.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): locking.check_bodies(bodies|{'extra':b''})

    def test_vacuous_checker_rejected(self):
        bodies,_ = self.synthetic()
        with patch.object(locking,'check_bodies'):
            with self.assertRaises(AssertionError): locking.mutations(bodies)

    def test_direct_tail_and_recursive_transfers(self):
        bodies,_ = self.synthetic()
        locking.check_edges(bodies)
        self.assertEqual(len(locking.EDGES),11)
        self.assertIn(('queue_link',0x9c4a,0xe9,0x9d3c),locking.EDGES)
        self.assertIn(('raise_status',0xbf15,0xe8,0xbeb0),locking.EDGES)
        for name,instruction,_,_ in locking.EDGES:
            for i in range(5):
                changed = bytearray(bodies[name])
                changed[instruction-locking.BODIES[name][0]+i] ^= 1
                with self.assertRaises(ValueError): locking.check_edges(bodies|{name:bytes(changed)})

    def test_saved_syscall_stub_instructions(self):
        for name,code in (('wait_stub','4c8bd1b8e30100000f05c3'),
                          ('signal_stub','4c8bd1b8710000000f05c3')):
            _,size,digest = locking.BODIES[name]
            self.assertEqual(size,11)
            self.assertEqual(hashlib.sha256(bytes.fromhex(code)).hexdigest(),digest)

    def test_frames_wait_node_tail_reuse_and_unknown_exception_depth(self):
        for capacity in (128,256,384,512):
            result = locking.geometry(locking.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                for origin,extra in (('engine',0),('wide_helper',-128)):
                    base = -14656-capacity+shift+extra
                    row = result[path][origin]
                    self.assertEqual(row['frames'],dict(lock=base-48,slow=base-160,
                        tail_wake=base-208,unlock=base-48,direct_wake=base-96))
                    self.assertEqual(row['selected_ordinary_low_from_high'],base-216)
                    self.assertEqual(len(row['spans']),13)
                    spans = {s['name']:s for s in row['spans']}
                    self.assertEqual(spans['slow 48-byte wait node']['offset_from_high'],base-128)
                    self.assertEqual(spans['slow 48-byte wait node']['bytes'],48)
                    self.assertEqual(spans['backoff input counter']['offset_from_high'],base-40)
                    self.assertEqual(spans['queue leaf return/home']['offset_from_high'],base-168)
                    for span in row['spans']:
                        self.assertGreaterEqual(span['offset_from_low'],0)
                        self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                    exceptional = row['exceptional']
                    self.assertEqual(exceptional['first_raise_frame_from_high'],base-1488)
                    self.assertEqual(exceptional['recursive_frame_step_bytes'],1440)
                    self.assertIsNone(exceptional['transitive_depth_bound'])
                    self.assertFalse(exceptional['cleanup_qualified'])
                    self.assertIsNone(exceptional['unknown_callee']['callee_frame_bytes'])

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(locking.geometry(locking.Window(0,65536),capacity),
                locking.geometry(locking.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): locking.geometry(locking.Window(0,65536),capacity)

    def test_wrong_file_before_parsing(self):
        with patch.object(locking.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): locking.inspect(b'MZ-unreviewed')

    def test_sections_and_explicit_nonclaims(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0x9650,0x96e0,0xcf78)])
        with patch.dict(locking.BODIES,specs,clear=True), \
                patch.object(locking.directory,'inspect',return_value=previous):
            with patch.object(locking.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = locking.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],1216)
            self.assertEqual({r['rva'] for r in result['unresolved']},{0xcf78,0x1b50})
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'lock_concurrency_qualified','wait_node_reclamation_proven',
                          'external_storage_erasure_proven','kernel_storage_qualified',
                          'sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(locking.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): locking.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
