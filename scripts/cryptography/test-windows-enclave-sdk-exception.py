"""Exceptional frame, dynamic-allocation and global-storage regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_exception as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(s) for n,(_,s,_) in review.BODIES.items()}
        for name,address,target in review.EDGES:
            offset = address-review.BODIES[name][0]
            bodies[name][offset:offset+5] = b'\xe8'+(target-address-5).to_bytes(4,'little',signed=True)
        for name,address,hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            offset = address-review.BODIES[name][0]
            bodies[name][offset:offset+len(code)] = code
        for address,prefix,target,immediate in review.REFERENCES:
            prefix,immediate = bytes.fromhex(prefix),bytes.fromhex(immediate)
            size = len(prefix)+4+len(immediate)
            offset = address-review.BODIES['fatal'][0]
            bodies['fatal'][offset:offset+size] = prefix + \
                (target-address-size).to_bytes(4,'little',signed=True)+immediate
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_and_all_body_bytes(self):
        bodies,specs = self.synthetic()
        with patch.dict(review.BODIES,specs,clear=True):
            self.assertEqual(review.mutations(bodies),929)
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

    def test_calls_anchors_and_global_references(self):
        bodies,_ = self.synthetic()
        review.check_edges(bodies)
        self.assertEqual((len(review.EDGES),len(review.ANCHORS),len(review.REFERENCES)),(18,8,15))
        positions = [(n,a-review.BODIES[n][0]+i) for n,a,_ in review.EDGES for i in range(5)]
        positions += [(n,a-review.BODIES[n][0]+i) for n,a,c in review.ANCHORS
                      for i in range(len(bytes.fromhex(c)))]
        positions += [('fatal',a-review.BODIES['fatal'][0]+i) for a,p,_,v in review.REFERENCES
                      for i in range(len(bytes.fromhex(p))+4+len(bytes.fromhex(v)))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): review.check_edges(bodies|{name:bytes(changed)})

    def test_global_storage_not_stack_and_virtual_not_raw(self):
        row = dict(rva=0x28000,virtual_size=0x1000,code=b'',flags=0x80000000)
        result = review.global_storage([row])
        self.assertEqual([(s['rva'],s['bytes']) for s in result],[(0x28860,768),(0x287c0,40)])
        for span in result:
            self.assertEqual(span['storage'],'SDK image global')
            self.assertIs(span['covered_by_stack_window'],False)
            self.assertIs(span['erasure_qualified'],False)
        for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                     [row|{'flags':0}],[row|{'virtual_size':0xb5f}]):
            with self.assertRaises(ValueError): review.global_storage(rows)

    def test_dword_allocation_rounding_and_overflow_boundary(self):
        for value,expected in ((0,0),(1,16),(15,16),(16,16),(17,32),
                               (0xfffffff0,0xfffffff0),(0xffffffff,0x100000000)):
            self.assertEqual(review.allocation_size(value),expected)
        for value in (-1,0x100000000,True,1.0,'1',None):
            with self.assertRaises(ValueError): review.allocation_size(value)

    def test_dynamic_pointer_is_not_an_invented_context_envelope(self):
        window = review.Window(0,65536)
        caller = 60000
        for size in (0,1,768,4096):
            result = review.dynamic_geometry(window,caller,size)
            rounded = (size+15)&-16
            current = caller-368-rounded
            self.assertEqual(result['rsp_from_high'],current-65536)
            self.assertEqual(result['context_pointer_from_high'],current+64-65536)
            self.assertEqual(result['allocation_bytes'],rounded)
            self.assertIsNone(result['context_write_extent'])
            self.assertIs(result['cleanup_qualified'],False)
        # Exact lower window edge passes geometry; one further aligned quantum
        # and a legitimate but very large DWORD size must fail, not be clamped.
        self.assertEqual(review.dynamic_geometry(window,caller,59632)['rsp_from_high'],-65536)
        for size in (59633,0xffffffff):
            with self.assertRaises(ValueError): review.dynamic_geometry(window,caller,size)

    def test_fixed_frames_tail_reuse_and_history(self):
        for capacity in (128,256,384,512):
            result = review.geometry(review.Window(0,65536),capacity)
            for path,shift in (('copy',0),('call_error',-256)):
                row = result[path]
                caller = -12080-capacity+shift
                self.assertEqual(row['fixed_frames'],dict(exception=caller-368,
                    fatal_via_cookie_tail=caller-144))
                self.assertEqual(row['nonnull_history_pointer_from_high'],caller-272)
                self.assertEqual(len(row['spans']),12)
                for span in row['spans']:
                    self.assertGreaterEqual(span['offset_from_low'],0)
                    self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
                for key in ('dynamic_allocation_bytes','context_write_extent','maximum_transitive_depth'):
                    self.assertIsNone(row[key])
                self.assertIs(row['history_write_bounds_qualified'],False)
                self.assertIs(row['exception_cleanup_qualified'],False)

    def test_translation_and_invalid_capacity(self):
        for capacity in (128,256,384,512):
            self.assertEqual(review.geometry(review.Window(0,65536),capacity),
                review.geometry(review.Window(1<<32,(1<<32)+65536),capacity))
        for capacity in (0,129,513,True,128.0):
            with self.assertRaises(ValueError): review.geometry(review.Window(0,65536),capacity)

    def test_identity_precedes_parsing(self):
        with patch.object(review.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): review.inspect(b'MZ-unreviewed')

    def test_sections_and_qualification_stays_false(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        global_row = dict(rva=0x28000,virtual_size=0x1000,code=b'',flags=0x80000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0xbc90,0x1160,0x1b50)])
        with patch.dict(review.BODIES,specs,clear=True), \
                patch.object(review.decoders,'inspect',return_value=previous):
            with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=([row,global_row],None)):
                result = review.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],929)
            self.assertEqual([r['rva'] for r in result['unresolved']],
                             [0x1b50]+[r for r,_ in review.UNREVIEWED])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'runtime_context_size_qualified','sdk_global_erasure_qualified',
                          'kernel_storage_qualified','sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row,global_row],[row|{'flags':0xa0000000},global_row],
                         [row|{'virtual_size':1},global_row],[row|{'code':b''},global_row],[row]):
                with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): review.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
