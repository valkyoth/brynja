"""Point-not-span, selected-copy and alternate-adapter regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_dispatch_helpers as review


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
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_and_every_byte(self):
        bodies,specs = self.synthetic()
        with patch.dict(review.BODIES,specs,clear=True):
            self.assertEqual(review.mutations(bodies),724)
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

    def test_calls_and_semantic_anchors(self):
        bodies,_ = self.synthetic()
        review.check_edges(bodies)
        self.assertEqual((len(review.EDGES),len(review.ANCHORS)),(2,8))
        positions = [(n,a-review.BODIES[n][0]+i) for n,a,_ in review.EDGES for i in range(5)]
        positions += [(n,a-review.BODIES[n][0]+i) for n,a,c in review.ANCHORS
                      for i in range(len(bytes.fromhex(c)))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): review.check_edges(bodies|{name:bytes(changed)})

    def test_point_not_access_width_or_progress(self):
        for low in (0,8,15):
            for high in (0,8,16,24):
                for address in range(32):
                    self.assertEqual(review.stack_point(low,high,address,False),low<=address<high)
                    self.assertEqual(review.stack_point(low,high,address,True),
                                     address in range(low,high) and address%8==0)
        # Accepted point, but an eight-byte access would cross the upper bound.
        self.assertTrue(review.stack_point(0,9,8,True))
        self.assertGreater(8+8,9)
        # Repeating an address is accepted: there is no progress history input.
        self.assertTrue(all(review.stack_point(0,16,8,True) for _ in range(3)))
        for bad in (-1,True,1.0,1<<64):
            with self.assertRaises(ValueError): review.stack_point(0,16,bad,True)
        with self.assertRaises(ValueError): review.stack_point(0,16,8,1)

    def test_copy_exact_selected_writes_and_self_alias(self):
        window = review.Window(0,65536)
        spans = review.copy_writes(window,1000,False)
        self.assertEqual([(s['offset_from_low']-1000,s['bytes']) for s in spans],
            [(48,4),(52,4),(56,2),(66,2),(68,4),(144,40),(216,40),(256,160),(512,160)])
        touched = {i for s in spans for i in range(s['offset_from_low']-1000,
                   s['offset_from_low']-1000+s['bytes'])}
        self.assertEqual(len(touched),416)
        self.assertTrue(set(range(58,66)).isdisjoint(touched))
        self.assertTrue(set(range(416,512)).isdisjoint(touched))
        self.assertEqual([(s['offset_from_low'],s['bytes']) for s in review.copy_writes(window,1000,True)],
                         [(1048,4)])
        review.copy_writes(window,65536-672,False)
        with self.assertRaises(ValueError): review.copy_writes(window,65536-671,False)
        review.copy_writes(window,65536-52,True)
        with self.assertRaises(ValueError): review.copy_writes(window,65536-51,True)
        with self.assertRaises(ValueError): review.copy_writes(window,True,True)
        with self.assertRaises(ValueError): review.copy_writes(window,1000,1)

    def test_geometry_aliases_and_translation(self):
        for capacity in (128,256,384,512):
            for size in (1279,1391):
                rows = review.geometry(review.Window(0,65536),capacity,size)
                self.assertEqual(rows,review.geometry(review.Window(1<<32,(1<<32)+65536),capacity,size))
                for path,shift in (('copy',0),('call_error',-256)):
                    work = -14304-capacity+shift-((size+15)&-16)
                    row = rows[path]
                    self.assertEqual(row['frames'],dict(adapter=work-144,flags=work-192,engine=work-320))
                    self.assertEqual(len(row['spans']),11)
                    self.assertEqual(row['spans'][7]['offset_from_high'],
                                     row['spans'][10]['offset_from_high'])
                    self.assertEqual(sum(s['bytes'] for s in row['copy_destination_writes']),416)
                    for field in ('os_stack_bounds_equal_clearing_window_proven',
                                  'arbitrary_source_or_overlap_validated','forward_progress_proven',
                                  'actual_runtime_allocation_observed','cleanup_qualified'):
                        self.assertFalse(row[field])
        for size in (-1,True,0xffffffff):
            with self.assertRaises(ValueError): review.geometry(review.Window(0,65536),512,size)

    def test_identity_precedes_parsing(self):
        with patch.object(review.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): review.inspect(b'MZ-unreviewed')

    def test_sections_and_no_new_qualification(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
            unresolved=[dict(rva=r) for r in (0x16d9c,0x172fc,0x93b8,0xc3f0,0xbf30)])
        with patch.dict(review.BODIES,specs,clear=True), \
                patch.object(review.dispatch,'inspect',return_value=previous):
            with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = review.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],724)
            self.assertEqual(result['unresolved'],[dict(rva=0xbf30)])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified','arbitrary_context_bounds_qualified',
                          'exception_unwind_cleanup_qualified','maximum_transitive_depth_qualified',
                          'sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(review.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): review.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
