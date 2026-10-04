"""Saved context-helper identity, conditional arithmetic and storage regressions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_sdk_context as context


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n:bytearray(s) for n,(_,s,_) in context.BODIES.items()}
        for name,address,opcode,target in context.EDGES:
            offset = address-context.BODIES[name][0]
            bodies[name][offset:offset+5] = bytes([opcode])+(target-address-5).to_bytes(4,'little',signed=True)
        for name,address,hexcode in context.ANCHORS:
            code = bytes.fromhex(hexcode)
            offset = address-context.BODIES[name][0]
            bodies[name][offset:offset+len(code)] = code
        bodies = {n:bytes(b) for n,b in bodies.items()}
        specs = {n:(context.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest())
                 for n,b in bodies.items()}
        return bodies,specs

    def test_population_and_every_body_byte(self):
        bodies,specs = self.synthetic()
        with patch.dict(context.BODIES,specs,clear=True):
            self.assertEqual(context.mutations(bodies),1280)
            for name,body in bodies.items():
                for value in (body[:-1],body+b'\x90'):
                    with self.assertRaises(ValueError): context.check_bodies(bodies|{name:value})
                with self.assertRaises(ValueError):
                    context.check_bodies({n:b for n,b in bodies.items() if n != name})
            with self.assertRaises(ValueError): context.check_bodies(bodies|{'extra':b''})

    def test_vacuous_checker_rejected(self):
        bodies,_ = self.synthetic()
        with patch.object(context,'check_bodies'):
            with self.assertRaises(AssertionError): context.mutations(bodies)

    def test_calls_tail_jump_and_capture_entry_anchors(self):
        bodies,_ = self.synthetic()
        context.check_edges(bodies)
        self.assertEqual((len(context.EDGES),len(context.ANCHORS)),(9,12))
        positions = [(n,a-context.BODIES[n][0]+i) for n,a,_,_ in context.EDGES for i in range(5)]
        positions += [(n,a-context.BODIES[n][0]+i) for n,a,c in context.ANCHORS
                      for i in range(len(bytes.fromhex(c)))]
        for name,index in positions:
            changed = bytearray(bodies[name])
            changed[index] ^= 1
            with self.assertRaises(ValueError): context.check_edges(bodies|{name:bytes(changed)})

    def test_all_feature_selectors_and_alignment(self):
        for bit in range(2,64):
            sizes = [0]*62
            sizes[bit-2] = 23
            self.assertEqual(context.xstate_size(1<<bit,True,0,sizes,0),599)
            self.assertEqual(context.xstate_size(0,True,0,sizes,0),576)
        sizes = [1,3]+[0]*60
        self.assertEqual(context.xstate_size(12,True,0,sizes,0),580)
        self.assertEqual(context.xstate_size(12,True,8,sizes,0),643)
        self.assertEqual(context.xstate_size(3,True,context.U64,sizes,0),576)
        self.assertEqual(context.xstate_size(context.U64,False,context.U64,sizes,4096),4096)
        # Independent accumulator for non-wrapping, deliberately synthetic tables.
        sizes = [(bit*37)%128 for bit in range(2,64)]
        for mask in (0,context.U64,0x5555555555555555,0xaaaaaaaaaaaaaaaa):
            total = 576
            for bit,size in enumerate(sizes,2):
                if mask & (1<<bit):
                    if bit % 2: total = ((total+63)//64)*64
                    total += size
            self.assertEqual(context.xstate_size(mask,True,0xaaaaaaaaaaaaaaaa,sizes,0),total)

    def test_dword_wrap_is_not_silently_replaced_with_checked_math(self):
        self.assertEqual(context.xstate_size(4,True,0,[context.U32]+[0]*61,0),575)
        sizes = [context.U32-576,0]+[0]*60
        self.assertEqual(context.xstate_size(12,True,8,sizes,0),0)
        for state_size in (0,511,context.U32):
            result = context.x64_layout(0,True,state_size)
            self.assertFalse(result['writes_fit_size_output'])
            self.assertFalse(result['configuration_validated'])

    def test_selected_layout_and_compacted_mask_extent(self):
        for base in (0,16,32,48,1<<32):
            basic = context.x64_layout(base,False)
            self.assertEqual((basic['size_output'],basic['allocation_bytes']),(1279,1280))
            self.assertTrue(basic['writes_fit_size_output'])
            for size in (576,577,832,4096):
                row = context.x64_layout(base,True,size)
                self.assertEqual(row['size_output'],815+size)
                self.assertTrue(row['writes_fit_size_output'])
                fill = row['writes'][2]
                self.assertEqual((base+fill['offset'])%64,0)
                self.assertEqual(fill['bytes'],size-512)
                self.assertEqual(row['writes'][3]['bytes'],8)
                self.assertFalse(row['erasure_qualified'])

    def test_bad_model_inputs(self):
        for bad in (-1,context.U32+1,True,1.0,'1'):
            with self.assertRaises(ValueError): context.x64_layout(0,True,bad)
        for base in (-16,1,True,context.U64):
            with self.assertRaises(ValueError): context.x64_layout(base,False)
        for mask in (-1,context.U64+1,True):
            with self.assertRaises(ValueError): context.xstate_size(mask,True,0,[0]*62,0)
        for sizes in ([0]*61,[0]*63,[True]+[0]*61):
            with self.assertRaises(ValueError): context.xstate_size(0,True,0,sizes,0)
        with self.assertRaises(ValueError): context.x64_layout(0,1)
        with self.assertRaises(ValueError): context.xstate_size(0,1,0,[0]*62,0)

    def test_frame_composition_and_capture_not_full_fxsave(self):
        for capacity in (128,256,384,512):
            for size in (1279,1391):
                rows = context.geometry(context.Window(0,65536),capacity,size)
                for path,shift in (('copy',0),('call_error',-256)):
                    fixed = -12448-capacity+shift
                    dynamic = fixed-((size+15)&-16)
                    row = rows[path]
                    self.assertEqual(row['frames'],dict(size=fixed-80,
                        initialize=dynamic-96,capture=dynamic-64))
                    self.assertEqual(len(row['spans']),13)
                    self.assertEqual(len(row['capture_spans']),6)
                    last = row['capture_spans'][-1]
                    self.assertEqual((last['offset_from_high'],last['bytes']),(dynamic+576,160))
                    self.assertFalse(row['actual_runtime_size_observed'])
                    self.assertIsNone(row['transitive_depth_bound'])
                self.assertEqual(rows,context.geometry(context.Window(1<<32,(1<<32)+65536),capacity,size))
        for size in (context.U32,True,-1):
            with self.assertRaises(ValueError): context.geometry(context.Window(0,65536),512,size)

    def test_identity_precedes_parsing(self):
        with patch.object(context.diagnostic.status.sdk.pe,'linked',side_effect=AssertionError('parse')):
            with self.assertRaises(ValueError): context.inspect(b'MZ-unreviewed')

    def test_sections_and_nonclaims(self):
        bodies,specs = self.synthetic()
        code = bytearray(0x20000)
        for name,(rva,size,_) in specs.items(): code[rva:rva+size] = bodies[name]
        row = dict(rva=0,virtual_size=len(code),code=bytes(code),flags=0x20000000)
        previous = dict(image_sha256='synthetic',version_observed='synthetic',residuals=[],
                        unresolved=[dict(rva=r) for r in (0x161a4,0x162b4,0x1500,0x1650)])
        with patch.dict(context.BODIES,specs,clear=True), \
                patch.object(context.exception,'inspect',return_value=previous):
            with patch.object(context.diagnostic.status.sdk.pe,'linked',return_value=([row],None)):
                result = context.inspect(b'fixture',True)
            self.assertEqual(result['body_byte_mutations_rejected'],1280)
            self.assertEqual(result['unresolved'],[dict(rva=0x1650)])
            for field in ('loaded_module_identity_proven','native_enclave_run_added',
                          'whole_image_qualified','production_qualified','runtime_feature_table_validated',
                          'maximum_transitive_depth_qualified','exception_unwind_cleanup_qualified',
                          'complete_extended_register_capture','sdk_self_erasure_claimed'):
                self.assertIs(result[field],False)
            for rows in ([],[row,row],[row|{'flags':0xa0000000}],
                         [row|{'virtual_size':1}],[row|{'code':b''}]):
                with patch.object(context.diagnostic.status.sdk.pe,'linked',return_value=(rows,None)):
                    with self.assertRaises(ValueError): context.inspect(b'fixture')


if __name__ == '__main__': unittest.main()
