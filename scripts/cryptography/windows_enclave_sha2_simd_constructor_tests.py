"""Non-vacuous startup-KAT and complete saved constructor regressions."""
from unittest.mock import patch
import windows_enclave_sha2_simd_constructor as k


class ConstructorTests:
    def test_constructor_public_blocks_are_complete_and_disjoint(self):
        for lane in ('simd256','simd512'):
            bits,frame,states,blocks,scratch,temp=k.parameters(lane)
            block=2*bits;width=256//bits;raw=k.public_blocks(lane)
            for index in range(width):
                value=raw[index*block:(index+1)*block]
                self.assertEqual(value[:4],b'abc\x80')
                self.assertEqual(value[4:-1],bytes(block-5));self.assertEqual(value[-1],24)
            schedule=2048 if bits==32 else 2560
            ranges=[(states,256),(blocks,512),(scratch,256+schedule+448),(temp,schedule)]
            covered=set()
            for start,length in ranges:
                region=set(range(start,start+length))
                self.assertFalse(region&covered);self.assertLessEqual(start+length,frame)
                covered|=region
            # Overlapping compiler stores are allowed, but a missing last-byte
            # store or incorrect integer cannot still describe valid padding.
            original=k.block_stores(lane)
            for changed in (original[:-1],[(at,b'\xff'*len(data)) for at,data in original]):
                with patch.object(k,'block_stores',return_value=changed):
                    with self.assertRaises(ValueError): k.public_blocks(lane)
        with self.assertRaises(ValueError): k.parameters('other')

    def test_constructor_iv_and_expected_constant_byte_orders(self):
        for lane,word,first,last in (
            ('simd256',4,0x6a09e667,0x5be0cd19),
            ('simd512',8,0x6a09e667f3bcc908,0x5be0cd19137e2179)):
            initial,answer=k.constants(lane);iv=b''.join(raw for _,raw in initial)
            self.assertEqual(int.from_bytes(iv[:word],'little'),first)
            self.assertEqual(int.from_bytes(iv[-word:],'little'),last)
            for name,raw in initial+answer:
                self.assertEqual(int(name[6:],16).to_bytes(32,'little'),raw)

    def test_constructor_comparison_rejects_every_output_bit_in_every_lane(self):
        count=0
        for lane in ('simd256','simd512'):
            bits,*_=k.parameters(lane);width=256//bits
            expected=b''.join(raw for _,raw in k.constants(lane)[1]);outputs=[expected]*width
            self.assertTrue(k.accepts(lane,outputs))
            for index in range(width):
                for bit in range(bits*8):
                    changed=bytearray(expected);changed[bit//8]^=1<<(bit%8)
                    bad=list(outputs);bad[index]=bytes(changed)
                    self.assertFalse(k.accepts(lane,bad));count+=1
            for bad in (outputs[:-1],outputs+[expected],[b'']*width):
                with self.assertRaises(ValueError): k.accepts(lane,bad)
        self.assertEqual(count,4096)


class ConstructorSavedTests:
    def test_constructor_review_is_required(self):
        import windows_enclave_sha2_batch_chains as c
        for lane,_,_,_,ir,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            with patch.object(k,'inspect',side_effect=ValueError('constructor review failed')) as gate:
                with self.assertRaisesRegex(ValueError,'constructor review failed'): c.shapes.inspect(bodies,ir,lane)
                gate.assert_called_once()

    def test_constructor_rejects_all_instruction_and_control_label_changes(self):
        count=0
        for lane,_,_,_,_,_,bodies in self.routes:
            if not lane.startswith('simd'): continue
            name=k.s.one(bodies,r'Resident3new$');lines=k.s.lines(bodies[name])
            k.inspect(bodies,lane)
            for at in range(3,len(lines)):
                for replacement in (['int3'],['retq',lines[at]]):
                    bad=lines[:at]+replacement+lines[at+1:]
                    with self.assertRaises(ValueError): k.inspect(bodies|{name:'\n'.join(bad)},lane)
                    count+=1
        self.assertEqual(count,1002)
        print('Complete SIMD constructor instruction/control and early-return mutants rejected: '+str(count))

    def test_linked_simd_startup_constants_reject_every_changed_byte_and_missing_extent(self):
        import windows_enclave_sha2_batch_chains as c
        count=0
        for lane,pin,_,_,_,_,_ in self.routes:
            if not lane.startswith('simd'): continue
            # Obtain the independently rebound image/object constants, not just
            # invented metadata that would make both good and bad inputs fail.
            report=c.inspect_route(self.saved,self.root,lane,pin,False)
            values={n:dict(bytes=size,sha256=sha)
                    for n,(size,sha) in report['semantics']['public_constructor_constants'].items()}
            c.public_constructor_constants(values,lane)
            initial,answer=k.constants(lane)
            for name,raw in initial+answer:
                for at in range(len(raw)):
                    bad=bytearray(raw);bad[at]^=1
                    with self.assertRaises(ValueError):
                        c.public_constructor_constants(values|{name:dict(bytes=len(raw),sha256=c.digest(bad))},lane)
                    count+=1
                for change in ({n:v for n,v in values.items() if n!=name},
                               values|{name:dict(bytes=0,sha256=c.digest(raw))}):
                    with self.assertRaises(ValueError): c.public_constructor_constants(change,lane)
        self.assertEqual(count,192)
        print('SIMD startup constant bytes rejected: '+str(count)+'; missing/extent mutants: 12')
