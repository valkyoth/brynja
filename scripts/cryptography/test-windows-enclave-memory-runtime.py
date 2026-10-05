"""Inspector and range-model regressions, not native memcpy/memset tests."""
import hashlib
import struct
import unittest
from unittest.mock import patch

import windows_enclave_memory_runtime as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        for n,address,h in review.ANCHORS:
            o=address-review.BODIES[n][0]; b=bytes.fromhex(h); bodies[n][o:o+len(b)]=b
        for n,address,op,target in review.BRANCHES:
            o=address-review.BODIES[n][0]; width=4 if len(op)==2 else 1
            bodies[n][o:o+len(op)+width]=op+(target-address-len(op)-width).to_bytes(width,'little',signed=True)
        for n,address,prefix,target,suffix in review.RIP_READS:
            o=address-review.BODIES[n][0]; p=bytes.fromhex(prefix); s=bytes.fromhex(suffix)
            b=p+struct.pack('<i',target-address-len(p)-4-len(s))+s
            bodies[n][o:o+len(b)]=b
        for n,address,table,small in review.DISPATCH:
            o=address-review.BODIES[n][0]
            b=bytes.fromhex('478b8c82' if small else '478b9c9a')+struct.pack('<I',table)
            b+=bytes.fromhex('4d03ca41ffe1' if small else '4d03da41ffe3')
            bodies[n][o:o+len(b)]=b
        return {n:bytes(b) for n,b in bodies.items()}

    def test_semantic_landmarks_and_control_flow(self):
        bodies=self.inputs(); review.check_instructions(bodies)
        sites=[(n,a,len(bytes.fromhex(h))) for n,a,h in review.ANCHORS]
        sites += [(n,a,len(op)+(4 if len(op)==2 else 1)) for n,a,op,_ in review.BRANCHES]
        sites += [(n,a,len(bytes.fromhex(p))+4+len(bytes.fromhex(s))) for n,a,p,_,s in review.RIP_READS]
        sites += [(n,a,14) for n,a,_,_ in review.DISPATCH]
        for n,a,size in sites:
            for i in range(a-review.BODIES[n][0],a-review.BODIES[n][0]+size):
                b=bytearray(bodies[n]); b[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:b})
        with self.assertRaises(ValueError): review.check_instructions({})

    def test_complete_body_identity(self):
        bodies=self.inputs()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for n,body in bodies.items():
                for i in range(len(body)):
                    b=bytearray(body); b[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:b})
                    count+=1
                for b in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:b})
                with self.assertRaises(ValueError): review.check_bodies({k:v for k,v in bodies.items() if k!=n})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,2617)

    def tables(self):
        b=b''.join(struct.pack('<16I',*v) for v in review.TABLES.values())
        return dict(rva=0xe900,virtual_size=len(b),code=b,flags=0x40000040)

    def test_all_table_bytes(self):
        row=self.tables(); records=review.check_tables([row])
        self.assertEqual(len(records),8)
        for i in range(512):
            b=bytearray(row['code']); b[i]^=1
            with self.assertRaises(ValueError): review.check_tables([row|{'code':b}])

    def test_table_mapping_and_outside_targets(self):
        row=self.tables()
        for rows in ([],[row,row],[row,row|{'rva':0xe910,'virtual_size':1}],
                     [row|{'code':row['code'][:-1]}],[row|{'virtual_size':511}],
                     [row|{'flags':0xc0000040}],[row|{'flags':0x60000040}]):
            with self.assertRaises(ValueError): review.check_tables(rows)
        # Even matching bytes cannot bless a table that points outside its body.
        changed=dict(review.TABLES); changed[0xe900]=(0x8550,)+changed[0xe900][1:]
        with patch.dict(review.TABLES,changed,clear=True):
            row=self.tables()
            with self.assertRaises(ValueError): review.check_tables([row])

    def test_vector_forward_ranges(self):
        # Enumerate all bounded small lengths and alignment residues plus long
        # threshold edges. Arithmetic model only; no image instructions execute.
        lengths=list(range(33,1025))+[2047,2048,2049,4095,4096,4097,8191,8192,8193,65535,65536]
        for width in (16,32):
            for alignment in range(width):
                for length in lengths:
                    spans,index=review.forward_spans(length,alignment,width)
                    self.assertIn(index,range(9))
                    covered=0
                    for start,size in sorted(spans):
                        self.assertGreaterEqual(start,0)
                        self.assertLessEqual(start+size,length)
                        self.assertLessEqual(start,covered)
                        covered=max(covered,start+size)
                    self.assertEqual(covered,length)

    def test_unwind_identity_without_decoder_expansion(self):
        rows=[dict(rva=a,virtual_size=len(bytes.fromhex(h)),code=bytes.fromhex(h),flags=0x40000040)
              for a,h in sorted({(a,h) for a,h,_ in review.UNWIND.values()})]
        fs=[(a,a+size,review.UNWIND[n][0]) for n,(a,size,_) in review.BODIES.items()]
        records=review.check_unwind(rows,fs)
        self.assertEqual([records[n]['version'] for n in review.BODIES],[2,1,2,1])
        self.assertTrue(all(not r['unwind_semantics_qualified'] for r in records.values()))
        for index,row in enumerate(rows):
            for i in range(len(row['code'])):
                b=bytearray(row['code']); b[i]^=1
                with self.assertRaises(ValueError):
                    review.check_unwind(rows[:index]+[row|{'code':b}]+rows[index+1:],fs)
        for index,f in enumerate(fs):
            for changed in ([],[f,f],[(f[0]+1,f[1],f[2])],[(f[0],f[1]-1,f[2])],
                            [(f[0],f[1],f[2]+4)]):
                with self.assertRaises(ValueError): review.check_unwind(rows,fs[:index]+changed+fs[index+1:])

    def test_model_domain_and_stack_reuse(self):
        for args in ((32,0,16),(65537,0,32),(64,-1,16),(64,16,16),(64,0,8),(True,0,16),(64,0,16.0)):
            with self.assertRaises(ValueError): review.forward_spans(*args)
        g=review.geometry()
        self.assertEqual(g['vector_paths_fixed_frame_bytes'],0)
        self.assertTrue(g['rep_paths_are_tail_transfers'])
        self.assertFalse(g['volatile_payload_registers_erased'])
        self.assertFalse(g['saved_register_slots_individually_erased'])
        self.assertFalse(g['maximum_transitive_depth_qualified'])
        spans=g['root_constructor_spans']
        self.assertEqual([s['bytes'] for s in spans],[16,8])
        self.assertEqual([s['offset_from_high'] for s in spans],[-19160,-19152])

    def test_identity_before_parsing(self):
        with patch.object(review.session.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
