"""Engine inspector regressions; artifact-free instruction fixtures, not crypto tests."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_engine_review as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={n:[dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
              for n,calls in review.CALLS.items()}
        for n,rows in refs.items():
            for r in rows:
                op=b'\x48\x8d\x15' if r['symbol']==review.PAD else b'\xe9' if n=='mask' else b'\xe8'
                o=r['offset']
                bodies[n][o-len(op):o+4]=op+bytes(4)
        for n,o,h in review.ANCHORS:
            code=bytes.fromhex(h)
            bodies[n][o:o+len(code)]=code
        for n,o,op,target in review.BRANCHES:
            width=4 if len(op)==2 or op==b'\xe9' else 1
            end=o+len(op)+width
            bodies[n][o:end]=op+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_landmarks_and_branches(self):
        bodies,refs=self.inputs()
        review.check_instructions(bodies,refs)
        sites=[(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1)) for n,o,op,_ in review.BRANCHES]
        for n,o,size in sites:
            for i in range(o,o+size):
                changed=bytearray(bodies[n])
                changed[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(changed)},refs)

    def test_all_reference_operands(self):
        bodies,refs=self.inputs()
        for n,rows in refs.items():
            for r in rows:
                o=r['offset']
                prefix=3 if r['symbol']==review.PAD else 1
                for i in range(o-prefix,o+4):
                    changed=bytearray(bodies[n])
                    changed[i]^=1
                    with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(changed)},refs)
                for field,value in (('symbol','wrong'),('offset',0),('addend',1),('trailing',1)):
                    changed=[row|{field:value} if row is r else row for row in rows]
                    with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
            if rows:
                for changed in (rows[1:],rows+[rows[0]]):
                    with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
            else:
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies,refs|{n:[dict(offset=1,symbol='wrong',addend=0,trailing=0)]})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_complete_body_identity(self):
        bodies,_=self.inputs()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for n,body in bodies.items():
                for i in range(len(body)):
                    changed=bytearray(body)
                    changed[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:bytes(changed)})
                    count+=1
                for changed in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:changed})
                with self.assertRaises(ValueError): review.check_bodies({k:v for k,v in bodies.items() if k!=n})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,2453)

    def test_padding_byte_and_section(self):
        row=dict(rva=128,virtual_size=2,code=b'\0\x80',flags=0x40000040)
        self.assertEqual(review.padding_constant([row],129)['byte'],128)
        for flag in (0xa0000000,0x80000000,0x20000000):
            with self.assertRaises(ValueError): review.padding_constant([row|{'flags':row['flags']|flag}],129)
        for code in (b'\0\0',b'\0',b'\0\x81'):
            with self.assertRaises(ValueError): review.padding_constant([row|{'code':code}],129)
        for rows,rva in (([],129),([row,row],129),([row],127),([row],130),([row|{'virtual_size':1}],129)):
            with self.assertRaises(ValueError): review.padding_constant(rows,rva)

    def test_relative_frame_slots(self):
        frames=review.relative_frames()
        self.assertEqual({n:f['fixed_bytes'] for n,f in frames.items()},
                         dict(absorb=104,finish=120,read=104,copy=40,xor=56))
        for f in frames.values():
            self.assertFalse(f['transitive_depth_qualified'])
            for s in f['slots']:
                self.assertGreaterEqual(s['offset_from_high'],-40-f['fixed_bytes'])
                self.assertLessEqual(s['offset_from_high']+s['bytes'],-40)
        self.assertEqual(frames['read']['slots'][0]['bytes'],8)
        self.assertEqual(frames['finish']['slots'][1]['bytes'],1)

    def test_identity_before_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
