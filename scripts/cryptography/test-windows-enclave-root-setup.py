"""Root setup inspector/model tests; not execution or general disassembly proofs."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_root_setup as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={n:[dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
              for n,calls in review.CALLS.items()}
        for n,rows in refs.items():
            for r in rows:
                op=review.operand(r['symbol']); o=r['offset']
                bodies[n][o-len(op):o+4]=op+bytes(4)
        for n,o,h in review.ANCHORS:
            code=bytes.fromhex(h); bodies[n][o:o+len(code)]=code
        for n,o,op,target in review.BRANCHES:
            width=4 if len(op)==2 or op==b'\xe9' else 1
            end=o+len(op)+width
            bodies[n][o:end]=op+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_landmarks_and_branches(self):
        bodies,refs=self.inputs(); review.check_instructions(bodies,refs)
        sites=[(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1)) for n,o,op,_ in review.BRANCHES]
        for n,o,size in sites:
            for i in range(o,o+size):
                b=bytearray(bodies[n]); b[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(b)},refs)

    def test_reference_operands_and_population(self):
        bodies,refs=self.inputs()
        for n,rows in refs.items():
            for r in rows:
                for i in range(r['offset']-len(review.operand(r['symbol'])),r['offset']+4):
                    b=bytearray(bodies[n]); b[i]^=1
                    with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(b)},refs)
                for field,value in (('symbol','wrong'),('offset',0),('trailing',1),('addend',1)):
                    changed=[row|{field:value} if row is r else row for row in rows]
                    with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
            for changed in (rows[1:],rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_body_identity(self):
        bodies,_=self.inputs()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for n,body in bodies.items():
                for i in range(len(body)):
                    b=bytearray(body); b[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:bytes(b)})
                    count+=1
                for b in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:b})
                with self.assertRaises(ValueError): review.check_bodies({k:v for k,v in bodies.items() if k!=n})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,3176)

    def test_bounded_prefix_arithmetic_model(self):
        # Independent bytepad-size calculation across every admitted customization
        # length. These are model comparisons, not native execution case counts.
        def encoded_size(value):
            width=1
            while value>=256:
                width+=1; value//=256
            return width+1
        for identity in range(1,5):
            rate=168 if identity%2 else 136
            for custom in range(8193):
                raw=encoded_size(rate)+encoded_size(96)+12+encoded_size(custom)+(custom+7)//8
                pad=0 if raw%rate==0 else rate-raw%rate
                r=review.reviewed_lengths(identity,1024,0,custom,8192)
                self.assertEqual(r['prefix_bytes'],raw+pad)
                self.assertEqual(r['algorithm'],6 if identity%2 else 7)
                self.assertEqual(r['expected_leaves'],0)
                self.assertLessEqual(r['prefix_bytes'],1176)

    def test_block_and_leaf_model_boundaries(self):
        for block in range(1,1025):
            r=review.reviewed_lengths(1,block,block*8*65536,0,0)
            self.assertEqual(r['expected_leaves'],65536)
            value=r['block_encoding']
            self.assertEqual(len(value),value[0]+1)
            self.assertEqual(int.from_bytes(value[1:],'big'),block)
            self.assertIn(value[0],(1,2))  # Specialized encoder shifts only 0/8.
            for bits,want in ((0,0),(1,1),(block*8,1),(block*8+1,2)):
                self.assertEqual(review.reviewed_lengths(4,block,bits,0,0)['expected_leaves'],want)
            with self.assertRaises(ValueError): review.reviewed_lengths(1,block,block*8*65536+1,0,0)
        for args in ((0,1,0,0,0),(5,1,0,0,0),(1,0,0,0,0),(1,1025,0,0,0),
                     (1,1,0,8193,0),(1,1,0,0,8193),(1,1,1<<64,0,0),(True,1,0,0,0)):
            with self.assertRaises(ValueError): review.reviewed_lengths(*args)

    def test_copy_span_bounds(self):
        result=review.geometry()
        self.assertFalse(result['earlier_copies_individually_erased'])
        self.assertFalse(result['all_reachable_callee_depths_qualified'])
        for s in result['spans']:
            self.assertGreaterEqual(s['offset_from_low'],0)
            self.assertLessEqual(s['offset_from_low']+s['bytes'],65536)
        moved=[s for s in result['spans'] if 'moved payload' in s['name']]
        self.assertEqual([s['bytes'] for s in moved],[943,943])

    def test_wrong_image_before_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
