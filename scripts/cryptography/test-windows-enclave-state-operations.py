"""Saved state-adapter inspector tests; no private artifact dependency."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_state_operations as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={n:[dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
              for n,calls in review.CALLS.items()}
        for n,calls in review.CALLS.items():
            for o in calls: bodies[n][o-1:o+4]=b'\xe8'+bytes(4)
        for n,o,h in review.ANCHORS:
            code=bytes.fromhex(h)
            bodies[n][o:o+len(code)]=code
        for n,o,op,target in review.BRANCHES:
            width=4 if len(op)==2 or op==b'\xe9' else 1
            end=o+len(op)+width
            bodies[n][o:end]=op+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_landmarks_calls_and_branch_mutations(self):
        bodies,refs=self.inputs()
        review.check_instructions(bodies,refs)
        sites=[(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o-1,5) for n,calls in review.CALLS.items() for o in calls]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1))
                  for n,o,op,_ in review.BRANCHES]
        for n,o,size in sites:
            for i in range(o,o+size):
                changed=bytearray(bodies[n])
                changed[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(changed)},refs)

    def test_relocation_identity_and_population(self):
        bodies,refs=self.inputs()
        for n,rows in refs.items():
            for field,value in (('symbol','other'),('offset',0),('addend',1),('trailing',1)):
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies,refs|{n:[rows[0]|{field:value},*rows[1:]]})
            for changed in (rows[1:],rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_whole_body_mutations(self):
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
        self.assertEqual(count,1452)

    def test_identity_before_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
