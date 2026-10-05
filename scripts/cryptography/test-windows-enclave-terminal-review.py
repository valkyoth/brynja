"""Terminal review regressions without requiring private saved artifacts."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_terminal_review as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={}
        for name,calls in review.CALLS.items():
            refs[name]=[dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
            for offset in calls:
                op=0xe9 if name=='encoded' and offset==0x24 else 0xe8
                bodies[name][offset-1:offset+4]=bytes([op])+bytes(4)
        for name,offset,hexcode in review.ANCHORS:
            code=bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)]=code
        for name,offset,op,target in review.BRANCHES:
            width=4 if len(op)==2 or op==b'\xe9' else 1
            end=offset+len(op)+width
            bodies[name][offset:end]=op+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_instruction_mutations(self):
        bodies,refs=self.inputs()
        review.check_instructions(bodies,refs)
        sites=[(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o-1,5) for n,calls in review.CALLS.items() for o in calls]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1)) for n,o,op,_ in review.BRANCHES]
        for name,offset,size in sites:
            for i in range(offset,offset+size):
                changed=bytearray(bodies[name])
                changed[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{name:bytes(changed)},refs)

    def test_relocation_identity_and_population(self):
        bodies,refs=self.inputs()
        for name,rows in refs.items():
            for field,value in (('symbol','other'),('offset',0),('addend',1),('trailing',1)):
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies,refs|{name:[rows[0]|{field:value},*rows[1:]]})
            for changed in (rows[1:],rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{name:changed})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_entire_body_identity(self):
        bodies,_=self.inputs()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for name,body in bodies.items():
                for i in range(len(body)):
                    changed=bytearray(body)
                    changed[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:bytes(changed)})
                    count+=1
                for changed in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{name:changed})
                with self.assertRaises(ValueError): review.check_bodies({n:b for n,b in bodies.items() if n!=name})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,1625)

    def test_identity_before_terminal_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
