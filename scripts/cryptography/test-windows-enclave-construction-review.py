"""Offline inspector regressions; fixtures are not native cryptographic execution."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_construction_review as review


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
                changed=bytearray(bodies[n]); changed[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(changed)},refs)

    def test_relocation_population_and_operands(self):
        bodies,refs=self.inputs()
        for n,rows in refs.items():
            for r in rows:
                for i in range(r['offset']-len(review.operand(r['symbol'])),r['offset']+4):
                    changed=bytearray(bodies[n]); changed[i]^=1
                    with self.assertRaises(ValueError): review.check_instructions(bodies|{n:bytes(changed)},refs)
                for field,value in (('symbol','wrong'),('offset',0),('addend',1),('trailing',1)):
                    changed=[row|{field:value} if row is r else row for row in rows]
                    with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
            for changed in (rows[1:],rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_all_body_bytes_and_lengths(self):
        bodies,_=self.inputs()
        specs={n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count=0
        with patch.dict(review.BODIES,specs,clear=True):
            review.check_bodies(bodies)
            for n,body in bodies.items():
                for i in range(len(body)):
                    changed=bytearray(body); changed[i]^=1
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:bytes(changed)})
                    count+=1
                for changed in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies|{n:changed})
                with self.assertRaises(ValueError): review.check_bodies({k:v for k,v in bodies.items() if k!=n})
            with self.assertRaises(ValueError): review.check_bodies(bodies|{'extra':b''})
        self.assertEqual(count,3226)

    def test_all_constant_bytes_and_permissions(self):
        expected=[bytes.fromhex(v)[::-1] for v in review.KAT]
        expected += [bytes(168),b''.join(n.to_bytes(8,'little') for n in (168,136,168,136))]
        for value in expected:
            row=dict(rva=128,virtual_size=len(value)+2,code=b'\0'+value+b'\0',flags=0x40000040)
            self.assertEqual(review.constant([row],129,value)['bytes'],len(value))
            for i in range(len(value)):
                code=bytearray(row['code']); code[i+1]^=1
                with self.assertRaises(ValueError): review.constant([row|{'code':bytes(code)}],129,value)
            for flags in (0x80000000,0x20000000,0xa0000000):
                with self.assertRaises(ValueError): review.constant([row|{'flags':row['flags']|flags}],129,value)
            for rows,rva in (([],129),([row,row],129),([row],127),([row],131),
                             ([row|{'virtual_size':len(value)}],129),
                             ([row|{'code':row['code'][:-2]}],129),
                             ([row,row|{'rva':129+len(value)-1}],129)):
                with self.assertRaises(ValueError): review.constant(rows,rva,value)

    def test_identity_before_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
