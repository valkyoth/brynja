"""Saved-root inspection regressions; no enclave or cryptographic execution."""
import hashlib
import json
import unittest
from unittest.mock import patch

import windows_enclave_root_return as review


class Tests(unittest.TestCase):
    def synthetic(self):
        bodies = {n: bytearray(s[1]) for n,s in review.BODIES.items()}
        refs = {n: [] for n in bodies}
        for name, calls in review.CALLS.items():
            refs[name] = [dict(offset=o, symbol=s, trailing=0, addend=0) for o,s in calls.items()]
            for offset in calls: bodies[name][offset-1:offset+4] = b'\xe8\0\0\0\0'
        for name, offset, hexcode in review.ANCHORS:
            code = bytes.fromhex(hexcode)
            bodies[name][offset:offset+len(code)] = code
        for name, offset, opcode, target in review.BRANCHES:
            width = 4 if len(opcode) == 2 or opcode == b'\xe9' else 1
            end = offset+len(opcode)+width
            bodies[name][offset:end] = opcode+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()}, refs

    def test_instruction_and_branch_mutations(self):
        bodies, refs = self.synthetic()
        review.check_instructions(bodies, refs)
        sites = [(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o-1,5) for n,c in review.CALLS.items() for o in c]
        sites += [(n,o,len(op)+(4 if len(op)==2 or op==b'\xe9' else 1)) for n,o,op,_ in review.BRANCHES]
        for name, offset, size in sites:
            for index in range(offset,offset+size):
                changed = bytearray(bodies[name]); changed[index] ^= 1
                with self.assertRaises(ValueError):
                    review.check_instructions(bodies | {name:bytes(changed)},refs)

    def test_call_targets_and_population(self):
        bodies, refs = self.synthetic()
        for name, calls in review.CALLS.items():
            for row in refs[name]:
                for field, value in (('symbol','other'),('addend',1),('trailing',1),('offset',0)):
                    changed = [r | {field:value} if r is row else r for r in refs[name]]
                    with self.assertRaises(ValueError):
                        review.check_instructions(bodies,refs | {name:changed})
            with self.assertRaises(ValueError): review.check_instructions(bodies,refs | {name:[]})
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_whole_reference_pins(self):
        _, refs = self.synthetic()
        pins = {n:hashlib.sha256(json.dumps(r,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                for n,r in refs.items()}
        with patch.dict(review.REFERENCES,pins,clear=True):
            review.check_references(refs)
            for name, rows in refs.items():
                variants = [rows+[dict(offset=0,symbol='injected',trailing=0,addend=0)]]
                if rows: variants += [rows[1:],rows+[rows[0]],list(reversed(rows))] if len(rows)>1 else [rows[1:]]
                for changed in variants:
                    with self.assertRaises(ValueError): review.check_references(refs | {name:changed})
            with self.assertRaises(ValueError): review.check_references({})

    def test_whole_body_pins(self):
        bodies,_ = self.synthetic()
        pins = {n:(review.BODIES[n][0],len(b),hashlib.sha256(b).hexdigest()) for n,b in bodies.items()}
        count = 0
        with patch.dict(review.BODIES,pins,clear=True):
            review.check_bodies(bodies)
            for name, body in bodies.items():
                for index in range(len(body)):
                    changed = bytearray(body); changed[index] ^= 1
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name:bytes(changed)})
                    count += 1
                for changed in (body[:-1],body+b'\0'):
                    with self.assertRaises(ValueError): review.check_bodies(bodies | {name:changed})
            with self.assertRaises(ValueError): review.check_bodies({})
            with self.assertRaises(ValueError): review.check_bodies(bodies | {'extra':b''})
        self.assertEqual(count,4131)

    def leaf_fixture(self):
        symbol = review.BODIES['region'][0]
        code = b'\x83\x3d'+bytes(5)+b'\xc3'
        refs = [dict(offset=2,symbol='slots',trailing=1,addend=0)]
        linked = code[:2]+(0x2000-0x207).to_bytes(4,'little',signed=True)+code[6:]
        rows = [dict(rva=0x200,virtual_size=8,code=linked,flags=0x60000020),
                dict(rva=0x2000,virtual_size=1024,code=bytes(1024),flags=0xc0000040)]
        anchor = dict(image_sha256=hashlib.sha256(b'image').hexdigest(),reference_targets={symbol:0x200})
        pin = (symbol,len(code),hashlib.sha256(code).hexdigest())
        refpin = hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return code,refs,rows,anchor,pin,refpin

    def bind_fixture(self, rows=None, runtime=(), anchor=None, code=None, refs=None):
        c,r,rs,a,p,rp = self.leaf_fixture()
        with patch.dict(review.BODIES,{'region':p}), patch.dict(review.REFERENCES,{'region':rp}), \
             patch.object(review.caller,'function',return_value=(c if code is None else code,r if refs is None else refs)), \
             patch.object(review.caller.pe,'linked',return_value=(rs if rows is None else rows,runtime)):
            return review.bind_leaf(b'object',b'image','region',a if anchor is None else anchor)

    def test_anchored_leaf_with_trailing_reference(self):
        result = self.bind_fixture()
        self.assertEqual(result['reference_targets'],{'slots':0x2000})
        code,refs,rows,anchor,_,_ = self.leaf_fixture()
        for altered in (code[:-1],code[:-1]+b'\x90'):
            with self.assertRaises(ValueError): self.bind_fixture(code=altered)
        for altered in ([],refs+[refs[0]],[refs[0] | {'trailing':0}]):
            with self.assertRaises(ValueError): self.bind_fixture(refs=altered)
        with self.assertRaises(ValueError): self.bind_fixture(anchor=anchor | {'image_sha256':'wrong'})

    def test_leaf_mapping_metadata_and_relocation_rejections(self):
        _,_,rows,anchor,_,_ = self.leaf_fixture()
        badrows = [rows+[rows[0]], [rows[0] | {'flags':0xe0000020},rows[1]],
                   [rows[0] | {'virtual_size':7},rows[1]],
                   [rows[0] | {'code':rows[0]['code'][:-1]+b'\x90'},rows[1]],
                   [rows[0] | {'code':rows[0]['code'][:2]+bytes(4)+rows[0]['code'][6:]}]]
        for changed in badrows:
            with self.assertRaises(ValueError): self.bind_fixture(rows=changed)
        for span in ((0x200,0x208,0),(0x1ff,0x201,0),(0x207,0x209,0)):
            with self.assertRaises(ValueError): self.bind_fixture(runtime=[span])
        with self.assertRaises(ValueError):
            self.bind_fixture(anchor=anchor | {'reference_targets':{review.BODIES['region'][0]:0x201}})

    def test_callee_and_shared_global_identity(self):
        records = [dict(entry='root',rva=100,reference_targets={'output':200,'slots':300}),
                   dict(entry='output',rva=200,reference_targets={'slots':300,'scheduler_completed':400}),
                   dict(entry='complete',rva=500,reference_targets={'scheduler_completed':400})]
        self.assertEqual(review.close_edges(records),{'slots':300,'scheduler_completed':400})
        for index,field in ((0,'output'),(1,'slots'),(2,'scheduler_completed')):
            changed = [dict(r,reference_targets=dict(r['reference_targets'])) for r in records]
            changed[index]['reference_targets'][field] += 1
            with self.assertRaises(ValueError): review.close_edges(changed)


if __name__ == '__main__': unittest.main()
