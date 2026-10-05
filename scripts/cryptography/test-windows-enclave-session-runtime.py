"""Artifact-free inspector/model regressions; not execution of image instructions."""
import hashlib
import unittest
from unittest.mock import patch

import windows_enclave_session_runtime as review


class Tests(unittest.TestCase):
    def inputs(self):
        bodies={n:bytearray(s[1]) for n,s in review.BODIES.items()}
        refs={n:[dict(offset=o,symbol=s,addend=0,trailing=0) for o,s in calls.items()]
              for n,calls in review.CALLS.items()}
        for n,rows in refs.items():
            for r in rows:
                op=b'\x4c\x8d\x1d' if n=='kernel' else b'\xe8'
                o=r['offset']; bodies[n][o-len(op):o+4]=op+bytes(4)
        for n,o,h in review.ANCHORS:
            b=bytes.fromhex(h); bodies[n][o:o+len(b)]=b
        for n,o,op,target in review.BRANCHES:
            width=4 if len(op)==2 else 1; end=o+len(op)+width
            bodies[n][o:end]=op+(target-end).to_bytes(width,'little',signed=True)
        return {n:bytes(b) for n,b in bodies.items()},refs

    def test_instruction_and_branch_mutations(self):
        bodies,refs=self.inputs()
        review.check_instructions(bodies,refs)
        sites=[(n,o,len(bytes.fromhex(h))) for n,o,h in review.ANCHORS]
        sites += [(n,o,len(op)+(4 if len(op)==2 else 1)) for n,o,op,_ in review.BRANCHES]
        for n,o,size in sites:
            for i in range(o,o+size):
                changed=bytearray(bodies[n]); changed[i]^=1
                with self.assertRaises(ValueError): review.check_instructions(bodies|{n:changed},refs)

    def test_reference_shape(self):
        bodies,refs=self.inputs()
        for n,rows in refs.items():
            for r in rows:
                for i in range(r['offset']-(3 if n=='kernel' else 1),r['offset']+4):
                    b=bytearray(bodies[n]); b[i]^=1
                    with self.assertRaises(ValueError): review.check_instructions(bodies|{n:b},refs)
                for key,value in (('symbol','bad'),('offset',0),('trailing',1),('addend',1)):
                    changed=[s|{key:value} if s is r else s for s in rows]
                    with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
            for changed in (rows[1:],rows+[rows[0]]):
                with self.assertRaises(ValueError): review.check_instructions(bodies,refs|{n:changed})
        with self.assertRaises(ValueError): review.check_instructions({},refs)
        with self.assertRaises(ValueError): review.check_instructions(bodies,{})

    def test_complete_body_pins(self):
        bodies,_=self.inputs()
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
        self.assertEqual(count,1540)

    def test_mapping_rejects_partial_aliases(self):
        row=dict(rva=128,virtual_size=8,code=b'abcdefgh',flags=0x60000020)
        self.assertEqual(review.executable([row],130,4),b'cdef')
        for rows in ([],[row,row],[row,row|{'rva':133,'virtual_size':1}],
                     [row|{'code':b'abcd'}],[row|{'virtual_size':4}],
                     [row|{'flags':0x40000040}],[row|{'flags':0xe0000020}]):
            with self.assertRaises(ValueError): review.executable(rows,130,4)
        for rva,size in ((-1,4),(130,0),(130,-1),(130,65537),(True,4)):
            with self.assertRaises(ValueError): review.executable([row],rva,size)

    def test_unwind_save_reconciliation(self):
        records={n:dict(handler=None) for n in review.CALLS}
        saves=[dict(register_class='xmm',register=r,offset=16*(r-6)) for r in range(6,16)]
        frames={'session':[dict(stack_bytes=40,saved_registers=[])],
                'kernel':[dict(stack_bytes=168,saved_registers=saves)]}
        review.check_frames(records,frames)
        for n in frames:
            with self.assertRaises(ValueError): review.check_frames(records|{n:dict(handler=1)},frames)
            for changed in ([],frames[n]*2,[frames[n][0]|{'stack_bytes':0}]):
                with self.assertRaises(ValueError): review.check_frames(records,frames|{n:changed})
        for changed in (saves[:-1],saves+[saves[0]],saves[::-1],
                        [s|{'offset':s['offset']+8} for s in saves]):
            with self.assertRaises(ValueError):
                review.check_frames(records,frames|{'kernel':[dict(stack_bytes=168,saved_registers=changed)]})

    def test_round_constants_are_immutable_and_exact(self):
        expected=b''.join(x.to_bytes(8,'little') for x in review.ROUND_CONSTANTS)
        self.assertEqual(len(expected),192)
        row=dict(rva=128,code=expected,virtual_size=192,flags=0x40000040)
        review.setup.construction.constant([row],128,expected)
        for i in range(192):
            b=bytearray(expected); b[i]^=1
            with self.assertRaises(ValueError): review.setup.construction.constant([row|{'code':b}],128,expected)
        for flag in (0xc0000040,0x60000040):
            with self.assertRaises(ValueError): review.setup.construction.constant([row|{'flags':flag}],128,expected)

    def test_valid_authority_domain(self):
        for health in range(3):
            for generation in (False,True):
                for kernel in range(6):
                    expected=('NotReady' if health==0 else 'Quarantined' if health==2 else
                              'StaleGeneration' if not generation else
                              'WrongArchitecture' if kernel in (2,3,5) else
                              'MissingTargetFeatures' if kernel in (0,1) else 'kernel_then_wipe')
                    self.assertEqual(review.session_path(health,generation,kernel),expected)
        for args in ((3,True,4),(1,True,6),(1,1,4),(False,True,4),(1,True,-1)):
            with self.assertRaises(ValueError): review.session_path(*args)

    def test_public_prefix_division_model(self):
        for rate in (136,168):
            for custom in range(8193):
                encoding=2 if custom<256 else 3
                numerator=(8*(2+2+encoding)+96+custom+7)//8
                remainder=review.prefix_remainder(numerator,rate)
                self.assertEqual(numerator-remainder,(numerator//rate)*rate)
                self.assertLess(remainder,rate)
        for n,d in ((-1,136),(1<<64,136),(1,0),(1,135)):
            with self.assertRaises(ValueError): review.prefix_remainder(n,d)

    def test_frame_saves_and_scope(self):
        g=review.geometry()
        self.assertEqual(g['relative_session_frame_bytes'],40)
        self.assertEqual(g['relative_kernel_frame_bytes'],168)
        self.assertEqual([s['bytes'] for s in g['spans']],[8,160,8,16,16])
        for s in g['spans']: self.assertGreaterEqual(s['offset_from_low'],0)
        self.assertFalse(g['probe_page_addresses_qualified'])
        self.assertFalse(g['transitive_depth_qualified'])
        self.assertFalse(g['kernel_saves_individually_erased'])
        self.assertTrue(g['kernel_and_scratch_calls_are_sequential'])

    def test_identity_before_parsing(self):
        with patch.object(review.slot.binding.obj,'select',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): review.inspect(b'object',b'image')


if __name__=='__main__': unittest.main()
