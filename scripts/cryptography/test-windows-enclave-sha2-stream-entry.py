"""Saved scalar SHA-2 entry regressions, not execution of the enclave image."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_stream_entry as r


def input_code(name):
    code = bytearray(r.PINS[name][0]);sites = set()
    def put(at,raw):
        code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
    for at,h in r.LANDMARKS[name]: put(at,bytes.fromhex(h))
    for at,h,target in r.BRANCHES.get(name,()):
        op = bytes.fromhex(h);width = 4 if len(op) == 2 or op == b'\xe9' else 1
        put(at,op+(target-at-len(op)-width).to_bytes(width,'little',signed=True))
    if name == 'RetainedWork':
        put(0xd0,bytes.fromhex('c6040f00')+b''.join(bytes.fromhex('c6440f')+bytes([i,0]) for i in range(1,8))+
            bytes.fromhex('4883c1084881f90010000075cc'))
        for at,h in ((0x207,'b80304000041becd000000483d33040000'),
                     (0x21a,'807c041d00'),(0x225,'807c041e00'),(0x22c,'807c041f00'),
                     (0x233,'807c042000488d4004'),(0x26d,'b80400000041becd000000'),
                     (0x278,'807c041c00'),(0x27f,'807c041d00'),(0x286,'807c041e00'),
                     (0x28d,'807c041f00'),(0x294,'483d00040000'),(0x29c,'807c042000488d4005')):
            put(at,bytes.fromhex(h))
    return bytes(code),sites


class Tests(unittest.TestCase):
    def test_complete_body_and_reference_identity(self):
        for name,(size,_,_) in r.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='callee',addend=0,trailing=0)]
            with patch.dict(r.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for wrong in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,wrong,refs)
                for wrong in ([],refs*2,[refs[0] | {'symbol':'other'}],[refs[0] | {'addend':4}]):
                    with self.assertRaises(ValueError): r.body_check(name,code,wrong)

    def test_lifecycle_receive_cleanup_and_all_reviewed_branches(self):
        for name in r.PINS:
            code,sites = input_code(name);r.instructions(name,code)
            for at in sites:
                changed = bytearray(code);changed[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,changed)

    def test_exact_page_and_buffer_readback_plan(self):
        code,_ = input_code('RetainedWork');plan = r.clearing_loops(code)
        self.assertEqual(plan,dict(page_bytes=4096,payload_rsp_offset=32,payload_bytes=1024,
                                   header_rsp_offset=1056,header_bytes=48))
        for at in (0xd0,0xf6,0xfa,0x101,0x208,0x215,0x239,0x26e,0x296,0x2a4):
            changed = bytearray(code);changed[at] ^= 1
            with self.assertRaises(ValueError): r.clearing_loops(changed)

    def test_six_exact_operation_targets(self):
        for table,entry in ((1000,100),(500,1500),(38124,5504)):
            raw = b''.join((entry+t-table).to_bytes(4,'little',signed=True) for t in r.DESTINATIONS)
            self.assertEqual(r.table_targets(raw,table,entry),list(r.DESTINATIONS))
            for i in range(24):
                changed = bytearray(raw);changed[i] ^= 1
                with self.assertRaises(ValueError): r.table_targets(changed,table,entry)
            for wrong in (raw[:-1],raw+bytes(4),raw[4:]+raw[:4]):
                with self.assertRaises(ValueError): r.table_targets(wrong,table,entry)

    def test_caller_edges_and_fixed_frames(self):
        parent = dict(image_sha256='image',retained_worker_rva=100)
        records = {}
        for name,rva,frame in (('RetainedWork',100,1160),(r.RECEIVE,200,104),(r.DROP,300,40)):
            records[name] = dict(rva=rva,image_sha256='image',reference_targets={r.RECEIVE:200,r.DROP:300,r.bounded.CLEAR:400},
                                 unwind=[dict(stack_bytes=frame,chain=None,saved_registers=[])])
        clear = dict(rva=400,image_sha256='image');r.reconcile(parent,records,clear)
        for name in records:
            wrong = copy.deepcopy(records);wrong[name]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.reconcile(parent,wrong,clear)
            for changes in ({'stack_bytes':0},{'chain':{}},{'saved_registers':[1]}):
                wrong = copy.deepcopy(records);wrong[name]['unwind'][0].update(changes)
                with self.assertRaises(ValueError): r.reconcile(parent,wrong,clear)
        for name,target in (('RetainedWork',r.RECEIVE),('RetainedWork',r.DROP),('RetainedWork',r.bounded.CLEAR),(r.DROP,r.bounded.CLEAR)):
            wrong = copy.deepcopy(records);wrong[name]['reference_targets'][target] += 1
            with self.assertRaises(ValueError): r.reconcile(parent,wrong,clear)
        with self.assertRaises(ValueError): r.reconcile(parent | {'retained_worker_rva':101},records,clear)

    def test_readonly_complete_table_mapping(self):
        raw = b''.join((100+t-1000).to_bytes(4,'little',signed=True) for t in r.DESTINATIONS)
        row = dict(rva=1000,virtual_size=24,code=raw,flags=0x40000040)
        self.assertEqual(r.linked_table([row],1000,100),list(r.DESTINATIONS))
        for rows in ([],[row,row],[row | {'code':raw[:-1]}],[row | {'virtual_size':23}],
                     [row | {'flags':0xc0000040}],[row | {'flags':0x60000040}],
                     [row,row | {'rva':1010,'virtual_size':1}]):
            with self.assertRaises(ValueError): r.linked_table(rows,1000,100)

    def test_translated_geometry_does_not_claim_callee_depth(self):
        result = r.geometry(r.bounded.Window(0,65536))
        self.assertEqual([result[n] for n in ('worker_rsp_from_high','receive_rsp_from_high','drop_rsp_from_high')],[-1264,-1376,-1312])
        self.assertEqual([s['bytes'] for s in result['spans']],[1024,48,1])
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['caller_register_erasure_claimed'])
        self.assertTrue(all(c['callee_frame_bytes'] is None for c in result['unknown_callees']))
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.bounded.Window(low,low+65536)))

    def test_bad_identity_rejected_before_binding(self):
        with patch.object(r.shared,'inspect',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
