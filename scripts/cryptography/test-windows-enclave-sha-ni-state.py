"""Focused saved-state review regressions; no new native cryptographic claim."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha_ni_state as r


def semantic_code(name):
    code = bytearray(r.PINS[name][0]);sites = {}
    for at,h in r.shapes.LANDMARKS[name]:
        for i,b in enumerate(bytes.fromhex(h),at):
            if i in sites: assert sites[i] == b
            code[i] = b;sites[i] = b
    if name == r.NEW:
        for a,b,n in r.shapes.REPEATS:
            for j in range(n):
                if b+j in sites: assert code[b+j] == code[a+j]
                code[b+j] = code[a+j];sites[b+j] = code[a+j]
    return code,sites


class Tests(unittest.TestCase):
    def test_complete_body_and_relocation_pins(self):
        for name,(size,_,_) in r.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='copy',addend=0,trailing=0)]
            with patch.dict(r.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for at in range(size):
                    bad = bytearray(code);bad[at] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,bad,refs)
                for bad in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,bad,refs)
                for bad in ([],refs*2,[refs[0] | {'symbol':'other'}],[refs[0] | {'trailing':1}]):
                    with self.assertRaises(ValueError): r.body_check(name,code,bad)

    def test_constructor_and_finalizer_semantic_landmarks(self):
        count = 0
        for name in (r.NEW,r.FINISH):
            code,sites = semantic_code(name);r.instructions(name,code)
            for at in sites:
                bad = code.copy();bad[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,bad)
                count += 1
        self.assertGreater(count,2100)

    def test_copy_equal_length_guard_and_register_erasure(self):
        code = bytes.fromhex('4883ec28b0024c39ca75104989d24c89c24d89d0e800000000b0ff4883c428c3')
        r.instructions(r.COPY,code)
        for at in range(len(code)):
            bad = bytearray(code);bad[at] ^= 1
            with self.assertRaises(ValueError): r.instructions(r.COPY,bad)
        code = bytes(61)+bytes.fromhex('31c031c931d2c3');r.instructions(r.BYTES,code)
        for at in range(61,68):
            bad = bytearray(code);bad[at] ^= 1
            with self.assertRaises(ValueError): r.instructions(r.BYTES,bad)

    def test_private_compiler_preconditions(self):
        text = 'define internal fastcc void @'+r.NEW+'(ptr dereferenceable(2000) %0, i16 range(i16 0, 7) %1) {\n'
        text += 'define internal fastcc i8 @'+r.FINISH+'(ptr dereferenceable(2000) %0, i64 range(i64 0, 33) %3) {\n'
        raw = text.encode()
        with patch.object(r.receiver,'IR_HASH',r.digest(raw)):
            self.assertFalse(r.preconditions(raw)['standalone_unbounded_call_claimed'])
            with self.assertRaises(ValueError): r.preconditions(raw+b' ')
        for bad in ('',text*2,text.replace('internal ',''),text.replace('0, 33','0, 65'),
                    text.replace('0, 7','0, 8'),text.replace('2000','1999')):
            raw = bad.encode()
            with patch.object(r.receiver,'IR_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.preconditions(raw)

    def fixture(self):
        def rec(address,size,saved=()):
            return dict(rva=address,image_sha256='same',reference_targets={},
                        unwind=[dict(stack_bytes=size,saved_registers=list(saved),chain=None)])
        records = {r.NEW:rec(100,7800,[dict(register_class='xmm',register=6,offset=7728)]),
                   r.FINISH:rec(200,2104),r.COPY:rec(300,40),r.BYTES:rec(400,0)}
        anchors = {n:rec(i,0) for i,n in enumerate(r.ANCHORS,500)}
        parent = dict(image_sha256='same',records={r.life.SCRATCH:dict(rva=600),
                      r.life.QUARANTINE:dict(reference_targets={r.life.wiping.WIPE:700})})
        targets = {n:v['rva'] for n,v in records.items()} | {r.life.SCRATCH:600,r.life.wiping.WIPE:700,
                   r.life.bounded.CLEAR:800,'memcpy':900,'memset':1000}
        for record in (*records.values(),*anchors.values()): record['reference_targets'] = targets.copy()
        return records,anchors,parent,800,900,1000

    def test_required_call_edges_and_same_image(self):
        args = self.fixture();r.reconcile(*args)
        for group in (0,1):
            for name,record in args[group].items():
                for callee in record['reference_targets']:
                    bad = copy.deepcopy(args);bad[group][name]['reference_targets'][callee] += 1
                    with self.assertRaises(ValueError): r.reconcile(*bad)
                bad = copy.deepcopy(args);bad[group][name]['image_sha256'] = 'other'
                with self.assertRaises(ValueError): r.reconcile(*bad)
        for caller,callee in ((r.BEGIN,r.NEW),(r.REHASH,r.NEW),(r.OWNER_FINISH,r.FINISH),(r.REHASH,r.FINISH)):
            bad = copy.deepcopy(args);del bad[1][caller]['reference_targets'][callee]
            with self.assertRaises(ValueError): r.reconcile(*bad)

    def test_frames_include_saved_vector_storage(self):
        args = self.fixture()
        for name in (r.NEW,r.FINISH,r.COPY):
            for change in ({'stack_bytes':64},{'chain':{}},{'saved_registers':[dict(register_class='xmm',register=7,offset=7728)]}):
                bad = copy.deepcopy(args);bad[0][name]['unwind'][0].update(change)
                with self.assertRaises(ValueError): r.reconcile(*bad)
        bad = copy.deepcopy(args);bad[0][r.NEW]['unwind'][0]['saved_registers'] = []
        with self.assertRaises(ValueError): r.reconcile(*bad)

    def test_geometry_not_a_maximum_depth_or_individual_erasure_claim(self):
        value = r.geometry(r.life.Window(0,65536))
        self.assertEqual([p['rsp_from_high'] for p in value['paths'].values()],[-13360,-13504,-5760,-7808])
        self.assertTrue(value['outer_window_cleanup_required'])
        self.assertFalse(value['maximum_transitive_depth_qualified'])
        self.assertFalse(value['constructor_saved_xmm6_individually_erased'])
        self.assertFalse(value['all_moved_copies_individually_erased'])
        for path in value['paths'].values():
            self.assertIsNone(path['unqualified_callee']['callee_frame_bytes'])
            for span in path['spans']: self.assertLessEqual(span['offset_from_high']+span['bytes'],0)
        for low in (4096,0x700000000000): self.assertEqual(value,r.geometry(r.life.Window(low,low+65536)))

    def test_both_iv_constants_in_object_and_linked_image(self):
        raw = [int(n[6:],16).to_bytes(32,'little') for n in r.IVS]
        rows = [dict(code=b,flags=0x40000000,nrelocs=0) for b in raw]
        syms = {i:dict(name=n,value=0,section=i+1) for i,n in enumerate(r.IVS)}
        linked = [dict(code=b,rva=100+i*32,virtual_size=32,flags=0x40000000) for i,b in enumerate(raw)]
        rec = dict(reference_targets={n:100+i*32 for i,n in enumerate(r.IVS)})
        with patch.object(r.obj,'tables',return_value=(rows,syms)),patch.object(r.shared.caller.pe,'linked',return_value=(linked,[])):
            self.assertEqual(len(r.constants(b'',b'',rec)),2)
            for i in range(2):
                for field,value in (('flags',0xc0000000),('nrelocs',1),('code',bytes(32))):
                    bad = copy.deepcopy(rows);bad[i][field] = value
                    with patch.object(r.obj,'tables',return_value=(bad,syms)):
                        with self.assertRaises(ValueError): r.constants(b'',b'',rec)
                for j in range(32):
                    bad = copy.deepcopy(linked);b = bytearray(bad[i]['code']);b[j] ^= 1;bad[i]['code'] = bytes(b)
                    with patch.object(r.shared.caller.pe,'linked',return_value=(bad,[])):
                        with self.assertRaises(ValueError): r.constants(b'',b'',rec)


if __name__ == '__main__': unittest.main()
