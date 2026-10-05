"""Offline owner lifecycle regressions, not a native cryptographic campaign."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_stream_lifecycle as r


def code_for(name):
    code = bytearray(r.PINS[name][0]);sites = set()
    def put(at,raw):
        code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
    for at,h in r.LANDMARKS[name]: put(at,bytes.fromhex(h))
    for at,stack,register,phase in r.COPY_SITES[name]:
        raw = r.copy_shape(stack,register,phase)
        if name in (r.QUARANTINE,r.DROP): raw = bytes.fromhex('488d5148')+raw[4:]
        put(at,raw)
    for at,h,target in r.BRANCHES.get(name,()):
        put(at,bytes.fromhex(h)+(target-at-2).to_bytes(1,'little',signed=True))
    return bytes(code),sites


class Tests(unittest.TestCase):
    def test_complete_bodies_and_reference_pins(self):
        for name,(size,_,_) in r.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='wipe',addend=0,trailing=0)]
            with patch.dict(r.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in ([],refs*2,[refs[0] | {'symbol':'other'}],[refs[0] | {'addend':1}]):
                    with self.assertRaises(ValueError): r.body_check(name,code,changed)

    def test_admission_and_complete_copy_wipe_metadata_sequences(self):
        for name in r.PINS:
            code,sites = code_for(name);r.instructions(name,code)
            for at in sites:
                changed = bytearray(code);changed[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,changed)
        for values in ((34,'rax',3),(0,'rsi',3),(40,'rdi',2)):
            with self.assertRaises(ValueError): r.copy_shape(*values)

    def test_nonzero_ingress_preserves_checked_successor_at_wrap_boundary(self):
        maximum = (1<<64)-1
        values = list(range(256))+[maximum-2,maximum-1,maximum]
        for stored in values:
            for requested in (0,1,stored,stored+1 if stored < maximum else 0,maximum):
                expected = requested != 0 and stored != maximum and stored+1 == requested
                self.assertEqual(r.sequence_model(stored,requested),expected)
        self.assertFalse(r.sequence_model(maximum,0))
        self.assertTrue(((maximum+1) & maximum) == 0)  # Omitting ingress would accept this.
        for values in ((-1,1),(1,1<<64),(True,1),(1,1.0)):
            with self.assertRaises(ValueError): r.sequence_model(*values)

    def test_ir_identity_and_internal_nonzero_precondition(self):
        line = 'define internal fastcc void @'+r.OPERATION+'(ptr %0, ptr %1, i64 noundef range(i64 1, 0) %2, i8 %3) {\n'
        raw = line.encode()
        with patch.object(r,'IR_HASH',r.digest(raw)):
            self.assertTrue(r.ir_precondition(raw)['nonzero_sequence_precondition'])
            with self.assertRaises(ValueError): r.ir_precondition(raw+b' ')
        for changed in ('',line*2,line.replace('internal ',''),line.replace('range(i64 1, 0)','range(i64 0, 10)')):
            raw = changed.encode()
            with patch.object(r,'IR_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.ir_precondition(raw)

    def test_entry_links_shared_callees_and_exact_frames(self):
        targets = {r.wiping.WIPE:6208,r.bounded.CLEAR:5920,'memcpy':28336,r.OPERATION:10464}
        records = {n:dict(rva=i,image_sha256='same',reference_targets=targets.copy(),
                         unwind=[dict(stack_bytes=1224,chain=None,saved_registers=[])]) for i,n in enumerate(r.PINS,100)}
        records[r.OPERATION]['rva'] = 10464
        parent = dict(image_sha256='same',clearing_leaf_rva=5920,records={
            'RetainedWork':dict(reference_targets={r.QUARANTINE:records[r.QUARANTINE]['rva'],r.DROP:records[r.DROP]['rva'],r.wiping.WIPE:6208}),
            r.entry.RECEIVE:dict(reference_targets={r.CANCEL:records[r.CANCEL]['rva']})})
        wipe = dict(rva=6208,image_sha256='same',reference_targets={r.bounded.CLEAR:5920})
        r.reconcile(parent,records,wipe)
        for name in records:
            for symbol in (r.wiping.WIPE,r.bounded.CLEAR,'memcpy'):
                wrong = copy.deepcopy(records);wrong[name]['reference_targets'][symbol] += 1
                with self.assertRaises(ValueError): r.reconcile(parent,wrong,wipe)
            wrong = copy.deepcopy(records);wrong[name]['image_sha256'] = 'different'
            with self.assertRaises(ValueError): r.reconcile(parent,wrong,wipe)
            for changes in ({'stack_bytes':1200},{'chain':{}},{'saved_registers':[1]}):
                wrong = copy.deepcopy(records);wrong[name]['unwind'][0].update(changes)
                with self.assertRaises(ValueError): r.reconcile(parent,wrong,wipe)
        for name in (r.QUARANTINE,r.DROP,r.CANCEL,r.OPERATION):
            wrong = copy.deepcopy(records);wrong[name]['rva'] += 1
            with self.assertRaises(ValueError): r.reconcile(parent,wrong,wipe)

    def test_stack_copies_and_preserved_residuals(self):
        result = r.geometry(r.bounded.Window(0,65536))
        self.assertEqual([v['rsp_from_high'] for v in result['paths'].values()],[-2496,-2608,-3840])
        for path in result['paths'].values():
            self.assertEqual([s['bytes'] for s in path['spans']],[1174,1170,1170])
            self.assertIsNone(path['memory_runtime_entry']['callee_frame_bytes'])
        self.assertFalse(result['original_inactive_owner_storage_erased'])
        self.assertFalse(result['complete_moved_enum_individually_erased'])
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertTrue(result['outer_window_and_page_teardown_required'])
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.bounded.Window(low,low+65536)))

    def test_bad_object_identity_fails_before_binding(self):
        with patch.object(r.shared,'inspect',side_effect=AssertionError('parsed')):
            with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
