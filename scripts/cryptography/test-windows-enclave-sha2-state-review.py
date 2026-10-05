"""Saved state review regressions, independent of native enclave execution."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_state_review as r


class Tests(unittest.TestCase):
    def test_body_relocations_and_all_byte_mutations(self):
        for name,(size,_,_) in r.shapes.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='callee',addend=0,trailing=0)]
            with patch.dict(r.shapes.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changes in ({'symbol':'other'},{'offset':2},{'addend':28},{'trailing':1}):
                    with self.assertRaises(ValueError): r.body_check(name,code,[refs[0] | changes])
                for changed in ([],refs*2):
                    with self.assertRaises(ValueError): r.body_check(name,code,changed)

    def test_semantic_landmarks_without_body_hash(self):
        for name in r.shapes.PINS:
            code = bytearray(r.shapes.PINS[name][0]);sites = set()
            for at,h in r.shapes.spans(name):
                raw = bytes.fromhex(h);code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
            r.shapes.instructions(name,code)
            for at in sites:
                changed = code.copy();changed[at] ^= 1
                with self.assertRaises(ValueError): r.shapes.instructions(name,changed)

    def test_all_nine_tables_bytes_and_readonly_mapping(self):
        for name,targets in r.shapes.TABLES.items():
            address,start = 40000,10000
            raw = b''.join((start+t-address-(i//7)*28).to_bytes(4,'little',signed=True) for i,t in enumerate(targets))
            row = dict(rva=address,virtual_size=len(raw),code=raw,flags=0x40000040)
            self.assertEqual(r.linked_table(name,[row],address,start),list(targets))
            for i in range(len(raw)):
                changed = bytearray(raw);changed[i] ^= 1
                with self.assertRaises(ValueError): r.linked_table(name,[row | {'code':bytes(changed)}],address,start)
            for rows in ([],[row,row],[row | {'code':raw[:-1]}],[row | {'virtual_size':len(raw)-1}],
                         [row | {'flags':0xc0000040}],[row | {'flags':0x60000040}]):
                with self.assertRaises(ValueError): r.linked_table(name,rows,address,start)
            with self.assertRaises(ValueError): r.table_targets(name,raw+b'\0',address,start)

    def test_cleanup_table_skips_only_consumed_variant(self):
        targets = r.shapes.TABLES[r.FINISH]
        for table,consumed in enumerate((6,5,4,3,2,1,0),1):
            row = targets[table*7:table*7+7]
            self.assertEqual(row.count(2716),1)
            self.assertEqual(row[consumed],2716)
            for tag in range(7):
                if tag != consumed: self.assertEqual(row[tag],2101 if tag == 6 else 2705)

    def test_constant_identity_size_and_every_byte(self):
        for name,(size,_) in r.CONSTANTS.items():
            raw = bytes(size) if name == r.ROUND else int(name[6:],16).to_bytes(16,'little')
            with patch.dict(r.CONSTANTS,{name:(size,r.digest(raw))}):
                r.constant_check(name,raw)
                for i in range(size):
                    changed = bytearray(raw);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.constant_check(name,changed)
                with self.assertRaises(ValueError): r.constant_check(name,raw[:-1])

    def test_compiler_preconditions_not_standalone_bounds(self):
        a = 'define internal fastcc void @'+r.NEW+'(i16 range(i16 0, 7), i16 range(i16 0, 512)) {\n'
        b = 'define internal fastcc i8 @'+r.FINISH+'(ptr dereferenceable(1174), i64 range(i64 0, 65)) {\n'
        raw = (a+b).encode()
        with patch.object(r.ops.lifecycle,'IR_HASH',r.digest(raw)):
            self.assertFalse(r.ir_preconditions(raw)['standalone_unbounded_call_claimed'])
            with self.assertRaises(ValueError): r.ir_preconditions(raw+b' ')
        for bad in (a,a+a+b,a+b+b,(a+b).replace('internal ',''),(a+b).replace('0, 65','0, 66'),
                    (a+b).replace('0, 7','0, 8'),(a+b).replace('0, 512','0, 513')):
            raw = bad.encode()
            with patch.object(r.ops.lifecycle,'IR_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.ir_preconditions(raw)

    def test_exact_frames_saved_register_and_parent_links(self):
        records = {r.NEW:dict(rva=10736,image_sha256='same',reference_targets={'memset':30064},
                   unwind=[dict(stack_bytes=1304,chain=None,saved_registers=[dict(register_class='xmm',register=6,offset=1216)])]),
                   r.FINISH:dict(rva=14624,image_sha256='same',reference_targets={r.ops.lifecycle.wiping.WIPE:6208},
                   unwind=[dict(stack_bytes=1384,chain=None,saved_registers=[])])}
        parent = dict(image_sha256='same',records={n:dict(reference_targets={r.NEW:10736,r.FINISH:14624})
                      for n in (r.ops.BEGIN,r.ops.REHASH,r.ops.FINISH)})
        r.reconcile(parent,records)
        for name in records:
            for change in ({'rva':1},{'image_sha256':'other'},{'reference_targets':{'unexpected':1}}):
                wrong = copy.deepcopy(records);wrong[name].update(change)
                with self.assertRaises(ValueError): r.reconcile(parent,wrong)
            for change in ({'stack_bytes':16},{'chain':{}},{'saved_registers':[dict(register_class='xmm',register=7,offset=1216)]}):
                wrong = copy.deepcopy(records);wrong[name]['unwind'][0].update(change)
                with self.assertRaises(ValueError): r.reconcile(parent,wrong)

    def test_translated_stack_and_width_mask_arithmetic(self):
        result = r.geometry(r.bounded.Window(0,65536))
        self.assertEqual([p['rsp_from_high'] for p in result['paths'].values()],[-3920,-4064,-5232,-4144])
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.bounded.Window(low,low+65536)))
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['all_by_value_source_copies_individually_erased'])
        for t in range(1,512):
            if t == 384: continue
            n,last,mask = r.shapes.width_model(t)
            self.assertEqual(n,(t+7)//8);self.assertTrue(0 <= last < 64)
            self.assertEqual(mask,255 if t%8 == 0 else (255 << (8-t%8)) & 255)
        for t in (0,384,512,-1,True,1.0):
            with self.assertRaises(ValueError): r.shapes.width_model(t)

    def test_bad_artifact_rejected(self):
        with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
