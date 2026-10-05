"""Offline caller-operation regressions; no native execution is inferred."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_stream_operations as r
import windows_enclave_sha2_stream_operation_shapes as shapes


def code_for(name):
    code = bytearray(r.PINS[name][0]);sites = set()
    def put(at,raw):
        code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
    for at,h in shapes.LANDMARKS[name]: put(at,bytes.fromhex(h))
    for at,stack,phase in shapes.COPY_SITES[name]: put(at,shapes.copy_shape(name,stack,phase))
    for at,h,target in shapes.BRANCHES[name]:
        width = 4 if h == 'e9' else 1
        put(at,bytes.fromhex(h)+(target-at-1-width).to_bytes(width,'little',signed=True))
    return bytes(code),sites


def linked(name,address,start):
    return b''.join((start+dest-address-(i//7)*28).to_bytes(4,'little',signed=True)
                    for i,dest in enumerate(r.TABLES[name][1]))


class Tests(unittest.TestCase):
    def test_full_body_and_reference_mutations(self):
        for name,(size,_,_) in r.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='callee',addend=0,trailing=0)]
            with patch.dict(r.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in ([],refs*2,[refs[0] | {'symbol':'wrong'}],[refs[0] | {'addend':1}],
                                [refs[0] | {'offset':2}],[refs[0] | {'trailing':1}]):
                    with self.assertRaises(ValueError): r.body_check(name,code,changed)

    def test_instruction_and_cleanup_mutations_without_hash_checks(self):
        for name in r.PINS:
            code,sites = code_for(name);shapes.instructions(name,code)
            for at in sites:
                changed = bytearray(code);changed[at] ^= 1
                with self.assertRaises(ValueError): shapes.instructions(name,changed)
        for args in ((r.BEGIN,0,3),(r.BEGIN,32,2),('unknown',32,3)):
            with self.assertRaises(ValueError): shapes.copy_shape(*args)

    def test_all_tables_and_each_byte(self):
        for name in r.TABLES:
            for address,start in ((38000,4000),(200000,100000)):
                raw = linked(name,address,start)
                self.assertEqual(r.table_targets(name,raw,address,start),list(r.TABLES[name][1]))
                for i in range(len(raw)):
                    changed = bytearray(raw);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.table_targets(name,changed,address,start)
                for changed in (raw[:-1],raw+b'\0',raw[4:]+raw[:4]):
                    with self.assertRaises(ValueError): r.table_targets(name,changed,address,start)
                for a,s in ((address+1,start),(address,start+1)):
                    with self.assertRaises(ValueError): r.table_targets(name,raw,a,s)

    def test_rehash_subtables_use_their_own_bases(self):
        address,start = 38428,17376;raw = linked(r.REHASH,address,start)
        # Treating the entire 84-byte section as one table gives wrong destinations.
        wrong = [address+int.from_bytes(raw[i:i+4],'little',signed=True)-start for i in range(0,84,4)]
        self.assertNotEqual(wrong,list(r.TABLES[r.REHASH][1]))
        obj = bytes.fromhex(r.TABLES[r.REHASH][0])
        actual = [int.from_bytes(obj[i:i+4],'little')-(i%28)-4 for i in range(0,84,4)]
        self.assertEqual(actual,list(r.TABLES[r.REHASH][1]))

    def test_readonly_linked_tables_and_mapping(self):
        for name in r.TABLES:
            raw = linked(name,10000,1000);size = len(raw)
            row = dict(rva=10000,virtual_size=size,code=raw,flags=0x40000040)
            self.assertEqual(r.linked_table(name,[row],10000,1000),list(r.TABLES[name][1]))
            for rows in ([],[row,row],[row | {'code':raw[:-1]}],[row | {'virtual_size':size-1}],
                         [row | {'flags':0xc0000040}],[row | {'flags':0x60000040}],
                         [row,row | {'rva':10010,'virtual_size':1}]):
                with self.assertRaises(ValueError): r.linked_table(name,rows,10000,1000)

    def test_actual_entry_admission_wipe_and_frame_binding(self):
        records = {n:dict(rva=i,image_sha256='same',reference_targets=r.TARGETS.copy(),
                         unwind=[dict(stack_bytes=r.FRAMES[n],chain=None,saved_registers=[])])
                   for i,n in enumerate(r.PINS,100)}
        parent = dict(image_sha256='same',records={r.lifecycle.OPERATION:dict(rva=10464)},workspace_wipe=dict(rva=6208))
        receiver = dict(reference_targets={n:v['rva'] for n,v in records.items()})
        r.reconcile(parent,receiver,records)
        for name in records:
            wrong = copy.deepcopy(records);wrong[name]['rva'] += 1
            with self.assertRaises(ValueError): r.reconcile(parent,receiver,wrong)
            wrong = copy.deepcopy(records);wrong[name]['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.reconcile(parent,receiver,wrong)
            for symbol in r.TARGETS:
                wrong = copy.deepcopy(records);wrong[name]['reference_targets'][symbol] += 1
                with self.assertRaises(ValueError): r.reconcile(parent,receiver,wrong)
            for change in ({'stack_bytes':16},{'chain':{}},{'saved_registers':[1]}):
                wrong = copy.deepcopy(records);wrong[name]['unwind'][0].update(change)
                with self.assertRaises(ValueError): r.reconcile(parent,receiver,wrong)
            wrong = copy.deepcopy(records);wrong[name]['reference_targets']['unexpected'] = 1
            with self.assertRaises(ValueError): r.reconcile(parent,receiver,wrong)

    def test_stack_geometry_and_honest_scope(self):
        result = r.geometry(r.bounded.Window(0,65536))
        self.assertEqual([v['rsp_from_high'] for v in result['operations'].values()],[-2608,-2624,-3840,-2752,-2624])
        self.assertEqual([v['admission_rsp_from_high'] for v in result['operations'].values()],[-3840,-3856,-5072,-3984,-3856])
        for low in (4096,0x700000000000):
            self.assertEqual(result,r.geometry(r.bounded.Window(low,low+65536)))
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertTrue(result['inactive_owner_bytes_require_page_teardown'])
        self.assertTrue(result['stack_copies_require_outer_window_cleanup'])
        for row in result['operations'].values(): self.assertIsNone(row['callee_entry']['callee_frame_bytes'])

    def test_rejects_wrong_artifact_before_inspection(self):
        with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
