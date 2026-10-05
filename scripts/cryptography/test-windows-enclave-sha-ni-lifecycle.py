"""SHA-NI saved-code review regressions; not cryptographic/native qualification."""
import copy
import json
import unittest
from unittest.mock import patch

import windows_enclave_sha_ni_lifecycle as r


def code_for(name,pins):
    code = bytearray(pins[name]['bytes']);sites = {}
    for at,raw in r.segments(name):
        for i,b in enumerate(raw,at):
            if i in sites: assert sites[i] == b, 'inconsistent semantic templates'
            sites[i] = b;code[i] = b
    return bytes(code),sites


class Tests(unittest.TestCase):
    def setUp(self):
        self.pins = r.specification(r.SPEC.read_bytes())

    def test_source_bound_complete_population(self):
        self.assertEqual(len(self.pins),8)
        self.assertEqual(sum(v['bytes'] for v in self.pins.values()),1976)
        with self.assertRaises(ValueError): r.specification(r.SPEC.read_bytes()+b' ')
        parsed = json.loads(r.SPEC.read_bytes())
        for field,value in (('schema',2),('route','sha2/mod.rs::open'),('functions',{})):
            raw = json.dumps(parsed | {field:value}).encode()
            with patch.object(r,'SPEC_HASH',r.digest(raw)):
                with self.assertRaises(ValueError): r.specification(raw)

    def test_semantic_mutations_independent_of_hashes(self):
        checked = 0
        for name in r.NAMES:
            code,sites = code_for(name,self.pins);r.instructions(name,code)
            for at in sites:
                bad = bytearray(code);bad[at] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,bad)
                checked += 1
        self.assertGreater(checked,1900)

    def test_complete_body_and_relocation_changes(self):
        for name in r.NAMES:
            code,_ = code_for(name,self.pins)
            refs = [dict(offset=26,symbol='memcpy',trailing=0,addend=0)]
            pin = dict(bytes=len(code),code_sha256=r.digest(code),refs_sha256=r.digest(r.shared.encoded(refs)))
            r.workers.body_check(code,refs,pin)
            for at in range(len(code)):
                bad = bytearray(code);bad[at] ^= 1
                with self.assertRaises(ValueError): r.workers.body_check(bad,refs,pin)
            for bad in (code[:-1],code+b'\0'):
                with self.assertRaises(ValueError): r.workers.body_check(bad,refs,pin)
            for bad in ([],refs*2,[refs[0] | {'symbol':'other'}],[refs[0] | {'addend':1}]):
                with self.assertRaises(ValueError): r.workers.body_check(code,bad,pin)

    def test_exact_full_page_store_loop(self):
        # Decode the fixed byte stores, independently of the generator's range.
        for reg,index in (('rsi',6),('rdi',7)):
            raw = r.page_loop(reg)
            self.assertEqual(raw[:4],bytes((0xc6,4,index,0)))
            offsets = [0]
            for at in range(4,39,5):
                self.assertEqual(raw[at:at+3],bytes((0xc6,0x44,index)))
                self.assertEqual(raw[at+4],0);offsets.append(raw[at+3])
            self.assertEqual(offsets,list(range(8)))
            self.assertEqual(raw[39:],bytes.fromhex('4883c008483d0010000075cd'))
            self.assertEqual(sorted(i+j for i in range(0,4096,8) for j in offsets),list(range(4096)))
        with self.assertRaises(ValueError): r.page_loop('rax')

    def test_sequence_zero_replay_gap_and_wrap(self):
        maximum = (1<<64)-1
        for stored in (*range(256),maximum-1,maximum):
            for requested in (0,1,stored,(stored+1)&maximum,(stored+2)&maximum,maximum):
                self.assertEqual(r.sequence_model(stored,requested),stored < maximum and requested == stored+1)
        for pair in ((True,1),(-1,1),(0,1<<64),(1,1.0)):
            with self.assertRaises(ValueError): r.sequence_model(*pair)

    def test_erased_active_fields_not_padding_or_original_owner(self):
        self.assertEqual(r.erased_regions(False,False),[])
        self.assertEqual(r.erased_regions(False,True),[])
        self.assertEqual(r.erased_regions(True,False),[(816,1170)])
        spans = r.erased_regions(True,True)
        erased = {i for start,size in spans for i in range(start,start+size)}
        self.assertEqual(len(erased),1874)
        self.assertTrue(erased < set(range(2000)))
        self.assertFalse(erased.intersection(range(800,816)))
        self.assertFalse(erased.intersection(range(1986,2000)))
        with self.assertRaises(ValueError): r.erased_regions(1,True)

    def fixture(self):
        def record(address,size):
            return dict(rva=address,image_sha256='same',reference_targets={},
                        unwind=[dict(stack_bytes=size,chain=None,saved_registers=[])])
        records = {n:record(1000+i,self.pins[n]['stack_bytes']) for i,n in enumerate(r.NAMES)}
        anchors = {'RetainedWork':record(100,1208),r.RECEIVE:record(200,168)}
        wipe,clear = record(300,40),record(400,0)
        all_records = {**records,**anchors,r.wiping.WIPE:wipe,r.bounded.CLEAR:clear}
        targets = {n:v['rva'] for n,v in all_records.items()} | {'memcpy':500,r.GUARD_ALIAS:records[r.GUARD]['rva']}
        for rec in all_records.values(): rec['reference_targets'] = targets.copy()
        return records,anchors,wipe,clear,500,self.pins

    def test_binding_wrong_edges_image_and_frames_rejected(self):
        args = self.fixture();r.reconcile(*args)
        for group in (0,1):
            for name,record in args[group].items():
                for symbol in record['reference_targets']:
                    wrong = copy.deepcopy(args);wrong[group][name]['reference_targets'][symbol] += 1
                    with self.assertRaises(ValueError): r.reconcile(*wrong)
                for changes in ({'stack_bytes':16},{'chain':{}},{'saved_registers':[1]}):
                    wrong = copy.deepcopy(args);wrong[group][name]['unwind'][0].update(changes)
                    with self.assertRaises(ValueError): r.reconcile(*wrong)
                wrong = copy.deepcopy(args);wrong[group][name]['image_sha256'] = 'other'
                with self.assertRaises(ValueError): r.reconcile(*wrong)
        for name in (r.QUARANTINE,r.OPERATION,r.CLEAR_OWNER,r.CANCEL,r.GUARD,r.DROP):
            for callee in (r.wiping.WIPE,r.SCRATCH,r.bounded.CLEAR):
                wrong = copy.deepcopy(args);del wrong[0][name]['reference_targets'][callee]
                with self.assertRaises(ValueError): r.reconcile(*wrong)

    def test_frame_spans_preserve_unqualified_depth_and_residuals(self):
        result = r.geometry(r.Window(0,65536))
        self.assertEqual([v['rsp_from_high'] for v in result['paths'].values()],[-3360,-3376,-3536,-3536,-5600])
        for v in result['paths'].values():
            self.assertEqual([s['bytes'] for s in v['spans']],[2000,1170,704])
            self.assertIsNone(v['memory_entry']['callee_frame_bytes'])
        self.assertEqual(result['constructor_rsp_from_high'],-5424)
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['complete_moved_enum_individually_erased'])
        self.assertFalse(result['original_inactive_owner_storage_erased'])
        self.assertTrue(result['outer_window_and_page_teardown_required'])
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.Window(low,low+65536)))


if __name__ == '__main__': unittest.main()
