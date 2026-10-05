"""Offline primitive binding regressions; no enclave or private artifacts needed."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sha2_primitives as r

s = r.shapes


class Tests(unittest.TestCase):
    def test_complete_bodies_and_reference_mutations(self):
        for name,(size,_,_) in s.PINS.items():
            code = bytes(size);refs = [dict(offset=1,symbol='callee',addend=0,trailing=0)]
            with patch.dict(s.PINS,{name:(size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.body_check(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.body_check(name,changed,refs)
                for delta in ({'symbol':'other'},{'offset':2},{'addend':1},{'trailing':1}):
                    with self.assertRaises(ValueError): r.body_check(name,code,[refs[0] | delta])
                for changed in ([],refs*2):
                    with self.assertRaises(ValueError): r.body_check(name,code,changed)

    def test_reused_helpers_require_exact_references_not_just_code(self):
        for name in (s.U32,s.COPY,s.BYTES): self.assertEqual(s.PINS[name],s.old.PINS[name])
        self.assertEqual(s.PINS[s.S32][:2],s.old.PINS[s.S32][:2])
        self.assertNotEqual(s.PINS[s.S32][2],s.old.PINS[s.S32][2])
        self.assertNotEqual(s.ROUND32,s.old.TABLE)

    def test_landmark_mutations_without_hash_dependency(self):
        for name,landmarks in s.LANDMARKS.items():
            if name in (s.F32,s.F64): continue  # Full renderer coverage below.
            code = bytearray(s.PINS[name][0]);sites = set()
            for at,h in landmarks:
                raw = bytes.fromhex(h);code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
            s.instructions(name,code)
            for i in sites:
                changed = code.copy();changed[i] ^= 1
                with self.assertRaises(ValueError): s.instructions(name,changed)

    def test_render_all_words_and_final_landmarks(self):
        for name,width,start,first in (
            (s.F32,4,384,'488d8e40040000ba0400000041b9040000004989d8e800000000'),
            (s.F64,8,406,'488dbe40040000ba0800000041b9080000004889f94d89f0e800000000')):
            code = bytearray(s.PINS[name][0]);sites = set()
            for at,h in s.LANDMARKS[name]:
                raw = bytes.fromhex(h);code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
            raw = bytes.fromhex(first);code[start-len(raw):start] = raw
            for i in range(1,8):
                raw = (b'\x4c\x8d\x86'+(1024+width*i).to_bytes(4,'little')+
                       b'\x48\x8d\x8e'+(1088+width*i).to_bytes(4,'little')+
                       b'\xba'+width.to_bytes(4,'little')+b'\x41\xb9'+width.to_bytes(4,'little')+b'\xe8'+bytes(4))
                code[start+(i-1)*30:start+i*30] = raw
            sites.update(range(start-len(bytes.fromhex(first)),start+210))
            s.instructions(name,code)
            self.assertEqual(sum(p['bytes'] for p in s.render_plan(name,code)),8*width)
            for i in sites:
                changed = code.copy();changed[i] ^= 1
                with self.assertRaises(ValueError): s.instructions(name,changed)

    def test_round_table_sizes_and_mutations(self):
        for name,(size,_) in r.CONSTANTS.items():
            raw = bytes(size)
            with patch.dict(r.CONSTANTS,{name:(size,r.digest(raw))}):
                r.constant_check(name,raw)
                for i in range(size):
                    changed = bytearray(raw);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.constant_check(name,changed)
                for changed in (raw[:-1],raw+b'\0'):
                    with self.assertRaises(ValueError): r.constant_check(name,changed)

    def test_complete_inventory_edges_frames_and_image(self):
        targets = {n:10000+1000*i for i,n in enumerate(s.PINS)} | r.EXTERNAL | {s.ROUND32:40000,s.ROUND64:41000}
        records = {n:dict(rva=targets[n],image_sha256='same',reference_targets={e:targets[e] for e in r.EDGES[n]}) for n in s.PINS}
        for n,frame in s.FRAMES.items(): records[n]['unwind'] = [dict(stack_bytes=frame,chain=None,saved_registers=[])]
        anchors = {n:dict(image_sha256='same',reference_targets={e:targets[e] for e in s.PINS})
                   for n in (r.state.NEW,r.state.FINISH,r.ops.UPDATE,r.ops.FINISH,r.ops.REHASH)}
        tables = {n:dict(rva=targets[n]) for n in r.CONSTANTS}
        r.reconcile(records,anchors,tables,'same')
        for n in records:
            for change in ({'image_sha256':'other'},{'rva':1},{'reference_targets':{'unknown':1}}):
                wrong = copy.deepcopy(records);wrong[n].update(change)
                with self.assertRaises(ValueError): r.reconcile(wrong,anchors,tables,'same')
            wrong = copy.deepcopy(records);del wrong[n]
            with self.assertRaises(ValueError): r.reconcile(wrong,anchors,tables,'same')
        for n in s.FRAMES:
            for change in ({'stack_bytes':0},{'chain':{}},{'saved_registers':[{}]}):
                wrong = copy.deepcopy(records);wrong[n]['unwind'][0].update(change)
                with self.assertRaises(ValueError): r.reconcile(wrong,anchors,tables,'same')
        for n in tables:
            wrong = copy.deepcopy(tables);wrong[n]['rva'] += 1
            with self.assertRaises(ValueError): r.reconcile(records,anchors,wrong,'same')

    def test_every_buffer_and_partial_bit_padding_boundary(self):
        for word,widths in ((32,(28,32)),(64,range(1,65))):
            for used in range(word*2):
                for bits in range(8):
                    for width in widths:
                        result = s.final_contract(word,used,bits,width)
                        self.assertEqual(result['blocks'],(used+1+word//4+word*2-1)//(word*2))
                        self.assertEqual(result['padding_bit'],1 << (7-bits))
                        self.assertEqual(result['zero_tail_bytes'],64-width)
            for used,bits,width in ((-1,0,32),(word*2,0,32),(0,8,32),(0,-1,32),(0,0,65),(0,0,0),(True,0,32)):
                with self.assertRaises(ValueError): s.final_contract(word,used,bits,width)
        with self.assertRaises(ValueError): s.final_contract(32,0,0,31)

    def test_selected_stack_geometry_is_translation_invariant(self):
        result = r.geometry(r.bounded.Window(0,65536))
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.bounded.Window(low,low+65536)))
        self.assertEqual(result['deepest_selected_caller_rsp_from_high'],-5232)
        self.assertEqual(result['deepest_selected_leaf_rsp_from_high'],-5416)
        self.assertFalse(result['maximum_transitive_depth_qualified'])
        self.assertFalse(result['individual_caller_spills_erased'])
        self.assertIsNone(result['runtime_entry']['callee_frame_bytes'])

    def test_bad_artifact_rejected(self):
        with self.assertRaises(ValueError): r.inspect(b'bad',b'bad',b'bad',b'bad',b'bad')


if __name__ == '__main__': unittest.main()
