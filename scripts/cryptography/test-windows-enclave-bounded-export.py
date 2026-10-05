"""Offline export/cross-copy regressions, not a new native enclave campaign."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_export as r


class Tests(unittest.TestCase):
    def test_complete_body_reference_pins(self):
        for name,(rva,size,_,_) in r.SPECS.items():
            code = bytes(size);refs = [dict(offset=2,symbol='active',trailing=0,addend=0)]
            with patch.dict(r.SPECS,{name:(rva,size,r.digest(code),r.digest(r.shared.encoded(refs)))}):
                r.check_body(name,code,refs)
                for i in range(size):
                    changed = bytearray(code);changed[i] ^= 1
                    with self.assertRaises(ValueError): r.check_body(name,changed,refs)
                for changed in ([],refs*2,[refs[0] | {'addend':8}],[refs[0] | {'symbol':'other'}]):
                    with self.assertRaises(ValueError): r.check_body(name,code,changed)
                for changed in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): r.check_body(name,changed,refs)

    def test_admission_token_readout_tail_and_failure_paths(self):
        for name,(_,size,_,_) in r.SPECS.items():
            code = bytearray(size);sites = set()
            for at,h in r.LANDMARKS[name]:
                raw = bytes.fromhex(h);code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
            if name == 'PublicCrossCopy':
                for at,h,target in r.BRANCHES:
                    op = bytes.fromhex(h);width = 4 if len(op) == 2 else 1
                    raw = op+(target-at-len(op)-width).to_bytes(width,'little',signed=True)
                    code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)))
                at = 0x86
                for i in range(4):
                    load = bytes.fromhex('488b0b') if i == 0 else bytes.fromhex('488b4b')+bytes([8*i])
                    raw = load+bytes.fromhex('48890d')+(16+8*i).to_bytes(4,'little')
                    code[at:at+len(raw)] = raw;sites.update(range(at,at+len(raw)));at += len(raw)
            r.instructions(name,code)
            for i in sites:
                changed = code.copy();changed[i] ^= 1
                with self.assertRaises(ValueError): r.instructions(name,changed)

    def test_rel32_reconstruction_keeps_addends_and_trailing_immediates(self):
        code = bytes(range(20))
        refs = [dict(offset=2,symbol='a',addend=8,trailing=1),dict(offset=12,symbol='b',addend=16,trailing=4)]
        result = r.linked_bytes(code,refs,100,dict(a=500,b=50))
        self.assertEqual(int.from_bytes(result[2:6],'little',signed=True),401)
        self.assertEqual(int.from_bytes(result[12:16],'little',signed=True),-54)
        self.assertEqual(result[:2]+result[6:12]+result[16:],code[:2]+code[6:12]+code[16:])
        for targets in (dict(a=500),dict(a=1<<40,b=50)):
            with self.assertRaises(ValueError): r.linked_bytes(code,refs,100,targets)
        for offset in (-1,17):
            with self.assertRaises(ValueError): r.linked_bytes(code,[refs[0] | {'offset':offset}],100,dict(a=500))

    def test_exact_linked_bytes_mapping_and_no_unwind_leaf(self):
        raw = bytes(range(60));row = dict(rva=100,code=raw,virtual_size=60,flags=0x60000020)
        r.mapped_code([row],[],110,raw[10:40],True)
        for i in range(30):
            changed = bytearray(raw);changed[10+i] ^= 1
            with self.assertRaises(ValueError): r.mapped_code([row | {'code':bytes(changed)}],[],110,raw[10:40],True)
        for rows in ([],[row,row],[row | {'flags':0xe0000020}],[row | {'virtual_size':39}],
                     [row | {'code':raw[:39]}]):
            with self.assertRaises(ValueError): r.mapped_code(rows,[],110,raw[10:40],True)
        for extent in ((109,111,0),(139,141,0),(110,140,0)):
            with self.assertRaises(ValueError): r.mapped_code([row],[extent],110,raw[10:40],True)

    def test_dispatcher_and_callback_global_identity(self):
        targets = r.TARGETS.copy()
        worker = dict(image_sha256='same',reference_targets=targets | {
            'PublicCrossCopy':r.SPECS['PublicCrossCopy'][0],'PublicRetainedCopy':r.SPECS['PublicRetainedCopy'][0]})
        common = dict(image_sha256='same',reference_targets=targets.copy())
        parent = dict(records={'callback':dict(image_sha256='same',reference_targets=targets.copy())})
        r.reconcile(parent,common,worker)
        for name in ('PublicCrossCopy','PublicRetainedCopy',r.TOKEN):
            wrong = copy.deepcopy(worker);wrong['reference_targets'][name] += 1
            with self.assertRaises(ValueError): r.reconcile(parent,common,wrong)
        for name in targets:
            wrong = copy.deepcopy(common);wrong['reference_targets'][name] += 1
            with self.assertRaises(ValueError): r.reconcile(parent,wrong,worker)
            wrong = copy.deepcopy(parent);wrong['records']['callback']['reference_targets'][name] += 1
            with self.assertRaises(ValueError): r.reconcile(wrong,common,worker)
        for place in ('worker','parent'):
            w,p = copy.deepcopy(worker),copy.deepcopy(parent)
            (w if place == 'worker' else p['records']['callback'])['image_sha256'] = 'other'
            with self.assertRaises(ValueError): r.reconcile(p,common,w)

    def test_metadata_spans_complete_nonexecutable_and_separate(self):
        row = dict(rva=40000,virtual_size=5000,flags=0xc0000040)
        self.assertEqual(len(r.metadata([row])),12)
        for rows in ([],[row,row],[row | {'flags':0xe0000040}],[row | {'flags':0x40000040}],
                     [row | {'virtual_size':1000}]):
            with self.assertRaises(ValueError): r.metadata(rows)
        with patch.dict(r.TARGETS,{'retained_output':r.TARGETS['retained_operation']}):
            with self.assertRaises(ValueError): r.metadata([row])

    def test_tail_geometry_retains_limits(self):
        result = r.geometry(r.dispatch.Window(0,65536))
        self.assertEqual(result['cross_rsp_from_high'],-512)
        self.assertEqual(result['inbound_rsp_from_high'],-560)
        self.assertEqual(result['outbound_rsp_from_high'],-512)
        self.assertTrue(result['output_adapter_is_tail_transfer'])
        for key in ('exported_host_controls_inside_window_claimed','maximum_transitive_depth_qualified','kernel_storage_qualified'):
            self.assertFalse(result[key])
        for low in (4096,0x700000000000): self.assertEqual(result,r.geometry(r.dispatch.Window(low,low+65536)))


if __name__ == '__main__': unittest.main()
