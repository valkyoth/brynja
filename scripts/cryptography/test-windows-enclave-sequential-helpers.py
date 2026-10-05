"""Offline helper inspection regressions; no native enclave or SDK claims."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sequential_helpers as review


class Tests(unittest.TestCase):
    def test_selected_local_frames_stay_inside_window(self):
        baseline = review.geometry(review.Window(0,65536))
        self.assertEqual(baseline['frames']['public_marker']['rsp_from_high'],-480)
        self.assertEqual(baseline['frames']['retained_page']['rsp_from_high'],-240)
        self.assertEqual(baseline['frames']['body']['rsp_from_high'],-96)
        self.assertFalse(baseline['maximum_transitive_depth_qualified'])
        self.assertFalse(baseline['pre_post_window_callback_frames_included'])
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.Window(low,low+65536)),baseline)
        for span in baseline['unknown_callees']:
            self.assertIsNone(span['callee_frame_bytes'])
            self.assertFalse(span['callee_spills_qualified'])

    def fixture(self):
        targets = {n:1000+i*1000 for i,n in enumerate(review.SPECS)}
        parent = dict(image_sha256='image',reference_targets=targets | {'retained_region':100})
        records = {n:dict(image_sha256='image',rva=targets[n],size=s[0],
                         reference_targets={'retained_region':100,'__imp_VirtualQuery':200},
                         handler=dict(symbol=review.HANDLERS[n]) if n in review.HANDLERS else None)
                   for n,s in review.SPECS.items()}
        records['retained_guards']['reference_targets']['retained_page'] = targets['retained_page']
        return parent,records,{'VirtualQuery':200}

    def test_parent_extent_image_and_population(self):
        parent,records,imports = self.fixture()
        review.reconcile(parent,records,imports)
        for name in records:
            for key,value in (('image_sha256','other'),('rva',0),('size',1)):
                changed = copy.deepcopy(records); changed[name][key] = value
                with self.assertRaises(ValueError): review.reconcile(parent,changed,imports)
            changed = copy.deepcopy(records); del changed[name]
            with self.assertRaises(ValueError): review.reconcile(parent,changed,imports)
        with self.assertRaises(ValueError): review.reconcile(parent,records | {'other':{}},imports)

    def test_helper_global_and_import_identity(self):
        parent,records,imports = self.fixture()
        for name,r in records.items():
            for symbol in r['reference_targets']:
                changed = copy.deepcopy(records); changed[name]['reference_targets'][symbol] += 1
                with self.assertRaises(ValueError): review.reconcile(parent,changed,imports)
        for wrong in ({},{'Other':200},{'VirtualQuery':201}):
            with self.assertRaises(ValueError): review.reconcile(parent,records,wrong)

    def test_handler_identity_is_not_optional(self):
        parent,records,imports = self.fixture()
        for name in review.HANDLERS:
            for wrong in (None,{'symbol':'unreviewed_handler'}):
                changed = copy.deepcopy(records); changed[name]['handler'] = wrong
                with self.assertRaises(ValueError): review.reconcile(parent,changed,imports)

    def test_complete_body_and_reference_pins(self):
        for name,(size,count,_,_) in review.SPECS.items():
            code = bytes(size)
            refs = [dict(offset=i*4,symbol='target',trailing=0,addend=0) for i in range(count)]
            spec = (size,count,review.digest(code),review.digest(review.shared.encoded(refs)))
            with patch.dict(review.SPECS,{name:spec}):
                review.check_template(name,code,refs)
                for index in range(size):
                    changed = bytearray(code); changed[index] ^= 1
                    with self.assertRaises(ValueError): review.check_template(name,changed,refs)
                for wrong in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.check_template(name,wrong,refs)
                for wrong in (refs[:-1],refs+refs[:1]):
                    with self.assertRaises(ValueError): review.check_template(name,code,wrong)
                for key,value in (('offset',1),('symbol','other'),('trailing',1),('addend',1)):
                    changed = copy.deepcopy(refs); changed[0][key] = value
                    with self.assertRaises(ValueError): review.check_template(name,code,changed)

    def test_instruction_and_branch_changes(self):
        bodies = {n:bytearray(s[0]) for n,s in review.SPECS.items()}
        sites = []
        for name,offset,hexcode in review.LANDMARKS:
            code = bytes.fromhex(hexcode); bodies[name][offset:offset+len(code)] = code
            sites += [(name,i) for i in range(offset,offset+len(code))]
        for name,offset,opcode,target in review.BRANCHES:
            bodies[name][offset:offset+2] = bytes([opcode])+(target-offset-2).to_bytes(1,'little',signed=True)
            sites += [(name,offset),(name,offset+1)]
        review.instructions(bodies)
        for name,index in sites:
            changed = bytearray(bodies[name]); changed[index] ^= 1
            with self.assertRaises(ValueError): review.instructions(bodies | {name:changed})
        with self.assertRaises(ValueError): review.instructions({})


if __name__ == '__main__': unittest.main()
