"""Saved-dispatch inspection regressions, not fresh cryptographic execution."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_bounded_dispatch as review


class Tests(unittest.TestCase):
    def test_table_mapping_symbol_and_protection_checks(self):
        table = dict(name=b'.rdata',flags=0x40000040,code=review.TABLE)
        symbols = {1:dict(value=0,section=1),2:dict(value=0,section=2,name='.text')}
        refs = [dict(offset=486,symbol='.rdata',symbol_index=1,addend=0,trailing=0)]
        relocs = {i:dict(kind=4,symbol=2) for i in range(0,40,4)}
        mapped = dict(rva=0x2000,virtual_size=40,code=bytes(40),flags=0x40000040)
        record = dict(rva=0x1000,reference_targets={'.rdata':0x2000})
        raw = b''.join((0x1000+d-0x2000).to_bytes(4,'little',signed=True) for d in review.DESTINATIONS)
        def run(t=table,s=symbols,r=refs,rel=relocs,m=mapped):
            with patch.object(review.obj,'select',return_value=([t],s,{'section':2},b'',r)), \
                 patch.object(review.obj,'relocations',return_value=rel), \
                 patch.object(review.shared.caller.pe,'linked',return_value=([m],[])), \
                 patch.object(review.mapping,'mapped',return_value=raw):
                return review.jump_table(b'',b'',record)
        self.assertEqual(run()['operation_offsets'],list(review.DESTINATIONS))
        for wrong in (table | {'flags':0xc0000040},table | {'code':review.TABLE[:-1]},table | {'name':b'.text'}):
            with self.assertRaises(ValueError): run(t=wrong)
        for wrong in ([],refs+refs,[refs[0] | {'addend':1}],[refs[0] | {'trailing':1}]):
            with self.assertRaises(ValueError): run(r=wrong)
        for wrong in ({},relocs | {0:dict(kind=3,symbol=2)}):
            with self.assertRaises(ValueError): run(rel=wrong)
        for key,value in (('value',1),('section',1),('name','other')):
            changed = copy.deepcopy(symbols);changed[2][key] = value
            with self.assertRaises(ValueError): run(s=changed)
        for wrong in (mapped | {'flags':0xc0000040},mapped | {'virtual_size':39}):
            with self.assertRaises(ValueError): run(m=wrong)

    def test_exact_jump_destinations_and_all_table_bytes(self):
        for entry,table in ((0x1020,0x8204),(0x100000,0x200000)):
            raw = b''.join((entry+d-table).to_bytes(4,'little',signed=True) for d in review.DESTINATIONS)
            self.assertEqual(review.table_destinations(raw,table,entry),list(review.DESTINATIONS))
            for index in range(40):
                changed = bytearray(raw); changed[index] ^= 1
                with self.assertRaises(ValueError): review.table_destinations(changed,table,entry)
            for wrong in (raw[:-1],raw+b'\0',raw[::-1]):
                with self.assertRaises(ValueError): review.table_destinations(wrong,table,entry)
            with self.assertRaises(ValueError): review.table_destinations(raw,table+1,entry)
            with self.assertRaises(ValueError): review.table_destinations(raw,table,entry+1)

    def test_object_table_relocation_addends(self):
        self.assertEqual([int.from_bytes(review.TABLE[i:i+4],'little')-i-4
                          for i in range(0,40,4)],list(review.DESTINATIONS))
        # Operation three is handled before the table; its spare table slot
        # points to the epilogue, not to an invented disposal label.
        self.assertEqual(review.DESTINATIONS[2],0x509)

    def test_instruction_and_branch_mutations(self):
        code = bytearray(1603); sites = set()
        for offset,hexcode in review.LANDMARKS:
            raw = bytes.fromhex(hexcode);code[offset:offset+len(raw)] = raw
            sites.update(range(offset,offset+len(raw)))
        for offset,opcode,target in review.BRANCHES:
            width = 4 if len(opcode) == 2 else 1
            raw = opcode+(target-offset-len(opcode)-width).to_bytes(width,'little',signed=True)
            code[offset:offset+len(raw)] = raw;sites.update(range(offset,offset+len(raw)))
        review.instructions(code)
        for index in sites:
            changed = bytearray(code);changed[index] ^= 1
            with self.assertRaises(ValueError): review.instructions(changed)
        with self.assertRaises(ValueError): review.instructions(code[:100])

    def test_complete_bodies_and_relocation_fields(self):
        code,clear = bytes(1603),bytes(105)
        refs = [dict(offset=10,symbol='clear',addend=0,trailing=0)]
        with patch.object(review,'BODY_HASH',review.digest(code)), \
             patch.object(review,'CLEAR_HASH',review.digest(clear)), \
             patch.object(review,'REF_HASH',review.digest(review.shared.encoded(refs))):
            review.bodies_check(code,refs,clear,[])
            for which,original in enumerate((code,clear)):
                for index in range(len(original)):
                    changed = bytearray(original);changed[index] ^= 1
                    with self.assertRaises(ValueError):
                        review.bodies_check(changed if which == 0 else code,refs,changed if which else clear,[])
            for key,value in (('offset',11),('symbol','other'),('addend',1),('trailing',1)):
                changed = copy.deepcopy(refs);changed[0][key] = value
                with self.assertRaises(ValueError): review.bodies_check(code,changed,clear,[])
            with self.assertRaises(ValueError): review.bodies_check(code,[],clear,[])
            with self.assertRaises(ValueError): review.bodies_check(code,refs,clear,refs)
            with self.assertRaises(ValueError): review.bodies_check(code[:-1],refs,clear,[])
            with self.assertRaises(ValueError): review.bodies_check(code,refs,clear+b'\0',[])

    def test_stack_copies_in_wrapper_window_not_individually_erased(self):
        baseline = review.geometry(review.Window(0,65536))
        self.assertEqual(baseline['worker_rsp_from_high'],-464)
        self.assertFalse(baseline['individual_stack_copies_erased'])
        self.assertFalse(baseline['maximum_transitive_depth_qualified'])
        self.assertIsNone(baseline['unknown_callee']['callee_frame_bytes'])
        for low in (4096,0x700000000000):
            self.assertEqual(review.geometry(review.Window(low,low+65536)),baseline)


if __name__ == '__main__': unittest.main()
