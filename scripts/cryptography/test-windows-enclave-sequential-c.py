"""Offline cross-image reconciliation regressions; no enclave execution."""
import copy
import unittest
from unittest.mock import patch

import windows_enclave_sequential_c as review


class Tests(unittest.TestCase):
    def test_instruction_and_branch_landmarks(self):
        bodies = {n:bytearray(s[0]) for n,s in review.BODIES.items()}
        sites = []
        for name,offset,hexcode in review.LANDMARKS:
            code = bytes.fromhex(hexcode); bodies[name][offset:offset+len(code)] = code
            sites += [(name,index) for index in range(offset,offset+len(code))]
        for name,offset,opcode,target in review.BRANCHES:
            bodies[name][offset:offset+2] = bytes([opcode])+int(target-offset-2).to_bytes(1,'little',signed=True)
            sites += [(name,offset),(name,offset+1)]
        review.check_instructions(bodies)
        for name,index in sites:
            changed = bytearray(bodies[name]); changed[index] ^= 1
            with self.assertRaises(ValueError): review.check_instructions(bodies | {name:changed})
        with self.assertRaises(ValueError): review.check_instructions({})

    def fixture(self):
        wrap = dict(image_sha256='image',global_target_rvas={'PublicLockedLow':100},
                    call_target_rvas={n:1000+i*2000 for i,n in enumerate(review.BODIES)})
        records = {n:dict(image_sha256='image',rva=wrap['call_target_rvas'][n],size=s[0],
                          references=[{}]*s[1],reference_targets={'PublicLockedLow':100,
                          '__imp_CallEnclave':200,'RetainedWork':9000}) for n,s in review.BODIES.items()}
        return records,wrap,{'CallEnclave':200}

    def test_complete_population_and_wrapper_entry_identity(self):
        records,wrap,imports = self.fixture()
        review.reconcile(records,wrap,imports)
        for name in records:
            changed = copy.deepcopy(records); del changed[name]
            with self.assertRaises(ValueError): review.reconcile(changed,wrap,imports)
            for key,value in (('image_sha256','other'),('rva',0),('size',37),('references',[{}]*3)):
                changed = copy.deepcopy(records); changed[name][key] = value
                with self.assertRaises(ValueError): review.reconcile(changed,wrap,imports)
        with self.assertRaises(ValueError): review.reconcile(records | {'extra':{}},wrap,imports)

    def test_shared_globals_helpers_and_named_imports(self):
        records,wrap,imports = self.fixture()
        for name in records:
            for symbol in records[name]['reference_targets']:
                changed = copy.deepcopy(records); changed[name]['reference_targets'][symbol] += 1
                with self.assertRaises(ValueError): review.reconcile(changed,wrap,imports)
        for wrong in ({},{'CallEnclave':201},{'OtherImport':200}):
            with self.assertRaises(ValueError): review.reconcile(records,wrap,wrong)
        changed = copy.deepcopy(records)
        for r in changed.values(): r['reference_targets']['__imp_Unexpected'] = 200
        with self.assertRaises(ValueError): review.reconcile(changed,wrap,imports)

    def test_distinct_worker_targets_do_not_require_cross_image_equivalence(self):
        records,wrap,imports = self.fixture()
        first = review.reconcile(records,wrap,imports)
        for r in records.values(): r['reference_targets']['RetainedWork'] = 19000
        second = review.reconcile(records,wrap,imports)
        self.assertNotEqual(first['RetainedWork'],second['RetainedWork'])

    def test_body_byte_length_and_complete_reference_mutations(self):
        for name,(size,count,_,_) in review.BODIES.items():
            code = bytes(size)
            refs = [dict(offset=i*4,symbol='target',trailing=0,addend=0) for i in range(count)]
            spec = (size,count,review.digest(code),review.digest(review.encoded(refs)))
            with patch.dict(review.BODIES,{name:spec}):
                review.check_body(name,code,refs)
                for index in range(size):
                    changed = bytearray(code); changed[index] ^= 1
                    with self.assertRaises(ValueError): review.check_body(name,changed,refs)
                for wrong in (code[:-1],code+b'\0'):
                    with self.assertRaises(ValueError): review.check_body(name,wrong,refs)
                for wrong in (refs[:-1],refs+refs[:1]):
                    with self.assertRaises(ValueError): review.check_body(name,code,wrong)
                for key,value in (('offset',1),('symbol','other'),('trailing',1),('addend',1)):
                    changed = copy.deepcopy(refs); changed[-1][key] = value
                    with self.assertRaises(ValueError): review.check_body(name,code,changed)

    def test_exact_saved_catalog_and_population(self):
        raw = review.CATALOG.read_bytes()
        rows = review.catalog(raw)
        self.assertEqual(len(rows),18)
        for field in ('route','sha256','object','object_sha256','image'):
            changed = copy.deepcopy(rows); changed[-1][field] += 'different'
            with self.assertRaises(ValueError): review.catalog(review.encoded(changed))
        for wrong in (rows[:-1],rows+rows[:1],rows[:-1]+rows[:1]):
            encoded = review.encoded(wrong)
            with patch.object(review,'CATALOG_SHA256',review.digest(encoded)):
                with self.assertRaises(ValueError): review.catalog(encoded)


if __name__ == '__main__': unittest.main()
