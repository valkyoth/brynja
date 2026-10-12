"""Staging lifetime/order/error regression tests for the separate 08A canary."""
import argparse
import copy
import json
from pathlib import Path
import unittest

import windows_enclave_resident_lock as lock
import windows_enclave_resident_probe as probe
import windows_enclave_resident_review as review
from windows_protection_probe import ProbeError

BASE, PAGE = 0x10000000, 0x10020000
LOCKED = 1 | (1 << 22)


class Host:
    def __init__(self): self.locks = set()
    def working_set(self,address,shape):
        return [LOCKED if address in self.locks else 1]*(shape.payload//4096)
    def lock(self,address,size):
        if address in self.locks: raise AssertionError('double lock')
        self.locks.add(address)
    def unlock(self,address,size):
        if address not in self.locks: raise AssertionError('unowned unlock')
        self.locks.remove(address)


def sample():
    rows = []
    for name,_,status,body in probe.cases():
        events,names = probe.expected_events(name,body)
        trace = ['admit','lock','all-pages-locked','admit-ack','clear-confirmed',
                 'still-locked','unlock','finish-ack'] if body else (
                 ['admit','deny','clear-confirmed','finish-ack'] if name == 'deny' else [])
        rows.append(dict(case=name,status=status,
            observations=[body,int(status==1),status,1,4096*bool(events),int(bool(events))],
            events=events,snapshots={n:[1 if n=='before' else LOCKED] for n in names},
            window_trace=trace,reentry=[0,0,0] if name=='reentry' else []))
    return rows


class Tests(unittest.TestCase):
    def test_complete_campaign_and_all_observations(self):
        rows = sample()
        probe.validate(rows)
        for i in range(len(rows)):
            for field in range(6):
                mutant = copy.deepcopy(rows)
                mutant[i]['observations'][field] ^= 1
                with self.assertRaises(ProbeError): probe.validate(mutant)

    def test_missing_reordered_and_repeated_campaigns_reject(self):
        rows = sample()
        for mutant in [[],rows[:-1],rows[::-1],rows+[rows[0]],[rows[0]]*len(rows)]:
            with self.assertRaises(ProbeError): probe.validate(mutant)

    def test_unlocked_incomplete_or_early_retirement_rejects(self):
        for field,value in [('events',['stage-unlock','stage-clear-confirmed']),
                            ('snapshots',{}),('reentry',[1])]:
            rows = sample()
            rows[0][field] = value
            with self.assertRaises(ProbeError): probe.validate(rows)
        for value in [[],[0],[1],[True],[LOCKED,LOCKED]]:
            rows = sample()
            rows[0]['snapshots']['staged'] = value
            with self.assertRaises(ProbeError): probe.validate(rows)

    def test_lock_lifetime_through_staged_observation_and_clear(self):
        host = Host()
        resident = lock.Resident(host,BASE)
        self.assertEqual(resident(PAGE|8),1)
        self.assertEqual(resident(PAGE|9),1)
        self.assertEqual(host.locks,{PAGE})
        self.assertEqual(resident(PAGE|10),1)
        self.assertEqual(host.locks,set())
        self.assertEqual(resident.phase,'finished')

    def test_denial_and_post_lock_failure_preserve_retirement(self):
        for fault,point in [('deny-stage',8),('after-stage-lock',8),('stage-observe',9)]:
            host = Host()
            resident = lock.Resident(host,BASE,fault)
            if point==9: self.assertEqual(resident(PAGE|8),1)
            self.assertEqual(resident(PAGE|point),0)
            self.assertEqual(resident(PAGE|10),1)
            self.assertFalse(host.locks)
            self.assertIsNone(resident.error)

    def test_no_release_of_another_owners_lock(self):
        host = Host()
        host.lock(PAGE,4096)
        resident = lock.Resident(host,BASE)
        self.assertEqual(resident(PAGE|8),0)
        self.assertIsNotNone(resident.error)
        self.assertEqual(host.locks,{PAGE})

    def test_stale_duplicate_and_wrong_phase_events(self):
        for commands in [[PAGE|9],[PAGE|10],[PAGE|8,PAGE|8],
                         [PAGE|8,(PAGE+4096)|10], [PAGE|8,PAGE|10,PAGE|10],
                         [PAGE|8,PAGE|0],[(PAGE+16)|8],[BASE|8],[(BASE+lock.LIMIT)|8]]:
            resident = lock.Resident(Host(),BASE)
            for command in commands: result=resident(command)
            self.assertEqual(result,0)
            self.assertIsNotNone(resident.error)

    def test_overlap_with_stack_rejects(self):
        resident = lock.Resident(Host(),BASE)
        self.assertEqual(resident(PAGE|8),1)
        self.assertEqual(resident(PAGE|9),1)
        self.assertEqual(resident((PAGE-4096)|0),0)
        self.assertIsNotNone(resident.error)
        self.assertTrue(resident.locked)


class SavedTests(unittest.TestCase):
    directory = None
    @classmethod
    def setUpClass(cls):
        cls.image = (cls.directory/'signed.dll').read_bytes()
        cls.text = (cls.directory/'disassembly.txt').read_text()
        cls.record = review.inspect(cls.directory,cls.text)

    def test_actual_graph_and_cleanup(self):
        self.assertEqual(self.record['direct_sites'],56)
        self.assertEqual(self.record['indirect_sites'],0)
        self.assertEqual(len(self.record['closure']['functions']),10)
        self.assertTrue(self.record['closure']['sdk_free_call_graph'])
        self.assertFalse(self.record['completion_package_closed'])
        self.assertFalse(self.record['transport_payload_handling_qualified'])
        leaf = self.record['retirement']
        self.assertEqual((leaf['page_bytes'],leaf['stores'],leaf['readbacks'],leaf['stack_bytes']),
                         (4096,512,512,0))

    def test_every_retirement_byte_is_load_bearing(self):
        obj = (self.directory/'retire.obj').read_bytes()
        rva = self.record['retirement']['rva']
        rows,_ = review.bridge.caller.pe.linked(self.image)
        row = next(r for r in rows if r['rva'] <= rva < r['rva']+len(r['code']))
        start = row['raw']+rva-row['rva']
        for i in range(len(review.RETIRE)):
            mutant = bytearray(self.image)
            mutant[start+i] ^= 1
            with self.assertRaises(ValueError): review.retire(obj,bytes(mutant),rva)

    def test_root_instruction_mutations_and_actual_call_targets_reject(self):
        obj = (self.directory/'normal.obj').read_bytes()
        raw,refs = review.bridge.caller.function(obj,'PublicIsolatedSha256')
        rva = self.record['root_binding']['rva']
        rows,_ = review.bridge.caller.pe.linked(self.image)
        row = next(r for r in rows if r['rva'] <= rva < r['rva']+len(r['code']))
        start = row['raw']+rva-row['rva']
        relocations = {i for r in refs for i in range(r['offset'],r['offset']+4)}
        for i in range(len(raw)):
            if i in relocations: continue
            mutant = bytearray(self.image)
            mutant[start+i] ^= 1
            with self.assertRaises(ValueError):
                review.bind(obj,bytes(mutant),'PublicIsolatedSha256',rva)
        # Tamper the real retirement branch target: original instruction bytes
        # remain normalized, but the linked leaf cannot bind at a wrong entry.
        at = next(r['offset'] for r in refs if r['symbol']=='IsolatedRetirePage')
        mutant = bytearray(self.image)
        mutant[start+at] ^= 1
        _,_,binding = review.bind(obj,bytes(mutant),'PublicIsolatedSha256',rva)
        with self.assertRaises(ValueError):
            review.retire((self.directory/'retire.obj').read_bytes(),bytes(mutant),
                          binding['reference_targets']['IsolatedRetirePage'])

    def test_native_identity_and_complete_campaign(self):
        record = json.loads((self.directory/'native-final.json').read_text())
        probe.validate(record['cases'])
        self.assertEqual(record['image_sha256'],self.record['image_sha256'])
        self.assertTrue(record['terminated'] and record['deleted'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path)
    parser.add_argument('--saved',type=Path)
    args = parser.parse_args()
    if args.native: probe.validate(json.loads(args.native.read_text())['cases'])
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    if args.saved:
        SavedTests.directory = args.saved
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SavedTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
