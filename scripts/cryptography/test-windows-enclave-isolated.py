"""Focused diagnostic regressions, not secret-compute qualification."""
import copy
import argparse
from pathlib import Path
import subprocess
import unittest

import windows_enclave_isolated_build as build
import windows_enclave_isolated_probe as probe
from windows_protection_probe import ProbeError
import windows_enclave_isolated_review as review


def sample():
    rows = []
    for name, _, status, body in probe.cases():
        trace = (['admit', 'lock', 'all-pages-locked', 'admit-ack', 'clear-confirmed',
                  'still-locked', 'unlock', 'finish-ack'] if body else
                 ['admit', 'deny', 'clear-confirmed', 'finish-ack'] if name == 'deny' else [])
        rows.append(dict(case=name, status=status, observations=[body, int(status == 1), status, 1],
                         callback_trace=trace, reentry=[0] if name == 'reentry' else []))
    return rows


class Tests(unittest.TestCase):
    def test_complete_result(self):
        probe.validate(sample())

    def test_no_missing_duplicate_reordered_or_empty_campaign(self):
        rows = sample()
        for mutant in [[], rows[:-1], rows+[rows[0]], rows[::-1], [rows[0]]*len(rows)]:
            with self.assertRaises(ProbeError): probe.validate(mutant)

    def test_every_observation_is_required(self):
        rows = sample()
        for i in range(len(rows)):
            for field in range(4):
                mutant = copy.deepcopy(rows)
                mutant[i]['observations'][field] ^= 1
                with self.assertRaises(ProbeError): probe.validate(mutant)

    def test_no_early_unlock_or_accepted_reentry(self):
        for field, replacement in [('callback_trace', ['unlock', 'clear-confirmed']), ('reentry', [1])]:
            mutant = sample()
            mutant[-2][field] = replacement
            with self.assertRaises(ProbeError): probe.validate(mutant)

    def test_wrapper_fails_fatally_before_sdk_after_dirty_readback(self):
        source = (build.SOURCE/'window_rust_x64.asm').read_text()
        result = build.wrapper(source)
        dirty = result.split('guarded_dirty:\n', 1)[1].split('guarded_restore:', 1)[0]
        self.assertEqual(dirty, '    mov ecx, 7\n    int 29h\n    jmp guarded_dirty\n')
        for mutant in [source.replace('guarded_dirty:', 'dirty:'), source+source]:
            with self.assertRaises(ValueError): build.wrapper(mutant)

    def test_checked_build_refuses_stale_sdk(self):
        with self.assertRaises(ValueError): build.sdk.reference(bytes(4096))

    def test_canary_does_not_replace_original_images(self):
        self.assertIn('isolated_sha256.c', build.FILES)
        self.assertNotIn('window_retained.c', build.FILES)
        self.assertIn('exist_ok=False', Path(build.__file__).read_text())

    def test_cleanup_mutant_requires_exact_failstop(self):
        probe.validate_dirty(subprocess.CompletedProcess([], 0xc0000409, '', ''))
        for code, out, err in [(0,'',''), (1,'',''), (0xc0000409,'PASS',''),
                               (0xc0000409,'','unexpected diagnostic')]:
            with self.assertRaises(ProbeError):
                probe.validate_dirty(subprocess.CompletedProcess([],code,out,err))


class SavedImageTests(unittest.TestCase):
    directory = None
    disassembly = None

    @classmethod
    def setUpClass(cls):
        cls.text = (cls.disassembly.read_text() if cls.disassembly else
                    review.review.decode.disassemble(cls.directory/'signed.dll'))
        cls.record = review.inspect(cls.directory,cls.text)

    def test_actual_compute_closure_and_bound(self):
        self.assertEqual(self.record['direct_sites'], 56)
        self.assertEqual(self.record['indirect_sites'], 0)
        self.assertEqual(len(self.record['closure']['functions']), 10)
        self.assertTrue(self.record['closure']['sdk_free_call_graph'])
        self.assertFalse(self.record['transport_payload_handling_qualified'])
        self.assertFalse(self.record['completion_package_closed'])
        for row in self.record['normal_compute_bound'].values():
            self.assertEqual(row['complete_stack_bytes'],2544)

    def test_actual_native_rows_and_source_bindings(self):
        import json
        record = json.loads((self.directory/'native.json').read_text())
        probe.validate(record['cases'])
        self.assertEqual(record['image_sha256'],self.record['image_sha256'])

    def test_actual_adapter_instruction_and_tail_mutations_reject(self):
        image = (self.directory/'signed.dll').read_bytes()
        obj = (self.directory/'normal.obj').read_bytes()
        wrapper = self.record['wrapper_binding']
        binding = self.record['entry_adapter']
        rust = dict(rva=binding['reference_targets']['IsolatedSha256'])
        rows,_ = review.workers.catalog.sdk.pe.linked(image)
        address = binding['rva']
        row = next(r for r in rows if r['rva'] <= address < r['rva']+len(r['code']))
        offset = row['raw']+address-row['rva']
        for i in range(len(review.BODY)):
            mutant = bytearray(image)
            mutant[offset+i] ^= 1
            # Relocations to internal data can move without changing instruction
            # identity; the exact source/PE digest remains their review boundary.
            relocation = any(at <= i < at+4 for at,_,_,_ in review.REFS[:-1])
            if relocation:
                continue
            with self.assertRaises(ValueError):
                review.cbody(obj,bytes(mutant),wrapper,rust)

    def test_sdk_edge_cannot_enter_existing_compute_graph(self):
        nodes = copy.deepcopy(self.record['function_geometry'])
        for scan in nodes['PublicRustBody']['scans']:
            for call in scan['calls']:
                call['targets'] = ['sdk:EnclaveCopyIntoEnclave']
        with self.assertRaises(ValueError): review.compute_closure(nodes,['PublicRustBody'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--saved', type=Path)
    parser.add_argument('--disassembly', type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    if args.saved:
        SavedImageTests.directory = args.saved
        SavedImageTests.disassembly = args.disassembly
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SavedImageTests))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
