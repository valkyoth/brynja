"""Saved-image continuation checks; no Windows/OS secret-residue experiment."""
import argparse
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_copy_success as review


class Tests(unittest.TestCase):
    sdk = None
    disassembly = None

    @classmethod
    def setUpClass(cls):
        cls.image = cls.sdk.read_bytes()
        cls.text = cls.disassembly.read_text()
        cls.report = review.inspect(cls.image, cls.text)
        cls.code = {}
        decoded = review.decode.parse(cls.text)
        for row in cls.report['bodies'].values():
            body = review.decode.body(cls.image, dict(rva=row['rva'], size=row['bytes']), decoded)
            cls.code.update({row['rva']+at: raw for at, (raw, _) in body.items()})

    def test_both_directions_and_thread_pointer_alternatives(self):
        self.assertEqual(len(self.report['paths']), 4)
        for direction in review.NAMES[:2]:
            for present in (False, True):
                result = review.continuation(self.code, direction, present)
                self.assertEqual(result['instructions'], 30 if present else 28)
                self.assertEqual(result['vector_writes'], 0)
                self.assertEqual(result['vector_state'], 'unchanged_from_syscall_return')
                self.assertEqual(result['status_writes'],
                    [dict(kind='stack', offset=-40, bytes=4, value=0)] +
                    ([dict(kind='thread', offset=0x1250, bytes=4, value=0)] if present else []))

    def test_no_invented_qualification_or_observed_leak(self):
        for name in ('os_returned_secret_residue_observed', 'os_vector_state_payload_free_proven',
                     'error_or_exception_paths_qualified', 'sdk_transport_payload_handling_qualified',
                     'native_execution_added', 'whole_image_qualified', 'completion_package_closed',
                     'production_qualified'):
            self.assertIs(self.report[name], False)

    def test_every_success_instruction_is_required(self):
        for direction in review.NAMES[:2]:
            for present in (False, True):
                path = review.continuation(self.code, direction, present)['instruction_rvas']
                for pc in path:
                    changed = self.code.copy()
                    del changed[pc]
                    with self.assertRaises(ValueError):
                        review.continuation(changed, direction, present)

    def test_vector_write_or_unmodeled_opcode_is_not_silently_accepted(self):
        entry = review.status.sdk.BODIES['EnclaveCopyIntoEnclave'][0] + 12
        for replacement in (b'\x0f\x57\xc0', b'\xc5\xfc\x77', b'\x0f\xae\x04\x24',
                            b'\x0f\x05', b'\xcc', b'\x90'):
            with self.assertRaises(ValueError):
                review.continuation(self.code | {entry: replacement}, review.NAMES[0], True)

    def test_status_lookup_branch_and_actual_call_target_matter(self):
        lookup = review.status.BODIES['status_lookup'][0]
        helper = review.status.BODIES['status_to_error'][0]
        for pc, raw in ((lookup+11, b'\x74\x07'), (helper+34, b'\xe8\x0e\x00\x00\x00'),
                        (helper+4, b'\x48\x83\xec\x20'), (lookup+0x129, b'\xc3')):
            with self.assertRaises(ValueError):
                review.continuation(self.code | {pc: raw}, review.NAMES[0], True)

    def test_loop_is_bounded_and_nonzero_status_is_not_claimed(self):
        entry = review.status.sdk.BODIES['EnclaveCopyIntoEnclave'][0] + 12
        with self.assertRaisesRegex(ValueError, 'bounded normal return'):
            review.continuation(self.code | {entry: b'\xeb\xfe'}, review.NAMES[0], True)
        for value in (True, -1, 1, 0x80000005, 0xc0000005, '0'):
            with self.assertRaises(ValueError):
                review.continuation(self.code, review.NAMES[0], True, value)
        for direction, pointer in (('CallEnclave', True), (review.NAMES[0], 1)):
            with self.assertRaises(ValueError): review.continuation(self.code, direction, pointer)

    def test_sdk_identity_is_checked_before_decode(self):
        changed = bytearray(self.image)
        changed[-1] ^= 1
        with patch.object(review.decode, 'parse', side_effect=AssertionError('not reached')):
            with self.assertRaises(ValueError): review.inspect(bytes(changed), self.text)

    def test_decoding_is_rebound_to_actual_image(self):
        decoded = review.decode.parse(self.text)
        pc = review.status.BODIES['copy_status'][0]
        for changed in ({k: v for k, v in decoded.items() if k != pc},
                        decoded | {pc: (b'\x48\x83\xec\x20', 'subq $0x20, %rsp')}):
            with patch.object(review.decode, 'parse', return_value=changed):
                with self.assertRaises(ValueError): review.inspect(self.image, self.text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--disassembly', type=Path, required=True)
    args = parser.parse_args()
    Tests.sdk, Tests.disassembly = args.sdk, args.disassembly
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
