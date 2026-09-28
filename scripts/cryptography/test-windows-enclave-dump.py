#!/usr/bin/env python3
"""No native calls or deliberate crashes: enclave dump non-vacuity regressions."""
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import windows_enclave_dump as probe
from windows_protection_probe import ProbeError


def target():
    return {'pid': 123, 'enclave': 0x10000, 'control': 0x20000, 'size': 8192,
            'internal_verification': True, 'clear_preflight': True, 'native_machine': '0x8664',
            'host_lock_verified': False}


def minidump(regions):
    count = len(regions)
    size = 16 + 16 * count
    blob = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
    blob += struct.pack('<IIIQQ', 9, size, 44, count, 44 + size)
    blob += b''.join(struct.pack('<QQ', address, len(data)) for address, data in regions)
    return blob + b''.join(data for _, data in regions)


class Tests(unittest.TestCase):
    def test_real_dump_parser_distinguishes_absent_partial_and_present(self):
        for length in (0, 4096, 8192):
            regions = [(0x20000, b'\x5a' * 8192)]
            if length:
                regions.insert(0, (0x10000, b'\xa5' * length))
            result = probe.analyze(minidump(regions), target())
            self.assertEqual(result['enclave_region_absent_in_this_dump'], length == 0)
            self.assertEqual(result['enclave_region']['included_bytes'], length)
            self.assertEqual(result['enclave_region']['complete_marker'], length == 8192)

    def test_missing_partial_wrong_control_and_invalid_dumps_reject(self):
        for control in (b'', b'\x5a' * 4096, b'\xa5' * 8192):
            regions = [(0x10000, b'\xa5' * 8192)]
            if control:
                regions.append((0x20000, control))
            with self.assertRaisesRegex(ProbeError, 'positive control'):
                probe.analyze(minidump(regions), target())
        for blob in (b'', b'MDMP', b'\0' * 8192):
            with self.assertRaises(ProbeError):
                probe.analyze(blob, target())

    def test_zero_filled_enclave_bytes_are_not_absence(self):
        result = probe.analyze(minidump([(0x10000, b'\0' * 8192),
                                        (0x20000, b'\x5a' * 8192)]), target())
        self.assertFalse(result['enclave_region_absent_in_this_dump'])
        self.assertFalse(result['enclave_region']['complete_marker'])

    def test_empty_descriptors_do_not_substitute_for_positive_control(self):
        blob = minidump([(0x10000, b''), (0x20000, b'')])
        with self.assertRaisesRegex(ProbeError, 'positive control'):
            probe.analyze(blob, target())
        blob = minidump([(0x10000, b''), (0x20000, b'\x5a' * 8192)])
        self.assertTrue(probe.analyze(blob, target())['enclave_region_absent_in_this_dump'])

    def test_invalid_attestation_addresses_and_overlap_reject(self):
        changes = [('pid', 124), ('pid', None), ('size', 1), ('native_machine', 'emulated'),
                   ('internal_verification', False), ('clear_preflight', False),
                   ('enclave', True), ('enclave', 0), ('enclave', 1 << 64),
                   ('control', 0x10000), ('control', 0x11fff)]
        for name, value in changes:
            record = target() | {name: value}
            with self.subTest(name=name, value=value), self.assertRaises(ProbeError):
                probe.validate_target(record, 123)

    def test_region_verifies_fill_clear_refill_and_cleanup(self):
        api = Mock()
        api.create.return_value = 0x10000
        api.load.return_value = (True, 0)
        api.call.side_effect = [0x11000, 8192, 8192, 0x11000, 8192, 8192]
        with probe.region(api, 'image') as address:
            self.assertEqual(address, 0x11000)
        self.assertEqual([call.args[1] for call in api.call.call_args_list], [1, 2, 3, 1, 2, 3])
        api.terminate.assert_called_once_with(0x10000)
        api.delete.assert_called_once_with(0x10000)

    def test_region_rejects_each_incomplete_marker_and_always_deletes(self):
        valid = [0x11000, 8192, 8192, 0x11000, 8192, 8192]
        for index in range(len(valid)):
            api = Mock()
            api.create.return_value = 0x10000
            api.load.return_value = (True, 0)
            values = valid.copy()
            values[index] = 0
            api.call.side_effect = values
            with self.subTest(index=index), self.assertRaises(ProbeError):
                with probe.region(api, 'image'):
                    pass
            api.terminate.assert_called_once()
            api.delete.assert_called_once()

    def test_setup_and_cleanup_failures_do_not_skip_delete(self):
        for stage in ('load', 'initialize', 'GetProcAddress', 'terminate'):
            api = Mock()
            api.create.return_value = 0x10000
            api.load.return_value = (True, 0)
            api.call.side_effect = [0x11000, 8192, 8192, 0x11000, 8192, 8192]
            getattr(api, stage).side_effect = ProbeError(stage)
            with self.subTest(stage=stage), self.assertRaises(ProbeError):
                with probe.region(api, 'image'):
                    pass
            api.delete.assert_called_once_with(0x10000)

    def test_child_exit_and_record_failures_are_not_exclusion(self):
        for code, output, errors in ((0, json.dumps(target()), ''),
                                    (1, json.dumps(target()), ''),
                                    (0xc0000602, json.dumps(target()), 'error'),
                                    (0xc0000602, '{}', ''),
                                    (0xc0000602, 'x' * 4096, '')):
            process = Mock(pid=123, returncode=code)
            process.communicate.return_value = (output, errors)
            context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
            with patch.object(probe.subprocess, 'Popen', return_value=context), self.assertRaises(ProbeError):
                probe.run_child('owned.exe', 'source.py', 'image.dll')

    def test_deliberate_crash_record_and_environment_allowlist(self):
        process = Mock(pid=123, returncode=0xc0000602)
        process.communicate.return_value = (json.dumps(target()), '')
        context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'not-a-real-secret', 'SYSTEMROOT': 'C:/Windows'}):
            with patch.object(probe.subprocess, 'Popen', return_value=context) as spawn:
                record, code = probe.run_child('owned.exe', 'source.py', 'image.dll')
        self.assertEqual(record, target())
        self.assertEqual(code, 0xc0000602)
        self.assertNotIn('GITHUB_TOKEN', spawn.call_args.kwargs['env'])
        self.assertEqual(spawn.call_args.kwargs['env']['SYSTEMROOT'], 'C:/Windows')

    def test_timeout_kills_only_owned_child(self):
        process = Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired('test', 90), ('', '')]
        context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
        with patch.object(probe.subprocess, 'Popen', return_value=context), self.assertRaisesRegex(ProbeError, '90 seconds'):
            probe.run_child('owned.exe', 'source.py', 'image.dll')
        process.kill.assert_called_once_with()

    def test_locked_dump_demands_all_pages_and_preserves_unlock(self):
        import windows_enclave_residency as residency
        good = {'page_count': 3, 'working_set_success': True,
                'pages': [{'valid': True, 'locked': True}] * 3}
        bad = [good | {'working_set_success': False}, good | {'pages': []},
               good | {'pages': [{'valid': True, 'locked': True}] * 2},
               good | {'pages': [{'valid': True, 'locked': False}] * 3},
               good | {'pages': [{'valid': False, 'locked': None}] * 3}]
        for snapshot in [good] + bad:
            api = Mock()
            api.attempt_lock.return_value = {'success': True, 'error': 0}
            api.snapshot.return_value = snapshot
            with patch.object(residency, 'Host', return_value=api):
                if snapshot == good:
                    with probe.locked_region(0x10000):
                        pass
                else:
                    with self.assertRaises(ProbeError):
                        with probe.locked_region(0x10000):
                            self.fail('must reject before crash')
            api.unlock.assert_called_once_with(0x10000, 8192)
        api = Mock()
        api.attempt_lock.return_value = {'success': False, 'error': 487}
        with patch.object(residency, 'Host', return_value=api), self.assertRaises(ProbeError):
            with probe.locked_region(0x10000):
                self.fail('must not crash')
        api.unlock.assert_not_called()

    def test_locked_mode_cannot_reuse_unlocked_child_record(self):
        process = Mock(pid=123, returncode=0xc0000602)
        process.communicate.return_value = (json.dumps(target()), '')
        context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
        with patch.object(probe.subprocess, 'Popen', return_value=context), self.assertRaisesRegex(ProbeError, 'mode mismatch'):
            probe.run_child('owned.exe', 'source.py', 'image.dll', True)

    def test_no_approval_means_no_native_or_registry_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'test.dll'
            image.write_bytes(b'synthetic fixture, never loaded')
            with patch.object(sys, 'argv', ['probe', str(image)]), patch.object(probe, 'Windows') as api:
                with self.assertRaisesRegex(ProbeError, 'explicit'):
                    probe.main()
                api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
