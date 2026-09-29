#!/usr/bin/env python3
"""Active-worker dump controls; no Windows calls or process crashes."""
import hashlib
import json
import os
import struct
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_host_dump as probe
import windows_enclave_host_dump_build as build
from windows_protection_probe import ProbeError


def target(event=2):
    return dict(pid=123, base=0x10000000, window=0x10010000, control=0x30000000,
                staging=0x40000000, event=event, locked_pages=16, epoch=1)


def blob(regions):
    count = len(regions)
    size = 16 + 16 * count
    header = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
    header += struct.pack('<IIIQQ', 9, size, 44, count, 44 + size)
    header += b''.join(struct.pack('<QQ', address, len(data)) for address, data in regions)
    return header + b''.join(data for _, data in regions)


def regions(event=2):
    return [(0x30000000, b'\x5a' * 8192),
            (0x40000000, bytes(32) if event == 2 else hashlib.sha256(b'').digest())]


class Tests(unittest.TestCase):
    def test_absent_partial_zero_and_present_window_are_distinct(self):
        for event in (2, 3):
            for count in (0, 1, 4096, 65536):
                value = probe.analyze(blob(regions(event) + [(0x10010000, bytes(count))]), target(event))
                self.assertEqual(value['window_included_bytes'], count)
                self.assertEqual(value['enclave_reservation_included_bytes'], count)
                self.assertEqual(value['window_absent_in_this_dump'], count == 0)

    def test_other_enclave_memory_does_not_become_window_exclusion_claim(self):
        value = probe.analyze(blob(regions() + [(0x10001000, b'x' * 128)]), target())
        self.assertTrue(value['window_absent_in_this_dump'])
        self.assertFalse(value['enclave_reservation_absent_in_this_dump'])
        self.assertEqual(value['enclave_reservation_included_bytes'], 128)

    def test_both_positive_controls_are_required_and_phase_specific(self):
        for event in (2, 3):
            for index in (0, 1):
                for bad in (b'', b'\x5a', b'\xff' * (8192 if index == 0 else 32)):
                    items = regions(event)
                    items[index] = (items[index][0], bad)
                    with self.assertRaises(ProbeError):
                        probe.analyze(blob(items), target(event))
        with self.assertRaises(ProbeError):
            probe.analyze(blob(regions(2)), target(3))
        for data in (b'', bytes(64), b'MDMP'):
            with self.assertRaises(ProbeError):
                probe.analyze(data, target())

    def test_identity_bounds_types_guards_and_controls(self):
        changes = dict(pid=124, base=0, window=0x10000000, control=0x10010000,
                       staging=0x30000001, event=3, locked_pages=15, epoch=2)
        for key, value in changes.items():
            for bad in (value, True, str(value), 2**64):
                with self.subTest(key=key, bad=bad), self.assertRaises(ProbeError):
                    probe.validate_target(target() | {key: bad}, 123, 2)
        for value in ({}, target() | {'extra': 1}, target() | {'window': 0x20000000-65536}):
            with self.assertRaises(ProbeError):
                probe.validate_target(value, 123, 2)

    def test_checkpoint_insertion_is_unique_and_after_locks(self):
        source = (build.host.SOURCE / 'native_host_transport.c').read_text()
        changed = build.instrument(source)
        self.assertEqual(changed.count(build.INSERT), 1)
        self.assertLess(changed.index('if (!call->locked || !pages(low, TRUE))'), changed.index(build.INSERT))
        for bad in (source.replace(build.NEEDLE, ''), source + build.NEEDLE,
                    source.replace('if (!call->locked || !pages(low, TRUE))', 'if (!call->locked)')):
            with self.assertRaises(ValueError):
                build.instrument(bad)

    def test_exit_errors_timeout_and_credential_minimization(self):
        for code, out, err in ((0, json.dumps(target()), ''), (1, json.dumps(target()), ''),
                               (0xc0000602, '{}', ''), (0xc0000602, json.dumps(target()), 'error'),
                               (0xc0000602, 'x'*4096, '')):
            process = Mock(pid=123, returncode=code)
            process.communicate.return_value = (out, err)
            context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
            with patch.object(probe.subprocess, 'Popen', return_value=context), self.assertRaises((ProbeError, ValueError)):
                probe.child('owned.exe', 'image.dll', 2)
        process = Mock(pid=123, returncode=0xc0000602)
        process.communicate.return_value = (json.dumps(target()), '')
        context = Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))
        with patch.dict(os.environ, {'UNRELATED_TOKEN': 'synthetic', 'SYSTEMROOT': 'C:/Windows'}):
            with patch.object(probe.subprocess, 'Popen', return_value=context) as spawn:
                self.assertEqual(probe.child('owned.exe', 'image.dll', 2)[0], target())
        self.assertNotIn('UNRELATED_TOKEN', spawn.call_args.kwargs['env'])
        process.communicate.side_effect = [subprocess.TimeoutExpired('owned.exe', 90), ('', '')]
        with patch.object(probe.subprocess, 'Popen', return_value=context), self.assertRaisesRegex(RuntimeError, '90 seconds'):
            probe.child('owned.exe', 'image.dll', 2)
        process.kill.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
