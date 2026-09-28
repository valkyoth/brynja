#!/usr/bin/env python3
"""Synthetic regressions; these do not establish Windows residency."""
from contextlib import contextmanager
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_residency as probe
from windows_protection_probe import ProbeError


class Tests(unittest.TestCase):
    def test_all_touched_pages_including_unaligned_region(self):
        self.assertEqual(probe.pages(0x10000, 8192, 4096), [0x10000, 0x11000])
        self.assertEqual(probe.pages(0x10001, 8192, 4096), [0x10000, 0x11000, 0x12000])
        for address, size, page in ((0, 8192, 4096), (True, 8192, 4096),
                                    (2**64 - 1, 8192, 4096), (1, 8191, 4096),
                                    (1, 8192, 0), (1, 8192, 4095), (1, 8192, 1)):
            with self.assertRaises(ProbeError):
                probe.pages(address, size, page)

    def test_invalid_working_set_flags_never_claim_locked(self):
        self.assertIsNone(probe.page_status(1 << 22)['locked'])
        self.assertFalse(probe.page_status(1)['locked'])
        self.assertTrue(probe.page_status(1 | 1 << 22)['locked'])
        for flags in (-1, 2**64, True):
            with self.assertRaises(ProbeError):
                probe.page_status(flags)

    def test_negative_lock_remains_negative_without_unlock(self):
        api = Mock()
        api.snapshot.side_effect = ['before', 'after']
        api.attempt_lock.return_value = {'success': False, 'error': 487}
        result = probe.inspect_candidate(api, 0x10000)
        self.assertEqual(result['lock'], {'success': False, 'error': 487})
        self.assertIsNone(result['unlock_succeeded'])
        api.unlock.assert_not_called()

    def test_success_unlocks_even_when_second_query_fails(self):
        for error in (None, ProbeError('query failed')):
            api = Mock()
            api.snapshot.side_effect = ['before', error or 'after']
            api.attempt_lock.return_value = {'success': True, 'error': 0}
            if error:
                with self.assertRaises(ProbeError):
                    probe.inspect_candidate(api, 0x10000)
            else:
                self.assertTrue(probe.inspect_candidate(api, 0x10000)['unlock_succeeded'])
            api.unlock.assert_called_once_with(0x10000, 8192)

    def test_failed_unlock_is_not_a_completed_observation(self):
        api = Mock()
        api.attempt_lock.return_value = {'success': True, 'error': 0}
        api.unlock.side_effect = ProbeError('unlock failed')
        with self.assertRaisesRegex(ProbeError, 'unlock failed'):
            probe.inspect_candidate(api, 0x10000)

    def test_bad_positive_control_prevents_enclave_execution(self):
        @contextmanager
        def mapping(*args):
            yield 0x20000

        for success, pages in ((False, []), (True, []),
                               (True, [{'valid': True, 'locked': True}]),
                               (True, [{'valid': False, 'locked': None}] * 2),
                               (True, [{'valid': True, 'locked': False}] * 2)):
            api = Mock()
            api.geometry.return_value = (4096, 65536)
            api.snapshot.return_value = {'working_set_success': success, 'pages': pages}
            with patch.object(probe, 'Host', return_value=api), patch.object(probe, 'mapping', mapping):
                with patch.object(probe, 'Native') as native, self.assertRaises(ProbeError):
                    probe.exercise('image.dll')
                native.assert_not_called()

    def test_child_errors_timeout_and_false_qualification_reject(self):
        valid = {'strict_qualified': False, 'production_signed': False,
                 'synthetic_only': True, 'deleted': True}
        results = [subprocess.CompletedProcess([], code, output, error)
                   for code, output, error in ((1, json.dumps(valid), ''),
                       (0, json.dumps(valid), 'error'), (0, 'x' * 8193, ''),
                       (0, '{}', ''), (0, json.dumps(valid | {'strict_qualified': True}), ''))]
        for result in results:
            with patch.object(probe.subprocess, 'run', return_value=result), self.assertRaises(ProbeError):
                probe.bounded(['child'])
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.bounded(['child'])


if __name__ == '__main__':
    unittest.main()
