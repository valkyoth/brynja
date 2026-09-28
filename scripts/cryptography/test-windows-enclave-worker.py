#!/usr/bin/env python3
"""Fail-closed worker inventory regressions; no enclave or Windows required."""
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import windows_enclave_worker as probe
from windows_protection_probe import ProbeError

BASE = 0x10000000


def values(mutant=False):
    return [BASE + 0x11000, BASE + 0x10000, BASE + 0x10000, 0x10000,
            BASE + 0x31000, BASE + 0x30000, BASE + 0x30000, 0x10000,
            0 if mutant else 8192]


def setup(mutant=False):
    api = Mock(machine='0x8664')
    api.create.return_value = BASE
    api.load.return_value = (True, 0)
    api.initialize_worker.return_value = 1
    entries = values(mutant)
    api.call.side_effect = lambda routine, op: (0 if mutant else 8192) if op == 0 else (
        entries[op - 1] if 1 <= op <= 9 else 0)
    host = Mock()
    host.query.side_effect = lambda address: SimpleNamespace(
        allocation=address if address in (BASE + 0x10000, BASE + 0x30000) else 0,
        base=address, size=0x10000, state=0x1000, protect=4)
    return api, host


class Tests(unittest.TestCase):
    def test_positive_and_mutant_are_distinct_nonqualifying_observations(self):
        for mutant in (False, True):
            api, host = setup(mutant)
            record = probe.exercise(api, host, 'image.dll', mutant)
            self.assertEqual(record['marker_clear_rejected'], mutant)
            self.assertEqual(record['normal_marker_clear_passed'], not mutant)
            self.assertEqual(len(record['calls']), 3)
            self.assertTrue(record['stable_observed_layout'])
            self.assertFalse(record['strict_qualified'] or record['full_worker_cleanup_proved'])
            self.assertEqual(record['calls'][0]['stack']['address_offset'], 0x11000)
            api.terminate.assert_called_once_with(BASE)
            api.delete.assert_called_once_with(BASE)

    def test_mutant_cannot_pass_normal_and_normal_cannot_count_as_mutant(self):
        for mutant in (False, True):
            api, host = setup(mutant)
            with self.assertRaisesRegex(ProbeError, 'clearing result'):
                probe.exercise(api, host, 'image.dll', not mutant)
            api.delete.assert_called_once()

    def test_invalid_inventory_cannot_turn_setup_failure_into_mutant_rejection(self):
        for mutant in (False, True):
            for index, bad in ((0, 0), (1, BASE - 1), (2, BASE + 0x12000),
                               (3, 1), (3, probe.LIMIT + 1), (4, BASE + 0x11000),
                               (7, 2**64), (8, 17)):
                record = values(mutant)
                record[index] = bad
                with self.subTest(mutant=mutant, index=index), self.assertRaises(ProbeError):
                    probe.checked_inventory(record, BASE, not mutant)
        with self.assertRaises(ProbeError):
            probe.checked_inventory([0] * 9, BASE, False)

    def test_partial_thread_initialization_rejects_and_cleans(self):
        for count in (0, 2):
            api, host = setup()
            api.initialize_worker.return_value = count
            with self.assertRaisesRegex(ProbeError, 'one initialized worker'):
                probe.exercise(api, host, 'image.dll', False)
            api.call.assert_not_called()
            api.terminate.assert_called_once()
            api.delete.assert_called_once()

    def test_failure_during_work_or_termination_still_attempts_delete(self):
        for stage in ('call', 'terminate'):
            api, host = setup()
            getattr(api, stage).side_effect = ProbeError(stage)
            with self.assertRaisesRegex(ProbeError, stage):
                probe.exercise(api, host, 'image.dll', False)
            api.delete.assert_called_once()

    def test_mapping_zero_size_wrong_base_overflow_and_excess_descriptors_reject(self):
        item = probe.checked_inventory(values(), BASE, True)['stack']
        for size, base in ((0, item['allocation_base']), (probe.LIMIT, item['allocation_base']),
                            (8192, item['allocation_base'] + 1)):
            host = Mock()
            host.query.return_value = SimpleNamespace(allocation=item['allocation_base'],
                base=base, size=size, state=4096, protect=4)
            with self.assertRaises(ProbeError):
                probe.mapped_ranges(host, item, BASE)
        host = Mock()
        host.query.side_effect = lambda address: SimpleNamespace(allocation=item['allocation_base'],
            base=address, size=1, state=4096, protect=4)
        with self.assertRaisesRegex(ValueError, 'descriptor limit'):
            probe.mapped_ranges(host, item, BASE)

    def test_false_claims_child_errors_and_timeout_reject(self):
        api, host = setup()
        good = probe.exercise(api, host, 'image.dll', False)
        for field in ('strict_qualified', 'production_signed', 'full_worker_cleanup_proved',
                       'synthetic_only', 'deleted', 'marker_clear_rejected', 'normal_marker_clear_passed'):
            bad = good | {field: not good[field]}
            result = Mock(returncode=0, stderr='', stdout=json.dumps(bad))
            with patch.object(probe.subprocess, 'run', return_value=result), self.assertRaises(ProbeError):
                probe.bounded(['child'], False)
        for code, out, error in ((1, json.dumps(good), ''), (0, json.dumps(good), 'error'),
                                 (0, 'x' * 32769, ''), (0, '{}', '')):
            with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=code, stdout=out, stderr=error)):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], False)
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.bounded(['child'], False)


if __name__ == '__main__':
    unittest.main()
