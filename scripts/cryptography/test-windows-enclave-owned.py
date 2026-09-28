#!/usr/bin/env python3
"""Owned public-marker lifecycle ordering and rejection regressions."""
import copy
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import windows_enclave_owned as probe
from windows_protection_probe import ProbeError

BASE, ALLOCATION = 0x10000000, 0x10300000
DATA = ALLOCATION + probe.PAGE
FLAGS = 1 | 1 << 22


def inventory():
    return [ALLOCATION, DATA, probe.RESERVED, probe.SIZE, probe.PAGE, 0x2000, 0x1000,
            4, 0x2000, probe.SIZE, probe.PAGE, probe.RESERVED - probe.PAGE - probe.SIZE,
            DATA + probe.SIZE]


def setup(mutant=False):
    events = []
    state = SimpleNamespace(phase=0, locked=False)
    api = Mock(machine='0x8664')
    api.create.return_value = BASE
    api.load.return_value = (True, 0)
    api.initialize_worker.return_value = 1
    def call(routine, op):
        events.append(('call', op))
        if op == 6:
            return state.phase
        if op == 7:
            return 0
        if 16 <= op < 29 and state.phase:
            return inventory()[op - 16]
        if op == 1 and state.phase == 0:
            state.phase = 1
            return DATA
        if op == 2 and state.phase == 1:
            if not state.locked:
                raise AssertionError('driver filled before lock')
            state.phase = 2
            return probe.SIZE
        if op == 3 and state.phase == 2:
            if mutant:
                return 0
            state.phase = 3
            return probe.SIZE
        if op == 5 and state.phase in (1, 3):
            return probe.SIZE
        if op == 4 and state.phase in (1, 3):
            if state.locked:
                raise AssertionError('driver released before unlock')
            state.phase = 0
            return 1
        return 0
    api.call.side_effect = call
    host = Mock()
    host.geometry.return_value = (probe.PAGE, probe.RESERVED)
    def lock(address, size):
        assert (address, size) == (DATA, probe.SIZE)
        state.locked = True
        events.append(('lock', state.phase))
    def unlock(address, size):
        assert state.phase in (1, 3), 'driver unlocked dirty payload'
        state.locked = False
        events.append(('unlock', state.phase))
    host.lock.side_effect = lock
    host.unlock.side_effect = unlock
    host.working_set.side_effect = lambda *args: [FLAGS, FLAGS] if state.locked else [1, 1]
    return api, host, state, events


class Tests(unittest.TestCase):
    def test_two_normal_cycles_clear_before_unlock_and_release(self):
        api, host, state, events = setup()
        record = probe.exercise(api, host, 'image.dll', False)
        self.assertEqual(len(record['cycles']), 2)
        self.assertEqual(state.phase, 0)
        self.assertFalse(state.locked)
        self.assertEqual([e for e in events if e[0] in ('lock', 'unlock')],
                         [('lock', 1), ('unlock', 3)] * 2)
        self.assertFalse(record['strict_qualified'] or record['full_worker_cleanup_proved'])
        api.terminate.assert_called_once_with(BASE)
        api.delete.assert_called_once_with(BASE)

    def test_mutant_never_explicitly_unlocks_or_releases_dirty_payload(self):
        api, host, state, _ = setup(True)
        record = probe.exercise(api, host, 'mutant.dll', True)
        self.assertTrue(record['cycles'][0]['missing_clear_rejected'])
        self.assertFalse(record['cycles'][0]['explicit_release'])
        self.assertEqual(state.phase, 2)
        host.unlock.assert_not_called()
        api.terminate.assert_called_once()
        api.delete.assert_called_once()

    def test_wrong_mode_never_masquerades_as_mutation_rejection(self):
        for actual in (False, True):
            api, host, _, _ = setup(actual)
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'image.dll', not actual)
            host.unlock.assert_not_called()
            api.delete.assert_called_once()

    def test_lock_failure_prevents_fill_and_releases_initial_zero_allocation(self):
        api, host, state, events = setup()
        host.lock.side_effect = ProbeError('lock failure')
        with self.assertRaisesRegex(ProbeError, 'lock failure'):
            probe.exercise(api, host, 'image.dll', False)
        # Only the intentional rejected fill on the empty state ran.
        self.assertEqual(events.count(('call', 2)), 1)
        self.assertEqual(state.phase, 0)
        host.unlock.assert_not_called()
        api.delete.assert_called_once()

    def test_incomplete_or_unlocked_pages_prevent_admission(self):
        for flags in ([], [FLAGS], [FLAGS, 1], [FLAGS, 1 << 22], [FLAGS, True], [FLAGS, 1 << 64]):
            api, host, state, events = setup()
            host.working_set.side_effect = None
            host.working_set.return_value = flags
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'image.dll', False)
            self.assertEqual(events.count(('call', 2)), 1)
            self.assertEqual(state.phase, 0)
            host.unlock.assert_called_once()
            api.delete.assert_called_once()

    def test_post_write_failure_does_not_unlock_dirty_state(self):
        api, host, state, _ = setup()
        host.working_set.side_effect = [[FLAGS, FLAGS], ProbeError('post-write query')]
        with self.assertRaisesRegex(ProbeError, 'post-write query'):
            probe.exercise(api, host, 'image.dll', False)
        self.assertEqual(state.phase, 2)
        host.unlock.assert_not_called()
        api.delete.assert_called_once()

    def test_failed_fill_dispatch_is_treated_as_potentially_dirty(self):
        api, host, _, _ = setup()
        original = api.call.side_effect
        def fail(routine, op):
            value = original(routine, op)
            if op == 2 and value:
                raise ProbeError('failed dispatch')
            return value
        api.call.side_effect = fail
        with self.assertRaisesRegex(ProbeError, 'failed dispatch'):
            probe.exercise(api, host, 'image.dll', False)
        host.unlock.assert_not_called()
        api.delete.assert_called_once()

    def test_cleanup_failures_are_not_success(self):
        for stage in ('unlock', 'terminate', 'delete'):
            api, host, _, _ = setup()
            getattr(host if stage == 'unlock' else api, stage).side_effect = ProbeError(stage)
            with self.assertRaisesRegex(ProbeError, stage):
                probe.exercise(api, host, 'image.dll', False)
            api.delete.assert_called_once()

    def test_incomplete_setup_and_thread_counts_fail_without_payload_lock(self):
        for count in (0, 2):
            api, host, _, _ = setup()
            api.initialize_worker.return_value = count
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'image.dll', False)
            host.lock.assert_not_called()
            api.delete.assert_called_once()
        api, host, _, _ = setup()
        api.load.return_value = False, 577
        with self.assertRaises(ProbeError):
            probe.exercise(api, host, 'image.dll', False)
        api.terminate.assert_not_called()
        api.delete.assert_called_once()

    def test_geometry_requires_owned_guards_inside_enclave(self):
        probe.geometry(inventory(), BASE, DATA)
        for index in range(13):
            values = inventory()
            values[index] += 1
            with self.subTest(index=index), self.assertRaises(ProbeError):
                probe.geometry(values, BASE, DATA)
        for allocation in (BASE - probe.RESERVED, BASE + probe.LIMIT, 1 << 64):
            values = inventory()
            values[0] = allocation
            with self.assertRaises(ProbeError):
                probe.geometry(values, BASE, DATA)

    def test_parent_rejects_false_claims_missing_pages_and_wrong_modes(self):
        api, host, _, _ = setup()
        good = probe.exercise(api, host, 'image.dll', False)
        for field in ('strict_qualified', 'production_signed', 'synthetic_only', 'deleted',
                      'full_worker_cleanup_proved', 'dump_exclusion_verified'):
            bad = good | {field: not good[field]}
            with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=0, stderr='', stdout=json.dumps(bad))):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], False)
        for field, value in (('before', [FLAGS]), ('after', [FLAGS, 1]), ('cleared', []),
                             ('explicit_release', False), ('missing_clear_rejected', True)):
            bad = copy.deepcopy(good)
            bad['cycles'][0][field] = value
            with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=0, stderr='', stdout=json.dumps(bad))):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], False)
        with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=0, stderr='', stdout=json.dumps(good))):
            self.assertEqual(probe.bounded(['child'], False), good)
            with self.assertRaises(ProbeError):
                probe.bounded(['child'], True)

    def test_child_error_noise_and_timeout_reject(self):
        for code, out, error in ((1, '{}', ''), (0, '{}', 'noise'), (0, 'x' * 32769, ''), (0, '{}', '')):
            with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=code, stdout=out, stderr=error)):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], False)
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.bounded(['child'], False)


if __name__ == '__main__':
    unittest.main()
