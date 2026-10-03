#!/usr/bin/env python3
"""Concurrent public-marker handshake and observation regressions, not VBS proof."""
import copy
import ctypes as c
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from windows_enclave_concurrent import INVALID
from windows_enclave_concurrent_stack import WindowsHandshake, validate, working_set_budget, host_read_rejected
from windows_protection_probe import ProbeError

BASE = 0x10000000


class Host:
    def __init__(self):
        self.locked = set()

    def lock(self, start, size):
        assert size == 65536 and start not in self.locked
        self.locked.add(start)

    def unlock(self, start, size):
        assert size == 65536 and start in self.locked
        self.locked.remove(start)

    def working_set(self, start, layout):
        return [1 | ((1 << 22) if start in self.locked else 0)] * 16


def fixture(mode):
    host = Host()
    handshake = WindowsHandshake(host, BASE, mode)
    lows = [BASE + 0x10000 + lane * 0x20000 for lane in range(4)]
    ran = [not (lane == 2 and mode in ('deny', 'after-lock')) for lane in range(4)]
    for lane, low in enumerate(lows):
        assert handshake(low | lane << 4) == int(ran[lane])
    if mode != 'missing-clear':
        for lane, low in enumerate(lows):
            assert handshake(low | lane << 4 | 1) == 1
    assert handshake.error is None
    mask = 15 if all(ran) else 11
    record = dict(mode=mode, threads=5, active_mask=mask, completed_mask=mask, exhausted_mask=0,
                  results=[lane + 100 if ran[lane] and mode != 'missing-clear' else INVALID for lane in range(4)],
                  joined=True, deleted=True, synthetic_only=True, production_qualified=False, lanes=[],
                  working_set_budget=dict(before=[204800, 1413120], requested=[8388608, 16777216],
                                          after=[8388608, 16777216], child_process_only=True))
    for lane, low in enumerate(lows):
        item = handshake.lanes[lane]
        record['lanes'].append(dict(
            values=[low - BASE, low - BASE + 65536, low - BASE + 1024 if ran[lane] else 0,
                    int(ran[lane]), int(mode != 'missing-clear'), 1, int(ran[lane]), 0],
            trace=item.trace, snapshots=item.snapshots, locked_until_teardown=item.locked,
            host_read_errors=[299] * 3 if ran[lane] else [],
            callback_error=str(item.error) if item.error else None))
    return record


class Tests(unittest.TestCase):
    def test_host_read_requires_actual_failure_without_transfer(self):
        for mode in ('rejected', 'success', 'copied', 'changed', 'no-error'):
            def read(process, address, output, size, copied):
                if mode == 'copied':
                    c.cast(copied, c.POINTER(c.c_size_t))[0] = 1
                if mode == 'changed':
                    output[0] = 0
                return mode == 'success'
            host = SimpleNamespace(bind=lambda *args: None,
                                   dll=SimpleNamespace(GetCurrentProcess=lambda: 1, ReadProcessMemory=read))
            with patch.object(c, 'set_last_error', create=True), \
                 patch.object(c, 'get_last_error', return_value=0 if mode == 'no-error' else 299, create=True):
                if mode == 'rejected':
                    self.assertEqual(host_read_rejected(host, BASE), 299)
                else:
                    with self.subTest(mode=mode), self.assertRaises(ProbeError):
                        host_read_rejected(host, BASE)

    def test_working_set_resource_setup_fails_closed(self):
        for failure in (None, 'read', 'set', 'ignored'):
            state = [200 * 1024, 1400 * 1024]

            def read(process, low, high):
                c.cast(low, c.POINTER(c.c_size_t))[0] = state[0]
                c.cast(high, c.POINTER(c.c_size_t))[0] = state[1]
                return failure != 'read'

            def write(process, low, high):
                if failure != 'ignored':
                    state[:] = [low, high]
                return failure != 'set'

            def ok(value, message):
                if not value:
                    raise ProbeError(message)

            host = SimpleNamespace(bind=lambda *args: None, ok=ok,
                dll=SimpleNamespace(GetCurrentProcess=lambda: 1,
                                    GetProcessWorkingSetSize=read, SetProcessWorkingSetSize=write))
            if failure:
                with self.subTest(failure=failure), self.assertRaises(ProbeError):
                    working_set_budget(host)
            else:
                value = working_set_budget(host)
                self.assertEqual(value['after'], [8 * 1024 * 1024, 16 * 1024 * 1024])
                self.assertTrue(value['child_process_only'])

    def test_all_modes(self):
        for mode in ('normal', 'deny', 'after-lock', 'missing-clear'):
            with self.subTest(mode=mode):
                validate(fixture(mode), mode)

    def test_overlap_and_foreign_finish_rejected(self):
        for offset in (0, 4096, 65536):
            handshake = WindowsHandshake(Host(), BASE, 'normal')
            low = BASE + 0x10000
            self.assertEqual(handshake(low), 1)
            self.assertEqual(handshake((low + offset) | 16), 0)
            self.assertEqual(handshake.error, 'disjoint worker windows')
        handshake = WindowsHandshake(Host(), BASE, 'normal')
        self.assertEqual(handshake(BASE + 0x10001), 0)
        self.assertEqual(handshake.error, 'finish belongs to same worker window')

    def test_bad_callback_words_and_replay(self):
        for word in (None, True, -1, 0, 1 << 64, BASE | 64, BASE | 2):
            handshake = WindowsHandshake(Host(), BASE, 'normal')
            self.assertEqual(handshake(word), 0)
            self.assertIsNotNone(handshake.error)
        handshake = WindowsHandshake(Host(), BASE, 'normal')
        self.assertEqual(handshake(BASE + 0x10000), 1)
        self.assertEqual(handshake(BASE + 0x10000), 0)

    def test_tampered_observations_reject(self):
        normal = fixture('normal')
        changes = [('threads', 1), ('active_mask', 7), ('completed_mask', 7),
                   ('exhausted_mask', 1), ('joined', False), ('deleted', False),
                   ('synthetic_only', False), ('production_qualified', True),
                   ('results', [100, 101, 102, INVALID])]
        for key, value in changes:
            record = copy.deepcopy(normal)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError):
                validate(record, 'normal')
        for lane in range(4):
            for field in range(8):
                record = copy.deepcopy(normal)
                record['lanes'][lane]['values'][field] ^= 1
                # A marker can legitimately move one byte within its window.
                if field == 2:
                    record['lanes'][lane]['values'][field] = 1
                with self.subTest(lane=lane, field=field), self.assertRaises(ProbeError):
                    validate(record, 'normal')
        for key, value in (('trace', []), ('snapshots', {}), ('host_read_errors', []),
                           ('locked_until_teardown', True), ('callback_error', 'failure')):
            record = copy.deepcopy(normal)
            record['lanes'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError):
                validate(record, 'normal')

    def test_budget_record_and_boolean_metadata_reject(self):
        for key, value in (('child_process_only', False), ('before', [0, 1]),
                           ('requested', [1, 2]), ('after', [1, 2])):
            record = fixture('normal')
            record['working_set_budget'][key] = value
            with self.subTest(key=key), self.assertRaises(ProbeError):
                validate(record, 'normal')
        record = fixture('normal')
        record['lanes'][0]['values'][3] = True
        with self.assertRaises(ProbeError):
            validate(record, 'normal')


if __name__ == '__main__':
    unittest.main()
