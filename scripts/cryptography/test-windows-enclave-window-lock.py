#!/usr/bin/env python3
"""Synthetic handshake regressions; mocks are not native residency evidence."""
import copy
import ctypes as c
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import windows_enclave_window_lock as model
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('window_runner',
            Path(__file__).with_name('check-windows-enclave-window-lock.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
BASE, LOW, LOCKED = 0x10000000, 0x10010020, (1 << 22) | 1
CALLBACK = c.CFUNCTYPE(c.c_void_p, c.c_void_p)


class Host:
    def __init__(self):
        self.locked, self.events, self.failure = False, [], None

    def geometry(self):
        return 4096, 65536

    def lock(self, address, size):
        self.events.append('lock')
        if self.failure == 'lock':
            raise RuntimeError('lock failed')
        self.locked = True

    def unlock(self, address, size):
        self.events.append('unlock')
        if self.failure == 'unlock':
            raise RuntimeError('unlock failed')
        self.locked = False

    def working_set(self, address, shape):
        if self.failure == 'query' and self.locked:
            raise RuntimeError('query failed')
        return [LOCKED if self.locked else 1] * (shape.payload // model.PAGE)


class Api:
    machine = '0x8664'
    def __init__(self, mutant=False):
        self.mutant, self.events, self.cb, self.values = mutant, [], None, {}
        self.count, self.failure = 1, None

    def create(self):
        return BASE

    def load(self, base, image):
        return True, 0

    def initialize_worker(self, base):
        return self.count

    def GetProcAddress(self, base, name):
        return 1 if name == b'PublicLockedHost' else 2

    def check(self, value, label):
        return value

    def call(self, routine, op):
        if routine == 1:
            self.cb = CALLBACK(op) if op else None
            return 1
        if op > 1:
            return self.values.get(op, 0)
        if self.cb is None:
            return 0
        admitted = bool(self.cb(LOW))
        steps = (47 if op else 31) if admitted else 0
        cleared = not self.mutant
        result = (steps | 64) if cleared and self.cb(LOW | 1) else 0
        self.values = {2: LOW, 3: LOW + model.SIZE, 4: LOW + 60000 if admitted else 0,
                       5: LOW + 50000 if admitted else 0, 6: steps,
                       7: int(cleared), 8: int(admitted)}
        return result

    def terminate(self, base):
        self.events.append('terminate')
        if self.failure == 'terminate':
            raise RuntimeError('terminate failed')

    def delete(self, base):
        self.events.append('delete')


def exercise(unwind=False, mutant=False, deny=False, fault=None, api=None, host=None):
    with patch.object(runner, 'callback', CALLBACK):
        return runner.exercise(api or Api(mutant), host or Host(), Path('synthetic.dll'),
                               unwind, mutant, deny, fault)


def bounded(value, unwind=False, mutant=False, deny=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(runner.subprocess, 'run', return_value=result) as run:
        result = runner.bounded(['child'], unwind, mutant, deny)
        assert run.call_args.kwargs['timeout'] == 30
        return result


class LockedWindowTests(unittest.TestCase):
    def test_normal_unwind_denial_and_mutant(self):
        for unwind in (False, True):
            for mutant, deny in ((False, False), (False, True), (True, False)):
                api, host = Api(mutant), Host()
                value = exercise(unwind, mutant, deny, api=api, host=host)
                self.assertEqual(bounded(value, unwind, mutant, deny), value)
                self.assertEqual(host.locked, mutant)
                self.assertEqual(api.events, ['terminate', 'delete'])
                self.assertEqual(len(value['calls']), 1 if mutant else 3)

    def test_page_rounding_covers_both_edge_pages(self):
        self.assertEqual(model.geometry(LOW, BASE), (LOW - 32, 17 * 4096))
        self.assertEqual(model.geometry(LOW - 32, BASE), (LOW - 32, 16 * 4096))
        for low in (None, True, -1, LOW + 1, BASE - 16, BASE + model.LIMIT - 16, 1 << 64):
            with self.assertRaises(ProbeError):
                model.geometry(low, BASE)

    def test_incomplete_invalid_or_unlocked_pages_rejected(self):
        flags = [LOCKED] * 17
        for broken in ([], flags[:-1], flags + [LOCKED], [True] * 17, [1] * 17,
                       [LOCKED] * 16 + [1 << 22], [LOCKED] * 16 + [-1]):
            with self.assertRaises(ProbeError):
                model.flags_check(broken, 17 * 4096, True)

    def test_preexisting_lock_is_not_released(self):
        host = Host()
        host.locked = True
        handshake = model.Handshake(host, BASE)
        self.assertEqual(handshake(LOW), 0)
        self.assertIsNotNone(handshake.error)
        self.assertEqual(handshake(LOW | 1), 1)
        self.assertEqual(host.events, [])
        self.assertTrue(host.locked)

    def test_denial_requires_finish_but_no_lock(self):
        host = Host()
        handshake = model.Handshake(host, BASE, deny=True)
        self.assertEqual(handshake(LOW), 0)
        self.assertEqual(handshake(LOW | 1), 1)
        self.assertEqual(host.events, [])
        self.assertEqual(handshake.trace, ['admit', 'deny', 'clear-confirmed', 'finish-ack'])

    def test_bad_order_address_replay_and_events_rejected(self):
        for argument in (None, True, 0, LOW | 2, LOW | 15, LOW | 1):
            handshake = model.Handshake(Host(), BASE)
            self.assertEqual(handshake(argument), 0)
            self.assertIsNotNone(handshake.error)
        for argument in (LOW, (LOW + 16) | 1):
            host = Host()
            handshake = model.Handshake(host, BASE)
            self.assertEqual(handshake(LOW), 1)
            self.assertEqual(handshake(argument), 0)
            self.assertTrue(handshake.locked)
            self.assertNotIn('unlock', host.events)
        handshake = model.Handshake(Host(), BASE)
        self.assertEqual(handshake(LOW), 1)
        self.assertEqual(handshake(LOW | 1), 1)
        self.assertEqual(handshake(LOW | 1), 0)

    def test_callback_exception_is_preserved_after_recovery(self):
        for fault in ('after-lock', 'after-observe'):
            host = Host()
            handshake = model.Handshake(host, BASE, fault=fault)
            self.assertEqual(handshake(LOW), 0)
            error = handshake.error
            self.assertTrue(handshake.locked)
            self.assertEqual(handshake(LOW | 1), 1)
            self.assertIs(handshake.error, error)
            self.assertFalse(handshake.locked)
            api, host = Api(), Host()
            with self.assertRaisesRegex(RuntimeError, fault):
                exercise(fault=fault, api=api, host=host)
            self.assertFalse(host.locked)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_finish_failure_keeps_lock_for_teardown_and_fails(self):
        api, host = Api(), Host()
        with self.assertRaisesRegex(RuntimeError, 'before-unlock'):
            exercise(fault='before-unlock', api=api, host=host)
        self.assertTrue(host.locked)
        self.assertNotIn('unlock', host.events)
        self.assertEqual(api.events, ['terminate', 'delete'])

    def test_native_api_failures_are_not_swallowed(self):
        for failure in ('lock', 'unlock', 'query'):
            host, api = Host(), Api()
            host.failure = failure
            with self.assertRaisesRegex(RuntimeError, failure + ' failed'):
                exercise(api=api, host=host)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_wrong_mutant_expectation_rejected(self):
        for actual in (False, True):
            with self.assertRaises(ProbeError):
                exercise(mutant=not actual, api=Api(actual))

    def test_schema_and_trace_mutations_rejected(self):
        value = exercise()
        for change in ([{name: True} for name in runner.NONCLAIMS] +
                       [{'deleted': False}, {'denied': True}, {'calls': []}, {'calls': [None]}]):
            with self.assertRaises(ProbeError):
                bounded({**value, **change})
        first = value['calls'][0]
        for field in first:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                bounded(broken)
        for index in range(len(first['trace'])):
            broken = copy.deepcopy(value)
            del broken['calls'][0]['trace'][index]
            with self.assertRaises(ProbeError):
                bounded(broken)
        for index in range(8):
            broken = copy.deepcopy(value)
            broken['calls'][0]['values'][index] = 0
            with self.assertRaises(ProbeError):
                bounded(broken)

    def test_child_exit_timeout_warning_and_partial_output_fail(self):
        value = exercise()
        for change in ({'returncode': 0xc0000005}, {'stderr': 'warning'}, {'stdout': ''},
                       {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                bounded(value, **change)
        with patch.object(runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.bounded(['child'], False, False, False)

    def test_single_worker_and_teardown_requirements(self):
        api = Api()
        api.count = 2
        with self.assertRaises(ProbeError):
            exercise(api=api)
        self.assertEqual(api.events, ['terminate', 'delete'])
        api = Api()
        api.failure = 'terminate'
        with self.assertRaisesRegex(RuntimeError, 'terminate failed'):
            exercise(api=api)
        self.assertEqual(api.events, ['terminate', 'delete'])

    def test_source_order_and_fixed_work_contract(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / 'assurance/windows-enclave-probe/window_lock.c').read_text()
        asm = (root / 'assurance/windows-enclave-probe/window_lock_x64.asm').read_text()
        for text in ('CallEnclave(host_callback', 'reply == (void*)1', 'if (active) { return 0; }',
                     'if (!admitted)', '__finally', 'EXCEPTION_CONTINUE_SEARCH'):
            self.assertIn(text, source)
        for text in ('.setframe rbp, 0', 'call __chkstk', 'jz admission_denied',
                     'IFNDEF BRYNJA_PROBE_SKIP_LOCKED_CLEAR', 'or r9, [r10]', 'test r9, r9'):
            self.assertIn(text, asm)
        ordered = ['sub rsp, rax', 'call PublicLockedAdmit', 'fill_locked_window:',
                   'call PublicLockedBody', 'clear_locked_window:', 'verify_locked_window:',
                   'jnz rejected_locked_window', 'call PublicLockedFinish']
        self.assertEqual([asm.index(t) for t in ordered], sorted(asm.index(t) for t in ordered))


if __name__ == '__main__':
    unittest.main()
