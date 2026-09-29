#!/usr/bin/env python3
"""Borrowed-input host regressions with mocks; not native cryptographic or residency evidence."""
import copy
import ctypes as c
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import unittest
from unittest.mock import patch

import windows_enclave_borrowed_worker as model
from windows_enclave_borrowed_cases import PUBLIC
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support
LOW, HIGH = guard.LOW, guard.HIGH


class Api(guard.Api):
    def __init__(self):
        super().__init__()
        self.instance, self.epoch = 0, 0

    def create(self):
        self.instance += 1
        self.epoch = 0
        return super().create()

    def GetProcAddress(self, base, name):
        return {b'PublicWire': 4, b'PublicWireControl': 5}.get(name, super().GetProcAddress(base, name))

    def call(self, routine, op):
        if routine == 5:
            return 1 if op == 24 else self.report[op - 16] if 16 <= op < 24 else 0
        if routine != 4:
            return super().call(routine, op)
        if self.cb is None:
            return 0
        self.epoch += 1
        token = [self.instance, 12345, self.epoch, 1]
        assert self.cb(LOW) == 1
        status, length, replay = 11, 0, 0
        if op != 1:
            header = c.string_at(op, 64)
            version, reserved, size, source, address, width, flags, tail = struct.unpack('<8Q', header)
            status = 10
            if version == 3 and reserved == flags == tail == 0 and size <= 1024 and width == 64:
                rejected_source = source == 1 or LOW <= source < HIGH
                snapshot = b'' if size == 0 else c.string_at(source, size) if not rejected_source else None
                copied = snapshot is not None and (size == 0 or self.cb(LOW | 4))
                if not copied:
                    self.report = [11, LOW + 40000, LOW + 42000, LOW + 44000, 0, 1, 0, 1170]
                    return self.finish()
                length = size
                results, spent = [], False
                for step in range(2):
                    c.memmove(address, struct.pack('<8Q', *token, results[0] if step else 0, 0, 0, 0), 64)
                    if not self.cb(LOW | (step + 2)):
                        results.append(13)
                        break
                    command = list(struct.unpack('<8Q', c.string_at(address, 64)))
                    submitted, action, flag, destination, out_width = command[:4], *command[4:]
                    if spent:
                        result = 21
                    elif submitted != token:
                        result = 10
                    elif action == 2 and flag == destination == out_width == 0:
                        result = 2
                    elif action == 1 and flag == PUBLIC and out_width == 32:
                        result = 12 if destination == 1 else 1
                        if result == 1:
                            c.memmove(destination, hashlib.sha256(snapshot).digest(), 32)
                    else:
                        result = 10
                    results.append(result)
                    spent = True
                status, replay = results[0], results[1] if len(results) == 2 else 0
        self.report = [status, LOW + 40000, LOW + 42000, LOW + 44000, length, 1, replay, 1170]
        return self.finish()

    def finish(self):
        self.values = {2: LOW, 3: HIGH, 4: LOW + 60000, 5: LOW + 50000, 6: 31, 7: 1, 8: 1}
        self.stats = [LOW - 4096, HIGH, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        assert self.cb(LOW | 1) == 1
        return 95


def exercise(mode='publish', api=None):
    with patch.object(model.previous, 'callback', support.CALLBACK):
        return model.exercise(api or Api(), support.Host(), Path('image.dll'), mode)


def child(value, mode='publish', **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(model.subprocess, 'run', return_value=result) as run:
        output = model.bounded_child(['child'], mode)
        assert run.call_args.kwargs['timeout'] == 120
        return output


class WireHostTests(unittest.TestCase):
    def test_all_modes_and_teardown(self):
        for mode in (name for name in model.MODES if name != 'page-fault'):
            api = Api()
            value = exercise(mode, api)
            self.assertEqual(child(value, mode), value)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_offer_order_and_scope_tampering(self):
        value = exercise()
        for call in range(len(value["calls"])):
            for field in range(8):
                broken = copy.deepcopy(value)
                broken['calls'][call]['offers'][1][field] ^= 1
                with self.assertRaises(ProbeError):
                    child(broken)
        for field in range(8):
            broken = copy.deepcopy(value)
            broken['calls'][0]['wire'][field] = 0 if field != 4 else 99
            with self.assertRaises(ProbeError):
                child(broken)
        broken = copy.deepcopy(value)
        broken['calls'][1]['offers'][0][2] = broken['calls'][1]['offers'][1][2] = 1
        with self.assertRaisesRegex(ProbeError, 'epoch'):
            child(broken)

    def test_claims_missing_fields_and_child_failures(self):
        value = exercise()
        for name in model.previous.guard.NONCLAIMS:
            with self.assertRaises(ProbeError):
                child(value | {name: True})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                child(broken)
        for change in ({'returncode': 0xc0000005}, {'stderr': 'warning'}, {'stdout': ''},
                       {'stdout': 'x' * 262145}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **change)
        with patch.object(model.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                model.bounded_child(['child'], 'publish')

    def test_handshake_requires_exact_order_and_locked_window(self):
        for events in ([LOW | 4], [LOW, LOW | 3], [LOW, (LOW + 16) | 4],
                       [LOW, LOW | 1, LOW | 2]):
            hook = model.BorrowedHandshake(support.Host(), support.BASE, model.Request('publish', 0))
            for event in events:
                hook(event)
            self.assertIsNotNone(hook.error)

    def test_internal_source_is_inside_admitted_window_and_bound_in_record(self):
        value = exercise('enclave-input')
        self.assertEqual(child(value, 'enclave-input'), value)
        for index in range(3):
            call = value['calls'][index]
            self.assertEqual(call['internal_source_offset'], call['values'][1] + 4096)
            self.assertEqual((call['copies'], call['offers'], call['wire'][0]), (0, [], 11))
            for bad in (None, 0, call['internal_source_offset'] + 1):
                broken = copy.deepcopy(value)
                broken['calls'][index]['internal_source_offset'] = bad
                with self.assertRaises(ProbeError):
                    child(broken, 'enclave-input')


if __name__ == '__main__':
    unittest.main()
