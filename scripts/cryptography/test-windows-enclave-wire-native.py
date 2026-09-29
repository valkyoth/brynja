#!/usr/bin/env python3
"""Wire host regressions with mocks; not native cryptographic or residency evidence."""
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

import windows_enclave_wire as model
from windows_enclave_wire_cases import PUBLIC
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
            snapshot = c.string_at(op, 1072)
            version, reserved, size, address, width, flags = struct.unpack('<6Q', snapshot[:48])
            status = 10
            if version == 2 and reserved == flags == 0 and size <= 1024 and width == 64:
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
                            c.memmove(destination, hashlib.sha256(snapshot[48:48 + size]).digest(), 32)
                    else:
                        result = 10
                    results.append(result)
                    spent = True
                status, replay = results[0], results[1] if len(results) == 2 else 0
        self.report = [status, LOW + 40000, LOW + 42000, LOW + 44000, length, 1, replay, 1170]
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
        assert run.call_args.kwargs['timeout'] == 30
        return output


class WireHostTests(unittest.TestCase):
    def test_all_modes_and_teardown(self):
        for mode in model.MODES:
            api = Api()
            value = exercise(mode, api)
            self.assertEqual(child(value, mode), value)
            self.assertEqual(api.events, ['terminate', 'delete'] * (2 if mode == 'cross-instance' else 1))

    def test_offer_order_and_scope_tampering(self):
        value = exercise()
        for call in range(3):
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
        with self.assertRaisesRegex(ProbeError, 'increasing'):
            child(broken)

    def test_cross_instance_is_real_distinct_donor_record(self):
        value = exercise('cross-instance')
        for change in (None, {}, value['donor'] | {'deleted': False}):
            with self.assertRaises(ProbeError):
                child(value | {'donor': change}, 'cross-instance')
        broken = copy.deepcopy(value)
        for call in broken['calls']:
            for offer in call['offers']:
                offer[:2] = value['donor']['calls'][0]['offers'][0][:2]
        with self.assertRaisesRegex(ProbeError, 'donor namespace'):
            child(broken, 'cross-instance')

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
                       {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **change)
        with patch.object(model.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                model.bounded_child(['child'], 'publish')

    def test_handshake_requires_exact_order_and_locked_window(self):
        for events in ([LOW | 2], [LOW, LOW | 3], [LOW, (LOW + 16) | 2],
                       [LOW, LOW | 1, LOW | 2]):
            hook = model.WireHandshake(support.Host(), support.BASE, model.Request('publish', 0))
            for event in events:
                hook(event)
            self.assertIsNotNone(hook.error)


if __name__ == '__main__':
    unittest.main()
