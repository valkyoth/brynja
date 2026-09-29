#!/usr/bin/env python3
"""Mock orchestration/tamper tests, never native enclave evidence."""
import copy
import ctypes as c
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_retained_native as model
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('persistent_tests',
    Path(__file__).with_name('test-windows-enclave-persistent-native.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


class Api(support.guard.Api):
    def __init__(self):
        super().__init__()
        self.index, self.report, self.output = 0, [], 0

    def GetProcAddress(self, base, name):
        return {b'PublicRetained': 4, b'PublicRetainedControl': 5,
                b'PublicRetainedOutput': 6}.get(name, super().GetProcAddress(base, name))

    def work(self, operation, callback):
        step = model.campaign()[self.index]
        self.index += 1
        assert operation == step[0]
        _, status, live, case = step
        region, data = support.REGION, support.DATA
        if operation == 0:
            if not callback(data | 8):
                self.report = [111, region, data, 0, 0, 0, 1, 0, 1, 0]
                return
        elif operation == 2 and not live:
            region = data = 0
        else:
            if not callback(data | 9):
                return
            if operation == 3 and not callback(data | 10):
                return
        if case is not None:
            c.memmove(self.output, hashlib.sha256(model.vectors()[case]).digest(), 32)
        self.report = [status, region, data, int(live), int(operation & 255 == 1),
                       4096 if operation == 3 else 0, int(operation == 3), 0, 1, operation]

    def call(self, routine, op):
        if routine == 5:
            return self.report[op - 16] if 16 <= op < 26 else 0
        if routine == 6:
            self.output = op
            return 1
        if routine != 4:
            return super().call(routine, op)
        if self.cb is None:
            return 0
        previous = self.cb
        def callback(argument):
            result = previous(argument)
            if argument & 15 == 0 and result:
                self.work(op, previous)
            return result
        self.cb = callback
        try:
            return super().call(2, 0)
        finally:
            self.cb = previous


def exercise(deny=False, api=None, host=None):
    with patch.object(model.storage.guard, 'callback', support.support.CALLBACK):
        return model.exercise(api or Api(), host or support.Host(), Path('image.dll'), deny)


class Tests(unittest.TestCase):
    def test_full_campaign_and_denial(self):
        for deny in (False, True):
            api, host = Api(), support.Host()
            value = exercise(deny, api, host)
            self.assertEqual(model.check_record(value, deny), value)
            self.assertEqual(api.events, ['terminate', 'delete'])
            self.assertFalse(host.pages)

    def test_all_report_fields_and_outputs_are_bound(self):
        value = exercise()
        for index in range(len(value['calls'])):
            for field in range(10):
                broken = copy.deepcopy(value)
                broken['calls'][index]['retained'][field] += 1
                with self.assertRaises(ProbeError):
                    model.check_record(broken, False)
            broken = copy.deepcopy(value)
            broken['calls'][index]['output'] = '00' * 32
            with self.assertRaises(ProbeError):
                model.check_record(broken, False)
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises((ProbeError, TypeError)):
                model.check_record(broken, False)

    def test_events_claims_and_residency_are_bound(self):
        value = exercise()
        for index in range(len(value['events'])):
            broken = copy.deepcopy(value)
            del broken['events'][index]
            with self.assertRaises(ProbeError):
                model.check_record(broken, False)
        for field in model.storage.guard.NONCLAIMS:
            with self.assertRaises(ProbeError):
                model.check_record({**value, field: True}, False)
        broken = copy.deepcopy(value)
        broken['calls'][1]['retained_flags'] = [1]
        with self.assertRaises(ProbeError):
            model.check_record(broken, False)

    def test_unlock_failure_still_tears_down(self):
        api, host = Api(), support.Host()
        host.failure = 'unlock'
        with self.assertRaisesRegex(RuntimeError, 'retained callback failed'):
            exercise(api=api, host=host)
        self.assertEqual(api.events, ['terminate', 'delete'])


if __name__ == '__main__':
    unittest.main()
