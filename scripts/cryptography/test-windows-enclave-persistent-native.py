#!/usr/bin/env python3
"""Retained-allocation orchestration regressions. Mocks are NOT platform evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

import windows_enclave_persistent as model
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support
BASE, REGION, DATA = support.BASE, support.BASE + 0x60000, support.BASE + 0x61000


class Host(support.Host):
    def __init__(self):
        super().__init__()
        self.pages = set()

    def lock(self, address, size):
        self.pages.add(address)

    def unlock(self, address, size):
        if self.failure == 'unlock' and size == 4096:
            raise RuntimeError('slot unlock failure')
        self.pages.remove(address)

    def working_set(self, address, shape):
        return [support.LOCKED if address in self.pages else 1] * (shape.payload // 4096)


class Api(guard.Api):
    def __init__(self):
        super().__init__()
        self.state = 0
        self.slot = []

    def GetProcAddress(self, base, name):
        return {b'PublicPersistent': 4, b'PublicPersistentControl': 5}.get(name, super().GetProcAddress(base, name))

    def work(self, op, cb):
        status, state = 10, self.state
        region = REGION if state else 0
        filled = checked = cleared = freed = faults = 0
        if op == 0 and not state:
            region = REGION
            if cb(DATA | 8):
                status, state = 1, 1
            else:
                status, state, freed = 11, 0, 1
        elif state and cb(DATA | 9):
            if op == 1 and state == 1:
                status, state, filled = 2, 2, 4096
            elif op == 2 and state == 2:
                status, checked = 3, 4096
            elif op == 3:
                cleared = 4096
                if cb(DATA | 10):
                    status, state, freed = 4, 0, 1
            elif op == 4:
                status, faults = 5, 4
        self.state = state
        self.slot = [status, region, region + 4096 if region else 0, state,
                     filled, checked, cleared, freed, 0, faults, 1]

    def call(self, routine, op):
        if routine == 5:
            return self.slot[op - 16] if 16 <= op < 27 else 0
        if routine != 4:
            return super().call(routine, op)
        if self.cb is None or op > 4:
            return 0
        previous = self.cb
        def cb(argument):
            result = previous(argument)
            if argument & 15 == 0 and result:
                self.work(op, previous)
            return result
        self.cb = cb
        try:
            return super().call(2, 0)
        finally:
            self.cb = previous


def exercise(deny=False, host=None, api=None):
    with patch.object(model.guard, 'callback', support.CALLBACK):
        return model.exercise(api or Api(), host or Host(), Path('image.dll'), deny)


class Tests(unittest.TestCase):
    def test_complete_campaign_and_denial(self):
        for deny in (False, True):
            host, api = Host(), Api()
            value = exercise(deny, host, api)
            self.assertEqual(model.validate_record(value, deny), value)
            self.assertEqual(api.events, ['terminate', 'delete'])
            self.assertFalse(host.pages)

    def test_each_report_field_and_missing_fields_rejected(self):
        value = exercise()
        for index in range(len(value['calls'])):
            for field in range(11):
                broken = copy.deepcopy(value)
                broken['calls'][index]['slot'][field] += 1
                with self.assertRaises(ProbeError):
                    model.validate_record(broken, False)
            for field in value['calls'][index]:
                broken = copy.deepcopy(value)
                del broken['calls'][index][field]
                with self.assertRaises((ProbeError, TypeError)):
                    model.validate_record(broken, False)

    def test_relocation_unlock_and_claim_tampering(self):
        value = exercise()
        broken = copy.deepcopy(value)
        broken['calls'][2]['slot'][1] += 8192
        broken['calls'][2]['slot'][2] += 8192
        with self.assertRaisesRegex(ProbeError, 'same allocation'):
            model.validate_record(broken, False)
        for event in range(len(value['events'])):
            broken = copy.deepcopy(value)
            del broken['events'][event]
            with self.assertRaises(ProbeError):
                model.validate_record(broken, False)
        for field in model.guard.NONCLAIMS:
            with self.assertRaises(ProbeError):
                model.validate_record({**value, field: True}, False)
        for flags in ([], [True], [1]):
            broken = copy.deepcopy(value)
            broken['calls'][2]['retained_flags'] = flags
            with self.assertRaises(ProbeError):
                model.validate_record(broken, False)

    def test_unlock_failure_tears_down_without_success_record(self):
        api, host = Api(), Host()
        host.failure = 'unlock'
        with self.assertRaisesRegex(RuntimeError, 'storage callback failed'):
            exercise(host=host, api=api)
        self.assertEqual(api.events, ['terminate', 'delete'])


if __name__ == '__main__':
    unittest.main()
