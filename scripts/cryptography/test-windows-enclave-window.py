#!/usr/bin/env python3
"""Focused observation-schema/failure regressions; native execution is separate."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import windows_enclave_window as window
from windows_protection_probe import ProbeError


class Api:
    machine = '0x8664'
    base = 0x10000000

    def __init__(self, unwind=False, mutant=False):
        self.unwind, self.mutant = unwind, mutant
        self.events = []
        self.count = 1
        self.load_ok = True
        self.failure = None

    def create(self):
        self.events.append('create')
        return self.base

    def load(self, base, image):
        return self.load_ok, 577

    def initialize_worker(self, base):
        return self.count

    def GetProcAddress(self, base, name):
        assert name == b'PublicWindow'
        return 123

    def check(self, value, label):
        assert value
        return value

    def call(self, routine, op):
        if self.failure == 'call':
            raise RuntimeError('call failed')
        steps = 47 if self.unwind else 31
        low = self.base + 0x10000
        if op <= 1:
            assert op == int(self.unwind)
            return 0 if self.mutant else steps | 64
        return {2: low, 3: low + window.SIZE, 4: low + 60000,
                5: low + 50000, 6: steps, 7: 0}[op]

    def terminate(self, base):
        self.events.append('terminate')
        if self.failure == 'terminate':
            raise RuntimeError('terminate failed')

    def delete(self, base):
        self.events.append('delete')
        if self.failure == 'delete':
            raise RuntimeError('delete failed')


def record(unwind=False, mutant=False):
    return window.exercise(Api(unwind, mutant), Path('synthetic.dll'), unwind, mutant)


def child(value, unwind=False, mutant=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for name, value in changes.items():
        setattr(result, name, value)
    with patch.object(window.subprocess, 'run', return_value=result) as run:
        result = window.bounded(['synthetic-child'], unwind, mutant)
        assert run.call_args.kwargs['timeout'] == 30
        return result


class WindowTests(unittest.TestCase):
    def test_four_modes_and_teardown(self):
        for unwind in (False, True):
            for mutant in (False, True):
                api = Api(unwind, mutant)
                value = window.exercise(api, Path('synthetic.dll'), unwind, mutant)
                self.assertEqual(child(value, unwind, mutant), value)
                self.assertEqual(api.events, ['create', 'terminate', 'delete'])
                self.assertEqual(len(value['calls']), 3)

    def test_no_mutant_can_pass_normal_mode(self):
        for unwind in (False, True):
            for mutant in (False, True):
                with self.assertRaises(ProbeError):
                    window.exercise(Api(unwind, mutant), Path('x.dll'), unwind, not mutant)

    def test_source_work_markers_and_bounds_cannot_be_weakened(self):
        base = [95, 65536, 131072, 125536, 115536, 31]
        for index, replacements in {0: [31, 0, True], 1: [-1, 65537], 2: [131071, 0],
                                    3: [131072, 115536], 4: [131000, 0],
                                    5: [0, 15, 23, 47]}.items():
            for replacement in replacements:
                values = base.copy()
                values[index] = replacement
                with self.assertRaises(ProbeError):
                    window.validate_call(values, 0, False, False)

    def test_claims_and_incomplete_child_records_rejected(self):
        value = record()
        mutations = [{name: True} for name in window.NONCLAIMS]
        mutations += [{'deleted': False}, {'synthetic_only': False}, {'unwind': True},
                      {'missing_clear_mutant': True}, {'native_machine': '0xaa64'},
                      {'calls': []}, {'calls': value['calls'][:2]}, {'calls': [None] * 3}]
        for change in mutations:
            with self.assertRaises(ProbeError):
                child({**value, **change})
        for name in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][name]
            with self.assertRaises(ProbeError):
                child(broken)

    def test_native_errors_never_become_observations(self):
        for changes in ({'returncode': 3221225477}, {'stderr': 'warning'},
                        {'stdout': ''}, {'stdout': 'x' * 32769}, {'stdout': 'invalid'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(record(), **changes)
        with patch.object(window.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                window.bounded(['child'], False, False)

    def test_setup_and_teardown_fail_closed(self):
        for field, value in (('count', 2), ('load_ok', False), ('machine', '0xaa64')):
            api = Api()
            setattr(api, field, value)
            with self.assertRaises(ProbeError):
                window.exercise(api, Path('x.dll'), False, False)
            if field != 'machine':
                self.assertEqual(api.events[-1], 'delete')
        for failure in ('call', 'terminate', 'delete'):
            api = Api()
            api.failure = failure
            with self.assertRaisesRegex(RuntimeError, failure + ' failed'):
                window.exercise(api, Path('x.dll'), False, False)
            self.assertEqual(api.events[-1], 'delete')

    def test_synthetic_frame_contract_is_reviewed_not_a_production_claim(self):
        root = Path(__file__).resolve().parents[2]
        asm = (root / 'assurance/windows-enclave-probe/window_x64.asm').read_text()
        for token in ('call __chkstk', '.pushreg rbp', '.setframe rbp, 0',
                      'call PublicWindowBody', 'lea rsp, [rbp - 65536]',
                      'IFNDEF BRYNJA_PROBE_SKIP_WINDOW_CLEAR', 'or r9, [r10]'):
            self.assertIn(token, asm)
        self.assertEqual(asm.count('call PublicWindowBody'), 1)
        self.assertLess(asm.index('sub rsp, rax'), asm.index('fill_window:'))
        self.assertLess(asm.index('lea rsp, [rbp - 65536]'), asm.index('clear_window:'))
        code = (root / 'assurance/windows-enclave-probe/window.c').read_text()
        self.assertIn('EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH', code)
        self.assertIn('__finally', code)
        self.assertIn('NOT a protected execution backend', code)


if __name__ == '__main__':
    unittest.main()
