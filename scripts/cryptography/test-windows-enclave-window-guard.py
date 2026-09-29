#!/usr/bin/env python3
"""Guard orchestration regressions. Native page faults must be tested separately."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import windows_enclave_window_guard as guard
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('lock_tests',
        Path(__file__).with_name('test-windows-enclave-window-lock.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
support.LOW = support.BASE + 0x20000
LOW, HIGH = support.LOW, support.LOW + 65536


class Api(support.Api):
    def __init__(self, mutant=False):
        super().__init__(mutant)
        self.mode, self.stats, self.broken = 0, [], None

    def GetProcAddress(self, base, name):
        if name == b'PublicGuardControl':
            return 3
        return super().GetProcAddress(base, name)

    def call(self, routine, op):
        if routine == 3:
            if 0 <= op <= 4:
                self.mode = op
                return 1
            if 16 <= op <= 28:
                value = self.stats[op - 16]
                return 0 if self.broken == op - 16 else value
            return 0
        result = super().call(routine, op)
        if routine == 2 and op <= 1 and self.cb is not None:
            probe = bool(self.values[8] and self.mode)
            self.stats = [LOW - 4096, HIGH, 1, 1, 2 if probe else 0, int(probe),
                          0xc0000005 if probe else 0, int(probe and self.mode in (2, 4)),
                          (LOW - 1 if self.mode <= 2 else HIGH) if probe else 0,
                          0, 0, 0, 0]
        return result


def exercise(mode='normal', unwind=False, mutant=False, deny=False, api=None, host=None):
    with patch.object(guard, 'callback', support.CALLBACK):
        return guard.exercise(api or Api(mutant), host or support.Host(), Path('image.dll'),
                              mode, unwind, mutant, deny)


def bounded(value, mode='normal', unwind=False, mutant=False, deny=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(guard.subprocess, 'run', return_value=result) as run:
        output = guard.bounded(['child'], mode, unwind, mutant, deny)
        assert run.call_args.kwargs['timeout'] == 30
        return output


class GuardTests(unittest.TestCase):
    def test_all_modes_cleanup_and_repeated_boundary_checks(self):
        for mode in guard.MODES:
            for unwind in (False, True):
                for mutant, deny in ((False, False), (True, False), (False, True)):
                    api, host = Api(mutant), support.Host()
                    value = exercise(mode, unwind, mutant, deny, api, host)
                    self.assertEqual(bounded(value, mode, unwind, mutant, deny), value)
                    self.assertEqual(api.events, ['terminate', 'delete'])
                    self.assertEqual(host.locked, mutant)

    def test_both_page_boundaries_and_alignment_required(self):
        base = [LOW - 4096, HIGH, 1, 1, 2, 1, 0xc0000005, 1, LOW - 1, 0, 0, 0, 0]
        for i in range(len(base)):
            broken = base.copy()
            broken[i] += 1
            with self.assertRaises(ProbeError):
                guard.validate_guards(broken, support.BASE, LOW, HIGH, 'write-low', False)
        for low, high in ((LOW + 16, HIGH + 16), (LOW, HIGH + 4096), (support.BASE, support.BASE + 65536)):
            with self.assertRaises(ProbeError):
                guard.validate_guards(base, support.BASE, low, high, 'write-low', False)
        for broken in ([], base[:-1], base + [0], [True] * 13):
            with self.assertRaises(ProbeError):
                guard.validate_guards(broken, support.BASE, LOW, HIGH, 'write-low', False)

    def test_single_fault_is_not_persistent_guard_proof(self):
        value = exercise('read-low')
        for count in (0, 1, 3):
            broken = copy.deepcopy(value)
            broken['calls'][0]['guards'][4] = count
            with self.assertRaises(ProbeError):
                bounded(broken, 'read-low')

    def test_unknown_and_mismatched_modes_rejected(self):
        value = exercise('write-high')
        for mode in ('normal', 'read-high', 'write-low', 'unknown'):
            with self.assertRaises(ProbeError):
                bounded(value, mode)

    def test_missing_guard_cannot_become_success(self):
        for field in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            api = Api()
            api.broken = field
            with self.assertRaises(ProbeError):
                exercise('write-low', api=api)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_claims_and_incomplete_records_rejected(self):
        value = exercise()
        for change in ([{name: True} for name in guard.NONCLAIMS] +
                       [{'denied': True}, {'deleted': False}, {'calls': []}, {'mode': 'read-low'}]):
            with self.assertRaises(ProbeError):
                bounded({**value, **change})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                bounded(broken)

    def test_crash_warning_timeout_and_malformed_child_fail(self):
        value = exercise()
        for change in ({'returncode': 0xc0000005}, {'stderr': 'warning'}, {'stdout': ''},
                       {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                bounded(value, **change)
        with patch.object(guard.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                guard.bounded(['child'], 'normal', False, False, False)

    def test_callback_failures_remain_errors_and_teardown_runs(self):
        for failure in ('lock', 'query', 'unlock'):
            api, host = Api(), support.Host()
            host.failure = failure
            with self.assertRaisesRegex(RuntimeError, 'guard handshake failed') as result:
                exercise(api=api, host=host)
            self.assertIn(failure, str(result.exception.__cause__))
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_worker_count_and_wrong_mutant_expectations(self):
        api = Api()
        api.count = 2
        with self.assertRaises(ProbeError):
            exercise(api=api)
        self.assertEqual(api.events, ['terminate', 'delete'])
        for actual in (False, True):
            with self.assertRaises(ProbeError):
                exercise(mutant=not actual, api=Api(actual))

    def test_fixed_source_boundary_protocol(self):
        root = Path(__file__).resolve().parents[2]
        code = (root / 'assurance/windows-enclave-probe/window_guard.c').read_text()
        asm = (root / 'assurance/windows-enclave-probe/window_guard_x64.asm').read_text()
        for token in ('PAGE_NOACCESS', 'EXCEPTION_CONTINUE_SEARCH',
                      'record->ExceptionInformation[1] != address',
                      'record->ExceptionInformation[0] != (ULONG_PTR)write',
                      'i < 2', 'PublicGuardRestore', 'low_changed', 'high_changed'):
            self.assertIn(token, code)
        self.assertNotIn('PAGE_GUARD', code)
        for token in ('and rax, -4096', 'lea rsp, [rax - 4128]', '.setframe rbp, 0',
                      'BRYNJA_PROBE_SKIP_GUARDED_CLEAR', 'call PublicGuardRestore'):
            self.assertIn(token, asm)
        ordered = ['call __chkstk', 'sub rsp, rax', 'call PublicLockedAdmit',
                   'guarded_fill:', 'call PublicLockedBody', 'guarded_clear:',
                   'guarded_readback:', 'call PublicLockedFinish', 'call PublicGuardRestore']
        self.assertEqual([asm.index(t) for t in ordered], sorted(asm.index(t) for t in ordered))


if __name__ == '__main__':
    unittest.main()
