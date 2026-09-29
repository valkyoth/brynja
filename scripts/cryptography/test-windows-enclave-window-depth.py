#!/usr/bin/env python3
"""Synthetic depth bookkeeping tests; mocks do not qualify native unwinding."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import windows_enclave_window_depth as depth
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support
LOW, HIGH = guard.LOW, guard.HIGH


def frames(requested, bounded, unwind):
    first = HIGH - 4352
    visits = min(requested + 1, (first - LOW - 16384) // 4112 + 1) if bounded else requested + 1
    minimum = first - (visits - 1) * 4112
    rejection = visits != requested + 1
    return [visits, first, minimum, minimum - 16 if rejection else 0,
            int(rejection), int(not rejection), int(unwind),
            3 if unwind else (2 if rejection else 1), 0, minimum - 96]


class Api(guard.Api):
    def __init__(self):
        super().__init__()
        self.requested, self.bounded, self.frames, self.damage = 0, True, [], None

    def GetProcAddress(self, base, name):
        return 4 if name == b'PublicDepthControl' else super().GetProcAddress(base, name)

    def call(self, routine, op):
        if routine == 4:
            if 0 <= op <= 32 or 256 <= op <= 288:
                self.requested, self.bounded = op & 255, bool(op & 256)
                return 1
            if 512 <= op <= 521:
                value = self.frames[op - 512]
                return value + 1 if self.damage == op - 512 else value
            return 0
        result = super().call(routine, op)
        if routine == 2 and op <= 1 and self.cb is not None:
            self.frames = frames(self.requested, self.bounded, bool(op))
        return result


def exercise(requested=4, bounded=True, unwind=False, rejection=False, api=None, host=None):
    with patch.object(depth, 'callback', support.CALLBACK):
        return depth.exercise(api or Api(), host or support.Host(), Path('image.dll'),
                              requested, bounded, unwind, rejection)


def child(value, requested=4, bounded=True, unwind=False, rejection=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(depth.subprocess, 'run', return_value=result) as run:
        output = depth.bounded_child(['child'], requested, bounded, unwind, rejection)
        assert run.call_args.kwargs['timeout'] == 30
        return output


class DepthTests(unittest.TestCase):
    def test_completed_bounded_and_unchecked_frames(self):
        for requested in (0, 1, 4, 8):
            for bounded in (False, True):
                for unwind in (False, True):
                    api, host = Api(), support.Host()
                    value = exercise(requested, bounded, unwind, api=api, host=host)
                    self.assertEqual(child(value, requested, bounded, unwind), value)
                    self.assertFalse(host.locked)
                    self.assertEqual(api.events, ['terminate', 'delete'])

    def test_budget_rejection_and_exception_retain_headroom(self):
        for unwind in (False, True):
            value = exercise(32, True, unwind, True)
            self.assertEqual(child(value, 32, True, unwind, True), value)
            item = value['calls'][0]
            self.assertGreaterEqual(item['depth'][2] - item['values'][1], 16384)
            self.assertLess(item['depth'][0], 33)

    def test_each_depth_field_is_load_bearing(self):
        for requested, rejection in ((4, False), (32, True)):
            for unwind in (False, True):
                value = exercise(requested, True, unwind, rejection)
                for index in range(9):
                    broken = copy.deepcopy(value)
                    broken['calls'][0]['depth'][index] += 1
                    with self.assertRaises(ProbeError):
                        child(broken, requested, True, unwind, rejection)

    def test_bad_stop_addresses_and_noninteger_records_rejected(self):
        values = frames(4, True, False)
        for local in (LOW - 1, values[2] + 4096, HIGH, 1 << 64):
            with self.assertRaises(ProbeError):
                depth.validate_depth(values[:-1] + [local], support.BASE, LOW, HIGH, 4, True, False, False)
        for broken in ([], values[:-1], values + [0], [True] * 10, [-1] * 10):
            with self.assertRaises(ProbeError):
                depth.validate_depth(broken, support.BASE, LOW, HIGH, 4, True, False, False)

    def test_early_or_late_budget_rejection_is_not_success(self):
        values = frames(32, True, False)
        for shift in (-4112, 4112):
            broken = values.copy()
            broken[0] -= shift // 4112
            for index in (2, 3, 9):
                broken[index] += shift
            with self.assertRaises(ProbeError):
                depth.validate_depth(broken, support.BASE, LOW, HIGH, 32, True, False, True)

    def test_modes_claims_and_incomplete_records_rejected(self):
        value = exercise()
        changes = [{name: True} for name in guard.guard.NONCLAIMS]
        changes += [{'bounded': False}, {'unwind': True}, {'rejection': True},
                    {'requested_depth': True}, {'requested_depth': 5}, {'deleted': False}, {'calls': []}]
        for change in changes:
            with self.assertRaises(ProbeError):
                child({**value, **change})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                child(broken)

    def test_crash_warning_timeout_and_invalid_json_fail(self):
        value = exercise()
        for change in ({'returncode': 0xc0000005}, {'returncode': 0xc00000fd},
                       {'stderr': 'warning'}, {'stdout': ''}, {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **change)
        with patch.object(depth.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                depth.bounded_child(['child'], 4, True, False, False)

    def test_failed_native_observations_still_teardown(self):
        for field in range(9):
            api = Api()
            api.damage = field
            with self.assertRaises(ProbeError):
                exercise(api=api)
            self.assertEqual(api.events, ['terminate', 'delete'])
        for failure in ('lock', 'query', 'unlock'):
            api, host = Api(), support.Host()
            host.failure = failure
            with self.assertRaises(RuntimeError):
                exercise(api=api, host=host)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_requests_and_workers_fail_closed(self):
        for requested in (-1, 33, True):
            with self.assertRaises(ProbeError):
                exercise(requested)
        with self.assertRaises(ProbeError):
            exercise(32, False, False, True)
        api = Api()
        api.count = 2
        with self.assertRaises(ProbeError):
            exercise(api=api)
        self.assertEqual(api.events, ['terminate', 'delete'])

    def test_fixed_frame_source_and_cleanup_protocol(self):
        root = Path(__file__).resolve().parents[2]
        code = (root / 'assurance/windows-enclave-probe/window_depth.c').read_text()
        asm = (root / 'assurance/windows-enclave-probe/window_depth_x64.asm').read_text()
        original = (root / 'assurance/windows-enclave-probe/window_guard_x64.asm').read_text()
        expected = original[original.index('EXTERN '):original.index('\nEND\n')]
        actual = asm[asm.index('EXTERN '):asm.index('\nEXTERN PublicDepthBounded')]
        self.assertEqual(actual.rstrip(), expected.replace('PublicLockedBody', 'PublicDepthBody').rstrip())
        recurse = asm[asm.index('PublicDepthRecurse PROC FRAME'):]
        ordered = ['.setframe rbp, 0', 'cmp PublicDepthBounded, 0', 'add r10, 20480',
                   'jb depth_reject', 'call __chkstk', 'sub rsp, rax', 'call PublicDepthVisit',
                   'call PublicDepthRecurse', 'call PublicDepthLeaf', 'call PublicDepthReject']
        self.assertEqual([recurse.index(t) for t in ordered], sorted(recurse.index(t) for t in ordered))
        for token in ('BRYNJA_PROBE_SKIP_DEPTH_ADMISSION', 'mov rax, 4096', 'sub rsp, 32'):
            self.assertIn(token, recurse)
        for token in ('requested_depth - visits', 'depth_stats[2] - frame != 4112',
                      'GetExceptionCode() == DEPTH_EXCEPTION', 'EXCEPTION_CONTINUE_SEARCH',
                      'if (active) { return 0; }'):
            self.assertIn(token, code)


if __name__ == '__main__':
    unittest.main()
