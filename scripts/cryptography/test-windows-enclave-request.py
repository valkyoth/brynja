#!/usr/bin/env python3
"""Request regressions and compiled mutations; mocks are not native evidence."""
import copy
import ctypes as c
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import windows_enclave_request as model
import windows_enclave_request_build as build
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support
LOW, HIGH = guard.LOW, guard.HIGH


class Api(guard.Api):
    def GetProcAddress(self, base, name):
        return {b'PublicRequest': 4, b'PublicRequestControl': 5}.get(name, super().GetProcAddress(base, name))

    def call(self, routine, op):
        if routine == 5:
            return 1 if op == 24 else self.report[op - 16] if 16 <= op < 24 else 0
        if routine != 4:
            return super().call(routine, op)
        if self.cb is None:
            return 0
        assert self.cb(LOW) == 1
        status, length, exported = 11, 0, 0
        if op != 1:
            snapshot = c.string_at(op, 1072)
            hook = self.cb(LOW | 2)
            version, operation, size, destination, width, flags = struct.unpack('<6Q', snapshot[:48])
            valid = version == 1 and size <= 1024
            valid &= ((operation == 1 and 0 < destination <= (1 << 64) - 33
                       and width == 32 and flags == model.PUBLIC)
                      or (operation == 2 and destination == width == flags == 0))
            status = 10 if hook else 13
            if hook and valid:
                length = size
                status = 2 if operation == 2 else 12 if destination == 1 else 1
                if status == 1:
                    c.memmove(destination, hashlib.sha256(snapshot[48:48 + size]).digest(), 32)
                    exported = 32
        self.report = [status, LOW + 40000, LOW + 42000, LOW + 44000, length, 1, exported, 1170]
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


class RequestTests(unittest.TestCase):
    def test_all_modes_and_teardown(self):
        for mode in model.MODES:
            api = Api()
            value = exercise(mode, api)
            self.assertEqual(child(value, mode), value)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_copy_hook_order_and_duplicate_rejected(self):
        for sequence in ([LOW | 2], [LOW, (LOW + 16) | 2], [LOW, LOW | 2, LOW | 2],
                         [LOW, LOW | 1, LOW | 2]):
            hook = model.RequestHandshake(support.Host(), support.BASE, model.Request('publish', 0))
            for event in sequence:
                hook(event)
            self.assertIsNotNone(hook.error)

    def test_reports_reject_tampering(self):
        value = exercise()
        for name in model.previous.guard.NONCLAIMS:
            with self.assertRaises(ProbeError):
                child({**value, name: True})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                child(broken)
        for field in range(8):
            broken = copy.deepcopy(value)
            broken['calls'][0]['request'][field] = 1 if field == 4 else 0
            with self.assertRaises(ProbeError):
                child(broken)
        for field, item in (('copies', 2), ('restricted', 0), ('digest', '00' * 32)):
            broken = copy.deepcopy(value)
            broken['calls'][0][field] = item
            with self.assertRaises(ProbeError):
                child(broken)
        overlap = [1, LOW, LOW, LOW, 0, 1, 32, 1170]
        with self.assertRaisesRegex(ProbeError, 'disjoint'):
            model.validate_request(overlap, support.BASE, LOW, HIGH, 'publish', 0)

    def test_bounded_child_failures_and_canaries(self):
        value = exercise()
        for changes in ({'returncode': 0xc0000005}, {'stderr': 'warning'}, {'stdout': ''},
                        {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **changes)
        with patch.object(model.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                model.bounded_child(['child'], 'publish')
        request = model.Request('discard', 0)
        request.output[0] = 0
        with self.assertRaisesRegex(ProbeError, 'canaries'):
            request.check_output()

    def test_compiled_snapshots_reject_three_mutants(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line.removeprefix('host: ') for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-enclave-request-') as directory:
            commands, mutations = build.build(Path(directory), target, testing=True)
            self.assertEqual(len(commands), 16)
            self.assertEqual(mutations, {})
            expected = {'reread': 'public_result_matches_and_snapshot_is_not_reread',
                        'missing-clear': 'copy_and_hook_failures_clear_local_storage',
                        'implicit-public': 'invalid_headers_never_export'}
            for variant in build.VARIANTS:
                binary = Path(directory) / (variant + ('.exe' if os.name == 'nt' else ''))
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if variant == 'normal':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('5 passed', result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected[variant] + ' ... FAILED', result.stdout)


if __name__ == '__main__':
    unittest.main()
