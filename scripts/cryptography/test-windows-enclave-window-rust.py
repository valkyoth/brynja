#!/usr/bin/env python3
"""Rust worker orchestration regressions, not platform qualification."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import windows_enclave_window_rust as model
from windows_protection_probe import ProbeError

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support


class Api(guard.Api):
    def __init__(self, rust_mutant=False, outer_mutant=False):
        super().__init__(outer_mutant)
        self.rust_mutant, self.rust_mode, self.report, self.damage = rust_mutant, 0, [], None

    def GetProcAddress(self, base, name):
        return 4 if name == b'PublicRustControl' else super().GetProcAddress(base, name)

    def call(self, routine, op):
        if routine == 4:
            if 0 <= op < 4:
                self.rust_mode = op
                return 1
            if 16 <= op < 20:
                return self.report[op - 16] + int(self.damage == op - 16)
            return 0
        result = super().call(routine, op)
        if routine == 2 and op <= 1 and self.cb is not None:
            dirty = self.rust_mutant and self.rust_mode != 2
            self.report = [0 if dirty else self.rust_mode + 1, guard.LOW + 60000,
                           (1024, 512, 0, 1024)[self.rust_mode], int(not dirty)]
        return result


def exercise(mode='success', unwind=False, mutant=False, api=None, host=None):
    with patch.object(model, 'callback', support.CALLBACK):
        return model.exercise(api or Api(mutant), host or support.Host(), Path('image.dll'), mode, unwind, mutant)


def child(value, mode='success', unwind=False, mutant=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(model.subprocess, 'run', return_value=result) as run:
        output = model.bounded_child(['child'], mode, unwind, mutant)
        assert run.call_args.kwargs['timeout'] == 30
        return output


class RustWindowTests(unittest.TestCase):
    def test_all_fixed_outcomes_and_mutant_detection(self):
        for mode in model.MODES:
            for unwind in (False, True):
                for mutant in (False, True):
                    if mutant and mode == 'reject':
                        continue
                    api, host = Api(mutant), support.Host()
                    value = exercise(mode, unwind, mutant, api, host)
                    self.assertEqual(child(value, mode, unwind, mutant), value)
                    self.assertFalse(host.locked)
                    self.assertEqual(api.events, ['terminate', 'delete'])

    def test_abi_fields_complete_and_in_bounds(self):
        value = [1, guard.LOW + 60000, 1024, 1]
        for field in (0, 2, 3):
            changed = value.copy()
            changed[field] += 1
            with self.assertRaises(ProbeError):
                model.validate_rust(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)
        for address in (guard.LOW - 1, guard.HIGH - 1023, 1 << 64):
            changed = value.copy()
            changed[1] = address
            with self.assertRaises(ProbeError):
                model.validate_rust(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)
        for changed in ([], value[:-1], value + [0], [True] * 4, [-1] * 4):
            with self.assertRaises(ProbeError):
                model.validate_rust(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)

    def test_cleanup_omission_and_wrong_mutant_expectations_fail(self):
        for actual in (False, True):
            with self.assertRaisesRegex(ProbeError, 'exact Rust outcome'):
                exercise(mutant=not actual, api=Api(actual))
        with self.assertRaisesRegex(ProbeError, 'exact execution/cleanup outcome'):
            exercise(api=Api(outer_mutant=True))
        with self.assertRaises(ProbeError):
            exercise('reject', mutant=True)

    def test_ownership_and_callback_failures_still_teardown(self):
        for field in (0, 2, 3):
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

    def test_claims_and_missing_fields_fail(self):
        value = exercise()
        changes = [{name: True} for name in model.guard.NONCLAIMS]
        changes += [{'c_exception_before': True}, {'mode': 'cancel'}, {'missing_rust_clear_mutant': True},
                    {'deleted': False}, {'calls': []}, {'synthetic_only': False}]
        for change in changes:
            with self.assertRaises(ProbeError):
                child({**value, **change})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                child(broken)

    def test_crashes_warnings_timeouts_and_invalid_json_fail(self):
        value = exercise()
        for change in ({'returncode': 0xc0000005}, {'stderr': 'warning'},
                       {'stdout': ''}, {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **change)
        with patch.object(model.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                model.bounded_child(['child'], 'success', False, False)

    def test_fixed_nonunwinding_source_and_unchanged_outer_frame(self):
        rust = (ROOT / 'assurance/windows-enclave-probe/window_rust.rs').read_text()
        code = (ROOT / 'assurance/windows-enclave-probe/window_rust.c').read_text()
        asm = (ROOT / 'assurance/windows-enclave-probe/window_rust_x64.asm').read_text()
        original = (ROOT / 'assurance/windows-enclave-probe/window_guard_x64.asm').read_text()
        self.assertEqual(asm, original.replace('PublicLockedBody', 'PublicRustBody'))
        for token in ('#![no_std]', '#[repr(C)]', 'pub extern "C" fn PublicRustWork',
                      'let mut marker = [0_u8; 1024]', 'probe_skip_rust_clear', 'read_volatile', 'write_volatile'):
            self.assertIn(token, rust)
        self.assertNotIn('extern "C-unwind"', rust)
        body = code[code.index('ULONG_PTR PublicRustBody'):code.index('__declspec(dllexport)')]
        self.assertLess(body.index('BaseLockedBody(raise)'), body.index('PublicRustWork('))
        self.assertNotIn('RaiseException', body)

    def test_compiled_rust_outcomes_reject_both_real_mutants(self):
        # On Windows this needs rustc on PATH. Native ABI execution uses the
        # separately cross-compiled COFF objects, not these host unit tests.
        import os
        with tempfile.TemporaryDirectory(prefix='brynja-public-rust-') as directory:
            for cfg in (None, 'probe_skip_rust_clear', 'probe_wrong_rust_result'):
                binary = Path(directory) / ((cfg or 'normal') + ('.exe' if os.name == 'nt' else ''))
                command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-C', 'opt-level=2',
                           str(ROOT / 'assurance/windows-enclave-probe/window_rust.rs'), '-o', str(binary)]
                if cfg:
                    command += ['--cfg', cfg]
                compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if cfg:
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn('every_fixed_outcome_checks_complete_local_clearing ... FAILED', run.stdout)
                else:
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn('3 passed', run.stdout)


if __name__ == '__main__':
    unittest.main()
