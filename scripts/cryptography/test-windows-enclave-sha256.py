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

import windows_enclave_sha256 as model
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
                           (40, 20, 0, 40)[self.rust_mode], int(not dirty)]
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
        value = [1, guard.LOW + 60000, 40, 1]
        for field in (0, 2, 3):
            changed = value.copy()
            changed[field] += 1
            with self.assertRaises(ProbeError):
                model.validate_sha256(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)
        for address in (guard.LOW - 1, guard.HIGH - 1023, 1 << 64):
            changed = value.copy()
            changed[1] = address
            with self.assertRaises(ProbeError):
                model.validate_sha256(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)
        for changed in ([], value[:-1], value + [0], [True] * 4, [-1] * 4):
            with self.assertRaises(ProbeError):
                model.validate_sha256(changed, support.BASE, guard.LOW, guard.HIGH, 'success', False)

    def test_cleanup_omission_and_wrong_mutant_expectations_fail(self):
        for actual in (False, True):
            with self.assertRaisesRegex(ProbeError, 'exact SHA-256 outcome'):
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
        changes += [{'c_exception_before': True}, {'mode': 'cancel'}, {'missing_local_clear_mutant': True},
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

    def test_oracle_and_explicit_dependency_closure(self):
        import windows_enclave_sha256_build as build
        self.assertEqual([len(data) for data in build.vectors()], list(build.LENGTHS))
        self.assertEqual(build.hashlib.sha256(build.vectors()[1]).hexdigest(),
                         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual((ROOT / 'assurance/windows-enclave-probe/sha256_vectors.rs').read_text(),
                         build.vector_source())
        build.check_graph()
        self.assertEqual(len(build.source_files()), len(set(build.source_files())))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for crate in build.CRATES:
                path = root / 'crates' / crate / 'Cargo.toml'
                path.parent.mkdir(parents=True)
                original = (ROOT / path.relative_to(root)).read_text()
                path.write_text(original)
            build.check_graph(root)
            path = root / 'crates/brynja-hash-sha2/Cargo.toml'
            original = path.read_text()
            for old, new in [('optional = true', 'optional = false'),
                             ('default = []', 'default = ["hardened"]'),
                             ('workspace = true', 'workspace = false')]:
                self.assertIn(old, original)
                path.write_text(original.replace(old, new))
                with self.assertRaises(AssertionError):
                    build.check_graph(root)
                path.write_text(original)

    def test_fixed_nonunwinding_source_and_unchanged_outer_frame(self):
        rust = (ROOT / 'assurance/windows-enclave-probe/window_sha256.rs').read_text()
        code = (ROOT / 'assurance/windows-enclave-probe/window_sha256.c').read_text()
        for token in ('#![no_std]', '#[repr(C)]', 'pub extern "C" fn PublicRustWork',
                      'probe_skip_sha256_clear', 'probe_bad_sha256_digest',
                      'read_volatile', 'write_volatile', 'brynja_hash_sha2::sha256',
                      'brynja_hash_sha2::Sha256::new()'):
            self.assertIn(token, rust)
        self.assertNotIn('extern "C-unwind"', rust)
        self.assertIn('#include "window_rust.c"', code)
        self.assertIn('__fastfail(FAST_FAIL_FATAL_APP_EXIT)', code)
        self.assertIn('assurance/windows-enclave-probe/window_rust_x64.asm', model.SOURCES)

    def test_compiled_rust_outcomes_reject_both_real_mutants(self):
        import os
        import windows_enclave_sha256_build as build
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line.removeprefix('host: ') for line in identity.splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='brynja-public-sha256-') as directory:
            commands = build.build(Path(directory), target, testing=True)
            self.assertEqual(len(commands), 6)
            self.assertFalse(any('feature=' in arg for command in commands for arg in command))
            for variant, cfg in build.VARIANTS.items():
                binary = Path(directory) / (variant + ('.exe' if os.name == 'nt' else ''))
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                if cfg:
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn('outcomes_and_local_cleanup ... FAILED', run.stdout)
                    if cfg == 'probe_bad_sha256_digest':
                        self.assertIn('independent_vectors_match_both_existing_apis ... FAILED', run.stdout)
                else:
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn('3 passed', run.stdout)


if __name__ == '__main__':
    unittest.main()
