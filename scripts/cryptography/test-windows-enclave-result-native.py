#!/usr/bin/env python3
"""Hardened-owner experiment regressions, not platform qualification."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import windows_enclave_result as model
import windows_enclave_result_build as build
from windows_protection_probe import ProbeError

ROOT = build.ROOT
spec = importlib.util.spec_from_file_location('guard_tests',
        Path(__file__).with_name('test-windows-enclave-window-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
support = guard.support


class Api(guard.Api):
    def __init__(self, outer_mutant=False):
        super().__init__(outer_mutant)
        self.owner_mode, self.report, self.damage = 0, [], None

    def GetProcAddress(self, base, name):
        return 4 if name == b'PublicRustControl' else super().GetProcAddress(base, name)

    def call(self, routine, op):
        if routine == 4:
            if 0 <= op < 4:
                self.owner_mode = op
                return 1
            if 16 <= op < 24:
                return self.report[op - 16] + int(self.damage == op - 16)
            return 0
        result = super().call(routine, op)
        if routine == 2 and op <= 1 and self.cb is not None:
            self.report = [self.owner_mode + 1, guard.LOW + 50000, guard.LOW + 52000, guard.LOW + 54000,
                           40 if self.owner_mode == 0 else 0, 40 if self.owner_mode == 0 else 20, 1, 1170]
        return result


def exercise(mode='success', unwind=False, api=None, host=None):
    with patch.object(model, 'callback', support.CALLBACK):
        return model.exercise(api or Api(), host or support.Host(), Path('image.dll'), mode, unwind)


def child(value, mode='success', unwind=False, **changes):
    result = subprocess.CompletedProcess([], 0, json.dumps(value), '')
    for key, item in changes.items():
        setattr(result, key, item)
    with patch.object(model.subprocess, 'run', return_value=result) as run:
        output = model.bounded_child(['child'], mode, unwind)
        assert run.call_args.kwargs['timeout'] == 30
        return output


class ResultWindowTests(unittest.TestCase):
    def test_modes_and_teardown(self):
        for mode in model.MODES:
            for unwind in (False, True):
                api, host = Api(), support.Host()
                value = exercise(mode, unwind, api, host)
                self.assertEqual(child(value, mode, unwind), value)
                self.assertFalse(host.locked)
                self.assertEqual(api.events, ['terminate', 'delete'])

    def test_complete_bounded_disjoint_report(self):
        value = [1, guard.LOW + 50000, guard.LOW + 52000, guard.LOW + 54000, 40, 40, 1, 1170]
        for field in (0, 4, 5, 6, 7):
            changed = value.copy()
            changed[field] += 1
            with self.assertRaises(ProbeError):
                model.validate_owner(changed, support.BASE, guard.LOW, guard.HIGH, 'success')
        for field, width in ((1, 1024), (2, 1170), (3, 33)):
            for address in (guard.LOW - 1, guard.HIGH - width + 1, 1 << 64):
                changed = value.copy()
                changed[field] = address
                with self.assertRaises(ProbeError):
                    model.validate_owner(changed, support.BASE, guard.LOW, guard.HIGH, 'success')
        for field in (2, 3):
            changed = value.copy()
            changed[field] = changed[1]
            with self.assertRaisesRegex(ProbeError, 'disjoint'):
                model.validate_owner(changed, support.BASE, guard.LOW, guard.HIGH, 'success')
        for changed in ([], value[:-1], value + [0], [True] * 8, [-1] * 8):
            with self.assertRaises(ProbeError):
                model.validate_owner(changed, support.BASE, guard.LOW, guard.HIGH, 'success')

    def test_failures_do_not_hide_behind_outer_clear(self):
        for field in (0, 4, 5, 6, 7):
            api = Api()
            api.damage = field
            with self.assertRaisesRegex(ProbeError, 'exact hardened ownership'):
                exercise(api=api)
            self.assertEqual(api.events, ['terminate', 'delete'])
        with self.assertRaisesRegex(ProbeError, 'exact execution/cleanup outcome'):
            exercise(api=Api(outer_mutant=True))
        for failure in ('lock', 'query', 'unlock'):
            api, host = Api(), support.Host()
            host.failure = failure
            with self.assertRaises(RuntimeError):
                exercise(api=api, host=host)
            self.assertEqual(api.events, ['terminate', 'delete'])

    def test_claims_incomplete_records_and_child_failures(self):
        value = exercise()
        changes = [{name: True} for name in model.guard.NONCLAIMS]
        changes += [{'c_exception_before': True}, {'mode': 'cancel'}, {'deleted': False},
                    {'calls': []}, {'synthetic_only': False}]
        for change in changes:
            with self.assertRaises(ProbeError):
                child({**value, **change})
        for field in value['calls'][0]:
            broken = copy.deepcopy(value)
            del broken['calls'][0][field]
            with self.assertRaises(ProbeError):
                child(broken)
        for change in ({'returncode': 0xc0000005}, {'stderr': 'warning'},
                       {'stdout': ''}, {'stdout': 'x' * 32769}, {'stdout': '{'}):
            with self.assertRaises((ProbeError, json.JSONDecodeError)):
                child(value, **change)
        with patch.object(model.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                model.bounded_child(['child'], 'success', False)

    def test_layout_assumptions_fail_closed(self):
        build.layout_check()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'crates/brynja-hash-sha2/src/hardened'
            folder.mkdir(parents=True)
            for name in ('owner.rs', 'in_place.rs'):
                (folder / name).write_text((ROOT / folder.relative_to(root) / name).read_text())
            build.layout_check(root)
            mutations = [('owner.rs', '[u8; 64]', '[u16; 32]'),
                         ('owner.rs', 'phase: [u8; 2]', 'phase: [u8; 3]'),
                         ('owner.rs', 'pub(crate) chaining_state', 'other: bool, pub(crate) chaining_state'),
                         ('in_place.rs', 'thread_bound: PhantomData<*mut ()>,', 'other: u64,'),
                         ('in_place.rs', 'owner: HardenedSha2Owner,', 'owner: Option<HardenedSha2Owner>,')]
            for name, old, new in mutations:
                path = folder / name
                text = path.read_text()
                self.assertIn(old, text)
                path.write_text(text.replace(old, new))
                with self.assertRaises(ValueError):
                    build.layout_check(root)
                path.write_text(text)



if __name__ == '__main__':
    unittest.main()
