#!/usr/bin/env python3
"""Synthetic stack/SEH driver regressions; native results remain separate."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_stack as probe
from windows_protection_probe import ProbeError

BASE, DATA = 0x10000000, 0x10301000
FLAGS = 1 | 1 << 22


def setup(mode):
    api = Mock(machine='0x8664')
    api.create.return_value = BASE
    api.load.return_value = (True, 0)
    api.initialize_worker.return_value = 1
    allocated = True
    markers = 47 if mode.endswith('unwind') else 31
    def call(routine, op):
        nonlocal allocated
        if op == 0:
            return 0
        if op == 1:
            return DATA
        if op == 2:
            return int(allocated)
        if op in (8, probe.MODES[mode]):
            return markers
        if op == 9:
            return DATA + 1024 if mode.startswith('owned') else BASE + 0x11000
        if op == 6:
            return probe.SIZE
        if op == 7:
            allocated = False
            return 1
        raise AssertionError(op)
    api.call.side_effect = call
    host = Mock()
    host.geometry.return_value = probe.PAGE, 65536
    host.working_set.return_value = [FLAGS] * (probe.SIZE // probe.PAGE)
    return api, host


class Tests(unittest.TestCase):
    def test_six_modes_require_exact_markers_and_cleanup(self):
        for mode in probe.MODES:
            api, host = setup(mode)
            record = probe.exercise(api, host, 'stack.dll', mode)
            self.assertEqual(record['mode'], mode)
            self.assertFalse(record['strict_qualified'] or record['rust_unwind_qualified'])
            self.assertEqual(host.working_set.call_count, 3)
            host.unlock.assert_called_once_with(DATA, probe.SIZE)
            api.terminate.assert_called_once_with(BASE)
            api.delete.assert_called_once_with(BASE)

    def test_missing_finally_clear_catch_or_wrong_frame_cannot_pass(self):
        for mode in probe.MODES:
            for op, value in ((probe.MODES[mode], 0), (8, 7), (9, 0),
                              (9, BASE + 0x11000 if mode.startswith('owned') else DATA + 1024)):
                api, host = setup(mode)
                original = api.call.side_effect
                api.call.side_effect = lambda routine, actual: value if actual == op else original(routine, actual)
                with self.assertRaises(ProbeError):
                    probe.exercise(api, host, 'stack.dll', mode)
                api.delete.assert_called_once()

    def test_geometry_and_setup_failure_never_enters_work(self):
        for op, value in ((1, 0), (1, DATA + 1), (1, BASE + probe.LIMIT), (2, 0)):
            api, host = setup('owned-normal')
            original = api.call.side_effect
            api.call.side_effect = lambda routine, actual: value if actual == op else original(routine, actual)
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'stack.dll', 'owned-normal')
            host.lock.assert_not_called()
            api.delete.assert_called_once()
        for count in (0, 2):
            api, host = setup('os-normal')
            api.initialize_worker.return_value = count
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'stack.dll', 'os-normal')
            api.call.assert_not_called()
            api.delete.assert_called_once()

    def test_all_pages_must_be_valid_and_locked_before_entry(self):
        for bad in ([FLAGS] * 15, [FLAGS] * 15 + [1], [FLAGS] * 15 + [1 << 22],
                    [FLAGS] * 15 + [True], [FLAGS] * 15 + [1 << 64]):
            api, host = setup('owned-normal')
            host.working_set.side_effect = [bad, [FLAGS] * 16]
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'stack.dll', 'owned-normal')
            self.assertFalse(any(call.args[1] == 12 for call in api.call.call_args_list))
            api.delete.assert_called_once()

    def test_failed_clearing_never_unlocks(self):
        api, host = setup('owned-normal')
        original = api.call.side_effect
        api.call.side_effect = lambda routine, op: 0 if op == 6 else original(routine, op)
        with self.assertRaisesRegex(ProbeError, 'zero readback'):
            probe.exercise(api, host, 'stack.dll', 'owned-normal')
        host.unlock.assert_not_called()
        api.delete.assert_called_once()

    def test_failed_native_call_and_teardown_remain_failures(self):
        for stage in ('call', 'terminate', 'delete'):
            api, host = setup('owned-unwind')
            if stage == 'call':
                original = api.call.side_effect
                def fail(routine, op):
                    if op == 13:
                        raise ProbeError('native execution failure')
                    return original(routine, op)
                api.call.side_effect = fail
            else:
                getattr(api, stage).side_effect = ProbeError(stage)
            with self.assertRaises(ProbeError):
                probe.exercise(api, host, 'stack.dll', 'owned-unwind')
            api.delete.assert_called_once()

    def test_parent_rejects_false_claims_wrong_mode_and_page_gaps(self):
        api, host = setup('os-normal')
        good = probe.exercise(api, host, 'stack.dll', 'os-normal')
        variants = [(key, not good[key]) for key in ('strict_qualified', 'production_signed',
                    'rust_unwind_qualified', 'dump_exclusion_verified', 'synthetic_only',
                    'deleted', 'whole_owned_region_cleared', 'released', 'frame_in_owned')]
        variants += [('mode', 'owned-normal'), ('markers', 47), ('locked_before', [FLAGS]),
                     ('locked_after', [FLAGS] * 15 + [1])]
        for key, value in variants:
            with patch.object(probe.subprocess, 'run', return_value=Mock(
                    returncode=0, stderr='', stdout=json.dumps(good | {key: value}))):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], 'os-normal')

    def test_crash_noise_and_timeout_are_inconclusive_not_success(self):
        for code, out, err in ((0xc0000028, '', ''), (1, '{}', ''), (0, '{}', 'warning'),
                               (0, 'x' * 32769, ''), (0, '{}', '')):
            with patch.object(probe.subprocess, 'run', return_value=Mock(returncode=code, stdout=out, stderr=err)):
                with self.assertRaises(ProbeError):
                    probe.bounded(['child'], 'owned-unwind')
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                probe.bounded(['child'], 'owned-unwind')

    def test_synthetic_trampoline_has_explicit_frame_and_one_fixed_target(self):
        root = Path(__file__).resolve().parents[2]
        lines = (root / 'assurance/windows-enclave-probe/stack_x64.asm').read_text().splitlines()
        code = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith(';')]
        self.assertEqual(code, ['EXTERN PublicStackWork:PROC', 'PUBLIC PublicSwitch', '.code',
            'PublicSwitch PROC FRAME', 'push rbp', '.pushreg rbp', 'mov rbp, rsp',
            '.setframe rbp, 0', '.endprolog', 'test rcx, rcx', 'jz current_stack',
            'mov rsp, rcx', 'current_stack:', 'sub rsp, 32', 'mov rcx, rdx',
            'call PublicStackWork', 'lea rsp, [rbp]', 'pop rbp', 'ret', 'PublicSwitch ENDP', 'END'])


if __name__ == '__main__':
    unittest.main()
