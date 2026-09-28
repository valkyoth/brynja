#!/usr/bin/env python3
"""Failure injection for the synthetic lifecycle; never production admission."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_lifecycle as probe
from windows_protection_probe import ProbeError

spec = importlib.util.spec_from_file_location('driver', Path(__file__).with_name('check-windows-enclave-lifecycle.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def api():
    value = Mock(machine='0x8664')
    value.create.return_value = 4096
    value.load.return_value = (True, 0)
    value.routine.return_value = 8192
    value.call.side_effect = lambda routine, item: item ^ 0x4252594e
    return value


class Tests(unittest.TestCase):
    def test_success_executes_all_values_and_cleans(self):
        value = api()
        result = probe.exercise(value, 'synthetic.dll', False)
        self.assertEqual([c.args[1] for c in value.call.call_args_list], list(probe.VALUES))
        value.terminate.assert_called_once_with(4096)
        value.delete.assert_called_once_with(4096)
        self.assertFalse(result['strict_qualified'])
        self.assertFalse(result['production_signed'])
        self.assertEqual(result['calls_passed'], 4)

    def test_unsigned_requires_exact_signature_rejection(self):
        for loaded, error in ((False, 577), (True, 0), (False, 5), (False, 0)):
            with self.subTest(loaded=loaded, error=error):
                value = api()
                value.load.return_value = (loaded, error)
                if not loaded and error == 577:
                    self.assertEqual(probe.exercise(value, 'image', True)['unsigned_rejection'], 577)
                else:
                    with self.assertRaises(ProbeError):
                        probe.exercise(value, 'image', True)
                value.initialize.assert_not_called()
                value.delete.assert_called_once_with(4096)

    def test_failed_create_does_not_delete_an_unowned_address(self):
        value = api()
        value.create.side_effect = ProbeError('create')
        with self.assertRaisesRegex(ProbeError, 'create'):
            probe.exercise(value, 'image', False)
        value.delete.assert_not_called()

    def test_every_failure_attempts_deletion_and_does_not_pass(self):
        for stage in ('load', 'initialize', 'routine', 'call', 'terminate', 'delete'):
            with self.subTest(stage=stage):
                value = api()
                getattr(value, stage).side_effect = ProbeError(stage)
                with self.assertRaisesRegex(ProbeError, stage):
                    probe.exercise(value, 'image', False)
                value.delete.assert_called_once_with(4096)
                if stage in ('routine', 'call', 'terminate', 'delete'):
                    value.terminate.assert_called_once_with(4096)

    def test_cleanup_failure_retains_original_failure(self):
        value = api()
        original = ProbeError('original call failure')
        value.call.side_effect = original
        value.terminate.side_effect = ProbeError('terminate')
        value.delete.side_effect = ProbeError('delete')
        with self.assertRaisesRegex(ProbeError, 'terminate; delete') as error:
            probe.exercise(value, 'image', False)
        self.assertIs(error.exception.__cause__, original)

    def test_wrong_result_rejects_then_cleans(self):
        value = api()
        value.call.side_effect = None
        value.call.return_value = 0
        with self.assertRaisesRegex(ProbeError, 'mismatch'):
            probe.exercise(value, 'image', False)
        value.terminate.assert_called_once()
        value.delete.assert_called_once()

    def test_native_contract_binding_and_nonwaiting_calls(self):
        value = object.__new__(probe.Native)
        value.kernel, value.enclave = Mock(), Mock()
        value.bind('LoadEnclaveImageW', probe.BOOL, [probe.PTR])
        self.assertIs(value.LoadEnclaveImageW, value.enclave.LoadEnclaveImageW)
        value.CallEnclave = Mock(return_value=1)
        self.assertEqual(value.call(8192, 123), 0)
        self.assertIs(value.CallEnclave.call_args.args[2], False)
        value.TerminateEnclave = Mock(return_value=1)
        value.terminate(4096)
        value.TerminateEnclave.assert_called_once_with(4096, False)

    def test_bounded_driver_rejects_crash_timeout_and_false_qualification(self):
        good = {'strict_qualified': False, 'production_signed': False,
                'synthetic_only': True, 'deleted': True}
        with patch.object(driver.subprocess, 'run', return_value=Mock(
                returncode=0, stderr='', stdout=json.dumps(good))) as run:
            self.assertEqual(driver.bounded(['child']), good)
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
        for code, errors, out in ((1, '', json.dumps(good)), (0, 'error', json.dumps(good)),
                                  (0, '', 'x' * 4097), (0, '', '{}'), (0, '', '[]')):
            with patch.object(driver.subprocess, 'run', return_value=Mock(
                    returncode=code, stderr=errors, stdout=out)), self.assertRaises(ProbeError):
                driver.bounded(['child'])
        for field in good:
            bad = {**good, field: not good[field]}
            with patch.object(driver.subprocess, 'run', return_value=Mock(
                    returncode=0, stderr='', stdout=json.dumps(bad))), self.assertRaises(ProbeError):
                driver.bounded(['child'])
        with patch.object(driver.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 30)), \
                self.assertRaises(subprocess.TimeoutExpired):
            driver.bounded(['child'])


if __name__ == '__main__':
    unittest.main()
