#!/usr/bin/env python3
"""Availability is neither enclave execution nor strict qualification."""
import copy
import ctypes as c
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_probe as probe
from windows_protection_probe import ProbeError


class Tests(unittest.TestCase):
    state = {'vbs_status': 0, 'services_configured': [0], 'services_running': [0],
             'processors': [{'Name': 'synthetic CPU', 'VirtualizationFirmwareEnabled': False,
                             'VMMonitorModeExtensions': False,
                             'SecondLevelAddressTranslationExtensions': False}]}

    def test_exact_flags_and_last_error_reset_for_each_query(self):
        api = Mock()
        api.dll.IsEnclaveTypeSupported.side_effect = [0, 1, 0]
        with patch.object(c, 'set_last_error', create=True) as reset, \
                patch.object(c, 'get_last_error', side_effect=[50, 0, 50], create=True):
            result = probe.supported(api)
        self.assertEqual([call.args for call in api.dll.IsEnclaveTypeSupported.call_args_list],
                         [(1,), (2,), (0x10,)])
        self.assertEqual([call.args for call in reset.call_args_list], [(0,), (0,), (0,)])
        self.assertEqual(result, {'sgx': {'supported': False, 'last_error': 50},
                                 'sgx2': {'supported': True, 'last_error': 0},
                                 'vbs': {'supported': False, 'last_error': 50}})

    def test_missing_api_is_error_not_assumed_support(self):
        api = Mock()
        api.bind.side_effect = ProbeError('missing export')
        with self.assertRaises(ProbeError):
            probe.supported(api)
        api.dll.IsEnclaveTypeSupported.assert_not_called()

    def test_positive_availability_never_becomes_qualification(self):
        api = Mock(native_machine='0x8664')
        for available in (True, False):
            support = {name: {'supported': available, 'last_error': 0} for name in probe.TYPES}
            with patch.object(probe, 'supported', return_value=support), \
                    patch.object(probe, 'host_state', return_value=self.state):
                result = probe.observation(api)
            self.assertIs(result['strict_qualified'], False)
            self.assertIs(result['enclave_created'], False)
            self.assertIs(result['machine_policy_changed'], False)
            self.assertEqual(result['status'], 'OBSERVATIONS_ONLY')

    def test_native_cim_is_bounded_and_checked(self):
        with patch.object(probe.subprocess, 'run', return_value=Mock(stdout=json.dumps(self.state),
                                                                   stderr='')) as run:
            self.assertEqual(probe.host_state(), self.state)
        self.assertEqual(run.call_args.kwargs['timeout'], 30)
        self.assertTrue(run.call_args.kwargs['check'])
        self.assertIn('-NonInteractive', run.call_args.args[0])

    def test_bad_cim_shapes_never_become_negative_or_positive_evidence(self):
        values = [None, [], {}, {**self.state, 'vbs_status': True},
                  {**self.state, 'vbs_status': 3}, {**self.state, 'services_running': None},
                  {**self.state, 'services_running': [True]}, {**self.state, 'processors': []}]
        invalid = copy.deepcopy(self.state)
        invalid['processors'][0]['VMMonitorModeExtensions'] = None
        values.append(invalid)
        for value in values:
            with self.subTest(value=value), \
                    patch.object(probe.subprocess, 'run', return_value=Mock(stdout=json.dumps(value), stderr='')), \
                    self.assertRaises(ProbeError):
                probe.host_state()

    def test_oversized_stderr_invalid_json_and_timeout_fail(self):
        for output, error in (('x' * 16385, ''), ('', ''), ('{}', 'CIM failure'), ('invalid', '')):
            with patch.object(probe.subprocess, 'run', return_value=Mock(stdout=output, stderr=error)), \
                    self.assertRaises((ProbeError, ValueError)):
                probe.host_state()
        for error in (subprocess.TimeoutExpired('powershell', 30), subprocess.CalledProcessError(1, 'powershell')):
            with patch.object(probe.subprocess, 'run', side_effect=error), self.assertRaises(type(error)):
                probe.host_state()


if __name__ == '__main__':
    unittest.main()
