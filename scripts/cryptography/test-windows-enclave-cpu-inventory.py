#!/usr/bin/env python3
"""CPU inventory schema, feature-bundle and fail-closed lifecycle regressions."""
import copy
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

import windows_enclave_cpu_inventory as probe
from windows_protection_probe import ProbeError


def complete():
    return [0x42525943, 1, 15, 7, 1 << 26, 0x1c000000, (1 << 29) | (1 << 5), 1, 1, 6, 0]


class Fake:
    machine = '0x8664'

    def __init__(self, failure=None):
        self.events = []
        self.failure = failure

    def step(self, name):
        self.events.append(name)
        if name == self.failure:
            raise ProbeError(name)

    def create(self):
        self.step('create')
        return 123

    def load(self, base, image):
        self.step('load')
        return True, 0

    def initialize(self, base):
        self.step('initialize')

    def GetProcAddress(self, base, name):
        assert name in (b'PublicCpuInventory', b'PublicCpuKernelProbe')
        return 456 if name == b'PublicCpuInventory' else 789

    def check(self, value, stage):
        return value

    def call(self, routine, index):
        self.step('call')
        if routine == 789:
            return list(probe.KERNEL_CASES.values())[index - 1] if 1 <= index <= 5 else 0
        return complete()[index] if index < len(probe.FIELDS) else probe.INVALID

    def terminate(self, base):
        self.step('terminate')

    def delete(self, base):
        self.step('delete')


class Tests(unittest.TestCase):
    def test_complete_and_scalar_only_observations(self):
        result = probe.interpret(complete())
        self.assertTrue(all(result['observed_prerequisites'].values()))
        for field in ('authorizes_execution', 'cryptographic_execution_tested', 'production_qualified'):
            self.assertIs(result[field], False)
        words = complete()
        words[2:] = [0] * 9
        self.assertFalse(any(probe.interpret(words)['observed_prerequisites'].values()))

    def test_every_required_feature_is_load_bearing(self):
        bundles = {
            'sha256_sha_ni': [(2, 1), (4, 1 << 26), (6, 1 << 29)],
            'avx2_batch_or_keccak': [(2, 1), (2, 2), (2, 4), (2, 8), (4, 1 << 26),
                                     (5, 1 << 26), (5, 1 << 27), (5, 1 << 28),
                                     (6, 1 << 5), (9, 2), (9, 4)],
        }
        bundles['sha512_dedicated'] = bundles['avx2_batch_or_keccak'] + [(8, 1)]
        for name, requirements in bundles.items():
            for index, mask in requirements:
                words = complete()
                words[index] &= ~mask
                self.assertFalse(probe.interpret(words)['observed_prerequisites'][name], (name, index, mask))
        for maximum in (0, 1, 6):
            words = complete()
            words[3] = maximum
            self.assertFalse(any(probe.interpret(words)['observed_prerequisites'].values()))
        words = complete()
        words[7] = 0
        self.assertFalse(probe.interpret(words)['observed_prerequisites']['sha512_dedicated'])

    def test_malformed_records_reject(self):
        for index in range(len(probe.FIELDS)):
            for value in (-1, 1 << 32, probe.INVALID, True, '1', None):
                words = complete()
                words[index] = value
                with self.assertRaises(ProbeError):
                    probe.interpret(words)
        for words in ([], complete()[:-1], complete() + [0], tuple(complete())):
            with self.assertRaises(ProbeError):
                probe.interpret(words)
        for index, value in ((0, 0), (1, 2), (2, 16)):
            words = complete()
            words[index] = value
            with self.assertRaises(ProbeError):
                probe.interpret(words)

    def test_lifecycle_cleanup_success_and_failures(self):
        api = Fake()
        value = probe.exercise(api, 'public-test-image')
        self.assertIs(value['deleted'], True)
        self.assertEqual(api.events.count('call'), 35)
        self.assertEqual(api.events[-2:], ['terminate', 'delete'])
        for failure in ('load', 'initialize', 'call', 'terminate', 'delete'):
            api = Fake(failure)
            with self.assertRaises(ProbeError):
                probe.exercise(api, 'public-test-image')
            self.assertEqual(api.events[-1], 'delete')

    def test_drift_and_bad_query_reject_but_delete(self):
        for mode in ('drift', 'bad-query', 'fault'):
            api = Fake()
            original = api.call

            def call(routine, index):
                value = original(routine, index)
                if mode == 'bad-query' and index == 11:
                    return 0
                if mode == 'fault' and index == 3:
                    return probe.INVALID
                if mode == 'drift' and index == 6 and api.events.count('call') > 13:
                    return 0
                return value

            api.call = call
            with self.assertRaises(ProbeError):
                probe.exercise(api, 'public-test-image')
            self.assertEqual(api.events[-1], 'delete')

    def test_child_rechecks_data_and_cannot_claim_qualification(self):
        good = probe.exercise(Fake(), 'public-test-image')
        def run(value):
            with patch.object(probe.subprocess, 'run', return_value=Mock(
                    returncode=0, stderr='', stdout=json.dumps(value))):
                return probe.bounded(['test-child'])
        self.assertEqual(run(good), good)
        for field, value in (('deleted', False), ('production_qualified', True),
                             ('production_qualified', 0), ('authorizes_execution', 0),
                             ('authorizes_execution', True), ('cryptographic_execution_tested', True),
                             ('repeated_samples', 0), ('native_machine', '0xaa64')):
            with self.assertRaises(ProbeError):
                run({**good, field: value})
        bad = copy.deepcopy(good)
        bad['raw']['leaf7_ebx'] = 0
        with self.assertRaises(ProbeError):
            run(bad)
        for code, errors, stdout in ((1, '', '{}'), (0, 'fault', '{}'), (0, '', 'x' * 16384)):
            with patch.object(probe.subprocess, 'run', return_value=Mock(
                    returncode=code, stderr=errors, stdout=stdout)), self.assertRaises(ProbeError):
                probe.bounded(['test-child'])

    def test_kernels_require_complete_actual_results(self):
        value = probe.exercise(Fake(), 'public-test-image', True)
        self.assertEqual(value['public_kernel_cases'], probe.KERNEL_CASES)
        self.assertIs(value['cryptographic_execution_tested'], True)
        for bad_route in range(1, 6):
            api = Fake()
            original = api.call
            api.call = lambda routine, index: 0 if routine == 789 and index == bad_route else original(routine, index)
            with self.assertRaises(ProbeError):
                probe.exercise(api, 'public-test-image', True)
            self.assertEqual(api.events[-1], 'delete')
        with patch.object(probe.subprocess, 'run', return_value=Mock(
                returncode=0, stderr='', stdout=json.dumps(value))):
            self.assertEqual(probe.bounded(['test-child'], True), value)
            with self.assertRaises(ProbeError):
                probe.bounded(['test-child'], False)
        api = Fake()
        original = api.call
        def missing_features(routine, index):
            result = original(routine, index)
            return 0 if routine == 456 and index == 2 else result
        api.call = missing_features
        with self.assertRaises(ProbeError):
            probe.exercise(api, 'public-test-image', True)
        self.assertEqual(api.events.count('call'), 35)
        with patch.object(probe.subprocess, 'run', side_effect=subprocess.TimeoutExpired('test', 30)), \
                self.assertRaises(subprocess.TimeoutExpired):
            probe.bounded(['test-child'])


if __name__ == '__main__':
    unittest.main()
