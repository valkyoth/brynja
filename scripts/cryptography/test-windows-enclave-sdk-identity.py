"""Focused public-code identity diagnostic regressions, no enclave required."""
import unittest
from unittest.mock import Mock

import windows_enclave_sdk_identity as identity


class IdentityTests(unittest.TestCase):
    def samples(self):
        return [[identity.MATCHED, 0x1000, identity.REJECTED, identity.REJECTED] for _ in range(3)]

    def test_complete(self):
        identity.validate_samples(self.samples())

    def test_each_changed_result_rejects(self):
        for row in range(3):
            for column in range(4):
                sample = self.samples()
                sample[row][column] ^= 1
                with self.assertRaises(ValueError): identity.validate_samples(sample)

    def test_missing_duplicate_or_boolean_rejects(self):
        for sample in ([], self.samples()[:2], self.samples()*2, [True]*3,
                       [[True, 0x1000, identity.REJECTED, identity.REJECTED]]*3):
            with self.assertRaises(ValueError): identity.validate_samples(sample)

    def api(self):
        api = Mock()
        api.create.return_value = 123
        api.load.return_value = (True, 0)
        api.call.side_effect = sum(self.samples(), [])
        return api

    def test_real_exercise_cleanup(self):
        api = self.api()
        result = identity.exercise(api, 'public.dll')
        self.assertTrue(result['loaded_text_matches_saved'])
        self.assertFalse(result['whole_module_identity_proven'])
        api.terminate.assert_called_once_with(123)
        api.delete.assert_called_once_with(123)

    def test_mismatch_still_cleans(self):
        api = self.api()
        api.call.side_effect = [0]*12
        with self.assertRaises(ValueError): identity.exercise(api, 'public.dll')
        api.terminate.assert_called_once_with(123)
        api.delete.assert_called_once_with(123)

    def test_failed_initialization_deletes(self):
        api = self.api()
        api.initialize.side_effect = RuntimeError('initialization')
        with self.assertRaises(RuntimeError): identity.exercise(api, 'public.dll')
        api.terminate.assert_not_called()
        api.delete.assert_called_once_with(123)

    def test_cleanup_failure_never_passes(self):
        for name in ('terminate', 'delete'):
            api = self.api()
            getattr(api, name).side_effect = RuntimeError('cleanup')
            with self.assertRaises(RuntimeError): identity.exercise(api, 'public.dll')
            api.delete.assert_called_once_with(123)

    def test_changed_sdk_rejects_before_parsing(self):
        for data in (b'', b'MZ', bytes(4096)):
            with self.assertRaises(ValueError): identity.reference(data)


if __name__ == '__main__':
    unittest.main()
