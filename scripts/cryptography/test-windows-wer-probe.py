#!/usr/bin/env python3
"""Local-only policy rollback and evidence-validity tests; never enable WER."""
from contextlib import nullcontext
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import windows_wer_probe as wer
from windows_protection_probe import ProbeError


class Registry:
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_EXPAND_SZ, REG_DWORD = 'machine', 1, 2, 3

    def __init__(self, existing=False, fail=None):
        self.existing, self.fail = existing, fail
        self.created, self.closed, self.deleted, self.values = [], [], [], []

    def OpenKey(self, hive, path):
        if not self.existing:
            raise FileNotFoundError(path)
        return 'existing'

    def CreateKeyEx(self, hive, path, reserved, access):
        self.created.append(path)
        return 'owned'

    def SetValueEx(self, key, name, reserved, kind, value):
        self.values.append((name, value))
        if name == self.fail:
            raise OSError('injected registry failure')

    def CloseKey(self, key):
        self.closed.append(key)

    def DeleteKey(self, hive, path):
        self.deleted.append(path)


class Tests(unittest.TestCase):
    name = 'brynja-wer-' + 'a' * 32 + '.exe'

    def test_policy_is_app_specific_and_removed_on_all_paths(self):
        for fail in (None, 'DumpFolder', 'DumpType', 'DumpCount', 'body'):
            registry = Registry(fail=fail)
            with self.subTest(fail=fail):
                with (self.assertRaises(OSError) if fail else nullcontext()):
                    with wer.application_policy(registry, self.name, 'C:/synthetic'):
                        if fail == 'body':
                            raise OSError('body failure')
                expected = wer.REGISTRY + '\\' + self.name
                self.assertEqual(registry.created, [expected])
                self.assertEqual(registry.deleted, [expected])
                self.assertEqual(registry.closed, ['owned'])
                self.assertEqual(registry.values[0], ('DumpFolder', 'C:/synthetic'))

    def test_existing_or_nonprobe_application_never_modified(self):
        registry = Registry(existing=True)
        with self.assertRaises(ProbeError):
            with wer.application_policy(registry, self.name, 'folder'):
                self.fail('must not run')
        self.assertFalse(registry.created or registry.values or registry.deleted)
        self.assertEqual(registry.closed, ['existing'])
        for name in ('python.exe', '../python.exe', 'brynja-wer-.exe', self.name + '\\other'):
            registry = Registry()
            with self.subTest(name=name), self.assertRaises(ProbeError):
                with wer.application_policy(registry, name, 'folder'):
                    self.fail('must not run')
            self.assertFalse(registry.created or registry.deleted)

    def test_positive_control_prevents_vacuous_exclusion(self):
        target = {'control': 0x20000, 'excluded': 0x10000, 'size': 32}
        for control_ok, included in ((False, 0), (True, 0), (True, 16), (True, 32)):
            answers = [{'complete_marker': control_ok}, {'included_bytes': included}]
            with patch.object(wer.dump, 'observe', side_effect=answers) as observe:
                if not control_ok:
                    with self.assertRaisesRegex(ProbeError, 'positive control'):
                        wer.analyze(b'', target)
                    self.assertEqual(observe.call_count, 1)
                else:
                    self.assertEqual(wer.analyze(b'', target)['registered_region_absent_in_this_dump'],
                                     included == 0)

    def test_real_parser_is_used_for_control_and_registered_ranges(self):
        regions = ((0x10000, b'\xa5' * 32), (0x20000, b'\x5a' * 32))
        blob = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
        blob += struct.pack('<IIIQQ', 9, 48, 44, 2, 92)
        blob += b''.join(struct.pack('<QQ', address, len(data)) for address, data in regions)
        blob += b''.join(data for _, data in regions)
        result = wer.analyze(blob, {'control': 0x20000, 'excluded': 0x10000, 'size': 32})
        self.assertFalse(result['registered_region_absent_in_this_dump'])
        self.assertTrue(result['wer_registered_region']['complete_marker'])

    def test_mapping_cleanup_and_registration_failure(self):
        spec = importlib.util.spec_from_file_location('mapping_tests',
            Path(__file__).with_name('test-windows-protection-probe.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for excluded, fail in ((False, None), (True, None), (True, 'register'),
                               (True, 'fill'), (True, 'clear')):
            api = module.Fake(fail)
            with self.subTest(excluded=excluded, fail=fail):
                with (self.assertRaises(ProbeError) if fail else nullcontext()):
                    with wer.mapping(api, wer.layout(4096, 65536, 4097), 0xa5, excluded):
                        pass
                if fail == 'clear':
                    self.assertNotIn('release', api.events)
                else:
                    self.assertEqual(api.events[-2:], ['unlock', 'release'])
                self.assertEqual('unregister' in api.events, excluded and fail not in ('register', 'clear'))

    def test_child_timeout_kills_only_owned_child_and_never_claims_success(self):
        process = Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired('test', 90), ('', '')]
        context = Mock()
        context.__enter__ = Mock(return_value=process)
        context.__exit__ = Mock(return_value=False)
        with patch.object(wer.subprocess, 'Popen', return_value=context) as spawn:
            with self.assertRaisesRegex(ProbeError, 'exceeded 90'):
                wer.run_child(Path('owned.exe'), Path('probe.py'))
        process.kill.assert_called_once_with()
        self.assertEqual(spawn.call_args.kwargs['env'].keys() & {'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN'}, set())

    def test_missing_approval_rejects_before_native_or_registry_work(self):
        with patch.object(sys, 'argv', ['probe']), patch.object(wer, 'Windows') as native:
            with self.assertRaisesRegex(ProbeError, 'explicit'):
                wer.main()
            native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
