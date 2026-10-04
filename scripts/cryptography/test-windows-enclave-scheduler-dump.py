"""Dump parsing/checkpoint regressions; no registry mutations or process crashes."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import windows_enclave_scheduler_dump as runner
import windows_enclave_scheduler_dump_model as model
from windows_protection_probe import ProbeError

EXPECTED = bytes(range(33))


def target(phase='root'):
    count, completed, cleared = {'root': (1, 0, 0), 'workers': (5, 1, 4), 'output': (5, 5, 18)}[phase]
    return dict(pid=123, phase=phase, base=0x10000000, control=0x30000000, staging=0x40000000,
                windows=[dict(low=0x10010000 + i * 0x20000, locked_pages=0 if phase == 'output' else 16)
                         for i in range(count)], completed=completed, cleared_frames=cleared,
                active=0 if phase == 'output' else count, output_verified=phase == 'output')


def blob(regions):
    size = 16 + 16 * len(regions)
    header = struct.pack('<6IQ', 0x504d444d, 0xa793, 1, 32, 0, 0, 2)
    header += struct.pack('<IIIQQ', 9, size, 44, len(regions), 44 + size)
    header += b''.join(struct.pack('<QQ', address, len(data)) for address, data in regions)
    return header + b''.join(data for _, data in regions)


def regions(phase):
    return [(0x30000000, b'\x5a' * 8192), (0x40000000, EXPECTED if phase == 'output' else b'\xa5' * 33)]


class Tests(unittest.TestCase):
    def test_dynamic_oracle_sources_are_bound(self):
        sources = runner.sources()
        for name in ('scripts/parallelhash/check-parallelhash-differential.py',
                     'scripts/sha3/check-cshake-differential.py',
                     'scripts/sha3/check-sha3-bit-differential.py'):
            self.assertEqual(sources[name], runner.digest(runner.ROOT / name))

    def test_all_phases_require_real_dump_controls(self):
        for phase in model.PHASES:
            value = model.analyze(blob(regions(phase)), target(phase), EXPECTED)
            self.assertTrue(value['reservation_absent_in_this_dump'])
            for index in range(2):
                for bad in (b'', b'\x5a', b'\xff' * len(regions(phase)[index][1])):
                    values = regions(phase)
                    values[index] = values[index][0], bad
                    with self.assertRaises(ProbeError):
                        model.analyze(blob(values), target(phase), EXPECTED)
        with self.assertRaises(ProbeError):
            model.analyze(blob(regions('root')), target('output'), EXPECTED)

    def test_partial_zero_and_complete_windows_are_not_exclusion(self):
        for phase in model.PHASES:
            for row in target(phase)['windows']:
                for count in (1, 4096, 65536):
                    value = model.analyze(blob(regions(phase) + [(row['low'], bytes(count))]), target(phase), EXPECTED)
                    self.assertFalse(value['windows_absent_in_this_dump'])
                    self.assertEqual(sum(value['window_included_bytes']), count)
                    self.assertEqual(value['reservation_included_bytes'], count)
        value = model.analyze(blob(regions('root') + [(0x10001000, bytes(64))]), target(), EXPECTED)
        self.assertTrue(value['windows_absent_in_this_dump'])
        self.assertFalse(value['reservation_absent_in_this_dump'])

    def test_missing_malformed_and_overlap_dumps_reject(self):
        for data in (b'', b'MDMP', bytes(64), blob(regions('root') * 2)):
            with self.assertRaises(ProbeError): model.analyze(data, target(), EXPECTED)

    def test_exact_progress_and_schema(self):
        for phase in model.PHASES:
            value = target(phase)
            model.validate(value, 123, phase)
            for key in ('pid', 'base', 'control', 'staging', 'cleared_frames', 'completed', 'active'):
                for bad in (True, '1', -1, 2**64):
                    with self.subTest(phase=phase, key=key, bad=bad), self.assertRaises(ProbeError):
                        model.validate(value | {key: bad}, 123, phase)
            for key in ('active', 'cleared_frames', 'completed'):
                with self.assertRaises(ProbeError): model.validate(value | {key: value[key] + 1}, 123, phase)
            for bad in (value | {'extra': 1}, value | {'pid': 124}, value | {'output_verified': not value['output_verified']}):
                with self.assertRaises(ProbeError): model.validate(bad, 123, phase)

    def test_window_bounds_population_locking_and_control_aliases(self):
        value = target('workers')
        for windows in ([], value['windows'][:4], value['windows'] + [value['windows'][0]]):
            with self.assertRaises(ProbeError): model.validate(value | {'windows': windows}, 123, 'workers')
        for key, bad in (('low', True), ('low', 0x10000000), ('low', 0x1fff0000),
                         ('low', 0x10010001), ('low', 2**64), ('locked_pages', 15), ('locked_pages', True)):
            changed = copy.deepcopy(value)
            changed['windows'][0][key] = bad
            with self.assertRaises(ProbeError): model.validate(changed, 123, 'workers')
        for key, bad in (('control', 0x10010000), ('staging', 0x30000001), ('base', 1)):
            with self.assertRaises(ProbeError): model.validate(value | {key: bad}, 123, 'workers')

    def process(self, code, out, err=''):
        process = Mock(pid=123, returncode=code)
        process.communicate.return_value = out, err
        return process, Mock(__enter__=Mock(return_value=process), __exit__=Mock(return_value=False))

    def test_exact_exit_clean_checkpoint_and_environment(self):
        for code, out, err in ((0, json.dumps(target()), ''), (1, json.dumps(target()), ''),
                               (0xc0000602, '{}', ''), (0xc0000602, json.dumps(target()), 'failure'),
                               (0xc0000602, 'x' * 16384, '')):
            _, context = self.process(code, out, err)
            with patch.object(runner.subprocess, 'Popen', return_value=context), self.assertRaises((ProbeError, ValueError)):
                runner.run_child('owned.exe', 'image.dll', 'root')
        _, context = self.process(0xc0000602, json.dumps(target()))
        with patch.dict(os.environ, {'UNRELATED_TOKEN': 'synthetic', 'SYSTEMROOT': 'C:/Windows'}):
            with patch.object(runner.subprocess, 'Popen', return_value=context) as spawn:
                self.assertEqual(runner.run_child('owned.exe', 'image.dll', 'root')[0], target())
                self.assertNotIn('UNRELATED_TOKEN', spawn.call_args.kwargs['env'])

    def test_timeout_kills_only_owned_child(self):
        process, context = self.process(None, '')
        process.communicate.side_effect = [subprocess.TimeoutExpired('owned', 90), ('', '')]
        with patch.object(runner.subprocess, 'Popen', return_value=context), self.assertRaises(RuntimeError):
            runner.run_child('owned.exe', 'image.dll', 'root')
        process.kill.assert_called_once_with()
        self.assertEqual(process.communicate.call_count, 2)

    def test_owned_dump_required_and_cleanup_on_analysis_failure(self):
        for mode in ('missing', 'malformed', 'valid'):
            with tempfile.TemporaryDirectory() as directory:
                original = Path(directory) / 'python.exe'
                original.write_bytes(b'synthetic interpreter')
                policies = []

                @contextmanager
                def policy(registry, name, folder):
                    self.assertRegex(name, runner.wer.APP)
                    policies.append(('installed', name, folder))
                    try:
                        if mode != 'missing':
                            data = b'bad' if mode == 'malformed' else blob(regions('root'))
                            (folder / (name + '.123.dmp')).write_bytes(data)
                        yield
                    finally: policies.append(('removed', name, folder))

                with patch.dict(runner.sys.modules, {'winreg': Mock()}), \
                        patch.object(runner, 'sys', SimpleNamespace(executable=str(original))), \
                        patch.object(runner.wer, 'application_policy', policy), \
                        patch.object(runner, 'run_child', return_value=(target(), 0xc0000602)):
                    if mode == 'valid':
                        self.assertTrue(runner.run('image.dll', 'root', EXPECTED)['raw_dump_removed'])
                    else:
                        with self.assertRaises(ProbeError): runner.run('image.dll', 'root', EXPECTED)
                self.assertEqual([item[0] for item in policies], ['installed', 'removed'])
                self.assertFalse(policies[0][2].exists())
                self.assertEqual(list(Path(directory).iterdir()), [original])


if __name__ == '__main__': unittest.main()
