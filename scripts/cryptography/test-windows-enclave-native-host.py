#!/usr/bin/env python3
"""Compile the private native bridge against the unchanged safe ledger."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

import windows_enclave_native_host_build as host
import windows_enclave_native_host_run as native


class NativeBridgeTests(unittest.TestCase):
    def test_native_counters_fail_closed(self):
        changes = 0
        for variant in native.VARIANTS + native.MUTANTS:
            if variant == 'normal':
                value = dict(result=0, created=5, deleted=5, calls=63, retained=0, cleanup_errors=0)
            elif variant == 'fail-delete':
                value = dict(result=14, created=1, deleted=0, calls=60, retained=1, cleanup_errors=2)
            elif variant in native.MUTANTS:
                count = 3 if variant == 'early' else 4
                value = dict(result=21, created=count, deleted=count, calls=62 if variant == 'early' else 63,
                             retained=0, cleanup_errors=0)
            else:
                value = dict(result=10, created=1, deleted=1, calls=0, retained=0, cleanup_errors=0)
            native.validate(value, variant)
            for key in value:
                for bad in (value[key] + 1, str(value[key]), bool(value[key])):
                    with self.assertRaises(ValueError):
                        native.validate({**value, key: bad}, variant)
                    changes += 1
            with self.assertRaises(ValueError):
                native.validate({**value, 'extra': 0}, variant)
        self.assertEqual(changes, 126)
        print('Native counter validator: 126 altered/type-confused fields and seven extra-field records rejected.')

    def test_bridge_and_real_cleanup_early_commit_mutants(self):
        with tempfile.TemporaryDirectory(prefix='brynja-native-bridge-') as temporary:
            directory = Path(temporary)
            for name in ('host_session_wire.rs', 'host_session_tests.rs', 'host_native_bridge_tests.rs'):
                shutil.copyfile(host.SOURCE / name, directory / name)
            source = directory / 'bridge.rs'
            source.write_text((host.SOURCE / 'host_session.rs').read_text() + '\n' +
                (host.SOURCE / 'host_native_bridge.rs').read_text().replace('pub(super)', 'pub(crate)') +
                '\n#[path="host_native_bridge_tests.rs"] mod native_tests;\n')
            for level in ('0', '2'):
                for mutation in (None, 'probe_host_ignore_cleanup', 'probe_host_commit_early'):
                    executable = directory / ('bridge.exe' if os.name == 'nt' else 'bridge')
                    command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-C', 'opt-level='+level,
                               str(source), '-o', str(executable)]
                    if mutation:
                        command += ['--cfg', mutation]
                    subprocess.run(command, capture_output=True, check=True, timeout=30)
                    result = subprocess.run([str(executable), 'native_tests::'],
                                            capture_output=True, text=True, timeout=30)
                    if mutation:
                        self.assertNotEqual(result.returncode, 0, mutation)
                        self.assertIn('native_bridge_never_commits_uncertain_output_or_reuses_owner ... FAILED', result.stdout)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('2 passed', result.stdout)
        print('Native bridge: two tests at O0/O2; early-commit and ignored-cleanup mutants rejected. '
              'Native OS execution: NO.')


if __name__ == '__main__':
    unittest.main()
