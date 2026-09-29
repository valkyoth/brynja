#!/usr/bin/env python3
"""Regression for native worker's early-rejection cleanup observation."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import windows_enclave_retained_worker_build as build


class Tests(unittest.TestCase):
    def test_busy_and_quarantined_fresh_workspace_and_setup_mutant(self):
        identity = subprocess.check_output(['rustc', '+1.98.1', '-vV'], text=True)
        target = next(line[6:] for line in identity.splitlines() if line.startswith('host: '))
        build.hardened.layout_check()
        with tempfile.TemporaryDirectory(prefix='retained-worker-regression-') as tmp:
            path = Path(tmp)
            build.base.build(path, target, panic='unwind')
            shutil.copyfile(build.base.SOURCE / 'retained_placement.rs', path / 'retained_placement.rs')
            args = build.placement.command(path, target, '2', False)
            args = ['panic=unwind' if arg == 'panic=abort' else arg for arg in args]
            subprocess.run(args, check=True, capture_output=True, timeout=90)
            source = path / 'window_retained.rs'
            original = (build.base.SOURCE / source.name).read_text()
            anchor = 'workspace.with(|state| state.cancel());'
            self.assertEqual(original.count(anchor), 1)
            for level in ('0', '2'):
                for mutant in (False, True):
                    source.write_text(original.replace(anchor, '') if mutant else original)
                    invocation = ['rustc', '+1.98.1', '--edition=2024', '--test', '-D', 'warnings',
                                  '-C', 'opt-level=' + level, '-L', 'dependency=' + str(path)]
                    for dep, archive in [('brynja_core', 'libbrynja_core.rlib'),
                                         ('brynja_hash_sha2', 'libbrynja_hash_sha2.rlib'),
                                         ('persistent_result', 'libpersistent_result_normal.rlib'),
                                         ('retained_placement', 'libretained_placement.rlib')]:
                        invocation += ['--extern', dep + '=' + str(path / archive)]
                    invocation += [str(source), '-o', str(path / 'worker-test')]
                    result = build.placement.run(invocation)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = build.placement.run([str(path / 'worker-test')])
                    self.assertEqual(result.returncode == 0, not mutant, result.stdout + result.stderr)
                    self.assertIn('fresh_workspace_rejections_are_zero_without_masking_post_operation_cleanup ... ' +
                                  ('FAILED' if mutant else 'ok'), result.stdout)


if __name__ == '__main__':
    unittest.main()
