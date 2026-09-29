#!/usr/bin/env python3
"""Bounded retained-worker input tests; mocked copy seam is not native evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_input_worker_build as build


class Tests(unittest.TestCase):
    def test_input_snapshot_cleanup_and_native_worker_regressions(self):
        target=next(x[6:] for x in subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).splitlines() if x.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='retained-input-worker-') as tmp:
            directory=Path(tmp); build.prepare(directory,target,True)
            expected={'clear':'oracle_copies_header_once_and_retains_correct_digest',
                      'copy':'partial_header_and_payload_failure_or_unwind_clear_and_quarantine',
                      'reread':'oracle_copies_header_once_and_retains_correct_digest',
                      'sequence':'invalid_sequence_never_reaches_payload_copy'}
            for level in ('0','2'):
                for name in build.VARIANTS:
                    build.compile(directory,target,level,True,name)
                    result=subprocess.run([str(directory/(name+'-test'))],capture_output=True,text=True,timeout=30)
                    self.assertEqual(result.returncode==0,name=='normal',result.stdout+result.stderr)
                    self.assertIn('3 passed' if name=='normal' else expected[name]+' ... FAILED',result.stdout)


if __name__=='__main__': unittest.main()
