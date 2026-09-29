#!/usr/bin/env python3
"""Composed private worker checks; OS calls are stubs, not native evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_rehash_worker_build as build


class Tests(unittest.TestCase):
    def test_composed_worker_with_real_owners_and_mutants(self):
        target=next(line[6:] for line in subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).splitlines() if line.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='retained-rehash-worker-') as tmp:
            directory=Path(tmp);build.prepare(directory,target,True)
            for name in ('normal','scratch','token','generation'):
                build.compile(directory,target,True,name)
                result=subprocess.run([str(directory/(name+'-test'))],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode==0,name=='normal',result.stdout+result.stderr)
                self.assertIn('4 passed' if name=='normal' else 'native_composition_checks_scratch_before_accepting_result ... FAILED',result.stdout)


if __name__=='__main__':unittest.main()
