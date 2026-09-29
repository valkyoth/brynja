#!/usr/bin/env python3
"""Focused borrowed-input retained-result tests; no native/platform qualification."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_borrowed_build as build


def host():
    return next(line[6:] for line in subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).splitlines()
                if line.startswith('host: '))


class Tests(unittest.TestCase):
    def test_real_hashes_copy_failures_cleanup_and_five_compiled_mutants(self):
        with tempfile.TemporaryDirectory(prefix='retained-borrowed-') as tmp:
            directory=Path(tmp); target=host()
            _,cases=build.prepare(directory,target,True)
            expected={
                'clear':'independent_vectors_survive_scratch_return_and_copy_only_once',
                'copy':'every_partial_copy_error_or_unwind_clears_and_quarantines',
                'reread':'independent_vectors_survive_scratch_return_and_copy_only_once',
                'width':'independent_vectors_survive_scratch_return_and_copy_only_once',
                'quarantine':'rejected_header_clears_full_capacity_without_copy_and_quarantines',
            }
            for level in ('0','2'):
                for name,cfg in build.VARIANTS.items():
                    build.compile(directory,target,level,True,cfg)
                    result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode==0,name=='normal',result.stdout+result.stderr)
                    self.assertIn('6 passed' if name=='normal' else expected[name]+' ... FAILED',result.stdout)
            print(f'Retained borrowed input: {cases} independent vectors; O0/O2 lifecycle and five compiled mutants.')

    def test_request_borrow_privacy_and_thread_ownership(self):
        with tempfile.TemporaryDirectory(prefix='retained-input-borrow-') as tmp:
            directory=Path(tmp)
            command=['rustc','+1.98.1','--edition=2024','--crate-name','retained_input','--crate-type','rlib',
                     str(build.SOURCE/'retained_input.rs'),'-o',str(directory/'libretained_input.rlib')]
            subprocess.run(command,check=True,capture_output=True,timeout=30)
            prefix='use retained_input::Request;\n'
            start='let mut bytes=[1u8;32]; let request=Request::new(&bytes,1).unwrap(); '
            cases=[('fn test() { '+start+'let _=request.metadata(); drop(request); bytes[0]=2; }',None)]
            cases += [(f'fn bound<T:{trait}>() {{}} fn test() {{ bound::<Request>(); }}','E0277')
                      for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug')]
            cases += [('fn test() { '+start+'bytes[0]=2; let _=request.metadata(); }','E0506'),
                      ("fn test() -> Request<'static> { let bytes=[1;32]; Request::new(&bytes,1).unwrap() }",'E0515'),
                      ('fn test() { '+start+'let _=request.header; }','E0616'),
                      ('fn test() { '+start+'request.metadata()[0]=0; }','E0594')]
            for source,diagnostic in cases:
                path=directory/'consumer.rs'; path.write_text(prefix+source)
                result=subprocess.run(['rustc','+1.98.1','--edition=2024','--crate-type','lib','--emit=metadata',
                    '--extern','retained_input='+str(directory/'libretained_input.rlib'),str(path),
                    '-o',str(directory/'consumer.rmeta')],capture_output=True,text=True,timeout=30)
                if diagnostic:
                    self.assertNotEqual(result.returncode,0,source); self.assertIn(diagnostic,result.stderr)
                else: self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
