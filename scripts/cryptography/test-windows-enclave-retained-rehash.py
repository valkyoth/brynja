#!/usr/bin/env python3
"""Component-only secret composition/ownership tests, not platform evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_rehash_build as build


def host():
    return next(line[6:] for line in subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).splitlines()
                if line.startswith('host: '))


class Tests(unittest.TestCase):
    def test_secret_composition_cleanup_and_five_compiled_mutants(self):
        with tempfile.TemporaryDirectory(prefix='retained-rehash-') as tmp:
            directory=Path(tmp);target=host();_,cases=build.prepare(directory,target,True)
            diagnostics={'scratch':'transform_replaces_value_and_generation_without_export',
                         'token':'wrong_cross_owner_and_stale_tokens_never_enter_operation',
                         'failure':'every_partial_failure_or_unwind_clears_old_and_new_result',
                         'commit':'transform_replaces_value_and_generation_without_export',
                         'generation':'transform_replaces_value_and_generation_without_export'}
            for level in ('0','2'):
                for name in build.VARIANTS:
                    build.compile(directory,target,level,True,name)
                    result=subprocess.run([str(directory/'slot-test')],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode==0,name=='normal',result.stdout+result.stderr)
                    self.assertIn('4 passed' if name=='normal' else diagnostics[name]+' ... FAILED',result.stdout)
                    if name=='normal':
                        result=subprocess.run([str(directory/'rehash-test')],capture_output=True,text=True,timeout=60)
                        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                        self.assertIn('3 passed',result.stdout)
            print(f'Secret composition: {cases} inputs / {cases*4} independent chain outputs; O0/O2, five mutants rejected.')

    def test_secret_borrows_cannot_escape_transform(self):
        with tempfile.TemporaryDirectory(prefix='retained-transform-borrows-') as tmp:
            directory=Path(tmp);target=host();build.prepare(directory,target,True);build.compile(directory,target,testing=True)
            prefix='use persistent_result::Slot;\n'
            start='let mut bytes=[0;32]; let mut slot=Slot::new(&mut bytes,[1,2]).unwrap(); let token=slot.fill(|_|true).unwrap(); let mut scratch=[0;32]; '
            cases=[('fn probe() { '+start+'slot.transform_secret(token,&mut scratch,|input,out|{out.copy_from_slice(input);true}).unwrap(); }',None),
                   ('fn probe() { '+start+'let mut escaped=None; slot.transform_secret(token,&mut scratch,|input,_|{escaped=Some(input);true}).unwrap(); let _=escaped; }','E0521'),
                   ('fn probe() { '+start+'slot.transform_secret(token,&mut scratch,|_,_|{let _=slot.cancel(token);true}).unwrap(); }','E0499'),
                   ('fn probe() { '+start+'slot.transform_secret(token,&mut scratch,|_,_|{scratch.fill(0);true}).unwrap(); }','E0499'),
                   ('fn probe() { '+start+'slot.transform_secret(token,&mut scratch,|_,_|{bytes.fill(0);true}).unwrap(); }','E0499')]
            for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
                cases.append(('fn bound<T:'+trait+'>(){} fn probe(){bound::<Slot>();}','E0277'))
            for body,diagnostic in cases:
                (directory/'consumer.rs').write_text(prefix+body)
                result=subprocess.run(['rustc','+1.98.1','--edition=2024','--crate-type','lib','--emit=metadata',
                    '-L','dependency='+str(directory),'--extern','persistent_result='+str(directory/'libpersistent_result_rehash.rlib'),
                    str(directory/'consumer.rs'),'-o',str(directory/'consumer.rmeta')],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode==0,diagnostic is None,result.stderr)
                if diagnostic:self.assertIn(diagnostic,result.stderr)


if __name__=='__main__':unittest.main()
