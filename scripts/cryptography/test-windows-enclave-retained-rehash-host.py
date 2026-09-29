#!/usr/bin/env python3
"""Mocked adapter/report tests are not native execution qualification."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_rehash_host_build as build
import windows_enclave_retained_rehash_host_run as native

spec=importlib.util.spec_from_file_location('borrowed_tests',Path(__file__).with_name('test-windows-enclave-retained-borrowed-host.py'))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)


class Tests(unittest.TestCase):
    def test_affine_composition_failure_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='retained-rehash-host-') as tmp:
            directory=Path(tmp);build.prepare(directory);support.tests(directory)
            path=directory/'retained_native_adapter_tests.rs';source=path.read_text()
            source=build.replace(source,'            4 => [5, 0, 0, 0],',
                                 '            8 => [8, 1, 0, 0],\n            9 => [103, 1, 0, 0],\n            4 => [5, 0, 0, 0],')
            source+='''
#[test]
fn composition_retains_affine_borrow_and_validates_each_report_field() {
    assert_eq!(CHAINS.len(), DIGESTS.len()); assert_ne!(CHAINS[1], DIGESTS[1]);
    for corrupt in [None,Some((8,0)),Some((8,1)),Some((8,2)),Some((8,3))] {
        reset(); MOCK.with(|l|l.borrow_mut().corrupt=corrupt);
        let mut owner=open(&[65,0],0).unwrap(); let pending=owner.begin(vector()).unwrap();
        match pending.rehash() {
            Ok(next) => { assert!(corrupt.is_none()); next.cancel().unwrap(); }
            Err(error) => { assert!(corrupt.is_some()); assert_eq!(error,Error::Protocol); }
        }
        MOCK.with(|l|l.borrow_mut().corrupt=None); owner.close().unwrap();
    }
    reset(); let mut owner=open(&[65,0],6).unwrap();
    assert!(matches!(owner.begin(vector()).unwrap().rehash(),Err(Error::Protocol)));
    assert_eq!(owner.state(),State::Quarantined); drop(owner);
    MOCK.with(|l|assert_eq!(l.borrow().calls,[0,1,8,9,3]));
}
'''
            path.write_text(source)
            for level in ('0','2'):
                result=subprocess.run(['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level='+level,
                                       str(directory/'retained_native_host.rs'),'-o',str(directory/'tests')],capture_output=True,text=True,timeout=60)
                self.assertEqual(result.returncode,0,result.stderr)
                result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertIn('11 passed',result.stdout)

    def test_rehash_report_rejects_field_and_copy_leaks(self):
        program=r'''#include "policy.h"
int main(void) {
    uint64_t good[9]={66000,68000,69000,1,1,2,7,8,0},r[9]; unsigned i,j;
    if(!retained_rehash_report(good,8,8,65536,131072,1,7)) return 1;
    for(i=0;i<9;++i) {
        for(j=0;j<9;++j)r[j]=good[j]; r[i]=i<3?1:r[i]+1;
        if(retained_rehash_report(r,8,8,65536,131072,1,7))return 2;
    }
    for(i=0;i<9;++i)r[i]=good[i]; r[1]=r[0];
    if(retained_rehash_report(r,8,8,65536,131072,1,7))return 3;
    for(i=0;i<9;++i)r[i]=good[i]; r[5]=0;r[7]=103;
    if(!retained_rehash_report(r,9,103,65536,131072,2,7))return 4;
    r[4]=2;if(retained_rehash_report(r,9,103,65536,131072,2,7))return 5;
    for(i=0;i<9;++i)r[i]=0;
    if(!retained_rehash_report(r,1,2,65536,131072,0,7))return 6;
    r[8]=1;if(!retained_rehash_report(r,2,3,65536,131072,1,7))return 7;
    r[0]=1;if(retained_rehash_report(r,2,3,65536,131072,1,7))return 8;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='rehash-report-') as tmp:
            directory=Path(tmp);(directory/'test.c').write_text(program)
            source=(build.SOURCE/'retained_rehash_report.h').read_text()
            for level in ('0','2'):
                for mutation in [None,('r[8] != 0','0'),('r[3] != 1','0'),('r[6] != epoch','0'),('r[5] != generation + 1','0')]:
                    (directory/'policy.h').write_text(build.replace(source,*mutation) if mutation else source)
                    subprocess.run(['cc','-std=c11','-O'+level,str(directory/'test.c'),'-o',str(directory/'test')],check=True,capture_output=True,timeout=30)
                    result=subprocess.run([str(directory/'test')],timeout=30)
                    self.assertEqual(result.returncode==0,mutation is None)

    def test_native_results_are_exact(self):
        for expected in list(native.EXPECTED.values())+list(native.IMAGES.values()):
            value=dict(zip(native.FIELDS,expected[1:]));native.validate(value,expected,expected[0])
            for key in native.FIELDS:
                for change in (value[key]+1,bool(value[key])):
                    with self.assertRaises(ValueError):native.validate(dict(value,**{key:change}),expected,expected[0])
            with self.assertRaises(ValueError):native.validate(value,expected,expected[0]+1)


if __name__=='__main__':unittest.main()
