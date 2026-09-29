#!/usr/bin/env python3
"""Cross-instance report negatives and isolated generated worker checks."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_cross_build as build
import windows_enclave_retained_cross_run as native


class Tests(unittest.TestCase):
    def test_exact_native_results(self):
        for expected in native.EXPECTED.values():
            value = dict(zip(native.FIELDS,expected[1:]))
            native.validate(value,expected[0],expected)
            for field in native.FIELDS:
                for bad in (value[field]+1,bool(value[field])):
                    with self.assertRaises(ValueError): native.validate(dict(value,**{field:bad}),expected[0],expected)
            with self.assertRaises(ValueError): native.validate(value,expected[0]+1,expected)

    def test_reports(self):
        program = r'''#include "policy.h"
int main(void) {
    uint64_t token[4]={500,2,1,1},copy[6]={1,1,500,2,1,1};
    uint64_t r[9]={66000,68000,69000,1,1,2,2,8,0},bad[9],c[6]; unsigned i,j;
    if(!retained_cross_report(copy,r,token,8,8,65536,131072,1,2))return 1;
    for(i=0;i<9;++i){for(j=0;j<9;++j)bad[j]=r[j];bad[i]=i<3?1:bad[i]+1;
        if(retained_cross_report(copy,bad,token,8,8,65536,131072,1,2))return 2;}
    for(i=0;i<6;++i){for(j=0;j<6;++j)c[j]=copy[j];++c[i];
        if(retained_cross_report(c,r,token,8,8,65536,131072,1,2))return 3;}
    if(retained_cross_report(copy,r,token,8,103,65536,131072,1,2))return 4;
    r[5]=0;r[7]=103;
    if(!retained_cross_report(copy,r,token,103,103,65536,131072,1,2))return 5;
    r[5]=2;if(retained_cross_report(copy,r,token,103,103,65536,131072,1,2))return 6;
    r[5]=0;r[1]=r[0];if(retained_cross_report(copy,r,token,103,103,65536,131072,1,2))return 7;
    return 0;
}'''
        source = (build.SOURCE/'retained_cross_report.h').read_text()
        with tempfile.TemporaryDirectory(prefix='retained-cross-policy-') as tmp:
            directory=Path(tmp);(directory/'test.c').write_text(program)
            for level in ('0','2'):
                for mutation in (None,('status != expected','0'),('copy[i+2] != token[i]','0'),
                                 ('r[3] != 1','0'),('r[8] != 0','0'),('r[5] != 0','0')):
                    (directory/'policy.h').write_text(build.replace(source,*mutation) if mutation else source)
                    subprocess.run(['cc','-std=c11','-O'+level,str(directory/'test.c'),'-o',str(directory/'test')],check=True,capture_output=True,timeout=30)
                    result=subprocess.run([str(directory/'test')],timeout=30)
                    self.assertEqual(result.returncode==0,mutation is None)

    def test_generated_worker_and_decoding(self):
        target=next(s[6:] for s in subprocess.check_output(['rustc','+1.98.1','-vV'],text=True).splitlines() if s.startswith('host: '))
        with tempfile.TemporaryDirectory(prefix='retained-cross-worker-') as tmp:
            directory=Path(tmp)
            build.prepare_image(directory/'image',target,True)
            build.prepare_host(directory/'host')
            source=(directory/'image/retained_input_worker.rs').read_text()
            self.assertIn('core::ptr::addr_of!(INSTANCE_ANCHOR).addr() as u64',source)
            self.assertNotIn('[0x52455441494e, next]',source)
            self.assertIn('owner->cross_expected',(directory/'host/retained_native_transport.c').read_text())
            try: build.worker.compile(directory/'image',target,True)
            except subprocess.CalledProcessError as error: self.fail(error.stderr)
            result=subprocess.run([str(directory/'image/normal-test')],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('5 passed',result.stdout)


if __name__ == '__main__': unittest.main()
