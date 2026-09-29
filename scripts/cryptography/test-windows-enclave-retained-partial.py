#!/usr/bin/env python3
"""Prefix selection/observations and exact generation anchors, not native evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_partial_build as build
import windows_enclave_retained_partial_run as native


class Tests(unittest.TestCase):
    def test_exact_native_results(self):
        for expected in native.EXPECTED.values():
            value = dict(zip(native.FIELDS,expected[1:]))
            native.validate(value,expected[0],expected)
            for field in native.FIELDS:
                for bad in (value[field]+1, bool(value[field])):
                    with self.assertRaises(ValueError):
                        native.validate(dict(value,**{field:bad}),expected[0],expected)
            with self.assertRaises(ValueError): native.validate(value,expected[0]+1,expected)

    def test_all_boundaries_and_tampered_observations(self):
        program = r'''#include "policy.h"
int main(void) {
    uint64_t k,n,p=999,r[5],changed[5]; unsigned i,j;
    for(k=1;k<=2;++k)for(n=0;n<=(k==1?32u:1024u);++n){
        uint64_t command=(k<<32)|n;
        if(!partial_copy_plan(command,k-1,k==1?32:1024,&p)||p!=n)return 1;
        if(partial_copy_plan(command,2-k,k==1?1024:32,&p))return 2;
        r[0]=command;r[1]=1;r[2]=n;r[3]=n!=0;r[4]=1;
        if(!partial_copy_report(r,command))return 3;
        for(i=0;i<5;++i){for(j=0;j<5;++j)changed[j]=r[j];++changed[i];
            if(partial_copy_report(changed,command))return 4;}
    }
    p=999;
    if(partial_copy_plan((1ull<<32)|33,0,32,&p)||p!=999)return 5;
    if(partial_copy_plan((2ull<<32)|1025,1,1024,&p)||p!=999)return 6;
    if(partial_copy_plan(3ull<<32,1,1024,&p)||p!=999)return 7;
    if(partial_copy_plan(1ull<<32,0,31,&p)||p!=999)return 8;
    return 0;
}'''
        source = (build.SOURCE/'retained_partial_copy.h').read_text()
        with tempfile.TemporaryDirectory(prefix='retained-partial-tests-') as tmp:
            directory = Path(tmp); (directory/'test.c').write_text(program)
            for level in ('0', '2'):
                for mutation in (None, ('count > size','0'), ('selected != kind + 1','0'),
                                 ('r[2] == count','1'), ('r[3] == (uint64_t)(count != 0)','1'), ('r[4] == 1','1')):
                    (directory/'policy.h').write_text(build.replace(source,*mutation) if mutation else source)
                    subprocess.run(['cc','-std=c11','-O'+level,str(directory/'test.c'),'-o',str(directory/'test')],check=True,capture_output=True,timeout=30)
                    result = subprocess.run([str(directory/'test')],timeout=30)
                    self.assertEqual(result.returncode == 0, mutation is None)

    def test_separate_native_generation(self):
        with tempfile.TemporaryDirectory(prefix='retained-partial-generation-') as tmp:
            directory = Path(tmp)
            build.prepare_image(directory/'image')
            build.prepare_host(directory/'host')
            source = (directory/'image/window_retained_borrowed.c').read_text()
            self.assertEqual(source.count('deliberate failure AFTER'),1)
            self.assertIn('partial_command = 0;',source)
            self.assertIn('EnclaveCopyIntoEnclave(destination, (const void*)source, (SIZE_T)prefix)',source)
            self.assertIn('partial_copy_report(observed, owner->partial_expected)',
                          (directory/'host/retained_native_transport.c').read_text())


if __name__ == '__main__': unittest.main()
