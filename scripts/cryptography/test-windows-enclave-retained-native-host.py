#!/usr/bin/env python3
"""Private native-adapter tests with an explicitly mocked OS ABI, not native evidence."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import windows_enclave_retained_native_host_build as build
import windows_enclave_retained_native_host_run as native


class Tests(unittest.TestCase):
    def test_prelock_nonresident_page_is_not_postlock_admission(self):
        with tempfile.TemporaryDirectory(prefix='retained-page-admission-') as tmp:
            directory=Path(tmp)
            original=(build.SOURCE/'retained_page_admission.h').read_text()
            anchor='return required ? (valid && locked) : !(valid && locked);'
            self.assertEqual(original.count(anchor),1)
            program='''#include "policy.h"
int main(void) {
    unsigned v,l,r;
    for(v=0;v<2;++v) for(l=0;l<2;++l) for(r=0;r<2;++r) {
        int expected=r ? (v==1 && l==1) : (v==0 || l==0);
        if(retained_page_accepts(v,l,r)!=expected) return 1;
    }
    return 0;
}
'''
            (directory/'test.c').write_text(program)
            for level in ('0','2'):
                for mutant in (None,'return valid && (locked == required);','return 1;'):
                    (directory/'policy.h').write_text(original.replace(anchor,mutant) if mutant else original)
                    subprocess.run(['cc','-std=c11','-O'+level,str(directory/'test.c'),'-o',str(directory/'test')],
                                   check=True,capture_output=True,timeout=30)
                    result=subprocess.run([str(directory/'test')],timeout=30)
                    self.assertEqual(result.returncode==0,mutant is None)

    def test_native_campaign_requires_exact_counters_and_failure_exits(self):
        for name, expected in native.EXPECTED.items():
            value=dict(zip(native.FIELDS,expected[1:]))
            native.validate(value,name,expected[0])
            for key in native.FIELDS:
                for replacement in (value[key]+1, bool(value[key])):
                    changed=dict(value,**{key:replacement})
                    with self.assertRaises(ValueError): native.validate(changed,name,expected[0])
            with self.assertRaises(ValueError): native.validate(value,name,expected[0]+1)
            with self.assertRaises(ValueError): native.validate(dict(value,extra=0),name,expected[0])

    def test_native_adapter_reports_ownership_and_teardown(self):
        with tempfile.TemporaryDirectory(prefix='retained-native-adapter-') as tmp:
            directory=Path(tmp)
            build.prepare(directory)
            shutil.copyfile(build.SOURCE / 'retained_native_adapter_tests.rs', directory / 'retained_native_adapter_tests.rs')
            source=directory / 'retained_native_host.rs'
            original=source.read_text()
            anchor='result != 1 || report != expected'
            self.assertEqual(original.count(anchor),1)
            for level in ('0','2'):
                for mutant in (False,True):
                    source.write_text(original.replace(anchor,'result != 1 || expected == [0; 4]') if mutant else original)
                    result=subprocess.run(['rustc','+1.98.1','--edition=2024','--test','-D','warnings',
                        '-C','opt-level='+level,str(source),'-o',str(directory/'tests')],
                        capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode==0,not mutant,result.stdout+result.stderr)
                    self.assertIn('every_native_report_field_is_required ... FAILED' if mutant else '6 passed',result.stdout)

    def test_generation_anchors_reject_missing_or_ambiguous_input(self):
        for source in ('','before before'):
            with self.assertRaises(ValueError): build.replace(source,'before','after')
        self.assertEqual(build.replace('before','before','after'),'after')


if __name__=='__main__': unittest.main()
