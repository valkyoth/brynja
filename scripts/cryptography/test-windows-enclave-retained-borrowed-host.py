#!/usr/bin/env python3
"""Mocked host ABI and portable report checks; not native qualification."""
import subprocess
import tempfile
from pathlib import Path
import unittest
import windows_enclave_retained_borrowed_host_build as build
import windows_enclave_retained_borrowed_host_run as native


def tests(directory):
    source=(build.SOURCE/'retained_native_adapter_tests.rs').read_text()
    source=build.replace(source,'    case: usize,','    case: usize,\n    epoch: u64,')
    source=build.replace(source,'extern "C" fn RetainedRun(','extern "C" fn RetainedInputRun(')
    source=build.replace(source,'    operation: u64,\n    output:', '    operation: u64,\n    input: *const u8,\n    output:')
    source=build.replace(source,'                l.live = true;', '                l.live = true;\n                l.epoch += 1;')
    source=build.replace(source,'                l.case = (operation >> 8) as usize;\n                [2, 1, 0, 0]',
                         '                assert!(!input.is_null());\n'
                         '                let header = unsafe { &*input.cast::<[u8; 32]>() };\n'
                         '                match retained_input::admit(header, l.epoch) {\n'
                         '                    Err(_) => [120, 1, 0, 0],\n'
                         '                    Ok((1, _)) => [121, 1, 0, 0],\n'
                         '                    Ok((address, length)) => {\n'
                         '                        let message = if length == 0 { &[] } else {\n'
                         '                            unsafe { core::slice::from_raw_parts(address as *const u8, length) }\n'
                         '                        };\n'
                         '                        l.case = MESSAGES.iter().position(|m| *m == message).unwrap();\n'
                         '                        [2, 1, 0, 0]\n'
                         '                    }\n                }')
    source=build.replace(source,'fn vector() -> PublicVector {\n    PublicVector::new(1).unwrap()\n}',
                         'fn vector() -> &\'static [u8] { MESSAGES[1] }')
    source=build.replace(source,'[0, 257, 2, 3, 0, 257, 4, 3]', '[0, 1, 2, 3, 0, 1, 4, 3]')
    source+='''
#[test]
fn borrowed_copy_finishes_before_input_lifetime_ends() {
    reset(); let mut owner = open(&[65, 0], 0).unwrap();
    for (index, message) in MESSAGES.iter().enumerate() {
        let pending = {
            let mut temporary = std::vec::Vec::from(*message);
            let pending = owner.begin(&temporary).unwrap();
            temporary.fill(0); drop(temporary); pending
        };
        let mut output = [0xcc; 32];
        pending.export_public(&mut output).unwrap();
        assert_eq!(output, DIGESTS[index]);
    }
}
#[test]
fn bad_length_never_enters_or_consumes_generation() {
    reset(); let mut owner = open(&[65, 0], 0).unwrap();
    assert!(matches!(owner.begin(&[0; 1025]), Err(Error::Bounds)));
    assert_eq!(owner.state(), State::Ready);
    MOCK.with(|l| assert!(l.borrow().calls.is_empty()));
    owner.begin(vector()).unwrap().cancel().unwrap();
}
#[test]
fn rejected_input_quarantines_but_retains_cleanup_responsibility() {
    for fault in [4, 5] {
        reset(); let mut owner = open(&[65, 0], fault).unwrap();
        assert!(matches!(owner.begin(vector()), Err(Error::Protocol)));
        assert_eq!(owner.state(), State::Quarantined);
        assert!(owner.begin(vector()).is_err());
        owner.close().unwrap(); drop(owner);
        MOCK.with(|l| { let l=l.borrow(); assert_eq!(l.calls,[0,1,3]); assert_eq!(l.close_calls,1); });
    }
}
#[test]
fn abandoned_or_forgotten_input_result_cannot_reopen() {
    for forget in [false, true] {
        reset(); let mut owner = open(&[65, 0], 0).unwrap();
        let pending = owner.begin(vector()).unwrap();
        if forget { core::mem::forget(pending); } else { drop(pending); }
        assert_eq!(owner.state(), if forget { State::Busy } else { State::Quarantined });
        assert!(owner.begin(vector()).is_err()); drop(owner);
        MOCK.with(|l| { let l=l.borrow(); assert_eq!(l.calls,[0,1,3]); assert_eq!(l.close_calls,1); });
    }
}
'''
    (directory/'retained_native_adapter_tests.rs').write_text(source)


class Tests(unittest.TestCase):
    def test_affine_ownership_compilation(self):
        with tempfile.TemporaryDirectory(prefix='retained-borrowed-negative-') as tmp:
            directory=Path(tmp);build.prepare(directory)
            root=directory/'retained_native_host.rs';original=root.read_text()
            positive='let mut owner=open(&[65,0],0).unwrap(); let pending=owner.begin(b"abc").unwrap(); drop(pending); owner.close().unwrap();'
            cases=[(positive,None),
                   ('let mut owner=open(&[65,0],0).unwrap(); let pending=owner.begin(b"abc").unwrap(); owner.close().unwrap(); drop(pending);','E0499'),
                   ('let mut owner=open(&[65,0],0).unwrap(); let pending=owner.begin(b"abc").unwrap(); drop(owner); drop(pending);','E0505')]
            for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
                cases.append(('fn needs<T: '+trait+'>(_:T) {} needs(open(&[65,0],0).unwrap());','E0277'))
                cases.append(('fn needs<T: '+trait+'>(_:T) {} let mut owner=open(&[65,0],0).unwrap(); needs(owner.begin(b"abc").unwrap());','E0277'))
            for body,diagnostic in cases:
                root.write_text(original+'\npub fn compile_probe() { '+body+' }\n')
                result=subprocess.run(['rustc','+1.98.1','--edition=2024','--crate-type','lib','--emit=metadata',
                                       '-D','warnings',str(root),'-o',str(directory/'probe.rmeta')],
                                      capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode==0,diagnostic is None,result.stderr)
                if diagnostic:self.assertIn(diagnostic,result.stderr)

    def test_rust_ownership_copy_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='retained-borrowed-host-') as tmp:
            directory=Path(tmp);build.prepare(directory);tests(directory)
            for level in ('0','2'):
                for cfg,diagnostic in [(None,'10 passed'),('probe_retained_host_reopen_abandoned','abandoned_or_forgotten_input_result_cannot_reopen ... FAILED'),
                                       ('probe_retained_host_early_commit','copy_failure_lost_completion_and_wrong_identity_never_commit ... FAILED'),
                                       ('probe_retained_host_ignore_receipt','copy_failure_lost_completion_and_wrong_identity_never_commit ... FAILED')]:
                    cmd=['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level='+level,
                         str(directory/'retained_native_host.rs'),'-o',str(directory/'tests')]
                    if cfg:cmd+=['--cfg',cfg]
                    compiled=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
                    self.assertEqual(compiled.returncode,0,compiled.stderr)
                    result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=30)
                    self.assertEqual(result.returncode==0,cfg is None,result.stdout+result.stderr)
                    self.assertIn(diagnostic,result.stdout)

    def test_native_results_reject_counter_claim_and_exit_drift(self):
        for name,expected in native.EXPECTED.items():
            value=dict(zip(native.FIELDS,expected[1:]));native.validate(value,name,expected[0])
            for key in native.FIELDS:
                for replacement in (value[key]+1,bool(value[key])):
                    with self.assertRaises(ValueError):native.validate(dict(value,**{key:replacement}),name,expected[0])
            with self.assertRaises(ValueError):native.validate(value,name,expected[0]+1)
            with self.assertRaises(ValueError):native.validate(dict(value,extra=0),name,expected[0])

    def test_c_input_report_fields_and_failure_classes(self):
        program=r'''#include "policy.h"
int main(void) {
    uint64_t initial[11]={1,1,1,1,66000,67000,69000,72000,3,1,7};
    uint64_t r[11]; unsigned i,j;
    for(i=0;i<11;++i) r[i]=initial[i];
    if(!retained_input_report(r,1,2,65536,131072,3,7)) return 1;
    for(i=0;i<11;++i) {
        for(j=0;j<11;++j) r[j]=initial[j];
        r[i]=(i>=4 && i<8)?1:r[i]+1;
        if(retained_input_report(r,1,2,65536,131072,3,7)) return 2;
    }
    for(i=0;i<11;++i) r[i]=initial[i];
    r[2]=r[3]=r[8]=0;
    if(!retained_input_report(r,1,120,65536,131072,3,7)) return 3;
    r[1]=0;
    if(!retained_input_report(r,1,121,65536,131072,3,7)) return 4;
    r[1]=r[2]=1; r[8]=3;
    if(!retained_input_report(r,1,121,65536,131072,3,7)) return 5;
    r[8]=r[2]=0;
    if(retained_input_report(r,1,121,65536,131072,0,7)) return 6;
    for(i=0;i<11;++i) r[i]=0;
    if(!retained_input_report(r,0,1,65536,131072,0,0)) return 7;
    for(i=0;i<11;++i) { r[i]=1; if(retained_input_report(r,0,1,65536,131072,0,0)) return 8; r[i]=0; }
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='retained-input-report-') as tmp:
            directory=Path(tmp);(directory/'test.c').write_text(program)
            original=(build.SOURCE/'retained_input_report.h').read_text()
            mutants=[('r[10] != epoch','0'),('r[9] != 1','0'),('r[0] != 1','0'),
                     ('a < low || a > high || widths[i] > high - a','0')]
            for level in ('0','2'):
                for mutation in [None]+mutants:
                    (directory/'policy.h').write_text(build.replace(original,*mutation) if mutation else original)
                    subprocess.run(['cc','-std=c11','-O'+level,str(directory/'test.c'),'-o',str(directory/'test')],check=True,capture_output=True,timeout=30)
                    result=subprocess.run([str(directory/'test')],timeout=30)
                    self.assertEqual(result.returncode==0,mutation is None,mutation)


if __name__=='__main__':unittest.main()
