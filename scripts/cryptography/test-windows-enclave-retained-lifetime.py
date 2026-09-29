#!/usr/bin/env python3
"""Nonrecycled host IDs and affine lifetime negatives, not platform admission."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import windows_enclave_retained_lifetime_build as build
import windows_enclave_retained_lifetime_run as native

spec=importlib.util.spec_from_file_location('borrowed_tests',Path(__file__).with_name('test-windows-enclave-retained-borrowed-host.py'))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)


def adapter_tests(directory):
    support.tests(directory)
    path=directory/'retained_native_adapter_tests.rs'
    source=build.replace(path.read_text(),'            4 => [5, 0, 0, 0],',
        '            8 => [8, 1, 0, 0],\n            9 => [103, 1, 0, 0],\n            4 => [5, 0, 0, 0],')
    # Mock HostOpen intentionally ALWAYS returns address 4096, across resources.
    source+='''
#[test]
fn reused_native_address_has_new_identity_and_stale_receipt_cannot_commit() {
    assert_eq!(CHAINS.len(),DIGESTS.len()); assert_ne!(CHAINS[1],DIGESTS[1]);
    reset(); let mut old=open(&[65,0],0).unwrap(); let previous=old.instance_id();
    old.close().unwrap(); drop(old);
    reset(); let mut replacement=open(&[65,0],7).unwrap();
    assert!(replacement.instance_id()>previous);
    let mut output=[0xcc;32];
    assert_eq!(replacement.begin(vector()).unwrap().export_public(&mut output),Err(Error::Protocol));
    assert_eq!(output,[0xcc;32]); assert_eq!(replacement.state(),State::Quarantined);
    replacement.close().unwrap(); drop(replacement);
    MOCK.with(|l| { let l=l.borrow(); assert_eq!(l.close_calls,1); assert!(!l.live); });
}
#[test]
fn closed_owner_is_terminal_and_never_reenters_native_code() {
    reset(); let mut owner=open(&[65,0],0).unwrap(); owner.close().unwrap();
    assert!(matches!(owner.begin(vector()),Err(Error::Closed)));
    owner.close().unwrap(); drop(owner);
    MOCK.with(|l| { let l=l.borrow(); assert_eq!(l.close_calls,1); assert!(l.calls.is_empty()); });
}
'''
    path.write_text(source)


class Tests(unittest.TestCase):
    def test_exact_native_results(self):
        for expected in native.EXPECTED.values():
            value=dict(zip(native.FIELDS,expected[1:]));native.validate(value,expected[0],expected)
            for field in native.FIELDS:
                for bad in (value[field]+1,bool(value[field])):
                    with self.assertRaises(ValueError):native.validate(dict(value,**{field:bad}),expected[0],expected)
            with self.assertRaises(ValueError):native.validate(value,expected[0]+1,expected)

    def test_counter_mutants(self):
        with tempfile.TemporaryDirectory(prefix='retained-id-mutants-') as tmp:
            directory=Path(tmp)
            source=(build.SOURCE/'retained_instance_id.rs').read_text()
            (directory/'root.rs').write_text('mod retained_instance_id;\n')
            for level in ('0','2'):
                for before,after in [('current.checked_add(1)?','Some(current.wrapping_add(1))?'),
                    ('current.checked_add(1)?','current'),('NonZeroU64::new(current)?','NonZeroU64::new(1)?')]:
                    (directory/'retained_instance_id.rs').write_text(build.replace(source,before,after))
                    subprocess.run(['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level='+level,
                        str(directory/'root.rs'),'-o',str(directory/'test')],check=True,capture_output=True,timeout=30)
                    result=subprocess.run([str(directory/'test')],capture_output=True,text=True,timeout=30)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn('FAILED',result.stdout)

    def test_identity_exhaustion_reuse_concurrency_and_receipts(self):
        with tempfile.TemporaryDirectory(prefix='retained-lifetime-') as tmp:
            directory=Path(tmp);build.prepare(directory);adapter_tests(directory)
            for level in ('0','2'):
                for cfg,failed in [(None,None),('probe_retained_recycled_identity','reused_native_address_has_new_identity'),
                    ('probe_retained_host_ignore_receipt','reused_native_address_has_new_identity')]:
                    command=['rustc','+1.98.1','--edition=2024','--test','-D','warnings','-C','opt-level='+level,
                        str(directory/'retained_native_host.rs'),'-o',str(directory/'tests')]
                    if cfg:command+=['--cfg',cfg]
                    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(result.returncode,0,result.stderr)
                    result=subprocess.run([str(directory/'tests')],capture_output=True,text=True,timeout=30)
                    self.assertEqual(result.returncode==0,failed is None,result.stdout+result.stderr)
                    self.assertIn('15 passed' if failed is None else failed,result.stdout)

    def test_ownership_compilation(self):
        with tempfile.TemporaryDirectory(prefix='retained-lifetime-negative-') as tmp:
            directory=Path(tmp);build.prepare(directory)
            root=directory/'retained_native_host.rs';original=root.read_text()
            cases=[('let mut o=open(&[65,0],0).unwrap(); let p=o.begin(b"abc").unwrap(); drop(p); o.close().unwrap();',None),
                ('let mut o=open(&[65,0],0).unwrap(); let p=o.begin(b"abc").unwrap(); o.close().unwrap(); drop(p);','E0499'),
                ('let mut o=open(&[65,0],0).unwrap(); let p=o.begin(b"abc").unwrap(); drop(o); drop(p);','E0505'),
                ('let p={let mut o=open(&[65,0],0).unwrap(); o.begin(b"abc").unwrap()}; drop(p);','E0597')]
            for trait in ('Send','Sync','Copy','Clone','core::fmt::Debug'):
                for value in ('open(&[65,0],0).unwrap()','o.begin(b"abc").unwrap()'):
                    cases.append(('fn needs<T:'+trait+'>(_:T){} let mut o=open(&[65,0],0).unwrap(); needs('+value+');','E0277'))
            for body,diagnostic in cases:
                root.write_text(original+'\nfn compile_probe(){'+body+'}\n')
                result=subprocess.run(['rustc','+1.98.1','--edition=2024','--crate-type','lib','--emit=metadata',
                    str(root),'-o',str(directory/'probe.rmeta')],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode==0,diagnostic is None,result.stderr)
                if diagnostic:self.assertIn(diagnostic,result.stderr)


if __name__=='__main__':unittest.main()
