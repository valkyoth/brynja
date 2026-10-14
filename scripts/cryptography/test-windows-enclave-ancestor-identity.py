#!/usr/bin/env python3
"""Native ancestor redirection while the final file name is restored afterward."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave/native'
MAIN = r'''
#![allow(dead_code)]
#[derive(Debug)] enum Error { Bounds, Image, Platform, Protocol, Release, Signature }
struct ImagePolicy;
mod protocol;
mod image {
    pub fn admit(bytes: &[u8], _: &crate::ImagePolicy) -> Result<(), crate::Error> {
        assert_eq!(bytes, &[1; 512]); Ok(())
    }
    pub fn admit_threads(b: &[u8], p: &crate::ImagePolicy, _: u32) -> Result<(), crate::Error> { admit(b,p) }
}
mod native {
    use crate::{Error, protocol};
    mod pin; mod sys; mod namespace;
    pub fn check() {
        let input = std::env::args().nth(1).unwrap();
        let result = pin::Pin::open(std::path::Path::new(&input), &crate::ImagePolicy);
        assert!(matches!(result, Err(Error::Image)), "redirected ancestor accepted");
        assert!(std::fs::OpenOptions::new().write(true).open(input).is_ok(), "error leaked file pin");
        println!("ANCESTOR_IDENTITY: rejected; final namespace restored; pins released");
    }
}
fn main() { native::check(); }
'''
BEFORE = '''        self.directory(end)?;
        let file = self.files.last().ok_or(Error::Image)?;'''
AFTER = r'''        use std::os::windows::ffi::OsStringExt;
        let selected = std::env::args().nth(3).unwrap();
        let root = volume_root(&self.location).unwrap();
        let attack = (selected == "root" && end == root) || (selected == "parent" && end != root);
        let shadow = if attack {
            let mut folder = self.location[..end].to_vec();
            if folder.last() != Some(&92) { folder.push(92); }
            folder.extend("probe-leaf".encode_utf16());
            Some(crate::nt_shadow::Shadow::globalroot(
                &std::ffi::OsString::from_wide(&folder), &std::env::args().nth(2).unwrap()))
        } else { None };
        self.directory(end)?;
        drop(shadow); // Restore GLOBALROOT before any final-file lookup.
        let file = self.files.last().ok_or(Error::Image)?;'''


def instrument(source):
    if source.count(BEFORE) != 1:
        raise ValueError('ancestor acquisition anchor changed')
    return source.replace(BEFORE, AFTER)


def run():
    if os.name != 'nt':
        raise RuntimeError('native Windows required; no skipped pass')
    source = instrument((SOURCE / 'pin.rs').read_text())
    compare = 'if actual.strip_suffix(&[92]).unwrap_or(&actual)'
    if source.count(compare) != 1:
        raise ValueError('ancestor identity comparison changed')
    fixture = (ROOT / 'assurance/windows-enclave-probe/nt_namespace.rs').read_text()
    with tempfile.TemporaryDirectory(prefix='brynja-ancestor-identity-') as directory:
        root = Path(directory)
        (root / 'native').mkdir()
        (root / 'original').mkdir()
        original = root / 'original/worker.dll'
        original.write_bytes(bytes([1]) * 512)
        for part in ('namespace.rs', 'sys.rs'):
            shutil.copyfile(SOURCE / part, root / 'native' / part)
        shutil.copyfile(SOURCE.parent / 'protocol.rs', root / 'protocol.rs')
        (root / 'main.rs').write_text(MAIN + fixture)
        for level in ('0', '2'):
            for mutant in (False, True):
                changed = source.replace(compare, 'if false && actual.strip_suffix(&[92]).unwrap_or(&actual)') if mutant else source
                (root / 'native/pin.rs').write_text(changed)
                exe = root / f'probe-{level}-{mutant}.exe'
                subprocess.run(['rustc', '+1.98.1', '--edition=2024', '-Dwarnings', '-C',
                                'opt-level=' + level, str(root / 'main.rs'), '-o', str(exe)],
                               check=True, timeout=90, stdout=sys.stdout, stderr=sys.stderr)
                for scope in ('root', 'parent'):
                    result = subprocess.run([str(exe), str(original), str(root / 'replacement'), scope],
                                            capture_output=True, text=True, timeout=30)
                    if result.returncode != (101 if mutant else 0):
                        raise AssertionError(result.stdout + result.stderr)
                    if mutant and 'redirected ancestor accepted' not in result.stderr:
                        raise AssertionError('mutant failed for an unrelated reason: ' + result.stderr)
                    if 'GLOBALROOT_SHADOW: direct-nt; created=true;' not in result.stdout:
                        raise AssertionError('redirection was not exercised')
                    print(f'Ancestor identity: O{level}; {scope}; mutant={mutant}: PASS', flush=True)
    print('Native ancestor identity: root/parent; both profiles; four mutants rejected; PASS')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        with open(sys.argv[2], 'w', buffering=1) as log:
            sys.stdout = sys.stderr = log
            try:
                run()
            except BaseException:
                import traceback
                traceback.print_exc()
                sys.exit(1)
    else:
        from windows_enclave_namespace import isolated
        isolated(Path(__file__).resolve())
