#!/usr/bin/env python3
"""Native DOS-alias race against the shipping Pin and Windows API wrappers.

Image parsing is replaced by a deterministic public-byte admission seam so the
alias can change precisely after inspection. This is file-binding evidence, not
signature or enclave qualification. Real enclave loading is tested separately.
"""
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave/native'
FIXTURE = r'''
#![allow(dead_code)]
#[derive(Debug)] enum Error { Bounds, Image, Platform, Protocol, Release, Signature }
struct ImagePolicy;
mod protocol;
mod image {
    pub fn admit(bytes: &[u8], _: &crate::ImagePolicy) -> Result<(), crate::Error> {
        assert_eq!(bytes, &[1; 512]);
        let args: Vec<_> = std::env::args().collect();
        assert!(std::process::Command::new("subst").args([&args[1], "/D"]).status().unwrap().success());
        assert!(std::process::Command::new("subst").args([&args[1], &args[2]]).status().unwrap().success());
        Ok(())
    }
    pub fn admit_threads(b: &[u8], p: &crate::ImagePolicy, _: u32) -> Result<(), crate::Error> { admit(b,p) }
}
mod native {
    use crate::protocol;
    mod pin;
    mod sys;
    pub fn check() {
        use std::os::windows::ffi::OsStringExt;
        let alias = std::env::args().nth(1).unwrap();
        let named = format!("{alias}\\worker.dll");
        let pin = pin::Pin::open(std::path::Path::new(&named), &crate::ImagePolicy).unwrap();
        assert_eq!(std::fs::read(&named).unwrap(), &[2; 512]); // redirected during admission
        let path = std::ffi::OsString::from_wide(&pin.location[..pin.location.len()-1]);
        assert!(path.to_string_lossy().starts_with(r"\\?\Volume{"));
        assert_eq!(std::fs::read(&path).unwrap(), &[1; 512]);
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(pin);
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
    }
}
fn main() { native::check(); }
'''


def run():
    if os.name != 'nt':
        raise RuntimeError('native Windows test; refusing to report a skipped pass')
    used = ctypes.windll.kernel32.GetLogicalDrives()
    if not used:
        raise RuntimeError('cannot enumerate drive aliases')
    letter = next((chr(i + 65) for i in range(25, 16, -1) if not used & (1 << i)), None)
    if letter is None:
        raise RuntimeError('no unused drive letter for isolated test')
    alias = letter + ':'
    with tempfile.TemporaryDirectory(prefix='brynja-pin-race-') as name:
        root = Path(name)
        (root / 'native').mkdir()
        (root / 'original').mkdir()
        (root / 'replacement').mkdir()
        (root / 'original/worker.dll').write_bytes(bytes([1]) * 512)
        (root / 'replacement/worker.dll').write_bytes(bytes([2]) * 512)
        for part in ('pin.rs', 'sys.rs'):
            shutil.copyfile(SOURCE / part, root / 'native' / part)
        shutil.copyfile(SOURCE.parent / 'protocol.rs', root / 'protocol.rs')
        (root / 'main.rs').write_text(FIXTURE)
        original = (root / 'native/pin.rs').read_text()
        for level in ('0', '2'):
            for mutant in (False, True):
                changed = original.replace('canonical.location.push(0);',
                    'canonical.location = pin.location.clone(); canonical.location.push(0);')
                if changed == original:
                    raise AssertionError('missing load-name mutant anchor')
                (root / 'native/pin.rs').write_text(changed if mutant else original)
                binary = root / 'probe.exe'
                subprocess.run(['rustc', '+1.98.1', '--edition=2024', '-Dwarnings',
                                '-C', 'opt-level=' + level, str(root / 'main.rs'), '-o', str(binary)],
                               check=True, timeout=90)
                subprocess.run(['subst', alias, str(root / 'original')], check=True, timeout=10)
                try:
                    result = subprocess.run([str(binary), alias, str(root / 'replacement')],
                                            capture_output=True, text=True, timeout=30)
                    if result.returncode != (101 if mutant else 0):
                        raise AssertionError(result.stdout + result.stderr)
                    if mutant and 'assertion failed' not in result.stderr:
                        raise AssertionError('mutant did not fail an assertion: ' + result.stderr)
                finally:
                    subprocess.run(['subst', alias, '/D'], check=True, timeout=10)
    print('Native image binding: O0/O2 DOS-alias redirection rejected; two path mutants rejected')


if __name__ == '__main__':
    run()
