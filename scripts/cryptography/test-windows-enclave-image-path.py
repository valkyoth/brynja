#!/usr/bin/env python3
"""Native DOS/GUID/GLOBALROOT races against the shipping Pin and Windows APIs.

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
import sys

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
    use crate::Error;
    use crate::protocol;
    mod pin;
    mod sys;
    mod namespace;
    pub fn check() {
        use std::os::windows::ffi::OsStringExt;
        let alias = std::env::args().nth(1).unwrap();
        let named = format!("{alias}\\worker.dll");
        let pin = pin::Pin::open(std::path::Path::new(&named), &crate::ImagePolicy).unwrap();
        assert_eq!(std::fs::read(&named).unwrap(), &[2; 512]); // redirected during admission
        let path = std::ffi::OsString::from_wide(&pin.location[..pin.location.len()-1]);
        assert!(path.to_string_lossy().starts_with(r"\\?\BrynjaImage-"));
        assert!(std::fs::File::open(&path).is_ok(), "loader alias retired before use");
        let args: Vec<_> = std::env::args().collect();
        use std::os::windows::io::AsRawHandle;
        let original = std::fs::File::open(&args[3]).unwrap();
        let canonical = std::ffi::OsString::from_wide(&sys::volume_path(original.as_raw_handle()).unwrap());
        let globalroot = args[4].starts_with("globalroot");
        let shadow = if globalroot {
            crate::shadow::Shadow::globalroot(&canonical, &args[2])
        } else {
            let shadow = crate::shadow::Shadow::new(&args[3], &args[2]);
            assert_eq!(std::fs::read(&shadow.path).unwrap(), b"guid-redirected");
            shadow
        };
        assert_eq!(std::fs::read(&path).unwrap(), &[1; 512]);
        if globalroot { println!("GLOBALROOT_CANONICAL_READ: original; write_guard=checked_below"); }
        assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
        drop(pin);
        assert!(std::fs::read(&path).is_err()); // temporary alias retired
        drop(original);
        assert!(std::fs::OpenOptions::new().write(true).open(&args[3]).is_ok());
        drop(shadow);
    }
}
fn main() { native::check(); }
'''
SHADOW = r'''
mod shadow {
    use std::os::windows::io::AsRawHandle;
    unsafe extern "system" {
        fn GetFinalPathNameByHandleW(h: *mut core::ffi::c_void, p: *mut u16, n: u32, f: u32) -> u32;
        fn DefineDosDeviceW(flags: u32, name: *const u16, target: *const u16) -> i32;
        fn GetLastError() -> u32;
    }
    pub struct Shadow { name: Vec<u16>, target: Vec<u16>, pub path: String, active: bool }
    impl Shadow {
        pub fn new(original: &str, replacement: &str) -> Self {
            let file = std::fs::File::open(original).unwrap();
            let mut buffer = [0u16;1024];
            let n = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), buffer.as_mut_ptr(), 1024, 1) };
            assert!(n > 0 && n < 1024);
            let path = String::from_utf16(&buffer[..n as usize]).unwrap();
            assert!(path.starts_with(r"\\?\Volume{"));
            let redirected = std::path::Path::new(replacement).join(&path[49..]);
            std::fs::create_dir_all(redirected.parent().unwrap()).unwrap();
            std::fs::write(redirected, b"guid-redirected").unwrap();
            let name: Vec<u16> = path[4..48].encode_utf16().chain(Some(0)).collect();
            let target: Vec<u16> = format!(r"\??\{replacement}").encode_utf16().chain(Some(0)).collect();
            assert_ne!(unsafe { DefineDosDeviceW(9, name.as_ptr(), target.as_ptr()) }, 0);
            Self { name, target, path, active: true }
        }
        pub fn globalroot(canonical: &std::ffi::OsStr, replacement: &str) -> Self {
            let canonical = canonical.to_str().unwrap();
            let suffix = canonical.strip_prefix(r"\\?\GLOBALROOT\").unwrap();
            let redirected = std::path::Path::new(replacement).join(suffix);
            std::fs::create_dir_all(redirected.parent().unwrap()).unwrap();
            std::fs::write(&redirected, b"globalroot-redirected").unwrap();
            let name: Vec<u16> = "GLOBALROOT".encode_utf16().chain(Some(0)).collect();
            let target: Vec<u16> = format!(r"\??\{replacement}").encode_utf16().chain(Some(0)).collect();
            let active = unsafe { DefineDosDeviceW(9, name.as_ptr(), target.as_ptr()) } != 0;
            let error = if active { 0 } else { unsafe { GetLastError() } };
            assert!(active || error != 0);
            // Either refusal or an ineffective local alias is acceptable. The
            // shipping canonical path must still read the original in both cases.
            println!("GLOBALROOT_SHADOW: created={active}; error={error}");
            Self { name, target, path: redirected.to_str().unwrap().to_owned(), active }
        }
    }
    impl Drop for Shadow {
        fn drop(&mut self) {
            if self.active {
                assert_ne!(unsafe { DefineDosDeviceW(15, self.name.as_ptr(), self.target.as_ptr()) }, 0);
            }
        }
    }
}
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
        for part in ('pin.rs', 'sys.rs', 'namespace.rs'):
            shutil.copyfile(SOURCE / part, root / 'native' / part)
        shutil.copyfile(SOURCE.parent / 'protocol.rs', root / 'protocol.rs')
        (root / 'main.rs').write_text(FIXTURE + SHADOW)
        original = (root / 'native/pin.rs').read_text()
        for level in ('0', '2'):
            for mutant in ('none', 'dos', 'guid', 'globalroot', 'globalroot-redirect', 'early-alias-drop'):
                changed = original.replace('canonical.location = location;',
                    'canonical.location = pin.location.clone(); canonical.location.push(0);')
                if changed == original:
                    raise AssertionError('missing load-name mutant anchor')
                early = original.replace('canonical.namespace = Some(namespace);', 'drop(namespace);')
                if early == original:
                    raise AssertionError('missing namespace-lifetime mutant anchor')
                (root / 'native/pin.rs').write_text(
                    changed if mutant == 'dos' else early if mutant == 'early-alias-drop' else original)
                # Model the old GUID load after all checks, then mutate that
                # GUID alias in the same logon session before opening the name.
                fixture = FIXTURE
                if mutant in ('guid', 'globalroot-redirect'):
                    fixture = fixture.replace('std::fs::read(&path).unwrap(), &[1; 512]',
                                              'std::fs::read(&shadow.path).unwrap(), &[1; 512]')
                (root / 'main.rs').write_text(fixture + SHADOW)
                print(f'Native namespace probe: O{level}; {mutant}', flush=True)
                binary = root / f'probe-{level}-{mutant}.exe'
                subprocess.run(['rustc', '+1.98.1', '--edition=2024', '-Dwarnings',
                                '-C', 'opt-level=' + level, str(root / 'main.rs'), '-o', str(binary)],
                               check=True, timeout=90, stdout=sys.stdout, stderr=sys.stderr)
                subprocess.run(['subst', alias, str(root / 'original')], check=True, timeout=10)
                try:
                    result = subprocess.run([str(binary), alias, str(root / 'replacement'),
                                             str(root / 'original/worker.dll'), mutant],
                                            capture_output=True, text=True, timeout=30)
                    negative = mutant in ('dos', 'guid', 'globalroot-redirect', 'early-alias-drop')
                    if result.returncode != (101 if negative else 0):
                        raise AssertionError(result.stdout + result.stderr)
                    if negative and not any(token in result.stderr for token in (
                            'assertion', 'loader alias retired before use')):
                        raise AssertionError('mutant did not fail an assertion: ' + result.stderr)
                    if mutant == 'globalroot':
                        if ('GLOBALROOT_SHADOW:' not in result.stdout or
                                'GLOBALROOT_CANONICAL_READ: original' not in result.stdout):
                            raise AssertionError('GLOBALROOT experiment was not executed')
                        print(result.stdout, end='', flush=True)
                finally:
                    subprocess.run(['subst', alias, '/D'], check=True, timeout=10)
    print('Native image binding: O0/O2 DOS, GUID and GLOBALROOT alias checks PASS; eight mutants rejected')


if __name__ == '__main__':
    if os.name != 'nt':
        raise RuntimeError('native Windows test; refusing to report a skipped pass')
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
