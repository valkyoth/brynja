"""Compile the shipping lifecycle owner against deterministic OS failures."""
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[2] / 'crates/brynja-crypto-cpu-std/src/windows_enclave/native'
HOST = r'''
#![allow(dead_code)]
#[derive(Debug, PartialEq, Eq)] enum Error { Release, Protocol }
mod engine { pub trait Driver { fn close(&mut self) -> Result<(), crate::Error>; } }
mod native {
    use crate::Error;
    use std::cell::Cell;
    struct Entries { registration: usize, input: usize, output: usize }
    struct Pin;
    impl Drop for Pin { fn drop(&mut self) { sys::PINS.with(|v| v.set(v.get()+1)); } }
    struct Backend {
        pin: Option<Pin>, base: usize, initialized: bool, terminated: bool,
        uncertain: bool, registrations_pending: Cell<bool>, thread: u32,
        slot: usize, slot_locked: bool, live: bool,
    }
    impl crate::engine::Driver for Backend {
        // SHIPPING_CLOSE
    }
    impl Backend {
        fn clear(&mut self) -> Result<(), Error> {
            if self.uncertain { Err(Error::Protocol) } else { Ok(()) }
        }
    }
    mod callback {
        pub fn take() -> Result<(), crate::Error> {
            super::sys::TAKEN.with(|v| v.set(v.get()+1)); Ok(())
        }
    }
    mod sys {
        use super::*;
        thread_local! {
            pub static CALLS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
            pub static DESTROY: Cell<usize> = const { Cell::new(0) };
            pub static FAIL: Cell<bool> = const { Cell::new(false) };
            pub static PINS: Cell<usize> = const { Cell::new(0) };
            pub static TAKEN: Cell<usize> = const { Cell::new(0) };
        }
        pub fn thread() -> u32 { 7 }
        pub fn call(entry: usize, value: usize) -> Result<usize, Error> {
            assert_eq!(value, 0);
            CALLS.with(|v| v.borrow_mut().push(entry));
            let fault = std::env::var("BRYNJA_LIFECYCLE_FAULT").unwrap_or_default();
            if fault == entry.to_string() { Err(Error::Protocol) } else { Ok(1) }
        }
        pub fn destroy(base: usize, initialized: bool, terminated: &mut bool) -> Result<(), Error> {
            assert_eq!(base, 0x10000000); assert!(initialized);
            DESTROY.with(|v| v.set(v.get()+1));
            *terminated = true; // deletion may still fail after termination
            if FAIL.with(Cell::get) { Err(Error::Release) } else { Ok(()) }
        }
        pub fn reset() {
            CALLS.with(|v| v.borrow_mut().clear()); DESTROY.with(|v| v.set(0));
            FAIL.with(|v| v.set(false)); PINS.with(|v| v.set(0)); TAKEN.with(|v| v.set(0));
        }
    }
    mod lifecycle;
}
'''
TESTS = r'''
#[cfg(test)] mod regression {
    use super::*;
    fn owner() -> Backend {
        Backend { pin: Some(super::super::Pin), base: 0x10000000,
            initialized: true, terminated: false, uncertain: true,
            registrations_pending: Cell::new(false), thread: 7, slot: 0x10020000,
            slot_locked: true, live: true }
    }
    fn entries() -> Entries { Entries { registration: 1, output: 2, input: 3 } }
    #[test] fn release_quarantined_resources_without_erasure_success() {
        sys::reset();
        let mut owner = owner();
        assert_eq!(owner.close(), Err(Error::Release));
        owner.destroy_quarantined().unwrap();
        assert!(owner.uncertain && owner.terminated);
        assert_eq!(owner.base, 0); assert_eq!(owner.slot, 0);
        assert!(!owner.slot_locked && !owner.live);
        assert!(owner.pin.is_none());
        drop(owner);
        assert_eq!(sys::DESTROY.with(Cell::get), 1);
        assert_eq!(sys::PINS.with(Cell::get), 1);
    }
    #[test] fn drop_uses_quarantined_destruction() {
        sys::reset(); drop(owner());
        assert_eq!(sys::DESTROY.with(Cell::get), 1);
        assert_eq!(sys::PINS.with(Cell::get), 1);
    }
    #[test] fn incomplete_revocation_and_wrong_thread_never_destroy() {
        for pending in [false, true] {
            sys::reset(); let mut owner = owner();
            if pending { owner.registrations_pending.set(true); } else { owner.thread = 8; }
            assert_eq!(owner.destroy_quarantined(), Err(Error::Release));
            assert_eq!(owner.base, 0x10000000); assert!(owner.pin.is_some());
            drop(owner);
            assert_eq!(sys::DESTROY.with(Cell::get), 0);
            assert_eq!(sys::PINS.with(Cell::get), 0);
        }
    }
    #[test] fn deletion_failure_retains_guards_and_allows_retry() {
        sys::reset(); let mut owner = owner(); sys::FAIL.with(|v| v.set(true));
        assert_eq!(owner.destroy_quarantined(), Err(Error::Release));
        assert!(owner.terminated && owner.uncertain && owner.pin.is_some());
        assert_eq!(owner.base, 0x10000000);
        sys::FAIL.with(|v| v.set(false)); owner.destroy_quarantined().unwrap();
        drop(owner);
        assert_eq!(sys::DESTROY.with(Cell::get), 2);
        assert_eq!(sys::PINS.with(Cell::get), 1);
    }
    #[test] fn unrecoverable_deletion_retains_guards() {
        sys::reset(); sys::FAIL.with(|v| v.set(true)); drop(owner());
        assert_eq!(sys::DESTROY.with(Cell::get), 1);
        assert_eq!(sys::PINS.with(Cell::get), 0);
    }
    #[test] fn success_and_unwind_revoke_before_allowing_destruction() {
        for unwind in [false, true] {
            sys::reset(); let owner = owner();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let guard = Registration::new(&entries(), &owner.registrations_pending);
                assert!(owner.registrations_pending.get());
                if unwind { panic!("synthetic unwind"); }
                guard.revoke();
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(!owner.registrations_pending.get());
            assert_eq!(sys::CALLS.with(|v| v.borrow().clone()), [1, 2, 3]);
            assert_eq!(sys::TAKEN.with(Cell::get), usize::from(unwind));
            drop(owner);
            assert_eq!(sys::DESTROY.with(Cell::get), 1);
        }
    }
    #[test] #[ignore] fn fatal_revocation_or_overlap() {
        let pending = Cell::new(std::env::var("BRYNJA_LIFECYCLE_FAULT").unwrap() == "overlap");
        Registration::new(&entries(), &pending).revoke();
        std::process::exit(77); // reaching here is a failed fail-stop contract
    }
}
'''


def check():
    # Every sequential transport must use the same checked registration guard.
    routes = ['mod', 'sha2', 'sha2_batch', 'sha3', 'sha3_batch', 'kmac',
              'tuplehash', 'parallelhash', 'sha256_simd', 'sha512_simd', 'keccak_simd']
    for route in routes:
        text = (SOURCE / (route + '.rs')).read_text()
        assert text.count('Registration::new(&self.entries, &self.registrations_pending)') == 1, route
        assert 'Registration {' not in text, route
    with tempfile.TemporaryDirectory(prefix='brynja-enclave-lifecycle-') as directory:
        root = Path(directory)
        (root / 'native').mkdir()
        backend = (SOURCE / 'mod.rs').read_text()
        close = backend.split('    fn close(&mut self) -> Result<(), Error> {', 1)[1]
        close = '    fn close(&mut self) -> Result<(), Error> {' + close.split('\n}\n', 1)[0]
        (root / 'main.rs').write_text(HOST.replace('        // SHIPPING_CLOSE', close))
        source = (SOURCE / 'lifecycle.rs').read_text()
        path = root / 'native/lifecycle.rs'
        path.write_text(source + TESTS)
        for level in ('0', '2'):
            binary = root / ('tests-' + level + ('.exe' if os.name == 'nt' else ''))
            command = ['rustc', '+1.98.1', '--edition=2024', '--test', '-Dwarnings',
                       '-C', 'opt-level=' + level, str(root / 'main.rs'), '-o', str(binary)]
            subprocess.run(command, check=True, timeout=90)
            subprocess.run([str(binary)], check=True, timeout=30)
            for fault in ('1', '2', '3', 'overlap'):
                env = dict(os.environ, BRYNJA_LIFECYCLE_FAULT=fault)
                result = subprocess.run([str(binary), '--ignored', '--exact',
                    'native::lifecycle::regression::fatal_revocation_or_overlap'],
                    env=env, capture_output=True, timeout=30)
                assert result.returncode in (-6, 0x40000015, 0xC0000409), result.returncode
        for index, (old, new) in enumerate([
            ('|| self.registrations_pending.get()', ''),
            ('self.pending.set(false);', ''),
            ('&& self.destroy_quarantined().is_err()', ''),
            ('sys::destroy(self.base, self.initialized, &mut self.terminated)?;',
             'let _ = sys::destroy(self.base, self.initialized, &mut self.terminated);'),
        ]):
            assert source.count(old) == 1
            path.write_text(source.replace(old, new) + TESTS)
            binary = root / ('mutant-' + str(index) + ('.exe' if os.name == 'nt' else ''))
            command[-1] = str(binary)
            subprocess.run(command, check=True, timeout=90)
            result = subprocess.run([str(binary)], capture_output=True, timeout=30)
            assert result.returncode == 101, result.stdout + result.stderr
    print('Shipping lifecycle: six O0/O2 tests, eight fatal probes, four mutants PASS; mocked OS')


if __name__ == '__main__':
    check()
