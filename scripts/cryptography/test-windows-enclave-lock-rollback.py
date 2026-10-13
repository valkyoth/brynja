#!/usr/bin/env python3
"""Exercise shipping callback acquisition/rollback with deterministic OS faults.

Compiles the actual Rust callback and protocol sources. The mocked OS boundary
does not establish Windows residency or enclave qualification.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/brynja-crypto-cpu-std/src/windows_enclave'
HOST = r'''
#![allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum Error { Bounds, Busy, Platform, Protocol, Release, Worker }
mod protocol;
mod native {
    use crate::protocol;
    pub mod sys {
        use std::cell::RefCell;
        use std::collections::VecDeque;
        #[derive(Debug, PartialEq, Eq)]
        pub enum Call { Pages(usize, usize, bool), Lock(usize, usize, bool) }
        thread_local! {
            static EXPECTED: RefCell<VecDeque<(Call, bool)>> = const { RefCell::new(VecDeque::new()) };
        }
        pub fn expect(calls: Vec<(Call, bool)>) {
            EXPECTED.with(|s| { assert!(s.borrow().is_empty()); *s.borrow_mut() = calls.into(); });
        }
        fn run(call: Call) -> bool {
            EXPECTED.with(|s| {
                let (expected, result) = s.borrow_mut().pop_front().expect("unexpected OS call");
                assert_eq!(call, expected);
                result
            })
        }
        pub fn done() { EXPECTED.with(|s| assert!(s.borrow().is_empty())); }
        pub fn pages(a: usize, n: usize, locked: bool) -> bool { run(Call::Pages(a, n, locked)) }
        pub fn lock(a: usize, n: usize, locked: bool) -> bool { run(Call::Lock(a, n, locked)) }
        pub fn call(_: usize, _: usize) -> Result<usize, crate::Error> { panic!("unexpected dispatch") }
    }
    mod callback;
    mod parallel_concurrent {
        use crate::Error;
        mod scheduler;
        mod callbacks;
    }
}
'''
SEQUENTIAL = r'''
#[cfg(test)] mod rollback_tests {
    use super::*;
    use sys::Call::{Pages, Lock};
    const BASE: usize = 0x10000000;
    const WINDOW: usize = BASE + 4096;
    const OWNER: usize = BASE + 0x20000;
    #[test]
    fn failed_post_lock_checks_roll_back_before_return() {
        for owner in [false, true] {
            for unlocked in [false, true] {
                let (address, count, bytes) = if owner { (OWNER, 1, 4096) } else { (WINDOW, 16, 65536) };
                let mut context = Context { base: BASE, low: WINDOW,
                    phase: u8::from(owner), locked: owner, ..Context::default() };
                sys::expect(vec![(Pages(address, count, false), true),
                    (Lock(address, bytes, true), true), (Pages(address, count, true), false),
                    (Lock(address, bytes, false), unlocked)]);
                install(context).unwrap();
                assert_eq!(callback(address | if owner {8} else {0}), 0);
                context = take().unwrap();
                assert!(context.error);
                assert_eq!(if owner {context.slot_locked} else {context.locked}, !unlocked);
                assert_eq!(if owner {context.slot_phase} else {context.phase}, 0);
                sys::done();
            }
        }
    }
    #[test]
    fn rejected_owner_acquisition_still_allows_window_cleanup_only() {
        install(Context { base: BASE, ..Context::default() }).unwrap();
        sys::expect(vec![(Pages(WINDOW, 16, false), true), (Lock(WINDOW, 65536, true), true),
            (Pages(WINDOW, 16, true), true)]);
        assert_eq!(callback(WINDOW), 1);
        sys::done();
        sys::expect(vec![(Pages(OWNER, 1, false), true), (Lock(OWNER, 4096, true), true),
            (Pages(OWNER, 1, true), false), (Lock(OWNER, 4096, false), true)]);
        assert_eq!(callback(OWNER | 8), 0);
        sys::done();
        // The failure latch must reject all further work and wrong-address release.
        assert_eq!(callback(OWNER | 8), 0);
        assert_eq!(callback(OWNER | 9), 0);
        assert_eq!(callback(OWNER | 10), 0);
        assert_eq!(callback(OWNER | 1), 0);
        sys::expect(vec![(Pages(WINDOW, 16, true), true), (Lock(WINDOW, 65536, false), true)]);
        assert_eq!(callback(WINDOW | 1), 1);
        sys::done();
        let context = take().unwrap();
        assert!(context.error); // cleanup is not operation success
        assert!(!context.locked && !context.slot_locked);
        assert_eq!(context.phase, 2);
    }
    #[test]
    fn failed_acquisition_does_not_unlock_unacquired_pages() {
        for pages_ok in [false, true] {
            let mut expected = vec![(Pages(WINDOW, 16, false), pages_ok)];
            if pages_ok { expected.push((Lock(WINDOW, 65536, true), false)); }
            sys::expect(expected);
            install(Context { base: BASE, ..Context::default() }).unwrap();
            assert_eq!(callback(WINDOW), 0);
            let context = take().unwrap();
            assert!(context.error && !context.locked);
            sys::done();
        }
    }
}
'''
CONCURRENT = r'''
#[cfg(test)] mod rollback_tests {
    use super::*;
    use sys::Call::{Pages, Lock};
    #[test]
    fn every_lane_rolls_back_failed_post_lock_verification() {
        for lane in 0..5 {
            for unlocked in [false, true] {
                let shared = Arc::new(Shared { base: 0x10000000, root: 0, leaf: 0,
                    query: 0, state: 0, register: 0, output: 0, frames: Mutex::default() });
                let low = shared.base + 4096 + lane * 0x20000;
                let installed = Installed::new(Context { shared: Arc::clone(&shared), lane,
                    scheduler: None, generation: 0 }).unwrap();
                sys::expect(vec![(Pages(low, 16, false), true), (Lock(low, 65536, true), true),
                    (Pages(low, 16, true), false), (Lock(low, 65536, false), unlocked)]);
                assert_eq!(callback(low | (lane << 4)), 0);
                sys::done();
                {
                    let frames = shared.frames.lock().unwrap();
                    assert!(frames.failed);
                    assert!(!frames.slots[lane].admitted);
                    assert_eq!(frames.slots[lane].locked, !unlocked);
                    assert_eq!(frames.slots[lane].phase, 1);
                }
                assert_eq!(shared.settled(), Err(Error::Release));
                // A failed rollback retains ownership; the real finish callback
                // may retry. A successful rollback must not unlock twice.
                let mut expected = vec![];
                if !unlocked {
                    expected.push((Pages(low, 16, true), true));
                    expected.push((Lock(low, 65536, false), true));
                }
                expected.push((Pages(low, 16, false), true));
                sys::expect(expected);
                assert_eq!(callback(low | (lane << 4) | 1), 1);
                sys::done();
                let frames = shared.frames.lock().unwrap();
                assert!(frames.failed);
                assert!(!frames.slots[lane].locked);
                assert_eq!(frames.slots[lane].phase, 2);
                drop(frames);
                assert_eq!(shared.settled(), Err(Error::Release)); // receipt still required
                drop(installed);
            }
        }
    }
}
'''


def check():
    with tempfile.TemporaryDirectory(prefix='brynja-lock-rollback-') as temporary:
        root = Path(temporary)
        (root / 'native/parallel_concurrent').mkdir(parents=True)
        (root / 'main.rs').write_text(HOST)
        shutil.copyfile(SOURCE / 'protocol.rs', root / 'protocol.rs')
        shutil.copyfile(SOURCE / 'native/parallel_concurrent/scheduler.rs',
                        root / 'native/parallel_concurrent/scheduler.rs')
        for relative, tests in [('native/callback.rs', SEQUENTIAL),
                                ('native/parallel_concurrent/callbacks.rs', CONCURRENT)]:
            (root / relative).write_text((SOURCE / relative).read_text() + tests)
        binary = root / ('tests.exe' if os.name == 'nt' else 'tests')
        for level in ('0', '2'):
            subprocess.run(['rustc', '+1.98.1', '--edition=2024', '--test', '-Dwarnings',
                            '-C', 'opt-level=' + level, str(root / 'main.rs'), '-o', str(binary)],
                           check=True, timeout=90)
            subprocess.run([str(binary)], check=True, timeout=30)
    print('Shipping callback rollback: O0/O2 fault checks PASS; mocked OS, not native qualification')


if __name__ == '__main__':
    check()
