extern crate std;
use super::*;
use std::{cell::RefCell, vec::Vec};
include!("retained_native_vectors.rs");

#[derive(Default)]
struct Ledger {
    live: bool,
    case: usize,
    calls: Vec<u64>,
    close_calls: usize,
    corrupt: Option<(u64, usize)>,
    fail_clear: bool,
    fail_close: bool,
    lost_begin: bool,
    retired: bool,
}
std::thread_local! { static MOCK: RefCell<Ledger> = RefCell::new(Ledger::default()); }
fn reset() {
    MOCK.with(|l| *l.borrow_mut() = Ledger::default());
}
#[unsafe(no_mangle)]
extern "C" fn HostOpen(_: *const u16) -> *mut c_void {
    core::ptr::without_provenance_mut(4096)
}
#[unsafe(no_mangle)]
extern "C" fn HostClose(_: *mut c_void) -> i32 {
    MOCK.with(|l| {
        let mut l = l.borrow_mut();
        l.close_calls += 1;
        assert!(
            !l.live,
            "cannot delete instead of destroying retained owner"
        );
        if l.fail_close {
            0
        } else {
            l.retired = true;
            1
        }
    })
}
#[unsafe(no_mangle)]
extern "C" fn HostCounter(_: u64) -> u64 {
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn RetainedRun(
    _: *mut c_void,
    operation: u64,
    output: *mut u8,
    report: *mut [u64; 4],
) -> i32 {
    MOCK.with(|l| {
        let mut l = l.borrow_mut();
        l.calls.push(operation);
        let op = operation & 255;
        let mut value = match op {
            0 => {
                l.live = true;
                [1, 0, 0, 0]
            }
            1 => {
                l.case = (operation >> 8) as usize;
                [2, 1, 0, 0]
            }
            2 => {
                // SAFETY: private synchronous adapter supplies its full live staging.
                unsafe { output.cast::<[u8; 32]>().write(DIGESTS[l.case]) };
                [3, 0, 0, 0]
            }
            3 => {
                if l.fail_clear {
                    return 0;
                }
                l.live = false;
                [4, 0, 4096, 1]
            }
            4 => [5, 0, 0, 0],
            6 => [105, 0, 0, 0],
            _ => return 0,
        };
        if let Some((which, field)) = l.corrupt {
            if op == which {
                value[field] ^= 1;
            }
        }
        // SAFETY: private synchronous adapter supplies exclusive initialized report.
        unsafe { report.write(value) };
        if op == 0 && l.lost_begin { 0 } else { 1 }
    })
}
fn vector() -> PublicVector {
    PublicVector::new(1).unwrap()
}

#[test]
fn export_and_cancel_require_page_destruction_before_receipt() {
    reset();
    let mut owner = open(&[65, 0], 0).unwrap();
    let mut output = [0xcc; 32];
    owner
        .begin(vector())
        .unwrap()
        .export_public(&mut output)
        .unwrap();
    assert_eq!(output, DIGESTS[1]);
    assert_eq!(owner.state(), State::Ready);
    owner.begin(vector()).unwrap().cancel().unwrap();
    MOCK.with(|l| {
        let l = l.borrow();
        assert_eq!(l.calls, [0, 257, 2, 3, 0, 257, 4, 3]);
        assert_eq!(l.close_calls, 0);
    });
    owner.close().unwrap();
    drop(owner);
    MOCK.with(|l| assert_eq!(l.borrow().close_calls, 1));
}
#[test]
fn every_native_report_field_is_required() {
    for op in [0, 1, 2, 3, 4] {
        for field in 0..4 {
            reset();
            MOCK.with(|l| l.borrow_mut().corrupt = Some((op, field)));
            let mut owner = open(&[65, 0], 0).unwrap();
            let mut output = [0xcc; 32];
            let result = match owner.begin(vector()) {
                Err(error) => Err(error),
                Ok(pending) if op == 4 => pending.cancel(),
                Ok(pending) => pending.export_public(&mut output),
            };
            assert!(result.is_err(), "op={op} field={field}");
            assert_eq!(owner.state(), State::Quarantined);
            assert_eq!(output, [0xcc; 32]);
            // Lost/malformed replies are not cleanup success; reset only the mock
            // corruption to test a later independently confirmed cleanup attempt.
            MOCK.with(|l| l.borrow_mut().corrupt = None);
            drop(owner);
        }
    }
}
#[test]
fn copy_failure_lost_completion_and_wrong_identity_never_commit() {
    for fault in 1..=3 {
        reset();
        let mut owner = open(&[65, 0], fault).unwrap();
        let mut output = [0xcc; 32];
        assert_eq!(
            owner.begin(vector()).unwrap().export_public(&mut output),
            Err(Error::Protocol)
        );
        assert_eq!(output, [0xcc; 32]);
        assert_eq!(owner.state(), State::Quarantined);
        drop(owner);
        MOCK.with(|l| {
            let l = l.borrow();
            assert!(!l.live);
            assert_eq!(l.close_calls, 1);
        });
    }
}
#[test]
fn failed_page_clearing_retains_actual_resource_without_delete() {
    reset();
    let mut owner = open(&[65, 0], 0).unwrap();
    core::mem::forget(owner.begin(vector()).unwrap());
    MOCK.with(|l| l.borrow_mut().fail_clear = true);
    assert_eq!(owner.close(), Err(Error::Release));
    drop(owner);
    MOCK.with(|l| {
        let l = l.borrow();
        assert!(l.live);
        assert_eq!(l.close_calls, 0);
        assert!(!l.retired);
    });
}
#[test]
fn lost_creation_reply_keeps_cleanup_responsibility() {
    reset();
    MOCK.with(|l| l.borrow_mut().lost_begin = true);
    let mut owner = open(&[65, 0], 0).unwrap();
    assert!(owner.begin(vector()).is_err());
    drop(owner);
    MOCK.with(|l| {
        let l = l.borrow();
        assert_eq!(l.calls, [0, 3]);
        assert_eq!(l.close_calls, 1);
    });
}
#[test]
fn failed_os_delete_retains_pointer_and_all_retries_fail() {
    reset();
    let mut owner = open(&[65, 0], 0).unwrap();
    MOCK.with(|l| l.borrow_mut().fail_close = true);
    assert_eq!(owner.close(), Err(Error::Release));
    assert_eq!(owner.state(), State::Quarantined);
    drop(owner);
    MOCK.with(|l| {
        let l = l.borrow();
        assert_eq!(l.close_calls, 3);
        assert!(!l.retired);
    });
}
