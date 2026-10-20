extern crate std;
use super::retained::Retained;
use crate::Error;
use core::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Owner<'a>(&'a Cell<usize>);
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_add(1));
    }
}

#[test]
fn failure_drops_both_owners_and_is_terminal() {
    let drops = Cell::new(0);
    let mut state = Retained::new((Owner(&drops), Owner(&drops)));
    assert_eq!(
        state.update(|_| Err(Error::ExecutionFailed)),
        Err(Error::ExecutionFailed)
    );
    assert_eq!(drops.get(), 2);
    let called = Cell::new(false);
    assert_eq!(
        state.update(|_| {
            called.set(true);
            Ok(())
        }),
        Err(Error::ExecutionFailed)
    );
    assert!(!called.get());
    assert!(state.take().is_err());
    assert_eq!(drops.get(), 2);
}

#[test]
fn unwind_drops_both_owners_and_is_terminal() {
    let drops = Cell::new(0);
    let mut state = Retained::new((Owner(&drops), Owner(&drops)));
    let result = catch_unwind(AssertUnwindSafe(|| {
        state.update(|_| std::panic::resume_unwind(std::boxed::Box::new("injected")))
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 2);
    assert!(state.take().is_err());
}

#[test]
fn atomic_length_rejection_preserves_both_owners() {
    let drops = Cell::new(0);
    let mut state = Retained::new((Owner(&drops), Owner(&drops)));
    assert_eq!(
        state.update(|_| Err(Error::MessageTooLong)),
        Err(Error::MessageTooLong)
    );
    assert_eq!(drops.get(), 0);
    assert_eq!(state.update(|_| Ok(())), Ok(()));
    drop(state.take());
    assert_eq!(drops.get(), 2);
}

#[test]
fn sha3_overflow_is_terminal_not_atomic_length_rejection() {
    assert_eq!(
        super::backends::sha3_error(brynja_hash_sha3::hardened_execution::Error::LengthOverflow),
        Error::ExecutionFailed
    );
}
