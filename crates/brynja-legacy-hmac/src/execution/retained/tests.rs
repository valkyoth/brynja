//! Synthetic owner-lifetime checks inside the real private implementation.
extern crate std;
use super::{Error, Retained};
use core::cell::Cell;
use std::boxed::Box;

struct Owner<'a>(&'a Cell<bool>);
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn expected_rejection_preserves_both_owners_but_fatal_error_destroys_both() -> Result<(), Error> {
    let left = Cell::new(false);
    let right = Cell::new(false);
    let mut slot = Retained::new((Owner(&left), Owner(&right)));
    slot.update(|_| Ok(()))?;
    assert_eq!(
        slot.update(|_| Err(Error::MessageTooLong)),
        Err(Error::MessageTooLong)
    );
    assert!(!left.get() && !right.get());
    assert_eq!(
        slot.update(|_| Err(Error::ExecutionFailed)),
        Err(Error::ExecutionFailed)
    );
    assert!(left.get() && right.get());
    let invoked = Cell::new(false);
    assert_eq!(
        slot.update(|_| {
            invoked.set(true);
            Ok(())
        }),
        Err(Error::ExecutionFailed)
    );
    assert!(!invoked.get());
    assert!(matches!(slot.take(), Err(Error::ExecutionFailed)));
    Ok(())
}

#[test]
fn recoverable_unwind_destroys_both_owners_and_is_terminal() {
    let left = Cell::new(false);
    let right = Cell::new(false);
    let mut slot = Retained::new((Owner(&left), Owner(&right)));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        slot.update(|_| std::panic::resume_unwind(Box::new("synthetic private-owner fault")))
    }));
    assert!(result.is_err());
    assert!(left.get() && right.get());
    assert!(matches!(slot.take(), Err(Error::ExecutionFailed)));
}

#[test]
fn success_transfers_ownership_and_cancellation_drops_it() -> Result<(), Error> {
    let left = Cell::new(false);
    let right = Cell::new(false);
    let slot = Retained::new((Owner(&left), Owner(&right)));
    let owners = slot.take()?;
    assert!(!left.get() && !right.get());
    drop(owners);
    assert!(left.get() && right.get());
    left.set(false);
    right.set(false);
    drop(Retained::new((Owner(&left), Owner(&right))));
    assert!(left.get() && right.get());
    Ok(())
}
