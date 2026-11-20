//! Explicit source-only secondary round-skip control; never a Cargo feature.
extern crate std;
use core::cell::Cell;

std::thread_local! {
    static PLAN: Cell<Option<(usize, bool)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        PLAN.set(None);
    }
}

pub(crate) fn plan(step: usize, inverse: bool) -> Reset {
    assert!(PLAN.get().is_none());
    PLAN.set(Some((step, inverse)));
    HITS.set(0);
    Reset
}

pub(crate) fn hits() -> usize {
    HITS.get()
}

pub(super) fn skip_substitution(step: usize, inverse: bool) -> bool {
    if PLAN.get() == Some((step, inverse)) {
        HITS.set(HITS.get().wrapping_add(1));
        true
    } else {
        false
    }
}
