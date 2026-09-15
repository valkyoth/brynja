use super::Error;

/// Caller-owned cumulative compression budget and cancellation callback.
/// One scalar block costs one; one AVX2/NEON call costs four/two respectively.
/// Padding is included. Failed/cancelled calls never refund performed work.
pub struct Control<'a> {
    remaining: u64,
    used: u64,
    cancelled: &'a mut dyn FnMut() -> bool,
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn batch_budget_is_atomic_and_never_wraps() {
        let maximum: u64 = kani::any();
        let first: u64 = kani::any();
        let second: u64 = kani::any();
        let mut cancel = || false;
        let mut control = super::Control::new(maximum, &mut cancel);
        for charge in [first, second] {
            let before = (control.remaining(), control.used());
            let accepted = control.charge(charge).is_ok();
            assert_eq!(accepted, charge <= before.0);
            if accepted {
                assert_eq!(control.remaining(), before.0 - charge);
                assert_eq!(control.used(), before.1 + charge);
            } else {
                assert_eq!((control.remaining(), control.used()), before);
            }
            assert_eq!(
                control.remaining().checked_add(control.used()),
                Some(maximum)
            );
        }
    }
}
impl<'a> Control<'a> {
    /// Creates a finite work budget; `u64::MAX` is an explicit large bound.
    pub fn new(maximum_blocks: u64, cancelled: &'a mut dyn FnMut() -> bool) -> Self {
        Self {
            remaining: maximum_blocks,
            used: 0,
            cancelled,
        }
    }
    /// Cumulative block-equivalent work charged through this control.
    pub const fn used(&self) -> u64 {
        self.used
    }
    /// Work still available, including across executor calls.
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
    pub(super) fn poll(&mut self) -> Result<(), Error> {
        if (self.cancelled)() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(super) fn charge(&mut self, blocks: u64) -> Result<(), Error> {
        self.poll()?;
        let remaining = self.remaining.checked_sub(blocks).ok_or(Error::WorkLimit)?;
        let used = self.used.checked_add(blocks).ok_or(Error::WorkLimit)?;
        self.remaining = remaining;
        self.used = used;
        Ok(())
    }
}
