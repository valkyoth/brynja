//! Typed constructor and budget projections for the private worker checker.
use brynja_legacy_hmac::md5_batch::Md5BatchControl;

#[inline(never)]
pub fn construct<'a>(budget: usize, callback: &'a mut dyn FnMut() -> bool) -> Md5BatchControl<'a> {
    Md5BatchControl::with_cancellation(budget, callback)
}

#[inline(never)]
pub fn remaining(control: &Md5BatchControl<'_>) -> usize {
    control.remaining()
}
