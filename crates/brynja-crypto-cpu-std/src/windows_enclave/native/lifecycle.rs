//! Resource release after quiescence is not a successful secret-erasure receipt.
use super::super::engine::Driver;
use super::{Backend, Entries, Error, callback, sys};
use core::cell::Cell;

pub(super) struct Registration<'a> {
    registration: usize,
    input: usize,
    output: usize,
    pending: &'a Cell<bool>,
}
impl<'a> Registration<'a> {
    pub(super) fn new(entries: &Entries, pending: &'a Cell<bool>) -> Self {
        // Overlap violates exclusive synchronous use; never clear another call's
        // registration state or let borrowed pointers escape on failure.
        if pending.replace(true) {
            std::process::abort();
        }
        Self {
            registration: entries.registration,
            input: entries.input,
            output: entries.output,
            pending,
        }
    }
    pub(super) fn revoke(self) {}
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        // The guard spans every synchronous call. It cannot reach Drop while
        // CallEnclave is active; callbacks have no access to the owning Backend.
        let a = sys::call(self.registration, 0);
        let b = sys::call(self.output, 0);
        let c = sys::call(self.input, 0);
        if a != Ok(1) || b != Ok(1) || c != Ok(1) {
            std::process::abort();
        }
        self.pending.set(false);
        if std::thread::panicking() {
            let _ = callback::take();
        }
    }
}
impl Backend {
    fn destroy_quarantined(&mut self) -> Result<(), Error> {
        if self.thread != sys::thread() || self.registrations_pending.get() {
            return Err(Error::Release);
        }
        if self.base != 0 {
            sys::destroy(self.base, self.initialized, &mut self.terminated)?;
            self.base = 0;
        }
        // DeleteEnclave released the mapping, including any retained page locks.
        // Do not unlock stale slot addresses or clear the quarantine latch.
        self.slot = 0;
        self.slot_locked = false;
        self.live = false;
        drop(self.pin.take());
        Ok(())
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        if self.close().is_err() && self.destroy_quarantined().is_err() {
            // Last resort only: preserve image guards if destruction was not
            // confirmed. A failed cleanup receipt never becomes successful.
            if let Some(pin) = self.pin.take() {
                core::mem::forget(pin);
            }
        }
    }
}
