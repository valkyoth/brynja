//! One-shot scoped publication. Closing and worker admission share one atomic
//! word: no worker can acquire a borrowed slot after the root closes admission.
#![forbid(unsafe_code)]
use core::sync::atomic::{AtomicU32, Ordering};

const RESERVED: u32 = 1 << 30;
const OPEN: u32 = 1 << 31;
const LIVE: u32 = 15 << 4;

pub struct Gate(AtomicU32);
pub struct Ticket<'a> {
    gate: &'a Gate,
    lane: u32,
}
impl Gate {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }
    pub fn reserve(&self) -> bool {
        self.0
            .compare_exchange(0, RESERVED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    // Called only after all four pointers are published by the reserved root.
    pub fn publish(&self) -> bool {
        self.0
            .compare_exchange(
                RESERVED,
                RESERVED | OPEN,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
    }
    pub fn enter(&self, lane: usize) -> Option<Ticket<'_>> {
        if lane >= 4 {
            return None;
        }
        let bit = 1_u32 << lane;
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            if state & OPEN == 0 || state & bit != 0 {
                return None;
            }
            match self.0.compare_exchange_weak(
                state,
                state | bit | (bit << 4),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Ticket {
                        gate: self,
                        lane: bit,
                    });
                }
                Err(next) => state = next,
            }
        }
    }
    pub fn close(&self) {
        self.0.fetch_and(!OPEN, Ordering::AcqRel);
    }
    pub fn quiescent(&self) -> bool {
        self.0.load(Ordering::Acquire) & LIVE == 0
    }
    #[cfg(test)]
    pub fn accepting(&self) -> bool {
        self.0.load(Ordering::Acquire) & OPEN != 0
    }
    pub fn all_succeeded(&self) -> bool {
        let state = self.0.load(Ordering::Acquire);
        state & (OPEN | LIVE) == 0 && state & 0x0f0f == 0x0f0f
    }
}
impl Ticket<'_> {
    pub fn succeeded(&self) {
        self.gate.0.fetch_or(self.lane << 8, Ordering::Release);
    }
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        // Final access to borrowed storage precedes this Release operation.
        self.gate.0.fetch_and(!(self.lane << 4), Ordering::Release);
    }
}
