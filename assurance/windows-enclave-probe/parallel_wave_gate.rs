//! Private reusable admission protocol; no pointers or OS protection here.
//! A root must close admission and observe quiescence before touching published
//! slots, and retire only after clearing publication and finishing reduction.
//! Dropping the root lease without retirement permanently seals this gate.
#![forbid(unsafe_code)]
#![no_std]
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

const OPEN: u64 = 1 << 17;
const RESERVED: u64 = 1 << 16;
const CLOSED: u64 = 1 << 18;
const LIVE: u64 = 15 << 4;
const LOW: u64 = u32::MAX as u64;

pub struct Gate(AtomicU64);
pub struct Wave<'gate> {
    gate: &'gate Gate,
    generation: u32,
    initial: u64,
    retired: bool,
    thread_bound: PhantomData<*mut ()>,
}
pub struct Ticket<'gate> {
    gate: &'gate Gate,
    lane: u64,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Exactly one root lease, with a nonzero, never-wrapping generation.
    pub fn reserve(&self, lanes: usize) -> Option<Wave<'_>> {
        if !(1..=4).contains(&lanes) {
            return None;
        }
        let previous = self.0.load(Ordering::Acquire);
        if previous & LOW != 0 {
            return None;
        }
        let generation = u32::try_from(previous >> 32).ok()?.checked_add(1)?;
        let initial = (u64::from(generation) << 32) | RESERVED | (((1 << lanes) - 1) << 12);
        self.0
            .compare_exchange(previous, initial, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(Wave {
            gate: self,
            generation,
            initial,
            retired: false,
            thread_bound: PhantomData,
        })
    }

    /// Reject stale/future generations and duplicate/inactive lanes in the same
    /// CAS that acquires a live borrow. The caller may load a slot ONLY afterward.
    pub fn enter(&self, generation: u32, lane: usize) -> Option<Ticket<'_>> {
        if generation == 0 || lane >= 4 {
            return None;
        }
        let bit = 1_u64 << lane;
        let mut state = self.0.load(Ordering::Acquire);
        loop {
            if state >> 32 != u64::from(generation)
                || state & OPEN == 0
                || state & bit != 0
                || state & (bit << 12) == 0
            {
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
}

impl Wave<'_> {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Root has initialized every active slot/pointer before this release.
    pub fn publish(&self) -> bool {
        !self.retired
            && self
                .gate
                .0
                .compare_exchange(
                    self.initial,
                    self.initial | OPEN,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    pub fn close(&self) {
        if !self.retired {
            let _ = self
                .gate
                .0
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    Some((state & !OPEN) | CLOSED)
                });
        }
    }

    /// False while admission remains open, even with zero current workers.
    pub fn quiescent(&self) -> bool {
        !self.retired && self.gate.0.load(Ordering::Acquire) & (OPEN | LIVE | CLOSED) == CLOSED
    }

    pub fn all_succeeded(&self) -> bool {
        let state = self.gate.0.load(Ordering::Acquire);
        let expected = (self.initial >> 12) & 15;
        !self.retired
            && state & (OPEN | LIVE | CLOSED) == CLOSED
            && state & 15 == expected
            && (state >> 8) & 15 == expected
    }

    /// Explicit root acknowledgement after publication/borrowed storage cleanup.
    /// The gate cannot prove that cleanup; raw-pointer adapters must enforce it.
    pub fn retire(&mut self) -> bool {
        let state = self.gate.0.load(Ordering::Acquire);
        if self.retired || state & (OPEN | LIVE | CLOSED) != CLOSED {
            return false;
        }
        if self
            .gate
            .0
            .compare_exchange(
                state,
                u64::from(self.generation) << 32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.retired = true;
        true
    }
}

impl Drop for Wave<'_> {
    fn drop(&mut self) {
        // Never unlock storage reuse implicitly, including on root unwind.
        self.close();
    }
}
impl Ticket<'_> {
    pub fn succeeded(&self) {
        self.gate.0.fetch_or(self.lane << 8, Ordering::Release);
    }
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        // Final slot access and worker-local clearing precede this release.
        self.gate.0.fetch_and(!(self.lane << 4), Ordering::Release);
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
#[path = "parallel_wave_gate_tests.rs"]
mod tests;
