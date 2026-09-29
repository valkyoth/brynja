//! Private host-runtime identities: never derive receipts from recyclable addresses.
//! IDs are local to one linked runtime/process. They are routing metadata, not
//! enclave identity, authentication, or restart-persistent capabilities.
use core::{
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

struct Sequence(AtomicU64);
impl Sequence {
    const fn new(next: u64) -> Self {
        Self(AtomicU64::new(next))
    }

    fn reserve(&self) -> Option<NonZeroU64> {
        let mut current = self.0.load(Ordering::Relaxed);
        // Bound contention work; rejection never falls back to an address ID.
        for _ in 0..64 {
            let identity = NonZeroU64::new(current)?;
            let next = current.checked_add(1)?;
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Some(identity),
                Err(observed) => current = observed,
            }
        }
        None
    }
}
static IDENTITIES: Sequence = Sequence::new(1);

pub(super) fn reserve() -> Option<NonZeroU64> {
    IDENTITIES.reserve()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{sync::Arc, thread, vec::Vec};

    #[test]
    fn zero_and_exhaustion_never_wrap_or_restart() {
        for start in [0, u64::MAX] {
            let sequence = Sequence::new(start);
            for _ in 0..3 {
                assert!(sequence.reserve().is_none());
            }
            assert_eq!(sequence.0.load(Ordering::Relaxed), start);
        }
        let sequence = Sequence::new(u64::MAX - 1);
        assert_eq!(sequence.reserve().unwrap().get(), u64::MAX - 1);
        assert!(sequence.reserve().is_none());
        assert_eq!(sequence.0.load(Ordering::Relaxed), u64::MAX);
    }
    #[test]
    fn failed_or_retired_resources_do_not_return_identity_to_sequence() {
        let sequence = Sequence::new(1);
        let failed = sequence.reserve().unwrap();
        let retired = sequence.reserve().unwrap();
        assert_eq!(
            (
                failed.get(),
                retired.get(),
                sequence.reserve().unwrap().get()
            ),
            (1, 2, 3)
        );
        assert_ne!(reserve(), reserve());
    }
    #[test]
    fn concurrent_reservations_are_unique_and_nonzero() {
        let sequence = Arc::new(Sequence::new(1));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let sequence = Arc::clone(&sequence);
            workers.push(thread::spawn(move || {
                let mut accepted = Vec::new();
                for _ in 0..128 {
                    if let Some(id) = sequence.reserve() {
                        accepted.push(id.get());
                    }
                }
                accepted
            }));
        }
        let mut accepted = Vec::new();
        for worker in workers {
            accepted.extend(worker.join().unwrap());
        }
        assert!(!accepted.is_empty());
        accepted.sort_unstable();
        for pair in accepted.windows(2) {
            assert!(pair[0] > 0 && pair[0] < pair[1]);
        }
        assert_eq!(
            sequence.0.load(Ordering::Relaxed),
            accepted.len() as u64 + 1
        );
    }
}
