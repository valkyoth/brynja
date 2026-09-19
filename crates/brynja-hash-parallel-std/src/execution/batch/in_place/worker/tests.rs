use super::super::{Config, Preference};
use super::*;
mod order;
use std::{
    cell::RefCell,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
thread_local! {static DROPS:RefCell<Vec<bool>>=const{RefCell::new(Vec::new())};}
pub(super) fn observe_drop(storage: &GroupSlots) {
    DROPS.with(|d| {
        d.borrow_mut()
            .push(storage.0.iter().flatten().flatten().all(|b| *b == 0))
    });
}
fn executor() -> Result<Executor, Error> {
    Executor::new(Config {
        workers: 3,
        max_leaves: 32,
        root: Preference::Portable,
        leaves: Preference::Portable,
        minimum_permutations: 1,
        max_group_permutations: 64,
    })
}
struct Complete(Arc<AtomicUsize>);
impl Drop for Complete {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct Inject<'a> {
    fail: Option<usize>,
    panic: bool,
    cancel: Option<usize>,
    started: usize,
    finished: Arc<AtomicUsize>,
    token: &'a CancellationToken,
}
impl Spawner for Inject<'_> {
    fn spawn<'s, 'e: 's, F, T>(
        &mut self,
        scope: &'s thread::Scope<'s, 'e>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'s, T>>
    where
        F: FnOnce() -> T + Send + 's,
        T: Send + 's,
    {
        if self.fail == Some(self.started) {
            return Err(io::Error::other("injected launch failure"));
        }
        if self.cancel == Some(self.started) {
            self.token.cancel();
        }
        self.started = self.started.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let finished = Arc::clone(&self.finished);
        let panic = self.panic;
        thread::Builder::new().spawn_scoped(scope, move || {
            let _completed = Complete(finished);
            let result = work();
            if panic {
                std::panic::resume_unwind(Box::new(()));
            }
            result
        })
    }
}
macro_rules! tests {
    ($faults:ident,$unwind:ident,$run:ident,$wave:ident,$plan:ident) => {
        #[test]
        fn $faults() -> Result<(), Error> {
            let plan = hash::$plan::new(b"ABCDEFGH", 1).map_err(crypto)?;
            let executor = executor()?;
            for (fail, panic, cancel, expected) in [
                (
                    Some(1),
                    false,
                    None,
                    Error::from(crate::execution::Error::Resource),
                ),
                (
                    None,
                    true,
                    None,
                    crate::execution::Error::WorkerPanicked.into(),
                ),
                (
                    None,
                    false,
                    Some(1),
                    crate::execution::Error::Cancelled.into(),
                ),
                (
                    None,
                    false,
                    None,
                    crypto(hash::ParallelHashError::LeafIdentity),
                ),
            ] {
                let token = CancellationToken::new();
                let finished = Arc::new(AtomicUsize::new(0));
                let mut spawner = Inject {
                    fail,
                    panic,
                    cancel,
                    started: 0,
                    finished: Arc::clone(&finished),
                    token: &token,
                };
                let mut slots = [[[0; 64]; 4]; 2];
                let mut merged = 0usize;
                let result = $wave(
                    &plan,
                    0,
                    &mut slots,
                    &executor,
                    &token,
                    &mut |_| {
                        merged = merged.saturating_add(1);
                        Err(hash::ParallelHashError::LeafIdentity)
                    },
                    &mut spawner,
                );
                if cancel.is_some() {
                    // Cancellation can be observed at the scheduler boundary
                    // or inside a leaf's Control::poll, depending on scheduling.
                    // Both exact errors preserve the original failure layer.
                    let mut cancelled = || true;
                    let inner = leaf::Control::new(64, &mut cancelled)
                        .poll()
                        .err()
                        .ok_or(Error::Limits)?;
                    let leaf_error = Error::Batch(leaf::Error::Hash(inner));
                    assert!(result == Err(expected) || result == Err(leaf_error));
                } else {
                    assert_eq!(result, Err(expected));
                }
                assert_eq!(finished.load(Ordering::SeqCst), spawner.started);
                assert_eq!(
                    merged,
                    usize::from(fail.is_none() && !panic && cancel.is_none())
                );
                assert_eq!(slots, [[[0; 64]; 4]; 2]);
            }
            Ok(())
        }
        #[test]
        fn $unwind() -> Result<(), Error> {
            let plan = hash::$plan::new(b"ABCDEFGH", 1).map_err(crypto)?;
            let executor = executor()?;
            for panic in [false, true] {
                let token = CancellationToken::new();
                let finished = Arc::new(AtomicUsize::new(0));
                let mut spawner = Inject {
                    fail: None,
                    panic: false,
                    cancel: None,
                    started: 0,
                    finished: Arc::clone(&finished),
                    token: &token,
                };
                DROPS.with(|d| d.borrow_mut().clear());
                let result = catch_unwind(AssertUnwindSafe(|| {
                    $run(
                        &plan,
                        &executor,
                        &token,
                        |leaves| {
                            // Parent storage guard must clear even deliberately forgotten results.
                            core::mem::forget(leaves);
                            if panic {
                                std::panic::resume_unwind(Box::new(()));
                            }
                            Ok(())
                        },
                        &mut spawner,
                    )
                }));
                if panic {
                    assert!(result.is_err());
                } else {
                    assert!(result.is_ok_and(|r| r.is_ok()));
                }
                assert_eq!(finished.load(Ordering::SeqCst), 2);
                DROPS.with(|d| assert_eq!(&*d.borrow(), &[true]));
            }
            Ok(())
        }
    };
}
tests!(
    scoped_multibuffer_join128,
    scoped_multibuffer_unwind128,
    run128_with,
    wave128,
    ParallelHash128Plan
);
tests!(
    scoped_multibuffer_join256,
    scoped_multibuffer_unwind256,
    run256_with,
    wave256,
    ParallelHash256Plan
);
#[test]
fn scoped_multibuffer_work_counters_are_atomic() -> Result<(), Error> {
    for field in 0..5 {
        let mut work = Work::default();
        match field {
            0 => work.groups = u128::MAX,
            1 => work.accelerated = u128::MAX,
            2 => work.vector_calls = u64::MAX,
            3 => work.vector_permutations = u64::MAX,
            _ => work.scalar_permutations = u64::MAX,
        };
        let before = format!("{work:?}");
        let report = leaf::KernelReport {
            accelerated_slots: 1,
            vector_calls: 1,
            vector_permutations: 1,
            scalar_permutations: 1,
            ..Default::default()
        };
        assert_eq!(work.add(report), Err(Error::Limits));
        assert_eq!(format!("{work:?}"), before);
    }
    DROPS.with(|d| d.borrow_mut().clear());
    let mut slots = GroupSlots::new(3)?;
    slots.0.fill([[0xa5; 64]; 4]);
    drop(slots);
    DROPS.with(|d| assert_eq!(&*d.borrow(), &[true]));
    Ok(())
}
