use super::*;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
enum Fault {
    None,
    Launch,
    PanicBefore,
    PanicAfter,
    Cancel,
}
struct Inject<'a> {
    fault: Fault,
    launched: usize,
    completed: Arc<AtomicUsize>,
    cancel: &'a CancellationToken,
}
impl Spawner for Inject<'_> {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        if matches!(self.fault, Fault::Launch) && self.launched == 1 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        self.launched = self.launched.checked_add(1).ok_or(io::ErrorKind::Other)?;
        if matches!(self.fault, Fault::Cancel) && self.launched == 2 {
            self.cancel.cancel();
        }
        let fault = self.fault;
        let completed = Arc::clone(&self.completed);
        thread::Builder::new().spawn_scoped(scope, move || {
            if matches!(fault, Fault::PanicBefore) {
                completed.fetch_add(1, Ordering::SeqCst);
                std::panic::resume_unwind(Box::new(()));
            }
            let result = work();
            completed.fetch_add(1, Ordering::SeqCst);
            if matches!(fault, Fault::PanicAfter) {
                std::panic::resume_unwind(Box::new(()));
            }
            result
        })
    }
}

macro_rules! check {
    ($name:ident, $batch:ident, $run:ident, $plan:ident, $workspace:ident, $n:expr) => {
        #[test]
        fn $name() -> Result<(), Error> {
            let plan = brynja_hash_parallel::$plan::new(b"four", 1)?;
            for fault in [
                Fault::Launch,
                Fault::PanicBefore,
                Fault::PanicAfter,
                Fault::Cancel,
                Fault::None,
            ] {
                let cancel = CancellationToken::new();
                let completed = Arc::new(AtomicUsize::new(0));
                let mut spawner = Inject {
                    fault,
                    launched: 0,
                    completed: Arc::clone(&completed),
                    cancel: &cancel,
                };
                let mut slots = [[0; $n]; 4];
                let mut merges = 0usize;
                let result = $batch(
                    &plan,
                    0,
                    &mut slots,
                    &cancel,
                    &mut |_| {
                        merges = merges.saturating_add(1);
                        Err(ParallelHashError::LeafIdentity)
                    },
                    &mut spawner,
                );
                let expected = match fault {
                    Fault::Launch => Error::ResourceExhausted,
                    Fault::PanicBefore | Fault::PanicAfter => Error::WorkerPanicked,
                    Fault::Cancel => Error::Cancelled,
                    Fault::None => Error::Construction(ParallelHashError::LeafIdentity),
                };
                assert_eq!(result, Err(expected));
                assert_eq!(completed.load(Ordering::SeqCst), spawner.launched);
                assert_eq!(merges, usize::from(matches!(fault, Fault::None)));
                assert_eq!(slots, [[0; $n]; 4]);
            }
            // Root admission fails before its callback after an injected worker
            // failure; the workspace can be borrowed for another operation.
            let mut workspace = brynja_hash_parallel::hardened_in_place::$workspace::new();
            let cancel = CancellationToken::new();
            let completed = Arc::new(AtomicUsize::new(0));
            let mut spawner = Inject {
                fault: Fault::Launch,
                launched: 0,
                completed,
                cancel: &cancel,
            };
            let result = workspace.with(&plan, b"", |mut root| {
                $run(&plan, 2, 4, &cancel, |leaf| root.merge(leaf), &mut spawner)
            })?;
            assert_eq!(result, Err(Error::ResourceExhausted));
            assert_eq!(workspace.with(&plan, b"", |root| root.cancel()), Ok(()));
            Ok(())
        }
    };
}
check!(
    scoped_workers_join_and_clear128,
    batch128,
    run128_with,
    ParallelHash128Plan,
    ParallelHash128CollectorWorkspace,
    32
);
check!(
    scoped_workers_join_and_clear256,
    batch256,
    run256_with,
    ParallelHash256Plan,
    ParallelHash256CollectorWorkspace,
    64
);

struct Overlap {
    barrier: Arc<Barrier>,
    second_done: Arc<AtomicUsize>,
    launched: usize,
}
impl Spawner for Overlap {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let index = self.launched;
        self.launched = self.launched.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let barrier = Arc::clone(&self.barrier);
        let done = Arc::clone(&self.second_done);
        thread::Builder::new().spawn_scoped(scope, move || {
            barrier.wait();
            let result = work();
            if index == 1 {
                done.store(1, Ordering::Release);
            } else {
                while done.load(Ordering::Acquire) == 0 {
                    thread::yield_now();
                }
            }
            result
        })
    }
}

#[test]
fn scoped_workers_overlap_and_merge_in_order() -> Result<(), Error> {
    let plan = brynja_hash_parallel::ParallelHash128Plan::new(b"AB", 1)?;
    let mut workspace =
        brynja_hash_parallel::hardened_in_place::ParallelHash128CollectorWorkspace::new();
    let mut spawner = Overlap {
        barrier: Arc::new(Barrier::new(2)),
        second_done: Arc::new(AtomicUsize::new(0)),
        launched: 0,
    };
    workspace.with(&plan, b"", |mut root| {
        run128_with(
            &plan,
            2,
            2,
            &CancellationToken::new(),
            |leaf| root.merge(leaf),
            &mut spawner,
        )
    })??;
    assert_eq!(spawner.launched, 2);
    assert_eq!(spawner.second_done.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn scoped_slots_clear_all_widths_and_admission_is_checked() {
    let mut narrow = Slots(vec![[0xa5; 32]; 3]);
    let mut wide = Slots(vec![[0xa5; 64]; 4]);
    narrow.clear();
    wide.clear();
    assert_eq!(narrow.0, vec![[0; 32]; 3]);
    assert_eq!(wide.0, vec![[0; 64]; 4]);
    let c = CancellationToken::new();
    assert_eq!(admit(1, 0, 1, &c), Err(Error::InvalidWorkerCount));
    assert_eq!(admit(0, 1, 0, &c), Err(Error::InvalidLeafLimit));
    assert_eq!(admit(2, 1, 1, &c), Err(Error::WorkLimitExceeded));
    assert_eq!(
        admit(u128::MAX, 1, u128::MAX, &c),
        Err(Error::ResourceExhausted)
    );
    assert_eq!(admit(0, 1, 1, &c), Ok(0));
}

#[test]
fn scoped_merge_unwind_joins_and_clears_results() -> Result<(), Error> {
    let plan = brynja_hash_parallel::ParallelHash128Plan::new(b"four", 1)?;
    let c = CancellationToken::new();
    let completed = Arc::new(AtomicUsize::new(0));
    let mut spawner = Inject {
        fault: Fault::None,
        launched: 0,
        completed: Arc::clone(&completed),
        cancel: &c,
    };
    let mut slots = [[0; 32]; 4];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        batch128(
            &plan,
            0,
            &mut slots,
            &c,
            &mut |_| std::panic::resume_unwind(Box::new(())),
            &mut spawner,
        )
    }));
    assert!(result.is_err());
    assert_eq!(completed.load(Ordering::SeqCst), 4);
    assert_eq!(slots, [[0; 32]; 4]);
    Ok(())
}
