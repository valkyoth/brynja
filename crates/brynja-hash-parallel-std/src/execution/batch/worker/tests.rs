use super::*;
use crate::execution::{Error as SchedulingError, Preference};
use brynja_hash_parallel::execution::{Identity, Mode};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn work_totals_are_exact_checked_and_atomic() -> Result<(), Error> {
    let mut work = Work::default();
    work.add(leaf::KernelReport {
        vector_calls: 2,
        vector_permutations: 8,
        scalar_permutations: 3,
        ..Default::default()
    })?;
    assert_eq!(
        work,
        Work {
            groups: 1,
            vector_calls: 2,
            vector_permutations: 8,
            scalar_permutations: 3
        }
    );
    for field in 0..4 {
        let mut full = Work {
            groups: u128::MAX,
            vector_calls: u64::MAX,
            vector_permutations: u64::MAX,
            scalar_permutations: u64::MAX,
        };
        let extra = Work {
            groups: u128::from(field == 0),
            vector_calls: u64::from(field == 1),
            vector_permutations: u64::from(field == 2),
            scalar_permutations: u64::from(field == 3),
        };
        assert_eq!(full.merge(extra), Err(Error::Limits));
        assert_eq!(
            full,
            Work {
                groups: u128::MAX,
                vector_calls: u64::MAX,
                vector_permutations: u64::MAX,
                scalar_permutations: u64::MAX
            }
        );
    }
    Ok(())
}

std::thread_local! { static DROPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }
pub(super) fn observe_drop(storage: &Storage) {
    if storage.0.iter().flatten().flatten().all(|v| *v == 0) {
        DROPS.with(|n| n.set(n.get().saturating_add(1)));
    }
}
#[test]
fn storage_drop_clears_all_live_transport_capacity() {
    let before = DROPS.with(|n| n.get());
    drop(Storage(vec![[[0xa5; 64]; leaf::CAPACITY]; 64]));
    assert_eq!(DROPS.with(|n| n.get()), before.saturating_add(1));
}

struct Injected<'a> {
    fail_at: Option<usize>,
    panic_at: Option<usize>,
    cancel_at: Option<usize>,
    started: usize,
    finished: Arc<AtomicUsize>,
    token: &'a CancellationToken,
}
impl Spawner for Injected<'_> {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let index = self.started;
        if self.fail_at == Some(index) {
            return Err(io::Error::other("injected spawn failure"));
        }
        self.started = self
            .started
            .checked_add(1)
            .ok_or_else(|| io::Error::other("test counter overflow"))?;
        // Injection happens on the spawning side so the helper need not move
        // a token loan of an unrelated lifetime into the worker.
        if self.cancel_at == Some(index) {
            self.token.cancel();
        }
        let panic_after_work = self.panic_at == Some(index);
        let finished = Arc::clone(&self.finished);
        let handle = thread::Builder::new().spawn_scoped(scope, move || {
            let _completion = Completion(finished);
            let result = work();
            assert!(
                !panic_after_work,
                "injected worker panic after computing output"
            );
            result
        })?;
        Ok(handle)
    }
}
struct Completion(Arc<AtomicUsize>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn executor() -> Result<Executor, Error> {
    Executor::new(crate::execution::batch::Config {
        workers: 3,
        max_leaves: 16,
        root: Preference::Portable,
        leaves: Preference::Portable,
        minimum_permutations: 1,
        max_group_permutations: 64,
    })
}

#[test]
fn spawn_errors_panics_and_cancellation_join_and_close_root() -> Result<(), Error> {
    for (fail_at, panic_at, cancel_at, expected, started) in [
        (
            Some(0),
            None,
            None,
            Error::Scheduling(SchedulingError::Resource),
            0,
        ),
        (
            Some(1),
            None,
            None,
            Error::Scheduling(SchedulingError::Resource),
            1,
        ),
        (
            Some(2),
            None,
            None,
            Error::Scheduling(SchedulingError::Resource),
            2,
        ),
        (
            None,
            Some(0),
            None,
            Error::Scheduling(SchedulingError::WorkerPanicked),
            3,
        ),
        (
            None,
            Some(2),
            None,
            Error::Scheduling(SchedulingError::WorkerPanicked),
            3,
        ),
        (
            None,
            None,
            Some(1),
            Error::Scheduling(SchedulingError::Cancelled),
            2,
        ),
    ] {
        let plan = Plan::new(Identity::ParallelHash128, &[0xa5; 48], 4, 16)?;
        let mut root = Collector::new(&plan, Mode::Portable, &[])?;
        let token = CancellationToken::new();
        let finished = Arc::new(AtomicUsize::new(0));
        let mut spawner = Injected {
            fail_at,
            panic_at,
            cancel_at,
            started: 0,
            finished: Arc::clone(&finished),
            token: &token,
        };
        assert_eq!(
            run_with(&plan, &mut root, &executor()?, &token, &mut spawner),
            Err(expected)
        );
        assert_eq!(spawner.started, started);
        assert_eq!(finished.load(Ordering::SeqCst), started);
        assert_eq!(root.merged_leaves(), 0);
        assert!(root.execute_serial(|_| Ok(Mode::Portable)).is_err());
        let mut output = [0xa5; 32];
        assert!(root.finalize_secret(&mut output).is_err());
        assert_eq!(output, [0; 32]);
    }
    Ok(())
}

#[test]
fn every_completed_or_panicking_worker_clears_its_output_slot() -> Result<(), Error> {
    for (fail_at, panic_at) in [(None, None), (Some(2), None), (None, Some(1))] {
        let plan = Plan::new(Identity::ParallelHash256, &[0xa5; 48], 4, 16)?;
        let mut root = Collector::new(&plan, Mode::Portable, &[])?;
        let token = CancellationToken::new();
        let finished = Arc::new(AtomicUsize::new(0));
        let mut spawner = Injected {
            fail_at,
            panic_at,
            cancel_at: None,
            started: 0,
            finished: Arc::clone(&finished),
            token: &token,
        };
        let mut slots = [[[0xa5; 64]; leaf::CAPACITY]; 3];
        let result = wave(
            &plan,
            &mut root,
            0,
            &mut slots,
            &executor()?,
            &token,
            &mut spawner,
        );
        assert_eq!(result.is_ok(), fail_at.is_none() && panic_at.is_none());
        assert_eq!(finished.load(Ordering::SeqCst), spawner.started);
        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(
                *slot,
                if index < spawner.started {
                    [[0; 64]; leaf::CAPACITY]
                } else {
                    [[0xa5; 64]; leaf::CAPACITY]
                }
            );
        }
    }
    Ok(())
}

struct Reverse {
    first: Option<std::sync::mpsc::Receiver<()>>,
    second: Option<std::sync::mpsc::SyncSender<()>>,
    completed: Arc<AtomicUsize>,
}
impl Spawner for Reverse {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        let completed = Arc::clone(&self.completed);
        if let Some(receiver) = self.first.take() {
            thread::Builder::new().spawn_scoped(scope, move || {
                // Order is a channel handshake, not a machine-speed assertion.
                // A failed/panicking second worker drops its sender. The outer
                // verifier deadline bounds a genuine scheduler deadlock.
                assert!(receiver.recv().is_ok());
                let result = work();
                assert_eq!(completed.fetch_add(1, Ordering::SeqCst), 1);
                result
            })
        } else {
            let sender = self
                .second
                .take()
                .ok_or_else(|| io::Error::other("unexpected third worker"))?;
            thread::Builder::new().spawn_scoped(scope, move || {
                let result = work();
                assert_eq!(completed.fetch_add(1, Ordering::SeqCst), 0);
                assert!(sender.send(()).is_ok());
                result
            })
        }
    }
}

#[test]
fn reversed_worker_completion_is_merged_in_submission_order() -> Result<(), Error> {
    for identity in [
        Identity::ParallelHash128,
        Identity::ParallelHash256,
        Identity::ParallelHashXof128,
        Identity::ParallelHashXof256,
    ] {
        let plan = Plan::new(identity, &[0x73; 32], 4, 8)?;
        let mut root = Collector::new(&plan, Mode::Portable, &[])?;
        let token = CancellationToken::new();
        let completed = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut spawner = Reverse {
            first: Some(receiver),
            second: Some(sender),
            completed: Arc::clone(&completed),
        };
        run_with(&plan, &mut root, &executor()?, &token, &mut spawner)?;
        assert_eq!(completed.load(Ordering::SeqCst), 2);
        assert_eq!(root.merged_leaves(), 8);
        let mut serial = Collector::new(&plan, Mode::Portable, &[])?;
        serial.execute_serial(|_| Ok(Mode::Portable))?;
        let mut output = [0xa5; 173];
        let mut expected = [0; 173];
        if matches!(
            identity,
            Identity::ParallelHashXof128 | Identity::ParallelHashXof256
        ) {
            let actual = root.finalize_xof()?.squeeze_final_secret(&mut output, 5)?;
            let reference = serial
                .finalize_xof()?
                .squeeze_final_secret(&mut expected, 5)?;
            assert_eq!(actual.expose(), reference.expose());
        } else {
            let actual = root.finalize_secret_bits(&mut output, 5)?;
            let reference = serial.finalize_secret_bits(&mut expected, 5)?;
            assert_eq!(actual.expose(), reference.expose());
        }
        assert_eq!(output, [0; 173]);
        assert_eq!(expected, [0; 173]);
    }
    Ok(())
}
