use std::{io, thread};

use brynja_core::clear_owned_region;
use brynja_hash_parallel::{
    ParallelHash128Collector, ParallelHash128Plan, ParallelHash256Collector, ParallelHash256Plan,
    ParallelHashError,
};

use crate::{CancellationToken, ParallelHashExecutorError};

struct LeafStorage<const N: usize>(Vec<[u8; N]>);

impl<const N: usize> LeafStorage<N> {
    fn zeroed(length: usize) -> Result<Self, ParallelHashExecutorError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(length)
            .map_err(|_| ParallelHashExecutorError::ResourceExhausted)?;
        storage.resize(length, [0; N]);
        Ok(Self(storage))
    }
}

impl<const N: usize> Drop for LeafStorage<N> {
    fn drop(&mut self) {
        for leaf in &mut self.0 {
            let _ = clear_owned_region(leaf);
        }
    }
}

trait ThreadSpawner {
    fn spawn_scoped<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope;
}

struct SystemThreadSpawner;

impl ThreadSpawner for SystemThreadSpawner {
    fn spawn_scoped<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        thread::Builder::new().spawn_scoped(scope, work)
    }
}

pub(crate) fn execute128<'plan, 'input>(
    plan: &'plan ParallelHash128Plan<'input>,
    collector: &mut ParallelHash128Collector<'plan>,
    workers: usize,
    max_leaves: u128,
    cancellation: &CancellationToken,
) -> Result<(), ParallelHashExecutorError> {
    execute128_with(
        plan,
        collector,
        workers,
        max_leaves,
        cancellation,
        &mut SystemThreadSpawner,
    )
}

fn execute128_with<'plan, 'input, S: ThreadSpawner>(
    plan: &'plan ParallelHash128Plan<'input>,
    collector: &mut ParallelHash128Collector<'plan>,
    workers: usize,
    max_leaves: u128,
    cancellation: &CancellationToken,
    spawner: &mut S,
) -> Result<(), ParallelHashExecutorError> {
    let leaves = admit_work(plan.leaf_count(), workers, max_leaves, cancellation)?;
    let slots = leaves.min(workers);
    let mut storage = LeafStorage::<32>::zeroed(slots)?;
    let mut base = 0_usize;
    while base < leaves {
        ensure_live(cancellation)?;
        let count = leaves
            .checked_sub(base)
            .map(|remaining| remaining.min(slots))
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        let batch = storage
            .0
            .get_mut(..count)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        execute128_batch(plan, collector, base, batch, cancellation, spawner)?;
        base = base
            .checked_add(count)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
    }
    Ok(())
}

fn execute128_batch<'plan, 'input, S: ThreadSpawner>(
    plan: &'plan ParallelHash128Plan<'input>,
    collector: &mut ParallelHash128Collector<'plan>,
    base: usize,
    batch: &mut [[u8; 32]],
    cancellation: &CancellationToken,
    spawner: &mut S,
) -> Result<(), ParallelHashExecutorError> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(batch.len())
            .map_err(|_| ParallelHashExecutorError::ResourceExhausted)?;
        let mut failure = None;
        for (offset, destination) in batch.iter_mut().enumerate() {
            if let Err(error) = ensure_live(cancellation) {
                failure = Some(error);
                break;
            }
            let index = leaf_index(base, offset)?;
            let job = plan.job(index)?;
            match spawner.spawn_scoped(scope, move || job.execute(destination)) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    failure.get_or_insert(ParallelHashExecutorError::ResourceExhausted);
                    break;
                }
            }
        }
        merge128(handles, collector, cancellation, failure)
    })
}

fn merge128<'plan, 'output>(
    handles: Vec<
        thread::ScopedJoinHandle<
            '_,
            Result<
                brynja_hash_parallel::ParallelHash128LeafResult<'plan, 'output>,
                ParallelHashError,
            >,
        >,
    >,
    collector: &mut ParallelHash128Collector<'plan>,
    cancellation: &CancellationToken,
    mut failure: Option<ParallelHashExecutorError>,
) -> Result<(), ParallelHashExecutorError> {
    for handle in handles {
        match join_worker(handle) {
            Err(error) => {
                failure.get_or_insert(error);
            }
            Ok(Err(error)) => {
                failure.get_or_insert(error.into());
            }
            Ok(Ok(result)) => {
                if failure.is_none() {
                    if let Err(error) = ensure_live(cancellation) {
                        failure = Some(error);
                    } else if let Err(error) = collector.merge(&result) {
                        failure = Some(error.into());
                    }
                }
                drop(result);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(crate) fn execute256<'plan, 'input>(
    plan: &'plan ParallelHash256Plan<'input>,
    collector: &mut ParallelHash256Collector<'plan>,
    workers: usize,
    max_leaves: u128,
    cancellation: &CancellationToken,
) -> Result<(), ParallelHashExecutorError> {
    execute256_with(
        plan,
        collector,
        workers,
        max_leaves,
        cancellation,
        &mut SystemThreadSpawner,
    )
}

fn execute256_with<'plan, 'input, S: ThreadSpawner>(
    plan: &'plan ParallelHash256Plan<'input>,
    collector: &mut ParallelHash256Collector<'plan>,
    workers: usize,
    max_leaves: u128,
    cancellation: &CancellationToken,
    spawner: &mut S,
) -> Result<(), ParallelHashExecutorError> {
    let leaves = admit_work(plan.leaf_count(), workers, max_leaves, cancellation)?;
    let slots = leaves.min(workers);
    let mut storage = LeafStorage::<64>::zeroed(slots)?;
    let mut base = 0_usize;
    while base < leaves {
        ensure_live(cancellation)?;
        let count = leaves
            .checked_sub(base)
            .map(|remaining| remaining.min(slots))
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        let batch = storage
            .0
            .get_mut(..count)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        execute256_batch(plan, collector, base, batch, cancellation, spawner)?;
        base = base
            .checked_add(count)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
    }
    Ok(())
}

fn execute256_batch<'plan, 'input, S: ThreadSpawner>(
    plan: &'plan ParallelHash256Plan<'input>,
    collector: &mut ParallelHash256Collector<'plan>,
    base: usize,
    batch: &mut [[u8; 64]],
    cancellation: &CancellationToken,
    spawner: &mut S,
) -> Result<(), ParallelHashExecutorError> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(batch.len())
            .map_err(|_| ParallelHashExecutorError::ResourceExhausted)?;
        let mut failure = None;
        for (offset, destination) in batch.iter_mut().enumerate() {
            if let Err(error) = ensure_live(cancellation) {
                failure = Some(error);
                break;
            }
            let index = leaf_index(base, offset)?;
            let job = plan.job(index)?;
            match spawner.spawn_scoped(scope, move || job.execute(destination)) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    failure.get_or_insert(ParallelHashExecutorError::ResourceExhausted);
                    break;
                }
            }
        }
        merge256(handles, collector, cancellation, failure)
    })
}

fn merge256<'plan, 'output>(
    handles: Vec<
        thread::ScopedJoinHandle<
            '_,
            Result<
                brynja_hash_parallel::ParallelHash256LeafResult<'plan, 'output>,
                ParallelHashError,
            >,
        >,
    >,
    collector: &mut ParallelHash256Collector<'plan>,
    cancellation: &CancellationToken,
    mut failure: Option<ParallelHashExecutorError>,
) -> Result<(), ParallelHashExecutorError> {
    for handle in handles {
        match join_worker(handle) {
            Err(error) => {
                failure.get_or_insert(error);
            }
            Ok(Err(error)) => {
                failure.get_or_insert(error.into());
            }
            Ok(Ok(result)) => {
                if failure.is_none() {
                    if let Err(error) = ensure_live(cancellation) {
                        failure = Some(error);
                    } else if let Err(error) = collector.merge(&result) {
                        failure = Some(error.into());
                    }
                }
                drop(result);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

fn admit_work(
    leaf_count: u128,
    workers: usize,
    max_leaves: u128,
    cancellation: &CancellationToken,
) -> Result<usize, ParallelHashExecutorError> {
    ensure_live(cancellation)?;
    if workers == 0 {
        return Err(ParallelHashExecutorError::InvalidWorkerCount);
    }
    if leaf_count > max_leaves {
        return Err(ParallelHashExecutorError::WorkLimitExceeded);
    }
    usize::try_from(leaf_count).map_err(|_| ParallelHashExecutorError::ResourceExhausted)
}

fn leaf_index(base: usize, offset: usize) -> Result<u128, ParallelHashExecutorError> {
    base.checked_add(offset)
        .and_then(|value| u128::try_from(value).ok())
        .ok_or(ParallelHashExecutorError::ResourceExhausted)
}

pub(crate) fn ensure_live(
    cancellation: &CancellationToken,
) -> Result<(), ParallelHashExecutorError> {
    if cancellation.is_cancelled() {
        Err(ParallelHashExecutorError::Cancelled)
    } else {
        Ok(())
    }
}

fn join_worker<T>(handle: thread::ScopedJoinHandle<'_, T>) -> Result<T, ParallelHashExecutorError> {
    handle
        .join()
        .map_err(|_| ParallelHashExecutorError::WorkerPanicked)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    struct FailAfterOne {
        spawned: bool,
        completed: Arc<AtomicBool>,
    }

    impl ThreadSpawner for FailAfterOne {
        fn spawn_scoped<'scope, 'env: 'scope, F, T>(
            &mut self,
            scope: &'scope thread::Scope<'scope, 'env>,
            work: F,
        ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            if self.spawned {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            self.spawned = true;
            let completed = Arc::clone(&self.completed);
            thread::Builder::new().spawn_scoped(scope, move || {
                let result = work();
                completed.store(true, Ordering::Release);
                result
            })
        }
    }

    struct PanickingSpawner {
        started: Arc<AtomicUsize>,
    }

    impl ThreadSpawner for PanickingSpawner {
        fn spawn_scoped<'scope, 'env: 'scope, F, T>(
            &mut self,
            scope: &'scope thread::Scope<'scope, 'env>,
            work: F,
        ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            let started = Arc::clone(&self.started);
            thread::Builder::new().spawn_scoped(scope, move || {
                drop(work);
                started.fetch_add(1, Ordering::AcqRel);
                std::panic::resume_unwind(Box::new(()))
            })
        }
    }

    #[test]
    fn launch_failure_is_typed_and_started_worker_is_joined() {
        let plan = ParallelHash128Plan::new(b"two exact leaves", 8);
        assert!(plan.is_ok());
        let Ok(plan) = plan else { return };
        let collector = ParallelHash128Collector::new(&plan, b"");
        assert!(collector.is_ok());
        let Ok(mut collector) = collector else { return };
        let completed = Arc::new(AtomicBool::new(false));
        let mut spawner = FailAfterOne {
            spawned: false,
            completed: Arc::clone(&completed),
        };
        let result = execute128_with(
            &plan,
            &mut collector,
            2,
            8,
            &CancellationToken::new(),
            &mut spawner,
        );
        assert_eq!(result, Err(ParallelHashExecutorError::ResourceExhausted));
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn launch_failure_is_typed_and_joined_for_parallel_hash256() {
        let plan = ParallelHash256Plan::new(b"two exact leaves", 8);
        assert!(plan.is_ok());
        let Ok(plan) = plan else { return };
        let collector = ParallelHash256Collector::new(&plan, b"");
        assert!(collector.is_ok());
        let Ok(mut collector) = collector else { return };
        let completed = Arc::new(AtomicBool::new(false));
        let mut spawner = FailAfterOne {
            spawned: false,
            completed: Arc::clone(&completed),
        };
        let result = execute256_with(
            &plan,
            &mut collector,
            2,
            8,
            &CancellationToken::new(),
            &mut spawner,
        );
        assert_eq!(result, Err(ParallelHashExecutorError::ResourceExhausted));
        assert!(completed.load(Ordering::Acquire));
    }

    #[test]
    fn worker_panic_becomes_closed_error() {
        let result = thread::scope(|scope| {
            let handle = thread::Builder::new()
                .spawn_scoped(scope, || std::panic::resume_unwind(Box::new(())));
            assert!(handle.is_ok());
            let Ok(handle) = handle else { return Ok(()) };
            join_worker(handle)
        });
        assert_eq!(
            result.err(),
            Some(ParallelHashExecutorError::WorkerPanicked)
        );
    }

    #[test]
    fn every_panicking_worker_is_joined_without_scope_unwind() {
        let plan = ParallelHash128Plan::new(b"two exact leaves", 8);
        assert!(plan.is_ok());
        let Ok(plan) = plan else { return };
        let collector = ParallelHash128Collector::new(&plan, b"");
        assert!(collector.is_ok());
        let Ok(mut collector) = collector else { return };
        let started = Arc::new(AtomicUsize::new(0));
        let mut spawner = PanickingSpawner {
            started: Arc::clone(&started),
        };
        let result = execute128_with(
            &plan,
            &mut collector,
            2,
            8,
            &CancellationToken::new(),
            &mut spawner,
        );
        assert_eq!(result, Err(ParallelHashExecutorError::WorkerPanicked));
        assert_eq!(started.load(Ordering::Acquire), 2);
    }
}
