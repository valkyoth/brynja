use crate::{CancellationToken, ParallelHashExecutorError as Error, worker::ensure_live};
use brynja_core::clear_owned_region;
use brynja_hash_parallel::ParallelHashError;
use std::{io, thread};

// Allocated empty, never resized with secret data, and borrowed disjointly by
// workers. No secret CV array is returned by value through a thread handle.
pub(crate) struct Slots<const N: usize>(pub(crate) Vec<[u8; N]>);
impl<const N: usize> Slots<N> {
    pub(crate) fn new(length: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(length)
            .map_err(|_| Error::ResourceExhausted)?;
        slots.resize(length, [0; N]);
        Ok(Self(slots))
    }
    #[inline(never)]
    fn clear(&mut self) {
        for slot in &mut self.0 {
            let _ = clear_owned_region(slot);
        }
    }
}
impl<const N: usize> Drop for Slots<N> {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) trait Spawner {
    fn spawn<'scope, 'env: 'scope, F, T>(
        &mut self,
        scope: &'scope thread::Scope<'scope, 'env>,
        work: F,
    ) -> io::Result<thread::ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope;
}
pub(crate) struct System;
impl Spawner for System {
    fn spawn<'scope, 'env: 'scope, F, T>(
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

pub(crate) fn admit(
    leaves: u128,
    workers: usize,
    limit: u128,
    cancel: &CancellationToken,
) -> Result<usize, Error> {
    ensure_live(cancel)?;
    if workers == 0 {
        return Err(Error::InvalidWorkerCount);
    }
    if limit == 0 {
        return Err(Error::InvalidLeafLimit);
    }
    if leaves > limit {
        return Err(Error::WorkLimitExceeded);
    }
    usize::try_from(leaves).map_err(|_| Error::ResourceExhausted)
}

macro_rules! worker {
    ($run:ident, $using:ident, $batch:ident, $plan:ident, $result:ident, $width:expr) => {
        pub(crate) fn $run<'plan, 'input>(
            plan: &'plan brynja_hash_parallel::$plan<'input>,
            workers: usize,
            limit: u128,
            cancel: &CancellationToken,
            merge: impl for<'out> FnMut(
                brynja_hash_parallel::$result<'plan, 'out>,
            ) -> Result<(), ParallelHashError>,
        ) -> Result<(), Error> {
            $using(plan, workers, limit, cancel, merge, &mut System)
        }
        fn $using<'plan, 'input>(
            plan: &'plan brynja_hash_parallel::$plan<'input>,
            workers: usize,
            limit: u128,
            cancel: &CancellationToken,
            mut merge: impl for<'out> FnMut(
                brynja_hash_parallel::$result<'plan, 'out>,
            ) -> Result<(), ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<(), Error> {
            let leaves = admit(plan.leaf_count(), workers, limit, cancel)?;
            let mut slots = Slots::<$width>::new(leaves.min(workers))?;
            let mut base = 0usize;
            while base < leaves {
                ensure_live(cancel)?;
                let count = leaves
                    .checked_sub(base)
                    .ok_or(Error::ResourceExhausted)?
                    .min(slots.0.len());
                let batch = slots.0.get_mut(..count).ok_or(Error::ResourceExhausted)?;
                $batch(plan, base, batch, cancel, &mut merge, spawner)?;
                base = base.checked_add(count).ok_or(Error::ResourceExhausted)?;
            }
            ensure_live(cancel)
        }
        fn $batch<'plan, 'input>(
            plan: &'plan brynja_hash_parallel::$plan<'input>,
            base: usize,
            batch: &mut [[u8; $width]],
            cancel: &CancellationToken,
            merge: &mut impl for<'out> FnMut(
                brynja_hash_parallel::$result<'plan, 'out>,
            ) -> Result<(), ParallelHashError>,
            spawner: &mut impl Spawner,
        ) -> Result<(), Error> {
            thread::scope(|scope| {
                let mut handles = Vec::new();
                handles
                    .try_reserve_exact(batch.len())
                    .map_err(|_| Error::ResourceExhausted)?;
                let mut failure = None;
                for (offset, destination) in batch.iter_mut().enumerate() {
                    let prepared = (|| {
                        ensure_live(cancel)?;
                        let index = base.checked_add(offset).ok_or(Error::ResourceExhausted)?;
                        Ok::<_, Error>(
                            plan.job(u128::try_from(index).map_err(|_| Error::ResourceExhausted)?)?,
                        )
                    })();
                    let job = match prepared {
                        Ok(job) => job,
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    };
                    match spawner.spawn(scope, move || {
                        ensure_live(cancel)?;
                        let result = job.execute(destination)?;
                        ensure_live(cancel)?;
                        Ok::<_, Error>(result)
                    }) {
                        Ok(handle) => handles.push(handle),
                        Err(_) => {
                            failure = Some(Error::ResourceExhausted);
                            break;
                        }
                    }
                }
                // All ordinary errors drain every handle. A merge unwind still
                // joins through thread::scope; slots outlive that scope and wipe.
                for handle in handles {
                    match handle.join() {
                        Err(_) => {
                            failure.get_or_insert(Error::WorkerPanicked);
                        }
                        Ok(Err(error)) => {
                            failure.get_or_insert(error);
                        }
                        Ok(Ok(leaf)) => {
                            if failure.is_none() {
                                if let Err(error) = ensure_live(cancel) {
                                    failure = Some(error);
                                } else if let Err(error) = merge(leaf) {
                                    failure = Some(error.into());
                                }
                            }
                        }
                    }
                }
                failure.map_or(Ok(()), Err)
            })
        }
    };
}
worker!(
    run128,
    run128_with,
    batch128,
    ParallelHash128Plan,
    ParallelHash128LeafResult,
    32
);
worker!(
    run256,
    run256_with,
    batch256,
    ParallelHash256Plan,
    ParallelHash256LeafResult,
    64
);

#[cfg(test)]
mod tests;
