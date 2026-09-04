//! Optional bounded native-thread execution for Brynja ParallelHash.
//!
//! This crate owns no cryptographic construction. It executes exact leaf jobs
//! from `brynja-hash-parallel`, joins them deterministically, and feeds their
//! lifetime-bound results to the portable ordered collector.

use std::sync::atomic::{AtomicBool, Ordering};

use brynja_core::clear_owned_region;
use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHash128Collector, ParallelHash128Plan,
    ParallelHash256Collector, ParallelHash256Plan, ParallelHashError,
    ParallelHashPublicDeclassification,
};

/// Cooperative cancellation shared with one or more executor calls.
pub struct CancellationToken {
    cancelled: AtomicBool,
}

impl CancellationToken {
    /// Creates a live token.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    /// Requests cancellation. Work already executing may finish and is erased.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Closed executor failure without worker or secret payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ParallelHashExecutorError {
    /// Worker count was zero.
    InvalidWorkerCount,
    /// A bounded allocation could not be reserved.
    ResourceExhausted,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// A worker panicked; no output was released.
    WorkerPanicked,
    /// The portable construction rejected the operation.
    Construction(ParallelHashError),
}

impl From<ParallelHashError> for ParallelHashExecutorError {
    fn from(error: ParallelHashError) -> Self {
        Self::Construction(error)
    }
}

/// Bounded native-thread executor.
pub struct ParallelHashExecutor {
    workers: usize,
}

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

impl ParallelHashExecutor {
    /// Creates an executor with a positive maximum worker count.
    pub fn new(workers: usize) -> Result<Self, ParallelHashExecutorError> {
        if workers == 0 {
            Err(ParallelHashExecutorError::InvalidWorkerCount)
        } else {
            Ok(Self { workers })
        }
    }

    /// Computes fixed-output ParallelHash128.
    pub fn parallel_hash128(
        &self,
        input: &[u8],
        block_size: usize,
        customization: &[u8],
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash128Plan::new(input, block_size)?;
        let mut collector = ParallelHash128Collector::new(&plan, customization)?;
        execute128(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector.finalize(output).map_err(Into::into)
    }

    /// Computes arbitrary-bit ParallelHash128 input, customization, and output.
    pub fn parallel_hash128_bits(
        &self,
        input: Fips202BitString<'_>,
        block_size: usize,
        customization: Fips202BitString<'_>,
        output: Fips202Output<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash128Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash128Collector::new_bits(&plan, customization)?;
        execute128(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector.finalize_bits(output).map_err(Into::into)
    }

    /// Computes fixed-output ParallelHash256.
    pub fn parallel_hash256(
        &self,
        input: &[u8],
        block_size: usize,
        customization: &[u8],
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash256Plan::new(input, block_size)?;
        let mut collector = ParallelHash256Collector::new(&plan, customization)?;
        execute256(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector.finalize(output).map_err(Into::into)
    }

    /// Computes arbitrary-bit ParallelHash256 input, customization, and output.
    pub fn parallel_hash256_bits(
        &self,
        input: Fips202BitString<'_>,
        block_size: usize,
        customization: Fips202BitString<'_>,
        output: Fips202Output<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash256Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash256Collector::new_bits(&plan, customization)?;
        execute256(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector.finalize_bits(output).map_err(Into::into)
    }

    /// Computes byte-oriented ParallelHashXOF128 output.
    pub fn parallel_hash_xof128(
        &self,
        input: &[u8],
        block_size: usize,
        customization: &[u8],
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash128Plan::new(input, block_size)?;
        let mut collector = ParallelHash128Collector::new(&plan, customization)?;
        execute128(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector
            .finalize_xof()?
            .squeeze_public(output, ParallelHashPublicDeclassification::acknowledge())
            .map_err(Into::into)
    }

    /// Computes arbitrary-bit ParallelHashXOF128 input, customization, and output.
    pub fn parallel_hash_xof128_bits(
        &self,
        input: Fips202BitString<'_>,
        block_size: usize,
        customization: Fips202BitString<'_>,
        output: Fips202Output<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash128Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash128Collector::new_bits(&plan, customization)?;
        execute128(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector
            .finalize_xof()?
            .squeeze_final_bits_public(output, ParallelHashPublicDeclassification::acknowledge())
            .map_err(Into::into)
    }

    /// Computes byte-oriented ParallelHashXOF256 output.
    pub fn parallel_hash_xof256(
        &self,
        input: &[u8],
        block_size: usize,
        customization: &[u8],
        output: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash256Plan::new(input, block_size)?;
        let mut collector = ParallelHash256Collector::new(&plan, customization)?;
        execute256(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector
            .finalize_xof()?
            .squeeze_public(output, ParallelHashPublicDeclassification::acknowledge())
            .map_err(Into::into)
    }

    /// Computes arbitrary-bit ParallelHashXOF256 input, customization, and output.
    pub fn parallel_hash_xof256_bits(
        &self,
        input: Fips202BitString<'_>,
        block_size: usize,
        customization: Fips202BitString<'_>,
        output: Fips202Output<'_>,
        cancellation: &CancellationToken,
    ) -> Result<(), ParallelHashExecutorError> {
        let plan = ParallelHash256Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash256Collector::new_bits(&plan, customization)?;
        execute256(&plan, &mut collector, self.workers, cancellation)?;
        ensure_live(cancellation)?;
        collector
            .finalize_xof()?
            .squeeze_final_bits_public(output, ParallelHashPublicDeclassification::acknowledge())
            .map_err(Into::into)
    }
}

fn execute128<'plan, 'input>(
    plan: &'plan ParallelHash128Plan<'input>,
    collector: &mut ParallelHash128Collector<'plan>,
    workers: usize,
    cancellation: &CancellationToken,
) -> Result<(), ParallelHashExecutorError> {
    let leaves = usize::try_from(plan.leaf_count())
        .map_err(|_| ParallelHashExecutorError::ResourceExhausted)?;
    let mut storage = LeafStorage::<32>::zeroed(leaves)?;
    for (batch_index, batch) in storage.0.chunks_mut(workers).enumerate() {
        ensure_live(cancellation)?;
        let base = batch_index
            .checked_mul(workers)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        std::thread::scope(|scope| -> Result<(), ParallelHashExecutorError> {
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
                let Some(index) = base
                    .checked_add(offset)
                    .and_then(|value| u128::try_from(value).ok())
                else {
                    failure = Some(ParallelHashExecutorError::ResourceExhausted);
                    break;
                };
                let Ok(job) = plan.job(index) else {
                    failure = Some(ParallelHashExecutorError::Construction(
                        ParallelHashError::LeafOrder,
                    ));
                    break;
                };
                handles.push(scope.spawn(move || job.execute(destination)));
            }
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
                };
            }
            failure.map_or(Ok(()), Err)
        })?;
    }
    Ok(())
}

fn execute256<'plan, 'input>(
    plan: &'plan ParallelHash256Plan<'input>,
    collector: &mut ParallelHash256Collector<'plan>,
    workers: usize,
    cancellation: &CancellationToken,
) -> Result<(), ParallelHashExecutorError> {
    let leaves = usize::try_from(plan.leaf_count())
        .map_err(|_| ParallelHashExecutorError::ResourceExhausted)?;
    let mut storage = LeafStorage::<64>::zeroed(leaves)?;
    for (batch_index, batch) in storage.0.chunks_mut(workers).enumerate() {
        ensure_live(cancellation)?;
        let base = batch_index
            .checked_mul(workers)
            .ok_or(ParallelHashExecutorError::ResourceExhausted)?;
        std::thread::scope(|scope| -> Result<(), ParallelHashExecutorError> {
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
                let Some(index) = base
                    .checked_add(offset)
                    .and_then(|value| u128::try_from(value).ok())
                else {
                    failure = Some(ParallelHashExecutorError::ResourceExhausted);
                    break;
                };
                let Ok(job) = plan.job(index) else {
                    failure = Some(ParallelHashExecutorError::Construction(
                        ParallelHashError::LeafOrder,
                    ));
                    break;
                };
                handles.push(scope.spawn(move || job.execute(destination)));
            }
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
                };
            }
            failure.map_or(Ok(()), Err)
        })?;
    }
    Ok(())
}

fn ensure_live(cancellation: &CancellationToken) -> Result<(), ParallelHashExecutorError> {
    if cancellation.is_cancelled() {
        Err(ParallelHashExecutorError::Cancelled)
    } else {
        Ok(())
    }
}

fn join_worker<T>(
    handle: std::thread::ScopedJoinHandle<'_, T>,
) -> Result<T, ParallelHashExecutorError> {
    handle
        .join()
        .map_err(|_| ParallelHashExecutorError::WorkerPanicked)
}

#[cfg(test)]
mod tests {
    #[test]
    fn worker_panic_becomes_closed_error() {
        let result = std::thread::scope(|scope| {
            super::join_worker(scope.spawn(|| std::panic::resume_unwind(Box::new(()))))
        });
        assert_eq!(
            result.err(),
            Some(super::ParallelHashExecutorError::WorkerPanicked)
        );
    }

    #[test]
    fn every_panicking_worker_is_joined_without_scope_unwind() {
        let result = std::thread::scope(|scope| {
            let handles = [
                scope.spawn(|| -> Result<(), ()> { std::panic::resume_unwind(Box::new(1_u8)) }),
                scope.spawn(|| -> Result<(), ()> { std::panic::resume_unwind(Box::new(2_u8)) }),
            ];
            let mut error = None;
            for handle in handles {
                if let Err(found) = super::join_worker(handle) {
                    error.get_or_insert(found);
                }
            }
            error
        });
        assert_eq!(
            result,
            Some(super::ParallelHashExecutorError::WorkerPanicked)
        );
    }
}
