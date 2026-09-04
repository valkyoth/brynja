//! Optional bounded native-thread execution for Brynja ParallelHash.
//!
//! This crate owns no cryptographic construction. It executes exact leaf jobs
//! from `brynja-hash-parallel`, joins them deterministically, and feeds their
//! lifetime-bound results to the portable ordered collector.

use std::sync::{
    Mutex, MutexGuard, TryLockError,
    atomic::{AtomicBool, Ordering},
};

use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHash128Collector, ParallelHash128Plan,
    ParallelHash256Collector, ParallelHash256Plan, ParallelHashError,
    ParallelHashPublicDeclassification,
};

mod worker;

use worker::{ensure_live, execute128, execute256};

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
    /// The configured maximum leaf count was zero.
    InvalidLeafLimit,
    /// The input exceeds the configured leaf-work budget.
    WorkLimitExceeded,
    /// A bounded allocation could not be reserved.
    ResourceExhausted,
    /// Cooperative cancellation was observed.
    Cancelled,
    /// A worker panicked or the operation gate was poisoned; no output was released.
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
    max_leaves: u128,
    operation_gate: Mutex<()>,
}

impl ParallelHashExecutor {
    /// Creates an executor with positive worker and leaf-work limits.
    pub fn new(workers: usize, max_leaves: u128) -> Result<Self, ParallelHashExecutorError> {
        if workers == 0 {
            Err(ParallelHashExecutorError::InvalidWorkerCount)
        } else if max_leaves == 0 {
            Err(ParallelHashExecutorError::InvalidLeafLimit)
        } else {
            Ok(Self {
                workers,
                max_leaves,
                operation_gate: Mutex::new(()),
            })
        }
    }

    fn enter_operation(&self) -> Result<MutexGuard<'_, ()>, ParallelHashExecutorError> {
        match self.operation_gate.try_lock() {
            Ok(operation) => Ok(operation),
            Err(TryLockError::WouldBlock) => Err(ParallelHashExecutorError::ResourceExhausted),
            Err(TryLockError::Poisoned(_)) => Err(ParallelHashExecutorError::WorkerPanicked),
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash128Plan::new(input, block_size)?;
        let mut collector = ParallelHash128Collector::new(&plan, customization)?;
        execute128(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash128Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash128Collector::new_bits(&plan, customization)?;
        execute128(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash256Plan::new(input, block_size)?;
        let mut collector = ParallelHash256Collector::new(&plan, customization)?;
        execute256(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash256Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash256Collector::new_bits(&plan, customization)?;
        execute256(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash128Plan::new(input, block_size)?;
        let mut collector = ParallelHash128Collector::new(&plan, customization)?;
        execute128(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash128Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash128Collector::new_bits(&plan, customization)?;
        execute128(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash256Plan::new(input, block_size)?;
        let mut collector = ParallelHash256Collector::new(&plan, customization)?;
        execute256(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
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
        let _operation = self.enter_operation()?;
        let plan = ParallelHash256Plan::new_bits(input, block_size)?;
        let mut collector = ParallelHash256Collector::new_bits(&plan, customization)?;
        execute256(
            &plan,
            &mut collector,
            self.workers,
            self.max_leaves,
            cancellation,
        )?;
        ensure_live(cancellation)?;
        collector
            .finalize_xof()?
            .squeeze_final_bits_public(output, ParallelHashPublicDeclassification::acknowledge())
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn all_public_operations_reject_concurrent_use_without_waiting() {
        let executor = ParallelHashExecutor::new(2, 8);
        assert!(executor.is_ok());
        let Ok(executor) = executor else { return };
        let operation = executor.enter_operation();
        assert!(operation.is_ok());
        let Ok(_operation) = operation else { return };

        let mut byte_output = [0_u8; 32];
        for result in [
            executor.parallel_hash128(b"", 1, b"", &mut byte_output, &CancellationToken::new()),
            executor.parallel_hash256(b"", 1, b"", &mut byte_output, &CancellationToken::new()),
            executor.parallel_hash_xof128(b"", 1, b"", &mut byte_output, &CancellationToken::new()),
            executor.parallel_hash_xof256(b"", 1, b"", &mut byte_output, &CancellationToken::new()),
        ] {
            assert_eq!(result, Err(ParallelHashExecutorError::ResourceExhausted));
        }

        let input = Fips202BitString::new(&[], 0);
        let customization = Fips202BitString::new(&[], 0);
        assert!(input.is_ok());
        assert!(customization.is_ok());
        let (Ok(input), Ok(customization)) = (input, customization) else {
            return;
        };
        for operation in 0..4 {
            let mut bit_output = [0_u8; 32];
            let output = Fips202Output::new(&mut bit_output, 8);
            assert!(output.is_ok());
            let Ok(output) = output else { return };
            let result = match operation {
                0 => executor.parallel_hash128_bits(
                    input,
                    1,
                    customization,
                    output,
                    &CancellationToken::new(),
                ),
                1 => executor.parallel_hash256_bits(
                    input,
                    1,
                    customization,
                    output,
                    &CancellationToken::new(),
                ),
                2 => executor.parallel_hash_xof128_bits(
                    input,
                    1,
                    customization,
                    output,
                    &CancellationToken::new(),
                ),
                _ => executor.parallel_hash_xof256_bits(
                    input,
                    1,
                    customization,
                    output,
                    &CancellationToken::new(),
                ),
            };
            assert_eq!(result, Err(ParallelHashExecutorError::ResourceExhausted));
        }

        assert_eq!(
            executor.enter_operation().err(),
            Some(ParallelHashExecutorError::ResourceExhausted)
        );
    }

    #[test]
    fn poisoned_operation_gate_fails_closed() {
        let executor = ParallelHashExecutor::new(2, 8);
        assert!(executor.is_ok());
        let Ok(executor) = executor else { return };
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let operation = executor.enter_operation();
            assert!(operation.is_ok());
            let Ok(_operation) = operation else { return };
            std::panic::resume_unwind(Box::new(()));
        }));
        assert!(unwind.is_err());
        assert_eq!(
            executor.enter_operation().err(),
            Some(ParallelHashExecutorError::WorkerPanicked)
        );
    }
}
