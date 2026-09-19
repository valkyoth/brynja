//! Bounded threads, each running a distinct clearing multibuffer executor.
//! Worker count and SIMD width are independent. Authorities are constructed on
//! workers; only completed plan-bound secret CV loans return to the root thread.
//! Ordinary non-erasing workspaces are never used. No implicit global dispatch.
//!
//! ```
//! use brynja_hash_parallel::{Fips202BitString, execution::Identity};
//! use brynja_hash_parallel_std::{CancellationToken, execution::batch::{Config, Executor, Error, Preference, Request}};
//! # fn main() -> Result<(), Error> {
//! let executor = Executor::new(Config { workers: 2, max_leaves: 32,
//!     root: Preference::Portable, leaves: Preference::Portable,
//!     minimum_permutations: 1, max_group_permutations: 64 })?;
//! let request = Request { identity: Identity::ParallelHash128,
//!     input: Fips202BitString::new(b"message", 8).map_err(|_| Error::Limits)?,
//!     block_size: 1, customization: Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)? };
//! let mut bytes = [0; 32];
//! let (secret, report) = executor.hash_secret(&request, &mut bytes, &CancellationToken::new())?;
//! assert_eq!(report.execution.leaves, 7);
//! assert_eq!(report.groups, 2);
//! drop(secret); assert_eq!(bytes, [0; 32]);
//! # Ok(()) }
//! ```
pub mod in_place;
mod selection;
mod worker;
pub use super::{Preference, Request};
use super::{Scratch, is_xof, live};
use crate::CancellationToken;
use brynja_core::clear_owned_region;
use brynja_hash_parallel::{
    ParallelHashPublicDeclassification as Public, ParallelHashSecretOutput,
    execution::{Collector, Plan, batch as leaf},
};

/// Exact failure; no backend error authorizes a portable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Zero crossover threshold or invalid scheduling limits.
    Limits,
    /// Root selection, scheduling, cancellation or worker panic.
    Scheduling(super::Error),
    /// Hardened multibuffer execution or transport failure.
    Batch(leaf::Error),
    /// Hosted multibuffer authority failure.
    Hosted(brynja_crypto_cpu_std::keccak_hardened_batch::Error),
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Scheduling(e)
    }
}
impl From<leaf::Error> for Error {
    fn from(e: leaf::Error) -> Self {
        Self::Batch(e)
    }
}
impl From<brynja_hash_parallel::execution::Error> for Error {
    fn from(e: brynja_hash_parallel::execution::Error) -> Self {
        Self::Scheduling(super::Error::Crypto(e))
    }
}
/// Explicit public thread, input and per-group work bounds.
pub struct Config {
    /// Maximum simultaneous workers, 1..=64; not a SIMD lane count.
    pub workers: usize,
    /// Maximum leaves for the complete input.
    pub max_leaves: u128,
    /// Independent single-state hardened root routing.
    pub root: Preference,
    /// Multibuffer worker routing. Require rejects incomplete final groups.
    pub leaves: Preference,
    /// Positive vector crossover in permutations per input lane.
    pub minimum_permutations: usize,
    /// Finite permutation budget for each group of at most four leaves. The
    /// complete-input leaf limit also bounds the number of groups. Root work
    /// remains under its separate construction/output contract. Zero allows no leaf work.
    pub max_group_permutations: u64,
}
/// Completed work, not platform certification or a live-authority token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Root route, leaf counts and maximum submitted threads per wave.
    pub execution: super::Report,
    /// Number of completed groups (at most four leaves each).
    pub groups: u128,
    /// Actual vector kernel calls across joined workers.
    pub vector_calls: u64,
    /// Actual independent-state vector permutations.
    pub vector_permutations: u64,
    /// Actual clearing scalar permutations, including tails.
    pub scalar_permutations: u64,
}
/// One operation at a time; memory is bounded by the configured worker count.
/// Each worker owns local CPU/hash state and transfers only completed clearing
/// CV loans. All started workers are joined on error/cancellation/panic.
pub struct Executor {
    base: super::Executor,
    minimum: usize,
    budget: u64,
}
impl Executor {
    /// Validates bounds without allocating worker slots or creating authorities.
    pub fn new(config: Config) -> Result<Self, Error> {
        if config.minimum_permutations == 0 {
            return Err(Error::Limits);
        }
        Ok(Self {
            base: super::Executor::new(super::Config {
                workers: config.workers,
                max_leaves: config.max_leaves,
                root: config.root,
                leaves: config.leaves,
            })?,
            minimum: config.minimum_permutations,
            budget: config.max_group_permutations,
        })
    }
    /// Transactional public bytes, with full scratch erasure on every exit.
    pub fn hash_public(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        self.hash_public_bits(
            request,
            output,
            if output.is_empty() { 0 } else { 8 },
            scratch,
            cancellation,
        )
    }
    /// Canonical public bits; routine and worker failures leave output unchanged.
    pub fn hash_public_bits(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let stage = Scratch(scratch);
        let _operation = self.base.gate()?;
        live(cancellation)?;
        let plan = self.base.plan(request)?;
        let owner = super::selection::Selection::new(self.base.config.root)?;
        let mut root = Collector::new_bits(&plan, owner.mode()?, request.customization)?;
        let report = self.execute(&plan, &mut root, cancellation)?;
        if is_xof(request.identity) {
            root.finalize_xof()?.squeeze_final_public(
                output,
                valid,
                stage.0,
                Public::acknowledge(),
            )?;
        } else {
            root.finalize_public_bits(output, valid, stage.0, Public::acknowledge())?;
        }
        Ok(report)
    }
    /// Transfers fixed/XOF secret bytes into an affine clearing output owner.
    pub fn hash_secret<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.hash_secret_bits(request, output, valid, cancellation)
    }
    /// Canonical secret output bits; every error clears the complete destination.
    pub fn hash_secret_bits<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        valid: u8,
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let _ = clear_owned_region(output);
        let _operation = self.base.gate()?;
        live(cancellation)?;
        let plan = self.base.plan(request)?;
        let owner = super::selection::Selection::new(self.base.config.root)?;
        let mut root = Collector::new_bits(&plan, owner.mode()?, request.customization)?;
        let report = self.execute(&plan, &mut root, cancellation)?;
        let value = if is_xof(request.identity) {
            root.finalize_xof()?.squeeze_final_secret(output, valid)?
        } else {
            root.finalize_secret_bits(output, valid)?
        };
        Ok((value, report))
    }
    fn execute<'plan, 'input>(
        &self,
        plan: &'plan Plan<'input>,
        root: &mut Collector<'plan, 'input, '_>,
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let work = worker::run(plan, root, self, cancellation)?;
        live(cancellation)?;
        Ok(Report {
            execution: super::Report {
                root: root.report(),
                leaves: root.merged_leaves(),
                accelerated_leaves: root.accelerated_leaves(),
                thread_width: self
                    .base
                    .config
                    .workers
                    .min(usize::try_from(work.groups).map_err(|_| Error::Limits)?),
            },
            groups: work.groups,
            vector_calls: work.vector_calls,
            vector_permutations: work.vector_permutations,
            scalar_permutations: work.scalar_permutations,
        })
    }
}
#[cfg(test)]
mod tests;
