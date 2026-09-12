//! Opt-in bounded threads with separately selected hardened worker/root routes.
//! CPU sessions are created inside each worker, never transferred across threads.
//! This executor owns scheduling only; all cryptography stays in Brynja leaves.
//!
//! ```
//! use brynja_hash_parallel::{Fips202BitString, execution::Identity};
//! use brynja_hash_parallel_std::{CancellationToken, execution::{Config, Error, Executor, Preference, Request}};
//! let executor = Executor::new(Config {
//!     workers: 2, max_leaves: 64,
//!     root: Preference::Prefer, leaves: Preference::Prefer,
//! })?;
//! let request = Request {
//!     identity: Identity::ParallelHash128,
//!     input: Fips202BitString::new(b"message", 8).map_err(|_| Error::Limits)?,
//!     block_size: 8,
//!     customization: Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?,
//! };
//! let mut output = [0; 32];
//! let mut scratch = [0; 32];
//! let report = executor.hash_public(&request, &mut output, &mut scratch, &CancellationToken::new())?;
//! assert_eq!(report.leaves, 1);
//! assert_eq!(scratch, [0; 32]);
//! # Ok::<(), Error>(())
//! ```

mod selection;
mod worker;

use crate::CancellationToken;
use brynja_core::clear_owned_region;
use brynja_hash_parallel::{
    Fips202BitString, ParallelHashPublicDeclassification as Public, ParallelHashSecretOutput,
    execution::{Collector, Identity, Plan, Report as RootReport, WorkerPolicy},
};
use selection::Selection;
use std::sync::{Mutex, TryLockError};

/// Public route preference, independently chosen for root and workers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preference {
    /// Never use CPU instructions outside the portable profile.
    Portable,
    /// Prefer acceleration; portable only when the platform lacks support.
    Prefer,
    /// Fail if accelerated authority is unavailable; no silent fallback.
    Require,
    /// Require a target-specialized binary with the complete ISA bundle.
    /// Deployment must preserve those features on every executing CPU; this
    /// does not perform hosted detection or change affinity/migration policy.
    RequireStatic,
}

/// Bounded scheduling or cryptographic failure without secret payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Workers must be 1..=64 and the leaf budget must be positive.
    Limits,
    /// Required platform acceleration is unavailable.
    Unavailable,
    /// Exact hosted detection/authority failure.
    Hosted(brynja_crypto_cpu_std::execution::Error),
    /// Exact target-specialized authority failure; never permits fallback.
    Static(brynja_crypto_cpu::static_execution::Error),
    /// Exact construction/worker execution failure.
    Crypto(brynja_hash_parallel::execution::Error),
    /// Concurrent use, allocation, or OS thread creation exhausted resources.
    Resource,
    /// Cooperative cancellation was observed; active jobs were joined/cleared.
    Cancelled,
    /// A worker panicked or the operation mutex was poisoned.
    WorkerPanicked,
}
impl From<brynja_hash_parallel::execution::Error> for Error {
    fn from(error: brynja_hash_parallel::execution::Error) -> Self {
        Self::Crypto(error)
    }
}

/// Exact public job limits. Threads and ISA acceleration are separate controls.
pub struct Config {
    /// Maximum simultaneous leaf workers; must be 1..=64.
    pub workers: usize,
    /// Maximum leaves in one complete input; must be positive.
    pub max_leaves: u128,
    /// Root-node selection before processing customization/leaf values.
    pub root: Preference,
    /// Per-thread selection before processing each secret-bearing leaf.
    pub leaves: Preference,
}

/// Borrowed canonical input/customization and exact standard identity.
/// Caller-owned input buffers are never erased by this descriptor.
pub struct Request<'a> {
    /// The fixed or XOF identity, never inferred from output length.
    pub identity: Identity,
    /// Arbitrary-bit canonical input.
    pub input: Fips202BitString<'a>,
    /// Positive standard block size B in bytes.
    pub block_size: usize,
    /// Arbitrary-bit customization; may be confidential.
    pub customization: Fips202BitString<'a>,
}

/// Completed public work observations, not independent verification evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Root route; None denotes portable hardened processing.
    pub root: Option<RootReport>,
    /// Number of completed and merged leaves.
    pub leaves: u128,
    /// Completed leaves that actually used an accelerated backend.
    pub accelerated_leaves: u128,
    /// Maximum submitted jobs in one bounded batch, not a SIMD lane count.
    pub thread_width: usize,
}

/// Single-operation, bounded thread executor with explicit routing policies.
pub struct Executor {
    config: Config,
    gate: Mutex<()>,
}
impl Executor {
    /// Validates resource limits without starting threads or touching secrets.
    pub fn new(config: Config) -> Result<Self, Error> {
        if !(1..=64).contains(&config.workers) || config.max_leaves == 0 {
            return Err(Error::Limits);
        }
        Ok(Self {
            config,
            gate: Mutex::new(()),
        })
    }
    fn plan<'a>(&self, request: &Request<'a>) -> Result<Plan<'a>, Error> {
        let workers = match self.config.leaves {
            Preference::Portable => WorkerPolicy::Portable,
            Preference::Prefer => WorkerPolicy::Mixed,
            Preference::Require | Preference::RequireStatic => WorkerPolicy::RequireAcceleration,
        };
        Ok(Plan::new_bits(
            request.identity,
            request.input,
            request.block_size,
            self.config.max_leaves,
        )?
        .with_worker_policy(workers))
    }
    fn gate(&self) -> Result<std::sync::MutexGuard<'_, ()>, Error> {
        match self.gate.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::WouldBlock) => Err(Error::Resource),
            Err(TryLockError::Poisoned(_)) => Err(Error::WorkerPanicked),
        }
    }
    /// Computes complete public bytes with transactional caller-owned staging.
    /// The entire scratch is cleared on every exit, including early admission failure.
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
    /// Computes canonical public output bits; output is unchanged on any error.
    pub fn hash_public_bits(
        &self,
        request: &Request<'_>,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        let stage = Scratch(scratch);
        let _operation = self.gate()?;
        live(cancellation)?;
        let plan = self.plan(request)?;
        let owner = Selection::new(self.config.root)?;
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
    /// Transfers secret bytes; all failures clear the entire destination.
    pub fn hash_secret<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.hash_secret_bits(request, output, valid, cancellation)
    }
    /// Transfers canonical secret output bits, including destination erasure on invalid widths.
    pub fn hash_secret_bits<'out>(
        &self,
        request: &Request<'_>,
        output: &'out mut [u8],
        valid: u8,
        cancellation: &CancellationToken,
    ) -> Result<(ParallelHashSecretOutput<'out>, Report), Error> {
        let _ = clear_owned_region(output);
        let _operation = self.gate()?;
        live(cancellation)?;
        let plan = self.plan(request)?;
        let owner = Selection::new(self.config.root)?;
        let mut root = Collector::new_bits(&plan, owner.mode()?, request.customization)?;
        let report = self.execute(&plan, &mut root, cancellation)?;
        let secret = if is_xof(request.identity) {
            root.finalize_xof()?.squeeze_final_secret(output, valid)?
        } else {
            root.finalize_secret_bits(output, valid)?
        };
        Ok((secret, report))
    }
    fn execute<'plan, 'input>(
        &self,
        plan: &'plan Plan<'input>,
        root: &mut Collector<'plan, 'input, '_>,
        cancellation: &CancellationToken,
    ) -> Result<Report, Error> {
        worker::run(plan, root, &self.config, cancellation)?;
        live(cancellation)?;
        let leaves = usize::try_from(plan.leaf_count()).map_err(|_| Error::Limits)?;
        Ok(Report {
            root: root.report(),
            leaves: root.merged_leaves(),
            accelerated_leaves: root.accelerated_leaves(),
            thread_width: self.config.workers.min(leaves),
        })
    }
}
fn is_xof(identity: Identity) -> bool {
    matches!(
        identity,
        Identity::ParallelHashXof128 | Identity::ParallelHashXof256
    )
}
pub(super) fn live(token: &CancellationToken) -> Result<(), Error> {
    if token.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
struct Scratch<'a>(&'a mut [u8]);
impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0);
    }
}

#[cfg(test)]
mod tests;
