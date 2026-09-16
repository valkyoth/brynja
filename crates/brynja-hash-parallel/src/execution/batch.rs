//! Bounded, plan-bound hardened SIMD leaf groups for scheduled ParallelHash.
//!
//! Root execution is independent. These are SHAKE leaves, never TupleHash items
//! or KMAC operations. Up to four contiguous leaves use one caller-owned
//! clearing workspace. Lengths, ordering and performed-work reports are public.
//! A supplied executor never silently falls back after failure. Require mode
//! applies to each group: an incomplete/ineligible final group rejects. Select
//! Prefer explicitly to allow scalar tails, or schedule a separate portable tail
//! under WorkerPolicy::Mixed. A RequireAcceleration worker policy rejects every
//! leaf that did not actually participate in a vector call.
//! No threads are created and no thread-bound authority or secret state becomes Send.
//!
//! ```
//! use brynja_hash_parallel::execution::{Collector, Identity, Mode, Plan, batch};
//! use brynja_hash_parallel::ParallelHashPublicDeclassification;
//! # fn main() -> Result<(), batch::Error> {
//! let plan = Plan::new(Identity::ParallelHash128, b"message", 2, 4)?;
//! let mut root = Collector::new(&plan, Mode::Portable, b"domain")?;
//! let mut workspace = batch::Workspace::new();
//! let mut cancel = || false;
//! let report = root.execute_batched(&batch::Executor::portable(), &mut workspace,
//!     &mut batch::Control::new(32, &mut cancel))?;
//! assert_eq!(report.leaves, 4);
//! let mut out = [0; 32];
//! let mut scratch = [0; 32];
//! root.finalize_public(&mut out, &mut scratch,
//!     ParallelHashPublicDeclassification::acknowledge())?;
//! # Ok(()) }
//! ```
pub use super::stream::batch::{Stream, StreamReader};
mod transfer;
use super::{Error as RootError, Plan, WorkerPolicy};
use brynja_core::clear_owned_region;
use brynja_hash_sha3::hardened_batch as hash;
pub use hash::{Authority, Control, Executor, Kernel, Mode, Report as KernelReport};
pub use transfer::TransferredLeaves;
/// Maximum independently scheduled leaves in one group, not a thread count.
pub const CAPACITY: usize = hash::CAPACITY;

/// Exact plan/root or batch failure. No failure authorizes route substitution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid provenance, ordering, root state or worker policy.
    Root(RootError),
    /// Exact leaf execution failure, including work budget and cancellation.
    Hash(hash::Error),
}
impl From<RootError> for Error {
    fn from(error: RootError) -> Self {
        Self::Root(error)
    }
}
impl From<hash::Error> for Error {
    fn from(error: hash::Error) -> Self {
        Self::Hash(error)
    }
}

/// Actual completed group accounting, separate from root and thread routing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Leaves merged by this call, excluding any previously merged leaves.
    pub leaves: u128,
    /// Leaves participating in at least one real vector call.
    pub accelerated_leaves: u128,
    /// Leaves processed entirely by clearing scalar code.
    pub scalar_leaves: u128,
    /// Actual vector calls, not an advertised SIMD width.
    pub vector_calls: u64,
    /// Actual independent-state vector permutations.
    pub vector_permutations: u64,
    /// Actual scalar permutations, including unequal tails.
    pub scalar_permutations: u64,
}

/// Clearing bounded leaf values and staging. No ordinary workspace conversion.
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Workspace;
/// fn require<T: Send>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Workspace;
/// fn require<T: Sync>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Workspace;
/// fn require<T: Copy>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Workspace;
/// fn require<T: Clone>() {}
/// require::<Workspace>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Workspace;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Workspace>();
/// ```
pub struct Workspace {
    hash: hash::Workspace,
    values: [[u8; 64]; CAPACITY],
    staging: [u8; 256],
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
impl Workspace {
    /// Allocates no heap storage; SIMD width and thread count are independent.
    pub fn new() -> Self {
        Self {
            hash: hash::Workspace::new(),
            values: [[0; 64]; CAPACITY],
            staging: [0; 256],
        }
    }
    /// Clears all active/unused capacity. Completed results retain an exclusive
    /// borrow until merged or dropped, preventing premature workspace reuse.
    pub fn clear(&mut self) {
        self.hash.clear();
        let _ = clear_owned_region(self.values.as_flattened_mut());
        let _ = clear_owned_region(&mut self.staging);
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        tests::observe_drop(self);
    }
}

/// Contiguous affine leaf job bound to the exact plan object and indices.
pub struct Job<'plan, 'input> {
    plan: &'plan Plan<'input>,
    start: u128,
    count: usize,
}
impl<'input> Plan<'input> {
    /// Selects 1..=4 consecutive leaves; no implicit shortening or reordering.
    pub fn batch(&self, start: u128, count: usize) -> Result<Job<'_, 'input>, Error> {
        let end = start.checked_add(count as u128).ok_or(RootError::State)?;
        if count == 0 || count > CAPACITY || end > self.leaf_count() {
            return Err(RootError::State.into());
        }
        Ok(Job {
            plan: self,
            start,
            count,
        })
    }
}
impl<'plan, 'input> Job<'plan, 'input> {
    /// Executes inner SHAKE with the complete standard 32/64-byte CV width.
    /// Failed work clears all supplied workspace; successful CVs remain secret
    /// and cannot be imported as public digests or forged collector tokens.
    pub fn execute<'out>(
        self,
        executor: &Executor<'_>,
        workspace: &'out mut Workspace,
        control: &mut Control<'_>,
    ) -> Result<Leaves<'plan, 'input, 'out>, Error> {
        workspace.clear();
        let kernel = executor.kernel()?;
        match self.plan.workers {
            WorkerPolicy::Portable if kernel.is_some() => {
                return Err(RootError::AccelerationUnavailable.into());
            }
            WorkerPolicy::RequireAcceleration if kernel.is_none() => {
                return Err(RootError::AccelerationUnavailable.into());
            }
            _ => {}
        }
        let algorithm = if self.plan.identity.wide() {
            hash::Algorithm::Shake256
        } else {
            hash::Algorithm::Shake128
        };
        let width = self.plan.identity.leaf_bytes();
        let mut inputs: [Option<hash::Input<'_>>; CAPACITY] = core::array::from_fn(|_| None);
        for (offset, slot) in inputs.iter_mut().enumerate().take(self.count) {
            let index = self
                .start
                .checked_add(offset as u128)
                .ok_or(RootError::State)?;
            *slot = Some(hash::Input::new(
                algorithm,
                self.plan.job(index)?.input,
                width.checked_mul(8).ok_or(RootError::State)?,
            )?);
        }
        let mut destinations: [Option<&mut [u8]>; CAPACITY] = core::array::from_fn(|_| None);
        for (slot, value) in destinations
            .iter_mut()
            .zip(&mut workspace.values)
            .take(self.count)
        {
            *slot = Some(value.get_mut(..width).ok_or(RootError::State)?);
        }
        let (inner, report) = executor.digest_secret(
            &inputs,
            destinations,
            &mut workspace.hash,
            &mut workspace.staging,
            control,
        )?;
        let active = (1_u8
            .checked_shl(u32::try_from(self.count).map_err(|_| RootError::State)?)
            .ok_or(RootError::State)?)
        .checked_sub(1)
        .ok_or(RootError::State)?;
        if report.accelerated_slots & !active != 0
            || (report.accelerated_slots != 0) != (report.vector_calls != 0)
            || (report.accelerated_slots != 0 && report.kernel != kernel)
        {
            executor.quarantine();
            return Err(RootError::State.into());
        }
        if self.plan.workers == WorkerPolicy::RequireAcceleration
            && report.accelerated_slots != active
        {
            return Err(RootError::AccelerationUnavailable.into());
        }
        Ok(Leaves {
            plan: self.plan,
            start: self.start,
            count: self.count,
            inner,
            report,
        })
    }
}

/// Unforgeable completed CVs, retaining plan/index identity and clearing borrows.
/// Thread-bound: consume with `transfer` for a separate completed-only transport
/// loan; no authority or unfinished hash state crosses workers.
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::{Collector, batch::Leaves};
/// fn reuse<'p, 'i>(root: &mut Collector<'p, 'i, '_>, leaves: Leaves<'p, 'i, '_>) {
///     let _ = root.merge_batch(leaves);
///     let _ = root.merge_batch(leaves);
/// }
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::{ParallelHashSecretOutput, execution::batch::Leaves};
/// fn forge<'a>(output: ParallelHashSecretOutput<'a>) -> Leaves<'static, 'static, 'a> {
///     output.into()
/// }
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Leaves;
/// fn require<T: Send>() {}
/// require::<Leaves<'_, '_, '_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Leaves;
/// fn require<T: Sync>() {}
/// require::<Leaves<'_, '_, '_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Leaves;
/// fn require<T: Copy>() {}
/// require::<Leaves<'_, '_, '_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Leaves;
/// fn require<T: Clone>() {}
/// require::<Leaves<'_, '_, '_>>();
/// ```
///
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Leaves;
/// fn require<T: core::fmt::Debug>() {}
/// require::<Leaves<'_, '_, '_>>();
/// ```
#[must_use = "merge or drop completed leaf values so their storage clears"]
pub struct Leaves<'plan, 'input, 'out> {
    pub(super) plan: &'plan Plan<'input>,
    pub(super) start: u128,
    pub(super) count: usize,
    pub(super) inner: hash::SecretBatchOutput<'out>,
    pub(super) report: KernelReport,
}
impl Leaves<'_, '_, '_> {
    /// Historical actual work only; cannot authorize further CPU execution.
    pub const fn report(&self) -> KernelReport {
        self.report
    }
    /// Number of consecutive completed leaves, not a CPU/thread width claim.
    pub const fn len(&self) -> usize {
        self.count
    }
    /// Completed batches are always nonempty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests;
