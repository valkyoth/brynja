use super::{Error, Identity, Mode, Report, WorkerPolicy, backend::State};
use crate::Fips202BitString;
use brynja_core::clear_owned_region;
use brynja_hash_sha3::HardenedSha3SecretOutput;

/// Immutable input division, exact identity and positive admitted leaf budget.
/// Input storage belongs to the caller; this descriptor does not erase it.
pub struct Plan<'input> {
    input: Fips202BitString<'input>,
    pub(super) identity: Identity,
    pub(super) block_size: usize,
    pub(super) leaves: u128,
    pub(super) workers: WorkerPolicy,
}
impl<'input> Plan<'input> {
    /// Plans bytes without allocating jobs. Each leaf performs at most B bytes.
    pub fn new(
        identity: Identity,
        input: &'input [u8],
        block_size: usize,
        max_leaves: u128,
    ) -> Result<Self, Error> {
        Self::new_bits(identity, super::bits(input)?, block_size, max_leaves)
    }
    /// Plans canonical arbitrary-bit input; only the final leaf can be partial.
    pub fn new_bits(
        identity: Identity,
        input: Fips202BitString<'input>,
        block_size: usize,
        max_leaves: u128,
    ) -> Result<Self, Error> {
        let leaves = crate::scheduled::leaf_count(input.bit_len(), block_size)?;
        if max_leaves == 0 || leaves > max_leaves {
            return Err(Error::WorkLimit);
        }
        Ok(Self {
            input,
            identity,
            block_size,
            leaves,
            workers: WorkerPolicy::Mixed,
        })
    }
    /// Constrains completed worker routes before any job or collector is borrowed.
    #[must_use]
    pub fn with_worker_policy(mut self, policy: WorkerPolicy) -> Self {
        self.workers = policy;
        self
    }
    /// Exact standard identity, including fixed versus XOF domain suffix.
    #[must_use]
    pub const fn identity(&self) -> Identity {
        self.identity
    }
    /// Number of scheduled leaves; empty input requires no leaf jobs.
    #[must_use]
    pub const fn leaf_count(&self) -> u128 {
        self.leaves
    }
    /// Standard block size B in bytes.
    #[must_use]
    pub const fn block_size(&self) -> usize {
        self.block_size
    }
    /// Obtains one affine job. Callers bound outstanding storage/concurrency.
    /// Recomputing an index is permitted, but the root merges it only once.
    pub fn job(&self, index: u128) -> Result<Job<'_, 'input>, Error> {
        let input = crate::scheduled::leaf_slice(self.input, self.block_size, self.leaves, index)?;
        Ok(Job {
            plan: self,
            index,
            input,
        })
    }
}

/// A leaf input loan; create its CPU authority on the executing worker thread.
pub struct Job<'plan, 'input> {
    plan: &'plan Plan<'input>,
    index: u128,
    input: Fips202BitString<'input>,
}
impl<'plan, 'input> Job<'plan, 'input> {
    /// Exact zero-based index in the retained plan.
    #[must_use]
    pub const fn index(&self) -> u128 {
        self.index
    }
    /// Exact canonical input length for this leaf.
    #[must_use]
    pub fn input_bits(&self) -> usize {
        self.input.bit_len()
    }
    /// Computes a complete secret-owned leaf; every error clears output.
    /// Output must be exactly `plan.identity().leaf_bytes()` bytes.
    pub fn execute<'out>(
        self,
        mode: Mode<'_>,
        output: &'out mut [u8],
    ) -> Result<Leaf<'plan, 'input, 'out>, Error> {
        let _ = clear_owned_region(output);
        if output.len() != self.plan.identity.leaf_bytes() {
            return Err(Error::OutputLength);
        }
        let mut state = State::new(mode, self.plan.identity.wide(), false, super::bits(&[])?)?;
        if !self.plan.workers.accepts(state.report()) {
            return Err(Error::AccelerationUnavailable);
        }
        // The full prefix stays bulk-absorbed; at most one partial byte remains.
        let tail = if self.input.is_byte_aligned() {
            state.update(self.input.as_bytes())?;
            super::bits(&[])?
        } else {
            let (last, prefix) = self.input.as_bytes().split_last().ok_or(Error::State)?;
            state.update(prefix)?;
            Fips202BitString::new(
                core::slice::from_ref(last),
                self.input.valid_bits_in_last_byte(),
            )
            .map_err(|_| Error::State)?
        };
        state.finish(tail)?;
        let inner = state.secret(output, 8, false)?;
        let route = state.report();
        if !self.plan.workers.accepts(route) {
            return Err(Error::AccelerationUnavailable);
        }
        Ok(Leaf {
            plan: self.plan,
            index: self.index,
            input_bits: self.input.bit_len(),
            route,
            inner,
        })
    }
}

/// Completed, unforgeable leaf provenance plus clearing output ownership.
/// A route report is diagnostic, not transferable CPU execution authority.
#[must_use = "merge or drop the leaf so its secret bytes are cleared"]
pub struct Leaf<'plan, 'input, 'out> {
    pub(super) plan: &'plan Plan<'input>,
    pub(super) index: u128,
    pub(super) input_bits: usize,
    pub(super) route: Option<Report>,
    pub(super) inner: HardenedSha3SecretOutput<'out>,
}
impl Leaf<'_, '_, '_> {
    /// Observes the completed leaf's backend identity and owner generation.
    #[must_use]
    pub const fn report(&self) -> Option<Report> {
        self.route
    }
    /// Exact input length bound to this job, including its partial final byte.
    #[must_use]
    pub const fn input_bits(&self) -> usize {
        self.input_bits
    }
}
