//! Incremental, bounded multibuffer input; no thread creation or allocation.
use super::CompleteInput;
use crate::Fips202BitString;
use crate::execution::{
    Collector, Error as RootError, Mode, Report, StreamConfig,
    batch::{self, Control, Error, Executor},
    binding::Binding,
};
use brynja_core::clear_owned_region;
mod output;
pub use output::StreamReader;

/// Distinct clearing stream buffering exactly four B-byte leaves.
/// Small updates retain pending bytes until a complete group is available.
/// Final partial groups use the supplied executor's explicit Prefer/Require
/// policy; a required route never silently changes to portable execution.
/// Root selection is independent; lengths and scheduling metadata are public.
/// Errors/unwind cancel the stream. Caller-owned input copies are not erased.
///
/// ```
/// use brynja_hash_parallel::execution::{batch, Identity, Mode, StreamConfig, WorkerPolicy};
/// # fn main() -> Result<(), batch::Error> {
/// let executor = batch::Executor::portable();
/// let mut storage = [0; 32]; // Four leaves, B = 8.
/// let mut stream = batch::Stream::new(StreamConfig {
///     identity: Identity::ParallelHash128, max_leaves: 16, workers: WorkerPolicy::Mixed,
/// }, 8, Mode::Portable, &executor, &mut storage, b"domain")?;
/// let mut no = || false;
/// let mut control = batch::Control::new(64, &mut no);
/// stream.update(b"message", &mut control)?;
/// let mut bytes = [0; 32];
/// let secret = stream.finalize_secret(&mut bytes, &mut control)?;
/// assert_eq!(secret.expose().len(), 32);
/// drop(secret);
/// assert_eq!(bytes, [0; 32]);
/// assert_eq!(storage, [0; 32]);
/// # Ok(()) }
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Stream;
/// fn require<T: Send>() {} require::<Stream<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Stream;
/// fn require<T: Sync>() {} require::<Stream<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Stream;
/// fn require<T: Copy>() {} require::<Stream<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Stream;
/// fn require<T: Clone>() {} require::<Stream<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::Stream;
/// fn require<T: core::fmt::Debug>() {} require::<Stream<'_, '_, '_>>();
/// ```
pub struct Stream<'workspace, 'worker, 'authority> {
    root: Collector<'static, 'static, 'authority>,
    executor: &'worker Executor<'worker>,
    workspace: &'workspace mut [u8],
    hash: batch::Workspace,
    used: [u8; 16],
    input_bits: [u8; 16],
    block: usize,
    limit: u128,
}
impl crate::execution::sealed::Owner for Stream<'_, '_, '_> {}
impl crate::execution::HardenedState for Stream<'_, '_, '_> {}
impl crate::execution::sealed::Owner for StreamReader<'_, '_, '_, '_> {}
impl crate::execution::HardenedState for StreamReader<'_, '_, '_, '_> {}
impl<'workspace, 'worker, 'authority> Stream<'workspace, 'worker, 'authority> {
    /// Clears supplied storage even on rejection; its length must be exactly 4B.
    pub fn new(
        config: StreamConfig,
        block: usize,
        root: Mode<'authority>,
        executor: &'worker Executor<'worker>,
        workspace: &'workspace mut [u8],
        custom: &[u8],
    ) -> Result<Self, Error> {
        let _ = clear_owned_region(workspace);
        Self::new_bits(
            config,
            block,
            root,
            executor,
            workspace,
            crate::execution::bits(custom)?,
        )
    }
    /// Arbitrary-bit customization with the same exact 4B storage contract.
    pub fn new_bits(
        config: StreamConfig,
        block: usize,
        root: Mode<'authority>,
        executor: &'worker Executor<'worker>,
        workspace: &'workspace mut [u8],
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        let _ = clear_owned_region(workspace);
        if block == 0 || block.checked_mul(batch::CAPACITY) != Some(workspace.len()) {
            return Err(RootError::Construction(crate::ParallelHashError::InvalidBlockSize).into());
        }
        if config.max_leaves == 0 {
            return Err(RootError::WorkLimit.into());
        }
        executor.kernel()?;
        Ok(Self {
            root: Collector::from_binding(
                Binding::Streaming {
                    identity: config.identity,
                    block,
                    limit: config.max_leaves,
                    workers: config.workers,
                },
                root,
                custom,
            )?,
            executor,
            workspace,
            hash: batch::Workspace::new(),
            used: [0; 16],
            input_bits: [0; 16],
            block,
            limit: config.max_leaves,
        })
    }
    /// Root route, not a worker execution claim.
    #[must_use]
    pub fn report(&self) -> Option<Report> {
        self.root.report()
    }
    /// Completed leaves only; pending bytes are excluded.
    #[must_use]
    pub fn merged_leaves(&self) -> u128 {
        self.root.merged_leaves()
    }
    /// Leaves that actually participated in a vector call.
    #[must_use]
    pub fn accelerated_leaves(&self) -> u128 {
        self.root.accelerated_leaves()
    }
    /// Public block size B; distinct from the 4B storage capacity.
    #[must_use]
    pub const fn block_size(&self) -> usize {
        self.block
    }
    /// Public complete input length, including pending bytes.
    #[must_use]
    pub fn input_bits(&self) -> u128 {
        u128::from_le_bytes(self.input_bits)
    }

    /// Buffers complete bytes and executes full groups. Reuse one Control across
    /// calls for a cumulative leaf-permutation budget; max_leaves always bounds
    /// the complete message. Root work retains its existing separate contract.
    pub fn update(&mut self, input: &[u8], control: &mut Control<'_>) -> Result<(), Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        control.poll()?;
        let total = guard.stream.preflight(
            (input.len() as u128)
                .checked_mul(8)
                .ok_or(RootError::WorkLimit)?,
        )?;
        guard.stream.update_inner(input, control)?;
        control.poll()?;
        guard.stream.input_bits = total.to_le_bytes();
        guard.complete = true;
        Ok(())
    }
    fn preflight(&self, additional: u128) -> Result<u128, Error> {
        if !self.root.absorbing() {
            return Err(RootError::State.into());
        }
        self.executor.kernel()?;
        let total = self
            .input_bits()
            .checked_add(additional)
            .ok_or(RootError::WorkLimit)?;
        if self.expected(total)? > self.limit {
            return Err(RootError::WorkLimit.into());
        }
        Ok(total)
    }
    fn expected(&self, total: u128) -> Result<u128, Error> {
        let bits = (self.block as u128)
            .checked_mul(8)
            .ok_or(RootError::State)?;
        let full = total.checked_div(bits).ok_or(RootError::State)?;
        let partial = total.checked_rem(bits).ok_or(RootError::State)? != 0;
        full.checked_add(u128::from(partial))
            .ok_or(RootError::State.into())
    }
    fn used(&self) -> Result<usize, Error> {
        usize::try_from(u128::from_le_bytes(self.used)).map_err(|_| RootError::State.into())
    }
    fn update_inner(&mut self, mut input: &[u8], control: &mut Control<'_>) -> Result<(), Error> {
        while !input.is_empty() {
            let used = self.used()?;
            let take = self
                .workspace
                .len()
                .checked_sub(used)
                .ok_or(RootError::State)?
                .min(input.len());
            if take == 0 {
                return Err(RootError::State.into());
            }
            let end = used.checked_add(take).ok_or(RootError::State)?;
            brynja_core::copy_secret_region(
                self.workspace.get_mut(used..end).ok_or(RootError::State)?,
                input.get(..take).ok_or(RootError::State)?,
            )
            .map_err(|_| RootError::State)?;
            self.used = (end as u128).to_le_bytes();
            input = input.get(take..).ok_or(RootError::State)?;
            if end == self.workspace.len() {
                self.flush(8, control)?;
            }
        }
        Ok(())
    }
    fn flush(&mut self, valid: u8, control: &mut Control<'_>) -> Result<(), Error> {
        let input = Fips202BitString::new(
            self.workspace.get(..self.used()?).ok_or(RootError::State)?,
            valid,
        )
        .map_err(|_| RootError::State)?;
        self.root
            .merge_stream_batch(input, self.executor, &mut self.hash, control)?;
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        Ok(())
    }
    fn finish_input(
        &mut self,
        tail: Fips202BitString<'_>,
        control: &mut Control<'_>,
    ) -> Result<CompleteInput<'_, 'authority>, Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        let stream = &mut guard.stream;
        control.poll()?;
        let total = stream.preflight(tail.bit_len() as u128)?;
        if tail.is_byte_aligned() {
            stream.update_inner(tail.as_bytes(), control)?;
            if stream.used()? != 0 {
                stream.flush(8, control)?;
            }
        } else {
            let (last, prefix) = tail.as_bytes().split_last().ok_or(RootError::State)?;
            stream.update_inner(prefix, control)?;
            let used = stream.used()?;
            brynja_core::copy_secret_region(
                core::slice::from_mut(stream.workspace.get_mut(used).ok_or(RootError::State)?),
                core::slice::from_ref(last),
            )
            .map_err(|_| RootError::State)?;
            stream.used = (used.checked_add(1).ok_or(RootError::State)? as u128).to_le_bytes();
            stream.flush(tail.valid_bits_in_last_byte(), control)?;
        }
        stream.input_bits = total.to_le_bytes();
        control.poll()?;
        stream.check_complete()?;
        guard.complete = true;
        drop(guard);
        Ok(CompleteInput {
            root: &mut self.root,
        })
    }
    fn check_complete(&self) -> Result<(), Error> {
        if self.used()? != 0 || self.root.merged_leaves() != self.expected(self.input_bits())? {
            return Err(RootError::State.into());
        }
        Ok(())
    }
    /// Permanently cancels root, pending input, CV workspace and private counters.
    #[inline(never)]
    pub fn cancel(&mut self) {
        self.root.cancel();
        self.hash.clear();
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.input_bits);
    }
}
impl Drop for Stream<'_, '_, '_> {
    fn drop(&mut self) {
        self.cancel();
    }
}
struct Operation<'state, 'workspace, 'worker, 'authority> {
    stream: &'state mut Stream<'workspace, 'worker, 'authority>,
    complete: bool,
}
impl Drop for Operation<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stream.cancel();
        }
    }
}
#[cfg(test)]
mod failures;
#[cfg(test)]
mod tests;
