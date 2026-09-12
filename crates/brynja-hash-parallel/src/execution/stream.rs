use super::{Collector, Error, Identity, Mode, Report, WorkerPolicy, binding::Binding};
use crate::Fips202BitString;
use brynja_core::clear_owned_region;

/// Public streaming identity, complete-input work budget and worker policy.
/// The caller-owned workspace length supplies the positive block size B.
pub struct StreamConfig {
    /// Exact fixed or XOF identity.
    pub identity: Identity,
    /// Positive maximum number of leaves, including any partial final leaf.
    pub max_leaves: u128,
    /// Worker route admission, independently selected from the root route.
    pub workers: WorkerPolicy,
}

/// Incremental hardened input owner with bounded caller-provided leaf storage.
/// Errors and recoverable unwind permanently cancel this owner. Caller input
/// slices are borrowed, not erased; private pending bytes and metadata are erased.
pub struct Stream<'workspace, 'authority> {
    pub(super) root: Collector<'static, 'static, 'authority>,
    workspace: &'workspace mut [u8],
    used: [u8; 16],
    input_bits: [u8; 16],
    limit: u128,
}
impl<'workspace, 'authority> Stream<'workspace, 'authority> {
    /// Selects the root before input processing. Clears the entire workspace
    /// even on construction failure; neither allocation nor a thread is created.
    pub fn new(
        config: StreamConfig,
        root: Mode<'authority>,
        workspace: &'workspace mut [u8],
        custom: &[u8],
    ) -> Result<Self, Error> {
        let _ = clear_owned_region(workspace);
        Self::new_bits(config, root, workspace, super::bits(custom)?)
    }
    /// Accepts canonical arbitrary-bit customization.
    pub fn new_bits(
        config: StreamConfig,
        root: Mode<'authority>,
        workspace: &'workspace mut [u8],
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        let _ = clear_owned_region(workspace);
        if workspace.is_empty() {
            return Err(crate::ParallelHashError::InvalidBlockSize.into());
        }
        if config.max_leaves == 0 {
            return Err(Error::WorkLimit);
        }
        let binding = Binding::Streaming {
            identity: config.identity,
            block: workspace.len(),
            limit: config.max_leaves,
            workers: config.workers,
        };
        Ok(Self {
            root: Collector::from_binding(binding, root, custom)?,
            workspace,
            used: [0; 16],
            input_bits: [0; 16],
            limit: config.max_leaves,
        })
    }
    /// Root route observation; not evidence of worker execution.
    #[must_use]
    pub fn report(&self) -> Option<Report> {
        self.root.report()
    }
    /// Number of complete leaves already merged (pending bytes are excluded).
    #[must_use]
    pub fn merged_leaves(&self) -> u128 {
        self.root.merged_leaves()
    }
    /// Number of completed leaves that actually used accelerated authority.
    #[must_use]
    pub fn accelerated_leaves(&self) -> u128 {
        self.root.accelerated_leaves()
    }
    /// Selected block size B in bytes.
    #[must_use]
    pub fn block_size(&self) -> usize {
        self.workspace.len()
    }
    /// Current complete input length, including buffered bytes.
    #[must_use]
    pub fn input_bits(&self) -> u128 {
        u128::from_le_bytes(self.input_bits)
    }

    /// Absorbs complete bytes. Selection runs once for each full leaf on this
    /// thread. Budget admission precedes mutation; any error/unwind clears state.
    pub fn update<'worker>(
        &mut self,
        input: &[u8],
        mut select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        let additional = u128::try_from(input.len())
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::WorkLimit)?;
        let total = guard.stream.preflight(additional)?;
        guard.stream.update_inner(input, &mut select)?;
        guard.stream.input_bits = total.to_le_bytes();
        guard.complete = true;
        Ok(())
    }
    fn preflight(&self, additional: u128) -> Result<u128, Error> {
        if !self.root.absorbing() {
            return Err(Error::State);
        }
        let total = self
            .input_bits()
            .checked_add(additional)
            .ok_or(Error::WorkLimit)?;
        let block_bits = u128::try_from(self.workspace.len())
            .ok()
            .and_then(|n| n.checked_mul(8))
            .ok_or(Error::WorkLimit)?;
        let full = total.checked_div(block_bits).ok_or(Error::State)?;
        let partial = total.checked_rem(block_bits).ok_or(Error::State)? != 0;
        let required = full
            .checked_add(u128::from(partial))
            .ok_or(Error::WorkLimit)?;
        if required > self.limit {
            return Err(Error::WorkLimit);
        }
        Ok(total)
    }
    fn used(&self) -> Result<usize, Error> {
        usize::try_from(u128::from_le_bytes(self.used)).map_err(|_| Error::State)
    }
    fn set_used(&mut self, used: usize) -> Result<(), Error> {
        self.used = u128::try_from(used)
            .map_err(|_| Error::State)?
            .to_le_bytes();
        Ok(())
    }
    fn update_inner<'worker>(
        &mut self,
        mut input: &[u8],
        select: &mut impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        while !input.is_empty() {
            let used = self.used()?;
            let capacity = self.workspace.len().checked_sub(used).ok_or(Error::State)?;
            let take = capacity.min(input.len());
            if take == 0 {
                return Err(Error::State);
            }
            let end = used.checked_add(take).ok_or(Error::State)?;
            self.workspace
                .get_mut(used..end)
                .ok_or(Error::State)?
                .copy_from_slice(input.get(..take).ok_or(Error::State)?);
            self.set_used(end)?;
            input = input.get(take..).ok_or(Error::State)?;
            if end == self.workspace.len() {
                self.flush(8, select)?;
            }
        }
        Ok(())
    }
    fn flush<'worker>(
        &mut self,
        valid: u8,
        select: &mut impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let used = self.used()?;
        let input = self.workspace.get(..used).ok_or(Error::State)?;
        let bits = Fips202BitString::new(input, valid).map_err(|_| Error::State)?;
        let mode = select(self.root.merged_leaves())?;
        self.root.merge_stream(bits, mode)?;
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        Ok(())
    }
    pub(super) fn finish_input<'worker>(
        &mut self,
        tail: Fips202BitString<'_>,
        mut select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            stream: self,
            complete: false,
        };
        let stream = &mut guard.stream;
        let total =
            stream.preflight(u128::try_from(tail.bit_len()).map_err(|_| Error::WorkLimit)?)?;
        let bytes = tail.as_bytes();
        if tail.is_byte_aligned() {
            stream.update_inner(bytes, &mut select)?;
            if stream.used()? != 0 {
                stream.flush(8, &mut select)?;
            }
        } else {
            let (last, prefix) = bytes.split_last().ok_or(Error::State)?;
            stream.update_inner(prefix, &mut select)?;
            let used = stream.used()?;
            *stream.workspace.get_mut(used).ok_or(Error::State)? = *last;
            stream.set_used(used.checked_add(1).ok_or(Error::State)?)?;
            stream.flush(tail.valid_bits_in_last_byte(), &mut select)?;
        }
        stream.input_bits = total.to_le_bytes();
        guard.complete = true;
        Ok(())
    }
    /// Clears the root, pending bytes and input metadata; permanently terminal.
    #[inline(never)]
    pub fn cancel(&mut self) {
        self.root.cancel();
        let _ = clear_owned_region(self.workspace);
        let _ = clear_owned_region(&mut self.used);
        let _ = clear_owned_region(&mut self.input_bits);
    }
}
impl Drop for Stream<'_, '_> {
    fn drop(&mut self) {
        self.cancel();
    }
}
pub(super) struct Operation<'state, 'workspace, 'authority> {
    pub(super) stream: &'state mut Stream<'workspace, 'authority>,
    pub(super) complete: bool,
}
impl Drop for Operation<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stream.cancel();
        }
    }
}

#[cfg(test)]
mod tests;
