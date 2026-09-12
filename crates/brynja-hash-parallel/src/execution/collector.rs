use super::binding::Binding;
use super::{Clear, Error, Leaf, Mode, Plan, Report, backend::State, encoding::Encoded};
use crate::{Fips202BitString, ParallelHashPublicDeclassification, ParallelHashSecretOutput};
use brynja_core::clear_owned_region;

/// Hardened root bound to one exact plan and one selected execution authority.
/// Leaf completion reports record historical work, not live worker authority.
pub struct Collector<'plan, 'input, 'authority> {
    binding: Binding<'plan, 'input>,
    state: State<'authority>,
    merged: [u8; 16],
    accelerated: [u8; 16],
    output_bits: [u8; 16],
    phase: [u8; 1],
}
impl<'plan, 'input, 'authority> Collector<'plan, 'input, 'authority> {
    /// Selects the root backend and absorbs the byte-oriented customization.
    pub fn new(
        plan: &'plan Plan<'input>,
        mode: Mode<'authority>,
        custom: &[u8],
    ) -> Result<Self, Error> {
        Self::new_bits(plan, mode, super::bits(custom)?)
    }
    /// Selects the root backend and absorbs arbitrary-bit customization.
    pub fn new_bits(
        plan: &'plan Plan<'input>,
        mode: Mode<'authority>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        Self::from_binding(Binding::Scheduled(plan), mode, custom)
    }
    pub(super) fn from_binding(
        binding: Binding<'plan, 'input>,
        mode: Mode<'authority>,
        custom: Fips202BitString<'_>,
    ) -> Result<Self, Error> {
        let mut root = Self {
            state: State::new(mode, binding.identity().wide(), true, custom)?,
            binding,
            merged: [0; 16],
            accelerated: [0; 16],
            output_bits: [0; 16],
            phase: [1],
        };
        let block = u128::try_from(root.binding.block()).map_err(|_| Error::State)?;
        root.state.update(Encoded::new(block, true)?.bytes()?)?;
        Ok(root)
    }
    /// Non-authorizing root route observation, separate from worker routing.
    #[must_use]
    pub fn report(&self) -> Option<Report> {
        self.state.report()
    }
    /// Number of ordered leaves successfully absorbed by this root.
    #[must_use]
    pub fn merged_leaves(&self) -> u128 {
        u128::from_le_bytes(self.merged)
    }
    /// Actual completed accelerated leaves, not a thread-count claim.
    #[must_use]
    pub fn accelerated_leaves(&self) -> u128 {
        u128::from_le_bytes(self.accelerated)
    }
    /// Borrows and absorbs exactly the next plan-bound completed result.
    /// Failure or unwind permanently clears the root; it cannot be retried.
    pub fn merge(&mut self, leaf: &Leaf<'plan, 'input, '_>) -> Result<(), Error> {
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let root = &mut guard.root;
        let plan = root.binding.scheduled()?;
        if root.phase != [1]
            || !core::ptr::eq(plan, leaf.plan)
            || leaf.index != root.merged_leaves()
            || leaf.index >= plan.leaves
            || leaf.input_bits != plan.job(leaf.index)?.input_bits()
        {
            return Err(Error::State);
        }
        root.absorb_value(leaf.inner.expose(), leaf.route)?;
        guard.complete = true;
        Ok(())
    }
    fn absorb_value(&mut self, value: &[u8], route: Option<Report>) -> Result<(), Error> {
        if self.phase != [1]
            || self.merged_leaves() >= self.binding.limit()
            || value.len() != self.binding.identity().leaf_bytes()
            || !self.binding.workers().accepts(route)
        {
            return Err(Error::State);
        }
        let merged = self.merged_leaves().checked_add(1).ok_or(Error::State)?;
        let accelerated = self
            .accelerated_leaves()
            .checked_add(u128::from(route.is_some()))
            .ok_or(Error::State)?;
        self.state.update(value)?;
        self.merged = merged.to_le_bytes();
        self.accelerated = accelerated.to_le_bytes();
        Ok(())
    }
    pub(super) fn merge_stream(
        &mut self,
        input: Fips202BitString<'_>,
        mode: Mode<'_>,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let root = &mut guard.root;
        if !matches!(root.binding, Binding::Streaming { .. }) || root.phase != [1] {
            return Err(Error::State);
        }
        let plan = Plan::new_bits(root.binding.identity(), input, root.binding.block(), 1)?
            .with_worker_policy(root.binding.workers());
        let mut slot = [0_u8; 64];
        let stage = Clear(&mut slot);
        let output = stage
            .0
            .get_mut(..plan.identity().leaf_bytes())
            .ok_or(Error::State)?;
        let leaf = plan.job(0)?.execute(mode, output)?;
        root.absorb_value(leaf.inner.expose(), leaf.route)?;
        guard.complete = true;
        Ok(())
    }
    pub(super) fn absorbing(&self) -> bool {
        self.phase == [1]
    }
    /// Serial, constant-storage leaf scheduling with per-leaf selection.
    /// The callback must create sessions on this thread. Callback failure/unwind
    /// clears this root; returned worker errors are never converted to fallback.
    pub fn execute_serial<'worker>(
        &mut self,
        mut select: impl FnMut(u128) -> Result<Mode<'worker>, Error>,
    ) -> Result<(), Error> {
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        if guard.root.phase != [1] {
            return Err(Error::State);
        }
        let plan = guard.root.binding.scheduled()?;
        while guard.root.merged_leaves() < plan.leaves {
            let index = guard.root.merged_leaves();
            let mut storage = [0_u8; 64];
            let stage = Clear(&mut storage);
            let output = stage
                .0
                .get_mut(..plan.identity.leaf_bytes())
                .ok_or(Error::State)?;
            let leaf = plan.job(index)?.execute(select(index)?, output)?;
            guard.root.merge(&leaf)?;
        }
        guard.complete = true;
        Ok(())
    }
    /// Clears private root state and metadata; later operations are terminal.
    #[inline(never)]
    pub fn cancel(&mut self) {
        self.state.wipe();
        let _ = clear_owned_region(&mut self.merged);
        let _ = clear_owned_region(&mut self.accelerated);
        let _ = clear_owned_region(&mut self.output_bits);
        let _ = clear_owned_region(&mut self.phase);
    }
    pub(super) fn finish(&mut self, output_bits: u128, xof: bool) -> Result<(), Error> {
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let root = &mut guard.root;
        if root.phase != [1]
            || root.binding.identity().xof() != xof
            || !root.binding.complete(root.merged_leaves())
        {
            return Err(Error::State);
        }
        root.state
            .update(Encoded::new(root.merged_leaves(), false)?.bytes()?)?;
        root.state
            .update(Encoded::new(output_bits, false)?.bytes()?)?;
        root.state.finish(super::bits(&[])?)?;
        root.phase = [2];
        guard.complete = true;
        Ok(())
    }
    pub(super) fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
        valid: u8,
        terminal: bool,
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        let _ = clear_owned_region(output);
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let root = &mut guard.root;
        let count = output_length(output.len(), valid)?;
        if root.phase != [2] || (!terminal && valid != if output.is_empty() { 0 } else { 8 }) {
            return Err(Error::State);
        }
        let total = u128::from_le_bytes(root.output_bits)
            .checked_add(count)
            .ok_or(Error::OutputLength)?;
        let owned = root.state.secret(output, valid, terminal)?;
        root.output_bits = total.to_le_bytes();
        if terminal {
            root.cancel();
        }
        guard.complete = true;
        Ok(ParallelHashSecretOutput::new(owned))
    }
    pub(super) fn public(
        &mut self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        terminal: bool,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let target = stage.0.get_mut(..output.len()).ok_or(Error::OutputLength)?;
        let secret = guard.root.secret(target, valid, terminal)?;
        output.copy_from_slice(secret.expose());
        guard.complete = true;
        Ok(())
    }
    /// Fixed public output with full-length transactional staging.
    /// Explicit declassification is required because this is a hardened owner.
    pub fn finalize_public(
        self,
        output: &mut [u8],
        scratch: &mut [u8],
        authority: ParallelHashPublicDeclassification,
    ) -> Result<(), Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_public_bits(output, valid, scratch, authority)
    }
    /// Fixed canonical public bits. Errors preserve output and erase scratch.
    pub fn finalize_public_bits(
        mut self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _authority: ParallelHashPublicDeclassification,
    ) -> Result<(), Error> {
        let stage = Clear(scratch);
        let count = output_length(output.len(), valid)?;
        self.finish(count, false)?;
        self.public(output, valid, stage.0, true)
    }
    /// Fixed secret bytes; every failure clears the complete destination.
    pub fn finalize_secret(self, output: &mut [u8]) -> Result<ParallelHashSecretOutput<'_>, Error> {
        let valid = if output.is_empty() { 0 } else { 8 };
        self.finalize_secret_bits(output, valid)
    }
    /// Fixed canonical secret bits; invalid widths also clear the destination.
    pub fn finalize_secret_bits(
        mut self,
        output: &mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'_>, Error> {
        let _ = clear_owned_region(output);
        self.finish(output_length(output.len(), valid)?, false)?;
        self.secret(output, valid, true)
    }
    /// Enters XOF mode only for a plan with the exact XOF identity.
    /// Reader abandonment clears this root; no inner sponge is moved out.
    pub fn finalize_xof(&mut self) -> Result<Reader<'_, 'plan, 'input, 'authority>, Error> {
        self.finish(0, true)?;
        Ok(Reader { root: self })
    }
}
impl Drop for Collector<'_, '_, '_> {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct Operation<'state, 'plan, 'input, 'authority> {
    root: &'state mut Collector<'plan, 'input, 'authority>,
    complete: bool,
}
impl Drop for Operation<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.root.cancel();
        }
    }
}

/// Exclusively borrowed hardened XOF reader. Drop closes the retained root.
pub struct Reader<'state, 'plan, 'input, 'authority> {
    root: &'state mut Collector<'plan, 'input, 'authority>,
}
impl Reader<'_, '_, '_, '_> {
    /// Transfers the next full-byte fragment into typed clearing ownership.
    pub fn squeeze_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<ParallelHashSecretOutput<'out>, Error> {
        self.root
            .secret(output, if output.is_empty() { 0 } else { 8 }, false)
    }
    /// Explicitly declassifies the next bytes; failures preserve output.
    pub fn squeeze_public(
        &mut self,
        output: &mut [u8],
        scratch: &mut [u8],
        _authority: ParallelHashPublicDeclassification,
    ) -> Result<(), Error> {
        self.root.public(
            output,
            if output.is_empty() { 0 } else { 8 },
            scratch,
            false,
        )
    }
    /// Consumes this reader into final canonical secret bits.
    pub fn squeeze_final_secret(
        self,
        output: &mut [u8],
        valid: u8,
    ) -> Result<ParallelHashSecretOutput<'_>, Error> {
        self.root.secret(output, valid, true)
    }
    /// Consumes this reader into final canonical public bits.
    pub fn squeeze_final_public(
        self,
        output: &mut [u8],
        valid: u8,
        scratch: &mut [u8],
        _authority: ParallelHashPublicDeclassification,
    ) -> Result<(), Error> {
        self.root.public(output, valid, scratch, true)
    }
}
impl Drop for Reader<'_, '_, '_, '_> {
    fn drop(&mut self) {
        self.root.cancel();
    }
}

pub(super) fn output_length(length: usize, valid: u8) -> Result<u128, Error> {
    // Validate structure without borrowing or exposing the actual destination.
    if length == 0 {
        return if valid == 0 {
            Ok(0)
        } else {
            Err(Error::OutputLength)
        };
    }
    if !(1..=8).contains(&valid) {
        return Err(Error::OutputLength);
    }
    u128::try_from(length.checked_sub(1).ok_or(Error::OutputLength)?)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(u128::from(valid)))
        .ok_or(Error::OutputLength)
}

#[cfg(test)]
mod tests;
