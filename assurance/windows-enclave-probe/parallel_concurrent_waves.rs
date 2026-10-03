//! Private constant-storage multi-wave scheduler. Not a shipping API or OS
//! protection primitive. The callback is an internal scheduling seam, not a
//! consumer callback admitted by a production enclave interface.
#![forbid(unsafe_code)]
use super::{Authority, Bits, Error, Phase, Plan, SecretEncodedInteger, Slot, State};
use super::{check_authority, empty, shape};
use brynja_core::clear_owned_region;
use core::marker::PhantomData;
use core::sync::atomic::Ordering;

/// Explicit private-fixture work bound, not an allocation proportional to input.
pub const MAX_LEAVES: usize = 65536;

pub struct Waves<'authority> {
    authority: &'authority Authority,
    state: State<'authority>,
    identity: u64,
    block: usize,
    total_bits: usize,
    expected_leaves: usize,
    consumed_bits: usize,
    merged_leaves: usize,
    output_bits: usize,
    output: [u8; 1024],
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
    #[cfg(test)]
    before_commit: Option<fn()>,
}

struct Operation<'a, 'authority> {
    root: &'a mut Waves<'authority>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.root.clear();
        }
    }
}

impl<'authority> Waves<'authority> {
    pub fn new(
        authority: &'authority Authority,
        identity: u64,
        block: usize,
        total_bits: usize,
        custom: Bits<'_>,
        output_bits: usize,
    ) -> Result<Self, Error> {
        // Reuse bounded-plan shape validation without pretending the entire
        // message fits in a single wave.
        let _ = Plan::new(identity, block, 0, custom.bit_len(), output_bits)?;
        check_authority(authority)?;
        let block_bits = block.checked_mul(8).ok_or(Error::Length)?;
        let expected_leaves = total_bits
            .checked_div(block_bits)
            .ok_or(Error::Length)?
            .checked_add(usize::from(
                total_bits.checked_rem(block_bits).ok_or(Error::Length)? != 0,
            ))
            .ok_or(Error::Length)?;
        if expected_leaves > MAX_LEAVES {
            return Err(Error::Length);
        }
        let mut state = State::setup(
            authority,
            identity,
            u128::try_from(custom.bit_len()).map_err(|_| Error::Length)?,
        )?;
        state.custom(custom)?;
        state.finish_custom()?;
        let mut framing = SecretEncodedInteger::empty();
        framing.left(u128::try_from(block).map_err(|_| Error::Length)?)?;
        state.update(framing.bytes()?)?;
        Ok(Self {
            authority,
            state,
            identity,
            block,
            total_bits,
            expected_leaves,
            consumed_bits: 0,
            merged_leaves: 0,
            output_bits,
            output: [0; 1024],
            phase: Phase::Working,
            thread_bound: PhantomData,
            #[cfg(test)]
            before_commit: None,
        })
    }

    fn clear(&mut self) {
        self.state = State::Empty;
        let _ = clear_owned_region(&mut self.output);
        self.phase = Phase::Dead;
    }

    pub fn cancel(&mut self) {
        self.clear();
    }

    /// Execute exactly the next wave, never a caller-selected range. The first
    /// argument is its public byte offset. The callback cannot retain borrowed
    /// slots/plan after return, or access this exclusively borrowed root. Native
    /// FFI adapters must separately prove join-before-return across raw pointers.
    pub fn wave<F>(&mut self, run: F) -> Result<(), Error>
    where
        F: for<'wave> FnOnce(usize, &'wave Plan, &mut [Slot<'wave>]) -> Result<(), Error>,
    {
        let mut op = Operation {
            root: self,
            complete: false,
        };
        if op.root.phase != Phase::Working || op.root.consumed_bits >= op.root.total_bits {
            return Err(Error::State);
        }
        check_authority(op.root.authority)?;
        let capacity = op.root.block.checked_mul(32).ok_or(Error::Length)?;
        let remaining = op
            .root
            .total_bits
            .checked_sub(op.root.consumed_bits)
            .ok_or(Error::Length)?;
        let bits = remaining.min(capacity);
        if !op.root.consumed_bits.is_multiple_of(8) {
            return Err(Error::State);
        }
        let offset = op.root.consumed_bits / 8;
        let plan = Plan::new(op.root.identity, op.root.block, bits, 0, 0)?;
        // This wave owns all slots for this exact plan. Do not allow a second
        // Batch to be manufactured from the callback's immutable plan reference.
        plan.claimed.store(true, Ordering::Release);
        let mut slots: [Slot<'_>; 4] = core::array::from_fn(|index| Slot::new(&plan, index));
        run(
            offset,
            &plan,
            slots.get_mut(..plan.leaves).ok_or(Error::Length)?,
        )?;
        plan.check()?;
        check_authority(op.root.authority)?;
        for (index, slot) in slots.iter_mut().enumerate() {
            if index < plan.leaves {
                slot.absorb(&mut op.root.state, &plan, index)?;
            } else if !slot.unused() {
                return Err(Error::State);
            }
        }
        let merged = op
            .root
            .merged_leaves
            .checked_add(plan.leaves)
            .ok_or(Error::Length)?;
        let consumed = op
            .root
            .consumed_bits
            .checked_add(bits)
            .ok_or(Error::Length)?;
        if merged > op.root.expected_leaves || consumed > op.root.total_bits {
            return Err(Error::State);
        }
        op.root.merged_leaves = merged;
        op.root.consumed_bits = consumed;
        op.complete = true;
        Ok(())
    }

    /// Exact completion required before adding the global count/output suffix.
    pub fn finish(&mut self) -> Result<(), Error> {
        let mut op = Operation {
            root: self,
            complete: false,
        };
        if op.root.phase != Phase::Working
            || op.root.consumed_bits != op.root.total_bits
            || op.root.merged_leaves != op.root.expected_leaves
        {
            return Err(Error::State);
        }
        check_authority(op.root.authority)?;
        let mut framing = SecretEncodedInteger::empty();
        framing.right(u128::try_from(op.root.merged_leaves).map_err(|_| Error::Length)?)?;
        op.root.state.update(framing.bytes()?)?;
        framing.right(if op.root.identity <= 2 {
            u128::try_from(op.root.output_bits).map_err(|_| Error::Length)?
        } else {
            0
        })?;
        op.root.state.update(framing.bytes()?)?;
        op.root.state.finish(empty()?)?;
        let (width, last) = shape(op.root.output_bits)?;
        op.root.state.squeeze(
            op.root.output.get_mut(..width).ok_or(Error::Length)?,
            last,
            true,
        )?;
        op.root.state = State::Empty;
        #[cfg(test)]
        if let Some(hook) = op.root.before_commit {
            hook();
        }
        check_authority(op.root.authority)?;
        op.root.phase = Phase::Retained;
        op.complete = true;
        Ok(())
    }

    /// Explicit public export only. Secret transport is not implemented here.
    pub fn declassify_to(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let op = Operation {
            root: self,
            complete: false,
        };
        if op.root.phase != Phase::Retained {
            return Err(Error::State);
        }
        check_authority(op.root.authority)?;
        let (width, _) = shape(op.root.output_bits)?;
        if destination.len() != width {
            return Err(Error::Length);
        }
        destination.copy_from_slice(op.root.output.get(..width).ok_or(Error::Length)?);
        Ok(())
    }
}
impl Drop for Waves<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
#[path = "parallel_concurrent_waves_tests.rs"]
mod parallel_concurrent_waves_tests;
