//! Private bounded concurrent-leaf component. NOT a shipping/protected-memory API.
//! All storage and frames must be admitted before enclave integration. Slots may
//! be borrowed by scoped workers; authorities are created on those workers and
//! never transferred. This component alone does not establish OS residency.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::Fips202BitString as Bits;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};
mod parallel_concurrent_slot;
mod parallel_stream_encoding;
#[path = "parallel_accelerated_state.rs"]
#[allow(clippy::large_enum_variant)]
// Keep the shared state inline for protected placement; no heap indirection.
mod state;
pub use parallel_concurrent_slot::Slot;
use parallel_stream_encoding::SecretEncodedInteger;
use state::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    State,
    Length,
    Bits,
    Crypto,
    Backend,
    Cancelled,
}

/// Immutable shape plus a one-way cancellation signal; never secret bytes.
/// Lengths, identities and scheduling shape are explicitly public metadata.
pub struct Plan {
    identity: u64,
    block: usize,
    input_bits: usize,
    custom_bits: usize,
    output_bits: usize,
    leaves: usize,
    cancelled: AtomicBool,
    claimed: AtomicBool,
}
impl Plan {
    pub fn new(
        identity: u64,
        block: usize,
        input_bits: usize,
        custom_bits: usize,
        output_bits: usize,
    ) -> Result<Self, Error> {
        if !(1..=4).contains(&identity) {
            return Err(Error::Identity);
        }
        if !(1..=1024).contains(&block) || custom_bits > 8192 || output_bits > 8192 {
            return Err(Error::Length);
        }
        let block_bits = block.checked_mul(8).ok_or(Error::Length)?;
        let leaves = input_bits
            .checked_div(block_bits)
            .ok_or(Error::Length)?
            .checked_add(usize::from(
                input_bits.checked_rem(block_bits).ok_or(Error::Length)? != 0,
            ))
            .ok_or(Error::Length)?;
        if leaves > 4 {
            return Err(Error::Length);
        }
        Ok(Self {
            identity,
            block,
            input_bits,
            custom_bits,
            output_bits,
            leaves,
            cancelled: AtomicBool::new(false),
            claimed: AtomicBool::new(false),
        })
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub fn leaf_bits(&self, index: usize) -> Result<usize, Error> {
        if index >= self.leaves {
            return Err(Error::Length);
        }
        let block = self.block.checked_mul(8).ok_or(Error::Length)?;
        let start = index.checked_mul(block).ok_or(Error::Length)?;
        Ok(self
            .input_bits
            .checked_sub(start)
            .ok_or(Error::Length)?
            .min(block))
    }
    fn width(&self) -> usize {
        if matches!(self.identity, 1 | 3) {
            32
        } else {
            64
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Fresh,
    Working,
    Retained,
    Dead,
}

pub struct Batch<'plan> {
    plan: &'plan Plan,
    authority: &'plan Authority,
    slots: [Slot<'plan>; 4],
    output: [u8; 1024],
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
    #[cfg(test)]
    before_commit: Option<fn()>,
}
struct Operation<'a, 'plan> {
    batch: &'a mut Batch<'plan>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.batch.clear();
        }
    }
}
impl<'plan> Batch<'plan> {
    pub fn new(plan: &'plan Plan, authority: &'plan Authority) -> Result<Self, Error> {
        plan.check()?;
        check_authority(authority)?;
        plan.claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        Ok(Self {
            plan,
            authority,
            slots: core::array::from_fn(|index| Slot::new(plan, index)),
            output: [0; 1024],
            phase: Phase::Fresh,
            thread_bound: PhantomData,
            #[cfg(test)]
            before_commit: None,
        })
    }
    /// Exactly one distribution. Borrowing prevents reduction/destruction while
    /// scoped workers still hold mutable slots. No authority crosses threads.
    pub fn workers(&mut self) -> Result<&mut [Slot<'plan>], Error> {
        if self.phase != Phase::Fresh {
            self.clear();
            return Err(Error::State);
        }
        if let Err(error) = self.plan.check() {
            self.clear();
            return Err(error);
        }
        self.phase = Phase::Working;
        self.slots.get_mut(..self.plan.leaves).ok_or(Error::Length)
    }
    fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
        }
        let _ = clear_owned_region(&mut self.output);
        self.phase = Phase::Dead;
    }
    pub fn cancel(&mut self) {
        self.plan.cancel();
        self.clear();
    }

    /// Join every worker before reduction; keep all CVs and output in admitted
    /// enclave memory. Fixed and XOF identities return a bounded output prefix.
    pub fn finish(&mut self, custom: Bits<'_>) -> Result<(), Error> {
        let mut op = Operation {
            batch: self,
            complete: false,
        };
        if op.batch.phase != Phase::Working {
            return Err(Error::State);
        }
        let plan = op.batch.plan;
        let authority = op.batch.authority;
        plan.check()?;
        check_authority(authority)?;
        if custom.bit_len() != plan.custom_bits {
            return Err(Error::Bits);
        }
        let mut root = State::setup(
            authority,
            plan.identity,
            u128::try_from(plan.custom_bits).map_err(|_| Error::Length)?,
        )?;
        root.custom(custom)?;
        root.finish_custom()?;
        let mut framing = SecretEncodedInteger::empty();
        framing.left(u128::try_from(plan.block).map_err(|_| Error::Length)?)?;
        root.update(framing.bytes()?)?;
        let mut consumed = 0_usize;
        for (index, slot) in op.batch.slots.iter_mut().enumerate() {
            if index < plan.leaves {
                plan.check()?;
                slot.absorb(&mut root, plan, index)?;
                consumed = consumed.checked_add(1).ok_or(Error::Length)?;
            } else if !slot.unused() {
                return Err(Error::State);
            }
        }
        if consumed != plan.leaves {
            return Err(Error::State);
        }
        framing.right(u128::try_from(consumed).map_err(|_| Error::Length)?)?;
        root.update(framing.bytes()?)?;
        framing.right(if plan.identity <= 2 {
            u128::try_from(plan.output_bits).map_err(|_| Error::Length)?
        } else {
            0
        })?;
        root.update(framing.bytes()?)?;
        root.finish(empty()?)?;
        let (width, last) = shape(plan.output_bits)?;
        root.squeeze(
            op.batch.output.get_mut(..width).ok_or(Error::Length)?,
            last,
            true,
        )?;
        root = State::Empty;
        drop(root);
        #[cfg(test)]
        if let Some(hook) = op.batch.before_commit {
            hook();
        }
        plan.check()?;
        check_authority(authority)?;
        op.batch.phase = Phase::Retained;
        op.complete = true;
        Ok(())
    }
    /// Explicit public declassification of the complete retained result only.
    /// Wrong destination length or revocation leaves it untouched, clears this
    /// batch and rejects. Production host transport is not implemented here.
    pub fn declassify_to(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let op = Operation {
            batch: self,
            complete: false,
        };
        if op.batch.phase != Phase::Retained {
            return Err(Error::State);
        }
        op.batch.plan.check()?;
        check_authority(op.batch.authority)?;
        let (width, _) = shape(op.batch.plan.output_bits)?;
        if destination.len() != width {
            return Err(Error::Length);
        }
        destination.copy_from_slice(op.batch.output.get(..width).ok_or(Error::Length)?);
        // Operation drop clears retained state after successful declassification too.
        Ok(())
    }
}
impl Drop for Batch<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
fn empty() -> Result<Bits<'static>, Error> {
    Bits::new(&[], 0).map_err(|_| Error::Bits)
}
fn shape(bits: usize) -> Result<(usize, u8), Error> {
    if bits == 0 {
        return Ok((0, 0));
    }
    let width = bits
        .checked_add(7)
        .ok_or(Error::Length)?
        .checked_div(8)
        .ok_or(Error::Length)?;
    let last = u8::try_from(bits.checked_sub(1).ok_or(Error::Length)? % 8 + 1)
        .map_err(|_| Error::Length)?;
    Ok((width, last))
}
fn check_authority(authority: &Authority) -> Result<(), Error> {
    if authority.report().kernel != Kernel::X86Keccak {
        return Err(Error::Backend);
    }
    authority.session().map(|_| ()).map_err(|_| Error::Backend)
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod parallel_concurrent_tests;
