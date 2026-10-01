//! Private AVX2 sequential retained-batch component, not enclave qualification.
//! Slots execute one at a time using the single-state AVX2 Keccak kernel.
//! This is not multi-message SIMD or a parallel worker implementation.
//! Eight public slots share at most 1024 retained bytes. Input and cSHAKE setup
//! stream through bounded snapshots; all frames require admitted enclave memory.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::Fips202BitString;
use core::marker::PhantomData;
use sha3_accelerated_state::State;
pub mod sha3_batch_accelerated_wire;
pub use sha3_stream::{Algorithm, Error};

/// Public output shape, including canonical low-bit-first final byte width.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Slot {
    pub identity: u64,
    pub width: usize,
    pub last: u8,
}
impl Slot {
    pub fn validate(self) -> Result<(), Error> {
        if self.identity == 0 {
            return if self.width == 0 && self.last == 0 {
                Ok(())
            } else {
                Err(Error::Identity)
            };
        }
        let algorithm = Algorithm::decode(self.identity)?;
        if let Some(width) = algorithm.fixed_width()
            && (self.width != width || self.last != 8)
        {
            return Err(Error::Length);
        }
        if self.width > 1024 || self.last > 8 || ((self.width == 0) != (self.last == 0)) {
            return Err(Error::Bits);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Collecting,
    Setup,
    Streaming,
    Sealed,
    Quarantined,
}
pub struct Owner<'cpu> {
    authority: &'cpu Authority,
    state: State<'cpu>,
    plan: [Slot; 8],
    active: Option<usize>,
    completed: u8,
    sequence: u64,
    remaining: u64,
    phase: Phase,
    output: [u8; 1024],
    thread_bound: PhantomData<*mut ()>,
}
const _: () = assert!(core::mem::size_of::<Owner<'_>>() <= 4096);
const _: () = assert!(core::mem::align_of::<Owner<'_>>() <= 4096);
struct Operation<'a, 'cpu> {
    owner: &'a mut Owner<'cpu>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.quarantine();
        }
    }
}
impl<'cpu> Owner<'cpu> {
    pub fn new(authority: &'cpu Authority) -> Result<Self, Error> {
        check_authority(authority)?;
        Ok(Self {
            authority,
            state: State::Empty,
            plan: [Slot {
                identity: 0,
                width: 0,
                last: 0,
            }; 8],
            active: None,
            completed: 0,
            sequence: 0,
            remaining: 0,
            phase: Phase::Empty,
            output: [0; 1024],
            thread_bound: PhantomData,
        })
    }
    fn operation(&mut self, sequence: u64, phase: Phase) -> Result<Operation<'_, 'cpu>, Error> {
        if self.phase != phase {
            self.quarantine();
            return Err(Error::State);
        }
        if self.sequence.checked_add(1) != Some(sequence) {
            self.quarantine();
            return Err(Error::Sequence);
        }
        let op = Operation {
            owner: self,
            complete: false,
        };
        check_authority(op.owner.authority)?;
        op.owner.sequence = sequence;
        Ok(op)
    }
    pub fn begin(&mut self, sequence: u64, plan: [Slot; 8], budget: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Empty)?;
        Self::validate_plan(&plan)?;
        op.owner.plan = plan;
        op.owner.remaining = budget;
        op.owner.phase = Phase::Collecting;
        op.complete = true;
        Ok(())
    }
    pub fn validate_plan(plan: &[Slot; 8]) -> Result<(), Error> {
        let mut width = 0_usize;
        for slot in plan {
            slot.validate()?;
            width = width.checked_add(slot.width).ok_or(Error::Length)?;
        }
        if width > 1024 || plan.iter().all(|s| s.identity == 0) {
            return Err(Error::Length);
        }
        Ok(())
    }
    fn next(&self) -> Option<usize> {
        self.plan.iter().enumerate().find_map(|(i, s)| {
            if s.identity != 0 && self.completed & (1_u8 << i) == 0 {
                Some(i)
            } else {
                None
            }
        })
    }
    pub fn start(
        &mut self,
        sequence: u64,
        slot: usize,
        name: u128,
        custom: u128,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Collecting)?;
        if op.owner.next() != Some(slot) {
            return Err(Error::State);
        }
        let algorithm = Algorithm::decode(op.owner.plan.get(slot).ok_or(Error::Length)?.identity)?;
        op.owner.state = if matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
            State::setup(op.owner.authority, algorithm, name, custom).map_err(|_| Error::Crypto)?
        } else {
            if name != 0 || custom != 0 {
                return Err(Error::Identity);
            }
            let empty = Fips202BitString::new(&[], 0).map_err(|_| Error::Bits)?;
            State::new(op.owner.authority, algorithm, empty, empty).map_err(|_| Error::Crypto)?
        };
        op.owner.active = Some(slot);
        op.owner.phase = Phase::Setup;
        op.complete = true;
        Ok(())
    }
    fn admit(&mut self, slot: usize, bytes: usize) -> Result<(), Error> {
        if self.active != Some(slot) {
            return Err(Error::State);
        }
        if bytes > 1024 {
            return Err(Error::Length);
        }
        self.remaining = self
            .remaining
            .checked_sub(u64::try_from(bytes).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?;
        Ok(())
    }
    pub fn setup_chunk(
        &mut self,
        sequence: u64,
        slot: usize,
        name: bool,
        input: &[u8],
        last: u8,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Setup)?;
        op.owner.admit(slot, input.len())?;
        if !matches!(
            op.owner.plan.get(slot).ok_or(Error::Length)?.identity,
            7 | 8
        ) {
            return Err(Error::Identity);
        }
        let input = Fips202BitString::new(input, last).map_err(|_| Error::Bits)?;
        // Empty setup fragments are no-ops after the outer phase/slot check.
        // The underlying exact-length setup may already have advanced phases.
        if input.bit_len() != 0 {
            op.owner
                .state
                .setup_chunk(name, input)
                .map_err(|_| Error::Crypto)?;
        }
        op.complete = true;
        Ok(())
    }
    pub fn finish_setup(&mut self, sequence: u64, slot: usize) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Setup)?;
        op.owner.admit(slot, 0)?;
        if matches!(
            op.owner.plan.get(slot).ok_or(Error::Length)?.identity,
            7 | 8
        ) {
            op.owner.state.finish_setup().map_err(|_| Error::Crypto)?;
        }
        op.owner.phase = Phase::Streaming;
        op.complete = true;
        Ok(())
    }
    pub fn update(&mut self, sequence: u64, slot: usize, input: &[u8]) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Streaming)?;
        op.owner.admit(slot, input.len())?;
        op.owner.state.update(input).map_err(|_| Error::Crypto)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish(
        &mut self,
        sequence: u64,
        slot: usize,
        input: &[u8],
        last: u8,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Streaming)?;
        op.owner.admit(slot, input.len())?;
        let bits = Fips202BitString::new(input, last).map_err(|_| Error::Bits)?;
        let shape = *op.owner.plan.get(slot).ok_or(Error::Length)?;
        let start = op
            .owner
            .plan
            .get(..slot)
            .ok_or(Error::Length)?
            .iter()
            .try_fold(0_usize, |n, s| n.checked_add(s.width))
            .ok_or(Error::Length)?;
        let end = start.checked_add(shape.width).ok_or(Error::Length)?;
        let output = op.owner.output.get_mut(start..end).ok_or(Error::Length)?;
        if Algorithm::decode(shape.identity)?.fixed_width().is_some() {
            op.owner
                .state
                .finish_fixed(bits, output)
                .map_err(|_| Error::Crypto)?;
        } else {
            op.owner.state.finish_xof(bits).map_err(|_| Error::Crypto)?;
            op.owner
                .state
                .squeeze(output, shape.last, true)
                .map_err(|_| Error::Crypto)?;
        }
        op.owner.state = State::Empty;
        op.owner.completed |= 1_u8
            .checked_shl(u32::try_from(slot).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?;
        op.owner.active = None;
        op.owner.phase = Phase::Collecting;
        op.complete = true;
        Ok(())
    }
    pub fn seal(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Collecting)?;
        if op.owner.next().is_some() {
            return Err(Error::State);
        }
        op.owner.phase = Phase::Sealed;
        op.complete = true;
        Ok(())
    }
    /// Trusted fixed OS-copy seam, not an application callback. Declassification
    /// is explicit and binds every slot's algorithm and exact output shape.
    pub fn export(
        &mut self,
        sequence: u64,
        expected: [Slot; 8],
        copy: impl FnOnce(&[u8; 1024]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Sealed)?;
        if expected != op.owner.plan {
            return Err(Error::Identity);
        }
        if !copy(&op.owner.output) {
            return Err(Error::Copy);
        }
        check_authority(op.owner.authority)?;
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::Collecting | Phase::Setup | Phase::Streaming | Phase::Sealed
        ) {
            self.quarantine();
            return Err(Error::State);
        }
        let phase = self.phase;
        let mut op = self.operation(sequence, phase)?;
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
    fn clear(&mut self) {
        self.state = State::Empty;
        let _ = clear_owned_region(&mut self.output);
        self.plan = [Slot::default(); 8];
        self.active = None;
        self.completed = 0;
        self.remaining = 0;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.authority.quarantine();
        self.phase = Phase::Quarantined;
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.quarantine();
    }
}
fn check_authority(authority: &Authority) -> Result<(), Error> {
    if authority.report().kernel != Kernel::X86Keccak {
        return Err(Error::Crypto);
    }
    authority.session().map(|_| ()).map_err(|_| Error::Crypto)
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha3_batch_accelerated_authority_tests;
#[cfg(test)]
mod sha3_batch_accelerated_tests;
#[cfg(test)]
mod sha3_batch_accelerated_wire_tests;
