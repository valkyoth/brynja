//! Private sequential SHA-2 batch component, not native or SIMD qualification.
//! Entire owner and frames require admitted enclave storage. Native placement
//! must destroy this owner and then erase all allocation bytes, including padding.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha2::BitString;
use core::marker::PhantomData;
pub use sha2_stream::{Algorithm, Error};
#[path = "sha2_stream_state.rs"]
mod state;
use state::State;
pub mod sha2_batch_wire;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Collecting,
    Streaming,
    Sealed,
    Quarantined,
}

/// Eight public plan slots. Identity zero means inactive, never an empty message.
/// Results occupy fixed 64-byte slots; unused suffixes and inactive slots are zero.
pub struct Owner {
    plan: [u64; 8],
    completed: u8,
    active: Option<usize>,
    state: Option<State>,
    output: [u8; 512],
    sequence: u64,
    remaining: u64,
    phase: Phase,
    thread_bound: PhantomData<*mut ()>,
}
const _: () = assert!(core::mem::size_of::<Owner>() <= 4096);
const _: () = assert!(core::mem::align_of::<Owner>() <= 4096);
struct Operation<'a> {
    owner: &'a mut Owner,
    complete: bool,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.quarantine();
        }
    }
}
impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}
impl Owner {
    pub const fn new() -> Self {
        Self {
            plan: [0; 8],
            completed: 0,
            active: None,
            state: None,
            output: [0; 512],
            sequence: 0,
            remaining: 0,
            phase: Phase::Empty,
            thread_bound: PhantomData,
        }
    }
    fn operation(&mut self, sequence: u64, phase: Phase) -> Result<Operation<'_>, Error> {
        if self.phase != phase {
            self.quarantine();
            return Err(Error::State);
        }
        if self.sequence.checked_add(1) != Some(sequence) {
            self.quarantine();
            return Err(Error::Sequence);
        }
        self.sequence = sequence;
        Ok(Operation {
            owner: self,
            complete: false,
        })
    }
    pub fn begin(
        &mut self,
        sequence: u64,
        plan: [u64; 8],
        max_input_bytes: u64,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Empty)?;
        if plan.iter().all(|v| *v == 0) {
            return Err(Error::Identity);
        }
        for value in plan {
            if value != 0 {
                Algorithm::decode(value)?;
            }
        }
        op.owner.plan = plan;
        op.owner.remaining = max_input_bytes;
        op.owner.phase = Phase::Collecting;
        op.complete = true;
        Ok(())
    }
    fn next(&self) -> Option<usize> {
        self.plan.iter().enumerate().find_map(|(slot, value)| {
            if *value != 0 && self.completed & (1_u8 << slot) == 0 {
                Some(slot)
            } else {
                None
            }
        })
    }
    pub fn start(&mut self, sequence: u64, slot: usize) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Collecting)?;
        if op.owner.next() != Some(slot) {
            return Err(Error::State);
        }
        let identity = *op.owner.plan.get(slot).ok_or(Error::Length)?;
        op.owner.state = Some(State::new(Algorithm::decode(identity)?));
        op.owner.active = Some(slot);
        op.owner.phase = Phase::Streaming;
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
    pub fn update(&mut self, sequence: u64, slot: usize, input: &[u8]) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Streaming)?;
        op.owner.admit(slot, input.len())?;
        op.owner.state.as_mut().ok_or(Error::State)?.update(input)?;
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
        let bits = BitString::new(input, last).map_err(|_| Error::Bits)?;
        let algorithm = Algorithm::decode(*op.owner.plan.get(slot).ok_or(Error::Identity)?)?;
        let start = slot.checked_mul(64).ok_or(Error::Length)?;
        let end = start.checked_add(algorithm.width()).ok_or(Error::Length)?;
        op.owner.state.take().ok_or(Error::State)?.finish(
            bits,
            op.owner.output.get_mut(start..end).ok_or(Error::Length)?,
        )?;
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
    /// Fixed trusted-adapter copy seam only, never an application callback.
    /// Explicit declassification must precede copying these results to the host.
    pub fn export(
        &mut self,
        sequence: u64,
        expected: [u64; 8],
        copy: impl FnOnce(&[u8; 512]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Sealed)?;
        if expected != op.owner.plan {
            return Err(Error::Identity);
        }
        if !copy(&op.owner.output) {
            return Err(Error::Copy);
        }
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::Collecting | Phase::Streaming | Phase::Sealed
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
        drop(self.state.take());
        let _ = clear_owned_region(&mut self.output);
        self.plan = [0; 8];
        self.completed = 0;
        self.active = None;
        self.remaining = 0;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.phase = Phase::Quarantined;
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.clear();
    }
}
struct Scratch([u8; 64]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha2_batch_tests;
#[cfg(test)]
mod sha2_batch_wire_tests;
