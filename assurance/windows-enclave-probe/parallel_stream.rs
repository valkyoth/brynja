//! Private sequential scalar ParallelHash enclave component, not a shipping API.
//! All state and call frames require admitted enclave memory. The placement
//! owner must destroy this value then erase its entire allocation, including
//! enum padding. No SIMD, multicore scheduling or native qualification claim.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha3::Fips202BitString as Bits;
use core::marker::PhantomData;
mod parallel_stream_encoding;
mod parallel_stream_input;
mod parallel_stream_state;
pub mod parallel_stream_wire;
use parallel_stream_encoding::SecretEncodedInteger;
use parallel_stream_input::Input;
use parallel_stream_state::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Sequence,
    State,
    Length,
    Bits,
    Copy,
    Crypto,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Custom,
    CustomRetained,
    Streaming,
    Reader,
    Retained,
    More,
    Quarantined,
}
pub struct Owner {
    root: State,
    input: Input,
    phase: Phase,
    sequence: u64,
    identity: u64,
    block: u64,
    budget: [u8; 8],
    output: [u8; 1024],
    width: usize,
    last: u8,
    next_width: usize,
    next_last: u8,
    thread_bound: PhantomData<*mut ()>,
}
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
            root: State::Empty,
            input: Input::new(),
            phase: Phase::Empty,
            sequence: 0,
            identity: 0,
            block: 0,
            budget: [0; 8],
            output: [0; 1024],
            width: 0,
            last: 0,
            next_width: 0,
            next_last: 0,
            thread_bound: PhantomData,
        }
    }
    fn operation(&mut self, sequence: u64, allowed: &[Phase]) -> Result<Operation<'_>, Error> {
        if !allowed.contains(&self.phase) {
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
    fn clear_output(&mut self) {
        let _ = clear_owned_region(&mut self.output);
        self.width = 0;
        self.last = 0;
    }
    fn clear(&mut self) {
        self.root = State::Empty;
        self.input.clear();
        self.clear_output();
        let _ = clear_owned_region(&mut self.budget);
        self.identity = 0;
        self.block = 0;
        self.next_width = 0;
        self.next_last = 0;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.phase = Phase::Quarantined;
    }
    fn charge(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        self.budget = u64::from_le_bytes(self.budget)
            .checked_sub(u64::try_from(input.len()).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?
            .to_le_bytes();
        Ok(())
    }
    /// Identities 1/2 are fixed ParallelHash128/256, 3/4 their XOF variants.
    /// B is positive bytes; the budget bounds supplied setup/message bytes.
    pub fn begin(
        &mut self,
        sequence: u64,
        identity: u64,
        block: u64,
        custom_bits: u128,
        budget: u64,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        op.owner.input.begin(identity, block)?;
        op.owner.root = State::setup(identity, custom_bits)?;
        op.owner.identity = identity;
        op.owner.block = block;
        op.owner.budget = budget.to_le_bytes();
        op.owner.phase = Phase::Custom;
        op.complete = true;
        Ok(())
    }
    pub fn custom(&mut self, sequence: u64, input: Bits<'_>) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        op.owner.charge(input.as_bytes())?;
        op.owner.root.custom(input)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish_custom(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        op.owner.root.finish_custom()?;
        let mut prefix = SecretEncodedInteger::empty();
        prefix.left(u128::from(op.owner.block))?;
        op.owner.root.update(prefix.bytes()?)?;
        if op.owner.phase == Phase::CustomRetained {
            let tail = Bits::new(
                op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
                op.owner.last,
            )
            .map_err(|_| Error::Bits)?;
            op.owner.input.finish(&mut op.owner.root, tail)?;
            op.owner.clear_output();
            let (width, last) = (op.owner.next_width, op.owner.next_last);
            op.owner.next_width = 0;
            op.owner.next_last = 0;
            op.owner.finish_root(width, last)?;
        } else {
            op.owner.phase = Phase::Streaming;
        }
        op.complete = true;
        Ok(())
    }
    pub fn update(&mut self, sequence: u64, input: &[u8]) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Streaming])?;
        op.owner.charge(input)?;
        op.owner.input.update(&mut op.owner.root, input)?;
        op.complete = true;
        Ok(())
    }
    /// Final tail is low-bit-first. Fixed output <=1024 bytes; XOF width/last=0.
    pub fn finish(
        &mut self,
        sequence: u64,
        tail: Bits<'_>,
        width: usize,
        last: u8,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Streaming])?;
        shape(width, last)?;
        let fixed = op.owner.identity <= 2;
        if !fixed && width != 0 {
            return Err(Error::Length);
        }
        op.owner.charge(tail.as_bytes())?;
        op.owner.input.finish(&mut op.owner.root, tail)?;
        op.owner.finish_root(width, last)?;
        op.complete = true;
        Ok(())
    }
    fn finish_root(&mut self, width: usize, last: u8) -> Result<(), Error> {
        let fixed = self.identity <= 2;
        let bits = if width == 0 {
            0
        } else {
            u128::try_from(width.checked_sub(1).ok_or(Error::Length)?)
                .map_err(|_| Error::Length)?
                .checked_mul(8)
                .and_then(|n| n.checked_add(u128::from(last)))
                .ok_or(Error::Length)?
        };
        let mut suffix = SecretEncodedInteger::empty();
        suffix.right(bits)?;
        self.root.update(suffix.bytes()?)?;
        self.root.finish(empty()?)?;
        let _ = clear_owned_region(&mut self.budget);
        if fixed {
            self.root.squeeze(
                self.output.get_mut(..width).ok_or(Error::Length)?,
                last,
                true,
            )?;
            self.root = State::Empty;
            self.width = width;
            self.last = last;
            self.phase = Phase::Retained;
        } else {
            self.phase = Phase::Reader;
        }
        Ok(())
    }
    /// Rehash exactly the retained bits, discarding any old reader. Stream only
    /// customization next; finish_custom finalizes the new complete message.
    pub fn rehash(
        &mut self,
        sequence: u64,
        identity: u64,
        block: u64,
        custom_bits: u128,
        budget: u64,
        output: (usize, u8),
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Retained, Phase::More])?;
        let (width, last) = output;
        shape(width, last)?;
        if identity > 2 && width != 0 {
            return Err(Error::Length);
        }
        op.owner.input.begin(identity, block)?;
        op.owner.root = State::setup(identity, custom_bits)?;
        op.owner.budget = budget
            .checked_sub(u64::try_from(op.owner.width).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?
            .to_le_bytes();
        op.owner.identity = identity;
        op.owner.block = block;
        op.owner.next_width = width;
        op.owner.next_last = last;
        op.owner.phase = Phase::CustomRetained;
        op.complete = true;
        Ok(())
    }
    pub fn squeeze(
        &mut self,
        sequence: u64,
        width: usize,
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Reader])?;
        shape(width, last)?;
        if !terminal && last != if width == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        op.owner.root.squeeze(
            op.owner.output.get_mut(..width).ok_or(Error::Length)?,
            last,
            terminal,
        )?;
        if terminal {
            op.owner.root = State::Empty;
        }
        op.owner.width = width;
        op.owner.last = last;
        op.owner.phase = if terminal {
            Phase::Retained
        } else {
            Phase::More
        };
        op.complete = true;
        Ok(())
    }
    /// Private trusted OS-copy seam, not a consumer callback or host secret API.
    pub fn export(
        &mut self,
        sequence: u64,
        identity: u64,
        width: usize,
        last: u8,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Retained, Phase::More])?;
        if identity != op.owner.identity {
            return Err(Error::Identity);
        }
        if width != op.owner.width || last != op.owner.last {
            return Err(Error::Length);
        }
        if !copy(op.owner.output.get(..width).ok_or(Error::Length)?) {
            return Err(Error::Copy);
        }
        let more = op.owner.phase == Phase::More;
        op.owner.clear_output();
        if more {
            op.owner.phase = Phase::Reader;
        } else {
            op.owner.clear();
            op.owner.phase = Phase::Empty;
        }
        op.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(
            sequence,
            &[
                Phase::Custom,
                Phase::CustomRetained,
                Phase::Streaming,
                Phase::Reader,
                Phase::Retained,
                Phase::More,
            ],
        )?;
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.quarantine();
    }
}
fn shape(width: usize, last: u8) -> Result<(), Error> {
    if width > 1024 {
        return Err(Error::Length);
    }
    if (width == 0 && last != 0) || (width != 0 && !(1..=8).contains(&last)) {
        return Err(Error::Bits);
    }
    Ok(())
}
fn empty() -> Result<Bits<'static>, Error> {
    Bits::new(&[], 0).map_err(|_| Error::Bits)
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod parallel_stream_tests;
#[cfg(test)]
mod parallel_stream_wire_tests;
