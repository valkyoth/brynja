//! Private AVX2 TupleHash component; not a shipping API or enclave qualification.
//! All owner storage and frames must live inside an admitted enclave. Placement
//! must erase the entire allocation after Drop, including enum padding/copies.
//! Public declared lengths frame exact items; no secret length query is exposed.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::clear_owned_region;
use brynja_hash_sha3::{Fips202BitString as Bits, left_encode_u128, right_encode_u128};
use core::marker::PhantomData;
mod tuple_accelerated_packer;
mod tuple_accelerated_state;
pub mod tuple_accelerated_wire;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use tuple_accelerated_packer::Packer;
use tuple_accelerated_state::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Sequence,
    State,
    Length,
    Bits,
    Copy,
    Crypto,
    Backend,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Custom,
    CustomRetained,
    Tuple,
    Item,
    Reader,
    Retained,
    More,
    Quarantined,
}
pub struct Owner<'cpu> {
    authority: &'cpu Authority,
    state: State<'cpu>,
    packer: Packer,
    phase: Phase,
    identity: u64,
    sequence: u64,
    remaining: [u8; 16],
    output: [u8; 1024],
    width: usize,
    last: u8,
    thread_bound: PhantomData<*mut ()>,
}
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
            packer: Packer::new(),
            phase: Phase::Empty,
            identity: 0,
            sequence: 0,
            remaining: [0; 16],
            output: [0; 1024],
            width: 0,
            last: 0,
            thread_bound: PhantomData,
        })
    }
    fn operation(
        &mut self,
        sequence: u64,
        allowed: &[Phase],
    ) -> Result<Operation<'_, 'cpu>, Error> {
        if !allowed.contains(&self.phase) {
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
    fn clear_output(&mut self) {
        let _ = clear_owned_region(&mut self.output);
        self.width = 0;
        self.last = 0;
    }
    fn clear(&mut self) {
        self.state = State::Empty;
        self.packer.clear();
        self.clear_output();
        let _ = clear_owned_region(&mut self.remaining);
        self.identity = 0;
    }
    pub fn quarantine(&mut self) {
        self.authority.quarantine();
        self.clear();
        self.phase = Phase::Quarantined;
    }
    pub fn begin(&mut self, sequence: u64, identity: u64, custom_bits: u128) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        op.owner.state = State::setup(op.owner.authority, identity, custom_bits)?;
        op.owner.identity = identity;
        op.owner.phase = Phase::Custom;
        op.complete = true;
        Ok(())
    }
    pub fn custom(&mut self, sequence: u64, input: Bits<'_>) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        bounded(input)?;
        op.owner.state.custom(input)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish_custom(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Custom, Phase::CustomRetained])?;
        op.owner.state.finish_custom()?;
        if op.owner.phase == Phase::CustomRetained {
            let bits = bit_width(op.owner.width, op.owner.last)?;
            let prefix = left_encode_u128(bits);
            op.owner
                .packer
                .append(&mut op.owner.state, bytes(prefix.as_bytes())?)?;
            let input = Bits::new(
                op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
                op.owner.last,
            )
            .map_err(|_| Error::Bits)?;
            op.owner.packer.append(&mut op.owner.state, input)?;
            op.owner.clear_output();
        }
        op.owner.phase = Phase::Tuple;
        op.complete = true;
        Ok(())
    }
    pub fn begin_item(&mut self, sequence: u64, bits: u128) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Tuple])?;
        let prefix = left_encode_u128(bits);
        op.owner
            .packer
            .append(&mut op.owner.state, bytes(prefix.as_bytes())?)?;
        op.owner.remaining = bits.to_le_bytes();
        op.owner.phase = Phase::Item;
        op.complete = true;
        Ok(())
    }
    pub fn fragment(&mut self, sequence: u64, input: Bits<'_>) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Item])?;
        bounded(input)?;
        let remaining = u128::from_le_bytes(op.owner.remaining)
            .checked_sub(u128::try_from(input.bit_len()).map_err(|_| Error::Length)?)
            .ok_or(Error::Length)?;
        op.owner.packer.append(&mut op.owner.state, input)?;
        op.owner.remaining = remaining.to_le_bytes();
        op.complete = true;
        Ok(())
    }
    pub fn finish_item(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Item])?;
        if op.owner.remaining != [0; 16] {
            return Err(Error::Length);
        }
        op.owner.phase = Phase::Tuple;
        op.complete = true;
        Ok(())
    }
    /// Fixed length is encoded exactly; XOF requires width=last=0 and encodes 0.
    pub fn finish(&mut self, sequence: u64, width: usize, last: u8) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Tuple])?;
        let bits = bit_width(width, last)?;
        let fixed = op.owner.identity <= 2;
        if !fixed && bits != 0 {
            return Err(Error::Length);
        }
        let suffix = right_encode_u128(bits);
        op.owner
            .packer
            .append(&mut op.owner.state, bytes(suffix.as_bytes())?)?;
        op.owner.packer.finish(&mut op.owner.state)?;
        if fixed {
            op.owner.state.squeeze(
                op.owner.output.get_mut(..width).ok_or(Error::Length)?,
                last,
                true,
            )?;
            op.owner.state = State::Empty;
            op.owner.width = width;
            op.owner.last = last;
            op.owner.phase = Phase::Retained;
        } else {
            op.owner.phase = Phase::Reader;
        }
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
        op.owner.state.squeeze(
            op.owner.output.get_mut(..width).ok_or(Error::Length)?,
            last,
            terminal,
        )?;
        if terminal {
            op.owner.state = State::Empty;
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
    /// Retained output becomes exactly one tuple member after streamed S setup.
    pub fn rehash(&mut self, sequence: u64, identity: u64, custom_bits: u128) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Retained, Phase::More])?;
        op.owner.state = State::setup(op.owner.authority, identity, custom_bits)?;
        op.owner.packer.clear();
        op.owner.identity = identity;
        op.owner.phase = Phase::CustomRetained;
        op.complete = true;
        Ok(())
    }
    /// Private trusted OS-copy seam, never an arbitrary shipping callback.
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
        check_authority(op.owner.authority)?;
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
                Phase::Tuple,
                Phase::Item,
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
impl Drop for Owner<'_> {
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
fn bit_width(width: usize, last: u8) -> Result<u128, Error> {
    shape(width, last)?;
    if width == 0 {
        return Ok(0);
    }
    u128::try_from(width.checked_sub(1).ok_or(Error::Length)?)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(u128::from(last)))
        .ok_or(Error::Length)
}
fn bounded(input: Bits<'_>) -> Result<(), Error> {
    if input.as_bytes().len() > 1024 {
        Err(Error::Length)
    } else {
        Ok(())
    }
}
fn bytes(input: &[u8]) -> Result<Bits<'_>, Error> {
    Bits::new(input, if input.is_empty() { 0 } else { 8 }).map_err(|_| Error::Bits)
}
#[cfg(test)]
extern crate std;
fn check_authority(authority: &Authority) -> Result<(), Error> {
    if authority.report().kernel != Kernel::X86Keccak {
        return Err(Error::Backend);
    }
    authority.session().map(|_| ()).map_err(|_| Error::Backend)
}
#[cfg(test)]
mod tuple_accelerated_authority_tests;
#[cfg(test)]
mod tuple_accelerated_tests;
