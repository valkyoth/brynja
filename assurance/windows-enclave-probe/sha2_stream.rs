//! Enclave worker component, not a host API or a platform-admission proof.
//!
//! The complete owner and every call frame must live in admitted enclave
//! storage. Only public identity/sequence metadata may cross the boundary.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_hash_sha2::{BitString, Sha512TBits};
use core::marker::PhantomData;
mod sha2_stream_state;
use sha2_stream_state::State;

/// Public algorithm identity. General /224 and /256 remain distinct identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha512T(Sha512TBits),
}
impl Algorithm {
    pub fn decode(value: u64) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Sha224),
            2 => Ok(Self::Sha256),
            3 => Ok(Self::Sha384),
            4 => Ok(Self::Sha512),
            5 => Ok(Self::Sha512_224),
            6 => Ok(Self::Sha512_256),
            0x1001..=0x11ff => Sha512TBits::new(
                u16::try_from(value.checked_sub(0x1000).ok_or(Error::Identity)?)
                    .map_err(|_| Error::Identity)?,
            )
            .map(Self::Sha512T)
            .map_err(|_| Error::Identity),
            _ => Err(Error::Identity),
        }
    }
    pub fn encode(self) -> u64 {
        match self {
            Self::Sha224 => 1,
            Self::Sha256 => 2,
            Self::Sha384 => 3,
            Self::Sha512 => 4,
            Self::Sha512_224 => 5,
            Self::Sha512_256 => 6,
            Self::Sha512T(t) => 0x1000 | u64::from(t.bits()),
        }
    }
    pub fn width(self) -> usize {
        match self {
            Self::Sha224 | Self::Sha512_224 => 28,
            Self::Sha256 | Self::Sha512_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Sha512T(t) => t.output_bytes(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Sequence,
    State,
    Length,
    Bits,
    Copy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Streaming,
    Retained,
    Quarantined,
}

/// A worker-owned object. Never move it into a host frame, serialize it, or
/// expose its output without deliberate public declassification. The native
/// placement adapter must wipe the entire storage AFTER dropping this object,
/// including inactive enum storage and padding left by compiler moves.
pub struct Owner {
    algorithm: Option<Algorithm>,
    state: Option<State>,
    output: [u8; 64],
    phase: Phase,
    sequence: u64,
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

impl Owner {
    pub const fn new() -> Self {
        Self {
            algorithm: None,
            state: None,
            output: [0; 64],
            phase: Phase::Empty,
            sequence: 0,
            thread_bound: PhantomData,
        }
    }
    fn operation(&mut self, sequence: u64, phase: Phase) -> Result<Operation<'_>, Error> {
        if self.phase != phase || self.phase == Phase::Quarantined {
            self.quarantine();
            return Err(Error::State);
        }
        if sequence == 0 || self.sequence.checked_add(1) != Some(sequence) {
            self.quarantine();
            return Err(Error::Sequence);
        }
        self.sequence = sequence;
        Ok(Operation {
            owner: self,
            complete: false,
        })
    }
    pub fn begin(&mut self, sequence: u64, algorithm: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Empty)?;
        let algorithm = Algorithm::decode(algorithm)?;
        op.owner.algorithm = Some(algorithm);
        op.owner.state = Some(State::new(algorithm));
        op.owner.phase = Phase::Streaming;
        op.complete = true;
        Ok(())
    }
    pub fn update(&mut self, sequence: u64, input: &[u8]) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Streaming)?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        op.owner.state.as_mut().ok_or(Error::State)?.update(input)?;
        op.complete = true;
        Ok(())
    }
    /// The final bounded chunk can contain zero through seven trailing bits.
    /// Canonical bytes require `last_bits=8`, except empty input requires zero.
    pub fn finish(&mut self, sequence: u64, input: &[u8], last_bits: u8) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Streaming)?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        let bits = BitString::new(input, last_bits).map_err(|_| Error::Bits)?;
        let width = op.owner.algorithm.ok_or(Error::Identity)?.width();
        let output = op.owner.output.get_mut(..width).ok_or(Error::Length)?;
        op.owner
            .state
            .take()
            .ok_or(Error::State)?
            .finish(bits, output)?;
        op.owner.phase = Phase::Retained;
        op.complete = true;
        Ok(())
    }
    /// Hash the exact retained bit string, not rounded bytes. This distinction
    /// is essential for non-byte-aligned general SHA-512/t digests.
    pub fn rehash(&mut self, sequence: u64, algorithm: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Retained)?;
        let previous = op.owner.algorithm.ok_or(Error::Identity)?;
        let algorithm = Algorithm::decode(algorithm)?;
        let input = op
            .owner
            .output
            .get(..previous.width())
            .ok_or(Error::Length)?;
        let last_bits = match previous {
            Algorithm::Sha512T(t) => u8::try_from(t.bits() % 8).map_err(|_| Error::Bits)?,
            _ => 0,
        };
        let bits = BitString::new(input, if last_bits == 0 { 8 } else { last_bits })
            .map_err(|_| Error::Bits)?;
        let mut temporary = Scratch([0; 64]);
        let destination = temporary
            .0
            .get_mut(..algorithm.width())
            .ok_or(Error::Length)?;
        State::new(algorithm).finish(bits, destination)?;
        let _ = clear_owned_region(&mut op.owner.output).map_err(|_| Error::Copy)?;
        copy_secret_region(
            op.owner
                .output
                .get_mut(..algorithm.width())
                .ok_or(Error::Length)?,
            destination,
        )
        .map_err(|_| Error::Copy)?;
        op.owner.algorithm = Some(algorithm);
        op.complete = true;
        Ok(())
    }
    /// Private adapter seam: substitute the fixed OS copy-out, never an
    /// application callback. The caller has explicitly declassified this result.
    /// A failed/partially completed copy still destroys the retained output.
    pub fn export_public(
        &mut self,
        sequence: u64,
        expected_algorithm: u64,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, Phase::Retained)?;
        let algorithm = op.owner.algorithm.ok_or(Error::Identity)?;
        if algorithm.encode() != expected_algorithm {
            return Err(Error::Identity);
        }
        if !copy(
            op.owner
                .output
                .get(..algorithm.width())
                .ok_or(Error::Length)?,
        ) {
            return Err(Error::Copy);
        }
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Streaming | Phase::Retained) {
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
        self.algorithm = None;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.phase = Phase::Quarantined;
    }
}
impl Default for Owner {
    fn default() -> Self {
        Self::new()
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
mod sha2_stream_tests;
