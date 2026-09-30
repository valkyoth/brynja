//! Private scalar enclave worker component; not a host API or qualification.
//! The owner and all call frames must remain in admitted enclave memory. The
//! placement adapter must drop the owner then wipe its entire allocation,
//! including inactive enum storage and padding. No application callback belongs
//! at the private OS-copy seam below.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::clear_owned_region;
use brynja_hash_sha3::Fips202BitString;
use core::marker::PhantomData;
mod sha3_stream_state;
use sha3_stream_state::State;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    Cshake128,
    Cshake256,
}
impl Algorithm {
    pub fn decode(value: u64) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Sha3_224),
            2 => Ok(Self::Sha3_256),
            3 => Ok(Self::Sha3_384),
            4 => Ok(Self::Sha3_512),
            5 => Ok(Self::Shake128),
            6 => Ok(Self::Shake256),
            7 => Ok(Self::Cshake128),
            8 => Ok(Self::Cshake256),
            _ => Err(Error::Identity),
        }
    }
    pub fn encode(self) -> u64 {
        match self {
            Self::Sha3_224 => 1,
            Self::Sha3_256 => 2,
            Self::Sha3_384 => 3,
            Self::Sha3_512 => 4,
            Self::Shake128 => 5,
            Self::Shake256 => 6,
            Self::Cshake128 => 7,
            Self::Cshake256 => 8,
        }
    }
    pub fn fixed_width(self) -> Option<usize> {
        match self {
            Self::Sha3_224 => Some(28),
            Self::Sha3_256 => Some(32),
            Self::Sha3_384 => Some(48),
            Self::Sha3_512 => Some(64),
            _ => None,
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
    Crypto,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Streaming,
    Squeezing,
    RetainedMore,
    RetainedFinal,
    Quarantined,
}

/// Fixed storage, with no public accumulated input/output counters or preflight
/// oracle. Each retained fragment is bounded; total XOF output is incremental.
pub struct Owner {
    state: State,
    algorithm: Option<Algorithm>,
    phase: Phase,
    sequence: u64,
    output: [u8; 1024],
    width: usize,
    last: u8,
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
            state: State::Empty,
            algorithm: None,
            phase: Phase::Empty,
            sequence: 0,
            output: [0; 1024],
            width: 0,
            last: 0,
            thread_bound: PhantomData,
        }
    }
    fn operation(&mut self, sequence: u64, allowed: &[Phase]) -> Result<Operation<'_>, Error> {
        if !allowed.contains(&self.phase) || self.phase == Phase::Quarantined {
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
    /// N and S use FIPS 202 low-bit-first canonical packing, unlike SHA-2.
    /// Each setup string is bounded to one transport snapshot in this protocol.
    pub fn begin(
        &mut self,
        sequence: u64,
        identity: u64,
        name: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        let algorithm = Algorithm::decode(identity)?;
        op.owner.state = State::new(algorithm, name, custom)?;
        op.owner.algorithm = Some(algorithm);
        op.owner.phase = Phase::Streaming;
        op.complete = true;
        Ok(())
    }
    pub fn update(&mut self, sequence: u64, input: &[u8]) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Streaming])?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        op.owner.state.update(input)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish(&mut self, sequence: u64, input: &[u8], last: u8) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Streaming])?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        let bits = Fips202BitString::new(input, last).map_err(|_| Error::Bits)?;
        op.owner.finish_state(bits)?;
        op.complete = true;
        Ok(())
    }
    fn finish_state(&mut self, bits: Fips202BitString<'_>) -> Result<(), Error> {
        match self.algorithm.ok_or(Error::Identity)?.fixed_width() {
            Some(width) => {
                let output = self.output.get_mut(..width).ok_or(Error::Length)?;
                self.state.finish_fixed(bits, output)?;
                self.width = width;
                self.last = 8;
                self.phase = Phase::RetainedFinal;
            }
            None => {
                self.state.finish_xof(bits)?;
                self.phase = Phase::Squeezing;
            }
        }
        Ok(())
    }
    /// Produce a retained fragment. A partial last byte is legal only for the
    /// terminal fragment; continuing after partial output is never permitted.
    pub fn squeeze(
        &mut self,
        sequence: u64,
        width: usize,
        last: u8,
        terminal: bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Squeezing])?;
        if !terminal && last != if width == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        let output = op.owner.output.get_mut(..width).ok_or(Error::Length)?;
        op.owner.state.squeeze(output, last, terminal)?;
        op.owner.width = width;
        op.owner.last = last;
        op.owner.phase = if terminal {
            Phase::RetainedFinal
        } else {
            Phase::RetainedMore
        };
        op.complete = true;
        Ok(())
    }
    /// Hash the exact retained fragment, without exporting it. Any previous
    /// XOF reader is discarded. The new result is a fixed digest or XOF reader.
    pub fn rehash(
        &mut self,
        sequence: u64,
        identity: u64,
        name: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedMore, Phase::RetainedFinal])?;
        let algorithm = Algorithm::decode(identity)?;
        let mut next = State::new(algorithm, name, custom)?;
        let input = Fips202BitString::new(
            op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
            op.owner.last,
        )
        .map_err(|_| Error::Bits)?;
        let mut scratch = Scratch([0; 1024]);
        if let Some(width) = algorithm.fixed_width() {
            next.finish_fixed(input, scratch.0.get_mut(..width).ok_or(Error::Length)?)?;
        } else {
            next.finish_xof(input)?;
        }
        op.owner.clear_output()?;
        op.owner.state = next;
        op.owner.algorithm = Some(algorithm);
        if let Some(width) = algorithm.fixed_width() {
            brynja_core::copy_secret_region(
                op.owner.output.get_mut(..width).ok_or(Error::Length)?,
                scratch.0.get(..width).ok_or(Error::Length)?,
            )
            .map_err(|_| Error::Copy)?;
            op.owner.width = width;
            op.owner.last = 8;
            op.owner.phase = Phase::RetainedFinal;
        } else {
            op.owner.phase = Phase::Squeezing;
        }
        op.complete = true;
        Ok(())
    }
    /// Fixed OS copy-out seam, not an application callback or implicit export.
    /// Identity AND exact shape must match before any copy, including zero output.
    pub fn export_public(
        &mut self,
        sequence: u64,
        identity: u64,
        width: usize,
        last: u8,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedMore, Phase::RetainedFinal])?;
        if op.owner.algorithm.ok_or(Error::Identity)?.encode() != identity {
            return Err(Error::Identity);
        }
        if width != op.owner.width || last != op.owner.last {
            return Err(Error::Length);
        }
        if !copy(op.owner.output.get(..width).ok_or(Error::Length)?) {
            return Err(Error::Copy);
        }
        let more = op.owner.phase == Phase::RetainedMore;
        op.owner.clear_output()?;
        if more {
            op.owner.phase = Phase::Squeezing;
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
                Phase::Streaming,
                Phase::Squeezing,
                Phase::RetainedMore,
                Phase::RetainedFinal,
            ],
        )?;
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(())
    }
    fn clear_output(&mut self) -> Result<(), Error> {
        let _ = clear_owned_region(&mut self.output).map_err(|_| Error::Copy)?;
        self.width = 0;
        self.last = 0;
        Ok(())
    }
    fn clear(&mut self) {
        self.state = State::Empty;
        let _ = self.clear_output();
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
struct Scratch([u8; 1024]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha3_stream_tests;
