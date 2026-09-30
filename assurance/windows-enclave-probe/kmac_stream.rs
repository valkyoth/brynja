//! Private scalar KMAC worker component, not a shipping API or qualification.
//! Place this owner and every call frame inside admitted enclave memory. After
//! Drop, clear its complete allocation including inactive enum storage/padding.
//! Setup currently bounds the complete key/customization to 1024 bytes each;
//! streamed setup and native transport remain separate work.
#![no_std]
#![forbid(unsafe_code)]
use brynja_core::{
    accumulate_secret_byte_difference, clear_owned_region, secret_difference_is_zero,
};
use brynja_mac_kmac::Fips202BitString;
use core::marker::PhantomData;
mod kmac_stream_state;
use kmac_stream_state::State;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Kmac128,
    Kmac256,
    KmacXof128,
    KmacXof256,
}
impl Algorithm {
    pub fn decode(value: u64) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Kmac128),
            2 => Ok(Self::Kmac256),
            3 => Ok(Self::KmacXof128),
            4 => Ok(Self::KmacXof256),
            _ => Err(Error::Identity),
        }
    }
    pub fn encode(self) -> u64 {
        match self {
            Self::Kmac128 => 1,
            Self::Kmac256 => 2,
            Self::KmacXof128 => 3,
            Self::KmacXof256 => 4,
        }
    }
    fn fixed(self) -> bool {
        matches!(self, Self::Kmac128 | Self::Kmac256)
    }
}
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
    Streaming,
    Squeezing,
    RetainedMore,
    RetainedFinal,
    Quarantined,
}
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
struct Scratch([u8; 1024]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}
struct Difference([u8; 1]);
impl Drop for Difference {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
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
        self.state = State::Empty;
        self.clear_output();
        self.algorithm = None;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.phase = Phase::Quarantined;
    }
    pub fn begin(
        &mut self,
        sequence: u64,
        identity: u64,
        key: Fips202BitString<'_>,
        custom: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Empty])?;
        let algorithm = Algorithm::decode(identity)?;
        op.owner.state = State::new(algorithm, key, custom)?;
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
    /// Fixed output binds right_encode to its exact bit length. XOF finalization
    /// instead requires width=last=0 and retains the reader, not output bytes.
    pub fn finish(
        &mut self,
        sequence: u64,
        input: Fips202BitString<'_>,
        width: usize,
        last: u8,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Streaming])?;
        if input.as_bytes().len() > 1024 {
            return Err(Error::Length);
        }
        if op.owner.algorithm.ok_or(Error::Identity)?.fixed() {
            shape(width, last)?;
            op.owner.state.fixed(
                input,
                op.owner.output.get_mut(..width).ok_or(Error::Length)?,
                last,
            )?;
            op.owner.width = width;
            op.owner.last = last;
            op.owner.phase = Phase::RetainedFinal;
        } else {
            if width != 0 || last != 0 {
                return Err(Error::Length);
            }
            op.owner.state.finish_xof(input)?;
            op.owner.phase = Phase::Squeezing;
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
        let mut op = self.operation(sequence, &[Phase::Squeezing])?;
        shape(width, last)?;
        if !terminal && last != if width == 0 { 0 } else { 8 } {
            return Err(Error::Bits);
        }
        op.owner.state.squeeze(
            op.owner.output.get_mut(..width).ok_or(Error::Length)?,
            last,
            terminal,
        )?;
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
    /// Constant-work comparison for the declared public tag shape. Mismatch is
    /// an authentication decision, not quarantine. No retained bytes escape.
    pub fn verify(
        &mut self,
        sequence: u64,
        identity: u64,
        candidate: Fips202BitString<'_>,
    ) -> Result<bool, Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedFinal])?;
        let algorithm = op.owner.algorithm.ok_or(Error::Identity)?;
        if !algorithm.fixed() || algorithm.encode() != identity {
            return Err(Error::Identity);
        }
        if candidate.as_bytes().len() != op.owner.width
            || candidate.valid_bits_in_last_byte() != op.owner.last
        {
            return Err(Error::Length);
        }
        let mut difference = Difference([0]);
        for (left, right) in op
            .owner
            .output
            .get(..op.owner.width)
            .ok_or(Error::Length)?
            .iter()
            .zip(candidate.as_bytes())
        {
            accumulate_secret_byte_difference(&mut difference.0[0], left, right);
        }
        let result = secret_difference_is_zero(&difference.0[0]).expose_public();
        op.owner.clear();
        op.owner.phase = Phase::Empty;
        op.complete = true;
        Ok(result)
    }
    /// Consume retained output as the next key, inside the protected boundary.
    /// Exact bit length and the next function's strength remain mandatory.
    pub fn rekey(
        &mut self,
        sequence: u64,
        identity: u64,
        custom: Fips202BitString<'_>,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedFinal, Phase::RetainedMore])?;
        let algorithm = Algorithm::decode(identity)?;
        let key = Fips202BitString::new(
            op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
            op.owner.last,
        )
        .map_err(|_| Error::Bits)?;
        let state = State::new(algorithm, key, custom)?;
        op.owner.state = state;
        op.owner.clear_output();
        op.owner.algorithm = Some(algorithm);
        op.owner.phase = Phase::Streaming;
        op.complete = true;
        Ok(())
    }
    /// Private trusted OS-copy seam only. A host wrapper must stage public output
    /// until copying/cleanup receipts succeed; this is not an application callback.
    pub fn export(
        &mut self,
        sequence: u64,
        identity: u64,
        width: usize,
        last: u8,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::RetainedFinal, Phase::RetainedMore])?;
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
        op.owner.clear_output();
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
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod kmac_stream_tests;
