//! Private accelerated enclave worker component; not a host API or qualification.
//! The owner and all call frames must remain in admitted enclave memory. The
//! placement adapter must drop the owner then wipe its entire allocation,
//! including inactive enum storage and padding. No application callback belongs
//! at the private OS-copy seam below.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::clear_owned_region;
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::Fips202BitString;
use core::marker::PhantomData;
use sha3_accelerated_state::State;

pub use sha3_stream::Algorithm;
pub mod sha3_accelerated_wire;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Setup,
    SetupRetained,
    Streaming,
    Squeezing,
    RetainedMore,
    RetainedFinal,
    Quarantined,
}

/// Fixed storage, with no public accumulated input/output counters or preflight
/// oracle. Each retained fragment is bounded; total XOF output is incremental.
pub struct Owner<'cpu> {
    authority: &'cpu Authority,
    state: State<'cpu>,
    algorithm: Option<Algorithm>,
    phase: Phase,
    sequence: u64,
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
            algorithm: None,
            phase: Phase::Empty,
            sequence: 0,
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
        if !allowed.contains(&self.phase) || self.phase == Phase::Quarantined {
            self.quarantine();
            return Err(Error::State);
        }
        if sequence == 0 || self.sequence.checked_add(1) != Some(sequence) {
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
        let algorithm = Algorithm::decode(identity).map_err(|_| Error::Identity)?;
        if name.bit_len() > 8192 || custom.bit_len() > 8192 {
            return Err(Error::Length);
        }
        if !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256)
            && (name.bit_len() != 0 || custom.bit_len() != 0)
        {
            return Err(Error::Identity);
        }
        op.owner.state =
            State::new(op.owner.authority, algorithm, name, custom).map_err(|_| Error::Crypto)?;
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
        op.owner.state.update(input).map_err(|_| Error::Crypto)?;
        op.complete = true;
        Ok(())
    }
    /// Start incremental cSHAKE setup from public lengths. If a fragment is
    /// retained, setup completion rehashes that exact fragment without export.
    pub fn setup(
        &mut self,
        sequence: u64,
        identity: u64,
        name: u128,
        custom: u128,
    ) -> Result<(), Error> {
        let mut op = self.operation(
            sequence,
            &[Phase::Empty, Phase::RetainedMore, Phase::RetainedFinal],
        )?;
        let algorithm = Algorithm::decode(identity).map_err(|_| Error::Identity)?;
        op.owner.state =
            State::setup(op.owner.authority, algorithm, name, custom).map_err(|_| Error::Crypto)?;
        op.owner.algorithm = Some(algorithm);
        op.owner.phase = if op.owner.phase == Phase::Empty {
            Phase::Setup
        } else {
            Phase::SetupRetained
        };
        op.complete = true;
        Ok(())
    }
    pub fn setup_chunk(
        &mut self,
        sequence: u64,
        name: bool,
        input: &[u8],
        last: u8,
    ) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Setup, Phase::SetupRetained])?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        let bits = Fips202BitString::new(input, last).map_err(|_| Error::Bits)?;
        op.owner
            .state
            .setup_chunk(name, bits)
            .map_err(|_| Error::Crypto)?;
        op.complete = true;
        Ok(())
    }
    pub fn finish_setup(&mut self, sequence: u64) -> Result<(), Error> {
        let mut op = self.operation(sequence, &[Phase::Setup, Phase::SetupRetained])?;
        op.owner.state.finish_setup().map_err(|_| Error::Crypto)?;
        if op.owner.phase == Phase::SetupRetained {
            let bits = Fips202BitString::new(
                op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
                op.owner.last,
            )
            .map_err(|_| Error::Bits)?;
            op.owner.state.finish_xof(bits).map_err(|_| Error::Crypto)?;
            op.owner.clear_output()?;
            op.owner.phase = Phase::Squeezing;
        } else {
            op.owner.phase = Phase::Streaming;
        }
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
                self.state
                    .finish_fixed(bits, output)
                    .map_err(|_| Error::Crypto)?;
                self.width = width;
                self.last = 8;
                self.phase = Phase::RetainedFinal;
            }
            None => {
                self.state.finish_xof(bits).map_err(|_| Error::Crypto)?;
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
        op.owner
            .state
            .squeeze(output, last, terminal)
            .map_err(|_| Error::Crypto)?;
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
        let algorithm = Algorithm::decode(identity).map_err(|_| Error::Identity)?;
        let mut next =
            State::new(op.owner.authority, algorithm, name, custom).map_err(|_| Error::Crypto)?;
        let input = Fips202BitString::new(
            op.owner.output.get(..op.owner.width).ok_or(Error::Length)?,
            op.owner.last,
        )
        .map_err(|_| Error::Bits)?;
        let mut scratch = Scratch([0; 1024]);
        if let Some(width) = algorithm.fixed_width() {
            next.finish_fixed(input, scratch.0.get_mut(..width).ok_or(Error::Length)?)
                .map_err(|_| Error::Crypto)?;
        } else {
            next.finish_xof(input).map_err(|_| Error::Crypto)?;
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
        check_authority(op.owner.authority)?;
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
                Phase::Setup,
                Phase::SetupRetained,
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
        self.authority.quarantine();
        self.phase = Phase::Quarantined;
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
fn check_authority(authority: &Authority) -> Result<(), Error> {
    if authority.report().kernel != Kernel::X86Keccak {
        return Err(Error::Backend);
    }
    authority.session().map(|_| ()).map_err(|_| Error::Backend)
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
mod sha3_accelerated_authority_tests;
#[cfg(test)]
mod sha3_accelerated_tests;
