//! Private retained SHA-NI worker component; not a host API or admission proof.
//! Authority, owner, staging and every frame must reside inside the enclave.
//! The placement adapter must destroy this owner before its borrowed authority,
//! then clear the entire backing page, including inactive storage and padding.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha2::BitString;
pub use sha2_stream::Algorithm;

mod sha2_accelerated_state;
pub mod sha2_accelerated_wire;
use sha2_accelerated_state::State;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Sequence,
    State,
    Length,
    Bits,
    Copy,
    Backend,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Empty,
    Streaming,
    Retained,
    Quarantined,
}

/// Borrows an already established exact SHA-NI authority. No portable route.
/// This private component is not an authority constructor or a public callback API.
pub struct Owner<'a> {
    authority: &'a Authority,
    algorithm: Option<Algorithm>,
    state: Option<State<'a>>,
    output: [u8; 32],
    phase: Phase,
    sequence: u64,
}

struct Operation<'s, 'a> {
    owner: &'s mut Owner<'a>,
    complete: bool,
}
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.quarantine();
        }
    }
}

impl<'a> Owner<'a> {
    pub fn new(authority: &'a Authority) -> Result<Self, Error> {
        check_authority(authority)?;
        Ok(Self {
            authority,
            algorithm: None,
            state: None,
            output: [0; 32],
            phase: Phase::Empty,
            sequence: 0,
        })
    }
    fn operation(&mut self, sequence: u64, phase: Phase) -> Result<Operation<'_, 'a>, Error> {
        if self.phase != phase || self.phase == Phase::Quarantined {
            self.quarantine();
            return Err(Error::State);
        }
        if sequence == 0 || self.sequence.checked_add(1) != Some(sequence) {
            self.quarantine();
            return Err(Error::Sequence);
        }
        let guard = Operation {
            owner: self,
            complete: false,
        };
        // Recheck even when the operation does not compress a block (retained
        // export, cancellation, empty update); stale authority never releases data.
        check_authority(guard.owner.authority)?;
        guard.owner.sequence = sequence;
        Ok(guard)
    }
    pub fn begin(&mut self, sequence: u64, identity: u64) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Empty)?;
        let algorithm = narrow(identity)?;
        guard.owner.state = Some(State::new(algorithm, guard.owner.authority)?);
        guard.owner.algorithm = Some(algorithm);
        guard.owner.phase = Phase::Streaming;
        guard.complete = true;
        Ok(())
    }
    pub fn update(&mut self, sequence: u64, input: &[u8]) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Streaming)?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        guard
            .owner
            .state
            .as_mut()
            .ok_or(Error::State)?
            .update(input)?;
        guard.complete = true;
        Ok(())
    }
    pub fn finish(&mut self, sequence: u64, input: &[u8], last: u8) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Streaming)?;
        if input.len() > 1024 {
            return Err(Error::Length);
        }
        let bits = BitString::new(input, last).map_err(|_| Error::Bits)?;
        let width = guard.owner.algorithm.ok_or(Error::Identity)?.width();
        guard.owner.state.take().ok_or(Error::State)?.finish(
            bits,
            guard.owner.output.get_mut(..width).ok_or(Error::Length)?,
        )?;
        guard.owner.phase = Phase::Retained;
        guard.complete = true;
        Ok(())
    }
    pub fn rehash(&mut self, sequence: u64, identity: u64) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Retained)?;
        let algorithm = narrow(identity)?;
        let previous = guard.owner.algorithm.ok_or(Error::Identity)?;
        let input = guard
            .owner
            .output
            .get(..previous.width())
            .ok_or(Error::Length)?;
        let bits = BitString::new(input, 8).map_err(|_| Error::Bits)?;
        let mut staging = Scratch([0; 32]);
        let output = staging
            .0
            .get_mut(..algorithm.width())
            .ok_or(Error::Length)?;
        State::new(algorithm, guard.owner.authority)?.finish(bits, output)?;
        let _ = clear_owned_region(&mut guard.owner.output).map_err(|_| Error::Copy)?;
        copy_secret_region(
            guard
                .owner
                .output
                .get_mut(..algorithm.width())
                .ok_or(Error::Length)?,
            output,
        )
        .map_err(|_| Error::Copy)?;
        guard.owner.algorithm = Some(algorithm);
        guard.complete = true;
        Ok(())
    }
    /// Private seam for the fixed OS copy-out after explicit declassification.
    pub fn export_public(
        &mut self,
        sequence: u64,
        identity: u64,
        copy: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Retained)?;
        let algorithm = guard.owner.algorithm.ok_or(Error::Identity)?;
        if algorithm.encode() != identity {
            return Err(Error::Identity);
        }
        if !copy(
            guard
                .owner
                .output
                .get(..algorithm.width())
                .ok_or(Error::Length)?,
        ) {
            return Err(Error::Copy);
        }
        check_authority(guard.owner.authority)?;
        guard.owner.clear();
        guard.owner.phase = Phase::Empty;
        guard.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Streaming | Phase::Retained) {
            self.quarantine();
            return Err(Error::State);
        }
        let mut guard = self.operation(sequence, self.phase)?;
        guard.owner.clear();
        guard.owner.phase = Phase::Empty;
        guard.complete = true;
        Ok(())
    }
    fn clear(&mut self) {
        drop(self.state.take());
        let _ = clear_owned_region(&mut self.output);
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
    if authority.report().kernel != Kernel::X86Sha256 {
        return Err(Error::Backend);
    }
    authority.session().map(|_| ()).map_err(|_| Error::Backend)
}
fn narrow(identity: u64) -> Result<Algorithm, Error> {
    let algorithm = Algorithm::decode(identity).map_err(|_| Error::Identity)?;
    if !matches!(algorithm, Algorithm::Sha224 | Algorithm::Sha256) {
        return Err(Error::Identity);
    }
    Ok(algorithm)
}
struct Scratch([u8; 32]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(&mut self.0);
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha2_accelerated_tests;
#[cfg(test)]
mod sha2_accelerated_wire_tests;
