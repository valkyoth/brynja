//! Private bounded eight-message AVX2 component, not yet an enclave worker/API.
//! All inputs, owners, workspace and frames must be admitted enclave storage.
//! This stage accepts at most 1024 bytes per lane, with at least one common
//! complete block. It does not claim arbitrary-length streaming or OS protection.
#![no_std]
#![forbid(unsafe_code)]
pub use batch::{Algorithm, Authority, Kernel};
use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_hash_sha2::{BitString, hardened_batch as batch};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    State,
    Sequence,
    Identity,
    Length,
    Bits,
    Backend,
    Work,
    Copy,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Empty,
    Retained,
    Quarantined,
}
pub struct Lane<'a> {
    pub identity: Algorithm,
    pub bytes: &'a [u8],
    pub last: u8,
}
pub struct Owner<'a> {
    authority: &'a Authority,
    plan: Option<[Algorithm; 8]>,
    output: [u8; 256],
    sequence: u64,
    phase: Phase,
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
struct Scratch([[u8; 32]; 8]);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0.as_flattened_mut());
    }
}
impl<'a> Owner<'a> {
    pub fn new(authority: &'a Authority) -> Result<Self, Error> {
        check(authority)?;
        Ok(Self {
            authority,
            plan: None,
            output: [0; 256],
            sequence: 0,
            phase: Phase::Empty,
        })
    }
    fn operation(&mut self, sequence: u64, phase: Phase) -> Result<Operation<'_, 'a>, Error> {
        if self.phase != phase {
            self.quarantine();
            return Err(Error::State);
        }
        if self.sequence.checked_add(1) != Some(sequence) {
            self.quarantine();
            return Err(Error::Sequence);
        }
        let guard = Operation {
            owner: self,
            complete: false,
        };
        check(guard.owner.authority)?;
        guard.owner.sequence = sequence;
        Ok(guard)
    }
    /// Eight complete independent messages, with canonical optional partial bits.
    /// Budget counts SIMD lane blocks, scalar tails and padding.
    /// Scalar tails are explicit; successful work must include real AVX2 calls.
    pub fn digest(
        &mut self,
        sequence: u64,
        lanes: [Lane<'_>; 8],
        budget: u64,
    ) -> Result<batch::Report, Error> {
        let mut guard = self.operation(sequence, Phase::Empty)?;
        let plan = lanes.each_ref().map(|lane| lane.identity);
        let mut inputs = [None, None, None, None, None, None, None, None];
        for (input, lane) in inputs.iter_mut().zip(&lanes) {
            if lane.bytes.len() > 1024 {
                return Err(Error::Length);
            }
            let bits = BitString::new(lane.bytes, lane.last).map_err(|_| Error::Bits)?;
            *input = Some(batch::Input::new(lane.identity, bits));
        }
        let session = guard
            .owner
            .authority
            .session()
            .map_err(|_| Error::Backend)?;
        let executor = batch::Executor::with_session(session, batch::Mode::Require, 1)
            .map_err(|_| Error::Backend)?;
        let mut workspace = batch::Workspace::new();
        let mut scratch = Scratch([[0; 32]; 8]);
        let mut destinations = [None, None, None, None, None, None, None, None];
        for ((destination, bytes), algorithm) in
            destinations.iter_mut().zip(scratch.0.iter_mut()).zip(plan)
        {
            *destination = Some(
                bytes
                    .get_mut(..algorithm.output_bytes())
                    .ok_or(Error::Length)?,
            );
        }
        let mut cancelled = || false; // Fixed internal control, not a host callback.
        let mut control = batch::Control::new(budget, &mut cancelled);
        let (output, report) = executor
            .digest_secret(&inputs, destinations, &mut workspace, &mut control)
            .map_err(|_| Error::Work)?;
        if report.kernel != Some(Kernel::Avx2) || report.vector_calls == 0 {
            return Err(Error::Backend);
        }
        check(guard.owner.authority)?;
        for (index, destination) in guard.owner.output.chunks_exact_mut(32).enumerate() {
            let source = output.expose(index).ok_or(Error::Identity)?;
            copy_secret_region(
                destination.get_mut(..source.len()).ok_or(Error::Length)?,
                source,
            )
            .map_err(|_| Error::Copy)?;
        }
        // Output owner's drop erases scratch; retained copies remain protected
        // by the enclosing owner. No public declassification is used internally.
        drop(output);
        check(guard.owner.authority)?;
        guard.owner.plan = Some(plan);
        guard.owner.phase = Phase::Retained;
        guard.complete = true;
        Ok(report)
    }
    pub fn export_public(
        &mut self,
        sequence: u64,
        plan: [Algorithm; 8],
        mut copy: impl FnMut(&[u8; 256]) -> bool,
    ) -> Result<(), Error> {
        let mut guard = self.operation(sequence, Phase::Retained)?;
        if guard.owner.plan != Some(plan) {
            return Err(Error::Identity);
        }
        if !copy(&guard.owner.output) {
            return Err(Error::Copy);
        }
        check(guard.owner.authority)?;
        guard.owner.clear();
        guard.owner.phase = Phase::Empty;
        guard.complete = true;
        Ok(())
    }
    pub fn cancel(&mut self, sequence: u64) -> Result<(), Error> {
        if self.phase == Phase::Quarantined {
            return Err(Error::State);
        }
        let mut guard = self.operation(sequence, self.phase)?;
        guard.owner.clear();
        guard.owner.phase = Phase::Empty;
        guard.complete = true;
        Ok(())
    }
    fn clear(&mut self) {
        let _ = clear_owned_region(&mut self.output);
        self.plan = None;
    }
    pub fn quarantine(&mut self) {
        self.clear();
        self.phase = Phase::Quarantined;
        self.authority.quarantine();
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.quarantine();
    }
}
fn check(authority: &Authority) -> Result<(), Error> {
    let session = authority.session().map_err(|_| Error::Backend)?;
    if session.kernel() != Kernel::Avx2 {
        return Err(Error::Backend);
    }
    session.ensure_healthy().map_err(|_| Error::Backend)
}
#[cfg(test)]
extern crate std;
#[cfg(test)]
mod sha256_simd_tests;
