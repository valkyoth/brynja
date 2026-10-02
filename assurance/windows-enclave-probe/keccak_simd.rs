//! Private bounded four-message AVX2 component, not an enclave worker/API.
//! Every message/name/customization is bounded to 1024 bytes; each output to
//! 2048 bits. All inputs, owners, scratch and frames require admitted storage.
//! No OS protection, whole-image cleanup or production qualification is implied.
#![no_std]
#![forbid(unsafe_code)]
pub use batch::{Algorithm, Authority, Kernel};
use brynja_core::{clear_owned_region, copy_secret_region};
use brynja_hash_sha3::{Fips202BitString, hardened_batch as batch};

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
/// Public identity and exact finite output width; not secret-derived metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub identity: Algorithm,
    pub output_bits: usize,
}
pub struct Lane<'a> {
    pub slot: Slot,
    pub message: Fips202BitString<'a>,
    pub name: Fips202BitString<'a>,
    pub custom: Fips202BitString<'a>,
}
pub struct Owner<'a> {
    authority: &'a Authority,
    plan: Option<[Slot; 4]>,
    output: [u8; 1024],
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
struct Scratch([[u8; 256]; 4]);
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
            output: [0; 1024],
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
    /// Four independent messages. Public budget counts independent permutations,
    /// including customization, padding and squeezing. Scalar tails are explicit;
    /// a successful request must perform an actual four-state AVX2 dispatch.
    pub fn digest(
        &mut self,
        sequence: u64,
        lanes: [Lane<'_>; 4],
        budget: u64,
    ) -> Result<batch::Report, Error> {
        let mut guard = self.operation(sequence, Phase::Empty)?;
        let plan = lanes.each_ref().map(|lane| lane.slot);
        let mut inputs = [None, None, None, None];
        for (input, lane) in inputs.iter_mut().zip(&lanes) {
            if lane.message.bit_len() > 8192
                || lane.name.bit_len() > 8192
                || lane.custom.bit_len() > 8192
                || lane.slot.output_bits > 2048
            {
                return Err(Error::Length);
            }
            *input = Some(
                batch::Input::with_customization(
                    lane.slot.identity,
                    lane.message,
                    lane.name,
                    lane.custom,
                    lane.slot.output_bits,
                )
                .map_err(|_| Error::Identity)?,
            );
        }
        let session = guard
            .owner
            .authority
            .session()
            .map_err(|_| Error::Backend)?;
        let executor = batch::Executor::with_session(session, batch::Mode::Require, 1)
            .map_err(|_| Error::Backend)?;
        let mut workspace = batch::Workspace::new();
        let mut scratch = Scratch([[0; 256]; 4]);
        let mut staging = Scratch([[0; 256]; 4]);
        let mut destinations = [None, None, None, None];
        for ((destination, bytes), slot) in
            destinations.iter_mut().zip(scratch.0.iter_mut()).zip(plan)
        {
            *destination = Some(
                bytes
                    .get_mut(..slot.output_bits.div_ceil(8))
                    .ok_or(Error::Length)?,
            );
        }
        let mut cancelled = || false; // Internal control, never a host callback.
        let mut control = batch::Control::new(budget, &mut cancelled);
        let (output, report) = executor
            .digest_secret(
                &inputs,
                destinations,
                &mut workspace,
                staging.0.as_flattened_mut(),
                &mut control,
            )
            .map_err(|_| Error::Work)?;
        if report.kernel != Some(Kernel::Avx2)
            || report.vector_calls == 0
            || report.accelerated_slots != 15
        {
            return Err(Error::Backend);
        }
        check(guard.owner.authority)?;
        for (index, destination) in guard.owner.output.chunks_exact_mut(256).enumerate() {
            let source = output.expose(index).ok_or(Error::Identity)?;
            copy_secret_region(
                destination.get_mut(..source.len()).ok_or(Error::Length)?,
                source,
            )
            .map_err(|_| Error::Copy)?;
        }
        drop(output);
        check(guard.owner.authority)?;
        guard.owner.plan = Some(plan);
        guard.owner.phase = Phase::Retained;
        guard.complete = true;
        Ok(report)
    }
    /// Fixed trusted OS-copy seam, not an exported application callback.
    /// Retained results occupy four zero-padded 256-byte slots in plan order.
    pub fn export_public(
        &mut self,
        sequence: u64,
        plan: [Slot; 4],
        mut copy: impl FnMut(&[u8; 1024]) -> bool,
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
mod keccak_simd_oracle_tests;
#[cfg(test)]
mod keccak_simd_tests;
