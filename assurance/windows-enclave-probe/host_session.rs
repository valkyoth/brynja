//! Research-only host ownership model. Does not load or own an OS enclave yet.
//! All inputs/staging are PUBLIC test data. No confidential-channel guarantee.
#![no_std]
#![forbid(unsafe_code)]

use core::marker::PhantomData;

#[path = "host_session_wire.rs"]
mod wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    Quarantined,
    Bounds,
    Exhausted,
    Protocol,
    Copy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Ready,
    Busy,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Exported,
    Cancelled,
}

/// Classification assertion only; cannot establish provenance or declassify.
pub struct PublicInput<'a>(&'a [u8]);

impl<'a> PublicInput<'a> {
    pub fn acknowledge(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

/// Export is explicitly public. Ordinary host buffers are never protected output.
pub enum Disposition<'a> {
    ExportPublic(&'a mut [u8; 32]),
    Cancel,
}

/// One future adapter-owned enclave instance. This isolated constructor creates
/// only a protocol ledger, NOT an enclave, authenticated identity or OS resource.
/// A native adapter must own the actual instance and never reset this ledger to
/// recover an uncertain call. The source-isolated fixture exposes no transport.
pub struct Session {
    namespace: Option<[u64; 2]>,
    epoch: u64,
    state: State,
    thread_bound: PhantomData<*mut ()>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            namespace: None,
            epoch: 0,
            state: State::Ready,
            thread_bound: PhantomData,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The three borrows retain session, public input and optional destination.
    /// Dropping before transport entry is harmless. Forgetting the scope leaves
    /// Busy latched; dropping after entry without verified completion quarantines.
    pub fn prepare<'session, 'input, 'output>(
        &'session mut self,
        input: PublicInput<'input>,
        disposition: Disposition<'output>,
    ) -> Result<Pending<'session, 'input, 'output>, Error> {
        match self.state {
            State::Busy => return Err(Error::Busy),
            State::Quarantined => return Err(Error::Quarantined),
            State::Ready => {}
        }
        if input.0.len() > 1024 {
            return Err(Error::Bounds);
        }
        if self.epoch == u64::MAX {
            return Err(Error::Exhausted);
        }
        self.state = State::Busy;
        Ok(Pending {
            session: self,
            input,
            disposition,
            phase: Phase::Prepared,
            token: None,
            first_status: 0,
            destination: 0,
            received: None,
            staging: [0; 32],
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Prepared,
    Entered,
    Offered,
    Replayed,
    Complete,
    Failed,
}

/// No raw token, byte view, callback, request constructor or completion method
/// is public. The internal adapter must validate real native observations before
/// completing. This model is not itself an OS trust or authentication boundary.
pub struct Pending<'session, 'input, 'output> {
    session: &'session mut Session,
    input: PublicInput<'input>,
    disposition: Disposition<'output>,
    phase: Phase,
    token: Option<[u64; 4]>,
    first_status: u64,
    destination: u64,
    received: Option<usize>,
    staging: [u8; 32],
}

impl Pending<'_, '_, '_> {
    fn fail<T>(&mut self) -> Result<T, Error> {
        self.session.state = State::Quarantined;
        self.phase = Phase::Failed;
        self.staging.fill(0);
        Err(Error::Protocol)
    }

    fn exporting(&self) -> bool {
        matches!(self.disposition, Disposition::ExportPublic(_))
    }

    fn finish(
        &mut self,
        first: u64,
        second: u64,
        inner_clear: bool,
        outer_clear: bool,
    ) -> Result<Outcome, Error> {
        if self.phase != Phase::Replayed
            || first != self.first_status
            || (self.exporting() && first == 1 && self.received != Some(32))
            || (!cfg!(probe_host_ignore_spent) && second != 21)
            || (!cfg!(probe_host_ignore_cleanup) && !(inner_clear && outer_clear))
        {
            return self.fail();
        }
        let outcome = match (&mut self.disposition, first) {
            (Disposition::ExportPublic(destination), 1) => {
                destination.copy_from_slice(&self.staging);
                Ok(Outcome::Exported)
            }
            (Disposition::ExportPublic(_), 12) => Err(Error::Copy),
            (Disposition::Cancel, 2) => Ok(Outcome::Cancelled),
            _ => return self.fail(),
        };
        self.staging.fill(0);
        self.phase = Phase::Complete;
        self.session.state = State::Ready;
        outcome
    }
}

impl Drop for Pending<'_, '_, '_> {
    fn drop(&mut self) {
        // Only public staging, not a compiler-resistant secret erasure claim.
        self.staging.fill(0);
        match self.phase {
            Phase::Prepared => self.session.state = State::Ready,
            Phase::Complete | Phase::Failed => {}
            _ => {
                self.session.state = if cfg!(probe_host_reuse_incomplete) {
                    State::Ready
                } else {
                    State::Quarantined
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "host_session_tests.rs"]
mod tests;
