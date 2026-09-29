//! Isolated affine host model. A native adapter must own/validate the OS resource.
//! Fixed public vectors only; no shipping API or native cleanup qualification.
#![no_std]
#![forbid(unsafe_code)]

use core::{marker::PhantomData, num::NonZeroU64};

pub(crate) mod transport {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Outcome {
        Ready,
        Exported,
        Cancelled,
        Released,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Receipt {
        pub identity: u64,
        pub generation: u64,
        pub outcome: Outcome,
        pub worker_clear: bool,
        pub result_clear: bool,
        pub deleted: bool,
    }
    /// Private trusted adapter boundary, not implementable by downstream callers.
    /// It must own its actual instance, serialize calls, validate native reports
    /// and never fabricate receipts. Release MUST NOT unwind (including in Drop).
    /// Failed release must retain OS/callback ownership, not free live resources.
    pub trait Driver {
        fn begin(&mut self, vector: u8, generation: u64) -> Result<Receipt, ()>;
        fn export(&mut self, generation: u64, public_staging: &mut [u8; 32])
        -> Result<Receipt, ()>;
        fn cancel(&mut self, generation: u64) -> Result<Receipt, ()>;
        fn release(&mut self, generation: u64) -> Result<Receipt, ()>;
    }
}
use transport::{Driver, Outcome, Receipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Busy,
    Quarantined,
    Closed,
    Exhausted,
    Protocol,
    Release,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Busy,
    Quarantined,
    Closed,
}

/// A selector for one of the native fixture's twenty PUBLIC vectors, not a
/// classification/provenance assertion for arbitrary application input.
pub struct PublicVector(u8);
impl PublicVector {
    pub fn new(index: u8) -> Result<Self, Error> {
        if index < 20 {
            Ok(Self(index))
        } else {
            Err(Error::Bounds)
        }
    }
}

pub struct Session<D: Driver> {
    driver: D,
    identity: NonZeroU64,
    generation: u64,
    state: State,
    thread_bound: PhantomData<*mut ()>,
}

impl<D: Driver> Session<D> {
    /// Native adapter only: identity must belong to this uniquely owned resource.
    pub(crate) fn from_driver(driver: D, identity: NonZeroU64) -> Self {
        Self {
            driver,
            identity,
            generation: 0,
            state: State::Ready,
            thread_bound: PhantomData,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    fn expected(&self, outcome: Outcome) -> Receipt {
        Receipt {
            identity: self.identity.get(),
            generation: self.generation,
            outcome,
            worker_clear: true,
            result_clear: outcome != Outcome::Ready,
            deleted: outcome == Outcome::Released,
        }
    }

    fn check(&self, receipt: Result<Receipt, ()>, outcome: Outcome) -> bool {
        if cfg!(probe_retained_host_ignore_receipt) {
            return receipt.is_ok();
        }
        receipt == Ok(self.expected(outcome))
    }

    pub fn begin(&mut self, vector: PublicVector) -> Result<Pending<'_, D>, Error> {
        match self.state {
            State::Ready => {}
            State::Busy => return Err(Error::Busy),
            State::Quarantined => return Err(Error::Quarantined),
            State::Closed => return Err(Error::Closed),
        }
        // Arm fail-closed state BEFORE either arithmetic or foreign entry.
        self.state = State::Quarantined;
        let Some(next) = self.generation.checked_add(1) else {
            return Err(Error::Exhausted);
        };
        self.generation = next;
        let receipt = self.driver.begin(vector.0, next);
        if !self.check(receipt, Outcome::Ready) {
            return Err(Error::Protocol);
        }
        self.state = State::Busy;
        Ok(Pending {
            session: self,
            armed: true,
        })
    }

    /// Available even after a forgotten pending result: this owner still owns
    /// the resource. Closed means confirmed release, not simply that Drop ran.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.state = State::Quarantined;
        let receipt = self.driver.release(self.generation);
        if !cfg!(probe_retained_host_false_close) && !self.check(receipt, Outcome::Released) {
            return Err(Error::Release);
        }
        self.state = State::Closed;
        Ok(())
    }
}

impl<D: Driver> Drop for Session<D> {
    fn drop(&mut self) {
        // The adapter records failures and retains the actual resource if OS
        // teardown is unconfirmed. Destructor execution is not a success receipt.
        let _ = self.close();
    }
}

/// Affine borrow of the resource owner; no token, pointer or secret byte access.
/// Dropping abandons/quarantines, with no foreign call in this destructor.
/// Forgetting leaves Busy latched; neither case authorizes another begin.
pub struct Pending<'session, D: Driver> {
    session: &'session mut Session<D>,
    armed: bool,
}

struct PublicStaging([u8; 32]);
impl Drop for PublicStaging {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl<D: Driver> Pending<'_, D> {
    pub fn export_public(mut self, destination: &mut [u8; 32]) -> Result<(), Error> {
        self.armed = false;
        self.session.state = State::Quarantined;
        let mut staging = PublicStaging([0; 32]);
        let receipt = self
            .session
            .driver
            .export(self.session.generation, &mut staging.0);
        if cfg!(probe_retained_host_early_commit) {
            destination.copy_from_slice(&staging.0);
        }
        if !self.session.check(receipt, Outcome::Exported) {
            return Err(Error::Protocol);
        }
        destination.copy_from_slice(&staging.0);
        self.session.state = State::Ready;
        Ok(())
    }

    pub fn cancel(mut self) -> Result<(), Error> {
        self.armed = false;
        self.session.state = State::Quarantined;
        let receipt = self.session.driver.cancel(self.session.generation);
        if !self.session.check(receipt, Outcome::Cancelled) {
            return Err(Error::Protocol);
        }
        self.session.state = State::Ready;
        Ok(())
    }
}

impl<D: Driver> Drop for Pending<'_, D> {
    fn drop(&mut self) {
        if self.armed {
            self.session.state = if cfg!(probe_retained_host_reopen_abandoned) {
                State::Ready
            } else {
                State::Quarantined
            };
        }
    }
}

#[cfg(test)]
#[path = "retained_host_tests.rs"]
mod tests;
