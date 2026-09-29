//! Isolated public-data lifecycle model. NOT protected allocation or a native API.
#![no_std]
#![forbid(unsafe_code)]

use core::marker::PhantomData;

pub const PUBLIC_OUTPUT: u64 = 0x5055_424c_4943;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Identity,
    Busy,
    Spent,
    Rejected,
    Fill,
    Copy,
    Exhausted,
    Quarantined,
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Busy,
    Ready,
    Quarantined,
    Closed,
}

/// Metadata can move; the exclusively borrowed storage does not move with it.
/// The adapter must establish protected residency before constructing this owner
/// and retain that residency until after owner destruction. This safe MODEL does
/// not attest allocation, locks, enclave identity or platform teardown.
/// Tokens are public routing metadata, not authentication capabilities.
pub struct Slot<'storage> {
    bytes: &'storage mut [u8; 32],
    identity: [u64; 2],
    generation: u64,
    state: State,
    thread_bound: PhantomData<*mut ()>,
}

impl<'storage> Slot<'storage> {
    pub fn new(bytes: &'storage mut [u8; 32], identity: [u64; 2]) -> Result<Self, Error> {
        let _ = brynja_core::clear_owned_region(bytes);
        if identity == [0; 2] {
            return Err(Error::Identity);
        }
        Ok(Self {
            bytes,
            identity,
            generation: 0,
            state: State::Idle,
            thread_bound: PhantomData,
        })
    }

    fn available(&self) -> Result<(), Error> {
        match self.state {
            State::Quarantined => Err(Error::Quarantined),
            State::Closed => Err(Error::Closed),
            _ => Ok(()),
        }
    }

    fn token(&self) -> [u64; 4] {
        [self.identity[0], self.identity[1], self.generation, 1]
    }

    fn clear(&mut self) {
        if !cfg!(probe_persistent_skip_clear) {
            let _ = brynja_core::clear_owned_region(self.bytes);
        }
    }

    /// Trusted test seam, not a proposed public callback API. A native adapter
    /// must substitute a fixed operation writing directly into protected storage.
    /// False or unwind invalidates the entire slot, including partial output.
    pub fn fill(&mut self, write: impl FnOnce(&mut [u8; 32]) -> bool) -> Result<[u64; 4], Error> {
        self.available()?;
        if self.state != State::Idle {
            return Err(Error::Busy);
        }
        let Some(next) = self.generation.checked_add(1) else {
            self.quarantine();
            return Err(Error::Exhausted);
        };
        if !cfg!(probe_persistent_reuse_generation) {
            self.generation = next;
        }
        self.clear();
        self.state = State::Busy;
        let mut guard = Operation {
            slot: self,
            success: None,
        };
        if !write(guard.slot.bytes) {
            return Err(Error::Fill);
        }
        let token = guard.slot.token();
        guard.success = Some(State::Ready);
        Ok(token)
    }

    fn consume(&mut self) -> Result<Operation<'_, 'storage>, Error> {
        self.available()?;
        if self.state != State::Ready {
            return Err(Error::Spent);
        }
        self.state = State::Busy;
        Ok(Operation {
            slot: self,
            success: None,
        })
    }

    /// Every attempt on a ready result consumes it, even wrong metadata. Failed
    /// copy-out can partially modify PUBLIC host output; it also quarantines.
    pub fn export_public(
        &mut self,
        token: [u64; 4],
        flag: u64,
        write: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let mut guard = self.consume()?;
        if (!cfg!(probe_persistent_ignore_token) && token != guard.slot.token())
            || (!cfg!(probe_persistent_implicit_public) && flag != PUBLIC_OUTPUT)
        {
            guard.success = Some(State::Idle);
            return Err(Error::Rejected);
        }
        if !write(guard.slot.bytes) {
            return Err(Error::Copy);
        }
        guard.success = Some(State::Idle);
        Ok(())
    }

    pub fn cancel(&mut self, token: [u64; 4]) -> Result<(), Error> {
        let mut guard = self.consume()?;
        let valid = token == guard.slot.token();
        guard.success = Some(State::Idle);
        if valid { Ok(()) } else { Err(Error::Rejected) }
    }

    /// Unknown completion / lost host receipt never reopens the slot.
    pub fn quarantine(&mut self) {
        self.clear();
        if self.state != State::Closed {
            self.state = State::Quarantined;
        }
    }

    /// Clears before the adapter may release residency. Not an OS-delete receipt.
    pub fn close(&mut self) {
        self.clear();
        self.state = State::Closed;
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

struct Operation<'operation, 'storage> {
    slot: &'operation mut Slot<'storage>,
    success: Option<State>,
}

impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if self.success != Some(State::Ready) {
            self.slot.clear();
        }
        self.slot.state = self.success.unwrap_or(State::Quarantined);
    }
}

#[cfg(test)]
#[path = "persistent_result_tests.rs"]
mod tests;
