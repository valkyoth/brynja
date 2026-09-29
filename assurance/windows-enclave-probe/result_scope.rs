//! Research-only scoped result ownership. Not an enclave transport or public API.
#![no_std]
#![forbid(unsafe_code)]

use brynja_core::OwnedSecretRegion;
use brynja_hash_sha2::hardened_in_place::Sha256Workspace;
use core::marker::PhantomData;

pub const PUBLIC_OUTPUT: u64 = 0x5055_424c_4943;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Exhausted,
    Hash,
    Rejected,
    Spent,
    Copy,
}

/// One experiment instance's sequence. The caller-supplied identity is ONLY a
/// diagnostic model input, not random authority or an authenticated identity.
/// A real enclave adapter must establish instance identity independently.
pub struct Issuer {
    identity: u64,
    last: u64,
    thread_bound: PhantomData<*mut ()>,
}

impl Issuer {
    pub fn new(identity: u64) -> Result<Self, Error> {
        if identity == 0 {
            return Err(Error::Identity);
        }
        Ok(Self {
            identity,
            last: 0,
            thread_bound: PhantomData,
        })
    }

    fn issue(&mut self) -> Result<[u64; 2], Error> {
        let next = self.last.checked_add(1).ok_or(Error::Exhausted)?;
        self.last = next;
        Ok([self.identity, next])
    }

    /// One scope, one result, no handle or secret storage survives scope exit.
    /// `input` and the public-output decision must be public test material here.
    /// The higher-ranked borrow prevents moving/returning the live handle.
    pub fn sha256<R>(
        &mut self,
        workspace: &mut Sha256Workspace,
        destination: &mut [u8; 32],
        input: &[u8],
        operation: impl for<'scope> FnOnce(&mut ResultHandle<'scope>) -> R,
    ) -> Result<R, Error> {
        // A failed admission must clear the supplied output as well.
        let _ = brynja_core::clear_owned_region(destination);
        let token = self.issue()?;
        let output = workspace
            .with(|mut state| {
                state.update(input)?;
                state.finalize_secret(destination)
            })
            .map_err(|_| Error::Hash)?;
        let mut handle = ResultHandle {
            output: Some(output),
            token,
            thread_bound: PhantomData,
        };
        Ok(operation(&mut handle))
        // Handle Drop releases the output owner even when operation unwinds.
    }
}

/// Affine result owner; deliberately no Clone/Copy/Debug/Send/Sync or byte view.
/// Raw token words are public routing metadata, NOT a cryptographic capability.
/// This file is an isolated research fixture, not a shipping facade.
pub struct ResultHandle<'scope> {
    output: Option<OwnedSecretRegion<'scope>>,
    token: [u64; 2],
    thread_bound: PhantomData<*mut ()>,
}

impl ResultHandle<'_> {
    pub fn token(&self) -> [u64; 2] {
        self.token
    }

    /// Every attempt is terminal, including malformed metadata and copy failure.
    /// Copy-out may partially modify its host destination before returning false;
    /// only enclave-owned storage cleanup is promised by this local model.
    pub fn export_public(
        &mut self,
        token: [u64; 2],
        flag: u64,
        write: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), Error> {
        let output = self.output.take().ok_or(Error::Spent)?;
        if (!cfg!(probe_ignore_result_token) && token != self.token)
            || (!cfg!(probe_implicit_result_public) && flag != PUBLIC_OUTPUT)
        {
            return Err(Error::Rejected);
        }
        let success = write(output.expose());
        if cfg!(probe_reusable_result) {
            self.output = Some(output);
        } else if cfg!(probe_forget_result) {
            core::mem::forget(output);
        }
        if success { Ok(()) } else { Err(Error::Copy) }
    }

    pub fn cancel(&mut self, token: [u64; 2]) -> Result<(), Error> {
        let _output = self.output.take().ok_or(Error::Spent)?;
        if token != self.token {
            Err(Error::Rejected)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "result_scope_tests.rs"]
mod tests;
