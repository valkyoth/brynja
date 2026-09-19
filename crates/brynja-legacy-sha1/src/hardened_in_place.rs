//! Scoped, caller-owned storage for collision-broken legacy SHA-1.
//!
//! Active state is borrowed, not returned by value. An independent scope guard
//! clears storage even if a handle is forgotten or the callback unwinds. Existing
//! by-value APIs are unchanged. This portable profile does not select hardware
//! acceleration or promise removal of registers, spills, compiler copies, caller
//! input or platform storage. Abort cannot run scope destructors. Memory hygiene
//! does not repair SHA-1 or make a raw digest an authentication mechanism.
//!
//! ```
//! use brynja_legacy_sha1::{Sha1Error, hardened_in_place::Sha1Workspace};
//! let mut workspace = Sha1Workspace::new();
//! let mut bytes = [0; 20];
//! let secret = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut bytes)
//! })?;
//! assert_eq!(secret.expose().len(), 20);
//! drop(secret);
//! assert_eq!(bytes, [0; 20]);
//! # Ok::<(), Sha1Error>(())
//! ```

use crate::{BitString, PublicDeclassification, Sha1Error, engine, output, owner::Sha1Owner};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
use core::marker::PhantomData;

struct Cleanup<'scope> {
    owner: &'scope mut Sha1Owner,
    keep: bool,
}
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.owner.wipe();
        }
    }
}

/// Allocation-free, thread-bound storage for one portable legacy SHA-1 scope.
///
/// The callback first receives the handle after the public IV is restored in
/// cleared storage. All six owned regions clear before the scope returns.
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_in_place::Sha1Workspace;
/// let mut workspace = Sha1Workspace::new();
/// let escaped = workspace.with(|state| state);
/// ```
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_in_place::Sha1Workspace;
/// let mut workspace = Sha1Workspace::new();
/// workspace.with(|_state| workspace.with(|_other| ()));
/// ```
pub struct Sha1Workspace {
    owner: Sha1Owner,
    thread_bound: PhantomData<*mut ()>,
}
impl Sha1Workspace {
    /// Creates empty storage containing only the public SHA-1 IV.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: Sha1Owner::new(),
            thread_bound: PhantomData,
        }
    }
    /// Runs with exclusive borrowed state. Output borrowing a separate caller
    /// destination may outlive this scope; the active state cannot escape it.
    pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce(Sha1<'scope>) -> R) -> R {
        self.owner.wipe();
        // Public IV only; never construct or move a populated owner here.
        self.owner.chaining_state.copy_from_slice(&[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
        ]);
        let cleanup = Cleanup {
            owner: &mut self.owner,
            keep: false,
        };
        operation(Sha1 {
            owner: &mut *cleanup.owner,
            active: true,
            thread_bound: PhantomData,
        })
    }
}
impl Default for Sha1Workspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Exclusive handle, with consuming finalization and no snapshot or length query.
///
/// An update error clears and terminates the state. A fresh computation requires
/// a new workspace scope. Public release always requires explicit declassification.
/// ```compile_fail
/// use brynja_legacy_sha1::hardened_in_place::Sha1Workspace;
/// let mut w = Sha1Workspace::new();
/// w.with(|mut s| { s.cancel(); s.update(b"late").ok(); });
/// ```
#[must_use = "finalize or cancel the scoped state"]
pub struct Sha1<'scope> {
    owner: &'scope mut Sha1Owner,
    active: bool,
    thread_bound: PhantomData<*mut ()>,
}
impl Sha1<'_> {
    /// Absorbs complete bytes. Failure or recoverable unwind clears the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha1Error> {
        self.check()?;
        self.active = false;
        let mut cleanup = Cleanup {
            owner: &mut *self.owner,
            keep: false,
        };
        let result = engine::update(cleanup.owner, input);
        if result.is_ok() {
            cleanup.keep = true;
            self.active = true;
        }
        result
    }
    /// Consumes the state and releases exactly twenty public bytes.
    /// On failure the public destination is unchanged.
    pub fn finalize_public(
        self,
        destination: &mut [u8],
        authority: PublicDeclassification,
    ) -> Result<(), Sha1Error> {
        self.finalize_bits_public(empty()?, destination, authority)
    }
    /// Consumes a canonical MSB-first bit tail before explicit public release.
    pub fn finalize_bits_public(
        mut self,
        tail: BitString<'_>,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Sha1Error> {
        if destination.len() != crate::DIGEST_BYTES {
            return Err(Sha1Error::OutputLength);
        }
        self.stage(tail)?;
        destination.copy_from_slice(&self.owner.output_staging);
        Ok(())
    }
    /// Consumes the state into typed secret output; errors clear all destination bytes.
    pub fn finalize_secret(
        self,
        destination: &mut [u8],
    ) -> Result<OwnedSecretRegion<'_>, Sha1Error> {
        match empty() {
            Ok(tail) => self.finalize_bits_secret(tail, destination),
            Err(error) => Err(output::failed(destination, error)),
        }
    }
    /// Consumes a canonical bit tail into typed secret output. Output initialization
    /// begins before finalization, so error and unwind also clear the destination.
    pub fn finalize_bits_secret<'out>(
        mut self,
        tail: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Sha1Error> {
        if destination.len() != crate::DIGEST_BYTES {
            return Err(output::failed(destination, Sha1Error::OutputLength));
        }
        let mut initialization =
            SecretRegionInitialization::begin(destination).map_err(|_| Sha1Error::SecretMemory)?;
        self.stage(tail)?;
        initialization
            .write(&self.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        initialization.finish().map_err(|_| Sha1Error::SecretMemory)
    }
    /// Clears the borrowed state without producing a digest.
    pub fn cancel(self) {}
    fn check(&self) -> Result<(), Sha1Error> {
        if self.active {
            Ok(())
        } else {
            Err(Sha1Error::StateConsumed)
        }
    }
    fn stage(&mut self, tail: BitString<'_>) -> Result<(), Sha1Error> {
        self.check()?;
        self.active = false;
        engine::finish(self.owner, tail)
    }
}
impl Drop for Sha1<'_> {
    fn drop(&mut self) {
        self.owner.wipe();
    }
}
fn empty() -> Result<BitString<'static>, Sha1Error> {
    BitString::new(&[], 0).map_err(|_| Sha1Error::MessageTooLong)
}

#[cfg(test)]
mod tests;
