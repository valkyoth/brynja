//! Scoped, caller-owned storage for collision-broken legacy MD5.
//!
//! Active state is borrowed, not returned by value. An independent scope guard
//! clears storage even if a handle is forgotten or the callback unwinds. Existing
//! by-value APIs are unchanged. This portable profile does not select hardware
//! acceleration or promise removal of registers, spills, compiler copies, caller
//! input or platform storage. Abort cannot run scope destructors. Memory hygiene
//! does not repair MD5 or make a raw digest an authentication mechanism.
//!
//! ```
//! use brynja_legacy_md5::{Md5Error, hardened_in_place::Md5Workspace};
//! let mut workspace = Md5Workspace::new();
//! let mut bytes = [0; 16];
//! let secret = workspace.with(|mut state| {
//!     state.update(b"abc")?;
//!     state.finalize_secret(&mut bytes)
//! })?;
//! assert_eq!(secret.expose().len(), 16);
//! drop(secret);
//! assert_eq!(bytes, [0; 16]);
//! # Ok::<(), Md5Error>(())
//! ```

use crate::{BitString, Md5Error, PublicDeclassification, engine, output, owner::Md5Owner};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization};
use core::marker::PhantomData;

struct Cleanup<'scope> {
    owner: &'scope mut Md5Owner,
    keep: bool,
}
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.owner.wipe();
        }
    }
}

/// Allocation-free, thread-bound storage for one portable legacy MD5 scope.
///
/// The callback first receives the handle after the public IV is restored in
/// cleared storage. All five owned regions clear before the scope returns.
/// ```compile_fail
/// use brynja_legacy_md5::hardened_in_place::Md5Workspace;
/// let mut workspace = Md5Workspace::new();
/// let escaped = workspace.with(|state| state);
/// ```
/// ```compile_fail
/// use brynja_legacy_md5::hardened_in_place::Md5Workspace;
/// let mut workspace = Md5Workspace::new();
/// workspace.with(|_state| workspace.with(|_other| ()));
/// ```
pub struct Md5Workspace {
    owner: Md5Owner,
    thread_bound: PhantomData<*mut ()>,
}
impl Md5Workspace {
    /// Creates empty storage containing only the public MD5 IV.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: Md5Owner::new(),
            thread_bound: PhantomData,
        }
    }
    /// Runs with exclusive borrowed state. Output borrowing a separate caller
    /// destination may outlive this scope; the active state cannot escape it.
    pub fn with<R>(&mut self, operation: impl for<'scope> FnOnce(Md5<'scope>) -> R) -> R {
        self.owner.wipe();
        // Public IV only; never construct or move a populated owner here.
        self.owner.chaining_state.copy_from_slice(&[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let cleanup = Cleanup {
            owner: &mut self.owner,
            keep: false,
        };
        operation(Md5 {
            owner: &mut *cleanup.owner,
            active: true,
            thread_bound: PhantomData,
        })
    }
}
impl Default for Md5Workspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Exclusive handle, with consuming finalization and no snapshot or length query.
///
/// An update error clears and terminates the state. A fresh computation requires
/// a new workspace scope. Public release always requires explicit declassification.
/// ```compile_fail
/// use brynja_legacy_md5::hardened_in_place::Md5Workspace;
/// let mut w = Md5Workspace::new();
/// w.with(|mut s| { s.cancel(); s.update(b"late").ok(); });
/// ```
#[must_use = "finalize or cancel the scoped state"]
pub struct Md5<'scope> {
    owner: &'scope mut Md5Owner,
    active: bool,
    thread_bound: PhantomData<*mut ()>,
}
impl Md5<'_> {
    /// Absorbs complete bytes. Failure or recoverable unwind clears the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Md5Error> {
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
    /// Consumes the state and releases exactly sixteen public bytes.
    /// On failure the public destination is unchanged.
    pub fn finalize_public(
        self,
        destination: &mut [u8],
        authority: PublicDeclassification,
    ) -> Result<(), Md5Error> {
        self.finalize_bits_public(empty()?, destination, authority)
    }
    /// Consumes a canonical MSB-first bit tail before explicit public release.
    pub fn finalize_bits_public(
        mut self,
        tail: BitString<'_>,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Md5Error> {
        if destination.len() != crate::DIGEST_BYTES {
            return Err(Md5Error::OutputLength);
        }
        self.stage(tail)?;
        destination.copy_from_slice(&self.owner.output_staging);
        Ok(())
    }
    /// Consumes the state into typed secret output; errors clear all destination bytes.
    pub fn finalize_secret(
        self,
        destination: &mut [u8],
    ) -> Result<OwnedSecretRegion<'_>, Md5Error> {
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
    ) -> Result<OwnedSecretRegion<'out>, Md5Error> {
        if destination.len() != crate::DIGEST_BYTES {
            return Err(output::failed(destination, Md5Error::OutputLength));
        }
        let mut initialization =
            SecretRegionInitialization::begin(destination).map_err(|_| Md5Error::SecretMemory)?;
        self.stage(tail)?;
        initialization
            .write(&self.owner.output_staging)
            .map_err(|_| Md5Error::SecretMemory)?;
        initialization.finish().map_err(|_| Md5Error::SecretMemory)
    }
    /// Clears the borrowed state without producing a digest.
    pub fn cancel(self) {}
    fn check(&self) -> Result<(), Md5Error> {
        if self.active {
            Ok(())
        } else {
            Err(Md5Error::StateConsumed)
        }
    }
    fn stage(&mut self, tail: BitString<'_>) -> Result<(), Md5Error> {
        self.check()?;
        self.active = false;
        engine::finish(self.owner, tail)
    }
}
impl Drop for Md5<'_> {
    fn drop(&mut self) {
        self.owner.wipe();
    }
}
fn empty() -> Result<BitString<'static>, Md5Error> {
    BitString::new(&[], 0).map_err(|_| Md5Error::MessageTooLong)
}

#[cfg(test)]
mod tests;
