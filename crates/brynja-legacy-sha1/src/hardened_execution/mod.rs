//! Opt-in hardened legacy SHA-1; collision-broken, not authentication or FIPS.
//!
//! Secret outputs retain typed ownership. Public output requires explicit
//! declassification. Drop and recoverable unwind clear source-owned buffers,
//! not registers, spills, compiler copies, platform storage or caller copies.
//! `mem::forget`, abort and forced termination can prevent Drop.
//!
//! ```
//! use brynja_legacy_sha1::hardened_execution::Executor;
//! let owner = Executor::portable();
//! let mut bytes = [0u8; 20];
//! let output = owner.hash_secret(b"secret", &mut bytes)?;
//! drop(output); // the borrowed destination is now cleared
//! assert_eq!(bytes, [0; 20]);
//! # Ok::<(), brynja_legacy_sha1::hardened_execution::Error>(())
//! ```

mod engine;
mod ownership;
mod stream;
pub use crate::cpu::HardenedAuthority as Authority;
use crate::{
    BitString, PublicDeclassification, Sha1Backend, Sha1BackendError, Sha1BackendHealth, Sha1Error,
};
use brynja_core::{OwnedSecretRegion, SecretRegionInitialization, clear_owned_region};
use core::cell::Cell;
pub use stream::Stream;

/// Explicit pre-startup selection. Failure after startup never falls back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// No instruction probing or accelerated execution.
    Portable,
    /// Fallback permitted only when no suitable authority is available.
    Prefer,
    /// Require an accelerated owner; return an error when unavailable.
    Require,
}
/// Public diagnostic error; never contains state, input or output material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Instruction selection, authority revocation or internal invariant failure.
    Backend(Sha1BackendError),
    /// Message/output width or typed destination initialization failure.
    Hash(Sha1Error),
    /// Permanently failed stream or revoked executor.
    Quarantined,
}
impl From<Sha1BackendError> for Error {
    fn from(value: Sha1BackendError) -> Self {
        Self::Backend(value)
    }
}
impl From<Sha1Error> for Error {
    fn from(value: Sha1Error) -> Self {
        Self::Hash(value)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Backend(_) => "SHA-1 hardened backend failed",
            Self::Hash(_) => "SHA-1 hardened input/output rejected",
            Self::Quarantined => "SHA-1 hardened owner quarantined",
        })
    }
}
impl core::error::Error for Error {}

/// Non-authorizing route metadata. No secret message-length/work report exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// None means portable processing.
    pub backend: Option<Sha1Backend>,
    /// Irreversible owner health, not live OS capability attestation.
    pub health: Sha1BackendHealth,
}

/// Non-cloneable, thread-bound owner of hardened execution policy.
pub struct Executor {
    authority: Option<Authority>,
    revoked: Cell<bool>,
}
impl Executor {
    #[cfg(test)]
    pub(crate) fn test_authority(authority: Authority) -> Self {
        Self {
            authority: Some(authority),
            revoked: Cell::new(false),
        }
    }
    /// Keeps even target-specialized binaries on the portable implementation.
    pub const fn portable() -> Self {
        Self {
            authority: None,
            revoked: Cell::new(false),
        }
    }
    /// Takes a distinct hardened authority, never an ordinary execution owner.
    pub fn with_authority(authority: Authority) -> Result<Self, Error> {
        authority.ensure_healthy()?;
        Ok(Self {
            authority: Some(authority),
            revoked: Cell::new(false),
        })
    }
    /// Explicit static selection; complete target features are deployment duties.
    /// **No runtime feature detection or migration protection is performed.**
    /// The callback repeats a compile-time constant. CPU affinity alone is not
    /// sufficient if hotplug or VM migration can invalidate the feature bundle.
    pub fn for_compiled_target(mode: Mode) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self::portable());
        }
        match Authority::for_compiled_target() {
            Ok(authority) => Self::with_authority(authority),
            Err(Sha1BackendError::MissingFeatures) if mode == Mode::Prefer => Ok(Self::portable()),
            Err(error) => Err(error.into()),
        }
    }
    /// Permanently revokes every operation borrowing this owner.
    pub fn quarantine(&self) {
        self.revoked.set(true);
        if let Some(authority) = &self.authority {
            authority.quarantine();
        }
    }
    /// Returns metadata only, never an execution capability.
    pub fn report(&self) -> Report {
        Report {
            backend: self.authority.as_ref().map(Authority::backend),
            health: if self.revoked.get() {
                Sha1BackendHealth::Quarantined
            } else {
                self.authority
                    .as_ref()
                    .map_or(Sha1BackendHealth::Healthy, Authority::health)
            },
        }
    }
    fn ready(&self) -> Result<(), Error> {
        if self.revoked.get() {
            return Err(Error::Quarantined);
        }
        if let Some(authority) = &self.authority {
            authority.ensure_healthy()?;
        }
        Ok(())
    }
    /// Starts an affine stream borrowing this owner, without classifying secrets as public.
    pub fn start(&self) -> Result<Stream<'_>, Error> {
        self.ready()?;
        Ok(Stream::new(self))
    }
    fn compress(&self, owner: &mut crate::owner::Sha1Owner) -> Result<(), Error> {
        self.ready()?;
        match &self.authority {
            Some(authority) => authority.compress(owner).map_err(Error::from),
            None => {
                crate::compress::compress(owner);
                Ok(())
            }
        }
    }
    /// One-shot byte hashing; errors and unwinding clear the entire destination.
    pub fn hash_secret<'out>(
        &self,
        input: &[u8],
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Error> {
        let mut output = begin_output(destination)?;
        let mut state = self.start()?;
        state.update(input)?;
        state.finish(empty()?)?;
        output
            .write(&state.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
    /// One-shot canonical MSB-first bit hashing into a typed secret owner.
    pub fn hash_bits_secret<'out>(
        &self,
        input: BitString<'_>,
        destination: &'out mut [u8],
    ) -> Result<OwnedSecretRegion<'out>, Error> {
        let mut output = begin_output(destination)?;
        let mut state = self.start()?;
        state.finish(input)?;
        output
            .write(&state.owner.output_staging)
            .map_err(|_| Sha1Error::SecretMemory)?;
        output.finish().map_err(|_| Sha1Error::SecretMemory.into())
    }
    /// One-shot byte hashing with explicit public release; errors preserve output.
    pub fn hash_public(
        &self,
        input: &[u8],
        destination: &mut [u8],
        public: PublicDeclassification,
    ) -> Result<(), Error> {
        let mut state = self.start()?;
        state.update(input)?;
        state.finalize_public(destination, public)
    }
    /// One-shot bit hashing with explicit public release; errors preserve output.
    pub fn hash_bits_public(
        &self,
        input: BitString<'_>,
        destination: &mut [u8],
        public: PublicDeclassification,
    ) -> Result<(), Error> {
        self.start()?
            .finalize_bits_public(input, destination, public)
    }
}

fn empty() -> Result<BitString<'static>, Error> {
    BitString::new(&[], 0).map_err(|_| Sha1Error::MessageTooLong.into())
}
fn begin_output(destination: &mut [u8]) -> Result<SecretRegionInitialization<'_>, Error> {
    if destination.len() != 20 {
        let _ = clear_owned_region(destination);
        return Err(Sha1Error::OutputLength.into());
    }
    SecretRegionInitialization::begin(destination).map_err(|_| Sha1Error::SecretMemory.into())
}
