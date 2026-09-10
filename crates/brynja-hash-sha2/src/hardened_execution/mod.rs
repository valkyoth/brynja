//! Explicit secret-bearing SHA-2 execution with mandatory owned-state cleanup.
//!
//! Portable by explicit selection; static/hosted acceleration is opt-in and
//! never silently replaces a failed backend. All private schedules, buffers,
//! state and vector staging clear on completion, cancellation, errors, unwind
//! and Drop. Registers, compiler copies/spills, caches, abort, `mem::forget`
//! and caller-created copies remain outside this bounded memory guarantee.
//!
//! ```
//! use brynja_hash_sha2::hardened_execution::{Execution, Sha256};
//! let mut destination = [0_u8; 32];
//! let digest = Sha256::hash_secret(Execution::portable(), b"secret input", &mut destination).unwrap();
//! assert_eq!(digest.digest.expose().len(), 32);
//! drop(digest); // clears the entire destination
//! assert_eq!(destination, [0; 32]);
//! ```
//! ```compile_fail,E0382
//! use brynja_hash_sha2::hardened_execution::{Execution, Sha256};
//! let mut hash = Sha256::new(Execution::portable()).unwrap();
//! hash.cancel();
//! hash.update(b"reuse").unwrap();
//! ```
//! ```compile_fail
//! fn cloneable<T: Clone>() {}
//! cloneable::<brynja_hash_sha2::hardened_execution::Sha256<'static>>();
//! ```
//! ```compile_fail
//! fn send<T: Send>() {}
//! send::<brynja_hash_sha2::hardened_execution::Sha256<'static>>();
//! ```

mod engine;
#[cfg(feature = "general-sha512-t")]
mod general;
mod named;
mod route;
#[cfg(test)]
mod tests;

pub use crate::PublicDeclassification;
pub use crate::execution::{Kernel, Mode, Report, Route, StaticSelection};
#[cfg(feature = "general-sha512-t")]
pub use general::{SecretOutput as GeneralSecretOutput, Sha512T};
pub use named::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
pub use route::Execution;

/// Typed failure; a backend error never authorizes portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Public message length or successful-work count exceeded its domain.
    MessageTooLong,
    /// Destination must have the exact digest width.
    OutputLength,
    /// Required secret output ownership could not be established.
    SecretMemory,
    /// This stream was invalidated by a backend failure or recoverable unwind.
    Failed,
    /// Authority, feature, kernel identity, health or generation failure.
    Backend(brynja_crypto_cpu::static_execution::Error),
}
impl From<brynja_crypto_cpu::static_execution::Error> for Error {
    fn from(error: brynja_crypto_cpu::static_execution::Error) -> Self {
        Self::Backend(error)
    }
}
impl From<brynja_core::SecretMemoryError> for Error {
    fn from(_: brynja_core::SecretMemoryError) -> Self {
        Self::SecretMemory
    }
}

/// Affine secret result. Dropping it clears its entire caller-owned destination.
pub struct SecretOutput<'a> {
    /// Explicit secret borrow; copies created by callers are their responsibility.
    pub digest: brynja_core::OwnedSecretRegion<'a>,
    /// Public route/work observation, not authority or independent verification.
    pub report: Report,
}

fn begin(
    destination: &mut [u8],
    length: usize,
) -> Result<brynja_core::SecretRegionInitialization<'_>, Error> {
    if destination.is_empty() {
        return Err(Error::OutputLength);
    }
    let actual = destination.len();
    let guard = brynja_core::SecretRegionInitialization::begin(destination)?;
    if actual != length {
        return Err(Error::OutputLength);
    }
    Ok(guard)
}
