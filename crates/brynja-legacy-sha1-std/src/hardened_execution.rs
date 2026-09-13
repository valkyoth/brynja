//! Optional hosted hardened SHA-1 for explicit legacy compatibility.
//!
//! SHA-1 is collision-broken. Cleanup is not FIPS or modern algorithm admission.
//! Availability trusts the OS/hypervisor's complete lifetime-wide feature ABI;
//! cached detection cannot establish live migration safety. Generic hosted x86
//! remains unavailable; explicitly specialized binaries can use the leaf API.
//!
//! ```
//! use brynja_legacy_sha1_std::hardened_execution::{select, Mode};
//! let executor = select(Mode::Prefer)?;
//! let mut bytes = [0; 20];
//! let output = executor.hash_secret(b"legacy secret", &mut bytes)?;
//! drop(output);
//! assert_eq!(bytes, [0; 20]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub use crate::execution::{Unavailable, availability};
pub use brynja_legacy_sha1::hardened_execution::{Executor, Mode, Stream};

/// Selection error; startup failure never authorizes fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Platform contract or complete feature bundle is absent.
    Unavailable(Unavailable),
    /// Hardened startup or owner validation failed.
    Execution(brynja_legacy_sha1::hardened_execution::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("hosted hardened SHA-1 selection failed")
    }
}
impl std::error::Error for Error {}

/// Chooses before input processing. Prefer only falls back for unavailability,
/// never for a failing KAT, revocation, invariant or execution error.
pub fn select(mode: Mode) -> Result<Executor, Error> {
    if mode == Mode::Portable {
        return Ok(Executor::portable());
    }
    match crate::execution::platform::construct_hardened() {
        Ok(authority) => Executor::with_authority(authority).map_err(Error::Execution),
        Err(Error::Unavailable(_)) if mode == Mode::Prefer => Ok(Executor::portable()),
        Err(error) => Err(error),
    }
}
