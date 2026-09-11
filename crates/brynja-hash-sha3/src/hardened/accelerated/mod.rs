//! Explicitly selected hardened SHA-3/SHAKE/cSHAKE instruction execution.
//!
//! Callers supply a thread-bound hardened Keccak session. Default and existing
//! portable owners are unchanged. Errors during execution irreversibly clear
//! the owner; there is no silent fallback. Source-owned secret regions clear on
//! cancellation, recoverable unwind and Drop. Registers, compiler copies/spills,
//! abort, caches and platform storage remain outside the memory-erasure claim.
//!
//! This v0.24.37 candidate is still under qualification. Do not treat the new
//! paths as release-approved before cleanup evidence, pentest and native review.

mod engine;
mod fixed;
mod reader;
mod xof;

fn empty() -> Result<crate::Fips202BitString<'static>, Error> {
    crate::Fips202BitString::new(&[], 0).map_err(|_| Error::LengthOverflow)
}
pub use super::{HardenedSha3SecretOutput, Sha3PublicDeclassification};
pub use brynja_crypto_cpu::hardened_execution::KeccakSession;
pub use brynja_crypto_cpu::static_execution::Report;
pub use fixed::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use reader::Reader;
pub use xof::{Cshake128, Cshake256, Shake128, Shake256};

/// Closed hardened acceleration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Exact backend failure; never authorizes fallback.
    Backend(brynja_crypto_cpu::static_execution::Error),
    /// Owner was cancelled, failed, or used in the wrong phase.
    Terminal,
    /// Message/output accounting would overflow.
    LengthOverflow,
    /// Invalid output width or insufficient staging capacity.
    OutputLength,
    /// Mandatory secret ownership/clearing could not be established.
    SecretMemory,
    /// cSHAKE prefix encoding failed before a valid owner was returned.
    PrefixEncoding,
}

impl From<super::HardenedSha3Error> for Error {
    fn from(_: super::HardenedSha3Error) -> Self {
        Self::SecretMemory
    }
}

mod sealed {
    pub trait State {}
}
/// Sealed affine owner marker, not an independent cryptographic certification.
pub trait HardenedState: sealed::State {}

macro_rules! sealed_owner {
    ($($name:ident),+) => { $(
        impl sealed::State for $name<'_> {}
        impl HardenedState for $name<'_> {}
    )+ };
}
sealed_owner!(
    Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256, Cshake128, Cshake256, Reader
);
