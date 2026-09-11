//! Opt-in, non-erasing SHA-3/SHAKE/cSHAKE execution for public data only.
//!
//! The default APIs stay portable. Every permutation, including suffix/padding
//! and incremental squeeze, uses one retained route. No failure-driven fallback.
//! AVX2 is a vectorized single-state permutation, not multi-message hashing.
//!
//! Readers offer bounded convenience output and arbitrary-sized output with
//! caller-provided scratch. Scratch permits transactional output without heap
//! allocation or replaying kernels: errors preserve the destination and reader.
//! Scratch itself may be modified on failure; it must contain public data only.
//!
//! ```
//! use brynja_hash_sha3::execution::{Execution, Public, Sha3_256};
//! let output = Sha3_256::hash(Execution::portable(), Public::new(b"abc")).unwrap();
//! assert_eq!(output.digest, brynja_hash_sha3::sha3_256(b"abc").unwrap());
//! ```
//! ```compile_fail,E0382
//! use brynja_hash_sha3::execution::{Execution, Public, Shake128};
//! let mut state = Shake128::new(Execution::portable()).unwrap();
//! let _ = state.finalize_xof();
//! state.update(Public::new(b"late")).unwrap();
//! ```
//! ```compile_fail,E0277
//! fn send<T: Send>() {}
//! send::<brynja_hash_sha3::execution::Shake128Reader<'static>>();
//! ```
//! ```compile_fail,E0061
//! use brynja_hash_sha3::{HardenedShake128, execution::Execution};
//! let _ = HardenedShake128::new(Execution::portable());
//! ```

mod cshake;
mod engine;
mod fixed;
mod route;
mod xof;

pub use brynja_crypto_cpu::static_execution::Kernel;
pub use cshake::{Cshake128, Cshake128Reader, Cshake256, Cshake256Reader};
pub use fixed::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use route::{Execution, Mode, Route, StaticSelection};
pub use xof::{Shake128, Shake128Reader, Shake256, Shake256Reader};

/// Explicit caller classification of bytes as public, non-secret-derived data.
/// This marker cannot inspect or prove secrecy. Never wrap keys, passwords,
/// MAC/KDF intermediates or other confidential material; use hardened APIs.
/// No implicit conversion is provided, so every input call site is explicit.
#[derive(Clone, Copy)]
pub struct Public<'a>(&'a [u8]);

impl<'a> Public<'a> {
    /// Asserts that these bytes may enter a non-erasing ordinary state.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

/// Explicit public-data classification of an already validated FIPS 202 bit string.
/// Canonical bit encoding does not imply public data: the caller must classify it.
/// Like [`Public`], this is an assertion, not automatic secrecy enforcement.
#[derive(Clone, Copy)]
pub struct PublicBits<'a>(crate::Fips202BitString<'a>);

impl<'a> PublicBits<'a> {
    /// Asserts that all valid bits may enter a non-erasing ordinary state.
    #[must_use]
    pub const fn new(bits: crate::Fips202BitString<'a>) -> Self {
        Self(bits)
    }
}

/// Maximum bytes accepted by a reader's stack-scratch convenience method.
/// Use `squeeze_with_scratch` for larger single transactional requests.
pub const INLINE_OUTPUT_BYTES: usize = 168;

/// Typed ordinary execution failure. No error authorizes portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Public message, output or successful-work accounting would overflow.
    LengthOverflow,
    /// Supplied scratch is shorter than the requested destination.
    ScratchTooSmall,
    /// Kernel selection, startup, quarantine or operation failed.
    Backend(brynja_crypto_cpu::static_execution::Error),
}

impl From<brynja_crypto_cpu::static_execution::Error> for Error {
    fn from(error: brynja_crypto_cpu::static_execution::Error) -> Self {
        Self::Backend(error)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SHA-3 execution failure: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Successful actual permutation counts; no validation or certification claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Immutable selected route.
    pub route: Route,
    /// Complete absorbed blocks, including cSHAKE setup but excluding final padding.
    pub absorb_permutations: u128,
    /// Final suffix and pad10*1 permutations.
    pub padding_permutations: u128,
    /// Additional squeeze permutations beyond the initial padded block.
    pub squeeze_permutations: u128,
}

impl Report {
    fn new(route: Route) -> Self {
        Self {
            route,
            absorb_permutations: 0,
            padding_permutations: 0,
            squeeze_permutations: 0,
        }
    }
}

/// Exact public digest identity and actual successful route/work observation.
pub struct Output<D> {
    /// Public non-erasing digest, not a secret owner or MAC.
    pub digest: D,
    /// Successful work performed on the selected route.
    pub report: Report,
}
