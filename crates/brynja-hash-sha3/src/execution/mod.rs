//! Opt-in, non-erasing SHA-3/SHAKE execution for public data only.
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
//! use brynja_hash_sha3::execution::{Execution, Sha3_256};
//! let output = Sha3_256::hash(Execution::portable(), b"abc").unwrap();
//! assert_eq!(output.digest, brynja_hash_sha3::sha3_256(b"abc").unwrap());
//! ```
//! ```compile_fail,E0382
//! use brynja_hash_sha3::execution::{Execution, Shake128};
//! let mut state = Shake128::new(Execution::portable()).unwrap();
//! let _ = state.finalize_xof();
//! state.update(b"late").unwrap();
//! ```
//! ```compile_fail,E0277
//! fn send<T: Send>() {}
//! send::<brynja_hash_sha3::execution::Shake128Reader<'static>>();
//! ```
//! ```compile_fail,E0061
//! use brynja_hash_sha3::{HardenedShake128, execution::Execution};
//! let _ = HardenedShake128::new(Execution::portable());
//! ```

mod engine;
mod fixed;
mod route;
mod xof;

pub use brynja_crypto_cpu::static_execution::Kernel;
pub use fixed::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
pub use route::{Execution, Mode, Route, StaticSelection};
pub use xof::{Shake128, Shake128Reader, Shake256, Shake256Reader};

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
    /// Complete message blocks, excluding padding.
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
