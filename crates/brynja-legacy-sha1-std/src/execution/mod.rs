//! Optional operational SHA-1 selection, confined to the legacy dependency graph.
//!
//! AArch64 system-wide feature APIs may authorize execution. Generic x86 CPUID
//! does not prove safety across CPU migration; use the leaf's explicit compiled
//! target route for specialized x86 binaries. No process affinity or global
//! registration is changed. SHA-1 remains collision-broken and public-only.
//!
//! ```
//! use brynja_legacy_sha1_std::execution::{select, Mode, PublicData};
//! let owner = select(Mode::Prefer)?;
//! let result = owner.hash(b"abc", PublicData::acknowledge());
//! assert_eq!(result.ok(), Some([0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,
//!     0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d]));
//! # Ok::<(), brynja_legacy_sha1_std::execution::Error>(())
//! ```

mod platform;
pub use brynja_legacy_sha1::execution::{Executor, Mode, PublicData, Stream};

/// Non-authorizing explanation for pre-execution unavailability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// Platform has no reviewed all-schedulable-CPU feature ABI for this route.
    UnsupportedPlatform,
    /// Complete SHA1/NEON feature bundle is absent.
    MissingFeatures,
}

/// Selection failure. Backend failure never authorizes portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No reviewed platform authority or complete feature bundle is available.
    Unavailable(Unavailable),
    /// Instruction startup or execution failed; do not fall back.
    Execution(brynja_legacy_sha1::execution::Error),
}

/// Observes operational availability; the result cannot create an authority.
pub fn availability() -> Result<(), Unavailable> {
    platform::availability()
}

/// Selects once, before processing input. Missing platform support may fall
/// back only in Prefer mode. Startup failure always propagates as an error.
pub fn select(mode: Mode) -> Result<Executor, Error> {
    if mode == Mode::Portable {
        return Ok(Executor::portable());
    }
    match platform::construct() {
        Ok(authority) => Executor::with_authority(authority).map_err(Error::Execution),
        Err(Error::Unavailable(_)) if mode == Mode::Prefer => Ok(Executor::portable()),
        Err(error) => Err(error),
    }
}
