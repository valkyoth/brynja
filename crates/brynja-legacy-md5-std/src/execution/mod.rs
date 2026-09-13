//! Optional ordinary MD5 batching, never a modern or secret-bearing service.
//!
//! Generic x86 CPUID is not a lifetime-wide platform authority. Use a binary
//! compiled for AVX2 there. Allowlisted AArch64 OS feature contracts can select
//! NEON dynamically. Neither route promises hotplug or VM-migration safety
//! when the deployment violates that contract. Defaults remain portable.

mod platform;
use brynja_legacy_md5::Md5Backend;
pub use brynja_legacy_md5::execution::{Executor, Mode, PublicData, Report};

/// Non-authorizing reason operational selection is unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// No reviewed platform feature ABI or complete compiled target bundle.
    UnsupportedPlatform,
    /// The allowlisted platform does not report the entire SIMD bundle.
    MissingFeatures,
}

/// Pre-operation selection failure, without input payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Prefer alone may fall back for unavailable platform support.
    Unavailable(Unavailable),
    /// KAT/authority failure; never permits portable fallback.
    Execution(brynja_legacy_md5::execution::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unavailable(_) => "MD5 hosted SIMD unavailable",
            Self::Execution(_) => "MD5 hosted authority failed",
        })
    }
}
impl core::error::Error for Error {}

/// Observational only; this identity cannot mint an execution authority.
pub fn availability() -> Result<Md5Backend, Unavailable> {
    platform::availability()
}

/// Selects an explicit batch policy before receiving public messages.
/// A required batch still rejects an ineligible workload, even on capable CPUs.
pub fn select(mode: Mode) -> Result<Executor, Error> {
    if mode == Mode::Portable {
        return Ok(Executor::portable());
    }
    match platform::construct() {
        Ok(authority) => Executor::with_authority(authority, mode).map_err(Error::Execution),
        Err(Error::Unavailable(_)) if mode == Mode::Prefer => Ok(Executor::portable()),
        Err(error) => Err(error),
    }
}
