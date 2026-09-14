//! Explicit hosted selection for the distinct clearing legacy MD5 SIMD profile.
//! Generic x86 stays portable; AVX2 requires complete binary specialization.
//! AArch64 uses the allowlisted OS NEON feature ABI. Cached detection is not
//! live revocation, arbitrary hotplug or VM-migration safety proof. Deployment
//! must preserve the advertised bundle on all CPUs throughout the owner lifetime.
mod platform;
pub use brynja_legacy_md5::hardened_execution::{Batch, Executor, Mode, Report};
use brynja_legacy_md5::{Md5Backend, hardened_execution};

/// Pre-operation unavailability, never a SIMD or secret-erasure capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// The platform lacks a reviewed feature ABI/complete compiled bundle.
    UnsupportedPlatform,
    /// The allowlisted platform does not advertise the required SIMD bundle.
    MissingFeatures,
}
/// Value-free selection failure; backend failure never permits fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Prefer may use portable execution only for this pre-operation condition.
    Unavailable(Unavailable),
    /// Startup/health failed; terminal, not a fallback trigger.
    Execution(hardened_execution::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unavailable(_) => "hardened MD5 platform unavailable",
            Self::Execution(_) => "hardened MD5 authority failed",
        })
    }
}
impl core::error::Error for Error {}
/// Non-authorizing platform observation. No secret input is accepted here.
pub fn availability() -> Result<Md5Backend, Unavailable> {
    platform::availability()
}
/// Explicit pre-input selection. Portable never creates instruction authority;
/// Require also rejects no-vector workloads at the consuming batch operation.
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
