//! Private platform-authority boundary. No caller-supplied feature assertions.
#![allow(unsafe_code)]

use super::{Error, Unavailable};
use brynja_legacy_sha1::{Sha1Backend, execution::Authority};

pub(super) fn availability() -> Result<(), Unavailable> {
    if !cfg!(all(
        target_arch = "aarch64",
        target_endian = "little",
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    )) {
        return Err(Unavailable::UnsupportedPlatform);
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("sha2")
    {
        return Ok(());
    }
    Err(Unavailable::MissingFeatures)
}

fn revalidate(backend: Sha1Backend) -> bool {
    backend == Sha1Backend::Aarch64Sha1 && availability().is_ok()
}

pub(super) fn construct() -> Result<Authority, Error> {
    availability().map_err(Error::Unavailable)?;
    // SAFETY: Only the allowlisted AArch64 system-wide feature APIs and complete
    // NEON/SHA2 (including SHA1) bundle pass availability. Their process ABI must
    // remain valid on every schedulable CPU, through hotplug and VM migration.
    // Generic x86 CPUID and unknown platforms cannot reach this boundary.
    // Same platform contract as the modern hosted execution adapter; no secret
    // operations are exposed by this ordinary SHA-1 adapter.
    // Revalidation retains a revocation hook, not migration/affinity proof:
    // standard-library feature detection can use cached OS capability results.
    unsafe { Authority::from_platform(Sha1Backend::Aarch64Sha1, revalidate) }
        .map_err(|error| Error::Execution(error.into()))
}

#[cfg(feature = "runtime-hardened-execution")]
pub(crate) fn construct_hardened()
-> Result<brynja_legacy_sha1::hardened_execution::Authority, crate::hardened_execution::Error> {
    use crate::hardened_execution::Error;
    availability().map_err(Error::Unavailable)?;
    // SAFETY: The same allowlisted AArch64 process-wide NEON/SHA2 contract
    // used above covers every schedulable CPU for the full owner lifetime.
    // This separate authority executes only the hardened scratch/owner kernel.
    // Cached feature detection is not live migration or feature-loss detection.
    unsafe {
        brynja_legacy_sha1::hardened_execution::Authority::from_platform(
            Sha1Backend::Aarch64Sha1,
            revalidate,
        )
    }
    .map_err(|error| Error::Execution(error.into()))
}
