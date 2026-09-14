//! Private platform boundary for distinct hardened ownership.
#![allow(unsafe_code)]
use super::{Error, Unavailable};
use brynja_legacy_md5::{Md5Backend, hardened_execution::Authority};

pub(super) fn availability() -> Result<Md5Backend, Unavailable> {
    if cfg!(all(target_arch = "x86_64", target_feature = "avx2")) {
        return Ok(Md5Backend::X86Avx2);
    }
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
    if std::arch::is_aarch64_feature_detected!("neon") {
        return Ok(Md5Backend::Aarch64Neon);
    }
    Err(Unavailable::MissingFeatures)
}
fn revalidate(backend: Md5Backend) -> bool {
    backend == Md5Backend::Aarch64Neon && availability() == Ok(backend)
}
pub(super) fn construct() -> Result<Authority, Error> {
    let backend = availability().map_err(Error::Unavailable)?;
    if backend == Md5Backend::X86Avx2 {
        return Authority::for_compiled_target().map_err(|e| Error::Execution(e.into()));
    }
    // SAFETY: Only allowlisted little-endian AArch64 platform-wide NEON ABI
    // reaches this boundary. The deployment must preserve that process bundle
    // on every schedulable CPU, including hotplug and migration. The cached
    // std detector is not a live CPU-migration monitor or proof of hypervisor
    // correctness. Generic x86 observations never authorize this constructor.
    unsafe { Authority::from_platform(backend, revalidate) }.map_err(|e| Error::Execution(e.into()))
}
