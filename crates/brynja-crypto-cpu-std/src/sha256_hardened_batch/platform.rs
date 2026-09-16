//! Private import of the complete hosted deployment contract.
#![allow(unsafe_code)]
use super::{CpuAuthority, Error, Kernel, backend};

fn available() -> Option<Kernel> {
    if Kernel::Avx2.compiled() {
        return Some(Kernel::Avx2);
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_endian = "little",
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    ))]
    if std::arch::is_aarch64_feature_detected!("neon") {
        return Some(Kernel::Neon);
    }
    None
}
fn revalidate(kernel: Kernel) -> bool {
    available() == Some(kernel)
}
pub(super) fn construct() -> Result<CpuAuthority, Error> {
    let kernel = available().ok_or(Error::Unavailable)?;
    if kernel == Kernel::Avx2 {
        return CpuAuthority::for_compiled_target(kernel).map_err(backend);
    }
    // SAFETY: Only allowlisted little-endian AArch64 OS feature ABIs plus NEON
    // reach here. A conforming OS/hypervisor preserves this advertised
    // process-wide instruction/context ABI on every schedulable CPU for the
    // authority lifetime, including hotplug and migration. Detection is cached,
    // not a live migration monitor. Generic x86 CPUID never reaches this import.
    unsafe { CpuAuthority::from_platform(kernel, revalidate) }.map_err(backend)
}
