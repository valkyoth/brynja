//! Private reviewed platform import; no public injectable detector.
#![allow(unsafe_code)]
use super::{CpuAuthority, Error, Kernel, backend};

fn available() -> Option<Kernel> {
    if Kernel::Avx2.compiled() {
        return Some(Kernel::Avx2);
    }
    #[cfg(all(
        target_arch = "aarch64",
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
    // SAFETY: Only allowlisted AArch64 OS feature ABIs plus NEON reach here.
    // A conforming OS/hypervisor must preserve its advertised process-wide ABI
    // on every schedulable CPU across hotplug and migration. Cached detection
    // is not fresh revocation evidence. Generic x86 CPUID cannot reach this path.
    unsafe { CpuAuthority::from_platform(kernel, revalidate) }.map_err(backend)
}
