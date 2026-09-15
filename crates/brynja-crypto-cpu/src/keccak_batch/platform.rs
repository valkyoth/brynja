//! Explicit platform proof and instruction-entry boundary.
#![allow(unsafe_code)]
use super::{Authority, Error, Kernel};

impl Authority {
    /// Imports an external no_std platform provider's feature proof.
    /// Intentionally public for providers in other crates; use the safe compiled
    /// constructor or hosted adapter unless providing that proof yourself.
    ///
    /// # Safety
    /// AVX2 requires AVX/AVX2 and OS-enabled XMM/YMM save/restore. NEON requires
    /// AArch64 ASIMD. All scheduled CPUs must retain the bundle for this owner's
    /// entire lifetime, including hotplug and VM migration. The callback must
    /// be sound for that deployment; returning true alone proves nothing.
    /// Establish the lifetime-wide CPU/OS guarantee before this call; a check
    /// immediately before dispatch cannot prevent intervening migration.
    /// CPU affinity may constrain scheduling but does not prove VM-host support.
    /// If this cannot be guaranteed, use portable execution instead.
    pub unsafe fn from_platform(
        kernel: Kernel,
        revalidate: fn(Kernel) -> bool,
    ) -> Result<Self, Error> {
        Self::create(kernel, revalidate)
    }
}

pub(super) fn dispatch(kernel: Kernel, states: &mut [[u64; 25]; 4]) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::Avx2 {
        // SAFETY: Sealed authority supplies the CPU/OS lifetime contract;
        // fixed-size exclusively borrowed initialized states meet kernel bounds.
        return unsafe { super::x86::permute(states) };
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::Neon {
        // SAFETY: Same sealed authority contract, for AArch64 ASIMD.
        return unsafe { super::arm::permute(states) };
    }
    let _ = (kernel, states);
    Err(Error::WrongArchitecture)
}
