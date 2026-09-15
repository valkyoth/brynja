//! Explicit platform import and isolated hardened instruction entry.
#![allow(unsafe_code)]
use super::{Authority, Error, Kernel, Workspace};

impl Authority {
    /// Imports platform authority, then runs the actual clearing-kernel KAT.
    /// Intentionally public for external hosted and no_std platform providers.
    ///
    /// # Safety
    /// Guarantee AVX2 plus OS XMM/YMM context, or little-endian AArch64 NEON,
    /// on EVERY schedulable CPU throughout this owner's lifetime, including
    /// hotplug and VM migration. Establish that deployment guarantee before
    /// construction. Revalidation can revoke; it is not a scheduler lock or a
    /// live migration monitor. Affinity and a successful KAT are insufficient.
    pub unsafe fn from_platform(
        kernel: Kernel,
        revalidate: fn(Kernel) -> bool,
    ) -> Result<Self, Error> {
        Self::create(kernel, revalidate)
    }
}
pub(super) fn dispatch(kernel: Kernel, workspace: &mut Workspace) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::Avx2 {
        // SAFETY: Only the private, live authority path dispatches, after
        // revalidation. Its lifetime-wide contract covers AVX2 and OS YMM.
        return unsafe { super::x86::compress_secret(workspace) };
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    if kernel == Kernel::Neon {
        // SAFETY: As above, the lifetime-wide authority covers NEON and endian.
        return unsafe { super::arm::compress_secret(workspace) };
    }
    let _ = (kernel, workspace);
    Err(Error::WrongArchitecture)
}
