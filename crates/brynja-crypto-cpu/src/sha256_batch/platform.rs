//! Sole authority import and instruction-entry boundary for the batch profile.
#![allow(unsafe_code)]

use super::{Authority, Error, Kernel};

impl Authority {
    /// Imports explicit platform authority and executes the startup vector KAT.
    ///
    /// # Safety
    /// Caller must guarantee the complete AVX2/OS XMM-YMM or AArch64 NEON
    /// bundle on EVERY schedulable CPU for this owner's entire lifetime,
    /// including hotplug and VM migration. The revalidator may revoke this
    /// authority, but a true callback result does not establish that guarantee.
    /// Current-core flags, cached detection, affinity or KAT alone are insufficient.
    pub unsafe fn from_platform(
        kernel: Kernel,
        revalidate: fn(Kernel) -> bool,
    ) -> Result<Self, Error> {
        Self::create(kernel, revalidate)
    }
}

pub(super) fn dispatch(
    kernel: Kernel,
    states: &mut [[u32; 8]; 8],
    blocks: &[[u8; 64]; 8],
) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::Avx2 {
        // SAFETY: The sealed owner was created under the complete static or
        // explicit platform lifetime contract; only its live session dispatches.
        return unsafe { super::x86::compress(states, blocks) };
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::Neon {
        // SAFETY: As above, the authority covers NEON on every schedulable CPU.
        return unsafe { super::arm::compress(states, blocks) };
    }
    let _ = (kernel, states, blocks);
    Err(Error::WrongArchitecture)
}
