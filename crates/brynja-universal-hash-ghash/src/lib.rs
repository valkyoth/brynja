//! Incremental GHASH over caller-framed blocks. Raw GHASH is not a MAC.
//! The hidden `__mode` interfaces are callable by any dependent when Cargo
//! enables them. They are unstable composition interfaces, not access controls.
#![no_std]
#![forbid(unsafe_code)]

// The compatibility feature makes the dependency available to evidence cfgs.
// By itself it selects no kernel and exports no CPU namespace.
#[cfg(feature = "cpu")]
use brynja_crypto_cpu as _;

#[cfg(feature = "hazmat-ghash")]
pub mod ghash;
#[cfg(all(feature = "__mode", not(feature = "hazmat-ghash")))]
mod ghash;

/// Implementation interface for Brynja modes, not a stable consumer API.
#[doc(hidden)]
#[cfg(feature = "__mode")]
pub mod __mode {
    pub use crate::ghash::{Error, Ghash, SecretHash};
    #[cfg(all(
        feature = "__mode-execution",
        target_arch = "x86_64",
        any(target_os = "linux", target_os = "windows")
    ))]
    pub use brynja_crypto_cpu::RuntimePclmul as PairMultiplier;
    #[cfg(all(
        feature = "__mode-execution",
        target_arch = "aarch64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    ))]
    pub use brynja_crypto_cpu::RuntimePmull as PairMultiplier;
    /// Borrows the already-admitted multiplier for one mode-owned frame.
    #[cfg(all(
        feature = "__mode-execution",
        any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        )
    ))]
    pub fn from_pair<'a>(
        kernel: &'a core::cell::RefCell<PairMultiplier>,
        h: &'a [u8; 16],
        work: &'a mut [u8; 16],
        budget: u64,
    ) -> Result<Ghash<'a>, Error> {
        Ghash::from_pair(kernel, h, work, budget)
    }
}
