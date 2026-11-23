use super::{Error, Ghash, field};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use brynja_crypto_cpu::RuntimePclmul as Native;
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
use brynja_crypto_cpu::RuntimeRv64 as Native;

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    any(target_os = "linux", target_os = "macos")
))]
use brynja_crypto_cpu::RuntimePmull as Native;

/// Only absence of a supported CPU bundle permits portable fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Use native GHASH when available, otherwise use portable GHASH.
    Prefer,
    /// Return an error rather than use portable GHASH.
    Require,
}

/// Selected implementation, not a FIPS validation or a health certificate.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    /// Portable fixed-work multiplication.
    Portable,
    /// Linux x86_64 PCLMULQDQ multiplication after startup validation.
    Pclmul,
    /// Linux RV64 scalar Zbc multiplication after startup validation (not vector GHASH).
    Rv64Zbc,
    /// Little-endian Linux or macOS AArch64 PMULL after startup validation.
    Pmull,
}

pub(super) enum Engine {
    Portable,
    #[cfg(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "riscv64")
        ),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        )
    ))]
    Native(Native),
}

impl Engine {
    fn select(mode: Mode) -> Result<Self, Error> {
        #[cfg(any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "riscv64")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        ))]
        if let Some(kernel) = Native::probe().map_err(|_| Error::Quarantined)? {
            return Ok(Self::Native(kernel));
        }
        match mode {
            Mode::Prefer => Ok(Self::Portable),
            Mode::Require => Err(Error::Unavailable),
        }
    }

    pub(super) fn check(&self) -> Result<(), Error> {
        match self {
            Self::Portable => Ok(()),
            #[cfg(any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "riscv64")
                ),
                all(
                    target_arch = "aarch64",
                    target_endian = "little",
                    any(target_os = "linux", target_os = "macos")
                )
            ))]
            Self::Native(kernel) => {
                if kernel.ready() {
                    Ok(())
                } else {
                    Err(Error::Quarantined)
                }
            }
        }
    }

    pub(super) fn product(&mut self, x: u128, h: u128) -> Result<u128, Error> {
        match self {
            Self::Portable => Ok(field::multiply(x, h)),
            #[cfg(any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "riscv64")
                ),
                all(
                    target_arch = "aarch64",
                    target_endian = "little",
                    any(target_os = "linux", target_os = "macos")
                )
            ))]
            Self::Native(kernel) => kernel.product(x, h).map_err(|_| Error::Quarantined),
        }
    }
}

impl<'a> Ghash<'a> {
    /// Selects a backend before touching the caller's workspace. Hosted Linux
    /// x86_64 requires PCLMULQDQ and SSE2; Linux RV64 requires scalar Zbc.
    /// Little-endian AArch64 Linux and macOS require NEON, AES and PMULL.
    /// PMULL startup checks correctness, not timing: the AWS identical-input
    /// timing observation remains inconclusive. Zbkc alone is not admitted.
    /// All routes require a passing per-owner
    /// known-answer test. The thread must remain on CPUs supporting that bundle.
    /// Other targets are unavailable. Neither mode falls back after failure.
    pub fn new_with_backend(
        h: &'a [u8; 16],
        workspace: &'a mut [u8; 16],
        max_bytes: u64,
        mode: Mode,
    ) -> Result<Self, Error> {
        let engine = Engine::select(mode)?;
        let mut owner = Self::new(h, workspace, max_bytes);
        owner.engine = engine;
        Ok(owner)
    }

    /// Returns the implementation selected for this owner's entire lifetime.
    pub fn backend(&self) -> Backend {
        match self.engine {
            Engine::Portable => Backend::Portable,
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Engine::Native(_) => Backend::Pclmul,
            #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
            Engine::Native(_) => Backend::Rv64Zbc,
            #[cfg(all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            ))]
            Engine::Native(_) => Backend::Pmull,
        }
    }
}
