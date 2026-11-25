use super::{Error, Ghash, field};
// The feature deliberately compiles on targets with no hosted detector.
#[cfg(not(any(
    any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "riscv64")
        ),
        all(target_os = "windows", target_arch = "x86_64")
    ),
    all(
        target_arch = "aarch64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    )
)))]
use brynja_crypto_cpu as _;
#[cfg(test)]
#[path = "failure_tests.rs"]
mod failure_tests;
#[cfg(all(
    any(target_os = "linux", target_os = "windows"),
    target_arch = "x86_64"
))]
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
    /// Linux/Windows x86_64 PCLMULQDQ multiplication after startup validation.
    Pclmul,
    /// Linux RV64 scalar Zbc multiplication after startup validation (not vector GHASH).
    Rv64Zbc,
    /// Little-endian Linux or macOS AArch64 PMULL after startup validation.
    Pmull,
}

pub(super) enum Engine {
    Portable,
    #[cfg(test)]
    FailAfterOne {
        first: bool,
        unwind: bool,
    },
    #[cfg(any(
        any(
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "riscv64")
            ),
            all(target_os = "windows", target_arch = "x86_64")
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
            any(
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "riscv64")
                ),
                all(target_os = "windows", target_arch = "x86_64")
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
            #[cfg(test)]
            Self::FailAfterOne { .. } => Ok(()),
            #[cfg(any(
                any(
                    all(
                        target_os = "linux",
                        any(target_arch = "x86_64", target_arch = "riscv64")
                    ),
                    all(target_os = "windows", target_arch = "x86_64")
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
            #[cfg(test)]
            Self::FailAfterOne { first, unwind } => {
                if core::mem::take(first) {
                    Ok(field::multiply(x, h))
                } else if *unwind {
                    failure_tests::interrupt();
                } else {
                    Err(Error::Quarantined)
                }
            }
            #[cfg(any(
                any(
                    all(
                        target_os = "linux",
                        any(target_arch = "x86_64", target_arch = "riscv64")
                    ),
                    all(target_os = "windows", target_arch = "x86_64")
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

// Begin only after budget admission; leave terminal on error or unwind.
pub(super) struct Pending<'b, 'a>(pub(super) &'b mut Ghash<'a>);

impl<'b, 'a> Pending<'b, 'a> {
    pub(super) fn begin(owner: &'b mut Ghash<'a>) -> Self {
        owner.terminal = true;
        Self(owner)
    }
}

impl Drop for Pending<'_, '_> {
    fn drop(&mut self) {
        if self.0.terminal {
            let _ = super::clear_owned_region(self.0.state);
            self.0.used = 0;
            self.0.remaining = 0;
        }
    }
}

impl<'a> Ghash<'a> {
    pub(super) fn check_health(&self) -> Result<(), Error> {
        if self.terminal {
            Err(Error::Quarantined)
        } else {
            self.engine.check()
        }
    }

    /// Selects a backend before touching the caller's workspace. Hosted Linux/Windows
    /// x86_64 requires PCLMULQDQ and SSE2; Linux RV64 requires scalar Zbc.
    /// Little-endian AArch64 Linux and macOS require NEON, AES and PMULL.
    /// PMULL startup checks correctness, not timing: the AWS identical-input
    /// timing observation remains inconclusive. Zbkc alone is not admitted.
    /// Native routes require a passing per-owner known-answer test and a stable
    /// ISA across the CPUs the process can use. No affinity lease is acquired:
    /// thread locality does not prevent scheduler migration. On a mixed or
    /// changing ISA without a platform guarantee, use the portable constructor.
    /// Neither mode sets Arm DIT, verifies RISC-V Zkt, or verifies Intel DOITM.
    /// Do not select a route on the assumption it provides qualified timing.
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
        #[cfg(all(
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
            ),
            any(feature = "aes-gcm-execution", feature = "gmac-execution")
        ))]
        if self.pair.is_some() {
            #[cfg(target_arch = "x86_64")]
            return Backend::Pclmul;
            #[cfg(target_arch = "aarch64")]
            return Backend::Pmull;
        }
        match self.engine {
            Engine::Portable => Backend::Portable,
            #[cfg(test)]
            Engine::FailAfterOne { .. } => unreachable!("test-only engine has no public identity"),
            #[cfg(all(
                any(target_os = "linux", target_os = "windows"),
                target_arch = "x86_64"
            ))]
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
