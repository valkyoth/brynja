//! Explicit hosted AES selection; never changes portable constructors.
//!
//! Only reviewed Linux/macOS AArch64 system feature interfaces authorize this
//! route. Generic x86 CPUID does not prove migration safety; use explicit static
//! execution on a target-specialized deployment instead. No affinity changes,
//! global installation, detector injection or automatic post-failure fallback.
//! Target-specialized binaries still require compatible hardware everywhere.

use brynja_crypto_cpu::aes::Authority as KernelAuthority;
pub use brynja_crypto_cpu::aes::{DitPolicy, Error as KernelError, Health, Kernel};

/// Caller preference, not a process-global setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Does not probe or execute startup instructions.
    Portable,
    /// Portable selection is allowed only before any kernel execution.
    Prefer,
    /// Missing acceleration is an error.
    Require,
}

/// Pre-execution unavailability, never an operational failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unavailable {
    /// A known architecture candidate has no native deployment admission.
    UnadmittedCandidate,
    /// Architecture or byte order differs from the requested backend.
    WrongArchitecture,
    /// Complete CPU and OS register-state bundle was not observed.
    MissingFeaturesOrOsState,
    /// No reviewed process-wide scheduling/migration guarantee.
    MissingMigrationGuarantee,
}

/// Immutable route selected before creating any key owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Caller explicitly requested portable execution.
    PortableRequested,
    /// Preferred acceleration was unavailable before startup execution.
    PortableFallback(Unavailable),
    /// Kernel authority exists; inspect live health before using it.
    Accelerated,
}

/// Value-free failure. Kernel errors never authorize a portable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Required route could not be established before execution.
    Unavailable(Unavailable),
    /// An admitted kernel failed; terminal for that owner.
    Kernel(KernelError),
}

/// Diagnostic observation only; cannot authorize instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Explicit requested backend.
    pub kernel: Kernel,
    /// Immutable selection outcome.
    pub route: Route,
    /// Current authority health, absent for portable selection.
    pub health: Option<Health>,
}

/// Thread-bound, non-cloneable hosted selection borrowing no secret material.
/// Borrow its kernel authority to construct the clearing key owners in
/// `brynja_crypto::aes::execution`. A portable result must be handled explicitly
/// with the existing portable key constructors; this adapter never copies keys.
///
/// ```
/// use brynja_crypto_cpu_std::aes::{Authority, Kernel, Mode, Route};
/// let owner = Authority::new(Kernel::ArmAes, Mode::Portable)?;
/// assert_eq!(owner.report().route, Route::PortableRequested);
/// assert!(owner.kernel_authority()?.is_none());
/// # Ok::<(), brynja_crypto_cpu_std::aes::Error>(())
/// ```
pub struct Authority {
    kernel: Kernel,
    route: Route,
    owner: Option<KernelAuthority>,
}

impl Authority {
    /// Runs startup KATs only after the private platform boundary admits the
    /// complete bundle. Failed startup returns a kernel error, never an
    /// accelerated selection or a portable fallback.
    pub fn new(kernel: Kernel, mode: Mode) -> Result<Self, Error> {
        Self::select(kernel, mode, || platform::construct(kernel))
    }

    /// Selects acceleration with an explicit Arm DIT policy. `IfAvailable`
    /// preserves normal selection semantics. `Require` rejects portable mode
    /// and disables pre-execution fallback even with `Mode::Prefer`: a request
    /// requiring DIT must never return an execution route without it.
    /// DIT scopes the expansion and block kernels, not arbitrary caller code.
    pub fn new_with_dit(kernel: Kernel, mode: Mode, policy: DitPolicy) -> Result<Self, Error> {
        let mode = dit_mode(mode, policy)?;
        Self::select(kernel, mode, || {
            platform::construct_with_dit(kernel, policy)
        })
    }

    /// Whether the selected kernel scopes expansion/block operations with DIT.
    /// False for portable selection. Does not describe the current thread bit.
    pub fn dit_enabled(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(KernelAuthority::dit_enabled)
    }

    fn select(
        kernel: Kernel,
        mode: Mode,
        construct: impl FnOnce() -> Result<KernelAuthority, Error>,
    ) -> Result<Self, Error> {
        if mode == Mode::Portable {
            return Ok(Self {
                kernel,
                route: Route::PortableRequested,
                owner: None,
            });
        }
        let (route, owner) = match construct() {
            Ok(owner) => {
                // Low-level construction retains failed owners for diagnostics.
                // A successful hosted selection must also admit a live session.
                // Failure here is operational: Prefer must not fall back.
                owner.session().map_err(Error::Kernel)?;
                (Route::Accelerated, Some(owner))
            }
            Err(Error::Unavailable(reason)) if mode == Mode::Prefer => {
                (Route::PortableFallback(reason), None)
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            kernel,
            route,
            owner,
        })
    }

    /// Returns a live diagnostic observation, not a permit or reset capability.
    pub fn report(&self) -> Report {
        Report {
            kernel: self.kernel,
            route: self.route,
            health: self.owner.as_ref().map(|owner| owner.report().health),
        }
    }

    /// `None` is an explicitly selected portable route, never a kernel failure.
    /// The borrowed owner cannot outlive this selection or be renewed by reports.
    pub fn kernel_authority(&self) -> Result<Option<&KernelAuthority>, Error> {
        if let Some(owner) = &self.owner {
            owner.session().map_err(Error::Kernel)?;
        }
        Ok(self.owner.as_ref())
    }

    /// Permanently revokes all keys/sessions borrowing this authority.
    pub fn quarantine(&self) {
        if let Some(owner) = &self.owner {
            owner.quarantine();
        }
    }
}

fn dit_mode(mode: Mode, policy: DitPolicy) -> Result<Mode, Error> {
    match (mode, policy) {
        (Mode::Portable, DitPolicy::Require) => Err(Error::Kernel(KernelError::DitUnavailable)),
        (_, DitPolicy::Require) => Ok(Mode::Require),
        _ => Ok(mode),
    }
}

mod platform {
    #![allow(unsafe_code)]
    use super::*;

    #[cfg(any(
        test,
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    ))]
    pub(super) fn assess(
        architecture: bool,
        aes: bool,
        vectors: bool,
        migration: bool,
    ) -> Result<(), Unavailable> {
        if !architecture {
            return Err(Unavailable::WrongArchitecture);
        }
        if !aes || !vectors {
            return Err(Unavailable::MissingFeaturesOrOsState);
        }
        if !migration {
            return Err(Unavailable::MissingMigrationGuarantee);
        }
        Ok(())
    }

    #[cfg(any(test, all(target_arch = "aarch64", target_endian = "little")))]
    pub(super) fn assess_arm(
        aes: bool,
        pmull: bool,
        vectors: bool,
        migration: bool,
    ) -> Result<(), Unavailable> {
        // Rust's `aes` target feature includes FEAT_PMULL. Linux std_detect
        // in both pinned compiler endpoints reports AES and PMULL separately;
        // do not infer the complete target-feature contract from AES alone.
        assess(true, aes && pmull, vectors, migration)
    }

    pub(super) fn availability(kernel: Kernel) -> Result<(), Unavailable> {
        if kernel == Kernel::RiscVScalarAes
            && cfg!(all(target_arch = "riscv64", target_endian = "little"))
        {
            // QEMU/evidence builds cannot create a production hosted route.
            return Err(Unavailable::UnadmittedCandidate);
        }
        #[cfg(target_arch = "x86_64")]
        if kernel == Kernel::X86AesNi {
            return assess(
                true,
                std::is_x86_feature_detected!("aes"),
                std::is_x86_feature_detected!("sse2"),
                false,
            );
        }
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if kernel == Kernel::ArmAes {
            return assess_arm(
                std::arch::is_aarch64_feature_detected!("aes"),
                std::arch::is_aarch64_feature_detected!("pmull"),
                std::arch::is_aarch64_feature_detected!("neon"),
                cfg!(any(target_os = "linux", target_os = "macos")),
            );
        }
        let _ = kernel;
        Err(Unavailable::WrongArchitecture)
    }

    pub(super) fn construct(kernel: Kernel) -> Result<KernelAuthority, Error> {
        construct_with_dit(kernel, DitPolicy::IfAvailable)
    }

    pub(super) fn construct_with_dit(
        kernel: Kernel,
        policy: DitPolicy,
    ) -> Result<KernelAuthority, Error> {
        availability(kernel).map_err(Error::Unavailable)?;
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        let dit_available =
            kernel == Kernel::ArmAes && std::arch::is_aarch64_feature_detected!("dit");
        #[cfg(not(all(target_arch = "aarch64", target_endian = "little")))]
        let dit_available = false;
        // SAFETY: Only little-endian Linux/macOS AArch64 with the complete Rust
        // AES/PMULL/NEON bundle passes. Linux HWCAP / Apple system sysctl interfaces
        // advertise a process-wide ISA ABI. The OS/hypervisor must preserve that
        // ABI across scheduling, hotplug and migration. CPUID-only x86 and all
        // unreviewed platforms fail closed. No public feature mask can bypass it.
        // The same system-wide feature interface admits DIT and its preserved
        // PSTATE at EL0. Absence is allowed only under IfAvailable. A failed
        // enable/readback during startup quarantines the owner, not fallback.
        unsafe { KernelAuthority::from_platform_with_dit(kernel, policy, dit_available) }
            .map_err(Error::Kernel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_dit_cannot_select_portable_or_fallback() -> Result<(), Error> {
        assert_eq!(
            dit_mode(Mode::Portable, DitPolicy::Require),
            Err(Error::Kernel(KernelError::DitUnavailable))
        );
        for mode in [Mode::Prefer, Mode::Require] {
            assert_eq!(dit_mode(mode, DitPolicy::Require), Ok(Mode::Require));
        }
        for mode in [Mode::Portable, Mode::Prefer, Mode::Require] {
            assert_eq!(dit_mode(mode, DitPolicy::IfAvailable), Ok(mode));
        }
        assert_eq!(
            Authority::new_with_dit(Kernel::ArmAes, Mode::Portable, DitPolicy::Require).err(),
            Some(Error::Kernel(KernelError::DitUnavailable))
        );
        let portable =
            Authority::new_with_dit(Kernel::ArmAes, Mode::Portable, DitPolicy::IfAvailable)?;
        assert!(!portable.dit_enabled());
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if platform::availability(Kernel::ArmAes).is_ok() {
            let detected = std::arch::is_aarch64_feature_detected!("dit");
            let optional = Authority::new(Kernel::ArmAes, Mode::Require)?;
            assert_eq!(optional.dit_enabled(), detected);
            for mode in [Mode::Prefer, Mode::Require] {
                let required = Authority::new_with_dit(Kernel::ArmAes, mode, DitPolicy::Require);
                if detected {
                    let required = required?;
                    assert!(required.dit_enabled());
                    assert_eq!(required.report().route, Route::Accelerated);
                    assert!(required.kernel_authority()?.is_some());
                } else {
                    assert_eq!(
                        required.err(),
                        Some(Error::Kernel(KernelError::DitUnavailable))
                    );
                }
            }
            if detected {
                println!("AES_DIT_HOSTED_PRESENT_PASS");
            } else {
                println!("AES_DIT_HOSTED_ABSENT_PASS");
            }
        }
        Ok(())
    }

    #[test]
    fn every_missing_precondition_fails_closed() {
        for mask in 0u8..16 {
            assert_eq!(
                platform::assess(mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0)
                    .is_ok(),
                mask == 15
            );
        }
        assert_eq!(
            platform::assess(true, true, true, false),
            Err(Unavailable::MissingMigrationGuarantee)
        );
        for mask in 0u8..16 {
            let aes = mask & 1 != 0;
            let pmull = mask & 2 != 0;
            let vectors = mask & 4 != 0;
            let migration = mask & 8 != 0;
            let expected = if !(aes && pmull && vectors) {
                Err(Unavailable::MissingFeaturesOrOsState)
            } else if !migration {
                Err(Unavailable::MissingMigrationGuarantee)
            } else {
                Ok(())
            };
            assert_eq!(
                platform::assess_arm(aes, pmull, vectors, migration),
                expected
            );
        }
    }

    #[test]
    fn portable_never_calls_detector_or_kernel() -> Result<(), Error> {
        let called = core::cell::Cell::new(false);
        let owner = Authority::select(Kernel::ArmAes, Mode::Portable, || {
            called.set(true);
            Err(Error::Kernel(KernelError::InternalDomain))
        })?;
        assert!(!called.get());
        assert_eq!(owner.report().route, Route::PortableRequested);
        assert!(owner.kernel_authority()?.is_none());
        owner.quarantine();
        assert_eq!(owner.report().health, None);
        Ok(())
    }

    #[test]
    fn fallback_only_for_pre_execution_unavailability() -> Result<(), Error> {
        for reason in [
            Unavailable::WrongArchitecture,
            Unavailable::MissingFeaturesOrOsState,
            Unavailable::MissingMigrationGuarantee,
        ] {
            let prefer = Authority::select(Kernel::ArmAes, Mode::Prefer, || {
                Err(Error::Unavailable(reason))
            })?;
            assert_eq!(prefer.report().route, Route::PortableFallback(reason));
            assert!(prefer.kernel_authority()?.is_none());
            assert_eq!(
                Authority::select(Kernel::ArmAes, Mode::Require, || Err(Error::Unavailable(
                    reason
                )))
                .err(),
                Some(Error::Unavailable(reason))
            );
        }
        Ok(())
    }

    #[test]
    fn selected_errors_never_fall_back() -> Result<(), Error> {
        for mode in [Mode::Require, Mode::Prefer] {
            for error in [
                KernelError::Quarantined,
                KernelError::InternalDomain,
                KernelError::StaleGeneration,
                KernelError::NotReady,
                KernelError::DitUnavailable,
            ] {
                assert_eq!(
                    Authority::select(Kernel::ArmAes, mode, || Err(Error::Kernel(error))).err(),
                    Some(Error::Kernel(error))
                );
            }
            assert!(
                std::panic::catch_unwind(|| Authority::select(Kernel::ArmAes, mode, || {
                    std::panic::resume_unwind(Box::new(()))
                }))
                .is_err()
            );
            for kernel in [Kernel::X86AesNi, Kernel::ArmAes] {
                // Exercise the Ok(quarantined-owner) path, not only an injected
                // Err. Baseline ARM uses real hosted admission; native static
                // builds exercise this without widening hosted x86 admission.
                let construct = || {
                    if kernel.check_compiled_target().is_ok() {
                        KernelAuthority::new(kernel).map_err(Error::Kernel)
                    } else {
                        platform::construct(kernel)
                    }
                };
                let raw = match construct() {
                    Ok(raw) => raw,
                    Err(Error::Unavailable(_)) => continue,
                    Err(error) => return Err(error),
                };
                assert_eq!(raw.report().health, Health::Healthy);
                let selected = Authority::select(kernel, mode, || Ok(raw))?;
                assert!(selected.kernel_authority()?.is_some());
                for policy in [DitPolicy::IfAvailable, DitPolicy::Require] {
                    let raw = construct()?;
                    raw.quarantine();
                    assert_eq!(raw.report().health, Health::Quarantined);
                    assert_eq!(
                        Authority::select(kernel, dit_mode(mode, policy)?, || Ok(raw)).err(),
                        Some(Error::Kernel(KernelError::Quarantined))
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn actual_platform_boundary_and_quarantine() -> Result<(), Error> {
        for kernel in [Kernel::X86AesNi, Kernel::ArmAes, Kernel::RiscVScalarAes] {
            match platform::availability(kernel) {
                Err(reason) => {
                    assert_eq!(
                        platform::construct(kernel).err(),
                        Some(Error::Unavailable(reason))
                    );
                    assert_eq!(
                        Authority::new(kernel, Mode::Require).err(),
                        Some(Error::Unavailable(reason))
                    );
                }
                Ok(()) => {
                    for mode in [Mode::Require, Mode::Prefer] {
                        let owner = Authority::new(kernel, mode)?;
                        assert_eq!(owner.report().health, Some(Health::Healthy));
                        let raw = owner
                            .kernel_authority()?
                            .ok_or(Error::Kernel(KernelError::NotReady))?;
                        let session = raw.session().map_err(Error::Kernel)?;
                        owner.quarantine();
                        assert_eq!(session.check(), Err(KernelError::Quarantined));
                        assert_eq!(
                            owner.kernel_authority().err(),
                            Some(Error::Kernel(KernelError::Quarantined))
                        );
                        assert_eq!(owner.report().route, Route::Accelerated);
                    }
                }
            }
        }
        Ok(())
    }
}
