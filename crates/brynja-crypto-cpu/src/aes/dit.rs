//! Scoped PSTATE.DIT for admitted Arm kernels, not a constant-time certification.
use super::Error;

/// Per-authority Arm data-independent-timing policy, independent of AES support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DitPolicy {
    /// Enable DIT when admitted; allow AES without it on other deployments.
    IfAvailable,
    /// Reject admission unless Arm DIT can be enabled. Never silently downgrade.
    Require,
}

pub(super) fn admit(policy: DitPolicy, available: bool) -> Result<bool, Error> {
    if policy == DitPolicy::Require && !available {
        return Err(Error::DitUnavailable);
    }
    Ok(available)
}

#[cfg(any(test, all(target_arch = "aarch64", target_endian = "little")))]
mod scoped {
    use super::Error;

    pub(super) trait Register {
        fn read(&self) -> u64;
        fn write(&self, value: u64);
    }

    pub(super) struct Scope<R: Register> {
        register: R,
        previous: u64,
    }

    impl<R: Register> Scope<R> {
        pub(super) fn enter(register: R) -> Result<Self, Error> {
            let previous = register.read();
            let guard = Self { register, previous };
            guard.register.write(1 << 24);
            if guard.register.read() & (1 << 24) == 0 {
                return Err(Error::DitUnavailable);
            }
            Ok(guard)
        }
    }

    impl<R: Register> Drop for Scope<R> {
        fn drop(&mut self) {
            self.register.write(self.previous);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    pub(super) struct Arm;

    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    #[allow(unsafe_code)]
    impl Register for Arm {
        fn read(&self) -> u64 {
            let value;
            // SAFETY: Arm is private and instantiated only after DIT admission.
            // Encoded register name supports generic Armv8 builds on both pinned
            // compilers. No nomem/readonly/pure: keep memory work within scope.
            unsafe {
                core::arch::asm!("mrs {value}, S3_3_C4_C2_5", value = out(reg) value,
                                      options(nostack, preserves_flags));
            }
            value
        }
        fn write(&self, value: u64) {
            // SAFETY: Same admission. DIT is bit 24, all other bits are RES0.
            // ISB conservatively separates state changes from the kernel body.
            unsafe {
                core::arch::asm!("msr S3_3_C4_C2_5, {value}", "isb", value = in(reg) value,
                                      options(nostack, preserves_flags));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::cell::Cell;
        struct Fake<'a>(&'a Cell<u64>, bool);
        impl Register for Fake<'_> {
            fn read(&self) -> u64 {
                self.0.get()
            }
            fn write(&self, value: u64) {
                if !self.1 {
                    self.0.set(value);
                }
            }
        }
        #[test]
        fn restores_both_prior_states_and_nested_scopes() -> Result<(), Error> {
            for previous in [0, 1 << 24] {
                let state = Cell::new(previous);
                {
                    let _outer = Scope::enter(Fake(&state, false))?;
                    assert_eq!(state.get(), 1 << 24);
                    {
                        let _inner = Scope::enter(Fake(&state, false))?;
                    }
                    assert_eq!(state.get(), 1 << 24);
                }
                assert_eq!(state.get(), previous);
            }
            Ok(())
        }
        #[test]
        fn failed_enable_is_an_error_before_work() {
            let state = Cell::new(0);
            assert!(matches!(
                Scope::enter(Fake(&state, true)),
                Err(Error::DitUnavailable)
            ));
            assert_eq!(state.get(), 0);
        }
        #[test]
        fn restores_on_error_and_unwind() {
            extern crate std;
            let state = Cell::new(0);
            let result = (|| -> Result<(), Error> {
                let _scope = Scope::enter(Fake(&state, false))?;
                Err(Error::InternalDomain)
            })();
            assert_eq!(result, Err(Error::InternalDomain));
            assert_eq!(state.get(), 0);
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), Error> {
                    let _scope = Scope::enter(Fake(&state, false))?;
                    std::panic::resume_unwind(std::boxed::Box::new(()));
                }));
            assert!(result.is_err());
            assert_eq!(state.get(), 0);
        }
    }

    #[cfg(all(
        test,
        feature = "aes-runtime-execution",
        target_arch = "aarch64",
        target_endian = "little"
    ))]
    #[test]
    #[allow(unsafe_code)]
    fn native_dit_restores_startup_expansion_blocks_and_unwind() -> Result<(), Error> {
        extern crate std;
        use crate::aes::{Authority, DitPolicy, Health, Kernel};
        if !std::arch::is_aarch64_feature_detected!("dit")
            || !std::arch::is_aarch64_feature_detected!("aes")
            || !std::arch::is_aarch64_feature_detected!("pmull")
            || !std::arch::is_aarch64_feature_detected!("neon")
            || !cfg!(any(target_os = "linux", target_os = "macos"))
        {
            std::println!("AES_DIT_NATIVE_UNAVAILABLE");
            return Ok(());
        }
        // Save the actual caller state for restoration even on test failure.
        let _original = Scope::enter(Arm)?;
        for prior in [0, 1 << 24] {
            Arm.write(prior);
            // SAFETY: OS-wide Linux/macOS feature interfaces above establish the
            // AES/PMULL/NEON and DIT bundle for this isolated synchronous test.
            let owner = unsafe {
                Authority::from_platform_with_dit(Kernel::ArmAes, DitPolicy::Require, true)
            }?;
            assert!(owner.dit_enabled());
            assert_eq!(owner.report().health, Health::Healthy);
            assert_eq!(Arm.read(), prior);
            let session = owner.session()?;
            macro_rules! width {
                ($k:literal, $s:literal, $expand:ident, $encrypt:ident, $decrypt:ident) => {{
                    let mut schedule = [0; $s];
                    let mut block = [0x5a; 16];
                    session.$expand(&[0; $k], &mut schedule)?;
                    assert_eq!(Arm.read(), prior);
                    session.$encrypt(&mut block, &schedule)?;
                    assert_eq!(Arm.read(), prior);
                    session.$decrypt(&mut block, &schedule)?;
                    assert_eq!(block, [0x5a; 16]);
                    assert_eq!(Arm.read(), prior);
                }};
            }
            width!(16, 176, expand128, encrypt128, decrypt128);
            width!(24, 208, expand192, encrypt192, decrypt192);
            width!(32, 240, expand256, encrypt256, decrypt256);
            {
                let _outer = Scope::enter(Arm)?;
                {
                    let _inner = Scope::enter(Arm)?;
                }
                assert_eq!(Arm.read(), 1 << 24);
            }
            assert_eq!(Arm.read(), prior);
            let result = std::panic::catch_unwind(|| -> Result<(), Error> {
                let _scope = Scope::enter(Arm)?;
                std::panic::resume_unwind(std::boxed::Box::new(()));
            });
            assert!(result.is_err());
            assert_eq!(Arm.read(), prior);
            owner.quarantine();
            assert!(matches!(owner.session(), Err(Error::Quarantined)));
            assert_eq!(Arm.read(), prior);
        }
        std::println!(
            "AES_DIT_NATIVE_PASS: startup all-widths expansion encrypt decrypt nested unwind quarantine prior-off prior-on"
        );
        Ok(())
    }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
pub(super) struct Guard {
    _scope: Option<scoped::Scope<scoped::Arm>>,
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[allow(unsafe_code)]
pub(super) unsafe fn enter(enabled: bool) -> Result<Guard, Error> {
    Ok(Guard {
        _scope: if enabled {
            Some(scoped::Scope::enter(scoped::Arm)?)
        } else {
            None
        },
    })
}

#[cfg(test)]
#[test]
fn policies_never_silently_downgrade_required_dit() {
    assert_eq!(admit(DitPolicy::IfAvailable, false), Ok(false));
    assert_eq!(admit(DitPolicy::IfAvailable, true), Ok(true));
    assert_eq!(admit(DitPolicy::Require, true), Ok(true));
    assert_eq!(admit(DitPolicy::Require, false), Err(Error::DitUnavailable));
}
