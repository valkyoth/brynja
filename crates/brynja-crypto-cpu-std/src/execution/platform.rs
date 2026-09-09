//! The only hosted permit-construction boundary; no public detector injection.
#![allow(unsafe_code)]

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use super::features::Features;
use super::{Kernel, KernelAuthority, KernelError, Unavailable};

pub(super) fn availability(kernel: Kernel) -> Result<(), Unavailable> {
    let (architecture, features) = detected(kernel);
    assess(architecture, features, system_guarantee())
}

fn assess(architecture: bool, features: bool, migration: bool) -> Result<(), Unavailable> {
    if !architecture {
        return Err(Unavailable::WrongArchitecture);
    }
    if !features {
        return Err(Unavailable::MissingFeaturesOrOsState);
    }
    if !migration {
        return Err(Unavailable::MissingMigrationGuarantee);
    }
    Ok(())
}

fn system_guarantee() -> bool {
    cfg!(all(
        target_arch = "aarch64",
        any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    ))
}

fn detected(kernel: Kernel) -> (bool, bool) {
    #[cfg(target_arch = "x86_64")]
    if matches!(kernel, Kernel::X86Sha256 | Kernel::X86Keccak) {
        let features = Features {
            sha: std::is_x86_feature_detected!("sha"),
            sse2: std::is_x86_feature_detected!("sse2"),
            avx: std::is_x86_feature_detected!("avx"),
            avx2: std::is_x86_feature_detected!("avx2"),
            ..Features::default()
        };
        return (true, features.supports(kernel));
    }
    #[cfg(target_arch = "aarch64")]
    if matches!(
        kernel,
        Kernel::ArmSha256 | Kernel::ArmSha512 | Kernel::ArmKeccak
    ) {
        let features = Features {
            neon: std::arch::is_aarch64_feature_detected!("neon"),
            sha2: std::arch::is_aarch64_feature_detected!("sha2"),
            sha3: std::arch::is_aarch64_feature_detected!("sha3"),
            ..Features::default()
        };
        return (true, features.supports(kernel));
    }
    let _ = kernel;
    (false, false)
}

pub(super) fn construct(kernel: Kernel) -> Result<KernelAuthority, KernelError> {
    // Recheck the private platform predicate at the actual permit boundary;
    // neither a diagnostic report nor choose() can authorize instructions.
    availability(kernel).map_err(|_| KernelError::MissingTargetFeatures)?;
    // SAFETY: Only the allowlisted AArch64 system-feature APIs plus the complete
    // Rust feature bundle pass availability(). Their OS ABI supplies the common
    // schedulable-CPU baseline and register-state support, including hotplug.
    // A conforming OS/hypervisor must preserve that process ABI on VM migration.
    // CPUID-only x86, unknown/BSD platforms and missing features cannot pass.
    // See docs/hosted-cpu-execution.md for the audited standard-library sources.
    unsafe { KernelAuthority::from_platform(kernel) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_missing_precondition_rejects() {
        for architecture in [false, true] {
            for features in [false, true] {
                for migration in [false, true] {
                    let result = assess(architecture, features, migration);
                    assert_eq!(result.is_ok(), architecture && features && migration);
                }
            }
        }
        assert_eq!(
            assess(true, false, true),
            Err(Unavailable::MissingFeaturesOrOsState)
        );
        // Heterogeneous masks, failed/unavailable affinity or VM guarantees do
        // not become valid merely because this CPU supports the instructions.
        assert_eq!(
            assess(true, true, false),
            Err(Unavailable::MissingMigrationGuarantee)
        );
    }

    #[test]
    fn unavailable_platform_cannot_construct_even_through_private_entry() {
        for kernel in Kernel::ALL {
            if availability(kernel).is_err() {
                assert!(matches!(
                    construct(kernel),
                    Err(KernelError::MissingTargetFeatures)
                ));
            }
        }
    }
}
