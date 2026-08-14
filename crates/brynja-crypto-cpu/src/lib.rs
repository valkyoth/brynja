//! First-party `no_std` CPU acceleration for Brynja cryptography.
//!
//! This crate owns isolated SHA-256 kernels for the x86 SHA extensions and
//! AArch64 SHA2 extensions, and the RISC-V Zknh extension. Safe execution requires either complete static
//! target-feature proof or a reviewed detector's explicit runtime attestation,
//! followed by a direct startup known-answer test. It performs no runtime CPU
//! probing, allocation, I/O, global registration, or protocol work.

#![no_std]

mod sha256;
mod sha256_schedule;

#[cfg(target_arch = "aarch64")]
mod aarch64_sha2;
#[cfg(target_arch = "riscv64")]
mod riscv64_zknh;
#[cfg(target_arch = "x86_64")]
mod x86_sha;

pub use sha256::{
    Sha256Backend, Sha256BackendError, Sha256BackendHealth, Sha256BackendReport,
    Sha256BackendSession,
};

/// The Brynja milestone that admitted the first CPU kernels.
pub const BOUNDARY_MILESTONE: &str = "0.22.2";

/// Whether an accelerated SHA-256 implementation is present for supported targets.
pub const IMPLEMENTED: bool = cfg!(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
));

/// Number of complete source implementations in this release.
pub const IMPLEMENTED_BACKEND_COUNT: usize = 3;

/// Number of accelerated backend identities admitted by current native evidence.
pub const ADMITTED_BACKEND_COUNT: usize = 0;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{
        ADMITTED_BACKEND_COUNT, BOUNDARY_MILESTONE, IMPLEMENTED, IMPLEMENTED_BACKEND_COUNT,
        Sha256Backend, Sha256BackendError, Sha256BackendHealth, Sha256BackendSession,
    };

    const ABC_BLOCK: [u8; 64] = {
        let mut block = [0_u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24;
        block
    };

    #[test]
    fn boundary_reports_exact_admitted_backends() {
        assert!(::core::hint::black_box(IMPLEMENTED));
        assert_eq!(IMPLEMENTED_BACKEND_COUNT, 3);
        assert_eq!(ADMITTED_BACKEND_COUNT, 0);
        assert_eq!(BOUNDARY_MILESTONE, "0.22.2");
        assert_eq!(Sha256Backend::X86Sha.required_features(), &["sha"]);
        assert_eq!(
            Sha256Backend::Aarch64Sha2.required_features(),
            &["neon", "sha2"]
        );
        assert_eq!(
            Sha256Backend::RiscVScalarCrypto.required_features(),
            &["zknh"]
        );
        assert!(!Sha256Backend::X86Sha.is_admitted());
        assert!(!Sha256Backend::Aarch64Sha2.is_admitted());
        assert!(!Sha256Backend::RiscVScalarCrypto.is_admitted());
    }

    #[test]
    fn unsupported_architecture_is_rejected_before_instruction_use() {
        let unavailable = if cfg!(target_arch = "x86_64") {
            Sha256Backend::Aarch64Sha2
        } else if cfg!(target_arch = "aarch64") {
            Sha256Backend::RiscVScalarCrypto
        } else {
            Sha256Backend::X86Sha
        };
        assert_eq!(
            Sha256BackendSession::for_test(unavailable, false).map(|_| ()),
            Err(Sha256BackendError::WrongArchitecture)
        );
    }

    #[test]
    fn corrupted_startup_answer_is_permanently_quarantined() {
        let Some(backend) = supported_test_backend() else {
            return;
        };
        let result = Sha256BackendSession::for_test(backend, true);
        assert!(result.is_ok());
        let Ok(session) = result else {
            return;
        };
        assert_eq!(session.health(), Sha256BackendHealth::Quarantined);
        let mut state = initial_state();
        assert_eq!(
            session.compress(&mut state, &ABC_BLOCK),
            Err(Sha256BackendError::Quarantined)
        );
        assert_eq!(session.health(), Sha256BackendHealth::Quarantined);
    }

    #[test]
    fn direct_native_backend_matches_the_known_digest_state() {
        let Some(backend) = supported_test_backend() else {
            return;
        };
        let result = Sha256BackendSession::for_test(backend, false);
        assert!(result.is_ok());
        let Ok(session) = result else {
            return;
        };
        assert_eq!(session.health(), Sha256BackendHealth::Healthy);
        let mut state = initial_state();
        assert_eq!(session.compress(&mut state, &ABC_BLOCK), Ok(()));
        assert_eq!(
            state,
            [
                0xba78_16bf,
                0x8f01_cfea,
                0x4141_40de,
                0x5dae_2223,
                0xb003_61a3,
                0x9617_7a9c,
                0xb410_ff61,
                0xf200_15ad,
            ]
        );
    }

    fn supported_test_backend() -> Option<Sha256Backend> {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("sha") {
            return Some(Sha256Backend::X86Sha);
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha2")
            && std::arch::is_aarch64_feature_detected!("neon")
        {
            return Some(Sha256Backend::Aarch64Sha2);
        }
        #[cfg(all(target_arch = "riscv64", target_feature = "zknh"))]
        return Some(Sha256Backend::RiscVScalarCrypto);
        None
    }

    const fn initial_state() -> [u32; 8] {
        [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ]
    }
}
