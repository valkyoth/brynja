//! First-party `no_std` CPU acceleration for Brynja cryptography.
//!
//! This crate owns isolated SHA-2 kernels plus Keccak-f\[1600\] candidates for
//! x86_64 AVX2 and AArch64 SHA3. Execution requires complete static
//! target-feature proof or, where separately admitted, reviewed runtime
//! attestation followed by a direct startup known-answer test. It performs no
//! runtime CPU probing, allocation, I/O, global registration, or protocol work.

#![no_std]

mod keccak;
mod keccak_constants;
mod sha256;
mod sha256_schedule;
mod sha512;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
mod sha512_schedule;

#[cfg(target_arch = "aarch64")]
mod aarch64_sha2;
#[cfg(target_arch = "aarch64")]
mod aarch64_sha3_keccak;
#[cfg(target_arch = "riscv64")]
mod riscv64_zknh;
#[cfg(target_arch = "x86_64")]
mod x86_avx2_keccak;
#[cfg(target_arch = "x86_64")]
mod x86_sha;

pub use keccak::{
    KeccakBackend, KeccakBackendError, KeccakBackendHealth, KeccakBackendReport,
    KeccakBackendSession,
};
pub use sha256::{
    Sha256Backend, Sha256BackendError, Sha256BackendHealth, Sha256BackendReport,
    Sha256BackendSession,
};
pub use sha512::{
    Sha512Backend, Sha512BackendError, Sha512BackendHealth, Sha512BackendReport,
    Sha512BackendSession,
};

/// The Brynja milestone that admitted the first CPU kernels.
pub const BOUNDARY_MILESTONE: &str = "0.24.4";

/// Whether an accelerated SHA-2 implementation is present for supported targets.
pub const IMPLEMENTED: bool = cfg!(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
));

/// Number of complete source implementations in this release.
pub const IMPLEMENTED_BACKEND_COUNT: usize = 7;

/// Number of Keccak-f\[1600\] source implementations.
pub const IMPLEMENTED_KECCAK_BACKEND_COUNT: usize = 2;

/// Number of SHA-256-family source implementations.
pub const IMPLEMENTED_SHA256_BACKEND_COUNT: usize = 3;

/// Number of SHA-512-family source implementations.
pub const IMPLEMENTED_SHA512_BACKEND_COUNT: usize = 2;

/// Number of accelerated backend identities admitted by current native evidence.
pub const ADMITTED_BACKEND_COUNT: usize = 0;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{
        ADMITTED_BACKEND_COUNT, BOUNDARY_MILESTONE, IMPLEMENTED, IMPLEMENTED_BACKEND_COUNT,
        IMPLEMENTED_KECCAK_BACKEND_COUNT, IMPLEMENTED_SHA256_BACKEND_COUNT,
        IMPLEMENTED_SHA512_BACKEND_COUNT, KeccakBackend, Sha256Backend, Sha256BackendError,
        Sha256BackendHealth, Sha256BackendSession, Sha512Backend, Sha512BackendError,
        Sha512BackendHealth, Sha512BackendSession,
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
        assert_eq!(IMPLEMENTED_BACKEND_COUNT, 7);
        assert_eq!(IMPLEMENTED_KECCAK_BACKEND_COUNT, 2);
        assert_eq!(IMPLEMENTED_SHA256_BACKEND_COUNT, 3);
        assert_eq!(IMPLEMENTED_SHA512_BACKEND_COUNT, 2);
        assert_eq!(ADMITTED_BACKEND_COUNT, 0);
        assert_eq!(BOUNDARY_MILESTONE, "0.24.4");
        assert_eq!(KeccakBackend::X86Avx2.required_features(), &["avx2"]);
        assert_eq!(
            KeccakBackend::Aarch64Sha3.required_features(),
            &["neon", "sha3"]
        );
        assert!(!KeccakBackend::X86Avx2.is_admitted());
        assert!(!KeccakBackend::Aarch64Sha3.is_admitted());
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
        assert_eq!(Sha512Backend::Aarch64Sha512.as_str(), "aarch64-sha512");
        assert_eq!(
            Sha512Backend::Aarch64Sha512.required_features(),
            &["neon", "sha3"]
        );
        assert_eq!(
            Sha512Backend::RiscVScalarCrypto.required_features(),
            &["zknh"]
        );
        assert!(!Sha512Backend::Aarch64Sha512.is_admitted());
        assert!(!Sha512Backend::RiscVScalarCrypto.is_admitted());
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
    fn unsupported_sha512_architecture_is_rejected_before_instruction_use() {
        let unavailable = if cfg!(target_arch = "aarch64") {
            Sha512Backend::RiscVScalarCrypto
        } else {
            Sha512Backend::Aarch64Sha512
        };
        assert_eq!(
            Sha512BackendSession::for_test(unavailable, false).map(|_| ()),
            Err(Sha512BackendError::WrongArchitecture)
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

    #[test]
    fn corrupted_sha512_answer_is_permanently_quarantined() {
        let Some(backend) = supported_sha512_test_backend() else {
            return;
        };
        let result = Sha512BackendSession::for_test(backend, true);
        assert!(result.is_ok());
        let Ok(session) = result else {
            return;
        };
        assert_eq!(session.health(), Sha512BackendHealth::Quarantined);
        let mut state = initial_sha512_state();
        assert_eq!(
            session.compress(&mut state, &abc_sha512_block()),
            Err(Sha512BackendError::Quarantined)
        );
    }

    #[test]
    fn direct_sha512_backend_matches_the_known_digest_state() {
        let Some(backend) = supported_sha512_test_backend() else {
            return;
        };
        let result = Sha512BackendSession::for_test(backend, false);
        assert!(result.is_ok());
        let Ok(session) = result else {
            return;
        };
        assert_eq!(session.health(), Sha512BackendHealth::Healthy);
        let mut state = initial_sha512_state();
        assert_eq!(session.compress(&mut state, &abc_sha512_block()), Ok(()));
        assert_eq!(
            state,
            [
                0xddaf_35a1_9361_7aba,
                0xcc41_7349_ae20_4131,
                0x12e6_fa4e_89a9_7ea2,
                0x0a9e_eee6_4b55_d39a,
                0x2192_992a_274f_c1a8,
                0x36ba_3c23_a3fe_ebbd,
                0x454d_4423_643c_e80e,
                0x2a9a_c94f_a54c_a49f,
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
        {
            Some(Sha256Backend::RiscVScalarCrypto)
        }
        #[cfg(not(all(target_arch = "riscv64", target_feature = "zknh")))]
        {
            None
        }
    }

    fn supported_sha512_test_backend() -> Option<Sha512Backend> {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("sha3")
            && std::arch::is_aarch64_feature_detected!("neon")
        {
            return Some(Sha512Backend::Aarch64Sha512);
        }
        #[cfg(all(target_arch = "riscv64", target_feature = "zknh"))]
        {
            Some(Sha512Backend::RiscVScalarCrypto)
        }
        #[cfg(not(all(target_arch = "riscv64", target_feature = "zknh")))]
        {
            None
        }
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

    const fn initial_sha512_state() -> [u64; 8] {
        [
            0x6a09_e667_f3bc_c908,
            0xbb67_ae85_84ca_a73b,
            0x3c6e_f372_fe94_f82b,
            0xa54f_f53a_5f1d_36f1,
            0x510e_527f_ade6_82d1,
            0x9b05_688c_2b3e_6c1f,
            0x1f83_d9ab_fb41_bd6b,
            0x5be0_cd19_137e_2179,
        ]
    }

    const fn abc_sha512_block() -> [u8; 128] {
        let mut block = [0_u8; 128];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[127] = 24;
        block
    }
}
