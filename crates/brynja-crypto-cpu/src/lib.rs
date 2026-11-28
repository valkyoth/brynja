//! First-party `no_std` CPU acceleration for Brynja cryptography.
//!
//! This crate owns isolated SHA-2 kernels plus Keccak-f\[1600\] candidates for
//! x86_64 AVX2 and AArch64 SHA3. Execution requires complete static
//! target-feature proof or, where separately admitted, reviewed runtime
//! attestation followed by a direct startup known-answer test. It performs no
//! implicit backend selection, allocation, global registration, or protocol work.
//! Explicit hosted GHASH probing uses platform feature discovery on Linux
//! x86_64/RV64 and little-endian Linux/macOS AArch64 (which may query the OS).

#![no_std]

#[cfg(all(feature = "poly1305-avx2", target_arch = "x86_64", target_os = "linux"))]
pub mod poly1305_avx2;

#[cfg(all(
    feature = "chacha20-sse2",
    target_arch = "x86_64",
    target_feature = "sse2"
))]
pub mod chacha20_sse2;

#[cfg(all(
    feature = "chacha20-neon",
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
pub mod chacha20_neon;

#[cfg(feature = "aes-static-execution")]
pub mod aes;

#[cfg(feature = "sha256-hardened-batch")]
pub mod sha256_hardened_batch;

#[cfg(feature = "sha512-hardened-batch")]
pub mod sha512_hardened_batch;

#[cfg(feature = "sha512-batch")]
pub mod sha512_batch;

#[cfg(feature = "keccak-batch")]
pub mod keccak_batch;

#[cfg(feature = "keccak-hardened-batch")]
pub mod keccak_hardened_batch;

#[cfg(feature = "sha256-batch")]
pub mod sha256_batch;

#[cfg(feature = "static-execution")]
pub mod static_execution;

#[cfg(feature = "runtime-execution")]
pub mod runtime_execution;

#[cfg(feature = "hardened-execution")]
pub mod hardened_execution;

mod keccak;
mod keccak_constants;
mod sha256;
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
mod sha256_schedule;
mod sha512;
#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    all(
        target_arch = "x86_64",
        any(feature = "static-execution", feature = "sha512-hardened-batch")
    )
))]
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
#[cfg(all(target_arch = "x86_64", feature = "static-execution"))]
mod x86_sha512;

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

/// Number of implementations in the historical candidate-backend APIs.
/// Does not count the separate opt-in execution or independent-message batch
/// APIs; see `static_execution::Kernel::ALL` when that feature is enabled.
pub const IMPLEMENTED_BACKEND_COUNT: usize = 7;

/// Number of Keccak-f\[1600\] source implementations.
pub const IMPLEMENTED_KECCAK_BACKEND_COUNT: usize = 2;

/// Number of SHA-256-family source implementations.
pub const IMPLEMENTED_SHA256_BACKEND_COUNT: usize = 3;

/// Number of SHA-512 implementations in the historical candidate API.
/// Dedicated x86 SHA-512 is available through the separate execution API.
pub const IMPLEMENTED_SHA512_BACKEND_COUNT: usize = 2;

/// Number of accelerated backend identities admitted by current native evidence.
pub const ADMITTED_BACKEND_COUNT: usize = 0;

#[cfg(any(
    test,
    all(feature = "poly1305-avx2", target_arch = "x86_64", target_os = "linux"),
    all(
        feature = "ghash-runtime-execution",
        target_arch = "aarch64",
        target_endian = "little",
        any(target_os = "linux", target_os = "macos")
    ),
    all(
        feature = "ghash-runtime-execution",
        any(
            target_os = "linux",
            all(target_os = "windows", target_arch = "x86_64")
        ),
        any(target_arch = "x86_64", target_arch = "riscv64")
    ),
    all(brynja_ghash_pclmul_evidence, target_arch = "x86_64"),
    all(
        brynja_ghash_rv64_evidence,
        target_arch = "riscv64",
        target_os = "linux"
    ),
    all(
        brynja_ghash_pmull_evidence,
        target_arch = "aarch64",
        target_endian = "little"
    )
))]
extern crate std;

#[cfg(all(
    any(
        test,
        brynja_ghash_pclmul_evidence,
        all(
            feature = "ghash-runtime-execution",
            any(target_os = "linux", target_os = "windows")
        )
    ),
    target_arch = "x86_64"
))]
mod ghash_pclmul;

#[cfg(all(
    feature = "ghash-runtime-execution",
    any(target_os = "linux", target_os = "windows"),
    target_arch = "x86_64"
))]
#[doc(hidden)]
pub use ghash_pclmul::runtime::{
    Quarantined as PclmulQuarantined, RuntimeProduct as RuntimePclmul,
};

#[doc(hidden)]
pub mod facade_api;

#[cfg(all(
    any(
        test,
        brynja_ghash_pmull_evidence,
        all(
            feature = "ghash-runtime-execution",
            any(target_os = "linux", target_os = "macos")
        )
    ),
    target_arch = "aarch64",
    target_endian = "little"
))]
mod ghash_pmull;

#[cfg(all(
    feature = "ghash-runtime-execution",
    target_arch = "aarch64",
    target_endian = "little",
    any(target_os = "linux", target_os = "macos")
))]
#[doc(hidden)]
pub use ghash_pmull::runtime::{Quarantined as PmullQuarantined, RuntimeProduct as RuntimePmull};

#[cfg(all(
    any(test, brynja_ghash_rv64_evidence, feature = "ghash-runtime-execution"),
    target_arch = "riscv64",
    target_os = "linux"
))]
mod ghash_rv64;

#[cfg(all(
    feature = "ghash-runtime-execution",
    target_os = "linux",
    target_arch = "riscv64"
))]
#[doc(hidden)]
pub use ghash_rv64::runtime::{Quarantined as Rv64Quarantined, RuntimeProduct as RuntimeRv64};

#[cfg(all(
    brynja_ghash_rv64_evidence,
    target_arch = "riscv64",
    target_os = "linux"
))]
#[doc(hidden)]
pub use ghash_rv64::RequiredRv64;

#[cfg(all(
    brynja_ghash_pmull_evidence,
    target_arch = "aarch64",
    target_endian = "little"
))]
#[doc(hidden)]
pub use ghash_pmull::RequiredPmull;

#[cfg(all(
    test,
    any(
        target_arch = "x86_64",
        all(target_arch = "riscv64", target_os = "linux"),
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod ghash_field_cases;

#[cfg(all(brynja_ghash_pclmul_evidence, target_arch = "x86_64"))]
#[doc(hidden)]
pub use ghash_pclmul::RequiredPclmul;

#[cfg(test)]
mod tests;
