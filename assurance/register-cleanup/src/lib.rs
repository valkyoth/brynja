//! Source-bound normal-return register tests; full qualification is pending.
//!
//! The modules below are the actual private production kernel sources.
//! This fixture adds machine-level observers without changing release admission.

#![no_std]

#[cfg(any(
    all(
        feature = "batch512-probe",
        any(
            feature = "sha256-probe",
            feature = "keccak-probe",
            feature = "batch256-probe"
        )
    ),
    all(feature = "keccak-probe", feature = "sha256-probe"),
    all(
        feature = "batch256-probe",
        any(feature = "sha256-probe", feature = "keccak-probe")
    )
))]
compile_error!("Select one kernel family per observer build");

#[cfg(all(target_arch = "x86_64", feature = "batch512-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/sha512_hardened_batch/x86/secret.rs"]
pub mod kernel;
#[cfg(all(target_arch = "aarch64", feature = "batch512-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/sha512_hardened_batch/arm/secret.rs"]
pub mod kernel;

#[cfg(all(target_arch = "x86_64", feature = "batch256-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/sha256_hardened_batch/x86/secret.rs"]
pub mod kernel;
#[cfg(all(target_arch = "aarch64", feature = "batch256-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/sha256_hardened_batch/arm/secret.rs"]
pub mod kernel;

#[cfg(all(target_arch = "x86_64", feature = "keccak-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/x86_avx2_keccak/secret.rs"]
pub mod kernel;

#[cfg(all(target_arch = "aarch64", feature = "keccak-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/aarch64_sha3_keccak/secret.rs"]
pub mod kernel;

#[cfg(all(
    target_arch = "x86_64",
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe"
    ))
))]
#[cfg_attr(
    not(feature = "sha256-probe"),
    path = "../../../crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"
)]
#[cfg_attr(
    feature = "sha256-probe",
    path = "../../../crates/brynja-crypto-cpu/src/x86_sha/secret.rs"
)]
pub mod kernel;

#[cfg(all(
    target_arch = "aarch64",
    not(any(
        feature = "keccak-probe",
        feature = "batch256-probe",
        feature = "batch512-probe"
    ))
))]
#[cfg_attr(
    not(feature = "sha256-probe"),
    path = "../../../crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"
)]
#[cfg_attr(
    feature = "sha256-probe",
    path = "../../../crates/brynja-crypto-cpu/src/aarch64_sha2/secret256.rs"
)]
pub mod kernel;

// The public FIPS round constants are shared with the existing implementation;
// the test oracle's schedule and compression recurrence are independent.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
#[cfg(not(feature = "keccak-probe"))]
#[allow(dead_code)] // Only the existing public round constants are used here.
#[cfg_attr(
    not(any(feature = "sha256-probe", feature = "batch256-probe")),
    path = "../../../crates/brynja-crypto-cpu/src/sha512_schedule.rs"
)]
#[cfg_attr(
    any(feature = "sha256-probe", feature = "batch256-probe"),
    path = "../../../crates/brynja-crypto-cpu/src/sha256_schedule.rs"
)]
mod constants;

#[cfg(all(test, feature = "keccak-probe"))]
#[path = "../../../crates/brynja-crypto-cpu/src/keccak_constants.rs"]
#[allow(dead_code)]
mod constants;

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
#[cfg_attr(feature = "sha256-probe", path = "tests256.rs")]
#[cfg_attr(feature = "keccak-probe", path = "keccak_tests.rs")]
#[cfg_attr(feature = "batch256-probe", path = "batch256_tests.rs")]
#[cfg_attr(feature = "batch512-probe", path = "batch512_tests.rs")]
mod tests;

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
mod guard_pages;
