//! Source-bound normal-return register tests; full qualification is pending.
//!
//! The SHA-2 modules below are the actual private production kernel sources.
//! This fixture adds machine-level observers without changing release admission.

#![no_std]

#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    not(feature = "sha256-probe"),
    path = "../../../crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"
)]
#[cfg_attr(
    feature = "sha256-probe",
    path = "../../../crates/brynja-crypto-cpu/src/x86_sha/secret.rs"
)]
pub mod kernel;

#[cfg(target_arch = "aarch64")]
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
#[allow(dead_code)] // Only the existing public round constants are used here.
#[cfg_attr(
    not(feature = "sha256-probe"),
    path = "../../../crates/brynja-crypto-cpu/src/sha512_schedule.rs"
)]
#[cfg_attr(
    feature = "sha256-probe",
    path = "../../../crates/brynja-crypto-cpu/src/sha256_schedule.rs"
)]
mod constants;

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
#[cfg_attr(feature = "sha256-probe", path = "tests256.rs")]
mod tests;

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
mod guard_pages;
