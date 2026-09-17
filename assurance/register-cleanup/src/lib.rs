//! Source-bound normal-return register tests; full qualification is pending.
//!
//! The SHA-512 modules below are the actual private production kernel sources.
//! This fixture adds machine-level observers without changing release admission.

#![no_std]

#[cfg(target_arch = "x86_64")]
#[path = "../../../crates/brynja-crypto-cpu/src/x86_sha512/secret.rs"]
pub mod sha512;

#[cfg(target_arch = "aarch64")]
#[path = "../../../crates/brynja-crypto-cpu/src/aarch64_sha2/secret512.rs"]
pub mod arm_sha512;

// The public FIPS round constants are shared with the existing implementation;
// the test oracle's schedule and compression recurrence are independent.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
#[allow(dead_code)] // Only the existing public round constants are used here.
#[path = "../../../crates/brynja-crypto-cpu/src/sha512_schedule.rs"]
mod constants;

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests;

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_os = "linux"
))]
mod guard_pages;
