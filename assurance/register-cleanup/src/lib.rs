//! Experimental normal-return register boundary. NOT a production backend.
//!
//! This fixture deliberately does not change release admission or production
//! dispatch. Its candidate must pass machine-level observers and compiler
//! checks before any production port can claim register cleanup.

#![no_std]

#[cfg(target_arch = "x86_64")]
pub mod sha512;

#[cfg(target_arch = "aarch64")]
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
