//! Little-endian AArch64 GHASH field multiplication; PMULL is detected separately from AES.
#![allow(unsafe_code)]

use core::arch::aarch64::vmull_p64;
use std::arch::is_aarch64_feature_detected;

#[path = "ghash_admission.rs"]
mod admission;
#[cfg(all(
    feature = "ghash-runtime-execution",
    any(target_os = "linux", target_os = "macos")
))]
#[path = "ghash_runtime.rs"]
pub(super) mod runtime;
#[cfg(brynja_ghash_pmull_evidence)]
pub use admission::RequiredProduct as RequiredPmull;

const FEATURE_COUNT: usize = 3;
fn host_features() -> [bool; FEATURE_COUNT] {
    // Rust's intrinsic requires neon,aes. Never infer PMULL from AES identity.
    [
        is_aarch64_feature_detected!("neon"),
        is_aarch64_feature_detected!("aes"),
        is_aarch64_feature_detected!("pmull") && !cfg!(brynja_ghash_deny_pmull),
    ]
}

#[target_feature(enable = "neon,aes")]
fn multiply(x: u128, h: u128) -> u128 {
    fn limbs(wire: u128) -> (u64, u64) {
        // Convert MSB-first wire coefficients into polynomial significance order.
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = wire.reverse_bits().to_le_bytes();
        (
            u64::from_le_bytes([a, b, c, d, e, f, g, h]),
            u64::from_le_bytes([i, j, k, l, m, n, o, p]),
        )
    }
    let (a, b) = limbs(x);
    let (c, d) = limbs(h);
    // Three 64x64 carry-less products reconstruct the 256-bit polynomial.
    let low = vmull_p64(a, c);
    let high = vmull_p64(b, d);
    let middle = vmull_p64(a ^ b, c ^ d) ^ low ^ high;
    let low = low ^ (middle << 64);
    let high = high ^ (middle >> 64);
    // Twice substitute x^128 = x^7 + x^2 + x + 1. The second fold fits.
    let fold = |v: u128| v ^ (v << 1) ^ (v << 2) ^ (v << 7);
    (low ^ fold(high) ^ fold((high >> 127) ^ (high >> 126) ^ (high >> 121))).reverse_bits()
}

#[test]
#[ignore = "requires an AArch64 CPU exposing PMULL"]
fn every_basis_pair_and_dense_inputs() -> Result<(), admission::Error> {
    let mut candidate = admission::Candidate::detect();
    assert_eq!(
        candidate.select(admission::Mode::Require)?,
        admission::Route::Accelerated
    );
    crate::ghash_field_cases::basis_and_dense(|x, h| candidate.product(x, h))
}

#[test]
#[ignore = "requires an AArch64 CPU exposing PMULL"]
fn nist_framed_recurrence() -> Result<(), admission::Error> {
    let mut candidate = admission::Candidate::detect();
    assert_eq!(
        candidate.select(admission::Mode::Require)?,
        admission::Route::Accelerated
    );
    crate::ghash_field_cases::framed(|x, h| candidate.product(x, h))
}
