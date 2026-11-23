//! x86 field product with independent ISA detection and startup self-test.
#![allow(unsafe_code)]

use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_xor_si128};
use core::mem::transmute;

#[path = "ghash_admission.rs"]
mod admission;
#[cfg(brynja_ghash_pclmul_evidence)]
pub use admission::RequiredProduct as RequiredPclmul;

const FEATURE_COUNT: usize = 2;

#[cfg(all(feature = "ghash-runtime-execution", target_os = "linux"))]
#[path = "ghash_runtime.rs"]
pub(super) mod runtime;
fn host_features() -> [bool; FEATURE_COUNT] {
    [
        std::is_x86_feature_detected!("pclmulqdq"),
        std::is_x86_feature_detected!("sse2"),
    ]
}

// Input and output represent a big-endian GHASH block as a number: the MSB
// is the coefficient of x^0. PCLMUL uses the opposite coefficient order.
#[target_feature(enable = "pclmulqdq,sse2")]
fn multiply(x: u128, h: u128) -> u128 {
    // SAFETY: on x86_64 these are equally sized plain bit containers with
    // every bit pattern valid. Low significance bits become the low lane.
    let (a, b) = unsafe {
        (
            transmute::<u128, __m128i>(x.reverse_bits()),
            transmute::<u128, __m128i>(h.reverse_bits()),
        )
    };
    let ll = _mm_clmulepi64_si128::<0x00>(a, b);
    let hh = _mm_clmulepi64_si128::<0x11>(a, b);
    let cross = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x01>(a, b),
        _mm_clmulepi64_si128::<0x10>(a, b),
    );
    // SAFETY: inverse bit-container conversion with the same layout as above.
    let (ll, hh, cross) = unsafe {
        (
            transmute::<__m128i, u128>(ll),
            transmute::<__m128i, u128>(hh),
            transmute::<__m128i, u128>(cross),
        )
    };
    let low = ll ^ (cross << 64);
    let high = hh ^ (cross >> 64);
    // Substitute x^128 = 1 + x + x^2 + x^7. Fold the at-most-seven
    // overflowing bits a second time; that product cannot overflow.
    let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    (low ^ high
        ^ (high << 1)
        ^ (high << 2)
        ^ (high << 7)
        ^ overflow
        ^ (overflow << 1)
        ^ (overflow << 2)
        ^ (overflow << 7))
        .reverse_bits()
}

#[cfg(test)]
mod tests {
    use super::admission::{Candidate, Error, Mode, Route};

    #[test]
    #[ignore = "native PCLMULQDQ correctness evidence"]
    fn every_basis_pair_and_dense_inputs() -> Result<(), Error> {
        let mut candidate = Candidate::detect();
        assert_eq!(candidate.select(Mode::Require)?, Route::Accelerated);
        crate::ghash_field_cases::basis_and_dense(|x, h| candidate.product(x, h))
    }

    #[test]
    #[ignore = "native PCLMULQDQ correctness evidence"]
    fn nist_framed_recurrence() -> Result<(), Error> {
        let mut candidate = Candidate::detect();
        assert_eq!(candidate.select(Mode::Prefer)?, Route::Accelerated);
        crate::ghash_field_cases::framed(|x, h| candidate.product(x, h))
    }
}
