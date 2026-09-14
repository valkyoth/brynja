//! Eight independent lanes; no ordinary SIMD scratch or raw-session API.
#![allow(unsafe_code)]
use super::{Md5BackendError, constants::CONSTANTS, scratch::Scratch};
use core::arch::x86_64::*;

#[target_feature(enable = "avx2")]
unsafe fn load(bytes: &[u8; 32]) -> __m256i {
    // SAFETY: The exact initialized array supplies the entire unaligned load.
    unsafe { _mm256_loadu_si256(bytes.as_ptr().cast()) }
}
#[target_feature(enable = "avx2")]
unsafe fn store(bytes: &mut [u8; 32], value: __m256i) {
    // SAFETY: The exact exclusive array supplies the entire unaligned store.
    unsafe { _mm256_storeu_si256(bytes.as_mut_ptr().cast(), value) }
}

#[target_feature(enable = "avx2")]
pub(super) unsafe fn compress_secret(s: &mut Scratch) -> Result<(), Md5BackendError> {
    // SAFETY: The caller's lifetime-wide authority covers AVX2 and OS YMM
    // context. Every load/store borrows a fixed live array within clearing s.
    // Intrinsic values/compiler copies retain documented register/spill limits.
    unsafe {
        for (destination, initial) in s.work.iter_mut().zip(&s.initial) {
            destination.copy_from_slice(initial);
        }
        for (round, constant) in CONSTANTS.into_iter().enumerate() {
            let [a, b, c, d] = &s.work;
            let (index, shift) = super::scratch::round(round)?;
            let word = s.words.get(index).ok_or(Md5BackendError::Quarantined)?;
            let [f, sum, rotated] = &mut s.temporary;
            store(
                f,
                match round {
                    0..=15 => _mm256_or_si256(
                        _mm256_and_si256(load(b), load(c)),
                        _mm256_andnot_si256(load(b), load(d)),
                    ),
                    16..=31 => _mm256_or_si256(
                        _mm256_and_si256(load(b), load(d)),
                        _mm256_andnot_si256(load(d), load(c)),
                    ),
                    32..=47 => _mm256_xor_si256(_mm256_xor_si256(load(b), load(c)), load(d)),
                    _ => _mm256_xor_si256(
                        load(c),
                        _mm256_or_si256(load(b), _mm256_xor_si256(load(d), _mm256_set1_epi32(-1))),
                    ),
                },
            );
            store(
                sum,
                _mm256_add_epi32(
                    _mm256_add_epi32(load(a), load(f)),
                    _mm256_add_epi32(
                        load(word),
                        _mm256_set1_epi32(i32::from_ne_bytes(constant.to_ne_bytes())),
                    ),
                ),
            );
            store(
                rotated,
                _mm256_or_si256(
                    _mm256_sllv_epi32(load(sum), _mm256_set1_epi32(shift)),
                    _mm256_srlv_epi32(load(sum), _mm256_set1_epi32(32_i32.saturating_sub(shift))),
                ),
            );
            let [a, b, c, d] = &mut s.work;
            a.copy_from_slice(d);
            d.copy_from_slice(c);
            c.copy_from_slice(b);
            store(b, _mm256_add_epi32(load(b), load(rotated)));
        }
        for (state, initial) in s.work.iter_mut().zip(&s.initial) {
            store(state, _mm256_add_epi32(load(state), load(initial)));
        }
    }
    Ok(())
}
