#![allow(unsafe_code)]

use super::constants::CONSTANTS;
use core::arch::x86_64::*;

/// Eight independent public-data compression blocks; complete AVX2 contract.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn compress(states: &mut [[u32; 4]; 8], blocks: &[[u8; 64]; 8]) {
    // SAFETY: Every load/store is exactly eight initialized u32s in a local
    // fixed array, unaligned intrinsics impose no stronger alignment. Exclusive
    // states cannot alias immutable blocks. The session covers AVX2 and OS YMM
    // support for the complete call, including migration between instructions.
    unsafe {
        let mut initial = [_mm256_setzero_si256(); 4];
        for (word, destination) in initial.iter_mut().enumerate() {
            let lane: [u32; 8] = core::array::from_fn(|i| {
                states
                    .get(i)
                    .and_then(|state| state.get(word))
                    .copied()
                    .unwrap_or(0)
            });
            *destination = _mm256_loadu_si256(lane.as_ptr().cast());
        }
        let mut words = [_mm256_setzero_si256(); 16];
        for (word, destination) in words.iter_mut().enumerate() {
            let lane = core::array::from_fn::<_, 8, _>(|i| {
                blocks
                    .get(i)
                    .and_then(|block| block.as_chunks::<4>().0.get(word))
                    .map(|bytes| u32::from_le_bytes(*bytes))
                    .unwrap_or(0)
            });
            *destination = _mm256_loadu_si256(lane.as_ptr().cast());
        }
        let [mut a, mut b, mut c, mut d] = initial;
        let ones = _mm256_set1_epi32(-1);
        for (round, constant) in CONSTANTS.into_iter().enumerate() {
            let (f, index, shifts) = match round {
                0..=15 => (
                    _mm256_or_si256(_mm256_and_si256(b, c), _mm256_andnot_si256(b, d)),
                    round,
                    [7, 12, 17, 22],
                ),
                16..=31 => (
                    _mm256_or_si256(_mm256_and_si256(b, d), _mm256_andnot_si256(d, c)),
                    (round.saturating_mul(5).saturating_add(1)) % 16,
                    [5, 9, 14, 20],
                ),
                32..=47 => (
                    _mm256_xor_si256(_mm256_xor_si256(b, c), d),
                    (round.saturating_mul(3).saturating_add(5)) % 16,
                    [4, 11, 16, 23],
                ),
                _ => (
                    _mm256_xor_si256(c, _mm256_or_si256(b, _mm256_xor_si256(d, ones))),
                    round.saturating_mul(7) % 16,
                    [6, 10, 15, 21],
                ),
            };
            let sum = _mm256_add_epi32(
                _mm256_add_epi32(a, f),
                _mm256_add_epi32(
                    words.get(index).copied().unwrap_or(_mm256_setzero_si256()),
                    _mm256_set1_epi32(i32::from_ne_bytes(constant.to_ne_bytes())),
                ),
            );
            let shift = shifts.get(round % 4).copied().unwrap_or(0_i32);
            let rotated = _mm256_or_si256(
                _mm256_sllv_epi32(sum, _mm256_set1_epi32(shift)),
                _mm256_srlv_epi32(sum, _mm256_set1_epi32(32_i32.saturating_sub(shift))),
            );
            a = d;
            d = c;
            c = b;
            b = _mm256_add_epi32(b, rotated);
        }
        for (word, (value, initial)) in [a, b, c, d].into_iter().zip(initial).enumerate() {
            let mut lane = [0_u32; 8];
            _mm256_storeu_si256(lane.as_mut_ptr().cast(), _mm256_add_epi32(value, initial));
            for (state, value) in states.iter_mut().zip(lane) {
                if let Some(destination) = state.get_mut(word) {
                    *destination = value;
                }
            }
        }
    }
}
