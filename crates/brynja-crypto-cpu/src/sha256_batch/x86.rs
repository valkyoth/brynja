//! First-party FIPS 180-4 word-parallel compression; 8 independent messages.
#![allow(unsafe_code)]
use super::Error;
use core::arch::x86_64::*;

#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn compress(
    states: &mut [[u32; 8]; 8],
    blocks: &[[u8; 64]; 8],
) -> Result<(), Error> {
    // SAFETY: The sealed caller supplies the complete CPU/OS lifetime bundle.
    // Each unaligned vector load/store touches exactly 8 initialized u32s in
    // a local fixed array. Exclusive states cannot alias immutable blocks.
    // All word/lane indices are checked; invariant failures never commit state.
    unsafe {
        macro_rules! add {
            ($a:expr, $b:expr) => {
                _mm256_add_epi32($a, $b)
            };
        }
        macro_rules! xor {
            ($a:expr, $b:expr) => {
                _mm256_xor_si256($a, $b)
            };
        }
        macro_rules! ror {
            ($a:expr, $n:literal) => {
                _mm256_or_si256(
                    _mm256_srli_epi32::<$n>($a),
                    _mm256_slli_epi32::<{ 32 - $n }>($a),
                )
            };
        }
        let mut initial = [_mm256_setzero_si256(); 8];
        for (word, value) in initial.iter_mut().enumerate() {
            let mut lanes = [0_u32; 8];
            for (out, state) in lanes.iter_mut().zip(states.iter()) {
                *out = *state.get(word).ok_or(Error::Invariant)?;
            }
            *value = _mm256_loadu_si256(lanes.as_ptr().cast());
        }
        let mut schedule = [_mm256_setzero_si256(); 64];
        for (word, value) in schedule.iter_mut().take(16).enumerate() {
            let mut lanes = [0_u32; 8];
            for (out, block) in lanes.iter_mut().zip(blocks.iter()) {
                let bytes = block.as_chunks::<4>().0.get(word).ok_or(Error::Invariant)?;
                *out = u32::from_be_bytes(*bytes);
            }
            *value = _mm256_loadu_si256(lanes.as_ptr().cast());
        }
        for t in 16_usize..64 {
            let x = *schedule
                .get(t.checked_sub(15).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?;
            let y = *schedule
                .get(t.checked_sub(2).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?;
            let s0 = xor!(xor!(ror!(x, 7), ror!(x, 18)), _mm256_srli_epi32::<3>(x));
            let s1 = xor!(xor!(ror!(y, 17), ror!(y, 19)), _mm256_srli_epi32::<10>(y));
            let w16 = *schedule
                .get(t.checked_sub(16).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?;
            let w7 = *schedule
                .get(t.checked_sub(7).ok_or(Error::Invariant)?)
                .ok_or(Error::Invariant)?;
            *schedule.get_mut(t).ok_or(Error::Invariant)? = add!(add!(w16, s0), add!(w7, s1));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = initial;
        for (word, constant) in schedule
            .into_iter()
            .zip(crate::sha256_schedule::ROUND_CONSTANTS)
        {
            let big1 = xor!(xor!(ror!(e, 6), ror!(e, 11)), ror!(e, 25));
            let choose = xor!(g, _mm256_and_si256(e, xor!(f, g)));
            let temp1 = add!(
                add!(add!(h, big1), choose),
                add!(
                    _mm256_set1_epi32(i32::from_ne_bytes(constant.to_ne_bytes())),
                    word
                )
            );
            let big0 = xor!(xor!(ror!(a, 2), ror!(a, 13)), ror!(a, 22));
            let majority = xor!(_mm256_and_si256(a, b), _mm256_and_si256(c, xor!(a, b)));
            let temp2 = add!(big0, majority);
            h = g;
            g = f;
            f = e;
            e = add!(d, temp1);
            d = c;
            c = b;
            b = a;
            a = add!(temp1, temp2);
        }
        for (word, (value, before)) in [a, b, c, d, e, f, g, h]
            .into_iter()
            .zip(initial)
            .enumerate()
        {
            let mut lanes = [0_u32; 8];
            let sum = add!(value, before);
            _mm256_storeu_si256(lanes.as_mut_ptr().cast(), sum);
            for (state, value) in states.iter_mut().zip(lanes) {
                *state.get_mut(word).ok_or(Error::Invariant)? = value;
            }
        }
        Ok(())
    }
}
