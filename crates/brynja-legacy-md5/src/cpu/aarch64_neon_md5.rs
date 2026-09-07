#![allow(unsafe_code)]

use super::constants::CONSTANTS;
use core::arch::aarch64::*;

/// Four independent public-data compression blocks; upper four slots untouched.
#[target_feature(enable = "neon")]
pub(super) unsafe fn compress(states: &mut [[u32; 4]; 8], blocks: &[[u8; 64]; 8]) {
    // SAFETY: Each NEON load/store spans exactly four initialized u32s in a
    // fixed local array with u32 alignment. Exclusive states cannot alias the
    // immutable blocks. The session covers NEON for the entire call including
    // CPU migration. Indices are bounded public round/word/lane positions.
    unsafe {
        let mut initial = [vdupq_n_u32(0); 4];
        for (word, destination) in initial.iter_mut().enumerate() {
            let lane: [u32; 4] = core::array::from_fn(|i| {
                states
                    .get(i)
                    .and_then(|state| state.get(word))
                    .copied()
                    .unwrap_or(0)
            });
            *destination = vld1q_u32(lane.as_ptr());
        }
        let mut words = [vdupq_n_u32(0); 16];
        for (word, destination) in words.iter_mut().enumerate() {
            let lane = core::array::from_fn::<_, 4, _>(|i| {
                blocks
                    .get(i)
                    .and_then(|block| block.as_chunks::<4>().0.get(word))
                    .map(|bytes| u32::from_le_bytes(*bytes))
                    .unwrap_or(0)
            });
            *destination = vld1q_u32(lane.as_ptr());
        }
        let [mut a, mut b, mut c, mut d] = initial;
        for (round, constant) in CONSTANTS.into_iter().enumerate() {
            let (f, index, shifts) = match round {
                0..=15 => (
                    vorrq_u32(vandq_u32(b, c), vbicq_u32(d, b)),
                    round,
                    [7, 12, 17, 22],
                ),
                16..=31 => (
                    vorrq_u32(vandq_u32(b, d), vbicq_u32(c, d)),
                    (round.saturating_mul(5).saturating_add(1)) % 16,
                    [5, 9, 14, 20],
                ),
                32..=47 => (
                    veorq_u32(veorq_u32(b, c), d),
                    (round.saturating_mul(3).saturating_add(5)) % 16,
                    [4, 11, 16, 23],
                ),
                _ => (
                    veorq_u32(c, vorrq_u32(b, vmvnq_u32(d))),
                    round.saturating_mul(7) % 16,
                    [6, 10, 15, 21],
                ),
            };
            let sum = vaddq_u32(
                vaddq_u32(a, f),
                vaddq_u32(
                    words.get(index).copied().unwrap_or(vdupq_n_u32(0)),
                    vdupq_n_u32(constant),
                ),
            );
            let shift = shifts.get(round % 4).copied().unwrap_or(0_i32);
            let rotated = vorrq_u32(
                vshlq_u32(sum, vdupq_n_s32(shift)),
                vshlq_u32(sum, vdupq_n_s32(shift.saturating_sub(32))),
            );
            a = d;
            d = c;
            c = b;
            b = vaddq_u32(b, rotated);
        }
        for (word, (value, initial)) in [a, b, c, d].into_iter().zip(initial).enumerate() {
            let mut lane = [0_u32; 4];
            vst1q_u32(lane.as_mut_ptr(), vaddq_u32(value, initial));
            for (state, value) in states.iter_mut().zip(lane) {
                if let Some(destination) = state.get_mut(word) {
                    *destination = value;
                }
            }
        }
    }
}
