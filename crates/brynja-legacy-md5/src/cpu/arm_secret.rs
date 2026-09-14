//! Four independent NEON lanes; upper packed storage stays owned and clears.
#![allow(unsafe_code)]
use super::{Md5BackendError, constants::CONSTANTS, scratch::Scratch};
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn load(bytes: &[u8; 32]) -> uint32x4_t {
    // SAFETY: The 16-byte byte-aligned NEON load fits the initialized array.
    unsafe { vreinterpretq_u32_u8(vld1q_u8(bytes.as_ptr())) }
}
#[target_feature(enable = "neon")]
unsafe fn store(bytes: &mut [u8; 32], value: uint32x4_t) {
    // SAFETY: The 16-byte byte-aligned store fits the exclusive 32-byte array.
    unsafe { vst1q_u8(bytes.as_mut_ptr(), vreinterpretq_u8_u32(value)) }
}

#[target_feature(enable = "neon")]
pub(super) unsafe fn compress_secret(s: &mut Scratch) -> Result<(), Md5BackendError> {
    // SAFETY: Lifetime-wide NEON authority covers this entire call. All loads
    // and stores use live fixed owner arrays; no unowned packed arrays exist.
    // The intrinsic values do not establish complete physical register erasure.
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
                    0..=15 => vorrq_u32(vandq_u32(load(b), load(c)), vbicq_u32(load(d), load(b))),
                    16..=31 => vorrq_u32(vandq_u32(load(b), load(d)), vbicq_u32(load(c), load(d))),
                    32..=47 => veorq_u32(veorq_u32(load(b), load(c)), load(d)),
                    _ => veorq_u32(load(c), vorrq_u32(load(b), vmvnq_u32(load(d)))),
                },
            );
            store(
                sum,
                vaddq_u32(
                    vaddq_u32(load(a), load(f)),
                    vaddq_u32(load(word), vdupq_n_u32(constant)),
                ),
            );
            store(
                rotated,
                vorrq_u32(
                    vshlq_u32(load(sum), vdupq_n_s32(shift)),
                    vshlq_u32(load(sum), vdupq_n_s32(shift.saturating_sub(32))),
                ),
            );
            let [a, b, c, d] = &mut s.work;
            a.copy_from_slice(d);
            d.copy_from_slice(c);
            c.copy_from_slice(b);
            store(b, vaddq_u32(load(b), load(rotated)));
        }
        for (state, initial) in s.work.iter_mut().zip(&s.initial) {
            store(state, vaddq_u32(load(state), load(initial)));
        }
    }
    Ok(())
}
