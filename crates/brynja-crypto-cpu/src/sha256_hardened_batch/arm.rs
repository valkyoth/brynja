//! Four clearing SHA-256 lanes; unused packed capacity remains owned.
#![allow(unsafe_code)]
use super::{Error, Workspace};
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn load(bytes: &[u8; 32]) -> uint32x4_t {
    // SAFETY: The byte-aligned 16-byte NEON load fits the initialized array.
    unsafe { vreinterpretq_u32_u8(vld1q_u8(bytes.as_ptr())) }
}
#[target_feature(enable = "neon")]
unsafe fn store(bytes: &mut [u8; 32], value: uint32x4_t) {
    // SAFETY: The byte-aligned 16-byte store fits the exclusive owner array.
    unsafe { vst1q_u8(bytes.as_mut_ptr(), vreinterpretq_u8_u32(value)) }
}

#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn compress_secret(s: &mut Workspace) -> Result<(), Error> {
    // SAFETY: The private dispatcher carries lifetime-wide little-endian NEON
    // authority. All loads/stores use fixed live owner arrays, including their
    // unused upper half. Intrinsic values and compiler-created copies retain
    // documented register/spill limits; no unowned vector arrays are created.
    unsafe {
        macro_rules! add {
            ($a:expr, $b:expr) => {
                vaddq_u32($a, $b)
            };
        }
        macro_rules! xor {
            ($a:expr, $b:expr) => {
                veorq_u32($a, $b)
            };
        }
        macro_rules! ror {
            ($a:expr, $n:literal) => {
                vorrq_u32(vshrq_n_u32::<$n>($a), vshlq_n_u32::<{ 32 - $n }>($a))
            };
        }
        for t in 16_usize..64 {
            let x = load(
                s.schedule
                    .get(t.checked_sub(15).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
            );
            let y = load(
                s.schedule
                    .get(t.checked_sub(2).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
            );
            let [sigma0, sigma1, ..] = &mut s.temporary;
            store(
                sigma0,
                xor!(xor!(ror!(x, 7), ror!(x, 18)), vshrq_n_u32::<3>(x)),
            );
            store(
                sigma1,
                xor!(xor!(ror!(y, 17), ror!(y, 19)), vshrq_n_u32::<10>(y)),
            );
            let w16 = load(
                s.schedule
                    .get(t.checked_sub(16).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
            );
            let w7 = load(
                s.schedule
                    .get(t.checked_sub(7).ok_or(Error::Invariant)?)
                    .ok_or(Error::Invariant)?,
            );
            store(
                s.schedule.get_mut(t).ok_or(Error::Invariant)?,
                add!(add!(w16, load(sigma0)), add!(w7, load(sigma1))),
            );
        }
        for (work, initial) in s.work.iter_mut().zip(&s.initial) {
            work.copy_from_slice(initial);
        }
        for (word, constant) in s
            .schedule
            .iter()
            .zip(crate::sha256_schedule::ROUND_CONSTANTS)
        {
            let [a, b, c, _, e, f, g, h] = &s.work;
            let [big0, big1, choose, majority, temp1, temp2] = &mut s.temporary;
            store(
                big0,
                xor!(xor!(ror!(load(a), 2), ror!(load(a), 13)), ror!(load(a), 22)),
            );
            store(
                big1,
                xor!(xor!(ror!(load(e), 6), ror!(load(e), 11)), ror!(load(e), 25)),
            );
            store(
                choose,
                xor!(load(g), vandq_u32(load(e), xor!(load(f), load(g)))),
            );
            store(
                majority,
                xor!(
                    vandq_u32(load(a), load(b)),
                    vandq_u32(load(c), xor!(load(a), load(b)))
                ),
            );
            store(
                temp1,
                add!(
                    add!(add!(load(h), load(big1)), load(choose)),
                    add!(vdupq_n_u32(constant), load(word))
                ),
            );
            store(temp2, add!(load(big0), load(majority)));
            let [a, b, c, d, e, f, g, h] = &mut s.work;
            h.copy_from_slice(g);
            g.copy_from_slice(f);
            f.copy_from_slice(e);
            store(e, add!(load(d), load(temp1)));
            d.copy_from_slice(c);
            c.copy_from_slice(b);
            b.copy_from_slice(a);
            store(a, add!(load(temp1), load(temp2)));
        }
        for (work, initial) in s.work.iter_mut().zip(&s.initial) {
            store(work, add!(load(work), load(initial)));
        }
    }
    Ok(())
}
