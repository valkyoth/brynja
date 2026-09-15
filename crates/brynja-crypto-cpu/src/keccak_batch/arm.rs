//! First-party FIPS 202 Keccak-f[1600], 2 independent states per vector.
#![allow(unsafe_code)]
use super::Error;
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn permute(states: &mut [[u64; 25]; 4]) -> Result<(), Error> {
    // SAFETY: Sealed caller supplies the CPU/OS lifetime bundle. Unaligned
    // loads/stores touch exactly 2 initialized u64s in local fixed arrays.
    // Checked indices reject invariant failures; the caller stages all writes.
    // Rotations use public constants in 0..64; a 64-bit shift contributes zero.
    unsafe {
        macro_rules! xor {
            ($a:expr, $b:expr) => {
                veorq_u64($a, $b)
            };
        }
        macro_rules! chi {
            ($a:expr, $b:expr, $c:expr) => {
                xor!($a, vbicq_u64($c, $b))
            };
        }
        macro_rules! splat {
            ($a:expr) => {
                vdupq_n_u64($a)
            };
        }
        macro_rules! rol {
            ($a:expr, $n:expr) => {
                vorrq_u64(
                    vshlq_u64($a, vdupq_n_s64(i64::from($n))),
                    vshlq_u64($a, vdupq_n_s64(i64::from($n) - 64)),
                )
            };
        }

        let zero = splat!(0_u64);
        let mut a = [zero; 25];
        for (word, out) in a.iter_mut().enumerate() {
            let mut lanes = [0_u64; 2];
            for (out, state) in lanes.iter_mut().zip(states.iter()) {
                *out = *state.get(word).ok_or(Error::Invariant)?;
            }
            *out = vld1q_u64(lanes.as_ptr());
        }
        for rc in crate::keccak_constants::ROUND_CONSTANTS {
            let mut c = [zero; 5];
            for row in a.as_chunks::<5>().0 {
                for (out, value) in c.iter_mut().zip(row) {
                    *out = xor!(*out, *value);
                }
            }
            let [c0, c1, c2, c3, c4] = c;
            let d = [
                xor!(c4, rol!(c1, 1_u32)),
                xor!(c0, rol!(c2, 1_u32)),
                xor!(c1, rol!(c3, 1_u32)),
                xor!(c2, rol!(c4, 1_u32)),
                xor!(c3, rol!(c0, 1_u32)),
            ];
            for row in a.as_chunks_mut::<5>().0 {
                for (value, delta) in row.iter_mut().zip(d) {
                    *value = xor!(*value, delta);
                }
            }
            let mut b = [zero; 25];
            for ((value, rotation), destination) in a
                .iter()
                .zip(crate::keccak_constants::ROTATION_OFFSETS)
                .zip(crate::keccak_constants::PI_DESTINATIONS)
            {
                *b.get_mut(destination).ok_or(Error::Invariant)? = rol!(*value, rotation);
            }
            for (out, row) in a
                .as_chunks_mut::<5>()
                .0
                .iter_mut()
                .zip(b.as_chunks::<5>().0)
            {
                let [b0, b1, b2, b3, b4] = *row;
                *out = [
                    chi!(b0, b1, b2),
                    chi!(b1, b2, b3),
                    chi!(b2, b3, b4),
                    chi!(b3, b4, b0),
                    chi!(b4, b0, b1),
                ];
            }
            let first = a.first_mut().ok_or(Error::Invariant)?;
            *first = xor!(*first, splat!(rc));
        }
        for (word, value) in a.into_iter().enumerate() {
            let mut lanes = [0_u64; 2];
            vst1q_u64(lanes.as_mut_ptr(), value);
            for (state, value) in states.iter_mut().zip(lanes) {
                *state.get_mut(word).ok_or(Error::Invariant)? = value;
            }
        }
        Ok(())
    }
}
