//! Two clearing Keccak lanes; unused packed capacity remains owned.
#![allow(unsafe_code)]
use super::{Error, Workspace};
use core::arch::aarch64::*;

#[target_feature(enable = "neon")]
unsafe fn load(bytes: &[u8; 32]) -> uint64x2_t {
    // SAFETY: The byte-aligned 16-byte NEON load fits the initialized array.
    unsafe { vreinterpretq_u64_u8(vld1q_u8(bytes.as_ptr())) }
}
#[target_feature(enable = "neon")]
unsafe fn store(bytes: &mut [u8; 32], value: uint64x2_t) {
    // SAFETY: The byte-aligned 16-byte store fits the exclusive owner array.
    unsafe { vst1q_u8(bytes.as_mut_ptr(), vreinterpretq_u8_u64(value)) }
}

#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn permute_secret(s: &mut Workspace) -> Result<(), Error> {
    // SAFETY: Private dispatch supplies lifetime-wide CPU/OS feature authority.
    // Fixed initialized owner arrays bound every unaligned intrinsic access.
    // Only public constants drive shifts and indices. Registers and compiler
    // copies retain the documented erasure limits; no packed aggregate escapes.
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

        for rc in crate::keccak_constants::ROUND_CONSTANTS {
            // All 25 state vectors, column parities, deltas and rho/pi/chi
            // staging reside in the owner; no local packed-vector arrays.
            for column in &mut s.columns {
                column.fill(0);
            }
            for row in s.state.as_chunks::<5>().0 {
                for (column, value) in s.columns.iter_mut().zip(row) {
                    store(column, xor!(load(column), load(value)));
                }
            }
            let [c0, c1, c2, c3, c4] = &s.columns;
            let [d0, d1, d2, d3, d4] = &mut s.deltas;
            store(d0, xor!(load(c4), rol!(load(c1), 1_u32)));
            store(d1, xor!(load(c0), rol!(load(c2), 1_u32)));
            store(d2, xor!(load(c1), rol!(load(c3), 1_u32)));
            store(d3, xor!(load(c2), rol!(load(c4), 1_u32)));
            store(d4, xor!(load(c3), rol!(load(c0), 1_u32)));
            for row in s.state.as_chunks_mut::<5>().0 {
                for (value, delta) in row.iter_mut().zip(&s.deltas) {
                    store(value, xor!(load(value), load(delta)));
                }
            }
            for ((value, rotation), destination) in s
                .state
                .iter()
                .zip(crate::keccak_constants::ROTATION_OFFSETS)
                .zip(crate::keccak_constants::PI_DESTINATIONS)
            {
                store(
                    s.staging.get_mut(destination).ok_or(Error::Invariant)?,
                    rol!(load(value), rotation),
                );
            }
            for (out, row) in s
                .state
                .as_chunks_mut::<5>()
                .0
                .iter_mut()
                .zip(s.staging.as_chunks::<5>().0)
            {
                let [b0, b1, b2, b3, b4] = row;
                let [a0, a1, a2, a3, a4] = out;
                store(a0, chi!(load(b0), load(b1), load(b2)));
                store(a1, chi!(load(b1), load(b2), load(b3)));
                store(a2, chi!(load(b2), load(b3), load(b4)));
                store(a3, chi!(load(b3), load(b4), load(b0)));
                store(a4, chi!(load(b4), load(b0), load(b1)));
            }
            let first = s.state.first_mut().ok_or(Error::Invariant)?;
            store(first, xor!(load(first), splat!(rc)));
        }
        Ok(())
    }
}
