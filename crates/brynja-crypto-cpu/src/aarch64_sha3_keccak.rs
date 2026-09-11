#![allow(unsafe_code)]

use core::arch::aarch64::{uint64x2_t, vbcaxq_u64, veor3q_u64, vld1q_u64, vrax1q_u64, vst1q_u64};

use crate::keccak_constants::{PI_DESTINATIONS, ROTATION_OFFSETS, ROUND_CONSTANTS};

pub(crate) fn permute(state: &mut [u64; 25]) {
    // SAFETY: The only safe caller holds a thread-bound session whose direct
    // startup KAT executed this function after complete NEON plus SHA3 proof.
    // Every vector access below uses a fixed live two-word local array.
    unsafe { permute_sha3(state) }
}

#[target_feature(enable = "sha3")]
unsafe fn permute_sha3(state: &mut [u64; 25]) {
    for constant in ROUND_CONSTANTS {
        let [
            a00,
            a01,
            a02,
            a03,
            a04,
            a10,
            a11,
            a12,
            a13,
            a14,
            a20,
            a21,
            a22,
            a23,
            a24,
            a30,
            a31,
            a32,
            a33,
            a34,
            a40,
            a41,
            a42,
            a43,
            a44,
        ] = *state;
        let c01 = veor3q_u64(
            veor3q_u64(load2(&[a00, a01]), load2(&[a10, a11]), load2(&[a20, a21])),
            load2(&[a30, a31]),
            load2(&[a40, a41]),
        );
        let c23 = veor3q_u64(
            veor3q_u64(load2(&[a02, a03]), load2(&[a12, a13]), load2(&[a22, a23])),
            load2(&[a32, a33]),
            load2(&[a42, a43]),
        );
        let [c0, c1] = store2(c01);
        let [c2, c3] = store2(c23);
        let c4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;
        let [d0, d1] = store2(vrax1q_u64(load2(&[c4, c0]), load2(&[c1, c2])));
        let [d2, d3] = store2(vrax1q_u64(load2(&[c1, c2]), load2(&[c3, c4])));
        let d4 = c3 ^ c0.rotate_left(1);
        for row in state.chunks_exact_mut(5) {
            if let [r0, r1, r2, r3, r4] = row {
                *r0 ^= d0;
                *r1 ^= d1;
                *r2 ^= d2;
                *r3 ^= d3;
                *r4 ^= d4;
            }
        }

        let mut rearranged = [0_u64; 25];
        for ((lane, rotation), destination) in
            state.iter().zip(ROTATION_OFFSETS).zip(PI_DESTINATIONS)
        {
            if let Some(target) = rearranged.get_mut(destination) {
                *target = lane.rotate_left(rotation);
            }
        }

        for (target, source) in state.chunks_exact_mut(5).zip(rearranged.chunks_exact(5)) {
            if let ([a0, a1, a2, a3, a4], [b0, b1, b2, b3, b4]) = (target, source) {
                let [r0, r1] = store2(vbcaxq_u64(
                    load2(&[*b0, *b1]),
                    load2(&[*b2, *b3]),
                    load2(&[*b1, *b2]),
                ));
                let [r2, r3] = store2(vbcaxq_u64(
                    load2(&[*b2, *b3]),
                    load2(&[*b4, *b0]),
                    load2(&[*b3, *b4]),
                ));
                *a0 = r0;
                *a1 = r1;
                *a2 = r2;
                *a3 = r3;
                *a4 = *b4 ^ ((!*b0) & *b1);
            }
        }
        if let Some(first) = state.first_mut() {
            *first ^= constant;
        }
    }
}

#[inline]
fn load2(words: &[u64; 2]) -> uint64x2_t {
    // SAFETY: `words` is one live exact two-word input vector.
    unsafe { vld1q_u64(words.as_ptr()) }
}

#[inline]
fn store2(vector: uint64x2_t) -> [u64; 2] {
    let mut words = [0_u64; 2];
    // SAFETY: `words` is one live exact two-word output vector.
    unsafe { vst1q_u64(words.as_mut_ptr(), vector) };
    words
}

#[cfg(feature = "hardened-execution")]
pub(crate) fn permute_secret(
    scratch: &mut crate::hardened_execution::keccak_scratch::KeccakScratch,
) -> Result<(), crate::static_execution::Error> {
    // SAFETY: The private dispatcher requires complete NEON/SHA3 authority.
    // Every vector accesses the first 16 initialized bytes of an owned array.
    unsafe { permute_secret_sha3(scratch) }
}

#[cfg(feature = "hardened-execution")]
#[target_feature(enable = "sha3")]
unsafe fn permute_secret_sha3(
    s: &mut crate::hardened_execution::keccak_scratch::KeccakScratch,
) -> Result<(), crate::static_execution::Error> {
    for constant in ROUND_CONSTANTS {
        s.theta_rho_pi()?;
        for row in 0..5 {
            for first in [0, 2] {
                s.stage_chi(row, first, 2)?;
                // SAFETY: Each source/destination owns 32 bytes; these unaligned
                // loads/stores use only its first 16 bytes and never alias writes.
                unsafe {
                    let current = vld1q_u64(s.current.as_ptr().cast());
                    let next = vld1q_u64(s.next.as_ptr().cast());
                    let following = vld1q_u64(s.following.as_ptr().cast());
                    let result = vbcaxq_u64(current, following, next);
                    vst1q_u64(s.current.as_mut_ptr().cast(), result);
                }
                s.commit_chi(row, first, 2)?;
            }
            s.last_chi(row)?;
        }
        s.iota(constant)?;
    }
    Ok(())
}
