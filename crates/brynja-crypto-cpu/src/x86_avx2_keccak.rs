#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m256i, _mm256_andnot_si256, _mm256_loadu_si256, _mm256_or_si256, _mm256_slli_epi64,
    _mm256_srli_epi64, _mm256_storeu_si256, _mm256_xor_si256,
};

use crate::keccak_constants::{PI_DESTINATIONS, ROTATION_OFFSETS, ROUND_CONSTANTS};

pub(crate) fn permute(state: &mut [u64; 25]) {
    // SAFETY: The only safe caller holds a thread-bound session whose direct
    // startup KAT executed this function after complete AVX2 feature proof.
    // Every load and store below uses a fixed live four-word local array.
    unsafe { permute_avx2(state) }
}

#[target_feature(enable = "avx2")]
unsafe fn permute_avx2(state: &mut [u64; 25]) {
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
        let columns = [
            a00 ^ a10 ^ a20 ^ a30 ^ a40,
            a01 ^ a11 ^ a21 ^ a31 ^ a41,
            a02 ^ a12 ^ a22 ^ a32 ^ a42,
            a03 ^ a13 ^ a23 ^ a33 ^ a43,
            a04 ^ a14 ^ a24 ^ a34 ^ a44,
        ];
        let [c0, c1, c2, c3, c4] = columns;
        let previous = load4(&[c4, c0, c1, c2]);
        let following = load4(&[c1, c2, c3, c4]);
        let rotated = _mm256_or_si256(
            _mm256_slli_epi64::<1>(following),
            _mm256_srli_epi64::<63>(following),
        );
        let [d0, d1, d2, d3] = store4(_mm256_xor_si256(previous, rotated));
        let d4 = c3 ^ c0.rotate_left(1);
        for row in state.chunks_exact_mut(5) {
            if let [r0, r1, r2, r3, r4] = row {
                let adjusted =
                    _mm256_xor_si256(load4(&[*r0, *r1, *r2, *r3]), load4(&[d0, d1, d2, d3]));
                [*r0, *r1, *r2, *r3] = store4(adjusted);
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
                let current = load4(&[*b0, *b1, *b2, *b3]);
                let next = load4(&[*b1, *b2, *b3, *b4]);
                let following = load4(&[*b2, *b3, *b4, *b0]);
                let chi = _mm256_xor_si256(current, _mm256_andnot_si256(next, following));
                [*a0, *a1, *a2, *a3] = store4(chi);
                *a4 = *b4 ^ ((!*b0) & *b1);
            }
        }
        if let Some(first) = state.first_mut() {
            *first ^= constant;
        }
    }
}

#[inline]
fn load4(words: &[u64; 4]) -> __m256i {
    // SAFETY: `words` is a live exact four-word array and unaligned reads are
    // explicitly supported by this intrinsic.
    unsafe { _mm256_loadu_si256(words.as_ptr().cast::<__m256i>()) }
}

#[inline]
fn store4(vector: __m256i) -> [u64; 4] {
    let mut words = [0_u64; 4];
    // SAFETY: `words` is a live exact four-word destination and the unaligned
    // store writes exactly its 32 bytes.
    unsafe { _mm256_storeu_si256(words.as_mut_ptr().cast::<__m256i>(), vector) };
    words
}
