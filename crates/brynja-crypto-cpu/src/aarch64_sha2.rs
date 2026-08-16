#![allow(unsafe_code)]

use core::arch::aarch64::{
    vaddq_u32, vaddq_u64, vextq_u64, vld1q_u32, vld1q_u64, vsha256h2q_u32, vsha256hq_u32,
    vsha512h2q_u64, vsha512hq_u64, vst1q_u32, vst1q_u64,
};

use crate::sha256_schedule::{ROUND_CONSTANTS, expanded};
use crate::sha512_schedule::{ROUND_CONSTANTS as ROUND_CONSTANTS_512, expanded as expanded512};

pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: The only safe caller holds a thread-bound session whose direct
    // startup KAT executed this same function after complete `neon` plus
    // `sha2` compile-time proof or reviewed runtime observation. All vector
    // loads and stores address fixed live arrays of the exact required size.
    unsafe { compress_sha2(state, block) }
}

#[target_feature(enable = "sha2")]
unsafe fn compress_sha2(state: &mut [u32; 8], block: &[u8; 64]) {
    let schedule = expanded(block);
    // SAFETY: `state` contains two complete four-word vectors. The wrapper's
    // documented proof covers feature availability and these reads are within
    // the one live shared input borrow.
    let (mut abcd, mut efgh) =
        unsafe { (vld1q_u32(state.as_ptr()), vld1q_u32(state.as_ptr().add(4))) };
    let saved_abcd = abcd;
    let saved_efgh = efgh;

    for (words, constants) in schedule
        .chunks_exact(4)
        .zip(ROUND_CONSTANTS.chunks_exact(4))
    {
        if let ([w0, w1, w2, w3], [k0, k1, k2, k3]) = (words, constants) {
            let wk_words = [
                w0.wrapping_add(*k0),
                w1.wrapping_add(*k1),
                w2.wrapping_add(*k2),
                w3.wrapping_add(*k3),
            ];
            // SAFETY: `wk_words` is one live four-word array.
            let wk = unsafe { vld1q_u32(wk_words.as_ptr()) };
            let previous_abcd = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, previous_abcd, wk);
        }
    }

    abcd = vaddq_u32(abcd, saved_abcd);
    efgh = vaddq_u32(efgh, saved_efgh);
    // SAFETY: `state` contains two complete four-word destinations under one
    // exclusive borrow, and both stores remain within those eight words.
    unsafe {
        vst1q_u32(state.as_mut_ptr(), abcd);
        vst1q_u32(state.as_mut_ptr().add(4), efgh);
    }
}

pub(crate) fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    // SAFETY: Static selection proves `neon` plus `sha3` before this wrapper
    // can be reached. The direct startup KAT executes the same kernel before
    // caller data, and both arrays have exact fixed sizes.
    unsafe { compress_sha512(state, block) }
}

#[target_feature(enable = "sha3")]
unsafe fn compress_sha512(state: &mut [u64; 8], block: &[u8; 128]) {
    let schedule = expanded512(block);
    // SAFETY: The exclusive eight-word state is four consecutive two-word
    // vectors; all reads remain inside that live allocation.
    let (mut ab, mut cd, mut ef, mut gh) = unsafe {
        (
            vld1q_u64(state.as_ptr()),
            vld1q_u64(state.as_ptr().add(2)),
            vld1q_u64(state.as_ptr().add(4)),
            vld1q_u64(state.as_ptr().add(6)),
        )
    };
    let (saved_ab, saved_cd, saved_ef, saved_gh) = (ab, cd, ef, gh);

    for (pair_index, (words, constants)) in schedule
        .chunks_exact(2)
        .zip(ROUND_CONSTANTS_512.chunks_exact(2))
        .enumerate()
    {
        let ([word0, word1], [constant0, constant1]) = (words, constants) else {
            continue;
        };
        let initial = [
            word0.wrapping_add(*constant0),
            word1.wrapping_add(*constant1),
        ];
        // SAFETY: `initial` is one live two-word vector.
        let initial = unsafe { vld1q_u64(initial.as_ptr()) };
        match pair_index % 4 {
            0 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), gh);
                let intermediate =
                    vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
                gh = vsha512h2q_u64(intermediate, cd, ab);
                cd = vaddq_u64(cd, intermediate);
            }
            1 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), ef);
                let intermediate =
                    vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
                ef = vsha512h2q_u64(intermediate, ab, gh);
                ab = vaddq_u64(ab, intermediate);
            }
            2 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), cd);
                let intermediate =
                    vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
                cd = vsha512h2q_u64(intermediate, gh, ef);
                gh = vaddq_u64(gh, intermediate);
            }
            _ => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), ab);
                let intermediate =
                    vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
                ab = vsha512h2q_u64(intermediate, ef, cd);
                ef = vaddq_u64(ef, intermediate);
            }
        }
    }

    ab = vaddq_u64(ab, saved_ab);
    cd = vaddq_u64(cd, saved_cd);
    ef = vaddq_u64(ef, saved_ef);
    gh = vaddq_u64(gh, saved_gh);
    // SAFETY: Four exact two-word stores cover the exclusive eight-word state
    // once without overlap outside its allocation.
    unsafe {
        vst1q_u64(state.as_mut_ptr(), ab);
        vst1q_u64(state.as_mut_ptr().add(2), cd);
        vst1q_u64(state.as_mut_ptr().add(4), ef);
        vst1q_u64(state.as_mut_ptr().add(6), gh);
    }
}
