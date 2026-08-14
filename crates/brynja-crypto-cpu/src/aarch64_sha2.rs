#![allow(unsafe_code)]

use core::arch::aarch64::{vaddq_u32, vld1q_u32, vsha256h2q_u32, vsha256hq_u32, vst1q_u32};

use crate::sha256_schedule::{ROUND_CONSTANTS, expanded};

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
