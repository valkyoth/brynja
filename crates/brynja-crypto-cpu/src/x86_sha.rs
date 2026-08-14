#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, _mm_set_epi32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32, _mm_storeu_si128,
};

use crate::sha256_schedule::{ROUND_CONSTANTS, expanded};

pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: The only safe caller holds a thread-bound session whose direct
    // startup KAT executed this same function after compile-time proof or a
    // reviewed runtime `sha` observation. The function reads one fixed block
    // and writes one live exclusive state array.
    unsafe { compress_sha(state, block) }
}

#[target_feature(enable = "sha")]
unsafe fn compress_sha(state: &mut [u32; 8], block: &[u8; 64]) {
    let schedule = expanded(block);
    let [a, b, c, d, e, f, g, h] = *state;
    let mut abef = _mm_set_epi32(a as i32, b as i32, e as i32, f as i32);
    let mut cdgh = _mm_set_epi32(c as i32, d as i32, g as i32, h as i32);

    for (words, constants) in schedule
        .chunks_exact(4)
        .zip(ROUND_CONSTANTS.chunks_exact(4))
    {
        if let ([w0, w1, w2, w3], [k0, k1, k2, k3]) = (words, constants) {
            let mut wk = _mm_set_epi32(
                w3.wrapping_add(*k3) as i32,
                w2.wrapping_add(*k2) as i32,
                w1.wrapping_add(*k1) as i32,
                w0.wrapping_add(*k0) as i32,
            );
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
            wk = _mm_shuffle_epi32::<0x0e>(wk);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, wk);
        }
    }

    let mut output_abef = [0_i32; 4];
    let mut output_cdgh = [0_i32; 4];
    // SAFETY: Both destinations are live aligned-or-unaligned four-lane arrays
    // with exactly 16 writable bytes and do not overlap either source value.
    unsafe {
        _mm_storeu_si128(output_abef.as_mut_ptr().cast::<__m128i>(), abef);
        _mm_storeu_si128(output_cdgh.as_mut_ptr().cast::<__m128i>(), cdgh);
    }
    let [out_f, out_e, out_b, out_a] = output_abef.map(i32::cast_unsigned);
    let [out_h, out_g, out_d, out_c] = output_cdgh.map(i32::cast_unsigned);
    *state = [
        a.wrapping_add(out_a),
        b.wrapping_add(out_b),
        c.wrapping_add(out_c),
        d.wrapping_add(out_d),
        e.wrapping_add(out_e),
        f.wrapping_add(out_f),
        g.wrapping_add(out_g),
        h.wrapping_add(out_h),
    ];
}
