//! Dedicated SHA-512 instructions, distinct from SHA-NI and AVX-512.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m256i, _mm_set_epi64x, _mm256_set_epi64x, _mm256_sha512msg1_epi64, _mm256_sha512msg2_epi64,
    _mm256_sha512rnds2_epi64, _mm256_storeu_si256,
};

use crate::sha512_schedule::ROUND_CONSTANTS;
use crate::static_execution::Error;

#[cfg(feature = "hardened-execution")]
pub(crate) fn compress_secret(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    // SAFETY: The sealed hardened session has the same SHA512/AVX2/AVX and OS-state
    // authority as the ordinary route. Only its distinct clearing scratch is
    // used; the operation guard erases both regions on return and unwind.
    unsafe { secret_sha512(state, block, scratch) }
}

#[cfg(feature = "hardened-execution")]
#[target_feature(enable = "sha512,avx2,avx")]
#[inline(never)]
unsafe fn secret_sha512(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    use crate::hardened_execution::scratch::{read64, write64};
    // A distinct owner-backed scalar schedule avoids the ordinary kernel's
    // non-clearing arrays. Dedicated round instructions still perform all
    // compression rounds. Registers and compiler-created copies are residuals.
    scratch.expand64(block);
    let mut abef = _mm256_set_epi64x(
        read64(state, 0) as i64,
        read64(state, 1) as i64,
        read64(state, 4) as i64,
        read64(state, 5) as i64,
    );
    let mut cdgh = _mm256_set_epi64x(
        read64(state, 2) as i64,
        read64(state, 3) as i64,
        read64(state, 6) as i64,
        read64(state, 7) as i64,
    );
    for (chunk, [k0, k1, k2, k3]) in ROUND_CONSTANTS.as_chunks::<4>().0.iter().enumerate() {
        let round = chunk.saturating_mul(4);
        cdgh = _mm256_sha512rnds2_epi64(
            cdgh,
            abef,
            _mm_set_epi64x(
                read64(&scratch.schedule, round.saturating_add(1)).wrapping_add(*k1) as i64,
                read64(&scratch.schedule, round).wrapping_add(*k0) as i64,
            ),
        );
        abef = _mm256_sha512rnds2_epi64(
            abef,
            cdgh,
            _mm_set_epi64x(
                read64(&scratch.schedule, round.saturating_add(3)).wrapping_add(*k3) as i64,
                read64(&scratch.schedule, round.saturating_add(2)).wrapping_add(*k2) as i64,
            ),
        );
    }
    // SAFETY: The two unaligned 32-byte stores cover exactly the exclusively
    // borrowed 64-byte vector owner, which remains live until guard cleanup.
    unsafe {
        _mm256_storeu_si256(scratch.vectors.as_mut_ptr().cast::<__m256i>(), abef);
        _mm256_storeu_si256(scratch.vectors.as_mut_ptr().add(32).cast::<__m256i>(), cdgh);
    }
    for (index, lane) in [3, 2, 7, 6, 1, 0, 5, 4].into_iter().enumerate() {
        let value = read64(state, index).wrapping_add(read64(&scratch.vectors, lane).swap_bytes());
        write64(state, index, value);
    }
}

pub(crate) fn compress(state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
    // SAFETY: Only sealed static/runtime authorities call this entry. They
    // establish SHA512 plus AVX2/AVX and enabled XMM/YMM OS state for the entire
    // operation. Fixed arrays are initialized, live and exclusively borrowed.
    unsafe { compress_sha512(state, block) }
}

#[target_feature(enable = "sha512,avx2,avx")]
#[inline(never)]
unsafe fn compress_sha512(state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
    let mut schedule = [0_u64; 80];
    for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for i in (16_usize..80).step_by(4) {
        let word = |back: usize| {
            schedule
                .get(i.saturating_sub(back))
                .copied()
                .ok_or(Error::Quarantined)
        };
        let first = _mm256_sha512msg1_epi64(
            _mm256_set_epi64x(
                word(13)? as i64,
                word(14)? as i64,
                word(15)? as i64,
                word(16)? as i64,
            ),
            _mm_set_epi64x(0, word(12)? as i64),
        );
        let mut partial = [0_u64; 4];
        // SAFETY: The unaligned store writes exactly the four initialized,
        // exclusively borrowed u64s of partial (32 bytes).
        unsafe { _mm256_storeu_si256(partial.as_mut_ptr().cast::<__m256i>(), first) };
        // Lane-local modulo additions preserve the schedule word ordering.
        for (offset, value) in partial.iter_mut().enumerate() {
            *value = value.wrapping_add(word(7_usize.saturating_sub(offset))?);
        }
        let [p0, p1, p2, p3] = partial;
        let next = _mm256_sha512msg2_epi64(
            _mm256_set_epi64x(p3 as i64, p2 as i64, p1 as i64, p0 as i64),
            _mm256_set_epi64x(word(1)? as i64, word(2)? as i64, 0, 0),
        );
        // SAFETY: i is one of 16,20,..,76. This writes four u64s wholly
        // within the live 80-word schedule, with no overlapping reference.
        unsafe { _mm256_storeu_si256(schedule.as_mut_ptr().add(i).cast::<__m256i>(), next) };
    }
    let [a, b, c, d, e, f, g, h] = *state;
    let mut abef = _mm256_set_epi64x(a as i64, b as i64, e as i64, f as i64);
    let mut cdgh = _mm256_set_epi64x(c as i64, d as i64, g as i64, h as i64);
    for ([w0, w1, w2, w3], [k0, k1, k2, k3]) in schedule
        .as_chunks::<4>()
        .0
        .iter()
        .zip(ROUND_CONSTANTS.as_chunks::<4>().0)
    {
        cdgh = _mm256_sha512rnds2_epi64(
            cdgh,
            abef,
            _mm_set_epi64x(w1.wrapping_add(*k1) as i64, w0.wrapping_add(*k0) as i64),
        );
        abef = _mm256_sha512rnds2_epi64(
            abef,
            cdgh,
            _mm_set_epi64x(w3.wrapping_add(*k3) as i64, w2.wrapping_add(*k2) as i64),
        );
    }
    let mut first = [0_u64; 4];
    let mut second = [0_u64; 4];
    // SAFETY: Each unaligned store writes exactly 32 bytes into a distinct
    // initialized, exclusively borrowed four-u64 array.
    unsafe {
        _mm256_storeu_si256(first.as_mut_ptr().cast::<__m256i>(), abef);
        _mm256_storeu_si256(second.as_mut_ptr().cast::<__m256i>(), cdgh);
    }
    let [ff, ee, bb, aa] = first;
    let [hh, gg, dd, cc] = second;
    *state = [
        a.wrapping_add(aa),
        b.wrapping_add(bb),
        c.wrapping_add(cc),
        d.wrapping_add(dd),
        e.wrapping_add(ee),
        f.wrapping_add(ff),
        g.wrapping_add(gg),
        h.wrapping_add(hh),
    ];
    Ok(())
}
