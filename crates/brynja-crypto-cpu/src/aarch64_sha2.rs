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

#[cfg(feature = "hardened-execution")]
pub(crate) fn compress_secret(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    // SAFETY: Sealed session checks complete NEON/SHA2 platform authority.
    // The scratch owner is aligned and every load/store stays in its 64 bytes.
    unsafe { secret_sha256(state, block, scratch) }
}

#[cfg(feature = "hardened-execution")]
#[target_feature(enable = "sha2")]
unsafe fn secret_sha256(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    use crate::hardened_execution::scratch::{read32, write32};
    scratch.expand32(block);
    for i in 0..8 {
        // write32 encodes BE bytes; .to_be() first makes that a native-endian
        // word in memory for vld1q_u32. Neither conversion is redundant.
        write32(&mut scratch.vectors, i, read32(state, i).to_be());
    }
    // SAFETY: Fixed offsets 0/16 each read sixteen bytes of aligned owner data.
    let (mut abcd, mut efgh) = unsafe {
        (
            vld1q_u32(scratch.vectors.as_ptr().cast()),
            vld1q_u32(scratch.vectors.as_ptr().add(16).cast()),
        )
    };
    let saved_abcd = abcd;
    let saved_efgh = efgh;
    for (chunk, constants) in ROUND_CONSTANTS.as_chunks::<4>().0.iter().enumerate() {
        let round = chunk.saturating_mul(4);
        for (j, constant) in constants.iter().enumerate() {
            let value = read32(&scratch.schedule, round.saturating_add(j)).wrapping_add(*constant);
            // The same BE-writer/native-load bridge applies to round words.
            write32(
                &mut scratch.vectors,
                8_usize.saturating_add(j),
                value.to_be(),
            );
        }
        // SAFETY: One complete aligned sixteen-byte vector at offset 32.
        let wk = unsafe { vld1q_u32(scratch.vectors.as_ptr().add(32).cast()) };
        let previous = abcd;
        abcd = vsha256hq_u32(abcd, efgh, wk);
        efgh = vsha256h2q_u32(efgh, previous, wk);
    }
    // SAFETY: Exclusive aligned owner stores at offsets 0/16 stay in bounds.
    unsafe {
        vst1q_u32(
            scratch.vectors.as_mut_ptr().cast(),
            vaddq_u32(abcd, saved_abcd),
        );
        vst1q_u32(
            scratch.vectors.as_mut_ptr().add(16).cast(),
            vaddq_u32(efgh, saved_efgh),
        );
    }
    for i in 0..8 {
        let value = read32(&scratch.vectors, i);
        // vst1q_u32 stored native bytes; undo read32's BE interpretation
        // before writing the external big-endian chaining state.
        write32(
            state,
            i,
            if cfg!(target_endian = "little") {
                value.swap_bytes()
            } else {
                value
            },
        );
    }
}

#[cfg(feature = "hardened-execution")]
pub(crate) fn compress512_secret(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    // SAFETY: Sealed session checks complete NEON/SHA3/SHA512 authority and
    // every vector access is confined to the aligned scratch owner.
    unsafe { secret_sha512(state, block, scratch) }
}

#[cfg(feature = "hardened-execution")]
#[target_feature(enable = "sha3")]
unsafe fn secret_sha512(
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut crate::hardened_execution::scratch::Scratch,
) {
    use crate::hardened_execution::scratch::{read64, write64};
    scratch.expand64(block);
    for i in 0..8 {
        // write64 encodes BE bytes; .to_be() first makes that a native-endian
        // word in memory for vld1q_u64. Neither conversion is redundant.
        write64(&mut scratch.vectors, i, read64(state, i).to_be());
    }
    // SAFETY: Four aligned two-word loads cover precisely 64 owned bytes.
    let (mut ab, mut cd, mut ef, mut gh) = unsafe {
        (
            vld1q_u64(scratch.vectors.as_ptr().cast()),
            vld1q_u64(scratch.vectors.as_ptr().add(16).cast()),
            vld1q_u64(scratch.vectors.as_ptr().add(32).cast()),
            vld1q_u64(scratch.vectors.as_ptr().add(48).cast()),
        )
    };
    let (saved_ab, saved_cd, saved_ef, saved_gh) = (ab, cd, ef, gh);
    for (pair, constants) in ROUND_CONSTANTS_512.as_chunks::<2>().0.iter().enumerate() {
        for (j, constant) in constants.iter().enumerate() {
            let value = read64(&scratch.schedule, pair.saturating_mul(2).saturating_add(j))
                .wrapping_add(*constant);
            // The same BE-writer/native-load bridge applies to round words.
            write64(&mut scratch.vectors, j, value.to_be());
        }
        // SAFETY: One aligned sixteen-byte input vector in the scratch owner.
        let initial = unsafe { vld1q_u64(scratch.vectors.as_ptr().cast()) };
        match pair % 4 {
            0 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), gh);
                let mid = vsha512hq_u64(sum, vextq_u64::<1>(ef, gh), vextq_u64::<1>(cd, ef));
                gh = vsha512h2q_u64(mid, cd, ab);
                cd = vaddq_u64(cd, mid);
            }
            1 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), ef);
                let mid = vsha512hq_u64(sum, vextq_u64::<1>(cd, ef), vextq_u64::<1>(ab, cd));
                ef = vsha512h2q_u64(mid, ab, gh);
                ab = vaddq_u64(ab, mid);
            }
            2 => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), cd);
                let mid = vsha512hq_u64(sum, vextq_u64::<1>(ab, cd), vextq_u64::<1>(gh, ab));
                cd = vsha512h2q_u64(mid, gh, ef);
                gh = vaddq_u64(gh, mid);
            }
            _ => {
                let sum = vaddq_u64(vextq_u64::<1>(initial, initial), ab);
                let mid = vsha512hq_u64(sum, vextq_u64::<1>(gh, ab), vextq_u64::<1>(ef, gh));
                ab = vsha512h2q_u64(mid, ef, cd);
                ef = vaddq_u64(ef, mid);
            }
        }
    }
    // SAFETY: Four aligned, exclusive sixteen-byte stores cover this owner.
    unsafe {
        vst1q_u64(scratch.vectors.as_mut_ptr().cast(), vaddq_u64(ab, saved_ab));
        vst1q_u64(
            scratch.vectors.as_mut_ptr().add(16).cast(),
            vaddq_u64(cd, saved_cd),
        );
        vst1q_u64(
            scratch.vectors.as_mut_ptr().add(32).cast(),
            vaddq_u64(ef, saved_ef),
        );
        vst1q_u64(
            scratch.vectors.as_mut_ptr().add(48).cast(),
            vaddq_u64(gh, saved_gh),
        );
    }
    for i in 0..8 {
        let value = read64(&scratch.vectors, i);
        // vst1q_u64 stored native bytes; undo read64's BE interpretation
        // before writing the external big-endian chaining state.
        write64(
            state,
            i,
            if cfg!(target_endian = "little") {
                value.swap_bytes()
            } else {
                value
            },
        );
    }
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
