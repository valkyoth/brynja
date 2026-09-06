#![allow(unsafe_code)]

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// All lanes are reversed: lane 3 is the earliest SHA-1 word.
#[target_feature(enable = "sha,sse2")]
pub(super) unsafe fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let [a, b, c, d, e] = *state;
    let mut abcd = _mm_set_epi32(a as i32, b as i32, c as i32, d as i32);
    let mut previous = abcd;
    let mut messages = [_mm_setzero_si128(); 20];
    for (message, bytes) in messages.iter_mut().zip(block.chunks_exact(16)) {
        let mut words = [0; 4];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            if let [a, b, c, d] = bytes {
                *word = u32::from_be_bytes([*a, *b, *c, *d]);
            }
        }
        let [a, b, c, d] = words;
        *message = _mm_set_epi32(a as i32, b as i32, c as i32, d as i32);
    }
    for group in 4_usize..20 {
        // Four-message recurrence implements ROTL1(W[t-3]^W[t-8]^W[t-14]^W[t-16]).
        let window = messages
            .get(group.saturating_sub(4)..group)
            .unwrap_or_default();
        if let [m0, m1, m2, m3] = window {
            let next = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(*m0, *m1), *m2), *m3);
            if let Some(destination) = messages.get_mut(group) {
                *destination = next;
            }
        }
    }
    for (group, message) in messages.into_iter().enumerate() {
        let input = if group == 0 {
            _mm_add_epi32(message, _mm_set_epi32(e as i32, 0, 0, 0))
        } else {
            _mm_sha1nexte_epu32(previous, message)
        };
        previous = abcd;
        abcd = match group {
            0..=4 => _mm_sha1rnds4_epu32::<0>(abcd, input),
            5..=9 => _mm_sha1rnds4_epu32::<1>(abcd, input),
            10..=14 => _mm_sha1rnds4_epu32::<2>(abcd, input),
            _ => _mm_sha1rnds4_epu32::<3>(abcd, input),
        };
    }
    let mut words = [0_i32; 4];
    // SAFETY: words is one live exclusive 16-byte destination; unaligned stores
    // accept its alignment and write no bytes outside this exact array.
    unsafe {
        _mm_storeu_si128(words.as_mut_ptr().cast(), abcd);
    }
    let [out_d, out_c, out_b, out_a] = words.map(i32::cast_unsigned);
    let final_e = _mm_cvtsi128_si32(_mm_shuffle_epi32::<0xff>(previous))
        .cast_unsigned()
        .rotate_left(30);
    *state = [
        a.wrapping_add(out_a),
        b.wrapping_add(out_b),
        c.wrapping_add(out_c),
        d.wrapping_add(out_d),
        e.wrapping_add(final_e),
    ];
}
