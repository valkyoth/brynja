#![allow(unsafe_code)]

use core::arch::aarch64::*;

#[target_feature(enable = "neon,sha2")]
pub(super) unsafe fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let [a, b, c, d, e] = *state;
    let initial = [a, b, c, d];
    // SAFETY: initial contains exactly the four live u32 lanes read by vld1q.
    let mut abcd = unsafe { vld1q_u32(initial.as_ptr()) };
    let mut hash_e = e;
    let mut messages = [vdupq_n_u32(0); 20];
    for (message, bytes) in messages.iter_mut().zip(block.chunks_exact(16)) {
        let mut words = [0; 4];
        for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            if let [a, b, c, d] = bytes {
                *word = u32::from_be_bytes([*a, *b, *c, *d]);
            }
        }
        // SAFETY: words is a live, initialized, exactly four-lane array.
        *message = unsafe { vld1q_u32(words.as_ptr()) };
    }
    for group in 4_usize..20 {
        let window = messages
            .get(group.saturating_sub(4)..group)
            .unwrap_or_default();
        if let [m0, m1, m2, m3] = window {
            let next = vsha1su1q_u32(vsha1su0q_u32(*m0, *m1, *m2), *m3);
            if let Some(destination) = messages.get_mut(group) {
                *destination = next;
            }
        }
    }
    for (group, message) in messages.into_iter().enumerate() {
        let next_e = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
        abcd = match group {
            0..=4 => vsha1cq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x5a827999))),
            5..=9 => vsha1pq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x6ed9eba1))),
            10..=14 => vsha1mq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x8f1bbcdc))),
            _ => vsha1pq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0xca62c1d6))),
        };
        hash_e = next_e;
    }
    let mut words = [0; 4];
    // SAFETY: words has exactly four live, exclusive, writable u32 lanes.
    unsafe {
        vst1q_u32(words.as_mut_ptr(), abcd);
    }
    let [out_a, out_b, out_c, out_d] = words;
    *state = [
        a.wrapping_add(out_a),
        b.wrapping_add(out_b),
        c.wrapping_add(out_c),
        d.wrapping_add(out_d),
        e.wrapping_add(hash_e),
    ];
}

/// Hardened schedule and store staging never use unowned local arrays.
#[cfg(feature = "hardened-execution")]
#[target_feature(enable = "neon,sha2")]
pub(super) unsafe fn compress_secret(
    owner: &mut crate::owner::Sha1Owner,
    scratch: &mut super::Scratch,
) -> Result<(), super::Sha1BackendError> {
    use super::Sha1BackendError as Error;
    use crate::hardened_execution::storage::{add, read, vector, vector_mut};
    let mut abcd = vdupq_n_u32(0);
    abcd = vsetq_lane_u32::<0>(read(&owner.chaining_state, 0)?, abcd);
    abcd = vsetq_lane_u32::<1>(read(&owner.chaining_state, 1)?, abcd);
    abcd = vsetq_lane_u32::<2>(read(&owner.chaining_state, 2)?, abcd);
    abcd = vsetq_lane_u32::<3>(read(&owner.chaining_state, 3)?, abcd);
    let mut hash_e = read(&owner.chaining_state, 4)?;
    for group in 0_usize..4 {
        let input = vector(&owner.block, group)?;
        let mut message = vdupq_n_u32(0);
        message = vsetq_lane_u32::<0>(read(input, 0)?, message);
        message = vsetq_lane_u32::<1>(read(input, 1)?, message);
        message = vsetq_lane_u32::<2>(read(input, 2)?, message);
        message = vsetq_lane_u32::<3>(read(input, 3)?, message);
        let destination = vector_mut(&mut owner.schedule, group)?;
        // SAFETY: Exactly 16 exclusive initialized owner bytes, byte-aligned store.
        unsafe {
            vst1q_u8(destination.as_mut_ptr(), vreinterpretq_u8_u32(message));
        }
    }
    for group in 4_usize..20 {
        let m0 = vector(
            &owner.schedule,
            group.checked_sub(4).ok_or(Error::Quarantined)?,
        )?;
        let m1 = vector(
            &owner.schedule,
            group.checked_sub(3).ok_or(Error::Quarantined)?,
        )?;
        let m2 = vector(
            &owner.schedule,
            group.checked_sub(2).ok_or(Error::Quarantined)?,
        )?;
        let m3 = vector(
            &owner.schedule,
            group.checked_sub(1).ok_or(Error::Quarantined)?,
        )?;
        // SAFETY: Four exact initialized 16-byte borrowed schedule regions.
        let message = unsafe {
            vsha1su1q_u32(
                vsha1su0q_u32(
                    vreinterpretq_u32_u8(vld1q_u8(m0.as_ptr())),
                    vreinterpretq_u32_u8(vld1q_u8(m1.as_ptr())),
                    vreinterpretq_u32_u8(vld1q_u8(m2.as_ptr())),
                ),
                vreinterpretq_u32_u8(vld1q_u8(m3.as_ptr())),
            )
        };
        let destination = vector_mut(&mut owner.schedule, group)?;
        // SAFETY: Exactly 16 exclusive owner bytes; byte-aligned store.
        unsafe {
            vst1q_u8(destination.as_mut_ptr(), vreinterpretq_u8_u32(message));
        }
    }
    for group in 0..20 {
        let source = vector(&owner.schedule, group)?;
        // SAFETY: Exactly 16 initialized source-owned schedule bytes.
        let message = unsafe { vreinterpretq_u32_u8(vld1q_u8(source.as_ptr())) };
        let next_e = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
        abcd = match group {
            0..=4 => vsha1cq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x5a827999))),
            5..=9 => vsha1pq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x6ed9eba1))),
            10..=14 => vsha1mq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0x8f1bbcdc))),
            _ => vsha1pq_u32(abcd, hash_e, vaddq_u32(message, vdupq_n_u32(0xca62c1d6))),
        };
        hash_e = next_e;
    }
    // SAFETY: Exact live 16-byte destination in the mandatory clearing owner.
    unsafe {
        vst1q_u8(scratch.lanes.as_mut_ptr(), vreinterpretq_u8_u32(abcd));
    }
    add(
        &mut owner.chaining_state,
        0,
        read(&scratch.lanes, 0)?.swap_bytes(),
    )?;
    add(
        &mut owner.chaining_state,
        1,
        read(&scratch.lanes, 1)?.swap_bytes(),
    )?;
    add(
        &mut owner.chaining_state,
        2,
        read(&scratch.lanes, 2)?.swap_bytes(),
    )?;
    add(
        &mut owner.chaining_state,
        3,
        read(&scratch.lanes, 3)?.swap_bytes(),
    )?;
    add(&mut owner.chaining_state, 4, hash_e)?;
    Ok(())
}
