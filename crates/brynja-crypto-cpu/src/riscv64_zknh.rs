#![allow(unsafe_code)]

use core::arch::asm;

use crate::sha256_schedule::ROUND_CONSTANTS;
use crate::sha512_schedule::{ROUND_CONSTANTS as ROUND_CONSTANTS_512, expanded as expanded512};

pub(crate) fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: The only safe caller holds a thread-bound session whose direct
    // startup KAT executed this same function after complete compile-time
    // `zknh` proof or explicit evidence-runner attestation. The inline
    // instructions touch registers only; Rust owns both exact-size arrays.
    unsafe { compress_zknh(state, block) }
}

#[target_feature(enable = "zknh")]
unsafe fn compress_zknh(state: &mut [u32; 8], block: &[u8; 64]) {
    let schedule = expanded(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let saved = *state;

    for (word, constant) in schedule.iter().zip(ROUND_CONSTANTS.iter()) {
        let choice = (e & f) ^ ((!e) & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let first = h
            .wrapping_add(sum1(e))
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(*word);
        let second = sum0(a).wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }

    *state = [
        saved[0].wrapping_add(a),
        saved[1].wrapping_add(b),
        saved[2].wrapping_add(c),
        saved[3].wrapping_add(d),
        saved[4].wrapping_add(e),
        saved[5].wrapping_add(f),
        saved[6].wrapping_add(g),
        saved[7].wrapping_add(h),
    ];
}

fn expanded(block: &[u8; 64]) -> [u32; 64] {
    let mut words = [0_u32; 64];
    for (word, bytes) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
        if let [first, second, third, fourth] = bytes {
            *word = u32::from_be_bytes([*first, *second, *third, *fourth]);
        }
    }
    for index in 16_usize..64 {
        let first = sig1(words.get(index - 2).copied().unwrap_or(0));
        let second = words.get(index - 7).copied().unwrap_or(0);
        let third = sig0(words.get(index - 15).copied().unwrap_or(0));
        let fourth = words.get(index - 16).copied().unwrap_or(0);
        if let Some(target) = words.get_mut(index) {
            *target = first
                .wrapping_add(second)
                .wrapping_add(third)
                .wrapping_add(fourth);
        }
    }
    words
}

#[inline(always)]
fn sig0(value: u32) -> u32 {
    let output: usize;
    // SAFETY: `compress_zknh` establishes Zknh before this private helper can
    // execute. The instruction has register-only inputs and output.
    unsafe {
        asm!("sha256sig0 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u32
}

#[inline(always)]
fn sig1(value: u32) -> u32 {
    let output: usize;
    // SAFETY: The private caller has established the same Zknh precondition.
    unsafe {
        asm!("sha256sig1 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u32
}

#[inline(always)]
fn sum0(value: u32) -> u32 {
    let output: usize;
    // SAFETY: The private caller has established the same Zknh precondition.
    unsafe {
        asm!("sha256sum0 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u32
}

#[inline(always)]
fn sum1(value: u32) -> u32 {
    let output: usize;
    // SAFETY: The private caller has established the same Zknh precondition.
    unsafe {
        asm!("sha256sum1 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u32
}

pub(crate) fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    // SAFETY: Static Zknh proof gates this function and the caller's direct KAT
    // executes it before caller data. Instructions use registers only; Rust
    // retains exclusive ownership of both exact-size arrays.
    unsafe { compress_zknh512(state, block) }
}

#[target_feature(enable = "zknh")]
unsafe fn compress_zknh512(state: &mut [u64; 8], block: &[u8; 128]) {
    let schedule = expanded512(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let saved = *state;

    for (word, constant) in schedule.iter().zip(ROUND_CONSTANTS_512.iter()) {
        let choice = (e & f) ^ ((!e) & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let first = h
            .wrapping_add(sum1_512(e))
            .wrapping_add(choice)
            .wrapping_add(*constant)
            .wrapping_add(*word);
        let second = sum0_512(a).wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }

    *state = [
        saved[0].wrapping_add(a),
        saved[1].wrapping_add(b),
        saved[2].wrapping_add(c),
        saved[3].wrapping_add(d),
        saved[4].wrapping_add(e),
        saved[5].wrapping_add(f),
        saved[6].wrapping_add(g),
        saved[7].wrapping_add(h),
    ];
}

#[inline(always)]
fn sum0_512(value: u64) -> u64 {
    let output: usize;
    // SAFETY: The private caller has established Zknh. The instruction has
    // register-only inputs and output.
    unsafe {
        asm!("sha512sum0 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u64
}

#[inline(always)]
fn sum1_512(value: u64) -> u64 {
    let output: usize;
    // SAFETY: The private caller has established Zknh. The instruction has
    // register-only inputs and output.
    unsafe {
        asm!("sha512sum1 {output}, {input}", input = in(reg) value as usize,
            output = lateout(reg) output, options(pure, nomem, nostack));
    }
    output as u64
}
