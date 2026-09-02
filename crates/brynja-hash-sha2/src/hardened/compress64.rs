use crate::compress64;

use super::owner::HardenedSha2Owner;

pub(crate) fn compress(owner: &mut HardenedSha2Owner) {
    for index in 0_usize..16 {
        let start = index.saturating_mul(8);
        let word = read64(&owner.block_copy, start);
        write64(&mut owner.message_schedule, start, word);
    }
    for index in 16_usize..80 {
        let value = compress64::small_sigma1(schedule(owner, index.saturating_sub(2)))
            .wrapping_add(schedule(owner, index.saturating_sub(7)))
            .wrapping_add(compress64::small_sigma0(schedule(
                owner,
                index.saturating_sub(15),
            )))
            .wrapping_add(schedule(owner, index.saturating_sub(16)));
        write64(&mut owner.message_schedule, index.saturating_mul(8), value);
    }

    let mut a = state(owner, 0);
    let mut b = state(owner, 1);
    let mut c = state(owner, 2);
    let mut d = state(owner, 3);
    let mut e = state(owner, 4);
    let mut f = state(owner, 5);
    let mut g = state(owner, 6);
    let mut h = state(owner, 7);
    for index in 0_usize..80 {
        let first = h
            .wrapping_add(compress64::big_sigma1(e))
            .wrapping_add(compress64::choose(e, f, g))
            .wrapping_add(compress64::round_constant(index))
            .wrapping_add(schedule(owner, index));
        let second = compress64::big_sigma0(a).wrapping_add(compress64::majority(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    for (index, value) in [a, b, c, d, e, f, g, h].into_iter().enumerate() {
        write_state(owner, index, state(owner, index).wrapping_add(value));
    }
    owner.message_schedule.fill(0);
}

fn state(owner: &HardenedSha2Owner, index: usize) -> u64 {
    read64(&owner.chaining_state, index.saturating_mul(8))
}

fn write_state(owner: &mut HardenedSha2Owner, index: usize, word: u64) {
    write64(&mut owner.chaining_state, index.saturating_mul(8), word);
}

fn schedule(owner: &HardenedSha2Owner, index: usize) -> u64 {
    read64(&owner.message_schedule, index.saturating_mul(8))
}

fn read64(bytes: &[u8], start: usize) -> u64 {
    let Some(window) = bytes.get(start..start.saturating_add(8)) else {
        return 0;
    };
    let Ok(array) = <[u8; 8]>::try_from(window) else {
        return 0;
    };
    u64::from_be_bytes(array)
}

fn write64(bytes: &mut [u8], start: usize, word: u64) {
    let Some(window) = bytes.get_mut(start..start.saturating_add(8)) else {
        return;
    };
    window.copy_from_slice(&word.to_be_bytes());
}
