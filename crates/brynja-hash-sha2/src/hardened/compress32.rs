use crate::compress;

use super::owner::HardenedSha2Owner;

pub(crate) fn compress(owner: &mut HardenedSha2Owner) {
    for index in 0_usize..16 {
        let start = index.saturating_mul(4);
        let word = read32(&owner.block_copy, start);
        write32(&mut owner.message_schedule, start, word);
    }
    for index in 16_usize..64 {
        let value = compress::small_sigma1(schedule(owner, index.saturating_sub(2)))
            .wrapping_add(schedule(owner, index.saturating_sub(7)))
            .wrapping_add(compress::small_sigma0(schedule(
                owner,
                index.saturating_sub(15),
            )))
            .wrapping_add(schedule(owner, index.saturating_sub(16)));
        write32(&mut owner.message_schedule, index.saturating_mul(4), value);
    }

    let mut a = state(owner, 0);
    let mut b = state(owner, 1);
    let mut c = state(owner, 2);
    let mut d = state(owner, 3);
    let mut e = state(owner, 4);
    let mut f = state(owner, 5);
    let mut g = state(owner, 6);
    let mut h = state(owner, 7);
    for index in 0_usize..64 {
        let first = h
            .wrapping_add(compress::big_sigma1(e))
            .wrapping_add(compress::choose(e, f, g))
            .wrapping_add(compress::round_constant(index))
            .wrapping_add(schedule(owner, index));
        let second = compress::big_sigma0(a).wrapping_add(compress::majority(a, b, c));
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

fn state(owner: &HardenedSha2Owner, index: usize) -> u32 {
    read32(&owner.chaining_state, index.saturating_mul(4))
}

fn write_state(owner: &mut HardenedSha2Owner, index: usize, word: u32) {
    write32(&mut owner.chaining_state, index.saturating_mul(4), word);
}

fn schedule(owner: &HardenedSha2Owner, index: usize) -> u32 {
    read32(&owner.message_schedule, index.saturating_mul(4))
}

fn read32(bytes: &[u8], start: usize) -> u32 {
    let Some(window) = bytes.get(start..start.saturating_add(4)) else {
        return 0;
    };
    let Ok(array) = <[u8; 4]>::try_from(window) else {
        return 0;
    };
    u32::from_be_bytes(array)
}

fn write32(bytes: &mut [u8], start: usize, word: u32) {
    let Some(window) = bytes.get_mut(start..start.saturating_add(4)) else {
        return;
    };
    window.copy_from_slice(&word.to_be_bytes());
}
