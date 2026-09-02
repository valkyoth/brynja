use crate::keccak::{PI_DESTINATIONS, ROTATION_OFFSETS, ROUND_CONSTANTS};

use super::owner::HardenedFips202Owner;

pub(crate) fn permute<const RATE: usize>(owner: &mut HardenedFips202Owner<RATE>) {
    for constant in ROUND_CONSTANTS {
        theta(owner);
        rho_pi(owner);
        chi(owner);
        write_lane(owner, 0, read_lane(owner, 0) ^ constant);
    }
    owner.wipe_permutation_scratch();
}

fn theta<const RATE: usize>(owner: &mut HardenedFips202Owner<RATE>) {
    for x in 0_usize..5 {
        let mut parity = 0_u64;
        for y in 0_usize..5 {
            parity ^= read_lane(owner, x.saturating_add(y.saturating_mul(5)));
        }
        write_word(&mut owner.permutation_columns, x, parity);
    }
    for x in 0_usize..5 {
        let left = read_word(&owner.permutation_columns, x.saturating_add(4) % 5);
        let right = read_word(&owner.permutation_columns, x.saturating_add(1) % 5).rotate_left(1);
        write_word(&mut owner.permutation_theta, x, left ^ right);
    }
    for index in 0_usize..25 {
        let value = read_lane(owner, index) ^ read_word(&owner.permutation_theta, index % 5);
        write_lane(owner, index, value);
    }
}

fn rho_pi<const RATE: usize>(owner: &mut HardenedFips202Owner<RATE>) {
    for index in 0_usize..25 {
        let rotation = ROTATION_OFFSETS.get(index).copied().unwrap_or(0);
        let destination = PI_DESTINATIONS.get(index).copied().unwrap_or(0);
        let value = read_lane(owner, index).rotate_left(rotation);
        write_word(&mut owner.permutation_rearranged, destination, value);
    }
}

fn chi<const RATE: usize>(owner: &mut HardenedFips202Owner<RATE>) {
    for row in 0_usize..5 {
        let first = row.saturating_mul(5);
        let b0 = read_word(&owner.permutation_rearranged, first);
        let b1 = read_word(&owner.permutation_rearranged, first.saturating_add(1));
        let b2 = read_word(&owner.permutation_rearranged, first.saturating_add(2));
        let b3 = read_word(&owner.permutation_rearranged, first.saturating_add(3));
        let b4 = read_word(&owner.permutation_rearranged, first.saturating_add(4));
        write_lane(owner, first, b0 ^ ((!b1) & b2));
        write_lane(owner, first.saturating_add(1), b1 ^ ((!b2) & b3));
        write_lane(owner, first.saturating_add(2), b2 ^ ((!b3) & b4));
        write_lane(owner, first.saturating_add(3), b3 ^ ((!b4) & b0));
        write_lane(owner, first.saturating_add(4), b4 ^ ((!b0) & b1));
    }
}

fn read_lane<const RATE: usize>(owner: &HardenedFips202Owner<RATE>, index: usize) -> u64 {
    read_word(&owner.sponge_lanes, index)
}

fn write_lane<const RATE: usize>(owner: &mut HardenedFips202Owner<RATE>, index: usize, value: u64) {
    write_word(&mut owner.sponge_lanes, index, value);
}

fn read_word(bytes: &[u8], index: usize) -> u64 {
    let Some(start) = index.checked_mul(8) else {
        return 0;
    };
    let Some(end) = start.checked_add(8) else {
        return 0;
    };
    let Some(window) = bytes.get(start..end) else {
        return 0;
    };
    let mut value = 0_u64;
    for (offset, byte) in window.iter().enumerate() {
        let shift = byte_shift(offset);
        value |= u64::from(*byte) << shift;
    }
    value
}

fn write_word(bytes: &mut [u8], index: usize, value: u64) {
    let Some(start) = index.checked_mul(8) else {
        return;
    };
    let Some(end) = start.checked_add(8) else {
        return;
    };
    let Some(window) = bytes.get_mut(start..end) else {
        return;
    };
    for (offset, byte) in window.iter_mut().enumerate() {
        let shift = byte_shift(offset);
        *byte = u8::try_from((value >> shift) & u64::from(u8::MAX)).unwrap_or_default();
    }
}

fn byte_shift(offset: usize) -> u32 {
    u32::try_from(offset)
        .unwrap_or_default()
        .checked_mul(8)
        .unwrap_or_default()
}
