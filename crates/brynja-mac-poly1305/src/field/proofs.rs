//! Development-only proof harnesses. No checker dependency in ordinary builds.
use super::*;

const B: u64 = 1 << 26;

// Represent up to 192 bits as hi:lo, independently of the five-limb carry loop.
fn weighted(words: [u64; 5]) -> (u64, u128) {
    let (mut hi, mut lo) = (0u64, 0u128);
    for (word, shift) in words.into_iter().zip([0u32, 26, 52, 78, 104]) {
        let word = u128::from(word);
        let (sum, carry) = lo.overflowing_add(word << shift);
        lo = sum;
        hi += u64::from(carry);
        if shift != 0 {
            hi += (word >> (128 - shift)) as u64;
        }
    }
    (hi, lo)
}

// Precondition: n < 2p. Subtract p = 3:ffff...fffb once, if needed.
fn canonical(hi: u64, lo: u128) -> (u64, u128) {
    const P_LO: u128 = u128::MAX - 4;
    if hi > 3 || (hi == 3 && lo >= P_LO) {
        let (diff, borrow) = lo.overflowing_sub(P_LO);
        (hi - 3 - u64::from(borrow), diff)
    } else {
        (hi, lo)
    }
}

#[kani::proof]
#[kani::unwind(18)]
fn columns_reduce_mod_p_without_losing_final_carry() {
    // Each of the five terms is < 2B * 5B, hence a column is < 50B^2
    // (< 2^58). Admit an even larger independent range for every column.
    let columns: [u64; 5] = kani::any();
    let columns = columns.map(|n| n & ((1 << 58) - 1));
    let (hi, lo) = weighted(columns);
    // Split at bit 130, then substitute 5 for 2^130 just once. The result
    // is < 2p and can be canonicalized independently by a wide subtraction.
    let (lo, carry) = lo.overflowing_add(5 * u128::from(hi >> 2));
    let reference = canonical((hi & 3) + u64::from(carry), lo);
    let reduced = reduce(columns);
    assert!(reduced.iter().all(|&v| v < B));
    let (hi, lo) = weighted(reduced);
    assert_eq!(canonical(hi, lo), reference);
}

#[kani::proof]
#[kani::unwind(18)]
fn final_tag_canonicalizes_before_pad_addition() {
    let h = kani::any::<[u64; 5]>().map(|v| v & MASK);
    let pad: [u8; 16] = kani::any();
    let (hi, lo) = weighted(h);
    let (_, canonical_low) = canonical(hi, lo);
    let expected = canonical_low.wrapping_add(u128::from_le_bytes(pad));
    assert_eq!(
        finish(&h.map(u64::to_le_bytes), &pad),
        expected.to_le_bytes()
    );
}

#[kani::proof]
#[kani::unwind(18)]
fn little_endian_key_clamp_matches_wire_rules() {
    let raw: [u8; 16] = kani::any();
    let mut masked = raw;
    for i in [3, 7, 11, 15] {
        masked[i] &= 15;
    }
    for i in [4, 8, 12] {
        masked[i] &= 252;
    }
    assert_eq!(
        weighted(clamped_limbs(&raw)),
        (0, u128::from_le_bytes(masked))
    );
}

#[kani::proof]
#[kani::unwind(18)]
fn admitted_block_products_fit_and_reestablish_limb_bounds() {
    let mut h = kani::any::<[u64; 5]>().map(|x| (x & MASK).to_le_bytes());
    let raw: [u8; 16] = kani::any();
    absorb(&mut h, &raw, &kani::any(), kani::any());
    assert!(h.iter().all(|v| u64::from_le_bytes(*v) < B));
}

#[kani::proof]
#[kani::unwind(18)]
fn all_basis_products_land_in_the_correct_column() {
    let (i, j) = (kani::any::<usize>(), kani::any::<usize>());
    kani::assume(i < 5 && j < 5);
    let mut left = [0; 5];
    let mut right = [0; 5];
    left[i] = 1;
    right[j] = 1;
    let mut expected = [0; 5];
    expected[(i + j) % 5] = if i + j >= 5 { 5 } else { 1 };
    for (actual, want) in columns(left, right).into_iter().zip(expected) {
        assert_eq!(actual, want);
    }
}
