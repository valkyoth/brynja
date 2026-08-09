//! Exhaustive and boundary tests for the v0.12 constant-time foundation.

use core::mem::size_of;

use brynja_core::{
    Choice, ConditionalSelect, ConditionalSwap, ConstantTimeEq, CtMask, compiler_barrier,
};

#[test]
fn choice_normalization_and_logic_are_exhaustive() {
    for raw in u8::MIN..=u8::MAX {
        let choice = Choice::from_lsb(raw);
        assert_eq!(choice.expose_public(), raw & 1 == 1);
        assert_eq!(choice.not().expose_public(), raw & 1 == 0);
    }

    for left in u8::MIN..=1 {
        for right in u8::MIN..=1 {
            let left_choice = Choice::from_lsb(left);
            let right_choice = Choice::from_lsb(right);
            assert_eq!(
                left_choice.and(right_choice).expose_public(),
                left & right == 1
            );
            assert_eq!(
                left_choice.or(right_choice).expose_public(),
                left | right == 1
            );
            assert_eq!(
                left_choice.xor(right_choice).expose_public(),
                left ^ right == 1
            );
        }
    }
}

#[test]
fn masks_select_every_byte_pair() {
    let false_mask = Choice::FALSE.mask();
    let true_mask = Choice::TRUE.mask();
    for left in u8::MIN..=u8::MAX {
        for right in u8::MIN..=u8::MAX {
            assert_eq!(false_mask.select_u8(left, right), left);
            assert_eq!(true_mask.select_u8(left, right), right);
        }
    }
}

#[test]
fn word_equality_is_exhaustive_for_bytes_and_covers_wide_boundaries() {
    for left in u8::MIN..=u8::MAX {
        for right in u8::MIN..=u8::MAX {
            assert_eq!(left.ct_eq(&right).expose_public(), left == right);
        }
    }

    let words16 = [u16::MIN, 1, 255, 256, u16::MAX - 1, u16::MAX];
    let words32 = [u32::MIN, 1, 65_535, 65_536, u32::MAX - 1, u32::MAX];
    let words64 = [u64::MIN, 1, u64::from(u32::MAX), u64::MAX - 1, u64::MAX];
    let words128 = [u128::MIN, 1, u128::from(u64::MAX), u128::MAX - 1, u128::MAX];
    let words_usize = [usize::MIN, 1, usize::MAX - 1, usize::MAX];

    check_pairs(&words16);
    check_pairs(&words32);
    check_pairs(&words64);
    check_pairs(&words128);
    check_pairs(&words_usize);
}

fn check_pairs<T>(values: &[T])
where
    T: ConstantTimeEq + PartialEq,
{
    for left in values {
        for right in values {
            assert_eq!(left.ct_eq(right).expose_public(), left == right);
        }
    }
}

#[test]
fn every_word_selects_and_swaps_for_both_choices() {
    check_select_swap(0_u8, u8::MAX);
    check_select_swap(0_u16, u16::MAX);
    check_select_swap(0_u32, u32::MAX);
    check_select_swap(0_u64, u64::MAX);
    check_select_swap(0_u128, u128::MAX);
    check_select_swap(0_usize, usize::MAX);
}

fn check_select_swap<T>(left: T, right: T)
where
    T: ConditionalSelect + ConditionalSwap + Copy + PartialEq + core::fmt::Debug,
{
    assert_eq!(T::conditional_select(&left, &right, Choice::FALSE), left);
    assert_eq!(T::conditional_select(&left, &right, Choice::TRUE), right);

    let mut false_left = left;
    let mut false_right = right;
    T::conditional_swap(&mut false_left, &mut false_right, Choice::FALSE);
    assert_eq!(false_left, left);
    assert_eq!(false_right, right);

    let mut true_left = left;
    let mut true_right = right;
    T::conditional_swap(&mut true_left, &mut true_right, Choice::TRUE);
    assert_eq!(true_left, right);
    assert_eq!(true_right, left);
}

#[test]
fn fixed_arrays_compare_every_mismatch_position_without_early_exit() {
    check_array_mismatches([0_u8; 0]);
    check_array_mismatches([0_u8; 1]);
    check_array_mismatches([0_u8; 2]);
    check_array_mismatches([0_u8; 16]);
    check_array_mismatches([0_u8; 32]);
}

fn check_array_mismatches<const N: usize>(baseline: [u8; N]) {
    assert!(baseline.ct_eq(&baseline).expose_public());
    for position in 0..N {
        let mut changed = baseline;
        for (index, byte) in changed.iter_mut().enumerate() {
            *byte = u8::from(index == position);
        }
        assert!(!baseline.ct_eq(&changed).expose_public());
        assert!(!changed.ct_eq(&baseline).expose_public());
    }
}

#[test]
fn fixed_arrays_select_and_swap_without_touching_unselected_values() {
    let left = [0x11_u8; 32];
    let right = [0xee_u8; 32];
    assert_eq!(
        <[u8; 32]>::conditional_select(&left, &right, Choice::FALSE),
        left
    );
    assert_eq!(
        <[u8; 32]>::conditional_select(&left, &right, Choice::TRUE),
        right
    );

    let mut false_left = left;
    let mut false_right = right;
    <[u8; 32]>::conditional_swap(&mut false_left, &mut false_right, Choice::FALSE);
    assert_eq!(false_left, left);
    assert_eq!(false_right, right);

    let mut true_left = left;
    let mut true_right = right;
    <[u8; 32]>::conditional_swap(&mut true_left, &mut true_right, Choice::TRUE);
    assert_eq!(true_left, right);
    assert_eq!(true_right, left);
}

#[test]
fn barrier_preserves_values_and_choice_mask_representations_are_minimal() {
    assert_eq!(compiler_barrier(0_u128), 0);
    assert_eq!(compiler_barrier(u128::MAX), u128::MAX);
    assert!(compiler_barrier(Choice::TRUE).expose_public());
    assert_eq!(size_of::<Choice>(), 1);
    assert_eq!(size_of::<CtMask>(), 1);
}
