use super::{Choice, ConditionalSelect, ConditionalSwap, ConstantTimeEq};

impl<const N: usize> ConstantTimeEq for [u8; N] {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut difference = 0_u8;
        for (left, right) in self.iter().zip(other.iter()) {
            difference |= *left ^ *right;
        }
        Choice::from_zero_test(difference)
    }
}

impl<const N: usize> ConditionalSelect for [u8; N] {
    #[inline(always)]
    fn conditional_select(if_false: &Self, if_true: &Self, choice: Choice) -> Self {
        let mask = choice.mask();
        let mut output = [0_u8; N];
        for ((destination, false_byte), true_byte) in
            output.iter_mut().zip(if_false.iter()).zip(if_true.iter())
        {
            *destination = mask.select_u8(*false_byte, *true_byte);
        }
        output
    }
}

impl<const N: usize> ConditionalSwap for [u8; N] {
    #[inline(always)]
    fn conditional_swap(left: &mut Self, right: &mut Self, choice: Choice) {
        let mask = choice.mask().u8();
        for (left_byte, right_byte) in left.iter_mut().zip(right.iter_mut()) {
            let selected = (*left_byte ^ *right_byte) & mask;
            *left_byte ^= selected;
            *right_byte ^= selected;
        }
    }
}
