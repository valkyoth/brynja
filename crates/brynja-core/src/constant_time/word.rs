use super::{Choice, ConditionalSelect, ConditionalSwap, ConstantTimeEq};

macro_rules! implement_word {
    ($word:ty, $select:ident) => {
        impl ConstantTimeEq for $word {
            #[inline(always)]
            fn ct_eq(&self, other: &Self) -> Choice {
                self.to_ne_bytes().ct_eq(&other.to_ne_bytes())
            }
        }

        impl ConditionalSelect for $word {
            #[inline(always)]
            fn conditional_select(if_false: &Self, if_true: &Self, choice: Choice) -> Self {
                choice.mask().$select(*if_false, *if_true)
            }
        }

        impl ConditionalSwap for $word {
            #[inline(always)]
            fn conditional_swap(left: &mut Self, right: &mut Self, choice: Choice) {
                let selected = *left ^ Self::conditional_select(left, right, choice);
                *left ^= selected;
                *right ^= selected;
            }
        }
    };
}

implement_word!(u8, select_u8);
implement_word!(u16, select_u16);
implement_word!(u32, select_u32);
implement_word!(u64, select_u64);
implement_word!(u128, select_u128);
implement_word!(usize, select_usize);
