//! Emitted-code roots for the v0.12.0 constant-time foundation.

#![no_std]

use brynja_core::{Choice, ConditionalSelect, ConditionalSwap, ConstantTimeEq, compiler_barrier};

macro_rules! word_roots {
    ($equal:ident, $select:ident, $swap:ident, $word:ty) => {
        /// Roots fixed-width word equality in emitted code.
        #[inline(never)]
        pub fn $equal(left: $word, right: $word) -> Choice {
            left.ct_eq(&right)
        }

        /// Roots fixed-width word selection in emitted code.
        #[inline(never)]
        pub fn $select(left: $word, right: $word, choice: Choice) -> $word {
            <$word>::conditional_select(&left, &right, choice)
        }

        /// Roots fixed-width word exchange in emitted code.
        #[inline(never)]
        pub fn $swap(left: &mut $word, right: &mut $word, choice: Choice) {
            <$word>::conditional_swap(left, right, choice);
        }
    };
}

word_roots!(equal_u8, select_u8, swap_u8, u8);
word_roots!(equal_u16, select_u16, swap_u16, u16);
word_roots!(equal_u32, select_u32, swap_u32, u32);
word_roots!(equal_u64, select_u64, swap_u64, u64);
word_roots!(equal_u128, select_u128, swap_u128, u128);
word_roots!(equal_usize, select_usize, swap_usize, usize);

/// Roots fixed-width byte-array equality in emitted code.
#[inline(never)]
pub fn equal_bytes(left: &[u8; 32], right: &[u8; 32]) -> Choice {
    left.ct_eq(right)
}

/// Roots fixed-width byte-array selection in emitted code.
#[inline(never)]
pub fn select_bytes(left: &[u8; 32], right: &[u8; 32], choice: Choice) -> [u8; 32] {
    <[u8; 32]>::conditional_select(left, right, choice)
}

/// Roots fixed-width byte-array exchange in emitted code.
#[inline(never)]
pub fn swap_bytes(left: &mut [u8; 32], right: &mut [u8; 32], choice: Choice) {
    <[u8; 32]>::conditional_swap(left, right, choice);
}

/// Roots the explicit compiler barrier in emitted code.
#[inline(never)]
pub fn barrier_word(value: u64) -> u64 {
    compiler_barrier(value)
}
