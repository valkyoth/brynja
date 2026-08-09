//! Fixed-width constant-time foundations.
//!
//! The operations in this module use fixed-work bitwise formulas and
//! compile-time array lengths. Source structure alone cannot prove the final
//! machine code constant-time on every compiler and target. Each later
//! cryptographic implementation must retain emitted-code and timing evidence
//! for the exact operations it uses.

mod barrier;
mod bytes;
mod choice;
mod word;

pub use barrier::compiler_barrier;
pub use choice::{Choice, CtMask};

/// Equality whose work does not depend on the compared value.
pub trait ConstantTimeEq {
    /// Compares two fixed-width values without early exit.
    fn ct_eq(&self, other: &Self) -> Choice;
}

/// Branch-free selection between two fixed-width values.
pub trait ConditionalSelect: Sized {
    /// Selects `if_true` when `choice` is true and `if_false` otherwise.
    #[must_use]
    fn conditional_select(if_false: &Self, if_true: &Self, choice: Choice) -> Self;
}

/// Branch-free conditional exchange of two fixed-width values.
pub trait ConditionalSwap {
    /// Exchanges `left` and `right` when `choice` is true.
    fn conditional_swap(left: &mut Self, right: &mut Self, choice: Choice);
}
