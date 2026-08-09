/// A normalized one-bit decision produced by constant-time operations.
///
/// ```compile_fail
/// let choice = brynja_core::Choice::TRUE;
/// let _ordinary_equality = choice == brynja_core::Choice::FALSE;
/// ```
///
/// ```compile_fail
/// let choice = brynja_core::Choice::TRUE;
/// println!("{choice:?}");
/// ```
//
// Deliberately omit formatting, equality, ordering, and hashing traits. A
// caller must explicitly declassify the final decision before branching.
#[derive(Clone, Copy)]
#[repr(transparent)]
#[must_use = "a constant-time decision must be consumed or explicitly declassified"]
pub struct Choice {
    value: u8,
}

impl Choice {
    /// The normalized false decision.
    pub const FALSE: Self = Self { value: 0 };

    /// The normalized true decision.
    pub const TRUE: Self = Self { value: 1 };

    /// Normalizes the least-significant bit of a public input.
    pub const fn from_lsb(value: u8) -> Self {
        Self { value: value & 1 }
    }

    /// Combines two decisions with logical AND.
    pub const fn and(self, other: Self) -> Self {
        Self::from_lsb(self.value & other.value)
    }

    /// Combines two decisions with logical OR.
    pub const fn or(self, other: Self) -> Self {
        Self::from_lsb(self.value | other.value)
    }

    /// Combines two decisions with logical XOR.
    pub const fn xor(self, other: Self) -> Self {
        Self::from_lsb(self.value ^ other.value)
    }

    /// Inverts this normalized decision.
    pub const fn not(self) -> Self {
        Self::from_lsb(self.value ^ 1)
    }

    /// Expands this decision into an opaque all-zero or all-one mask.
    pub const fn mask(self) -> CtMask {
        CtMask {
            value: 0_u8.wrapping_sub(self.value),
        }
    }

    /// Explicitly declassifies the final decision for public control flow.
    ///
    /// Calling this before all secret comparisons are combined can expose a
    /// partial result through timing. Protocol code should normally call it
    /// once, at the final public accept-or-reject boundary.
    #[must_use]
    pub const fn expose_public(self) -> bool {
        self.value != 0
    }

    pub(super) const fn from_zero_test(value: u8) -> Self {
        let nonzero = (value | value.wrapping_neg()) >> 7;
        Self::from_lsb(nonzero ^ 1)
    }
}

/// An opaque mask whose bits are either all zero or all one.
///
/// ```compile_fail
/// let _forged = brynja_core::CtMask { value: 0x55 };
/// ```
//
// Construction is restricted to normalized `Choice` values. Raw mask bytes
// are not exposed, so the invariant cannot be forged through safe APIs.
#[derive(Clone, Copy)]
#[repr(transparent)]
#[must_use = "a constant-time mask must govern an operation"]
pub struct CtMask {
    value: u8,
}

impl CtMask {
    pub(super) const fn u8(self) -> u8 {
        self.value
    }

    pub(super) fn u16(self) -> u16 {
        0_u16.wrapping_sub(u16::from(self.value >> 7))
    }

    pub(super) fn u32(self) -> u32 {
        0_u32.wrapping_sub(u32::from(self.value >> 7))
    }

    pub(super) fn u64(self) -> u64 {
        0_u64.wrapping_sub(u64::from(self.value >> 7))
    }

    pub(super) fn u128(self) -> u128 {
        0_u128.wrapping_sub(u128::from(self.value >> 7))
    }

    pub(super) fn usize(self) -> usize {
        0_usize.wrapping_sub(usize::from(self.value >> 7))
    }

    /// Selects one byte without exposing the raw mask.
    #[must_use]
    pub const fn select_u8(self, if_false: u8, if_true: u8) -> u8 {
        (if_false & !self.u8()) | (if_true & self.u8())
    }

    /// Selects one 16-bit word without exposing the raw mask.
    #[must_use]
    pub fn select_u16(self, if_false: u16, if_true: u16) -> u16 {
        (if_false & !self.u16()) | (if_true & self.u16())
    }

    /// Selects one 32-bit word without exposing the raw mask.
    #[must_use]
    pub fn select_u32(self, if_false: u32, if_true: u32) -> u32 {
        (if_false & !self.u32()) | (if_true & self.u32())
    }

    /// Selects one 64-bit word without exposing the raw mask.
    #[must_use]
    pub fn select_u64(self, if_false: u64, if_true: u64) -> u64 {
        (if_false & !self.u64()) | (if_true & self.u64())
    }

    /// Selects one 128-bit word without exposing the raw mask.
    #[must_use]
    pub fn select_u128(self, if_false: u128, if_true: u128) -> u128 {
        (if_false & !self.u128()) | (if_true & self.u128())
    }

    /// Selects one pointer-width word without exposing the raw mask.
    #[must_use]
    pub fn select_usize(self, if_false: usize, if_true: usize) -> usize {
        (if_false & !self.usize()) | (if_true & self.usize())
    }
}
