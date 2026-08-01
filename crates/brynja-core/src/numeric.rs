//! Checked bounded integer foundations.

use core::convert::TryFrom;

/// A closed, non-secret reason that a checked numeric operation failed.
///
/// The error deliberately carries neither the rejected value nor its bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum NumericError {
    /// A value exceeded the type-level maximum.
    AboveMaximum,
    /// Primitive addition or multiplication overflowed.
    Overflow,
    /// Subtraction would have produced a negative value.
    Underflow,
    /// A value cannot be represented by the target platform's pointer width.
    PlatformWidth,
    /// A monotonic domain cannot advance without reuse or wraparound.
    Exhausted,
}

/// A `u64` value restricted to the inclusive range `0..=MAX`.
///
/// Construction and arithmetic are checked in every build profile. The type
/// does not implement `Debug` or `Display`, preventing accidental disclosure
/// when it is used for a caller-selected limit.
///
/// ```compile_fail
/// let value = brynja_core::BoundedU64::<8>::new(3);
/// println!("{value:?}");
/// ```
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedU64<const MAX: u64> {
    value: u64,
}

impl<const MAX: u64> BoundedU64<MAX> {
    /// The smallest admitted value.
    pub const MINIMUM: Self = Self { value: 0 };

    /// Returns the inclusive type-level maximum.
    pub const MAXIMUM: u64 = MAX;

    /// Constructs a value when it is within the type-level bound.
    pub const fn new(value: u64) -> Result<Self, NumericError> {
        if value <= MAX {
            Ok(Self { value })
        } else {
            Err(NumericError::AboveMaximum)
        }
    }

    /// Returns the contained value.
    pub const fn get(self) -> u64 {
        self.value
    }

    /// Returns how far this value is from the inclusive maximum.
    pub const fn remaining(self) -> u64 {
        MAX.saturating_sub(self.value)
    }

    /// Returns whether this value is zero.
    pub const fn is_zero(self) -> bool {
        self.value == 0
    }

    /// Adds without primitive overflow or crossing `MAX`.
    pub const fn checked_add(self, amount: u64) -> Result<Self, NumericError> {
        match self.value.checked_add(amount) {
            Some(value) => Self::new(value),
            None => Err(NumericError::Overflow),
        }
    }

    /// Multiplies without primitive overflow or crossing `MAX`.
    pub const fn checked_mul(self, factor: u64) -> Result<Self, NumericError> {
        match self.value.checked_mul(factor) {
            Some(value) => Self::new(value),
            None => Err(NumericError::Overflow),
        }
    }

    /// Subtracts without crossing zero.
    pub const fn checked_sub(self, amount: u64) -> Result<Self, NumericError> {
        match self.value.checked_sub(amount) {
            Some(value) => Ok(Self { value }),
            None => Err(NumericError::Underflow),
        }
    }
}

/// A `usize` value restricted to the inclusive range `0..=MAX`.
///
/// Conversion from a wire-sized `u64` fails when the platform pointer width
/// cannot represent the value, before the configured bound is considered.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedUsize<const MAX: usize> {
    value: usize,
}

impl<const MAX: usize> BoundedUsize<MAX> {
    /// The smallest admitted value.
    pub const MINIMUM: Self = Self { value: 0 };

    /// Returns the inclusive type-level maximum.
    pub const MAXIMUM: usize = MAX;

    /// Constructs a value when it is within the type-level bound.
    pub const fn new(value: usize) -> Result<Self, NumericError> {
        if value <= MAX {
            Ok(Self { value })
        } else {
            Err(NumericError::AboveMaximum)
        }
    }

    /// Converts and bounds a platform-independent wire-sized value.
    pub fn from_u64(value: u64) -> Result<Self, NumericError> {
        match usize::try_from(value) {
            Ok(value) => Self::new(value),
            Err(_) => Err(NumericError::PlatformWidth),
        }
    }

    /// Returns the contained value.
    pub const fn get(self) -> usize {
        self.value
    }

    /// Returns how far this value is from the inclusive maximum.
    pub const fn remaining(self) -> usize {
        MAX.saturating_sub(self.value)
    }

    /// Returns whether this value is zero.
    pub const fn is_zero(self) -> bool {
        self.value == 0
    }

    /// Adds without primitive overflow or crossing `MAX`.
    pub const fn checked_add(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_add(amount) {
            Some(value) => Self::new(value),
            None => Err(NumericError::Overflow),
        }
    }

    /// Multiplies without primitive overflow or crossing `MAX`.
    pub const fn checked_mul(self, factor: usize) -> Result<Self, NumericError> {
        match self.value.checked_mul(factor) {
            Some(value) => Self::new(value),
            None => Err(NumericError::Overflow),
        }
    }

    /// Subtracts without crossing zero.
    pub const fn checked_sub(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_sub(amount) {
            Some(value) => Ok(Self { value }),
            None => Err(NumericError::Underflow),
        }
    }
}
