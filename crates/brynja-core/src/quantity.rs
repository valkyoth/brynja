//! Semantically distinct bounded counts and lengths.

use crate::{BoundedUsize, NumericError};

/// A bounded number of protocol items.
///
/// `Count` is intentionally not interchangeable with [`Length`].
///
/// ```compile_fail
/// fn accepts_count(_: brynja_core::Count<8>) {}
/// let length = brynja_core::Length::<8>::new(1);
/// if let Ok(length) = length {
///     accepts_count(length);
/// }
/// ```
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Count<const MAX: usize> {
    value: BoundedUsize<MAX>,
}

impl<const MAX: usize> Count<MAX> {
    /// The zero count.
    pub const ZERO: Self = Self {
        value: BoundedUsize::MINIMUM,
    };

    /// Constructs a count within `0..=MAX`.
    pub const fn new(value: usize) -> Result<Self, NumericError> {
        match BoundedUsize::new(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Converts and bounds a platform-independent wire-sized count.
    pub fn from_u64(value: u64) -> Result<Self, NumericError> {
        match BoundedUsize::from_u64(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Returns the count.
    pub const fn get(self) -> usize {
        self.value.get()
    }

    /// Returns the remaining headroom to `MAX`.
    pub const fn remaining(self) -> usize {
        self.value.remaining()
    }

    /// Adds items without overflow or exceeding `MAX`.
    pub const fn checked_add(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_add(amount) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Subtracts items without crossing zero.
    pub const fn checked_sub(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_sub(amount) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }
}

/// A bounded byte length.
///
/// The type stores no slice and performs no allocation or buffer access.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Length<const MAX: usize> {
    value: BoundedUsize<MAX>,
}

impl<const MAX: usize> Length<MAX> {
    /// The zero length.
    pub const ZERO: Self = Self {
        value: BoundedUsize::MINIMUM,
    };

    /// Constructs a length within `0..=MAX`.
    pub const fn new(value: usize) -> Result<Self, NumericError> {
        match BoundedUsize::new(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Converts and bounds a platform-independent wire-sized length.
    pub fn from_u64(value: u64) -> Result<Self, NumericError> {
        match BoundedUsize::from_u64(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Returns the byte length.
    pub const fn get(self) -> usize {
        self.value.get()
    }

    /// Returns the remaining headroom to `MAX`.
    pub const fn remaining(self) -> usize {
        self.value.remaining()
    }

    /// Adds bytes without overflow or exceeding `MAX`.
    pub const fn checked_add(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_add(amount) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Multiplies a byte length without overflow or exceeding `MAX`.
    pub const fn checked_mul(self, factor: usize) -> Result<Self, NumericError> {
        match self.value.checked_mul(factor) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Subtracts bytes without crossing zero.
    pub const fn checked_sub(self, amount: usize) -> Result<Self, NumericError> {
        match self.value.checked_sub(amount) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }
}
