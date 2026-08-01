//! Non-wrapping sequence-number and epoch value domains.

use crate::{BoundedU64, NumericError};

/// A monotonic sequence number restricted to `0..=MAX`.
///
/// Advancing past `MAX` returns [`NumericError::Exhausted`]; it never wraps or
/// reuses zero. Read/write state ownership remains a later engine concern.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SequenceNumber<const MAX: u64> {
    value: BoundedU64<MAX>,
}

impl<const MAX: u64> SequenceNumber<MAX> {
    /// The initial sequence number.
    pub const ZERO: Self = Self {
        value: BoundedU64::MINIMUM,
    };

    /// Constructs a sequence number within `0..=MAX`.
    pub const fn new(value: u64) -> Result<Self, NumericError> {
        match BoundedU64::new(value) {
            Ok(value) => Ok(Self { value }),
            Err(error) => Err(error),
        }
    }

    /// Returns the sequence number.
    pub const fn get(self) -> u64 {
        self.value.get()
    }

    /// Returns the number of advances remaining before exhaustion.
    pub const fn remaining(self) -> u64 {
        self.value.remaining()
    }

    /// Advances by one without wraparound.
    pub const fn next(self) -> Result<Self, NumericError> {
        self.advance_by(1)
    }

    /// Advances by an explicit amount without wraparound.
    pub const fn advance_by(self, amount: u64) -> Result<Self, NumericError> {
        if amount <= self.remaining() {
            match self.value.checked_add(amount) {
                Ok(value) => Ok(Self { value }),
                Err(_) => Err(NumericError::Exhausted),
            }
        } else {
            Err(NumericError::Exhausted)
        }
    }
}

/// A monotonic 16-bit epoch restricted to `0..=MAX`.
///
/// The value is protocol-neutral. Epoch interpretation and key ownership stay
/// with their later version-specific engines.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Epoch<const MAX: u16> {
    value: u16,
}

impl<const MAX: u16> Epoch<MAX> {
    /// The initial epoch.
    pub const ZERO: Self = Self { value: 0 };

    /// Constructs an epoch within `0..=MAX`.
    pub const fn new(value: u16) -> Result<Self, NumericError> {
        if value <= MAX {
            Ok(Self { value })
        } else {
            Err(NumericError::AboveMaximum)
        }
    }

    /// Returns the epoch value.
    pub const fn get(self) -> u16 {
        self.value
    }

    /// Returns the number of advances remaining before exhaustion.
    pub const fn remaining(self) -> u16 {
        MAX.saturating_sub(self.value)
    }

    /// Advances by one without wraparound.
    pub const fn next(self) -> Result<Self, NumericError> {
        self.advance_by(1)
    }

    /// Advances by an explicit amount without wraparound.
    pub const fn advance_by(self, amount: u16) -> Result<Self, NumericError> {
        if amount <= self.remaining() {
            match self.value.checked_add(amount) {
                Some(value) => Ok(Self { value }),
                None => Err(NumericError::Exhausted),
            }
        } else {
            Err(NumericError::Exhausted)
        }
    }
}
