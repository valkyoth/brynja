//! Checked duration representation shared by the distinct clock domains.

/// Nanoseconds in one second.
pub const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// A closed time-domain construction or arithmetic failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TimeError {
    /// A subsecond value was not canonical.
    InvalidNanosecond,
    /// Checked arithmetic exceeded the represented domain.
    Overflow,
    /// Checked arithmetic would move before the represented value.
    Underflow,
    /// A wall-time or monotonic window ended before it began.
    ReversedRange,
    /// A clock generation must not be zero.
    ZeroGeneration,
    /// Two monotonic values came from different runtime generations.
    GenerationMismatch,
    /// A policy-bound value was used for the wrong purpose.
    PurposeMismatch,
    /// A duration cannot be represented as monotonic nanosecond ticks.
    DurationTooLarge,
}

/// A nonnegative, canonical duration.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockDuration {
    seconds: u64,
    nanoseconds: u32,
}

impl ClockDuration {
    /// Zero elapsed time.
    pub const ZERO: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };

    /// Constructs a canonical seconds-and-nanoseconds duration.
    pub const fn from_parts(seconds: u64, nanoseconds: u32) -> Result<Self, TimeError> {
        if nanoseconds < NANOS_PER_SECOND {
            Ok(Self {
                seconds,
                nanoseconds,
            })
        } else {
            Err(TimeError::InvalidNanosecond)
        }
    }

    /// Constructs a whole-second duration.
    #[must_use]
    pub const fn from_seconds(seconds: u64) -> Self {
        Self {
            seconds,
            nanoseconds: 0,
        }
    }

    /// Returns the whole-second component.
    #[must_use]
    pub const fn whole_seconds(self) -> u64 {
        self.seconds
    }

    /// Returns the canonical subsecond component.
    #[must_use]
    pub const fn subsec_nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    /// Returns whether the duration is zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.seconds == 0 && self.nanoseconds == 0
    }

    /// Adds two durations without wrapping.
    pub const fn checked_add(self, other: Self) -> Result<Self, TimeError> {
        let subsecond_sum = match self.nanoseconds.checked_add(other.nanoseconds) {
            Some(value) => value,
            None => return Err(TimeError::Overflow),
        };
        let (nanoseconds, carry) = if subsecond_sum >= NANOS_PER_SECOND {
            let nanoseconds = match subsecond_sum.checked_sub(NANOS_PER_SECOND) {
                Some(value) => value,
                None => return Err(TimeError::Overflow),
            };
            (nanoseconds, 1_u64)
        } else {
            (subsecond_sum, 0_u64)
        };
        let seconds = match self.seconds.checked_add(other.seconds) {
            Some(value) => value,
            None => return Err(TimeError::Overflow),
        };
        match seconds.checked_add(carry) {
            Some(seconds) => Ok(Self {
                seconds,
                nanoseconds,
            }),
            None => Err(TimeError::Overflow),
        }
    }

    /// Subtracts a duration without crossing zero.
    pub fn checked_sub(self, other: Self) -> Result<Self, TimeError> {
        if self < other {
            return Err(TimeError::Underflow);
        }
        if self.nanoseconds >= other.nanoseconds {
            let seconds = self
                .seconds
                .checked_sub(other.seconds)
                .ok_or(TimeError::Underflow)?;
            let nanoseconds = self
                .nanoseconds
                .checked_sub(other.nanoseconds)
                .ok_or(TimeError::Underflow)?;
            Ok(Self {
                seconds,
                nanoseconds,
            })
        } else {
            let seconds = self
                .seconds
                .checked_sub(other.seconds)
                .and_then(|value| value.checked_sub(1))
                .ok_or(TimeError::Underflow)?;
            let difference = other
                .nanoseconds
                .checked_sub(self.nanoseconds)
                .ok_or(TimeError::Underflow)?;
            let nanoseconds = NANOS_PER_SECOND
                .checked_sub(difference)
                .ok_or(TimeError::Underflow)?;
            Ok(Self {
                seconds,
                nanoseconds,
            })
        }
    }

    pub(crate) fn as_tick_nanoseconds(self) -> Result<u64, TimeError> {
        let seconds = self
            .seconds
            .checked_mul(u64::from(NANOS_PER_SECOND))
            .ok_or(TimeError::DurationTooLarge)?;
        seconds
            .checked_add(u64::from(self.nanoseconds))
            .ok_or(TimeError::DurationTooLarge)
    }
}
