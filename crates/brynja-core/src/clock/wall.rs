//! Externally adjustable wall-clock values and validity ranges.

use super::{ClockDuration, NANOS_PER_SECOND, TimeError};

/// A canonical Unix wall-clock time for later PKI validity decisions.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WallTime {
    unix_seconds: i64,
    nanoseconds: u32,
}

impl WallTime {
    /// Constructs a canonical Unix time, including times before the epoch.
    pub const fn from_unix_parts(unix_seconds: i64, nanoseconds: u32) -> Result<Self, TimeError> {
        if nanoseconds < NANOS_PER_SECOND {
            Ok(Self {
                unix_seconds,
                nanoseconds,
            })
        } else {
            Err(TimeError::InvalidNanosecond)
        }
    }

    /// Returns the floor Unix-second component.
    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }

    /// Returns the canonical subsecond component.
    #[must_use]
    pub const fn subsec_nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    /// Adds a duration without leaving the signed Unix-second domain.
    pub fn checked_add(self, duration: ClockDuration) -> Result<Self, TimeError> {
        let subsecond_sum = self
            .nanoseconds
            .checked_add(duration.subsec_nanoseconds())
            .ok_or(TimeError::Overflow)?;
        let (nanoseconds, carry) = if subsecond_sum >= NANOS_PER_SECOND {
            (
                subsecond_sum
                    .checked_sub(NANOS_PER_SECOND)
                    .ok_or(TimeError::Overflow)?,
                1_i128,
            )
        } else {
            (subsecond_sum, 0_i128)
        };
        let seconds = i128::from(self.unix_seconds)
            .checked_add(i128::from(duration.whole_seconds()))
            .and_then(|value| value.checked_add(carry))
            .ok_or(TimeError::Overflow)?;
        let unix_seconds = i64::try_from(seconds).map_err(|_| TimeError::Overflow)?;
        Ok(Self {
            unix_seconds,
            nanoseconds,
        })
    }

    /// Subtracts a duration without leaving the signed Unix-second domain.
    pub fn checked_sub(self, duration: ClockDuration) -> Result<Self, TimeError> {
        let (nanoseconds, borrow) = if self.nanoseconds >= duration.subsec_nanoseconds() {
            (
                self.nanoseconds
                    .checked_sub(duration.subsec_nanoseconds())
                    .ok_or(TimeError::Underflow)?,
                0_i128,
            )
        } else {
            let difference = duration
                .subsec_nanoseconds()
                .checked_sub(self.nanoseconds)
                .ok_or(TimeError::Underflow)?;
            (
                NANOS_PER_SECOND
                    .checked_sub(difference)
                    .ok_or(TimeError::Underflow)?,
                1_i128,
            )
        };
        let seconds = i128::from(self.unix_seconds)
            .checked_sub(i128::from(duration.whole_seconds()))
            .and_then(|value| value.checked_sub(borrow))
            .ok_or(TimeError::Underflow)?;
        let unix_seconds = i64::try_from(seconds).map_err(|_| TimeError::Underflow)?;
        Ok(Self {
            unix_seconds,
            nanoseconds,
        })
    }

    /// Returns the nonnegative duration since an earlier wall time.
    pub fn duration_since(self, earlier: Self) -> Result<ClockDuration, TimeError> {
        if self < earlier {
            return Err(TimeError::Underflow);
        }
        let seconds = i128::from(self.unix_seconds)
            .checked_sub(i128::from(earlier.unix_seconds))
            .ok_or(TimeError::Overflow)?;
        let (seconds, nanoseconds) = if self.nanoseconds >= earlier.nanoseconds {
            (
                seconds,
                self.nanoseconds
                    .checked_sub(earlier.nanoseconds)
                    .ok_or(TimeError::Underflow)?,
            )
        } else {
            let difference = earlier
                .nanoseconds
                .checked_sub(self.nanoseconds)
                .ok_or(TimeError::Underflow)?;
            (
                seconds.checked_sub(1).ok_or(TimeError::Underflow)?,
                NANOS_PER_SECOND
                    .checked_sub(difference)
                    .ok_or(TimeError::Underflow)?,
            )
        };
        let seconds = u64::try_from(seconds).map_err(|_| TimeError::Overflow)?;
        ClockDuration::from_parts(seconds, nanoseconds)
    }
}

/// The result of evaluating a wall time against an inclusive validity range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WallTimeStatus {
    /// The value precedes the range.
    Before,
    /// The value is inside the inclusive range.
    Valid,
    /// The value follows the range.
    After,
}

/// One immutable inclusive wall-time validity range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WallTimeRange {
    not_before: WallTime,
    not_after: WallTime,
}

impl WallTimeRange {
    /// Constructs an ordered inclusive range.
    pub fn new(not_before: WallTime, not_after: WallTime) -> Result<Self, TimeError> {
        if not_before <= not_after {
            Ok(Self {
                not_before,
                not_after,
            })
        } else {
            Err(TimeError::ReversedRange)
        }
    }

    /// Evaluates one explicit wall time without reading a clock.
    #[must_use]
    pub fn evaluate(self, time: WallTime) -> WallTimeStatus {
        if time < self.not_before {
            WallTimeStatus::Before
        } else if time > self.not_after {
            WallTimeStatus::After
        } else {
            WallTimeStatus::Valid
        }
    }
}

/// A downstream wall-clock source capability.
pub trait WallClockSource {
    /// Returns one explicit wall time or explicit unavailability.
    fn read_wall_time(&mut self) -> Result<WallTime, super::ClockUnavailable>;
}
