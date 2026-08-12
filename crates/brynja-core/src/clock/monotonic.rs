//! Generation- and purpose-bound monotonic time.

use super::{ClockDuration, NANOS_PER_SECOND, TimeError};

/// A nonzero runtime/boot generation for monotonic time.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClockGeneration(u64);

impl ClockGeneration {
    /// Constructs a nonzero generation selected by the platform boundary.
    pub const fn new(value: u64) -> Result<Self, TimeError> {
        if value == 0 {
            Err(TimeError::ZeroGeneration)
        } else {
            Ok(Self(value))
        }
    }

    /// Advances the generation without reuse or wraparound.
    pub const fn next(self) -> Result<Self, TimeError> {
        match self.0.checked_add(1) {
            Some(value) => Self::new(value),
            None => Err(TimeError::Overflow),
        }
    }
}

/// An opaque generation-bound monotonic observation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MonotonicInstant {
    generation: ClockGeneration,
    tick_nanoseconds: u64,
}

impl core::fmt::Debug for MonotonicInstant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MonotonicInstant(REDACTED)")
    }
}

impl MonotonicInstant {
    /// Returns the runtime generation without exposing the raw tick value.
    #[must_use]
    pub const fn generation(self) -> ClockGeneration {
        self.generation
    }

    /// Computes elapsed time only inside the same generation and direction.
    pub fn elapsed_since(self, earlier: Self) -> Result<ClockDuration, TimeError> {
        require_generation(self, earlier)?;
        let ticks = self
            .tick_nanoseconds
            .checked_sub(earlier.tick_nanoseconds)
            .ok_or(TimeError::Underflow)?;
        duration_from_ticks(ticks)
    }
}

/// The security purpose bound to a monotonic deadline.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MonotonicPurpose {
    /// General timer scheduling.
    Timer,
    /// Freshness policy.
    Freshness,
    /// Ticket lifetime policy.
    Ticket,
    /// Replay-window policy.
    Replay,
}

/// The state of a checked monotonic deadline.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeadlineStatus {
    /// The deadline has not elapsed; the value is the exact remaining time.
    Pending(ClockDuration),
    /// The deadline has elapsed or is exactly reached.
    Reached,
}

/// An immutable generation- and purpose-bound monotonic deadline.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct MonotonicDeadline {
    purpose: MonotonicPurpose,
    generation: ClockGeneration,
    tick_nanoseconds: u64,
}

impl MonotonicDeadline {
    /// Constructs a deadline with checked tick arithmetic.
    pub fn new(
        start: MonotonicInstant,
        duration: ClockDuration,
        purpose: MonotonicPurpose,
    ) -> Result<Self, TimeError> {
        let amount = duration.as_tick_nanoseconds()?;
        let tick_nanoseconds = start
            .tick_nanoseconds
            .checked_add(amount)
            .ok_or(TimeError::Overflow)?;
        Ok(Self {
            purpose,
            generation: start.generation,
            tick_nanoseconds,
        })
    }

    /// Requires the exact semantic purpose chosen at construction.
    pub fn require_purpose(self, purpose: MonotonicPurpose) -> Result<(), TimeError> {
        if self.purpose == purpose {
            Ok(())
        } else {
            Err(TimeError::PurposeMismatch)
        }
    }

    /// Evaluates the deadline for its exact purpose and runtime generation.
    pub fn evaluate(
        self,
        now: MonotonicInstant,
        purpose: MonotonicPurpose,
    ) -> Result<DeadlineStatus, TimeError> {
        self.require_purpose(purpose)?;
        if self.generation != now.generation {
            return Err(TimeError::GenerationMismatch);
        }
        match self.tick_nanoseconds.checked_sub(now.tick_nanoseconds) {
            Some(0) | None => Ok(DeadlineStatus::Reached),
            Some(ticks) => Ok(DeadlineStatus::Pending(duration_from_ticks(ticks)?)),
        }
    }
}

/// An explicit, value-free indication that a clock cannot currently be read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClockUnavailable;

/// A downstream monotonic tick source capability.
pub trait MonotonicClockSource {
    /// Returns one raw monotonic nanosecond tick or explicit unavailability.
    fn read_monotonic_ticks(&mut self) -> Result<u64, ClockUnavailable>;
}

/// A closed monotonic clock state-machine failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MonotonicClockError {
    /// The source is currently unavailable; prior state remains usable.
    Unavailable,
    /// The source moved backwards and the wrapper entered terminal failure.
    Regressed,
    /// A prior rollback permanently failed this wrapper.
    Failed,
}

/// A checked monotonic source wrapper with terminal rollback detection.
pub struct MonotonicClock<S: MonotonicClockSource> {
    source: S,
    generation: ClockGeneration,
    last_tick: Option<u64>,
    failed: bool,
}

impl<S: MonotonicClockSource> MonotonicClock<S> {
    /// Binds a source to one explicit runtime generation.
    #[must_use]
    pub const fn new(source: S, generation: ClockGeneration) -> Self {
        Self {
            source,
            generation,
            last_tick: None,
            failed: false,
        }
    }

    /// Reads a nondecreasing instant or fails closed after rollback.
    pub fn read(&mut self) -> Result<MonotonicInstant, MonotonicClockError> {
        if self.failed {
            return Err(MonotonicClockError::Failed);
        }
        let tick_nanoseconds = self
            .source
            .read_monotonic_ticks()
            .map_err(|_unavailable| MonotonicClockError::Unavailable)?;
        if self.last_tick.is_some_and(|last| tick_nanoseconds < last) {
            self.failed = true;
            return Err(MonotonicClockError::Regressed);
        }
        self.last_tick = Some(tick_nanoseconds);
        Ok(MonotonicInstant {
            generation: self.generation,
            tick_nanoseconds,
        })
    }

    /// Reports whether rollback permanently failed this wrapper.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }
}

fn require_generation(first: MonotonicInstant, second: MonotonicInstant) -> Result<(), TimeError> {
    if first.generation == second.generation {
        Ok(())
    } else {
        Err(TimeError::GenerationMismatch)
    }
}

fn duration_from_ticks(ticks: u64) -> Result<ClockDuration, TimeError> {
    let seconds = ticks.div_euclid(u64::from(NANOS_PER_SECOND));
    let remainder = ticks.rem_euclid(u64::from(NANOS_PER_SECOND));
    let nanoseconds = u32::try_from(remainder).map_err(|_| TimeError::Overflow)?;
    ClockDuration::from_parts(seconds, nanoseconds)
}
