//! Deterministic, non-production clock sources for state-machine tests.

use brynja_core::{ClockUnavailable, MonotonicClockSource, WallClockSource, WallTime};

/// One scripted deterministic clock reading.
#[derive(Clone, Copy)]
pub enum DeterministicReading<T> {
    /// Return this exact value.
    Value(T),
    /// Return explicit clock unavailability.
    Unavailable,
}

/// A finite deterministic wall-clock source.
pub struct DeterministicWallClock<'readings> {
    readings: &'readings [DeterministicReading<WallTime>],
    cursor: usize,
}

impl<'readings> DeterministicWallClock<'readings> {
    /// Binds the exact finite reading script.
    #[must_use]
    pub const fn new(readings: &'readings [DeterministicReading<WallTime>]) -> Self {
        Self {
            readings,
            cursor: 0,
        }
    }

    /// Returns the number of consumed scripted entries.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.cursor
    }
}

impl WallClockSource for DeterministicWallClock<'_> {
    fn read_wall_time(&mut self) -> Result<WallTime, ClockUnavailable> {
        let reading = self
            .readings
            .get(self.cursor)
            .copied()
            .ok_or(ClockUnavailable)?;
        self.cursor = self.cursor.checked_add(1).ok_or(ClockUnavailable)?;
        match reading {
            DeterministicReading::Value(value) => Ok(value),
            DeterministicReading::Unavailable => Err(ClockUnavailable),
        }
    }
}

/// A finite deterministic monotonic-tick source.
pub struct DeterministicMonotonicClock<'readings> {
    readings: &'readings [DeterministicReading<u64>],
    cursor: usize,
}

impl<'readings> DeterministicMonotonicClock<'readings> {
    /// Binds the exact finite reading script.
    #[must_use]
    pub const fn new(readings: &'readings [DeterministicReading<u64>]) -> Self {
        Self {
            readings,
            cursor: 0,
        }
    }

    /// Returns the number of consumed scripted entries.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.cursor
    }
}

impl MonotonicClockSource for DeterministicMonotonicClock<'_> {
    fn read_monotonic_ticks(&mut self) -> Result<u64, ClockUnavailable> {
        let reading = self
            .readings
            .get(self.cursor)
            .copied()
            .ok_or(ClockUnavailable)?;
        self.cursor = self.cursor.checked_add(1).ok_or(ClockUnavailable)?;
        match reading {
            DeterministicReading::Value(value) => Ok(value),
            DeterministicReading::Unavailable => Err(ClockUnavailable),
        }
    }
}
